package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/auth"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type TOTPHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewTOTPHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *TOTPHandler {
	return &TOTPHandler{
		db:     db,
		logger: logger,
		config: config,
	}
}

type GenerateCodeRequest struct {
	AccountID string `json:"account_id" binding:"required"`
}

type VerifyCodeRequest struct {
	AccountID string `json:"account_id" binding:"required"`
	Code      string `json:"code" binding:"required,len=6"`
	Signature string `json:"signature,omitempty"`
}

type TOTPResponse struct {
	Code      string `json:"code"`
	Signature string `json:"signature"`
	ExpiresAt int64  `json:"expires_at"`
	Period    int    `json:"period"`
}

func (h *TOTPHandler) GenerateCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req GenerateCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid generate code request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	account, err := storage.GetAccountByID(h.db, req.AccountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate code"})
		return
	}

	pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period)
	
	code, err := pqtotp.GenerateCode(time.Now())
	if err != nil {
		h.logger.Error("Failed to generate TOTP code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate code"})
		return
	}

	signature, err := crypto.SignData([]byte(code), userID)
	if err != nil {
		h.logger.Error("Failed to sign TOTP code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate signature"})
		return
	}

	now := time.Now()
	timeSlot := now.Unix() / int64(account.Period)
	expiresAt := (timeSlot + 1) * int64(account.Period)

	if err := storage.LogAuditEvent(h.db, userID, "", "totp_generated", map[string]interface{}{
		"account_id":   req.AccountID,
		"service_name": account.ServiceName,
		"timestamp":    now.Unix(),
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("TOTP code generated", "user_id", userID, "account_id", req.AccountID)

	c.JSON(http.StatusOK, TOTPResponse{
		Code:      code,
		Signature: signature,
		ExpiresAt: expiresAt,
		Period:    account.Period,
	})
}

func (h *TOTPHandler) VerifyCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req VerifyCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid verify code request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsNumeric(req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code must be numeric"})
		return
	}

	account, err := storage.GetAccountByID(h.db, req.AccountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify code"})
		return
	}

	pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period)
	
	isValid, err := pqtotp.VerifyCode(req.Code, time.Now())
	if err != nil {
		h.logger.Error("Failed to verify TOTP code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify code"})
		return
	}

	if req.Signature != "" {
		sigValid, err := crypto.VerifySignature([]byte(req.Code), req.Signature, userID)
		if err != nil || !sigValid {
			h.logger.Warn("Invalid signature", "user_id", userID, "account_id", req.AccountID)
			isValid = false
		}
	}

	result := "failed"
	if isValid {
		result = "success"
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "totp_verified", map[string]interface{}{
		"account_id":   req.AccountID,
		"service_name": account.ServiceName,
		"result":       result,
		"timestamp":    time.Now().Unix(),
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	if isValid {
		h.logger.Info("TOTP code verified successfully", "user_id", userID, "account_id", req.AccountID)
		c.JSON(http.StatusOK, gin.H{
			"valid":   true,
			"message": "Code verified successfully",
		})
	} else {
		h.logger.Warn("TOTP code verification failed", "user_id", userID, "account_id", req.AccountID)
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"message": "Invalid code",
		})
	}
}

func (h *TOTPHandler) GetQRCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	accountID := c.Param("account_id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account ID required"})
		return
	}

	account, err := storage.GetAccountByID(h.db, accountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	qrData, err := auth.GenerateQRCode(user.Username, account.ServiceName, secretKey, account.Issuer)
	if err != nil {
		h.logger.Error("Failed to generate QR code", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	h.logger.Info("QR code generated", "user_id", userID, "account_id", accountID)

	c.Header("Content-Type", "image/png")
	c.Data(http.StatusOK, "image/png", qrData)
}

func (h *TOTPHandler) RotateKeys(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	keyRotator := auth.NewKeyRotator(h.db, h.logger)
	if err := keyRotator.RotateUserKeys(userID); err != nil {
		h.logger.Error("Failed to rotate keys", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate keys"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "keys_rotated", map[string]interface{}{
		"timestamp":  time.Now().Unix(),
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Keys rotated", "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Keys rotated successfully",
		"rotated_at": time.Now().Unix(),
	})
}