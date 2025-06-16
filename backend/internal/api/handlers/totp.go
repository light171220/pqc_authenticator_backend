package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/auth"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type TOTPHandler struct {
	db         *storage.Database
	logger     utils.Logger
	config     *utils.Config
	keyMgr     *crypto.KeyManager
	rateLimits sync.Map
}

type RateLimit struct {
	count     int
	resetTime time.Time
	mutex     sync.Mutex
}

func NewTOTPHandler(db *storage.Database, logger utils.Logger, config *utils.Config, keyMgr *crypto.KeyManager) *TOTPHandler {
	handler := &TOTPHandler{
		db:     db,
		logger: logger,
		config: config,
		keyMgr: keyMgr,
	}
	
	go handler.cleanupRateLimits()
	return handler
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
	Signature string `json:"signature,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
	Period    int    `json:"period"`
	TimeSync  int64  `json:"time_sync"`
}

func (h *TOTPHandler) GenerateCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req GenerateCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid generate code request", "error", err, "user_id", userID)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	if !h.checkGenerationRateLimit(userID, req.AccountID) {
		h.logger.Warn("TOTP generation rate limit exceeded", "user_id", userID, "account_id", req.AccountID)
		h.respondWithError(c, utils.ErrTooManyRequests)
		return
	}

	account, err := storage.GetAccountByID(h.db.DB, req.AccountID)
	if err != nil {
		h.logger.Error("Failed to get account", "error", err, "account_id", req.AccountID, "user_id", userID)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if account.UserID != userID {
		h.logger.Warn("Unauthorized account access attempt", "user_id", userID, "account_id", req.AccountID, "owner_id", account.UserID)
		h.respondWithError(c, utils.ErrForbidden)
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err, "account_id", req.AccountID)
		h.respondWithError(c, utils.ErrInternalServer)
		return
	}
	defer crypto.SecureZeroMemory(secretKey)

	pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period, h.keyMgr, userID)
	
	now := time.Now()
	var code, signature string

	if h.config.TOTP.RequireSignature {
		code, signature, err = pqtotp.GenerateCodeWithSignature(now)
		if err != nil {
			h.logger.Error("Failed to generate TOTP code with signature", "error", err, "account_id", req.AccountID)
			h.respondWithError(c, utils.ErrInternalServer)
			return
		}
	} else {
		code, err = pqtotp.GenerateCode(now)
		if err != nil {
			h.logger.Error("Failed to generate TOTP code", "error", err, "account_id", req.AccountID)
			h.respondWithError(c, utils.ErrInternalServer)
			return
		}
	}

	timeSlot := now.Unix() / int64(account.Period)
	expiresAt := (timeSlot + 1) * int64(account.Period)

	if err := storage.LogAuditEvent(h.db.DB, userID, "", "totp_generated", map[string]interface{}{
		"account_id":    req.AccountID,
		"service_name":  account.ServiceName,
		"timestamp":     now.Unix(),
		"ip_address":    c.ClientIP(),
		"user_agent":    c.GetHeader("User-Agent"),
		"has_signature": signature != "",
		"result":        "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("TOTP code generated", "user_id", userID, "account_id", req.AccountID)

	response := TOTPResponse{
		Code:      code,
		ExpiresAt: expiresAt,
		Period:    account.Period,
		TimeSync:  now.Unix(),
	}

	if signature != "" {
		response.Signature = signature
	}

	c.JSON(http.StatusOK, response)
}

func (h *TOTPHandler) VerifyCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req VerifyCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid verify code request", "error", err, "user_id", userID)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	if !utils.IsNumeric(req.Code) {
		h.logger.Warn("Invalid code format", "user_id", userID, "account_id", req.AccountID)
		h.respondWithError(c, utils.NewAppError("INVALID_CODE_FORMAT", "Code must be numeric", 400))
		return
	}

	if !h.checkVerificationRateLimit(userID, req.AccountID) {
		h.logger.Warn("TOTP verification rate limit exceeded", "user_id", userID, "account_id", req.AccountID)
		h.respondWithError(c, utils.ErrTooManyRequests)
		return
	}

	account, err := storage.GetAccountByID(h.db.DB, req.AccountID)
	if err != nil {
		h.logger.Error("Failed to get account", "error", err, "account_id", req.AccountID, "user_id", userID)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if account.UserID != userID {
		h.logger.Warn("Unauthorized account access attempt", "user_id", userID, "account_id", req.AccountID, "owner_id", account.UserID)
		h.respondWithError(c, utils.ErrForbidden)
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err, "account_id", req.AccountID)
		h.respondWithError(c, utils.ErrInternalServer)
		return
	}
	defer crypto.SecureZeroMemory(secretKey)

	pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period, h.keyMgr, userID)
	
	now := time.Now()
	var isValid bool

	if h.config.TOTP.RequireSignature && req.Signature != "" {
		isValid, err = pqtotp.VerifyCodeWithSignature(req.Code, req.Signature, now)
	} else {
		isValid, err = pqtotp.VerifyCode(req.Code, now)
	}

	if err != nil {
		h.logger.Error("Failed to verify TOTP code", "error", err, "account_id", req.AccountID)
		h.respondWithError(c, utils.ErrInternalServer)
		return
	}

	result := "failed"
	if isValid {
		result = "success"
	}

	if err := storage.LogAuditEvent(h.db.DB, userID, "", "totp_verified", map[string]interface{}{
		"account_id":    req.AccountID,
		"service_name":  account.ServiceName,
		"result":        result,
		"timestamp":     now.Unix(),
		"ip_address":    c.ClientIP(),
		"user_agent":    c.GetHeader("User-Agent"),
		"has_signature": req.Signature != "",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	if isValid {
		h.logger.Info("TOTP verification successful", "user_id", userID, "account_id", req.AccountID)
	} else {
		h.logger.Warn("TOTP verification failed", "user_id", userID, "account_id", req.AccountID)
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":       isValid,
		"account_id":  req.AccountID,
		"verified_at": now.Unix(),
	})
}

func (h *TOTPHandler) GetQRCode(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	accountID := c.Param("account_id")
	if accountID == "" {
		h.respondWithError(c, utils.NewAppError("MISSING_ACCOUNT_ID", "Account ID required", 400))
		return
	}

	account, err := storage.GetAccountByID(h.db.DB, accountID)
	if err != nil {
		h.logger.Error("Failed to get account", "error", err, "account_id", accountID, "user_id", userID)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if account.UserID != userID {
		h.logger.Warn("Unauthorized account access attempt", "user_id", userID, "account_id", accountID, "owner_id", account.UserID)
		h.respondWithError(c, utils.ErrForbidden)
		return
	}

	user, err := storage.GetUserByID(h.db.DB, userID)
	if err != nil {
		h.logger.Error("Failed to get user", "error", err, "user_id", userID)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to decrypt secret key", "error", err, "account_id", accountID)
		h.respondWithError(c, utils.ErrInternalServer)
		return
	}
	defer crypto.SecureZeroMemory(secretKey)

	qrCodeData, err := auth.GenerateQRCodeData(user.Username, account.ServiceName, secretKey, account.Issuer)
	if err != nil {
		h.logger.Error("Failed to generate QR code data", "error", err, "account_id", accountID)
		h.respondWithError(c, utils.NewAppError("QR_GENERATION_FAILED", "Failed to generate QR code", 500))
		return
	}

	c.JSON(http.StatusOK, qrCodeData)
}

func (h *TOTPHandler) RotateKeys(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	if err := h.keyMgr.RotateUserKeys(userID); err != nil {
		h.logger.Error("Failed to rotate user keys", "user_id", userID, "error", err)
		h.respondWithError(c, utils.NewAppError("KEY_ROTATION_FAILED", "Failed to rotate keys", 500))
		return
	}

	if err := storage.LogAuditEvent(h.db.DB, userID, "", "keys_rotated", map[string]interface{}{
		"timestamp":  time.Now().Unix(),
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User keys rotated", "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message":    "Keys rotated successfully",
		"rotated_at": time.Now().Unix(),
	})
}

func (h *TOTPHandler) TimeSync(c *gin.Context) {
	now := time.Now()
	
	c.JSON(http.StatusOK, gin.H{
		"server_time": now.Unix(),
		"utc_time":    now.UTC().Format(time.RFC3339),
		"timezone":    now.Format("-0700 MST"),
	})
}

func (h *TOTPHandler) checkGenerationRateLimit(userID, accountID string) bool {
	key := userID + ":" + accountID + ":generate"
	return h.checkRateLimit(key, h.config.TOTP.MaxGenerationsPerHour, time.Hour)
}

func (h *TOTPHandler) checkVerificationRateLimit(userID, accountID string) bool {
	key := userID + ":" + accountID + ":verify"
	return h.checkRateLimit(key, 20, time.Minute)
}

func (h *TOTPHandler) checkRateLimit(key string, maxRequests int, window time.Duration) bool {
	now := time.Now()
	
	value, exists := h.rateLimits.Load(key)
	if !exists {
		rateLimit := &RateLimit{
			count:     1,
			resetTime: now.Add(window),
		}
		h.rateLimits.Store(key, rateLimit)
		return true
	}
	
	rateLimit := value.(*RateLimit)
	rateLimit.mutex.Lock()
	defer rateLimit.mutex.Unlock()
	
	if now.After(rateLimit.resetTime) {
		rateLimit.count = 1
		rateLimit.resetTime = now.Add(window)
		return true
	}
	
	if rateLimit.count >= maxRequests {
		return false
	}
	
	rateLimit.count++
	return true
}

func (h *TOTPHandler) cleanupRateLimits() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		h.rateLimits.Range(func(key, value interface{}) bool {
			rateLimit := value.(*RateLimit)
			if now.After(rateLimit.resetTime.Add(time.Hour)) {
				h.rateLimits.Delete(key)
			}
			return true
		})
	}
}

func (h *TOTPHandler) respondWithError(c *gin.Context, err *utils.AppError) {
	traceID := c.GetHeader("X-Trace-ID")
	if traceID == "" {
		traceID = utils.GenerateTraceID()
	}
	
	sanitizedErr := utils.SanitizeError(err)
	response := utils.NewErrorResponse(sanitizedErr, traceID)
	
	c.JSON(sanitizedErr.HTTPCode, response)
}