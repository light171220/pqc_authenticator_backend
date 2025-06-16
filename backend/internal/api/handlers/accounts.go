package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type AccountHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
	keyMgr *crypto.KeyManager
}

func NewAccountHandler(db *sql.DB, logger utils.Logger, config *utils.Config, keyMgr *crypto.KeyManager) *AccountHandler {
	return &AccountHandler{
		db:     db,
		logger: logger,
		config: config,
		keyMgr: keyMgr,
	}
}

type CreateAccountRequest struct {
	ServiceName string `json:"service_name" binding:"required,min=1,max=100"`
	ServiceURL  string `json:"service_url" binding:"required,url"`
	Issuer      string `json:"issuer" binding:"required,min=1,max=100"`
	Digits      int    `json:"digits,omitempty"`
	Period      int    `json:"period,omitempty"`
}

type UpdateAccountRequest struct {
	ServiceName string `json:"service_name,omitempty"`
	ServiceURL  string `json:"service_url,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
}

type AccountResponse struct {
	ID          string    `json:"id"`
	ServiceName string    `json:"service_name"`
	ServiceURL  string    `json:"service_url"`
	Algorithm   string    `json:"algorithm"`
	Digits      int       `json:"digits"`
	Period      int       `json:"period"`
	Issuer      string    `json:"issuer"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *AccountHandler) CreateAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	var req CreateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid create account request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	digits := req.Digits
	if digits == 0 {
		digits = h.config.TOTP.DefaultDigits
	}

	period := req.Period
	if period == 0 {
		period = h.config.TOTP.DefaultPeriod
	}

	if digits < 6 || digits > 8 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Digits must be between 6 and 8",
			"code":  "INVALID_DIGITS",
		})
		return
	}

	if period < 15 || period > 300 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Period must be between 15 and 300 seconds",
			"code":  "INVALID_PERIOD",
		})
		return
	}

	secretKey, err := crypto.GenerateSecretKey()
	if err != nil {
		h.logger.Error("Failed to generate secret key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create account",
			"code":  "SECRET_GENERATION_FAILED",
		})
		return
	}

	encryptedSecret, err := crypto.EncryptData(secretKey, h.config.Security.EncryptionKey)
	if err != nil {
		h.logger.Error("Failed to encrypt secret key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create account",
			"code":  "ENCRYPTION_FAILED",
		})
		return
	}

	account := &storage.Account{
		ID:          uuid.New().String(),
		UserID:      userID,
		ServiceName: req.ServiceName,
		ServiceURL:  req.ServiceURL,
		SecretKey:   encryptedSecret,
		Algorithm:   "SHAKE256",
		Digits:      digits,
		Period:      period,
		Issuer:      req.Issuer,
		CreatedAt:   time.Now(),
	}

	if err := storage.CreateAccount(h.db, account); err != nil {
		h.logger.Error("Failed to create account", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create account",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "account_created", map[string]interface{}{
		"account_id":   account.ID,
		"service_name": account.ServiceName,
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Account created", "user_id", userID, "account_id", account.ID)

	c.JSON(http.StatusCreated, AccountResponse{
		ID:          account.ID,
		ServiceName: account.ServiceName,
		ServiceURL:  account.ServiceURL,
		Algorithm:   account.Algorithm,
		Digits:      account.Digits,
		Period:      account.Period,
		Issuer:      account.Issuer,
		CreatedAt:   account.CreatedAt,
	})
}

func (h *AccountHandler) ListAccounts(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	accounts, err := storage.GetUserAccounts(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user accounts", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve accounts",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	var response []AccountResponse
	for _, account := range accounts {
		response = append(response, AccountResponse{
			ID:          account.ID,
			ServiceName: account.ServiceName,
			ServiceURL:  account.ServiceURL,
			Algorithm:   account.Algorithm,
			Digits:      account.Digits,
			Period:      account.Period,
			Issuer:      account.Issuer,
			CreatedAt:   account.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"accounts": response})
}

func (h *AccountHandler) GetAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	accountID := c.Param("id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Account ID required",
			"code":  "MISSING_ACCOUNT_ID",
		})
		return
	}

	account, err := storage.GetAccountByID(h.db, accountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Account not found",
			"code":  "ACCOUNT_NOT_FOUND",
		})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied",
			"code":  "ACCESS_DENIED",
		})
		return
	}

	c.JSON(http.StatusOK, AccountResponse{
		ID:          account.ID,
		ServiceName: account.ServiceName,
		ServiceURL:  account.ServiceURL,
		Algorithm:   account.Algorithm,
		Digits:      account.Digits,
		Period:      account.Period,
		Issuer:      account.Issuer,
		CreatedAt:   account.CreatedAt,
	})
}

func (h *AccountHandler) UpdateAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	accountID := c.Param("id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Account ID required",
			"code":  "MISSING_ACCOUNT_ID",
		})
		return
	}

	var req UpdateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid update account request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	account, err := storage.GetAccountByID(h.db, accountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Account not found",
			"code":  "ACCOUNT_NOT_FOUND",
		})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied",
			"code":  "ACCESS_DENIED",
		})
		return
	}

	if req.ServiceName != "" {
		account.ServiceName = req.ServiceName
	}
	if req.ServiceURL != "" {
		account.ServiceURL = req.ServiceURL
	}
	if req.Issuer != "" {
		account.Issuer = req.Issuer
	}

	if err := storage.UpdateAccount(h.db, account); err != nil {
		h.logger.Error("Failed to update account", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update account",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "account_updated", map[string]interface{}{
		"account_id":   accountID,
		"service_name": account.ServiceName,
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Account updated", "user_id", userID, "account_id", accountID)

	c.JSON(http.StatusOK, AccountResponse{
		ID:          account.ID,
		ServiceName: account.ServiceName,
		ServiceURL:  account.ServiceURL,
		Algorithm:   account.Algorithm,
		Digits:      account.Digits,
		Period:      account.Period,
		Issuer:      account.Issuer,
		CreatedAt:   account.CreatedAt,
	})
}

func (h *AccountHandler) DeleteAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	accountID := c.Param("id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Account ID required",
			"code":  "MISSING_ACCOUNT_ID",
		})
		return
	}

	account, err := storage.GetAccountByID(h.db, accountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Account not found",
			"code":  "ACCOUNT_NOT_FOUND",
		})
		return
	}

	if account.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied",
			"code":  "ACCESS_DENIED",
		})
		return
	}

	if err := storage.DeleteAccount(h.db, accountID); err != nil {
		h.logger.Error("Failed to delete account", "account_id", accountID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete account",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "account_deleted", map[string]interface{}{
		"account_id":   accountID,
		"service_name": account.ServiceName,
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Account deleted", "user_id", userID, "account_id", accountID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Account deleted successfully",
		"code":    "SUCCESS",
	})
}