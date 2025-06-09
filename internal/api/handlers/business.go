package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pqc-authenticator/internal/auth"
	"pqc-authenticator/internal/business"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type BusinessHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewBusinessHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *BusinessHandler {
	return &BusinessHandler{
		db:     db,
		logger: logger,
		config: config,
	}
}

type RegisterBusinessRequest struct {
	CompanyName  string `json:"company_name" binding:"required,min=1,max=100"`
	ContactEmail string `json:"contact_email" binding:"required,email"`
	Plan         string `json:"plan,omitempty"`
}

type SetupIntegrationRequest struct {
	IntegrationType string                 `json:"integration_type" binding:"required"`
	Settings        map[string]interface{} `json:"settings" binding:"required"`
	WebhookURL      string                 `json:"webhook_url,omitempty"`
}

type VerifyBusinessTOTPRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required,len=6"`
}

type ProvisionUserRequest struct {
	ExternalUserID string `json:"external_user_id" binding:"required"`
	Username       string `json:"username" binding:"required"`
	Email          string `json:"email" binding:"required,email"`
}

type BusinessResponse struct {
	ID           string                 `json:"id"`
	CompanyName  string                 `json:"company_name"`
	ContactEmail string                 `json:"contact_email"`
	APIKey       string                 `json:"api_key"`
	Plan         string                 `json:"plan"`
	Settings     map[string]interface{} `json:"settings"`
	CreatedAt    time.Time              `json:"created_at"`
}

func (h *BusinessHandler) RegisterBusiness(c *gin.Context) {
	var req RegisterBusinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid business registration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsValidEmail(req.ContactEmail) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	plan := req.Plan
	if plan == "" {
		plan = "basic"
	}

	apiKey := utils.GenerateAPIKey()

	business := &storage.Business{
		ID:           uuid.New().String(),
		CompanyName:  req.CompanyName,
		ContactEmail: req.ContactEmail,
		APIKey:       apiKey,
		Plan:         plan,
		Settings:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
	}

	if err := storage.CreateBusiness(h.db, business); err != nil {
		h.logger.Error("Failed to register business", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register business"})
		return
	}

	if err := storage.LogAuditEvent(h.db, "", business.ID, "business_registered", map[string]interface{}{
		"company_name": business.CompanyName,
		"contact_email": business.ContactEmail,
		"plan":         business.Plan,
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Business registered", "business_id", business.ID, "company_name", business.CompanyName)

	c.JSON(http.StatusCreated, BusinessResponse{
		ID:           business.ID,
		CompanyName:  business.CompanyName,
		ContactEmail: business.ContactEmail,
		APIKey:       business.APIKey,
		Plan:         business.Plan,
		Settings:     business.Settings,
		CreatedAt:    business.CreatedAt,
	})
}

func (h *BusinessHandler) GetDashboard(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	analytics := business.NewAnalytics(h.db, h.logger)
	dashboardData, err := analytics.GetDashboardData(businessID)
	if err != nil {
		h.logger.Error("Failed to get dashboard data", "business_id", businessID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve dashboard data"})
		return
	}

	c.JSON(http.StatusOK, dashboardData)
}

func (h *BusinessHandler) SetupIntegration(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	var req SetupIntegrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid setup integration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	integration := business.NewIntegration(h.db, h.logger, h.config)
	integrationID, err := integration.Setup(businessID, req.IntegrationType, req.Settings, req.WebhookURL)
	if err != nil {
		h.logger.Error("Failed to setup integration", "business_id", businessID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to setup integration"})
		return
	}

	if err := storage.LogAuditEvent(h.db, "", businessID, "integration_setup", map[string]interface{}{
		"integration_id":   integrationID,
		"integration_type": req.IntegrationType,
		"ip_address":       c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Integration setup", "business_id", businessID, "integration_id", integrationID)

	c.JSON(http.StatusCreated, gin.H{
		"integration_id": integrationID,
		"message":        "Integration setup successfully",
	})
}

func (h *BusinessHandler) VerifyTOTP(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	var req VerifyBusinessTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid verify TOTP request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsNumeric(req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code must be numeric"})
		return
	}

	businessUser, err := storage.GetBusinessUser(h.db, businessID, req.UserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !businessUser.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "User account is inactive"})
		return
	}

	accounts, err := storage.GetUserAccounts(h.db, req.UserID)
	if err != nil || len(accounts) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No accounts found for user"})
		return
	}

	isValid := false
	for _, account := range accounts {
		secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
		if err != nil {
			continue
		}

		pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period)
		valid, err := pqtotp.VerifyCode(req.Code, time.Now())
		if err == nil && valid {
			isValid = true
			break
		}
	}

	result := "failed"
	if isValid {
		result = "success"
	}

	if err := storage.LogAuditEvent(h.db, req.UserID, businessID, "business_totp_verified", map[string]interface{}{
		"result":     result,
		"timestamp":  time.Now().Unix(),
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	if isValid {
		h.logger.Info("Business TOTP verification successful", "business_id", businessID, "user_id", req.UserID)
	} else {
		h.logger.Warn("Business TOTP verification failed", "business_id", businessID, "user_id", req.UserID)
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   isValid,
		"user_id": req.UserID,
		"verified_at": time.Now().Unix(),
	})
}

func (h *BusinessHandler) ProvisionUser(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	var req ProvisionUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid provision user request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	user, err := storage.GetUserByUsername(h.db, req.Username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	existingBusinessUser, _ := storage.GetBusinessUser(h.db, businessID, user.ID)
	if existingBusinessUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already provisioned"})
		return
	}

	businessUser := &storage.BusinessUser{
		ID:             uuid.New().String(),
		BusinessID:     businessID,
		UserID:         user.ID,
		ExternalUserID: req.ExternalUserID,
		IsActive:       true,
		CreatedAt:      time.Now(),
	}

	if err := storage.CreateBusinessUser(h.db, businessUser); err != nil {
		h.logger.Error("Failed to provision user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to provision user"})
		return
	}

	if err := storage.LogAuditEvent(h.db, user.ID, businessID, "user_provisioned", map[string]interface{}{
		"external_user_id": req.ExternalUserID,
		"username":         req.Username,
		"ip_address":       c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User provisioned", "business_id", businessID, "user_id", user.ID)

	c.JSON(http.StatusCreated, gin.H{
		"user_id":          user.ID,
		"external_user_id": req.ExternalUserID,
		"message":          "User provisioned successfully",
	})
}

func (h *BusinessHandler) GetAnalytics(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	days := 30
	if d := c.Query("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	analytics := business.NewAnalytics(h.db, h.logger)
	data, err := analytics.GetAnalytics(businessID, days)
	if err != nil {
		h.logger.Error("Failed to get analytics", "business_id", businessID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve analytics"})
		return
	}

	c.JSON(http.StatusOK, data)
}

func (h *BusinessHandler) ConfigureWebhook(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Business authentication required"})
		return
	}

	var req struct {
		WebhookURL string   `json:"webhook_url" binding:"required,url"`
		Events     []string `json:"events" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid webhook configuration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	webhook := business.NewWebhook(h.db, h.logger, h.config)
	if err := webhook.Configure(businessID, req.WebhookURL, req.Events); err != nil {
		h.logger.Error("Failed to configure webhook", "business_id", businessID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to configure webhook"})
		return
	}

	if err := storage.LogAuditEvent(h.db, "", businessID, "webhook_configured", map[string]interface{}{
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Webhook configured", "business_id", businessID, "webhook_url", req.WebhookURL)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Webhook configured successfully",
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
	})
}