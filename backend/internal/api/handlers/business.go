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

type BusinessUserResponse struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	ExternalUserID string    `json:"external_user_id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivity   time.Time `json:"last_activity,omitempty"`
}

func (h *BusinessHandler) RegisterBusiness(c *gin.Context) {
	var req RegisterBusinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid business registration request", "error", err)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	if !utils.IsValidEmail(req.ContactEmail) {
		h.respondWithError(c, utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400))
		return
	}

	plan := req.Plan
	if plan == "" {
		plan = "basic"
	}

	if plan != "basic" && plan != "pro" && plan != "enterprise" {
		h.respondWithError(c, utils.NewAppError("INVALID_PLAN", "Invalid plan type", 400))
		return
	}

	apiKey, err := utils.GenerateAPIKey()
	if err != nil {
		h.logger.Error("Failed to generate API key", "error", err)
		h.respondWithError(c, utils.NewAppError("API_KEY_GENERATION_FAILED", "Failed to register business", 500))
		return
	}

	business := &storage.Business{
		ID:           uuid.New().String(),
		CompanyName:  utils.SanitizeUserInput(req.CompanyName),
		ContactEmail: req.ContactEmail,
		APIKey:       apiKey,
		Plan:         plan,
		Settings:     make(map[string]interface{}),
		CreatedAt:    time.Now(),
	}

	if err := storage.CreateBusiness(h.db, business); err != nil {
		h.logger.Error("Failed to register business", "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}

	if err := storage.LogAuditEvent(h.db, "", business.ID, "business_registered", map[string]interface{}{
		"company_name":  business.CompanyName,
		"contact_email": business.ContactEmail,
		"plan":          business.Plan,
		"ip_address":    c.ClientIP(),
		"user_agent":    c.GetHeader("User-Agent"),
		"result":        "success",
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
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	analytics := business.NewAnalytics(h.db, h.logger)
	dashboardData, err := analytics.GetDashboardData(businessID)
	if err != nil {
		h.logger.Error("Failed to get dashboard data", "business_id", businessID, "error", err)
		h.respondWithError(c, utils.NewAppError("DASHBOARD_ERROR", "Failed to retrieve dashboard data", 500))
		return
	}

	c.JSON(http.StatusOK, dashboardData)
}

func (h *BusinessHandler) SetupIntegration(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req SetupIntegrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid setup integration request", "error", err)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	validTypes := []string{"api", "saml", "oidc", "webhook"}
	isValid := false
	for _, validType := range validTypes {
		if req.IntegrationType == validType {
			isValid = true
			break
		}
	}
	
	if !isValid {
		h.respondWithError(c, utils.NewAppError("INVALID_INTEGRATION_TYPE", "Invalid integration type", 400))
		return
	}

	integration := business.NewIntegration(h.db, h.logger, h.config)
	integrationID, err := integration.Setup(businessID, req.IntegrationType, req.Settings, req.WebhookURL)
	if err != nil {
		h.logger.Error("Failed to setup integration", "business_id", businessID, "error", err)
		h.respondWithError(c, utils.NewAppError("INTEGRATION_SETUP_FAILED", "Failed to setup integration", 500))
		return
	}

	if err := storage.LogAuditEvent(h.db, "", businessID, "integration_setup", map[string]interface{}{
		"integration_id":   integrationID,
		"integration_type": req.IntegrationType,
		"ip_address":       c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
		"result":           "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Integration setup", "business_id", businessID, "integration_id", integrationID)

	c.JSON(http.StatusCreated, gin.H{
		"integration_id": integrationID,
		"message":        "Integration setup successfully",
		"code":           "SUCCESS",
	})
}

func (h *BusinessHandler) VerifyTOTP(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req VerifyBusinessTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid verify TOTP request", "error", err)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	if !utils.IsNumeric(req.Code) {
		h.respondWithError(c, utils.NewAppError("INVALID_CODE_FORMAT", "Code must be numeric", 400))
		return
	}

	businessUser, err := storage.GetBusinessUser(h.db, businessID, req.UserID)
	if err != nil {
		h.logger.Error("Failed to get business user", "business_id", businessID, "user_id", req.UserID, "error", err)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if !businessUser.IsActive {
		h.respondWithError(c, utils.NewAppError("USER_INACTIVE", "User account is inactive", 403))
		return
	}

	accounts, err := storage.GetUserAccounts(h.db, req.UserID)
	if err != nil || len(accounts) == 0 {
		h.logger.Error("Failed to get user accounts", "user_id", req.UserID, "error", err)
		h.respondWithError(c, utils.NewAppError("NO_ACCOUNTS", "No accounts found for user", 404))
		return
	}

	keyMgr := crypto.NewKeyManager(h.db)
	isValid := false
	var validAccount *storage.Account
	
	for _, account := range accounts {
		secretKey, err := crypto.DecryptData(account.SecretKey, h.config.Security.EncryptionKey)
		if err != nil {
			h.logger.Error("Failed to decrypt secret key", "account_id", account.ID, "error", err)
			continue
		}

		pqtotp := auth.NewPQTOTP(secretKey, account.Digits, account.Period, keyMgr, req.UserID)
		valid, err := pqtotp.VerifyCode(req.Code, time.Now())
		crypto.SecureZeroMemory(secretKey)
		
		if err == nil && valid {
			isValid = true
			validAccount = account
			break
		}
	}

	result := "failed"
	if isValid {
		result = "success"
	}

	auditDetails := map[string]interface{}{
		"result":     result,
		"timestamp":  time.Now().Unix(),
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
	}
	
	if validAccount != nil {
		auditDetails["account_id"] = validAccount.ID
		auditDetails["service_name"] = validAccount.ServiceName
	}

	if err := storage.LogAuditEvent(h.db, req.UserID, businessID, "business_totp_verified", auditDetails); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	if isValid {
		h.logger.Info("Business TOTP verification successful", "business_id", businessID, "user_id", req.UserID)
	} else {
		h.logger.Warn("Business TOTP verification failed", "business_id", businessID, "user_id", req.UserID)
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":       isValid,
		"user_id":     req.UserID,
		"verified_at": time.Now().Unix(),
	})
}

func (h *BusinessHandler) ProvisionUser(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req ProvisionUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid provision user request", "error", err)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	if !utils.IsValidEmail(req.Email) {
		h.respondWithError(c, utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400))
		return
	}

	if !utils.IsValidUsername(req.Username) {
		h.respondWithError(c, utils.NewAppError("INVALID_USERNAME", "Invalid username format", 400))
		return
	}

	user, err := storage.GetUserByUsername(h.db, req.Username)
	if err != nil {
		h.logger.Error("Failed to get user", "username", req.Username, "error", err)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	existingBusinessUser, _ := storage.GetBusinessUser(h.db, businessID, user.ID)
	if existingBusinessUser != nil {
		h.respondWithError(c, utils.NewAppError("USER_ALREADY_PROVISIONED", "User already provisioned", 409))
		return
	}

	businessUser := &storage.BusinessUser{
		ID:             uuid.New().String(),
		BusinessID:     businessID,
		UserID:         user.ID,
		ExternalUserID: utils.SanitizeUserInput(req.ExternalUserID),
		IsActive:       true,
		CreatedAt:      time.Now(),
	}

	if err := storage.CreateBusinessUser(h.db, businessUser); err != nil {
		h.logger.Error("Failed to provision user", "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}

	if err := storage.LogAuditEvent(h.db, user.ID, businessID, "user_provisioned", map[string]interface{}{
		"external_user_id": req.ExternalUserID,
		"username":         req.Username,
		"ip_address":       c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
		"result":           "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User provisioned", "business_id", businessID, "user_id", user.ID)

	c.JSON(http.StatusCreated, gin.H{
		"user_id":          user.ID,
		"external_user_id": req.ExternalUserID,
		"message":          "User provisioned successfully",
		"code":             "SUCCESS",
	})
}

func (h *BusinessHandler) DeprovisionUser(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	userID := c.Param("user_id")
	if userID == "" {
		h.respondWithError(c, utils.NewAppError("MISSING_USER_ID", "User ID required", 400))
		return
	}

	businessUser, err := storage.GetBusinessUser(h.db, businessID, userID)
	if err != nil {
		h.logger.Error("Failed to get business user", "business_id", businessID, "user_id", userID, "error", err)
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	query := `UPDATE business_users SET is_active = false WHERE business_id = ? AND user_id = ?`
	if _, err := h.db.Exec(query, businessID, userID); err != nil {
		h.logger.Error("Failed to deprovision user", "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, businessID, "user_deprovisioned", map[string]interface{}{
		"external_user_id": businessUser.ExternalUserID,
		"ip_address":       c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
		"result":           "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User deprovisioned", "business_id", businessID, "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "User deprovisioned successfully",
		"code":    "SUCCESS",
	})
}

func (h *BusinessHandler) GetAnalytics(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
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
		h.respondWithError(c, utils.NewAppError("ANALYTICS_ERROR", "Failed to retrieve analytics", 500))
		return
	}

	c.JSON(http.StatusOK, data)
}

func (h *BusinessHandler) ConfigureWebhook(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	var req struct {
		WebhookURL string   `json:"webhook_url" binding:"required,url"`
		Events     []string `json:"events" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid webhook configuration request", "error", err)
		h.respondWithError(c, utils.ErrInvalidRequest)
		return
	}

	validEvents := []string{"user_provisioned", "user_deprovisioned", "totp_verified", "key_rotated"}
	for _, event := range req.Events {
		isValid := false
		for _, validEvent := range validEvents {
			if event == validEvent {
				isValid = true
				break
			}
		}
		if !isValid {
			h.respondWithError(c, utils.NewAppError("INVALID_EVENT", "Invalid webhook event: "+event, 400))
			return
		}
	}

	webhook := business.NewWebhook(h.db, h.logger, h.config)
	if err := webhook.Configure(businessID, req.WebhookURL, req.Events); err != nil {
		h.logger.Error("Failed to configure webhook", "business_id", businessID, "error", err)
		h.respondWithError(c, utils.NewAppError("WEBHOOK_CONFIG_FAILED", "Failed to configure webhook", 500))
		return
	}

	if err := storage.LogAuditEvent(h.db, "", businessID, "webhook_configured", map[string]interface{}{
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
		"result":      "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Webhook configured", "business_id", businessID, "webhook_url", req.WebhookURL)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Webhook configured successfully",
		"webhook_url": req.WebhookURL,
		"events":      req.Events,
		"code":        "SUCCESS",
	})
}

func (h *BusinessHandler) TestWebhook(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	webhook := business.NewWebhook(h.db, h.logger, h.config)
	err := webhook.SendEvent(businessID, "webhook_test", map[string]interface{}{
		"message":   "This is a webhook test",
		"timestamp": time.Now().Unix(),
		"test_id":   uuid.New().String(),
	})

	if err != nil {
		h.logger.Error("Failed to send test webhook", "business_id", businessID, "error", err)
		h.respondWithError(c, utils.NewAppError("WEBHOOK_TEST_FAILED", "Failed to send test webhook", 500))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Test webhook sent successfully",
		"code":    "SUCCESS",
	})
}

func (h *BusinessHandler) ListUsers(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	limit := 50
	offset := 0

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	query := `
		SELECT bu.id, bu.user_id, bu.external_user_id, bu.is_active, bu.created_at,
		       u.username, u.email
		FROM business_users bu
		JOIN users u ON bu.user_id = u.id
		WHERE bu.business_id = ?
		ORDER BY bu.created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := h.db.Query(query, businessID, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list business users", "business_id", businessID, "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}
	defer rows.Close()

	var users []BusinessUserResponse
	for rows.Next() {
		var user BusinessUserResponse
		var username, email string
		
		err := rows.Scan(&user.ID, &user.UserID, &user.ExternalUserID, &user.IsActive, 
			&user.CreatedAt, &username, &email)
		if err != nil {
			h.logger.Error("Failed to scan user row", "error", err)
			continue
		}
		
		user.Username = username
		user.Email = email
		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"users":  users,
		"total":  len(users),
		"limit":  limit,
		"offset": offset,
	})
}

func (h *BusinessHandler) ActivateUser(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	userID := c.Param("user_id")
	if userID == "" {
		h.respondWithError(c, utils.NewAppError("MISSING_USER_ID", "User ID required", 400))
		return
	}

	query := `UPDATE business_users SET is_active = true WHERE business_id = ? AND user_id = ?`
	result, err := h.db.Exec(query, businessID, userID)
	if err != nil {
		h.logger.Error("Failed to activate user", "business_id", businessID, "user_id", userID, "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, businessID, "user_activated", map[string]interface{}{
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User activated", "business_id", businessID, "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "User activated successfully",
		"code":    "SUCCESS",
	})
}

func (h *BusinessHandler) DeactivateUser(c *gin.Context) {
	businessID := c.GetString("business_id")
	if businessID == "" {
		h.respondWithError(c, utils.ErrUnauthorized)
		return
	}

	userID := c.Param("user_id")
	if userID == "" {
		h.respondWithError(c, utils.NewAppError("MISSING_USER_ID", "User ID required", 400))
		return
	}

	query := `UPDATE business_users SET is_active = false WHERE business_id = ? AND user_id = ?`
	result, err := h.db.Exec(query, businessID, userID)
	if err != nil {
		h.logger.Error("Failed to deactivate user", "business_id", businessID, "user_id", userID, "error", err)
		h.respondWithError(c, utils.ErrDatabaseError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.respondWithError(c, utils.ErrNotFound)
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, businessID, "user_deactivated", map[string]interface{}{
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User deactivated", "business_id", businessID, "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "User deactivated successfully",
		"code":    "SUCCESS",
	})
}

func (h *BusinessHandler) respondWithError(c *gin.Context, err *utils.AppError) {
	traceID := c.GetHeader("X-Trace-ID")
	if traceID == "" {
		traceID = utils.GenerateTraceID()
	}
	
	sanitizedErr := utils.SanitizeError(err)
	response := utils.NewErrorResponse(sanitizedErr, traceID)
	
	c.JSON(sanitizedErr.HTTPCode, response)
}