package api

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"pqc-authenticator/internal/api/handlers"
	"pqc-authenticator/internal/api/middleware"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"

	"github.com/gin-gonic/gin"
)

type Server struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
	keyMgr *crypto.KeyManager
	server *http.Server
}

func NewServer(db *sql.DB, logger utils.Logger, config *utils.Config) *Server {
	return &Server{
		db:     db,
		logger: logger,
		config: config,
		keyMgr: crypto.NewKeyManagerWithKey(db, config.Security.EncryptionKey),
	}
}

func (s *Server) Router() *gin.Engine {
	if s.config.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.Recovery(s.logger))
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS(s.config.CORS))
	r.Use(middleware.ValidateOrigin(s.config.CORS.AllowedOrigins))
	r.Use(middleware.RateLimit(s.config.Security.RateLimitRequests, s.config.Security.RateLimitWindow))
	r.Use(s.requestSizeLimit())
	r.Use(s.requestTimeout())

	r.TrustedPlatform = gin.PlatformCloudflare
	r.MaxMultipartMemory = 32 << 20

	userHandler := handlers.NewUserHandler(s.db, s.logger, s.config)
	deviceHandler := handlers.NewDeviceHandler(s.db, s.logger, s.config)
	accountHandler := handlers.NewAccountHandler(s.db, s.logger, s.config, s.keyMgr)
	totpHandler := handlers.NewTOTPHandler(&storage.Database{DB: s.db}, s.logger, s.config, s.keyMgr)
	businessHandler := handlers.NewBusinessHandler(s.db, s.logger, s.config)
	backupHandler := handlers.NewBackupHandler(s.db, s.logger, s.config)
	healthHandler := handlers.NewHealthHandler(s.db, s.logger)

	r.GET("/health", healthHandler.HealthCheck)
	r.GET("/readiness", healthHandler.ReadinessCheck)
	r.GET("/metrics", middleware.RequirePermission("metrics"), healthHandler.Metrics)

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		auth.Use(middleware.RateLimit(10, time.Minute))
		{
			auth.POST("/register", s.validateRegistration(), userHandler.Register)
			auth.POST("/login", s.validateLogin(), userHandler.Login)
			auth.POST("/logout", middleware.JWTAuth(s.config.Security.JWTSecret, &storage.Database{DB: s.db}), userHandler.Logout)
			auth.POST("/refresh", middleware.JWTAuth(s.config.Security.JWTSecret, &storage.Database{DB: s.db}), userHandler.RefreshToken)
		}

		protected := v1.Group("/")
		protected.Use(middleware.JWTAuth(s.config.Security.JWTSecret, &storage.Database{DB: s.db}))
		{
			users := protected.Group("/users")
			{
				users.GET("/profile", userHandler.GetProfile)
				users.PUT("/profile", s.validateProfileUpdate(), userHandler.UpdateProfile)
				users.DELETE("/profile", userHandler.DeleteAccount)
			}

			devices := protected.Group("/devices")
			{
				devices.POST("/register", s.validateDeviceRegistration(), deviceHandler.RegisterDevice)
				devices.GET("", deviceHandler.ListDevices)
				devices.DELETE("/:id", s.validateUUID("id"), deviceHandler.RemoveDevice)
				devices.PUT("/:id/activate", s.validateUUID("id"), deviceHandler.ActivateDevice)
				devices.PUT("/:id/deactivate", s.validateUUID("id"), deviceHandler.DeactivateDevice)
			}

			accounts := protected.Group("/accounts")
			{
				accounts.POST("", s.validateAccountCreation(), accountHandler.CreateAccount)
				accounts.GET("", accountHandler.ListAccounts)
				accounts.GET("/:id", s.validateUUID("id"), accountHandler.GetAccount)
				accounts.PUT("/:id", s.validateUUID("id"), accountHandler.UpdateAccount)
				accounts.DELETE("/:id", s.validateUUID("id"), accountHandler.DeleteAccount)
			}

			totp := protected.Group("/totp")
			{
				totp.POST("/generate", s.validateTOTPGeneration(), totpHandler.GenerateCode)
				totp.POST("/verify", s.validateTOTPVerification(), totpHandler.VerifyCode)
				totp.GET("/qr/:account_id", s.validateUUID("account_id"), totpHandler.GetQRCode)
				totp.POST("/rotate-keys", totpHandler.RotateKeys)
				totp.GET("/time-sync", totpHandler.TimeSync)
			}

			backup := protected.Group("/backup")
			{
				backup.POST("/create", s.validateBackupCreation(), backupHandler.CreateBackup)
				backup.POST("/restore", s.validateBackupRestore(), backupHandler.RestoreBackup)
				backup.GET("/download", backupHandler.DownloadBackup)
				backup.POST("/verify", s.validateBackupVerify(), backupHandler.VerifyBackup)
			}

			admin := protected.Group("/admin")
			admin.Use(middleware.RequirePermission("admin"))
			{
				admin.GET("/audit-logs", userHandler.GetAuditLogs)
				admin.GET("/sessions", userHandler.GetActiveSessions)
				admin.DELETE("/sessions/:id", s.validateUUID("id"), userHandler.RevokeSession)
			}
		}
	}

	business := r.Group("/api/business/v1")
	business.Use(middleware.BusinessAPIAuth(&storage.Database{DB: s.db}))
	business.Use(middleware.RateLimit(100, time.Minute))
	{
		business.POST("/register", s.validateBusinessRegistration(), businessHandler.RegisterBusiness)
		business.GET("/dashboard", businessHandler.GetDashboard)
		business.POST("/integration", s.validateIntegrationSetup(), businessHandler.SetupIntegration)
		business.POST("/verify", s.validateBusinessTOTP(), businessHandler.VerifyTOTP)
		business.POST("/provision", s.validateUserProvisioning(), businessHandler.ProvisionUser)
		business.DELETE("/provision/:user_id", s.validateUUID("user_id"), businessHandler.DeprovisionUser)
		business.GET("/analytics", businessHandler.GetAnalytics)
		business.POST("/webhook", s.validateWebhookConfig(), businessHandler.ConfigureWebhook)
		business.POST("/webhook/test", businessHandler.TestWebhook)
		business.GET("/users", businessHandler.ListUsers)
		business.PUT("/users/:user_id/activate", s.validateUUID("user_id"), businessHandler.ActivateUser)
		business.PUT("/users/:user_id/deactivate", s.validateUUID("user_id"), businessHandler.DeactivateUser)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, utils.NewErrorResponse(
			utils.NewAppError("NOT_FOUND", "Endpoint not found", 404),
			utils.GenerateTraceID()))
	})

	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, utils.NewErrorResponse(
			utils.NewAppError("METHOD_NOT_ALLOWED", "Method not allowed", 405),
			utils.GenerateTraceID()))
	})

	return r
}

func (s *Server) Start(ctx context.Context) error {
	router := s.Router()

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	s.server = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler:        router,
		ReadTimeout:    s.config.Server.ReadTimeout,
		WriteTimeout:   s.config.Server.WriteTimeout,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: s.config.Server.MaxHeaderBytes,
		TLSConfig:      tlsConfig,
	}

	s.logger.Info("Starting server",
		"host", s.config.Server.Host,
		"port", s.config.Server.Port,
		"mode", s.config.Server.Mode,
		"tls_enabled", s.config.Security.TLSCertFile != "",
	)

	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down server")
		
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Server shutdown error", "error", err)
		}
	}()

	var err error
	if s.config.Security.TLSCertFile != "" && s.config.Security.TLSKeyFile != "" {
		err = s.server.ListenAndServeTLS(s.config.Security.TLSCertFile, s.config.Security.TLSKeyFile)
	} else {
		s.logger.Warn("Running without TLS - not recommended for production")
		err = s.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server start failed: %w", err)
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	return s.server.Shutdown(ctx)
}

func (s *Server) requestSizeLimit() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		const maxRequestSize = 10 << 20
		
		if c.Request.ContentLength > maxRequestSize {
			c.JSON(http.StatusRequestEntityTooLarge, utils.NewErrorResponse(
				utils.NewAppError("REQUEST_TOO_LARGE", "Request body too large", 413),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestSize)
		c.Next()
	})
}

func (s *Server) requestTimeout() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
}

func (s *Server) validateProfileUpdate() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			Email string `json:"email,omitempty"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if req.Email != "" && !utils.IsValidEmail(req.Email) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateDeviceRegistration() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			DeviceName        string `json:"device_name"`
			DeviceFingerprint string `json:"device_fingerprint"`
			PublicKey         string `json:"public_key"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.DeviceName) == 0 || len(req.DeviceName) > 100 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_DEVICE_NAME", "Device name must be 1-100 characters", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.DeviceFingerprint) == 0 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("MISSING_FINGERPRINT", "Device fingerprint required", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !crypto.IsValidPublicKey(req.PublicKey) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_PUBLIC_KEY", "Invalid public key format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateAccountCreation() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			ServiceName string `json:"service_name"`
			ServiceURL  string `json:"service_url"`
			Issuer      string `json:"issuer"`
			Digits      int    `json:"digits,omitempty"`
			Period      int    `json:"period,omitempty"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.ValidateServiceName(req.ServiceName) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_SERVICE_NAME", "Invalid service name", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidURL(req.ServiceURL) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_SERVICE_URL", "Invalid service URL", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.ValidateIssuer(req.Issuer) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_ISSUER", "Invalid issuer", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if req.Digits != 0 && !utils.ValidateTOTPDigits(req.Digits) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_DIGITS", "TOTP digits must be 6-8", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if req.Period != 0 && !utils.ValidateTOTPPeriod(req.Period) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_PERIOD", "TOTP period must be 15-300 seconds", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateTOTPGeneration() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			AccountID string `json:"account_id"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !s.isValidUUID(req.AccountID) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_ACCOUNT_ID", "Invalid account ID format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateTOTPVerification() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			AccountID string `json:"account_id"`
			Code      string `json:"code"`
			Signature string `json:"signature,omitempty"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !s.isValidUUID(req.AccountID) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_ACCOUNT_ID", "Invalid account ID format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.Code) != 6 || !utils.IsNumeric(req.Code) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_CODE", "Code must be 6 digits", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateBackupCreation() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsStrongPassword(req.Password) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("WEAK_BACKUP_PASSWORD", "Backup password must be strong", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateBackupRestore() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			BackupData string `json:"backup_data"`
			Password   string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.BackupData) == 0 || len(req.Password) == 0 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("MISSING_BACKUP_DATA", "Backup data and password required", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateBackupVerify() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			BackupData string `json:"backup_data"`
			Password   string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.BackupData) == 0 || len(req.Password) == 0 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("MISSING_BACKUP_DATA", "Backup data and password required", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateBusinessRegistration() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			CompanyName  string `json:"company_name"`
			ContactEmail string `json:"contact_email"`
			Plan         string `json:"plan,omitempty"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.CompanyName) == 0 || len(req.CompanyName) > 100 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_COMPANY_NAME", "Company name must be 1-100 characters", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidEmail(req.ContactEmail) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateIntegrationSetup() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			IntegrationType string                 `json:"integration_type"`
			Settings        map[string]interface{} `json:"settings"`
			WebhookURL      string                 `json:"webhook_url,omitempty"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
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
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_INTEGRATION_TYPE", "Invalid integration type", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if req.WebhookURL != "" && !utils.IsValidURL(req.WebhookURL) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_WEBHOOK_URL", "Invalid webhook URL", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateBusinessTOTP() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			UserID string `json:"user_id"`
			Code   string `json:"code"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !s.isValidUUID(req.UserID) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_USER_ID", "Invalid user ID format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.Code) != 6 || !utils.IsNumeric(req.Code) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_CODE", "Code must be 6 digits", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateUserProvisioning() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			ExternalUserID string `json:"external_user_id"`
			Username       string `json:"username"`
			Email          string `json:"email"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.ExternalUserID) == 0 || len(req.ExternalUserID) > 100 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_EXTERNAL_USER_ID", "External user ID must be 1-100 characters", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidUsername(req.Username) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_USERNAME", "Invalid username format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidEmail(req.Email) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateWebhookConfig() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			WebhookURL string   `json:"webhook_url"`
			Events     []string `json:"events"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidURL(req.WebhookURL) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_WEBHOOK_URL", "Invalid webhook URL", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.Events) == 0 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("MISSING_EVENTS", "At least one event must be specified", 400),
				utils.GenerateTraceID()))
			c.Abort()
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
				c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
					utils.NewAppError("INVALID_EVENT", "Invalid webhook event: "+event, 400),
					utils.GenerateTraceID()))
				c.Abort()
				return
			}
		}
		
		c.Next()
	})
}

func (s *Server) validateUUID(param string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		value := c.Param(param)
		if !s.isValidUUID(value) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_"+strings.ToUpper(param), "Invalid "+param+" format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		c.Next()
	})
}

func (s *Server) isValidUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if char != '-' {
				return false
			}
		} else {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	
	return true
}

func (s *Server) validateRegistration() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidUsername(req.Username) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_USERNAME", "Invalid username format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsValidEmail(req.Email) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_EMAIL", "Invalid email format", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if !utils.IsStrongPassword(req.Password) {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("WEAK_PASSWORD", "Password does not meet security requirements", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}

func (s *Server) validateLogin() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidRequest, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(req.Username) == 0 || len(req.Password) == 0 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.ErrInvalidCredentials, utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	})
}