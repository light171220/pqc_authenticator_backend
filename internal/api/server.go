package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/api/handlers"
	"pqc-authenticator/internal/api/middleware"
	"pqc-authenticator/internal/utils"
)

type Server struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewServer(db *sql.DB, logger utils.Logger, config *utils.Config) *Server {
	return &Server{
		db:     db,
		logger: logger,
		config: config,
	}
}

func (s *Server) Router() *gin.Engine {
	if s.config.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.Recovery(s.logger))
	r.Use(middleware.CORS())
	r.Use(middleware.RateLimit(s.config.Security.RateLimitRequests, s.config.Security.RateLimitWindow))

	userHandler := handlers.NewUserHandler(s.db, s.logger, s.config)
	deviceHandler := handlers.NewDeviceHandler(s.db, s.logger, s.config)
	accountHandler := handlers.NewAccountHandler(s.db, s.logger, s.config)
	totpHandler := handlers.NewTOTPHandler(s.db, s.logger, s.config)
	businessHandler := handlers.NewBusinessHandler(s.db, s.logger, s.config)
	backupHandler := handlers.NewBackupHandler(s.db, s.logger, s.config)
	healthHandler := handlers.NewHealthHandler(s.db, s.logger)

	r.GET("/health", healthHandler.HealthCheck)

	v1 := r.Group("/api/v1")
	{
		users := v1.Group("/users")
		{
			users.POST("/register", userHandler.Register)
			users.POST("/login", userHandler.Login)
			users.GET("/profile", userHandler.GetProfile)
			users.PUT("/profile", userHandler.UpdateProfile)
		}

		devices := v1.Group("/devices")
		{
			devices.POST("/register", deviceHandler.RegisterDevice)
			devices.GET("", deviceHandler.ListDevices)
			devices.DELETE("/:id", deviceHandler.RemoveDevice)
		}

		accounts := v1.Group("/accounts")
		{
			accounts.POST("", accountHandler.CreateAccount)
			accounts.GET("", accountHandler.ListAccounts)
			accounts.GET("/:id", accountHandler.GetAccount)
			accounts.PUT("/:id", accountHandler.UpdateAccount)
			accounts.DELETE("/:id", accountHandler.DeleteAccount)
		}

		totp := v1.Group("/totp")
		{
			totp.POST("/generate", totpHandler.GenerateCode)
			totp.POST("/verify", totpHandler.VerifyCode)
			totp.GET("/qr/:account_id", totpHandler.GetQRCode)
			totp.POST("/rotate-keys", totpHandler.RotateKeys)
		}

		backup := v1.Group("/backup")
		{
			backup.POST("/create", backupHandler.CreateBackup)
			backup.POST("/restore", backupHandler.RestoreBackup)
			backup.GET("/download", backupHandler.DownloadBackup)
		}
	}

	business := r.Group("/api/business/v1")
	{
		business.POST("/register", businessHandler.RegisterBusiness)
		business.GET("/dashboard", businessHandler.GetDashboard)
		business.POST("/integration", businessHandler.SetupIntegration)
		business.POST("/verify", businessHandler.VerifyTOTP)
		business.POST("/provision", businessHandler.ProvisionUser)
		business.GET("/analytics", businessHandler.GetAnalytics)
		business.POST("/webhook", businessHandler.ConfigureWebhook)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "endpoint not found",
		})
	})

	return r
}