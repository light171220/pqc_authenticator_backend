package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Import SQLite driver explicitly - this MUST be first
	_ "github.com/mattn/go-sqlite3"

	"pqc-authenticator/internal/api"
	"pqc-authenticator/internal/auth"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger := utils.NewLogger(config.Logging.Level, config.Logging.Format, config.Logging.Output)

	logger.Info("Starting PQC Authenticator", 
		"version", version, 
		"build_time", buildTime,
		"mode", config.Server.Mode)

	dbConfig := &storage.Config{
		Type:           config.Database.Type,
		Path:           config.Database.Path,
		MaxConnections: config.Database.MaxConnections,
		MaxRetries:     config.Database.MaxRetries,
		RetryDelay:     config.Database.RetryDelay,
	}

	db, err := storage.DB(dbConfig)
	if err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database", "error", err)
		}
	}()

	logger.Info("Database connected successfully")

	if err := storage.RunMigrations(db.DB); err != nil {
		logger.Fatal("Failed to run migrations", "error", err)
	}

	logger.Info("Database migrations completed")

	keyRotator := auth.NewKeyRotator(db.DB, logger)
	rotatorCtx, rotatorCancel := context.WithCancel(context.Background())
	defer rotatorCancel()

	go func() {
		keyRotator.Start(rotatorCtx, config.TOTP.KeyRotationInterval)
	}()

	logger.Info("Key rotator started")

	server := api.NewServer(db.DB, logger, config)

	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	go func() {
		if err := server.Start(serverCtx); err != nil {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	logger.Info("Server started successfully", 
		"host", config.Server.Host, 
		"port", config.Server.Port)

	<-quit

	logger.Info("Received shutdown signal, shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	keyRotator.Stop()
	logger.Info("Key rotator stopped")

	serverCancel()

	if err := server.Stop(shutdownCtx); err != nil {
		logger.Error("Error during server shutdown", "error", err)
	} else {
		logger.Info("Server shutdown completed")
	}

	logger.Info("Application exited cleanly")
}