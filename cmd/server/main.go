package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pqc-authenticator/internal/api"
	"pqc-authenticator/internal/auth"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

func main() {
	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger := utils.NewLogger(config.Logging.Level, config.Logging.Format)

	db, err := storage.NewSQLiteDB(config.Database.Path)
	if err != nil {
		logger.Fatal("Failed to initialize database", "error", err)
	}
	defer db.Close()

	if err := storage.RunMigrations(db); err != nil {
		logger.Fatal("Failed to run migrations", "error", err)
	}

	keyRotator := auth.NewKeyRotator(db, logger)
	go keyRotator.Start(context.Background(), config.TOTP.KeyRotationInterval)

	server := api.NewServer(db, logger, config)
	
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port),
		Handler:      server.Router(),
		ReadTimeout:  config.Server.ReadTimeout,
		WriteTimeout: config.Server.WriteTimeout,
	}

	go func() {
		logger.Info("Starting server", "address", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keyRotator.Stop()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exited")
}