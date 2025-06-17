package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	// Import SQLite driver explicitly - this MUST be first
	_ "github.com/mattn/go-sqlite3"

	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

func main() {
	config, err := utils.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("Running database migrations...\n")
	fmt.Printf("Database path: %s\n", config.Database.Path)

	// Create database directory if it doesn't exist
	dbDir := filepath.Dir(config.Database.Path)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}

	dbConfig := &storage.Config{
		Type:           config.Database.Type,
		Path:           config.Database.Path,
		MaxConnections: config.Database.MaxConnections,
		MaxRetries:     config.Database.MaxRetries,
		RetryDelay:     config.Database.RetryDelay,
	}

	db, err := storage.DB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Failed to close database: %v", err)
		}
	}()

	fmt.Println("Database connected successfully")

	// Get migration status before running
	migrationStatus, err := storage.GetMigrationStatus(db.DB)
	if err != nil {
		log.Printf("Warning: Could not get migration status: %v", err)
	} else {
		fmt.Printf("Current migrations applied: %d\n", len(migrationStatus))
		for _, migration := range migrationStatus {
			fmt.Printf("  Migration %d applied at %s (took %dms)\n", 
				migration.Version, 
				migration.AppliedAt.Format("2006-01-02 15:04:05"), 
				migration.ExecutionTimeMs)
		}
	}

	// Run migrations
	if err := storage.RunMigrations(db.DB); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Get updated migration status
	newMigrationStatus, err := storage.GetMigrationStatus(db.DB)
	if err != nil {
		log.Printf("Warning: Could not get updated migration status: %v", err)
	} else {
		fmt.Printf("Total migrations now applied: %d\n", len(newMigrationStatus))
	}

	fmt.Println("Database migrations completed successfully")

	// Optional verification
	if len(os.Args) > 1 && os.Args[1] == "--verify" {
		fmt.Println("Verifying database schema...")
		
		if err := db.Health(); err != nil {
			log.Fatalf("Database health check failed: %v", err)
		}
		
		fmt.Println("Database verification completed successfully")
	}
}