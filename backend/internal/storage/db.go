package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	*sql.DB
	maxRetries int
	retryDelay time.Duration
}

type Config struct {
	Type           string
	Path           string
	URL            string
	MaxConnections int
	MaxRetries     int
	RetryDelay     time.Duration
}

func DB(config *Config) (*Database, error) {
	if config.MaxConnections <= 0 {
		config.MaxConnections = 25
	}

	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	if config.RetryDelay <= 0 {
		config.RetryDelay = 5 * time.Second
	}

	var connectionString string
	var driverName string

	if config.URL != "" {
		connectionString = config.URL
		if strings.Contains(connectionString, "postgres://") {
			config.Type = "postgres"
			driverName = "postgres"
		} else {
			config.Type = "sqlite3"
			driverName = "sqlite3"
		}
	} else {
		switch config.Type {
		case "postgres":
			if config.URL == "" {
				return nil, fmt.Errorf("postgres URL is required")
			}
			connectionString = config.URL
			driverName = "postgres"
		case "sqlite", "sqlite3":
			if config.Path == "" {
				config.Path = "./data/authenticator.db"
			}
			dir := filepath.Dir(config.Path)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create database directory: %w", err)
			}
			connectionString = fmt.Sprintf("%s?_foreign_keys=1&_journal_mode=WAL&_synchronous=NORMAL&_timeout=5000&_busy_timeout=5000", config.Path)
			driverName = "sqlite3"
		default:
			return nil, fmt.Errorf("unsupported database type: %s", config.Type)
		}
	}

	db, err := openWithRetry(driverName, connectionString, config)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(config.MaxConnections)
	db.SetMaxIdleConns(config.MaxConnections / 2)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{
		DB:         db,
		maxRetries: config.MaxRetries,
		retryDelay: config.RetryDelay,
	}, nil
}

func openWithRetry(driverName, connectionString string, config *Config) (*sql.DB, error) {
	var db *sql.DB
	var err error
	
	for i := 0; i < config.MaxRetries; i++ {
		db, err = sql.Open(driverName, connectionString)
		if err == nil {
			if err = db.Ping(); err == nil {
				break
			}
		}
		
		if i < config.MaxRetries-1 {
			time.Sleep(config.RetryDelay)
		}
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to open database after %d retries: %w", config.MaxRetries, err)
	}
	
	return db, nil
}

func (db *Database) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return db.PingContext(ctx)
}

func (db *Database) Stats() sql.DBStats {
	return db.DB.Stats()
}

func (db *Database) ExecWithRetry(query string, args ...interface{}) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var result sql.Result
	var err error
	
	for i := 0; i < db.maxRetries; i++ {
		result, err = db.ExecContext(ctx, query, args...)
		if err == nil {
			return result, nil
		}
		
		if !isRetryableError(err) || ctx.Err() != nil {
			break
		}
		
		if i < db.maxRetries-1 {
			select {
			case <-time.After(db.retryDelay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	return result, fmt.Errorf("operation failed after %d retries", db.maxRetries)
}

func (db *Database) QueryWithRetry(query string, args ...interface{}) (*sql.Rows, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rows *sql.Rows
	var err error
	
	for i := 0; i < db.maxRetries; i++ {
		rows, err = db.QueryContext(ctx, query, args...)
		if err == nil {
			return rows, nil
		}
		
		if !isRetryableError(err) || ctx.Err() != nil {
			break
		}
		
		if i < db.maxRetries-1 {
			select {
			case <-time.After(db.retryDelay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	return rows, fmt.Errorf("operation failed after %d retries", db.maxRetries)
}

func (db *Database) QueryRowWithRetry(query string, args ...interface{}) *sql.Row {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	return db.QueryRowContext(ctx, query, args...)
}

func (db *Database) BeginTx() (*sql.Tx, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return db.DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "database is locked") ||
		   strings.Contains(errStr, "database is busy") ||
		   strings.Contains(errStr, "connection reset") ||
		   strings.Contains(errStr, "broken pipe") ||
		   strings.Contains(errStr, "connection refused") ||
		   strings.Contains(errStr, "timeout")
}