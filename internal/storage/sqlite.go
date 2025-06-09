package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func NewSQLiteDB(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if dir != "." {
		// Directory creation should be handled by the caller
	}

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)

	return db, nil
}

func CloseDB(db *sql.DB) error {
	return db.Close()
}