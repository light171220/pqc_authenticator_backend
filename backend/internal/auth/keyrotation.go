package auth

import (
	"context"
	"database/sql"
	"time"

	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type KeyRotator struct {
	db      *sql.DB
	logger  utils.Logger
	keyMgr  *crypto.KeyManager
	stopCh  chan struct{}
	running bool
}

func NewKeyRotator(db *sql.DB, logger utils.Logger) *KeyRotator {
	return &KeyRotator{
		db:     db,
		logger: logger,
		keyMgr: crypto.NewKeyManager(db),
		stopCh: make(chan struct{}),
	}
}

func (kr *KeyRotator) Start(ctx context.Context, interval time.Duration) {
	if kr.running {
		kr.logger.Warn("Key rotator already running")
		return
	}

	kr.running = true
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	kr.logger.Info("Key rotator started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			kr.logger.Info("Key rotator stopped due to context cancellation")
			kr.running = false
			return
		case <-kr.stopCh:
			kr.logger.Info("Key rotator stopped")
			kr.running = false
			return
		case <-ticker.C:
			kr.logger.Info("Starting scheduled key rotation")
			if err := kr.RotateExpiredKeys(); err != nil {
				kr.logger.Error("Failed to rotate expired keys", "error", err)
			}
			if err := kr.CleanupOldKeys(); err != nil {
				kr.logger.Error("Failed to cleanup old keys", "error", err)
			}
		}
	}
}

func (kr *KeyRotator) Stop() {
	if !kr.running {
		return
	}
	close(kr.stopCh)
}

func (kr *KeyRotator) RotateExpiredKeys() error {
	rows, err := kr.db.Query(`
		SELECT DISTINCT user_id 
		FROM user_keypairs 
		WHERE is_active = true 
		AND (expires_at IS NOT NULL AND expires_at < ? OR created_at < ?)`,
		time.Now(), time.Now().Add(-24*time.Hour*30))
	if err != nil {
		return err
	}
	defer rows.Close()

	var rotatedCount int
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			kr.logger.Error("Failed to scan user ID", "error", err)
			continue
		}

		if err := kr.RotateUserKeys(userID); err != nil {
			kr.logger.Error("Failed to rotate keys for user", "user_id", userID, "error", err)
			continue
		}
		rotatedCount++
	}

	kr.logger.Info("Key rotation completed", "rotated_users", rotatedCount)
	return nil
}

func (kr *KeyRotator) RotateUserKeys(userID string) error {
	if err := kr.keyMgr.RotateUserKeys(userID); err != nil {
		return err
	}

	if err := storage.LogAuditEvent(kr.db, userID, "", "user_keys_rotated", map[string]interface{}{
		"timestamp":    time.Now().Unix(),
		"rotation_type": "scheduled",
	}); err != nil {
		kr.logger.Warn("Failed to log key rotation audit event", "error", err)
	}

	kr.logger.Info("User keys rotated", "user_id", userID)
	return nil
}

func (kr *KeyRotator) ForceRotateUserKeys(userID string) error {
	if err := kr.keyMgr.RotateUserKeys(userID); err != nil {
		return err
	}

	if err := storage.LogAuditEvent(kr.db, userID, "", "user_keys_rotated", map[string]interface{}{
		"timestamp":    time.Now().Unix(),
		"rotation_type": "forced",
	}); err != nil {
		kr.logger.Warn("Failed to log key rotation audit event", "error", err)
	}

	kr.logger.Info("User keys force rotated", "user_id", userID)
	return nil
}

func (kr *KeyRotator) CleanupOldKeys() error {
	result, err := kr.db.Exec(`
		DELETE FROM user_keypairs 
		WHERE is_active = false 
		AND created_at < ?`,
		time.Now().Add(-48*time.Hour))
	if err != nil {
		return err
	}

	deletedCount, _ := result.RowsAffected()
	if deletedCount > 0 {
		kr.logger.Info("Old keys cleaned up", "deleted_count", deletedCount)
	}

	return kr.keyMgr.CleanupExpiredKeys()
}

func (kr *KeyRotator) GetKeyAge(userID string) (time.Duration, error) {
	keypair, err := kr.keyMgr.GetActiveKeyPair(userID)
	if err != nil {
		return 0, err
	}

	return time.Since(keypair.CreatedAt), nil
}