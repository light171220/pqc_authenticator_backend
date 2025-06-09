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
	db     *sql.DB
	logger utils.Logger
	stopCh chan struct{}
}

func NewKeyRotator(db *sql.DB, logger utils.Logger) *KeyRotator {
	return &KeyRotator{
		db:     db,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

func (kr *KeyRotator) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	kr.logger.Info("Key rotator started", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			kr.logger.Info("Key rotator stopped due to context cancellation")
			return
		case <-kr.stopCh:
			kr.logger.Info("Key rotator stopped")
			return
		case <-ticker.C:
			kr.logger.Info("Starting scheduled key rotation")
			if err := kr.RotateAllKeys(); err != nil {
				kr.logger.Error("Failed to rotate keys", "error", err)
			}
		}
	}
}

func (kr *KeyRotator) Stop() {
	close(kr.stopCh)
}

func (kr *KeyRotator) RotateAllKeys() error {
	users, err := storage.GetAllUsers(kr.db)
	if err != nil {
		return err
	}

	for _, user := range users {
		if err := kr.RotateUserKeys(user.ID); err != nil {
			kr.logger.Error("Failed to rotate keys for user", "user_id", user.ID, "error", err)
			continue
		}
	}

	if err := kr.CleanupOldKeys(); err != nil {
		kr.logger.Error("Failed to cleanup old keys", "error", err)
	}

	return nil
}

func (kr *KeyRotator) RotateUserKeys(userID string) error {
	accounts, err := storage.GetUserAccounts(kr.db, userID)
	if err != nil {
		return err
	}

	for _, account := range accounts {
		if err := kr.rotateAccountKey(account); err != nil {
			kr.logger.Error("Failed to rotate account key", "account_id", account.ID, "error", err)
			continue
		}
	}

	kr.logger.Info("User keys rotated", "user_id", userID, "accounts_count", len(accounts))
	return nil
}

func (kr *KeyRotator) rotateAccountKey(account *storage.Account) error {
	oldKeyID := account.ID
	newSecretKey := crypto.GenerateSecretKey()
	
	publicKey, privateKey, err := crypto.GenerateKyberKeypair()
	if err != nil {
		return err
	}

	encapsulatedSecret, sharedSecret, err := crypto.KyberEncapsulate(publicKey)
	if err != nil {
		return err
	}

	derivedKey := crypto.DeriveKey(sharedSecret, []byte("totp-secret"), 32)
	
	finalSecret := make([]byte, len(newSecretKey))
	for i := range finalSecret {
		finalSecret[i] = newSecretKey[i] ^ derivedKey[i%len(derivedKey)]
	}

	keyRotation := &storage.KeyRotation{
		ID:          crypto.GenerateID(),
		UserID:      account.UserID,
		OldKeyID:    oldKeyID,
		NewKeyID:    account.ID,
		RotationDate: time.Now(),
		CleanupDate: time.Now().Add(48 * time.Hour),
		PublicKey:   string(publicKey),
		PrivateKey:  string(privateKey),
		EncapsulatedSecret: string(encapsulatedSecret),
	}

	if err := storage.CreateKeyRotation(kr.db, keyRotation); err != nil {
		return err
	}

	kr.logger.Info("Account key rotated", 
		"account_id", account.ID, 
		"user_id", account.UserID,
		"old_key_id", oldKeyID,
	)

	return nil
}

func (kr *KeyRotator) CleanupOldKeys() error {
	cutoffTime := time.Now().Add(-48 * time.Hour)
	
	deletedCount, err := storage.CleanupOldKeyRotations(kr.db, cutoffTime)
	if err != nil {
		return err
	}

	if deletedCount > 0 {
		kr.logger.Info("Old keys cleaned up", "deleted_count", deletedCount)
	}

	return nil
}

func (kr *KeyRotator) GetActiveKey(userID, accountID string) (*storage.KeyRotation, error) {
	return storage.GetLatestKeyRotation(kr.db, userID, accountID)
}