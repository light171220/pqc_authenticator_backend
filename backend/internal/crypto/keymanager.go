package crypto

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/google/uuid"
	"pqc-authenticator/internal/storage"
)

type KeyManager struct {
	db            *sql.DB
	encryptionKey string
}

func NewKeyManager(db *sql.DB) *KeyManager {
	encryptionKey := SHAKE256([]byte("default-key-encryption"), 32)
	return &KeyManager{
		db:            db,
		encryptionKey: base64.StdEncoding.EncodeToString(encryptionKey),
	}
}

func NewKeyManagerWithKey(db *sql.DB, encryptionKey string) *KeyManager {
	return &KeyManager{
		db:            db,
		encryptionKey: encryptionKey,
	}
}

func (km *KeyManager) CreateUserKeyPair(userID string) (*storage.UserKeypair, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey.Bytes())
	
	privateKeyBytes := privateKey.Bytes()
	encryptedPrivateKey, err := EncryptData(privateKeyBytes, km.encryptionKey)
	if err != nil {
		SecureZeroMemory(privateKeyBytes)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}
	SecureZeroMemory(privateKeyBytes)

	keypair := &storage.UserKeypair{
		ID:         uuid.New().String(),
		UserID:     userID,
		PublicKey:  publicKeyB64,
		PrivateKey: encryptedPrivateKey,
		IsActive:   true,
		CreatedAt:  time.Now(),
		KeyVersion: 1,
		Algorithm:  "dilithium-mode3",
	}

	tx, err := km.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := storage.DeactivateUserKeypairs(km.db, userID); err != nil {
		return nil, fmt.Errorf("failed to deactivate old keys: %w", err)
	}

	if err := storage.CreateUserKeypair(km.db, keypair); err != nil {
		return nil, fmt.Errorf("failed to insert keypair: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return keypair, nil
}

func (km *KeyManager) GetActiveKeyPair(userID string) (*storage.UserKeypair, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	keypair, err := storage.GetUserKeypairByUserID(km.db, userID)
	if err == sql.ErrNoRows {
		return km.CreateUserKeyPair(userID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get keypair: %w", err)
	}

	return keypair, nil
}

func (km *KeyManager) SignData(userID string, data []byte) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user ID cannot be empty")
	}
	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}

	keypair, err := km.GetActiveKeyPair(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get keypair: %w", err)
	}

	encryptedPrivateKey := keypair.PrivateKey
	privateKeyBytes, err := DecryptData(encryptedPrivateKey, km.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt private key: %w", err)
	}
	defer SecureZeroMemory(privateKeyBytes)

	if len(privateKeyBytes) != mode3.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}

	var privateKey mode3.PrivateKey
	var skArray [mode3.PrivateKeySize]byte
	copy(skArray[:], privateKeyBytes)
	privateKey.Unpack(&skArray)

	message := append([]byte(userID+":"), data...)
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&privateKey, message, signature)

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (km *KeyManager) VerifySignature(userID string, data []byte, signatureB64 string) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("user ID cannot be empty")
	}
	if len(data) == 0 {
		return false, fmt.Errorf("data cannot be empty")
	}
	if signatureB64 == "" {
		return false, fmt.Errorf("signature cannot be empty")
	}

	keypair, err := km.GetActiveKeyPair(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get keypair: %w", err)
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(keypair.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(publicKeyBytes) != mode3.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	var publicKey mode3.PublicKey
	var pkArray [mode3.PublicKeySize]byte
	copy(pkArray[:], publicKeyBytes)
	publicKey.Unpack(&pkArray)

	message := append([]byte(userID+":"), data...)
	return mode3.Verify(&publicKey, message, signatureBytes), nil
}

func (km *KeyManager) RotateUserKeys(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	oldKeypair, err := km.GetActiveKeyPair(userID)
	if err != nil {
		return fmt.Errorf("failed to get current keypair: %w", err)
	}

	newKeypair, err := km.CreateUserKeyPair(userID)
	if err != nil {
		return fmt.Errorf("failed to create new keypair: %w", err)
	}

	rotation := &storage.KeyRotation{
		ID:           uuid.New().String(),
		UserID:       userID,
		OldKeyID:     oldKeypair.ID,
		NewKeyID:     newKeypair.ID,
		RotationType: "manual",
		RotationDate: time.Now(),
		Status:       "completed",
		InitiatedBy:  "system",
	}

	if err := storage.CreateKeyRotation(km.db, rotation); err != nil {
		return fmt.Errorf("failed to log key rotation: %w", err)
	}

	return nil
}

func (km *KeyManager) CleanupExpiredKeys() error {
	cutoffTime := time.Now().Add(-72 * time.Hour)
	
	_, err := storage.CleanupOldKeyRotations(km.db, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired keys: %w", err)
	}

	return nil
}

func (km *KeyManager) GetKeyAge(userID string) (time.Duration, error) {
	if userID == "" {
		return 0, fmt.Errorf("user ID cannot be empty")
	}

	keypair, err := km.GetActiveKeyPair(userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get keypair: %w", err)
	}

	return time.Since(keypair.CreatedAt), nil
}

func (km *KeyManager) DeactivateAllUserKeys(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	if err := storage.DeactivateUserKeypairs(km.db, userID); err != nil {
		return fmt.Errorf("failed to deactivate keys: %w", err)
	}

	return nil
}

func (km *KeyManager) GetKeypairByID(keypairID string) (*storage.UserKeypair, error) {
	if keypairID == "" {
		return nil, fmt.Errorf("keypair ID cannot be empty")
	}

	return storage.GetUserKeypairByID(km.db, keypairID)
}

func (km *KeyManager) ScheduledRotation(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	age, err := km.GetKeyAge(userID)
	if err != nil {
		return fmt.Errorf("failed to get key age: %w", err)
	}

	if age > 24*time.Hour {
		oldKeypair, err := km.GetActiveKeyPair(userID)
		if err != nil {
			return fmt.Errorf("failed to get current keypair: %w", err)
		}

		newKeypair, err := km.CreateUserKeyPair(userID)
		if err != nil {
			return fmt.Errorf("failed to create new keypair: %w", err)
		}

		rotation := &storage.KeyRotation{
			ID:           uuid.New().String(),
			UserID:       userID,
			OldKeyID:     oldKeypair.ID,
			NewKeyID:     newKeypair.ID,
			RotationType: "scheduled",
			RotationDate: time.Now(),
			CleanupDate:  &[]time.Time{time.Now().Add(72 * time.Hour)}[0],
			Status:       "completed",
			InitiatedBy:  "scheduler",
		}

		if err := storage.CreateKeyRotation(km.db, rotation); err != nil {
			return fmt.Errorf("failed to log scheduled rotation: %w", err)
		}
	}

	return nil
}