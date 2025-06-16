package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func EncryptData(data []byte, key string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}
	if len(key) == 0 {
		return "", fmt.Errorf("key cannot be empty")
	}

	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		keyBytes = SHAKE256(keyBytes, 32)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptData(encryptedData, key string) ([]byte, error) {
	if encryptedData == "" || key == "" {
		return nil, fmt.Errorf("encrypted data and key cannot be empty")
	}

	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		keyBytes = SHAKE256(keyBytes, 32)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func EncryptDataWithPassword(data []byte, password string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}

	key := KDF([]byte(password), salt, 100000, 32)
	defer SecureZeroMemory(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	result := append(salt, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

func DecryptDataWithPassword(encryptedData, password string) ([]byte, error) {
	if encryptedData == "" || password == "" {
		return nil, fmt.Errorf("encrypted data and password cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(data) < 44 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	salt := data[:32]
	data = data[32:]

	key := KDF([]byte(password), salt, 100000, 32)
	defer SecureZeroMemory(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short for nonce")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func EncryptWithNonce(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(data) == 0 || len(key) == 0 {
		return nil, fmt.Errorf("data and key cannot be empty")
	}

	if len(key) != 32 {
		key = SHAKE256(key, 32)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		nonce = SHAKE256(nonce, gcm.NonceSize())
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func DecryptWithNonce(encryptedData []byte, key []byte) ([]byte, error) {
	if len(encryptedData) == 0 || len(key) == 0 {
		return nil, fmt.Errorf("encrypted data and key cannot be empty")
	}

	if len(key) != 32 {
		key = SHAKE256(key, 32)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}