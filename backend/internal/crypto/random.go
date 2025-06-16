package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}
	
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("random bytes generation failed: %w", err)
	}
	return bytes, nil
}

func GenerateSecretKey() ([]byte, error) {
	return GenerateRandomBytes(32)
}

func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}

func GenerateRandomBase32(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	
	encoded := base32.StdEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		return encoded[:length], nil
	}
	return encoded, nil
}

func GenerateAPIKey() (string, error) {
	randomPart, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}
	return "pqc_" + randomPart, nil
}

func GenerateID() string {
	return uuid.New().String()
}

func GenerateSessionToken() (string, error) {
	return GenerateRandomString(64)
}

func GenerateNonce() ([]byte, error) {
	return GenerateRandomBytes(16)
}

func GenerateRandomNumber(max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}
	
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, fmt.Errorf("random number generation failed: %w", err)
	}
	
	return n.Int64(), nil
}

func GenerateRandomHex(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

func GenerateOTPSecret() (string, error) {
	secret, err := GenerateRandomBytes(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

func GenerateRecoveryCode() (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 16)
	
	for i := range code {
		num, err := GenerateRandomNumber(int64(len(charset)))
		if err != nil {
			return "", err
		}
		code[i] = charset[num]
	}
	
	result := string(code)
	return result[:4] + "-" + result[4:8] + "-" + result[8:12] + "-" + result[12:16], nil
}

func GenerateSalt() ([]byte, error) {
	return GenerateRandomBytes(32)
}

func GenerateCSRFToken() (string, error) {
	return GenerateRandomString(32)
}

type SecureRandomGenerator struct {
	entropy []byte
}

func NewSecureRandomGenerator() (*SecureRandomGenerator, error) {
	entropy, err := GenerateRandomBytes(64)
	if err != nil {
		return nil, fmt.Errorf("entropy generation failed: %w", err)
	}
	
	return &SecureRandomGenerator{
		entropy: entropy,
	}, nil
}

func (sr *SecureRandomGenerator) GenerateBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}
	
	additional, err := GenerateRandomBytes(length)
	if err != nil {
		return nil, fmt.Errorf("additional entropy generation failed: %w", err)
	}
	
	combined := append(sr.entropy, additional...)
	result := SHAKE256(combined, length)
	
	newEntropy := SHAKE256(sr.entropy, 64)
	copy(sr.entropy, newEntropy)
	
	return result, nil
}

func (sr *SecureRandomGenerator) GenerateString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	
	bytes, err := sr.GenerateBytes(length)
	if err != nil {
		return "", err
	}
	
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) < length {
		return encoded, nil
	}
	return encoded[:length], nil
}

func (sr *SecureRandomGenerator) GenerateNumber(max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}
	
	bytes, err := sr.GenerateBytes(8)
	if err != nil {
		return 0, err
	}
	
	num := big.NewInt(0).SetBytes(bytes)
	result := big.NewInt(0)
	result.Mod(num, big.NewInt(max))
	
	return result.Int64(), nil
}