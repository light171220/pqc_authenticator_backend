package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

func GenerateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return bytes
}

func GenerateSecretKey() []byte {
	return GenerateRandomBytes(32)
}

func GenerateRandomString(length int) string {
	bytes := GenerateRandomBytes(length)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func GenerateRandomBase32(length int) string {
	bytes := GenerateRandomBytes(length)
	encoded := base32.StdEncoding.EncodeToString(bytes)
	if len(encoded) > length {
		return encoded[:length]
	}
	return encoded
}

func GenerateAPIKey() string {
	prefix := "pqc_"
	randomPart := GenerateRandomString(32)
	return prefix + randomPart
}

func GenerateID() string {
	return uuid.New().String()
}

func GenerateSessionToken() string {
	return GenerateRandomString(64)
}

func GenerateNonce() []byte {
	return GenerateRandomBytes(16)
}

func GenerateRandomNumber(max int64) int64 {
	if max <= 0 {
		return 0
	}
	
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("failed to generate random number: %v", err))
	}
	
	return n.Int64()
}

func GenerateRandomHex(length int) string {
	bytes := GenerateRandomBytes(length)
	return fmt.Sprintf("%x", bytes)
}

func GenerateOTPSecret() string {
	secret := GenerateRandomBytes(20)
	return base32.StdEncoding.EncodeToString(secret)
}

func GenerateRecoveryCode() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 16)
	
	for i := range code {
		num := GenerateRandomNumber(int64(len(charset)))
		code[i] = charset[num]
	}
	
	result := string(code)
	return result[:4] + "-" + result[4:8] + "-" + result[8:12] + "-" + result[12:16]
}

func GenerateSalt() []byte {
	return GenerateRandomBytes(32)
}

func GenerateCSRFToken() string {
	return GenerateRandomString(32)
}

type SecureRandom struct {
	entropy []byte
}

func NewSecureRandom() *SecureRandom {
	return &SecureRandom{
		entropy: GenerateRandomBytes(64),
	}
}

func (sr *SecureRandom) GenerateBytes(length int) []byte {
	additional := GenerateRandomBytes(length)
	combined := append(sr.entropy, additional...)
	result := SHAKE256(combined, length)
	
	sr.entropy = SHAKE256(sr.entropy, 64)
	
	return result
}

func (sr *SecureRandom) GenerateString(length int) string {
	bytes := sr.GenerateBytes(length)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func (sr *SecureRandom) GenerateNumber(max int64) int64 {
	if max <= 0 {
		return 0
	}
	
	bytes := sr.GenerateBytes(8)
	num := big.NewInt(0).SetBytes(bytes)
	result := big.NewInt(0)
	result.Mod(num, big.NewInt(max))
	
	return result.Int64()
}