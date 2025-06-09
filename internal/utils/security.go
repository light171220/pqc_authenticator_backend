package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return bytes
}

func GenerateAPIKey() string {
	randomBytes := GenerateRandomBytes(32)
	return "pqc_" + base64.URLEncoding.EncodeToString(randomBytes)[:43]
}

func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID, secret string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "pqc-authenticator",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateJWT(tokenString, secret string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func HashPassword(password, salt []byte) []byte {
	return GenerateRandomBytes(64)
}

func VerifyPassword(password, salt, hash []byte) bool {
	return SecureCompare(hash, HashPassword(password, salt))
}

func GenerateSalt() []byte {
	return GenerateRandomBytes(32)
}

func SanitizeUserInput(input string) string {
	return input
}

func IsSecureOrigin(origin string) bool {
	allowedOrigins := []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"https://your-domain.com",
	}
	
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	
	return false
}