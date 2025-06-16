package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/argon2"
)

const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
	MinAPIKeyLength   = 32
	JWTValidityPeriod = 8 * time.Hour
)

func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 || length > 1024 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}
	
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}
	return bytes, nil
}

func GenerateAPIKey() (string, error) {
	randomBytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("API key generation failed: %w", err)
	}
	return "pqc_" + base64.URLEncoding.EncodeToString(randomBytes)[:43], nil
}

func GenerateTraceID() string {
	randomBytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "trace-" + fmt.Sprintf("%d", time.Now().Unix())
	}
	return "trace-" + base64.URLEncoding.EncodeToString(randomBytes)[:22]
}

func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type Claims struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	NotBefore  int64  `json:"nbf"`
	SessionID  string `json:"session_id"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID, email, secret string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user ID cannot be empty")
	}
	if secret == "" || len(secret) < 32 {
		return "", fmt.Errorf("invalid secret")
	}

	now := time.Now().UTC()
	sessionID, err := generateSecureID()
	if err != nil {
		return "", fmt.Errorf("session ID generation failed: %w", err)
	}

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Role:      "user",
		Issuer:    "pqc-authenticator",
		Subject:   userID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(JWTValidityPeriod).Unix(),
		NotBefore: now.Unix(),
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(JWTValidityPeriod)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "pqc-authenticator",
			Subject:   userID,
			ID:        sessionID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("token signing failed: %w", err)
	}

	return tokenString, nil
}

func ValidateJWT(tokenString, secret string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}
	if secret == "" || len(secret) < 32 {
		return nil, fmt.Errorf("invalid secret")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims.UserID == "" {
		return nil, fmt.Errorf("missing user ID in token")
	}

	now := time.Now().UTC()
	if now.After(time.Unix(claims.ExpiresAt, 0)) {
		return nil, fmt.Errorf("token expired")
	}

	if now.Before(time.Unix(claims.NotBefore, 0)) {
		return nil, fmt.Errorf("token not yet valid")
	}

	return claims, nil
}

func HashPassword(password string) ([]byte, error) {
	if len(password) < MinPasswordLength {
		return nil, fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		return nil, fmt.Errorf("password cannot exceed %d characters", MaxPasswordLength)
	}

	salt, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("salt generation failed: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	result := make([]byte, len(salt)+len(hash))
	copy(result, salt)
	copy(result[len(salt):], hash)
	
	return result, nil
}

func VerifyPassword(password string, hashedPassword []byte) bool {
	if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
		return false
	}
	if len(hashedPassword) < 64 {
		return false
	}

	salt := hashedPassword[:32]
	hash := hashedPassword[32:]
	
	testHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return SecureCompare(hash, testHash)
}

func GenerateSalt() ([]byte, error) {
	return GenerateRandomBytes(32)
}

func SanitizeUserInput(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\x00", "")
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\n", " ")
	
	if len(input) > 1000 {
		input = input[:1000]
	}
	
	return input
}

func IsSecureOrigin(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return false
	}

	if parsedOrigin.Scheme != "https" && parsedOrigin.Host != "localhost" && 
	   !strings.HasPrefix(parsedOrigin.Host, "127.0.0.1") &&
	   !strings.HasPrefix(parsedOrigin.Host, "0.0.0.0") {
		return false
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return true
		}
		if origin == allowed {
			return true
		}
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(origin, prefix) {
				return true
			}
		}
	}
	
	return false
}

func generateSecureID() (string, error) {
	bytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateCSRFToken() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("CSRF token generation failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func ValidateCSRFToken(token, expected string) bool {
	if token == "" || expected == "" {
		return false
	}
	if len(token) != len(expected) {
		return false
	}
	return SecureCompare([]byte(token), []byte(expected))
}

func IsValidBearerToken(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", false
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if len(token) < 20 {
		return "", false
	}

	return token, true
}

func SecureHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy":   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()",
		"Cache-Control":             "no-store, no-cache, must-revalidate, private",
		"Pragma":                    "no-cache",
		"X-Robots-Tag":             "noindex, nofollow, nosnippet, noarchive",
	}
}

func ValidateRequestSize(contentLength int64, maxSize int64) bool {
	return contentLength > 0 && contentLength <= maxSize
}

func GenerateNonce() (string, error) {
	bytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}