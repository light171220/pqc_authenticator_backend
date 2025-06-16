package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		burst:    max(1, requestsPerMinute/10),
	}
	
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[key] = limiter
	}

	return limiter
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		for key, limiter := range rl.limiters {
			if limiter.Tokens() == float64(rl.burst) {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	return rl.getLimiter(key).Allow()
}

var authRateLimiter = NewRateLimiter(10)

func JWTAuth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		
		if !authRateLimiter.Allow(clientIP) {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, utils.NewErrorResponse(
				utils.ErrRateLimitExceeded,
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("MISSING_AUTH_HEADER", "Authorization header required", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		token, valid := utils.IsValidBearerToken(authHeader)
		if !valid {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("INVALID_AUTH_FORMAT", "Invalid authorization format", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		claims, err := utils.ValidateJWT(token, jwtSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("INVALID_TOKEN", "Invalid or expired token", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("session_id", claims.SessionID)
		c.Set("token_issued_at", time.Unix(claims.IssuedAt, 0))
		c.Set("client_ip", clientIP)
		c.Set("user_agent", userAgent)
		c.Next()
	}
}

func BusinessAPIAuth(db *storage.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		if !authRateLimiter.Allow(clientIP) {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, utils.NewErrorResponse(
				utils.ErrRateLimitExceeded,
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("MISSING_API_KEY", "API key required", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		if !isValidAPIKeyFormat(apiKey) {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("INVALID_API_KEY_FORMAT", "Invalid API key format", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		business, err := storage.GetBusinessByAPIKey(db.DB, apiKey)
		if err != nil || business == nil {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("INVALID_API_KEY", "Invalid API key", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		c.Set("business_id", business.ID)
		c.Set("business", business)
		c.Set("api_key", apiKey)
		c.Set("client_ip", clientIP)
		c.Set("user_agent", c.GetHeader("User-Agent"))
		c.Next()
	}
}

func APIKeyAuth(validKeys []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("MISSING_API_KEY", "API key required", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		var keyValid bool
		for _, validKey := range validKeys {
			if len(apiKey) == len(validKey) && 
			   subtle.ConstantTimeCompare([]byte(apiKey), []byte(validKey)) == 1 {
				keyValid = true
				break
			}
		}

		if !keyValid {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("INVALID_API_KEY", "Invalid API key", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		c.Next()
	}
}

func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, utils.NewErrorResponse(
				utils.NewAppError("AUTH_REQUIRED", "Authentication required", 401),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}

		if permission == "admin" {
		}

		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		headers := utils.SecureHeaders()
		for key, value := range headers {
			c.Header(key, value)
		}
		
		nonce, err := utils.GenerateNonce()
		if err == nil {
			c.Header("Content-Security-Policy", 
				"default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		}
		
		c.Next()
	}
}

func ValidateOrigin(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && !utils.IsSecureOrigin(origin, allowedOrigins) {
			c.JSON(http.StatusForbidden, utils.NewErrorResponse(
				utils.NewAppError("FORBIDDEN_ORIGIN", "Origin not allowed", 403),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		c.Next()
	}
}

func ContentTypeValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType == "" {
				c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
					utils.NewAppError("MISSING_CONTENT_TYPE", "Content-Type header required", 400),
					utils.GenerateTraceID()))
				c.Abort()
				return
			}
			
			if !strings.HasPrefix(contentType, "application/json") && 
			   !strings.HasPrefix(contentType, "multipart/form-data") {
				c.JSON(http.StatusUnsupportedMediaType, utils.NewErrorResponse(
					utils.NewAppError("UNSUPPORTED_MEDIA_TYPE", "Unsupported content type", 415),
					utils.GenerateTraceID()))
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = utils.GenerateTraceID()
		}
		
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func IPWhitelist(allowedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedIPs) == 0 {
			c.Next()
			return
		}
		
		clientIP := c.ClientIP()
		allowed := false
		
		for _, allowedIP := range allowedIPs {
			if clientIP == allowedIP {
				allowed = true
				break
			}
		}
		
		if !allowed {
			c.JSON(http.StatusForbidden, utils.NewErrorResponse(
				utils.NewAppError("IP_NOT_ALLOWED", "IP address not allowed", 403),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		c.Next()
	}
}

func UserAgentValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("MISSING_USER_AGENT", "User-Agent header required", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		if len(userAgent) > 500 {
			c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
				utils.NewAppError("INVALID_USER_AGENT", "User-Agent header too long", 400),
				utils.GenerateTraceID()))
			c.Abort()
			return
		}
		
		suspiciousPatterns := []string{
			"<script>", "</script>", "javascript:", "data:",
			"<iframe>", "</iframe>", "<object>", "</object>",
		}
		
		userAgentLower := strings.ToLower(userAgent)
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(userAgentLower, pattern) {
				c.JSON(http.StatusBadRequest, utils.NewErrorResponse(
					utils.NewAppError("SUSPICIOUS_USER_AGENT", "Suspicious User-Agent detected", 400),
					utils.GenerateTraceID()))
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

func isValidAPIKeyFormat(apiKey string) bool {
	if !strings.HasPrefix(apiKey, "pqc_") {
		return false
	}
	if len(apiKey) < 20 || len(apiKey) > 100 {
		return false
	}
	
	keyPart := strings.TrimPrefix(apiKey, "pqc_")
	for _, char := range keyPart {
		if !((char >= 'A' && char <= 'Z') || 
			 (char >= 'a' && char <= 'z') || 
			 (char >= '0' && char <= '9') || 
			 char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}