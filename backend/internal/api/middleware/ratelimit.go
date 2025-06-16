package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func newRateLimiter(requestsPerWindow int, window time.Duration) *rateLimiter {
	r := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Every(window / time.Duration(requestsPerWindow)),
		burst:    max(1, requestsPerWindow/10),
	}

	go r.cleanupVisitors()
	return r
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[key] = &visitor{limiter, time.Now()}
		return limiter.Allow()
	}

	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

func (rl *rateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, v := range rl.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(rl.visitors, key)
			}
		}
		rl.mu.Unlock()
	}
}

var globalRateLimiter *rateLimiter
var rateLimiterOnce sync.Once

func RateLimit(requestsPerWindow int, window time.Duration) gin.HandlerFunc {
	rateLimiterOnce.Do(func() {
		globalRateLimiter = newRateLimiter(requestsPerWindow, window)
	})

	return gin.HandlerFunc(func(c *gin.Context) {
		key := c.ClientIP()
		
		if userID := c.GetString("user_id"); userID != "" {
			key = fmt.Sprintf("user:%s", userID)
		}

		if !globalRateLimiter.allow(key) {
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", requestsPerWindow))
			c.Header("X-RateLimit-Window", window.String())
			c.Header("Retry-After", fmt.Sprintf("%.0f", window.Seconds()))
			
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Too many requests, please try again later",
				"retry_after": window.Seconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

