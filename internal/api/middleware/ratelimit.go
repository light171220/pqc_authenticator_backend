package middleware

import (
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

func newRateLimiter(requestsPerMinute int) *rateLimiter {
	r := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Every(time.Minute / time.Duration(requestsPerMinute)),
		burst:    requestsPerMinute,
	}

	go r.cleanupVisitors()
	return r
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitor{limiter, time.Now()}
		return limiter.Allow()
	}

	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

func (rl *rateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

var globalRateLimiter *rateLimiter

func RateLimit(requestsPerMinute int, window time.Duration) gin.HandlerFunc {
	if globalRateLimiter == nil {
		globalRateLimiter = newRateLimiter(requestsPerMinute)
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		ip := c.ClientIP()

		if !globalRateLimiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}