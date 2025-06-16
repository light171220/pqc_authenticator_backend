package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/utils"
)

type HealthHandler struct {
	db     *sql.DB
	logger utils.Logger
}

func NewHealthHandler(db *sql.DB, logger utils.Logger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: logger,
	}
}

type HealthResponse struct {
	Status    string                 `json:"status"`
	Timestamp int64                  `json:"timestamp"`
	Version   string                 `json:"version"`
	Services  map[string]interface{} `json:"services"`
	Uptime    string                 `json:"uptime"`
}

type ReadinessResponse struct {
	Ready      bool                   `json:"ready"`
	Timestamp  int64                  `json:"timestamp"`
	Services   map[string]interface{} `json:"services"`
	Version    string                 `json:"version"`
}

type MetricsResponse struct {
	Timestamp    int64                  `json:"timestamp"`
	Memory       map[string]interface{} `json:"memory"`
	Goroutines   int                    `json:"goroutines"`
	Database     map[string]interface{} `json:"database"`
	Version      string                 `json:"version"`
	Uptime       string                 `json:"uptime"`
}

var (
	startTime = time.Now()
	version   = "1.0.0"
)

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	timestamp := time.Now().Unix()
	services := make(map[string]interface{})

	dbStatus := h.checkDatabaseHealth(c)
	services["database"] = dbStatus

	overallStatus := "healthy"
	if dbStatus["status"] != "healthy" {
		overallStatus = "unhealthy"
	}

	uptime := time.Since(startTime)

	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: timestamp,
		Version:   version,
		Services:  services,
		Uptime:    uptime.String(),
	}

	statusCode := http.StatusOK
	if overallStatus != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	timestamp := time.Now().Unix()
	services := make(map[string]interface{})

	dbReady := h.checkDatabaseReadiness(c)
	services["database"] = dbReady

	ready := dbReady["ready"].(bool)

	response := ReadinessResponse{
		Ready:     ready,
		Timestamp: timestamp,
		Services:  services,
		Version:   version,
	}

	statusCode := http.StatusOK
	if !ready {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

func (h *HealthHandler) Metrics(c *gin.Context) {
	timestamp := time.Now().Unix()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memory := map[string]interface{}{
		"alloc_bytes":       m.Alloc,
		"total_alloc_bytes": m.TotalAlloc,
		"sys_bytes":         m.Sys,
		"lookups":           m.Lookups,
		"mallocs":           m.Mallocs,
		"frees":             m.Frees,
		"heap_alloc_bytes":  m.HeapAlloc,
		"heap_sys_bytes":    m.HeapSys,
		"heap_idle_bytes":   m.HeapIdle,
		"heap_inuse_bytes":  m.HeapInuse,
		"heap_released_bytes": m.HeapReleased,
		"heap_objects":      m.HeapObjects,
		"stack_inuse_bytes": m.StackInuse,
		"stack_sys_bytes":   m.StackSys,
		"gc_runs":           m.NumGC,
		"gc_pause_total_ns": m.PauseTotalNs,
		"last_gc_time":      time.Unix(0, int64(m.LastGC)).Format(time.RFC3339),
	}

	database := h.getDatabaseMetrics()
	uptime := time.Since(startTime)

	response := MetricsResponse{
		Timestamp:  timestamp,
		Memory:     memory,
		Goroutines: runtime.NumGoroutine(),
		Database:   database,
		Version:    version,
		Uptime:     uptime.String(),
	}

	c.JSON(http.StatusOK, response)
}

func (h *HealthHandler) checkDatabaseHealth(c *gin.Context) map[string]interface{} {
	status := map[string]interface{}{
		"status": "healthy",
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if err := h.db.PingContext(ctx); err != nil {
		status["status"] = "unhealthy"
		status["error"] = err.Error()
		h.logger.Error("Database health check failed", "error", err)
		return status
	}

	dbStats := h.db.Stats()
	status["open_connections"] = dbStats.OpenConnections
	status["in_use"] = dbStats.InUse
	status["idle"] = dbStats.Idle
	status["wait_count"] = dbStats.WaitCount
	status["wait_duration_ms"] = dbStats.WaitDuration.Milliseconds()
	status["max_idle_closed"] = dbStats.MaxIdleClosed
	status["max_idle_time_closed"] = dbStats.MaxIdleTimeClosed
	status["max_lifetime_closed"] = dbStats.MaxLifetimeClosed

	return status
}

func (h *HealthHandler) checkDatabaseReadiness(c *gin.Context) map[string]interface{} {
	readiness := map[string]interface{}{
		"ready": true,
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	var result int
	err := h.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil || result != 1 {
		readiness["ready"] = false
		if err != nil {
			readiness["error"] = err.Error()
		}
		h.logger.Error("Database readiness check failed", "error", err)
	}

	return readiness
}

func (h *HealthHandler) getDatabaseMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"status": "unknown",
	}

	if err := h.db.Ping(); err != nil {
		metrics["status"] = "unhealthy"
		metrics["error"] = err.Error()
		return metrics
	}

	metrics["status"] = "healthy"
	
	dbStats := h.db.Stats()
	metrics["open_connections"] = dbStats.OpenConnections
	metrics["in_use"] = dbStats.InUse
	metrics["idle"] = dbStats.Idle
	metrics["wait_count"] = dbStats.WaitCount
	metrics["wait_duration_ms"] = dbStats.WaitDuration.Milliseconds()
	metrics["max_idle_closed"] = dbStats.MaxIdleClosed
	metrics["max_idle_time_closed"] = dbStats.MaxIdleTimeClosed
	metrics["max_lifetime_closed"] = dbStats.MaxLifetimeClosed

	var userCount, accountCount, deviceCount int
	if err := h.db.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = 1").Scan(&userCount); err == nil {
		metrics["active_users"] = userCount
	}
	if err := h.db.QueryRow("SELECT COUNT(*) FROM accounts WHERE is_active = 1").Scan(&accountCount); err == nil {
		metrics["active_accounts"] = accountCount
	}
	if err := h.db.QueryRow("SELECT COUNT(*) FROM devices WHERE is_active = 1").Scan(&deviceCount); err == nil {
		metrics["active_devices"] = deviceCount
	}

	var dbSize int64
	if err := h.db.QueryRow("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()").Scan(&dbSize); err == nil {
		metrics["database_size_bytes"] = dbSize
	}

	return metrics
}