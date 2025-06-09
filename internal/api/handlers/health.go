package handlers

import (
	"database/sql"
	"net/http"
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
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	timestamp := time.Now().Unix()
	services := make(map[string]interface{})

	dbStatus := "healthy"
	if err := h.db.Ping(); err != nil {
		dbStatus = "unhealthy"
		h.logger.Error("Database health check failed", "error", err)
	}

	services["database"] = map[string]interface{}{
		"status": dbStatus,
	}

	overallStatus := "healthy"
	if dbStatus != "healthy" {
		overallStatus = "unhealthy"
	}

	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: timestamp,
		Version:   "1.0.0",
		Services:  services,
	}

	if overallStatus == "healthy" {
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusServiceUnavailable, response)
	}
}