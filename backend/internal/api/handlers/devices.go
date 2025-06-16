package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type DeviceHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewDeviceHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *DeviceHandler {
	return &DeviceHandler{
		db:     db,
		logger: logger,
		config: config,
	}
}

type RegisterDeviceRequest struct {
	DeviceName        string `json:"device_name" binding:"required,min=1,max=100"`
	DeviceFingerprint string `json:"device_fingerprint" binding:"required"`
	PublicKey         string `json:"public_key" binding:"required"`
}

type DeviceResponse struct {
	ID                string    `json:"id"`
	DeviceName        string    `json:"device_name"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IsActive          bool      `json:"is_active"`
	LastUsed          time.Time `json:"last_used"`
	CreatedAt         time.Time `json:"created_at"`
}

func (h *DeviceHandler) RegisterDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid device registration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !crypto.IsValidPublicKey(req.PublicKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	existingDevice, _ := storage.GetDeviceByFingerprint(h.db, userID, req.DeviceFingerprint)
	if existingDevice != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Device already registered"})
		return
	}

	device := &storage.Device{
		ID:                uuid.New().String(),
		UserID:            userID,
		DeviceName:        req.DeviceName,
		DeviceFingerprint: req.DeviceFingerprint,
		PublicKey:         req.PublicKey,
		IsActive:          true,
		LastUsed:          time.Now(),
		CreatedAt:         time.Now(),
	}

	if err := storage.CreateDevice(h.db, device); err != nil {
		h.logger.Error("Failed to register device", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register device"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "device_registered", map[string]interface{}{
		"device_id":   device.ID,
		"device_name": device.DeviceName,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Device registered", "user_id", userID, "device_id", device.ID)

	c.JSON(http.StatusCreated, DeviceResponse{
		ID:                device.ID,
		DeviceName:        device.DeviceName,
		DeviceFingerprint: device.DeviceFingerprint,
		IsActive:          device.IsActive,
		LastUsed:          device.LastUsed,
		CreatedAt:         device.CreatedAt,
	})
}

func (h *DeviceHandler) ListDevices(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	devices, err := storage.GetUserDevices(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user devices", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve devices"})
		return
	}

	var response []DeviceResponse
	for _, device := range devices {
		response = append(response, DeviceResponse{
			ID:                device.ID,
			DeviceName:        device.DeviceName,
			DeviceFingerprint: device.DeviceFingerprint,
			IsActive:          device.IsActive,
			LastUsed:          device.LastUsed,
			CreatedAt:         device.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"devices": response})
}

func (h *DeviceHandler) RemoveDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	deviceID := c.Param("id")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Device ID required"})
		return
	}

	device, err := storage.GetDeviceByID(h.db, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	if device.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if err := storage.DeleteDevice(h.db, deviceID); err != nil {
		h.logger.Error("Failed to delete device", "device_id", deviceID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove device"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "device_removed", map[string]interface{}{
		"device_id":   deviceID,
		"device_name": device.DeviceName,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Device removed", "user_id", userID, "device_id", deviceID)

	c.JSON(http.StatusOK, gin.H{"message": "Device removed successfully"})
}

func (h *DeviceHandler) ActivateDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	deviceID := c.Param("id")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Device ID required"})
		return
	}

	device, err := storage.GetDeviceByID(h.db, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	if device.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "device_activated", map[string]interface{}{
		"device_id":   deviceID,
		"device_name": device.DeviceName,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Device activated", "user_id", userID, "device_id", deviceID)

	c.JSON(http.StatusOK, gin.H{"message": "Device activated successfully"})
}

func (h *DeviceHandler) DeactivateDevice(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	deviceID := c.Param("id")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Device ID required"})
		return
	}

	device, err := storage.GetDeviceByID(h.db, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	if device.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "device_deactivated", map[string]interface{}{
		"device_id":   deviceID,
		"device_name": device.DeviceName,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Device deactivated", "user_id", userID, "device_id", deviceID)

	c.JSON(http.StatusOK, gin.H{"message": "Device deactivated successfully"})
}