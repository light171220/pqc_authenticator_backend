package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type BackupHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewBackupHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *BackupHandler {
	return &BackupHandler{
		db:     db,
		logger: logger,
		config: config,
	}
}

type CreateBackupRequest struct {
	Password string `json:"password" binding:"required,min=8"`
}

type RestoreBackupRequest struct {
	BackupData string `json:"backup_data" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type BackupData struct {
	Version   string              `json:"version"`
	CreatedAt time.Time           `json:"created_at"`
	User      *storage.User       `json:"user"`
	Devices   []*storage.Device   `json:"devices"`
	Accounts  []*storage.Account  `json:"accounts"`
}

func (h *BackupHandler) CreateBackup(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req CreateBackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid create backup request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsStrongPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Backup password must be strong"})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	devices, err := storage.GetUserDevices(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user devices for backup", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	accounts, err := storage.GetUserAccounts(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user accounts for backup", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	backupData := &BackupData{
		Version:   "1.0",
		CreatedAt: time.Now(),
		User:      user,
		Devices:   devices,
		Accounts:  accounts,
	}

	jsonData, err := json.Marshal(backupData)
	if err != nil {
		h.logger.Error("Failed to marshal backup data", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	encryptedBackup, err := crypto.EncryptDataWithPassword(jsonData, req.Password)
	if err != nil {
		h.logger.Error("Failed to encrypt backup data", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "backup_created", map[string]interface{}{
		"backup_size": len(encryptedBackup),
		"timestamp":   time.Now().Unix(),
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Backup created", "user_id", userID, "backup_size", len(encryptedBackup))

	c.JSON(http.StatusOK, gin.H{
		"backup_data": encryptedBackup,
		"created_at":  backupData.CreatedAt.Unix(),
		"size":        len(encryptedBackup),
		"message":     "Backup created successfully",
	})
}

func (h *BackupHandler) RestoreBackup(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req RestoreBackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid restore backup request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	decryptedData, err := crypto.DecryptDataWithPassword(req.BackupData, req.Password)
	if err != nil {
		h.logger.Warn("Failed to decrypt backup data", "user_id", userID, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid backup data or password"})
		return
	}

	var backupData BackupData
	if err := json.Unmarshal(decryptedData, &backupData); err != nil {
		h.logger.Error("Failed to unmarshal backup data", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid backup format"})
		return
	}

	if backupData.Version != "1.0" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported backup version"})
		return
	}

	if backupData.User.ID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Backup belongs to different user"})
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		h.logger.Error("Failed to begin transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore backup"})
		return
	}
	defer tx.Rollback()

	for _, device := range backupData.Devices {
		existingDevice, _ := storage.GetDeviceByFingerprint(h.db, userID, device.DeviceFingerprint)
		if existingDevice == nil {
			if err := storage.CreateDevice(h.db, device); err != nil {
				h.logger.Error("Failed to restore device", "device_id", device.ID, "error", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore devices"})
				return
			}
		}
	}

	for _, account := range backupData.Accounts {
		existingAccount, _ := storage.GetAccountByServiceName(h.db, userID, account.ServiceName)
		if existingAccount == nil {
			if err := storage.CreateAccount(h.db, account); err != nil {
				h.logger.Error("Failed to restore account", "account_id", account.ID, "error", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore accounts"})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("Failed to commit restore transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore backup"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "backup_restored", map[string]interface{}{
		"backup_version": backupData.Version,
		"backup_date":    backupData.CreatedAt.Unix(),
		"devices_count":  len(backupData.Devices),
		"accounts_count": len(backupData.Accounts),
		"timestamp":      time.Now().Unix(),
		"ip_address":     c.ClientIP(),
		"user_agent":     c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Backup restored", "user_id", userID, "backup_date", backupData.CreatedAt)

	c.JSON(http.StatusOK, gin.H{
		"message":        "Backup restored successfully",
		"devices_count":  len(backupData.Devices),
		"accounts_count": len(backupData.Accounts),
		"backup_date":    backupData.CreatedAt.Unix(),
	})
}

func (h *BackupHandler) DownloadBackup(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	password := c.Query("password")
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password required"})
		return
	}

	if !utils.IsStrongPassword(password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Backup password must be strong"})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	devices, err := storage.GetUserDevices(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user devices for backup", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	accounts, err := storage.GetUserAccounts(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user accounts for backup", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	backupData := &BackupData{
		Version:   "1.0",
		CreatedAt: time.Now(),
		User:      user,
		Devices:   devices,
		Accounts:  accounts,
	}

	jsonData, err := json.Marshal(backupData)
	if err != nil {
		h.logger.Error("Failed to marshal backup data", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	encryptedBackup, err := crypto.EncryptDataWithPassword(jsonData, password)
	if err != nil {
		h.logger.Error("Failed to encrypt backup data", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "backup_downloaded", map[string]interface{}{
		"backup_size": len(encryptedBackup),
		"timestamp":   time.Now().Unix(),
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Backup downloaded", "user_id", userID, "backup_size", len(encryptedBackup))

	filename := "pqc-authenticator-backup-" + time.Now().Format("2006-01-02") + ".dat"
	
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", string(rune(len(encryptedBackup))))
	
	c.Data(http.StatusOK, "application/octet-stream", []byte(encryptedBackup))
}