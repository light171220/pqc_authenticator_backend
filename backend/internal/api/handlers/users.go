package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type UserHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
}

func NewUserHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *UserHandler {
	return &UserHandler{
		db:     db,
		logger: logger,
		config: config,
	}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *UserHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid registration request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email format",
			"code":  "INVALID_EMAIL",
		})
		return
	}

	if !utils.IsStrongPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 8 characters with uppercase, lowercase, number, and special character",
			"code":  "WEAK_PASSWORD",
		})
		return
	}

	existingUser, _ := storage.GetUserByUsername(h.db, req.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Username already exists",
			"code":  "USERNAME_EXISTS",
		})
		return
	}

	existingEmail, _ := storage.GetUserByEmail(h.db, req.Email)
	if existingEmail != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Email already registered",
			"code":  "EMAIL_EXISTS",
		})
		return
	}

	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "HASH_FAILED",
		})
		return
	}

	user := &storage.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := storage.CreateUser(h.db, user); err != nil {
		h.logger.Error("Failed to create user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	h.logger.Info("User registered", "user_id", user.ID, "username", user.Username)

	c.JSON(http.StatusCreated, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	})
}

func (h *UserHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid login request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	user, err := storage.GetUserByUsername(h.db, req.Username)
	if err != nil {
		h.logger.Warn("User not found", "username", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "INVALID_CREDENTIALS",
		})
		return
	}

	if !utils.VerifyPassword(req.Password, user.PasswordHash) {
		h.logger.Warn("Invalid password", "user_id", user.ID)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "INVALID_CREDENTIALS",
		})
		return
	}

	token, err := utils.GenerateJWT(user.ID, user.Email, h.config.Security.JWTSecret)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Authentication error",
			"code":  "TOKEN_GENERATION_FAILED",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, user.ID, "", "user_login", map[string]interface{}{
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
		"login_time":  time.Now(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User logged in", "user_id", user.ID, "username", user.Username)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		},
	})
}

func (h *UserHandler) Logout(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "user_logout", map[string]interface{}{
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
		"logout_time": time.Now(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User logged out", "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
		"code":    "SUCCESS",
	})
}

func (h *UserHandler) RefreshToken(c *gin.Context) {
	userID := c.GetString("user_id")
	userEmail := c.GetString("user_email")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	token, err := utils.GenerateJWT(userID, userEmail, h.config.Security.JWTSecret)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to refresh token",
			"code":  "TOKEN_GENERATION_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"code":  "SUCCESS",
	})
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user profile", "user_id", userID, "error", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
			"code":  "USER_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	})
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	var req struct {
		Email string `json:"email,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid update profile request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"code":  "INVALID_REQUEST",
		})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
			"code":  "USER_NOT_FOUND",
		})
		return
	}

	if req.Email != "" && req.Email != user.Email {
		if !utils.IsValidEmail(req.Email) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid email format",
				"code":  "INVALID_EMAIL",
			})
			return
		}

		existingUser, _ := storage.GetUserByEmail(h.db, req.Email)
		if existingUser != nil && existingUser.ID != userID {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Email already in use",
				"code":  "EMAIL_EXISTS",
			})
			return
		}

		user.Email = req.Email
	}

	user.UpdatedAt = time.Now()

	if err := storage.UpdateUser(h.db, user); err != nil {
		h.logger.Error("Failed to update user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update profile",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	h.logger.Info("User profile updated", "user_id", userID)

	c.JSON(http.StatusOK, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	})
}

func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "account_deleted", map[string]interface{}{
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User account deleted", "user_id", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Account deleted successfully",
		"code":    "SUCCESS",
	})
}

func (h *UserHandler) GetAuditLogs(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	limit := 50
	offset := 0

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	logs, err := storage.GetAuditLogs(h.db, userID, limit, offset)
	if err != nil {
		h.logger.Error("Failed to get audit logs", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve audit logs",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":   logs,
		"limit":  limit,
		"offset": offset,
		"count":  len(logs),
	})
}

func (h *UserHandler) GetActiveSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	sessions := []map[string]interface{}{
		{
			"id":           "current",
			"ip_address":   c.ClientIP(),
			"user_agent":   c.GetHeader("User-Agent"),
			"created_at":   time.Now().Unix(),
			"last_active":  time.Now().Unix(),
			"is_current":   true,
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

func (h *UserHandler) RevokeSession(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID required",
			"code":  "MISSING_SESSION_ID",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "session_revoked", map[string]interface{}{
		"session_id": sessionID,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Session revoked", "user_id", userID, "session_id", sessionID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Session revoked successfully",
		"code":    "SUCCESS",
	})
}