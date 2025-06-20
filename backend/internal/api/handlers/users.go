package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"pqc-authenticator/internal/crypto"
	"pqc-authenticator/internal/storage"
	"pqc-authenticator/internal/utils"
)

type UserHandler struct {
	db     *sql.DB
	logger utils.Logger
	config *utils.Config
	keyMgr *crypto.KeyManager
}

func NewUserHandler(db *sql.DB, logger utils.Logger, config *utils.Config) *UserHandler {
	return &UserHandler{
		db:     db,
		logger: logger,
		config: config,
		keyMgr: crypto.NewKeyManagerWithKey(db, config.Security.EncryptionKey),
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

type PasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type PasswordResetConfirmRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	EmailVerified bool  `json:"email_verified"`
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
		IsActive:     true,
		FailedLoginAttempts: 0,
	}

	tx, err := h.db.Begin()
	if err != nil {
		h.logger.Error("Failed to begin transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "DATABASE_ERROR",
		})
		return
	}
	defer tx.Rollback()

	if err := storage.CreateUser(h.db, user); err != nil {
		h.logger.Error("Failed to create user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	_, err = h.keyMgr.CreateUserKeyPair(user.ID)
	if err != nil {
		h.logger.Error("Failed to create user keypair", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "KEYPAIR_CREATION_FAILED",
		})
		return
	}

	if err := h.SendEmailVerification(user.ID, user.Email); err != nil {
		h.logger.Warn("Failed to send verification email", "error", err)
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("Failed to commit transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, user.ID, "", "user_registered", map[string]interface{}{
		"username":   user.Username,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User registered", "user_id", user.ID, "username", user.Username)

	c.JSON(http.StatusCreated, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		EmailVerified: false,
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

	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Account is disabled",
			"code":  "ACCOUNT_DISABLED",
		})
		return
	}

	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Account is temporarily locked",
			"code":  "ACCOUNT_LOCKED",
		})
		return
	}

	if !utils.VerifyPassword(req.Password, user.PasswordHash) {
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= h.config.Security.MaxLoginAttempts {
			lockUntil := time.Now().Add(h.config.Security.LockoutDuration)
			user.LockedUntil = &lockUntil
		}
		user.UpdatedAt = time.Now()
		storage.UpdateUser(h.db, user)

		h.logger.Warn("Invalid password", "user_id", user.ID)
		
		storage.LogAuditEvent(h.db, user.ID, "", "login_failed", map[string]interface{}{
			"reason":     "invalid_password",
			"attempts":   user.FailedLoginAttempts,
			"ip_address": c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
			"result":     "failed",
		})

		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "INVALID_CREDENTIALS",
		})
		return
	}

	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLogin = &now
	user.UpdatedAt = now
	storage.UpdateUser(h.db, user)

	token, err := utils.GenerateJWT(user.ID, user.Email, h.config.Security.JWTSecret)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Authentication error",
			"code":  "TOKEN_GENERATION_FAILED",
		})
		return
	}

	tokenHash := sha256.Sum256([]byte(token))
	session := &storage.Session{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		TokenHash:    hex.EncodeToString(tokenHash[:]),
		ExpiresAt:    time.Now().Add(h.config.Security.SessionTimeout),
		LastActivity: time.Now(),
		IPAddress:    c.ClientIP(),
		UserAgent:    c.GetHeader("User-Agent"),
		IsActive:     true,
		CreatedAt:    time.Now(),
	}

	if err := storage.CreateSession(h.db, session); err != nil {
		h.logger.Warn("Failed to create session", "error", err)
	}

	if err := storage.LogAuditEvent(h.db, user.ID, "", "user_login", map[string]interface{}{
		"session_id": session.ID,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"login_time": time.Now().Unix(),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User logged in", "user_id", user.ID, "username", user.Username)

	var emailVerified bool
	query := `SELECT email_verified FROM users WHERE id = ?`
	err = h.db.QueryRow(query, user.ID).Scan(&emailVerified)
	if err != nil {
		emailVerified = false
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			EmailVerified: emailVerified,
		},
	})
}

func (h *UserHandler) RequestPasswordReset(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	user, err := storage.GetUserByEmail(h.db, req.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link has been sent"})
		return
	}

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	query := `UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?`
	expiresAt := time.Now().Add(time.Hour)
	_, err = h.db.Exec(query, token, expiresAt, user.ID)
	if err != nil {
		h.logger.Error("Failed to set password reset token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	if err := storage.LogAuditEvent(h.db, user.ID, "", "password_reset_requested", map[string]interface{}{
		"email":      req.Email,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now().Unix(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Password reset requested", "user_id", user.ID, "email", req.Email)

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset instructions sent",
		"token":   token,
	})
}

func (h *UserHandler) ResetPassword(c *gin.Context) {
	var req PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsStrongPassword(req.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password does not meet security requirements"})
		return
	}

	query := `SELECT id, email FROM users WHERE password_reset_token = ? AND password_reset_expires > ? AND is_active = 1`
	var userID, email string
	err := h.db.QueryRow(query, req.Token, time.Now()).Scan(&userID, &email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
		return
	}

	passwordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		h.logger.Error("Failed to hash new password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	updateQuery := `UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL, 
		failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`
	_, err = h.db.Exec(updateQuery, passwordHash, time.Now(), userID)
	if err != nil {
		h.logger.Error("Failed to update password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	storage.RevokeAllUserSessions(h.db, userID, "password_reset")

	if err := storage.LogAuditEvent(h.db, userID, "", "password_reset_completed", map[string]interface{}{
		"email":      email,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now().Unix(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Password reset completed", "user_id", userID, "email", email)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (h *UserHandler) SendEmailVerification(userID, email string) error {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	query := `UPDATE users SET email_verification_token = ? WHERE id = ?`
	_, err := h.db.Exec(query, token, userID)
	if err != nil {
		return err
	}

	h.logger.Info("Email verification token generated", "user_id", userID, "token", token)
	return nil
}

func (h *UserHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Verification token required"})
		return
	}

	query := `SELECT id, email FROM users WHERE email_verification_token = ? AND is_active = 1`
	var userID, email string
	err := h.db.QueryRow(query, token).Scan(&userID, &email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification token"})
		return
	}

	updateQuery := `UPDATE users SET email_verified = 1, email_verification_token = NULL, updated_at = ? WHERE id = ?`
	_, err = h.db.Exec(updateQuery, time.Now(), userID)
	if err != nil {
		h.logger.Error("Failed to verify email", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify email"})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "email_verified", map[string]interface{}{
		"email":      email,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now().Unix(),
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Email verified", "user_id", userID, "email", email)

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func (h *UserHandler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	user, err := storage.GetUserByEmail(h.db, req.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, verification has been resent"})
		return
	}

	var emailVerified bool
	query := `SELECT email_verified FROM users WHERE id = ?`
	err = h.db.QueryRow(query, user.ID).Scan(&emailVerified)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check verification status"})
		return
	}

	if emailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	if err := h.SendEmailVerification(user.ID, user.Email); err != nil {
		h.logger.Error("Failed to send verification email", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

func (h *UserHandler) Logout(c *gin.Context) {
	userID := c.GetString("user_id")
	sessionID := c.GetString("session_id")
	
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	if sessionID != "" {
		storage.RevokeSession(h.db, sessionID, "user_logout")
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "user_logout", map[string]interface{}{
		"session_id":  sessionID,
		"ip_address":  c.ClientIP(),
		"user_agent":  c.GetHeader("User-Agent"),
		"logout_time": time.Now().Unix(),
		"result":      "success",
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
	sessionID := c.GetString("session_id")
	
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	if sessionID != "" {
		storage.UpdateSessionActivity(h.db, sessionID)
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

	var emailVerified bool
	query := `SELECT email_verified FROM users WHERE id = ?`
	err = h.db.QueryRow(query, userID).Scan(&emailVerified)
	if err != nil {
		emailVerified = false
	}

	c.JSON(http.StatusOK, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		EmailVerified: emailVerified,
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
		
		emailVerifiedQuery := `UPDATE users SET email_verified = 0 WHERE id = ?`
		h.db.Exec(emailVerifiedQuery, userID)
		
		if err := h.SendEmailVerification(userID, req.Email); err != nil {
			h.logger.Warn("Failed to send verification email", "error", err)
		}
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

	if err := storage.LogAuditEvent(h.db, userID, "", "profile_updated", map[string]interface{}{
		"changes":    map[string]string{"email": req.Email},
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("User profile updated", "user_id", userID)

	var emailVerified bool
	query := `SELECT email_verified FROM users WHERE id = ?`
	err = h.db.QueryRow(query, userID).Scan(&emailVerified)
	if err != nil {
		emailVerified = false
	}

	c.JSON(http.StatusOK, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		EmailVerified: emailVerified,
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

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
			"code":  "USER_NOT_FOUND",
		})
		return
	}

	user.IsActive = false
	user.UpdatedAt = time.Now()
	
	if err := storage.UpdateUser(h.db, user); err != nil {
		h.logger.Error("Failed to deactivate user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete account",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	storage.RevokeAllUserSessions(h.db, userID, "account_deleted")
	h.keyMgr.DeactivateAllUserKeys(userID)

	if err := storage.LogAuditEvent(h.db, userID, "", "account_deleted", map[string]interface{}{
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now().Unix(),
		"result":     "success",
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

	sessions, err := storage.GetSessionsByUserID(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user sessions", "user_id", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve sessions",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	var sessionData []map[string]interface{}
	currentSessionID := c.GetString("session_id")
	
	for _, session := range sessions {
		sessionInfo := map[string]interface{}{
			"id":           session.ID,
			"ip_address":   session.IPAddress,
			"user_agent":   session.UserAgent,
			"created_at":   session.CreatedAt.Unix(),
			"last_active":  session.LastActivity.Unix(),
			"expires_at":   session.ExpiresAt.Unix(),
			"is_current":   session.ID == currentSessionID,
		}
		sessionData = append(sessionData, sessionInfo)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessionData,
		"count":    len(sessionData),
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

	if err := storage.RevokeSession(h.db, sessionID, "revoked_by_user"); err != nil {
		h.logger.Error("Failed to revoke session", "session_id", sessionID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to revoke session",
			"code":  "DATABASE_ERROR",
		})
		return
	}

	if err := storage.LogAuditEvent(h.db, userID, "", "session_revoked", map[string]interface{}{
		"session_id": sessionID,
		"ip_address": c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"timestamp":  time.Now().Unix(),
		"result":     "success",
	}); err != nil {
		h.logger.Warn("Failed to log audit event", "error", err)
	}

	h.logger.Info("Session revoked", "user_id", userID, "session_id", sessionID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Session revoked successfully",
		"code":    "SUCCESS",
	})
}