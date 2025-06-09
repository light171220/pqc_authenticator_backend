package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !utils.IsValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	if !utils.IsStrongPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters with uppercase, lowercase, number, and special character"})
		return
	}

	existingUser, _ := storage.GetUserByUsername(h.db, req.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	existingEmail, _ := storage.GetUserByEmail(h.db, req.Email)
	if existingEmail != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	salt := utils.GenerateRandomBytes(32)
	passwordHash := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	user := &storage.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: append(salt, passwordHash...),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := storage.CreateUser(h.db, user); err != nil {
		h.logger.Error("Failed to create user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	user, err := storage.GetUserByUsername(h.db, req.Username)
	if err != nil {
		h.logger.Warn("User not found", "username", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if len(user.PasswordHash) < 32 {
		h.logger.Error("Invalid password hash format", "user_id", user.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication error"})
		return
	}

	salt := user.PasswordHash[:32]
	storedHash := user.PasswordHash[32:]
	providedHash := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	if !utils.SecureCompare(storedHash, providedHash) {
		h.logger.Warn("Invalid password", "user_id", user.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := utils.GenerateJWT(user.ID, h.config.Security.JWTSecret)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication error"})
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

func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		h.logger.Error("Failed to get user profile", "user_id", userID, "error", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		Email string `json:"email,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid update profile request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	user, err := storage.GetUserByID(h.db, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if req.Email != "" && req.Email != user.Email {
		if !utils.IsValidEmail(req.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}

		existingUser, _ := storage.GetUserByEmail(h.db, req.Email)
		if existingUser != nil && existingUser.ID != userID {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already in use"})
			return
		}

		user.Email = req.Email
	}

	user.UpdatedAt = time.Now()

	if err := storage.UpdateUser(h.db, user); err != nil {
		h.logger.Error("Failed to update user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
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