package storage

import (
	"time"
)

type User struct {
	ID                 string    `json:"id" db:"id"`
	Username           string    `json:"username" db:"username"`
	Email              string    `json:"email" db:"email"`
	PasswordHash       []byte    `json:"-" db:"password_hash"`
	RecoveryPhraseHash []byte    `json:"-" db:"recovery_phrase_hash"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
	IsActive           bool      `json:"is_active" db:"is_active"`
	LastLogin          *time.Time `json:"last_login" db:"last_login"`
	FailedLoginAttempts int       `json:"-" db:"failed_login_attempts"`
	LockedUntil        *time.Time `json:"-" db:"locked_until"`
}

type UserKeypair struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	PublicKey  string    `json:"public_key" db:"public_key"`
	PrivateKey string    `json:"-" db:"private_key"`
	IsActive   bool      `json:"is_active" db:"is_active"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at" db:"expires_at"`
	KeyVersion int       `json:"key_version" db:"key_version"`
	Algorithm  string    `json:"algorithm" db:"algorithm"`
}

type Device struct {
	ID                string    `json:"id" db:"id"`
	UserID            string    `json:"user_id" db:"user_id"`
	DeviceName        string    `json:"device_name" db:"device_name"`
	DeviceFingerprint string    `json:"device_fingerprint" db:"device_fingerprint"`
	PublicKey         string    `json:"public_key" db:"public_key"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	LastUsed          time.Time `json:"last_used" db:"last_used"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	IPAddress         string    `json:"ip_address" db:"ip_address"`
	UserAgent         string    `json:"user_agent" db:"user_agent"`
	DeviceType        string    `json:"device_type" db:"device_type"`
}

type Account struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	ServiceName string    `json:"service_name" db:"service_name"`
	ServiceURL  string    `json:"service_url" db:"service_url"`
	SecretKey   string    `json:"-" db:"secret_key"`
	Algorithm   string    `json:"algorithm" db:"algorithm"`
	Digits      int       `json:"digits" db:"digits"`
	Period      int       `json:"period" db:"period"`
	Issuer      string    `json:"issuer" db:"issuer"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	LastUsed    *time.Time `json:"last_used" db:"last_used"`
	UsageCount  int       `json:"usage_count" db:"usage_count"`
}

type Business struct {
	ID           string                 `json:"id" db:"id"`
	CompanyName  string                 `json:"company_name" db:"company_name"`
	ContactEmail string                 `json:"contact_email" db:"contact_email"`
	APIKey       string                 `json:"api_key" db:"api_key"`
	APIKeyHash   string                 `json:"-" db:"api_key_hash"`
	Plan         string                 `json:"plan" db:"plan"`
	Settings     map[string]interface{} `json:"settings" db:"settings"`
	WebhookURL   string                 `json:"webhook_url" db:"webhook_url"`
	WebhookSecret string                `json:"-" db:"webhook_secret"`
	IsActive     bool                   `json:"is_active" db:"is_active"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	UsageLimit   int                    `json:"usage_limit" db:"usage_limit"`
	UsageCount   int                    `json:"usage_count" db:"usage_count"`
}

type BusinessUser struct {
	ID             string    `json:"id" db:"id"`
	BusinessID     string    `json:"business_id" db:"business_id"`
	UserID         string    `json:"user_id" db:"user_id"`
	ExternalUserID string    `json:"external_user_id" db:"external_user_id"`
	Role           string    `json:"role" db:"role"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
	LastActivity   *time.Time `json:"last_activity" db:"last_activity"`
}

type KeyRotation struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	OldKeyID     string    `json:"old_key_id" db:"old_key_id"`
	NewKeyID     string    `json:"new_key_id" db:"new_key_id"`
	RotationType string    `json:"rotation_type" db:"rotation_type"`
	RotationDate time.Time `json:"rotation_date" db:"rotation_date"`
	CleanupDate  *time.Time `json:"cleanup_date" db:"cleanup_date"`
	Status       string    `json:"status" db:"status"`
	ErrorMessage string    `json:"error_message" db:"error_message"`
	InitiatedBy  string    `json:"initiated_by" db:"initiated_by"`
}

type AuditLog struct {
	ID           string                 `json:"id" db:"id"`
	UserID       string                 `json:"user_id" db:"user_id"`
	BusinessID   string                 `json:"business_id" db:"business_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   string                 `json:"resource_id" db:"resource_id"`
	Details      map[string]interface{} `json:"details" db:"details"`
	IPAddress    string                 `json:"ip_address" db:"ip_address"`
	UserAgent    string                 `json:"user_agent" db:"user_agent"`
	SessionID    string                 `json:"session_id" db:"session_id"`
	RiskScore    int                    `json:"risk_score" db:"risk_score"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	RequestID    string                 `json:"request_id" db:"request_id"`
}

type Session struct {
	ID                string    `json:"id" db:"id"`
	UserID            string    `json:"user_id" db:"user_id"`
	DeviceID          string    `json:"device_id" db:"device_id"`
	TokenHash         string    `json:"-" db:"token_hash"`
	ExpiresAt         time.Time `json:"expires_at" db:"expires_at"`
	LastActivity      time.Time `json:"last_activity" db:"last_activity"`
	IPAddress         string    `json:"ip_address" db:"ip_address"`
	UserAgent         string    `json:"user_agent" db:"user_agent"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	RevokedAt         *time.Time `json:"revoked_at" db:"revoked_at"`
	RevocationReason  string    `json:"revocation_reason" db:"revocation_reason"`
}

type RateLimit struct {
	ID          string    `json:"id" db:"id"`
	Identifier  string    `json:"identifier" db:"identifier"`
	Action      string    `json:"action" db:"action"`
	Count       int       `json:"count" db:"count"`
	WindowStart time.Time `json:"window_start" db:"window_start"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
}

type BackupMetadata struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	BackupType string   `json:"backup_type" db:"backup_type"`
	FileSize  int64     `json:"file_size" db:"file_size"`
	Encrypted bool      `json:"encrypted" db:"encrypted"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at" db:"expires_at"`
	Checksum  string    `json:"checksum" db:"checksum"`
}