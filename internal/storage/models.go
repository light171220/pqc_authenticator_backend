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
}

type Business struct {
	ID           string                 `json:"id" db:"id"`
	CompanyName  string                 `json:"company_name" db:"company_name"`
	ContactEmail string                 `json:"contact_email" db:"contact_email"`
	APIKey       string                 `json:"api_key" db:"api_key"`
	Plan         string                 `json:"plan" db:"plan"`
	Settings     map[string]interface{} `json:"settings" db:"settings"`
	WebhookURL   string                 `json:"webhook_url" db:"webhook_url"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

type BusinessUser struct {
	ID             string    `json:"id" db:"id"`
	BusinessID     string    `json:"business_id" db:"business_id"`
	UserID         string    `json:"user_id" db:"user_id"`
	ExternalUserID string    `json:"external_user_id" db:"external_user_id"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type KeyRotation struct {
	ID                 string    `json:"id" db:"id"`
	UserID             string    `json:"user_id" db:"user_id"`
	OldKeyID           string    `json:"old_key_id" db:"old_key_id"`
	NewKeyID           string    `json:"new_key_id" db:"new_key_id"`
	RotationDate       time.Time `json:"rotation_date" db:"rotation_date"`
	CleanupDate        time.Time `json:"cleanup_date" db:"cleanup_date"`
	PublicKey          string    `json:"public_key" db:"public_key"`
	PrivateKey         string    `json:"private_key" db:"private_key"`
	EncapsulatedSecret string    `json:"encapsulated_secret" db:"encapsulated_secret"`
}

type AuditLog struct {
	ID         string                 `json:"id" db:"id"`
	UserID     string                 `json:"user_id" db:"user_id"`
	BusinessID string                 `json:"business_id" db:"business_id"`
	Action     string                 `json:"action" db:"action"`
	Details    map[string]interface{} `json:"details" db:"details"`
	IPAddress  string                 `json:"ip_address" db:"ip_address"`
	UserAgent  string                 `json:"user_agent" db:"user_agent"`
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
}