package storage

import (
	"database/sql"
	"encoding/json"
	"time"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

func CreateUser(db *sql.DB, user *User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, user.ID, user.Username, user.Email, user.PasswordHash, user.RecoveryPhraseHash, 
		user.CreatedAt, user.UpdatedAt, user.IsActive)
	return err
}

func GetUserByID(db *sql.DB, userID string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at, is_active, 
		last_login, failed_login_attempts, locked_until FROM users WHERE id = ?`
	row := db.QueryRow(query, userID)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, 
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive, &user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at, is_active,
		last_login, failed_login_attempts, locked_until FROM users WHERE username = ?`
	row := db.QueryRow(query, username)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, 
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive, &user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at, is_active,
		last_login, failed_login_attempts, locked_until FROM users WHERE email = ?`
	row := db.QueryRow(query, email)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, 
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive, &user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func UpdateUser(db *sql.DB, user *User) error {
	query := `UPDATE users SET username = ?, email = ?, updated_at = ?, last_login = ?, 
		failed_login_attempts = ?, locked_until = ? WHERE id = ?`
	_, err := db.Exec(query, user.Username, user.Email, user.UpdatedAt, user.LastLogin, 
		user.FailedLoginAttempts, user.LockedUntil, user.ID)
	return err
}

func GetAllUsers(db *sql.DB) ([]*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at, is_active,
		last_login, failed_login_attempts, locked_until FROM users WHERE is_active = 1`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, 
			&user.CreatedAt, &user.UpdatedAt, &user.IsActive, &user.LastLogin, &user.FailedLoginAttempts, &user.LockedUntil)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

func CreateUserKeypair(db *sql.DB, keypair *UserKeypair) error {
	query := `
		INSERT INTO user_keypairs (id, user_id, public_key, private_key, is_active, created_at, expires_at, key_version, algorithm)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, keypair.ID, keypair.UserID, keypair.PublicKey, keypair.PrivateKey, 
		keypair.IsActive, keypair.CreatedAt, keypair.ExpiresAt, keypair.KeyVersion, keypair.Algorithm)
	return err
}

func GetUserKeypairByUserID(db *sql.DB, userID string) (*UserKeypair, error) {
	query := `SELECT id, user_id, public_key, private_key, is_active, created_at, expires_at, key_version, algorithm
		FROM user_keypairs WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1`
	row := db.QueryRow(query, userID)
	
	var keypair UserKeypair
	err := row.Scan(&keypair.ID, &keypair.UserID, &keypair.PublicKey, &keypair.PrivateKey, 
		&keypair.IsActive, &keypair.CreatedAt, &keypair.ExpiresAt, &keypair.KeyVersion, &keypair.Algorithm)
	if err != nil {
		return nil, err
	}
	return &keypair, nil
}

func GetUserKeypairByID(db *sql.DB, keypairID string) (*UserKeypair, error) {
	query := `SELECT id, user_id, public_key, private_key, is_active, created_at, expires_at, key_version, algorithm
		FROM user_keypairs WHERE id = ?`
	row := db.QueryRow(query, keypairID)
	
	var keypair UserKeypair
	err := row.Scan(&keypair.ID, &keypair.UserID, &keypair.PublicKey, &keypair.PrivateKey, 
		&keypair.IsActive, &keypair.CreatedAt, &keypair.ExpiresAt, &keypair.KeyVersion, &keypair.Algorithm)
	if err != nil {
		return nil, err
	}
	return &keypair, nil
}

func UpdateUserKeypairStatus(db *sql.DB, keypairID string, isActive bool) error {
	query := `UPDATE user_keypairs SET is_active = ? WHERE id = ?`
	_, err := db.Exec(query, isActive, keypairID)
	return err
}

func DeactivateUserKeypairs(db *sql.DB, userID string) error {
	query := `UPDATE user_keypairs SET is_active = 0 WHERE user_id = ?`
	_, err := db.Exec(query, userID)
	return err
}

func CreateDevice(db *sql.DB, device *Device) error {
	query := `
		INSERT INTO devices (id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at, ip_address, user_agent, device_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, device.ID, device.UserID, device.DeviceName, device.DeviceFingerprint, device.PublicKey, 
		device.IsActive, device.LastUsed, device.CreatedAt, device.IPAddress, device.UserAgent, device.DeviceType)
	return err
}

func GetDeviceByID(db *sql.DB, deviceID string) (*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at, 
		ip_address, user_agent, device_type FROM devices WHERE id = ?`
	row := db.QueryRow(query, deviceID)
	
	var device Device
	err := row.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, 
		&device.IsActive, &device.LastUsed, &device.CreatedAt, &device.IPAddress, &device.UserAgent, &device.DeviceType)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func GetDeviceByFingerprint(db *sql.DB, userID, fingerprint string) (*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at,
		ip_address, user_agent, device_type FROM devices WHERE user_id = ? AND device_fingerprint = ?`
	row := db.QueryRow(query, userID, fingerprint)
	
	var device Device
	err := row.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, 
		&device.IsActive, &device.LastUsed, &device.CreatedAt, &device.IPAddress, &device.UserAgent, &device.DeviceType)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func GetUserDevices(db *sql.DB, userID string) ([]*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at,
		ip_address, user_agent, device_type FROM devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		var device Device
		err := rows.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, 
			&device.IsActive, &device.LastUsed, &device.CreatedAt, &device.IPAddress, &device.UserAgent, &device.DeviceType)
		if err != nil {
			return nil, err
		}
		devices = append(devices, &device)
	}
	return devices, nil
}

func UpdateDeviceLastUsed(db *sql.DB, deviceID string) error {
	query := `UPDATE devices SET last_used = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.Exec(query, deviceID)
	return err
}

func DeleteDevice(db *sql.DB, deviceID string) error {
	query := `DELETE FROM devices WHERE id = ?`
	_, err := db.Exec(query, deviceID)
	return err
}

func CreateAccount(db *sql.DB, account *Account) error {
	query := `
		INSERT INTO accounts (id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, created_at, updated_at, is_active, usage_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, account.ID, account.UserID, account.ServiceName, account.ServiceURL, account.SecretKey, 
		account.Algorithm, account.Digits, account.Period, account.Issuer, account.CreatedAt, account.UpdatedAt, account.IsActive, account.UsageCount)
	return err
}

func GetAccountByID(db *sql.DB, accountID string) (*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, 
		created_at, updated_at, is_active, last_used, usage_count FROM accounts WHERE id = ?`
	row := db.QueryRow(query, accountID)
	
	var account Account
	err := row.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, 
		&account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt, &account.UpdatedAt,
		&account.IsActive, &account.LastUsed, &account.UsageCount)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func GetAccountByServiceName(db *sql.DB, userID, serviceName string) (*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, 
		created_at, updated_at, is_active, last_used, usage_count FROM accounts WHERE user_id = ? AND service_name = ?`
	row := db.QueryRow(query, userID, serviceName)
	
	var account Account
	err := row.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, 
		&account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt, &account.UpdatedAt,
		&account.IsActive, &account.LastUsed, &account.UsageCount)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func GetUserAccounts(db *sql.DB, userID string) ([]*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, 
		created_at, updated_at, is_active, last_used, usage_count FROM accounts WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var account Account
		err := rows.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, 
			&account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt, &account.UpdatedAt,
			&account.IsActive, &account.LastUsed, &account.UsageCount)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, &account)
	}
	return accounts, nil
}

func UpdateAccount(db *sql.DB, account *Account) error {
	query := `UPDATE accounts SET service_name = ?, service_url = ?, issuer = ?, updated_at = ?, last_used = ? WHERE id = ?`
	_, err := db.Exec(query, account.ServiceName, account.ServiceURL, account.Issuer, account.UpdatedAt, account.LastUsed, account.ID)
	return err
}

func DeleteAccount(db *sql.DB, accountID string) error {
	query := `UPDATE accounts SET is_active = 0 WHERE id = ?`
	_, err := db.Exec(query, accountID)
	return err
}

func CreateBusiness(db *sql.DB, business *Business) error {
	settingsJSON, err := json.Marshal(business.Settings)
	if err != nil {
		return err
	}
	
	hash := sha256.Sum256([]byte(business.APIKey))
	apiKeyHash := hex.EncodeToString(hash[:])
	
	query := `
		INSERT INTO businesses (id, company_name, contact_email, api_key, api_key_hash, plan, settings, webhook_url, webhook_secret, is_active, created_at, updated_at, usage_limit, usage_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = db.Exec(query, business.ID, business.CompanyName, business.ContactEmail, business.APIKey, apiKeyHash, business.Plan, 
		string(settingsJSON), business.WebhookURL, business.WebhookSecret, business.IsActive, business.CreatedAt, business.UpdatedAt, 
		business.UsageLimit, business.UsageCount)
	return err
}

func GetBusinessByID(db *sql.DB, businessID string) (*Business, error) {
	query := `SELECT id, company_name, contact_email, api_key, plan, settings, webhook_url, is_active, created_at, updated_at, usage_limit, usage_count 
		FROM businesses WHERE id = ?`
	row := db.QueryRow(query, businessID)
	
	var business Business
	var settingsJSON string
	err := row.Scan(&business.ID, &business.CompanyName, &business.ContactEmail, &business.APIKey, &business.Plan, 
		&settingsJSON, &business.WebhookURL, &business.IsActive, &business.CreatedAt, &business.UpdatedAt, 
		&business.UsageLimit, &business.UsageCount)
	if err != nil {
		return nil, err
	}
	
	if err := json.Unmarshal([]byte(settingsJSON), &business.Settings); err != nil {
		business.Settings = make(map[string]interface{})
	}
	
	return &business, nil
}

func GetBusinessByAPIKey(db *sql.DB, apiKey string) (*Business, error) {
	query := `SELECT id, company_name, contact_email, api_key, plan, settings, webhook_url, is_active, created_at, updated_at, usage_limit, usage_count 
		FROM businesses WHERE api_key = ? AND is_active = 1`
	row := db.QueryRow(query, apiKey)
	
	var business Business
	var settingsJSON string
	err := row.Scan(&business.ID, &business.CompanyName, &business.ContactEmail, &business.APIKey, &business.Plan, 
		&settingsJSON, &business.WebhookURL, &business.IsActive, &business.CreatedAt, &business.UpdatedAt, 
		&business.UsageLimit, &business.UsageCount)
	if err != nil {
		return nil, err
	}
	
	if err := json.Unmarshal([]byte(settingsJSON), &business.Settings); err != nil {
		business.Settings = make(map[string]interface{})
	}
	
	return &business, nil
}

func CreateBusinessUser(db *sql.DB, businessUser *BusinessUser) error {
	query := `
		INSERT INTO business_users (id, business_id, user_id, external_user_id, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, businessUser.ID, businessUser.BusinessID, businessUser.UserID, businessUser.ExternalUserID, 
		businessUser.Role, businessUser.IsActive, businessUser.CreatedAt, businessUser.UpdatedAt)
	return err
}

func GetBusinessUser(db *sql.DB, businessID, userID string) (*BusinessUser, error) {
	query := `SELECT id, business_id, user_id, external_user_id, role, is_active, created_at, updated_at, last_activity 
		FROM business_users WHERE business_id = ? AND user_id = ?`
	row := db.QueryRow(query, businessID, userID)
	
	var businessUser BusinessUser
	err := row.Scan(&businessUser.ID, &businessUser.BusinessID, &businessUser.UserID, &businessUser.ExternalUserID, 
		&businessUser.Role, &businessUser.IsActive, &businessUser.CreatedAt, &businessUser.UpdatedAt, &businessUser.LastActivity)
	if err != nil {
		return nil, err
	}
	return &businessUser, nil
}

func GetBusinessUserByExternalID(db *sql.DB, businessID, externalUserID string) (*BusinessUser, error) {
	query := `SELECT id, business_id, user_id, external_user_id, role, is_active, created_at, updated_at, last_activity 
		FROM business_users WHERE business_id = ? AND external_user_id = ?`
	row := db.QueryRow(query, businessID, externalUserID)
	
	var businessUser BusinessUser
	err := row.Scan(&businessUser.ID, &businessUser.BusinessID, &businessUser.UserID, &businessUser.ExternalUserID, 
		&businessUser.Role, &businessUser.IsActive, &businessUser.CreatedAt, &businessUser.UpdatedAt, &businessUser.LastActivity)
	if err != nil {
		return nil, err
	}
	return &businessUser, nil
}

func CreateKeyRotation(db *sql.DB, keyRotation *KeyRotation) error {
	query := `
		INSERT INTO key_rotations (id, user_id, old_key_id, new_key_id, rotation_type, rotation_date, cleanup_date, status, error_message, initiated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, keyRotation.ID, keyRotation.UserID, keyRotation.OldKeyID, keyRotation.NewKeyID, 
		keyRotation.RotationType, keyRotation.RotationDate, keyRotation.CleanupDate, keyRotation.Status, 
		keyRotation.ErrorMessage, keyRotation.InitiatedBy)
	return err
}

func GetLatestKeyRotation(db *sql.DB, userID, keyID string) (*KeyRotation, error) {
	query := `SELECT id, user_id, old_key_id, new_key_id, rotation_type, rotation_date, cleanup_date, status, error_message, initiated_by 
		FROM key_rotations WHERE user_id = ? AND new_key_id = ? ORDER BY rotation_date DESC LIMIT 1`
	row := db.QueryRow(query, userID, keyID)
	
	var keyRotation KeyRotation
	err := row.Scan(&keyRotation.ID, &keyRotation.UserID, &keyRotation.OldKeyID, &keyRotation.NewKeyID, 
		&keyRotation.RotationType, &keyRotation.RotationDate, &keyRotation.CleanupDate, &keyRotation.Status, 
		&keyRotation.ErrorMessage, &keyRotation.InitiatedBy)
	if err != nil {
		return nil, err
	}
	return &keyRotation, nil
}

func CleanupOldKeyRotations(db *sql.DB, cutoffTime time.Time) (int64, error) {
	query := `DELETE FROM key_rotations WHERE cleanup_date < ?`
	result, err := db.Exec(query, cutoffTime)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func CreateSession(db *sql.DB, session *Session) error {
	query := `
		INSERT INTO sessions (id, user_id, device_id, token_hash, expires_at, last_activity, ip_address, user_agent, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, session.ID, session.UserID, session.DeviceID, session.TokenHash, session.ExpiresAt, 
		session.LastActivity, session.IPAddress, session.UserAgent, session.IsActive, session.CreatedAt)
	return err
}

func GetSessionByToken(db *sql.DB, tokenHash string) (*Session, error) {
	query := `SELECT id, user_id, device_id, token_hash, expires_at, last_activity, ip_address, user_agent, is_active, created_at, revoked_at, revocation_reason 
		FROM sessions WHERE token_hash = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP`
	row := db.QueryRow(query, tokenHash)
	
	var session Session
	err := row.Scan(&session.ID, &session.UserID, &session.DeviceID, &session.TokenHash, &session.ExpiresAt, 
		&session.LastActivity, &session.IPAddress, &session.UserAgent, &session.IsActive, &session.CreatedAt, 
		&session.RevokedAt, &session.RevocationReason)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func GetSessionsByUserID(db *sql.DB, userID string) ([]*Session, error) {
	query := `SELECT id, user_id, device_id, token_hash, expires_at, last_activity, ip_address, user_agent, is_active, created_at, revoked_at, revocation_reason 
		FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY last_activity DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		err := rows.Scan(&session.ID, &session.UserID, &session.DeviceID, &session.TokenHash, &session.ExpiresAt, 
			&session.LastActivity, &session.IPAddress, &session.UserAgent, &session.IsActive, &session.CreatedAt, 
			&session.RevokedAt, &session.RevocationReason)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &session)
	}
	return sessions, nil
}

func UpdateSessionActivity(db *sql.DB, sessionID string) error {
	query := `UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := db.Exec(query, sessionID)
	return err
}

func RevokeSession(db *sql.DB, sessionID, reason string) error {
	query := `UPDATE sessions SET is_active = 0, revoked_at = CURRENT_TIMESTAMP, revocation_reason = ? WHERE id = ?`
	_, err := db.Exec(query, reason, sessionID)
	return err
}

func RevokeAllUserSessions(db *sql.DB, userID, reason string) error {
	query := `UPDATE sessions SET is_active = 0, revoked_at = CURRENT_TIMESTAMP, revocation_reason = ? WHERE user_id = ? AND is_active = 1`
	_, err := db.Exec(query, reason, userID)
	return err
}

func LogAuditEvent(db *sql.DB, userID, businessID, action string, details map[string]interface{}) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}
	
	query := `
		INSERT INTO audit_logs (id, user_id, business_id, action, details, ip_address, user_agent, session_id, request_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	ipAddress := ""
	userAgent := ""
	sessionID := ""
	requestID := ""
	
	if details != nil {
		if ip, ok := details["ip_address"].(string); ok {
			ipAddress = ip
		}
		if ua, ok := details["user_agent"].(string); ok {
			userAgent = ua
		}
		if sid, ok := details["session_id"].(string); ok {
			sessionID = sid
		}
		if rid, ok := details["request_id"].(string); ok {
			requestID = rid
		}
	}
	
	_, err = db.Exec(query, uuid.New().String(), userID, businessID, action, string(detailsJSON), 
		ipAddress, userAgent, sessionID, requestID, time.Now())
	return err
}

func GetAuditLogs(db *sql.DB, userID string, limit, offset int) ([]*AuditLog, error) {
	query := `SELECT id, user_id, business_id, action, resource_type, resource_id, details, ip_address, user_agent, session_id, risk_score, created_at, request_id 
		FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.Query(query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var detailsJSON string
		err := rows.Scan(&log.ID, &log.UserID, &log.BusinessID, &log.Action, &log.ResourceType, &log.ResourceID, 
			&detailsJSON, &log.IPAddress, &log.UserAgent, &log.SessionID, &log.RiskScore, &log.CreatedAt, &log.RequestID)
		if err != nil {
			return nil, err
		}
		
		if err := json.Unmarshal([]byte(detailsJSON), &log.Details); err != nil {
			log.Details = make(map[string]interface{})
		}
		
		logs = append(logs, &log)
	}
	return logs, nil
}