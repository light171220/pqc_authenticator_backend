package storage

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

func CreateUser(db *sql.DB, user *User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, user.ID, user.Username, user.Email, user.PasswordHash, user.RecoveryPhraseHash, user.CreatedAt, user.UpdatedAt)
	return err
}

func GetUserByID(db *sql.DB, userID string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at FROM users WHERE id = ?`
	row := db.QueryRow(query, userID)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at FROM users WHERE username = ?`
	row := db.QueryRow(query, username)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at FROM users WHERE email = ?`
	row := db.QueryRow(query, email)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func UpdateUser(db *sql.DB, user *User) error {
	query := `UPDATE users SET username = ?, email = ?, updated_at = ? WHERE id = ?`
	_, err := db.Exec(query, user.Username, user.Email, user.UpdatedAt, user.ID)
	return err
}

func GetAllUsers(db *sql.DB) ([]*User, error) {
	query := `SELECT id, username, email, password_hash, recovery_phrase_hash, created_at, updated_at FROM users`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.RecoveryPhraseHash, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

func CreateDevice(db *sql.DB, device *Device) error {
	query := `
		INSERT INTO devices (id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, device.ID, device.UserID, device.DeviceName, device.DeviceFingerprint, device.PublicKey, device.IsActive, device.LastUsed, device.CreatedAt)
	return err
}

func GetDeviceByID(db *sql.DB, deviceID string) (*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at FROM devices WHERE id = ?`
	row := db.QueryRow(query, deviceID)
	
	var device Device
	err := row.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, &device.IsActive, &device.LastUsed, &device.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func GetDeviceByFingerprint(db *sql.DB, userID, fingerprint string) (*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at FROM devices WHERE user_id = ? AND device_fingerprint = ?`
	row := db.QueryRow(query, userID, fingerprint)
	
	var device Device
	err := row.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, &device.IsActive, &device.LastUsed, &device.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func GetUserDevices(db *sql.DB, userID string) ([]*Device, error) {
	query := `SELECT id, user_id, device_name, device_fingerprint, public_key, is_active, last_used, created_at FROM devices WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		var device Device
		err := rows.Scan(&device.ID, &device.UserID, &device.DeviceName, &device.DeviceFingerprint, &device.PublicKey, &device.IsActive, &device.LastUsed, &device.CreatedAt)
		if err != nil {
			return nil, err
		}
		devices = append(devices, &device)
	}
	return devices, nil
}

func DeleteDevice(db *sql.DB, deviceID string) error {
	query := `DELETE FROM devices WHERE id = ?`
	_, err := db.Exec(query, deviceID)
	return err
}

func CreateAccount(db *sql.DB, account *Account) error {
	query := `
		INSERT INTO accounts (id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, account.ID, account.UserID, account.ServiceName, account.ServiceURL, account.SecretKey, account.Algorithm, account.Digits, account.Period, account.Issuer, account.CreatedAt)
	return err
}

func GetAccountByID(db *sql.DB, accountID string) (*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, created_at FROM accounts WHERE id = ?`
	row := db.QueryRow(query, accountID)
	
	var account Account
	err := row.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, &account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func GetAccountByServiceName(db *sql.DB, userID, serviceName string) (*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, created_at FROM accounts WHERE user_id = ? AND service_name = ?`
	row := db.QueryRow(query, userID, serviceName)
	
	var account Account
	err := row.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, &account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func GetUserAccounts(db *sql.DB, userID string) ([]*Account, error) {
	query := `SELECT id, user_id, service_name, service_url, secret_key, algorithm, digits, period, issuer, created_at FROM accounts WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var account Account
		err := rows.Scan(&account.ID, &account.UserID, &account.ServiceName, &account.ServiceURL, &account.SecretKey, &account.Algorithm, &account.Digits, &account.Period, &account.Issuer, &account.CreatedAt)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, &account)
	}
	return accounts, nil
}

func UpdateAccount(db *sql.DB, account *Account) error {
	query := `UPDATE accounts SET service_name = ?, service_url = ?, issuer = ? WHERE id = ?`
	_, err := db.Exec(query, account.ServiceName, account.ServiceURL, account.Issuer, account.ID)
	return err
}

func DeleteAccount(db *sql.DB, accountID string) error {
	query := `DELETE FROM accounts WHERE id = ?`
	_, err := db.Exec(query, accountID)
	return err
}

func CreateBusiness(db *sql.DB, business *Business) error {
	settingsJSON, err := json.Marshal(business.Settings)
	if err != nil {
		return err
	}
	
	query := `
		INSERT INTO businesses (id, company_name, contact_email, api_key, plan, settings, webhook_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = db.Exec(query, business.ID, business.CompanyName, business.ContactEmail, business.APIKey, business.Plan, string(settingsJSON), business.WebhookURL, business.CreatedAt)
	return err
}

func GetBusinessByID(db *sql.DB, businessID string) (*Business, error) {
	query := `SELECT id, company_name, contact_email, api_key, plan, settings, webhook_url, created_at FROM businesses WHERE id = ?`
	row := db.QueryRow(query, businessID)
	
	var business Business
	var settingsJSON string
	err := row.Scan(&business.ID, &business.CompanyName, &business.ContactEmail, &business.APIKey, &business.Plan, &settingsJSON, &business.WebhookURL, &business.CreatedAt)
	if err != nil {
		return nil, err
	}
	
	if err := json.Unmarshal([]byte(settingsJSON), &business.Settings); err != nil {
		business.Settings = make(map[string]interface{})
	}
	
	return &business, nil
}

func GetBusinessByAPIKey(db *sql.DB, apiKey string) (*Business, error) {
	query := `SELECT id, company_name, contact_email, api_key, plan, settings, webhook_url, created_at FROM businesses WHERE api_key = ?`
	row := db.QueryRow(query, apiKey)
	
	var business Business
	var settingsJSON string
	err := row.Scan(&business.ID, &business.CompanyName, &business.ContactEmail, &business.APIKey, &business.Plan, &settingsJSON, &business.WebhookURL, &business.CreatedAt)
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
		INSERT INTO business_users (id, business_id, user_id, external_user_id, is_active, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, businessUser.ID, businessUser.BusinessID, businessUser.UserID, businessUser.ExternalUserID, businessUser.IsActive, businessUser.CreatedAt)
	return err
}

func GetBusinessUser(db *sql.DB, businessID, userID string) (*BusinessUser, error) {
	query := `SELECT id, business_id, user_id, external_user_id, is_active, created_at FROM business_users WHERE business_id = ? AND user_id = ?`
	row := db.QueryRow(query, businessID, userID)
	
	var businessUser BusinessUser
	err := row.Scan(&businessUser.ID, &businessUser.BusinessID, &businessUser.UserID, &businessUser.ExternalUserID, &businessUser.IsActive, &businessUser.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &businessUser, nil
}

func CreateKeyRotation(db *sql.DB, keyRotation *KeyRotation) error {
	query := `
		INSERT INTO key_rotations (id, user_id, old_key_id, new_key_id, rotation_date, cleanup_date, public_key, private_key, encapsulated_secret)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, keyRotation.ID, keyRotation.UserID, keyRotation.OldKeyID, keyRotation.NewKeyID, keyRotation.RotationDate, keyRotation.CleanupDate, keyRotation.PublicKey, keyRotation.PrivateKey, keyRotation.EncapsulatedSecret)
	return err
}

func GetLatestKeyRotation(db *sql.DB, userID, keyID string) (*KeyRotation, error) {
	query := `SELECT id, user_id, old_key_id, new_key_id, rotation_date, cleanup_date, public_key, private_key, encapsulated_secret FROM key_rotations WHERE user_id = ? AND new_key_id = ? ORDER BY rotation_date DESC LIMIT 1`
	row := db.QueryRow(query, userID, keyID)
	
	var keyRotation KeyRotation
	err := row.Scan(&keyRotation.ID, &keyRotation.UserID, &keyRotation.OldKeyID, &keyRotation.NewKeyID, &keyRotation.RotationDate, &keyRotation.CleanupDate, &keyRotation.PublicKey, &keyRotation.PrivateKey, &keyRotation.EncapsulatedSecret)
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

func LogAuditEvent(db *sql.DB, userID, businessID, action string, details map[string]interface{}) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}
	
	query := `
		INSERT INTO audit_logs (id, user_id, business_id, action, details, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	ipAddress := ""
	userAgent := ""
	if details != nil {
		if ip, ok := details["ip_address"].(string); ok {
			ipAddress = ip
		}
		if ua, ok := details["user_agent"].(string); ok {
			userAgent = ua
		}
	}
	
	_, err = db.Exec(query, uuid.New().String(), userID, businessID, action, string(detailsJSON), ipAddress, userAgent, time.Now())
	return err
}

func GetAuditLogs(db *sql.DB, userID string, limit, offset int) ([]*AuditLog, error) {
	query := `SELECT id, user_id, business_id, action, details, ip_address, user_agent, created_at FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := db.Query(query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		var detailsJSON string
		err := rows.Scan(&log.ID, &log.UserID, &log.BusinessID, &log.Action, &detailsJSON, &log.IPAddress, &log.UserAgent, &log.CreatedAt)
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