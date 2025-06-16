package storage

import (
	"database/sql"
	"fmt"
	"time"
)

var migrations = []string{
	`
	PRAGMA foreign_keys = ON;
	PRAGMA journal_mode = WAL;
	PRAGMA synchronous = NORMAL;
	PRAGMA cache_size = -64000;
	PRAGMA temp_store = memory;
	PRAGMA mmap_size = 268435456;
	`,
	`
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash BLOB NOT NULL,
		recovery_phrase_hash BLOB,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN DEFAULT 1,
		last_login DATETIME,
		failed_login_attempts INTEGER DEFAULT 0,
		locked_until DATETIME,
		email_verified BOOLEAN DEFAULT 0,
		email_verification_token TEXT,
		password_reset_token TEXT,
		password_reset_expires DATETIME,
		CONSTRAINT chk_username_length CHECK (length(username) >= 3 AND length(username) <= 50),
		CONSTRAINT chk_email_format CHECK (email LIKE '%@%.%'),
		CONSTRAINT chk_failed_attempts CHECK (failed_login_attempts >= 0)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS user_keypairs (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		key_version INTEGER DEFAULT 1,
		algorithm TEXT DEFAULT 'dilithium-mode3',
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT chk_single_active_key UNIQUE (user_id, is_active),
		CONSTRAINT chk_key_version CHECK (key_version > 0)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		device_name TEXT NOT NULL,
		device_fingerprint TEXT NOT NULL,
		public_key TEXT NOT NULL,
		is_active BOOLEAN DEFAULT 1,
		last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT,
		device_type TEXT DEFAULT 'unknown',
		push_token TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, device_fingerprint),
		CONSTRAINT chk_device_name_length CHECK (length(device_name) >= 1 AND length(device_name) <= 100)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		service_name TEXT NOT NULL,
		service_url TEXT,
		secret_key TEXT NOT NULL,
		algorithm TEXT DEFAULT 'SHAKE256',
		digits INTEGER DEFAULT 6,
		period INTEGER DEFAULT 30,
		issuer TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN DEFAULT 1,
		last_used DATETIME,
		usage_count INTEGER DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT chk_digits_range CHECK (digits >= 6 AND digits <= 8),
		CONSTRAINT chk_period_range CHECK (period >= 15 AND period <= 300),
		CONSTRAINT chk_service_name_length CHECK (length(service_name) >= 1 AND length(service_name) <= 100),
		CONSTRAINT chk_usage_count CHECK (usage_count >= 0),
		UNIQUE(user_id, service_name)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS businesses (
		id TEXT PRIMARY KEY,
		company_name TEXT NOT NULL,
		contact_email TEXT NOT NULL,
		api_key TEXT UNIQUE NOT NULL,
		api_key_hash TEXT NOT NULL,
		plan TEXT DEFAULT 'basic',
		settings TEXT DEFAULT '{}',
		webhook_url TEXT,
		webhook_secret TEXT,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		subscription_expires DATETIME,
		usage_limit INTEGER DEFAULT 1000,
		usage_count INTEGER DEFAULT 0,
		CONSTRAINT chk_plan_type CHECK (plan IN ('basic', 'pro', 'enterprise')),
		CONSTRAINT chk_company_name_length CHECK (length(company_name) >= 1 AND length(company_name) <= 200),
		CONSTRAINT chk_contact_email_format CHECK (contact_email LIKE '%@%.%'),
		CONSTRAINT chk_usage_count CHECK (usage_count >= 0),
		CONSTRAINT chk_usage_limit CHECK (usage_limit > 0)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS business_users (
		id TEXT PRIMARY KEY,
		business_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		external_user_id TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		permissions TEXT DEFAULT '{}',
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_activity DATETIME,
		FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(business_id, user_id),
		UNIQUE(business_id, external_user_id),
		CONSTRAINT chk_role_type CHECK (role IN ('admin', 'user', 'readonly'))
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS key_rotations (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		old_key_id TEXT,
		new_key_id TEXT NOT NULL,
		rotation_type TEXT DEFAULT 'scheduled',
		rotation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
		cleanup_date DATETIME,
		status TEXT DEFAULT 'completed',
		error_message TEXT,
		initiated_by TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT chk_rotation_type CHECK (rotation_type IN ('scheduled', 'forced', 'emergency', 'manual')),
		CONSTRAINT chk_status CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'rolled_back'))
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		business_id TEXT,
		action TEXT NOT NULL,
		resource_type TEXT,
		resource_id TEXT,
		details TEXT DEFAULT '{}',
		ip_address TEXT,
		user_agent TEXT,
		session_id TEXT,
		risk_score INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_id TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
		FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE SET NULL,
		CONSTRAINT chk_risk_score CHECK (risk_score >= 0 AND risk_score <= 100)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS rate_limits (
		id TEXT PRIMARY KEY,
		identifier TEXT NOT NULL,
		action TEXT NOT NULL,
		count INTEGER DEFAULT 1,
		window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		UNIQUE(identifier, action)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		device_id TEXT,
		token_hash TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		revoked_at DATETIME,
		revocation_reason TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS backup_metadata (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		backup_type TEXT NOT NULL,
		file_size INTEGER,
		encrypted BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		checksum TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		CONSTRAINT chk_backup_type CHECK (backup_type IN ('full', 'incremental', 'accounts_only'))
	);
	`,
	`
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
	CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_until);
	CREATE INDEX IF NOT EXISTS idx_user_keypairs_user_id ON user_keypairs(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_keypairs_active ON user_keypairs(user_id, is_active);
	CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(device_fingerprint);
	CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active);
	CREATE INDEX IF NOT EXISTS idx_devices_last_used ON devices(last_used);
	CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
	CREATE INDEX IF NOT EXISTS idx_accounts_active ON accounts(is_active);
	CREATE INDEX IF NOT EXISTS idx_accounts_last_used ON accounts(last_used);
	CREATE INDEX IF NOT EXISTS idx_businesses_api_key ON businesses(api_key);
	CREATE INDEX IF NOT EXISTS idx_businesses_active ON businesses(is_active);
	CREATE INDEX IF NOT EXISTS idx_business_users_business_id ON business_users(business_id);
	CREATE INDEX IF NOT EXISTS idx_business_users_user_id ON business_users(user_id);
	CREATE INDEX IF NOT EXISTS idx_business_users_active ON business_users(is_active);
	CREATE INDEX IF NOT EXISTS idx_key_rotations_user_id ON key_rotations(user_id);
	CREATE INDEX IF NOT EXISTS idx_key_rotations_date ON key_rotations(rotation_date);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_business_id ON audit_logs(business_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);
	CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, action);
	CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);
	CREATE INDEX IF NOT EXISTS idx_backup_metadata_user_id ON backup_metadata(user_id);
	CREATE INDEX IF NOT EXISTS idx_backup_metadata_created_at ON backup_metadata(created_at);
	`,
	`
	CREATE TRIGGER IF NOT EXISTS update_users_updated_at 
	AFTER UPDATE ON users 
	FOR EACH ROW 
	WHEN NEW.updated_at = OLD.updated_at
	BEGIN 
		UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; 
	END;
	`,
	`
	CREATE TRIGGER IF NOT EXISTS update_accounts_updated_at 
	AFTER UPDATE ON accounts 
	FOR EACH ROW 
	WHEN NEW.updated_at = OLD.updated_at
	BEGIN 
		UPDATE accounts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; 
	END;
	`,
	`
	CREATE TRIGGER IF NOT EXISTS update_businesses_updated_at 
	AFTER UPDATE ON businesses 
	FOR EACH ROW 
	WHEN NEW.updated_at = OLD.updated_at
	BEGIN 
		UPDATE businesses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; 
	END;
	`,
	`
	CREATE TRIGGER IF NOT EXISTS cleanup_expired_sessions
	AFTER INSERT ON sessions
	FOR EACH ROW
	BEGIN
		DELETE FROM sessions WHERE expires_at < datetime('now', '-1 hour');
	END;
	`,
	`
	CREATE TRIGGER IF NOT EXISTS cleanup_expired_rate_limits
	AFTER INSERT ON rate_limits
	FOR EACH ROW
	BEGIN
		DELETE FROM rate_limits WHERE expires_at < datetime('now', '-1 hour');
	END;
	`,
	`
	CREATE TRIGGER IF NOT EXISTS increment_account_usage
	AFTER UPDATE OF last_used ON accounts
	FOR EACH ROW
	WHEN NEW.last_used > OLD.last_used
	BEGIN
		UPDATE accounts SET usage_count = usage_count + 1 WHERE id = NEW.id;
	END;
	`,
	`
	CREATE VIEW IF NOT EXISTS active_sessions AS
	SELECT s.*, u.username, u.email
	FROM sessions s
	JOIN users u ON s.user_id = u.id
	WHERE s.is_active = 1 AND s.expires_at > CURRENT_TIMESTAMP;
	`,
	`
	CREATE VIEW IF NOT EXISTS user_statistics AS
	SELECT 
		u.id,
		u.username,
		u.email,
		u.created_at,
		u.last_login,
		COUNT(DISTINCT a.id) as account_count,
		COUNT(DISTINCT d.id) as device_count,
		COUNT(DISTINCT s.id) as active_session_count
	FROM users u
	LEFT JOIN accounts a ON u.id = a.user_id AND a.is_active = 1
	LEFT JOIN devices d ON u.id = d.user_id AND d.is_active = 1
	LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = 1 AND s.expires_at > CURRENT_TIMESTAMP
	WHERE u.is_active = 1
	GROUP BY u.id;
	`,
}

func RunMigrations(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migration transaction start failed: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			execution_time_ms INTEGER DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("schema_migrations table creation failed: %w", err)
	}

	var lastVersion int
	err = tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&lastVersion)
	if err != nil {
		return fmt.Errorf("last migration version query failed: %w", err)
	}

	for i := lastVersion; i < len(migrations); i++ {
		start := time.Now()
		
		if _, err := tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d execution failed: %w", i+1, err)
		}

		executionTime := time.Since(start).Milliseconds()
		_, err = tx.Exec("INSERT INTO schema_migrations (version, execution_time_ms) VALUES (?, ?)", 
			i+1, executionTime)
		if err != nil {
			return fmt.Errorf("migration %d recording failed: %w", i+1, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration transaction commit failed: %w", err)
	}

	return nil
}

func GetMigrationStatus(db *sql.DB) ([]MigrationInfo, error) {
	rows, err := db.Query(`
		SELECT version, applied_at, execution_time_ms 
		FROM schema_migrations 
		ORDER BY version ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("migration status query failed: %w", err)
	}
	defer rows.Close()

	var migrations []MigrationInfo
	for rows.Next() {
		var migration MigrationInfo
		err := rows.Scan(&migration.Version, &migration.AppliedAt, &migration.ExecutionTimeMs)
		if err != nil {
			return nil, fmt.Errorf("migration status scan failed: %w", err)
		}
		migrations = append(migrations, migration)
	}

	return migrations, nil
}

type MigrationInfo struct {
	Version         int       `json:"version"`
	AppliedAt       time.Time `json:"applied_at"`
	ExecutionTimeMs int64     `json:"execution_time_ms"`
}