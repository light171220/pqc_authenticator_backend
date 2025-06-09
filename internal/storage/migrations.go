package storage

import (
	"database/sql"
	"fmt"
)

var migrations = []string{
	`
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash BLOB NOT NULL,
		recovery_phrase_hash BLOB,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, device_fingerprint)
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
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS businesses (
		id TEXT PRIMARY KEY,
		company_name TEXT NOT NULL,
		contact_email TEXT NOT NULL,
		api_key TEXT UNIQUE NOT NULL,
		plan TEXT DEFAULT 'basic',
		settings TEXT DEFAULT '{}',
		webhook_url TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS business_users (
		id TEXT PRIMARY KEY,
		business_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		external_user_id TEXT NOT NULL,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(business_id, user_id),
		UNIQUE(business_id, external_user_id)
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS key_rotations (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		old_key_id TEXT,
		new_key_id TEXT NOT NULL,
		rotation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
		cleanup_date DATETIME,
		public_key TEXT,
		private_key TEXT,
		encapsulated_secret TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`,
	`
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		business_id TEXT,
		action TEXT NOT NULL,
		details TEXT DEFAULT '{}',
		ip_address TEXT,
		user_agent TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
		FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE SET NULL
	);
	`,
	`
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(device_fingerprint);
	CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);
	CREATE INDEX IF NOT EXISTS idx_businesses_api_key ON businesses(api_key);
	CREATE INDEX IF NOT EXISTS idx_business_users_business_id ON business_users(business_id);
	CREATE INDEX IF NOT EXISTS idx_business_users_user_id ON business_users(user_id);
	CREATE INDEX IF NOT EXISTS idx_key_rotations_user_id ON key_rotations(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_business_id ON audit_logs(business_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	`,
}

func RunMigrations(db *sql.DB) error {
	for i, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("failed to run migration %d: %w", i+1, err)
		}
	}
	return nil
}