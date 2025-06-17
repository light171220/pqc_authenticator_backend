package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Security SecurityConfig `yaml:"security"`
	TOTP     TOTPConfig     `yaml:"totp"`
	Business BusinessConfig `yaml:"business"`
	Logging  LoggingConfig  `yaml:"logging"`
	CORS     CORSConfig     `yaml:"cors"`
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Mode         string        `yaml:"mode"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	MaxHeaderBytes int         `yaml:"max_header_bytes"`
}

type DatabaseConfig struct {
	Type           string        `yaml:"type"`
	Path           string        `yaml:"path"`
	URL            string        `yaml:"url"`
	MaxConnections int           `yaml:"max_connections"`
	MaxRetries     int           `yaml:"max_retries"`
	RetryDelay     time.Duration `yaml:"retry_delay"`
}

type SecurityConfig struct {
	JWTSecret           string        `yaml:"-"`
	EncryptionKey       string        `yaml:"-"`
	RateLimitRequests   int           `yaml:"rate_limit_requests"`
	RateLimitWindow     time.Duration `yaml:"rate_limit_window"`
	RequireStrongAuth   bool          `yaml:"require_strong_auth"`
	SessionTimeout      time.Duration `yaml:"session_timeout"`
	ForceSecureSecrets  bool          `yaml:"force_secure_secrets"`
	MaxLoginAttempts    int           `yaml:"max_login_attempts"`
	LockoutDuration     time.Duration `yaml:"lockout_duration"`
	TLSCertFile         string        `yaml:"tls_cert_file"`
	TLSKeyFile          string        `yaml:"tls_key_file"`
}

type TOTPConfig struct {
	DefaultPeriod         int           `yaml:"default_period"`
	DefaultDigits         int           `yaml:"default_digits"`
	KeyRotationInterval   time.Duration `yaml:"key_rotation_interval"`
	BackupKeyRetention    time.Duration `yaml:"backup_key_retention"`
	RequireSignature      bool          `yaml:"require_signature"`
	MaxClockSkew          time.Duration `yaml:"max_clock_skew"`
	MaxGenerationsPerHour int           `yaml:"max_generations_per_hour"`
}

type BusinessConfig struct {
	WebhookTimeout      time.Duration `yaml:"webhook_timeout"`
	AnalyticsRetention  time.Duration `yaml:"analytics_retention"`
	MaxIntegrations     int           `yaml:"max_integrations"`
	RequireWhitelist    bool          `yaml:"require_whitelist"`
}

type LoggingConfig struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	Output      string `yaml:"output"`
	AuditLevel  string `yaml:"audit_level"`
	MaxFileSize string `yaml:"max_file_size"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"`
	ExposedHeaders   []string `yaml:"expose_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`
}

func LoadConfig() (*Config, error) {
	config := getDefaultConfig()

	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		if err := loadConfigFromFile(config, configFile); err != nil {
			return nil, fmt.Errorf("config file load failed: %w", err)
		}
	}

	overrideWithEnvVars(config)

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	if err := loadSecretsFromEnv(config); err != nil {
		return nil, fmt.Errorf("secrets load failed: %w", err)
	}

	return config, nil
}

func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           getEnvOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:           getEnvIntOrDefault("SERVER_PORT", 8443),
			Mode:           getEnvOrDefault("SERVER_MODE", "release"),
			ReadTimeout:    15 * time.Second,
			WriteTimeout:   15 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
		Database: DatabaseConfig{
			Type:           getEnvOrDefault("DATABASE_TYPE", "sqlite"),
			Path:           getEnvOrDefault("DATABASE_PATH", "/app/data/authenticator.db"),
			URL:            getEnvOrDefault("DATABASE_URL", ""),
			MaxConnections: getEnvIntOrDefault("DATABASE_MAX_CONNECTIONS", 50),
			MaxRetries:     5,
			RetryDelay:     2 * time.Second,
		},
		Security: SecurityConfig{
			RateLimitRequests:   getEnvIntOrDefault("RATE_LIMIT_REQUESTS", 50),
			RateLimitWindow:     time.Minute,
			RequireStrongAuth:   true,
			SessionTimeout:      8 * time.Hour,
			ForceSecureSecrets:  true,
			MaxLoginAttempts:    3,
			LockoutDuration:     30 * time.Minute,
			TLSCertFile:         getEnvOrDefault("TLS_CERT_FILE", ""),
			TLSKeyFile:          getEnvOrDefault("TLS_KEY_FILE", ""),
		},
		TOTP: TOTPConfig{
			DefaultPeriod:         30,
			DefaultDigits:         6,
			KeyRotationInterval:   24 * time.Hour,
			BackupKeyRetention:    72 * time.Hour,
			RequireSignature:      true,
			MaxClockSkew:          30 * time.Second,
			MaxGenerationsPerHour: 100,
		},
		Business: BusinessConfig{
			WebhookTimeout:     5 * time.Second,
			AnalyticsRetention: 365 * 24 * time.Hour,
			MaxIntegrations:    5,
			RequireWhitelist:   true,
		},
		Logging: LoggingConfig{
			Level:       getEnvOrDefault("LOG_LEVEL", "info"),
			Format:      "json",
			Output:      getEnvOrDefault("LOG_OUTPUT", "stdout"),
			AuditLevel:  "info",
			MaxFileSize: "500MB",
		},
		CORS: CORSConfig{
			AllowedOrigins:   strings.Split(getEnvOrDefault("CORS_ALLOWED_ORIGINS", ""), ","),
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-API-Key"},
			ExposedHeaders:   []string{"X-Total-Count", "X-Rate-Limit"},
			AllowCredentials: true,
			MaxAge:           86400,
		},
	}
}

func loadConfigFromFile(config *Config, filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("config file read failed: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("config file parse failed: %w", err)
	}

	return nil
}

func overrideWithEnvVars(config *Config) {
	if val := os.Getenv("SERVER_HOST"); val != "" {
		config.Server.Host = val
	}
	if val := os.Getenv("SERVER_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil && port > 0 && port <= 65535 {
			config.Server.Port = port
		}
	}
	if val := os.Getenv("SERVER_MODE"); val != "" && (val == "debug" || val == "release") {
		config.Server.Mode = val
	}
	if val := os.Getenv("DATABASE_URL"); val != "" {
		config.Database.URL = val
		if strings.Contains(val, "postgres://") {
			config.Database.Type = "postgres"
		}
	}
	if val := os.Getenv("DATABASE_PATH"); val != "" {
		config.Database.Path = val
	}
	if val := os.Getenv("DATABASE_TYPE"); val != "" {
		config.Database.Type = val
	}
	if val := os.Getenv("DATABASE_MAX_CONNECTIONS"); val != "" {
		if maxConns, err := strconv.Atoi(val); err == nil && maxConns > 0 {
			config.Database.MaxConnections = maxConns
		}
	}
	if val := os.Getenv("RATE_LIMIT_REQUESTS"); val != "" {
		if rateLimit, err := strconv.Atoi(val); err == nil && rateLimit > 0 {
			config.Security.RateLimitRequests = rateLimit
		}
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		if isValidLogLevel(val) {
			config.Logging.Level = val
		}
	}
	if val := os.Getenv("CORS_ALLOWED_ORIGINS"); val != "" {
		origins := strings.Split(val, ",")
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		config.CORS.AllowedOrigins = origins
	}
}

func loadSecretsFromEnv(config *Config) error {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		generatedSecret, err := generateSecureSecret(64)
		if err != nil {
			return fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		jwtSecret = generatedSecret
	}
	if len(jwtSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}
	config.Security.JWTSecret = jwtSecret

	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		generatedKey, err := generateSecureSecret(64)
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		encryptionKey = generatedKey
	}
	if len(encryptionKey) < 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be at least 32 characters")
	}
	config.Security.EncryptionKey = encryptionKey

	return nil
}

func validateConfig(config *Config) error {
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Server.Mode != "debug" && config.Server.Mode != "release" {
		return fmt.Errorf("invalid server mode: %s", config.Server.Mode)
	}

	if config.Database.Type != "sqlite" && config.Database.Type != "postgres" {
		return fmt.Errorf("invalid database type: %s", config.Database.Type)
	}

	if config.Database.Type == "sqlite" && config.Database.Path == "" && config.Database.URL == "" {
		return fmt.Errorf("database path cannot be empty for SQLite")
	}

	if config.Database.Type == "postgres" && config.Database.URL == "" {
		return fmt.Errorf("database URL cannot be empty for PostgreSQL")
	}

	if config.Database.MaxConnections <= 0 {
		return fmt.Errorf("database max connections must be positive")
	}

	if config.Security.RateLimitRequests <= 0 {
		return fmt.Errorf("rate limit requests must be positive")
	}

	if config.TOTP.DefaultPeriod < 15 || config.TOTP.DefaultPeriod > 300 {
		return fmt.Errorf("TOTP period must be between 15 and 300 seconds")
	}

	if config.TOTP.DefaultDigits < 6 || config.TOTP.DefaultDigits > 8 {
		return fmt.Errorf("TOTP digits must be between 6 and 8")
	}

	if config.Security.MaxLoginAttempts <= 0 {
		return fmt.Errorf("max login attempts must be positive")
	}

	if !isValidLogLevel(config.Logging.Level) {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

func generateSecureSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("secret generation failed: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func isValidLogLevel(level string) bool {
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	for _, valid := range validLevels {
		if strings.ToLower(level) == valid {
			return true
		}
	}
	return false
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func (c *Config) IsDevelopment() bool {
	return c.Server.Mode == "debug"
}

func (c *Config) IsProduction() bool {
	return c.Server.Mode == "release"
}

func (c *Config) GetDatabaseConfig() *DatabaseConfig {
	return &c.Database
}

func (c *Config) String() string {
	configCopy := *c
	configCopy.Security.JWTSecret = "[REDACTED]"
	configCopy.Security.EncryptionKey = "[REDACTED]"
	
	data, _ := yaml.Marshal(&configCopy)
	return string(data)
}