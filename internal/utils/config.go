package utils

import (
	"os"
	"strconv"
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
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Mode         string        `yaml:"mode"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type DatabaseConfig struct {
	Type           string `yaml:"type"`
	Path           string `yaml:"path"`
	MaxConnections int    `yaml:"max_connections"`
}

type SecurityConfig struct {
	JWTSecret           string        `yaml:"jwt_secret"`
	EncryptionKey       string        `yaml:"encryption_key"`
	RateLimitRequests   int           `yaml:"rate_limit_requests"`
	RateLimitWindow     time.Duration `yaml:"rate_limit_window"`
}

type TOTPConfig struct {
	DefaultPeriod         int           `yaml:"default_period"`
	DefaultDigits         int           `yaml:"default_digits"`
	KeyRotationInterval   time.Duration `yaml:"key_rotation_interval"`
	BackupKeyRetention    time.Duration `yaml:"backup_key_retention"`
}

type BusinessConfig struct {
	WebhookTimeout      time.Duration `yaml:"webhook_timeout"`
	AnalyticsRetention  time.Duration `yaml:"analytics_retention"`
	MaxIntegrations     int           `yaml:"max_integrations"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

func LoadConfig() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Host:         getEnvOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvAsIntOrDefault("SERVER_PORT", 8080),
			Mode:         getEnvOrDefault("SERVER_MODE", "debug"),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			Type:           getEnvOrDefault("DATABASE_TYPE", "sqlite"),
			Path:           getEnvOrDefault("DATABASE_PATH", "./data/authenticator.db"),
			MaxConnections: getEnvAsIntOrDefault("DATABASE_MAX_CONNECTIONS", 25),
		},
		Security: SecurityConfig{
			JWTSecret:           getEnvOrDefault("JWT_SECRET", "change-this-secret"),
			EncryptionKey:       getEnvOrDefault("ENCRYPTION_KEY", "32-byte-encryption-key-change-this"),
			RateLimitRequests:   getEnvAsIntOrDefault("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:     parseDurationOrDefault(getEnvOrDefault("RATE_LIMIT_WINDOW", "1m"), time.Minute),
		},
		TOTP: TOTPConfig{
			DefaultPeriod:       30,
			DefaultDigits:       6,
			KeyRotationInterval: 24 * time.Hour,
			BackupKeyRetention:  48 * time.Hour,
		},
		Business: BusinessConfig{
			WebhookTimeout:      parseDurationOrDefault(getEnvOrDefault("WEBHOOK_TIMEOUT", "10s"), 10*time.Second),
			AnalyticsRetention:  parseDurationOrDefault(getEnvOrDefault("ANALYTICS_RETENTION", "90d"), 90*24*time.Hour),
			MaxIntegrations:     10,
		},
		Logging: LoggingConfig{
			Level:  getEnvOrDefault("LOG_LEVEL", "info"),
			Format: getEnvOrDefault("LOG_FORMAT", "json"),
			Output: getEnvOrDefault("LOG_OUTPUT", "stdout"),
		},
	}

	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		if err := loadConfigFromFile(config, configFile); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat("configs/config.yaml"); err == nil {
		if err := loadConfigFromFile(config, "configs/config.yaml"); err != nil {
			return nil, err
		}
	}

	return config, nil
}

func loadConfigFromFile(config *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, config)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func parseDurationOrDefault(value string, defaultValue time.Duration) time.Duration {
	if duration, err := time.ParseDuration(value); err == nil {
		return duration
	}
	return defaultValue
}