package utils

import (
	"fmt"
	"runtime"
)

type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewAppError(code, message string) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:    code,
		Message: message,
		File:    file,
		Line:    line,
	}
}

func NewAppErrorWithDetails(code, message, details string) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
		File:    file,
		Line:    line,
	}
}

var (
	ErrInvalidRequest     = NewAppError("INVALID_REQUEST", "Invalid request format")
	ErrUnauthorized       = NewAppError("UNAUTHORIZED", "Authentication required")
	ErrForbidden          = NewAppError("FORBIDDEN", "Access denied")
	ErrNotFound           = NewAppError("NOT_FOUND", "Resource not found")
	ErrConflict           = NewAppError("CONFLICT", "Resource already exists")
	ErrValidationFailed   = NewAppError("VALIDATION_FAILED", "Input validation failed")
	ErrInternalServer     = NewAppError("INTERNAL_SERVER_ERROR", "Internal server error")
	ErrRateLimitExceeded  = NewAppError("RATE_LIMIT_EXCEEDED", "Rate limit exceeded")
	ErrInvalidCredentials = NewAppError("INVALID_CREDENTIALS", "Invalid username or password")
	ErrTokenExpired       = NewAppError("TOKEN_EXPIRED", "Authentication token has expired")
	ErrInvalidToken       = NewAppError("INVALID_TOKEN", "Invalid authentication token")
	ErrCryptoError        = NewAppError("CRYPTO_ERROR", "Cryptographic operation failed")
	ErrDatabaseError      = NewAppError("DATABASE_ERROR", "Database operation failed")
	ErrNetworkError       = NewAppError("NETWORK_ERROR", "Network operation failed")
	ErrConfigError        = NewAppError("CONFIG_ERROR", "Configuration error")
)

func WrapError(err error, code, message string) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:    code,
		Message: message,
		Details: err.Error(),
		File:    file,
		Line:    line,
	}
}

func IsAppError(err error) (*AppError, bool) {
	if appErr, ok := err.(*AppError); ok {
		return appErr, true
	}
	return nil, false
}