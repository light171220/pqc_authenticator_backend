package utils

import (
	"fmt"
	"runtime"
)

type AppError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	HTTPCode  int    `json:"-"`
	Details   string `json:"-"`
	File      string `json:"-"`
	Line      int    `json:"-"`
	Internal  error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Internal
}

func NewAppError(code, message string, httpCode int) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:     code,
		Message:  message,
		HTTPCode: httpCode,
		File:     file,
		Line:     line,
	}
}

func NewAppErrorWithDetails(code, message string, httpCode int, details string) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:     code,
		Message:  message,
		HTTPCode: httpCode,
		Details:  details,
		File:     file,
		Line:     line,
	}
}

func WrapError(err error, code, message string, httpCode int) *AppError {
	_, file, line, _ := runtime.Caller(1)
	return &AppError{
		Code:     code,
		Message:  message,
		HTTPCode: httpCode,
		Details:  err.Error(),
		File:     file,
		Line:     line,
		Internal: err,
	}
}

var (
	ErrInvalidRequest     = NewAppError("INVALID_REQUEST", "Invalid request format", 400)
	ErrUnauthorized       = NewAppError("UNAUTHORIZED", "Authentication required", 401)
	ErrForbidden          = NewAppError("FORBIDDEN", "Access denied", 403)
	ErrNotFound           = NewAppError("NOT_FOUND", "Resource not found", 404)
	ErrConflict           = NewAppError("CONFLICT", "Resource already exists", 409)
	ErrValidationFailed   = NewAppError("VALIDATION_FAILED", "Input validation failed", 400)
	ErrInternalServer     = NewAppError("INTERNAL_SERVER_ERROR", "An internal error occurred", 500)
	ErrRateLimitExceeded  = NewAppError("RATE_LIMIT_EXCEEDED", "Rate limit exceeded", 429)
	ErrInvalidCredentials = NewAppError("INVALID_CREDENTIALS", "Invalid credentials", 401)
	ErrTokenExpired       = NewAppError("TOKEN_EXPIRED", "Authentication token has expired", 401)
	ErrInvalidToken       = NewAppError("INVALID_TOKEN", "Invalid authentication token", 401)
	ErrCryptoError        = NewAppError("CRYPTO_ERROR", "Cryptographic operation failed", 500)
	ErrDatabaseError      = NewAppError("DATABASE_ERROR", "Database operation failed", 500)
	ErrNetworkError       = NewAppError("NETWORK_ERROR", "Network operation failed", 500)
	ErrConfigError        = NewAppError("CONFIG_ERROR", "Configuration error", 500)
	ErrServiceUnavailable = NewAppError("SERVICE_UNAVAILABLE", "Service temporarily unavailable", 503)
	ErrTooManyRequests    = NewAppError("TOO_MANY_REQUESTS", "Too many requests", 429)
)

func IsAppError(err error) (*AppError, bool) {
	if appErr, ok := err.(*AppError); ok {
		return appErr, true
	}
	return nil, false
}

func SanitizeError(err error) *AppError {
	if appErr, ok := IsAppError(err); ok {
		return &AppError{
			Code:     appErr.Code,
			Message:  appErr.Message,
			HTTPCode: appErr.HTTPCode,
		}
	}
	
	return ErrInternalServer
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	TraceID string `json:"trace_id,omitempty"`
}

func NewErrorResponse(err *AppError, traceID string) ErrorResponse {
	return ErrorResponse{
		Error:   err.Message,
		Code:    err.Code,
		TraceID: traceID,
	}
}