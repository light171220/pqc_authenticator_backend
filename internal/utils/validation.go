package utils

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	numericRegex = regexp.MustCompile(`^[0-9]+$`)
)

func IsValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}

func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func IsNumeric(str string) bool {
	return numericRegex.MatchString(str)
}

func IsValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 50 {
		return false
	}

	for _, char := range username {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) && char != '_' && char != '-' {
			return false
		}
	}

	return true
}

func IsValidURL(url string) bool {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		return false
	}

	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func SanitizeInput(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\x00", "")
	return input
}

func ValidateServiceName(serviceName string) bool {
	serviceName = strings.TrimSpace(serviceName)
	if len(serviceName) < 1 || len(serviceName) > 100 {
		return false
	}

	for _, char := range serviceName {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) && char != ' ' && char != '-' && char != '_' && char != '.' {
			return false
		}
	}

	return true
}

func ValidateIssuer(issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	if len(issuer) < 1 || len(issuer) > 100 {
		return false
	}

	return true
}

func ValidateTOTPDigits(digits int) bool {
	return digits >= 6 && digits <= 8
}

func ValidateTOTPPeriod(period int) bool {
	return period >= 15 && period <= 300
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	
	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Field+": "+err.Message)
	}
	
	return strings.Join(messages, ", ")
}

func (ve *ValidationErrors) Add(field, message string) {
	*ve = append(*ve, ValidationError{
		Field:   field,
		Message: message,
	})
}

func (ve ValidationErrors) HasErrors() bool {
	return len(ve) > 0
}