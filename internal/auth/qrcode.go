package auth

import (
	"encoding/base32"
	"fmt"
	"net/url"

	"github.com/skip2/go-qrcode"
)

func GenerateQRCode(username, serviceName string, secret []byte, issuer string) ([]byte, error) {
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	
	params := url.Values{}
	params.Set("secret", secretBase32)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHAKE256")
	params.Set("digits", "6")
	params.Set("period", "30")

	label := fmt.Sprintf("%s:%s", issuer, username)
	if serviceName != "" {
		label = fmt.Sprintf("%s (%s):%s", issuer, serviceName, username)
	}

	otpauthURL := fmt.Sprintf("otpauth://totp/%s?%s", 
		url.QueryEscape(label), 
		params.Encode())

	qrCode, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	return qrCode, nil
}

func GenerateQRCodeURL(username, serviceName string, secret []byte, issuer string) (string, error) {
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	
	params := url.Values{}
	params.Set("secret", secretBase32)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHAKE256")
	params.Set("digits", "6")
	params.Set("period", "30")

	label := fmt.Sprintf("%s:%s", issuer, username)
	if serviceName != "" {
		label = fmt.Sprintf("%s (%s):%s", issuer, serviceName, username)
	}

	otpauthURL := fmt.Sprintf("otpauth://totp/%s?%s", 
		url.QueryEscape(label), 
		params.Encode())

	return otpauthURL, nil
}

type QRCodeData struct {
	URL        string `json:"url"`
	Secret     string `json:"secret"`
	Algorithm  string `json:"algorithm"`
	Digits     int    `json:"digits"`
	Period     int    `json:"period"`
	Issuer     string `json:"issuer"`
	Username   string `json:"username"`
	Service    string `json:"service"`
}

func GenerateQRCodeData(username, serviceName string, secret []byte, issuer string) (*QRCodeData, error) {
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	
	url, err := GenerateQRCodeURL(username, serviceName, secret, issuer)
	if err != nil {
		return nil, err
	}

	return &QRCodeData{
		URL:       url,
		Secret:    secretBase32,
		Algorithm: "SHAKE256",
		Digits:    6,
		Period:    30,
		Issuer:    issuer,
		Username:  username,
		Service:   serviceName,
	}, nil
}