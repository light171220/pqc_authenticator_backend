package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

type DilithiumKeypair struct {
	PublicKey  mode3.PublicKey
	PrivateKey mode3.PrivateKey
}

func GenerateDilithiumKeypair() (*DilithiumKeypair, error) {
	publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium keypair: %w", err)
	}

	return &DilithiumKeypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (kp *DilithiumKeypair) Sign(message []byte) ([]byte, error) {
	signature := mode3.Sign(kp.PrivateKey, message)
	return signature, nil
}

func (kp *DilithiumKeypair) Verify(message, signature []byte) bool {
	return mode3.Verify(kp.PublicKey, message, signature)
}

func (kp *DilithiumKeypair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

func (kp *DilithiumKeypair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey[:])
}

func LoadDilithiumKeypairFromBase64(publicKeyB64, privateKeyB64 string) (*DilithiumKeypair, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	var publicKey mode3.PublicKey
	var privateKey mode3.PrivateKey

	if len(publicKeyBytes) != len(publicKey) {
		return nil, fmt.Errorf("invalid public key length: expected %d, got %d", len(publicKey), len(publicKeyBytes))
	}

	if len(privateKeyBytes) != len(privateKey) {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", len(privateKey), len(privateKeyBytes))
	}

	copy(publicKey[:], publicKeyBytes)
	copy(privateKey[:], privateKeyBytes)

	return &DilithiumKeypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func SignData(data []byte, userID string) (string, error) {
	kp, err := GenerateDilithiumKeypair()
	if err != nil {
		return "", err
	}

	message := append([]byte(userID+":"), data...)
	signature, err := kp.Sign(message)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifySignature(data []byte, signatureB64, userID string) (bool, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	kp, err := GenerateDilithiumKeypair()
	if err != nil {
		return false, err
	}

	message := append([]byte(userID+":"), data...)
	return kp.Verify(message, signatureBytes), nil
}

func VerifyWithPublicKey(data []byte, signatureB64, publicKeyB64 string) (bool, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	var publicKey mode3.PublicKey
	if len(publicKeyBytes) != len(publicKey) {
		return false, fmt.Errorf("invalid public key length")
	}
	copy(publicKey[:], publicKeyBytes)

	return mode3.Verify(publicKey, data, signatureBytes), nil
}

func IsValidPublicKey(publicKeyB64 string) bool {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}

	var publicKey mode3.PublicKey
	return len(publicKeyBytes) == len(publicKey)
}