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
		return nil, fmt.Errorf("dilithium keypair generation failed: %w", err)
	}

	return &DilithiumKeypair{
		PublicKey:  *publicKey,
		PrivateKey: *privateKey,
	}, nil
}

func (kp *DilithiumKeypair) Sign(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&kp.PrivateKey, message, signature)
	return signature, nil
}

func (kp *DilithiumKeypair) Verify(message, signature []byte) bool {
	if len(message) == 0 || len(signature) == 0 {
		return false
	}
	return mode3.Verify(&kp.PublicKey, message, signature)
}

func (kp *DilithiumKeypair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey.Bytes())
}

func (kp *DilithiumKeypair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey.Bytes())
}

func LoadDilithiumKeypairFromBase64(publicKeyB64, privateKeyB64 string) (*DilithiumKeypair, error) {
	if publicKeyB64 == "" || privateKeyB64 == "" {
		return nil, fmt.Errorf("keys cannot be empty")
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("public key decode failed: %w", err)
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("private key decode failed: %w", err)
	}

	if len(publicKeyBytes) != mode3.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: expected %d, got %d", mode3.PublicKeySize, len(publicKeyBytes))
	}

	if len(privateKeyBytes) != mode3.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", mode3.PrivateKeySize, len(privateKeyBytes))
	}

	var publicKey mode3.PublicKey
	var privateKey mode3.PrivateKey
	var pkArray [mode3.PublicKeySize]byte
	var skArray [mode3.PrivateKeySize]byte

	copy(pkArray[:], publicKeyBytes)
	copy(skArray[:], privateKeyBytes)

	publicKey.Unpack(&pkArray)
	privateKey.Unpack(&skArray)

	return &DilithiumKeypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func VerifyWithPublicKey(data []byte, signatureB64, publicKeyB64 string) (bool, error) {
	if len(data) == 0 || signatureB64 == "" || publicKeyB64 == "" {
		return false, fmt.Errorf("invalid input parameters")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("signature decode failed: %w", err)
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false, fmt.Errorf("public key decode failed: %w", err)
	}

	if len(publicKeyBytes) != mode3.PublicKeySize {
		return false, fmt.Errorf("invalid public key length")
	}

	var publicKey mode3.PublicKey
	var pkArray [mode3.PublicKeySize]byte
	copy(pkArray[:], publicKeyBytes)
	publicKey.Unpack(&pkArray)

	return mode3.Verify(&publicKey, data, signatureBytes), nil
}

func IsValidPublicKey(publicKeyB64 string) bool {
	if publicKeyB64 == "" {
		return false
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}

	return len(publicKeyBytes) == mode3.PublicKeySize
}