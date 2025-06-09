package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

type KyberKeypair struct {
	PublicKey  kyber768.PublicKey
	PrivateKey kyber768.PrivateKey
}

func GenerateKyberKeypair() ([]byte, []byte, error) {
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Kyber keypair: %w", err)
	}

	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return publicKeyBytes, privateKeyBytes, nil
}

func KyberEncapsulate(publicKeyBytes []byte) ([]byte, []byte, error) {
	var publicKey kyber768.PublicKey
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	ciphertext, sharedSecret, err := kyber768.EncryptTo(publicKey, nil, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate: %w", err)
	}

	return ciphertext, sharedSecret, nil
}

func KyberDecapsulate(ciphertext, privateKeyBytes []byte) ([]byte, error) {
	var privateKey kyber768.PrivateKey
	if err := privateKey.UnmarshalBinary(privateKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	sharedSecret, err := kyber768.DecryptTo(privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}

	return sharedSecret, nil
}

func EncodeKyberPublicKey(publicKeyBytes []byte) string {
	return base64.StdEncoding.EncodeToString(publicKeyBytes)
}

func DecodeKyberPublicKey(publicKeyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(publicKeyB64)
}

func EncodeKyberPrivateKey(privateKeyBytes []byte) string {
	return base64.StdEncoding.EncodeToString(privateKeyBytes)
}

func DecodeKyberPrivateKey(privateKeyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(privateKeyB64)
}

func KyberKeyExchange(privateKeyB64, publicKeyB64 string) ([]byte, error) {
	privateKeyBytes, err := DecodeKyberPrivateKey(privateKeyB64)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := DecodeKyberPublicKey(publicKeyB64)
	if err != nil {
		return nil, err
	}

	var privateKey kyber768.PrivateKey
	if err := privateKey.UnmarshalBinary(privateKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	var publicKey kyber768.PublicKey
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	ciphertext, sharedSecret, err := kyber768.EncryptTo(publicKey, nil, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to perform key exchange: %w", err)
	}

	_ = ciphertext

	return sharedSecret, nil
}

func ValidateKyberKeys(publicKeyB64, privateKeyB64 string) error {
	publicKeyBytes, err := DecodeKyberPublicKey(publicKeyB64)
	if err != nil {
		return fmt.Errorf("invalid public key encoding: %w", err)
	}

	privateKeyBytes, err := DecodeKyberPrivateKey(privateKeyB64)
	if err != nil {
		return fmt.Errorf("invalid private key encoding: %w", err)
	}

	var publicKey kyber768.PublicKey
	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	var privateKey kyber768.PrivateKey
	if err := privateKey.UnmarshalBinary(privateKeyBytes); err != nil {
		return fmt.Errorf("invalid private key format: %w", err)
	}

	ciphertext, originalSecret, err := kyber768.EncryptTo(publicKey, nil, rand.Reader)
	if err != nil {
		return fmt.Errorf("encryption test failed: %w", err)
	}

	decryptedSecret, err := kyber768.DecryptTo(privateKey, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption test failed: %w", err)
	}

	if len(originalSecret) != len(decryptedSecret) {
		return fmt.Errorf("key validation failed: secret length mismatch")
	}

	for i := range originalSecret {
		if originalSecret[i] != decryptedSecret[i] {
			return fmt.Errorf("key validation failed: secret mismatch")
		}
	}

	return nil
}