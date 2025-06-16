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
	publicKey.Unpack(publicKeyBytes)

	ciphertext := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	seed := make([]byte, kyber768.EncapsulationSeedSize)
	
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	publicKey.EncapsulateTo(ciphertext, sharedSecret, seed)

	return ciphertext, sharedSecret, nil
}

func KyberDecapsulate(ciphertext, privateKeyBytes []byte) ([]byte, error) {
	var privateKey kyber768.PrivateKey
	privateKey.Unpack(privateKeyBytes)

	sharedSecret := make([]byte, kyber768.SharedKeySize)
	privateKey.DecapsulateTo(sharedSecret, ciphertext)

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
	privateKey.Unpack(privateKeyBytes)

	var publicKey kyber768.PublicKey
	publicKey.Unpack(publicKeyBytes)

	ciphertext := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	seed := make([]byte, kyber768.EncapsulationSeedSize)
	
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	publicKey.EncapsulateTo(ciphertext, sharedSecret, seed)

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

	if len(publicKeyBytes) != kyber768.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", kyber768.PublicKeySize, len(publicKeyBytes))
	}

	if len(privateKeyBytes) != kyber768.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", kyber768.PrivateKeySize, len(privateKeyBytes))
	}

	var publicKey kyber768.PublicKey
	publicKey.Unpack(publicKeyBytes)

	var privateKey kyber768.PrivateKey
	privateKey.Unpack(privateKeyBytes)

	ciphertext := make([]byte, kyber768.CiphertextSize)
	originalSecret := make([]byte, kyber768.SharedKeySize)
	seed := make([]byte, kyber768.EncapsulationSeedSize)
	
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to generate random seed: %w", err)
	}

	publicKey.EncapsulateTo(ciphertext, originalSecret, seed)

	decryptedSecret := make([]byte, kyber768.SharedKeySize)
	privateKey.DecapsulateTo(decryptedSecret, ciphertext)

	if len(originalSecret) != len(decryptedSecret) {
		return fmt.Errorf("key validation failed: secret length mismatch")
	}

	if !SecureCompare(originalSecret, decryptedSecret) {
		return fmt.Errorf("key validation failed: secret mismatch")
	}

	return nil
}