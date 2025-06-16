package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"pqc-authenticator/internal/storage"
)

type SignatureManager struct {
	privateKey mode3.PrivateKey
	publicKey  mode3.PublicKey
}

func NewSignatureManager() (*SignatureManager, error) {
	publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium keypair: %w", err)
	}

	return &SignatureManager{
		privateKey: *privateKey,
		publicKey:  *publicKey,
	}, nil
}

func (sm *SignatureManager) SignTOTPCode(code string, userID string) (string, error) {
	message := []byte(fmt.Sprintf("%s:%s", userID, code))
	
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&sm.privateKey, message, signature)
	
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (sm *SignatureManager) VerifyTOTPSignature(code, signature, userID string) (bool, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	message := []byte(fmt.Sprintf("%s:%s", userID, code))
	
	return mode3.Verify(&sm.publicKey, message, signatureBytes), nil
}

func (sm *SignatureManager) GetPublicKey() string {
	return base64.StdEncoding.EncodeToString(sm.publicKey.Bytes())
}

func (sm *SignatureManager) GetPrivateKey() string {
	return base64.StdEncoding.EncodeToString(sm.privateKey.Bytes())
}

func LoadSignatureManagerFromKeys(publicKeyStr, privateKeyStr string) (*SignatureManager, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(publicKeyBytes) != mode3.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", mode3.PublicKeySize, len(publicKeyBytes))
	}

	if len(privateKeyBytes) != mode3.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", mode3.PrivateKeySize, len(privateKeyBytes))
	}

	var publicKey mode3.PublicKey
	var privateKey mode3.PrivateKey

	var pkArray [mode3.PublicKeySize]byte
	var skArray [mode3.PrivateKeySize]byte

	copy(pkArray[:], publicKeyBytes)
	copy(skArray[:], privateKeyBytes)

	publicKey.Unpack(&pkArray)
	privateKey.Unpack(&skArray)

	return &SignatureManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

type DeviceSignatureManager struct {
	deviceID string
	sm       *SignatureManager
}

func NewDeviceSignatureManager(deviceID string) (*DeviceSignatureManager, error) {
	sm, err := NewSignatureManager()
	if err != nil {
		return nil, err
	}

	return &DeviceSignatureManager{
		deviceID: deviceID,
		sm:       sm,
	}, nil
}

func (dsm *DeviceSignatureManager) SignForDevice(data []byte) (string, error) {
	message := append([]byte(dsm.deviceID+":"), data...)
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&dsm.sm.privateKey, message, signature)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (dsm *DeviceSignatureManager) VerifyDeviceSignature(data []byte, signature string, device *storage.Device) (bool, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(device.PublicKey)
	if err != nil {
		return false, err
	}

	if len(publicKeyBytes) != mode3.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	var publicKey mode3.PublicKey
	var pkArray [mode3.PublicKeySize]byte
	copy(pkArray[:], publicKeyBytes)
	publicKey.Unpack(&pkArray)

	message := append([]byte(device.ID+":"), data...)
	return mode3.Verify(&publicKey, message, signatureBytes), nil
}

func (dsm *DeviceSignatureManager) GetKeysForStorage() (string, string) {
	return dsm.sm.GetPublicKey(), dsm.sm.GetPrivateKey()
}