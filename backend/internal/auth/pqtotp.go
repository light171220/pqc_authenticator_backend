package auth

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/sha3"
	"pqc-authenticator/internal/crypto"
)

type PQTOTP struct {
	secret    []byte
	digits    int
	period    int
	keyMgr    *crypto.KeyManager
	userID    string
	algorithm string
}

func NewPQTOTP(secret []byte, digits, period int, keyMgr *crypto.KeyManager, userID string) *PQTOTP {
	return &PQTOTP{
		secret:    secret,
		digits:    digits,
		period:    period,
		keyMgr:    keyMgr,
		userID:    userID,
		algorithm: "SHAKE256",
	}
}

func (pq *PQTOTP) GenerateCode(timestamp time.Time) (string, error) {
	counter := uint64(timestamp.Unix()) / uint64(pq.period)
	
	shake := sha3.NewShake256()
	shake.Write(pq.secret)
	
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	shake.Write(counterBytes)
	
	hashBytes := make([]byte, 32)
	shake.Read(hashBytes)
	
	h := hmac.New(sha3.New256, pq.secret)
	h.Write(counterBytes)
	hash := h.Sum(nil)
	
	for i := 0; i < len(hashBytes) && i < len(hash); i++ {
		hash[i] ^= hashBytes[i]
	}
	
	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	
	mod := uint32(math.Pow10(pq.digits))
	code = code % mod
	
	format := fmt.Sprintf("%%0%dd", pq.digits)
	return fmt.Sprintf(format, code), nil
}

func (pq *PQTOTP) GenerateCodeWithSignature(timestamp time.Time) (string, string, error) {
	code, err := pq.GenerateCode(timestamp)
	if err != nil {
		return "", "", err
	}

	signature, err := pq.keyMgr.SignData(pq.userID, []byte(code))
	if err != nil {
		return "", "", err
	}

	return code, signature, nil
}

func (pq *PQTOTP) VerifyCode(code string, timestamp time.Time) (bool, error) {
	window := 1
	
	for i := -window; i <= window; i++ {
		testTime := timestamp.Add(time.Duration(i) * time.Duration(pq.period) * time.Second)
		expectedCode, err := pq.GenerateCode(testTime)
		if err != nil {
			return false, err
		}
		
		if crypto.SecureCompare([]byte(code), []byte(expectedCode)) {
			return true, nil
		}
	}
	
	return false, nil
}

func (pq *PQTOTP) VerifyCodeWithSignature(code, signature string, timestamp time.Time) (bool, error) {
	codeValid, err := pq.VerifyCode(code, timestamp)
	if err != nil || !codeValid {
		return false, err
	}

	if signature == "" {
		return codeValid, nil
	}

	signatureValid, err := pq.keyMgr.VerifySignature(pq.userID, []byte(code), signature)
	if err != nil {
		return false, err
	}

	return codeValid && signatureValid, nil
}

func (pq *PQTOTP) GetTimeRemaining(timestamp time.Time) int {
	counter := timestamp.Unix() / int64(pq.period)
	nextCounter := counter + 1
	nextTime := nextCounter * int64(pq.period)
	return int(nextTime - timestamp.Unix())
}

func (pq *PQTOTP) GetAlgorithm() string {
	return pq.algorithm
}