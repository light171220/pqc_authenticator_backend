package auth

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/sha3"
)

type TOTP struct {
	secret []byte
	digits int
	period int
}

func NewTOTP(secret []byte, digits, period int) *TOTP {
	return &TOTP{
		secret: secret,
		digits: digits,
		period: period,
	}
}

func (t *TOTP) GenerateCode(timestamp time.Time) (string, error) {
	counter := uint64(timestamp.Unix()) / uint64(t.period)
	
	h := hmac.New(sha3.New256, t.secret)
	
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	
	h.Write(counterBytes)
	hash := h.Sum(nil)
	
	offset := hash[len(hash)-1] & 0x0F
	
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	
	mod := uint32(math.Pow10(t.digits))
	code = code % mod
	
	format := fmt.Sprintf("%%0%dd", t.digits)
	return fmt.Sprintf(format, code), nil
}

func (t *TOTP) VerifyCode(code string, timestamp time.Time) (bool, error) {
	window := 1
	
	for i := -window; i <= window; i++ {
		testTime := timestamp.Add(time.Duration(i) * time.Duration(t.period) * time.Second)
		expectedCode, err := t.GenerateCode(testTime)
		if err != nil {
			return false, err
		}
		
		if hmac.Equal([]byte(code), []byte(expectedCode)) {
			return true, nil
		}
	}
	
	return false, nil
}