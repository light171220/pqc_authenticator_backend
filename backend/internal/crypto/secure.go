package crypto

import (
	"crypto/rand"
	"crypto/subtle"
)

func SecureZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func SecureRandom(length int) ([]byte, error) {
	data := make([]byte, length)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

type SecureBuffer struct {
	data []byte
}

func NewSecureBuffer(size int) (*SecureBuffer, error) {
	data, err := SecureRandom(size)
	if err != nil {
		return nil, err
	}
	return &SecureBuffer{data: data}, nil
}

func (sb *SecureBuffer) Data() []byte {
	return sb.data
}

func (sb *SecureBuffer) Clear() {
	SecureZeroMemory(sb.data)
}

func (sb *SecureBuffer) Size() int {
	return len(sb.data)
}