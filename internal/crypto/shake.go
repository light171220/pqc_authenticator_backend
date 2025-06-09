package crypto

import (
	"crypto/hmac"

	"golang.org/x/crypto/sha3"
)

func SHAKE256(data []byte, outputLen int) []byte {
	shake := sha3.NewShake256()
	shake.Write(data)
	
	output := make([]byte, outputLen)
	shake.Read(output)
	
	return output
}

func SHAKE256WithKey(key, data []byte, outputLen int) []byte {
	shake := sha3.NewShake256()
	shake.Write(key)
	shake.Write(data)
	
	output := make([]byte, outputLen)
	shake.Read(output)
	
	return output
}

func HMACSHA3(key, data []byte) []byte {
	h := hmac.New(sha3.New256, key)
	h.Write(data)
	return h.Sum(nil)
}

func HMACSHAKE256(key, data []byte) []byte {
	return SHAKE256WithKey(key, data, 32)
}

func DeriveKey(masterKey, salt []byte, keyLen int) []byte {
	shake := sha3.NewShake256()
	shake.Write(masterKey)
	shake.Write(salt)
	
	derivedKey := make([]byte, keyLen)
	shake.Read(derivedKey)
	
	return derivedKey
}

func KDF(password, salt []byte, iterations, keyLen int) []byte {
	if iterations < 1 {
		iterations = 10000
	}

	key := append(password, salt...)
	
	for i := 0; i < iterations; i++ {
		key = SHAKE256(key, len(key))
	}
	
	return SHAKE256(key, keyLen)
}

func SecureHash(data []byte) []byte {
	return SHAKE256(data, 64)
}

func HashWithSalt(data, salt []byte) []byte {
	combined := append(salt, data...)
	return SHAKE256(combined, 32)
}

type SHAKE256Context struct {
	shake sha3.ShakeHash
}

func NewSHAKE256Context() *SHAKE256Context {
	return &SHAKE256Context{
		shake: sha3.NewShake256(),
	}
}

func (ctx *SHAKE256Context) Write(data []byte) {
	ctx.shake.Write(data)
}

func (ctx *SHAKE256Context) Read(output []byte) {
	ctx.shake.Read(output)
}

func (ctx *SHAKE256Context) Clone() *SHAKE256Context {
	newShake := sha3.NewShake256()
	
	return &SHAKE256Context{
		shake: newShake,
	}
}

func (ctx *SHAKE256Context) Sum(outputLen int) []byte {
	cloned := ctx.Clone()
	output := make([]byte, outputLen)
	cloned.shake.Read(output)
	return output
}