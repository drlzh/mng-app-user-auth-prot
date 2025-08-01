package argon2_api

import (
	"errors"
	"golang.org/x/crypto/argon2"
)

const (
	// Default recommended values
	DefaultArgon2iTime    = 3
	DefaultArgon2iMemory  = 32 * 1024 // 32 MiB
	DefaultArgon2idTime   = 1
	DefaultArgon2idMemory = 64 * 1024 // 64 MiB
	DefaultThreads        = 4
	DefaultKeyLength      = 32
)

// DeriveKeyArgon2i derives a cryptographic key using Argon2i.
func DeriveKeyArgon2i(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, errors.New("password and salt must be non-empty")
	}
	if time == 0 || memory == 0 || threads == 0 || keyLen == 0 {
		return nil, errors.New("invalid Argon2i parameters")
	}
	return argon2.Key(password, salt, time, memory, threads, keyLen), nil
}

// DeriveKeyArgon2id derives a cryptographic key using Argon2id.
func DeriveKeyArgon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(password) == 0 || len(salt) == 0 {
		return nil, errors.New("password and salt must be non-empty")
	}
	if time == 0 || memory == 0 || threads == 0 || keyLen == 0 {
		return nil, errors.New("invalid Argon2id parameters")
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// DeriveKeyDefault returns a 32-byte key using Argon2id with recommended defaults.
func DeriveKeyDefault(password, salt []byte) ([]byte, error) {
	return DeriveKeyArgon2id(password, salt, DefaultArgon2idTime, DefaultArgon2idMemory, DefaultThreads, DefaultKeyLength)
}
