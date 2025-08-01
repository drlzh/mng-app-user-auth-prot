package chacha_poly1305_api

import (
	"crypto/cipher"
	"errors"

	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha_poly1305/chacha_poly1305_impl"
)

const (
	KeySize    = chacha_poly1305_impl.KeySize
	NonceSize  = chacha_poly1305_impl.NonceSize
	NonceSizeX = chacha_poly1305_impl.NonceSizeX
	TagSize    = chacha_poly1305_impl.Overhead
)

var (
	ErrInvalidKey   = errors.New("chacha-poly: invalid key length")
	ErrInvalidNonce = errors.New("chacha-poly: invalid nonce length")
	ErrDecryption   = errors.New("chacha-poly: decryption failed")
)

// Encrypt encrypts the plaintext using ChaCha-Poly1305 or XChaCha-Poly1305 depending on nonce size.
// Returns ciphertext with authentication tag appended, or error.
func Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := getAEAD(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt authenticates and decrypts the ciphertext using the appropriate AEAD.
// Returns plaintext, or error if authentication fails.
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := getAEAD(key, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// EncryptDetached returns ciphertext and tag separately.
func EncryptDetached(key, nonce, plaintext, aad []byte) (ciphertext []byte, tag []byte, err error) {
	out, err := Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = out[:len(out)-TagSize]
	tag = out[len(out)-TagSize:]
	return
}

// DecryptDetached verifies tag and decrypts separately provided ciphertext.
func DecryptDetached(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	combined := append(ciphertext, tag...)
	return Decrypt(key, nonce, combined, aad)
}

// getAEAD returns a cipher.AEAD implementation based on nonce length.
func getAEAD(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	switch len(nonce) {
	case NonceSize:
		return chacha_poly1305_impl.New(key)
	case NonceSizeX:
		return chacha_poly1305_impl.NewX(key)
	default:
		return nil, ErrInvalidNonce
	}
}
