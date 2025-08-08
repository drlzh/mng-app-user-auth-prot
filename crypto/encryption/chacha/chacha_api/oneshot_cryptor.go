package chacha_api

import (
	"errors"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha/chacha_impl"
)

// Encrypt encrypts the plaintext using D-CC100 or D-XCC100 (based on nonce length).
// Returns ciphertext of equal length.
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	return EncryptWithRounds(key, nonce, plaintext, 100)
}

// Decrypt decrypts the ciphertext using ChaCha or XChaCha (based on nonce length).
// Returns plaintext of equal length.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	return DecryptWithRounds(key, nonce, ciphertext, 100)
}

// EncryptWithRounds allows custom round count.
func EncryptWithRounds(key, nonce, plaintext []byte, rounds int) ([]byte, error) {
	if len(key) != chacha_impl.KeySize {
		return nil, errors.New("chacha: invalid key length")
	}
	if len(nonce) != chacha_impl.NonceSize && len(nonce) != chacha_impl.NonceSizeX {
		return nil, errors.New("chacha: invalid nonce length")
	}

	cipher, err := chacha_impl.NewUnauthenticatedCipherWithCustomRoundCount(key, nonce, rounds)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(plaintext))
	cipher.XORKeyStream(dst, plaintext)
	return dst, nil
}

// DecryptWithRounds is symmetric with EncryptWithRounds
func DecryptWithRounds(key, nonce, ciphertext []byte, rounds int) ([]byte, error) {
	return EncryptWithRounds(key, nonce, ciphertext, rounds)
}
