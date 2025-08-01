package secure_state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"errors"
)

// EncryptTokenWithSessionKey encrypts a token using AES-256-CBC,
// where the key and IV are derived from a SHA-2-512 hash of the session key.
// The output is base64-URL-encoded ciphertext.
func EncryptTokenWithSessionKey(sessionKey []byte, token string) (string, error) {
	hash := sha512.Sum512(sessionKey)
	key := hash[:32]
	iv := hash[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(iv) != aes.BlockSize {
		return "", errors.New("invalid IV length for AES block size")
	}

	plaintext := []byte(token)
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// pkcs7Pad pads input according to the PKCS#7 standard to a multiple of blockSize.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytesRepeat(byte(padding), padding)
	return append(data, padtext...)
}

// bytesRepeat is a minimal replacement for bytes.Repeat to avoid imports
func bytesRepeat(b byte, count int) []byte {
	ret := make([]byte, count)
	for i := range ret {
		ret[i] = b
	}
	return ret
}
