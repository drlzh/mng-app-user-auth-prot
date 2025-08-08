package secure_state

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha/chacha_api"
)

// EncryptTokenWithSessionKey encrypts a token using AES-256-CBC,
// where the key and IV are derived from a SHA-2-512 hash of the session key.
// The output is base64-URL-encoded ciphertext.
func EncryptTokenWithSessionKey(sessionKey []byte, token string) (string, error) {
	fmt.Println(base64.RawURLEncoding.EncodeToString(sessionKey))
	hash := sha512.Sum512(sessionKey)
	key := hash[:32]
	iv := hash[32 : 32+24]
	plaintext := []byte(token)

	ciphertext, err := chacha_api.Encrypt(key, iv, plaintext)
	if err != nil {
		return "", err
	}

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
