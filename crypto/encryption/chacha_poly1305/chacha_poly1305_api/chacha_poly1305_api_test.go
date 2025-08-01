package chacha_poly1305_api

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestChaChaPoly1305API(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSizeX) // Using XChaCha for wider nonce
	aad := []byte("authenticated-but-not-encrypted")
	message := []byte("Secret message requiring authenticity and confidentiality.")

	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// === One-shot encrypt/decrypt ===
	ciphertext, err := Encrypt(key, nonce, message, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(ciphertext[:len(message)], message) {
		t.Error("Ciphertext should not match plaintext — encryption may be broken")
	}

	plaintext, err := Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(message, plaintext) {
		t.Error("Decrypted plaintext does not match original")
	}

	// === Detached tag usage ===
	ct, tag, err := EncryptDetached(key, nonce, message, aad)
	if err != nil {
		t.Fatalf("EncryptDetached failed: %v", err)
	}
	pt2, err := DecryptDetached(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("DecryptDetached failed: %v", err)
	}
	if !bytes.Equal(message, pt2) {
		t.Error("Detached decryption failed to recover original message")
	}

	// === Tampered tag test ===
	tag[0] ^= 0xFF // corrupt tag
	_, err = DecryptDetached(key, nonce, ct, tag, aad)
	if err == nil {
		t.Error("Tampering should have caused decryption/authentication to fail")
	}

	// === Short nonce error ===
	_, err = Encrypt(key, nonce[:5], message, aad)
	if err == nil {
		t.Error("Expected error on short nonce, but got nil")
	}
}
