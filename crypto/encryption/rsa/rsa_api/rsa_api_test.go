package rsa_api

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key gen failed: %v", err)
	}
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF")
	label := []byte("label")

	ciphertext, err := Encrypt(pub, msg, label)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(ciphertext, msg) {
		t.Errorf("Ciphertext should not match plaintext")
	}

	plaintext, err := Decrypt(priv, ciphertext, label)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, msg) {
		t.Errorf("Decryption mismatch")
	}
}
