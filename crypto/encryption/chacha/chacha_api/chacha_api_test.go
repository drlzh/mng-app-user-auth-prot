package chacha_api

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"testing"
)

func TestChaChaAPI(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24) // XChaCha
	rand.Read(key)
	rand.Read(nonce)

	plaintext := []byte("This is a top-secret message that must be kept confidential!")

	// --- One-shot Encrypt/Decrypt ---
	ciphertext, err := Encrypt(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("One-shot Encrypt failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("One-shot encryption output should differ from plaintext")
	}
	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("One-shot Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("One-shot decryption result does not match original")
	}

	// --- Streaming Reader-based Encrypt/Decrypt ---
	var buf bytes.Buffer
	input := bytes.NewReader(plaintext)

	streamEncReader, err := NewStreamEncryptor(input, key, nonce, 20)
	if err != nil {
		t.Fatalf("StreamEncryptor (reader) failed: %v", err)
	}
	if _, err := io.Copy(&buf, streamEncReader); err != nil {
		t.Fatalf("Streaming reader encrypt copy failed: %v", err)
	}
	cipherStream := buf.Bytes()
	if bytes.Equal(cipherStream, plaintext) {
		t.Error("Streaming reader ciphertext should differ from plaintext")
	}

	decryptInput := bytes.NewReader(cipherStream)
	streamDecReader, err := NewStreamDecryptor(decryptInput, key, nonce, 20)
	if err != nil {
		t.Fatalf("StreamDecryptor (reader) failed: %v", err)
	}
	var decBuf bytes.Buffer
	if _, err := io.Copy(&decBuf, streamDecReader); err != nil {
		t.Fatalf("Streaming reader decrypt copy failed: %v", err)
	}
	if !bytes.Equal(decBuf.Bytes(), plaintext) {
		t.Error("Streaming reader decryption result does not match original")
	}

	// --- Streaming Writer-based Encrypt/Decrypt ---
	tmpEncFile, err := os.CreateTemp("", "chacha_enc_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpEncFile.Name())

	streamEncWriter, err := NewStreamEncryptorWriter(tmpEncFile, key, nonce, 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streamEncWriter.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	streamEncWriter.Close()

	encContent, _ := os.ReadFile(tmpEncFile.Name())
	if bytes.Equal(encContent, plaintext) {
		t.Error("Streaming writer ciphertext should differ from plaintext")
	}

	tmpDecFile, err := os.CreateTemp("", "chacha_dec_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpDecFile.Name())

	encFile, _ := os.Open(tmpEncFile.Name())
	decWriter, err := NewStreamDecryptorWriter(tmpDecFile, key, nonce, 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(decWriter, encFile); err != nil {
		t.Fatal(err)
	}
	decWriter.Close()

	decResult, err := os.ReadFile(tmpDecFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decResult, plaintext) {
		t.Error("Streaming writer decryption result does not match original")
	}

	// --- Seek support demonstration ---
	input.Seek(10, io.SeekStart)
	streamEncReader, _ = NewStreamEncryptor(input, key, nonce, 20)
	streamEncReader.(io.Seeker).Seek(10, io.SeekStart)
	chunk := make([]byte, 10)
	streamEncReader.Read(chunk)
	if len(chunk) != 10 {
		t.Error("Seek-based read failed to produce expected chunk")
	}
}
