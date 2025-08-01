package chacha_api

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
)

func TestDriver() {
	fmt.Println("=== ChaCha API Test Driver ===")

	key := make([]byte, 32)
	nonce := make([]byte, 24) // XChaCha
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("This is a top-secret message that must be kept confidential!")

	// --- One-shot Encrypt/Decrypt ---
	fmt.Println("\n[One-shot Encrypt/Decrypt]")
	ciphertext, err := Encrypt(key, nonce, plaintext)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}

	// Ensure ciphertext differs from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		fmt.Println("❌ One-shot encryption failed: ciphertext matches plaintext!")
	} else {
		fmt.Println("✅ One-shot encryption output differs from plaintext")
	}

	decrypted, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Printf("✅ Match after decryption: %v\n", bytes.Equal(plaintext, decrypted))

	// --- Streaming Reader-based Encrypt/Decrypt ---
	fmt.Println("\n[Streaming Reader Encrypt/Decrypt]")
	var buf bytes.Buffer
	input := bytes.NewReader(plaintext)

	streamEncReader, err := NewStreamEncryptor(input, key, nonce, 20)
	if err != nil {
		log.Fatalf("StreamEncryptor failed: %v", err)
	}
	if _, err := io.Copy(&buf, streamEncReader); err != nil {
		log.Fatalf("Encryption io.Copy failed: %v", err)
	}
	cipherStream := buf.Bytes()

	if bytes.Equal(cipherStream, plaintext) {
		fmt.Println("❌ Streaming reader encryption failed: output matches plaintext")
	} else {
		fmt.Println("✅ Streaming reader ciphertext differs from plaintext")
	}

	decryptInput := bytes.NewReader(cipherStream)
	streamDecReader, err := NewStreamDecryptor(decryptInput, key, nonce, 20)
	if err != nil {
		log.Fatalf("StreamDecryptor failed: %v", err)
	}
	var decBuf bytes.Buffer
	if _, err := io.Copy(&decBuf, streamDecReader); err != nil {
		log.Fatalf("Decryption io.Copy failed: %v", err)
	}
	fmt.Printf("✅ Match after streaming reader: %v\n", bytes.Equal(plaintext, decBuf.Bytes()))

	// --- Streaming Writer-based Encrypt/Decrypt ---
	fmt.Println("\n[Streaming Writer Encrypt/Decrypt]")
	tmpEncFile, err := os.CreateTemp("", "chacha_enc_*.bin")
	if err != nil {
		log.Fatalf("Temp file creation failed: %v", err)
	}
	defer os.Remove(tmpEncFile.Name())

	streamEncWriter, err := NewStreamEncryptorWriter(tmpEncFile, key, nonce, 20)
	if err != nil {
		log.Fatalf("StreamEncryptorWriter failed: %v", err)
	}
	if _, err := streamEncWriter.Write(plaintext); err != nil {
		log.Fatalf("Writer encrypt failed: %v", err)
	}
	streamEncWriter.Close()

	encContent, _ := os.ReadFile(tmpEncFile.Name())
	if bytes.Equal(encContent, plaintext) {
		fmt.Println("❌ Streaming writer encryption failed: file content matches plaintext")
	} else {
		fmt.Println("✅ Streaming writer ciphertext differs from plaintext")
	}

	tmpDecFile, err := os.CreateTemp("", "chacha_dec_*.bin")
	if err != nil {
		log.Fatalf("Temp file creation failed: %v", err)
	}
	defer os.Remove(tmpDecFile.Name())

	encFile, _ := os.Open(tmpEncFile.Name())
	decWriter, err := NewStreamDecryptorWriter(tmpDecFile, key, nonce, 20)
	if err != nil {
		log.Fatalf("StreamDecryptorWriter failed: %v", err)
	}
	if _, err := io.Copy(decWriter, encFile); err != nil {
		log.Fatalf("io.Copy to decWriter failed: %v", err)
	}
	decWriter.Close()

	decResult, err := os.ReadFile(tmpDecFile.Name())
	if err != nil {
		log.Fatalf("ReadFile after decryption failed: %v", err)
	}
	fmt.Printf("✅ Match after streaming writer: %v\n", bytes.Equal(plaintext, decResult))

	// --- Seek support demonstration ---
	fmt.Println("\n[Seek Demo]")
	input.Seek(10, io.SeekStart)
	streamEncReader, _ = NewStreamEncryptor(input, key, nonce, 20)
	streamEncReader.(io.Seeker).Seek(10, io.SeekStart)
	chunk := make([]byte, 10)
	streamEncReader.Read(chunk)
	fmt.Printf("Encrypted chunk from offset 10: %x\n", chunk)

	fmt.Println("=== End of ChaCha API test ===")
}
