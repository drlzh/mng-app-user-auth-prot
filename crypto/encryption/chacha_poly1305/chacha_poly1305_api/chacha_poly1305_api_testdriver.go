package chacha_poly1305_api

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/utils/timetrace"
	"log"
)

func TestDriver() {
	defer timetrace.TrackFunc("TestDriver")()
	fmt.Println("=== ChaCha-Poly1305 API Test Driver ===")

	// === Setup ===
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSizeX) // Use XChaCha variant
	aad := []byte("authenticated-but-not-encrypted")
	message := []byte("Secret message requiring authenticity and confidentiality.")

	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}

	// === One-shot encrypt/decrypt ===
	fmt.Println("\n[One-shot Encrypt/Decrypt]")
	var ciphertext []byte
	func() {
		defer timetrace.TrackFunc("Encrypt")()
		var err error
		ciphertext, err = Encrypt(key, nonce, message, aad)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
	}()

	if bytes.Equal(ciphertext[:len(message)], message) {
		fmt.Println("❌ Ciphertext should not match plaintext — encryption may be broken")
	} else {
		fmt.Println("✅ Ciphertext is different from plaintext (as expected)")
	}

	func() {
		defer timetrace.TrackFunc("Decrypt")()
		plaintext, err := Decrypt(key, nonce, ciphertext, aad)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
		fmt.Printf("✅ Match after decryption: %v\n", bytes.Equal(message, plaintext))
	}()

	// === Detached tag usage ===
	fmt.Println("\n[Detached Encrypt/Decrypt]")
	var ct, tag []byte
	func() {
		defer timetrace.TrackFunc("EncryptDetached")()
		var err error
		ct, tag, err = EncryptDetached(key, nonce, message, aad)
		if err != nil {
			log.Fatalf("EncryptDetached failed: %v", err)
		}
	}()

	func() {
		defer timetrace.TrackFunc("DecryptDetached")()
		pt2, err := DecryptDetached(key, nonce, ct, tag, aad)
		if err != nil {
			log.Fatalf("DecryptDetached failed: %v", err)
		}
		fmt.Printf("✅ Match after detached decrypt: %v\n", bytes.Equal(message, pt2))
	}()

	// === Tampered tag test ===
	fmt.Println("\n[Authentication Failure Test]")
	tag[0] ^= 0xFF // Corrupt tag
	func() {
		defer timetrace.TrackFunc("Tampered DecryptDetached")()
		_, err := DecryptDetached(key, nonce, ct, tag, aad)
		fmt.Printf("✅ Expected failure on tampered tag: %v\n", err != nil)
	}()

	// === Short nonce error ===
	fmt.Println("\n[Invalid Nonce Length Test]")
	func() {
		defer timetrace.TrackFunc("Short Nonce Encrypt")()
		_, err := Encrypt(key, nonce[:5], message, aad)
		fmt.Printf("✅ Expected failure on short nonce: %v\n", err != nil)
	}()

	fmt.Println("=== End of ChaCha-Poly1305 test ===")
}

func RunningCompetition() {
	const (
		KeySize     = 32
		NonceSizeX  = 24
		MessageSize = 100 << 20 // 100 MB
	)

	fmt.Println("=== Benchmarker ===")

	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSizeX)
	aad := []byte("authenticated-but-not-encrypted")
	message := make([]byte, MessageSize)

	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}
	if _, err := rand.Read(message); err != nil {
		log.Fatalf("Failed to generate message: %v", err)
	}

	// === Benchmark: Encrypt ===
	var ciphertext []byte
	func() {
		defer timetrace.TrackFunc("Encrypt")()
		var err error
		ciphertext, err = Encrypt(key, nonce, message, aad)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
	}()

	// === Benchmark: Decrypt ===
	func() {
		defer timetrace.TrackFunc("Decrypt")()
		plaintext, err := Decrypt(key, nonce, ciphertext, aad)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
		fmt.Printf("✅ Decryption correct? %v\n", bytes.Equal(plaintext, message))
	}()

	// === Benchmark: EncryptDetached ===
	var detachedCiphertext, tag []byte
	func() {
		defer timetrace.TrackFunc("EncryptDetached")()
		var err error
		detachedCiphertext, tag, err = EncryptDetached(key, nonce, message, aad)
		if err != nil {
			log.Fatalf("EncryptDetached failed: %v", err)
		}
	}()

	// === Benchmark: DecryptDetached ===
	func() {
		defer timetrace.TrackFunc("DecryptDetached")()
		pt, err := DecryptDetached(key, nonce, detachedCiphertext, tag, aad)
		if err != nil {
			log.Fatalf("DecryptDetached failed: %v", err)
		}
		fmt.Printf("✅ Detached decryption correct? %v\n", bytes.Equal(pt, message))
	}()

	fmt.Println("=== End of Benchmarker ===")
}
