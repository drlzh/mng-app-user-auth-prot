package rsa_api

import (
	"bytes"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/utils/timetrace"
	"log"
)

func TestDriver() {
	defer timetrace.TrackFunc("TestDriver")()
	fmt.Println("=== RSA API Test Driver ===")

	// === Generate Key Pair ===
	func() {
		defer timetrace.TrackFunc("GenerateKeyPair")()
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}

		message := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF.")
		label := []byte("rsa-context")

		// === Encrypt / Decrypt ===
		fmt.Println("\n[Encrypt / Decrypt]")
		var ciphertext []byte
		func() {
			defer timetrace.TrackFunc("Encrypt")()
			ciphertext, err = Encrypt(pub, message, label)
			if err != nil {
				log.Fatalf("Encrypt failed: %v", err)
			}
		}()

		fmt.Printf("✅ Ciphertext differs from plaintext: %v\n", !bytes.Equal(ciphertext, message))

		var plaintext []byte
		func() {
			defer timetrace.TrackFunc("Decrypt")()
			plaintext, err = Decrypt(priv, ciphertext, label)
			if err != nil {
				log.Fatalf("Decrypt failed: %v", err)
			}
		}()

		fmt.Printf("✅ Decryption matches original: %v\n", bytes.Equal(plaintext, message))
	}()

	fmt.Println("=== End of RSA API Test ===")
}
