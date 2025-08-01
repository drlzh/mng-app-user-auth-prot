package ed448_api

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/drlzh/mng-app-user-auth-prot/utils/timetrace"
)

func TestDriver() {
	defer timetrace.TrackFunc("TestDriver")()
	fmt.Println("=== Ed448/X448 API Test Driver ===")

	message := []byte("Critical transaction: sign and verify")

	// --- Ed448 Keygen / Sign / Verify ---
	fmt.Println("\n[Ed448: Sign/Verify]")
	var priv PrivateKey
	var pub PublicKey
	func() {
		defer timetrace.TrackFunc("GenerateKeyPair")()
		var err error
		priv, pub, err = GenerateKeyPair()
		if err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}
	}()

	var sig Signature
	func() {
		defer timetrace.TrackFunc("Sign")()
		var err error
		sig, err = Sign(priv, message)
		if err != nil {
			log.Fatalf("Sign failed: %v", err)
		}
	}()

	valid := Verify(sig, message, pub)
	fmt.Printf("✅ Signature valid: %v\n", valid)

	// --- X448 Shared Secret (ECDH) ---
	fmt.Println("\n[X448: Shared Secret]")
	priv1, pub1, _ := GenerateX448KeyPair()
	priv2, pub2, _ := GenerateX448KeyPair()

	secret1, err1 := ComputeSharedSecret(priv1, pub2)
	secret2, err2 := ComputeSharedSecret(priv2, pub1)

	if err1 != nil || err2 != nil {
		log.Fatalf("❌ Shared secret computation failed: %v %v", err1, err2)
	}
	fmt.Printf("✅ Shared secrets match: %v\n", bytes.Equal(secret1[:], secret2[:]))

	fmt.Println("=== End of Ed448/X448 API Test ===")
}

func readHexInput(prompt string) ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	input = strings.TrimSpace(input)
	return hex.DecodeString(input)
}

func InteractiveTestDriver() {
	fmt.Println("🔐 X448 Interactive Secret Sharing")

	for {
		fmt.Println("\nOptions:")
		fmt.Println("1. Generate X448 keypair")
		fmt.Println("2. Derive shared secret (ECDH via X448)")
		fmt.Println("q. Quit")
		fmt.Print("> ")

		var choice string
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			priv, pub, err := GenerateX448KeyPair()
			if err != nil {
				log.Fatalf("❌ Failed to generate X448 keypair: %v", err)
			}
			fmt.Println("✅ X448 Private Key:", hex.EncodeToString(priv[:]))
			fmt.Println("✅ X448 Public Key: ", hex.EncodeToString(pub[:]))

		case "2":
			privBytes, err := readHexInput("Enter your X448 private key (56 bytes hex): ")
			if err != nil || len(privBytes) != X448KeySize {
				log.Fatalf("❌ Invalid private key: %v", err)
			}
			var priv X448Key
			copy(priv[:], privBytes)

			pubBytes, err := readHexInput("Enter peer X448 public key (56 bytes hex): ")
			if err != nil || len(pubBytes) != X448KeySize {
				log.Fatalf("❌ Invalid public key: %v", err)
			}
			var pub X448Key
			copy(pub[:], pubBytes)

			secret, err := ComputeSharedSecret(priv, pub)
			if err != nil {
				log.Fatalf("❌ Failed to compute shared secret: %v", err)
			}
			fmt.Println("🔑 Shared Secret:", hex.EncodeToString(secret[:]))

		case "q":
			fmt.Println("Goodbye.")
			return

		default:
			fmt.Println("Invalid option.")
		}
	}
}
