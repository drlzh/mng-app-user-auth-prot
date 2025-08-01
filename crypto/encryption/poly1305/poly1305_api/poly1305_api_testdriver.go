package poly1305_api

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
)

func TestDriver() {
	fmt.Println("=== Poly1305 API Test Driver ===")

	// Generate random key
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("Hello, this is a secure message.")
	modified := []byte("Hello, this is a tampered message.")

	// --- One-shot Compute and Verify ---
	fmt.Println("\n[One-shot]")
	tag, err := ComputeTag(message, &key)
	if err != nil {
		log.Fatalf("ComputeTag failed: %v", err)
	}
	fmt.Printf("Tag: %x\n", tag)

	valid, err := VerifyTag(message, &tag, &key)
	if err != nil {
		log.Fatalf("VerifyTag failed: %v", err)
	}
	fmt.Printf("Verification (correct): %v\n", valid)

	valid, err = VerifyTag(modified, &tag, &key)
	fmt.Printf("Verification (tampered): %v\n", valid)

	// --- Must variants ---
	fmt.Println("\n[Must* variants]")
	mustTag := MustComputeTag(message, &key)
	fmt.Printf("MustComputeTag output: %x\n", mustTag)

	mustValid := MustVerifyTag(message, &mustTag, &key)
	fmt.Printf("MustVerifyTag (valid): %v\n", mustValid)

	mustInvalid := MustVerifyTag(modified, &mustTag, &key)
	fmt.Printf("MustVerifyTag (invalid): %v\n", mustInvalid)

	// --- Streaming MAC ---
	fmt.Println("\n[Streaming MAC]")

	mac, err := NewMAC(&key)
	if err != nil {
		log.Fatalf("NewMAC failed: %v", err)
	}

	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("this is a "),
		[]byte("secure message."),
	}

	for _, chunk := range chunks {
		if _, err := mac.Write(chunk); err != nil {
			log.Fatalf("MAC Write failed: %v", err)
		}
	}

	sum := mac.Sum(nil)
	fmt.Printf("Streaming Tag: %x\n", sum)

	expectedTag := MustComputeTag(message, &key)
	match := bytes.Equal(sum, expectedTag[:])
	fmt.Printf("Streaming tag matches ComputeTag: %v\n", match)

	fmt.Println("=== End of Poly1305 test ===\n")
}
