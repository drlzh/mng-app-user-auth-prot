package poly1305_api

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPoly1305API(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	message := []byte("Hello, this is a secure message.")
	modified := []byte("Hello, this is a tampered message.")

	// --- One-shot Compute and Verify ---
	tag, err := ComputeTag(message, &key)
	if err != nil {
		t.Fatalf("ComputeTag failed: %v", err)
	}

	valid, err := VerifyTag(message, &tag, &key)
	if err != nil {
		t.Fatalf("VerifyTag failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid tag verification to pass")
	}

	valid, err = VerifyTag(modified, &tag, &key)
	if err != nil {
		t.Fatalf("VerifyTag failed for tampered message: %v", err)
	}
	if valid {
		t.Error("Expected tag verification to fail for modified message")
	}

	// --- Must variants ---
	mustTag := MustComputeTag(message, &key)
	if !bytes.Equal(tag[:], mustTag[:]) {
		t.Error("MustComputeTag does not match ComputeTag output")
	}

	if !MustVerifyTag(message, &mustTag, &key) {
		t.Error("MustVerifyTag failed on valid input")
	}
	if MustVerifyTag(modified, &mustTag, &key) {
		t.Error("MustVerifyTag incorrectly succeeded on tampered message")
	}

	// --- Streaming MAC ---
	mac, err := NewMAC(&key)
	if err != nil {
		t.Fatalf("NewMAC failed: %v", err)
	}

	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("this is a "),
		[]byte("secure message."),
	}
	for _, chunk := range chunks {
		if _, err := mac.Write(chunk); err != nil {
			t.Fatalf("MAC Write failed: %v", err)
		}
	}
	streamingTag := mac.Sum(nil)

	expected := MustComputeTag(message, &key)
	if !bytes.Equal(streamingTag, expected[:]) {
		t.Error("Streaming tag does not match MustComputeTag output")
	}
}
