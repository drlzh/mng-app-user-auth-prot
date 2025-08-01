package hashcash_api

import (
	"encoding/base64"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/utils/timetrace"
	"log"
	"time"
)

func testFullFlow() {
	defer timetrace.TrackFunc("testFullFlow")()

	subject := "test@example.com"
	difficulty := 20
	ttl := 2 * time.Minute
	maxDifficulty := 24

	fmt.Println("🔐 Generating new Hashcash challenge...")

	// Step 1: Create challenge
	challenge, err := CreateChallenge(Config{
		Subject:    subject,
		Difficulty: difficulty,
		TTL:        ttl,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create challenge: %v", err)
	}
	fmt.Println("✅ Challenge created.")

	fmt.Println("📤 Hashcash token (sent to client):")
	fmt.Println(challenge.Token)

	// Step 2: Simulate client solving
	fmt.Println("⚙️  Solving challenge (client-side simulation)...")
	defer timetrace.TrackFunc("client-side PoW solving")()
	solvedToken, err := SolveChallenge(challenge.Token, maxDifficulty)
	if err != nil {
		log.Fatalf("❌ Failed to solve challenge: %v", err)
	}
	fmt.Println("✅ Challenge solved.")
	fmt.Println("📤 Solved token:")
	fmt.Println(solvedToken)

	// Step 3: Verify on server
	fmt.Println("🔍 Verifying token...")
	defer timetrace.TrackFunc("server-side verification")()
	err = VerifyToken(solvedToken, subject)
	if err != nil {
		log.Fatalf("❌ Challenge verification failed: %v", err)
	}
	fmt.Println("🎉 Challenge successfully verified! All steps passed.")
}

func testBadCases() {
	defer timetrace.TrackFunc("testBadCases")()

	subject := "attacker@example.com"
	difficulty := 20
	ttl := 2 * time.Minute
	maxDifficulty := 24

	fmt.Println("🔐 Generating valid challenge...")

	challenge, err := CreateChallenge(Config{
		Subject:    subject,
		Difficulty: difficulty,
		TTL:        ttl,
	})
	if err != nil {
		log.Fatalf("❌ Challenge generation failed: %v", err)
	}

	solvedToken, err := SolveChallenge(challenge.Token, maxDifficulty)
	if err != nil {
		log.Fatalf("❌ PoW solving failed: %v", err)
	}
	fmt.Println("✅ Challenge solved.")

	// ========== CASE 1: Invalid Signature ==========

	fmt.Println("\n🔍 Test 1: Tampering with Signature...")

	parts := decodeTokenParts(solvedToken)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[4])
	sigBytes[0] ^= 0xFF
	parts[4] = base64.RawURLEncoding.EncodeToString(sigBytes)

	tamperedToken := encodeTokenParts(parts)
	err = VerifyToken(tamperedToken, subject)
	if err != nil {
		fmt.Printf("✅ Signature tampering correctly detected: %v\n", err)
	} else {
		fmt.Println("❌ Signature tampering was not detected!")
	}

	// ========== CASE 2: Invalid PoW Solution ==========

	fmt.Println("\n🔍 Test 2: Tampering with Counter...")

	parts = decodeTokenParts(solvedToken)
	counterBytes, _ := base64.RawURLEncoding.DecodeString(parts[6])
	counterBytes[0] ^= 0xFF
	parts[6] = base64.RawURLEncoding.EncodeToString(counterBytes)

	tamperedToken2 := encodeTokenParts(parts)
	err = VerifyToken(tamperedToken2, subject)
	if err != nil {
		fmt.Printf("✅ PoW tampering correctly detected: %v\n", err)
	} else {
		fmt.Println("❌ PoW tampering was not detected!")
	}

	// ========== Summary ==========
	fmt.Println("\n🔚 testBadCases finished.")
}

func decodeTokenParts(token string) []string {
	parts := make([]string, 0)
	for range [7]string{} {
		parts = append(parts, "")
	}
	copy(parts, splitN(token, ":", 7))
	return parts
}

func encodeTokenParts(parts []string) string {
	return join(parts, ":")
}

// Safe string split and join utilities for compatibility
func splitN(s, sep string, n int) []string {
	p := make([]string, 0, n)
	split := s
	for i := 0; i < n-1; i++ {
		idx := len(split)
		if pos := indexOf(split, sep); pos >= 0 {
			idx = pos
		}
		p = append(p, split[:idx])
		if idx+1 < len(split) {
			split = split[idx+1:]
		} else {
			split = ""
		}
	}
	p = append(p, split)
	return p
}

func indexOf(s, sep string) int {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func join(parts []string, sep string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += sep
		}
		result += part
	}
	return result
}

func TestDriver() {
	testFullFlow()
	testBadCases()
}
