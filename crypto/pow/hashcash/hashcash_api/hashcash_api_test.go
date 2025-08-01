package hashcash_api

import (
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestHashcashFullFlow(t *testing.T) {
	subject := "test@example.com"
	difficulty := 20
	ttl := 2 * time.Minute
	maxDifficulty := 24

	// Step 1: Create challenge
	challenge, err := CreateChallenge(Config{
		Subject:    subject,
		Difficulty: difficulty,
		TTL:        ttl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, challenge.Token)

	// Step 2: Solve challenge
	solvedToken, err := SolveChallenge(challenge.Token, maxDifficulty)
	require.NoError(t, err)
	require.NotEmpty(t, solvedToken)

	// Step 3: Verify solved token
	err = VerifyToken(solvedToken, subject)
	require.NoError(t, err)
}

func TestHashcashTampering(t *testing.T) {
	subject := "attacker@example.com"
	difficulty := 20
	ttl := 2 * time.Minute
	maxDifficulty := 24

	// Create and solve challenge
	challenge, err := CreateChallenge(Config{
		Subject:    subject,
		Difficulty: difficulty,
		TTL:        ttl,
	})
	require.NoError(t, err)

	solvedToken, err := SolveChallenge(challenge.Token, maxDifficulty)
	require.NoError(t, err)

	// Split the token into parts
	parts := strings.Split(solvedToken, ":")
	require.Len(t, parts, 7)

	// === CASE 1: Tamper with signature ===
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	sigBytes[0] ^= 0xFF // flip one byte
	parts[4] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tamperedSigToken := strings.Join(parts, ":")

	err = VerifyToken(tamperedSigToken, subject)
	require.Error(t, err, "expected signature verification failure")

	// === CASE 2: Tamper with PoW counter ===
	parts = strings.Split(solvedToken, ":")
	counterBytes, err := base64.RawURLEncoding.DecodeString(parts[6])
	require.NoError(t, err)
	counterBytes[0] ^= 0xFF
	parts[6] = base64.RawURLEncoding.EncodeToString(counterBytes)
	tamperedPoWToken := strings.Join(parts, ":")

	err = VerifyToken(tamperedPoWToken, subject)
	require.Error(t, err, "expected PoW validation failure")
}
