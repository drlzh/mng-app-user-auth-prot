package hashcash_api

import (
	"github.com/drlzh/mng-app-user-auth-prot/crypto/pow/hashcash/hashcash_impl"
	"time"
)

// Config defines the creation parameters for a hashcash challenge.
type Config struct {
	Subject    string
	Difficulty int
	TTL        time.Duration
}

// Challenge represents a Hashcash challenge to be solved by a client.
type Challenge struct {
	Token string // Full token string, ready to send to client
}

// CreateChallenge generates a new Hashcash challenge token.
func CreateChallenge(cfg Config) (*Challenge, error) {
	h, err := hashcash_impl.New(cfg.Subject, cfg.Difficulty, cfg.TTL)
	if err != nil {
		return nil, err
	}
	return &Challenge{
		Token: h.String(),
	}, nil
}

// SolveChallenge is intended for client-side simulation/testing.
// It solves a challenge locally and returns the full token.
func SolveChallenge(token string, maxBits int) (string, error) {
	h, err := hashcash_impl.Parse(token)
	if err != nil {
		return "", err
	}
	if err := h.Solve(maxBits); err != nil {
		return "", err
	}
	return h.String(), nil
}

// VerifyToken verifies both the signature and the PoW of a token.
func VerifyToken(token string, expectedSubject string) error {
	h, err := hashcash_impl.Parse(token)
	if err != nil {
		return err
	}
	return h.Verify(expectedSubject)
}
