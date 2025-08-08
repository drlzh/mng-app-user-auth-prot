package hashcash_impl

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	"strconv"
	"strings"
	"time"

	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

const (
	Version       = "1"
	Separator     = ":"
	MaxDifficulty = 26
)

var (
	ErrInvalidFormat      = errors.New("invalid hashcash format")
	ErrInvalidVersion     = errors.New("invalid hashcash version")
	ErrInvalidDifficulty  = errors.New("difficulty out of range")
	ErrInvalidTimestamp   = errors.New("invalid timestamp")
	ErrExpired            = errors.New("hashcash has expired")
	ErrSubjectMismatch    = errors.New("subject mismatch")
	ErrSignatureInvalid   = errors.New("invalid Ed448 signature")
	ErrSignatureMalformed = errors.New("malformed signature")
	ErrUnsupportedAlg     = errors.New("unsupported algorithm")
	ErrInvalidPoW         = errors.New("invalid proof-of-work")
)

type Hashcash struct {
	Version    string
	Difficulty int
	Timestamp  time.Time
	Subject    string
	Ext        string // base64-encoded Ed448 signature
	Nonce      string // base64url-encoded random nonce
	Counter    string // base64url-encoded solution (client computes this)
}

// New creates a new unsigned Hashcash challenge and embeds the signature in `Ext`.
func New(subject string, difficulty int, ttl time.Duration) (*Hashcash, error) {
	if difficulty <= 0 || difficulty > MaxDifficulty {
		return nil, ErrInvalidDifficulty
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	h := &Hashcash{
		Version:    Version,
		Difficulty: difficulty,
		Timestamp:  time.Now().Add(ttl).UTC().Truncate(time.Second),
		Subject:    subject,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
	}

	// Sign canonical header (no counter yet)
	sig, err := ed448_api.Sign(user_auth_global_config.Ed448HashcashPrivateKey(), []byte(h.unsignedHeader()))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	h.Ext = base64.RawURLEncoding.EncodeToString(sig[:])
	return h, nil
}

// canonicalHeader returns the string to sign: all fields before the counter
func (h *Hashcash) canonicalHeader() string {
	return strings.Join([]string{
		h.Version,
		strconv.Itoa(h.Difficulty),
		strconv.FormatInt(h.Timestamp.Unix(), 10),
		h.Subject,
		h.Ext,
		h.Nonce,
	}, Separator)
}

func (h *Hashcash) unsignedHeader() string {
	return strings.Join([]string{
		h.Version,
		strconv.Itoa(h.Difficulty),
		strconv.FormatInt(h.Timestamp.Unix(), 10),
		h.Subject,
		"", // empty Ext (signature not included)
		h.Nonce,
	}, Separator)
}

// String returns the full Hashcash token including the counter.
func (h *Hashcash) String() string {
	return h.canonicalHeader() + Separator + h.Counter
}

// Solve brute-forces the counter to satisfy the difficulty.
func (h *Hashcash) Solve(maxBits int) error {
	if h.Difficulty > maxBits || h.Difficulty > MaxDifficulty {
		return ErrInvalidDifficulty
	}

	var counter uint32
	buf := make([]byte, 4)
	bits := h.Difficulty
	bytesToCheck := (bits + 7) / 8

	base := h.canonicalHeader()
	for {
		binary.LittleEndian.PutUint32(buf, counter)
		counterB64 := base64.RawURLEncoding.EncodeToString(buf)
		h.Counter = counterB64

		full := base + Separator + counterB64
		hash := sha256.Sum256([]byte(full))

		if leadingZeroBits(hash[:bytesToCheck], bits) {
			return nil
		}
		counter++
	}
}

// Verify checks the signature and the PoW.
func (h *Hashcash) Verify(expectedSubject string) error {
	if h.Version != Version {
		return ErrInvalidVersion
	}
	if h.Difficulty < 0 || h.Difficulty > MaxDifficulty {
		return ErrInvalidDifficulty
	}
	if h.Subject != expectedSubject {
		return ErrSubjectMismatch
	}
	if time.Now().After(h.Timestamp) {
		return ErrExpired
	}

	// Decode and verify signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(h.Ext)
	if err != nil || len(sigBytes) != ed448_api.SignatureSize {
		return ErrSignatureMalformed
	}
	sig := ed448_api.Signature(sigBytes)

	if !ed448_api.Verify(sig, []byte(h.unsignedHeader()), user_auth_global_config.Ed448HashcashPublicKey()) {
		return ErrSignatureInvalid
	}

	// Verify PoW
	full := h.canonicalHeader() + Separator + h.Counter
	hash := sha256.Sum256([]byte(full))
	bits := h.Difficulty
	bytesToCheck := (bits + 7) / 8

	if !leadingZeroBits(hash[:bytesToCheck], bits) {
		return ErrInvalidPoW
	}

	return nil
}

// Parse decodes a full Hashcash string into a struct.
func Parse(s string) (*Hashcash, error) {
	parts := strings.Split(s, Separator)
	if len(parts) != 7 {
		return nil, ErrInvalidFormat
	}
	if parts[0] != Version {
		return nil, ErrInvalidVersion
	}

	bits, err := strconv.Atoi(parts[1])
	if err != nil || bits < 0 || bits > MaxDifficulty {
		return nil, ErrInvalidDifficulty
	}

	tsUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, ErrInvalidTimestamp
	}

	return &Hashcash{
		Version:    parts[0],
		Difficulty: bits,
		Timestamp:  time.Unix(tsUnix, 0).UTC(),
		Subject:    parts[3],
		Ext:        parts[4],
		Nonce:      parts[5],
		Counter:    parts[6],
	}, nil
}

// leadingZeroBits checks that the hash has the required number of leading 0 bits.
func leadingZeroBits(hash []byte, bits int) bool {
	full := bits / 8
	rem := bits % 8

	for i := 0; i < full; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	// top rem bits of next byte must be zero
	return (hash[full] >> (8 - rem)) == 0
}
