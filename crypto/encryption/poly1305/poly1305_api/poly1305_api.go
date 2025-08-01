package poly1305_api

import (
	"errors"

	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/poly1305/poly1305_impl"
)

// TagSize defines the number of bytes in a Poly1305 tag.
const TagSize = poly1305_impl.TagSize

// ComputeTag computes a Poly1305 tag from the given message and 32-byte key.
// Returns the 16-byte tag.
func ComputeTag(message []byte, key *[32]byte) ([TagSize]byte, error) {
	if key == nil {
		return [TagSize]byte{}, errors.New("poly1305: nil key")
	}
	var tag [TagSize]byte
	poly1305_impl.Sum(&tag, message, key)
	return tag, nil
}

// VerifyTag checks if the provided tag is valid for the given message and key.
// Returns true if valid, false otherwise.
func VerifyTag(message []byte, tag *[TagSize]byte, key *[32]byte) (bool, error) {
	if key == nil || tag == nil {
		return false, errors.New("poly1305: nil input to VerifyTag")
	}
	ok := poly1305_impl.Verify(tag, message, key)
	return ok, nil
}

// MustComputeTag is a variant of ComputeTag that panics on error.
// Suitable for internal use or when input is guaranteed safe.
func MustComputeTag(message []byte, key *[32]byte) [TagSize]byte {
	var tag [TagSize]byte
	poly1305_impl.Sum(&tag, message, key)
	return tag
}

// MustVerifyTag panics if any input is nil, returns false otherwise.
func MustVerifyTag(message []byte, tag *[TagSize]byte, key *[32]byte) bool {
	return poly1305_impl.Verify(tag, message, key)
}

// NewMAC creates a new Poly1305 MAC for streaming usage.
// The key must be unique per message or session to maintain security.
func NewMAC(key *[32]byte) (*poly1305_impl.MAC, error) {
	if key == nil {
		return nil, errors.New("poly1305: nil key")
	}
	return poly1305_impl.New(key), nil
}
