// Package chacha_poly1305_impl implements the ChaCha-Poly1305 AEAD and its
// extended nonce variant XChaCha-Poly1305
// Uses the custom ChaCha impl
package chacha_poly1305_impl

import (
	"crypto/cipher"
	"errors"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20-Poly1305
	// variant of this AEAD, in bytes.
	NonceSizeX = 24

	// Overhead is the size of the Poly1305 authentication tag, and the
	// difference between a ciphertext length and its plaintext.
	Overhead = 16
)

type chacha_poly1305 struct {
	key [KeySize]byte
}

// New returns a ChaCha-Poly1305 AEAD that uses the given 256-bit key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha-poly1305: bad key length")
	}
	ret := new(chacha_poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha_poly1305) NonceSize() int {
	return NonceSize
}

func (c *chacha_poly1305) Overhead() int {
	return Overhead
}

func (c *chacha_poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha-poly1305: bad nonce length passed to Seal")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha-poly1305: plaintext too large")
	}

	return c.seal(dst, nonce, plaintext, additionalData)
}

var ErrOpen = errors.New("chacha-poly1305: message authentication failed")

func (c *chacha_poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("chacha-poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, ErrOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha-poly1305: ciphertext too large")
	}

	return c.open(dst, nonce, ciphertext, additionalData)
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
