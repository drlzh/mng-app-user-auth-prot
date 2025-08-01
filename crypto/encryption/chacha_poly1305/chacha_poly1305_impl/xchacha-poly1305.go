package chacha_poly1305_impl

import (
	"crypto/cipher"
	"errors"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha/chacha_impl"
)

type xchacha_poly1305 struct {
	key [chacha_impl.KeySize]byte
}

// NewX returns a XChaCha20-Poly1305 AEAD that uses the given 256-bit key.
//
// XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
// suitable to be generated randomly without risk of collisions. It should be
// preferred when nonce uniqueness cannot be trivially ensured, or whenever
// nonces are randomly generated.
func NewX(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha_impl.KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(xchacha_poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (*xchacha_poly1305) NonceSize() int {
	return chacha_impl.NonceSizeX
}

func (*xchacha_poly1305) Overhead() int {
	return Overhead
}

func (x *xchacha_poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chacha_impl.NonceSizeX {
		panic("chacha-poly1305: bad nonce length passed to Seal")
	}

	// XChaCha20-Poly1305 technically supports a 64-bit counter, so there is no
	// size limit. However, since we reuse the ChaCha20-Poly1305 implementation,
	// the second half of the counter is not available. This is unlikely to be
	// an issue because the cipher.AEAD API requires the entire message to be in
	// memory, and the counter overflows at 256 GB.
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	c := new(chacha_poly1305)
	hKey, _ := chacha_impl.HChaCha(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, chacha_impl.NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.seal(dst, cNonce[:], plaintext, additionalData)
}

func (x *xchacha_poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha_impl.NonceSizeX {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, ErrOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}

	c := new(chacha_poly1305)
	hKey, _ := chacha_impl.HChaCha(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, chacha_impl.NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.open(dst, cNonce[:], ciphertext, additionalData)
}
