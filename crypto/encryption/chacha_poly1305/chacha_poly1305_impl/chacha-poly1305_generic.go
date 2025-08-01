package chacha_poly1305_impl

import (
	"encoding/binary"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha/chacha_impl"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/poly1305/poly1305_impl"
	"github.com/drlzh/mng-app-user-auth-prot/utils/alias/alias_impl"
)

func writeWithPadding(p *poly1305_impl.MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.Write(buf[:padLen])
	}
}

func writeUint64(p *poly1305_impl.MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	p.Write(buf[:])
}

func (c *chacha_poly1305) seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return c.sealGeneric(dst, nonce, plaintext, additionalData)
}

func (c *chacha_poly1305) open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return c.openGeneric(dst, nonce, ciphertext, additionalData)
}

func (c *chacha_poly1305) sealGeneric(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+poly1305_impl.TagSize)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]
	if alias_impl.InexactOverlap(out, plaintext) {
		panic("chacha-poly1305: invalid buffer overlap")
	}

	var polyKey [32]byte
	s, _ := chacha_impl.NewUnauthenticatedCipher(c.key[:], nonce)
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes
	s.XORKeyStream(ciphertext, plaintext)

	p := poly1305_impl.New(&polyKey)
	writeWithPadding(p, additionalData)
	writeWithPadding(p, ciphertext)
	writeUint64(p, len(additionalData))
	writeUint64(p, len(plaintext))
	p.Sum(tag[:0])

	return ret
}

func (c *chacha_poly1305) openGeneric(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	var polyKey [32]byte
	s, _ := chacha_impl.NewUnauthenticatedCipher(c.key[:], nonce)
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.SetCounter(1) // set the counter to 1, skipping 32 bytes

	p := poly1305_impl.New(&polyKey)
	writeWithPadding(p, additionalData)
	writeWithPadding(p, ciphertext)
	writeUint64(p, len(additionalData))
	writeUint64(p, len(ciphertext))

	ret, out := sliceForAppend(dst, len(ciphertext))
	if alias_impl.InexactOverlap(out, ciphertext) {
		panic("chacha-poly1305: invalid buffer overlap")
	}
	if !p.Verify(tag) {
		for i := range out {
			out[i] = 0
		}
		return nil, ErrOpen
	}

	s.XORKeyStream(out, ciphertext)
	return ret, nil
}
