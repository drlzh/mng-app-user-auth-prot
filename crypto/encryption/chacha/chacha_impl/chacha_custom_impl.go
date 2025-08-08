package chacha_impl

// Copyright 2025 DAIDO Developers. All rights reserved.

// Package chacha_impl implements the Daido-ChaCha100 and Daido-XChaCha100 encryption algorithms
// inspired by RFC 8439.

// Daido-XCC100-Poly1305 operates at around 200MB/s unoptimized as pure Go implementation,
// and is expected to offer paranoid-level security. Optimized versions are faster.
// It will only be used to encrypt server OPAQUE AKE states and various AuthTicket structs
// XCC key will be further protected with RSA-5120-SHA3-512-OAEP
// I think the speed-for-security is justifiable and worthwhile,
// as the entire OPAQUE server stateful secret is offloaded to the client for statelessness,
// which should never be exposed, or the security guarantees of OPAQUE would be violated,
// and the server state generally weigh no more than a dozen bytes.
// AuthTicket is also extremely sensitive, and not expected to be larger than a few KBs in the
// worst-case scenario.

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"github.com/drlzh/mng-app-user-auth-prot/utils/alias/alias_impl"
	"math/bits"
)

const (
	// KeySize is the size of the key used by this cipher, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// cipher, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20 variant of
	// this cipher, in bytes.
	NonceSizeX = 24

	blockSize = 64

	bufSize = blockSize
)

// Cipher is a stateful instance of D-CC100 or D-XCC100 using a particular key
// and nonce. A *Cipher implements the cipher.Stream interface.
type Cipher struct {
	// The ChaCha100 state is 16 words: 4 constant, 8 of key, 1 of counter
	// (incremented after each block), and 3 of nonce.
	key     [8]uint32
	counter uint32
	nonce   [3]uint32

	// The last len bytes of buf are leftover key stream bytes from the previous
	// XORKeyStream invocation. The size of buf depends on how many blocks are
	// computed at a time by xorKeyStreamBlocks.
	buf [bufSize]byte
	len int

	// overflow is set when the counter overflowed, no more blocks can be
	// generated, and the next XORKeyStream call should panic.
	overflow bool

	// The counter-independent results of the first round are cached after they
	// are computed the first time.
	precompDone      bool
	p1, p5, p9, p13  uint32
	p2, p6, p10, p14 uint32
	p3, p7, p11, p15 uint32

	// Number of ChaCha rounds (must be even)
	roundCount int
}

var _ cipher.Stream = (*Cipher)(nil)

func (s *Cipher) xorKeyStreamBlocks(dst, src []byte) {
	s.xorKeyStreamBlocksGeneric(dst, src)
}

// NewUnauthenticatedCipher creates a new ChaCha100 stream cipher with the given
// 32 bytes key and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided,
// the XChaCha100 construction will be used. It returns an error if key or nonce
// have any other length.
func NewUnauthenticatedCipher(key, nonce []byte) (*Cipher, error) {
	return NewUnauthenticatedCipherWithCustomRoundCount(key, nonce, 100)
}

func NewUnauthenticatedCipherWithCustomRoundCount(key, nonce []byte, rounds int) (*Cipher, error) {
	if rounds%2 != 0 || rounds < 2 {
		return nil, errors.New("chacha: round count must be an even number ≥ 2")
	}

	// This function is split into a wrapper so that the Cipher allocation will
	// be inlined, and depending on how the caller uses the return value, won't
	// escape to the heap.
	c := &Cipher{roundCount: rounds}
	return newUnauthenticatedCipher(c, key, nonce)
}

func newUnauthenticatedCipher(c *Cipher, key, nonce []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha: wrong key size")
	}
	if len(nonce) == NonceSizeX {
		// XChaCha uses the ChaCha core to mix 16 bytes of the nonce into a
		// derived key, allowing it to operate on a nonce of 24 bytes.
		// See draft-irtf-cfrg-xchacha-01, Section 2.3.
		dk := make([]byte, 32)
		if err := hChaChaCore(dk, key, nonce[0:16], c.roundCount); err != nil {
			return nil, err
		}
		key = dk

		cNonce := make([]byte, NonceSize)
		copy(cNonce[4:12], nonce[16:24])
		nonce = cNonce
	} else if len(nonce) != NonceSize {
		return nil, errors.New("chacha: wrong nonce size")
	}

	key, nonce = key[:KeySize], nonce[:NonceSize] // bounds check elimination hint
	c.key = [8]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	}
	c.nonce = [3]uint32{
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	}
	return c, nil
}

// The constant first 4 words of the ChaCha state.
// 16-byte nothing-up-my-sleeve number
const (
	j0 uint32 = 0x41544D53 // ATMS
	j1 uint32 = 0x4B524247 // KRBG
	j2 uint32 = 0x54564C49 // TVLI
	j3 uint32 = 0x5A454849 // ZEHI
	// Extract full syllables from the romanization, take first letters of each syllable,
	// and keep the last character of both the first and last name
	// [A]r[t]e[m]                = A,T,M
	// [S][k]o[r]o[b]o[g]a[t]o[v] = S,K,R,B,G,T,V
	// [L][i]                     = L,I
	// [Z]h[e]n[h]a[i]            = Z,E,H,I
)

// quarterRound shuffles the bits of 4 state words.
// It's executed 4 times for each of the ChaCha rounds, operating on all 16
// words each round, in columnar or diagonal groups of 4 at a time.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// SetCounter sets the Cipher counter. The next invocation of XORKeyStream will
// behave as if (64 * counter) bytes had been encrypted so far.
//
// To prevent accidental counter reuse, SetCounter panics if counter is less
// than the current value.
//
// Note that the execution time of XORKeyStream is not independent of the
// counter value.
func (s *Cipher) SetCounter(counter uint32) {
	// Internally, s may buffer multiple blocks, which complicates this
	// implementation slightly. When checking whether the counter has rolled
	// back, we must use both s.counter and s.len to determine how many blocks
	// we have already output.
	outputCounter := s.counter - uint32(s.len)/blockSize
	if s.overflow || counter < outputCounter {
		panic("chacha: SetCounter attempted to rollback counter")
	}

	// In the general case, we set the new counter value and reset s.len to 0,
	// causing the next call to XORKeyStream to refill the buffer. However, if
	// we're advancing within the existing buffer, we can save work by simply
	// setting s.len.
	if counter < s.counter {
		s.len = int(s.counter-counter) * blockSize
	} else {
		s.counter = counter
		s.len = 0
	}
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream will panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Cipher
// maintains state and does not reset at each XORKeyStream call.
func (s *Cipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("chacha: output smaller than input")
	}
	dst = dst[:len(src)]
	if alias_impl.InexactOverlap(dst, src) {
		panic("chacha: invalid buffer overlap")
	}

	// First, drain any remaining key stream from a previous XORKeyStream.
	if s.len != 0 {
		keyStream := s.buf[bufSize-s.len:]
		if len(src) < len(keyStream) {
			keyStream = keyStream[:len(src)]
		}
		_ = src[len(keyStream)-1] // bounds check elimination hint
		for i, b := range keyStream {
			dst[i] = src[i] ^ b
		}
		s.len -= len(keyStream)
		dst, src = dst[len(keyStream):], src[len(keyStream):]
	}
	if len(src) == 0 {
		return
	}

	// If we'd need to let the counter overflow and keep generating output,
	// panic immediately. If instead we'd only reach the last block, remember
	// not to generate any more output after the buffer is drained.
	numBlocks := (uint64(len(src)) + blockSize - 1) / blockSize
	if s.overflow || uint64(s.counter)+numBlocks > 1<<32 {
		panic("chacha: counter overflow")
	} else if uint64(s.counter)+numBlocks == 1<<32 {
		s.overflow = true
	}

	// xorKeyStreamBlocks implementations expect input lengths that are a
	// multiple of bufSize. Platform-specific ones process multiple blocks at a
	// time, so have bufSizes that are a multiple of blockSize.

	full := len(src) - len(src)%bufSize
	if full > 0 {
		s.xorKeyStreamBlocks(dst[:full], src[:full])
	}
	dst, src = dst[full:], src[full:]

	// If using a multi-block xorKeyStreamBlocks would overflow, use the generic
	// one that does one block at a time.
	const blocksPerBuf = bufSize / blockSize
	if uint64(s.counter)+blocksPerBuf > 1<<32 {
		s.buf = [bufSize]byte{}
		numBlocks := (len(src) + blockSize - 1) / blockSize
		buf := s.buf[bufSize-numBlocks*blockSize:]
		copy(buf, src)
		s.xorKeyStreamBlocksGeneric(buf, buf)
		s.len = len(buf) - copy(dst, buf)
		return
	}

	// If we have a partial (multi-)block, pad it for xorKeyStreamBlocks, and
	// keep the leftover keystream for the next XORKeyStream invocation.
	if len(src) > 0 {
		s.buf = [bufSize]byte{}
		copy(s.buf[:], src)
		s.xorKeyStreamBlocks(s.buf[:], s.buf[:])
		s.len = bufSize - copy(dst, s.buf[:])
	}
}

func (s *Cipher) xorKeyStreamBlocksGeneric(dst, src []byte) {
	if len(dst) != len(src) || len(dst)%blockSize != 0 {
		panic("chacha: internal error: wrong dst and/or src length")
	}

	numRounds := s.roundCount
	if numRounds < 2 || numRounds%2 != 0 {
		panic("chacha: internal error: invalid round count")
	}
	numIterations := (numRounds - 2) / 2

	// To generate each block of key stream, the initial cipher state
	// (represented below) is passed through 20 rounds of shuffling,
	// alternatively applying quarterRounds by columns (like 1, 5, 9, 13)
	// or by diagonals (like 1, 6, 11, 12).
	//
	//      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
	//      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
	//     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
	//
	//            c=constant k=key b=blockcount n=nonce
	var (
		c0, c1, c2, c3   = j0, j1, j2, j3
		c4, c5, c6, c7   = s.key[0], s.key[1], s.key[2], s.key[3]
		c8, c9, c10, c11 = s.key[4], s.key[5], s.key[6], s.key[7]
		_, c13, c14, c15 = s.counter, s.nonce[0], s.nonce[1], s.nonce[2]
	)

	// Three quarters of the first round don't depend on the counter, so we can
	// calculate them here, and reuse them for multiple blocks in the loop, and
	// for future XORKeyStream invocations.
	if !s.precompDone {
		s.p1, s.p5, s.p9, s.p13 = quarterRound(c1, c5, c9, c13)
		s.p2, s.p6, s.p10, s.p14 = quarterRound(c2, c6, c10, c14)
		s.p3, s.p7, s.p11, s.p15 = quarterRound(c3, c7, c11, c15)
		s.precompDone = true
	}

	// A condition of len(src) > 0 would be sufficient, but this also
	// acts as a bounds check elimination hint.
	for len(src) >= 64 && len(dst) >= 64 {
		// The remainder of the first column round.
		fcr0, fcr4, fcr8, fcr12 := quarterRound(c0, c4, c8, s.counter)

		// The second diagonal round.
		x0, x5, x10, x15 := quarterRound(fcr0, s.p5, s.p10, s.p15)
		x1, x6, x11, x12 := quarterRound(s.p1, s.p6, s.p11, fcr12)
		x2, x7, x8, x13 := quarterRound(s.p2, s.p7, fcr8, s.p13)
		x3, x4, x9, x14 := quarterRound(s.p3, fcr4, s.p9, s.p14)

		// The remaining rounds.
		for i := 0; i < numIterations; i++ {
			// Column round.
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
		}

		// Add back the initial state to generate the key stream, then
		// XOR the key stream with the source and write out the result.
		addXor(dst[0:4], src[0:4], x0, c0)
		addXor(dst[4:8], src[4:8], x1, c1)
		addXor(dst[8:12], src[8:12], x2, c2)
		addXor(dst[12:16], src[12:16], x3, c3)
		addXor(dst[16:20], src[16:20], x4, c4)
		addXor(dst[20:24], src[20:24], x5, c5)
		addXor(dst[24:28], src[24:28], x6, c6)
		addXor(dst[28:32], src[28:32], x7, c7)
		addXor(dst[32:36], src[32:36], x8, c8)
		addXor(dst[36:40], src[36:40], x9, c9)
		addXor(dst[40:44], src[40:44], x10, c10)
		addXor(dst[44:48], src[44:48], x11, c11)
		addXor(dst[48:52], src[48:52], x12, s.counter)
		addXor(dst[52:56], src[52:56], x13, c13)
		addXor(dst[56:60], src[56:60], x14, c14)
		addXor(dst[60:64], src[60:64], x15, c15)

		s.counter += 1

		src, dst = src[blockSize:], dst[blockSize:]
	}
}

// CipherSeek sets the cipher’s stream position to the specified byte offset.
// The next XORKeyStream call will start from this byte.
// This enables streamable encryption/decryption and random access.
//
// Returns an error if offset is negative or would exceed ChaCha20's 2^32 block limit.
func (s *Cipher) CipherSeek(offset int64) error {
	if offset < 0 {
		return errors.New("chacha: cannot seek to negative offset")
	}

	block := offset / blockSize
	rem := offset % blockSize

	if block >= 1<<32 {
		return errors.New("chacha: offset too large (counter would overflow)")
	}

	s.counter = uint32(block)
	s.len = int(rem)
	s.overflow = false
	s.precompDone = false // Re-precompute after seek for safety

	return nil
}

// CipherPosition returns the number of bytes processed so far by the cipher.
func (s *Cipher) CipherPosition() uint64 {
	return uint64(s.counter)*blockSize - uint64(s.len)
}

// HChaCha uses the ChaCha core to generate a derived key from a 32 bytes
// key and a 16 bytes nonce. It returns an error if key or nonce have any other
// length. It is used as part of the XChaCha20 construction.
func HChaCha(key, nonce []byte) ([]byte, error) {
	return HChaChaWithRounds(key, nonce, 20)
}

// Public API: custom round count.
func HChaChaWithRounds(key, nonce []byte, rounds int) ([]byte, error) {
	out := make([]byte, 32)
	if err := hChaChaCore(out, key, nonce, rounds); err != nil {
		return nil, err
	}
	return out, nil
}

func hChaChaCore(out, key, nonce []byte, rounds int) error {
	if len(key) != KeySize {
		return errors.New("chacha: wrong HChaCha key size")
	}
	if len(nonce) != 16 {
		return errors.New("chacha: wrong HChaCha nonce size")
	}
	if rounds%2 != 0 || rounds < 2 {
		return errors.New("chacha: round count must be an even number ≥ 2")
	}
	_ = out[31] // BCE hint, also ensures len(out) >= 32

	x0, x1, x2, x3 := j0, j1, j2, j3
	x4 := binary.LittleEndian.Uint32(key[0:4])
	x5 := binary.LittleEndian.Uint32(key[4:8])
	x6 := binary.LittleEndian.Uint32(key[8:12])
	x7 := binary.LittleEndian.Uint32(key[12:16])
	x8 := binary.LittleEndian.Uint32(key[16:20])
	x9 := binary.LittleEndian.Uint32(key[20:24])
	x10 := binary.LittleEndian.Uint32(key[24:28])
	x11 := binary.LittleEndian.Uint32(key[28:32])
	x12 := binary.LittleEndian.Uint32(nonce[0:4])
	x13 := binary.LittleEndian.Uint32(nonce[4:8])
	x14 := binary.LittleEndian.Uint32(nonce[8:12])
	x15 := binary.LittleEndian.Uint32(nonce[12:16])

	iters := rounds / 2
	for i := 0; i < iters; i++ {
		// Column round.
		x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
		x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
		x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
		x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

		// Diagonal round.
		x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
		x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
		x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
		x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
	}

	binary.LittleEndian.PutUint32(out[0:4], x0)
	binary.LittleEndian.PutUint32(out[4:8], x1)
	binary.LittleEndian.PutUint32(out[8:12], x2)
	binary.LittleEndian.PutUint32(out[12:16], x3)
	binary.LittleEndian.PutUint32(out[16:20], x12)
	binary.LittleEndian.PutUint32(out[20:24], x13)
	binary.LittleEndian.PutUint32(out[24:28], x14)
	binary.LittleEndian.PutUint32(out[28:32], x15)
	return nil
}
