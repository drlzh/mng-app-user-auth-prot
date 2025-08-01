package chacha_api

import (
	"errors"
	"io"

	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha/chacha_impl"
)

const DefaultRounds = 20

// ===============================
// === Encryptor/Decryptor Reader
// ===============================

// NewStreamEncryptor wraps an io.Reader with on-the-fly ChaCha encryption.
// Automatically selects ChaCha20 or XChaCha20 based on nonce size.
func NewStreamEncryptor(r io.Reader, key, nonce []byte, rounds int) (io.Reader, error) {
	return newCryptReader(r, key, nonce, rounds)
}

// NewStreamDecryptor wraps an io.Reader with on-the-fly ChaCha decryption.
// Since ChaCha is symmetric, it uses the same path as encryption.
func NewStreamDecryptor(r io.Reader, key, nonce []byte, rounds int) (io.Reader, error) {
	return newCryptReader(r, key, nonce, rounds)
}

func NewStreamEncryptorDefault(r io.Reader, key, nonce []byte) (io.Reader, error) {
	return newCryptReader(r, key, nonce, DefaultRounds)
}

func NewStreamDecryptorDefault(r io.Reader, key, nonce []byte) (io.Reader, error) {
	return newCryptReader(r, key, nonce, DefaultRounds)
}

// internal shared implementation
func newCryptReader(r io.Reader, key, nonce []byte, rounds int) (io.Reader, error) {
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		return nil, errors.New("stream: reader must implement io.ReadSeeker to support seek")
	}
	c, err := chacha_impl.NewUnauthenticatedCipherWithCustomRoundCount(key, nonce, rounds)
	if err != nil {
		return nil, err
	}
	return &streamReader{src: rs, cipher: c, buf: make([]byte, 4096)}, nil
}

type streamReader struct {
	src    io.ReadSeeker
	cipher *chacha_impl.Cipher
	buf    []byte
}

func (sr *streamReader) Read(p []byte) (int, error) {
	if cap(sr.buf) < len(p) {
		sr.buf = make([]byte, len(p))
	}
	sr.buf = sr.buf[:len(p)]

	n, err := sr.src.Read(sr.buf)
	if n > 0 {
		sr.cipher.XORKeyStream(p[:n], sr.buf[:n])
	}
	return n, err
}

func (sr *streamReader) Seek(offset int64, whence int) (int64, error) {
	newPos, err := sr.src.Seek(offset, whence)
	if err != nil {
		return 0, err
	}
	if err := sr.cipher.CipherSeek(newPos); err != nil {
		return 0, err
	}
	return newPos, nil
}

// ===============================
// === Encryptor/Decryptor Writer
// ===============================

// NewStreamEncryptorWriter wraps an io.Writer with a ChaCha stream cipher.
// It encrypts data written to it before passing to the underlying writer.
func NewStreamEncryptorWriter(w io.Writer, key, nonce []byte, rounds int) (io.WriteCloser, error) {
	return newCryptWriter(w, key, nonce, rounds)
}

// NewStreamDecryptorWriter wraps an io.Writer with a ChaCha stream cipher.
// It decrypts data before writing to the underlying writer.
func NewStreamDecryptorWriter(w io.Writer, key, nonce []byte, rounds int) (io.WriteCloser, error) {
	return newCryptWriter(w, key, nonce, rounds)
}

func NewStreamEncryptorWriterDefault(w io.Writer, key, nonce []byte) (io.WriteCloser, error) {
	return newCryptWriter(w, key, nonce, DefaultRounds)
}

func NewStreamDecryptorWriterDefault(w io.Writer, key, nonce []byte) (io.WriteCloser, error) {
	return newCryptWriter(w, key, nonce, DefaultRounds)
}

func newCryptWriter(w io.Writer, key, nonce []byte, rounds int) (io.WriteCloser, error) {
	ws, ok := w.(io.WriteSeeker)
	if !ok {
		return nil, errors.New("stream: writer must implement io.WriteSeeker to support seek")
	}
	c, err := chacha_impl.NewUnauthenticatedCipherWithCustomRoundCount(key, nonce, rounds)
	if err != nil {
		return nil, err
	}
	return &streamWriter{dst: ws, cipher: c, buf: make([]byte, 4096)}, nil
}

type streamWriter struct {
	dst    io.WriteSeeker
	cipher *chacha_impl.Cipher
	buf    []byte
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	if cap(sw.buf) < len(p) {
		sw.buf = make([]byte, len(p))
	}
	sw.buf = sw.buf[:len(p)]
	sw.cipher.XORKeyStream(sw.buf, p)
	return sw.dst.Write(sw.buf)
}

func (sw *streamWriter) Close() error {
	// nothing to clean up — just implement io.WriteCloser
	if closer, ok := sw.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (sw *streamWriter) Seek(offset int64, whence int) (int64, error) {
	newPos, err := sw.dst.Seek(offset, whence)
	if err != nil {
		return 0, err
	}
	if err := sw.cipher.CipherSeek(newPos); err != nil {
		return 0, err
	}
	return newPos, nil
}
