package ed448_api

import (
	"crypto"
	"crypto/rand"
	"errors"

	circl_x448 "github.com/cloudflare/circl/dh/x448"
	circl_ed448 "github.com/cloudflare/circl/sign/ed448"
)

const (
	PrivKeySize   = circl_ed448.PrivateKeySize
	PubKeySize    = circl_ed448.PublicKeySize
	SeedSize      = circl_ed448.SeedSize
	SignatureSize = circl_ed448.SignatureSize

	// X448 constants
	SharedSecretSize = circl_x448.Size
	X448KeySize      = circl_x448.Size
)

// Ed448 aliases
type (
	PrivateKey = circl_ed448.PrivateKey
	PublicKey  = circl_ed448.PublicKey
	Signature  = []byte
)

// X448 types
type (
	X448Key      = [X448KeySize]byte
	SharedSecret = [SharedSecretSize]byte
)

// ======================== Ed448 API ========================

// GenerateKeyPair generates an Ed448 keypair.
func GenerateKeyPair() (PrivateKey, PublicKey, error) {
	pub, priv, err := circl_ed448.GenerateKey(rand.Reader)
	return priv, pub, err
}

// Sign signs the message with Ed448 (pure mode, no context).
func Sign(priv PrivateKey, message []byte) (Signature, error) {
	return circl_ed448.Sign(priv, message, ""), nil
}

// Verify verifies an Ed448 signature with no context.
func Verify(sig Signature, message []byte, pub PublicKey) bool {
	return circl_ed448.Verify(pub, message, sig, "")
}

// ======================== Ed448 Extensions ========================

// SignWithContext uses Ed448 (pure) with context.
func SignWithContext(priv PrivateKey, message []byte, ctx string) (Signature, error) {
	if len(ctx) > circl_ed448.ContextMaxSize {
		return nil, errors.New("context too long (max 255 bytes)")
	}
	return circl_ed448.Sign(priv, message, ctx), nil
}

// SignPh uses Ed448ph (pre-hash) with context.
func SignPh(priv PrivateKey, message []byte, ctx string) (Signature, error) {
	if len(ctx) > circl_ed448.ContextMaxSize {
		return nil, errors.New("context too long (max 255 bytes)")
	}
	return circl_ed448.SignPh(priv, message, ctx), nil
}

// VerifyWithContext verifies an Ed448 signature with context.
func VerifyWithContext(pub PublicKey, message, sig []byte, ctx string) bool {
	return circl_ed448.Verify(pub, message, sig, ctx)
}

// VerifyPh verifies an Ed448ph signature with context.
func VerifyPh(pub PublicKey, message, sig []byte, ctx string) bool {
	return circl_ed448.VerifyPh(pub, message, sig, ctx)
}

// SignWithOpts signs using either Ed448 or Ed448Ph based on SignerOptions.
func SignWithOpts(priv PrivateKey, message []byte, opts *circl_ed448.SignerOptions) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("SignerOpts must use crypto.Hash(0)")
	}
	return priv.Sign(rand.Reader, message, opts)
}

// VerifyAny verifies a signature using SignerOptions (pure or pre-hash).
func VerifyAny(pub PublicKey, message, sig []byte, opts crypto.SignerOpts) bool {
	return circl_ed448.VerifyAny(pub, message, sig, opts)
}

// NewKeyFromSeed creates a deterministic Ed448 private key from a 57-byte seed.
func NewKeyFromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("invalid seed length (must be 57 bytes)")
	}
	return circl_ed448.NewKeyFromSeed(seed), nil
}

// ======================== X448 API ========================

// GenerateX448KeyPair generates a new X448 (ECDH) keypair.
func GenerateX448KeyPair() (priv X448Key, pub X448Key, err error) {
	priv, err = generateX448SecretKey()
	if err != nil {
		return
	}
	circl_x448.KeyGen((*circl_x448.Key)(&pub), (*circl_x448.Key)(&priv))
	return priv, pub, nil
}

func generateX448SecretKey() (secret X448Key, err error) {
	_, err = rand.Read(secret[:])
	if err != nil {
		return X448Key{}, err
	}
	// Clamp as per RFC 7748
	secret[0] &= 252
	secret[55] |= 128
	secret[55] &= 127
	return secret, nil
}

// ComputeSharedSecret computes a shared secret from own private and peer public X448 keys.
func ComputeSharedSecret(myPriv X448Key, theirPub X448Key) (SharedSecret, error) {
	var shared SharedSecret
	success := circl_x448.Shared((*circl_x448.Key)(&shared), (*circl_x448.Key)(&myPriv), (*circl_x448.Key)(&theirPub))
	if !success {
		return SharedSecret{}, errors.New("invalid peer public key (low-order point)")
	}
	return shared, nil
}
