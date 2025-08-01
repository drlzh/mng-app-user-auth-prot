package secure_state

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/chacha_poly1305/chacha_poly1305_api"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/encryption/rsa/rsa_api"
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

const (
	OpaqueServerStateVersion = "v1"
	KeyBlockVersion          = "v1"
	KeyEncryptionAlgorithm   = "RSA-5120-SHA3-512-OAEP"
	SignatureAlgorithm       = "Ed448"
	AkeStateNonceSize        = 64
)

// CreateOpaqueStateEnvelope serializes, signs, encrypts, and wraps the opaque server state.
func CreateOpaqueStateEnvelope(step string, akeStateB64 string) (op.OpaqueServerStateEnvelope, error) {
	// Generate nonce
	nonce := make([]byte, AkeStateNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	// Construct OpaqueServerState
	state := op.OpaqueServerState{
		Version:            OpaqueServerStateVersion,
		Step:               step,
		AkeServerState:     akeStateB64,
		UnixTimestamp:      time.Now().Unix(),
		Nonce:              nonceB64,
		SignatureAlgorithm: SignatureAlgorithm,
	}

	// Sign the serialized state
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	sig, err := ed448_api.Sign(user_auth_global_config.Ed448PersephonePrivateKey(), stateBytes)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}
	state.Signature = base64.RawURLEncoding.EncodeToString(sig[:])

	// Re-marshal with signature
	signedStateBytes, err := json.Marshal(state)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	// Generate symmetric key
	symmetricKey := make([]byte, chacha_poly1305_api.KeySize)
	if _, err := rand.Read(symmetricKey); err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	// Encrypt state using symmetric key
	nonceEnc := make([]byte, chacha_poly1305_api.NonceSizeX)
	if _, err := rand.Read(nonceEnc); err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}
	ciphertext, err := chacha_poly1305_api.Encrypt(symmetricKey, nonceEnc, signedStateBytes, nil)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	// Encrypt symmetric key using RSA
	encKey, err := rsa_api.Encrypt(user_auth_global_config.RsaOpaqueEnvelopePublicKey(), symmetricKey, nil)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	// Sign symmetric key using Ed448
	sigKey, err := ed448_api.Sign(user_auth_global_config.Ed448PersephonePrivateKey(), symmetricKey)
	if err != nil {
		return op.OpaqueServerStateEnvelope{}, err
	}

	// Assemble envelope
	return op.OpaqueServerStateEnvelope{
		EnvelopeKeyBlock: op.EnvelopeKeyBlock{
			Version:                                KeyBlockVersion,
			EncryptedEphemeralSymmetricEnvelopeKey: base64.RawURLEncoding.EncodeToString(encKey),
			SignatureKeyID:                         SignatureAlgorithm,
			EphemeralSymmetricEnvelopeKeySignature: base64.RawURLEncoding.EncodeToString(sigKey[:]),
		},
		EncryptedOpaqueServerState: base64.RawURLEncoding.EncodeToString(append(nonceEnc, ciphertext...)),
	}, nil
}

// VerifyAndDecryptEnvelope extracts and verifies the OpaqueServerStateEnvelope and returns base64-encoded AKE state.
func VerifyAndDecryptEnvelope(env op.OpaqueServerStateEnvelope) (string, error) {
	// --- Decrypt symmetric key ---
	encKey, err := base64.RawURLEncoding.DecodeString(env.EnvelopeKeyBlock.EncryptedEphemeralSymmetricEnvelopeKey)
	if err != nil {
		return "", errors.New("invalid base64 in encrypted symmetric key")
	}
	sigKeyB64 := env.EnvelopeKeyBlock.EphemeralSymmetricEnvelopeKeySignature
	sigKeyBytes, err := base64.RawURLEncoding.DecodeString(sigKeyB64)
	if err != nil || len(sigKeyBytes) != ed448_api.SignatureSize {
		return "", errors.New("invalid signature on symmetric key")
	}
	var sigKey ed448_api.Signature
	copy(sigKey[:], sigKeyBytes)

	symmetricKey, err := rsa_api.Decrypt(user_auth_global_config.RsaOpaqueEnvelopePrivateKey(), encKey, nil)
	if err != nil {
		return "", errors.New("RSA decryption of symmetric key failed")
	}

	if !ed448_api.Verify(sigKey, symmetricKey, user_auth_global_config.Ed448PersephonePublicKey()) {
		return "", errors.New("Ed448 signature on symmetric key verification failed")
	}

	// --- Decrypt opaque state ---
	ciphertextWithNonce, err := base64.RawURLEncoding.DecodeString(env.EncryptedOpaqueServerState)
	if err != nil || len(ciphertextWithNonce) <= chacha_poly1305_api.NonceSizeX {
		return "", errors.New("invalid base64 or ciphertext size")
	}
	nonce := ciphertextWithNonce[:chacha_poly1305_api.NonceSizeX]
	ciphertext := ciphertextWithNonce[chacha_poly1305_api.NonceSizeX:]

	plaintext, err := chacha_poly1305_api.Decrypt(symmetricKey, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption of OpaqueServerState failed")
	}

	// --- Verify OpaqueServerState signature ---
	var state op.OpaqueServerState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return "", errors.New("failed to unmarshal decrypted server state")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(state.Signature)
	if err != nil || len(sigBytes) != ed448_api.SignatureSize {
		return "", errors.New("invalid base64 or length of state signature")
	}
	var sig ed448_api.Signature
	copy(sig[:], sigBytes)

	// Remove signature before verification
	stateCopy := state
	stateCopy.Signature = ""
	msgBytes, err := json.Marshal(stateCopy)
	if err != nil {
		return "", errors.New("failed to re-marshal server state for signature verification")
	}

	if !ed448_api.Verify(sig, msgBytes, user_auth_global_config.Ed448PersephonePublicKey()) {
		return "", errors.New("signature on server state verification failed")
	}

	return state.AkeServerState, nil
}
