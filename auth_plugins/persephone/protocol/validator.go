package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

func GenerateTraceID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func SignTraceID(traceID string) (string, error) {
	priv := user_auth_global_config.Ed448PersephonePrivateKey()
	sig, err := ed448_api.Sign(priv, []byte(traceID))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig[:]), nil
}

func VerifyTraceID(traceID, signature string) error {
	pub := user_auth_global_config.Ed448PersephonePublicKey()
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sigBytes) != ed448_api.SignatureSize {
		return errors.New("invalid base64 or signature size")
	}

	var sig ed448_api.Signature
	copy(sig[:], sigBytes)

	if !ed448_api.Verify(sig, []byte(traceID), pub) {
		return errors.New("signature verification failed")
	}
	return nil
}
