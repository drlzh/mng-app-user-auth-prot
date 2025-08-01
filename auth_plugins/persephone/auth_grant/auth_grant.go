package auth_grant

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	ag "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_grant/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
	"time"
)

func CreateAuthGrant(
	grantID string,
	grantType string,
	associatedID string,
	scope string,
	payload json.RawMessage,
	ttl time.Duration,
) (*ag.AuthGrant, error) {
	nonce := make([]byte, ag.AuthGrantNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	now := time.Now().Unix()
	expiry := now + int64(ttl.Seconds())

	grant := ag.AuthGrant{
		Version:                ag.AuthGrantVersion,
		GrantID:                grantID,
		GrantType:              grantType,
		IssuedAtUnixTimestamp:  now,
		ExpiresAtUnixTimestamp: expiry,
		AssociatedID:           associatedID,
		Scope:                  scope,
		Nonce:                  nonceB64,
		Payload:                payload,
		SigningKeyIdentifier:   ag.AuthGrantCurrentSigningKeyIdentifier,
	}

	// Serialize without signature
	toSign, err := json.Marshal(withoutSig(grant))
	if err != nil {
		return nil, err
	}

	sig, err := ed448_api.Sign(uagc.Ed448AuthTicketPrivateKey(), toSign)
	if err != nil {
		return nil, err
	}
	grant.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return &grant, nil
}

func withoutSig(g ag.AuthGrant) ag.AuthGrant {
	g.Signature = ""
	return g
}

func VerifyAuthGrant(grant *ag.AuthGrant) error {
	if time.Now().Unix() > grant.ExpiresAtUnixTimestamp {
		return errors.New("auth grant has expired")
	}

	toVerify := withoutSig(*grant)

	data, err := json.Marshal(toVerify)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(grant.Signature)
	if err != nil {
		return err
	}

	if !ed448_api.Verify(sig, data, uagc.Ed448AuthTicketPublicKey()) {
		return errors.New("invalid signature on AuthGrant")
	}

	return nil
}
