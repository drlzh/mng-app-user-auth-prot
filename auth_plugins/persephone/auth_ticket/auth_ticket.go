package auth_ticket

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	at "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_ticket/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
	"time"
)

func CreateAuthTicket(
	user uagc.UniqueUser,
	purpose string,
	scope string,
	isRehydrated bool,
	payload json.RawMessage,
) (*at.AuthTicket, error) {
	nonceBuf := make([]byte, at.AuthTicketNonceSize)
	if _, err := rand.Read(nonceBuf); err != nil {
		return nil, err
	}
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonceBuf)

	ticket := at.AuthTicket{
		Version:               at.AuthTicketVersion,
		AuthenticatedUser:     user,
		IssuedAtUnixTimestamp: time.Now().Unix(),
		Purpose:               purpose,
		Scope:                 scope,
		Nonce:                 nonceB64,
		IsRehydrated:          isRehydrated,
		Payload:               payload,
		SigningKeyIdentifier:  at.AuthTicketCurrentSigningKeyIdentifier,
	}

	toSign, err := json.Marshal(withoutSig(ticket))
	if err != nil {
		return nil, err
	}

	sig, err := ed448_api.Sign(uagc.Ed448AuthTicketPrivateKey(), toSign)
	if err != nil {
		return nil, err
	}
	ticket.Signature = base64.RawURLEncoding.EncodeToString(sig)

	return &ticket, nil
}

func withoutSig(t at.AuthTicket) at.AuthTicket {
	t.Signature = ""
	return t
}

func VerifyAuthTicket(ticket *at.AuthTicket) error {
	toVerify := withoutSig(*ticket)

	bytes, err := json.Marshal(toVerify)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(ticket.Signature)
	if err != nil {
		return err
	}

	if !ed448_api.Verify(sig, bytes, uagc.Ed448AuthTicketPublicKey()) {
		return errors.New("invalid signature on AuthTicket")
	}

	now := time.Now().Unix()
	if now-ticket.IssuedAtUnixTimestamp > int64(at.AuthTicketTTL.Seconds()) {
		return errors.New("auth ticket expired")
	}

	return nil
}
