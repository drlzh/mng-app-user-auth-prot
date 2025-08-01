package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_ticket"
	at "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_ticket/structs"
	ss "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/secure_state"
	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/ed448/ed448_api"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
	"time"
)

func HandleLogin(
	svc *opaque_api.DefaultOpaqueService,
	req op.OpaqueClientReply,
) (any, string, string, string) {

	switch req.CommandType {
	case op.OpaqueCmdLoginStepOne:
		var clientPayload op.ClientLoginPayload
		if err := json.Unmarshal([]byte(req.ClientPayload), &clientPayload); err != nil {
			return nil, "400", "Invalid login payload", err.Error()
		}

		loginResp, serverState, err := svc.LoginStep1(clientPayload.User, req.OpaqueClientResponse)
		if err != nil {
			return nil, "400", "LoginStep1 failed", err.Error()
		}

		envelope, err := ss.CreateOpaqueStateEnvelope(
			op.OpaqueCmdLoginStepOne,
			serverState,
		)
		if err != nil {
			return nil, "500", "Failed to seal opaque state", err.Error()
		}

		reply := op.OpaqueServerReply{
			CommandType:               op.OpaqueCmdLoginStepOne,
			OpaqueServerResponse:      loginResp,
			OpaqueServerStateEnvelope: envelope,
			ServerPayload:             "",
		}
		return reply, "200", "Login Step One successful", ""

	case op.OpaqueCmdLoginStepTwo:
		sessionAuth, err := handleOpaqueLoginStepTwo(svc, req)
		if err != nil {
			return nil, "400", "LoginStep2 failed", err.Error()
		}

		reply := op.OpaqueServerReply{
			CommandType:          op.OpaqueCmdLoginStepTwo,
			OpaqueServerResponse: sessionAuth,
			ServerPayload:        "",
		}
		return reply, "200", "Login successful", ""

	case op.OpaqueCmdLoginWithStub:
		sessionAuth, err := handleOpaqueLoginWithStub(req)
		if err != nil {
			return nil, "400", "LoginWithStub failed", err.Error()
		}

		reply := op.OpaqueServerReply{
			CommandType:          op.OpaqueCmdLoginWithStub,
			OpaqueServerResponse: sessionAuth,
			ServerPayload:        "",
		}
		return reply, "200", "Login finalized", ""

	default:
		return nil, "400", "Unsupported login command", req.CommandType
	}
}

func handleOpaqueLoginStepTwo(
	svc *opaque_api.DefaultOpaqueService,
	msg op.OpaqueClientReply,
) (string, error) {
	// Parse client payload to extract username
	var clientPayload op.ClientLoginPayload
	if err := json.Unmarshal([]byte(msg.ClientPayload), &clientPayload); err != nil {
		return "", fmt.Errorf("invalid login payload: %w", err)
	}
	user := clientPayload.User

	// Envelope is embedded in msg
	env := msg.OpaqueServerStateEnvelope

	// Decrypt and verify the envelope
	state, err := ss.VerifyAndDecryptEnvelope(env)
	if err != nil {
		return "", fmt.Errorf("envelope decryption failed: %w", err)
	}

	sessionKeyB64, err := svc.LoginStep2(msg.OpaqueClientResponse, state)
	if err != nil {
		return "", fmt.Errorf("opaque login step 2 failed: %w", err)
	}

	// Decode session key
	sessionKey, err := base64.RawURLEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		return "", fmt.Errorf("session key decode failed: %w", err)
	}

	// Retrieve AT
	ticket, err := auth_ticket.CreateAuthTicket(
		user,
		at.AuthTicketPurposeLogin,
		"",
		false,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to issue token: %w", err)
	}

	ticketBytes, err := json.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("marshal auth ticket: %w", err)
	}
	ticketStr := string(ticketBytes)

	// Encrypt token with session key
	encToken, err := ss.EncryptTokenWithSessionKey(sessionKey, ticketStr)
	if err != nil {
		return "", fmt.Errorf("token encryption failed: %w", err)
	}

	// Marshal and encode final response
	resp := op.LoginSuccessResponse{
		Success:        true,
		EncryptedToken: encToken,
	}
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("marshal login success response failed: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(jsonBytes), nil
}

func handleOpaqueLoginWithStub(msg op.OpaqueClientReply) (string, error) {
	// Extract client login stub
	var stub op.ClientLoginStub
	if err := json.Unmarshal([]byte(msg.ClientPayload), &stub); err != nil {
		return "", fmt.Errorf("invalid login stub payload: %w", err)
	}
	assertion := stub.PartialLoginAssertion

	// Verify signature on PartialLoginAssertion
	if err := verifyPartialLoginAssertion(&assertion); err != nil {
		return "", fmt.Errorf("invalid partial login assertion: %w", err)
	}

	// Rehydrate UniqueUser
	user := uagc.UniqueUser{
		TenantID:    assertion.PartialUser.TenantID,
		SubID:       assertion.PartialUser.SubID,
		UserID:      assertion.PartialUser.UserID,
		UserGroupID: stub.DesiredUserGroupID,
	}

	// Create signed AuthTicket
	authTicket, err := auth_ticket.CreateAuthTicket(
		user,
		at.AuthTicketPurposeLogin,
		"",
		false,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create auth ticket: %w", err)
	}

	// Encrypt with sessionKey from KE2 (in envelope)
	env := msg.OpaqueServerStateEnvelope
	state, err := ss.VerifyAndDecryptEnvelope(env)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt opaque state: %w", err)
	}

	sessionKey, err := base64.RawURLEncoding.DecodeString(state.AkeServerState)
	if err != nil {
		return "", fmt.Errorf("invalid base64 AKE session key: %w", err)
	}

	serialized, err := json.Marshal(authTicket)
	if err != nil {
		return "", fmt.Errorf("marshal ticket failed: %w", err)
	}

	encToken, err := ss.EncryptTokenWithSessionKey(sessionKey, serialized)
	if err != nil {
		return "", fmt.Errorf("token encryption failed: %w", err)
	}

	resp := op.LoginSuccessResponse{
		Version:                   "v1",
		Success:                   true,
		RequireUserGroupSelection: false,
		EncryptedToken:            encToken,
	}
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("marshal login success response failed: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(jsonBytes), nil
}

func verifyPartialLoginAssertion(assertion *op.PartialLoginAssertion) error {
	unsigned := *assertion
	unsigned.Signature = ""

	data, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal unsigned: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(assertion.Signature)
	if err != nil {
		return fmt.Errorf("signature decode: %w", err)
	}

	if !ed448_api.Verify(sig, data, uagc.Ed448AuthTicketPublicKey()) {
		return fmt.Errorf("signature invalid")
	}

	// Optional: check freshness
	now := time.Now().Unix()
	if now-assertion.IssuedAtUnixTimestamp > 300 {
		return fmt.Errorf("assertion too old")
	}

	return nil
}
