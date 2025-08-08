package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_ticket"
	at "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/auth_ticket/structs"
	ss "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/secure_state"
	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
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
			OpaqueServerResponse: "",
			ServerPayload:        sessionAuth,
		}
		return reply, "200", "Login successful", ""

	default:
		return nil, "400", "Unsupported login command", req.CommandType
	}
}

func handleOpaqueLoginStepTwo(
	svc *opaque_api.DefaultOpaqueService,
	msg op.OpaqueClientReply,
) (string, error) {
	var clientPayload op.ClientLoginPayload
	if err := json.Unmarshal([]byte(msg.ClientPayload), &clientPayload); err != nil {
		return "", fmt.Errorf("invalid login payload: %w", err)
	}
	coreUser := clientPayload.User

	env := msg.OpaqueServerStateEnvelope
	state, err := ss.VerifyAndDecryptEnvelope(env)
	if err != nil {
		return "", fmt.Errorf("envelope decryption failed: %w", err)
	}

	sessionKeyB64, err := svc.LoginStep2(msg.OpaqueClientResponse, state)
	if err != nil {
		return "", fmt.Errorf("opaque login step 2 failed: %w", err)
	}

	sessionKey, err := base64.RawURLEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		return "", fmt.Errorf("session key decode failed: %w", err)
	}

	bindings, err := svc.Store().GetUserGroupsForUser(coreUser)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user group bindings: %w", err)
	}

	var entries []op.LoginPerUserGroupEntry
	for _, b := range bindings {
		uu := uagc.UniqueUser{
			TenantID:    coreUser.TenantID,
			UserID:      coreUser.UserID,
			UserGroupID: b.UserGroupID,
			SubID:       "", // not used for now
		}

		ticket, err := auth_ticket.CreateAuthTicket(
			uu,
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

		encToken, err := ss.EncryptTokenWithSessionKey(sessionKey, string(ticketBytes))
		if err != nil {
			return "", fmt.Errorf("token encryption failed: %w", err)
		}

		entries = append(entries, op.LoginPerUserGroupEntry{
			UserGroupID:     uu.UserGroupID,
			UserGroupName:   uagc.FriendlyNameForGroupID(uu.UserGroupID),
			EncryptedTicket: encToken,
		})
	}

	resp := op.LoginSuccessResponse{
		Version:        op.LoginSuccessResponseVersion,
		Success:        true,
		UserGroupCount: len(entries),
		UserGroups:     entries,
	}

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("marshal login success response failed: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(jsonBytes), nil
}
