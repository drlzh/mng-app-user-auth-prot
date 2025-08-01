package handlers

import (
	"encoding/json"
	"time"

	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
)

func HandlePasswordReset(
	svc *opaque_api.DefaultOpaqueService,
	req op.OpaqueClientReply,
) (any, string, string, string) {
	var payload op.ClientLoginPayload
	if err := json.Unmarshal([]byte(req.ClientPayload), &payload); err != nil {
		return nil, "400", "Invalid client payload", err.Error()
	}

	switch req.CommandType {
	case op.OpaqueCmdPasswordResetStepOne:
		return handleResetStep1(svc, req, payload)

	case op.OpaqueCmdPasswordResetStepTwo:
		return handleResetStep2(svc, req, payload)

	default:
		return nil, "400", "Unsupported password reset command", req.CommandType
	}
}

func handleResetStep1(
	svc *opaque_api.DefaultOpaqueService,
	req op.OpaqueClientReply,
	payload op.ClientLoginPayload,
) (any, string, string, string) {
	respB64, err := svc.PasswordResetStep1(payload.User, req.OpaqueClientResponse)
	if err != nil {
		return nil, "400", "Password reset Step 1 failed", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:          op.OpaqueCmdPasswordResetStepOne,
		OpaqueServerResponse: respB64,
	}, "200", "OK", ""
}

func handleResetStep2(
	svc *opaque_api.DefaultOpaqueService,
	req op.OpaqueClientReply,
	payload op.ClientLoginPayload,
) (any, string, string, string) {
	if err := svc.PasswordResetStep2(payload.User, req.OpaqueClientResponse); err != nil {
		return nil, "400", "Password reset Step 2 failed", err.Error()
	}

	ack := op.ServerOpaqueRegistrationSuccessAcknowledgementPayload{
		UnixTimestamp: time.Now().Unix(),
		Status:        "password_reset_complete",
	}

	payloadBytes, err := json.Marshal(ack)
	if err != nil {
		return nil, "500", "Failed to encode ack payload", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:   op.OpaqueCmdPasswordResetStepTwo,
		ServerPayload: string(payloadBytes),
	}, "200", "OK", ""
}
