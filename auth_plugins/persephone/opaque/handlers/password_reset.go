package handlers

import (
	"encoding/json"
	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	prg "github.com/drlzh/mng-app-user-auth-prot/password_reset_gate"
	ti "github.com/drlzh/mng-app-user-auth-prot/token_issuer"
)

// HandlePasswordReset dispatches OPAQUE password reset steps.
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
	allowed, err := prg.AllowPasswordReset(payload.Username)
	if err != nil {
		return nil, "500", "Reset policy check failed", err.Error()
	}
	if !allowed {
		return nil, "403", "Password reset denied", "Policy disallows reset for this user"
	}

	respB64, err := svc.PasswordResetStep1(payload.Username, req.OpaqueClientResponse)
	if err != nil {
		return nil, "400", "Password reset Step 1 failed", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:          op.OpaqueCmdPasswordResetStepOne,
		OpaqueServerResponse: respB64,
	}, "200", "OK", ""
}

func handleResetStep2(svc *opaque_api.DefaultOpaqueService, req op.OpaqueClientReply, payload op.ClientLoginPayload) (any, string, string, string) {
	err := svc.PasswordResetStep2(payload.Username, req.OpaqueClientResponse)
	if err != nil {
		return nil, "400", "Password reset Step 2 failed", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:          op.OpaqueCmdPasswordResetStepTwo,
		OpaqueServerResponse: "Password reset complete",
	}, "200", "OK", ""
}
