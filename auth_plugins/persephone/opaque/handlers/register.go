package handlers

import (
	"encoding/json"
	"time"

	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

func HandleRegister(
	svc *opaque_api.DefaultOpaqueService,
	req op.OpaqueClientReply,
) (any, string, string, string) {

	switch req.CommandType {
	case op.OpaqueCmdRegisterStepOne:
		return handleRegisterStepOne(svc, req)

	case op.OpaqueCmdRegisterStepTwo:
		return handleRegisterStepTwo(svc, req)

	default:
		return nil, "400", "Unknown registration command", req.CommandType
	}
}

func handleRegisterStepOne(
	svc *opaque_api.DefaultOpaqueService,
	reg op.OpaqueClientReply,
) (any, string, string, string) {
	var clientPayload op.ClientRegistrationPayload
	if err := json.Unmarshal([]byte(reg.ClientPayload), &clientPayload); err != nil {
		return nil, "400", "Invalid client payload", err.Error()
	}

	respB64, err := svc.RegistrationStep1(clientPayload.User, reg.OpaqueClientResponse)
	if err != nil {
		return nil, "400", "OPAQUE step one failed", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:          op.OpaqueCmdRegisterStepOne,
		OpaqueServerResponse: respB64,
	}, "200", "OPAQUE step one successful", ""
}

func handleRegisterStepTwo(
	svc *opaque_api.DefaultOpaqueService,
	reg op.OpaqueClientReply,
) (any, string, string, string) {
	var clientPayload op.ClientRegistrationPayload
	if err := json.Unmarshal([]byte(reg.ClientPayload), &clientPayload); err != nil {
		return nil, "400", "Invalid client payload", err.Error()
	}

	// Step 2: Store OPAQUE record by CoreUser
	if err := svc.RegistrationStep2(clientPayload.User, reg.OpaqueClientResponse); err != nil {
		return nil, "500", "OPAQUE step two failed", err.Error()
	}

	// Step 3: Store composite roles (optional)
	if len(clientPayload.NewGroups) > 0 {
		if err := uagc.ValidateAllRolesMatchCore(clientPayload.User, clientPayload.NewGroups); err != nil {
			return nil, "400", "Invalid role bindings", err.Error()
		}
		if err := svc.Store().UpdateRoles(clientPayload.User, clientPayload.NewGroups); err != nil {
			return nil, "500", "Failed to store user roles", err.Error()
		}
	}

	ack := op.ServerOpaqueRegistrationSuccessAcknowledgementPayload{
		UnixTimestamp: time.Now().Unix(),
		Status:        "success",
	}
	payloadBytes, err := json.Marshal(ack)
	if err != nil {
		return nil, "500", "Failed to encode ack payload", err.Error()
	}

	return op.OpaqueServerReply{
		CommandType:   op.OpaqueCmdRegisterStepTwo,
		ServerPayload: string(payloadBytes),
	}, "200", "OPAQUE registration complete", ""
}
