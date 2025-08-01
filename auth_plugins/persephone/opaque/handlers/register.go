package handlers

import (
	"encoding/json"
	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	"time"
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

func handleRegisterStepOne(svc *opaque_api.DefaultOpaqueService, reg op.OpaqueClientReply) (any, string, string, string) {
	var clientPayload op.ClientRegistrationPayload
	if err := json.Unmarshal([]byte(reg.ClientPayload), &clientPayload); err != nil {
		return nil, "400", "Invalid client payload", err.Error()
	}

	respB64, err := svc.RegistrationStep1(clientPayload.UserID, reg.OpaqueClientResponse)
	if err != nil {
		return nil, "400", "OPAQUE step one failed", err.Error()
	}

	resp := op.OpaqueServerReply{
		CommandType:          op.OpaqueCmdRegisterStepOne,
		OpaqueServerResponse: respB64,
	}
	return resp, "200", "OPAQUE step one successful", ""
}

func handleRegisterStepTwo(svc *opaque_api.DefaultOpaqueService, reg op.OpaqueClientReply) (any, string, string, string) {
	var clientPayload op.ClientRegistrationPayload
	if err := json.Unmarshal([]byte(reg.ClientPayload), &clientPayload); err != nil {
		return nil, "400", "Invalid client payload", err.Error()
	}

	err := svc.RegistrationStep2(clientPayload.UserID, reg.OpaqueClientResponse)
	if err != nil {
		return nil, "500", "OPAQUE step two failed", err.Error()
	}

	ack := op.ServerOpaqueRegistrationSuccessAcknowledgementPayload{
		UnixTimestamp: time.Now().Unix(),
		Status:        "success",
	}

	payloadBytes, err := json.Marshal(ack)
	if err != nil {
		return nil, "500", "Failed to encode ack payload", err.Error()
	}

	resp := op.OpaqueServerReply{
		CommandType:   op.OpaqueCmdRegisterStepTwo,
		ServerPayload: string(payloadBytes),
	}
	return resp, "200", "OPAQUE registration complete", ""
}
