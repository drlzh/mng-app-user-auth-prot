package handlers

import (
	"encoding/json"
	op "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/pow/hashcash/hashcash_api"
)

func DispatchOpaque(
	payload string,
	traceID string,
	svc *opaque_api.DefaultOpaqueService,
) (any, string, string, string) {
	var msg op.OpaqueClientReply
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return nil, "400", "Invalid OPAQUE message", err.Error()
	}

	// PoW check — here reused across subcommands
	if err := hashcash_api.VerifyToken(msg.PoWSolution, "OPAQUE_INIT"); err != nil {
		return nil, "403", "PoW verification failed", err.Error()
	}

	switch msg.CommandType {
	case op.OpaqueCmdLoginStepOne, op.OpaqueCmdLoginStepTwo, op.OpaqueCmdLoginWithStub:
		return HandleLogin(svc, msg)

	case op.OpaqueCmdRegisterStepOne, op.OpaqueCmdRegisterStepTwo:
		return HandleRegister(svc, msg)

	case op.OpaqueCmdPasswordResetStepOne, op.OpaqueCmdPasswordResetStepTwo:
		return HandlePasswordReset(svc, msg)

	default:
		return nil, "400", "Unknown OPAQUE subcommand", msg.CommandType
	}
}
