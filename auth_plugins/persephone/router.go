package persephone

import (
	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/config"
	handlers "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/opaque/handlers"
	proto "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/protocol"
	psp "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
)

func Dispatch(
	raw string,
	statusIn, infoIn, extendedIn string,
	svc *opaque_api.DefaultOpaqueService,
	conf *config.Config,
) (payloadOut any, statusOut, infoOut, extendedOut string) {
	cmd, payload, traceID, signature, err := UnwrapFromPersephoneRequest(raw)
	if err != nil {
		return nil, "400", "Invalid PSP request", err.Error()
	}

	// Special handling for protocol init (no signature needed)
	if cmd == psp.PspCmdInitiateProtocol {
		resp, status, info, extended := proto.HandleProtocolInit()
		return resp, status, info, extended
	}

	// Verify Trace ID signature
	if err := proto.VerifyTraceID(traceID, signature); err != nil {
		return nil, "403", "Trace validation failed", err.Error()
	}

	// Route commands
	switch cmd {
	case psp.PspCmdOpaqueInitiateOpaque:
		inner, status, info, extended := handlers.HandleOpaqueInit(payload, traceID, conf)
		return WrapToPersephoneReply(cmd, inner, status, info, extended, traceID, signature)

	case psp.PspCmdOpaqueExecute:
		inner, status, info, extended := handlers.DispatchOpaque(payload, traceID, svc)
		return WrapToPersephoneReply(cmd, inner, status, info, extended, traceID, signature)

	default:
		return nil, "400", "Unknown PSP command", cmd
	}
}
