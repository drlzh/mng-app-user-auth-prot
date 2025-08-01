package protocol

import (
	psp "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/structs"
)

func HandleProtocolInit() (any, string, string, string) {
	traceID, err := GenerateTraceID()
	if err != nil {
		return nil, "500", "TraceID generation failed", err.Error()
	}

	signature, err := SignTraceID(traceID)
	if err != nil {
		return nil, "500", "TraceID signing failed", err.Error()
	}

	resp := psp.PersephoneProtocolServerReply{
		PersephoneVersion:         psp.PersephoneVersion,
		PersephoneCommand:         psp.PspCmdInitiateProtocol,
		PersephonePayload:         "",
		TraceID:                   traceID,
		TraceIDSignature:          signature,
		TraceIDSignatureAlgorithm: psp.SignatureAlgorithmEd448,
	}
	return resp, "200", "OK", ""
}
