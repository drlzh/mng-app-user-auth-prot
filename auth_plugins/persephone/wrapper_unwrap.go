package persephone

import (
	"encoding/json"
	"fmt"
	psp "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/structs"
)

func WrapToPersephoneReply(
	cmd string,
	payload any,
	status, info, extended string,
	traceID string,
	signature string,
) (payloadOut any, statusOut, infoOut, extendedOut string) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "500", "Failed to marshal payload", err.Error()
	}

	pspResp := psp.PersephoneProtocolServerReply{
		PersephoneVersion:         psp.PersephoneVersion,
		PersephoneCommand:         cmd,
		PersephonePayload:         string(payloadBytes),
		TraceID:                   traceID,
		TraceIDSignature:          signature,
		TraceIDSignatureAlgorithm: psp.SignatureAlgorithmEd448,
	}

	return pspResp, status, info, extended
}

func UnwrapFromPersephoneRequest(raw string) (cmd string, payload string, traceID string, signature string, err error) {
	var req psp.PersephoneProtocolClientReply
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return "", "", "", "", err
	}

	if req.PersephoneVersion != psp.PersephoneVersion {
		return "", "", "", "", fmt.Errorf("unsupported version: %s", req.PersephoneVersion)
	}

	return req.PersephoneCommand, req.PersephonePayload, req.TraceID, req.TraceIDSignature, nil
}
