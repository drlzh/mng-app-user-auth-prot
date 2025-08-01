package structs

import (
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

/*
  OPAQUE server initialized.
  Paste `registrationRequest` from RN client: ...
  ✅ registrationResponse (send to RN client): ...
  Paste `registrationRecord` from RN client: ...
  ✅ Registration complete.
  Paste `startLoginRequest` from RN client: ...
  ✅ loginResponse (send to RN client): ...
 Paste `finishLoginRequest` from RN client: ...
  ✅ Login complete. Derived sessionKey: ...
*/

const (
	OpaqueCmdLoginStepOne = "OPAQUE_LOGIN_STEP_ONE"
	OpaqueCmdLoginStepTwo = "OPAQUE_LOGIN_STEP_TWO"
)

const (
	EnvelopeKeyBlockVersion     = "v1"
	OpaqueServerStateVersion    = "v1"
	LoginSuccessResponseVersion = "v1"
)

type EnvelopeKeyBlock struct {
	Version                                string `json:"version"`
	EncryptedEphemeralSymmetricEnvelopeKey string `json:"encrypted_ephemeral_symmetric_master_key"`
	SignatureKeyID                         string `json:"signature_key_id"`
	EphemeralSymmetricEnvelopeKeySignature string `json:"encrypted_ephemeral_symmetric_envelope_key_signature"`
}

type OpaqueServerState struct {
	Version            string `json:"version"`
	Step               string `json:"step"`
	AkeServerState     string `json:"ake_server_state"`
	UnixTimestamp      int64  `json:"unix_timestamp"`
	Nonce              string `json:"nonce"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

type OpaqueServerStateEnvelope struct {
	EnvelopeKeyBlock           EnvelopeKeyBlock `json:"envelope_key_block"`
	EncryptedOpaqueServerState string           `json:"encrypted_opaque_server_state"`
}

type ClientLoginPayload struct {
	User uagc.CoreUser `json:"user"`
}

type LoginPerUserGroupEntry struct {
	UserGroupID     string `json:"user_group_id"`
	UserGroupName   string `json:"user_group_name"`
	EncryptedTicket string `json:"encrypted_ticket"`
}

type LoginSuccessResponse struct {
	Version        string                   `json:"version"`
	Success        bool                     `json:"success"`
	UserGroupCount int                      `json:"user_group_count"`
	UserGroups     []LoginPerUserGroupEntry `json:"user_groups"`
}
