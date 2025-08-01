package structs

import uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"

const (
	OpaqueCmdRegisterStepOne      = "OPAQUE_REGISTER_STEP_ONE"
	OpaqueCmdRegisterStepTwo      = "OPAQUE_REGISTER_STEP_TWO"
	OpaqueCmdPasswordResetStepOne = "OPAQUE_RESET_STEP_ONE"
	OpaqueCmdPasswordResetStepTwo = "OPAQUE_RESET_STEP_TWO"
)

type ServerOpaqueRegistrationSuccessAcknowledgementPayload struct {
	UnixTimestamp int64  `json:"unix_timestamp"`
	Status        string `json:"status"`
}

type ClientRegistrationPayload struct {
	User uagc.UniqueUser `json:"user"`
}
