package structs

import "time"

const (
	OpaqueCmdInitiateStepOne   = "OPAQUE_INIT_STEP_ONE"
	OpaqueCmdInitiateStepTwo   = "OPAQUE_INIT_STEP_TWO"
	OpaqueCmdInitiateStepThree = "OPAQUE_INIT_STEP_THREE"
	OpaqueCmdInitiateStepFour  = "OPAQUE_INIT_STEP_FOUR"
)

const (
	DefaultPoWDifficulty = 20
	OpaquePoWTTL         = 5 * time.Minute
	DefaultPoWSubject    = "OPAQUE_INIT"
)

type OpaqueInit struct {
	InitStep    string `json:"init_step"`
	InitPayload string `json:"init_payload"`
}

type ClientOpaqueInitStepOnePayload struct {
	UnixTimestamp int64 `json:"unix_timestamp"`
}

type ServerOpaqueInitStepTwoPayload struct {
	UnixTimestamp int64  `json:"unix_timestamp"`
	PoWChallenge  string `json:"pow_challenge"`
}

type ClientOpaqueInitStepThreePayload struct {
	UnixTimestamp int64  `json:"unix_timestamp"`
	PoWSolution   string `json:"pow_challenge"`
}

type ServerOpaqueInitStepFourPayload struct {
	UnixTimestamp int64 `json:"unix_timestamp"`
	Success       bool  `json:"success"`
}
