package structs

import "time"

const (
	HydrateCmdInitiateStepOne   = "HYDRATE_INIT_STEP_ONE"
	HydrateCmdInitiateStepTwo   = "HYDRATE_INIT_STEP_TWO"
	HydrateCmdInitiateStepThree = "HYDRATE_INIT_STEP_THREE"
	HydrateCmdInitiateStepFour  = "HYDRATE_INIT_STEP_FOUR"
)

const (
	DefaultPoWDifficulty = 20
	HydratePoWTTL        = 5 * time.Minute
	DefaultPoWSubject    = "HYDRATE_INIT"
)

type HydrateInit struct {
	InitStep    string `json:"init_step"`
	InitPayload string `json:"init_payload"`
}

type ClientHydrateInitStepOnePayload struct {
	UnixTimestamp int64 `json:"unix_timestamp"`
}

type ServerHydrateInitStepTwoPayload struct {
	UnixTimestamp int64  `json:"unix_timestamp"`
	PoWChallenge  string `json:"pow_challenge"`
}

type ClientHydrateInitStepThreePayload struct {
	UnixTimestamp int64  `json:"unix_timestamp"`
	PoWSolution   string `json:"pow_challenge"`
}

type ServerHydrateInitStepFourPayload struct {
	UnixTimestamp int64 `json:"unix_timestamp"`
	Success       bool  `json:"success"`
}
