package handlers

import (
	"encoding/json"
	config "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/config"
	hd "github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/hydrate/structs"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/pow/hashcash/hashcash_api"
	"time"
)

// HandleHydrateInit processes PSP_CMD_HYDRATE_INITIATE_HYDRATE using raw JSON payload + trace
func HandleHydrateInit(payload string, traceID string, conf *config.Config) (any, string, string, string) {
	var init hd.HydrateInit
	if err := json.Unmarshal([]byte(payload), &init); err != nil {
		return nil, "400", "Invalid HydrateInit JSON", err.Error()
	}

	switch init.InitStep {
	case hd.HydrateCmdInitiateStepOne:
		return handleInitStepOne(init.InitPayload, conf)

	case hd.HydrateCmdInitiateStepThree:
		return handleInitStepThree(init.InitPayload, conf)

	default:
		return nil, "400", "Unknown init_step", init.InitStep
	}
}

func handleInitStepOne(payload string, conf *config.Config) (any, string, string, string) {
	var step1 hd.ClientHydrateInitStepOnePayload
	if err := json.Unmarshal([]byte(payload), &step1); err != nil {
		return nil, "400", "Invalid StepOne payload", err.Error()
	}

	cfg := hashcash_api.Config{
		Subject:    conf.PoWSubject,
		Difficulty: conf.PoWDifficulty,
		TTL:        conf.PoWTTL,
	}

	chal, err := hashcash_api.CreateChallenge(cfg)
	if err != nil {
		return nil, "500", "PoW challenge creation failed", err.Error()
	}

	resp := hd.ServerHydrateInitStepTwoPayload{
		UnixTimestamp: time.Now().Unix(),
		PoWChallenge:  chal.Token,
	}
	return resp, "200", "PoW challenge issued", ""
}

func handleInitStepThree(payload string, conf *config.Config) (any, string, string, string) {
	var step3 hd.ClientHydrateInitStepThreePayload
	if err := json.Unmarshal([]byte(payload), &step3); err != nil {
		return nil, "400", "Invalid StepThree payload", err.Error()
	}

	if err := hashcash_api.VerifyToken(step3.PoWSolution, conf.PoWSubject); err != nil {
		return hd.ServerHydrateInitStepFourPayload{
			UnixTimestamp: time.Now().Unix(),
			Success:       false,
		}, "403", "PoW verification failed", err.Error()
	}

	return hd.ServerHydrateInitStepFourPayload{
		UnixTimestamp: time.Now().Unix(),
		Success:       true,
	}, "200", "PoW verified", ""
}
