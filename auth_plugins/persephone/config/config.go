package config

import "time"

type Config struct {
	PoWSubject    string
	PoWDifficulty int
	PoWTTL        time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		PoWSubject:    "OPAQUE_INIT",
		PoWDifficulty: 10,
		PoWTTL:        5 * time.Minute,
	}
}
