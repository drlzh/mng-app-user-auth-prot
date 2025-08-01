package auth_server

import (
	"encoding/json"
	"fmt"
)

type TransportMessage struct {
	Status             string `json:"status"`
	StatusInfo         string `json:"status_info"`
	StatusExtendedInfo string `json:"status_extended_info"`
	Payload            string `json:"payload"`
}

type TransportWrapper interface {
	Unwrap(raw []byte) (payload string, status string, info string, extended string, err error)
	Wrap(payload string, status, info, extended string) ([]byte, error)
}

type DefaultTransportWrapper struct{}

func (DefaultTransportWrapper) Unwrap(raw []byte) (string, string, string, string, error) {
	var msg TransportMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return "", "", "", "", fmt.Errorf("invalid transport message: %w", err)
	}
	if msg.Payload == "" {
		return "", "", "", "", fmt.Errorf("missing payload")
	}
	return msg.Payload, msg.Status, msg.StatusInfo, msg.StatusExtendedInfo, nil
}

func (DefaultTransportWrapper) Wrap(payload string, status, info, extended string) ([]byte, error) {
	msg := TransportMessage{
		Status:             status,
		StatusInfo:         info,
		StatusExtendedInfo: extended,
		Payload:            payload,
	}
	return json.Marshal(msg)
}
