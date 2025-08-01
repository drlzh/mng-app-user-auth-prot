package structs

type OpaqueServerReply struct {
	CommandType               string                    `json:"command_type"`
	OpaqueServerStateEnvelope OpaqueServerStateEnvelope `json:"opaque_server_state_envelope,omitempty"`
	OpaqueServerResponse      string                    `json:"opaque_server_response"`
	ServerPayload             string                    `json:"server_payload,omitempty"`
}

type OpaqueClientReply struct {
	PoWSolution               string                    `json:"pow"`
	UnixTimestamp             int64                     `json:"unix_timestamp"`
	CommandType               string                    `json:"command_type"`
	OpaqueServerStateEnvelope OpaqueServerStateEnvelope `json:"opaque_server_state_envelope,omitempty"`
	OpaqueClientResponse      string                    `json:"client_response"`
	ClientPayload             string                    `json:"client_payload"`
}
