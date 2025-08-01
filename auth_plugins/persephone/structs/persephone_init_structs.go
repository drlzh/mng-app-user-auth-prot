package structs

type PersephoneClientInitiateProtocolRequest struct {
	ClientPersephoneProtocolVersion string `json:"client_persephone_protocol_version"`
	UnixTimestamp                   int64  `json:"unix_timestamp"`
}

type PersephoneServerInitiateProtocolResponse struct {
	ClientPersephoneProtocolVersion string `json:"client_persephone_protocol_version"`
	UnixTimestamp                   int64  `json:"unix_timestamp"`
	TraceID                         string `json:"trace_id,omitempty"`
	TraceIDSignature                string `json:"trace_id_signature,omitempty"`
	TraceIDSignatureAlgorithm       string `json:"trace_id_signature_algorithm,omitempty"`
}
