package structs

type PersephoneProtocolClientReply struct {
	PersephoneVersion         string `json:"persephone_version"`
	PersephoneCommand         string `json:"persephone_command"`
	PersephonePayload         string `json:"persephone_payload"`
	TraceID                   string `json:"trace_id,omitempty"`
	TraceIDSignature          string `json:"trace_id_signature,omitempty"`
	TraceIDSignatureAlgorithm string `json:"trace_id_signature_algorithm,omitempty"`
}

type PersephoneProtocolServerReply struct {
	PersephoneVersion         string `json:"persephone_version"`
	PersephoneCommand         string `json:"persephone_command"`
	PersephonePayload         string `json:"persephone_payload"`
	TraceID                   string `json:"trace_id,omitempty"`
	TraceIDSignature          string `json:"trace_id_signature,omitempty"`
	TraceIDSignatureAlgorithm string `json:"trace_id_signature_algorithm,omitempty"`
}
