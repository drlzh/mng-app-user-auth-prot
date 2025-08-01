package structs

import "encoding/json"

type AuthGrant struct {
	Version                string          `json:"version"`
	GrantID                string          `json:"grant_id"`
	GrantType              string          `json:"grant_type"`                // e.g., "register", "reset_password"
	IssuedAtUnixTimestamp  int64           `json:"issued_at_unix_timestamp"`  // When?
	ExpiresAtUnixTimestamp int64           `json:"expires_at_unix_timestamp"` //
	AssociatedID           string          `json:"associated_id,omitempty"`   // Reserved for future Hestia integration
	Scope                  string          `json:"scope,omitempty"`           // Reserved for now
	Nonce                  string          `json:"nonce"`                     // unique per grant
	Payload                json.RawMessage `json:"payload"`                   // metadata
	SigningKeyIdentifier   string          `json:"signing_key_identifier"`    // Signed by the last authority
	Signature              string          `json:"signature"`
}
