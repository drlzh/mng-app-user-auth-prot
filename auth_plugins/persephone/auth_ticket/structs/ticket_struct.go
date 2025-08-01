package structs

import (
	"encoding/json"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

type AuthTicket struct {
	Version               string          `json:"version"`
	AuthenticatedUser     uagc.UniqueUser `json:"authenticated_user"`       // Who is being authenticated
	IssuedAtUnixTimestamp int64           `json:"issued_at_unix_timestamp"` // When?
	Purpose               string          `json:"purpose"`                  // Why? E.g., login
	Scope                 string          `json:"scope,omitempty"`          // Reserved for now
	Nonce                 string          `json:"nonce"`                    // random string
	IsRehydrated          bool            `json:"is_rehydrated"`            // derived from RememberMe offline storage
	Payload               json.RawMessage `json:"payload"`                  // Payload
	SigningKeyIdentifier  string          `json:"signing_key_identifier"`   // allowing key rotation
	Signature             string          `json:"signature"`                // Ed448 for now
}

type RehydratedTicketPayload struct {
	HydrateVersion       string     `json:"hydrate_version"`
	AssociatedTicket     AuthTicket `json:"associated_ticket"` // The fresh AT that was used to generate this
	DeviceIdentifier     string     `json:"device_identifier"` // User's device
	SigningKeyIdentifier string     `json:"signing_key_identifier"`
	Signature            string     `json:"signature"`
}

// UserRoleSwitchPayload UserRole switch will be initiated from the offline-cached Hydrate data to
// facilitate OPAQUE-less 'signing-in-as-another-role' without necessitating a fresh AT
type UserRoleSwitchPayload struct {
	RehydratedTicketPayload RehydratedTicketPayload `json:"hydrate_associated_data"`
	SwitchFrom              uagc.UniqueUser         `json:"switch_from"`
} // TODO: add local identity remembering of the last used role as default to frontend
