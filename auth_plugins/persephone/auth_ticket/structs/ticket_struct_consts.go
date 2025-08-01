package structs

import "time"

const (
	AuthTicketVersion                     string        = "v1"
	AuthTicketPurposeLogin                string        = "AUTH_TICKET_PURPOSE_LOGIN"
	AuthTicketPurposeRegister             string        = "AUTH_TICKET_PURPOSE_REGISTER"
	AuthTicketPurposePasswordReset        string        = "AUTH_TICKET_PURPOSE_PASSWORD_RESET"
	AuthTicketPurposeUserRoleSwitch       string        = "AUTH_TICKET_PURPOSE_USER_ROLE_SWITCH"
	AuthTicketCurrentSigningKeyIdentifier string        = "FirstBlood"
	AuthTicketTTL                         time.Duration = 2 * time.Minute
	AuthTicketNonceSize                                 = 64
)

// Allow the user to pick Org, UserGroup, on UI without providing auto query by username
// Break simplicity but allows no info leak or DOS
