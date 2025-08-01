package opaque_store

import (
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

// OpaqueClientStore defines how to load and save OPAQUE client registration records.
type OpaqueClientStore interface {
	// Save stores a serialized opaque.ClientRecord under a UniqueUser identity.
	Save(user user_auth_global_config.UniqueUser, record []byte) error

	// Load retrieves the stored record for a specific UniqueUser.
	Load(user user_auth_global_config.UniqueUser) ([]byte, error)

	// Exists checks if a registration record exists for a specific UniqueUser.
	Exists(user user_auth_global_config.UniqueUser) (bool, error)

	// FindAllIdentitiesForUserID returns all UniqueUser identities (with different UserGroupID, etc.)
	// matching the given TenantID + UserID (SubID optional).
	FindAllIdentitiesForUserID(
		tenantID string,
		userID string,
	) ([]user_auth_global_config.UniqueUser, error)

	// Delete an identity's registration record (e.g. for account deletion)
	Delete(user user_auth_global_config.UniqueUser) error
}
