package opaque_store

import (
	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

type OpaqueClientStore interface {
	// Save and load full user records
	SaveRaw(user user_auth_global_config.CoreUser, data []byte) error
	LoadRaw(user user_auth_global_config.CoreUser) ([]byte, error)

	// Query and manage role bindings
	GetUserGroupsForUser(user user_auth_global_config.CoreUser) ([]user_auth_global_config.UserGroupBinding, error)
	UpdateRoles(user user_auth_global_config.CoreUser, roles []user_auth_global_config.UserGroupBinding) error

	// Lifecycle
	Exists(user user_auth_global_config.CoreUser) (bool, error)
	Delete(user user_auth_global_config.CoreUser) error
}
