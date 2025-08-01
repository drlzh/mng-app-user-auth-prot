package opaque_store

import (
	"fmt"

	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
	"github.com/drlzh/mng-app-user-auth-prot/utils/ghetto_db"
)

type GhettoAdapter struct {
	db        *ghetto_db.GhettoDB
	tableName string
}

func NewGhettoAdapter(db *ghetto_db.GhettoDB) *GhettoAdapter {
	const defaultTable = "opaque_client_store"
	db.CreateTable(defaultTable)
	return &GhettoAdapter{
		db:        db,
		tableName: defaultTable,
	}
}

// SaveRaw stores the OpaqueUserRecord JSON blob under CoreUser key.
func (a *GhettoAdapter) SaveRaw(user user_auth_global_config.CoreUser, data []byte) error {
	return a.db.Upsert(a.tableName, user.EncodeKey(), data)
}

// LoadRaw retrieves the full serialized OpaqueUserRecord.
func (a *GhettoAdapter) LoadRaw(user user_auth_global_config.CoreUser) ([]byte, error) {
	return a.db.Get(a.tableName, user.EncodeKey())
}

// Exists checks whether a CoreUser has a stored record.
func (a *GhettoAdapter) Exists(user user_auth_global_config.CoreUser) (bool, error) {
	return a.db.Exists(a.tableName, user.EncodeKey())
}

// Delete removes the full record for a CoreUser.
func (a *GhettoAdapter) Delete(user user_auth_global_config.CoreUser) error {
	return a.db.Delete(a.tableName, user.EncodeKey())
}

// GetUserGroupsForUser loads and extracts role bindings.
func (a *GhettoAdapter) GetUserGroupsForUser(user user_auth_global_config.CoreUser) ([]user_auth_global_config.UserGroupBinding, error) {
	raw, err := a.LoadRaw(user)
	if err != nil {
		return nil, fmt.Errorf("load user record: %w", err)
	}
	rec, err := user_auth_global_config.DeserializeOpaqueUserRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("deserialize user record: %w", err)
	}
	return rec.UserGroups, nil
}

// UpdateRoles replaces the role list (deduped) for the given CoreUser.
func (a *GhettoAdapter) UpdateRoles(user user_auth_global_config.CoreUser, roles []user_auth_global_config.UserGroupBinding) error {
	raw, err := a.LoadRaw(user)
	if err != nil {
		return fmt.Errorf("load record for role update: %w", err)
	}
	rec, err := user_auth_global_config.DeserializeOpaqueUserRecord(raw)
	if err != nil {
		return fmt.Errorf("deserialize for role update: %w", err)
	}
	rec.UserGroups = user_auth_global_config.DeduplicateRoles(roles)
	newBytes, err := user_auth_global_config.SerializeOpaqueUserRecord(rec)
	if err != nil {
		return fmt.Errorf("serialize updated record: %w", err)
	}
	return a.SaveRaw(user, newBytes)
}
