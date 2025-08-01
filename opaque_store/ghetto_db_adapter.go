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

func (a *GhettoAdapter) Save(user user_auth_global_config.UniqueUser, record []byte) error {
	return a.db.Upsert(a.tableName, user.String(), record)
}

func (a *GhettoAdapter) Load(user user_auth_global_config.UniqueUser) ([]byte, error) {
	return a.db.Get(a.tableName, user.String())
}

func (a *GhettoAdapter) Exists(user user_auth_global_config.UniqueUser) (bool, error) {
	return a.db.Exists(a.tableName, user.String())
}

func (a *GhettoAdapter) FindAllIdentitiesForUserID(
	tenantID string,
	userID string,
) ([]user_auth_global_config.UniqueUser, error) {
	keys, err := a.db.ListKeys(a.tableName)
	if err != nil {
		return nil, fmt.Errorf("list keys error: %w", err)
	}

	var matches []user_auth_global_config.UniqueUser
	for _, k := range keys {
		u, err := user_auth_global_config.UniqueUserFromString(k)
		if err != nil {
			continue // skip malformed
		}
		if u.TenantID == tenantID && u.UserID == userID {
			matches = append(matches, u)
		}
	}
	return matches, nil
}

func (a *GhettoAdapter) Delete(user user_auth_global_config.UniqueUser) error {
	return a.db.Delete(a.tableName, user.String())
}
