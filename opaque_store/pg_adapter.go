package opaque_store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
	_ "github.com/lib/pq"
)

/*
CREATE TABLE opaque_client_store (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
*/

type PgAdapter struct {
	db        *sql.DB
	tableName string
}

func NewPgAdapter(db *sql.DB) *PgAdapter {
	return &PgAdapter{
		db:        db,
		tableName: "opaque_client_store",
	}
}

// ─── Core ──────────────────────────────────────────────────────

func (a *PgAdapter) SaveRaw(user user_auth_global_config.CoreUser, data []byte) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (tenant_id, user_id, record)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET record = EXCLUDED.record
	`, a.tableName)
	_, err := a.db.ExecContext(context.Background(), query, user.TenantID, user.UserID, data)
	return err
}

func (a *PgAdapter) LoadRaw(user user_auth_global_config.CoreUser) ([]byte, error) {
	query := fmt.Sprintf(`SELECT record FROM %s WHERE tenant_id = $1 AND user_id = $2`, a.tableName)
	var data []byte
	err := a.db.QueryRowContext(context.Background(), query, user.TenantID, user.UserID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found: %s|%s", user.TenantID, user.UserID)
	}
	return data, err
}

func (a *PgAdapter) Exists(user user_auth_global_config.CoreUser) (bool, error) {
	query := fmt.Sprintf(`SELECT 1 FROM %s WHERE tenant_id = $1 AND user_id = $2`, a.tableName)
	var dummy int
	err := a.db.QueryRowContext(context.Background(), query, user.TenantID, user.UserID).Scan(&dummy)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (a *PgAdapter) Delete(user user_auth_global_config.CoreUser) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $1 AND user_id = $2`, a.tableName)
	_, err := a.db.ExecContext(context.Background(), query, user.TenantID, user.UserID)
	return err
}

// ─── Roles ──────────────────────────────────────────────────────

func (a *PgAdapter) GetUserGroupsForUser(user user_auth_global_config.CoreUser) ([]user_auth_global_config.UserGroupBinding, error) {
	data, err := a.LoadRaw(user)
	if err != nil {
		return nil, err
	}
	rec, err := user_auth_global_config.DeserializeOpaqueUserRecord(data)
	if err != nil {
		return nil, err
	}
	return rec.UserGroups, nil
}

func (a *PgAdapter) UpdateRoles(user user_auth_global_config.CoreUser, roles []user_auth_global_config.UserGroupBinding) error {
	data, err := a.LoadRaw(user)
	if err != nil {
		return err
	}
	rec, err := user_auth_global_config.DeserializeOpaqueUserRecord(data)
	if err != nil {
		return err
	}
	rec.UserGroups = user_auth_global_config.DeduplicateRoles(roles)
	updatedData, err := user_auth_global_config.SerializeOpaqueUserRecord(rec)
	if err != nil {
		return err
	}
	return a.SaveRaw(user, updatedData)
}
