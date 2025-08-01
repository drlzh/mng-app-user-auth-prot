package user_auth_global_config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type UniqueUser struct {
	TenantID    string `json:"tenant_id"`        // Which dojo?
	UserGroupID string `json:"user_group_id"`    // Role or others (if we ever need to group a few users to test groups, this will be useful)
	UserID      string `json:"user_id"`          // Currently equiv. to username
	SubID       string `json:"sub_id,omitempty"` // Reserved for future use if T+UG is not enough
}

type CoreUser struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
}

type UserGroupBinding struct {
	CoreUser    CoreUser `json:"core_user"`
	UserGroupID string   `json:"user_group_id"`    // e.g. "student", "coach"
	SubID       string   `json:"sub_id,omitempty"` // Optional disambiguator
}

type OpaqueUserRecord struct {
	OpaqueRecord []byte             `json:"opaque_record"` // OPAQUE client record
	UserGroups   []UserGroupBinding `json:"user_groups"`   // Assigned roles
}

// EncodeKey returns a safe DB key like "dojo-a|akira"
func (u CoreUser) EncodeKey() string {
	encode := url.PathEscape
	return encode(u.TenantID) + "|" + encode(u.UserID)
}

// DecodeKey parses a DB key into a CoreUser.
func DecodeKey(s string) (CoreUser, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 2 {
		return CoreUser{}, errors.New("invalid CoreUser key format")
	}
	decode := url.PathUnescape
	tid, err1 := decode(parts[0])
	uid, err2 := decode(parts[1])
	if err1 != nil || err2 != nil {
		return CoreUser{}, errors.New("failed to decode CoreUser key")
	}
	return CoreUser{TenantID: tid, UserID: uid}, nil
}

// BelongsTo verifies this role matches a CoreUser identity.
func (r UserGroupBinding) BelongsTo(user CoreUser) bool {
	return r.CoreUser.TenantID == user.TenantID && r.CoreUser.UserID == user.UserID
}

// EncodeKey generates a safe composite key if needed.
func (r UserGroupBinding) EncodeKey() string {
	encode := url.PathEscape
	return encode(r.CoreUser.TenantID) + "|" + encode(r.CoreUser.UserID) + "|" + encode(r.UserGroupID) + "|" + encode(r.SubID)
}

// AddRoles merges roles into the record with deduplication.
func (r *OpaqueUserRecord) AddRoles(newRoles []UserGroupBinding) {
	r.UserGroups = DeduplicateRoles(append(r.UserGroups, newRoles...))
}

// HasRole checks if a given role is assigned.
func (r *OpaqueUserRecord) HasRole(roleID string) bool {
	for _, role := range r.UserGroups {
		if role.UserGroupID == roleID {
			return true
		}
	}
	return false
}

// DeduplicateRoles removes duplicate (RoleID+SubID) entries.
func DeduplicateRoles(input []UserGroupBinding) []UserGroupBinding {
	seen := make(map[string]struct{})
	var result []UserGroupBinding
	for _, r := range input {
		key := r.UserGroupID + "|" + r.SubID
		if _, exists := seen[key]; !exists {
			result = append(result, r)
			seen[key] = struct{}{}
		}
	}
	return result
}

// ValidateAllRolesMatchCore ensures all roles belong to the same user.
func ValidateAllRolesMatchCore(core CoreUser, roles []UserGroupBinding) error {
	for _, r := range roles {
		if !r.BelongsTo(core) {
			return fmt.Errorf("role %+v does not match core user %+v", r, core)
		}
	}
	return nil
}

// SerializeOpaqueUserRecord → JSON
func SerializeOpaqueUserRecord(rec *OpaqueUserRecord) ([]byte, error) {
	return json.Marshal(rec)
}

// DeserializeOpaqueUserRecord ← JSON
func DeserializeOpaqueUserRecord(data []byte) (*OpaqueUserRecord, error) {
	var rec OpaqueUserRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	rec.UserGroups = DeduplicateRoles(rec.UserGroups)
	return &rec, nil
}
