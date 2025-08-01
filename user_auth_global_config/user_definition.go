package user_auth_global_config

import (
	"errors"
	"net/url"
	"strings"
)

type UniqueUser struct {
	TenantID    string `json:"tenant_id"`        // Which dojo?
	UserGroupID string `json:"user_group_id"`    // Role or others (if we ever need to group a few users to test groups, this will be useful)
	SubID       string `json:"sub_id,omitempty"` // Reserved for future use if T+UG is not enough
	UserID      string `json:"user_id"`          // Currently equiv. to username
}

func (u UniqueUser) String() string {
	encode := url.PathEscape
	return strings.Join([]string{
		encode(u.TenantID),
		encode(u.UserID),
		encode(u.UserGroupID),
		encode(u.SubID),
	}, "|")
}

func UniqueUserFromString(s string) (UniqueUser, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 4 {
		return UniqueUser{}, errors.New("invalid UniqueUser string")
	}
	decode := url.PathUnescape
	tid, err1 := decode(parts[0])
	uid, err2 := decode(parts[1])
	ugid, err3 := decode(parts[2])
	sid, err4 := decode(parts[3])

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return UniqueUser{}, errors.New("failed to decode one or more components")
	}

	return UniqueUser{
		TenantID:    tid,
		UserID:      uid,
		UserGroupID: ugid,
		SubID:       sid,
	}, nil
}
