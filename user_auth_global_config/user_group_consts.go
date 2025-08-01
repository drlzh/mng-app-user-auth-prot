package user_auth_global_config

const (
	UserGroupAdult     = "USER_GROUP_ADULT"
	UserGroupCoach     = "USER_GROUP_COACH"
	UserGroupDeveloper = "USER_GROUP_DEVELOPER"
	UserGroupStaff     = "USER_GROUP_STAFF"
	UserGroupParent    = "USER_GROUP_PARENT"
	UserGroupChild     = "USER_GROUP_CHILD"
)

var UserGroupNames = map[string]string{
	UserGroupAdult:     "Adult Member",
	UserGroupCoach:     "Coach",
	UserGroupDeveloper: "Developer",
	UserGroupStaff:     "Staff",
	UserGroupParent:    "Parent",
	UserGroupChild:     "Child Member",
}

func FriendlyNameForGroupID(groupID string) string {
	if name, ok := UserGroupNames[groupID]; ok {
		return name
	}
	return groupID // fallback
}
