package context

import (
	"database/sql"
	ti "github.com/drlzh/mng-app-user-auth-prot/token_issuer"
)

type AppContext struct {
	DB           *sql.DB
	TokenIssuer  ti.TokenIssuer
	PluginExtras map[string]any
}
