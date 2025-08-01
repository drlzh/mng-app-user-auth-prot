package context

import (
	"database/sql"
)

type AppContext struct {
	DB           *sql.DB
	PluginExtras map[string]any
}
