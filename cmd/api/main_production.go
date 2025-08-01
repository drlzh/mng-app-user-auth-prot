package main

import (
	"database/sql"
	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/demeter"
	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone"
	"github.com/drlzh/mng-app-user-auth-prot/auth_server"
	"github.com/drlzh/mng-app-user-auth-prot/auth_service_registry"
	"github.com/drlzh/mng-app-user-auth-prot/internal/context"
	_ "github.com/lib/pq"
	"log"
	"os"
)

var Plugins = []auth_service_registry.PluginFactory{
	{
		Name:     "DEMETER",                // Reports health of the Authentication Service (AS)
		Handler:  demeter.NewHealthHandler, // not fully implemented yet
		Config:   nil,
		Extras:   nil,
		Required: false,
	},
	{
		Name:     "PERSEPHONE", // PSP auth protocol master router
		Handler:  func() auth_service_registry.AuthSubsystemHandler { return persephone.NewPersephoneHandler() },
		Config:   nil,              // Fallback to DefaultConfig (<ProjectRoot>\auth_plugins\persephone\config\config.go: DefaultConfig())
		Extras:   map[string]any{}, // This is cancerous and is currently deprecated
		Required: true,
	},
	// This will be a part of the Auditable Trust Service (ATS), no longer handled by AS for better decoupling
	// See <ProjectRoot>\auth_plugins\hestia\structs\hestia_structs.go for documentation
	// {
	// 	Name:     "HESTIA",
	//	Handler:  hestia.NewAuditingHandler, // not fully implemented yet
	//	Config:   nil,
	//	Extras:   nil,
	//	Required: false,
	// },
}

func connectToPostgres() *sql.DB {
	dsn := os.Getenv("PGSQL_DSN")
	if dsn == "" {
		log.Fatal("❌ Missing PGSQL_DSN environment variable")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("❌ Failed to open DB connection: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("❌ Failed to ping DB: %v", err)
	}

	log.Println("✅ Connected to PostgreSQL")
	return db
}

func main_production() {
	var db *sql.DB = nil // In production, replace with db := connectToPostgres()
	// This will make Persephone default to in-memory GhettoDB for easier local testing
	// See <ProjectRoot>\auth_plugins\persephone\persephone.go: Init()

	appCtx := &context.AppContext{DB: db}

	for _, plugin := range Plugins {
		if err := auth_service_registry.RegisterPlugin(plugin, appCtx); err != nil {
			log.Fatalf("❌ Plugin [%s] error: %v", plugin.Name, err)
		}
		log.Printf("🔌 Registered plugin: %s", plugin.Name)
	}

	log.Printf("📋 Registered routes: %v", auth_service_registry.ListRegisteredRoutes())

	auth_server.StartAuthServer()
}
