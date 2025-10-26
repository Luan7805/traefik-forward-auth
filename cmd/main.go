package main

import (
	"database/sql"
	"fmt"
	"net/http"

	internal "github.com/jordemort/traefik-forward-auth/internal"
	_ "github.com/lib/pq"
)

// Main
func main() {
	// Parse options
	config := internal.NewGlobalConfig()

	// Setup logger
	log := internal.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	var db *sql.DB
	if config.N8N.Enabled {
		var err error
		log.Info("Connecting to N8N database...")
		db, err = sql.Open("postgres", config.N8N.DbConnectionString)
		if err != nil {
			log.Fatalf("Failed to open N8N database connection: %v", err)
		}
		if err = db.Ping(); err != nil {
			log.Fatalf("Failed to ping N8N database: %v", err)
		}
		log.Info("Successfully connected to N8N database")
		defer db.Close()
	}

	// Build server
	server := internal.NewServer(db)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
