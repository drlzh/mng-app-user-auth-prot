package auth_server

import (
	"encoding/json"
	"github.com/drlzh/mng-app-user-auth-prot/auth_service_registry"
	"github.com/rs/cors"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	defaultPort = ":8080"
	fullPrefix  = "/api/v1/auth/"
)

func StartAuthServer() {
	// CORS configuration – edit for production!
	c := cors.New(cors.Options{
		// AllowedOrigins must list the origin(s) you trust.
		// Use []string{"*"} only for local dev.
		// Change to real domain name
		AllowedOrigins: []string{"http://localhost:8081"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		// ExposeHeaders is optional – it tells the browser which headers
		// from the response it may read (like a custom `X-…` header).
		ExposedHeaders:   []string{"*"},
		AllowCredentials: true, // use only if you need cookies / auth header
		// Optionally enable logging in dev:
		// Debug: true,
	})

	// All routes (including `/psp`) go under the CORS handler.
	http.Handle("/", c.Handler(http.HandlerFunc(AuthEndpoint)))

	// If you have other routes (health etc.) register them BEFORE
	// the CORS wrapper, or add another `http.Handler` chain
	// that includes the CORS middleware for those routes as well.

	log.Printf("🚀 Auth server running on %s", defaultPort)
	if err := http.ListenAndServe(defaultPort, nil); err != nil {
		log.Fatalf("❌ Auth server failed: %v", err)
	}
}

/*
func StartAuthServer() {
	http.HandleFunc(fullPrefix, AuthEndpoint)

	log.Printf("🚀 Auth server running on %s", defaultPort)
	if err := http.ListenAndServe(defaultPort, nil); err != nil {
		log.Fatalf("❌ Auth server failed: %v", err)
	}
}
*/

func AuthEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "405", "Method Not Allowed", "", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		writeError(w, "415", "Unsupported Media Type", ct, http.StatusUnsupportedMediaType)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, "400", "Body Read Error", err.Error(), http.StatusBadRequest)
		return
	}

	// Use transport wrapper
	wrapper := DefaultTransportWrapper{}
	pluginPayload, statusIn, infoIn, extendedIn, err := wrapper.Unwrap(body)
	if err != nil {
		writeError(w, "400", "Transport unwrapping failed", err.Error(), http.StatusBadRequest)
		return
	}

	normalizedPath := normalizePath(r.URL.Path)
	payloadOut, statusOut, infoOut, extendedOut := auth_service_registry.Dispatch(normalizedPath, pluginPayload, statusIn, infoIn, extendedIn)

	respBytes, err := wrapper.Wrap(marshalToString(payloadOut), statusOut, infoOut, extendedOut)
	if err != nil {
		writeError(w, "500", "Transport wrapping failed", err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(mapStatusCode(statusOut))
	w.Write(respBytes)
}

func normalizePath(p string) string {
	// Strip known prefix `/api/v1/auth/`
	p = strings.TrimPrefix(p, fullPrefix)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func writeError(w http.ResponseWriter, status, info, extended string, code int) {
	resp := TransportMessage{
		Status:             status,
		StatusInfo:         info,
		StatusExtendedInfo: extended,
		Payload:            "",
	}
	respBytes, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respBytes)
}

func mapStatusCode(status string) int {
	switch status {
	case "400":
		return http.StatusBadRequest
	case "404":
		return http.StatusNotFound
	case "405":
		return http.StatusMethodNotAllowed
	case "415":
		return http.StatusUnsupportedMediaType
	case "422":
		return http.StatusUnprocessableEntity
	case "500":
		return http.StatusInternalServerError
	default:
		return http.StatusOK
	}
}

func marshalToString(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}
