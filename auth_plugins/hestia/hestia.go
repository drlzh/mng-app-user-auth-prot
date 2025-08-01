package hestia

import (
	"github.com/drlzh/mng-app-user-auth-prot/auth_service_registry"
	"github.com/drlzh/mng-app-user-auth-prot/internal/context"
)

type AuditingHandler struct{}

func NewAuditingHandler() auth_service_registry.AuthSubsystemHandler {
	return &AuditingHandler{}
}

func (h *AuditingHandler) Init(appCtx *context.AppContext) error {
	return nil
}

func (h *AuditingHandler) SetConfig(config any) error {
	return nil
}

func (h *AuditingHandler) GetConfig() any {
	return nil
}

func (h *AuditingHandler) Routes() []string {
	return []string{"/auditing"}
}

func (h *AuditingHandler) HandleRequest(path string, payloadIn string, statusIn, infoIn, extendedIn string) (any, string, string, string) {
	return map[string]any{
		"status": "OK",
		"routes": auth_service_registry.ListRegisteredRoutes(),
	}, "200", "OK", ""
}
