package demeter

import (
	"github.com/drlzh/mng-app-user-auth-prot/auth_service_registry"
	"github.com/drlzh/mng-app-user-auth-prot/internal/context"
)

type HealthHandler struct{}

func NewHealthHandler() auth_service_registry.AuthSubsystemHandler {
	return &HealthHandler{}
}

func (h *HealthHandler) Init(appCtx *context.AppContext) error {
	return nil
}

func (h *HealthHandler) SetConfig(config any) error {
	return nil
}

func (h *HealthHandler) GetConfig() any {
	return nil
}

func (h *HealthHandler) Routes() []string {
	return []string{"/health"}
}

func (h *HealthHandler) HandleRequest(path string, payloadIn string, statusIn, infoIn, extendedIn string) (any, string, string, string) {
	return map[string]any{
		"status": "OK",
		"routes": auth_service_registry.ListRegisteredRoutes(),
	}, "200", "OK", ""
}
