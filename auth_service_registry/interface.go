package auth_service_registry

import "github.com/drlzh/mng-app-user-auth-prot/internal/context"

type AuthSubsystemHandler interface {
	Init(*context.AppContext) error
	SetConfig(config any) error
	GetConfig() any
	Routes() []string
	HandleRequest(path string, payloadIn string, statusIn, infoIn, extendedIn string) (payloadOut any, statusOut, infoOut, extendedOut string)
}

type PluginFactory struct {
	Name     string
	Handler  func() AuthSubsystemHandler
	Config   any
	Extras   map[string]any
	Required bool
}
