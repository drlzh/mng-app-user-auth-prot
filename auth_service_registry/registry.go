package auth_service_registry

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/drlzh/mng-app-user-auth-prot/internal/context"
)

type routeEntry struct {
	Path    string
	Handler AuthSubsystemHandler
}

var (
	mu      sync.RWMutex
	entries []routeEntry
)

func RegisterPlugin(p PluginFactory, appCtx *context.AppContext) error {
	handler := p.Handler()
	if handler == nil {
		return fmt.Errorf("plugin [%s] has nil handler", p.Name)
	}

	// Inject config
	if p.Config != nil {
		if err := handler.SetConfig(p.Config); err != nil {
			return fmt.Errorf("plugin [%s] config error: %v", p.Name, err)
		}
	}

	// Inject extras into AppContext
	if appCtx.PluginExtras == nil {
		appCtx.PluginExtras = map[string]any{}
	}
	for k, v := range p.Extras {
		appCtx.PluginExtras[k] = v
	}

	if err := handler.Init(appCtx); err != nil {
		if p.Required {
			return fmt.Errorf("❌ required plugin [%s] failed to initialize: %v", p.Name, err)
		}
		log.Printf("⚠️ skipping optional plugin [%s]: init failed: %v", p.Name, err)
		return nil
	}

	routes := handler.Routes()
	if err := checkRouteConflicts(routes); err != nil {
		if p.Required {
			return fmt.Errorf("❌ required plugin [%s] route conflict: %v", p.Name, err)
		}
		log.Printf("⚠️ skipping optional plugin [%s]: %v", p.Name, err)
		return nil
	}

	mu.Lock()
	defer mu.Unlock()
	for _, route := range routes {
		entries = append(entries, routeEntry{Path: route, Handler: handler})
	}
	return nil
}

func checkRouteConflicts(routes []string) error {
	for _, newRoute := range routes {
		for _, existing := range entries {
			if strings.HasPrefix(newRoute, existing.Path) || strings.HasPrefix(existing.Path, newRoute) {
				return fmt.Errorf("route [%s] conflicts with existing [%s]", newRoute, existing.Path)
			}
		}
	}
	return nil
}

func Dispatch(path string, payloadIn string, status, infoIn, extendedIn string) (payloadOut any, statusOut, infoOut, extendedOut string) {
	mu.RLock()
	defer mu.RUnlock()

	for _, entry := range entries {
		if strings.HasPrefix(path, entry.Path) {
			return entry.Handler.HandleRequest(path, payloadIn, status, infoIn, extendedIn)
		}
	}
	return nil, "404", "Unsupported endpoint", path
}

func ListRegisteredRoutes() []string {
	mu.RLock()
	defer mu.RUnlock()
	routes := make([]string, len(entries))
	for i, entry := range entries {
		routes[i] = entry.Path
	}
	return routes
}
