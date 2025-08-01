package persephone

import (
	"errors"
	"github.com/drlzh/mng-app-user-auth-prot/auth_plugins/persephone/config"
	"github.com/drlzh/mng-app-user-auth-prot/crypto/auth/opaque/opaque_api"
	"github.com/drlzh/mng-app-user-auth-prot/internal/context"
	"github.com/drlzh/mng-app-user-auth-prot/opaque_store"
	"github.com/drlzh/mng-app-user-auth-prot/utils/ghetto_db"
)

// PSP Design Principle:
// "Good systems don't 'fight back' - they should be structurally unattackable by making attacks irrelevant, meaningless, unworthy, and harmless, so we don't have to care."
// I.e. We don’t have to be strong to 'win'; we make the battle unnecessary.
// (so that we don't need IT security staff 24x7)

type PersephoneHandler struct {
	svc  *opaque_api.DefaultOpaqueService
	conf *config.Config
}

func NewPersephoneHandler() *PersephoneHandler {
	return &PersephoneHandler{}
}

func (h *PersephoneHandler) SetConfig(c any) error {
	if c == nil {
		// Fallback to default config
		h.conf = config.DefaultConfig()
		return nil
	}

	cfg, ok := c.(*config.Config)
	if !ok || cfg == nil {
		return errors.New("invalid config type or nil pointer")
	}

	h.conf = cfg
	return nil
}

func (h *PersephoneHandler) GetConfig() any {
	return h.conf
}

func (h *PersephoneHandler) Init(ctx *context.AppContext) error {
	// Load default config if none provided
	if h.conf == nil {
		h.conf = config.DefaultConfig()
	}

	var store opaque_store.OpaqueClientStore
	if ctx.DB != nil {
		store = opaque_store.NewPgAdapter(ctx.DB)
	} else {
		store = opaque_store.NewGhettoAdapter(ghetto_db.New())
	}
	h.svc = opaque_api.NewDefaultOpaqueService(store)

	return nil
}

func (h *PersephoneHandler) Routes() []string {
	// Outer API routes for auth subsystem registry
	return []string{"/login", "/register", "/password-reset"}
}

func (h *PersephoneHandler) HandleRequest(path string, payloadIn string, statusIn, infoIn, extendedIn string) (payloadOut any, statusOut, infoOut, extendedOut string) {
	return Dispatch(payloadIn, statusIn, infoIn, extendedIn, h.svc, h.conf)
}
