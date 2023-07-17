package actions

import (
	"github.com/quexten/goldwarden/agent/config"
	"github.com/quexten/goldwarden/agent/sockets"
	"github.com/quexten/goldwarden/agent/systemauth"
	"github.com/quexten/goldwarden/agent/vault"
	"github.com/quexten/goldwarden/ipc"
)

var AgentActionsRegistry = newActionsRegistry()

type Action func(ipc.IPCMessage, *config.Config, *vault.Vault, sockets.CallingContext) (interface{}, error)
type ActionsRegistry struct {
	actions map[ipc.IPCMessageType]Action
}

func newActionsRegistry() *ActionsRegistry {
	return &ActionsRegistry{
		actions: make(map[ipc.IPCMessageType]Action),
	}
}

func (registry *ActionsRegistry) Register(messageType ipc.IPCMessageType, action Action) {
	registry.actions[messageType] = action
}

func (registry *ActionsRegistry) Get(messageType ipc.IPCMessageType) (Action, bool) {
	action, ok := registry.actions[messageType]
	return action, ok
}

func ensureIsLoggedIn(action Action) Action {
	return func(request ipc.IPCMessage, cfg *config.Config, vault *vault.Vault, ctx sockets.CallingContext) (interface{}, error) {
		if hash, err := cfg.GetMasterPasswordHash(); err != nil || len(hash) == 0 {
			return ipc.IPCMessageFromPayload(ipc.ActionResponse{
				Success: false,
				Message: "Not logged in",
			})
		}

		return action(request, cfg, vault, ctx)
	}
}

func ensureIsNotLocked(action Action) Action {
	return func(request ipc.IPCMessage, cfg *config.Config, vault *vault.Vault, ctx sockets.CallingContext) (interface{}, error) {
		if cfg.IsLocked() {
			err := cfg.TryUnlock(vault)
			if err != nil {
				return ipc.IPCMessageFromPayload(ipc.ActionResponse{
					Success: false,
					Message: err.Error(),
				})
			}
		}

		return action(request, cfg, vault, ctx)
	}
}

func ensureBiometricsAuthorized(approvalType systemauth.Approval, action Action) Action {
	return func(request ipc.IPCMessage, cfg *config.Config, vault *vault.Vault, ctx sockets.CallingContext) (interface{}, error) {
		if !systemauth.CheckBiometrics(approvalType) {
			return ipc.IPCMessageFromPayload(ipc.ActionResponse{
				Success: false,
				Message: "Polkit authorization failed required",
			})
		}

		return action(request, cfg, vault, ctx)
	}
}

func ensureEverything(approvalType systemauth.Approval, action Action) Action {
	return ensureIsNotLocked(ensureIsLoggedIn(ensureBiometricsAuthorized(approvalType, action)))
}