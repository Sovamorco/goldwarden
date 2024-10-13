package actions

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/keys-pub/go-libfido2"
	"github.com/quexten/goldwarden/cli/agent/bitwarden"
	"github.com/quexten/goldwarden/cli/agent/bitwarden/crypto"
	"github.com/quexten/goldwarden/cli/agent/config"
	"github.com/quexten/goldwarden/cli/agent/sockets"
	"github.com/quexten/goldwarden/cli/agent/systemauth/biometrics"
	"github.com/quexten/goldwarden/cli/agent/systemauth/pinentry"
	"github.com/quexten/goldwarden/cli/agent/vault"

	"github.com/quexten/goldwarden/cli/ipc/messages"
)

func handleUnlockVault(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	if !cfg.HasPin() {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: false,
			Message: "No pin set",
		})
		if err != nil {
			panic(err)
		}

		return
	}

	if !cfg.IsLocked() {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: true,
			Message: "Unlocked",
		})
		if err != nil {
			panic(err)
		}

		return
	}

	err = cfg.TryUnlock(vault)
	if err != nil {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: false,
			Message: "wrong pin: " + err.Error(),
		})
		if err != nil {
			panic(err)
		}

		return
	}

	actionsLog.Info("Unlocking vault...")
	if cfg.IsLoggedIn() {
		token, err := cfg.GetToken()
		if err == nil {
			if token.AccessToken != "" {
				ctx := context.Background()
				gotToken := bitwarden.RefreshToken(ctx, cfg)
				if gotToken {
					actionsLog.Info("Token refreshed")
				} else {
					actionsLog.Warn("Token refresh failed")
				}
				token, err := cfg.GetToken()
				if err != nil {
					actionsLog.Error("Could not get token: %s", err.Error())
				}
				userSymmkey, err := cfg.GetUserSymmetricKey()
				if err != nil {
					actionsLog.Error("Could not get user symmetric key: %s", err.Error())
				}

				var safeUserSymmkey crypto.SymmetricEncryptionKey
				if vault.Keyring.IsMemguard {
					safeUserSymmkey, err = crypto.MemguardSymmetricEncryptionKeyFromBytes(userSymmkey)
				} else {
					safeUserSymmkey, err = crypto.MemorySymmetricEncryptionKeyFromBytes(userSymmkey)
				}
				if err != nil {
					actionsLog.Error("Could not create safe user symmetric key: %s", err.Error())
				}

				err = bitwarden.DoFullSync(context.WithValue(ctx, bitwarden.AuthToken{}, token.AccessToken), vault, cfg, &safeUserSymmkey, true)
				if err != nil {
					actionsLog.Error("Could not sync: %s", err.Error())
				}
			} else {
				actionsLog.Warn("Access token is empty")
			}
		} else {
			actionsLog.Warn("Could not get token: %s", err.Error())
		}
	}

	response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
	})
	if err != nil {
		panic(err)
	}

	return
}

func handleLockVault(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	if !cfg.HasPin() {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: false,
			Message: "No pin set",
		})
		if err != nil {
			panic(err)
		}

		return
	}

	if cfg.IsLocked() {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: true,
			Message: "Locked",
		})
		if err != nil {
			panic(err)
		}

		return
	}

	cfg.Lock()
	vault.Clear()
	vault.Keyring.Lock()

	response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
	})
	if err != nil {
		panic(err)
	}

	return
}

func handleWipeVault(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	cfg.Purge()
	err = cfg.WriteConfig()
	if err != nil {
		panic(err)
	}
	vault.Clear()

	response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
	})
	if err != nil {
		panic(err)
	}

	return
}

func handleUpdateVaultPin(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	//todo refactor
	if cfg.HasPin() {
		authenticated := false
		if cfg.IsLocked() {
			actionsLog.Info("Browser Biometrics: Vault is locked, asking for pin...")
			err := cfg.TryUnlock(vault)
			if err != nil {
				actionsLog.Info("Browser Biometrics: Vault not unlocked")
				return messages.IPCMessage{}, err
			}
			ctx1 := context.Background()
			success := sync(ctx1, vault, cfg)
			if !success {
				actionsLog.Info("Browser Biometrics: Vault not synced")
				return messages.IPCMessage{}, err
			}
			actionsLog.Info("Browser Biometrics: Vault unlocked")
			authenticated = true
		} else {
			authenticated = biometrics.CheckBiometrics(biometrics.BrowserBiometrics)
			if !authenticated {
				// todo, skip when explicitly denied instead of error
				actionsLog.Info("Browser Biometrics: Biometrics not approved, asking for pin...")
				pin, err := pinentry.GetPassword("Goldwarden", "Enter your pin to unlock your vault")
				if err == nil {
					authenticated = cfg.VerifyPin(pin)
					if !authenticated {
						actionsLog.Info("Browser Biometrics: Pin not approved")
					} else {
						actionsLog.Info("Browser Biometrics: Pin approved")
					}
				}
			} else {
				actionsLog.Info("Browser Biometrics: Biometrics approved")
			}
		}

		if !authenticated {
			response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
				Success: false,
				Message: "Not authenticated",
			})
			if err != nil {
				return messages.IPCMessage{}, err
			} else {
				return response, nil
			}
		}
	}

	pin, err := pinentry.GetPassword("Pin Change", "Enter your desired pin")
	if err != nil {
		response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
			Success: false,
			Message: err.Error(),
		})
		if err != nil {
			return messages.IPCMessage{}, err
		} else {
			return response, nil
		}
	}

	cfg.ConfigFile.LockType = config.LockTypePin
	err = cfg.WriteConfig()
	if err != nil {
		return messages.IPCMessage{}, err
	}

	cfg.UpdatePin([]byte(pin), true)

	response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
	})

	return
}

func handlePinStatus(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	var pinStatus string
	if cfg.HasPin() {
		pinStatus = "enabled"
	} else {
		pinStatus = "disabled"
	}

	response, err = messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
		Message: pinStatus,
	})

	return
}

func handleUpdateVaultPinFido(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (messages.IPCMessage, error) {
	if cfg.HasPin() {
		authenticated := false
		if cfg.IsLocked() {
			actionsLog.Info("Browser Biometrics: Vault is locked, asking for pin...")
			err := cfg.TryUnlock(vault)
			if err != nil {
				actionsLog.Info("Browser Biometrics: Vault not unlocked")
				return messages.IPCMessage{}, err
			}
			ctx1 := context.Background()
			success := sync(ctx1, vault, cfg)
			if !success {
				actionsLog.Info("Browser Biometrics: Vault not synced")
				return messages.IPCMessage{}, err
			}
			actionsLog.Info("Browser Biometrics: Vault unlocked")
			authenticated = true
		} else {
			authenticated = biometrics.CheckBiometrics(biometrics.BrowserBiometrics)
			if !authenticated {
				// todo, skip when explicitly denied instead of error
				actionsLog.Info("Browser Biometrics: Biometrics not approved, asking for pin...")
				pin, err := pinentry.GetPassword("Goldwarden", "Enter your pin to unlock your vault")
				if err == nil {
					authenticated = cfg.VerifyPin(pin)
					if !authenticated {
						actionsLog.Info("Browser Biometrics: Pin not approved")
					} else {
						actionsLog.Info("Browser Biometrics: Pin approved")
					}
				}
			} else {
				actionsLog.Info("Browser Biometrics: Biometrics approved")
			}
		}

		if !authenticated {
			response, err := messages.IPCMessageFromPayload(messages.ActionResponse{
				Success: false,
				Message: "Not authenticated",
			})
			if err != nil {
				return messages.IPCMessage{}, err
			}

			return response, nil
		}
	}

	devices, err := libfido2.DeviceLocations()
	if err != nil {
		return messages.IPCMessage{}, err
	}

	if len(devices) == 0 {
		return messages.IPCMessage{}, errors.New("no FIDO2 devices found")
	}

	device, err := libfido2.NewDevice(devices[0].Path)
	if err != nil {
		return messages.IPCMessage{}, err
	}

	cdh := libfido2.RandBytes(32)
	userID := libfido2.RandBytes(32)

	cancel, err := pinentry.Message("Fido2", "Touch your token for attestation")
	if err != nil {
		return messages.IPCMessage{}, err
	}

	attest, err := device.MakeCredential(
		cdh,
		libfido2.RelyingParty{
			ID:   "goldwarden",
			Name: "goldwarden",
		},
		libfido2.User{
			ID:   userID,
			Name: "sovamorco@sovamor.co",
		},
		libfido2.ES256, // Algorithm
		"",
		&libfido2.MakeCredentialOpts{
			Extensions:  []libfido2.Extension{libfido2.HMACSecretExtension},
			CredProtect: libfido2.CredProtectNone,
		},
	)

	cerr := cancel()
	if cerr != nil {
		actionsLog.Error("Error cancelling pinentry prompt: %v", err)
	}

	if err != nil {
		return messages.IPCMessage{}, err
	}

	salt := libfido2.RandBytes(32)

	cdh = libfido2.RandBytes(32)

	cancel, err = pinentry.Message("Fido2", "Touch your token for assertion")
	if err != nil {
		return messages.IPCMessage{}, err
	}

	assertion, err := device.Assertion(
		"goldwarden",
		cdh,
		[][]byte{attest.CredentialID},
		"",
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			HMACSalt:   salt,
		},
	)

	cerr = cancel()
	if cerr != nil {
		actionsLog.Error("Error cancelling pinentry prompt: %v", err)
	}

	if err != nil {
		return messages.IPCMessage{}, err
	}

	cfg.ConfigFile.FIDO2.CredentialID = base64.StdEncoding.EncodeToString(attest.CredentialID)
	cfg.ConfigFile.FIDO2.Salt = base64.StdEncoding.EncodeToString(salt)
	cfg.ConfigFile.LockType = config.LockTypeFIDO2

	err = cfg.WriteConfig()
	if err != nil {
		return messages.IPCMessage{}, err
	}

	cfg.UpdatePin(assertion.HMACSecret, true)

	return messages.IPCMessageFromPayload(messages.ActionResponse{
		Success: true,
	})
}

func handleVaultStatus(request messages.IPCMessage, cfg *config.Config, vault *vault.Vault, callingContext *sockets.CallingContext) (response messages.IPCMessage, err error) {
	var vaultStatus messages.VaultStatusResponse = messages.VaultStatusResponse{}
	vaultStatus.Locked = cfg.IsLocked()
	vaultStatus.NumberOfLogins = len(vault.GetLogins())
	vaultStatus.NumberOfNotes = len(vault.GetNotes())
	vaultStatus.LastSynced = vault.GetLastSynced()
	vaultStatus.WebsocketConnected = vault.IsWebsocketConnected()
	vaultStatus.PinSet = cfg.HasPin()
	vaultStatus.LoggedIn = cfg.IsLoggedIn()
	response, err = messages.IPCMessageFromPayload(vaultStatus)
	return
}

func init() {
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.UnlockVaultRequest{}), handleUnlockVault)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.LockVaultRequest{}), handleLockVault)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.WipeVaultRequest{}), handleWipeVault)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.UpdateVaultPINRequest{}), handleUpdateVaultPin)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.GetVaultPINRequest{}), handlePinStatus)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.UpdateVaultPINFIDORequest{}), handleUpdateVaultPinFido)
	AgentActionsRegistry.Register(messages.MessageTypeForEmptyPayload(messages.VaultStatusRequest{}), handleVaultStatus)
}
