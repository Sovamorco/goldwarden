package cmd

import (
	"fmt"

	"github.com/quexten/goldwarden/cli/ipc/messages"
	"github.com/spf13/cobra"
)

var pinCmd = &cobra.Command{
	Use:   "pin",
	Short: "Manage the vault pin",
	Long:  `Manage the vault pin. The pin is used to unlock the vault.`,
}

var setPinCmd = &cobra.Command{
	Use:   "set",
	Short: "Set a new pin",
	Long:  `Set a new pin. The pin is used to unlock the vault.`,
	Run: func(cmd *cobra.Command, args []string) {
		result, err := commandClient.SendToAgent(messages.UpdateVaultPINRequest{})
		if err != nil {
			handleSendToAgentError(err)
			return
		}

		switch result.(type) {
		case messages.ActionResponse:
			if result.(messages.ActionResponse).Success {
				fmt.Println("Pin updated")
			} else {
				fmt.Println("Pin updating failed: " + result.(messages.ActionResponse).Message)
			}
		default:
			fmt.Println("Wrong response type")
		}
	},
}

var pinStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if a pin is set",
	Long:  `Check if a pin is set. The pin is used to unlock the vault.`,
	Run: func(cmd *cobra.Command, args []string) {
		result, err := commandClient.SendToAgent(messages.GetVaultPINRequest{})
		if err != nil {
			handleSendToAgentError(err)
			return
		}

		if response, ok := result.(messages.ActionResponse); ok {
			fmt.Println("Pin status: " + response.Message)
		} else {
			fmt.Println("Wrong response type")
		}
	},
}

var pinFidoCmd = &cobra.Command{
	Use:   "fido",
	Short: "Manage the vault pin using FIDO2",
	Long:  `Manage the vault pin using FIDO2.`,
	Run: func(cmd *cobra.Command, args []string) {
		result, err := commandClient.SendToAgent(messages.UpdateVaultPINFIDORequest{})
		if err != nil {
			handleSendToAgentError(err)
			return
		}

		if response, ok := result.(messages.ActionResponse); ok {
			fmt.Println("FIDO2 pin status: " + response.Message)
		} else {
			fmt.Println("Wrong response type")
		}
	},
}

func init() {
	vaultCmd.AddCommand(pinCmd)
	pinCmd.AddCommand(setPinCmd)
	pinCmd.AddCommand(pinStatusCmd)
	pinCmd.AddCommand(pinFidoCmd)
}
