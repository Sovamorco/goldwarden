package pinentry

import (
	"errors"
	"os"

	"github.com/quexten/goldwarden/cli/logging"
)

var log = logging.GetLogger("Goldwarden", "Pinentry")
var systemAuthDisabled = false

type Pinentry struct {
	GetPassword func(title string, description string) (string, error)
	GetApproval func(title string, description string) (bool, error)
	Message      func(title string, description string) (func() error, error)
}

var externalPinentry Pinentry = Pinentry{}

func init() {
	if os.Getenv("GOLDWARDEN_SYSTEM_AUTH_DISABLED") == "true" {
		systemAuthDisabled = true
	}
}

func SetExternalPinentry(pinentry Pinentry) error {
	if externalPinentry.GetPassword != nil {
		return errors.New("external pinentry already set")
	}

	externalPinentry = pinentry
	return nil
}

func GetPassword(title string, description string) (string, error) {
	password, err := getPassword(title, description)
	if err == nil {
		return password, nil
	}

	if externalPinentry.GetPassword != nil {
		return externalPinentry.GetPassword(title, description)
	}

	return password, err
}

func GetApproval(title string, description string) (bool, error) {
	approval, err := getApproval(title, description)
	if err == nil {
		return approval, nil
	}

	if externalPinentry.GetApproval != nil {
		return externalPinentry.GetApproval(title, description)
	}

	return approval, err
}

func Message(title string, description string) (func() error, error) {
	cancel, err := message(title, description)
	if err == nil {
		return cancel, nil
	}

	if externalPinentry.Message != nil {
		return externalPinentry.Message(title, description)
	}

	return cancel, err
}
