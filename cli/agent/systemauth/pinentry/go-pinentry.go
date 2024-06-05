//go:build freebsd || linux || darwin

package pinentry

import (
	"bufio"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/twpayne/go-pinentry"
)

func getPassword(title string, description string) (string, error) {
	binaryClientOption := pinentry.WithBinaryNameFromGnuPGAgentConf()
	if runtime.GOOS == "darwin" {
		binaryClientOption = pinentry.WithBinaryName("pinentry-mac")
	}

	client, err := pinentry.NewClient(
		binaryClientOption,
		pinentry.WithGPGTTY(),
		pinentry.WithTitle(title),
		pinentry.WithDesc(description),
		pinentry.WithPrompt(title),
	)
	log.Info("Asking for pin |%s|%s|", title, description)

	if err != nil {
		return "", err
	}
	defer client.Close()

	switch pin, fromCache, err := client.GetPIN(); {
	case pinentry.IsCancelled(err):
		log.Info("Cancelled")
		return "", errors.New("Cancelled")
	case err != nil:
		return "", err
	case fromCache:
		log.Info("Got pin from cache")
		return pin, nil
	default:
		log.Info("Got pin from user")
		return pin, nil
	}
}

func getApproval(title string, description string) (bool, error) {
	if systemAuthDisabled {
		return true, nil
	}

	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle(title),
		pinentry.WithDesc(description),
		pinentry.WithPrompt(title),
	)
	log.Info("Asking for approval |%s|%s|", title, description)

	if err != nil {
		return false, err
	}
	defer client.Close()

	switch _, err := client.Confirm("Confirm"); {
	case pinentry.IsCancelled(err):
		log.Info("Cancelled")
		return false, errors.New("Cancelled")
	case err != nil:
		return false, err
	default:
		log.Info("Got approval from user")
		return true, nil
	}
}

func message(title string, description string) (func() error, error) {
	p := process{}

	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle(title),
		pinentry.WithDesc(description),
		pinentry.WithPrompt(title),
		pinentry.WithCancel("OK"),
		pinentry.WithProcess(&p),
	)

	log.Info("Creating message |%s|%s|", title, description)

	if err != nil {
		return nil, err
	}

	go client.Confirm("OK")

	log.Info("Created message |%s|%s|", title, description)

	return p.Close, nil
}

type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func (p *process) Close() error {
	err := p.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		log.Error("Error sending SIGTERM to process: %v", err)
	}

	return p.stdin.Close()
}

func (p *process) ReadLine() ([]byte, bool, error) {
	return p.stdout.ReadLine()
}

func (p *process) Start(name string, args []string) (err error) {
	p.cmd = exec.Command(name, args...)
	p.stdin, err = p.cmd.StdinPipe()
	if err != nil {
		return
	}
	var stdoutPipe io.ReadCloser
	stdoutPipe, err = p.cmd.StdoutPipe()
	if err != nil {
		return
	}
	p.stdout = bufio.NewReader(stdoutPipe)
	err = p.cmd.Start()
	return
}

func (p *process) Write(data []byte) (int, error) {
	return p.stdin.Write(data)
}
