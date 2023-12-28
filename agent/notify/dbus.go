//go:build linux || freebsd

package notify

import (
	"github.com/godbus/dbus/v5"
)

var closeListenerMap = make(map[uint32]func())

func Notify(title string, body string, actionName string, onclose func()) error {
	bus, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	obj := bus.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	actions := []string{}
	if actionName != "" {
		actions = append(actions, actionName)
	}
	call := obj.Call("org.freedesktop.Notifications.Notify", 0, "goldwarden", uint32(0), "", title, body, actions, map[string]dbus.Variant{}, int32(60000))
	if call.Err != nil {
		return call.Err
	}
	if len(call.Body) < 1 {
		return nil
	}
	id := call.Body[0].(uint32)
	closeListenerMap[id] = onclose

	return nil
}

func ListenForNotifications() error {
	bus, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	err = bus.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.Notifications"))
	if err != nil {
		return err
	}

	signals := make(chan *dbus.Signal, 10)
	bus.Signal(signals)
	for {
		select {
		case message := <-signals:
			if message.Name == "org.freedesktop.Notifications.NotificationClosed" {
				if len(message.Body) < 1 {
					continue
				}
				id, ok := message.Body[0].(uint32)
				if !ok {
					continue
				}
				if id == 0 {
					continue
				}
				if closeListener, ok := closeListenerMap[id]; ok {
					delete(closeListenerMap, id)
					closeListener()
				}
			}
		}
	}

	return nil
}
