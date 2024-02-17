#Python DBUS Test Server
#runs until the Quit() method is called via DBUS

from gi import require_version
require_version('Gtk', '4.0')
require_version('Adw', '1')
from gi.repository import Gtk
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from threading import Thread
import subprocess
import os

daemon_token = None
root_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, os.pardir))

class GoldwardenDBUSService(dbus.service.Object):
    def __init__(self):
        bus_name = dbus.service.BusName('com.quexten.Goldwarden.autofill', bus=dbus.SessionBus())
        dbus.service.Object.__init__(self, bus_name, '/com/quexten/Goldwarden')

    @dbus.service.method('com.quexten.Goldwarden.Autofill')
    def autofill(self):
        p = subprocess.Popen(["python3", "-m", "src.gui.quickaccess"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=root_path, start_new_session=True)
        p.stdin.write(f"{daemon_token}\n".encode())
        p.stdin.flush()
        return ""

def daemon():
    DBusGMainLoop(set_as_default=True)
    service = GoldwardenDBUSService()
    from gi.repository import GLib, GObject as gobject
    gobject.MainLoop().run()

def run_daemon(token):
    global daemon_token
    daemon_token = token
    thread = Thread(target=daemon)
    thread.start()
    