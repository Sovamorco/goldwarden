import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import gc
import time
from gi.repository import Gtk, Adw, GLib
import goldwarden
import clipboard
from threading import Thread
import sys
import os

class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        self.autofill_window = MainWindow(application=app)
        self.autofill_window.logins = []
        self.autofill_window.present()
        logins = goldwarden.get_vault_logins()
        if logins == None:
            return
        app.autofill_window.logins = logins

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.set_child(self.stack)

        self.box = Gtk.Box()
        self.box.set_orientation(Gtk.Orientation.VERTICAL)
        self.stack.add_named(self.box, "box")

        self.text_view = Adw.EntryRow()
        self.text_view.set_title("Search")
        # on type func
        def on_type(entry):
            if len(entry.get_text()) > 1:
                self.history_list.show()
            else:
                self.history_list.hide()

            while self.history_list.get_first_child() != None:
                self.history_list.remove(self.history_list.get_first_child())

            self.filtered_logins = list(filter(lambda i: entry.get_text().lower() in i["name"].lower(), self.logins))
            if len( self.filtered_logins) > 10:
                 self.filtered_logins =  self.filtered_logins[0:10]
            self.starts_with_logins = list(filter(lambda i: i["name"].lower().startswith(entry.get_text().lower()), self.logins))
            self.other_logins = list(filter(lambda i: i not in self.starts_with_logins ,  self.filtered_logins))
            self.filtered_logins = None

            for i in self.starts_with_logins  + self.other_logins :
                action_row = Adw.ActionRow()
                action_row.set_title(i["name"])
                action_row.set_subtitle(i["username"])
                action_row.set_icon_name("dialog-password")
                action_row.set_activatable(True)
                action_row.password = i["password"]
                action_row.username = i["username"]
                self.history_list.append(action_row)
            self.starts_with_logins = None
            self.other_logins = None
        self.text_view.connect("changed", lambda entry: on_type(entry))
        self.box.append(self.text_view)
    
        self.history_list = Gtk.ListBox()
        # margin'
        self.history_list.set_margin_start(10)
        self.history_list.set_margin_end(10)
        self.history_list.set_margin_top(10)
        self.history_list.set_margin_bottom(10)
        self.history_list.hide()

        keycont = Gtk.EventControllerKey()
        def handle_keypress(cotroller, keyval, keycode, state, user_data):
            if keycode == 36:
                print("enter")
                self.hide()
                def do_autotype(username, password):
                    time.sleep(0.5)
                    goldwarden.autotype(username, password)
                    os._exit(0)
                autotypeThread = Thread(target=do_autotype, args=(self.history_list.get_selected_row().username, self.history_list.get_selected_row().password,))
                autotypeThread.start()
                print(self.history_list.get_selected_row().get_title())
            if keyval == 112:
                print("copy password")
                clipboard.write(self.history_list.get_selected_row().password)
            elif keyval == 117:
                print("copy username")
                clipboard.write(self.history_list.get_selected_row().username)
                
        keycont.connect('key-pressed', handle_keypress, self)
        self.add_controller(keycont)

        self.history_list.get_style_context().add_class("boxed-list")
        self.box.append(self.history_list)
        self.set_default_size(700, 700)
        self.set_title("Goldwarden")

app = MyApp(application_id="com.quexten.Goldwarden.autofill-menu")
app.run(sys.argv)