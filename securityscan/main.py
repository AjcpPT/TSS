import sys
import gi

# Requer versões modernas do GTK
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio

from securityscan.ui.window import TSSWindow
from securityscan.ui.i18n import _

class TSSApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id='com.github.ajcppt.tss',
                         flags=Gio.ApplicationFlags.FLAGS_NONE)

    def do_startup(self):
        Adw.Application.do_startup(self)
        
        # Ação global para sair da aplicação (atalho no menu)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda a, p: self.quit())
        self.add_action(quit_action)

    def do_activate(self):
        # Cria a janela principal do Tuga Security Scan
        win = self.props.active_window
        if not win:
            win = TSSWindow(application=self)
        win.present()

if __name__ == '__main__':
    # Inicia a aplicação
    app = TSSApplication()
    exit_status = app.run(sys.argv)
    sys.exit(exit_status)