import os
import shutil
import subprocess
import threading
import webbrowser
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib

from securityscan.ui.i18n import _, Translator
from securityscan.core.settings import app_settings

# Importa todas as abas
from securityscan.ui.tabs.clamav_tab import ClamAVTab
from securityscan.ui.tabs.rootkit_tab import RootkitTab
from securityscan.ui.tabs.tab_full import FullScanTab
from securityscan.ui.tabs.tab_quarantine import QuarantineTab
from securityscan.ui.tabs.tab_monitor import MonitorTab
from securityscan.ui.tabs.tab_updates import UpdatesTab
from securityscan.ui.tabs.tab_logs import LogsTab
from securityscan.ui.tabs.tab_scheduler import ScheduleTab


class TSSWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.set_title("Tuga Security Scan (TSS)")
        self.set_default_size(950, 700)

        # Caminho para o logo SVG
        self.logo_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data", "securityscan.svg")
        )

        # Caixa principal vertical
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(self.main_box)

        self._setup_actions()
        self._create_header_bar()
        self._create_tabs()
        GLib.idle_add(self._check_dependencies)

    # ------------------------------------------------------------------ #
    # ACTIONS
    # ------------------------------------------------------------------ #

    def _setup_actions(self):
        actions = [
            ("about",        self.on_about_action),
            ("donate",       self.on_donate_action),
            ("lang_pt",      lambda a, p: self.change_language("PT")),
            ("lang_en",      lambda a, p: self.change_language("EN")),
            ("tab_clamav",   lambda a, p: self.stack.set_visible_child_name("clamav")),
            ("tab_rootkit",  lambda a, p: self.stack.set_visible_child_name("rootkit")),
            ("tab_full",     lambda a, p: self.stack.set_visible_child_name("full")),
            ("tab_quar",     lambda a, p: self.stack.set_visible_child_name("quarantine")),
            ("tab_monitor",  lambda a, p: self.stack.set_visible_child_name("monitor")),
            ("tab_updates",  lambda a, p: self.stack.set_visible_child_name("updates")),
            ("tab_logs",     lambda a, p: self.stack.set_visible_child_name("logs")),
            ("tab_schedule", lambda a, p: self.stack.set_visible_child_name("schedule")),
        ]
        for name, callback in actions:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    # ------------------------------------------------------------------ #
    # HEADER BAR
    # ------------------------------------------------------------------ #

    def _create_header_bar(self):
        """
        Cria a HeaderBar com:
        - Título: Tuga Security Scan (TSS)
        - Menu Ferramentas (atalhos para todas as abas)
        - Botão PT | EN (idioma)
        - Botão ☕ Donativo
        - Botão Sobre
        """
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        # Título centrado
        title_widget = Adw.WindowTitle()
        title_widget.set_title("Tuga Security Scan")
        title_widget.set_subtitle("TSS by AjcpPT")
        header.set_title_widget(title_widget)

        # --- LADO ESQUERDO: Menu Ferramentas ---
        tools_btn = Gtk.MenuButton()
        tools_btn.set_label(_("menu_tools"))
        tools_btn.set_icon_name("open-menu-symbolic")
        tools_btn.set_tooltip_text(_("menu_tools"))

        tools_menu = Gio.Menu()
        tools_menu.append(_("tab_clamav"),     "win.tab_clamav")
        tools_menu.append(_("tab_rootkit"),    "win.tab_rootkit")
        tools_menu.append(_("tab_full"),       "win.tab_full")
        tools_menu.append(_("tab_quarantine"), "win.tab_quar")
        tools_menu.append(_("tab_monitor"),    "win.tab_monitor")
        tools_menu.append(_("tab_updates"),    "win.tab_updates")
        tools_menu.append(_("tab_logs"),       "win.tab_logs")
        tools_menu.append(_("tab_schedule"),   "win.tab_schedule")

        tools_btn.set_menu_model(tools_menu)
        header.pack_start(tools_btn)

        # --- LADO DIREITO: Idioma, Donativo, Sobre ---

        # Botão idioma PT | EN
        lang_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        lang_box.add_css_class("linked")  # Une os botões visualmente

        btn_pt = Gtk.Button(label="PT")
        btn_pt.set_tooltip_text("Mudar para Português")
        btn_pt.connect("clicked", lambda b: self.change_language("PT"))

        btn_en = Gtk.Button(label="EN")
        btn_en.set_tooltip_text("Switch to English")
        btn_en.connect("clicked", lambda b: self.change_language("EN"))

        lang_box.append(btn_pt)
        lang_box.append(btn_en)
        header.pack_end(lang_box)

        # Botão Sobre
        about_btn = Gtk.Button()
        about_btn.set_icon_name("help-about-symbolic")
        about_btn.set_tooltip_text(_("menu_about_app"))
        about_btn.connect("clicked", lambda b: self.on_about_action(None, None))
        header.pack_end(about_btn)

        # Botão Donativo ☕
        donate_btn = Gtk.Button(label="☕")
        donate_btn.set_tooltip_text(_("menu_donate"))
        donate_btn.connect("clicked", lambda b: self.on_donate_action(None, None))
        header.pack_end(donate_btn)

        self.main_box.append(header)

    # ------------------------------------------------------------------ #
    # TABS
    # ------------------------------------------------------------------ #

    def _create_tabs(self):
        """Cria o ViewStack com todas as abas."""
        self.stack = Adw.ViewStack()
        self.stack.set_vexpand(True)

        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)

        self.main_box.append(switcher)
        self.main_box.append(self.stack)

        # 1. ClamAV
        p = self.stack.add_titled(ClamAVTab(), "clamav", _("tab_clamav"))
        p.set_icon_name("security-high-symbolic")

        # 2. Rootkit
        p = self.stack.add_titled(RootkitTab(), "rootkit", _("tab_rootkit"))
        p.set_icon_name("find-location-symbolic")

        # 3. Full Scan
        p = self.stack.add_titled(FullScanTab(), "full", _("tab_full"))
        p.set_icon_name("system-search-symbolic")

        # 4. Quarentena
        p = self.stack.add_titled(QuarantineTab(), "quarantine", _("tab_quarantine"))
        p.set_icon_name("user-trash-symbolic")

        # 5. Monitor em tempo real
        p = self.stack.add_titled(MonitorTab(), "monitor", _("tab_monitor"))
        p.set_icon_name("network-transmit-receive-symbolic")

        # 6. Atualizações
        p = self.stack.add_titled(UpdatesTab(), "updates", _("tab_updates"))
        p.set_icon_name("software-update-available-symbolic")

        # 7. Logs
        p = self.stack.add_titled(LogsTab(), "logs", _("tab_logs"))
        p.set_icon_name("text-x-generic-symbolic")

        # 8. Agendamento
        p = self.stack.add_titled(ScheduleTab(), "schedule", _("tab_schedule"))
        p.set_icon_name("alarm-symbolic")

    # ------------------------------------------------------------------ #
    # ABOUT
    # ------------------------------------------------------------------ #

    def on_about_action(self, action, param):
        about = Adw.AboutWindow(transient_for=self)
        about.set_application_name("Tuga Security Scan (TSS)")
        about.set_version("1.0.0")
        about.set_developer_name("Arlindo Pereira")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.set_website("https://github.com/AjcpPT/TSS")
        about.set_issue_url("https://github.com/AjcpPT/TSS/issues")
        about.set_support_url("https://ko-fi.com/ajcppt")
        about.set_comments(
            "Uma suite de segurança para Linux que integra ClamAV e rkhunter/chkrootkit "
            "numa interface gráfica moderna.\n\n"
            "☕ Se gostas do TSS, podes apoiar o desenvolvimento em ko-fi.com/ajcppt"
        )
        about.add_credit_section(
            "Desenvolvimento",
            ["Arlindo Pereira (ajcppt@aol.com)", "AI Assistant"]
        )
        about.add_link(_("menu_donate"), "https://ko-fi.com/ajcppt")

        # Tenta carregar o logo SVG
        if os.path.exists(self.logo_path):
            try:
                from gi.repository import GdkPixbuf
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_size(self.logo_path, 128, 128)
                from gi.repository import Gdk
                texture = Gdk.Texture.new_for_pixbuf(pixbuf)
                about.set_application_icon("security-high-symbolic")
            except Exception:
                about.set_application_icon("security-high-symbolic")
        else:
            about.set_application_icon("security-high-symbolic")

        about.present()

    # ------------------------------------------------------------------ #
    # DONATIVO
    # ------------------------------------------------------------------ #

    def on_donate_action(self, action, param):
        """Abre o Ko-fi no browser."""
        webbrowser.open("https://ko-fi.com/ajcppt")

    # ------------------------------------------------------------------ #
    # IDIOMA
    # ------------------------------------------------------------------ #

    def change_language(self, lang_code):
        app_settings.set("language", lang_code)
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Idioma / Language",
            body="Reinicie a aplicação para aplicar as alterações.\nRestart the application to apply changes."
        )
        dialog.add_response("ok", "OK")
        dialog.present()

    # ------------------------------------------------------------------ #
    # VERIFICAÇÃO DE DEPENDÊNCIAS
    # ------------------------------------------------------------------ #

    def _is_tool_installed(self, tool_name):
        """Verifica se uma ferramenta está instalada, incluindo pastas de root."""
        if shutil.which(tool_name):
            return True
        for p in ['/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin']:
            if os.path.exists(f"{p}/{tool_name}"):
                return True
        return False

    def _check_dependencies(self):
        """Verifica se ClamAV, rkhunter e chkrootkit estão instalados."""
        missing = []
        if not self._is_tool_installed("clamscan"):
            missing.append("clamav")
        if not self._is_tool_installed("rkhunter"):
            missing.append("rkhunter")
        if not self._is_tool_installed("chkrootkit"):
            missing.append("chkrootkit")

        if missing:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading=_("missing_deps_title"),
                body=_("missing_deps_msg") + f"\n\nPacotes em falta: {', '.join(missing)}"
            )
            dialog.add_response("ignore", _("btn_ignore"))
            dialog.add_response("install", _("btn_install"))
            dialog.set_response_appearance("install", Adw.ResponseAppearance.SUGGESTED)

            def on_response(dlg, response):
                if response == "install":
                    self._install_dependencies(missing)

            dialog.connect("response", on_response)
            dialog.present()

        return False  # Remove o idle_add

    def _install_dependencies(self, missing_pkgs):
        """Instala os pacotes em falta via pkexec apt-get."""
        self.waiting_dialog = Adw.MessageDialog(
            transient_for=self,
            heading=_("missing_deps_title"),
            body=_("installing_msg")
        )
        self.waiting_dialog.present()

        def install_worker():
            cmd = ["pkexec", "apt-get", "install", "-y"] + missing_pkgs
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    GLib.idle_add(self._on_install_finished, True, "")
                else:
                    GLib.idle_add(self._on_install_finished, False, result.stderr)
            except Exception as e:
                GLib.idle_add(self._on_install_finished, False, str(e))

        thread = threading.Thread(target=install_worker, daemon=True)
        thread.start()

    def _on_install_finished(self, success, error_msg):
        """Callback após tentativa de instalação."""
        if hasattr(self, 'waiting_dialog') and self.waiting_dialog:
            self.waiting_dialog.close()

        if success:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading=_("install_success_title"),
                body=_("install_success_msg")
            )
        else:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading=_("install_error_title"),
                body=_("install_error_msg") + f"\n\nErro:\n{error_msg}"
            )
        dialog.add_response("ok", "OK")
        dialog.present()
        return False
