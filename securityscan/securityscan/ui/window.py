import os
import shutil
import subprocess
import threading
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib

from securityscan.ui.i18n import _, Translator
from securityscan.core.settings import app_settings

# Importa a aba real do ClamAV que acabámos de criar
from securityscan.ui.tabs.clamav_tab import ClamAVTab
# Importa as abas
from securityscan.ui.tabs.clamav_tab import ClamAVTab
from securityscan.ui.tabs.rootkit_tab import RootkitTab

class TSSWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        self.set_title(_("app_title"))
        self.set_default_size(900, 600)
        
        self.logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "tss_logo.png"))
        
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(self.main_box)

        self._setup_actions()
        self._create_menu_bar()
        self._create_tabs()
        GLib.idle_add(self._check_dependencies)

    def _setup_actions(self):
        actions =[
            ("about", self.on_about_action),
            ("lang_pt", lambda a, p: self.change_language("PT")),
            ("lang_en", lambda a, p: self.change_language("EN")),
            ("tab_clamav", lambda a, p: self.stack.set_visible_child_name("clamav")),
            ("tab_rootkit", lambda a, p: self.stack.set_visible_child_name("rootkit")),
            ("tab_full", lambda a, p: self.stack.set_visible_child_name("full")),
            ("tab_quar", lambda a, p: self.stack.set_visible_child_name("quarantine"))
        ]
        for name, callback in actions:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def _create_menu_bar(self):
        menu = Gio.Menu()
        file_menu = Gio.Menu()
        file_menu.append(_("menu_quit"), "app.quit")
        menu.append_submenu(_("menu_file"), file_menu)

        options_menu = Gio.Menu()
        lang_menu = Gio.Menu()
        lang_menu.append(_("menu_lang_pt"), "win.lang_pt")
        lang_menu.append(_("menu_lang_en"), "win.lang_en")
        options_menu.append_submenu(_("menu_lang"), lang_menu)
        menu.append_submenu(_("menu_options"), options_menu)

        tools_menu = Gio.Menu()
        tools_menu.append(_("tab_clamav"), "win.tab_clamav")
        tools_menu.append(_("tab_rootkit"), "win.tab_rootkit")
        tools_menu.append(_("tab_full"), "win.tab_full")
        tools_menu.append(_("tab_quarantine"), "win.tab_quar")
        menu.append_submenu(_("menu_tools"), tools_menu)

        about_menu = Gio.Menu()
        about_menu.append(_("menu_about_app"), "win.about")
        menu.append_submenu(_("menu_about"), about_menu)

        menubar = Gtk.PopoverMenuBar.new_from_model(menu)
        self.main_box.append(menubar)

def _create_tabs(self):
        """Cria o sistema de abas."""
        self.stack = Adw.ViewStack()
        self.stack.set_vexpand(True)

        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)
        self.main_box.append(switcher)
        self.main_box.append(self.stack)

        # 1. ABA DO CLAMAV
        clamav_page = self.stack.add_titled(ClamAVTab(), "clamav", _("tab_clamav"))
        clamav_page.set_icon_name("security-high-symbolic")

        # 2. ABA DO ROOTKIT (NOVA)
        rootkit_page = self.stack.add_titled(RootkitTab(), "rootkit", _("tab_rootkit"))
        rootkit_page.set_icon_name("find-location-symbolic")

        # As outras continuam placeholders até às próximas etapas
        self._add_placeholder_page("full", _("tab_full"), "system-search-symbolic")
        self._add_placeholder_page("quarantine", _("tab_quarantine"), "user-trash-symbolic")
        self._add_placeholder_page("monitor", _("tab_monitor"), "network-transmit-receive-symbolic")
        self._add_placeholder_page("logs", _("tab_logs"), "text-x-generic-symbolic")
        self._add_placeholder_page("schedule", _("tab_schedule"), "alarm-symbolic")

    def _add_placeholder_page(self, name, title, icon_name):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        label = Gtk.Label(label=f"Em construção. A carregar botões para o Módulo: {title}...")
        label.add_css_class("title-1")
        box.append(label)
        page = self.stack.add_titled(box, name, title)
        page.set_icon_name(icon_name)

    def on_about_action(self, action, param):
        about = Adw.AboutWindow(transient_for=self)
        about.set_application_name(_("app_title"))
        about.set_version("1.0.0")
        about.set_developer_name("Arlindo Pereira (ajcppt@aol.com)")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.set_website("https://github.com/AjcpPT/TSS")
        about.set_issue_url("https://github.com/AjcpPT/TSS/issues")
        about.set_support_url("https://ko-fi.com/ajcppt") 
        about.add_credit_section("Desenvolvimento Backend & Frontend",["Arlindo Pereira", "AI Assistant"])
        if os.path.exists(self.logo_path): about.set_application_icon(self.logo_path)
        about.present()

    def change_language(self, lang_code):
        app_settings.set("language", lang_code)
        dialog = Adw.MessageDialog(transient_for=self, heading="Idioma / Language", body="Reinicie a aplicação para aplicar as alterações.")
        dialog.add_response("ok", "OK")
        dialog.present()

    def _is_tool_installed(self, tool_name):
        """Verifica se a app existe de forma agressiva (inclui pastas de Root)"""
        if shutil.which(tool_name): return True
        # Procura onde o rkhunter gosta de se esconder no Linux
        for p in['/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin']:
            if os.path.exists(f"{p}/{tool_name}"): return True
        return False

    def _check_dependencies(self):
        missing =[]
        if not self._is_tool_installed("clamscan"): missing.append("clamav")
        if not self._is_tool_installed("rkhunter"): missing.append("rkhunter")
        if not self._is_tool_installed("chkrootkit"): missing.append("chkrootkit")

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
                if response == "install": self._install_dependencies(missing)
            dialog.connect("response", on_response)
            dialog.present()

    def _install_dependencies(self, missing_pkgs):
        self.waiting_dialog = Adw.MessageDialog(transient_for=self, heading=_("missing_deps_title"), body=_("installing_msg"))
        self.waiting_dialog.present()
        def install_worker():
            cmd =["pkexec", "apt-get", "install", "-y"] + missing_pkgs
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0: GLib.idle_add(self._on_install_finished, True, "")
                else: GLib.idle_add(self._on_install_finished, False, result.stderr)
            except Exception as e:
                GLib.idle_add(self._on_install_finished, False, str(e))
        thread = threading.Thread(target=install_worker, daemon=True)
        thread.start()

    def _on_install_finished(self, success, error_msg):
        if hasattr(self, 'waiting_dialog') and self.waiting_dialog: self.waiting_dialog.close()
        if success:
            dialog = Adw.MessageDialog(transient_for=self, heading=_("install_success_title"), body=_("install_success_msg"))
        else:
            dialog = Adw.MessageDialog(transient_for=self, heading=_("install_error_title"), body=_("install_error_msg") + f"\n\nErro:\n{error_msg}")
        dialog.add_response("ok", "OK")
        dialog.present()