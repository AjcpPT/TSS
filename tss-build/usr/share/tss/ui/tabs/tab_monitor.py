import os
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib

# Importa o motor de proteção ativa e definições
from securityscan.core.monitor import monitor_manager
from securityscan.core.settings import app_settings
from securityscan.ui.i18n import _

class MonitorTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Título
        title = Gtk.Label(label=_("tab_monitor"))
        title.add_css_class("title-1")
        self.append(title)

        info = Gtk.Label(label="Monitoriza a pasta selecionada em tempo real.\nFicheiros maliciosos recém-criados ou descarregados são enviados automaticamente para a Quarentena.")
        info.set_justify(Gtk.Justification.CENTER)
        info.add_css_class("dim-label")
        self.append(info)

        # --- SELEÇÃO DA PASTA ALVO ---
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        target_box.set_halign(Gtk.Align.CENTER)
        
        target_box.append(Gtk.Label(label="Pasta a Vigiar: "))
        
        # Define a pasta de Transferências por defeito, se não houver outra guardada
        dl_path = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not dl_path:
            dl_path = os.path.expanduser("~/Downloads")
            
        self.target_path = app_settings.get("monitor_target", dl_path)
        self.lbl_target = Gtk.Label(label=self.target_path)
        self.lbl_target.add_css_class("accent")
        target_box.append(self.lbl_target)
        
        btn_browse = Gtk.Button(icon_name="folder-open-symbolic")
        btn_browse.set_tooltip_text("Alterar pasta monitorizada")
        btn_browse.connect("clicked", self.on_browse_clicked)
        target_box.append(btn_browse)
        
        self.append(target_box)

        # --- INTERRUPTOR DE PROTEÇÃO (ON/OFF) ---
        switch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        switch_box.set_halign(Gtk.Align.CENTER)
        switch_box.set_margin_top(10)
        switch_box.set_margin_bottom(10)
        
        self.lbl_status = Gtk.Label(label="🔴 Proteção Desativada")
        self.lbl_status.add_css_class("title-4")
        
        self.switch_enable = Gtk.Switch()
        
        # Liga a interface ao motor ANTES de verificar o estado atual
        monitor_manager.set_alert_callback(self.on_monitor_alert)
        
        # Verifica se já estava ativado noutra sessão
        is_enabled = app_settings.get("monitor_enabled", False)
        self.switch_enable.set_active(is_enabled)
        self.switch_enable.connect("notify::active", self.on_switch_toggled)
        
        switch_box.append(self.lbl_status)
        switch_box.append(self.switch_enable)
        self.append(switch_box)

        # --- CAIXA DE REGISTOS (LOGS) ---
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textbuffer = self.textview.get_buffer()
        scroll.set_child(self.textview)
        self.append(scroll)
        
        # Se estava ativado na base de dados, inicia logo ao criar a aba
        if is_enabled:
            self._start_monitor()

    def on_browse_clicked(self, btn):
        """Abre janela para escolher nova pasta para vigiar."""
        chooser = Gtk.FileChooserNative.new(
            title="Selecione a pasta para monitorizar",
            parent=self.get_root(),
            action=Gtk.FileChooserAction.SELECT_FOLDER,
            accept_label="Selecionar", cancel_label="Cancelar"
        )
        chooser.connect("response", self.on_chooser_response)
        chooser.show()

    def on_chooser_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            folder_file = dialog.get_file()
            if folder_file:
                path = folder_file.get_path()
                self.target_path = path
                self.lbl_target.set_text(path)
                app_settings.set("monitor_target", path)
                self.log_message(f"Alvo alterado para: {path}")
                
                # Se o monitor estava ligado, tem de ser reiniciado para assumir a nova pasta
                if self.switch_enable.get_active():
                    monitor_manager.stop()
                    self._start_monitor()

    def on_switch_toggled(self, switch, gparam):
        """Lida com o utilizador a ligar/desligar o switch."""
        if switch.get_active():
            self._start_monitor()
        else:
            self._stop_monitor()

    def _start_monitor(self):
        # A função start() do backend retorna False se o pacote watchdog não estiver instalado
        if monitor_manager.start(targets=[self.target_path]):
            self.lbl_status.set_text("🟢 Proteção Ativa")
            self.log_message(f"Proteção em Tempo Real INICIADA na pasta:\n{self.target_path}")
        else:
            self.switch_enable.set_active(False)
            self.log_message("ERRO: Não foi possível iniciar a proteção.\n(Verifique se tem o pacote watchdog instalado: pip install watchdog)")

    def _stop_monitor(self):
        monitor_manager.stop()
        self.lbl_status.set_text("🔴 Proteção Desativada")
        self.log_message("Proteção em Tempo Real PARADA.")

    def log_message(self, msg):
        """Imprime mensagem na caixa de texto."""
        end_iter = self.textbuffer.get_end_iter()
        self.textbuffer.insert(end_iter, msg + "\n")
        self.textview.scroll_to_mark(self.textbuffer.get_insert(), 0.0, True, 0.0, 1.0)

    def on_monitor_alert(self, file_path, virus_name):
        """Callback chamado pelo motor de fundo quando apanha um vírus."""
        GLib.idle_add(self._update_alert_ui, file_path, virus_name)

    def _update_alert_ui(self, file_path, virus_name):
        msg = f"⚡ INTERCEÇÃO EM TEMPO REAL!\n  -> Ameaça: {virus_name}\n  -> Ficheiro: {file_path}\n  -> Ação: O ficheiro foi destruído e movido para a Quarentena."
        self.log_message(msg)
        return False