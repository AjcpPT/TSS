import os
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib

# Importa o agendador e as settings
from securityscan.core.scheduler import app_scheduler
from securityscan.core.settings import app_settings
from securityscan.ui.i18n import _

class ScheduleTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Título
        title = Gtk.Label(label=_("tab_schedule"))
        title.add_css_class("title-1")
        self.append(title)

        info = Gtk.Label(label="Agende uma verificação completa (Full Scan) para correr automaticamente todos os dias.\nA aplicação (ou o processo de fundo) tem de estar aberta à hora marcada.")
        info.set_justify(Gtk.Justification.CENTER)
        info.add_css_class("dim-label")
        self.append(info)

        # Contentor centralizado para o formulário
        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        form_box.set_halign(Gtk.Align.CENTER)
        self.append(form_box)

        # --- ESCOLHER A HORA ---
        time_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        time_box.set_halign(Gtk.Align.CENTER)
        
        time_box.append(Gtk.Label(label="Hora da Verificação (Diária): "))

        # SpinButtons para Hora (0-23) e Minuto (0-59)
        self.spin_hour = Gtk.SpinButton.new_with_range(0, 23, 1)
        self.spin_hour.set_orientation(Gtk.Orientation.VERTICAL)
        
        time_box.append(self.spin_hour)
        time_box.append(Gtk.Label(label=":"))
        
        self.spin_minute = Gtk.SpinButton.new_with_range(0, 59, 1)
        self.spin_minute.set_orientation(Gtk.Orientation.VERTICAL)
        time_box.append(self.spin_minute)
        
        form_box.append(time_box)

        # --- ESCOLHER A PASTA ALVO ---
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        target_box.set_halign(Gtk.Align.CENTER)
        
        target_box.append(Gtk.Label(label="Pasta a analisar: "))
        
        # Recupera o default
        dl_path = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not dl_path:
            dl_path = os.path.expanduser("~/Downloads")
            
        self.target_path = app_settings.get("scheduled_scan_target", dl_path)
        
        self.lbl_target = Gtk.Label(label=self.target_path)
        self.lbl_target.add_css_class("accent")
        target_box.append(self.lbl_target)
        
        btn_browse = Gtk.Button(icon_name="folder-open-symbolic")
        btn_browse.set_tooltip_text("Escolher outra pasta para o agendamento")
        btn_browse.connect("clicked", self.on_browse_clicked)
        target_box.append(btn_browse)
        
        form_box.append(target_box)

        # --- BOTÕES DE AÇÃO ---
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        btn_box.set_halign(Gtk.Align.CENTER)
        btn_box.set_margin_top(10)
        
        btn_save = Gtk.Button(label="Guardar e Ativar")
        btn_save.add_css_class("suggested-action")
        btn_save.connect("clicked", self.on_save_clicked)
        btn_box.append(btn_save)
        
        btn_clear = Gtk.Button(label="Desativar Agendamento")
        btn_clear.add_css_class("destructive-action")
        btn_clear.connect("clicked", self.on_clear_clicked)
        btn_box.append(btn_clear)

        form_box.append(btn_box)

        # --- ESTADO ATUAL ---
        self.status_label = Gtk.Label(label="")
        self.status_label.set_margin_top(20)
        self.status_label.add_css_class("title-4")
        form_box.append(self.status_label)

        # Carrega os dados para preencher a interface visualmente
        self._load_current_settings()
        
        # Tenta iniciar o motor de agendamento por trás (necessita do pacote 'schedule')
        if not app_scheduler.start():
            self.status_label.set_text("⚠️ ERRO: Falta instalar a biblioteca de agendamento.\nAbra o terminal e execute: pip install schedule")
            self.status_label.add_css_class("error")

    def _load_current_settings(self):
        """Lê os settings e atualiza os SpinButtons e Labels."""
        mode = app_settings.get("scheduled_scan_mode", "none")
        time_str = app_settings.get("scheduled_scan_time", "12:00")
        
        try:
            h, m = time_str.split(":")
            self.spin_hour.set_value(int(h))
            self.spin_minute.set_value(int(m))
        except ValueError:
            pass

        if mode == "daily":
            self.status_label.set_text(f"🟢 Agendamento ATIVO para as {time_str}")
        else:
            self.status_label.set_text("🔴 Sem scans agendados.")

    def on_browse_clicked(self, btn):
        chooser = Gtk.FileChooserNative.new(
            title="Selecione a pasta para o Scan Agendado",
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

    def on_save_clicked(self, btn):
        """Pega na hora escolhida, guarda nos settings e ativa no motor."""
        # Formata para ter sempre dois dígitos (ex: 09:05)
        h = int(self.spin_hour.get_value())
        m = int(self.spin_minute.get_value())
        time_str = f"{h:02d}:{m:02d}"
        
        app_scheduler.set_daily_scan(time_str, self.target_path)
        self.status_label.set_text(f"🟢 Agendamento ATIVO para as {time_str}")
        
        # Confirmação visual
        self._show_msg("Sucesso", f"O Full Scan foi agendado para correr diariamente às {time_str}.")

    def on_clear_clicked(self, btn):
        """Limpa o agendamento."""
        app_scheduler.clear_schedule()
        self.status_label.set_text("🔴 Sem scans agendados.")

    def _show_msg(self, title, message):
        root_window = self.get_root()
        from gi.repository import Adw
        dialog = Adw.MessageDialog(transient_for=root_window, heading=title, body=message)
        dialog.add_response("ok", "OK")
        dialog.present()