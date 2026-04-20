import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib

# Importamos o motor de backend de rootkits
from securityscan.core.scanner_rootkit import scanner_rootkit
from securityscan.ui.i18n import _

class RootkitTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Título da Aba
        title = Gtk.Label(label=_("tab_rootkit"))
        title.add_css_class("title-1")
        self.append(title)

        # Informação
        info_label = Gtk.Label(label="Aviso: A verificação de rootkits procura vulnerabilidades em todo o sistema operativo.\nAlguns avisos (Warnings) podem ser falsos positivos se não correr a aplicação como Root.")
        info_label.set_justify(Gtk.Justification.CENTER)
        info_label.add_css_class("dim-label")
        self.append(info_label)

        # --- BOTÕES DE CONTROLO ---
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_box.set_halign(Gtk.Align.CENTER)
        
        self.btn_start = Gtk.Button(label="Iniciar Verificação do Sistema")
        self.btn_start.add_css_class("suggested-action")
        self.btn_start.connect("clicked", self.on_start_clicked)
        
        self.btn_stop = Gtk.Button(label="Parar / Cancelar")
        self.btn_stop.add_css_class("destructive-action")
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect("clicked", self.on_stop_clicked)
        
        btn_box.append(self.btn_start)
        btn_box.append(self.btn_stop)
        self.append(btn_box)

        # --- ESTADO E PROGRESSO ---
        self.status_label = Gtk.Label(label="Pronto para iniciar.")
        self.append(self.status_label)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_fraction(0.0)
        self.append(self.progress_bar)

        # --- LOG / CAIXA DE TEXTO ---
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textbuffer = self.textview.get_buffer()
        scroll.set_child(self.textview)
        self.append(scroll)

    def log_message(self, msg):
        end_iter = self.textbuffer.get_end_iter()
        self.textbuffer.insert(end_iter, msg + "\n")
        self.textview.scroll_to_mark(self.textbuffer.get_insert(), 0.0, True, 0.0, 1.0)

    def on_start_clicked(self, btn):
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.textbuffer.set_text("")
        self.progress_bar.set_fraction(0.1)
            
        self.status_label.set_text("Scan de Rootkits em curso...")
        self.log_message("--- A iniciar motor Rootkit (rkhunter/chkrootkit) ---")

        # Chama o nosso motor de rootkit
        scanner_rootkit.scan(
            on_progress=self.on_progress,
            on_warning=self.on_warning,
            on_finished=self.on_finished
        )

    def on_stop_clicked(self, btn):
        scanner_rootkit.stop_scan()
        self.status_label.set_text("A cancelar a verificação...")

    def on_progress(self, message):
        # Transfere as mensagens do backend (thread) para a interface
        GLib.idle_add(self._update_progress_ui, message)

    def _update_progress_ui(self, message):
        self.status_label.set_text(f"A verificar: {message}")
        self.progress_bar.pulse()
        return False

    def on_warning(self, source, warning_msg):
        GLib.idle_add(self._update_warning_ui, source, warning_msg)

    def _update_warning_ui(self, source, warning_msg):
        self.log_message(f"⚠️ [{source.upper()}] ALERTA: {warning_msg}")
        return False

    def on_finished(self, summary_dict):
        GLib.idle_add(self._update_finished_ui, summary_dict)

    def _update_finished_ui(self, summary_dict):
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.progress_bar.set_fraction(1.0)
        
        status = summary_dict.get("status")
        if status == "completed":
            scanned = summary_dict["summary"]["scanned_items"]
            warnings = summary_dict["summary"]["warnings"]
            self.status_label.set_text(f"Concluído! {scanned} verificados, {warnings} alertas.")
            self.log_message(f"\n--- SCAN CONCLUÍDO ---\nVerificações executadas: {scanned}\nAlertas/Avisos: {warnings}")
        elif status == "cancelled":
            self.status_label.set_text("Cancelado pelo utilizador.")
            self.log_message("\n--- SCAN CANCELADO ---")
        else:
            self.status_label.set_text("Erro no scan.")
            self.log_message(f"\nERRO: {summary_dict.get('message')}")
        return False