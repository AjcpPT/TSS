import os
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib

# Importamos o nosso orquestrador Full Scan e utilitários
from securityscan.core.scanner_full import scanner_full
from securityscan.core.scanner_clamav import get_usb_targets
from securityscan.ui.i18n import _

class FullScanTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        self.target_paths =[]

        # Título da Aba
        title = Gtk.Label(label=_("tab_full"))
        title.add_css_class("title-1")
        self.append(title)
        
        info = Gtk.Label(label="Executa o ClamAV (no alvo escolhido) e o Rootkit Scanner (no sistema) em simultâneo.")
        info.add_css_class("dim-label")
        self.append(info)

        # --- SELEÇÃO DE ALVO (Para a parte do ClamAV) ---
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        target_box.set_halign(Gtk.Align.CENTER)
        
        target_box.append(Gtk.Label(label="Alvo ClamAV: "))
        
        self.target_model = Gtk.StringList.new([])
        self.target_dropdown = Gtk.DropDown(model=self.target_model)
        target_box.append(self.target_dropdown)
        
        btn_browse = Gtk.Button(icon_name="folder-open-symbolic")
        btn_browse.set_tooltip_text("Procurar e selecionar outra pasta...")
        btn_browse.connect("clicked", self.on_browse_clicked)
        target_box.append(btn_browse)

        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
        btn_refresh.set_tooltip_text("Atualizar Pens USB")
        btn_refresh.connect("clicked", self.refresh_targets)
        target_box.append(btn_refresh)
        
        self.append(target_box)

        # --- BOTÕES DE CONTROLO ---
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_box.set_halign(Gtk.Align.CENTER)
        
        self.btn_start = Gtk.Button(label="Iniciar Verificação Simultânea")
        self.btn_start.add_css_class("suggested-action")
        self.btn_start.connect("clicked", self.on_start_clicked)
        
        self.btn_stop = Gtk.Button(label="Parar / Cancelar Tudo")
        self.btn_stop.add_css_class("destructive-action")
        self.btn_stop.set_sensitive(False)
        self.btn_stop.connect("clicked", self.on_stop_clicked)
        
        btn_box.append(self.btn_start)
        btn_box.append(self.btn_stop)
        self.append(btn_box)

        # --- ESTADO E PROGRESSO ---
        self.status_label = Gtk.Label(label="Pronto para iniciar orquestrador.")
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

        self.refresh_targets()

    def refresh_targets(self, *args):
        self.target_paths.clear()
        strings =[]

        dl_path = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not dl_path: dl_path = os.path.expanduser("~/Downloads")
        dl_name = os.path.basename(dl_path)
        
        strings.append(f"📥 Pasta: {dl_name}")
        self.target_paths.append(dl_path)

        strings.append("💻 Sistema Completo (/)")
        self.target_paths.append("/")

        usbs = get_usb_targets()
        for u in usbs:
            usb_name = os.path.basename(u)
            strings.append(f"🔌 USB: {usb_name}")
            self.target_paths.append(u)

        self.target_model.splice(0, self.target_model.get_n_items(), strings)
        self.target_dropdown.set_selected(0)

    def on_browse_clicked(self, btn):
        chooser = Gtk.FileChooserNative.new(
            title="Selecione a pasta para o ClamAV",
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
                folder_name = os.path.basename(path)
                self.target_paths.append(path)
                self.target_model.append(f"📁 Escolhida: {folder_name}")
                self.target_dropdown.set_selected(len(self.target_paths) - 1)

    def log_message(self, msg):
        end_iter = self.textbuffer.get_end_iter()
        self.textbuffer.insert(end_iter, msg + "\n")
        self.textview.scroll_to_mark(self.textbuffer.get_insert(), 0.0, True, 0.0, 1.0)

    def on_start_clicked(self, btn):
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.textbuffer.set_text("")
        self.progress_bar.set_fraction(0.1)
        
        idx = self.target_dropdown.get_selected()
        target = self.target_paths[idx]
            
        self.status_label.set_text("Scan Simultâneo em curso...")
        self.log_message(f"--- A iniciar ClamAV em {target} e Rootkit no Sistema ---")

        scanner_full.scan(
            target_path=target,
            on_progress=self.on_progress,
            on_alert=self.on_alert,
            on_finished=self.on_finished
        )

    def on_stop_clicked(self, btn):
        scanner_full.stop_scan()
        self.status_label.set_text("A cancelar todos os processos...")

    def on_progress(self, source, message):
        GLib.idle_add(self._update_progress_ui, source, message)

    def _update_progress_ui(self, source, message):
        # A barra de estado mostra qual motor está a enviar atividade naquele milissegundo!
        self.status_label.set_text(f"[{source}] A verificar: {message}")
        self.progress_bar.pulse()
        return False

    def on_alert(self, source, warning_msg):
        GLib.idle_add(self._update_alert_ui, source, warning_msg)

    def _update_alert_ui(self, source, warning_msg):
        self.log_message(f"🛑 ALERTA[{source}]: {warning_msg}")
        return False

    def on_finished(self, summary_dict):
        GLib.idle_add(self._update_finished_ui, summary_dict)

    def _update_finished_ui(self, summary_dict):
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.progress_bar.set_fraction(1.0)
        
        status = summary_dict.get("status")
        if status == "completed":
            self.status_label.set_text("Full Scan Concluído! Verifique a janela de logs.")
            self.log_message("\n=== RESUMO GLOBAL ===")
            
            c_sum = summary_dict["summary"]["clamav"]
            if c_sum and c_sum["status"] == "completed":
                self.log_message(f"[ClamAV] Verificados: {c_sum['summary']['scanned']} | Infetados: {c_sum['summary']['infected']}")
                
            r_sum = summary_dict["summary"]["rootkit"]
            if r_sum and r_sum["status"] == "completed":
                self.log_message(f"[Rootkit] Verificados: {r_sum['summary']['scanned_items']} | Alertas: {r_sum['summary']['warnings']}")
                
        elif status == "cancelled":
            self.status_label.set_text("Cancelado pelo utilizador.")
            self.log_message("\n--- SCAN CANCELADO ---")
        else:
            self.status_label.set_text("Erro durante o scan.")
            
        return False