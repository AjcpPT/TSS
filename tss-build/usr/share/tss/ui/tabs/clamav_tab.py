import os
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib, Gio

# Importamos o motor de backend
from securityscan.core.scanner_clamav import scanner_clamav, get_usb_targets
from securityscan.core.settings import app_settings
from securityscan.ui.i18n import _

class ClamAVTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Array invisível para guardar os caminhos reais (paths) das opções
        self.target_paths =[]

        # Título da Aba
        title = Gtk.Label(label=_("tab_clamav"))
        title.add_css_class("title-1")
        self.append(title)

        # --- SELEÇÃO DE ALVO (COM NAVEGADOR DE PASTAS) ---
        target_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        target_box.set_halign(Gtk.Align.CENTER)
        
        target_box.append(Gtk.Label(label="Alvo do Scan: "))
        
        self.target_model = Gtk.StringList.new([])
        self.target_dropdown = Gtk.DropDown(model=self.target_model)
        target_box.append(self.target_dropdown)
        
        # 1. NOVO BOTÃO: Procurar Pasta na Árvore do Sistema
        btn_browse = Gtk.Button(icon_name="folder-open-symbolic")
        btn_browse.set_tooltip_text("Procurar e selecionar outra pasta no sistema...")
        btn_browse.connect("clicked", self.on_browse_clicked)
        target_box.append(btn_browse)

        # 2. Botão: Atualizar Pens USB
        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
        btn_refresh.set_tooltip_text("Atualizar lista de Pens USB ligadas")
        btn_refresh.connect("clicked", self.refresh_targets)
        target_box.append(btn_refresh)
        
        self.append(target_box)

        # --- OPÇÃO: SCAN AUTOMÁTICO USB ---
        usb_auto_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        usb_auto_box.set_halign(Gtk.Align.CENTER)
        
        self.usb_switch = Gtk.Switch()
        self.usb_switch.set_active(app_settings.get("auto_scan_usb", False))
        self.usb_switch.connect("notify::active", self.on_usb_switch_toggled)
        
        usb_auto_box.append(Gtk.Label(label="Verificar Pens USB automaticamente ao ligar"))
        usb_auto_box.append(self.usb_switch)
        self.append(usb_auto_box)

        # --- BOTÕES DE CONTROLO ---
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_box.set_halign(Gtk.Align.CENTER)
        
        self.btn_start = Gtk.Button(label="Iniciar Verificação")
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

        # Preenche a lista padrão
        self.refresh_targets()

    def refresh_targets(self, *args):
        """Atualiza a lista padrão com a pasta de downloads e as pens USB reais."""
        self.target_paths.clear()
        strings =[]

        # 1. Pasta Inteligente
        dl_path = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        if not dl_path:
            dl_path = os.path.expanduser("~/Downloads")
        dl_name = os.path.basename(dl_path)
        
        strings.append(f"📥 Pasta: {dl_name}")
        self.target_paths.append(dl_path)

        # 2. Sistema Completo
        strings.append("💻 Sistema Completo (/)")
        self.target_paths.append("/")

        # 3. Pens USB
        usbs = get_usb_targets()
        for u in usbs:
            usb_name = os.path.basename(u)
            strings.append(f"🔌 USB: {usb_name}")
            self.target_paths.append(u)

        # Atualiza a UI e seleciona o primeiro item por defeito
        self.target_model.splice(0, self.target_model.get_n_items(), strings)
        self.target_dropdown.set_selected(0)
        
        if usbs:
            self.log_message(f"Detetadas {len(usbs)} Pen(s) USB prontas a verificar.")

    def on_browse_clicked(self, btn):
        """Abre a janela nativa de navegação de pastas (Árvore de sistema)."""
        # FileChooserNative garante compatibilidade máxima no Linux
        chooser = Gtk.FileChooserNative.new(
            title="Selecione a pasta para verificar",
            parent=self.get_root(),
            action=Gtk.FileChooserAction.SELECT_FOLDER,
            accept_label="Selecionar",
            cancel_label="Cancelar"
        )
        chooser.connect("response", self.on_chooser_response)
        chooser.show()

    def on_chooser_response(self, dialog, response):
        """Recebe a pasta escolhida pelo utilizador na árvore."""
        if response == Gtk.ResponseType.ACCEPT:
            folder_file = dialog.get_file()
            if folder_file:
                path = folder_file.get_path()
                folder_name = os.path.basename(path)
                
                # Adiciona à lista de opções e seleciona automaticamente
                self.target_paths.append(path)
                self.target_model.append(f"📁 Escolhida: {folder_name}")
                
                # Seleciona o último item (o que acabámos de adicionar)
                self.target_dropdown.set_selected(len(self.target_paths) - 1)
                self.log_message(f"Pasta personalizada selecionada: {path}")

    def on_usb_switch_toggled(self, switch, gparam):
        ativo = switch.get_active()
        app_settings.set("auto_scan_usb", ativo)
        estado = "ATIVADO" if ativo else "DESATIVADO"
        self.log_message(f"-> Scan automático de Pen USB {estado}.")

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
            
        self.status_label.set_text("Scan em curso...")
        self.log_message(f"--- A iniciar motor ClamAV no alvo: {target} ---")

        scanner_clamav.scan(
            target_path=target,
            on_progress=self.on_progress,
            on_infected=self.on_infected,
            on_finished=self.on_finished
        )

    def on_stop_clicked(self, btn):
        scanner_clamav.stop_scan()
        self.status_label.set_text("A cancelar o processo...")

    def on_progress(self, file_path):
        GLib.idle_add(self._update_progress_ui, file_path)

    def _update_progress_ui(self, file_path):
        self.status_label.set_text(f"A verificar: {file_path}")
        self.progress_bar.pulse()
        return False

    def on_infected(self, file_path, virus_name):
        GLib.idle_add(self._update_infected_ui, file_path, virus_name)

    def _update_infected_ui(self, file_path, virus_name):
        self.log_message(f"⚠️ AMEAÇA ENCONTRADA: {virus_name}\n -> Ficheiro: {file_path}")
        return False

    def on_finished(self, summary_dict):
        GLib.idle_add(self._update_finished_ui, summary_dict)

    def _update_finished_ui(self, summary_dict):
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.progress_bar.set_fraction(1.0)
        
        status = summary_dict.get("status")
        if status == "completed":
            scanned = summary_dict["summary"]["scanned"]
            inf = summary_dict["summary"]["infected"]
            self.status_label.set_text(f"Concluído! {scanned} verificados, {inf} ameaças.")
            self.log_message(f"\n--- SCAN CONCLUÍDO ---\nVerificados: {scanned}\nInfetados: {inf}")
        elif status == "cancelled":
            self.status_label.set_text("Cancelado pelo utilizador.")
            self.log_message("\n--- SCAN CANCELADO ---")
        else:
            self.status_label.set_text("Erro no scan.")
            self.log_message(f"\nERRO: {summary_dict.get('message')}")
        return False