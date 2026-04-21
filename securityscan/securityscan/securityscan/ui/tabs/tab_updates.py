import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib

# Importa os atualizadores do backend e definições
from securityscan.core.updater_clamav import updater_clamav
from securityscan.core.updater_rootkit import updater_rootkit
from securityscan.core.updater_app import updater_app
from securityscan.core.settings import app_settings
from securityscan.ui.i18n import _

class UpdatesTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Versão atual do TSS
        self.CURRENT_APP_VERSION = "1.0.0"

        # Título da Aba
        title = Gtk.Label(label="Atualizações e Bases de Dados")
        title.add_css_class("title-1")
        self.append(title)

        # Usamos ScrolledWindow para o caso de o ecrã ser pequeno
        main_scroll = Gtk.ScrolledWindow()
        main_scroll.set_vexpand(True)
        self.append(main_scroll)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        main_scroll.set_child(content_box)

        # ==========================================
        # GRUPO 1: CLAMAV E BASES DE DADOS
        # ==========================================
        clamav_group = Adw.PreferencesGroup()
        clamav_group.set_title("Motor de Antivírus (ClamAV)")
        clamav_group.set_description("Gerir atualizações oficiais, comunitárias e bases de dados pagas.")
        
        # Botão: Atualizar agora
        btn_update_clamav = Gtk.Button(label="Procurar Atualizações (Freshclam)", icon_name="software-update-available-symbolic")
        btn_update_clamav.add_css_class("suggested-action")
        btn_update_clamav.connect("clicked", self.on_update_clamav_clicked)
        clamav_group.add(self._create_row_with_widget("Atualizar Assinaturas Agora", btn_update_clamav))

        # Switch: Bases de Dados Gratuitas Comunitárias (Sanesecurity, LMD, etc)
        self.switch_free_dbs = Gtk.Switch()
        self.switch_free_dbs.set_valign(Gtk.Align.CENTER)
        self.switch_free_dbs.set_active(app_settings.get("clamav_free_extra_dbs", False))
        clamav_group.add(self._create_row_with_widget("Ativar Bases Comunitárias (Gratuitas)", self.switch_free_dbs, "Inclui Sanesecurity, Linux Malware Detect, Fangiox, etc."))

        # Switch: Bases Pagas / Premium (SecuriteInfo)
        self.switch_paid_dbs = Gtk.Switch()
        self.switch_paid_dbs.set_valign(Gtk.Align.CENTER)
        self.switch_paid_dbs.set_active(app_settings.get("clamav_paid_db_enabled", False))
        self.switch_paid_dbs.connect("notify::active", self.on_paid_db_toggled)
        clamav_group.add(self._create_row_with_widget("Ativar Bases Premium (SecuriteInfo / Outras)", self.switch_paid_dbs))

        # Entry: Token/Login (Fica invisível se o switch estiver desligado)
        self.box_token = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.box_token.set_margin_top(5)
        self.box_token.set_margin_bottom(5)
        
        self.entry_token = Gtk.Entry()
        self.entry_token.set_visibility(False)  # Esconde os caracteres como password
        self.entry_token.set_hexpand(True)
        self.entry_token.set_text(app_settings.get("clamav_paid_token", ""))
        self.entry_token.set_placeholder_text("Insira a sua chave API (Token / Login)...")
        
        btn_save_token = Gtk.Button(label="Guardar Configuração")
        btn_save_token.connect("clicked", self.on_save_db_config)
        
        self.box_token.append(self.entry_token)
        self.box_token.append(btn_save_token)
        
        self.row_token = self._create_row_with_widget("Token de Acesso Premium", self.box_token)
        self.row_token.set_visible(self.switch_paid_dbs.get_active())
        clamav_group.add(self.row_token)

        content_box.append(clamav_group)

        # ==========================================
        # GRUPO 2: ROOTKIT SCANNER
        # ==========================================
        rootkit_group = Adw.PreferencesGroup()
        rootkit_group.set_title("Motor Anti-Rootkit (RKHunter)")
        rootkit_group.set_description("Atualizar lista de ameaças e mapeamento das propriedades do sistema (necessita de sudo/pkexec no backend).")
        
        btn_update_rk = Gtk.Button(label="Atualizar RKHunter", icon_name="software-update-available-symbolic")
        btn_update_rk.connect("clicked", self.on_update_rootkit_clicked)
        rootkit_group.add(self._create_row_with_widget("Atualizar Bases e Propriedades do Sistema", btn_update_rk))
        
        content_box.append(rootkit_group)

        # ==========================================
        # GRUPO 3: ATUALIZAÇÃO DA APLICAÇÃO (TSS)
        # ==========================================
        app_group = Adw.PreferencesGroup()
        app_group.set_title("Tuga Security Scan (TSS)")
        app_group.set_description(f"Versão Instalada: v{self.CURRENT_APP_VERSION}")
        
        btn_update_app = Gtk.Button(label="Verificar Atualizações", icon_name="system-search-symbolic")
        btn_update_app.connect("clicked", self.on_check_app_update_clicked)
        app_group.add(self._create_row_with_widget("Procurar nova versão no GitHub", btn_update_app))
        
        content_box.append(app_group)

        # ==========================================
        # CONSOLA DE RESULTADOS (LOGS DA ATUALIZAÇÃO)
        # ==========================================
        log_frame = Gtk.Frame()
        log_frame.set_margin_top(15)
        
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textview.set_monospace(True)
        self.textview.set_size_request(-1, 150) # Altura mínima
        self.textbuffer = self.textview.get_buffer()
        
        scroll_log = Gtk.ScrolledWindow()
        scroll_log.set_child(self.textview)
        log_frame.set_child(scroll_log)
        
        content_box.append(Gtk.Label(label="Registo de Atualizações:", halign=Gtk.Align.START))
        content_box.append(log_frame)

        # Botão guardar log
        save_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        save_box.set_halign(Gtk.Align.END)
        save_box.set_margin_top(5)
        btn_save = Gtk.Button()
        btn_save_inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        btn_save_inner.append(Gtk.Image.new_from_icon_name("document-save-symbolic"))
        btn_save_inner.append(Gtk.Label(label="Guardar Log"))
        btn_save.set_child(btn_save_inner)
        btn_save.connect("clicked", self.on_save_log_clicked)
        save_box.append(btn_save)
        content_box.append(save_box)

    def _create_row_with_widget(self, title, widget, subtitle=None):
        """Helper para criar uma linha bonita de definições ao estilo Adw.ActionRow."""
        row = Adw.ActionRow()
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        row.add_suffix(widget)
        return row

    def log_message(self, msg):
        """Imprime mensagem na consola da aba."""
        end_iter = self.textbuffer.get_end_iter()
        self.textbuffer.insert(end_iter, msg + "\n")
        self.textview.scroll_to_mark(self.textbuffer.get_insert(), 0.0, True, 0.0, 1.0)

    # --- CALLBACKS CLAMAV ---
    def on_paid_db_toggled(self, switch, gparam):
        """Mostra/Esconde o campo do Token quando se ativa as bases pagas."""
        is_active = switch.get_active()
        self.row_token.set_visible(is_active)

    def on_save_db_config(self, btn):
        """Guarda as definições das bases extra (gratuitas e pagas)."""
        free_active = self.switch_free_dbs.get_active()
        paid_active = self.switch_paid_dbs.get_active()
        token = self.entry_token.get_text().strip()

        app_settings.set("clamav_free_extra_dbs", free_active)
        
        # O backend trata da lógica
        updater_clamav.configure_paid_databases(enable=paid_active, token=token)
        
        self.log_message("\n[SISTEMA] Configuração de Bases de Dados Guardada!")
        self.log_message(f" -> Bases Comunitárias (Gratuitas): {'Ativas' if free_active else 'Inativas'}")
        self.log_message(f" -> Bases Premium (Pagas): {'Ativas' if paid_active else 'Inativas'}")
        
        root_window = self.get_root()
        dialog = Adw.MessageDialog(transient_for=root_window, heading="Guardado", body="A configuração de bases de dados foi guardada com sucesso.\n(Nota: As bases de terceiros serão processadas no próximo update).")
        dialog.add_response("ok", "OK")
        dialog.present()

    def on_update_clamav_clicked(self, btn):
        btn.set_sensitive(False)
        self.log_message("\n--- A Iniciar Atualização do ClamAV (Freshclam) ---")
        updater_clamav.update_signatures(
            on_progress=lambda msg: GLib.idle_add(self._print_log, msg),
            on_finished=lambda res: GLib.idle_add(self._on_update_finished, btn, res)
        )

    # --- CALLBACKS ROOTKIT ---
    def on_update_rootkit_clicked(self, btn):
        btn.set_sensitive(False)
        self.log_message("\n--- A Iniciar Atualização do RKHunter ---")
        updater_rootkit.update(
            on_progress=lambda msg: GLib.idle_add(self._print_log, msg),
            on_finished=lambda res: GLib.idle_add(self._on_update_finished, btn, res)
        )

    # --- CALLBACKS TSS APP ---
    def on_check_app_update_clicked(self, btn):
        btn.set_sensitive(False)
        self.log_message("\n--- A Verificar Atualizações do Tuga Security Scan (GitHub) ---")
        updater_app.check_for_updates(
            current_version=self.CURRENT_APP_VERSION,
            on_finished=lambda res: GLib.idle_add(self._on_app_update_finished, btn, res)
        )

    # --- FUNÇÕES DE SUPORTE (THREADS -> UI) ---
    def _print_log(self, msg):
        self.log_message(msg)
        return False

    def _on_update_finished(self, btn, result):
        btn.set_sensitive(True)
        status = result.get("status")
        msg = result.get("message", "")
        if status == "success":
            self.log_message(f"[SUCESSO] {msg}")
        else:
            self.log_message(f"[ERRO/AVISO] {msg}")
        return False

    def on_save_log_clicked(self, btn):
        dialog = Gtk.FileChooserNative.new(
            title="Guardar Log de Atualizações",
            parent=self.get_root(),
            action=Gtk.FileChooserAction.SAVE,
            accept_label="Guardar",
            cancel_label="Cancelar"
        )
        dialog.set_current_name("tss_updates_log.txt")
        dialog.connect("response", self._on_save_response)
        dialog.show()

    def _on_save_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                path = file.get_path()
                start = self.textbuffer.get_start_iter()
                end = self.textbuffer.get_end_iter()
                content = self.textbuffer.get_text(start, end, True)
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content)
                    self.log_message(f"\n-> Log guardado em: {path}")
                except Exception as e:
                    self.log_message(f"\nERRO ao guardar log: {e}")

    def _on_app_update_finished(self, btn, result):
        btn.set_sensitive(True)
        status = result.get("status")
        if status == "update_available":
            v_nova = result.get('latest_version')
            url = result.get('download_url')
            notas = result.get('release_notes')
            self.log_message(f"🎉 NOVA VERSÃO DO TSS DISPONÍVEL: v{v_nova}")
            self.log_message(f"Link: {url}\nNotas:\n{notas}")
            
            # Pop-up bonito para atualizar
            root_window = self.get_root()
            dialog = Adw.MessageDialog(transient_for=root_window, heading="Nova Versão Disponível!", body=f"A versão v{v_nova} do Tuga Security Scan já está disponível.\nDeseja aceder ao GitHub para descarregar?")
            dialog.add_response("cancel", "Mais Tarde")
            dialog.add_response("open", "Descarregar Agora")
            dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)
            
            def on_response(dlg, response):
                if response == "open":
                    import webbrowser
                    webbrowser.open(url)
            dialog.connect("response", on_response)
            dialog.present()
            
        elif status == "up_to_date":
            self.log_message("✅ A sua aplicação já está na versão mais recente.")
        else:
            self.log_message(f"❌ Erro ao verificar atualização da App: {result.get('message')}")
        return False