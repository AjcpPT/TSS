import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib

from securityscan.core.scanner_rootkit import scanner_rootkit
from securityscan.ui.i18n import _


class RootkitTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # --- TÍTULO ---
        title = Gtk.Label(label=_("tab_rootkit"))
        title.add_css_class("title-1")
        self.append(title)

        # --- DESCRIÇÃO INFORMATIVA ---
        info_label = Gtk.Label(
            label="O scan de rootkits analisa o sistema completo em busca de rootkits,\n"
                  "backdoors e exploits. Não é possível limitar a pastas específicas."
        )
        info_label.set_justify(Gtk.Justification.CENTER)
        info_label.add_css_class("dim-label")
        self.append(info_label)

        # --- SELEÇÃO DE FERRAMENTA ---
        tool_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        tool_box.set_halign(Gtk.Align.CENTER)
        tool_box.append(Gtk.Label(label="Ferramenta:"))

        self.tool_model = Gtk.StringList.new([
            "rkhunter + chkrootkit (Recomendado)",
            "rkhunter (apenas)",
            "chkrootkit (apenas)"
        ])
        self.tool_dropdown = Gtk.DropDown(model=self.tool_model)
        self.tool_dropdown.set_selected(0)
        tool_box.append(self.tool_dropdown)
        self.append(tool_box)

        # --- OPÇÕES ADICIONAIS ---
        options_frame = Gtk.Frame(label="Opções")
        options_frame.set_margin_top(5)
        options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        options_box.set_margin_top(10)
        options_box.set_margin_bottom(10)
        options_box.set_margin_start(15)
        options_box.set_margin_end(15)

        verbose_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        verbose_box.append(Gtk.Label(label="Output detalhado (verbose)"))
        self.verbose_switch = Gtk.Switch()
        self.verbose_switch.set_active(False)
        self.verbose_switch.set_halign(Gtk.Align.END)
        self.verbose_switch.set_hexpand(True)
        verbose_box.append(self.verbose_switch)
        options_box.append(verbose_box)

        skip_slow_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        skip_slow_box.append(Gtk.Label(label="Saltar verificações lentas"))
        self.skip_slow_switch = Gtk.Switch()
        self.skip_slow_switch.set_active(False)
        self.skip_slow_switch.set_halign(Gtk.Align.END)
        self.skip_slow_switch.set_hexpand(True)
        skip_slow_box.append(self.skip_slow_switch)
        options_box.append(skip_slow_box)

        options_frame.set_child(options_box)
        self.append(options_frame)

        # --- AVISO ROOT ---
        warn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        warn_box.set_halign(Gtk.Align.CENTER)
        warn_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        warn_label = Gtk.Label(label="Requer privilégios de administrador — será pedida a password")
        warn_label.add_css_class("dim-label")
        warn_box.append(warn_icon)
        warn_box.append(warn_label)
        self.append(warn_box)

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

        # --- LOG ESTILO TERMINAL ---
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textview.add_css_class("monospace")
        self.textbuffer = self.textview.get_buffer()
        scroll.set_child(self.textview)
        self.append(scroll)

        # --- BOTÃO GUARDAR LOG (ícone + texto visível) ---
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
        self.append(save_box)

    def log_message(self, msg):
        end_iter = self.textbuffer.get_end_iter()
        self.textbuffer.insert(end_iter, msg + "\n")
        self.textview.scroll_to_mark(self.textbuffer.get_insert(), 0.0, True, 0.0, 1.0)

    def _get_selected_tool(self):
        idx = self.tool_dropdown.get_selected()
        return ["both", "rkhunter", "chkrootkit"][idx]

    def on_start_clicked(self, btn):
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.textbuffer.set_text("")
        self.progress_bar.set_fraction(0.1)

        tool = self._get_selected_tool()
        verbose = self.verbose_switch.get_active()
        skip_slow = self.skip_slow_switch.get_active()

        self.status_label.set_text("A aguardar autenticação...")
        self.log_message(f"--- A iniciar scan de rootkits (ferramenta: {tool}) ---")
        self.log_message("-> Será pedida a password de administrador numa janela separada.")
        if verbose:
            self.log_message("-> Modo verbose ativado.")
        if skip_slow:
            self.log_message("-> Verificações lentas desativadas.")

        scanner_rootkit.scan(
            tool=tool,
            verbose=verbose,
            skip_slow=skip_slow,
            on_progress=self.on_progress,
            on_threat=self.on_threat,
            on_finished=self.on_finished
        )

    def on_stop_clicked(self, btn):
        scanner_rootkit.stop_scan()
        self.status_label.set_text("A cancelar o processo...")

    def on_progress(self, message):
        GLib.idle_add(self._update_progress_ui, message)

    def _update_progress_ui(self, message):
        self.status_label.set_text(f"A verificar: {message}")
        self.progress_bar.pulse()
        self.log_message(message)
        return False

    def on_threat(self, threat_description):
        GLib.idle_add(self._update_threat_ui, threat_description)

    def _update_threat_ui(self, threat_description):
        self.log_message(f"⚠️  AMEAÇA DETETADA: {threat_description}")
        return False

    def on_finished(self, summary_dict):
        GLib.idle_add(self._update_finished_ui, summary_dict)

    def _update_finished_ui(self, summary_dict):
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.progress_bar.set_fraction(1.0)

        status = summary_dict.get("status")
        if status == "completed":
            threats = summary_dict.get("threats", 0)
            warnings = summary_dict.get("warnings", 0)
            self.status_label.set_text(f"Concluído! {threats} ameaça(s), {warnings} aviso(s).")
            self.log_message(f"\n--- SCAN CONCLUÍDO ---\nAmeaças: {threats}\nAvisos: {warnings}")
        elif status == "cancelled":
            self.status_label.set_text("Cancelado pelo utilizador.")
            self.log_message("\n--- SCAN CANCELADO ---")
        elif status == "no_root":
            self.status_label.set_text("Autenticação cancelada ou insuficiente.")
            self.log_message(
                "\nERRO: A password não foi introduzida ou foi cancelada.\n"
                "Tente novamente e introduza a password de administrador quando solicitado."
            )
        else:
            self.status_label.set_text("Erro no scan.")
            self.log_message(f"\nERRO: {summary_dict.get('message', 'Erro desconhecido')}")
        return False

    def on_save_log_clicked(self, btn):
        dialog = Gtk.FileChooserNative.new(
            title="Guardar Log do Rootkit",
            parent=self.get_root(),
            action=Gtk.FileChooserAction.SAVE,
            accept_label="Guardar",
            cancel_label="Cancelar"
        )
        dialog.set_current_name("tss_rootkit_log.txt")
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