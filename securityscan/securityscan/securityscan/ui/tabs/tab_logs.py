import os
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib, Gio

# Importa o nosso gestor de logs
from securityscan.core.logger import app_logger
from securityscan.ui.i18n import _

class LogsTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Mapeamento do Dropdown para os nomes dos ficheiros de log internos
        self.log_types =["system", "clamav", "rootkit"]

        # Título da Aba
        title = Gtk.Label(label=_("tab_logs"))
        title.add_css_class("title-1")
        self.append(title)

        # --- BARRA DE FERRAMENTAS ---
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        toolbar.set_halign(Gtk.Align.CENTER)
        
        toolbar.append(Gtk.Label(label="Ver Registo de: "))
        
        # Dropdown para escolher o tipo de log
        self.log_dropdown = Gtk.DropDown.new_from_strings([
            "Eventos de Sistema", 
            "Scans do ClamAV", 
            "Scans de Rootkits"
        ])
        self.log_dropdown.connect("notify::selected", self.on_log_changed)
        toolbar.append(self.log_dropdown)
        
        # Botão Atualizar
        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
        btn_refresh.set_tooltip_text("Atualizar o log selecionado")
        btn_refresh.connect("clicked", lambda b: self.refresh_log())
        toolbar.append(btn_refresh)
        
        # Separador visual
        toolbar.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        # Botão Limpar
        btn_clear = Gtk.Button(label="Limpar Log")
        btn_clear.add_css_class("destructive-action")
        btn_clear.connect("clicked", self.on_clear_clicked)
        toolbar.append(btn_clear)

        # Botões de Exportação
        btn_export_txt = Gtk.Button(label="Exportar TXT")
        btn_export_txt.connect("clicked", lambda b: self.on_export_clicked("txt"))
        toolbar.append(btn_export_txt)
        
        btn_export_pdf = Gtk.Button(label="Exportar PDF")
        btn_export_pdf.connect("clicked", lambda b: self.on_export_clicked("pdf"))
        toolbar.append(btn_export_pdf)

        self.append(toolbar)

        # --- ÁREA DE VISUALIZAÇÃO DE TEXTO ---
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        
        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_monospace(True) # Usa fonte tipo terminal para logs
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        
        # Adiciona algum espaçamento interno ao texto
        self.textview.set_left_margin(10)
        self.textview.set_right_margin(10)
        self.textview.set_top_margin(10)
        self.textview.set_bottom_margin(10)
        
        self.textbuffer = self.textview.get_buffer()
        scroll.set_child(self.textview)
        self.append(scroll)

        # Carrega o log do Sistema (índice 0) por defeito
        self.refresh_log()

    def get_current_log_type(self) -> str:
        """Devolve o identificador interno ('system', 'clamav', etc) selecionado."""
        idx = self.log_dropdown.get_selected()
        return self.log_types[idx]

    def on_log_changed(self, dropdown, gparam):
        """Dispara sempre que o utilizador muda a opção no dropdown."""
        self.refresh_log()

    def refresh_log(self):
        """Vai buscar o texto do log ao backend e mete no ecrã."""
        log_type = self.get_current_log_type()
        content = app_logger.get_log_content(log_type)
        self.textbuffer.set_text(content)
        
        # Faz scroll até ao fim para ver as entradas mais recentes
        GLib.idle_add(self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        end_iter = self.textbuffer.get_end_iter()
        self.textview.scroll_to_mark(self.textbuffer.create_mark(None, end_iter, False), 0.0, True, 0.0, 1.0)
        return False

    def on_clear_clicked(self, btn):
        """Limpa o ficheiro de log atual."""
        log_type = self.get_current_log_type()
        app_logger.clear_log(log_type)
        self.refresh_log()

    def on_export_clicked(self, format_type):
        """Abre a janela de gravação nativa para exportar ficheiros."""
        log_type = self.get_current_log_type()
        
        # Sugestão de nome de ficheiro
        default_name = f"securityscan_{log_type}_log.{format_type}"

        chooser = Gtk.FileChooserNative.new(
            title=f"Exportar Log como {format_type.upper()}",
            parent=self.get_root(),
            action=Gtk.FileChooserAction.SAVE,
            accept_label="Guardar", 
            cancel_label="Cancelar"
        )
        
        chooser.set_current_name(default_name)
        
        # Usamos uma função local/lambda para passar o format_type para o callback
        chooser.connect("response", lambda dialog, response: self.on_save_response(dialog, response, format_type, log_type))
        chooser.show()

    def on_save_response(self, dialog, response, format_type, log_type):
        """Processa a resposta da janela de gravar ficheiro."""
        if response == Gtk.ResponseType.ACCEPT:
            target_file = dialog.get_file()
            if target_file:
                path = target_file.get_path()
                
                # Executa a exportação consoante o tipo
                success = False
                if format_type == "txt":
                    success = app_logger.export_txt(log_type, path)
                elif format_type == "pdf":
                    success = app_logger.export_pdf(log_type, path)

                # Mostra o resultado na UI (usando Gtk.AlertDialog no GTK4)
                if success:
                    self._show_msg(f"Sucesso", f"Log exportado com sucesso para:\n{path}")
                else:
                    self._show_msg("Erro", "Ocorreu um erro ao exportar o ficheiro. (Se for PDF, verifique se instalou o 'fpdf2').")

    def _show_msg(self, title, message):
        """Mostra uma janela de aviso simples usando Adw.MessageDialog."""
        root_window = self.get_root()
        from gi.repository import Adw
        dialog = Adw.MessageDialog(transient_for=root_window, heading=title, body=message)
        dialog.add_response("ok", "OK")
        dialog.present()