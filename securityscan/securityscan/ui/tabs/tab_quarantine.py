import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib

from securityscan.core.quarantine import quarantine_manager
from securityscan.ui.i18n import _

class QuarantineTab(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Título da Aba
        title = Gtk.Label(label=_("tab_quarantine"))
        title.add_css_class("title-1")
        self.append(title)

        info = Gtk.Label(label="Os ficheiros listados aqui foram neutralizados e isolados do sistema.\nEles não podem causar danos enquanto estiverem na Quarentena.")
        info.set_justify(Gtk.Justification.CENTER)
        info.add_css_class("dim-label")
        self.append(info)

        # Barra de Ferramentas da Quarentena
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        toolbar.set_halign(Gtk.Align.CENTER)
        
        btn_refresh = Gtk.Button(label="Atualizar Lista", icon_name="view-refresh-symbolic")
        btn_refresh.connect("clicked", self.refresh_list)
        toolbar.append(btn_refresh)
        
        self.append(toolbar)

        # Lista de Ficheiros em Quarentena
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE) # Apenas usamos os botões de cada linha
        self.listbox.add_css_class("boxed-list") # Estilo moderno do Libadwaita
        
        scroll.set_child(self.listbox)
        self.append(scroll)

        # Carrega a lista pela primeira vez
        self.refresh_list()

    def refresh_list(self, *args):
        """Lê os itens da quarentena e recria a lista na interface."""
        # Limpa os itens antigos
        while child := self.listbox.get_first_child():
            self.listbox.remove(child)

        items = quarantine_manager.list_quarantined()

        if not items:
            # Mostra uma mensagem se estiver vazio
            empty_lbl = Gtk.Label(label="A Quarentena está vazia. O seu sistema está limpo!")
            empty_lbl.set_margin_top(20)
            empty_lbl.set_margin_bottom(20)
            self.listbox.append(empty_lbl)
            return

        # Preenche com os ficheiros infetados
        for item in items:
            row = self._create_row(item)
            self.listbox.append(row)

    def _create_row(self, item):
        """Cria uma linha visual para cada ficheiro infetado."""
        row = Gtk.ListBoxRow()
        
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        hbox.set_margin_top(10)
        hbox.set_margin_bottom(10)
        hbox.set_margin_start(10)
        hbox.set_margin_end(10)
        
        # Ícone de Aviso
        icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        icon.set_pixel_size(32)
        hbox.append(icon)
        
        # Informação em texto
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        vbox.set_hexpand(True)
        vbox.set_valign(Gtk.Align.CENTER)
        
        name_lbl = Gtk.Label(label=f"<b>{item['original_name']}</b>")
        name_lbl.set_use_markup(True)
        name_lbl.set_halign(Gtk.Align.START)
        
        details_lbl = Gtk.Label(label=f"Infeção: {item['virus_name']} | Data: {item['timestamp']}")
        details_lbl.set_halign(Gtk.Align.START)
        details_lbl.add_css_class("dim-label")
        
        path_lbl = Gtk.Label(label=f"Caminho original: {item['original_path']}")
        path_lbl.set_halign(Gtk.Align.START)
        path_lbl.add_css_class("caption")
        
        vbox.append(name_lbl)
        vbox.append(details_lbl)
        vbox.append(path_lbl)
        hbox.append(vbox)
        
        # Botão Restaurar
        btn_restore = Gtk.Button(label="Restaurar")
        btn_restore.set_valign(Gtk.Align.CENTER)
        btn_restore.set_tooltip_text("Devolve o ficheiro ao local original.")
        # Passamos o ID do ficheiro para a função do botão
        btn_restore.connect("clicked", self.on_restore_clicked, item['id'])
        
        # Botão Apagar
        btn_delete = Gtk.Button(label="Apagar")
        btn_delete.set_valign(Gtk.Align.CENTER)
        btn_delete.add_css_class("destructive-action")
        btn_delete.set_tooltip_text("Elimina o ficheiro permanentemente do disco.")
        btn_delete.connect("clicked", self.on_delete_clicked, item['id'])
        
        hbox.append(btn_restore)
        hbox.append(btn_delete)
        
        row.set_child(hbox)
        return row

    def on_restore_clicked(self, btn, q_id):
        """Restaura o ficheiro e avisa o utilizador."""
        if quarantine_manager.restore_file(q_id):
            self._show_dialog("Ficheiro Restaurado", "O ficheiro foi devolvido com sucesso à sua pasta original.")
        else:
            self._show_dialog("Erro", "Não foi possível restaurar o ficheiro.")
        self.refresh_list()

    def on_delete_clicked(self, btn, q_id):
        """Apaga o ficheiro definitivamente e avisa o utilizador."""
        if quarantine_manager.delete_file(q_id):
            self._show_dialog("Ficheiro Apagado", "A ameaça foi eliminada permanentemente do seu computador.")
        else:
            self._show_dialog("Erro", "Não foi possível eliminar o ficheiro.")
        self.refresh_list()

    def _show_dialog(self, title, message):
        """Função auxiliar para mostrar mensagens."""
        # Como estamos numa aba, o 'parent' ideal é a janela principal
        root_window = self.get_root()
        dialog = Adw.MessageDialog(transient_for=root_window, heading=title, body=message)
        dialog.add_response("ok", "OK")
        dialog.present()