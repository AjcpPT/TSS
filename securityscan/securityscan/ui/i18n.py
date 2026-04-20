from securityscan.core.settings import app_settings

class Translator:
    """Sistema de traduções (PT e EN)."""
    
    STRINGS = {
        "PT": {
            "app_title": "Tuga Security Scan (TSS) by AjcpPT",
            "menu_file": "Ficheiro",
            "menu_quit": "Sair",
            "menu_options": "Opções",
            "menu_lang": "Idioma",
            "menu_lang_pt": "Português",
            "menu_lang_en": "Inglês",
            "menu_tools": "Ferramentas",
            "menu_about": "Sobre",
            "menu_about_app": "Sobre o TSS",
            "tab_clamav": "Scan ClamAV",
            "tab_rootkit": "Scan Rootkit",
            "tab_full": "Full Scan",
            "tab_quarantine": "Quarentena",
            "tab_monitor": "Proteção Ativa",
            "tab_logs": "Registos (Logs)",
            "tab_schedule": "Agendador",
            "missing_deps_title": "Dependências em Falta",
            "missing_deps_msg": "Os motores de busca (ClamAV / RKHunter) não estão instalados no sistema. O TSS necessita deles para funcionar.\nDeseja instalá-los agora?",
            "btn_install": "Instalar Agora",
            "btn_ignore": "Ignorar",
            "installing_msg": "A pedir permissões e a instalar dependências...\nIsto pode demorar alguns minutos. Por favor, aguarde.",
            "install_success_title": "Instalação Concluída",
            "install_success_msg": "Instalação concluída com sucesso! Por favor, reinicie o Tuga Security Scan para detetar os novos motores.",
            "install_error_title": "Erro na Instalação",
            "install_error_msg": "Não foi possível concluir a instalação. Pode ter sido cancelada ou ocorreu um erro de rede.",
        },
        "EN": {
            "app_title": "Tuga Security Scan (TSS) by AjcpPT",
            "menu_file": "File",
            "menu_quit": "Quit",
            "menu_options": "Options",
            "menu_lang": "Language",
            "menu_lang_pt": "Portuguese",
            "menu_lang_en": "English",
            "menu_tools": "Tools",
            "menu_about": "About",
            "menu_about_app": "About TSS",
            "tab_clamav": "ClamAV Scan",
            "tab_rootkit": "Rootkit Scan",
            "tab_full": "Full Scan",
            "tab_quarantine": "Quarantine",
            "tab_monitor": "Active Protection",
            "tab_logs": "Logs",
            "tab_schedule": "Scheduler",
            "missing_deps_title": "Missing Dependencies",
            "missing_deps_msg": "The scan engines (ClamAV / RKHunter) are not installed on your system. TSS requires them to function.\nDo you want to install them now?",
            "btn_install": "Install Now",
            "btn_ignore": "Ignore",
            "installing_msg": "Requesting permissions and installing dependencies...\nThis might take a few minutes. Please wait.",
            "install_success_title": "Installation Complete",
            "install_success_msg": "Installation finished successfully! Please restart Tuga Security Scan to detect the new engines.",
            "install_error_title": "Installation Error",
            "install_error_msg": "Could not complete the installation. It might have been canceled or a network error occurred.",
        }
    }

    @classmethod
    def get(cls, key: str) -> str:
        lang = app_settings.get("language", "PT")
        if lang not in cls.STRINGS:
            lang = "PT"
        return cls.STRINGS[lang].get(key, key)

_ = Translator.get