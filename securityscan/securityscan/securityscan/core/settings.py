import os
import json

class SettingsManager:
    """
    Gere as configurações persistentes da aplicação.
    Guarda os dados em ~/.config/securityscan/settings.json
    """
    
    def __init__(self):
        # Define o caminho padrão de configuração no Linux
        self.config_dir = os.path.expanduser("~/.config/securityscan")
        self.config_file = os.path.join(self.config_dir, "settings.json")
        
        # Definições padrão caso o ficheiro não exista
        self.settings = {
            "auto_update": True,
            "scan_downloads_on_startup": False,
            "quarantine_dir": os.path.expanduser("~/.local/share/securityscan/quarantine"),
            "monitor_enabled": False,
            "clamav_heuristics": True,
            "theme": "system"  # system, light, dark
        }
        
        self.load()

    def load(self):
        """Carrega as definições do ficheiro JSON."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_settings = json.load(f)
                    # Atualiza os defaults com as definições guardadas
                    self.settings.update(user_settings)
            except Exception as e:
                print(f"Erro ao carregar settings: {e}")
        else:
            # Se não existir, guarda os defaults
            self.save()

    def save(self):
        """Guarda as definições atuais no ficheiro JSON."""
        os.makedirs(self.config_dir, exist_ok=True)
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            print(f"Erro ao guardar settings: {e}")

    def get(self, key, default=None):
        """Obtém um valor de configuração."""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Altera um valor e guarda imediatamente."""
        self.settings[key] = value
        self.save()

# Criamos uma instância global para importar facilmente em outros módulos
# Exemplo: from core.settings import app_settings
app_settings = SettingsManager()