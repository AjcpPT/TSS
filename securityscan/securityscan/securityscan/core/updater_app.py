import threading
import logging
import json
import urllib.request
from urllib.error import URLError

# Integração com os módulos do sistema
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger

class AppUpdater:
    """
    Gestor de atualizações da própria aplicação.
    Consulta a API do GitHub para verificar novas versões.
    """
    def __init__(self):
        self._is_checking = False
        # TODO: Alterar para o URL do teu repositório real no GitHub no futuro
        self.github_api_url = "https://api.github.com/repos/AjcpPT/TSS/releases/latest"

    def check_for_updates(self, current_version: str, on_finished=None) -> bool:
        """
        Inicia a verificação de nova versão numa thread em background.
        :param current_version: Ex: "1.0.0"
        """
        if self._is_checking:
            app_logger.log("system", "Verificação de atualização da app já em curso.", logging.WARNING)
            return False

        self._is_checking = True
        thread = threading.Thread(
            target=self._run_check,
            args=(current_version, on_finished),
            daemon=True
        )
        thread.start()
        return True

    def _run_check(self, current_version, on_finished):
        """Lógica interna para chamada de rede."""
        app_logger.log("system", "A verificar se há atualizações para a aplicação SecurityScan...")
        
        # --- MODO SIMULAÇÃO (Placeholder) ---
        # Mantém esta variável como True até teres o GitHub pronto.
        is_simulation = True
        if is_simulation:
            import time
            time.sleep(1.5)  # Simula a latência de rede
            simulated_latest_version = "1.0.1"  # Finge que a net tem a v1.0.1
            
            if simulated_latest_version > current_version:
                result = {
                    "status": "update_available",
                    "latest_version": simulated_latest_version,
                    "release_notes": "• Correção de bugs visuais.\n• Maior rapidez no scan do ClamAV.",
                    "download_url": "https://github.com/TEU-USER/SecurityScan/releases/latest"
                }
                app_logger.log("system", f"Nova atualização encontrada: v{simulated_latest_version}", logging.INFO)
            else:
                result = {
                    "status": "up_to_date",
                    "latest_version": current_version,
                    "message": "A aplicação já está na versão mais recente."
                }
                app_logger.log("system", "A aplicação já está atualizada.", logging.INFO)
            
            self._is_checking = False
            if on_finished:
                on_finished(result)
            return
        # ------------------------------------

        # --- MODO REAL (API GITHUB) ---
        try:
            req = urllib.request.Request(self.github_api_url, headers={'User-Agent': 'SecurityScan-App'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                # Assume que as tags são tipo "v1.0.1" ou "1.0.1"
                latest_version = data.get("tag_name", "").replace("v", "")
                
                if latest_version and latest_version > current_version:
                    result = {
                        "status": "update_available",
                        "latest_version": latest_version,
                        "release_notes": data.get("body", "Sem notas de lançamento disponíveis."),
                        "download_url": data.get("html_url", "")
                    }
                    app_logger.log("system", f"Nova atualização encontrada: v{latest_version}", logging.INFO)
                else:
                    result = {
                        "status": "up_to_date",
                        "latest_version": current_version,
                        "message": "A aplicação já está na versão mais recente."
                    }
                    app_logger.log("system", "A aplicação SecurityScan está atualizada.", logging.INFO)
                    
        except URLError as e:
            msg = f"Erro de rede ao verificar atualizações da app: {e}"
            app_logger.log("system", msg, logging.ERROR)
            result = {"status": "error", "message": msg}
        except Exception as e:
            msg = f"Erro inesperado ao verificar atualizações da app: {e}"
            app_logger.log("system", msg, logging.ERROR)
            result = {"status": "error", "message": msg}

        self._is_checking = False
        if on_finished:
            on_finished(result)

# Instância global
updater_app = AppUpdater()