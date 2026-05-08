import subprocess
import threading
import logging

# Integração com os nossos módulos
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger

class ClamAVUpdater:
    """
    Gestor de atualizações de assinaturas de vírus do ClamAV.
    Executa o 'freshclam' em background e processa as credenciais.
    """
    def __init__(self):
        self._is_running = False
        self._process = None

    def update_signatures(self, on_progress=None, on_finished=None) -> bool:
        """Inicia a atualização numa thread de background."""
        if self._is_running:
            app_logger.log("system", "Já existe uma atualização do ClamAV a decorrer.", logging.WARNING)
            return False

        self._is_running = True
        thread = threading.Thread(
            target=self._run_update,
            args=(on_progress, on_finished),
            daemon=True
        )
        thread.start()
        return True

    def _run_update(self, on_progress, on_finished):
        """Lógica interna de parsing do freshclam."""
        app_logger.log("system", "Início da verificação de atualizações do ClamAV (freshclam)...")
        
        # freshclam necessita de pkexec para ter permissões de escrita em /var/lib/clamav
        cmd = ["pkexec", "freshclam"]
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            success = False
            is_locked = False

            # Lemos a saída de consola do freshclam em tempo real
            for line in self._process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                # Se houver callbacks, atualiza a UI
                if on_progress:
                    on_progress(line)
                    
                # Verifica se o ficheiro está bloqueado pelo serviço automático do Linux
                if "locked by another process" in line.lower() or "already running" in line.lower():
                    is_locked = True
                    app_logger.log("system", "O serviço automático já está a correr no background.", logging.INFO)

                # Verifica indicadores de sucesso
                if "database updated" in line.lower() or "up-to-date" in line.lower():
                    success = True

            self._process.wait()
            
            # Se for bem-sucedido ou se já estiver a ser tratado pelo daemon do sistema
            if self._process.returncode == 0 or success or is_locked:
                msg = "Bases de dados do ClamAV atualizadas ou em processo automático."
                app_logger.log("system", msg, logging.INFO)
                if on_finished:
                    on_finished({"status": "success", "message": msg})
            elif self._process.returncode == 126:
                msg = "Autenticação cancelada pelo utilizador."
                app_logger.log("system", msg, logging.WARNING)
                if on_finished:
                    on_finished({"status": "error", "message": msg})
            elif self._process.returncode == 127:
                msg = "Permissões insuficientes para atualizar o ClamAV."
                app_logger.log("system", msg, logging.WARNING)
                if on_finished:
                    on_finished({"status": "error", "message": msg})
            else:
                msg = f"Erro ao atualizar o ClamAV. Código: {self._process.returncode}"
                app_logger.log("system", msg, logging.WARNING)
                if on_finished:
                    on_finished({"status": "error", "message": msg})

        except FileNotFoundError:
            msg = "Comando 'freshclam' não encontrado. O ClamAV está instalado?"
            app_logger.log("system", msg, logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": msg})
        except Exception as e:
            app_logger.log("system", f"Erro crítico na atualização: {e}", logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": str(e)})

        self._is_running = False

    def configure_paid_databases(self, enable: bool, token: str = "") -> bool:
        """
        Configura credenciais de bases de dados privadas.
        Na prática, isto dita se a app injeta o token no ficheiro de configuração nativo.
        """
        app_settings.set("clamav_paid_db_enabled", enable)
        
        if enable and token:
            # Num cenário real, tokens sensíveis devem usar uma lib como o 'keyring' para o Secret Service do Linux
            app_settings.set("clamav_paid_token", token)
            app_logger.log("system", "Credenciais de base de dados privada configuradas com sucesso.", logging.INFO)
            return True
        elif not enable:
            app_settings.set("clamav_paid_token", "")
            app_logger.log("system", "Bases de dados privadas desativadas. A usar bases gratuitas padrão.", logging.INFO)
            return True
            
        return False

# Instância global
updater_clamav = ClamAVUpdater()