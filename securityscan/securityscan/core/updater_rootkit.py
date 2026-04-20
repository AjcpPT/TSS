import os
import subprocess
import threading
import logging
import shutil

# Integração com os nossos módulos
from securityscan.core.logger import app_logger

class RootkitUpdater:
    """
    Gestor de atualizações para ferramentas Anti-Rootkit (rkhunter).
    Faz o update de bases de dados e a atualização de propriedades de ficheiros do sistema.
    """
    def __init__(self):
        self._is_running = False

    def is_installed(self) -> bool:
        """Verifica se o rkhunter está instalado."""
        return shutil.which("rkhunter") is not None

    def update(self, on_progress=None, on_finished=None) -> bool:
        """Inicia a atualização numa thread de background."""
        if not self.is_installed():
            msg = "O pacote 'rkhunter' não está instalado no sistema."
            app_logger.log("system", msg, logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": msg})
            return False

        if self._is_running:
            app_logger.log("system", "Atualização do rkhunter já está em curso.", logging.WARNING)
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
        """Lógica executada na thread em background."""
        
        # 1. Verifica permissões
        if os.geteuid() != 0:
            aviso = "Aviso: A atualização do rkhunter requer permissões de ROOT (sudo) para ter sucesso na gravação das novas propriedades."
            app_logger.log("system", aviso, logging.WARNING)
            if on_progress:
                on_progress(aviso)

        app_logger.log("system", "A iniciar atualização do rkhunter...")

        # 2. Atualiza as bases de dados online (update)
        success_update = self._execute_command(
            cmd=["rkhunter", "--update", "--nocolors"],
            desc="Atualização de bases de dados online",
            on_progress=on_progress
        )

        # 3. Atualiza as propriedades dos ficheiros de sistema (propupd)
        success_prop = self._execute_command(
            cmd=["rkhunter", "--propupd", "--nocolors"],
            desc="Atualização de propriedades do sistema (propupd)",
            on_progress=on_progress
        )

        self._is_running = False

        if success_update and success_prop:
            msg = "Atualização do rkhunter concluída com sucesso."
            app_logger.log("system", msg, logging.INFO)
            if on_finished:
                on_finished({"status": "success", "message": msg})
        else:
            msg = "A atualização do rkhunter terminou com erros ou foi rejeitada devido a falta de privilégios."
            app_logger.log("system", msg, logging.WARNING)
            if on_finished:
                on_finished({"status": "error", "message": msg})

    def _execute_command(self, cmd: list, desc: str, on_progress) -> bool:
        """Executa um comando de subprocesso e capta o output para a UI."""
        try:
            if on_progress:
                on_progress(f"\n--- {desc.upper()} ---")

            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )

            for line in process.stdout:
                line = line.strip()
                if line:
                    # Filtra linhas redundantes de ecrãs de clear para a UI
                    if on_progress and not line.startswith("\r"):
                        on_progress(line)

            process.wait()
            # returncode 0 = Sucesso. No rkhunter, outros códigos significam falha ou necessidade de revisão.
            return process.returncode == 0
        except Exception as e:
            app_logger.log("system", f"Erro crítico na etapa [{desc}]: {e}", logging.ERROR)
            return False

# Instância global
updater_rootkit = RootkitUpdater()