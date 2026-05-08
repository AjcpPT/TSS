import os
import subprocess
import threading
import logging
import shutil

from securityscan.core.logger import app_logger

class RootkitUpdater:
    """
    Gestor de atualizações para ferramentas Anti-Rootkit (rkhunter).
    Usa pkexec para pedir password graficamente.
    """
    def __init__(self):
        self._is_running = False

    def is_installed(self) -> bool:
        return shutil.which("rkhunter") is not None

    def update(self, on_progress=None, on_finished=None) -> bool:
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
        app_logger.log("system", "A iniciar atualização do rkhunter via pkexec...")
        if on_progress:
            on_progress("-> Será pedida a password de administrador.")

        # Atualiza bases de dados online
        success_update = self._execute_command(
            cmd=["pkexec", "rkhunter", "--update", "--nocolors"],
            desc="Atualização de bases de dados online",
            on_progress=on_progress
        )

        # Atualiza propriedades dos ficheiros do sistema
        success_prop = self._execute_command(
            cmd=["pkexec", "rkhunter", "--propupd", "--nocolors"],
            desc="Atualização de propriedades do sistema (propupd)",
            on_progress=on_progress
        )

        self._is_running = False

        # Considera sucesso se pelo menos o propupd funcionou
        if success_prop:
            if success_update:
                msg = "Atualização do rkhunter concluída com sucesso."
            else:
                msg = "Propriedades do sistema atualizadas. As bases de dados online falharam (mirrors indisponíveis?)."
            app_logger.log("system", msg, logging.INFO)
            if on_finished:
                on_finished({"status": "success", "message": msg})
        else:
            msg = "A atualização do rkhunter falhou. Verifique se a autenticação foi aceite."
            app_logger.log("system", msg, logging.WARNING)
            if on_finished:
                on_finished({"status": "error", "message": msg})

    def _execute_command(self, cmd: list, desc: str, on_progress) -> bool:
        try:
            if on_progress:
                on_progress(f"\n--- {desc.upper()} ---")

            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )

            for line in process.stdout:
                line = line.strip()
                if line and on_progress and not line.startswith("\r"):
                    on_progress(line)

            process.wait()

            # pkexec retorna 126 se cancelado, 127 se sem permissões
            if process.returncode == 126:
                if on_progress:
                    on_progress("-> Autenticação cancelada pelo utilizador.")
                return False
            elif process.returncode == 127:
                if on_progress:
                    on_progress("-> Permissões insuficientes.")
                return False

            return process.returncode == 0

        except Exception as e:
            app_logger.log("system", f"Erro crítico na etapa [{desc}]: {e}", logging.ERROR)
            return False

# Instância global
updater_rootkit = RootkitUpdater()
