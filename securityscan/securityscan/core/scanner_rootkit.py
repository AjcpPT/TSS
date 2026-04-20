import os
import subprocess
import threading
import logging
import shutil

# Integração com os módulos já criados
from securityscan.core.logger import app_logger

class RootkitScanner:
    """
    Controlador para scan de rootkits utilizando 'rkhunter' e/se 'chkrootkit'.
    Executa os scans em background e emite callbacks para a interface gráfica.
    """

    def __init__(self):
        self._process = None
        self._is_running = False

    def check_dependencies(self) -> dict:
        """Verifica quais os scanners de rootkit instalados."""
        return {
            "rkhunter": shutil.which("rkhunter") is not None,
            "chkrootkit": shutil.which("chkrootkit") is not None
        }

    def stop_scan(self):
        """Interrompe o scan de rootkits em execução."""
        if self._is_running and self._process:
            self._process.terminate()
            self._is_running = False
            app_logger.log("rootkit", "Scan de rootkits interrompido pelo utilizador.", logging.WARNING)

    def scan(self, on_progress=None, on_warning=None, on_finished=None) -> bool:
        """
        Inicia o scan em background.
        :param on_progress: Callback f(message) a cada item verificado.
        :param on_warning: Callback f(source, warning_msg) quando deteta algo suspeito.
        :param on_finished: Callback f(summary_dict) no final.
        """
        deps = self.check_dependencies()
        if not deps["rkhunter"] and not deps["chkrootkit"]:
            msg = "Nem o rkhunter nem o chkrootkit estão instalados no sistema."
            app_logger.log("rootkit", msg, logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": msg})
            return False

        if self._is_running:
            app_logger.log("rootkit", "Já existe um scan de rootkit em execução.", logging.WARNING)
            return False

        # Inicia a thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(deps, on_progress, on_warning, on_finished),
            daemon=True
        )
        thread.start()
        return True

    def _run_scan(self, deps, on_progress, on_warning, on_finished):
        """Lógica central: corre rkhunter e chkrootkit de forma sequencial."""
        self._is_running = True
        summary = {"scanned_items": 0, "warnings": 0, "warning_details":[]}

        app_logger.log("rootkit", "Início do scan de Rootkits.")

        # Verifica permissões (Root é ideal para estes scans)
        if os.geteuid() != 0:
            msg_priv = "O scan está a ser executado sem privilégios de ROOT. Alguns resultados podem estar ocultos ou gerar falsos positivos."
            app_logger.log("rootkit", msg_priv, logging.WARNING)
            if on_warning:
                on_warning("Permissões", msg_priv)

        try:
            # 1. Executa RKHUNTER
            if deps["rkhunter"] and self._is_running:
                self._run_rkhunter(summary, on_progress, on_warning)

            # 2. Executa CHKROOTKIT
            if deps["chkrootkit"] and self._is_running:
                self._run_chkrootkit(summary, on_progress, on_warning)

        except Exception as e:
            app_logger.log("rootkit", f"Erro crítico durante o scan de rootkits: {e}", logging.ERROR)
            self._is_running = False
            if on_finished:
                on_finished({"status": "error", "message": str(e)})
            return

        self._is_running = False

        # Se não foi interrompido a meio
        if self._process and self._process.returncode is not None and self._process.returncode < 0:
            if on_finished:
                on_finished({"status": "cancelled", "summary": summary})
        else:
            app_logger.log("rootkit", f"Scan de rootkits concluído. Alertas encontrados: {summary['warnings']}")
            if on_finished:
                on_finished({"status": "completed", "summary": summary})

    def _run_rkhunter(self, summary, on_progress, on_warning):
        """Sub-processo dedicado ao rkhunter."""
        app_logger.log("rootkit", "A iniciar rkhunter...")
        
        # Parâmetros: check (scan), skip-keypress (não pausar), nocolors (facilita parsing)
        cmd =["rkhunter", "--check", "--skip-keypress", "--nocolors"]
        
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        for line in self._process.stdout:
            line = line.strip()
            if not line:
                continue

            # Captura de progresso
            if "Checking" in line:
                summary["scanned_items"] += 1
                if on_progress:
                    # Limpa a linha para enviar para a UI sem as tags de [ OK ]
                    clean_msg = line.split("[")[0].strip()
                    on_progress(f"[rkhunter] {clean_msg}")

            # Captura de alertas/infeções
            if "Warning:" in line or "[ Warning ]" in line:
                summary["warnings"] += 1
                summary["warning_details"].append(("rkhunter", line))
                app_logger.log("rootkit", f"Alerta rkhunter: {line}", logging.WARNING)
                if on_warning:
                    on_warning("rkhunter", line)

        self._process.wait()

    def _run_chkrootkit(self, summary, on_progress, on_warning):
        """Sub-processo dedicado ao chkrootkit."""
        app_logger.log("rootkit", "A iniciar chkrootkit...")
        cmd = ["chkrootkit"]
        
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        for line in self._process.stdout:
            line = line.strip()
            if not line:
                continue

            summary["scanned_items"] += 1
            if on_progress:
                clean_msg = line.split("...")[0].strip()
                on_progress(f"[chkrootkit] {clean_msg}")

            if "INFECTED" in line or "Vulnerable" in line:
                summary["warnings"] += 1
                summary["warning_details"].append(("chkrootkit", line))
                app_logger.log("rootkit", f"Alerta chkrootkit: {line}", logging.WARNING)
                if on_warning:
                    on_warning("chkrootkit", line)

        self._process.wait()


# Instância global
scanner_rootkit = RootkitScanner()