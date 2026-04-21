import os
import subprocess
import threading
import logging
import shutil

# Importa os módulos que já criámos
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger


class ClamAVScanner:
    """
    Controlador para o scanner ClamAV.
    Permite scans em background, interrupções e callbacks para a UI.
    """

    def __init__(self):
        self._process = None
        self._is_running = False

    def is_installed(self) -> bool:
        """Verifica se o ClamAV está instalado no sistema."""
        return shutil.which("clamscan") is not None

    def stop_scan(self):
        """Interrompe o scan em execução."""
        if self._is_running and self._process:
            self._process.terminate()
            self._is_running = False
            app_logger.log("clamav", "Scan interrompido pelo utilizador.", logging.WARNING)

    def scan(self, target_path: str, on_progress=None, on_infected=None, on_finished=None) -> bool:
        """
        Inicia o scan numa thread separada.
        :param target_path: Caminho da pasta/ficheiro a verificar.
        :param on_progress: Callback f(file_path) chamado a cada ficheiro processado.
        :param on_infected: Callback f(file_path, virus_name) chamado quando deteta ameaça.
        :param on_finished: Callback f(summary_dict) chamado no final do scan.
        """
        if not self.is_installed():
            msg = "ClamAV (clamscan) não está instalado no sistema."
            app_logger.log("clamav", msg, logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": msg})
            return False

        if self._is_running:
            app_logger.log("clamav", "Já existe um scan ClamAV em execução.", logging.WARNING)
            return False

        # Inicia a thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(target_path, on_progress, on_infected, on_finished),
            daemon=True # Garante que a thread morre se a app fechar
        )
        thread.start()
        return True

    def _run_scan(self, target_path, on_progress, on_infected, on_finished):
        """Lógica interna executada pela thread em background."""
        self._is_running = True
        app_logger.log("clamav", f"Iniciado scan em: {target_path}")

        if not os.path.exists(target_path):
            msg = f"O caminho não existe: {target_path}"
            app_logger.log("clamav", msg, logging.ERROR)
            self._is_running = False
            if on_finished:
                on_finished({"status": "error", "message": msg})
            return

        # Construir o comando
        cmd = ["clamscan", "--recursive"]

        # Aplica heurística consoante as settings
        if not app_settings.get("clamav_heuristics", True):
            # Desativa o scan heurístico de PUAs (Potentially Unwanted Applications)
            cmd.append("--detect-pua=no")

        cmd.append(target_path)

        summary = {"scanned": 0, "infected": 0, "infected_files":[]}

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1  # Leitura linha a linha
            )

            is_summary = False

            # Lemos o output do clamscan em tempo real
            for line in self._process.stdout:
                line = line.strip()
                if not line:
                    continue

                if "----------- SCAN SUMMARY -----------" in line:
                    is_summary = True

                if not is_summary:
                    # Ficheiro limpo
                    if line.endswith("OK"):
                        file_path = line.rsplit(":", 1)[0]
                        summary["scanned"] += 1
                        if on_progress:
                            on_progress(file_path)
                            
                    # Ficheiro infetado
                    elif "FOUND" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            file_path = parts[0].strip()
                            virus_info = parts[1].replace("FOUND", "").strip()
                            summary["infected"] += 1
                            summary["infected_files"].append((file_path, virus_info))
                            
                            app_logger.log("clamav", f"Infeção detetada: {file_path} - {virus_info}", logging.WARNING)
                            
                            if on_infected:
                                on_infected(file_path, virus_info)
                            if on_progress:
                                on_progress(file_path)

            self._process.wait()

        except Exception as e:
            app_logger.log("clamav", f"Erro crítico durante o scan: {e}", logging.ERROR)
            self._is_running = False
            if on_finished:
                on_finished({"status": "error", "message": str(e)})
            return

        self._is_running = False

        # Verifica se foi cancelado
        if self._process.returncode < 0:
            if on_finished:
                on_finished({"status": "cancelled", "summary": summary})
        else:
            app_logger.log("clamav", f"Scan concluído. Verificados: {summary['scanned']}, Infetados: {summary['infected']}")
            if on_finished:
                on_finished({"status": "completed", "summary": summary})


# Instância global para ser utilizada pela App
scanner_clamav = ClamAVScanner()

# --- Funções Auxiliares de Targets ---

def get_downloads_target() -> str:
    """Devolve a pasta de downloads do utilizador atual."""
    return os.path.expanduser("~/Downloads")

def get_usb_targets() -> list:
    """Devolve uma lista com os caminhos das Pens USB ligadas."""
    user = os.environ.get("USER", "")
    base_paths = [f"/media/{user}", f"/run/media/{user}"]
    usb_drives =[]
    
    for base in base_paths:
        if os.path.exists(base):
            for drive in os.listdir(base):
                usb_drives.append(os.path.join(base, drive))
                
    return usb_drives