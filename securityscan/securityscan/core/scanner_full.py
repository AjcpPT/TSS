import threading
import logging

# Integração com os módulos que já criámos
from securityscan.core.logger import app_logger
from securityscan.core.scanner_clamav import scanner_clamav
from securityscan.core.scanner_rootkit import scanner_rootkit

class FullScanner:
    """
    Orquestrador que executa o ClamAV e o Rootkit Scanner em simultâneo.
    Unifica os resultados e emite callbacks consolidados para a UI.
    """

    def __init__(self):
        self._is_running = False
        self._lock = threading.Lock()
        
        # Variáveis de estado para sabermos quem já terminou
        self._clamav_done = False
        self._rootkit_done = False
        self._summary = {"clamav": None, "rootkit": None}
        self._master_on_finished = None

    def stop_scan(self):
        """Interrompe ambos os scans."""
        if self._is_running:
            scanner_clamav.stop_scan()
            scanner_rootkit.stop_scan()
            app_logger.log("system", "Full Scan interrompido pelo utilizador.", logging.WARNING)
            self._is_running = False

    def scan(self, target_path: str, on_progress=None, on_alert=None, on_finished=None) -> bool:
        """
        Inicia os dois scans em simultâneo.
        :param target_path: Caminho alvo para o ClamAV (o Rootkit verifica sempre o sistema).
        :param on_progress: Callback f(source, message) chamado a cada ficheiro processado.
        :param on_alert: Callback f(source, warning_msg) chamado quando deteta ameaça.
        :param on_finished: Callback f(summary_dict) chamado quando AMBOS terminarem.
        """
        if self._is_running:
            app_logger.log("system", "Já existe um Full Scan em execução.", logging.WARNING)
            return False

        self._is_running = True
        self._clamav_done = False
        self._rootkit_done = False
        self._summary = {"clamav": None, "rootkit": None}
        self._master_on_finished = on_finished

        app_logger.log("system", f"A iniciar Full Scan. Alvo ClamAV: {target_path}")

        # --- Callbacks Intercetores ---
        
        def _clamav_finished(summary_dict):
            with self._lock:
                self._clamav_done = True
                self._summary["clamav"] = summary_dict
                self._check_completion()

        def _rootkit_finished(summary_dict):
            with self._lock:
                self._rootkit_done = True
                self._summary["rootkit"] = summary_dict
                self._check_completion()

        def _clamav_infected(file_path, virus_name):
            if on_alert:
                on_alert("ClamAV", f"Ficheiro: {file_path} | Vírus: {virus_name}")

        def _rootkit_warning(source, warning_msg):
            if on_alert:
                on_alert(f"Rootkit ({source})", warning_msg)
                
        def _clamav_progress(file_path):
            if on_progress:
                on_progress("ClamAV", file_path)

        def _rootkit_progress(message):
            if on_progress:
                on_progress("Rootkit", message)


        # --- Início Simultâneo ---
        
        clamav_started = scanner_clamav.scan(
            target_path=target_path,
            on_progress=_clamav_progress,
            on_infected=_clamav_infected,
            on_finished=_clamav_finished
        )

        rootkit_started = scanner_rootkit.scan(
            on_progress=_rootkit_progress,
            on_warning=_rootkit_warning,
            on_finished=_rootkit_finished
        )

        # Prevenção: E se uma das ferramentas não estiver instalada e nem chegar a iniciar?
        with self._lock:
            if not clamav_started:
                self._clamav_done = True
                self._summary["clamav"] = {"status": "error", "message": "ClamAV não iniciou (não instalado?)."}
            if not rootkit_started:
                self._rootkit_done = True
                self._summary["rootkit"] = {"status": "error", "message": "Rootkit scanner não iniciou (não instalado?)."}
            
            # Se nenhum iniciar, finaliza logo
            if not clamav_started and not rootkit_started:
                self._check_completion()
        
        return True

    def _check_completion(self):
        """Verifica se ambos terminaram. Se sim, dispara o evento final."""
        if self._clamav_done and self._rootkit_done:
            self._is_running = False
            app_logger.log("system", "Full Scan concluído.")
            if self._master_on_finished:
                self._master_on_finished({
                    "status": "completed",
                    "summary": self._summary
                })

# Instância global
scanner_full = FullScanner()