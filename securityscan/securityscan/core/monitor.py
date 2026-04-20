import os
import time
import threading
import queue
import logging
import subprocess

# Tenta importar watchdog (necessário instalar: pip install watchdog)
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# Integração com os nossos módulos
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger
from securityscan.core.quarantine import quarantine_manager

class ScanEventHandler(FileSystemEventHandler):
    """Interceta eventos de criação de ficheiros e envia para a fila de verificação."""
    def __init__(self, scan_queue):
        super().__init__()
        self.scan_queue = scan_queue

    def on_created(self, event):
        # Apenas processa ficheiros (ignora a criação de pastas)
        if not event.is_directory:
            self.scan_queue.put(event.src_path)

class RealTimeMonitor:
    """
    Gestor da proteção em tempo real.
    Observa a pasta selecionada e efetua scans silenciosos a novos ficheiros.
    """

    def __init__(self):
        self.observer = None
        self.is_running = False
        self.scan_queue = queue.Queue()
        self.worker_thread = None
        self.on_alert_callback = None

    def set_alert_callback(self, callback):
        """Define a função da UI a ser chamada quando apanha um vírus."""
        self.on_alert_callback = callback

    def start(self, targets=None) -> bool:
        """Inicia a proteção em tempo real nos caminhos especificados."""
        if not WATCHDOG_AVAILABLE:
            app_logger.log("system", "Falha: O pacote 'watchdog' não está instalado.", logging.ERROR)
            return False

        if self.is_running:
            return True

        if targets is None:
            targets = [os.path.expanduser("~/Downloads")]

        self.observer = Observer()
        handler = ScanEventHandler(self.scan_queue)

        valid_targets = 0
        for target in targets:
            if os.path.exists(target):
                self.observer.schedule(handler, target, recursive=True)
                valid_targets += 1

        if valid_targets == 0:
            app_logger.log("system", "Nenhum alvo válido para monitorizar.", logging.WARNING)
            return False

        self.is_running = True
        self.observer.start()

        # Inicia o detetive silencioso
        self.worker_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.worker_thread.start()

        app_settings.set("monitor_enabled", True)
        app_logger.log("system", "Proteção em Tempo Real ATIVADA.", logging.INFO)
        return True

    def stop(self):
        """Para a proteção em tempo real."""
        if self.is_running and self.observer:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            app_settings.set("monitor_enabled", False)
            app_logger.log("system", "Proteção em Tempo Real DESATIVADA.", logging.INFO)

    def _scan_worker(self):
        """Thread que consome a fila de ficheiros e verifica um a um."""
        while self.is_running:
            try:
                # Aguarda um ficheiro (timeout de 1s para poder quebrar o ciclo no 'stop')
                file_path = self.scan_queue.get(timeout=1)
                
                # Aguarda 2 segundos para dar tempo do ficheiro acabar de ser escrito no disco (ex: downloads browser)
                time.sleep(2)
                
                if os.path.exists(file_path):
                    # app_logger.log("clamav", f"[Monitor] A verificar ficheiro novo: {file_path}", logging.INFO)
                    
                    cmd = ["clamscan", "--no-summary", file_path]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
                    
                    # Se encontrou vírus no ficheiro novo
                    if "FOUND" in result.stdout:
                        virus_name = "Unknown"
                        for line in result.stdout.split('\n'):
                            if "FOUND" in line:
                                parts = line.split(":")
                                if len(parts) >= 2:
                                    virus_name = parts[1].replace("FOUND", "").strip()
                                    break
                                    
                        msg = f"Ameaça neutralizada em tempo real: {file_path} [{virus_name}]"
                        app_logger.log("clamav", msg, logging.WARNING)
                        
                        # Ativa Auto-Quarentena instantaneamente!
                        quarantine_manager.quarantine_file(file_path, virus_name)
                        
                        # Alerta a Interface Gráfica
                        if self.on_alert_callback:
                            self.on_alert_callback(file_path, virus_name)

            except queue.Empty:
                continue
            except Exception as e:
                app_logger.log("system", f"Erro no worker do monitor: {e}", logging.ERROR)


# Instância global
monitor_manager = RealTimeMonitor()