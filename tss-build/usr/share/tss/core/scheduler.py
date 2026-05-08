import time
import threading
import logging
import os

# Precisamos da biblioteca schedule (pip install schedule)
try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

# Integração com os nossos módulos
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger
from securityscan.core.scanner_full import scanner_full


class ScanScheduler:
    """
    Gestor de agendamento de scans.
    Mantém uma thread leve em background a verificar os horários.
    """
    def __init__(self):
        self._is_running = False
        self._thread = None

    def start(self) -> bool:
        """Inicia o relógio do agendador e carrega as definições."""
        if not SCHEDULE_AVAILABLE:
            app_logger.log("system", "Falha no Scheduler: pacote 'schedule' não instalado.", logging.ERROR)
            return False

        if self._is_running:
            return True

        self._load_jobs_from_settings()

        self._is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        
        app_logger.log("system", "Serviço de Agendamento (Scheduler) INICIADO.", logging.INFO)
        return True

    def stop(self):
        """Para o agendador."""
        self._is_running = False
        if SCHEDULE_AVAILABLE:
            schedule.clear()
        app_logger.log("system", "Serviço de Agendamento PARADO.", logging.INFO)

    def _run_loop(self):
        """Loop que corre a cada 1 minuto (aproximadamente) para verificar a hora."""
        while self._is_running:
            schedule.run_pending()
            # Dorme 10 segundos para não consumir CPU (não precisamos de precisão ao milissegundo)
            time.sleep(10)

    def set_daily_scan(self, run_time: str, target_path: str):
        """
        Agenda um Full Scan diário.
        :param run_time: String no formato "HH:MM" (ex: "14:30")
        :param target_path: Pasta alvo do ClamAV
        """
        if not SCHEDULE_AVAILABLE: return

        # Limpa tarefas anteriores para não duplicar (nesta versão simplificada, permitimos 1 scan agendado global)
        schedule.clear()
        
        # Guarda na configuração
        app_settings.set("scheduled_scan_mode", "daily")
        app_settings.set("scheduled_scan_time", run_time)
        app_settings.set("scheduled_scan_target", target_path)

        # Regista a tarefa
        schedule.every().day.at(run_time).do(self._trigger_scan, target_path)
        app_logger.log("system", f"Novo Agendamento: Scan diário configurado para as {run_time} em {target_path}")

    def clear_schedule(self):
        """Remove todos os agendamentos."""
        if not SCHEDULE_AVAILABLE: return
        schedule.clear()
        app_settings.set("scheduled_scan_mode", "none")
        app_logger.log("system", "Agendamentos removidos com sucesso.")

    def _load_jobs_from_settings(self):
        """Lê o settings.json para repor o agendamento no arranque da app."""
        if not SCHEDULE_AVAILABLE: return
        schedule.clear()

        mode = app_settings.get("scheduled_scan_mode", "none")
        if mode == "daily":
            run_time = app_settings.get("scheduled_scan_time", "12:00")
            target = app_settings.get("scheduled_scan_target", os.path.expanduser("~/Downloads"))
            
            schedule.every().day.at(run_time).do(self._trigger_scan, target)
            app_logger.log("system", f"Agendamento carregado do disco: Diariamente às {run_time}")

    def _trigger_scan(self, target_path: str):
        """Função chamada pelo scheduler quando chega à hora exata."""
        app_logger.log("system", "O Scheduler disparou! A iniciar Full Scan Automático...")
        
        # Inicia o scan usando o módulo já existente!
        scanner_full.scan(
            target_path=target_path,
            on_progress=None,  # Como é background, não chateamos a UI com progresso detalhado
            on_alert=self._on_scheduled_alert,
            on_finished=self._on_scheduled_finished
        )

    # Callbacks do scan automático
    def _on_scheduled_alert(self, source, warning_msg):
        app_logger.log("system", f"[SCAN AUTOMÁTICO] Alerta de {source}: {warning_msg}", logging.WARNING)

    def _on_scheduled_finished(self, summary_dict):
        app_logger.log("system", "[SCAN AUTOMÁTICO] Concluído com sucesso!")


# Instância global
app_scheduler = ScanScheduler()

# NOTA PARA TESTE: A biblioteca schedule suporta ".every(5).seconds.do(...)"
# O que nos vai dar muito jeito para o script de teste!