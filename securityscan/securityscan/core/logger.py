import os
import logging
from logging.handlers import TimedRotatingFileHandler
import shutil
from datetime import datetime

# Tenta importar fpdf2 para exportação PDF
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


class SecurityLogger:
    """
    Sistema de Logs para a aplicação.
    Separa os logs por tipos (clamav, rootkit, updater, system).
    """
    
    def __init__(self):
        self.log_dir = os.path.expanduser("~/.local/share/securityscan/logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.loggers = {}

    def _get_logger(self, log_type: str):
        """Configura e devolve um logger específico para um tipo de evento."""
        if log_type in self.loggers:
            return self.loggers[log_type]

        logger = logging.getLogger(log_type)
        logger.setLevel(logging.INFO)
        
        # Evitar duplicação de handlers se o logger já existir
        if not logger.handlers:
            log_file = os.path.join(self.log_dir, f"{log_type}.log")
            
            # TimedRotatingFileHandler guarda logs por 30 dias (backupCount=30)
            # à meia-noite (when="midnight"). Isso resolve a necessidade de "limpeza".
            fh = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=30)
            fh.setLevel(logging.INFO)
            
            formatter = logging.Formatter('%(asctime)s -[%(levelname)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            fh.setFormatter(formatter)
            
            logger.addHandler(fh)

        self.loggers[log_type] = logger
        return logger

    def log(self, log_type: str, message: str, level=logging.INFO):
        """Grava uma mensagem no log especificado."""
        logger = self._get_logger(log_type)
        logger.log(level, message)

    def get_log_content(self, log_type: str) -> str:
        """Devolve o texto completo do log para exibição na UI."""
        log_file = os.path.join(self.log_dir, f"{log_type}.log")
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                return f.read()
        return "Nenhum log encontrado."

    def clear_log(self, log_type: str):
        """Limpa o conteúdo de um log específico manualmente."""
        log_file = os.path.join(self.log_dir, f"{log_type}.log")
        if os.path.exists(log_file):
            open(log_file, 'w').close()  # Trunca o ficheiro
            self.log(log_type, "Log limpo manualmente pelo utilizador.", logging.INFO)

    def export_txt(self, log_type: str, dest_path: str) -> bool:
        """Exporta o log atual para um ficheiro TXT."""
        log_file = os.path.join(self.log_dir, f"{log_type}.log")
        if os.path.exists(log_file):
            try:
                shutil.copy2(log_file, dest_path)
                return True
            except Exception as e:
                self.log("system", f"Erro ao exportar TXT: {e}", logging.ERROR)
        return False

    def export_pdf(self, log_type: str, dest_path: str) -> bool:
        """Exporta o log atual para um ficheiro PDF."""
        if not FPDF_AVAILABLE:
            self.log("system", "Falha na exportação: Biblioteca fpdf2 não instalada.", logging.ERROR)
            return False
            
        content = self.get_log_content(log_type)
        if not content or content == "Nenhum log encontrado.":
            return False

        try:
            pdf = FPDF()
            pdf.add_page()
            # Font Helvetica é nativa no FPDF
            pdf.set_font("Helvetica", size=10)
            
            title = f"SecurityScan Log Report - {log_type.upper()}"
            pdf.set_font("Helvetica", style="B", size=14)
            pdf.cell(0, 10, title, align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            
            pdf.set_font("Helvetica", size=9)
            for line in content.split('\n'):
                # FPDF lida melhor com texto latin-1 ou substituições automáticas
                pdf.multi_cell(0, 5, line)
                
            pdf.output(dest_path)
            return True
        except Exception as e:
            self.log("system", f"Erro ao gerar PDF: {e}", logging.ERROR)
            return False

# Instância global
app_logger = SecurityLogger()