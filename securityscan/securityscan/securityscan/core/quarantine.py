import os
import shutil
import json
import uuid
import logging
from datetime import datetime

# Integração com os módulos que já criámos
from securityscan.core.settings import app_settings
from securityscan.core.logger import app_logger

class QuarantineManager:
    """
    Gere a quarentena de ficheiros infetados.
    Permite isolar, restaurar, apagar permanentemente e listar ameaças.
    """

    def __init__(self):
        # Vai buscar o diretório da quarentena às settings
        self.quarantine_dir = app_settings.get("quarantine_dir", os.path.expanduser("~/.local/share/securityscan/quarantine"))
        self.index_file = os.path.join(self.quarantine_dir, "index.json")
        self._ensure_dir()

    def _ensure_dir(self):
        """Garante que a pasta da quarentena e o ficheiro de index existem."""
        os.makedirs(self.quarantine_dir, exist_ok=True)
        if not os.path.exists(self.index_file):
            self._save_index({})

    def _load_index(self) -> dict:
        """Carrega o registo atual de ficheiros em quarentena."""
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                app_logger.log("system", f"Erro ao ler index da quarentena: {e}", logging.ERROR)
        return {}

    def _save_index(self, data: dict):
        """Guarda o registo no ficheiro JSON."""
        try:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            app_logger.log("system", f"Erro ao guardar index da quarentena: {e}", logging.ERROR)

    def quarantine_file(self, file_path: str, virus_name: str = "Unknown") -> bool:
        """
        Move um ficheiro para a quarentena de forma segura.
        :param file_path: Caminho atual do ficheiro infetado.
        :param virus_name: Nome da ameaça detetada.
        """
        if not os.path.exists(file_path):
            app_logger.log("system", f"Falha na quarentena: Ficheiro não existe ({file_path})", logging.WARNING)
            return False

        # Gerar um ID único para o ficheiro na quarentena (evita colisão de nomes)
        q_id = uuid.uuid4().hex
        safe_filename = f"{q_id}.q"
        dest_path = os.path.join(self.quarantine_dir, safe_filename)

        try:
            # Mover para a quarentena
            shutil.move(file_path, dest_path)
            
            # Remover permissões de execução (Leitura e Escrita apenas para o dono)
            os.chmod(dest_path, 0o600)

            # Registar no Index
            index = self._load_index()
            index[q_id] = {
                "original_path": file_path,
                "original_name": os.path.basename(file_path),
                "virus_name": virus_name,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "stored_file": safe_filename
            }
            self._save_index(index)
            
            app_logger.log("clamav", f"Ficheiro movido para quarentena: {file_path} [{virus_name}]", logging.INFO)
            return True

        except Exception as e:
            app_logger.log("system", f"Erro ao colocar {file_path} em quarentena: {e}", logging.ERROR)
            return False

    def list_quarantined(self) -> list:
        """Devolve uma lista com todos os itens na quarentena para a UI."""
        index = self._load_index()
        results =[]
        for q_id, info in index.items():
            info["id"] = q_id
            results.append(info)
        return results

    def restore_file(self, q_id: str) -> bool:
        """Restaura o ficheiro para o seu local original (ou perto, se a pasta não existir)."""
        index = self._load_index()
        if q_id not in index:
            return False

        info = index[q_id]
        stored_path = os.path.join(self.quarantine_dir, info["stored_file"])
        original_path = info["original_path"]

        # Se o diretório original já não existir, restaura para o Desktop
        orig_dir = os.path.dirname(original_path)
        if not os.path.exists(orig_dir):
            original_path = os.path.join(os.path.expanduser("~/Desktop"), info["original_name"])

        try:
            shutil.move(stored_path, original_path)
            # Tenta repor permissões padrão
            os.chmod(original_path, 0o644)
            
            # Remove do Index
            del index[q_id]
            self._save_index(index)
            
            app_logger.log("system", f"Ficheiro restaurado da quarentena para: {original_path}", logging.INFO)
            return True
        except Exception as e:
            app_logger.log("system", f"Erro ao restaurar ficheiro {q_id}: {e}", logging.ERROR)
            return False

    def delete_file(self, q_id: str) -> bool:
        """Apaga o ficheiro de vez do disco rígido."""
        index = self._load_index()
        if q_id not in index:
            return False

        info = index[q_id]
        stored_path = os.path.join(self.quarantine_dir, info["stored_file"])

        try:
            if os.path.exists(stored_path):
                os.remove(stored_path)
            
            del index[q_id]
            self._save_index(index)
            
            app_logger.log("system", f"Ficheiro apagado permanentemente da quarentena: {info['original_name']}", logging.INFO)
            return True
        except Exception as e:
            app_logger.log("system", f"Erro ao apagar ficheiro {q_id}: {e}", logging.ERROR)
            return False

# Instância global
quarantine_manager = QuarantineManager()