import os
import subprocess
import threading
import logging
import shutil

from securityscan.core.logger import app_logger


class RootkitScanner:
    """
    Controlador para scan de rootkits utilizando rkhunter e/ou chkrootkit.
    Usa pkexec para pedir password graficamente.
    """

    def __init__(self):
        self._process = None
        self._is_running = False

    def check_dependencies(self) -> dict:
        """Verifica quais os scanners instalados, incluindo pastas de root."""
        deps = {"rkhunter": False, "chkrootkit": False}
        search_paths = ['/usr/sbin', '/sbin', '/usr/bin', '/bin', '/usr/local/sbin']
        for tool in ["rkhunter", "chkrootkit"]:
            if shutil.which(tool):
                deps[tool] = True
            else:
                for p in search_paths:
                    if os.path.exists(f"{p}/{tool}"):
                        deps[tool] = True
                        break
        return deps

    def stop_scan(self):
        """Interrompe o scan em execução."""
        if self._is_running and self._process:
            self._process.terminate()
            self._is_running = False
            app_logger.log("rootkit", "Scan interrompido pelo utilizador.", logging.WARNING)

    def scan(self, tool="both", verbose=False, skip_slow=False,
             on_progress=None, on_threat=None, on_finished=None) -> bool:
        """
        Inicia o scan em background com pkexec.
        :param tool: "both", "rkhunter" ou "chkrootkit"
        :param verbose: output detalhado
        :param skip_slow: saltar verificações lentas
        :param on_progress: Callback f(message)
        :param on_threat: Callback f(threat_description)
        :param on_finished: Callback f(summary_dict)
        """
        deps = self.check_dependencies()

        if not deps["rkhunter"] and not deps["chkrootkit"]:
            msg = "Nem o rkhunter nem o chkrootkit estão instalados."
            app_logger.log("rootkit", msg, logging.ERROR)
            if on_finished:
                on_finished({"status": "error", "message": msg})
            return False

        if self._is_running:
            app_logger.log("rootkit", "Já existe um scan em execução.", logging.WARNING)
            return False

        thread = threading.Thread(
            target=self._run_scan,
            args=(deps, tool, verbose, skip_slow, on_progress, on_threat, on_finished),
            daemon=True
        )
        thread.start()
        return True

    def _run_scan(self, deps, tool, verbose, skip_slow, on_progress, on_threat, on_finished):
        """Lógica central do scan."""
        self._is_running = True
        summary = {"threats": 0, "warnings": 0, "details": []}

        app_logger.log("rootkit", "Início do scan de rootkits.")

        try:
            run_rkhunter = tool in ("both", "rkhunter") and deps["rkhunter"]
            run_chkrootkit = tool in ("both", "chkrootkit") and deps["chkrootkit"]

            if run_rkhunter and self._is_running:
                self._run_rkhunter(summary, verbose, skip_slow, on_progress, on_threat)

            if run_chkrootkit and self._is_running:
                self._run_chkrootkit(summary, on_progress, on_threat)

        except PermissionError as e:
            self._is_running = False
            app_logger.log("rootkit", f"Erro de permissões: {e}", logging.ERROR)
            if on_finished:
                on_finished({"status": "no_root", "message": str(e)})
            return
        except Exception as e:
            app_logger.log("rootkit", f"Erro crítico: {e}", logging.ERROR)
            self._is_running = False
            if on_finished:
                on_finished({"status": "error", "message": str(e)})
            return

        was_cancelled = not self._is_running
        self._is_running = False

        if was_cancelled:
            if on_finished:
                on_finished({"status": "cancelled"})
        else:
            app_logger.log("rootkit", f"Scan concluído. Ameaças: {summary['threats']}, Avisos: {summary['warnings']}")
            if on_finished:
                on_finished({
                    "status": "completed",
                    "threats": summary["threats"],
                    "warnings": summary["warnings"],
                    "details": summary["details"]
                })

    def _check_pkexec(self):
        """Verifica se pkexec está disponível."""
        if not shutil.which("pkexec"):
            raise Exception(
                "pkexec não encontrado.\n"
                "Instale com: sudo apt install policykit-1"
            )

    def _is_real_threat(self, line: str) -> bool:
        """
        Determina se uma linha do rkhunter é uma ameaça real.
        Ignora [ Not found ], [ OK ], [ None found ] e linhas informativas.
        Só marca como ameaça se tiver [ Infected ] ou [ Warning ].
        """
        # Ignorar explicitamente resultados negativos / informativos
        ignore_markers = [
            "[ Not found ]",
            "[ OK ]",
            "[ None found ]",
            "[ Found ]",
            "Rootkit Hunter version",
            "Rootkits checked :",
            "Possible rootkits:",
            "Files checked:",
            "Suspect files:",
            "System checks summary",
            "All results have been written",
            "The system checks took",
        ]
        for marker in ignore_markers:
            if marker in line:
                return False

        # Só são ameaças reais estas marcações
        threat_markers = ["[ Warning ]", "[ Infected ]", "Warning:"]
        for marker in threat_markers:
            if marker in line:
                return True

        return False

    def _is_real_threat_chkrootkit(self, line: str) -> bool:
        """
        Determina se uma linha do chkrootkit é uma ameaça real.
        Só marca como ameaça se tiver INFECTED.
        'not infected' e 'not tested' são ignorados.
        """
        line_lower = line.lower()
        if "not infected" in line_lower:
            return False
        if "not tested" in line_lower:
            return False
        if "nothing found" in line_lower:
            return False
        if "no suspect" in line_lower:
            return False
        if "infected" in line_lower or "vulnerable" in line_lower:
            return True
        return False

    def _categorize_rkhunter_line(self, line: str) -> str:
        """
        Categoriza uma linha do rkhunter:
        - "threat"   → ameaça real ([ Warning ] ou [ Infected ])
        - "progress" → linha de progresso normal
        - "ignore"   → ignorar completamente
        """
        ignore_markers = [
            "[ Not found ]", "[ OK ]", "[ None found ]", "[ Found ]",
            "Rootkit Hunter version", "Rootkits checked",
            "Possible rootkits", "Files checked", "Suspect files",
            "System checks summary", "All results have been written",
            "The system checks took", "======",
        ]
        for marker in ignore_markers:
            if marker in line:
                return "ignore"

        if "[ Warning ]" in line or "[ Infected ]" in line or "Warning:" in line:
            return "threat"

        if "Checking" in line or "Performing" in line:
            return "progress"

        return "ignore"

    def _run_rkhunter(self, summary, verbose, skip_slow, on_progress, on_threat):
        """Corre rkhunter via pkexec com filtragem correta de output."""
        self._check_pkexec()
        app_logger.log("rootkit", "A iniciar rkhunter via pkexec...")

        cmd = ["pkexec", "rkhunter", "--check", "--skip-keypress", "--nocolors"]
        if verbose:
            cmd.append("--verbose-logging")
        if skip_slow:
            cmd += ["--disable-tests", "suspscan"]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in self._process.stdout:
                if not self._is_running:
                    self._process.terminate()
                    break

                line = line.strip()
                if not line:
                    continue

                category = self._categorize_rkhunter_line(line)

                if category == "progress":
                    # Limpa a linha para mostrar só o que interessa
                    clean_msg = line.split("[")[0].strip()
                    if clean_msg:
                        if on_progress:
                            on_progress(f"[rkhunter] {clean_msg}")

                elif category == "threat":
                    summary["warnings"] += 1
                    summary["details"].append(("rkhunter", line))
                    app_logger.log("rootkit", f"Aviso rkhunter: {line}", logging.WARNING)
                    if on_threat:
                        on_threat(f"[rkhunter] {line.strip()}")

                # category == "ignore" → não faz nada

            self._process.wait()

            if self._process.returncode == 126:
                raise PermissionError("Autenticação cancelada pelo utilizador.")
            elif self._process.returncode == 127:
                raise PermissionError("Permissões insuficientes para executar o rkhunter.")

        except FileNotFoundError:
            raise Exception("rkhunter não encontrado no sistema.")

    def _run_chkrootkit(self, summary, on_progress, on_threat):
        """Corre chkrootkit via pkexec com filtragem correta de output."""
        self._check_pkexec()
        app_logger.log("rootkit", "A iniciar chkrootkit via pkexec...")

        cmd = ["pkexec", "chkrootkit"]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in self._process.stdout:
                if not self._is_running:
                    self._process.terminate()
                    break

                line = line.strip()
                if not line:
                    continue

                # Mostrar progresso — linha sem resultado ainda
                if "..." in line and "INFECTED" not in line.upper():
                    clean_msg = line.split("...")[0].strip()
                    if clean_msg and on_progress:
                        on_progress(f"[chkrootkit] {clean_msg}")

                # Só ameaças reais — ignora "not infected"
                if self._is_real_threat_chkrootkit(line):
                    summary["threats"] += 1
                    summary["details"].append(("chkrootkit", line))
                    app_logger.log("rootkit", f"Ameaça chkrootkit: {line}", logging.ERROR)
                    if on_threat:
                        on_threat(f"[chkrootkit] ⚠️ {line}")

            self._process.wait()

            if self._process.returncode == 126:
                raise PermissionError("Autenticação cancelada pelo utilizador.")
            elif self._process.returncode == 127:
                raise PermissionError("Permissões insuficientes para executar o chkrootkit.")

        except FileNotFoundError:
            raise Exception("chkrootkit não encontrado no sistema.")


# Instância global
scanner_rootkit = RootkitScanner()