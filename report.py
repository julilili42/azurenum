from enum import Enum, auto
from typing import Optional, List, Dict, Any, TextIO
import json
import config as cfg


class Severity(Enum):
    INFO = auto()
    LINK = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    ERROR = auto()


class NullReporter:
    def info(self, *_): pass
    def error(self, *_): pass
    def raw(self, *_): pass
    def low(self, *_): pass
    def med(self, *_): pass
    def high(self, *_): pass
    def link(self, *_): pass
    def header(self, *_): pass


class Reporter:
    def __init__(self, out_text: Optional[TextIO] = None, out_json: Optional[TextIO] = None):
        self._cfg = cfg
        self._text_lines: List[str] = []
        self._findings: List[Dict[str, Any]] = []
        self._text_path = out_text
        self._json_path = out_json

    def info(self, msg: str):  self._line(msg, Severity.INFO)
    def link(self, msg: str):  self._line(msg, Severity.LINK)
    def low(self, msg: str):   self._line(msg, Severity.LOW)
    def med(self, msg: str):   self._line(msg, Severity.MEDIUM)
    def high(self, msg: str):  self._line(msg, Severity.HIGH)
    def error(self, msg: str): self._line(msg, Severity.ERROR)

    def _line(self, msg: str, sev: Severity = Severity.INFO):
        tag = {
            Severity.INFO: f"{self._cfg.CYAN}[+]{self._cfg.NC}",
            Severity.LOW: f"{self._cfg.YELLOW}[L]{self._cfg.NC}",
            Severity.MEDIUM: f"{self._cfg.ORANGE}[M]{self._cfg.NC}",
            Severity.HIGH: f"{self._cfg.RED}[H]{self._cfg.NC}",
            Severity.LINK: f"{self._cfg.CYAN}[+]{self._cfg.NC}",
            Severity.ERROR: f"{self._cfg.RED}[-]{self._cfg.NC}",
        }[sev]
        text = f"{tag} {msg}" if sev != Severity.LINK else f"{self._cfg.CYAN}[+] {msg}{self._cfg.NC}"
        print(text)
        self._text_lines.append(text)
        if sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH) and self._json_path:
            crit = {Severity.LOW: "low", Severity.MEDIUM: "medium",
                    Severity.HIGH: "high"}[sev]
            self._findings.append({"criticality": crit, "description": msg})

    def header(self, title: str):
        self.raw("\n" + "#" * 49)
        self.raw(f"# {title}")
        self.raw("#" * 49 + "\n")

    def raw(self, msg: str):
        print(msg)
        self._text_lines.append(msg)

    def save(self):
        if self._text_path:
            self._text_path.write("\n".join(self._text_lines))
            self._text_path.close()
        if self._json_path:
            json.dump({"findings": self._findings},
                      self._json_path, ensure_ascii=False, indent=2)
            self._json_path.close()
