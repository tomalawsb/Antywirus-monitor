from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOW_CONFIDENCE = "niska"
MEDIUM_CONFIDENCE = "średnia"
HIGH_CONFIDENCE = "wysoka"
ALERT_LEVELS = {MEDIUM_CONFIDENCE, HIGH_CONFIDENCE}

KNOWN_ANTIVIRUSES = {
    "avast": "Avast",
    "avg": "AVG",
    "norton": "Norton",
    "symantec": "Norton",
    "mcafee": "McAfee",
    "kaspersky": "Kaspersky",
    "bitdefender": "Bitdefender",
    "eset": "ESET",
    "nod32": "ESET",
    "avira": "Avira",
    "malwarebytes": "Malwarebytes",
    "mbam": "Malwarebytes",
    "panda": "Panda",
    "sophos": "Sophos",
    "trend micro": "Trend Micro",
    "trendmicro": "Trend Micro",
    "f-secure": "F-Secure",
    "fsecure": "F-Secure",
    "g data": "G Data",
    "gdata": "G Data",
    "comodo": "Comodo",
}

INSTALLER_KEYWORDS = {
    "setup",
    "installer",
    "install",
    "instalator",
    "installation",
    "onlineinstaller",
    "webinstaller",
    "downloadmanager",
}

DEFENDER_MARKERS = {
    "microsoft defender",
    "windows defender",
    "securityhealthservice",
    "securityhealthservice.exe",
    "securityhealthsystray",
    "securityhealthsystray.exe",
    "msmpeng",
    "msmpeng.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "windefend",
    "windows security",
}

WINDOWS_SYSTEM_PROCESSES = {
    "system",
    "idle",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "audiodg.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
    "smartscreen.exe",
}

WINDOWS_SYSTEM_DIR_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
)


@dataclass(frozen=True)
class DetectionResult:
    detected: bool
    antivirus_name: str
    confidence: str
    score: int
    reason: str
    process_info: dict[str, Any]

    @property
    def should_alert(self) -> bool:
        return self.detected and self.confidence in ALERT_LEVELS


class AntivirusInstallerDetector:
    def __init__(self, settings_store=None, logger=None):
        self.settings_store = settings_store
        self.logger = logger

    def analyze_process(self, process_info: dict[str, Any]) -> DetectionResult:
        safe_info = self._normalize_process_info(process_info)

        try:
            if self._is_ignored_process(safe_info):
                return DetectionResult(False, "", LOW_CONFIDENCE, 0, "Proces Microsoft Defender albo zwykły proces systemowy Windows został zignorowany.", safe_info)

            av_names = self._find_antivirus_names(safe_info)
            installer_words = self._find_installer_keywords(safe_info)

            if not av_names:
                return DetectionResult(False, "", LOW_CONFIDENCE, 0, "Brak powiązania ze znanym producentem antywirusa.", safe_info)

            if not installer_words:
                return DetectionResult(False, "", LOW_CONFIDENCE, 40, "Wykryto nazwę antywirusa, ale brak cech instalatora. Sam proces nie wystarcza do alertu.", safe_info)

            score = 55
            reasons = ["wykryto nazwę znanego antywirusa: " + ", ".join(av_names)]

            score += 30
            reasons.append("wykryto słowo sugerujące instalator: " + ", ".join(installer_words))

            if self._looks_like_download_or_temp_path(safe_info):
                score += 10
                reasons.append("plik uruchomiono z katalogu pobierania albo tymczasowego")

            if safe_info.get("command_line"):
                score += 5

            score = min(score, 100)
            confidence = self._confidence_from_score(score)

            return DetectionResult(
                detected=confidence in ALERT_LEVELS,
                antivirus_name=av_names[0],
                confidence=confidence,
                score=score,
                reason="; ".join(reasons),
                process_info=safe_info,
            )

        except Exception:
            if self.logger:
                self.logger.exception("Błąd podczas analizy nowo uruchomionego procesu")
            return DetectionResult(False, "", LOW_CONFIDENCE, 0, "Błąd analizy procesu. Szczegóły zapisano w logu.", safe_info)

    def _normalize_process_info(self, process_info: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(process_info, dict):
            process_info = {}

        return {
            "pid": process_info.get("pid") or process_info.get("process_id") or "",
            "process_name": str(process_info.get("process_name") or process_info.get("name") or ""),
            "exe_path": str(process_info.get("exe_path") or process_info.get("executable_path") or process_info.get("path") or ""),
            "command_line": str(process_info.get("command_line") or ""),
        }

    def _combined_text(self, process_info: dict[str, Any]) -> str:
        parts = [process_info["process_name"], process_info["exe_path"], process_info["command_line"]]
        try:
            if process_info["exe_path"]:
                parts.append(Path(process_info["exe_path"]).stem)
        except Exception:
            pass
        return " ".join(parts).replace("/", "\\").lower()

    def _is_ignored_process(self, process_info: dict[str, Any]) -> bool:
        process_name = process_info["process_name"].strip().lower()
        exe_path = process_info["exe_path"].replace("/", "\\").strip().lower()
        text = self._combined_text(process_info)

        if process_name in WINDOWS_SYSTEM_PROCESSES:
            return True

        if any(marker in text for marker in DEFENDER_MARKERS):
            return True

        if any(marker in exe_path for marker in WINDOWS_SYSTEM_DIR_MARKERS) and process_name in WINDOWS_SYSTEM_PROCESSES:
            return True

        return False

    def _find_antivirus_names(self, process_info: dict[str, Any]) -> list[str]:
        text = self._combined_text(process_info)
        found: list[str] = []
        for marker, display_name in KNOWN_ANTIVIRUSES.items():
            if marker in text and display_name not in found:
                found.append(display_name)
        return found

    def _find_installer_keywords(self, process_info: dict[str, Any]) -> list[str]:
        text = self._combined_text(process_info)
        return sorted(keyword for keyword in INSTALLER_KEYWORDS if keyword in text)

    def _looks_like_download_or_temp_path(self, process_info: dict[str, Any]) -> bool:
        text = self._combined_text(process_info)
        return any(marker in text for marker in ("\\downloads\\", "\\pobrane\\", "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"))

    def _confidence_from_score(self, score: int) -> str:
        if score >= 85:
            return HIGH_CONFIDENCE
        if score >= 60:
            return MEDIUM_CONFIDENCE
        return LOW_CONFIDENCE
