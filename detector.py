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
    "mcafee": "McAfee",
    "kaspersky": "Kaspersky",
    "bitdefender": "Bitdefender",
    "eset": "ESET",
    "nod32": "ESET",
    "avira": "Avira",
    "malwarebytes": "Malwarebytes",
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

DEFENDER_AND_WINDOWS_EXCLUSIONS = {
    "msmpeng.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "microsoftdefender.exe",
    "windowsdefender.exe",
    "nisserv.exe",
    "mpssvc.exe",
    "smartscreen.exe",
    "windefend.exe",
    "sihost.exe",
    "svchost.exe",
    "explorer.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "dwm.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
}

DEFENDER_TEXT_MARKERS = {
    "microsoft defender",
    "windows defender",
    "securityhealthservice",
    "msmpeng",
    "windows security",
    "windefend",
}

WINDOWS_SYSTEM_DIR_MARKERS = {
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
}


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
    def __init__(self, settings_store, logger):
        self.settings_store = settings_store
        self.logger = logger

    def analyze_process(self, process_info: dict[str, Any]) -> DetectionResult:
        safe_info = self._normalize_process_info(process_info)

        try:
            if self._is_excluded_process(safe_info):
                return DetectionResult(
                    detected=False,
                    antivirus_name="",
                    confidence=LOW_CONFIDENCE,
                    score=0,
                    reason="Proces systemowy Windows lub Microsoft Defender został zignorowany.",
                    process_info=safe_info,
                )

            score = 0
            reasons: list[str] = []

            matched_av_names = self._find_antivirus_names(safe_info)
            installer_matches = self._find_installer_keywords(safe_info)

            if matched_av_names:
                score += 55
                reasons.append("wykryto nazwę znanego antywirusa: " + ", ".join(matched_av_names))

            if installer_matches:
                score += 35
                reasons.append("wykryto słowo sugerujące instalator: " + ", ".join(installer_matches))

            if self._looks_like_download_or_temp_installer(safe_info):
                score += 10
                reasons.append("plik wygląda na uruchomiony z katalogu pobierania lub tymczasowego")

            detected = bool(matched_av_names and installer_matches)

            if not detected:
                return DetectionResult(
                    detected=False,
                    antivirus_name="",
                    confidence=LOW_CONFIDENCE,
                    score=min(score, 40),
                    reason=(
                        "Brak wystarczającego związku z instalatorem antywirusa. "
                        "Samo setup.exe/install.exe nie wystarcza do alertu."
                    ),
                    process_info=safe_info,
                )

            antivirus_name = matched_av_names[0]
            confidence = self._confidence_from_score(score)

            return DetectionResult(
                detected=True,
                antivirus_name=antivirus_name,
                confidence=confidence,
                score=score,
                reason="; ".join(reasons),
                process_info=safe_info,
            )

        except Exception:
            self.logger.exception("Błąd podczas analizy nowego procesu")
            return DetectionResult(
                detected=False,
                antivirus_name="",
                confidence=LOW_CONFIDENCE,
                score=0,
                reason="Błąd analizy procesu. Szczegóły zapisano w logu.",
                process_info=safe_info,
            )

    def _normalize_process_info(self, process_info: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(process_info, dict):
            process_info = {}

        process_id = process_info.get("pid") or process_info.get("process_id") or ""
        process_name = process_info.get("name") or process_info.get("process_name") or ""
        exe_path = process_info.get("exe_path") or process_info.get("executable_path") or ""
        command_line = process_info.get("command_line") or ""

        return {
            "pid": process_id,
            "process_name": str(process_name or ""),
            "exe_path": str(exe_path or ""),
            "command_line": str(command_line or ""),
        }

    def _is_excluded_process(self, process_info: dict[str, Any]) -> bool:
        process_name = process_info["process_name"].strip().lower()
        exe_path = process_info["exe_path"].strip().lower()
        command_line = process_info["command_line"].strip().lower()
        combined = f"{process_name} {exe_path} {command_line}"

        if process_name in DEFENDER_AND_WINDOWS_EXCLUSIONS:
            return True

        if any(marker in combined for marker in DEFENDER_TEXT_MARKERS):
            return True

        if process_name and any(marker in exe_path for marker in WINDOWS_SYSTEM_DIR_MARKERS):
            if process_name in DEFENDER_AND_WINDOWS_EXCLUSIONS:
                return True

        return False

    def _find_antivirus_names(self, process_info: dict[str, Any]) -> list[str]:
        haystack = self._combined_text(process_info)
        found: list[str] = []

        for marker, display_name in KNOWN_ANTIVIRUSES.items():
            if marker in haystack and display_name not in found:
                found.append(display_name)

        return found

    def _find_installer_keywords(self, process_info: dict[str, Any]) -> list[str]:
        haystack = self._combined_text(process_info)
        found: list[str] = []

        for keyword in INSTALLER_KEYWORDS:
            if keyword in haystack:
                found.append(keyword)

        return sorted(found)

    def _looks_like_download_or_temp_installer(self, process_info: dict[str, Any]) -> bool:
        exe_path = process_info["exe_path"].strip().lower()
        command_line = process_info["command_line"].strip().lower()
        text = f"{exe_path} {command_line}"

        markers = [
            "\\downloads\\",
            "\\pobrane\\",
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
        ]

        return any(marker in text for marker in markers)

    def _combined_text(self, process_info: dict[str, Any]) -> str:
        process_name = process_info["process_name"].lower()
        exe_path = process_info["exe_path"].lower()
        command_line = process_info["command_line"].lower()
        file_stem = ""

        if exe_path:
            try:
                file_stem = Path(exe_path).stem.lower()
            except Exception:
                file_stem = ""

        return f"{process_name} {exe_path} {command_line} {file_stem}"

    def _confidence_from_score(self, score: int) -> str:
        if score >= 85:
            return HIGH_CONFIDENCE
        if score >= 60:
            return MEDIUM_CONFIDENCE
        return LOW_CONFIDENCE
