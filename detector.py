from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CONFIDENCE_LOW_MIN = 25
CONFIDENCE_MEDIUM_MIN = 55
CONFIDENCE_HIGH_MIN = 80

INSTALLER_WORDS = (
    "setup",
    "installer",
    "install",
    "instalator",
    "installation",
    "onlineinstall",
    "webinstall",
    "onlineinstaller",
    "webinstaller",
    "downloadmanager",
)

ANTIVIRUS_SIGNATURES = {
    "Avast": ("avast",),
    "AVG": ("avg",),
    "Norton": ("norton", "symantec"),
    "McAfee": ("mcafee",),
    "Kaspersky": ("kaspersky", "kav", "kisa"),
    "Bitdefender": ("bitdefender",),
    "ESET": ("eset", "nod32", "eav"),
    "Avira": ("avira",),
    "Malwarebytes": ("malwarebytes", "mbam"),
    "Panda": ("panda",),
    "Sophos": ("sophos",),
    "Trend Micro": ("trend micro", "trendmicro", "titanium"),
    "F-Secure": ("f-secure", "fsecure"),
    "G Data": ("g data", "gdata"),
    "Comodo": ("comodo",),
}

DEFENDER_WORDS = (
    "microsoft defender",
    "windows defender",
    "securityhealthservice",
    "securityhealthservice.exe",
    "securityhealthsystray",
    "securityhealthsystray.exe",
    "msmpeng.exe",
    "msmpeng",
    "mpcmdrun.exe",
    "nissrv.exe",
    "defender",
    "windefend",
    "windows security",
)

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
    "fontdrvhost.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "conhost.exe",
    "dllhost.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "wudfhost.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
    "smartscreen.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "msmpeng.exe",
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
    confidence: int
    confidence_level: str
    reason: str
    process_info: dict[str, Any] = field(default_factory=dict)

    @property
    def should_alert(self) -> bool:
        return self.detected and self.confidence >= CONFIDENCE_MEDIUM_MIN


class AntivirusInstallerDetector:
    def __init__(self, settings_store=None, logger=None):
        self.settings_store = settings_store
        self.logger = logger

    def analyze_process(self, process_info: dict[str, Any] | None) -> DetectionResult:
        safe_info = self._normalize_process_info(process_info)

        try:
            if self._is_ignored_process(safe_info):
                return DetectionResult(
                    detected=False,
                    antivirus_name="",
                    confidence=0,
                    confidence_level="brak",
                    reason="Proces systemowy albo Microsoft Defender został zignorowany.",
                    process_info=safe_info,
                )

            text = self._build_search_text(safe_info)
            installer_hits = self._find_installer_words(text)
            av_name, av_hits = self._find_antivirus_signature(text)

            if not av_name:
                return DetectionResult(
                    detected=False,
                    antivirus_name="",
                    confidence=0,
                    confidence_level="brak",
                    reason="Brak powiązania procesu ze znanym antywirusem. Sam setup.exe nie wystarcza do alertu.",
                    process_info=safe_info,
                )

            confidence = self._calculate_confidence(safe_info, installer_hits, av_hits)
            confidence_level = self._confidence_level(confidence)
            detected = confidence >= CONFIDENCE_LOW_MIN

            if not installer_hits:
                reason = (
                    f"Znaleziono nazwę antywirusa {av_name}, ale brak cech instalatora. "
                    "Alert nie zostanie pokazany bez średniej albo wysokiej pewności."
                )
            else:
                reason = (
                    f"Proces wygląda na instalator antywirusa {av_name}. "
                    f"Trafienia AV: {', '.join(av_hits)}. "
                    f"Trafienia instalatora: {', '.join(installer_hits)}."
                )

            return DetectionResult(
                detected=detected,
                antivirus_name=av_name,
                confidence=confidence,
                confidence_level=confidence_level,
                reason=reason,
                process_info=safe_info,
            )

        except Exception as error:
            if self.logger:
                self.logger.exception("Błąd podczas analizy procesu przez detector.py")

            return DetectionResult(
                detected=False,
                antivirus_name="",
                confidence=0,
                confidence_level="brak",
                reason=f"Błąd detekcji: {error}",
                process_info=safe_info,
            )

    def _normalize_process_info(self, process_info: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(process_info, dict):
            process_info = {}

        pid = process_info.get("pid", process_info.get("process_id", ""))
        name = process_info.get("name", process_info.get("process_name", ""))
        exe_path = process_info.get("exe_path", process_info.get("executable_path", process_info.get("path", "")))
        command_line = process_info.get("command_line", "")

        return {
            "pid": pid,
            "name": str(name or ""),
            "process_name": str(name or ""),
            "exe_path": str(exe_path or ""),
            "executable_path": str(exe_path or ""),
            "command_line": str(command_line or ""),
        }

    def _is_ignored_process(self, process_info: dict[str, Any]) -> bool:
        name = process_info.get("name", "").strip().lower()
        text = self._build_search_text(process_info)

        if name in WINDOWS_SYSTEM_PROCESSES:
            return True

        if any(word in text for word in DEFENDER_WORDS):
            return True

        exe_path = process_info.get("exe_path", "").replace("/", "\\").lower()
        if any(marker in exe_path for marker in WINDOWS_SYSTEM_DIR_MARKERS) and name in WINDOWS_SYSTEM_PROCESSES:
            return True

        return False

    def _build_search_text(self, process_info: dict[str, Any]) -> str:
        parts = [
            process_info.get("name", ""),
            process_info.get("process_name", ""),
            process_info.get("exe_path", ""),
            process_info.get("executable_path", ""),
            process_info.get("command_line", ""),
        ]

        exe_path = str(process_info.get("exe_path", ""))
        if exe_path:
            try:
                parts.append(Path(exe_path).name)
                parts.append(Path(exe_path).stem)
            except Exception:
                pass

        return " ".join(str(part or "") for part in parts).replace("/", "\\").lower()

    def _find_installer_words(self, text: str) -> list[str]:
        return [word for word in INSTALLER_WORDS if word in text]

    def _find_antivirus_signature(self, text: str) -> tuple[str, list[str]]:
        best_name = ""
        best_hits: list[str] = []

        for antivirus_name, keywords in ANTIVIRUS_SIGNATURES.items():
            hits = [keyword for keyword in keywords if keyword in text]
            if len(hits) > len(best_hits):
                best_name = antivirus_name
                best_hits = hits

        return best_name, best_hits

    def _calculate_confidence(
        self,
        process_info: dict[str, Any],
        installer_hits: list[str],
        av_hits: list[str],
    ) -> int:
        name = process_info.get("name", "").lower()
        exe_path = process_info.get("exe_path", "").replace("/", "\\").lower()
        command_line = process_info.get("command_line", "").lower()
        file_name = Path(exe_path).name.lower() if exe_path else name

        if file_name in ("setup.exe", "install.exe", "installer.exe") and not av_hits:
            return 0

        score = 0

        if av_hits:
            score += 40

        if installer_hits:
            score += 30

        if any(hit in file_name for hit in av_hits):
            score += 15

        if any(word in file_name for word in INSTALLER_WORDS):
            score += 10

        if any(hit in command_line for hit in av_hits):
            score += 10

        if any(word in command_line for word in INSTALLER_WORDS):
            score += 5

        if any(folder in exe_path for folder in ("\\downloads\\", "\\pobrane\\", "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\")):
            score += 5

        if av_hits and not installer_hits:
            score = min(score, 45)

        return max(0, min(score, 100))

    def _confidence_level(self, confidence: int) -> str:
        if confidence >= CONFIDENCE_HIGH_MIN:
            return "wysoka"
        if confidence >= CONFIDENCE_MEDIUM_MIN:
            return "średnia"
        if confidence >= CONFIDENCE_LOW_MIN:
            return "niska"
        return "brak"
