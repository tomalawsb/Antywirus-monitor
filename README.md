# Antywirus Monitor

Lekki edukacyjny monitor uruchamiania instalatorów antywirusów dla Windows.

## Aktualny etap

Projekt zawiera działający szkielet aplikacji PySide6 działającej w zasobniku systemowym oraz moduł `process_watcher.py` oparty o WMI `Win32_ProcessStartTrace`.

Program nie skanuje cyklicznie wszystkich procesów. Reaguje na zdarzenie uruchomienia nowego procesu zgłaszane przez Windows.

## Wymagania

- Windows
- Python 3.10+
- PySide6
- WMI
- pywin32

## Instalacja

```bash
pip install -r requirements.txt
```

## Uruchomienie

```bash
python main.py
```

## Struktura

```text
main.py
app_context.py
process_watcher.py
detector.py
tray.py
alert_dialog.py
settings_dialog.py
settings_store.py
logger_setup.py
resources.py
requirements.txt
```
