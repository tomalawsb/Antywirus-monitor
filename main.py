import sys
from PySide6.QtWidgets import QApplication, QMessageBox

from app_context import AppContext
from logger_setup import setup_logging, install_exception_hook
from resources import get_app_base_dir


APP_NAME = "AV Awareness Monitor"


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("AV Awareness Monitor")
    app.setQuitOnLastWindowClosed(False)

    base_dir = get_app_base_dir()
    logger = setup_logging(base_dir)
    install_exception_hook(logger)

    context = None

    try:
        context = AppContext(app=app, base_dir=base_dir, logger=logger)
        context.start()
        return app.exec()

    except Exception as error:
        logger.exception("Błąd krytyczny podczas startu programu")
        QMessageBox.critical(
            None,
            "Błąd programu",
            f"Nie udało się uruchomić programu:\n\n{error}",
        )
        return 1

    finally:
        if context is not None:
            context.shutdown()


if __name__ == "__main__":
    sys.exit(main())
