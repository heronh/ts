from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from tslab.ui.main_window import MainWindow


def run(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)
    app = QApplication(args)
    app.setApplicationName("TS Lab")
    app.setOrganizationName("tslab")
    window = MainWindow()
    window.show()
    if len(args) > 1 and not args[1].startswith("-"):
        from pathlib import Path

        path = Path(args[1])
        if path.is_file():
            try:
                window.ts.open(str(path))
                info = window.ts.info()
                window.packet_spin.setRange(0, max(0, int(info.packet_count) - 1))
                window.file_label.setText(str(path))
                window._start_scan()
            except Exception:
                pass
    return app.exec()
