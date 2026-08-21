from __future__ import annotations

import os

import pytest

from tests.ts_factory import build_sample_ts

pytest.importorskip("PySide6")


def test_main_window_loads_sample(tmp_path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from tslab.ui.main_window import MainWindow

    app = QApplication.instance() or QApplication(["tslab-test"])
    sample = tmp_path / "sample.ts"
    sample.write_bytes(build_sample_ts())

    window = MainWindow()
    window.ts.open(str(sample))
    pids = window.ts.scan()
    window._on_scan_done(pids)
    assert window.pid_table.rowCount() >= 4
    assert window.hex_view.toPlainText()
    window.close()
    del window
    # Keep the process-wide QApplication alive for other tests.
    assert app is not None
