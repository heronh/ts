from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from tslab.workers import parse_pid


class SearchPanel(QWidget):
    search_requested = Signal(object, object, bytes, int)
    hit_selected = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.pid_edit = QLineEdit()
        self.pid_edit.setPlaceholderText("PID (ex: 0x100) ou vazio = todos")
        self.table_id_edit = QLineEdit()
        self.table_id_edit.setPlaceholderText("table_id (ex: 0x00 para PAT)")
        self.payload_edit = QLineEdit()
        self.payload_edit.setPlaceholderText("hex no payload (ex: 1B)")
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(1, 100000)
        self.limit_spin.setValue(256)
        self.search_button = QPushButton("Buscar")
        self.status = QLabel("Nenhuma busca.")

        form = QFormLayout()
        form.addRow("PID", self.pid_edit)
        form.addRow("Table ID", self.table_id_edit)
        form.addRow("Payload hex", self.payload_edit)
        form.addRow("Limite", self.limit_spin)

        controls = QHBoxLayout()
        controls.addLayout(form, 1)
        controls.addWidget(self.search_button)

        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Pacote", "PID", "CC", "PUSI"])
        self.results.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results.verticalHeader().setVisible(False)
        self.results.horizontalHeader().setStretchLastSection(True)

        layout = QVBoxLayout(self)
        layout.addLayout(controls)
        layout.addWidget(self.results, 1)
        layout.addWidget(self.status)

        self.search_button.clicked.connect(self._emit_search)
        self.pid_edit.returnPressed.connect(self._emit_search)
        self.payload_edit.returnPressed.connect(self._emit_search)
        self.results.cellDoubleClicked.connect(self._select_hit)

    def _emit_search(self) -> None:
        try:
            pid = parse_pid(self.pid_edit.text())
            table_raw = self.table_id_edit.text().strip()
            table_id = int(table_raw, 0) if table_raw else None
            payload_text = self.payload_edit.text().strip().replace(" ", "")
            payload = bytes.fromhex(payload_text) if payload_text else b""
        except ValueError:
            self.status.setText("PID, table_id ou hex inválido.")
            return
        self.search_requested.emit(pid, table_id, payload, int(self.limit_spin.value()))

    def set_busy(self, busy: bool) -> None:
        self.search_button.setEnabled(not busy)

    def show_hits(self, hits) -> None:
        self.results.setRowCount(len(hits))
        for row, hit in enumerate(hits):
            self.results.setItem(row, 0, QTableWidgetItem(str(hit.packet_index)))
            self.results.setItem(row, 1, QTableWidgetItem(f"0x{hit.pid:04X}"))
            self.results.setItem(row, 2, QTableWidgetItem(str(hit.cc)))
            self.results.setItem(row, 3, QTableWidgetItem("sim" if hit.pusi else "não"))
        self.status.setText(f"{len(hits)} resultado(s)")

    def _select_hit(self, row: int, _column: int) -> None:
        item = self.results.item(row, 0)
        if item is not None:
            self.hit_selected.emit(int(item.text()))
