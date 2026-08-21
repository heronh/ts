from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from tslab._core import RemapBackend, TransportStream
from tslab.workers import parse_pid


class RemapDialog(QDialog):
    def __init__(self, parent=None, pids: list | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Remapear PIDs")
        self.resize(520, 360)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["PID origem", "PID destino"])
        self.table.horizontalHeader().setStretchLastSection(True)
        if pids:
            for stats in pids:
                if stats.pid == 0x1FFF:
                    continue
                self._add_row(f"0x{stats.pid:04X}", f"0x{stats.pid:04X}")
        if self.table.rowCount() == 0:
            self._add_row("0x0100", "0x0200")

        add_btn = QPushButton("Adicionar")
        remove_btn = QPushButton("Remover")
        add_btn.clicked.connect(lambda: self._add_row("", ""))
        remove_btn.clicked.connect(self._remove_row)

        row_btns = QHBoxLayout()
        row_btns.addWidget(add_btn)
        row_btns.addWidget(remove_btn)
        row_btns.addStretch(1)

        self.output_edit = QLineEdit()
        browse = QPushButton("…")
        browse.clicked.connect(self._browse)
        out_row = QHBoxLayout()
        out_row.addWidget(self.output_edit, 1)
        out_row.addWidget(browse)

        self.update_psi = QCheckBox("Atualizar PAT/PMT (e PCR)")
        self.update_psi.setChecked(True)

        self.backend = QComboBox()
        self.backend.addItem("Nativo (C++)", RemapBackend.Native)
        tsduck_label = "TSDuck (tsp)"
        if TransportStream.tsduck_available():
            version = TransportStream.tsduck_version()
            if version:
                tsduck_label = f"TSDuck ({version})"
        else:
            tsduck_label += " — não instalado"
        self.backend.addItem(tsduck_label, RemapBackend.Tsduck)
        if not TransportStream.tsduck_available():
            self.backend.model().item(1).setEnabled(False)

        form = QFormLayout()
        form.addRow("Arquivo de saída", out_row)
        form.addRow("Backend", self.backend)
        form.addRow("", self.update_psi)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table, 1)
        layout.addLayout(row_btns)
        layout.addLayout(form)
        layout.addWidget(buttons)

        self.pid_map: dict[int, int] = {}
        self.output_path = ""
        self.use_tsduck = False
        self.update_psi_flag = True

    def _add_row(self, src: str, dst: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(src))
        self.table.setItem(row, 1, QTableWidgetItem(dst))

    def _remove_row(self) -> None:
        row = self.table.currentRow()
        if row >= 0:
            self.table.removeRow(row)

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Salvar TS", "", "MPEG-TS (*.ts *.mpg);;Todos (*)")
        if path:
            self.output_edit.setText(path)

    def _accept(self) -> None:
        mapping: dict[int, int] = {}
        try:
            for row in range(self.table.rowCount()):
                src_item = self.table.item(row, 0)
                dst_item = self.table.item(row, 1)
                src_text = src_item.text() if src_item else ""
                dst_text = dst_item.text() if dst_item else ""
                if not src_text.strip() and not dst_text.strip():
                    continue
                src = parse_pid(src_text)
                dst = parse_pid(dst_text)
                if src is None or dst is None:
                    raise ValueError("PID vazio")
                if src == dst:
                    continue
                mapping[src] = dst
        except ValueError as exc:
            QMessageBox.warning(self, "Remapear PIDs", f"PID inválido: {exc}")
            return

        if not mapping:
            QMessageBox.warning(self, "Remapear PIDs", "Informe ao menos um par origem ≠ destino.")
            return
        output = self.output_edit.text().strip()
        if not output:
            QMessageBox.warning(self, "Remapear PIDs", "Escolha o arquivo de saída.")
            return
        if self.backend.currentData() == RemapBackend.Tsduck and not TransportStream.tsduck_available():
            QMessageBox.warning(self, "Remapear PIDs", "TSDuck (tsp) não está no PATH.")
            return

        self.pid_map = mapping
        self.output_path = output
        self.use_tsduck = self.backend.currentData() == RemapBackend.Tsduck
        self.update_psi_flag = self.update_psi.isChecked()
        self.accept()
