from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Qt, Slot
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from tslab._core import RemapBackend, TransportStream
from tslab.ui.remap_dialog import RemapDialog
from tslab.ui.search_panel import SearchPanel
from tslab.workers import EngineWorker, format_bytes, hex_dump


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TS Lab — analisador MPEG-TS")
        self.resize(1200, 760)

        self.ts = TransportStream()
        self.pids = []
        self._thread: QThread | None = None
        self._worker: EngineWorker | None = None
        self._busy = False

        self._build_toolbar()
        self._build_central()
        self._build_status()
        self._set_busy(False)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Principal")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        open_action = QAction("Abrir…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        remap_action = QAction("Remapear PIDs…", self)
        remap_action.setShortcut("Ctrl+R")
        remap_action.triggered.connect(self.remap_pids)
        toolbar.addAction(remap_action)

        rescan_action = QAction("Analisar", self)
        rescan_action.triggered.connect(self._start_scan)
        toolbar.addAction(rescan_action)

        self._open_action = open_action
        self._remap_action = remap_action
        self._rescan_action = rescan_action

        menubar = self.menuBar()
        file_menu = menubar.addMenu("Arquivo")
        file_menu.addAction(open_action)
        file_menu.addAction(remap_action)
        file_menu.addSeparator()
        quit_action = QAction("Sair", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        analysis_menu = menubar.addMenu("Análise")
        analysis_menu.addAction(rescan_action)

        help_menu = menubar.addMenu("Ajuda")
        about = QAction("Sobre", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)

    def _build_central(self) -> None:
        self.pid_table = QTableWidget(0, 7)
        self.pid_table.setHorizontalHeaderLabels(
            ["PID", "Hex", "Pacotes", "%", "CC err", "Scrambled", "Tipo"]
        )
        self.pid_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pid_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pid_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pid_table.verticalHeader().setVisible(False)
        self.pid_table.setSortingEnabled(True)
        header = self.pid_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pid_table.itemSelectionChanged.connect(self._pid_selected)

        packet_bar = QHBoxLayout()
        packet_bar.addWidget(QLabel("Pacote"))
        self.packet_spin = QSpinBox()
        self.packet_spin.setRange(0, 0)
        self.packet_spin.valueChanged.connect(self._show_packet)
        packet_bar.addWidget(self.packet_spin)
        self.packet_meta = QLabel("—")
        packet_bar.addWidget(self.packet_meta, 1)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("monospace", 10))
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        packet_page = QWidget()
        packet_layout = QVBoxLayout(packet_page)
        packet_layout.addLayout(packet_bar)
        packet_layout.addWidget(self.hex_view, 1)

        self.analysis_view = QPlainTextEdit()
        self.analysis_view.setReadOnly(True)
        self.analysis_view.setFont(QFont("monospace", 10))

        self.search_panel = SearchPanel()
        self.search_panel.search_requested.connect(self._start_search)
        self.search_panel.hit_selected.connect(self._jump_to_packet)

        tabs = QTabWidget()
        tabs.addTab(packet_page, "Pacote")
        tabs.addTab(self.search_panel, "Pesquisa")
        tabs.addTab(self.analysis_view, "Análise")
        self.tabs = tabs

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.pid_table)
        splitter.addWidget(tabs)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.addWidget(splitter)
        self.setCentralWidget(container)

    def _build_status(self) -> None:
        status = QStatusBar()
        self.setStatusBar(status)
        self.file_label = QLabel("Nenhum arquivo aberto")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setFixedWidth(180)
        self.progress.setValue(0)
        status.addWidget(self.file_label, 1)
        status.addPermanentWidget(self.progress)

    def open_file(self) -> None:
        if self._busy:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir MPEG-TS", "", "MPEG-TS (*.ts *.mpg *.m2ts);;Todos (*)"
        )
        if not path:
            return
        try:
            self.ts.close()
            self.ts.open(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Abrir arquivo", str(exc))
            return
        info = self.ts.info()
        self.packet_spin.setRange(0, max(0, int(info.packet_count) - 1))
        self.file_label.setText(
            f"{path}  •  {format_bytes(info.size)}  •  {info.packet_count} pacotes de {info.packet_size} bytes"
        )
        self._start_scan()

    def remap_pids(self) -> None:
        if self._busy:
            return
        if not self.ts.is_open():
            QMessageBox.information(self, "Remapear PIDs", "Abra um arquivo TS primeiro.")
            return
        dialog = RemapDialog(self, self.pids)
        if dialog.exec() != RemapDialog.DialogCode.Accepted:
            return
        backend = RemapBackend.Tsduck if dialog.use_tsduck else RemapBackend.Native
        self._start_worker()
        self._set_busy(True)
        self.statusBar().showMessage("Remapeando PIDs…")
        self._worker.request_remap.emit(
            dialog.output_path, dialog.pid_map, dialog.update_psi_flag, backend
        )

    def _start_scan(self) -> None:
        if not self.ts.is_open() or self._busy:
            return
        self._start_worker()
        self._set_busy(True)
        self.statusBar().showMessage("Analisando PIDs…")
        self._worker.request_scan.emit()

    def _start_search(self, pid, table_id, payload: bytes, limit: int) -> None:
        if not self.ts.is_open() or self._busy:
            return
        self._start_worker()
        self._set_busy(True)
        self.search_panel.set_busy(True)
        self.statusBar().showMessage("Buscando…")
        self._worker.request_search.emit(pid, table_id, payload, limit)

    def _start_worker(self) -> None:
        self._stop_worker()
        self._thread = QThread(self)
        self._worker = EngineWorker(self.ts)
        self._worker.moveToThread(self._thread)
        self._worker.progress.connect(self.progress.setValue)
        self._worker.failed.connect(self._on_failed)
        self._worker.scan_done.connect(self._on_scan_done)
        self._worker.search_done.connect(self._on_search_done)
        self._worker.remap_done.connect(self._on_remap_done)
        self._thread.start()

    def _stop_worker(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
            self._thread = None
        self._worker = None

    def closeEvent(self, event) -> None:  # noqa: N802
        self._stop_worker()
        self.ts.close()
        super().closeEvent(event)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._open_action.setEnabled(not busy)
        self._remap_action.setEnabled(not busy)
        self._rescan_action.setEnabled(not busy)
        self.search_panel.set_busy(busy)
        self.pid_table.setEnabled(not busy)
        self.packet_spin.setEnabled(not busy)
        if not busy:
            self.progress.setValue(0)

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._set_busy(False)
        QMessageBox.critical(self, "TS Lab", message)

    @Slot(object)
    def _on_scan_done(self, pids) -> None:
        self.pids = list(pids)
        self._fill_pid_table()
        self._fill_analysis()
        if self.pids:
            self._jump_to_packet(int(self.pids[0].first_index))
        self._set_busy(False)
        self.statusBar().showMessage(f"{len(self.pids)} PID(s) encontrados", 4000)

    @Slot(object)
    def _on_search_done(self, hits) -> None:
        self.search_panel.show_hits(hits)
        self.tabs.setCurrentWidget(self.search_panel)
        self._set_busy(False)
        self.statusBar().showMessage(f"{len(hits)} resultado(s)", 4000)

    @Slot(str)
    def _on_remap_done(self, output_path: str) -> None:
        self._set_busy(False)
        QMessageBox.information(self, "Remapear PIDs", f"Arquivo gravado:\n{output_path}")

    def _fill_pid_table(self) -> None:
        total = sum(stats.packets for stats in self.pids) or 1
        self.pid_table.setSortingEnabled(False)
        self.pid_table.setRowCount(len(self.pids))
        for row, stats in enumerate(self.pids):
            pct = 100.0 * stats.packets / total
            values = [
                str(stats.pid),
                f"0x{stats.pid:04X}",
                str(stats.packets),
                f"{pct:.2f}",
                str(stats.cc_errors),
                str(stats.scrambled),
                stats.type_label,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in {0, 2, 4, 5}:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, int(stats.first_index))
                self.pid_table.setItem(row, column, item)
        self.pid_table.setSortingEnabled(True)

    def _fill_analysis(self) -> None:
        if not self.ts.is_open():
            return
        info = self.ts.info()
        total = sum(stats.packets for stats in self.pids) or 1
        lines = [
            f"Arquivo     : {info.path}",
            f"Tamanho     : {format_bytes(info.size)} ({info.size} bytes)",
            f"Pacote      : {info.packet_size} bytes  offset={info.sync_offset}",
            f"Pacotes     : {info.packet_count}",
            f"TSDuck      : {TransportStream.tsduck_version() or 'não encontrado (backend nativo)'}",
            "",
            "Distribuição de PIDs",
            "--------------------",
        ]
        for stats in sorted(self.pids, key=lambda item: item.packets, reverse=True):
            pct = 100.0 * stats.packets / total
            bar = "█" * int(pct / 2) + "░" * (50 - int(pct / 2))
            lines.append(
                f"PID 0x{stats.pid:04X}  {pct:6.2f}%  {bar}  {stats.type_label}  "
                f"cc_err={stats.cc_errors} tei={stats.tei}"
            )
        self.analysis_view.setPlainText("\n".join(lines))

    def _pid_selected(self) -> None:
        items = self.pid_table.selectedItems()
        if not items:
            return
        first = self.pid_table.item(items[0].row(), 0)
        if first is not None:
            index = int(first.data(Qt.ItemDataRole.UserRole))
            self._jump_to_packet(index)

    def _jump_to_packet(self, index: int) -> None:
        self.packet_spin.setValue(index)
        self._show_packet(index)
        self.tabs.setCurrentIndex(0)

    def _show_packet(self, index: int) -> None:
        if not self.ts.is_open() or index < 0:
            return
        try:
            packet = bytes(self.ts.read_packet(index))
        except Exception as exc:  # noqa: BLE001
            self.hex_view.setPlainText(str(exc))
            return
        pid = ((packet[1] & 0x1F) << 8) | packet[2] if len(packet) >= 3 else 0
        pusi = "PUSI" if len(packet) > 1 and packet[1] & 0x40 else ""
        cc = packet[3] & 0x0F if len(packet) > 3 else 0
        self.packet_meta.setText(f"PID 0x{pid:04X}   CC {cc}   {pusi}")
        self.hex_view.setPlainText(hex_dump(packet))

    def _about(self) -> None:
        tsduck = TransportStream.tsduck_version() or "não instalado"
        QMessageBox.about(
            self,
            "Sobre o TS Lab",
            "Esqueleto de analisador MPEG-TS para Linux.\n\n"
            "UI: Python / PySide6\n"
            "Núcleo: C++ (mmap, scan, busca, remap de PID)\n"
            f"Backend opcional: TSDuck (tsp) — {tsduck}\n\n"
            "Arquivos grandes são mapeados em memória; a reescrita gera um arquivo novo.",
        )
