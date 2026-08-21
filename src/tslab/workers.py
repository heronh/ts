from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from tslab._core import RemapBackend, TransportStream


class EngineWorker(QObject):
    """Executa scan/busca/remap fora da UI thread."""

    request_scan = Signal()
    request_search = Signal(object, object, bytes, int)
    request_remap = Signal(str, dict, bool, object)

    progress = Signal(int)
    failed = Signal(str)
    scan_done = Signal(object)
    search_done = Signal(object)
    remap_done = Signal(str)

    def __init__(self, ts: TransportStream) -> None:
        super().__init__()
        self._ts = ts
        self.request_scan.connect(self.scan)
        self.request_search.connect(self.search)
        self.request_remap.connect(self.remap)

    @Slot()
    def scan(self) -> None:
        try:
            pids = self._ts.scan(progress=self.progress.emit)
            self.scan_done.emit(pids)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))

    @Slot(object, object, bytes, int)
    def search(self, pid: int | None, table_id: int | None, payload: bytes, limit: int) -> None:
        try:
            hits = self._ts.search(
                pid=pid,
                table_id=table_id,
                payload=payload,
                limit=limit,
                progress=self.progress.emit,
            )
            self.search_done.emit(hits)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))

    @Slot(str, dict, bool, object)
    def remap(self, output_path: str, pid_map: dict, update_psi: bool, backend: RemapBackend) -> None:
        try:
            self._ts.remap(
                output_path,
                pid_map,
                update_psi=update_psi,
                backend=backend,
                progress=self.progress.emit,
            )
            self.remap_done.emit(output_path)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


def hex_dump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04X}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def parse_pid(text: str) -> int | None:
    text = text.strip()
    if not text or text.lower() in {"*", "todos", "any"}:
        return None
    return int(text, 0)
