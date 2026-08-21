"""Analisador MPEG-TS (esqueleto híbrido PySide6 + C++)."""

from tslab._core import FileInfo, PidStats, RemapBackend, SearchHit, TransportStream

__all__ = [
    "FileInfo",
    "PidStats",
    "RemapBackend",
    "SearchHit",
    "TransportStream",
]
__version__ = "0.1.0"
