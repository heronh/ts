from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tslab._core import RemapBackend, TransportStream


def _parse_pid(value: str) -> int:
    return int(value, 0)


def _parse_map(values: list[str]) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for item in values:
        if "=" not in item:
            raise argparse.ArgumentTypeError(f"Mapeamento inválido: {item} (use 0x100=0x200)")
        src, dst = item.split("=", 1)
        mapping[_parse_pid(src)] = _parse_pid(dst)
    return mapping


def _print_pids(pids) -> None:
    print(f"{'PID':>6}  {'hex':>6}  {'pacotes':>10}  {'%':>6}  {'CC err':>7}  tipo")
    total = sum(p.packets for p in pids) or 1
    for stats in pids:
        pct = 100.0 * stats.packets / total
        print(
            f"{stats.pid:6d}  0x{stats.pid:04X}  {stats.packets:10d}  {pct:5.1f}%  "
            f"{stats.cc_errors:7d}  {stats.type_label}"
        )


def cmd_scan(path: Path) -> int:
    ts = TransportStream()
    ts.open(str(path))
    info = ts.info()
    print(f"arquivo: {info.path}")
    print(f"tamanho: {info.size} bytes")
    print(f"pacote:  {info.packet_size} bytes  sync_offset={info.sync_offset}")
    print(f"pacotes: {info.packet_count}")
    print(f"TSDuck:  {TransportStream.tsduck_version() or 'não encontrado'}")
    pids = ts.scan()
    _print_pids(pids)
    return 0


def cmd_search(path: Path, pid: int | None, table_id: int | None, payload: bytes, limit: int) -> int:
    ts = TransportStream()
    ts.open(str(path))
    hits = ts.search(pid=pid, table_id=table_id, payload=payload, limit=limit)
    print(f"{len(hits)} resultado(s)")
    for hit in hits:
        pusi = "PUSI" if hit.pusi else "    "
        print(f"  pkt {hit.packet_index:10d}  PID 0x{hit.pid:04X}  CC {hit.cc:2d}  {pusi}")
    return 0


def cmd_remap(path: Path, output: Path, mapping: dict[int, int], update_psi: bool, use_tsduck: bool) -> int:
    ts = TransportStream()
    ts.open(str(path))
    backend = RemapBackend.Tsduck if use_tsduck else RemapBackend.Native
    ts.remap(str(output), mapping, update_psi=update_psi, backend=backend)
    print(f"gravado: {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tslab", description="Analisador MPEG-TS (CLI)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Listar PIDs e estatísticas")
    scan.add_argument("arquivo")

    info = sub.add_parser("info", help="Alias de scan")
    info.add_argument("arquivo")

    search = sub.add_parser("search", help="Buscar pacotes")
    search.add_argument("arquivo")
    search.add_argument("--pid", type=_parse_pid)
    search.add_argument("--table-id", type=_parse_pid)
    search.add_argument("--payload-hex", default="", help="Sequência hex no payload, ex: 47aabb")
    search.add_argument("--limit", type=int, default=32)

    remap = sub.add_parser("remap", help="Reescrever PIDs em um arquivo novo")
    remap.add_argument("arquivo")
    remap.add_argument("saida")
    remap.add_argument("--map", nargs="+", required=True, help="Pares from=to, ex: 0x100=0x200")
    remap.add_argument("--no-psi", action="store_true", help="Não atualizar PAT/PMT")
    remap.add_argument("--tsduck", action="store_true", help="Usar tsp (TSDuck) se disponível")

    args = parser.parse_args(argv)
    try:
        if args.cmd in {"scan", "info"}:
            return cmd_scan(Path(args.arquivo))
        if args.cmd == "search":
            payload = bytes.fromhex(args.payload_hex) if args.payload_hex else b""
            return cmd_search(Path(args.arquivo), args.pid, args.table_id, payload, args.limit)
        if args.cmd == "remap":
            return cmd_remap(
                Path(args.arquivo),
                Path(args.saida),
                _parse_map(args.map),
                update_psi=not args.no_psi,
                use_tsduck=args.tsduck,
            )
    except Exception as exc:  # noqa: BLE001 - CLI surface
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    return 0
