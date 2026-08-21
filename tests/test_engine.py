from __future__ import annotations

from pathlib import Path

import pytest

from tests.ts_factory import build_sample_ts
from tslab._core import RemapBackend, TransportStream


@pytest.fixture()
def sample_ts(tmp_path: Path) -> Path:
    path = tmp_path / "sample.ts"
    path.write_bytes(build_sample_ts())
    return path


def _by_pid(pids) -> dict[int, object]:
    return {stats.pid: stats for stats in pids}


def test_scan_identifies_pat_pmt_and_elementary_streams(sample_ts: Path) -> None:
    ts = TransportStream()
    ts.open(str(sample_ts))
    info = ts.info()
    assert info.packet_size == 188
    assert info.packet_count > 10
    pids = _by_pid(ts.scan())
    assert 0x0000 in pids
    assert pids[0x0000].type_label == "PAT"
    assert pids[0x1000].type_label == "PMT"
    assert pids[0x0100].type_label == "H.264"
    assert pids[0x0101].type_label == "AAC ADTS"
    assert pids[0x1FFF].type_label == "NULL"
    assert pids[0x0100].packets == 20
    packet = bytes(ts.read_packet(pids[0x0100].first_index))
    assert packet[0] == 0x47
    assert ((packet[1] & 0x1F) << 8 | packet[2]) == 0x0100


def test_search_by_pid_and_payload(sample_ts: Path) -> None:
    ts = TransportStream()
    ts.open(str(sample_ts))
    hits = ts.search(pid=0x0100, payload=b"VIDEO-0003")
    assert len(hits) == 1
    hits_all = ts.search(pid=0x0100, limit=100)
    assert len(hits_all) == 20
    pat = ts.search(table_id=0x00)
    assert pat
    assert pat[0].pid == 0


def test_native_remap_updates_header_and_pmt(sample_ts: Path, tmp_path: Path) -> None:
    ts = TransportStream()
    ts.open(str(sample_ts))
    ts.scan()
    output = tmp_path / "remapped.ts"
    ts.remap(str(output), {0x0100: 0x0200}, update_psi=True, backend=RemapBackend.Native)

    out = TransportStream()
    out.open(str(output))
    pids = _by_pid(out.scan())
    assert 0x0100 not in pids
    assert 0x0200 in pids
    assert pids[0x0200].packets == 20
    assert pids[0x0200].type_label == "H.264"
    assert pids[0x0101].type_label == "AAC ADTS"

    hits = out.search(pid=0x0200, payload=b"VIDEO-0000")
    assert len(hits) == 1


def test_open_rejects_non_ts(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a transport stream" * 20)
    ts = TransportStream()
    with pytest.raises(RuntimeError, match="Sincronismo"):
        ts.open(str(junk))
