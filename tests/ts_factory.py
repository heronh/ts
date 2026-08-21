from __future__ import annotations


def mpeg_crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= (byte << 24) & 0xFFFFFFFF
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def ts_packet(pid: int, payload: bytes, cc: int = 0, pusi: bool = False) -> bytes:
    if len(payload) > 184:
        raise ValueError("payload TS maior que 184 bytes")
    packet = bytearray(188)
    packet[0] = 0x47
    packet[1] = (0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)
    packet[2] = pid & 0xFF
    packet[3] = 0x10 | (cc & 0x0F)
    packet[4 : 4 + len(payload)] = payload
    if len(payload) < 184:
        packet[4 + len(payload) :] = b"\xff" * (184 - len(payload))
    return bytes(packet)


def section_packet(pid: int, section: bytes, cc: int = 0) -> bytes:
    payload = bytes([0]) + section
    payload = payload[:184].ljust(184, b"\xff")
    return ts_packet(pid, payload, cc=cc, pusi=True)


def _finish_section(header_and_body: bytes) -> bytes:
    crc = mpeg_crc32(header_and_body)
    return header_and_body + crc.to_bytes(4, "big")


def pat_section(pmt_pid: int = 0x1000, program_number: int = 1, ts_id: int = 1) -> bytes:
    programs = program_number.to_bytes(2, "big") + (0xE000 | pmt_pid).to_bytes(2, "big")
    section_length = 5 + len(programs) + 4
    header = bytes(
        [
            0x00,
            0xB0 | ((section_length >> 8) & 0x0F),
            section_length & 0xFF,
            (ts_id >> 8) & 0xFF,
            ts_id & 0xFF,
            0xC1,
            0x00,
            0x00,
        ]
    )
    return _finish_section(header + programs)


def pmt_section(
    program_number: int = 1,
    pcr_pid: int = 0x0100,
    streams: list[tuple[int, int]] | None = None,
) -> bytes:
    if streams is None:
        streams = [(0x1B, 0x0100), (0x0F, 0x0101)]
    loop = bytearray()
    for stream_type, elementary_pid in streams:
        loop.append(stream_type)
        loop += (0xE000 | elementary_pid).to_bytes(2, "big")
        loop += (0xF000).to_bytes(2, "big")
    section_length = 9 + len(loop) + 4
    header = bytes(
        [
            0x02,
            0xB0 | ((section_length >> 8) & 0x0F),
            section_length & 0xFF,
            (program_number >> 8) & 0xFF,
            program_number & 0xFF,
            0xC1,
            0x00,
            0x00,
        ]
    )
    pcr = (0xE000 | pcr_pid).to_bytes(2, "big")
    info_len = (0xF000).to_bytes(2, "big")
    return _finish_section(header + pcr + info_len + bytes(loop))


def build_sample_ts(
    video_pid: int = 0x0100,
    audio_pid: int = 0x0101,
    pmt_pid: int = 0x1000,
    video_packets: int = 20,
    audio_packets: int = 10,
) -> bytes:
    chunks: list[bytes] = []
    chunks.append(section_packet(0x0000, pat_section(pmt_pid=pmt_pid), cc=0))
    chunks.append(
        section_packet(
            pmt_pid,
            pmt_section(pcr_pid=video_pid, streams=[(0x1B, video_pid), (0x0F, audio_pid)]),
            cc=0,
        )
    )
    for i in range(video_packets):
        payload = f"VIDEO-{i:04d}".encode().ljust(184, b"\x00")
        chunks.append(ts_packet(video_pid, payload, cc=(i + 1) & 0x0F, pusi=(i == 0)))
    for i in range(audio_packets):
        payload = f"AUDIO-{i:04d}".encode().ljust(184, b"\x00")
        chunks.append(ts_packet(audio_pid, payload, cc=(i + 1) & 0x0F, pusi=(i == 0)))
    chunks.append(ts_packet(0x1FFF, b"\xff" * 184, cc=0))
    chunks.append(section_packet(0x0000, pat_section(pmt_pid=pmt_pid), cc=1))
    return b"".join(chunks)
