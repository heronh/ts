#include "tslab/psi.h"

#include "tslab/crc.h"
#include "tslab/packet.h"

#include <cstring>

namespace tslab {
namespace {

std::size_t section_start(const std::uint8_t* packet, std::size_t packet_size) {
  if (!payload_unit_start(packet)) {
    return packet_size;
  }
  const std::size_t offset = payload_offset(packet, packet_size);
  if (offset >= packet_size) {
    return packet_size;
  }
  const std::uint8_t pointer = packet[offset];
  const std::size_t start = offset + 1 + pointer;
  if (start >= packet_size) {
    return packet_size;
  }
  return start;
}

bool section_fits(const std::uint8_t* packet, std::size_t packet_size, std::size_t start,
                  std::size_t& section_length) {
  if (start + 3 > packet_size) {
    return false;
  }
  section_length = static_cast<std::size_t>(((packet[start + 1] & 0x0F) << 8) | packet[start + 2]);
  const std::size_t total = 3 + section_length;
  return start + total <= packet_size;
}

void write_crc(std::uint8_t* section, std::size_t section_length) {
  const std::uint32_t crc = mpeg_crc32(section, 3 + section_length - 4);
  std::uint8_t* crc_bytes = section + 3 + section_length - 4;
  crc_bytes[0] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
  crc_bytes[1] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
  crc_bytes[2] = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
  crc_bytes[3] = static_cast<std::uint8_t>(crc & 0xFF);
}

std::uint16_t read_pid13(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>(((bytes[0] & 0x1F) << 8) | bytes[1]);
}

void write_pid13(std::uint8_t* bytes, std::uint16_t pid) {
  bytes[0] = static_cast<std::uint8_t>((bytes[0] & 0xE0) | ((pid >> 8) & 0x1F));
  bytes[1] = static_cast<std::uint8_t>(pid & 0xFF);
}

}  // namespace

bool parse_pat_packet(const std::uint8_t* packet, std::size_t packet_size,
                      std::vector<ProgramMap>& programs) {
  programs.clear();
  const std::size_t start = section_start(packet, packet_size);
  std::size_t section_length = 0;
  if (!section_fits(packet, packet_size, start, section_length)) {
    return false;
  }
  if (packet[start] != 0x00) {
    return false;
  }
  if (section_length < 9) {
    return false;
  }
  const std::uint8_t* loop = packet + start + 8;
  const std::uint8_t* crc = packet + start + 3 + section_length - 4;
  while (loop + 4 <= crc) {
    ProgramMap entry;
    entry.program_number = static_cast<std::uint16_t>((loop[0] << 8) | loop[1]);
    entry.pmt_pid = read_pid13(loop + 2);
    programs.push_back(entry);
    loop += 4;
  }
  return true;
}

bool parse_pmt_packet(const std::uint8_t* packet, std::size_t packet_size, PmtInfo& info) {
  info = {};
  const std::size_t start = section_start(packet, packet_size);
  std::size_t section_length = 0;
  if (!section_fits(packet, packet_size, start, section_length)) {
    return false;
  }
  if (packet[start] != 0x02) {
    return false;
  }
  if (section_length < 13) {
    return false;
  }
  const std::uint8_t* section = packet + start;
  info.program_number = static_cast<std::uint16_t>((section[3] << 8) | section[4]);
  info.pcr_pid = read_pid13(section + 8);
  const std::size_t program_info_length =
      static_cast<std::size_t>(((section[10] & 0x0F) << 8) | section[11]);
  const std::uint8_t* loop = section + 12 + program_info_length;
  const std::uint8_t* crc = section + 3 + section_length - 4;
  while (loop + 5 <= crc) {
    ElementaryStream es;
    es.stream_type = loop[0];
    es.elementary_pid = read_pid13(loop + 1);
    const std::size_t es_info_length = static_cast<std::size_t>(((loop[3] & 0x0F) << 8) | loop[4]);
    info.streams.push_back(es);
    loop += 5 + es_info_length;
  }
  return true;
}

bool rewrite_pat_packet(std::uint8_t* packet, std::size_t packet_size,
                        const std::unordered_map<std::uint16_t, std::uint16_t>& pid_map) {
  const std::size_t start = section_start(packet, packet_size);
  std::size_t section_length = 0;
  if (!section_fits(packet, packet_size, start, section_length) || packet[start] != 0x00) {
    return false;
  }
  bool changed = false;
  std::uint8_t* loop = packet + start + 8;
  std::uint8_t* crc = packet + start + 3 + section_length - 4;
  while (loop + 4 <= crc) {
    const std::uint16_t pid = read_pid13(loop + 2);
    const auto it = pid_map.find(pid);
    if (it != pid_map.end()) {
      write_pid13(loop + 2, it->second);
      changed = true;
    }
    loop += 4;
  }
  if (changed) {
    write_crc(packet + start, section_length);
  }
  return changed;
}

bool rewrite_pmt_packet(std::uint8_t* packet, std::size_t packet_size,
                        const std::unordered_map<std::uint16_t, std::uint16_t>& pid_map) {
  const std::size_t start = section_start(packet, packet_size);
  std::size_t section_length = 0;
  if (!section_fits(packet, packet_size, start, section_length) || packet[start] != 0x02) {
    return false;
  }
  bool changed = false;
  std::uint8_t* section = packet + start;
  const std::uint16_t pcr_pid = read_pid13(section + 8);
  const auto pcr_it = pid_map.find(pcr_pid);
  if (pcr_it != pid_map.end()) {
    write_pid13(section + 8, pcr_it->second);
    changed = true;
  }
  const std::size_t program_info_length =
      static_cast<std::size_t>(((section[10] & 0x0F) << 8) | section[11]);
  std::uint8_t* loop = section + 12 + program_info_length;
  std::uint8_t* crc = section + 3 + section_length - 4;
  while (loop + 5 <= crc) {
    const std::uint16_t pid = read_pid13(loop + 1);
    const auto it = pid_map.find(pid);
    if (it != pid_map.end()) {
      write_pid13(loop + 1, it->second);
      changed = true;
    }
    const std::size_t es_info_length = static_cast<std::size_t>(((loop[3] & 0x0F) << 8) | loop[4]);
    loop += 5 + es_info_length;
  }
  if (changed) {
    write_crc(section, section_length);
  }
  return changed;
}

const char* stream_type_label(std::uint8_t stream_type) {
  switch (stream_type) {
    case 0x01:
      return "MPEG-1 Video";
    case 0x02:
      return "MPEG-2 Video";
    case 0x03:
      return "MPEG-1 Audio";
    case 0x04:
      return "MPEG-2 Audio";
    case 0x06:
      return "PES privado";
    case 0x0F:
      return "AAC ADTS";
    case 0x11:
      return "AAC LATM";
    case 0x1B:
      return "H.264";
    case 0x24:
      return "HEVC";
    case 0x42:
      return "AVS";
    case 0x86:
      return "SCTE-35";
    default:
      return "ES";
  }
}

}  // namespace tslab
