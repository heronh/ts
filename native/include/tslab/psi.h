#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace tslab {

struct ProgramMap {
  std::uint16_t program_number = 0;
  std::uint16_t pmt_pid = 0;
};

struct ElementaryStream {
  std::uint8_t stream_type = 0;
  std::uint16_t elementary_pid = 0;
};

struct PmtInfo {
  std::uint16_t program_number = 0;
  std::uint16_t pcr_pid = 0;
  std::vector<ElementaryStream> streams;
};

bool parse_pat_packet(const std::uint8_t* packet, std::size_t packet_size, std::vector<ProgramMap>& programs);

bool parse_pmt_packet(const std::uint8_t* packet, std::size_t packet_size, PmtInfo& info);

// Rewrites PID references inside a single-packet PAT/PMT section and fixes CRC.
// Returns true if the packet payload was modified.
bool rewrite_pat_packet(std::uint8_t* packet, std::size_t packet_size,
                        const std::unordered_map<std::uint16_t, std::uint16_t>& pid_map);

bool rewrite_pmt_packet(std::uint8_t* packet, std::size_t packet_size,
                        const std::unordered_map<std::uint16_t, std::uint16_t>& pid_map);

const char* stream_type_label(std::uint8_t stream_type);

}  // namespace tslab
