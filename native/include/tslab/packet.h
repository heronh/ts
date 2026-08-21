#pragma once

#include <cstddef>
#include <cstdint>

namespace tslab {

inline constexpr std::size_t kTsPacketSize = 188;
inline constexpr std::size_t kTsPacketSizeRs = 204;
inline constexpr std::uint8_t kTsSyncByte = 0x47;
inline constexpr std::uint16_t kNullPid = 0x1FFF;
inline constexpr std::uint16_t kPatPid = 0x0000;
inline constexpr std::uint16_t kCatPid = 0x0001;
inline constexpr std::uint16_t kMaxPid = 0x1FFF;

inline bool has_sync(const std::uint8_t* packet) {
  return packet[0] == kTsSyncByte;
}

inline std::uint16_t pid_of(const std::uint8_t* packet) {
  return static_cast<std::uint16_t>(((packet[1] & 0x1F) << 8) | packet[2]);
}

inline void set_pid(std::uint8_t* packet, std::uint16_t pid) {
  packet[1] = static_cast<std::uint8_t>((packet[1] & 0xE0) | ((pid >> 8) & 0x1F));
  packet[2] = static_cast<std::uint8_t>(pid & 0xFF);
}

inline bool payload_unit_start(const std::uint8_t* packet) {
  return (packet[1] & 0x40) != 0;
}

inline bool transport_error(const std::uint8_t* packet) {
  return (packet[1] & 0x80) != 0;
}

inline std::uint8_t scrambling(const std::uint8_t* packet) {
  return static_cast<std::uint8_t>((packet[3] >> 6) & 0x03);
}

inline std::uint8_t adaptation_field_control(const std::uint8_t* packet) {
  return static_cast<std::uint8_t>((packet[3] >> 4) & 0x03);
}

inline std::uint8_t continuity_counter(const std::uint8_t* packet) {
  return static_cast<std::uint8_t>(packet[3] & 0x0F);
}

inline bool has_payload(const std::uint8_t* packet) {
  return (adaptation_field_control(packet) & 0x01) != 0;
}

inline bool has_adaptation(const std::uint8_t* packet) {
  return (adaptation_field_control(packet) & 0x02) != 0;
}

// Returns payload offset within the 188-byte packet, or 188 if none.
inline std::size_t payload_offset(const std::uint8_t* packet, std::size_t packet_size = kTsPacketSize) {
  if (!has_payload(packet)) {
    return packet_size;
  }
  std::size_t offset = 4;
  if (has_adaptation(packet)) {
    const std::uint8_t adaptation_length = packet[4];
    offset = 5 + adaptation_length;
  }
  if (offset > packet_size) {
    return packet_size;
  }
  return offset;
}

}  // namespace tslab
