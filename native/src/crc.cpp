#include "tslab/crc.h"

namespace tslab {

std::uint32_t mpeg_crc32(const std::uint8_t* data, std::size_t length) {
  std::uint32_t crc = 0xFFFFFFFFu;
  for (std::size_t i = 0; i < length; ++i) {
    crc ^= static_cast<std::uint32_t>(data[i]) << 24;
    for (int bit = 0; bit < 8; ++bit) {
      if (crc & 0x80000000u) {
        crc = (crc << 1) ^ 0x04C11DB7u;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}

}  // namespace tslab
