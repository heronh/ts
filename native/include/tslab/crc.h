#pragma once

#include <cstddef>
#include <cstdint>

namespace tslab {

// MPEG-2 / DVB CRC-32 (polynomial 0x04C11DB7, init 0xFFFFFFFF).
std::uint32_t mpeg_crc32(const std::uint8_t* data, std::size_t length);

}  // namespace tslab
