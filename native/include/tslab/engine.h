#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tslab {

using ProgressFn = std::function<void(int percent)>;

struct FileInfo {
  std::string path;
  std::uint64_t size = 0;
  std::uint16_t packet_size = 188;
  std::uint64_t sync_offset = 0;
  std::uint64_t packet_count = 0;
};

struct PidStats {
  std::uint16_t pid = 0;
  std::uint64_t packets = 0;
  std::uint64_t pusi = 0;
  std::uint64_t cc_errors = 0;
  std::uint64_t tei = 0;
  std::uint64_t scrambled = 0;
  std::uint64_t first_index = 0;
  std::uint64_t last_index = 0;
  std::uint8_t stream_type = 0;
  std::uint16_t pcr_pid = 0;
  std::string type_label;
};

struct SearchQuery {
  std::optional<std::uint16_t> pid;
  std::optional<std::uint8_t> table_id;
  std::vector<std::uint8_t> payload_contains;
  std::uint64_t start_packet = 0;
  std::uint32_t limit = 256;
};

struct SearchHit {
  std::uint64_t packet_index = 0;
  std::uint16_t pid = 0;
  std::uint8_t cc = 0;
  bool pusi = false;
};

enum class RemapBackend { Native, Tsduck };

struct RemapOptions {
  std::unordered_map<std::uint16_t, std::uint16_t> pid_map;
  bool update_psi = true;
  RemapBackend backend = RemapBackend::Native;
};

class TransportStream {
 public:
  TransportStream();
  ~TransportStream();

  TransportStream(const TransportStream&) = delete;
  TransportStream& operator=(const TransportStream&) = delete;

  void open(const std::string& path);
  void close();
  bool is_open() const;

  const FileInfo& info() const;
  const std::vector<PidStats>& last_scan() const;

  std::vector<PidStats> scan(const ProgressFn& progress = {});
  std::vector<std::uint8_t> read_packet(std::uint64_t index) const;
  std::vector<SearchHit> search(const SearchQuery& query, const ProgressFn& progress = {}) const;
  void remap(const std::string& output_path, const RemapOptions& options,
             const ProgressFn& progress = {}) const;

  static bool tsduck_available();
  static std::string tsduck_version();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tslab
