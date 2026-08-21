#include "tslab/engine.h"

#include "tslab/mapped_file.h"
#include "tslab/packet.h"
#include "tslab/psi.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <unordered_set>

namespace tslab {

void remap_with_tsduck(const std::string& input, const std::string& output,
                       const RemapOptions& options, const ProgressFn& progress);

namespace {

void report_progress(const ProgressFn& progress, std::uint64_t done, std::uint64_t total) {
  if (!progress || total == 0) {
    return;
  }
  int percent = static_cast<int>((done * 100) / total);
  if (percent < 0) {
    percent = 0;
  }
  if (percent > 100) {
    percent = 100;
  }
  progress(percent);
}

bool sync_at(const std::uint8_t* data, std::uint64_t size, std::uint64_t offset, std::uint16_t packet_size) {
  constexpr int kProbe = 8;
  int seen = 0;
  for (int i = 0; i < kProbe; ++i) {
    const std::uint64_t pos = offset + static_cast<std::uint64_t>(i) * packet_size;
    if (pos >= size) {
      break;
    }
    ++seen;
    if (data[pos] != kTsSyncByte) {
      return false;
    }
  }
  return seen >= 2;
}

bool detect_layout(const std::uint8_t* data, std::uint64_t size, std::uint16_t& packet_size,
                   std::uint64_t& sync_offset) {
  const std::uint16_t candidates[] = {static_cast<std::uint16_t>(kTsPacketSize),
                                      static_cast<std::uint16_t>(kTsPacketSizeRs)};
  for (std::uint16_t candidate : candidates) {
    const std::uint64_t limit = std::min<std::uint64_t>(size, candidate);
    for (std::uint64_t offset = 0; offset < limit; ++offset) {
      if (sync_at(data, size, offset, candidate)) {
        packet_size = candidate;
        sync_offset = offset;
        return true;
      }
    }
  }
  return false;
}

const char* reserved_pid_label(std::uint16_t pid) {
  switch (pid) {
    case kPatPid:
      return "PAT";
    case kCatPid:
      return "CAT";
    case 0x0002:
      return "TSDT";
    case 0x0011:
      return "SDT/BAT";
    case 0x0012:
      return "EIT";
    case 0x0014:
      return "TDT/TOT";
    case kNullPid:
      return "NULL";
    default:
      return nullptr;
  }
}

std::size_t table_id_offset(const std::uint8_t* packet, std::size_t packet_size) {
  if (!payload_unit_start(packet)) {
    return packet_size;
  }
  const std::size_t offset = payload_offset(packet, packet_size);
  if (offset >= packet_size) {
    return packet_size;
  }
  const std::uint8_t pointer = packet[offset];
  const std::size_t start = offset + 1 + pointer;
  return start < packet_size ? start : packet_size;
}

bool payload_contains(const std::uint8_t* packet, std::size_t packet_size,
                      const std::vector<std::uint8_t>& needle) {
  if (needle.empty()) {
    return true;
  }
  const std::size_t offset = payload_offset(packet, packet_size);
  if (offset >= packet_size) {
    return false;
  }
  const std::uint8_t* begin = packet + offset;
  const std::uint8_t* end = packet + packet_size;
  return std::search(begin, end, needle.begin(), needle.end()) != end;
}

class FileCloser {
 public:
  explicit FileCloser(std::FILE* file) : file_(file) {}
  ~FileCloser() {
    if (file_ != nullptr) {
      std::fclose(file_);
    }
  }
  FileCloser(const FileCloser&) = delete;
  FileCloser& operator=(const FileCloser&) = delete;

 private:
  std::FILE* file_;
};

}  // namespace

class TransportStream::Impl {
 public:
  MappedFile file;
  FileInfo info;
  std::vector<PidStats> pids;
  std::unordered_set<std::uint16_t> pmt_pids;

  const std::uint8_t* packet_ptr(std::uint64_t index) const {
    if (!file.is_open()) {
      throw std::runtime_error("Nenhum arquivo TS aberto");
    }
    if (index >= info.packet_count) {
      throw std::runtime_error("Índice de pacote fora do intervalo");
    }
    return file.data() + info.sync_offset + index * info.packet_size;
  }
};

TransportStream::TransportStream() : impl_(std::make_unique<Impl>()) {}

TransportStream::~TransportStream() = default;

void TransportStream::open(const std::string& path) {
  impl_->file.open(path);
  impl_->pids.clear();
  impl_->pmt_pids.clear();
  impl_->info = {};
  impl_->info.path = path;
  impl_->info.size = impl_->file.size();

  if (impl_->file.size() < kTsPacketSize * 2) {
    throw std::runtime_error("Arquivo pequeno demais para ser um MPEG-TS");
  }
  if (!detect_layout(impl_->file.data(), impl_->file.size(), impl_->info.packet_size,
                     impl_->info.sync_offset)) {
    throw std::runtime_error("Sincronismo MPEG-TS (0x47) não encontrado");
  }
  impl_->info.packet_count =
      (impl_->file.size() - impl_->info.sync_offset) / impl_->info.packet_size;
}

void TransportStream::close() {
  impl_->file.close();
  impl_->pids.clear();
  impl_->pmt_pids.clear();
  impl_->info = {};
}

bool TransportStream::is_open() const { return impl_->file.is_open(); }

const FileInfo& TransportStream::info() const { return impl_->info; }

const std::vector<PidStats>& TransportStream::last_scan() const { return impl_->pids; }

std::vector<PidStats> TransportStream::scan(const ProgressFn& progress) {
  if (!is_open()) {
    throw std::runtime_error("Nenhum arquivo TS aberto");
  }
  impl_->file.advise_sequential();

  std::array<PidStats, 8192> table {};
  std::array<std::int16_t, 8192> last_cc {};
  last_cc.fill(-1);
  std::array<bool, 8192> seen {};
  std::vector<ProgramMap> programs;
  std::vector<PmtInfo> pmts;

  const std::uint16_t packet_size = impl_->info.packet_size;
  const std::uint64_t count = impl_->info.packet_count;
  int last_percent = -1;

  for (std::uint64_t i = 0; i < count; ++i) {
    const std::uint8_t* pkt = impl_->packet_ptr(i);
    if (!has_sync(pkt)) {
      continue;
    }
    const std::uint16_t pid = pid_of(pkt);
    PidStats& stats = table[pid];
    if (!seen[pid]) {
      seen[pid] = true;
      stats.pid = pid;
      stats.first_index = i;
    }
    stats.packets += 1;
    stats.last_index = i;
    if (payload_unit_start(pkt)) {
      stats.pusi += 1;
    }
    if (transport_error(pkt)) {
      stats.tei += 1;
    }
    if (scrambling(pkt) != 0) {
      stats.scrambled += 1;
    }
    if (has_payload(pkt)) {
      const std::uint8_t cc = continuity_counter(pkt);
      if (last_cc[pid] >= 0) {
        const std::uint8_t expected = static_cast<std::uint8_t>((last_cc[pid] + 1) & 0x0F);
        if (cc != expected && cc != last_cc[pid]) {
          stats.cc_errors += 1;
        }
      }
      last_cc[pid] = cc;
    }
    if (pid == kPatPid && payload_unit_start(pkt)) {
      parse_pat_packet(pkt, packet_size, programs);
    }
    if (payload_unit_start(pkt)) {
      PmtInfo pmt;
      if (parse_pmt_packet(pkt, packet_size, pmt)) {
        pmts.push_back(pmt);
      }
    }
    if (progress) {
      const int percent = count == 0 ? 100 : static_cast<int>((i * 100) / count);
      if (percent != last_percent) {
        last_percent = percent;
        progress(percent);
      }
    }
  }

  impl_->pmt_pids.clear();
  for (const auto& program : programs) {
    if (program.program_number != 0) {
      impl_->pmt_pids.insert(program.pmt_pid);
      table[program.pmt_pid].type_label = "PMT";
    } else {
      table[program.pmt_pid].type_label = "NIT";
    }
  }
  for (const auto& pmt : pmts) {
    if (pmt.pcr_pid <= kMaxPid && table[pmt.pcr_pid].type_label.empty()) {
      table[pmt.pcr_pid].pcr_pid = pmt.pcr_pid;
      table[pmt.pcr_pid].type_label = "PCR";
    }
    for (const auto& es : pmt.streams) {
      auto& stats = table[es.elementary_pid];
      stats.stream_type = es.stream_type;
      stats.pcr_pid = pmt.pcr_pid;
      stats.type_label = stream_type_label(es.stream_type);
    }
  }
  for (std::uint16_t pid = 0; pid <= kMaxPid; ++pid) {
    if (!seen[pid]) {
      continue;
    }
    if (table[pid].type_label.empty()) {
      if (const char* label = reserved_pid_label(pid)) {
        table[pid].type_label = label;
      } else {
        table[pid].type_label = "desconhecido";
      }
    }
  }

  std::vector<PidStats> result;
  result.reserve(64);
  for (std::uint16_t pid = 0; pid <= kMaxPid; ++pid) {
    if (seen[pid]) {
      result.push_back(table[pid]);
    }
  }
  impl_->pids = result;
  if (progress) {
    progress(100);
  }
  return result;
}

std::vector<std::uint8_t> TransportStream::read_packet(std::uint64_t index) const {
  const std::uint8_t* pkt = impl_->packet_ptr(index);
  return {pkt, pkt + impl_->info.packet_size};
}

std::vector<SearchHit> TransportStream::search(const SearchQuery& query,
                                               const ProgressFn& progress) const {
  if (!is_open()) {
    throw std::runtime_error("Nenhum arquivo TS aberto");
  }
  impl_->file.advise_sequential();
  std::vector<SearchHit> hits;
  const std::uint64_t count = impl_->info.packet_count;
  const std::uint16_t packet_size = impl_->info.packet_size;
  const std::uint64_t start = std::min(query.start_packet, count);
  int last_percent = -1;

  for (std::uint64_t i = start; i < count; ++i) {
    const std::uint8_t* pkt = impl_->packet_ptr(i);
    if (!has_sync(pkt)) {
      continue;
    }
    const std::uint16_t pid = pid_of(pkt);
    if (query.pid && pid != *query.pid) {
      continue;
    }
    if (query.table_id) {
      const std::size_t tid_at = table_id_offset(pkt, packet_size);
      if (tid_at >= packet_size || pkt[tid_at] != *query.table_id) {
        continue;
      }
    }
    if (!payload_contains(pkt, packet_size, query.payload_contains)) {
      continue;
    }
    SearchHit hit;
    hit.packet_index = i;
    hit.pid = pid;
    hit.cc = continuity_counter(pkt);
    hit.pusi = payload_unit_start(pkt);
    hits.push_back(hit);
    if (hits.size() >= query.limit) {
      break;
    }
    if (progress) {
      const int percent = count == 0 ? 100 : static_cast<int>((i * 100) / count);
      if (percent != last_percent) {
        last_percent = percent;
        progress(percent);
      }
    }
  }
  if (progress) {
    progress(100);
  }
  return hits;
}

void TransportStream::remap(const std::string& output_path, const RemapOptions& options,
                            const ProgressFn& progress) const {
  if (!is_open()) {
    throw std::runtime_error("Nenhum arquivo TS aberto");
  }
  if (options.pid_map.empty()) {
    throw std::runtime_error("Mapeamento de PIDs vazio");
  }
  for (const auto& [from, to] : options.pid_map) {
    if (from > kMaxPid || to > kMaxPid) {
      throw std::runtime_error("PID fora do intervalo 0..0x1FFF");
    }
  }
  if (options.backend == RemapBackend::Tsduck) {
    if (!tsduck_available()) {
      throw std::runtime_error("TSDuck (tsp) não encontrado no PATH");
    }
    remap_with_tsduck(impl_->info.path, output_path, options, progress);
    return;
  }

  impl_->file.advise_sequential();
  std::FILE* out = std::fopen(output_path.c_str(), "wb");
  if (out == nullptr) {
    throw std::runtime_error("Não foi possível criar o arquivo de saída: " + output_path);
  }
  FileCloser closer(out);

  std::unordered_set<std::uint16_t> pmt_pids = impl_->pmt_pids;
  const std::uint16_t packet_size = impl_->info.packet_size;
  const std::uint64_t count = impl_->info.packet_count;
  std::vector<std::uint8_t> buffer(8 * 1024 * 1024);
  std::size_t used = 0;
  int last_percent = -1;
  std::vector<std::uint8_t> packet(packet_size);

  auto flush = [&]() {
    if (used == 0) {
      return;
    }
    if (std::fwrite(buffer.data(), 1, used, out) != used) {
      throw std::runtime_error("Falha ao gravar o arquivo de saída");
    }
    used = 0;
  };

  for (std::uint64_t i = 0; i < count; ++i) {
    std::memcpy(packet.data(), impl_->packet_ptr(i), packet_size);
    std::uint8_t* pkt = packet.data();
    if (has_sync(pkt)) {
      const std::uint16_t orig_pid = pid_of(pkt);
      if (options.update_psi) {
        if (orig_pid == kPatPid) {
          std::vector<ProgramMap> programs;
          if (parse_pat_packet(pkt, packet_size, programs)) {
            for (const auto& program : programs) {
              if (program.program_number != 0) {
                pmt_pids.insert(program.pmt_pid);
              }
            }
          }
          rewrite_pat_packet(pkt, packet_size, options.pid_map);
        } else if (pmt_pids.count(orig_pid) || payload_unit_start(pkt)) {
          rewrite_pmt_packet(pkt, packet_size, options.pid_map);
        }
      }
      const auto it = options.pid_map.find(orig_pid);
      if (it != options.pid_map.end()) {
        set_pid(pkt, it->second);
      }
    }
    if (used + packet_size > buffer.size()) {
      flush();
    }
    std::memcpy(buffer.data() + used, pkt, packet_size);
    used += packet_size;
    if (progress) {
      const int percent = count == 0 ? 100 : static_cast<int>((i * 100) / count);
      if (percent != last_percent) {
        last_percent = percent;
        progress(percent);
      }
    }
  }
  flush();
  if (progress) {
    progress(100);
  }
}

}  // namespace tslab
