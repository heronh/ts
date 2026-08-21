#pragma once

#include <cstdint>
#include <string>

namespace tslab {

class MappedFile {
 public:
  MappedFile() = default;
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;
  MappedFile(MappedFile&& other) noexcept;
  MappedFile& operator=(MappedFile&& other) noexcept;
  ~MappedFile();

  void open(const std::string& path);
  void close() noexcept;

  bool is_open() const { return data_ != nullptr; }
  const std::uint8_t* data() const { return data_; }
  std::uint64_t size() const { return size_; }
  const std::string& path() const { return path_; }

  void advise_sequential() const;
  void advise_random() const;

 private:
  int fd_ = -1;
  std::uint8_t* data_ = nullptr;
  std::uint64_t size_ = 0;
  std::string path_;
};

}  // namespace tslab
