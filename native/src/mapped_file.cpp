#include "tslab/mapped_file.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdexcept>
#include <utility>

namespace tslab {

MappedFile::MappedFile(MappedFile&& other) noexcept {
  *this = std::move(other);
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  close();
  fd_ = other.fd_;
  data_ = other.data_;
  size_ = other.size_;
  path_ = std::move(other.path_);
  other.fd_ = -1;
  other.data_ = nullptr;
  other.size_ = 0;
  return *this;
}

MappedFile::~MappedFile() { close(); }

void MappedFile::open(const std::string& path) {
  close();
  fd_ = ::open(path.c_str(), O_RDONLY);
  if (fd_ < 0) {
    throw std::runtime_error("Não foi possível abrir o arquivo: " + path);
  }

  struct stat st {};
  if (fstat(fd_, &st) != 0) {
    close();
    throw std::runtime_error("Não foi possível obter o tamanho de: " + path);
  }
  if (st.st_size < 0) {
    close();
    throw std::runtime_error("Tamanho de arquivo inválido: " + path);
  }
  size_ = static_cast<std::uint64_t>(st.st_size);
  if (size_ == 0) {
    path_ = path;
    return;
  }

  void* mapped = mmap(nullptr, static_cast<std::size_t>(size_), PROT_READ, MAP_PRIVATE, fd_, 0);
  if (mapped == MAP_FAILED) {
    close();
    throw std::runtime_error("mmap falhou para: " + path);
  }
  data_ = static_cast<std::uint8_t*>(mapped);
  path_ = path;
}

void MappedFile::close() noexcept {
  if (data_ != nullptr && size_ > 0) {
    munmap(data_, static_cast<std::size_t>(size_));
  }
  if (fd_ >= 0) {
    ::close(fd_);
  }
  fd_ = -1;
  data_ = nullptr;
  size_ = 0;
  path_.clear();
}

void MappedFile::advise_sequential() const {
  if (data_ != nullptr && size_ > 0) {
    madvise(data_, static_cast<std::size_t>(size_), MADV_SEQUENTIAL);
  }
}

void MappedFile::advise_random() const {
  if (data_ != nullptr && size_ > 0) {
    madvise(data_, static_cast<std::size_t>(size_), MADV_RANDOM);
  }
}

}  // namespace tslab
