#include "tslab/engine.h"

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace tslab {
namespace {

int run_process(const std::vector<std::string>& args, std::string& output) {
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    throw std::runtime_error("pipe() falhou ao executar TSDuck");
  }

  const pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    throw std::runtime_error("fork() falhou ao executar TSDuck");
  }

  if (pid == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
      argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);
    execvp(argv[0], argv.data());
    _exit(127);
  }

  close(pipefd[1]);
  std::array<char, 4096> buf {};
  while (true) {
    const ssize_t n = read(pipefd[0], buf.data(), buf.size());
    if (n > 0) {
      output.append(buf.data(), static_cast<std::size_t>(n));
      continue;
    }
    if (n == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(pipefd[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
}

std::string first_line(const std::string& text) {
  const auto pos = text.find('\n');
  return pos == std::string::npos ? text : text.substr(0, pos);
}

}  // namespace

bool TransportStream::tsduck_available() {
  std::string output;
  const int code = run_process({"tsp", "--version"}, output);
  return code == 0;
}

std::string TransportStream::tsduck_version() {
  std::string output;
  const int code = run_process({"tsp", "--version"}, output);
  if (code != 0) {
    return {};
  }
  return first_line(output);
}

void remap_with_tsduck(const std::string& input, const std::string& output,
                       const RemapOptions& options, const ProgressFn& progress) {
  if (options.pid_map.empty()) {
    throw std::runtime_error("Mapeamento de PIDs vazio");
  }

  std::vector<std::string> args = {"tsp", "-I", "file", input, "-P", "remap"};
  if (!options.update_psi) {
    args.emplace_back("--no-psi");
  }
  for (const auto& [from, to] : options.pid_map) {
    char mapping[32];
    std::snprintf(mapping, sizeof(mapping), "0x%04X=0x%04X", from, to);
    args.emplace_back(mapping);
  }
  args.insert(args.end(), {"-O", "file", output});

  if (progress) {
    progress(1);
  }
  std::string captured;
  const int code = run_process(args, captured);
  if (code != 0) {
    throw std::runtime_error("TSDuck tsp falhou (" + std::to_string(code) + "): " + captured);
  }
  if (progress) {
    progress(100);
  }
}

}  // namespace tslab
