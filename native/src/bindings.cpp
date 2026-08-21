#include "tslab/engine.h"

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <optional>
#include <unordered_map>

namespace py = pybind11;

namespace {

tslab::ProgressFn wrap_progress(const py::object& callback) {
  if (callback.is_none()) {
    return {};
  }
  return [callback](int percent) {
    py::gil_scoped_acquire acquire;
    callback(percent);
  };
}

}  // namespace

PYBIND11_MODULE(_core, module) {
  module.doc() = "Núcleo C++ do analisador MPEG-TS (mmap, scan, busca, remap)";

  py::class_<tslab::FileInfo>(module, "FileInfo")
      .def_readonly("path", &tslab::FileInfo::path)
      .def_readonly("size", &tslab::FileInfo::size)
      .def_readonly("packet_size", &tslab::FileInfo::packet_size)
      .def_readonly("sync_offset", &tslab::FileInfo::sync_offset)
      .def_readonly("packet_count", &tslab::FileInfo::packet_count);

  py::class_<tslab::PidStats>(module, "PidStats")
      .def_readonly("pid", &tslab::PidStats::pid)
      .def_readonly("packets", &tslab::PidStats::packets)
      .def_readonly("pusi", &tslab::PidStats::pusi)
      .def_readonly("cc_errors", &tslab::PidStats::cc_errors)
      .def_readonly("tei", &tslab::PidStats::tei)
      .def_readonly("scrambled", &tslab::PidStats::scrambled)
      .def_readonly("first_index", &tslab::PidStats::first_index)
      .def_readonly("last_index", &tslab::PidStats::last_index)
      .def_readonly("stream_type", &tslab::PidStats::stream_type)
      .def_readonly("pcr_pid", &tslab::PidStats::pcr_pid)
      .def_readonly("type_label", &tslab::PidStats::type_label);

  py::class_<tslab::SearchHit>(module, "SearchHit")
      .def_readonly("packet_index", &tslab::SearchHit::packet_index)
      .def_readonly("pid", &tslab::SearchHit::pid)
      .def_readonly("cc", &tslab::SearchHit::cc)
      .def_readonly("pusi", &tslab::SearchHit::pusi);

  py::enum_<tslab::RemapBackend>(module, "RemapBackend")
      .value("Native", tslab::RemapBackend::Native)
      .value("Tsduck", tslab::RemapBackend::Tsduck);

  py::class_<tslab::TransportStream>(module, "TransportStream")
      .def(py::init<>())
      .def("open", &tslab::TransportStream::open, py::arg("path"))
      .def("close", &tslab::TransportStream::close)
      .def("is_open", &tslab::TransportStream::is_open)
      .def("info", &tslab::TransportStream::info, py::return_value_policy::copy)
      .def(
          "scan",
          [](tslab::TransportStream& self, py::object progress) {
            auto fn = wrap_progress(progress);
            py::gil_scoped_release release;
            return self.scan(fn);
          },
          py::arg("progress") = py::none())
      .def("read_packet", &tslab::TransportStream::read_packet, py::arg("index"))
      .def(
          "search",
          [](const tslab::TransportStream& self, std::optional<std::uint16_t> pid,
             std::optional<std::uint8_t> table_id, py::bytes payload, std::uint64_t start_packet,
             std::uint32_t limit, py::object progress) {
            tslab::SearchQuery query;
            query.pid = pid;
            query.table_id = table_id;
            query.start_packet = start_packet;
            query.limit = limit;
            const std::string raw = payload;
            query.payload_contains.assign(raw.begin(), raw.end());
            auto fn = wrap_progress(progress);
            py::gil_scoped_release release;
            return self.search(query, fn);
          },
          py::arg("pid") = py::none(), py::arg("table_id") = py::none(), py::arg("payload") = py::bytes(""),
          py::arg("start_packet") = 0, py::arg("limit") = 256, py::arg("progress") = py::none())
      .def(
          "remap",
          [](const tslab::TransportStream& self, const std::string& output_path,
             const std::unordered_map<std::uint16_t, std::uint16_t>& pid_map, bool update_psi,
             tslab::RemapBackend backend, py::object progress) {
            tslab::RemapOptions options;
            options.pid_map = pid_map;
            options.update_psi = update_psi;
            options.backend = backend;
            auto fn = wrap_progress(progress);
            py::gil_scoped_release release;
            self.remap(output_path, options, fn);
          },
          py::arg("output_path"), py::arg("pid_map"), py::arg("update_psi") = true,
          py::arg("backend") = tslab::RemapBackend::Native, py::arg("progress") = py::none())
      .def_static("tsduck_available", &tslab::TransportStream::tsduck_available)
      .def_static("tsduck_version", &tslab::TransportStream::tsduck_version);
}
