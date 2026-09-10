// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_DATA_STRUCTURES_H__
#define DATACRUMBS_COMMON_DATA_STRUCTURES_H__
// include first
#include <datacrumbs/datacrumbs_config.h>
// other headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/typedefs.h>
// dependency headers
#include <json-c/json.h>

#ifndef DATACRUMBS_MAX_CAPTURE_ARGS
#define DATACRUMBS_MAX_CAPTURE_ARGS 5
#endif
#ifndef DATACRUMBS_MAX_CAPTURE_BYTES
#define DATACRUMBS_MAX_CAPTURE_BYTES 64
#endif
// std headers
#include <string>
#include <unordered_map>
#include <vector>

namespace datacrumbs {

/**
 * @brief Argument capture specification for one probe function argument.
 */
struct ProbeArgCaptureSpec {
  unsigned int index = 0;
  unsigned int num_bytes = 0;
  bool is_pointer = false;
  std::string label;
  std::string c_type;

  json_object* toJson() const {
    json_object* j = json_object_new_object();
    json_object_object_add(j, "index", json_object_new_int(index));
    json_object_object_add(j, "num_bytes", json_object_new_int(num_bytes));
    json_object_object_add(j, "is_pointer", json_object_new_boolean(is_pointer));
    json_object_object_add(j, "label", json_object_new_string(label.c_str()));
    json_object_object_add(j, "c_type", json_object_new_string(c_type.c_str()));
    return j;
  }

  static ProbeArgCaptureSpec fromJson(const json_object* j) {
    ProbeArgCaptureSpec spec;
    json_object* obj = nullptr;
    if (json_object_object_get_ex(j, "index", &obj)) spec.index = json_object_get_int(obj);
    if (json_object_object_get_ex(j, "num_bytes", &obj)) spec.num_bytes = json_object_get_int(obj);
    if (json_object_object_get_ex(j, "is_pointer", &obj)) {
      spec.is_pointer = json_object_get_boolean(obj);
    }
    if (json_object_object_get_ex(j, "label", &obj) && obj)
      spec.label = json_object_get_string(obj);
    if (json_object_object_get_ex(j, "c_type", &obj) && obj)
      spec.c_type = json_object_get_string(obj);
    return spec;
  }
};

/**
 * @brief Runtime metadata mapped by event id for fast decode/writer lookup.
 */
struct RuntimeEventMetadata {
  ProbeType probe_type = ProbeType::KPROBE;
  std::string probe_name;
  std::string function_name;
  std::vector<ProbeArgCaptureSpec> arg_specs;
};

/**
 * @brief Unified event wrapper used by runtime writers.
 */
struct EventWithId {
  char event_type;
  unsigned long long index;
  unsigned int type;
  unsigned long long tgid_pid;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  DataCrumbsArgs* args;
  EventWithId(char _event_type, unsigned long long _index, unsigned int _type,
              unsigned long long _tgid_pid, unsigned long long _event_id, unsigned long long _ts,
              unsigned long long _dur, DataCrumbsArgs* _args)
      : event_type(_event_type),
        index(_index),
        type(_type),
        tgid_pid(_tgid_pid),
        event_id(_event_id),
        ts(_ts),
        dur(_dur),
        args(_args) {}
  // Copy constructor
  EventWithId(const EventWithId& other)
      : event_type(other.event_type),
        index(other.index),
        type(other.type),
        tgid_pid(other.tgid_pid),
        event_id(other.event_id),
        ts(other.ts),
        dur(other.dur),
        args(other.args) {}

  // Move constructor
  EventWithId(EventWithId&& other) noexcept
      : event_type(other.event_type),
        index(other.index),
        type(other.type),
        tgid_pid(other.tgid_pid),
        event_id(other.event_id),
        ts(other.ts),
        dur(other.dur),
        args(other.args) {}
};

/**
 * @brief Base probe definition shared by runtime probe variants.
 */
class Probe {
 public:
  // Default constructor
  Probe() {}
  // Copy constructor
  Probe(const Probe& other)
      : type(other.type),
        name(other.name),
        functions(other.functions),
        function_arguments(other.function_arguments) {
    DC_LOG_TRACE("Probe copy constructor called");
  }

  // Move constructor
  Probe(Probe&& other) noexcept
      : type(other.type),
        name(std::move(other.name)),
        functions(std::move(other.functions)),
        function_arguments(std::move(other.function_arguments)) {
    DC_LOG_TRACE("Probe move constructor called");
  }
  // Constructor initializing the probe type
  Probe(ProbeType _type) : type(_type) { DC_LOG_TRACE("Probe constructor called"); }

  ProbeType type;                      // The type of probe (e.g., SYSCALLS, KPROBE, etc.)
  std::string name;                    // Name of the probe
  std::vector<std::string> functions;  // List of functions or arguments for the probe
  std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>>
      function_arguments;  // Optional per-function runtime arg capture specification
  /// Optional per-function declaration of where a newly created PID can be read
  /// from, keyed by function name with a source name such as "return". Declared
  /// in the user configuration and validated by the probe manager, so which
  /// calls create processes is configuration rather than compiled-in knowledge.
  std::unordered_map<std::string, std::string> new_pid_functions;

  // Validates the probe's configuration
  virtual bool validate() const {
    DC_LOG_TRACE("Probe::validate called");
    if (name.empty()) {
      DC_LOG_DEBUG("Probe name is empty");
      return false;
    }
    if (functions.empty()) {
      DC_LOG_DEBUG("Probe functions are empty");
      return false;
    }
    return true;
  }

  // Serializes the probe to a JSON object
  virtual json_object* toJson(bool include_functions = true) const {
    DC_LOG_TRACE("Probe::toJson called");
    json_object* j = json_object_new_object();
    json_object_object_add(j, "type", json_object_new_int(static_cast<int>(type)));
    json_object_object_add(j, "name", json_object_new_string(name.c_str()));

    json_object* funcs = json_object_new_array();
    if (include_functions) {
      for (const auto& func : functions) {
        json_object_array_add(funcs, json_object_new_string(func.c_str()));
      }
    } else {
      json_object_array_add(funcs, json_object_new_string(""));
    }

    json_object_object_add(j, "functions", funcs);

    if (!function_arguments.empty()) {
      json_object* jfunction_arguments = json_object_new_object();
      for (const auto& [function_name, arg_specs] : function_arguments) {
        json_object* jarg_specs = json_object_new_array();
        for (const auto& arg_spec : arg_specs) {
          json_object_array_add(jarg_specs, arg_spec.toJson());
        }
        json_object_object_add(jfunction_arguments, function_name.c_str(), jarg_specs);
      }
      json_object_object_add(j, "function_arguments", jfunction_arguments);
    }

    if (!new_pid_functions.empty()) {
      json_object* jnew_pid = json_object_new_object();
      for (const auto& [function_name, source] : new_pid_functions) {
        json_object_object_add(jnew_pid, function_name.c_str(),
                               json_object_new_string(source.c_str()));
      }
      json_object_object_add(j, "new_pid_functions", jnew_pid);
    }

    return j;
  }

  // Deserializes a probe from a JSON object
  static Probe fromJson(const json_object* j) {
    DC_LOG_TRACE("Probe::fromJson called");
    Probe p(static_cast<ProbeType>(json_object_get_int(json_object_object_get(j, "type"))));
    json_object* name_obj = json_object_object_get(j, "name");
    if (name_obj) p.name = json_object_get_string(name_obj);

    json_object* funcs_obj = json_object_object_get(j, "functions");
    if (funcs_obj && json_object_get_type(funcs_obj) == json_type_array) {
      int len = json_object_array_length(funcs_obj);
      for (int i = 0; i < len; ++i) {
        json_object* func = json_object_array_get_idx(funcs_obj, i);
        if (func) p.functions.push_back(json_object_get_string(func));
      }
    }

    json_object* function_arguments_obj = json_object_object_get(j, "function_arguments");
    if (function_arguments_obj &&
        json_object_get_type(function_arguments_obj) == json_type_object) {
      json_object_object_foreach(function_arguments_obj, function_name, arg_specs_obj) {
        if (!arg_specs_obj || json_object_get_type(arg_specs_obj) != json_type_array) {
          continue;
        }
        std::vector<ProbeArgCaptureSpec> arg_specs;
        const int spec_len = json_object_array_length(arg_specs_obj);
        for (int i = 0; i < spec_len; ++i) {
          json_object* arg_spec_obj = json_object_array_get_idx(arg_specs_obj, i);
          if (!arg_spec_obj || json_object_get_type(arg_spec_obj) != json_type_object) {
            continue;
          }
          arg_specs.push_back(ProbeArgCaptureSpec::fromJson(arg_spec_obj));
        }
        p.function_arguments[function_name] = std::move(arg_specs);
      }
    }

    json_object* new_pid_obj = json_object_object_get(j, "new_pid_functions");
    if (new_pid_obj && json_object_get_type(new_pid_obj) == json_type_object) {
      json_object_object_foreach(new_pid_obj, function_name, source_obj) {
        if (!source_obj || json_object_get_type(source_obj) != json_type_string) {
          continue;
        }
        p.new_pid_functions[function_name] = json_object_get_string(source_obj);
      }
    }
    return p;
  }

  const std::vector<ProbeArgCaptureSpec>* getArgSpecs(const std::string& function_name) const {
    const auto it = function_arguments.find(function_name);
    if (it == function_arguments.end()) {
      return nullptr;
    }
    return &it->second;
  }

  /**
   * @brief Name of the source a new PID can be read from for a function.
   *
   * @param function_name Function being attached. Example: "__x64_sys_clone3".
   * @return Source name such as "return", or an empty string when this function
   *         is not declared as creating a process.
   */
  const std::string& getNewPidSource(const std::string& function_name) const {
    static const std::string kNone;
    const auto it = new_pid_functions.find(function_name);
    return it == new_pid_functions.end() ? kNone : it->second;
  }
};

/**
 * @brief Probe definition for syscall function lists.
 */
struct SysCallProbe : public Probe {
 public:
  SysCallProbe(const SysCallProbe& other) : Probe(other) {
    DC_LOG_TRACE("SysCallProbe copy constructor called");
  }
  SysCallProbe() : Probe(ProbeType::SYSCALLS) { DC_LOG_TRACE("SysCallProbe constructor called"); }
  // Validates the syscall probe's configuration
  bool validate() const override {
    DC_LOG_TRACE("SysCallProbe::validate called");
    return Probe::validate();
  }

  // Serializes the syscall probe to a JSON object
  json_object* toJson(bool include_functions = true) const override {
    DC_LOG_TRACE("SysCallProbe::toJson called");
    // No extra fields, just use base
    return Probe::toJson(include_functions);
  }

  // Deserializes a syscall probe from a JSON object
  static SysCallProbe fromJson(const json_object* j) {
    DC_LOG_TRACE("SysCallProbe::fromJson called");
    SysCallProbe p;
    Probe base = Probe::fromJson(j);
    p.type = base.type;
    p.name = base.name;
    p.functions = base.functions;
    p.function_arguments = base.function_arguments;
    return p;
  }
};

/**
 * @brief Probe definition for kernel kprobes.
 */
struct KProbe : public Probe {
 public:
  KProbe(const KProbe& other) : Probe(other) { DC_LOG_TRACE("KProbe copy constructor called"); }
  KProbe() : Probe(ProbeType::KPROBE) { DC_LOG_TRACE("KProbe constructor called"); }
  // No extra fields for KProbe, just use base class serialization/deserialization

  // Validates the kprobe's configuration
  bool validate() const override {
    DC_LOG_TRACE("KProbe::validate called");
    return Probe::validate();
  }

  // Serializes the kprobe to a JSON object
  json_object* toJson(bool include_functions = true) const override {
    DC_LOG_TRACE("KProbe::toJson called");
    // No extra fields, just use base
    return Probe::toJson(include_functions);
  }

  // Deserializes a kprobe from a JSON object
  static KProbe fromJson(const json_object* j) {
    DC_LOG_TRACE("KProbe::fromJson called");
    KProbe p;
    Probe base = Probe::fromJson(j);
    p.type = base.type;
    p.name = base.name;
    p.functions = base.functions;
    p.function_arguments = base.function_arguments;
    return p;
  }
};

/**
 * @brief Probe definition for user-space uprobes.
 */
struct UProbe : public Probe {
 public:
  UProbe(const UProbe& other)
      : Probe(other), binary_path(other.binary_path), include_offsets(other.include_offsets) {
    DC_LOG_TRACE("UProbe copy constructor called");
  }
  UProbe() : Probe(ProbeType::UPROBE), binary_path(), include_offsets(false) {
    DC_LOG_TRACE("UProbe constructor called");
  }
  std::string binary_path;  // Path to the binary being probed
  bool include_offsets;
  // Validates the uprobe's configuration
  bool validate() const override {
    DC_LOG_TRACE("UProbe::validate called");
    if (!Probe::validate()) return false;
    if (binary_path.empty()) {
      DC_LOG_DEBUG("UProbe binary_path is empty");
      return false;
    }
    return true;
  }

  // Serializes the uprobe to a JSON object
  json_object* toJson(bool include_functions = true) const override {
    DC_LOG_TRACE("UProbe::toJson called");
    json_object* j = Probe::toJson(include_functions);
    json_object_object_add(j, "binary_path", json_object_new_string(binary_path.c_str()));
    json_object_object_add(j, "include_offsets", json_object_new_boolean(include_offsets));
    return j;
  }

  // Deserializes a uprobe from a JSON object
  static UProbe fromJson(const json_object* j) {
    DC_LOG_TRACE("UProbe::fromJson called");
    UProbe p;
    Probe base = Probe::fromJson(j);
    p.type = base.type;
    p.name = base.name;
    p.functions = base.functions;
    p.function_arguments = base.function_arguments;
    json_object* bin_obj = json_object_object_get(j, "binary_path");
    if (bin_obj) p.binary_path = json_object_get_string(bin_obj);

    json_object* include_offsets_obj = json_object_object_get(j, "include_offsets");
    if (include_offsets_obj) p.include_offsets = json_object_get_boolean(include_offsets_obj);

    return p;
  }
};

/**
 * @brief Probe definition for USDT probes.
 */
struct USDTProbe : public Probe {
 public:
  USDTProbe(const USDTProbe& other)
      : Probe(other), binary_path(other.binary_path), provider(other.provider) {
    DC_LOG_TRACE("USDTProbe copy constructor called");
  }
  USDTProbe() : Probe(ProbeType::USDT), binary_path(), provider() {
    DC_LOG_TRACE("USDTProbe constructor called");
  }
  std::string binary_path;  // Path to the binary being probed
  std::string provider;     // USDT provider name

  // Validates the USDT probe's configuration
  bool validate() const override {
    DC_LOG_TRACE("USDTProbe::validate called");
    if (!Probe::validate()) return false;
    if (binary_path.empty()) {
      DC_LOG_DEBUG("USDTProbe binary_path is empty");
      return false;
    }
    if (provider.empty()) {
      DC_LOG_DEBUG("USDTProbe provider is empty");
      return false;
    }
    return true;
  }

  // Serializes the USDT probe to a JSON object
  json_object* toJson(bool include_functions = true) const override {
    DC_LOG_TRACE("USDTProbe::toJson called");
    json_object* j = Probe::toJson(include_functions);
    json_object_object_add(j, "binary_path", json_object_new_string(binary_path.c_str()));
    json_object_object_add(j, "provider", json_object_new_string(provider.c_str()));
    return j;
  }

  // Deserializes a USDT probe from a JSON object
  static USDTProbe fromJson(const json_object* j) {
    DC_LOG_TRACE("USDTProbe::fromJson called");
    USDTProbe p;
    Probe base = Probe::fromJson(j);
    p.type = base.type;
    p.name = base.name;
    p.functions = base.functions;
    p.function_arguments = base.function_arguments;

    json_object* bin_obj = json_object_object_get(j, "binary_path");
    if (bin_obj) p.binary_path = json_object_get_string(bin_obj);

    json_object* provider_obj = json_object_object_get(j, "provider");
    if (provider_obj) p.provider = json_object_get_string(provider_obj);

    return p;
  }
};

/**
 * @brief Probe definition for custom BPF-based probes.
 */
struct CustomProbe : public Probe {
 public:
  CustomProbe(const CustomProbe& other)
      : Probe(other),
        bpf_path(other.bpf_path),
        start_event_id(other.start_event_id),
        process_header(other.process_header),
        event_type(other.event_type) {
    DC_LOG_TRACE("CustomProbe copy constructor called");
  }
  CustomProbe()
      : Probe(ProbeType::CUSTOM), bpf_path(), start_event_id(), process_header(), event_type(1) {
    DC_LOG_TRACE("CustomProbe constructor called");
  }
  std::string bpf_path;        // Path to the BPF program
  uint64_t start_event_id;     // Starting event ID for the probe
  std::string process_header;  // Header file for the process
  uint64_t event_type;         // Event type for the probe

  // Validates the Custom probe's configuration
  bool validate() const override {
    DC_LOG_TRACE("CustomProbe::validate called");
    if (!Probe::validate()) return false;
    if (bpf_path.empty()) {
      DC_LOG_DEBUG("CustomProbe bpf_path is empty");
      return false;
    }
    if (start_event_id == 0) {
      DC_LOG_DEBUG("CustomProbe start_event_id is not set");
      return false;
    }
    if (process_header.empty()) {
      DC_LOG_DEBUG("CustomProbe process_header is empty");
      return false;
    }
    if (event_type == 0) {
      DC_LOG_DEBUG("CustomProbe event_type is not set");
      return false;
    }
    DC_LOG_DEBUG("CustomProbe validated successfully: %s", name.c_str());
    return true;
  }

  // Serializes the USDT probe to a JSON object
  json_object* toJson(bool include_functions = true) const override {
    DC_LOG_TRACE("CustomProbe::toJson called");
    json_object* j = Probe::toJson(include_functions);
    json_object_object_add(j, "bpf_path", json_object_new_string(bpf_path.c_str()));
    json_object_object_add(j, "start_event_id", json_object_new_int64(start_event_id));
    json_object_object_add(j, "process_header", json_object_new_string(process_header.c_str()));
    json_object_object_add(j, "event_type", json_object_new_int64(event_type));
    return j;
  }

  // Deserializes a Custom probe from a JSON object
  static CustomProbe fromJson(const json_object* j) {
    DC_LOG_TRACE("CustomProbe::fromJson called");
    CustomProbe p;
    Probe base = Probe::fromJson(j);
    p.type = base.type;
    p.name = base.name;
    p.functions = base.functions;
    p.function_arguments = base.function_arguments;

    json_object* bpf_obj = json_object_object_get(j, "bpf_path");
    if (bpf_obj) p.bpf_path = json_object_get_string(bpf_obj);

    json_object* start_event_id_obj = json_object_object_get(j, "start_event_id");
    if (start_event_id_obj) p.start_event_id = json_object_get_int64(start_event_id_obj);

    json_object* process_header_obj = json_object_object_get(j, "process_header");
    if (process_header_obj) p.process_header = json_object_get_string(process_header_obj);
    json_object* event_type_obj = json_object_object_get(j, "event_type");
    if (event_type_obj) p.event_type = json_object_get_int64(event_type_obj);

    return p;
  }
};

/**
 * @brief Base configuration for explorer capture sources.
 */
class CaptureProbe {
 public:
  // Constructor initializing the capture type
  CaptureProbe(CaptureType _type) : type(_type) { DC_LOG_TRACE("CaptureProbe constructor called"); }

  CaptureType type;      // The type of capture (e.g., KSYM, HEADER, BINARY, USDT)
  std::string regex;     // Regex pattern for matching
  std::string name;      // Name of the capture probe
  ProbeType probe_type;  // Type of probe associated with the capture
  bool enable_explorer;  // Flag to enable explorer for this capture probe
  std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>>
      function_arguments;  // Optional per-function arg capture specification from YAML

  const std::vector<ProbeArgCaptureSpec>* getArgSpecs(const std::string& function_name) const {
    auto lookup = [this](const std::string& key) -> const std::vector<ProbeArgCaptureSpec>* {
      const auto it = function_arguments.find(key);
      if (it == function_arguments.end()) {
        return nullptr;
      }
      return &it->second;
    };

    if (const auto* exact = lookup(function_name)) {
      return exact;
    }

    const auto offset_pos = function_name.find(':');
    const std::string base_name =
        (offset_pos == std::string::npos) ? function_name : function_name.substr(0, offset_pos);
    if (base_name != function_name) {
      if (const auto* base = lookup(base_name)) {
        return base;
      }
    }

    if (probe_type == ProbeType::SYSCALLS) {
      if (const auto* prefixed = lookup("sys_" + base_name)) {
        return prefixed;
      }
      if (const auto* x64_prefixed = lookup("__x64_sys_" + base_name)) {
        return x64_prefixed;
      }
    }

    if (const auto* wildcard = lookup("*")) {
      return wildcard;
    }
    return lookup("default");
  }
};

/**
 * @brief Capture probe for kernel symbol source.
 */
class KernelCaptureProbe : public CaptureProbe {
 public:
  KernelCaptureProbe() : CaptureProbe(CaptureType::KSYM) {
    DC_LOG_TRACE("KernelCaptureProbe constructor called");
  }
};

/**
 * @brief Capture probe for header-based symbol extraction.
 */
class HeaderCaptureProbe : public CaptureProbe {
 public:
  HeaderCaptureProbe() : CaptureProbe(CaptureType::HEADER), file() {
    DC_LOG_TRACE("HeaderCaptureProbe constructor called");
  }
  std::string file;  // Name of the header to capture
};

/**
 * @brief Capture probe for ELF binary symbol extraction.
 */
class BinaryCaptureProbe : public CaptureProbe {
 public:
  BinaryCaptureProbe() : CaptureProbe(CaptureType::BINARY), file(), include_offsets(false) {
    DC_LOG_TRACE("BinaryCaptureProbe constructor called");
  }
  std::string file;  // Path to the binary
  bool include_offsets;
};

/**
 * @brief Capture probe for USDT provider/function extraction.
 */
class USDTCaptureProbe : public CaptureProbe {
 public:
  USDTCaptureProbe() : CaptureProbe(CaptureType::USDT), binary_path(), provider() {
    DC_LOG_TRACE("USDTCaptureProbe constructor called");
  }
  std::string binary_path;  // Path to the binary
  std::string provider;     // USDT provider name
};

class CustomCaptureProbe : public CaptureProbe {
 public:
  CustomCaptureProbe()
      : CaptureProbe(CaptureType::CUSTOM),
        bpf_file(),
        probe_file(),
        start_event_id(100000),
        process_header(),
        event_type(1) {
    DC_LOG_TRACE("CustomCaptureProbe constructor called");
  }
  std::string bpf_file;        // Path to the custom bpf file
  std::string probe_file;      // Path to the custom probe file
  uint64_t start_event_id;     // Starting event ID for the probe
  std::string process_header;  // Header file for the process
  uint64_t event_type;         // Event type for the probe
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_COMMON_DATA_STRUCTURES_H__
