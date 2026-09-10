// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

// Internal headers
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/server/process/event_processor.h>

#include <unordered_map>
#include <unordered_set>

// std headers
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  if (level >= LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

static bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
  auto* event_processor = static_cast<datacrumbs::EventProcessor*>(ctx);
  return event_processor->handle_event(data, data_sz);
}

inline static int lookup_and_delete(int map_fd, datacrumbs::EventProcessor* event_processor,
                                    struct string_t* keys, unsigned int* values,
                                    unsigned int batch_size, struct string_t* in_batch) {
  int ret = bpf_map_lookup_and_delete_batch_compat(map_fd, in_batch, &in_batch, keys, values,
                                                   &batch_size, 0);
  if (ret < 0 && errno != ENOENT) {
    perror("bpf_map_lookup_and_delete_batch file_map");
    return -1;
  }
  for (unsigned int i = 0; i < batch_size; ++i) {
    event_processor->update_filename(keys[i].str, values[i]);
  }
  if (ret < 0 && errno == ENOENT) {
    return 0;
  }
  return 1;
}

static volatile bool stop = false;

static void sig_handler(int) {
  stop = true;
  DC_LOG_INFO("\nReceived SIGINT, stopping server loop");
}

static bool split_uprobe_target(const std::string& symbol_with_offset, std::string* symbol_name,
                                unsigned long* offset) {
  const auto pos = symbol_with_offset.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  *symbol_name = symbol_with_offset.substr(0, pos);
  *offset = std::stoul(symbol_with_offset.substr(pos + 1), nullptr, 0);
  return true;
}

static std::string normalize_syscall_name_for_attach(const std::string& function_name) {
  if (function_name.rfind("__x64_sys_", 0) == 0) {
    return function_name.substr(10);
  }
  if (function_name.rfind("sys_", 0) == 0) {
    return function_name.substr(4);
  }
  return function_name;
}

static unsigned int runtime_probe_kind(datacrumbs::ProbeType probe_type) {
  switch (probe_type) {
    case datacrumbs::ProbeType::KPROBE:
      return DATACRUMBS_RUNTIME_PROBE_KIND_KPROBE;
    case datacrumbs::ProbeType::UPROBE:
      return DATACRUMBS_RUNTIME_PROBE_KIND_UPROBE;
    case datacrumbs::ProbeType::SYSCALLS:
      return DATACRUMBS_RUNTIME_PROBE_KIND_SYSCALL;
    case datacrumbs::ProbeType::USDT:
      return DATACRUMBS_RUNTIME_PROBE_KIND_USDT;
    default:
      return 0;
  }
}

/**
 * @brief Translate a configured new-PID source name into its BPF source id.
 *
 * Which calls create processes is declared in the user configuration, validated
 * by the probe manager, and carried in the signed probe descriptor, so this is
 * only the string-to-id mapping for the sources BPF knows how to read. Adding a
 * source means adding a name here and a matching case in track_new_pid().
 *
 * @param source_name Source declared for the function. Example: "return".
 * @return A DATACRUMBS_NEW_PID_SOURCE_* value; NONE when unset or unrecognised.
 */
static unsigned int new_pid_source_id(const std::string& source_name) {
  if (source_name.empty()) {
    return DATACRUMBS_NEW_PID_SOURCE_NONE;
  }
  if (source_name == "return") {
    return DATACRUMBS_NEW_PID_SOURCE_RETURN;
  }
  DC_LOG_WARN("Unknown new-pid source '%s'; processes created here will not be traced",
              source_name.c_str());
  return DATACRUMBS_NEW_PID_SOURCE_NONE;
}

static int populate_event_arg_config(
    int map_fd, uint64_t cookie, uint64_t event_id, datacrumbs::ProbeType probe_type,
    const std::string& function_name, const std::string& new_pid_source,
    const std::vector<datacrumbs::ProbeArgCaptureSpec>* arg_specs) {
  // Populate one compact per-event capture schema consumed directly by BPF programs.
  runtime_event_config_t config = {};
  config.event_id = event_id;
  config.probe_kind = runtime_probe_kind(probe_type);
  config.new_pid_source = new_pid_source_id(new_pid_source);
  if (config.new_pid_source != DATACRUMBS_NEW_PID_SOURCE_NONE) {
    DC_LOG_DEBUG("Probe '%s' declared as creating processes via '%s'; children will be traced",
                 function_name.c_str(), new_pid_source.c_str());
  }
  if (arg_specs != nullptr) {
    config.arg_count = std::min<unsigned int>(arg_specs->size(), DATACRUMBS_MAX_CAPTURE_ARGS);
    for (unsigned int index = 0; index < config.arg_count; ++index) {
      const auto& spec = (*arg_specs)[index];
      config.arg_index[index] = (*arg_specs)[index].index;
      if (spec.is_pointer) {
        if (is_char_pointer_type(spec.c_type)) {
          config.arg_num_bytes[index] =
              std::min<unsigned int>(spec.num_bytes, DATACRUMBS_MAX_CAPTURE_BYTES);
          config.arg_is_pointer[index] = 1;
        } else {
          config.arg_num_bytes[index] = 0;
          config.arg_is_pointer[index] = 0;
        }
      } else {
        config.arg_num_bytes[index] = std::min<unsigned int>(spec.num_bytes, 8U);
        config.arg_is_pointer[index] = 0;
      }
    }
  }
  if (bpf_map_update_elem(map_fd, &cookie, &config, BPF_ANY) < 0) {
    DC_LOG_ERROR("Failed to populate event_arg_config_map for cookie=%llu event_id=%llu", cookie,
                 event_id);
    return -1;
  }
  return 0;
}

static int attach_runtime_probes(datacrumbs::EventProcessor* event_processor,
                                 struct datacrumbs_bpf* skel) {
  // Resolve all generic attach programs and shared config map before per-probe loop.
  auto config_manager = event_processor->configManager_;
  auto* client_start = bpf_object__find_program_by_name(skel->obj, "trace_client_start");
  auto* client_stop = bpf_object__find_program_by_name(skel->obj, "trace_client_stop");
  auto* kprobe_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_kprobe_entry");
  auto* kprobe_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_kprobe_exit");
  auto* syscall_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_syscall_entry");
  auto* syscall_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_syscall_exit");
  auto* uprobe_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_uprobe_entry");
  auto* uprobe_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_uprobe_exit");
  auto* usdt_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_usdt_entry");
  auto* usdt_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_usdt_exit");
  const int event_arg_config_fd = bpf_map__fd(skel->maps.event_arg_config_map);

  if (event_arg_config_fd < 0) {
    DC_LOG_ERROR("Failed to get event_arg_config_map fd: %d", event_arg_config_fd);
    return 1;
  }

  if (!kprobe_entry || !kprobe_exit) {
    DC_LOG_ERROR("Failed to find generic kprobe BPF programs");
    return 1;
  }
  if (!syscall_entry || !syscall_exit) {
    DC_LOG_ERROR("Failed to find generic syscall BPF programs");
    return 1;
  }
  if (!uprobe_entry || !uprobe_exit) {
    DC_LOG_ERROR("Failed to find generic uprobe BPF programs");
    return 1;
  }
  if (!usdt_entry || !usdt_exit) {
    DC_LOG_ERROR("Failed to find generic usdt BPF programs");
    return 1;
  }
  if (!client_start || !client_stop) {
    DC_LOG_ERROR("Failed to find client init BPF programs");
    return 1;
  }

  {
    // Always hook datacrumbs client lifecycle entry/exit points.
    struct bpf_uprobe_opts start_opts = {};
    start_opts.sz = sizeof(start_opts);
    start_opts.func_name = "datacrumbs_start";
    struct bpf_uprobe_opts stop_opts = {};
    stop_opts.sz = sizeof(stop_opts);
    stop_opts.func_name = "datacrumbs_stop";
    auto* start_link =
        bpf_program__attach_uprobe_opts(client_start, -1, DATACRUMBS_CLIENT_LIB, 0, &start_opts);
    auto* stop_link =
        bpf_program__attach_uprobe_opts(client_stop, -1, DATACRUMBS_CLIENT_LIB, 0, &stop_opts);
    if (libbpf_get_error(start_link) || libbpf_get_error(stop_link)) {
      DC_LOG_ERROR("Failed to attach datacrumbs client hooks for %s", DATACRUMBS_CLIENT_LIB);
      return 1;
    }
  }

  int total_requested = 0;
  int total_attached = 0;
  int total_failed = 0;
  uint64_t cookie = 1;
  bool runtime_probe_state_updated = false;

  for (const auto& probe : config_manager->runtime_probes) {
    for (const auto& function_name : probe->functions) {
      // Resolve generated runtime event id first; attachment is skipped when mapping is missing.
      const auto event_id = config_manager->get_runtime_event_id(probe->name, function_name);
      if (!event_id.has_value()) {
        DC_LOG_WARN("Skipping runtime probe without generated event id: %s.%s", probe->name.c_str(),
                    function_name.c_str());
        total_failed += 2;
        continue;
      }

      const uint64_t current_cookie = cookie++;
      if (probe->type == datacrumbs::ProbeType::KPROBE) {
        // Attach entry+exit kprobes and track runtime state success/failure.
        total_requested += 2;
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      function_name, probe->getNewPidSource(function_name),
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_kprobe_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_kprobe_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        auto* entry_link =
            bpf_program__attach_kprobe_opts(kprobe_entry, function_name.c_str(), &entry_opts);
        auto* exit_link =
            bpf_program__attach_kprobe_opts(kprobe_exit, function_name.c_str(), &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::SYSCALLS) {
        // Normalize syscall names to avoid double-prefix attach failures.
        total_requested += 2;
        const std::string syscall_name = normalize_syscall_name_for_attach(function_name);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      function_name, probe->getNewPidSource(function_name),
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_ksyscall_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_ksyscall_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        auto* entry_link =
            bpf_program__attach_ksyscall(syscall_entry, syscall_name.c_str(), &entry_opts);
        auto* exit_link =
            bpf_program__attach_ksyscall(syscall_exit, syscall_name.c_str(), &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::UPROBE) {
        // Attach uprobes by symbol or resolved offset target.
        total_requested += 2;
        auto uprobe = std::dynamic_pointer_cast<datacrumbs::UProbe>(probe);
        std::string symbol_name;
        unsigned long offset = 0;
        const bool has_offset = uprobe && split_uprobe_target(function_name, &symbol_name, &offset);
        if (!uprobe) {
          DC_LOG_WARN("Skipping invalid uprobe config for %s.%s", probe->name.c_str(),
                      function_name.c_str());
          total_failed += 2;
          continue;
        }
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      function_name, probe->getNewPidSource(function_name),
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_uprobe_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_uprobe_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        if (!has_offset) {
          entry_opts.func_name = function_name.c_str();
          exit_opts.func_name = function_name.c_str();
        }
        auto* entry_link = bpf_program__attach_uprobe_opts(
            uprobe_entry, -1, uprobe->binary_path.c_str(), offset, &entry_opts);
        auto* exit_link = bpf_program__attach_uprobe_opts(
            uprobe_exit, -1, uprobe->binary_path.c_str(), offset, &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::USDT) {
        // Attach USDT entry/exit probes against configured provider/function.
        total_requested += 2;
        auto usdt = std::dynamic_pointer_cast<datacrumbs::USDTProbe>(probe);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      function_name, probe->getNewPidSource(function_name),
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_usdt_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.usdt_cookie = current_cookie;
        struct bpf_usdt_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.usdt_cookie = current_cookie;
        auto* entry_link = usdt ? bpf_program__attach_usdt(
                                      usdt_entry, -1, usdt->binary_path.c_str(),
                                      usdt->provider.c_str(), function_name.c_str(), &entry_opts)
                                : nullptr;
        auto* exit_link = usdt ? bpf_program__attach_usdt(usdt_exit, -1, usdt->binary_path.c_str(),
                                                          usdt->provider.c_str(),
                                                          function_name.c_str(), &exit_opts)
                               : nullptr;
        if (!usdt || libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else {
        DC_LOG_WARN("Skipping unsupported runtime probe type %d for %s",
                    static_cast<int>(probe->type), probe->name.c_str());
        total_failed += 2;
      }
    }
  }

  if (runtime_probe_state_updated) {
    // Persist latest success/failure status for runtime diagnostics/reporting.
    config_manager->persist_runtime_probe_state();
  }

  DC_LOG_INFO("Runtime probe attachment summary: requested=%d attached=%d failed=%d",
              total_requested, total_attached, total_failed);
  return 0;
}

static int main_process(datacrumbs::EventProcessor* event_processor) {
  DC_LOG_TRACE("main: start");
  datacrumbs::utils::Timer timer;
  timer.resumeTime();

  struct datacrumbs_bpf* skel = nullptr;
  struct ring_buffer* rb = nullptr;
  int err = 0;
  libbpf_set_print(libbpf_print_fn);

  skel = datacrumbs_bpf__open_and_load();
  if (!skel) {
    DC_LOG_ERROR("Failed to open BPF object");
    return 1;
  }

  err = datacrumbs_bpf__attach(skel);
  if (err) {
    DC_LOG_ERROR("Failed to attach BPF skeleton: %d", err);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  err = attach_runtime_probes(event_processor, skel);
  if (err) {
    DC_LOG_ERROR("Failed to attach runtime probes: %d", err);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }

#if !(defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1))
  DC_LOG_WARN("DATACRUMBS_ENABLE_OPT is OFF. Nothing will be captured");
#endif
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  DC_LOG_PRINT("DataCrumbs in Tracer mode");
#else
  DC_LOG_PRINT("DataCrumbs in Profiler mode");
#endif

#if defined(DATACRUMBS_ENABLE_INCLUSION_PATH) && (DATACRUMBS_ENABLE_INCLUSION_PATH == 1)
  int inclusion_trie = bpf_map__fd(skel->maps.inclusion_path_trie);
  if (inclusion_trie < 0) {
    DC_LOG_ERROR("Failed to get inclusion path trie: %d", inclusion_trie);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  struct string_t* cur_key = nullptr;
  struct string_t next_key = {};
  struct string_t value = {};
  for (;;) {
    err = bpf_map_get_next_key(inclusion_trie, cur_key, &next_key);
    if (err) break;
    bpf_map_delete_elem(inclusion_trie, &next_key);
    cur_key = &next_key;
  }

  std::unordered_map<unsigned int, string_t> inclusion_list;
  const std::string inclusion_paths = event_processor->configManager_->inclusion_paths;
  if (!inclusion_paths.empty()) {
    std::stringstream ss(inclusion_paths);
    std::string path;
    unsigned int idx = 1;
    while (std::getline(ss, path, ':')) {
      if (!path.empty()) {
        string_t s = {};
        size_t copy_len = path.size();
        if (copy_len > sizeof(s.str) - 1) copy_len = sizeof(s.str) - 1;
        strncpy(s.str, path.c_str(), copy_len);
        s.str[copy_len] = '\0';
        s.len = copy_len * 8;
        inclusion_list[idx++] = s;
      }
    }
  }
  for (const auto& pair : inclusion_list) {
    if (bpf_map_update_elem(inclusion_trie, &pair.second, &pair.second, BPF_ANY) < 0) {
      DC_LOG_ERROR("Failed to update inclusion path trie for %s", pair.second.str);
      datacrumbs_bpf__destroy(skel);
      return 1;
    }
  }
  cur_key = nullptr;
  next_key = {};
  for (;;) {
    err = bpf_map_get_next_key(inclusion_trie, cur_key, &next_key);
    if (err) break;
    bpf_map_lookup_elem(inclusion_trie, &next_key, &value);
    DC_LOG_INFO("Trie key: %s, len: %u, value_len: %u", next_key.str, next_key.len, value.len);
    cur_key = &next_key;
  }
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  int failed_events_fd = bpf_map__fd(skel->maps.failed_request);
  if (failed_events_fd < 0) {
    DC_LOG_ERROR("Failed to get failed events fd: %d", failed_events_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event, event_processor, nullptr);
  if (!rb) {
    DC_LOG_ERROR("Failed to create ring buffer");
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
#else
  INITIALIZE_MAP_1();
#ifdef GET_DATA_2_EXISTS
  INITIALIZE_MAP_2();
#endif
#ifdef GET_DATA_3_EXISTS
  INITIALIZE_MAP_3();
#endif
#ifdef GET_DATA_4_EXISTS
  int profile_4_fd = initialize_map_4(skel);
#endif
#ifdef GET_DATA_5_EXISTS
  int profile_5_fd = initialize_map_5(skel);
#endif
#ifdef GET_DATA_6_EXISTS
  int profile_6_fd = initialize_map_6(skel);
#endif
#ifdef GET_DATA_7_EXISTS
  int profile_7_fd = initialize_map_7(skel);
#endif
#ifdef GET_DATA_8_EXISTS
  int profile_8_fd = initialize_map_8(skel);
#endif
#ifdef GET_DATA_9_EXISTS
  int profile_9_fd = initialize_map_9(skel);
#endif
  int latest_interval_fd = bpf_map__fd(skel->maps.latest_interval);
  if (latest_interval_fd < 0) {
    DC_LOG_ERROR("Failed to get latest interval map fd: %d", latest_interval_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
#endif

  int file_hash_fd = bpf_map__fd(skel->maps.file_map);
  if (file_hash_fd < 0) {
    DC_LOG_ERROR("Failed to get file hash fd: %d", file_hash_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }

  const double elapsed = timer.pauseTime();
  DC_LOG_PRINT("Initialization of DataCrumbs elapsed time: %f seconds", elapsed);
  {
    std::error_code ec;
    std::filesystem::create_directories(
        event_processor->configManager_->server_ready_file.parent_path(), ec);
    std::ofstream ready_output(event_processor->configManager_->server_ready_file);
    if (ready_output.is_open()) {
      ready_output << "ready\n";
    }
  }
  DC_LOG_INFO("DataCrumbs ready to run for user:%s run_id:%s trace_file:%s",
              event_processor->configManager_->user.c_str(),
              event_processor->configManager_->run_id.c_str(),
              event_processor->configManager_->trace_file_path.c_str());

  signal(SIGINT, sig_handler);
  unsigned int batch_size = 1024;
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
  struct string_t* keys =
      static_cast<struct string_t*>(malloc(batch_size * sizeof(struct string_t)));
  unsigned int* values = static_cast<unsigned int*>(malloc(batch_size * sizeof(unsigned int)));
  struct string_t* in_batch = nullptr;
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 2)
  INITIALIZE_MAP_LOOKUP_1();
#ifdef GET_DATA_2_EXISTS
  INITIALIZE_MAP_LOOKUP_2();
#endif
#ifdef GET_DATA_3_EXISTS
  INITIALIZE_MAP_LOOKUP_3();
#endif
#ifdef GET_DATA_4_EXISTS
  INITIALIZE_MAP_LOOKUP_4();
#endif
#ifdef GET_DATA_5_EXISTS
  INITIALIZE_MAP_LOOKUP_5();
#endif
#ifdef GET_DATA_6_EXISTS
  INITIALIZE_MAP_LOOKUP_6();
#endif
#ifdef GET_DATA_7_EXISTS
  INITIALIZE_MAP_LOOKUP_7();
#endif
#ifdef GET_DATA_8_EXISTS
  INITIALIZE_MAP_LOOKUP_8();
#endif
#ifdef GET_DATA_9_EXISTS
  INITIALIZE_MAP_LOOKUP_9();
#endif
#endif

  unsigned long long last_processed_timestamp = 0;
  while (!stop) {
    err = 0;
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
    err = lookup_and_delete(file_hash_fd, event_processor, keys, values, batch_size, in_batch);
    if (err == -EINTR) {
      err = 0;
      break;
    }
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
    int failed_events = 0;
    err = bpf_map_lookup_elem(failed_events_fd, &DATACRUMBS_FAILED_EVENTS_KEY, &failed_events);
    if (err == 0) {
      event_processor->failed_events = failed_events;
    }
    err = ring_buffer__poll(rb, 10);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      DC_LOG_ERROR("Error polling ring buffer: %d", err);
      break;
    }
#else
    unsigned long long latest_ts = 0;
    err = bpf_map_lookup_elem(latest_interval_fd, &DATACRUMBS_TS_KEY, &latest_ts);
    if (err == 0) {
      if (last_processed_timestamp == 0) {
        last_processed_timestamp = latest_ts;
      }
      if (latest_ts > last_processed_timestamp) {
        last_processed_timestamp = latest_ts;
        LOOKUP_1_CALL();
#ifdef GET_DATA_2_EXISTS
        LOOKUP_2_CALL();
#endif
#ifdef GET_DATA_3_EXISTS
        LOOKUP_3_CALL();
#endif
#ifdef GET_DATA_4_EXISTS
        LOOKUP_4_CALL();
#endif
#ifdef GET_DATA_5_EXISTS
        LOOKUP_5_CALL();
#endif
#ifdef GET_DATA_6_EXISTS
        LOOKUP_6_CALL();
#endif
#ifdef GET_DATA_7_EXISTS
        LOOKUP_7_CALL();
#endif
#ifdef GET_DATA_8_EXISTS
        LOOKUP_8_CALL();
#endif
#ifdef GET_DATA_9_EXISTS
        LOOKUP_9_CALL();
#endif
      }
    }
#endif
  }

  batch_size = 1024 * 1024;
  DC_LOG_INFO("");
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 2)
  DC_LOG_INFO("Collecting remaining profiling events");
  while (LOOKUP_1_CALL() != -1);
#ifdef GET_DATA_2_EXISTS
  while (LOOKUP_2_CALL() != -1);
#endif
#ifdef GET_DATA_3_EXISTS
  while (LOOKUP_3_CALL() != -1);
#endif
#ifdef GET_DATA_4_EXISTS
  while (LOOKUP_4_CALL() != -1);
#endif
#ifdef GET_DATA_5_EXISTS
  while (LOOKUP_5_CALL() != -1);
#endif
#ifdef GET_DATA_6_EXISTS
  while (LOOKUP_6_CALL() != -1);
#endif
#ifdef GET_DATA_7_EXISTS
  while (LOOKUP_7_CALL() != -1);
#endif
#ifdef GET_DATA_8_EXISTS
  while (LOOKUP_8_CALL() != -1);
#endif
#ifdef GET_DATA_9_EXISTS
  while (LOOKUP_9_CALL() != -1);
#endif
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  int failed_events = 0;
  err = bpf_map_lookup_elem(failed_events_fd, &DATACRUMBS_FAILED_EVENTS_KEY, &failed_events);
  if (err == 0) {
    DC_LOG_PRINT("Total %d events failed", failed_events);
  }
#endif

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
  DC_LOG_PRINT("Collecting string metadata from file_map...");
  while (lookup_and_delete(file_hash_fd, event_processor, keys, values, batch_size, in_batch) ==
         1) {
  }
  if (keys) free(keys);
  if (values) free(values);
#endif

  DC_LOG_PRINT("Finalizing DataCrumbs...");
  if (stop) {
    DC_LOG_INFO("Received SIGINT (Ctrl-C), exiting gracefully");
  }
  timer.resumeTime();
  event_processor->finalize();
  {
    std::error_code ec;
    std::filesystem::remove(event_processor->configManager_->server_ready_file, ec);
  }

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  ring_buffer__free(rb);
#endif
  datacrumbs_bpf__destroy(skel);

  const double finalize_elapsed = timer.pauseTime();
  DC_LOG_PRINT("Finalization and cleanup of DataCrumbs elapsed: %f seconds", finalize_elapsed);
  DC_LOG_PRINT("Failed events: %d", event_processor->failed_events);
  DC_LOG_PRINT("Total events: %llu", event_processor->event_index.load());
  DC_LOG_TRACE("main: end");
  return 0;
}

static int main_call(int argc, char** argv) {
  if (argc < 4) {
    DC_LOG_ERROR("Usage: %s <signed-probes.json.gz> <run-id> <user>", argv[0]);
    return 1;
  }

  const std::string run_id = argv[2];
  const std::string user = argv[3];
  auto config_manager =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance(argv[1], run_id,
                                                                                   user, true);
  if (!config_manager) {
    DC_LOG_ERROR("Failed to initialize runtime configuration manager");
    return 1;
  }
  auto event_processor = datacrumbs::EventProcessor(argv[1]);
  event_processor.configManager_->print_configurations();
  return main_process(&event_processor);
}
