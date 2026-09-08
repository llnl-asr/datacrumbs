// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_RUNTIME_CONFIGURATION_MANAGER_H__
#define DATACRUMBS_COMMON_RUNTIME_CONFIGURATION_MANAGER_H__

#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/datacrumbs_config.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace datacrumbs {

/**
 * @brief Runtime probe state bucket keyed by scope string to function-name set.
 *
 * Example:
 * - key: "binary:/usr/lib/libc.so.6"
 * - value: {"open", "read", "write"}
 */
using RuntimeProbeScopes = std::unordered_map<std::string, std::unordered_set<std::string>>;

/**
 * @brief Manages runtime probe configuration, IDs, and runtime probe-state persistence.
 */
class RuntimeConfigurationManager {
 public:
  /**
   * @brief Default constructor is intentionally invalid for normal runtime usage.
   * @throws std::runtime_error in implementation to force explicit runtime probe path
   * initialization.
   */
  RuntimeConfigurationManager();

  /**
   * @brief Construct and initialize runtime configuration for one run.
   * @param runtime_probe_file Signed probe payload path.
   *        Example: "/tmp/datacrumbs-ci-probes.json.gz".
   * @param explicit_run_id Runtime run identifier.
   *        Example: "1".
   * @param explicit_user Runtime user used for paths/logging.
   *        Example: "runner".
   * @param print Whether to print resolved configuration to logs.
   * @throws std::runtime_error on invalid/missing configuration or probe payload problems.
   */
  explicit RuntimeConfigurationManager(const std::filesystem::path& runtime_probe_file,
                                       const std::string& explicit_run_id,
                                       const std::string& explicit_user, bool print = true);

  /**
   * @brief Print resolved runtime configuration values.
   */
  void print_configurations() const;

  /**
   * @brief Lookup runtime event id for a probe/function pair.
   * @param probe_name Probe category/group name.
   * @param function_name Function symbol name.
   * @return Event id when found, std::nullopt otherwise.
   */
  std::optional<uint64_t> get_runtime_event_id(const std::string& probe_name,
                                               const std::string& function_name) const;

  /**
   * @brief Lookup runtime metadata by event id.
   * @param event_id Runtime event identifier.
   * @return Pointer to metadata when found, nullptr otherwise.
   */
  const RuntimeEventMetadata* get_runtime_event_metadata(uint64_t event_id) const;

  /// Base data directory used for runtime state and artifacts.
  std::filesystem::path data_dir;
  /// Trace directory where runtime traces are written.
  std::filesystem::path trace_log_dir;
  /// Full path to the generated trace file for this run.
  std::filesystem::path trace_file_path;
  /// Signed probe file path used at runtime.
  std::filesystem::path probe_file_path;
  /// System configuration sqlite path (optional source for overrides).
  std::filesystem::path system_probe_path;
  /// Runtime probe-state sqlite path (invalid/successful attachment memory).
  std::filesystem::path runtime_probe_state_db_path;
  /// Runtime run directory.
  std::filesystem::path server_run_dir;
  /// File storing current run id.
  std::filesystem::path server_run_id_file;
  /// Ready file used by service supervision.
  std::filesystem::path server_ready_file;

  /// Runtime user.
  std::string user;
  /// Runtime log directory.
  std::string log_dir;
  /// Runtime hostname.
  std::string hostname;
  /// Runtime run id.
  std::string run_id;
  /// Trace directory pattern template (for example "%YY%/%MM%/%DD%").
  std::string trace_dir_pattern;
  /// Runtime inclusion paths (colon-separated).
  std::string inclusion_paths;

  /// Loaded runtime probes ready for attach.
  std::vector<std::shared_ptr<Probe>> runtime_probes;
  /// Event id to (probe_name, function_name) map.
  std::unordered_map<uint64_t, std::pair<std::string, std::string>> category_map;
  /// (probe_name, function_name) composite key to event id map.
  std::unordered_map<std::string, uint64_t> runtime_event_ids;
  /// Event id to runtime metadata map.
  std::unordered_map<uint64_t, RuntimeEventMetadata> runtime_event_metadata;
  /// Known invalid runtime probe functions grouped by probe scope.
  std::unordered_map<std::string, RuntimeProbeScopes> invalid_runtime_probes;
  /// Known successful runtime probe functions grouped by probe scope.
  std::unordered_map<std::string, RuntimeProbeScopes> successful_runtime_probes;

  /**
   * @brief Check whether a probe/function pair is known invalid from prior runs.
   * @return true when function is known invalid and not superseded by success.
   */
  bool is_known_invalid_runtime_probe(const std::shared_ptr<Probe>& probe,
                                      const std::string& function_name) const;

  /**
   * @brief Record a failed runtime probe attachment.
   */
  void record_invalid_runtime_probe(const std::shared_ptr<Probe>& probe,
                                    const std::string& function_name);

  /**
   * @brief Record a successful runtime probe attachment.
   */
  void record_successful_runtime_probe(const std::shared_ptr<Probe>& probe,
                                       const std::string& function_name);

  /**
   * @brief Persist runtime invalid/success attachment state through the manager service.
   */
  void persist_runtime_probe_state() const;

 private:
  /// Derive runtime paths and computed configuration values.
  void derive_configurations();
  /// Load runtime overrides from system configuration sqlite when available.
  void load_runtime_system_configuration();
  /// Parse and validate signed runtime probe payload.
  void load_runtime_probe_file();
  /// Load prior runtime invalid/success memory from sqlite.
  void load_runtime_probe_state();
  /// Validate runtime configuration invariants before attach.
  void validate_configurations() const;
};

}  // namespace datacrumbs

#endif
