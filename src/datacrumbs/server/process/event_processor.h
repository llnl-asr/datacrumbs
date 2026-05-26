// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_SERVER_PROCESS_DEF
#define DATACRUMBS_SERVER_PROCESS_DEF
// BPF Headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// Generated Headers
#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_config.h>
// Internal Headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/server/bpf/compat/map.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>

// std headers
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <json-c/json.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <fstream>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace datacrumbs {

/**
 * @brief Runtime event processor that decodes captured events and writes trace output.
 */
class EventProcessor {
 public:
  /**
   * @brief Construct the event processor for a signed runtime probe file.
   * @param probe_file Signed probe file path.
   *        Example: "/tmp/datacrumbs-ci-probes.json.gz".
   */
  explicit EventProcessor(const std::filesystem::path& probe_file);

  ~EventProcessor() {}

  /**
   * @brief Handle one event record from the BPF ring buffer.
   * @return 0 on success, non-zero on decode/write failure.
   */
  int handle_event(void* data, size_t data_sz);

  /**
   * @brief Update filename cache for hash-based filename events.
   * @return 0 on success.
   */
  int update_filename(const char* filename, unsigned int hash);

  /**
   * @brief Capture general counter event (currently placeholder).
   * @return Always 0 in current implementation.
   */
  int capture_general_counter(struct profile_key_t* key, struct profile_value_t* value) {
    return 0;
  }

  /**
   * @brief Capture USDT counter event (currently placeholder).
   * @return Always 0 in current implementation.
   */
  int capture_usdt_counter(struct usdt_profile_key_t* key, struct profile_value_t* value) {
    return 0;
  }

  /**
   * @brief Flush and finalize trace output.
   * @return 0 on success, non-zero on finalization error.
   */
  int finalize();

 public:
  /// Runtime configuration manager instance for this run.
  std::shared_ptr<RuntimeConfigurationManager> configManager_;
  /// Trace writer implementation.
  std::shared_ptr<datacrumbs::ChromeWriter> writer_;
  /// Count of failed event-processing operations.
  int failed_events;
  /// Monotonic event index used to order emitted events.
  std::atomic<uint64_t> event_index{0};

 private:
  /// Set of processed filename hashes to avoid duplicate filename updates.
  std::unordered_set<unsigned int> processed_hashes_;
};

}  // namespace datacrumbs

#endif
