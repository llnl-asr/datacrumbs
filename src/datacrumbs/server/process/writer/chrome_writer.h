// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// Other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/server/process/compress/zlib_compressor.h>
// std headers
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <any>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace datacrumbs {

/**
 * @brief Async writer that emits runtime events to Chrome trace format.
 */
class ChromeWriter {
 public:
  /**
   * @brief Construct writer using runtime-configured output path/compression.
   */
  ChromeWriter();

  /**
   * @brief Destructor flushes pending data and joins worker thread.
   */
  ~ChromeWriter();

  /**
   * @brief Enqueue event for background serialization.
   * @param event Heap-allocated event payload.
   */
  void push_event(EventWithId* event);

  /**
   * @brief Serialize and write one event immediately.
   * @param event_with_id Event payload including runtime event_id.
   */
  void write_event(EventWithId* event_with_id);

  /**
   * @brief Flush queued events and close output stream.
   */
  void finalize();

 private:
  /// Background consumer loop for queued events.
  void worker_loop();

  /// Tracks whether next serialized event needs comma separator handling.
  bool first_event_ = true;

  /// Serialize/flush mutex for output stream.
  std::mutex file_mutex_;

  /// Queue of pending runtime events.
  std::deque<EventWithId*> event_queue_;
  /// Queue mutex.
  std::mutex queue_mutex_;
  /// Queue wait/notify condition.
  std::condition_variable queue_cv_;
  /// Background writer thread.
  std::thread worker_;
  /// Stop request flag for worker loop.
  bool stop_flag_;
  /// Finalization state guard.
  bool finalized_;
  /// Monotonic local index for emitted events.
  unsigned long index_;
  /// Compression sink used for trace output.
  ZlibCompression* compressor_;
  /// Compression chunk size in bytes.
  size_t chunk_size_;
};

}  // namespace datacrumbs
