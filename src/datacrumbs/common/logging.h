// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once

#include <datacrumbs/datacrumbs_config.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#define LOG_LEVEL_PRINT 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_TRACE 5

namespace datacrumbs::logging_internal {

/// Default interval for progress status emission.
inline constexpr std::chrono::seconds kDefaultProgressLogInterval{5};

/**
 * @brief Mutable per-key progress bookkeeping state.
 */
struct ProgressState {
  /// First observation timestamp for this progress key.
  std::chrono::steady_clock::time_point start_time;
  /// Last time a progress line was emitted.
  std::chrono::steady_clock::time_point last_emit_time;
  /// Last seen numeric value.
  size_t last_value = 0;
  /// Whether state has been initialized.
  bool initialized = false;
};

/**
 * @brief Snapshot returned from state update to decide whether to emit logs.
 */
struct ProgressSnapshot {
  /// Whether caller should emit a progress line.
  bool should_emit = false;
  /// Time elapsed since the tracked operation started.
  std::chrono::duration<double> elapsed{0.0};
  /// Average processing rate.
  double rate = 0.0;
};

/**
 * @brief Resolve output stream for logging.
 * @return FILE handle for active sink.
 */
inline FILE* get_log_file() {
#ifdef LOG_TO_FILE
  static FILE* file = std::fopen(LOG_FILE_PATH, "a");
  return file;
#else
  return stdout;
#endif
}

inline std::mutex& get_log_mutex() {
  static std::mutex mtx;
  return mtx;
}

inline std::mutex& get_progress_mutex() {
  static std::mutex mtx;
  return mtx;
}

inline std::unordered_map<std::string, ProgressState>& get_progress_states() {
  static std::unordered_map<std::string, ProgressState> states;
  return states;
}

inline std::string format_message(const char* fmt, va_list args) {
  va_list args_copy;
  va_copy(args_copy, args);
  const int required = std::vsnprintf(nullptr, 0, fmt, args_copy);
  va_end(args_copy);

  if (required <= 0) {
    return {};
  }

  std::vector<char> buffer(static_cast<size_t>(required) + 1);
  std::vsnprintf(buffer.data(), buffer.size(), fmt, args);
  return std::string(buffer.data(), static_cast<size_t>(required));
}

inline void write_log_line(const char* level, const std::string& message) {
  std::lock_guard<std::mutex> lock(get_log_mutex());
  FILE* out = get_log_file();
  std::fprintf(out, "[%s] %s\n", level, message.c_str());
  std::fflush(out);
}

inline void write_log_fragment(const std::string& message) {
  std::lock_guard<std::mutex> lock(get_log_mutex());
  FILE* out = get_log_file();
  std::fputs(message.c_str(), out);
  std::fflush(out);
}

inline void log_message_fmt(const char* level, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const std::string message = format_message(fmt, args);
  va_end(args);
  write_log_line(level, message);
}

inline void log_message_fmt_no_new_line(const char* /*level*/, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const std::string message = format_message(fmt, args);
  va_end(args);
  write_log_fragment(message);
}

template <typename... Args>
inline void log_message(const char* level, const char* fmt, Args&&... args) {
  log_message_fmt(level, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_message_no_new_line(const char* level, const char* fmt, Args&&... args) {
  log_message_fmt_no_new_line(level, fmt, std::forward<Args>(args)...);
}

inline std::string format_compact_count(double value) {
  const char* suffix = "";
  if (value >= 1e9) {
    value /= 1e9;
    suffix = "G";
  } else if (value >= 1e6) {
    value /= 1e6;
    suffix = "M";
  } else if (value >= 1e3) {
    value /= 1e3;
    suffix = "K";
  }

  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%.2f%s", value, suffix);
  std::string result(buffer);
  if (const auto dot = result.find('.'); dot != std::string::npos) {
    while (!result.empty() && result.back() == '0') {
      result.pop_back();
    }
    if (!result.empty() && result.back() == '.') {
      result.pop_back();
    }
  }
  return result;
}

/**
 * @brief Render an elapsed duration as "1h 2m 3s", "2m 3s" or "3.21s".
 *
 * Units are split with duration_cast rather than by dividing a seconds count,
 * so the conversion factors are supplied and checked by the type system instead
 * of appearing as literals. duration_cast truncates toward zero, which is what
 * the whole-unit fields want.
 *
 * @param elapsed Duration to render. Example: 90s renders as "1m 30s".
 * @return Formatted duration string.
 */
inline std::string format_elapsed(std::chrono::duration<double> elapsed) {
  char buffer[64];
  const auto hours = std::chrono::duration_cast<std::chrono::hours>(elapsed);
  const auto minutes = std::chrono::duration_cast<std::chrono::minutes>(elapsed - hours);
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed - hours - minutes);

  if (hours.count() > 0) {
    std::snprintf(buffer, sizeof(buffer), "%lldh %lldm %llds",
                  static_cast<long long>(hours.count()), static_cast<long long>(minutes.count()),
                  static_cast<long long>(seconds.count()));
  } else if (minutes.count() > 0) {
    std::snprintf(buffer, sizeof(buffer), "%lldm %llds", static_cast<long long>(minutes.count()),
                  static_cast<long long>(seconds.count()));
  } else {
    std::snprintf(buffer, sizeof(buffer), "%.2fs", elapsed.count());
  }
  return buffer;
}

inline ProgressSnapshot update_progress_state(const std::string& key, size_t current,
                                              std::chrono::steady_clock::duration min_interval,
                                              bool completed) {
  using clock = std::chrono::steady_clock;

  const auto now = clock::now();
  std::lock_guard<std::mutex> lock(get_progress_mutex());
  auto& states = get_progress_states();
  auto& state = states[key];

  if (!state.initialized || current < state.last_value) {
    state.start_time = now;
    state.last_emit_time = now;
    state.last_value = 0;
    state.initialized = true;
  }

  if (!completed && (now - state.last_emit_time) < min_interval) {
    state.last_value = current;
    return {};
  }

  ProgressSnapshot snapshot;
  snapshot.should_emit = true;
  snapshot.elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(
      now - state.start_time);
  snapshot.rate = snapshot.elapsed.count() > 0.0
                      ? static_cast<double>(current) / snapshot.elapsed.count()
                      : 0.0;

  if (completed) {
    states.erase(key);
  } else {
    state.last_emit_time = now;
    state.last_value = current;
  }

  return snapshot;
}

inline void emit_progress_line(const std::string& message) {
#ifdef LOG_TO_FILE
  write_log_line("PRINT", message);
#else
  write_log_fragment("\r" + message);
#endif
}

inline void finish_console_progress_line() {
#ifndef LOG_TO_FILE
  write_log_line("PRINT", "");
#endif
}

/**
 * @brief Emit aggregated progress information with total count.
 * @param message Progress message key.
 * @param current Current completed count.
 * @param total Total expected count.
 * @param min_interval Minimum time between emissions.
 */
inline void log_progress(
    const std::string& message, size_t current, size_t total,
    std::chrono::steady_clock::duration min_interval = kDefaultProgressLogInterval) {
  const bool completed = total > 0 && current >= total;
  const ProgressSnapshot snapshot =
      update_progress_state(message, current, min_interval, completed);
  if (!snapshot.should_emit) {
    return;
  }

  const double percent =
      total > 0 ? (100.0 * static_cast<double>(current) / static_cast<double>(total)) : 0.0;
  const std::string line = message + " [" + std::to_string(current) + "/" + std::to_string(total) +
                           "] " + std::to_string(static_cast<int>(percent)) + "% completed | " +
                           format_elapsed(snapshot.elapsed) + " elapsed | " +
                           format_compact_count(snapshot.rate) + " events/s";
  emit_progress_line(line);

  if (completed) {
    finish_console_progress_line();
    write_log_line("PRINT", message +
                                " done. Total time: " + format_elapsed(snapshot.elapsed) +
                                ", Avg rate: " + format_compact_count(snapshot.rate) + " events/s");
  }
}

/**
 * @brief Emit open-ended progress information without total.
 * @param message Progress message key.
 * @param current Current processed count.
 * @param min_interval Minimum time between emissions.
 */
inline void log_progress(
    const std::string& message, size_t current,
    std::chrono::steady_clock::duration min_interval = kDefaultProgressLogInterval) {
  const ProgressSnapshot snapshot = update_progress_state(message, current, min_interval, false);
  if (!snapshot.should_emit) {
    return;
  }

  const std::string line = message + " [" + format_compact_count(static_cast<double>(current)) +
                           " events] | " + format_elapsed(snapshot.elapsed) +
                           " elapsed | " + format_compact_count(snapshot.rate) + " events/s";
  emit_progress_line(line);
}

}  // namespace datacrumbs::logging_internal

#define DC_LOG_PRINT(...) datacrumbs::logging_internal::log_message("PRINT", __VA_ARGS__)
#define DC_LOG_PRINT_NO_NEW_LINE(...) \
  datacrumbs::logging_internal::log_message_no_new_line("PRINT", __VA_ARGS__)

#if DATACRUMBS_LOG_LEVEL >= LOG_LEVEL_ERROR
#define DC_LOG_ERROR(...) datacrumbs::logging_internal::log_message("ERROR", __VA_ARGS__)
#else
#define DC_LOG_ERROR(...) (void)0
#endif

#if DATACRUMBS_LOG_LEVEL >= LOG_LEVEL_WARN
#define DC_LOG_WARN(...) datacrumbs::logging_internal::log_message("WARN", __VA_ARGS__)
#else
#define DC_LOG_WARN(...) (void)0
#endif

#if DATACRUMBS_LOG_LEVEL >= LOG_LEVEL_INFO
#define DC_LOG_INFO(...) datacrumbs::logging_internal::log_message("INFO", __VA_ARGS__)
#else
#define DC_LOG_INFO(...) (void)0
#endif

#if DATACRUMBS_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define DC_LOG_DEBUG(...) datacrumbs::logging_internal::log_message("DEBUG", __VA_ARGS__)
#else
#define DC_LOG_DEBUG(...) (void)0
#endif

#if DATACRUMBS_LOG_LEVEL >= LOG_LEVEL_TRACE
#define DC_LOG_TRACE(...) datacrumbs::logging_internal::log_message("TRACE", __VA_ARGS__)
#else
#define DC_LOG_TRACE(...) (void)0
#endif

#define DC_LOG_PROGRESS(message, current, total) \
  DC_LOG_PROGRESS_THROTTLED(message, current, total, 5)

#define DC_LOG_PROGRESS_SINGLE(message, current) \
  DC_LOG_PROGRESS_SINGLE_THROTTLED(message, current, 5)

#define DC_LOG_PROGRESS_THROTTLED(message, current, total, interval_seconds) \
  datacrumbs::logging_internal::log_progress(                                \
      message, current, total, std::chrono::seconds(static_cast<long long>(interval_seconds)))

#define DC_LOG_PROGRESS_SINGLE_THROTTLED(message, current, interval_seconds) \
  datacrumbs::logging_internal::log_progress(                                \
      message, current, std::chrono::seconds(static_cast<long long>(interval_seconds)))
