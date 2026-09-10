// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_ENUMERATIONS_H__
#define DATACRUMBS_COMMON_ENUMERATIONS_H__

// include first
#include <datacrumbs/datacrumbs_config.h>
// other headers
#include "datacrumbs/common/logging.h"

// std headers
#include <stdexcept>
#include <string>

namespace datacrumbs {

/**
 * @brief Runtime operating mode.
 */
enum class Mode : uint8_t {
  PROFILER = 0,
  TRACER = 1,
};

/**
 * @brief Convert mode string to enum value.
 * @param s Mode string.
 *        Example: "profiler" or "tracer".
 * @param type Output enum value.
 * @throws std::invalid_argument for unknown mode string.
 */
inline void convert(const std::string& s, Mode& type) {
  DC_LOG_TRACE("Entering convert for Mode with input: %s", s.c_str());
  if (s == "profiler") {
    type = Mode::PROFILER;
    DC_LOG_DEBUG("Converted string '%s' to Mode::PROFILER", s.c_str());
  } else if (s == "tracer") {
    type = Mode::TRACER;
    DC_LOG_DEBUG("Converted string '%s' to Mode::TRACER", s.c_str());
  } else {
    DC_LOG_ERROR("Unknown Mode string: '%s'", s.c_str());
    throw std::invalid_argument("Unknown Mode: " + s + ". Valid types are: profiler or tracer.");
  }
  DC_LOG_TRACE("Exiting convert for Mode");
}

/**
 * @brief Probe types supported by datacrumbs runtime.
 */
enum class ProbeType : uint8_t {
  SYSCALLS = 0,
  KPROBE = 1,
  UPROBE = 2,
  USDT = 3,
  CUSTOM = 4,
};

/**
 * @brief Convert probe type string to enum.
 * @param s Probe type string.
 *        Example: "syscalls", "kprobe", "uprobe", "usdt", "custom".
 * @param type Output enum value.
 * @throws std::invalid_argument for unknown probe type.
 */
inline void convert(const std::string& s, ProbeType& type) {
  DC_LOG_TRACE("Entering convert for ProbeType with input: %s", s.c_str());
  if (s == "syscalls") {
    type = ProbeType::SYSCALLS;
    DC_LOG_DEBUG("Converted string '%s' to ProbeType::SYSCALLS", s.c_str());
  } else if (s == "kprobe") {
    type = ProbeType::KPROBE;
    DC_LOG_DEBUG("Converted string '%s' to ProbeType::KPROBE", s.c_str());
  } else if (s == "uprobe") {
    type = ProbeType::UPROBE;
    DC_LOG_DEBUG("Converted string '%s' to ProbeType::UPROBE", s.c_str());
  } else if (s == "usdt") {
    type = ProbeType::USDT;
    DC_LOG_DEBUG("Converted string '%s' to ProbeType::USDT", s.c_str());
  } else if (s == "custom") {
    type = ProbeType::CUSTOM;
    DC_LOG_DEBUG("Converted string '%s' to ProbeType::CUSTOM", s.c_str());
  } else {
    DC_LOG_INFO("Unknown ProbeType string: '%s'", s.c_str());
    throw std::invalid_argument("Unknown ProbeType: " + s +
                                ". Valid types are: syscalls, kprobe, uprobe, or usdt.");
  }
  DC_LOG_TRACE("Exiting convert for ProbeType");
}

/**
 * @brief Capture-source types used by probe explorer.
 */
enum class CaptureType : uint8_t {
  HEADER = 0,
  BINARY = 1,
  KSYM = 2,
  USDT = 3,
  CUSTOM = 4,  // Custom capture type for user-defined probes
};

/**
 * @brief Convert capture type string to enum.
 * @param s Capture type string.
 *        Example: "header", "binary", "ksym", "usdt", "custom".
 * @param type Output enum value.
 * @throws std::invalid_argument for unknown capture type.
 */
inline void convert(const std::string& s, CaptureType& type) {
  DC_LOG_TRACE("Entering convert for CaptureType with input: %s", s.c_str());
  if (s == "header") {
    type = CaptureType::HEADER;
    DC_LOG_DEBUG("Converted string '%s' to CaptureType::HEADER", s.c_str());
  } else if (s == "binary") {
    type = CaptureType::BINARY;
    DC_LOG_DEBUG("Converted string '%s' to CaptureType::BINARY", s.c_str());
  } else if (s == "ksym") {
    type = CaptureType::KSYM;
    DC_LOG_DEBUG("Converted string '%s' to CaptureType::KSYM", s.c_str());
  } else if (s == "usdt") {
    type = CaptureType::USDT;
    DC_LOG_DEBUG("Converted string '%s' to CaptureType::USDT", s.c_str());
  } else if (s == "custom") {
    type = CaptureType::CUSTOM;
    DC_LOG_DEBUG("Converted string '%s' to CaptureType::CUSTOM", s.c_str());
  } else {
    DC_LOG_INFO("Unknown CaptureType string: '%s'", s.c_str());
    throw std::invalid_argument("Unknown CaptureType: " + s +
                                ". Valid types are: header, binary, ksym, usdt, or custom.");
  }
  DC_LOG_TRACE("Exiting convert for CaptureType");
}

}  // namespace datacrumbs

#endif  // DATACRUMBS_COMMON_ENUMERATIONS_H__
