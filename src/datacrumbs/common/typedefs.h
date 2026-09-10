// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_config.h>
// std headers
#include <any>
#include <string>
#include <unordered_map>
#include <vector>

/**
 * @brief Captured raw argument payload for runtime event export.
 */
struct CapturedArgumentValue {
  /// Captured C/C++ type name as configured.
  std::string c_type;
  /// Whether raw_value represents a pointer value.
  bool is_pointer = false;
  /// Raw register/argument value from event payload.
  unsigned long long raw_value = 0;
  /// Capture status code from runtime/BPF layer.
  unsigned int data_status = 0;
  /// Optional captured bytes when pointer dereference capture succeeds.
  std::vector<unsigned char> bytes;
};

/// Generic event argument map used by event writers.
typedef std::unordered_map<std::string, std::any> DataCrumbsArgs;
