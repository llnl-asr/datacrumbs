// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_SERVER_BPF_SHARED_H
#define DATACRUMBS_SERVER_BPF_SHARED_H

#include <custom_probes_process.h>
#include <datacrumbs/datacrumbs_config.h>

/// Runtime key for tracking timestamp map entries.
static int DATACRUMBS_TS_KEY = 1;
/// Runtime key for failed event accounting.
static int DATACRUMBS_FAILED_EVENTS_KEY = 2;

#define DATACRUMBS_MAX_CAPTURE_ARGS 5
#define DATACRUMBS_MAX_CAPTURE_BYTES 64

/**
 * @brief Runtime probe kinds used in event configuration maps.
 */
enum datacrumbs_runtime_probe_kind_t {
  DATACRUMBS_RUNTIME_PROBE_KIND_KPROBE = 1,
  DATACRUMBS_RUNTIME_PROBE_KIND_UPROBE = 2,
  DATACRUMBS_RUNTIME_PROBE_KIND_SYSCALL = 3,
  DATACRUMBS_RUNTIME_PROBE_KIND_USDT = 4,
};

/**
 * @brief Generic event payload emitted from BPF to userspace.
 */
struct generic_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned int arg_count;
  unsigned long long args[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned char arg_data[DATACRUMBS_MAX_CAPTURE_ARGS][DATACRUMBS_MAX_CAPTURE_BYTES];
  /// USDT class-name hash; zero for probe kinds that do not resolve a class.
  unsigned int class_hash;
  /// USDT method-name hash; zero for probe kinds that do not resolve a method.
  unsigned int method_hash;
};
typedef struct generic_event_t general_event_t;
/**
 * @brief USDT-specific event payload emitted from BPF to userspace.
 */
struct usdt_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
};

/// Fixed-size string read buffer used in BPF structs.
#define MAX_STR_READ_LEN 256

/**
 * @brief Composite key identifying a runtime function event.
 */
struct fn_key_t {
  unsigned long long id;
  unsigned long long event_id;
};

/**
 * @brief Temporary per-call state stored in BPF maps.
 */
struct fn_value_t {
  unsigned long long ts;
  unsigned int arg_count;
  unsigned long long args[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned char arg_data[DATACRUMBS_MAX_CAPTURE_ARGS][DATACRUMBS_MAX_CAPTURE_BYTES];
};

/**
 * @brief Runtime argument-capture configuration for one event id.
 */
struct runtime_event_config_t {
  unsigned long long event_id;
  unsigned int probe_kind;
  unsigned int arg_count;
  unsigned int arg_index[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_num_bytes[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_is_pointer[DATACRUMBS_MAX_CAPTURE_ARGS];
};

/**
 * @brief Convenience key/value pair wrapper for function maps.
 */
struct fn_t {
  struct fn_key_t key;
  struct fn_value_t value;
};

/**
 * @brief Fixed-size string object used in BPF map keys/values.
 */
struct string_t {
  unsigned int len;
  char str[MAX_STR_READ_LEN];
};

/**
 * @brief Key for general profiling counters.
 */
struct profile_key_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long time_interval;
};

/**
 * @brief Value for general profiling counters.
 */
struct profile_value_t {
  unsigned long long duration;
  unsigned long long frequency;
};

/**
 * @brief Key for USDT profiling counters.
 */
struct usdt_profile_key_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long time_interval;
  unsigned int class_hash;
  unsigned int method_hash;
};

/**
 * @brief Wrapper pairing general profile key/value pointers for processing.
 */
struct counter_event_t {
  struct profile_key_t* key;
  struct profile_value_t* value;
};

/**
 * @brief Wrapper pairing USDT profile key/value pointers for processing.
 */
struct usdt_counter_event_t {
  struct usdt_profile_key_t* key;
  struct profile_value_t* value;
};

#endif  // DATACRUMBS_SERVER_BPF_SHARED_H
