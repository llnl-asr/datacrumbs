// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once

// BPF Headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// other headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>  // Logging header
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>
// std headers
#include <errno.h>
#include <grp.h>
#include <json-c/json.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define GET_DATA_3_EXISTS

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 2)
#define INITIALIZE_MAP_3()                                          \
  int profile_3_fd = bpf_map__fd(skel->maps.usdt_profile);          \
  if (profile_3_fd < 0) {                                           \
    DC_LOG_ERROR("Failed to get profile map fd: %d", profile_3_fd); \
    datacrumbs_bpf__destroy(skel);                                  \
    return 1;                                                       \
  }

#define INITIALIZE_MAP_LOOKUP_3()                                                         \
  struct usdt_profile_key_t* usdt_keys =                                                  \
      (struct usdt_profile_key_t*)malloc(batch_size * sizeof(struct usdt_profile_key_t)); \
  struct profile_value_t* usdt_values =                                                   \
      (struct profile_value_t*)malloc(batch_size * sizeof(struct profile_value_t));       \
  struct usdt_profile_key_t* usdt_in_batch = nullptr;

#define LOOKUP_3_CALL()                                                                   \
  lookup_3(profile_3_fd, latest_ts, &event_processor, batch_size, usdt_keys, usdt_values, \
           usdt_in_batch)

inline static int lookup_3(int map_fd, unsigned long long latest_timestamp,
                           datacrumbs::EventProcessor* event_processor, unsigned int batch_size,
                           struct usdt_profile_key_t* keys, struct profile_value_t* values,
                           struct usdt_profile_key_t* in_batch) {
  // Batch-read USDT profiler map entries, emit events, then remove processed keys.
  int ret = bpf_map_lookup_batch(map_fd, in_batch, &in_batch, keys, values, &batch_size, 0);
  if (ret < 0 && errno != ENOENT) {
    perror("bpf_map_lookup_batch usdt");
    return -1;
  }
  if (batch_size < 1) {
    return -1;
  }
  struct usdt_profile_key_t delete_keys[batch_size];
  unsigned int j = 0;
  // Process the retrieved keys and values
  for (int i = 0; i < batch_size; ++i) {
    if (latest_timestamp == 0 || keys[i].time_interval <= latest_timestamp) {
      struct usdt_counter_event_t event;
      event.key = &keys[i];
      event.value = &values[i];
      event_processor->handle_event(&event, 1024);
      delete_keys[j++] = keys[i];
    }
  }
  ret = bpf_map_delete_batch(map_fd, delete_keys, &j, NULL);
  if (ret < 0) {
    perror("bpf_map_delete_batch usdt");
  }
  // Check if the end of the map has been reached
  if (ret < 0 && errno == ENOENT) {
    return -1;
  }
  return 0;
}
#endif

/**
 * @brief Convert raw USDT payload into EventWithId wrapper.
 * @param data Raw USDT event payload.
 * @param index Monotonic event index.
 * @return Newly allocated EventWithId.
 */
static datacrumbs::EventWithId* get_data_3(void* data, uint64_t index) {
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  struct usdt_event_t* base = (usdt_event_t*)data;
  auto event = new datacrumbs::EventWithId(NORMAL_EVENT, index, base->type, base->id,
                                           base->event_id, base->ts, base->dur, nullptr);
#else
  struct usdt_counter_event_t* base = (usdt_counter_event_t*)data;
  auto args = new DataCrumbsArgs();
  args->emplace("duration", base->value->duration);
  args->emplace("frequency", base->value->frequency);
  args->emplace("clazz", base->key->class_hash);
  args->emplace("method", base->key->method_hash);
  auto event = new datacrumbs::EventWithId(COUNTER_EVENT, index, base->key->type, base->key->id,
                                           base->key->event_id, base->key->time_interval, 0, args);
#endif
  return event;
}
