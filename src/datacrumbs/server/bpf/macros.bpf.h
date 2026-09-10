// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_SERVER_BPF_MACROS_BPF_H
#define DATACRUMBS_SERVER_BPF_MACROS_BPF_H

#include <datacrumbs/server/bpf/shared.h>

/**
 * @brief Macro set for defining BPF ring buffers and maps.
 */
#define DATACRUMBS_BPF_RING_BUF_1_ARGS(name) \
  struct {                                   \
    __uint(type, BPF_MAP_TYPE_RINGBUF);      \
    __uint(max_entries, 1024 * 1024);        \
  } name SEC(".maps");

#define DATACRUMBS_BPF_RING_BUF_2_ARGS(name, size) \
  struct {                                         \
    __uint(type, BPF_MAP_TYPE_RINGBUF);            \
    __uint(max_entries, size);                     \
  } name SEC(".maps");

#define GET_3TH_ARG(arg1, arg2, arg3, ...) arg3
#define DATACRUMBS_BPF_RING_BUF_MACRO_CHOOSER(...) \
  GET_3TH_ARG(__VA_ARGS__, DATACRUMBS_BPF_RING_BUF_2_ARGS, DATACRUMBS_BPF_RING_BUF_1_ARGS, )

#define DATACRUMBS_RINGBUF(...) DATACRUMBS_BPF_RING_BUF_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

/**
 * @brief Macro set for defining hash maps with optional max_entries.
 */

#define DATACRUMBS_MAP_3_ARGS(name, map_key, map_value) \
  struct {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);                    \
    __uint(max_entries, 10240);                         \
    __type(key, map_key);                               \
    __type(value, map_value);                           \
  } name SEC(".maps");

#define DATACRUMBS_MAP_4_ARGS(name, map_key, map_value, size) \
  struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                          \
    __uint(max_entries, size);                                \
    __type(key, map_key);                                     \
    __type(value, map_value);                                 \
  } name SEC(".maps");

#define GET_5TH_ARG(arg1, arg2, arg3, arg4, arg5, ...) arg5
#define DATACRUMBS_MAP_MACRO_CHOOSER(...) \
  GET_5TH_ARG(__VA_ARGS__, DATACRUMBS_MAP_4_ARGS, DATACRUMBS_MAP_3_ARGS, )

#define DATACRUMBS_MAP(...) DATACRUMBS_MAP_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

#define DATACRUMBS_TRIE_3_ARGS(name, map_key, map_value) \
  struct {                                               \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);                 \
    __uint(key_size, sizeof(map_key));                   \
    __uint(value_size, sizeof(map_value));               \
    __uint(max_entries, 10000);                          \
    __uint(pinning, LIBBPF_PIN_BY_NAME);                 \
    __uint(map_flags, BPF_F_NO_PREALLOC);                \
  } name SEC(".maps");

#define DATACRUMBS_TRIE_4_ARGS(name, map_key, map_value, size) \
  struct {                                                     \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);                       \
    __uint(max_entries, size);                                 \
    __type(key, map_key);                                      \
    __type(value, map_value);                                  \
    __uint(pinning, LIBBPF_PIN_BY_NAME);                       \
    __uint(map_flags, BPF_F_NO_PREALLOC);                      \
  } name SEC(".maps");

#define DATACRUMBS_TRIE_MACRO_CHOOSER(...) \
  GET_5TH_ARG(__VA_ARGS__, DATACRUMBS_TRIE_4_ARGS, DATACRUMBS_TRIE_3_ARGS, )

#define DATACRUMBS_TRIE(...) DATACRUMBS_TRIE_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

/**
 * @brief Macro set for declaring extern ring buffers.
 */
#define DATACRUMBS_BPF_RING_BUF_EXTERN_1_ARGS(name) \
  extern struct {                                   \
    __uint(type, BPF_MAP_TYPE_RINGBUF);             \
    __uint(max_entries, 1024 * 1024);               \
  } name SEC(".maps");
#define DATACRUMBS_BPF_RING_BUF_EXTERN_2_ARGS(name, size) \
  extern struct {                                         \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                   \
    __uint(max_entries, size);                            \
  } name SEC(".maps");

#define DATACRUMBS_BPF_RING_BUF_EXTERN_MACRO_CHOOSER(...)         \
  GET_3TH_ARG(__VA_ARGS__, DATACRUMBS_BPF_RING_BUF_EXTERN_2_ARGS, \
              DATACRUMBS_BPF_RING_BUF_EXTERN_1_ARGS, )

#define DATACRUMBS_RINGBUF_EXTERN(...) \
  DATACRUMBS_BPF_RING_BUF_EXTERN_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

/**
 * @brief Macro set for declaring extern hash maps.
 */

#define DATACRUMBS_MAP_EXTERN_3_ARGS(name, map_key, map_value) \
  extern struct {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);                           \
    __uint(max_entries, 10240);                                \
    __type(key, map_key);                                      \
    __type(value, map_value);                                  \
  } name SEC(".maps");

#define DATACRUMBS_MAP_EXTERN_4_ARGS(name, map_key, map_value, size) \
  extern struct {                                                    \
    __uint(type, BPF_MAP_TYPE_HASH);                                 \
    __uint(max_entries, size);                                       \
    __type(key, map_key);                                            \
    __type(value, map_value);                                        \
  } name SEC(".maps");

#define DATACRUMBS_MAP_EXTERN_MACRO_CHOOSER(...) \
  GET_5TH_ARG(__VA_ARGS__, DATACRUMBS_MAP_EXTERN_4_ARGS, DATACRUMBS_MAP_EXTERN_3_ARGS, )

#define DATACRUMBS_MAP_EXTERN(...) DATACRUMBS_MAP_EXTERN_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

#define DATACRUMBS_TRIE_EXTERN_3_ARGS(name, map_key, map_value) \
  __weak struct {                                               \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);                        \
    __uint(key_size, sizeof(map_key));                          \
    __uint(value_size, sizeof(map_value));                      \
    __uint(max_entries, 10000);                                 \
    __uint(map_flags, BPF_F_NO_PREALLOC);                       \
  } name SEC(".maps");

#define DATACRUMBS_TRIE_EXTERN_4_ARGS(name, map_key, map_value, size) \
  __weak struct {                                                     \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);                              \
    __uint(max_entries, size);                                        \
    __type(key, map_key);                                             \
    __type(value, map_value);                                         \
    __uint(map_flags, BPF_F_NO_PREALLOC);                             \
  } name SEC(".maps");

#define DATACRUMBS_TRIE_EXTERN_MACRO_CHOOSER(...) \
  GET_5TH_ARG(__VA_ARGS__, DATACRUMBS_TRIE_EXTERN_4_ARGS, DATACRUMBS_TRIE_EXTERN_3_ARGS, )

#define DATACRUMBS_TRIE_EXTERN(...) DATACRUMBS_TRIE_EXTERN_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

/**
 * @brief Small helper macros used by BPF templates.
 */
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#ifndef ENABLE_BPF_PRINTK
#define ENABLE_BPF_PRINTK 0
#endif

#if defined(DATACRUMBS_BPF_PRINT_ENABLE_FLAG) && (DATACRUMBS_BPF_PRINT_ENABLE_FLAG == 1)
#define DBG_PRINTK(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) \
  do {                       \
  } while (0)
#endif

#define DATACRUMBS_RB_RESERVE(name, type, event)                                                \
  event = bpf_ringbuf_reserve(&name, sizeof(type), 0);                                          \
  if (!event) {                                                                                 \
    u32 failed_count = mark_failed_events();                                                    \
    (void)failed_count;                                                                         \
    DBG_PRINTK("Failed to reserve %d events space for event:%llu in ring buffer", failed_count, \
               event_id);                                                                       \
    return 0;                                                                                   \
  }

#define DATACRUMBS_SKIP_SMALL_EVENTS(fn, te)                                                     \
  if (te - fn->ts <                                                                              \
      DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS) { /* Skip events with duration less than 1ms */ \
    DBG_PRINTK("Skipping small event with duration %llu ns", te - fn->ts);                       \
    return 0;                                                                                    \
  }

#define DATACRUMBS_COLLECT_TIME(event) \
  event->ts = fn->ts;                  \
  event->dur = (te - fn->ts);

#define DATACRUMBS_EVENT_SUBMIT(event, pid_tgid, event_id) \
  bpf_ringbuf_submit(event, 0);                            \
  DBG_PRINTK("Pushed pid:%d, event_id:%llu to output\n", (u32)pid_tgid, event_id);

#endif  // DATACRUMBS_SERVER_BPF_MACROS_BPF_H