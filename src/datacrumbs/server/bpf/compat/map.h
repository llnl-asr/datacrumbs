// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_SERVER_BPF_COMPAT_H
#define DATACRUMBS_SERVER_BPF_COMPAT_H
// Configuration
#include <datacrumbs/datacrumbs_config.h>

// header

#include <bpf/bpf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if DATACRUMBS_KERNEL_GET_VERSION(5, 6, 0) > DATACRUMBS_KERNEL_VERSION

/* Forward declaration for the batch options struct. */
struct bpf_map_batch_opts;

/**
 * @brief Compatibility implementation of lookup-and-delete batch map API.
 * @return 1 when batch filled and more entries may remain, -1 on ENOENT/end or error.
 */
inline static int bpf_map_lookup_and_delete_batch_compat(int fd, void* in_batch, void* out_batch,
                                                         void* keys, void* values,
                                                         unsigned int* count,
                                                         const struct bpf_map_batch_opts* opts) {
  // The older syscalls don't support batch options, so this is unused.
  (void)opts;

  unsigned int num_to_process = *count;
  unsigned int processed = 0;
  void* current_key = in_batch;
  void* key_ptr = keys;
  void* value_ptr = values;

  if (!count || !keys || !values) {
    errno = EINVAL;
    *count = 0;
    return -1;
  }

  // Get the map info to determine key and value sizes
  struct bpf_map_info info;
  unsigned int info_len = sizeof(info);
  if (bpf_map_get_info_by_fd(fd, &info, &info_len)) {
    *count = 0;
    return -1;
  }

  // Loop through the map to find, get, and delete elements
  while (processed < num_to_process) {
    void* next_key_storage = NULL;
    void* next_key = NULL;

    // bpf_map_get_next_key requires a non-const key pointer
    if (current_key) {
      next_key_storage = malloc(info.key_size);
      if (!next_key_storage) {
        errno = ENOMEM;
        *count = processed;
        return -1;
      }
      memcpy(next_key_storage, current_key, info.key_size);
    }

    if (bpf_map_get_next_key(fd, next_key_storage, &next_key)) {
      if (next_key_storage) free(next_key_storage);
      if (errno == ENOENT) {
        // End of map, cleanup and set the return count
        *count = processed;
        errno = ENOENT;
        return -1;  // Return -1 for success/end-of-map
      }
      // Other error
      *count = processed;
      return -1;
    }

    if (next_key_storage) free(next_key_storage);

    // Lookup the element and copy its value
    if (bpf_map_lookup_elem(fd, next_key, value_ptr)) {
      // Element may have been deleted by another process; continue
      continue;
    }

    // Copy key and value to output arrays
    memcpy(key_ptr, next_key, info.key_size);
    key_ptr += info.key_size;
    value_ptr += info.value_size;

    // Delete the element
    bpf_map_delete_elem(fd, next_key);

    current_key = next_key;
    processed++;
  }

  *count = processed;

  if (out_batch && processed > 0) {
    // Set out_batch to the last key processed to enable further batches
    memcpy(out_batch, current_key, info.key_size);
    // We've processed the full batch, so more elements might be available
    return 1;
  } else {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

/**
 * @brief Compatibility implementation of lookup batch map API.
 * @return 1 when batch filled and more entries may remain, -1 on ENOENT/end or error.
 */
inline static int bpf_map_lookup_batch_compat(int fd, void* in_batch, void* out_batch, void* keys,
                                              void* values, unsigned int* count,
                                              const struct bpf_map_batch_opts* opts) {
  // The older syscalls don't support batch options, so this is unused.
  (void)opts;

  unsigned int num_to_process;
  unsigned int processed = 0;
  void* current_key;
  void* key_ptr = keys;
  void* value_ptr = values;
  struct bpf_map_info info;
  unsigned int info_len = sizeof(info);
  void* next_key_storage = NULL;

  if (!count || !keys || !values) {
    errno = EINVAL;
    if (count) *count = 0;
    return -1;
  }

  num_to_process = *count;

  // Get the map info to determine key and value sizes
  if (bpf_map_get_info_by_fd(fd, &info, &info_len)) {
    *count = 0;
    return -1;
  }

  // Allocate storage for next key for safe iteration
  next_key_storage = malloc(info.key_size);
  if (!next_key_storage) {
    errno = ENOMEM;
    *count = 0;
    return -1;
  }

  current_key = in_batch;

  // Loop through the map to find and get elements
  while (processed < num_to_process) {
    void* next_key_out = NULL;

    if (bpf_map_get_next_key(fd, current_key, next_key_storage)) {
      if (errno == ENOENT) {
        // End of map, cleanup and set the return count
        *count = processed;
        free(next_key_storage);
        if (out_batch && processed > 0) {
          memcpy(out_batch, current_key, info.key_size);
        }
        errno = ENOENT;
        return -1;  // Return 0 for success/end-of-map
      }
      // Other error
      *count = processed;
      free(next_key_storage);
      return -1;
    }

    next_key_out = next_key_storage;

    // Lookup the element and copy its value
    if (bpf_map_lookup_elem(fd, next_key_out, value_ptr)) {
      // Element may have been deleted by another process; continue
      current_key = next_key_out;
      continue;
    }

    // Copy key and value to output arrays
    memcpy(key_ptr, next_key_out, info.key_size);

    key_ptr = (char*)key_ptr + info.key_size;
    value_ptr = (char*)value_ptr + info.value_size;

    current_key = next_key_out;
    processed++;
  }

  *count = processed;

  if (out_batch && processed > 0) {
    // Set out_batch to the last key processed to enable further batches
    memcpy(out_batch, current_key, info.key_size);
    // We've processed the full batch, so more elements might be available
    free(next_key_storage);
    return 1;
  } else {
    errno = ENOENT;
    return -1;
  }

  free(next_key_storage);
  return 0;
}
#else
#define bpf_map_lookup_and_delete_batch_compat bpf_map_lookup_and_delete_batch
#define bpf_map_lookup_batch_compat bpf_map_lookup_batch
#endif

#endif