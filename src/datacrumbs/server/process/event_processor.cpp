
// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/server/process/event_processor.h>
// other headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>
//
#include <datacrumbs/server/process/processing/general_event.h>
#include <datacrumbs/server/process/processing/usdt_event.h>
// Include generated
#include <datacrumbs/datacrumbs_config.h>
// dependency headers
#include <json-c/json.h>

// std headers
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

#define GET_DATA_FUNCTION(INDEX)                                       \
  auto write_event = get_data_##INDEX(data, event_index.fetch_add(1)); \
  if (write_event != nullptr) {                                        \
    writer->push_event(write_event);                                   \
  }

namespace datacrumbs {

namespace {

bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}

std::unique_ptr<DataCrumbsArgs> build_runtime_args(
    const generic_event_t* event, const datacrumbs::RuntimeEventMetadata* metadata) {
  if (event == nullptr || metadata == nullptr || metadata->arg_specs.empty()) {
    return nullptr;
  }

  // Build named argument map using capture metadata so writer can serialize rich values.
  auto args = std::make_unique<DataCrumbsArgs>();
  const unsigned int arg_count =
      std::min<unsigned int>(event->arg_count, metadata->arg_specs.size());
  for (unsigned int index = 0; index < arg_count; ++index) {
    const auto& spec = metadata->arg_specs[index];
    CapturedArgumentValue value;
    value.c_type = spec.c_type;
    value.is_pointer = spec.is_pointer;
    value.raw_value = event->args[index];
    value.data_status = event->arg_data_status[index];
    const unsigned int data_len = std::min<unsigned int>(
        event->arg_data_len[index],
        is_char_pointer_type(spec.c_type) ? DATACRUMBS_MAX_CAPTURE_BYTES : 8U);
    value.bytes.assign(event->arg_data[index], event->arg_data[index] + data_len);

    std::string label = spec.label.empty() ? ("arg" + std::to_string(index + 1)) : spec.label;
    args->emplace(std::move(label), std::move(value));
  }
  return args;
}

}  // namespace

EventProcessor::EventProcessor(const std::filesystem::path& probe_file) {
  (void)probe_file;
  configManager_ = datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  writer_ = datacrumbs::Singleton<datacrumbs::ChromeWriter>::get_instance();
  if (!writer_) {
    DC_LOG_ERROR("Failed to create ChromeWriter instance");
  }
  failed_events = 0;
}

int EventProcessor::handle_event(void* data, size_t data_sz) {
  DC_LOG_TRACE("handle_event: start");

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  struct generic_event_t* event = (generic_event_t*)data;
#else
  struct profile_key_t* event = (profile_key_t*)((counter_event_t*)data)->key;
#endif
  unsigned int pid = event->id;

  // Skip empty identity payloads to avoid emitting malformed trace entries.
  if (pid == 0) {
    DC_LOG_DEBUG("handle_event: pid is 0, skipping event");
    return 0;
  }
  auto it = configManager_->category_map.find(event->event_id);
  if (it != configManager_->category_map.end()) {
    const auto& [probe_name, function_name] = it->second;
    // Print event info to stdout for debugging
    DC_LOG_DEBUG("%-6u  %-6llu  %s.%s", pid, event->event_id, probe_name.c_str(),
                 function_name.c_str());
    // Resolve writer instance and route event to the appropriate payload converter.
    auto writer = datacrumbs::Singleton<datacrumbs::ChromeWriter>::get_instance();
    if (!writer) {
      DC_LOG_ERROR("Failed to create ChromeWriter instance");
      return 1;
    }
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
    auto metadata = configManager_->get_runtime_event_metadata(event->event_id);
    auto runtime_args = build_runtime_args(event, metadata);
    auto write_event =
        new datacrumbs::EventWithId(NORMAL_EVENT, event_index.fetch_add(1), event->type, event->id,
                                    event->event_id, event->ts, event->dur, runtime_args.release());
    writer->push_event(write_event);
#else
    if (event->type > 0) {
      if (event->type == 1) {
        GET_DATA_FUNCTION(1);
      }
#ifdef GET_DATA_2_EXISTS
      else if (event->type == 2) {
        GET_DATA_FUNCTION(2);
      }
#endif
#ifdef GET_DATA_3_EXISTS
      else if (event->type == 3) {
        GET_DATA_FUNCTION(3);
      }
#endif
#ifdef GET_DATA_4_EXISTS
      else if (event->type == 4) {
        GET_DATA_FUNCTION(4);
      }
#endif
#ifdef GET_DATA_5_EXISTS
      else if (event->type == 5) {
        GET_DATA_FUNCTION(5);
      }
#endif
#ifdef GET_DATA_6_EXISTS
      else if (event->type == 6) {
        GET_DATA_FUNCTION(6);
      }
#endif
#ifdef GET_DATA_7_EXISTS
      else if (event->type == 7) {
        GET_DATA_FUNCTION(7);
      }
#endif
#ifdef GET_DATA_8_EXISTS
      else if (event->type == 8) {
        GET_DATA_FUNCTION(8);
      }
#endif
#ifdef GET_DATA_9_EXISTS
      else if (event->type == 9) {
        GET_DATA_FUNCTION(9);
      }
#endif
#ifdef GET_DATA_10_EXISTS
      else if (event->type == 10) {
        GET_DATA_FUNCTION(10);
      }
#endif
      else {
        DC_LOG_WARN("Unknown event type: %u, skipping event", event->type);
        return 0;
      }
    } else {
      DC_LOG_WARN("Event type is not positive, skipping event");
      return 0;
    }
#endif
  } else {
    // If no category found, print warning
    DC_LOG_WARN("No category found for event_id %llu", event->event_id);
  }
  DC_LOG_TRACE("handle_event: end");
  // std::string progress_msg =
  //     "Processed events failed: " + std::to_string(failed_events) + " current:";
  // if (configManager_->mpi_rank == 0) DC_LOG_PROGRESS_SINGLE_THROTTLED(progress_msg.c_str(),
  // event_index, 5);
  return 0;
}
int EventProcessor::update_filename(const char* filename, unsigned int hash) {
  // De-duplicate filename metadata records by hash to reduce trace noise and size.
  if (processed_hashes_.find(hash) != processed_hashes_.end()) {
    DC_LOG_DEBUG("Filename %s with hash %u already processed, skipping", filename, hash);
    return 0;  // Skip if already processed
  }
  auto file_str = utils::remove_non_utf8(filename);

  processed_hashes_.insert(hash);  // Mark this hash as processed
  auto args = new DataCrumbsArgs();
  args->emplace("value", file_str);
  args->emplace("hash", hash);
  auto event =
      new datacrumbs::EventWithId(METADATA_EVENT, event_index.fetch_add(1), 0, 0, 0, 0, 0, args);
  if (writer_) {
    writer_->write_event(event);
  }
  return 0;
}
int EventProcessor::finalize() {
  // Flush writer queue and close output stream after final event counters are logged.
  DC_LOG_PRINT("Collected %d events and failed %d events", event_index.load(), failed_events);
  auto writer_ = datacrumbs::Singleton<datacrumbs::ChromeWriter>::get_instance();
  if (writer_) {
    writer_->finalize();
  }
  DC_LOG_DEBUG("EventProcessor finalized");
  return 0;
}

};  // namespace datacrumbs
