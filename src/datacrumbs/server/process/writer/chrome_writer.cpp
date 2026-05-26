// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/server/process/writer/chrome_writer.h>
// internal headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/compress/zlib_compressor.h>

#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>

namespace {

std::string json_escape(const std::string& input) {
  std::string escaped;
  escaped.reserve(input.size() + 8);
  for (unsigned char ch : input) {
    switch (ch) {
      case '\"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (ch < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
          escaped += buffer;
        } else {
          escaped += static_cast<char>(ch);
        }
    }
  }
  return escaped;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char byte : bytes) {
    oss << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return oss.str();
}

std::string pointer_json(unsigned long long raw_value) {
  std::ostringstream oss;
  oss << "\"0x" << std::hex << raw_value << "\"";
  return oss.str();
}

bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}
bool is_float_type(const std::string& c_type) {
  return c_type == "float";
}
bool is_double_type(const std::string& c_type) {
  return c_type == "double";
}
bool is_signed_type(const std::string& c_type) {
  if (c_type.empty()) return false;
  if (c_type.find("unsigned") != std::string::npos) return false;
  return c_type.find("int") != std::string::npos || c_type.find("long") != std::string::npos ||
         c_type.find("short") != std::string::npos || c_type.find("ssize_t") != std::string::npos ||
         c_type.find("pid_t") != std::string::npos || c_type == "char";
}

std::string decode_scalar_json(const CapturedArgumentValue& value) {
  const unsigned int width = std::min<std::size_t>(value.bytes.size(), sizeof(unsigned long long));
  unsigned long long raw = 0;
  if (width > 0) {
    std::memcpy(&raw, value.bytes.data(), width);
  } else {
    raw = value.raw_value;
  }

  if (is_float_type(value.c_type) && width >= sizeof(float)) {
    float number = 0.0f;
    std::memcpy(&number, value.bytes.data(), sizeof(float));
    return std::to_string(number);
  }
  if (is_double_type(value.c_type) && width >= sizeof(double)) {
    double number = 0.0;
    std::memcpy(&number, value.bytes.data(), sizeof(double));
    return std::to_string(number);
  }
  if (is_signed_type(value.c_type)) {
    long long signed_value = 0;
    switch (width) {
      case 1:
        signed_value = static_cast<signed char>(raw & 0xff);
        break;
      case 2:
        signed_value = static_cast<short>(raw & 0xffff);
        break;
      case 4:
        signed_value = static_cast<int>(raw & 0xffffffffu);
        break;
      default:
        signed_value = static_cast<long long>(raw);
        break;
    }
    return std::to_string(signed_value);
  }
  return std::to_string(raw);
}

std::string serialize_captured_argument(const CapturedArgumentValue& value) {
  if (value.is_pointer) {
    if (value.data_status == 2 && !value.bytes.empty()) {
      if (is_char_pointer_type(value.c_type)) {
        std::string text;
        for (unsigned char ch : value.bytes) {
          if (ch == '\0') break;
          text.push_back(static_cast<char>(ch));
        }
        return "\"" + json_escape(text) + "\"";
      }
      std::ostringstream oss;
      oss << "{\"value\":" << decode_scalar_json(value)
          << ",\"address\":" << pointer_json(value.raw_value) << "}";
      return oss.str();
    }
    return pointer_json(value.raw_value);
  }

  if ((value.data_status == 1 || value.data_status == 2) && !value.bytes.empty()) {
    return decode_scalar_json(value);
  }

  if (!value.bytes.empty()) {
    return "\"0x" + bytes_to_hex(value.bytes) + "\"";
  }

  return std::to_string(value.raw_value);
}

std::string serialize_any_value(const std::any& value) {
  if (value.type() == typeid(int)) {
    return std::to_string(std::any_cast<int>(value));
  } else if (value.type() == typeid(unsigned long long)) {
    return std::to_string(std::any_cast<unsigned long long>(value));
  } else if (value.type() == typeid(unsigned int)) {
    return std::to_string(std::any_cast<unsigned int>(value));
  } else if (value.type() == typeid(uint64_t)) {
    return std::to_string(std::any_cast<uint64_t>(value));
  } else if (value.type() == typeid(float)) {
    return std::to_string(std::any_cast<float>(value));
  } else if (value.type() == typeid(double)) {
    return std::to_string(std::any_cast<double>(value));
  } else if (value.type() == typeid(const char*)) {
    return "\"" + json_escape(std::any_cast<const char*>(value)) + "\"";
  } else if (value.type() == typeid(std::string)) {
    return "\"" + json_escape(std::any_cast<std::string>(value)) + "\"";
  } else if (value.type() == typeid(CapturedArgumentValue)) {
    return serialize_captured_argument(std::any_cast<CapturedArgumentValue>(value));
  }
  return "\"<unsupported>\"";
}

}  // namespace

// Specialization of the Singleton instance for KSymCapture.
// This holds the shared pointer to the singleton instance.
template <>
std::shared_ptr<datacrumbs::ChromeWriter>
    datacrumbs::Singleton<datacrumbs::ChromeWriter>::instance = nullptr;

// Specialization of the flag to stop creating new instances of KSymCapture.
template <>
bool datacrumbs::Singleton<datacrumbs::ChromeWriter>::stop_creating_instances = false;

namespace datacrumbs {
ChromeWriter::ChromeWriter() : stop_flag_(false), finalized_(false), chunk_size_(16 * 1024 * 1024) {
  // Initialize compression sink with runtime-configured output path.
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  compressor_ = new ZlibCompression(configManager_->trace_file_path, chunk_size_);
  // file_ = std::fopen(configManager_->trace_file_path.c_str(), "a+");
  auto pwd = getpwnam(configManager_->user.c_str());
  uid_t uid = pwd ? pwd->pw_uid : static_cast<uid_t>(-1);
  gid_t gid = pwd ? pwd->pw_gid : static_cast<gid_t>(-1);
  // Set file ownership to configManager_->user
  chown(configManager_->trace_file_path.c_str(), uid, gid);
  // Optionally set permissions (e.g., rw-r-----)
  chmod(configManager_->trace_file_path.c_str(), 0660);
  compressor_->compress("[\n");
  first_event_ = true;
  // Start asynchronous queue consumer.
  worker_ = std::thread([this]() { this->worker_loop(); });
}

// Destructor flushes and closes the file, and joins the worker thread.
ChromeWriter::~ChromeWriter() {
  finalize();
  delete compressor_;
  compressor_ = nullptr;
}
void ChromeWriter::finalize() {
  {
    // Gate finalization so repeated finalize()/destructor paths remain idempotent.
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (finalized_) {
      return;
    }
    stop_flag_ = true;
    finalized_ = true;
  }
  DC_LOG_DEBUG("ChromeWriter worker loop exiting");
  queue_cv_.notify_one();
  if (worker_.joinable()) worker_.join();
  if (compressor_ != nullptr) {
    // Close JSON array and finalize gzip stream.
    compressor_->compress("]");
    compressor_->finalize();
  }
  DC_LOG_DEBUG("ChromeWriter finalized");
}

void ChromeWriter::push_event(EventWithId* event) {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    event_queue_.emplace_back(event);
  }
  queue_cv_.notify_one();
}

// Serialize and write a single event to the file, including event_id as "id".
void ChromeWriter::write_event(EventWithId* event_with_id) {
  index_++;
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  uint64_t index = event_with_id->index;
  auto args = event_with_id->args;

  unsigned int pid = event_with_id->tgid_pid;
  unsigned int tid = event_with_id->tgid_pid >> 32;
  // Resolve category/function labels from runtime event id mapping.
  auto it = configManager_->category_map.find(event_with_id->event_id);
  if (it != configManager_->category_map.end()) {
    std::string probe_name = it->second.first;
    std::string function_name = it->second.second;
    // Convert nanosecond-scale counter durations to microseconds for Chrome trace readability.
    if (args != nullptr && event_with_id->event_type == COUNTER_EVENT &&
        args->find("duration") != args->end()) {
      unsigned long long duration = std::any_cast<unsigned int>((*args)["duration"]);
      if (duration > std::numeric_limits<unsigned long long>::max() / 1000) {
        duration = std::numeric_limits<unsigned long long>::max();
      } else {
        duration = static_cast<unsigned long long>(std::floor(duration / 1000.0));
      }
      (*args)["duration"] = duration;
    }
    char buffer[1024];
    unsigned long long ts_us = 0;
    if (event_with_id->ts > std::numeric_limits<unsigned long long>::max() / 1000) {
      ts_us = std::numeric_limits<unsigned long long>::max();
    } else {
      ts_us = static_cast<unsigned long long>(std::floor(event_with_id->ts / 1000.0));
    }
    unsigned long long dur_us = 0;
    if (event_with_id->dur > std::numeric_limits<unsigned long long>::max() / 1000) {
      dur_us = std::numeric_limits<unsigned long long>::max();
    } else {
      dur_us = static_cast<unsigned long long>(std::ceil(event_with_id->dur / 1000.0));
    }
    int len = 0;
    // Build base event JSON for the specific phase marker type.
    if (event_with_id->event_type == COUNTER_EVENT) {
      len = std::snprintf(
          buffer, sizeof(buffer), R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c","ts":%llu)", index_,
          function_name.c_str(), probe_name.c_str(), event_with_id->event_type, ts_us);
    } else if (event_with_id->event_type == METADATA_EVENT) {
      len = std::snprintf(buffer, sizeof(buffer), R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c")",
                          index_, function_name.c_str(), probe_name.c_str(),
                          event_with_id->event_type);
    } else if (event_with_id->event_type == NORMAL_EVENT) {
      // Normal even
      len = std::snprintf(
          buffer, sizeof(buffer),
          R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c","ts":%llu,"dur":%llu,"pid":%d,"tid":%d)",
          index_, function_name.c_str(), probe_name.c_str(), event_with_id->event_type, ts_us,
          dur_us, pid, tid);
    } else {
      return;
    }

    std::string args_json = "{";

    bool first = true;
    if (args != nullptr && !args->empty()) {
      // Serialize dynamic key/value args map into JSON object payload.
      for (auto pair : *args) {
        const std::string& key = pair.first;
        const std::any& value = pair.second;
        if (!first) args_json += ",";
        args_json += "\"";
        args_json += key;
        args_json += "\":";
        args_json += serialize_any_value(value);
        first = false;
      }
    }
    args_json += "}";

    {
      std::lock_guard<std::mutex> lock(file_mutex_);
      std::string event_json = std::string(buffer, len) + ",\"args\":" + args_json + "}\n";
      DC_LOG_DEBUG("Writing event: %s", event_json.c_str());
      compressor_->compress(event_json);
    }
  }
  if (args != nullptr) {
    delete args;  // Clean up args after use
  }
  if (event_with_id != nullptr) {
    delete event_with_id;  // Clean up event after writing
  }
}

void ChromeWriter::worker_loop() {
  DC_LOG_DEBUG("ChromeWriter worker loop started");
  int count = 0;
  while (true) {
    EventWithId* event_with_id = nullptr;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      // Wait for either new work or explicit shutdown request.
      queue_cv_.wait(lock, [this] { return !event_queue_.empty() || stop_flag_; });
      if (event_queue_.empty() && stop_flag_) {
        break;
      }
      if (!event_queue_.empty()) {
        event_with_id = event_queue_.front();
        event_queue_.pop_front();
        DC_LOG_DEBUG("Processing event with ID: %d and %d left", event_with_id->event_id,
                     event_queue_.size());
      } else {
        continue;
      }
    }
    if (event_with_id != nullptr) {
      write_event(event_with_id);
    }
    count++;
  }
  DC_LOG_DEBUG("ChromeWriter worker loop exiting");
}
}  // namespace datacrumbs
