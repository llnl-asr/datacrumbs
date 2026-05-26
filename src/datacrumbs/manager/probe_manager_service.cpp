// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include "datacrumbs/manager/probe_manager_service.h"

#include <arpa/inet.h>
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/probe_file.h>
#include <datacrumbs/datacrumbs_config.h>
#include <grp.h>
#include <json-c/json.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char* kRpcVersion = "2.0";
constexpr const char* kSignMethod = "sign_probe_payload";
constexpr const char* kReportRuntimeStateMethod = "report_runtime_probe_state";
constexpr const char* kRequiredChecksumAlgorithm = "hmac-sha256";

bool key_exists(const std::unordered_set<std::string>& keys, const std::string& key) {
  return keys.find(key) != keys.end();
}

std::unordered_set<std::string> object_keys(json_object* obj) {
  std::unordered_set<std::string> keys;
  if (obj == nullptr || json_object_get_type(obj) != json_type_object) {
    return keys;
  }
  json_object_object_foreach(obj, key, val) {
    (void)val;
    keys.insert(key);
  }
  return keys;
}

bool validate_exact_keys(json_object* obj, const std::unordered_set<std::string>& required,
                         const std::unordered_set<std::string>& optional,
                         const std::string& context, std::vector<std::string>* errors) {
  bool ok = true;
  const auto keys = object_keys(obj);
  for (const auto& req : required) {
    if (!key_exists(keys, req)) {
      errors->push_back(context + ": missing required key '" + req + "'");
      ok = false;
    }
  }
  for (const auto& key : keys) {
    if (!key_exists(required, key) && !key_exists(optional, key)) {
      errors->push_back(context + ": unexpected key '" + key + "'");
      ok = false;
    }
  }
  return ok;
}

bool user_has_gid(const std::vector<gid_t>& gids, gid_t gid) {
  return std::find(gids.begin(), gids.end(), gid) != gids.end();
}

bool user_can_read_path(const std::string& username, const std::string& path, std::string* err) {
  struct stat st{};
  if (stat(path.c_str(), &st) != 0) {
    if (err != nullptr) {
      *err = "path does not exist or is not stat-able: " + path;
    }
    return false;
  }

  struct passwd* pwd = getpwnam(username.c_str());
  if (pwd == nullptr) {
    if (err != nullptr) {
      *err = "failed to resolve user '" + username + "'";
    }
    return false;
  }

  if (pwd->pw_uid == 0) {
    return true;
  }

  int ngroups = 0;
  getgrouplist(username.c_str(), pwd->pw_gid, nullptr, &ngroups);
  if (ngroups <= 0) {
    ngroups = 1;
  }
  std::vector<gid_t> groups(static_cast<size_t>(ngroups));
  if (getgrouplist(username.c_str(), pwd->pw_gid, groups.data(), &ngroups) < 0) {
    groups.clear();
    groups.push_back(pwd->pw_gid);
  } else {
    groups.resize(static_cast<size_t>(ngroups));
  }

  bool readable = false;
  if (st.st_uid == pwd->pw_uid) {
    readable = (st.st_mode & S_IRUSR) != 0;
  } else if (user_has_gid(groups, st.st_gid)) {
    readable = (st.st_mode & S_IRGRP) != 0;
  } else {
    readable = (st.st_mode & S_IROTH) != 0;
  }

  if (!readable && err != nullptr) {
    *err = "user '" + username + "' does not have read access to '" + path + "'";
  }
  return readable;
}

std::unordered_set<std::string> load_kernel_symbols() {
  std::unordered_set<std::string> symbols;
  std::ifstream file("/proc/kallsyms");
  if (!file.is_open()) {
    return symbols;
  }
  std::string addr;
  std::string type;
  std::string name;
  while (file >> addr >> type >> name) {
    if (type == "T" || type == "t") {
      symbols.insert(name);
    }
  }
  return symbols;
}

std::string strip_offset_suffix(const std::string& function_name) {
  const auto pos = function_name.find(':');
  return pos == std::string::npos ? function_name : function_name.substr(0, pos);
}

std::string syscall_base_name(const std::string& function_name) {
  std::string base_name = strip_offset_suffix(function_name);
  if (base_name.rfind("__x64_sys_", 0) == 0) {
    base_name = base_name.substr(10);
  } else if (base_name.rfind("sys_", 0) == 0) {
    base_name = base_name.substr(4);
  }
  return base_name;
}

bool is_valid_kernel_function(const std::unordered_set<std::string>& kernel_symbols,
                              datacrumbs::ProbeType probe_type, const std::string& function_name) {
  const std::string base_name = probe_type == datacrumbs::ProbeType::SYSCALLS
                                    ? syscall_base_name(function_name)
                                    : strip_offset_suffix(function_name);
  if (probe_type == datacrumbs::ProbeType::KPROBE) {
    return key_exists(kernel_symbols, base_name);
  }
  if (probe_type == datacrumbs::ProbeType::SYSCALLS) {
    if (key_exists(kernel_symbols, base_name)) {
      return true;
    }
    if (key_exists(kernel_symbols, "sys_" + base_name)) {
      return true;
    }
    if (key_exists(kernel_symbols, "__x64_sys_" + base_name)) {
      return true;
    }
    return false;
  }
  return true;
}

bool validate_function_arguments(json_object* function_arguments, const std::string& context,
                                 std::vector<std::string>* errors) {
  if (function_arguments == nullptr) {
    return true;
  }
  if (json_object_get_type(function_arguments) != json_type_object) {
    errors->push_back(context + ": 'function_arguments' must be an object");
    return false;
  }
  bool ok = true;
  json_object_object_foreach(function_arguments, function_name, arg_specs) {
    if (json_object_get_type(arg_specs) != json_type_array) {
      errors->push_back(context + ": function_arguments['" + std::string(function_name) +
                        "'] must be an array");
      ok = false;
      continue;
    }
    const int arg_count = json_object_array_length(arg_specs);
    for (int i = 0; i < arg_count; ++i) {
      json_object* arg_spec = json_object_array_get_idx(arg_specs, i);
      const std::string arg_context = context + ": function_arguments['" +
                                      std::string(function_name) + "'][" + std::to_string(i) + "]";
      if (arg_spec == nullptr || json_object_get_type(arg_spec) != json_type_object) {
        errors->push_back(arg_context + " must be an object");
        ok = false;
        continue;
      }
      if (!validate_exact_keys(arg_spec, {"index", "num_bytes", "is_pointer", "label", "c_type"},
                               {}, arg_context, errors)) {
        ok = false;
      }
      json_object* value = nullptr;
      if (!json_object_object_get_ex(arg_spec, "index", &value) ||
          json_object_get_type(value) != json_type_int) {
        errors->push_back(arg_context + ": 'index' must be an integer");
        ok = false;
      }
      if (!json_object_object_get_ex(arg_spec, "num_bytes", &value) ||
          json_object_get_type(value) != json_type_int) {
        errors->push_back(arg_context + ": 'num_bytes' must be an integer");
        ok = false;
      }
      if (!json_object_object_get_ex(arg_spec, "is_pointer", &value) ||
          json_object_get_type(value) != json_type_boolean) {
        errors->push_back(arg_context + ": 'is_pointer' must be a boolean");
        ok = false;
      }
      if (!json_object_object_get_ex(arg_spec, "label", &value) ||
          json_object_get_type(value) != json_type_string) {
        errors->push_back(arg_context + ": 'label' must be a string");
        ok = false;
      }
      if (!json_object_object_get_ex(arg_spec, "c_type", &value) ||
          json_object_get_type(value) != json_type_string) {
        errors->push_back(arg_context + ": 'c_type' must be a string");
        ok = false;
      }
    }
  }
  return ok;
}

std::string join_errors(const std::vector<std::string>& errors) {
  if (errors.empty()) {
    return "";
  }
  std::ostringstream stream;
  stream << "payload validation failed (" << errors.size() << " error(s)):";
  for (const auto& error : errors) {
    stream << "\n- " << error;
  }
  return stream.str();
}

bool sqlite_exec(sqlite3* db, const char* sql, std::string* error) {
  char* sqlite_error = nullptr;
  const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &sqlite_error);
  if (rc == SQLITE_OK) {
    return true;
  }
  if (error != nullptr) {
    const char* message = sqlite_error != nullptr ? sqlite_error : sqlite3_errmsg(db);
    *error = message != nullptr ? message : "sqlite error";
  }
  if (sqlite_error != nullptr) {
    sqlite3_free(sqlite_error);
  }
  return false;
}

std::string json_to_string(json_object* obj) {
  if (obj == nullptr) {
    return "";
  }
  const char* text = json_object_get_string(obj);
  return text != nullptr ? text : "";
}

void validate_path_access_for_user(const std::string& requesting_user, const std::string& context,
                                   const std::string& path, std::vector<std::string>* errors,
                                   bool* ok) {
  if (requesting_user.empty()) {
    errors->push_back("payload.summary.user is required to validate path access");
    *ok = false;
    return;
  }
  std::string access_error;
  if (!user_can_read_path(requesting_user, path, &access_error)) {
    errors->push_back(context + ": " + access_error);
    *ok = false;
  }
}

std::string json_string_or_empty(json_object* root, const char* key) {
  json_object* value = nullptr;
  if (root == nullptr || !json_object_object_get_ex(root, key, &value) ||
      json_object_get_type(value) != json_type_string) {
    return "";
  }
  return json_object_get_string(value);
}

}  // namespace

ProbeManagerService::ProbeManagerService()
    : host_(DATACRUMBS_PROBE_MANAGER_TCP_HOST), port_(DATACRUMBS_PROBE_MANAGER_TCP_PORT) {}

ProbeManagerService::~ProbeManagerService() {
  if (server_fd_ >= 0) {
    close(server_fd_);
  }
}

int ProbeManagerService::run() {
  // Step 1/3: Initialize process-level safety and secret material.
  signal(SIGPIPE, SIG_IGN);

  std::string secret;
  if (!datacrumbs::probe_file::ensure_probe_secret(&secret)) {
    DC_LOG_ERROR("Failed to create or read probe signing secret");
    return 1;
  }

  // Step 2/3: Initialize the listening socket.
  if (!initialize_socket()) {
    return 1;
  }

  DC_LOG_INFO("Datacrumbs probe manager service listening on %s:%d", host_.c_str(), port_);

  // Step 3/3: Accept and process client requests serially.
  for (;;) {
    const int client_fd = accept(server_fd_, nullptr, nullptr);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      DC_LOG_ERROR("Failed to accept manager connection");
      continue;
    }
    try {
      handle_client(client_fd);
    } catch (const std::exception& ex) {
      const std::string response_payload = build_response("", false, "", ex.what(), -32603);
      write_all_to_fd(client_fd, response_payload);
      DC_LOG_ERROR("Manager request handling failed: %s", ex.what());
    } catch (...) {
      const std::string response_payload =
          build_response("", false, "", "unexpected manager service error", -32603);
      write_all_to_fd(client_fd, response_payload);
      DC_LOG_ERROR("Manager request handling failed: unknown exception");
    }
    close(client_fd);
  }

  return 0;
}

bool ProbeManagerService::initialize_socket() {
  server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd_ < 0) {
    DC_LOG_ERROR("Failed to create manager TCP socket");
    return false;
  }

  int reuse_addr = 1;
  setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* resolved = nullptr;
  const std::string port_str = std::to_string(port_);
  const int gai_rc = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &resolved);
  if (gai_rc != 0) {
    DC_LOG_ERROR("Failed to resolve manager TCP host '%s': %s", host_.c_str(),
                 gai_strerror(gai_rc));
    return false;
  }

  sockaddr_in address{};
  std::memcpy(&address, resolved->ai_addr, sizeof(address));
  freeaddrinfo(resolved);

  if (bind(server_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    DC_LOG_ERROR("Failed to bind manager TCP socket at %s:%d: %s", host_.c_str(), port_,
                 std::strerror(errno));
    return false;
  }

  if (listen(server_fd_, 16) != 0) {
    DC_LOG_ERROR("Failed to listen on manager TCP socket");
    return false;
  }

  return true;
}

void ProbeManagerService::handle_client(int client_fd) const {
  // Step 1/3: Read and parse the incoming JSON-RPC request.
  std::string request_payload;
  std::string request_id;

  if (!read_all_from_fd(client_fd, &request_payload)) {
    write_all_to_fd(client_fd,
                    build_response("", false, "", "failed to read signing request", -32700));
    return;
  }

  json_object* request_root = json_tokener_parse(request_payload.c_str());
  if (request_root == nullptr || json_object_get_type(request_root) != json_type_object) {
    if (request_root != nullptr) {
      json_object_put(request_root);
    }
    write_all_to_fd(client_fd,
                    build_response("", false, "", "failed to parse manager RPC request", -32700));
    return;
  }

  // Step 2/3: Validate RPC envelope fields and locate params.
  const std::string version = json_string_or_empty(request_root, "jsonrpc");
  request_id = json_string_or_empty(request_root, "id");
  const std::string method = json_string_or_empty(request_root, "method");
  if (version != kRpcVersion || (method != kSignMethod && method != kReportRuntimeStateMethod)) {
    json_object_put(request_root);
    write_all_to_fd(client_fd,
                    build_response(request_id, false, "", "unsupported RPC method", -32601));
    return;
  }

  json_object* params = nullptr;
  if (!json_object_object_get_ex(request_root, "params", &params) ||
      json_object_get_type(params) != json_type_object) {
    json_object_put(request_root);
    write_all_to_fd(client_fd,
                    build_response(request_id, false, "", "missing params object", -32602));
    return;
  }

  // Step 3/3: Dispatch to method-specific request handlers.
  if (method == kSignMethod) {
    json_object* signing_payload_obj = nullptr;
    if (!json_object_object_get_ex(params, "signing_payload", &signing_payload_obj) ||
        json_object_get_type(signing_payload_obj) != json_type_string) {
      json_object_put(request_root);
      write_all_to_fd(client_fd,
                      build_response(request_id, false, "", "missing signing payload", -32602));
      return;
    }

    const std::string signing_payload = json_object_get_string(signing_payload_obj);
    json_object_put(request_root);

    std::string error;
    std::string checksum = sign_signing_payload(signing_payload, &error);
    if (checksum.empty()) {
      write_all_to_fd(client_fd, build_response(request_id, false, "", error, -32603));
    } else {
      write_all_to_fd(client_fd, build_response(request_id, true, checksum, "", 0));
    }
    return;
  }

  json_object* state_payload_obj = nullptr;
  json_object* state_hmac_obj = nullptr;
  if (!json_object_object_get_ex(params, "state_payload", &state_payload_obj) ||
      json_object_get_type(state_payload_obj) != json_type_string ||
      !json_object_object_get_ex(params, "state_hmac", &state_hmac_obj) ||
      json_object_get_type(state_hmac_obj) != json_type_string) {
    json_object_put(request_root);
    write_all_to_fd(client_fd,
                    build_response(request_id, false, "", "missing state payload or hmac", -32602));
    return;
  }

  const std::string state_payload = json_object_get_string(state_payload_obj);
  const std::string state_hmac = json_object_get_string(state_hmac_obj);
  json_object_put(request_root);

  std::string error;
  if (!report_runtime_probe_state(state_payload, state_hmac, &error)) {
    write_all_to_fd(client_fd, build_response(request_id, false, "", error, -32603));
    return;
  }

  write_all_to_fd(client_fd, build_response(request_id, true, "accepted", "", 0));
}

std::string ProbeManagerService::build_response(const std::string& request_id, bool ok,
                                                const std::string& payload,
                                                const std::string& error, int error_code) const {
  json_object* root = json_object_new_object();
  json_object_object_add(root, "jsonrpc", json_object_new_string(kRpcVersion));
  if (!request_id.empty()) {
    json_object_object_add(root, "id", json_object_new_string(request_id.c_str()));
  }
  if (ok) {
    json_object* result = json_object_new_object();
    json_object_object_add(result, "checksum", json_object_new_string(payload.c_str()));
    json_object_object_add(root, "result", result);
  } else {
    json_object* error_object = json_object_new_object();
    json_object_object_add(error_object, "code", json_object_new_int(error_code));
    json_object_object_add(error_object, "message", json_object_new_string(error.c_str()));
    json_object_object_add(root, "error", error_object);
  }
  const char* response = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
  std::string output = response != nullptr ? response : "";
  json_object_put(root);
  return output;
}

bool ProbeManagerService::read_all_from_fd(int fd, std::string* payload) const {
  char buffer[4096];
  payload->clear();
  ssize_t read_bytes = 0;
  for (;;) {
    read_bytes = read(fd, buffer, sizeof(buffer));
    if (read_bytes > 0) {
      payload->append(buffer, static_cast<std::size_t>(read_bytes));
      continue;
    }
    if (read_bytes < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  return read_bytes == 0;
}

bool ProbeManagerService::write_all_to_fd(int fd, const std::string& payload) const {
  std::size_t total_written = 0;
  while (total_written < payload.size()) {
    const ssize_t written =
        write(fd, payload.data() + total_written, payload.size() - total_written);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return false;
    }
    total_written += static_cast<std::size_t>(written);
  }
  return true;
}

std::string ProbeManagerService::sign_signing_payload(const std::string& request_payload,
                                                      std::string* error) const {
  std::vector<std::string> validation_errors;
  if (!validate_signing_payload(request_payload, &validation_errors)) {
    if (error != nullptr) {
      *error = join_errors(validation_errors);
    }
    return "";
  }

  std::string secret;
  if (!datacrumbs::probe_file::ensure_probe_secret(&secret)) {
    if (error != nullptr) {
      *error = "failed to read signing secret";
    }
    return "";
  }

  const std::string result = datacrumbs::probe_file::hmac_sha256_hex(secret, request_payload);
  if (result.empty() && error != nullptr) {
    *error = "failed to compute probe signature";
  }
  return result;
}

bool ProbeManagerService::report_runtime_probe_state(const std::string& state_payload,
                                                     const std::string& state_hmac,
                                                     std::string* error) const {
  std::string secret;
  if (!datacrumbs::probe_file::ensure_probe_secret(&secret)) {
    if (error != nullptr) {
      *error = "failed to read signing secret for runtime state auth";
    }
    return false;
  }

  const std::string expected_hmac = datacrumbs::probe_file::hmac_sha256_hex(secret, state_payload);
  if (expected_hmac.empty() || expected_hmac != state_hmac) {
    if (error != nullptr) {
      *error = "runtime state authentication failed";
    }
    return false;
  }

  return persist_runtime_probe_state_payload(state_payload, error);
}

bool ProbeManagerService::validate_signing_payload(const std::string& signing_payload,
                                                   std::vector<std::string>* errors) const {
  // Step 1/4: Parse the root object and validate top-level required keys.
  json_object* root = json_tokener_parse(signing_payload.c_str());
  if (root == nullptr || json_object_get_type(root) != json_type_object) {
    if (errors != nullptr) {
      errors->push_back("root payload must be a JSON object");
    }
    if (root != nullptr) {
      json_object_put(root);
    }
    return false;
  }

  bool ok = true;
  ok = validate_exact_keys(root, {"summary", "categories", "checksum_algorithm"}, {}, "payload",
                           errors) &&
       ok;

  // Step 2/4: Validate checksum algorithm and summary metadata contract.
  json_object* checksum_algorithm_obj = nullptr;
  if (!json_object_object_get_ex(root, "checksum_algorithm", &checksum_algorithm_obj) ||
      json_object_get_type(checksum_algorithm_obj) != json_type_string ||
      std::string(json_object_get_string(checksum_algorithm_obj)) != kRequiredChecksumAlgorithm) {
    errors->push_back("payload.checksum_algorithm must be string 'hmac-sha256'");
    ok = false;
  }

  json_object* summary = nullptr;
  if (!json_object_object_get_ex(root, "summary", &summary) ||
      json_object_get_type(summary) != json_type_object) {
    errors->push_back("payload.summary must be an object");
    ok = false;
  } else {
    ok = validate_exact_keys(
             summary, {"config_file_path", "probe_file_path", "hostname", "user", "install_user"},
             {}, "payload.summary", errors) &&
         ok;
    for (const auto& key :
         {"config_file_path", "probe_file_path", "hostname", "user", "install_user"}) {
      json_object* value = nullptr;
      if (!json_object_object_get_ex(summary, key, &value) ||
          json_object_get_type(value) != json_type_string ||
          std::string(json_object_get_string(value)).empty()) {
        errors->push_back(std::string("payload.summary.") + key + " must be a non-empty string");
        ok = false;
      }
    }

    const std::string summary_user = json_string_or_empty(summary, "user");
    const std::string config_path = json_string_or_empty(summary, "config_file_path");
    if (!config_path.empty()) {
      validate_path_access_for_user(summary_user, "payload.summary.config_file_path", config_path,
                                    errors, &ok);
    }
  }

  std::string requesting_user;
  if (summary != nullptr && json_object_get_type(summary) == json_type_object) {
    requesting_user = json_string_or_empty(summary, "user");
  }

  // Step 3/4: Validate each category/probe entry and function list constraints.
  json_object* categories = nullptr;
  if (!json_object_object_get_ex(root, "categories", &categories) ||
      json_object_get_type(categories) != json_type_array) {
    errors->push_back("payload.categories must be an array");
    ok = false;
  } else {
    const auto kernel_symbols = load_kernel_symbols();
    if (kernel_symbols.empty()) {
      errors->push_back("failed to load kernel symbols from /proc/kallsyms");
      ok = false;
    }

    const int probe_count = json_object_array_length(categories);
    for (int i = 0; i < probe_count; ++i) {
      json_object* probe = json_object_array_get_idx(categories, i);
      const std::string context = "payload.categories[" + std::to_string(i) + "]";
      if (probe == nullptr || json_object_get_type(probe) != json_type_object) {
        errors->push_back(context + " must be an object");
        ok = false;
        continue;
      }

      json_object* type_obj = nullptr;
      json_object* name_obj = nullptr;
      json_object* functions_obj = nullptr;
      json_object* function_arguments_obj = nullptr;
      if (!json_object_object_get_ex(probe, "type", &type_obj) ||
          json_object_get_type(type_obj) != json_type_int) {
        errors->push_back(context + ".type must be an integer");
        ok = false;
        continue;
      }

      const int probe_type_value = json_object_get_int(type_obj);
      if (probe_type_value < static_cast<int>(datacrumbs::ProbeType::SYSCALLS) ||
          probe_type_value > static_cast<int>(datacrumbs::ProbeType::CUSTOM)) {
        errors->push_back(context + ".type contains invalid probe type value");
        ok = false;
        continue;
      }
      const auto probe_type = static_cast<datacrumbs::ProbeType>(probe_type_value);

      std::unordered_set<std::string> required_keys = {"type", "name", "functions"};
      std::unordered_set<std::string> optional_keys = {"function_arguments"};
      if (probe_type == datacrumbs::ProbeType::UPROBE) {
        required_keys.insert("binary_path");
        required_keys.insert("include_offsets");
      } else if (probe_type == datacrumbs::ProbeType::USDT) {
        required_keys.insert("binary_path");
        required_keys.insert("provider");
      } else if (probe_type == datacrumbs::ProbeType::CUSTOM) {
        required_keys.insert("bpf_path");
        required_keys.insert("start_event_id");
        required_keys.insert("process_header");
        required_keys.insert("event_type");
      }
      ok = validate_exact_keys(probe, required_keys, optional_keys, context, errors) && ok;

      if (!json_object_object_get_ex(probe, "name", &name_obj) ||
          json_object_get_type(name_obj) != json_type_string ||
          std::string(json_object_get_string(name_obj)).empty()) {
        errors->push_back(context + ".name must be a non-empty string");
        ok = false;
      }

      if (!json_object_object_get_ex(probe, "functions", &functions_obj) ||
          json_object_get_type(functions_obj) != json_type_array) {
        errors->push_back(context + ".functions must be an array");
        ok = false;
      } else {
        const int function_count = json_object_array_length(functions_obj);
        if (function_count == 0) {
          errors->push_back(context + ".functions must not be empty");
          ok = false;
        }
        for (int fidx = 0; fidx < function_count; ++fidx) {
          json_object* function_obj = json_object_array_get_idx(functions_obj, fidx);
          const std::string function_context = context + ".functions[" + std::to_string(fidx) + "]";
          if (function_obj == nullptr || json_object_get_type(function_obj) != json_type_string ||
              std::string(json_object_get_string(function_obj)).empty()) {
            errors->push_back(function_context + " must be a non-empty string");
            ok = false;
            continue;
          }
          const std::string function_name = json_object_get_string(function_obj);
          if (!kernel_symbols.empty() &&
              !is_valid_kernel_function(kernel_symbols, probe_type, function_name)) {
            errors->push_back(function_context + " kernel symbol not found in /proc/kallsyms: '" +
                              function_name + "'");
            ok = false;
          }
        }
      }

      if (json_object_object_get_ex(probe, "function_arguments", &function_arguments_obj)) {
        ok = validate_function_arguments(function_arguments_obj, context, errors) && ok;
      }

      json_object* binary_path_obj = nullptr;
      if (json_object_object_get_ex(probe, "binary_path", &binary_path_obj)) {
        if (json_object_get_type(binary_path_obj) != json_type_string ||
            std::string(json_object_get_string(binary_path_obj)).empty()) {
          errors->push_back(context + ".binary_path must be a non-empty string");
          ok = false;
        } else {
          const std::string binary_path = json_object_get_string(binary_path_obj);
          validate_path_access_for_user(requesting_user, context + ".binary_path", binary_path,
                                        errors, &ok);
        }
      }

      if (probe_type == datacrumbs::ProbeType::UPROBE) {
        json_object* include_offsets_obj = nullptr;
        if (!json_object_object_get_ex(probe, "include_offsets", &include_offsets_obj) ||
            json_object_get_type(include_offsets_obj) != json_type_boolean) {
          errors->push_back(context + ".include_offsets must be a boolean");
          ok = false;
        }
      }
      if (probe_type == datacrumbs::ProbeType::USDT) {
        json_object* provider_obj = nullptr;
        if (!json_object_object_get_ex(probe, "provider", &provider_obj) ||
            json_object_get_type(provider_obj) != json_type_string ||
            std::string(json_object_get_string(provider_obj)).empty()) {
          errors->push_back(context + ".provider must be a non-empty string");
          ok = false;
        }
      }
      if (probe_type == datacrumbs::ProbeType::CUSTOM) {
        json_object* value = nullptr;
        if (!json_object_object_get_ex(probe, "bpf_path", &value) ||
            json_object_get_type(value) != json_type_string ||
            std::string(json_object_get_string(value)).empty()) {
          errors->push_back(context + ".bpf_path must be a non-empty string");
          ok = false;
        } else {
          validate_path_access_for_user(requesting_user, context + ".bpf_path",
                                        json_object_get_string(value), errors, &ok);
        }
        if (!json_object_object_get_ex(probe, "process_header", &value) ||
            json_object_get_type(value) != json_type_string ||
            std::string(json_object_get_string(value)).empty()) {
          errors->push_back(context + ".process_header must be a non-empty string");
          ok = false;
        } else {
          validate_path_access_for_user(requesting_user, context + ".process_header",
                                        json_object_get_string(value), errors, &ok);
        }
        if (!json_object_object_get_ex(probe, "start_event_id", &value) ||
            json_object_get_type(value) != json_type_int) {
          errors->push_back(context + ".start_event_id must be an integer");
          ok = false;
        }
        if (!json_object_object_get_ex(probe, "event_type", &value) ||
            json_object_get_type(value) != json_type_int) {
          errors->push_back(context + ".event_type must be an integer");
          ok = false;
        }
      }
    }
  }

  // Step 4/4: Release parsed JSON resources and return aggregate result.
  json_object_put(root);
  return ok;
}

bool ProbeManagerService::persist_runtime_probe_state_payload(const std::string& state_payload,
                                                              std::string* error) const {
  // Step 1/6: Parse and validate required runtime state payload fields.
  json_object* root = json_tokener_parse(state_payload.c_str());
  if (root == nullptr || json_object_get_type(root) != json_type_object) {
    if (root != nullptr) {
      json_object_put(root);
    }
    if (error != nullptr) {
      *error = "runtime state payload must be a JSON object";
    }
    return false;
  }

  json_object* db_path_obj = nullptr;
  json_object* node_id_obj = nullptr;
  json_object* invalid_entries_obj = nullptr;
  json_object* successful_entries_obj = nullptr;
  if (!json_object_object_get_ex(root, "database_path", &db_path_obj) ||
      json_object_get_type(db_path_obj) != json_type_string ||
      !json_object_object_get_ex(root, "node_id", &node_id_obj) ||
      json_object_get_type(node_id_obj) != json_type_string ||
      !json_object_object_get_ex(root, "invalid_entries", &invalid_entries_obj) ||
      json_object_get_type(invalid_entries_obj) != json_type_array ||
      !json_object_object_get_ex(root, "successful_entries", &successful_entries_obj) ||
      json_object_get_type(successful_entries_obj) != json_type_array) {
    json_object_put(root);
    if (error != nullptr) {
      *error =
          "runtime state payload must include database_path, node_id, invalid_entries, and "
          "successful_entries";
    }
    return false;
  }

  const std::string database_path = json_object_get_string(db_path_obj);
  const std::string node_id = json_object_get_string(node_id_obj);
  if (database_path.empty() || node_id.empty()) {
    json_object_put(root);
    if (error != nullptr) {
      *error = "runtime state payload has empty database_path or node_id";
    }
    return false;
  }

  // Step 2/6: Open/create sqlite database used for runtime state persistence.
  sqlite3* db = nullptr;
  if (sqlite3_open_v2(database_path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      nullptr) != SQLITE_OK) {
    if (error != nullptr) {
      *error = std::string("failed to open runtime state database: ") +
               (db != nullptr ? sqlite3_errmsg(db) : "sqlite open failed");
    }
    if (db != nullptr) {
      sqlite3_close(db);
    }
    json_object_put(root);
    return false;
  }

  // Step 3/6: Ensure schema exists and start a write transaction.
  sqlite3_busy_timeout(db, 5000);
  if (!sqlite_exec(db,
                   "CREATE TABLE IF NOT EXISTS runtime_probe_status_by_node ("
                   "node_id TEXT NOT NULL,"
                   "probe_group TEXT NOT NULL,"
                   "scope_key TEXT NOT NULL,"
                   "function_name TEXT NOT NULL,"
                   "status TEXT NOT NULL CHECK (status IN ('invalid', 'successful')),"
                   "PRIMARY KEY (node_id, probe_group, scope_key, function_name, status)"
                   ");",
                   error) ||
      !sqlite_exec(db, "BEGIN IMMEDIATE TRANSACTION;", error)) {
    sqlite3_close(db);
    json_object_put(root);
    return false;
  }

  // Step 4/6: Prepare reusable insert/delete statements.
  sqlite3_stmt* insert_stmt = nullptr;
  sqlite3_stmt* delete_invalid_stmt = nullptr;
  const char* insert_sql =
      "INSERT OR IGNORE INTO runtime_probe_status_by_node "
      "(node_id, probe_group, scope_key, function_name, status) VALUES (?, ?, ?, ?, ?);";
  const char* delete_invalid_sql =
      "DELETE FROM runtime_probe_status_by_node WHERE node_id = ? AND probe_group = ? AND "
      "scope_key = ? AND function_name = ? AND status = 'invalid';";

  if (sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, nullptr) != SQLITE_OK ||
      sqlite3_prepare_v2(db, delete_invalid_sql, -1, &delete_invalid_stmt, nullptr) != SQLITE_OK) {
    if (error != nullptr) {
      *error = std::string("failed to prepare sqlite statements: ") + sqlite3_errmsg(db);
    }
    if (insert_stmt != nullptr) {
      sqlite3_finalize(insert_stmt);
    }
    if (delete_invalid_stmt != nullptr) {
      sqlite3_finalize(delete_invalid_stmt);
    }
    sqlite_exec(db, "ROLLBACK;", nullptr);
    sqlite3_close(db);
    json_object_put(root);
    return false;
  }

  // Step 5/6: Persist successful/invalid entry arrays with invalid cleanup semantics.
  auto persist_entries = [&](json_object* entries, const char* status) -> bool {
    const int count = json_object_array_length(entries);
    for (int i = 0; i < count; ++i) {
      json_object* entry = json_object_array_get_idx(entries, i);
      if (entry == nullptr || json_object_get_type(entry) != json_type_object) {
        continue;
      }
      json_object* probe_group_obj = nullptr;
      json_object* scope_key_obj = nullptr;
      json_object* function_name_obj = nullptr;
      if (!json_object_object_get_ex(entry, "probe_group", &probe_group_obj) ||
          json_object_get_type(probe_group_obj) != json_type_string ||
          !json_object_object_get_ex(entry, "scope_key", &scope_key_obj) ||
          json_object_get_type(scope_key_obj) != json_type_string ||
          !json_object_object_get_ex(entry, "function_name", &function_name_obj) ||
          json_object_get_type(function_name_obj) != json_type_string) {
        continue;
      }

      const std::string probe_group = json_to_string(probe_group_obj);
      const std::string scope_key = json_to_string(scope_key_obj);
      const std::string function_name = json_to_string(function_name_obj);

      if (std::string(status) == "successful") {
        sqlite3_reset(delete_invalid_stmt);
        sqlite3_clear_bindings(delete_invalid_stmt);
        sqlite3_bind_text(delete_invalid_stmt, 1, node_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(delete_invalid_stmt, 2, probe_group.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(delete_invalid_stmt, 3, scope_key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(delete_invalid_stmt, 4, function_name.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(delete_invalid_stmt) != SQLITE_DONE) {
          if (error != nullptr) {
            *error =
                std::string("failed to cleanup invalid runtime probe entry: ") + sqlite3_errmsg(db);
          }
          return false;
        }
      }

      sqlite3_reset(insert_stmt);
      sqlite3_clear_bindings(insert_stmt);
      sqlite3_bind_text(insert_stmt, 1, node_id.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(insert_stmt, 2, probe_group.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(insert_stmt, 3, scope_key.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(insert_stmt, 4, function_name.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_text(insert_stmt, 5, status, -1, SQLITE_STATIC);
      if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
        if (error != nullptr) {
          *error = std::string("failed to persist runtime probe entry: ") + sqlite3_errmsg(db);
        }
        return false;
      }
    }
    return true;
  };

  // Step 6/6: Finalize statements, commit/rollback transaction, and cleanup resources.
  const bool persisted_successful = persist_entries(successful_entries_obj, "successful");
  const bool persisted_invalid =
      persisted_successful && persist_entries(invalid_entries_obj, "invalid");

  sqlite3_finalize(delete_invalid_stmt);
  sqlite3_finalize(insert_stmt);

  const bool committed = persisted_invalid && sqlite_exec(db, "COMMIT;", error);
  if (!committed) {
    sqlite_exec(db, "ROLLBACK;", nullptr);
  }

  sqlite3_close(db);
  json_object_put(root);
  return committed;
}
