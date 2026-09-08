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
#include <munge.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char* kRpcVersion = "2.0";
constexpr const char* kSignMethod = "sign_probe_payload";
constexpr const char* kReportRuntimeStateMethod = "report_runtime_probe_state";
constexpr const char* kRequiredChecksumAlgorithm = "hmac-sha256";

/**
 * @brief Upper bound on argument specs declared for a single probed function.
 *
 * BPF programs can only capture a handful of arguments, so anything beyond this
 * is malformed input rather than a workload the runtime could ever service.
 */
constexpr int kMaxFunctionArguments = 64;

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

/**
 * @brief Identity of an RPC caller, attested by munge rather than claimed.
 */
struct CallerIdentity {
  uid_t uid = static_cast<uid_t>(-1);  ///< Caller uid attested by munged.
  gid_t gid = static_cast<gid_t>(-1);  ///< Caller primary gid attested by munged.
};

/**
 * @brief Authenticate an RPC caller from the munge credential on the request.
 *
 * The manager serves the whole cluster from one node, so it has no peer
 * credentials to consult. munged validates the credential against the
 * cluster-wide key and reports the uid/gid of the process that created it.
 *
 * The credential carries the SHA-256 of the request payload, so a credential
 * captured within its TTL cannot be paired with a different payload. munged
 * additionally rejects a credential that has already been decoded, which stops
 * straight replay.
 *
 * @param credential Base64 munge credential from the request envelope.
 * @param payload Request payload the credential must be bound to.
 * @param identity Output populated with the attested uid/gid on success.
 * @param error Output populated with the rejection reason on failure.
 * @return True when the credential is valid and bound to this payload.
 * @throws No explicit exceptions are thrown.
 */
bool authenticate_caller(const std::string& credential, const std::string& payload,
                         CallerIdentity* identity, std::string* error) {
  if (credential.empty()) {
    if (error != nullptr) {
      *error = "request is missing a munge credential";
    }
    return false;
  }

  void* decoded = nullptr;
  int decoded_length = 0;
  uid_t uid = static_cast<uid_t>(-1);
  gid_t gid = static_cast<gid_t>(-1);
  const munge_err_t rc =
      munge_decode(credential.c_str(), nullptr, &decoded, &decoded_length, &uid, &gid);
  if (rc != EMUNGE_SUCCESS) {
    if (error != nullptr) {
      *error = std::string("munge credential rejected: ") + munge_strerror(rc);
    }
    free(decoded);
    return false;
  }

  const std::string bound_digest =
      decoded != nullptr && decoded_length > 0
          ? std::string(static_cast<const char*>(decoded), static_cast<std::size_t>(decoded_length))
          : std::string();
  free(decoded);

  const std::string payload_digest = datacrumbs::probe_file::sha256_hex(payload);
  if (payload_digest.empty() || bound_digest != payload_digest) {
    if (error != nullptr) {
      *error = "munge credential is not bound to this request payload";
    }
    return false;
  }

  identity->uid = uid;
  identity->gid = gid;
  return true;
}

/**
 * @brief Check read access to a path as a specific uid by dropping privileges.
 *
 * The manager runs as root, so it cannot answer this by inspecting mode bits:
 * POSIX ACLs, parent-directory traversal bits, mount flags and NFS root_squash
 * all change the answer. root_squash in particular maps the manager to nobody,
 * so an in-process check would fail on paths the user can read perfectly well.
 * A forked child drops to the target credentials and lets the kernel decide.
 *
 * @param uid Requesting user's uid, attested by munge. Example: 35619.
 * @param gid Requesting user's primary gid. Example: 35619.
 * @param path Path to probe. Example: "/p/lustre1/haridev/config.yaml".
 * @param err Output populated with the failure reason when access is denied.
 * @return True when the path could be opened for reading as that uid.
 * @throws No explicit exceptions are thrown.
 */
bool uid_can_read_path(uid_t uid, gid_t gid, const std::string& path, std::string* err) {
  if (uid == 0) {
    if (err != nullptr) {
      *err = "refusing to evaluate path access for uid 0";
    }
    return false;
  }

  int pipe_fds[2] = {-1, -1};
  if (pipe(pipe_fds) != 0) {
    if (err != nullptr) {
      *err = std::string("failed to create access-check pipe: ") + std::strerror(errno);
    }
    return false;
  }

  const pid_t pid = fork();
  if (pid < 0) {
    if (err != nullptr) {
      *err = std::string("failed to fork access-check child: ") + std::strerror(errno);
    }
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return false;
  }

  if (pid == 0) {
    // Child: drop every privilege before touching the path.
    close(pipe_fds[0]);
    int child_errno = 0;

    // When the service is already running as the identity being checked there is
    // nothing to drop, and setgroups would fail for lack of CAP_SETGID. The open
    // below is still a faithful check because the credentials are already right.
    const bool already_target = (getuid() == uid && getgid() == gid);

    // Supplementary groups must be replaced before setgid/setuid so that no
    // root group membership survives into the probe.
    struct passwd* pwd = already_target ? nullptr : getpwuid(uid);
    if (pwd != nullptr) {
      int ngroups = 0;
      getgrouplist(pwd->pw_name, gid, nullptr, &ngroups);
      if (ngroups > 0) {
        std::vector<gid_t> groups(static_cast<std::size_t>(ngroups));
        if (getgrouplist(pwd->pw_name, gid, groups.data(), &ngroups) >= 0) {
          groups.resize(static_cast<std::size_t>(ngroups));
          if (setgroups(groups.size(), groups.data()) != 0) {
            child_errno = errno;
          }
        }
      }
    } else if (!already_target && setgroups(0, nullptr) != 0) {
      child_errno = errno;
    }

    if (child_errno == 0 && !already_target && setgid(gid) != 0) {
      child_errno = errno;
    }
    if (child_errno == 0 && !already_target && setuid(uid) != 0) {
      child_errno = errno;
    }
    // Refuse to continue if privileges somehow survived the drop.
    if (child_errno == 0 && (getuid() != uid || geteuid() != uid)) {
      child_errno = EPERM;
    }

    if (child_errno == 0) {
      const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (fd < 0) {
        child_errno = errno;
      } else {
        close(fd);
      }
    }

    const ssize_t ignored = write(pipe_fds[1], &child_errno, sizeof(child_errno));
    static_cast<void>(ignored);
    close(pipe_fds[1]);
    _exit(0);
  }

  // Parent: collect the child's errno and reap it.
  close(pipe_fds[1]);
  int child_errno = ECHILD;
  const ssize_t read_bytes = read(pipe_fds[0], &child_errno, sizeof(child_errno));
  close(pipe_fds[0]);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }

  if (read_bytes != static_cast<ssize_t>(sizeof(child_errno))) {
    if (err != nullptr) {
      *err = "access-check child did not report a result";
    }
    return false;
  }
  if (child_errno != 0) {
    if (err != nullptr) {
      *err = "uid " + std::to_string(uid) + " cannot read '" + path +
             "': " + std::strerror(child_errno);
    }
    return false;
  }
  return true;
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
    if (arg_count > kMaxFunctionArguments) {
      errors->push_back(context + ": function_arguments['" + std::string(function_name) +
                        "'] exceeds the maximum of " + std::to_string(kMaxFunctionArguments) +
                        " argument specs");
      ok = false;
      continue;
    }
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

/**
 * @brief Verify the calling user can read a path named in the signing payload.
 *
 * Paths reaching the manager are already cluster-visible in practice: the signed
 * probe file has to be readable by the root server on the compute node, and a
 * uprobe target has to be present there to be attachable at all. A path that is
 * not visible simply fails later on its own, so the manager does not police
 * where paths live; it only refuses to sign probes against files the requesting
 * user cannot read.
 *
 * @param caller Identity attested by munge, never claimed by the payload.
 * @param context Field being validated, used to prefix the error message.
 *        Example: "payload.summary.config_file_path".
 * @param path Path to check.
 * @param errors Output list collecting validation failures.
 * @param ok Cleared when the check fails.
 */
void validate_path_access_for_caller(const CallerIdentity& caller, const std::string& context,
                                     const std::string& path, std::vector<std::string>* errors,
                                     bool* ok) {
  std::string access_error;
  if (!uid_can_read_path(caller.uid, caller.gid, path, &access_error)) {
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

  if (geteuid() != 0) {
    DC_LOG_WARN(
        "Probe manager is running as uid %u, not root. Access checks for any other user will fail "
        "with EPERM because dropping privileges requires CAP_SETUID/CAP_SETGID.",
        static_cast<unsigned>(geteuid()));
  }

  DC_LOG_INFO("Datacrumbs probe manager service listening on %s:%d", host_.c_str(), port_);

  // Step 3/3: Accept connections and service each on its own thread.
  //
  // Handling serially let one peer that connected and never sent anything block
  // every other caller, including the root service reporting runtime state. Each
  // connection now runs independently under its own deadline, and the count is
  // capped so a flood cannot spawn unbounded threads.
  std::atomic<int> active_connections{0};

  for (;;) {
    const int client_fd = accept(server_fd_, nullptr, nullptr);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      DC_LOG_ERROR("Failed to accept manager connection");
      continue;
    }

    if (active_connections.load() >= DATACRUMBS_PROBE_MANAGER_MAX_CONNECTIONS) {
      DC_LOG_WARN("Refusing manager connection: %d concurrent connections already active",
                  DATACRUMBS_PROBE_MANAGER_MAX_CONNECTIONS);
      write_all_to_fd(client_fd, build_response("", false, "", "manager service is busy", -32603));
      close(client_fd);
      continue;
    }

    // Bound every send and receive on this socket so a peer that stalls mid
    // transfer cannot pin the thread past the deadline.
    struct timeval timeout{};
    timeout.tv_sec = DATACRUMBS_PROBE_MANAGER_REQUEST_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    active_connections.fetch_add(1);
    std::thread([this, client_fd, &active_connections]() {
      try {
        handle_client(client_fd);
      } catch (const std::exception& ex) {
        write_all_to_fd(client_fd, build_response("", false, "", ex.what(), -32603));
        DC_LOG_ERROR("Manager request handling failed: %s", ex.what());
      } catch (...) {
        write_all_to_fd(client_fd,
                        build_response("", false, "", "unexpected manager service error", -32603));
        DC_LOG_ERROR("Manager request handling failed: unknown exception");
      }
      close(client_fd);
      active_connections.fetch_sub(1);
    }).detach();
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

  // Authenticate before doing any work. The manager serves the whole cluster over
  // TCP, so the caller's identity comes from a munge credential bound to this
  // request's payload rather than from anything the request claims about itself.
  const std::string credential = json_string_or_empty(request_root, "credential");
  const std::string bound_payload = method == kSignMethod
                                        ? json_string_or_empty(params, "signing_payload")
                                        : json_string_or_empty(params, "state_payload");
  CallerIdentity caller;
  std::string auth_error;
  if (!authenticate_caller(credential, bound_payload, &caller, &auth_error)) {
    DC_LOG_WARN("Rejected manager RPC (%s): %s", method.c_str(), auth_error.c_str());
    json_object_put(request_root);
    write_all_to_fd(client_fd, build_response(request_id, false, "", auth_error, -32600));
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

    // Probe configuration is always attributed to a real user. Root has no
    // legitimate reason to request a signature, and allowing it would let a
    // root-run client obtain probes that bypass every per-user access check.
    if (caller.uid == 0) {
      DC_LOG_WARN("Rejected signing request from uid 0");
      write_all_to_fd(client_fd, build_response(request_id, false, "",
                                                "uid 0 may not request probe signing", -32600));
      return;
    }

    std::string error;
    const std::string document =
        sign_signing_payload(signing_payload, caller.uid, caller.gid, &error);
    if (document.empty()) {
      write_all_to_fd(client_fd, build_response(request_id, false, "", error, -32603));
    } else {
      write_all_to_fd(client_fd, build_response(request_id, true, document, "", 0));
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

  // Runtime state is only ever reported by the root datacrumbs server, which is a
  // vetted system binary started by systemd. Anyone else reaching this method is
  // either misconfigured or probing, and the shared secret alone would not say
  // which, so the attested uid is checked as well.
  if (caller.uid != 0) {
    DC_LOG_WARN("Rejected runtime state report from uid %u", static_cast<unsigned>(caller.uid));
    write_all_to_fd(client_fd, build_response(request_id, false, "",
                                              "only root may report runtime probe state", -32600));
    return;
  }

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
    json_object_object_add(result, "document", json_object_new_string(payload.c_str()));
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
  // This runs before the caller is authenticated, so it is the boundary that has
  // to hold against an anonymous peer. Three independent bounds apply: a socket
  // receive timeout so a silent peer cannot block, a total deadline so a peer
  // dribbling one byte per timeout cannot hold the connection open indefinitely,
  // and a size cap so a peer cannot exhaust memory.
  char buffer[4096];
  payload->clear();

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(DATACRUMBS_PROBE_MANAGER_REQUEST_TIMEOUT_SECONDS);
  ssize_t read_bytes = 0;
  for (;;) {
    if (std::chrono::steady_clock::now() >= deadline) {
      DC_LOG_WARN("Manager request exceeded the %d second deadline; closing connection",
                  DATACRUMBS_PROBE_MANAGER_REQUEST_TIMEOUT_SECONDS);
      return false;
    }

    read_bytes = read(fd, buffer, sizeof(buffer));
    if (read_bytes > 0) {
      if (payload->size() + static_cast<std::size_t>(read_bytes) >
          static_cast<std::size_t>(DATACRUMBS_PROBE_MANAGER_MAX_REQUEST_BYTES)) {
        DC_LOG_WARN("Manager request exceeded the %d byte limit; closing connection",
                    DATACRUMBS_PROBE_MANAGER_MAX_REQUEST_BYTES);
        return false;
      }
      payload->append(buffer, static_cast<std::size_t>(read_bytes));
      continue;
    }
    if (read_bytes < 0 && errno == EINTR) {
      continue;
    }
    // SO_RCVTIMEO surfaces as EAGAIN/EWOULDBLOCK: the peer stopped sending without
    // closing, which is the silent-connection case.
    if (read_bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      DC_LOG_WARN("Manager request timed out waiting for data; closing connection");
      return false;
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
                                                      uid_t caller_uid, gid_t caller_gid,
                                                      std::string* error) const {
  std::vector<std::string> validation_errors;
  if (!validate_signing_payload(request_payload, caller_uid, caller_gid, &validation_errors)) {
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

  // Rebuild the document from the client's payload, then overwrite the identity
  // fields with values the caller could not influence. The signature therefore
  // covers a uid attested by munge rather than one asserted in the request.
  json_object* root = json_tokener_parse(request_payload.c_str());
  if (root == nullptr || json_object_get_type(root) != json_type_object) {
    if (error != nullptr) {
      *error = "failed to parse signing payload";
    }
    if (root != nullptr) {
      json_object_put(root);
    }
    return "";
  }

  json_object* summary = nullptr;
  json_object* categories = nullptr;
  if (!json_object_object_get_ex(root, "summary", &summary) ||
      !json_object_object_get_ex(root, "categories", &categories)) {
    if (error != nullptr) {
      *error = "signing payload is missing summary or categories";
    }
    json_object_put(root);
    return "";
  }

  const std::int64_t expires_at =
      static_cast<std::int64_t>(std::time(nullptr)) + DATACRUMBS_PROBE_SIGNATURE_TTL_SECONDS;
  json_object_object_add(summary, "uid",
                         json_object_new_int64(static_cast<std::int64_t>(caller_uid)));
  json_object_object_add(summary, "schema_version",
                         json_object_new_string(datacrumbs::probe_file::kProbeSchemaVersion));
  json_object_object_add(summary, "expires_at", json_object_new_int64(expires_at));

  const std::string canonical =
      datacrumbs::probe_file::signed_document_payload(summary, categories);
  const std::string checksum = datacrumbs::probe_file::hmac_sha256_hex(secret, canonical);
  if (checksum.empty()) {
    if (error != nullptr) {
      *error = "failed to compute probe signature";
    }
    json_object_put(root);
    return "";
  }

  json_object_object_add(root, "checksum_algorithm", json_object_new_string("hmac-sha256"));
  json_object_object_add(root, "checksum", json_object_new_string(checksum.c_str()));

  const char* document = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
  const std::string result = document != nullptr ? document : "";
  json_object_put(root);

  if (result.empty() && error != nullptr) {
    *error = "failed to serialize signed document";
  }
  DC_LOG_INFO("Signed probe document for uid %u (expires at %lld)",
              static_cast<unsigned>(caller_uid), static_cast<long long>(expires_at));
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
                                                   uid_t caller_uid, gid_t caller_gid,
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
  // Identity is taken from the munge credential, never from the payload, so every
  // path check below is evaluated against the caller the kernel and munged agree on.
  const CallerIdentity caller{caller_uid, caller_gid};
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
    // `uid`, `schema_version` and `expires_at` are injected by the manager after
    // validation, so a client that supplies them is rejected rather than having
    // them silently overwritten.
    ok = validate_exact_keys(summary,
                             {"config_file_path", "probe_file_path", "hostname", "install_user"},
                             {}, "payload.summary", errors) &&
         ok;
    for (const auto& key : {"config_file_path", "probe_file_path", "hostname", "install_user"}) {
      json_object* value = nullptr;
      if (!json_object_object_get_ex(summary, key, &value) ||
          json_object_get_type(value) != json_type_string ||
          std::string(json_object_get_string(value)).empty()) {
        errors->push_back(std::string("payload.summary.") + key + " must be a non-empty string");
        ok = false;
      }
    }

    const std::string config_path = json_string_or_empty(summary, "config_file_path");
    if (!config_path.empty()) {
      validate_path_access_for_caller(caller, "payload.summary.config_file_path", config_path,
                                      errors, &ok);
    }
  }

  // Step 3/4: Validate each category/probe entry and function list constraints.
  json_object* categories = nullptr;
  if (!json_object_object_get_ex(root, "categories", &categories) ||
      json_object_get_type(categories) != json_type_array) {
    errors->push_back("payload.categories must be an array");
    ok = false;
  } else {
    // Cap the array before any per-entry work. Everything below is expensive:
    // /proc/kallsyms is parsed, and each path check forks a process to drop
    // privileges, so an uncapped array is an amplifier rather than a slow loop.
    const int probe_count = json_object_array_length(categories);
    if (probe_count > DATACRUMBS_MAX_PROBE_CATEGORIES) {
      errors->push_back("payload.categories exceeds the maximum of " +
                        std::to_string(DATACRUMBS_MAX_PROBE_CATEGORIES) + " entries");
      json_object_put(root);
      return false;
    }

    const auto kernel_symbols = load_kernel_symbols();
    if (kernel_symbols.empty()) {
      errors->push_back("failed to load kernel symbols from /proc/kallsyms");
      ok = false;
    }

    // Functions are counted across every category: the runtime enforces the same
    // ceiling when the file is loaded, so a payload above it could never be used.
    int total_function_count = 0;
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
        total_function_count += function_count;
        if (total_function_count > DATACRUMBS_MAX_RUNTIME_FUNCTIONS) {
          errors->push_back("payload.categories declares more than " +
                            std::to_string(DATACRUMBS_MAX_RUNTIME_FUNCTIONS) +
                            " functions in total, which the runtime cannot load");
          json_object_put(root);
          return false;
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
          validate_path_access_for_caller(caller, context + ".binary_path", binary_path, errors,
                                          &ok);
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
          validate_path_access_for_caller(caller, context + ".bpf_path",
                                          json_object_get_string(value), errors, &ok);
        }
        if (!json_object_object_get_ex(probe, "process_header", &value) ||
            json_object_get_type(value) != json_type_string ||
            std::string(json_object_get_string(value)).empty()) {
          errors->push_back(context + ".process_header must be a non-empty string");
          ok = false;
        } else {
          validate_path_access_for_caller(caller, context + ".process_header",
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
  // Connections are serviced concurrently now, so serialise writers rather than
  // letting two transactions race for the same sqlite file and fail as BUSY.
  static std::mutex persist_mutex;
  const std::lock_guard<std::mutex> persist_guard(persist_mutex);

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
    if (count > DATACRUMBS_MAX_RUNTIME_FUNCTIONS) {
      if (error != nullptr) {
        *error = "runtime state payload declares more than " +
                 std::to_string(DATACRUMBS_MAX_RUNTIME_FUNCTIONS) + " entries";
      }
      return false;
    }
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
