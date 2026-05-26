// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_MANAGER_PROBE_MANAGER_SERVICE_H__
#define DATACRUMBS_MANAGER_PROBE_MANAGER_SERVICE_H__

#include <string>
#include <vector>

/**
 * @brief TCP-based JSON-RPC service for probe signing and runtime probe-state ingestion.
 *
 * The service accepts requests from probe configurator clients and from runtime
 * datacrumbs servers, validates request payloads, signs probe payloads, and
 * persists runtime probe attachment outcomes for future filtering decisions.
 */
class ProbeManagerService {
 public:
  /**
  * @brief Construct the service using compile-time configured host/port settings.
  *
  * Uses values from the datacrumbs public configuration, for example:
  * - host: "127.0.0.1" or "runnervmyxb0g"
  * - port: 43123
  *
  * @throws No explicit exceptions are thrown by this constructor.
  */
  ProbeManagerService();

  /**
  * @brief Close the listening socket if it is open.
  *
  * @throws No explicit exceptions are thrown by this destructor.
  */
  ~ProbeManagerService();

  /**
  * @brief Start the manager service loop and process incoming RPC connections.
  *
  * The service accepts one request per TCP connection and sends a JSON-RPC
  * response. Per-request JSON-RPC error codes emitted by downstream handlers
  * include:
  * - -32700: parse/read failure
  * - -32601: unsupported method
  * - -32602: invalid params
  * - -32603: internal processing failure
  *
  * @return 0 if the loop exits normally, 1 on startup failure
  *         (for example secret initialization or socket bind/listen failure).
  * @throws No explicit exceptions are thrown; unexpected exceptions during
  *         request handling are caught and converted to JSON-RPC -32603.
  */
  int run();

 private:
  /**
  * @brief Create, bind, and listen on the manager TCP socket.
  *
  * @return true when socket creation/bind/listen succeeds, false otherwise.
  * @throws No explicit exceptions are thrown.
  */
  bool initialize_socket();

  /**
  * @brief Handle one client request/response exchange on an accepted socket.
  *
  * @param client_fd Accepted TCP socket file descriptor.
  *        Example: a positive FD such as 7 returned by `accept()`.
  *
  * Writes a JSON-RPC response for both success and failure cases.
  * Typical error codes written are -32700, -32601, -32602, and -32603.
  *
  * @throws May propagate unexpected standard exceptions from internal helpers;
  *         caller (`run`) catches and maps them to JSON-RPC -32603.
  */
  void handle_client(int client_fd) const;

  /**
  * @brief Build a JSON-RPC response string.
  *
  * @param request_id JSON-RPC request id.
  *        Example: "runtime-state-1" or "42".
  * @param ok true to emit a `result` object, false to emit an `error` object.
  * @param payload Success payload used as checksum value when `ok=true`.
  *        Example: "f1a5..." or "accepted".
  * @param error Error message when `ok=false`.
  *        Example: "missing signing payload".
  * @param error_code JSON-RPC error code when `ok=false`.
  *        Examples: -32700, -32601, -32602, -32603.
  * @return Serialized JSON-RPC response string.
  * @throws No explicit exceptions are thrown.
  */
  std::string build_response(const std::string& request_id, bool ok, const std::string& payload,
                             const std::string& error, int error_code) const;

  /**
  * @brief Read all bytes until EOF from a file descriptor.
  *
  * @param fd Readable file descriptor.
  *        Example: accepted client socket FD such as 7.
  * @param payload Output buffer populated with full request body.
  *        Example result: "{\"jsonrpc\":\"2.0\",...}".
  * @return true on clean EOF after reading, false on read failure.
  * @throws No explicit exceptions are thrown.
  */
  bool read_all_from_fd(int fd, std::string* payload) const;

  /**
  * @brief Write a full payload to a file descriptor.
  *
  * @param fd Writable file descriptor.
  *        Example: accepted client socket FD such as 7.
  * @param payload Serialized response body.
  *        Example: "{\"jsonrpc\":\"2.0\",\"result\":...}".
  * @return true when all bytes are written, false on write failure.
  * @throws No explicit exceptions are thrown.
  */
  bool write_all_to_fd(int fd, const std::string& payload) const;

  /**
  * @brief Validate and sign a probe-signing payload.
  *
  * @param signing_payload JSON payload to validate/sign.
  *        Example: "{\"summary\":...,\"categories\":...,\"checksum_algorithm\":\"hmac-sha256\"}".
  * @param error Output message set when signing fails.
  *        Example: "payload validation failed (...)".
  * @return Non-empty HMAC checksum on success, empty string on failure.
  * @throws No explicit exceptions are thrown.
  */
  std::string sign_signing_payload(const std::string& signing_payload, std::string* error) const;

  /**
  * @brief Authenticate and persist runtime probe state reported by a runtime node.
  *
  * @param state_payload Runtime state JSON payload.
  *        Example: "{\"database_path\":\"/tmp/...sqlite\",\"node_id\":\"n1\",...}".
  * @param state_hmac HMAC for state_payload.
  *        Example: "7d4f...".
  * @param error Output message set when auth/persistence fails.
  *        Example: "runtime state authentication failed".
  * @return true on successful auth and persistence, false otherwise.
  * @throws No explicit exceptions are thrown.
  */
  bool report_runtime_probe_state(const std::string& state_payload, const std::string& state_hmac,
                                  std::string* error) const;

  /**
  * @brief Validate the structure and semantics of the signing payload.
  *
  * @param signing_payload JSON payload to validate.
  *        Example: signed payload input used by `sign_signing_payload`.
  * @param errors Output list collecting all validation failures.
  *        Example entry: "payload.categories[0].functions[2] kernel symbol not found in /proc/kallsyms".
  * @return true when payload is valid, false when one or more checks fail.
  * @throws No explicit exceptions are thrown.
  */
  bool validate_signing_payload(const std::string& signing_payload,
                                std::vector<std::string>* errors) const;

  /**
  * @brief Persist runtime probe state entries into sqlite storage.
  *
  * @param state_payload JSON document containing database_path, node_id,
  *        invalid_entries, and successful_entries.
  *        Example: "{\"database_path\":\"/tmp/probes-runtime-status-node.sqlite\",...}".
  * @param error Output message set when sqlite operations fail.
  *        Example: "failed to prepare sqlite statements: ...".
  * @return true on successful transaction commit, false on parse/open/sql failures.
  * @throws No explicit exceptions are thrown.
  */
  bool persist_runtime_probe_state_payload(const std::string& state_payload,
                                           std::string* error) const;

  /**
   * @brief Manager TCP bind/listen host.
   * Example values: "127.0.0.1", "runnervmyxb0g".
   */
  std::string host_;

  /**
   * @brief Manager TCP bind/listen port.
   * Example value: 43123.
   */
  int port_;

  /**
   * @brief Listening server socket file descriptor.
   * -1 indicates "not initialized".
   */
  int server_fd_ = -1;
};

#endif
