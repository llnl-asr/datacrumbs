// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_PROBE_FILE_H__
#define DATACRUMBS_COMMON_PROBE_FILE_H__

#include <fcntl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace datacrumbs::probe_file {

/**
 * @brief Probe secret file path used for HMAC signing and verification.
 * @return Filesystem path to the probe secret.
 */
inline std::filesystem::path secret_path() {
  return DATACRUMBS_PROBE_SECRET_FILE;
}

/**
 * @brief Convert bytes to lowercase hex string.
 * @param data Input byte buffer.
 * @param size Number of bytes.
 * @return Hex representation.
 */
inline std::string bytes_to_hex(const unsigned char* data, std::size_t size) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < size; ++i) {
    oss << std::setw(2) << static_cast<unsigned int>(data[i]);
  }
  return oss.str();
}

/**
 * @brief Read text file content.
 * @param path File path.
 * @return File content, or empty string on open failure.
 */
inline std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    return "";
  }
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

/**
 * @brief Read probe payload from plain or gzip-compressed file.
 * @param path Probe file path.
 * @return Decoded payload text, or empty string on failure.
 */
inline std::string read_probe_payload(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return "";
  }

  unsigned char magic[2] = {0, 0};
  input.read(reinterpret_cast<char*>(magic), sizeof(magic));
  input.close();

  const bool is_gzip = magic[0] == 0x1f && magic[1] == 0x8b;
  if (!is_gzip) {
    return read_text_file(path);
  }

  gzFile gz_file = gzopen(path.string().c_str(), "rb");
  if (gz_file == nullptr) {
    return "";
  }

  std::string payload;
  char buffer[4096];
  int read_bytes = 0;
  while ((read_bytes = gzread(gz_file, buffer, sizeof(buffer))) > 0) {
    payload.append(buffer, read_bytes);
  }
  gzclose(gz_file);
  return payload;
}

/**
 * @brief Write a file with owner-only permissions.
 * @param path Destination path.
 * @param content File content.
 * @return True if write and permission updates succeed.
 */
inline bool write_owner_only_file(const std::filesystem::path& path, const std::string& content) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    return false;
  }

  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    return false;
  }

  const ssize_t written = write(fd, content.data(), content.size());
  const bool chown_ok = (geteuid() != 0) || (fchown(fd, 0, 0) == 0);
  const bool chmod_ok = (fchmod(fd, S_IRUSR) == 0);
  const bool close_ok = (close(fd) == 0);
  return written == static_cast<ssize_t>(content.size()) && chown_ok && chmod_ok && close_ok;
}

/**
 * @brief Write gzip-compressed file content.
 * @param path Destination path.
 * @param payload Uncompressed payload text.
 * @return True on successful gzip write.
 */
inline bool write_gzip_file(const std::filesystem::path& path, const std::string& payload) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    return false;
  }

  gzFile gz_file = gzopen(path.string().c_str(), "wb");
  if (gz_file == nullptr) {
    return false;
  }

  const int written = gzwrite(gz_file, payload.data(), static_cast<unsigned int>(payload.size()));
  const int close_status = gzclose(gz_file);
  chmod(path.c_str(), S_IRUSR | S_IWUSR);
  return written > 0 && close_status == Z_OK;
}

/**
 * @brief Ensure probe secret exists and is owner-restricted.
 * @param secret_out Optional output with loaded/generated secret.
 * @return True when secret is available for signing.
 */
inline bool ensure_probe_secret(std::string* secret_out = nullptr) {
  const auto path = secret_path();
  std::string secret = read_text_file(path);
  if (!secret.empty()) {
    if (geteuid() == 0) {
      chown(path.c_str(), 0, 0);
    }
    chmod(path.c_str(), S_IRUSR);
    if (secret_out != nullptr) {
      *secret_out = secret;
    }
    return true;
  }

  std::error_code ec;
  if (std::filesystem::exists(path, ec) && geteuid() != 0) {
    return false;
  }
  if (geteuid() != 0) {
    return false;
  }

  unsigned char random_bytes[32];
  if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
    return false;
  }

  secret = bytes_to_hex(random_bytes, sizeof(random_bytes));
  if (!write_owner_only_file(path, secret)) {
    return false;
  }

  if (secret_out != nullptr) {
    *secret_out = secret;
  }
  return true;
}

/**
 * @brief Compute HMAC SHA-256 in hex form.
 * @param secret Shared signing secret.
 * @param payload Payload to sign.
 * @return Hex checksum, or empty string on HMAC failure.
 */
inline std::string hmac_sha256_hex(const std::string& secret, const std::string& payload) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  if (HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
           reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest,
           &digest_len) == nullptr) {
    return "";
  }
  return bytes_to_hex(digest, digest_len);
}

/**
 * @brief Compute SHA-256 of a payload in hex form.
 *
 * Used to bind a munge credential to the exact request it accompanies, so a
 * credential captured inside its TTL cannot be replayed against a different
 * payload.
 *
 * @param payload Payload to digest. Example: a serialized signing payload.
 * @return Hex digest, or empty string on digest failure.
 */
inline std::string sha256_hex(const std::string& payload) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return "";
  }
  const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(ctx, payload.data(), payload.size()) == 1 &&
                  EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok) {
    return "";
  }
  return bytes_to_hex(digest, digest_len);
}

/**
 * @brief Schema version of the signed probe document.
 *
 * Version "2" replaced the client-asserted `user` field with a manager-injected
 * numeric `uid`, and added `expires_at`. Documents without a matching version
 * are rejected rather than interpreted under the old rules.
 */
inline constexpr const char* kProbeSchemaVersion = "2";

/**
 * @brief Sentinel meaning "do not enforce a uid" when verifying a document.
 */
inline constexpr uid_t kAnyUid = static_cast<uid_t>(-1);

/**
 * @brief Serialize categories object for signing.
 * @param categories JSON categories array/object.
 * @return Compact JSON payload string.
 */
inline std::string categories_payload(json_object* categories) {
  const char* payload = json_object_to_json_string_ext(categories, JSON_C_TO_STRING_PLAIN);
  return payload != nullptr ? payload : "";
}

/**
 * @brief Build canonical JSON payload for signature verification.
 * @param summary Summary object.
 * @param categories Categories object.
 * @return Canonical compact JSON string.
 */
inline std::string signed_document_payload(json_object* summary, json_object* categories) {
  json_object* root = json_object_new_object();
  json_object_object_add(root, "summary", json_object_get(summary));
  json_object_object_add(root, "categories", json_object_get(categories));
  json_object_object_add(root, "checksum_algorithm", json_object_new_string("hmac-sha256"));
  const char* payload = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
  const std::string result = payload != nullptr ? payload : "";
  json_object_put(root);
  return result;
}

/**
 * @brief Build signed categories document with checksum.
 * @param categories Categories JSON array.
 * @param summary_fields Summary key/value fields.
 * @param secret HMAC secret.
 * @return Newly created JSON document (caller owns ref).
 */
inline json_object* build_signed_categories_document(
    json_object* categories, const std::unordered_map<std::string, std::string>& summary_fields,
    const std::string& secret) {
  json_object* root = json_object_new_object();
  json_object* summary = json_object_new_object();

  for (const auto& [key, value] : summary_fields) {
    json_object_object_add(summary, key.c_str(), json_object_new_string(value.c_str()));
  }

  json_object_object_add(root, "summary", summary);
  json_object_object_add(root, "categories", json_object_get(categories));
  json_object_object_add(root, "checksum_algorithm", json_object_new_string("hmac-sha256"));
  const std::string payload = signed_document_payload(summary, categories);
  json_object_object_add(root, "checksum",
                         json_object_new_string(hmac_sha256_hex(secret, payload).c_str()));
  return root;
}

/**
 * @brief Validate signed root document and extract categories.
 * @param root Root JSON object.
 * @param secret HMAC secret.
 * @param error Optional error message on validation failure.
 * @return Borrowed categories object reference on success, nullptr on failure.
 */
inline json_object* verified_categories_from_root(json_object* root, const std::string& secret,
                                                  std::string* error = nullptr,
                                                  uid_t expected_uid = kAnyUid) {
  if (root == nullptr || json_object_get_type(root) != json_type_object) {
    if (error != nullptr) {
      *error = "probe file root must be a JSON object";
    }
    return nullptr;
  }

  json_object* categories = nullptr;
  json_object* summary = nullptr;
  json_object* checksum_obj = nullptr;
  json_object* algorithm_obj = nullptr;
  if (!json_object_object_get_ex(root, "summary", &summary) ||
      json_object_get_type(summary) != json_type_object) {
    if (error != nullptr) {
      *error = "probe file is missing summary object";
    }
    return nullptr;
  }
  if (!json_object_object_get_ex(root, "categories", &categories) ||
      json_object_get_type(categories) != json_type_array) {
    if (error != nullptr) {
      *error = "probe file is missing a categories array";
    }
    return nullptr;
  }

  if (!json_object_object_get_ex(root, "checksum", &checksum_obj) ||
      json_object_get_type(checksum_obj) != json_type_string) {
    if (error != nullptr) {
      *error = "probe file is missing checksum";
    }
    return nullptr;
  }
  if (!json_object_object_get_ex(root, "checksum_algorithm", &algorithm_obj) ||
      json_object_get_type(algorithm_obj) != json_type_string ||
      std::string(json_object_get_string(algorithm_obj)) != "hmac-sha256") {
    if (error != nullptr) {
      *error = "probe file checksum algorithm is unsupported";
    }
    return nullptr;
  }

  const std::string expected =
      hmac_sha256_hex(secret, signed_document_payload(summary, categories));
  const std::string actual = json_object_get_string(checksum_obj);
  if (expected.empty() || actual != expected) {
    if (error != nullptr) {
      *error = "probe file checksum verification failed";
    }
    return nullptr;
  }

  // A valid signature only proves the manager produced this document. It must
  // also be the document this consumer is entitled to use, otherwise any signed
  // probe file is a bearer token usable by any user on any node.
  json_object* schema_obj = nullptr;
  if (!json_object_object_get_ex(summary, "schema_version", &schema_obj) ||
      json_object_get_type(schema_obj) != json_type_string ||
      std::string(json_object_get_string(schema_obj)) != kProbeSchemaVersion) {
    if (error != nullptr) {
      *error = std::string("probe file schema version is not '") + kProbeSchemaVersion +
               "'; regenerate the probe file";
    }
    return nullptr;
  }

  json_object* expires_obj = nullptr;
  if (!json_object_object_get_ex(summary, "expires_at", &expires_obj) ||
      json_object_get_type(expires_obj) != json_type_int) {
    if (error != nullptr) {
      *error = "probe file summary is missing expires_at";
    }
    return nullptr;
  }
  const std::int64_t expires_at = json_object_get_int64(expires_obj);
  const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
  if (now >= expires_at) {
    if (error != nullptr) {
      *error = "probe file signature expired at " + std::to_string(expires_at) + " (now " +
               std::to_string(now) + "); regenerate the probe file";
    }
    return nullptr;
  }

  json_object* uid_obj = nullptr;
  if (!json_object_object_get_ex(summary, "uid", &uid_obj) ||
      json_object_get_type(uid_obj) != json_type_int) {
    if (error != nullptr) {
      *error = "probe file summary is missing uid";
    }
    return nullptr;
  }
  if (expected_uid != kAnyUid) {
    const uid_t document_uid = static_cast<uid_t>(json_object_get_int64(uid_obj));
    if (document_uid != expected_uid) {
      if (error != nullptr) {
        *error = "probe file was signed for uid " + std::to_string(document_uid) +
                 " but is being loaded for uid " + std::to_string(expected_uid);
      }
      return nullptr;
    }
  }

  return json_object_get(categories);
}

/**
 * @brief Load, verify, and return categories from signed probe file.
 * @param path Probe file path.
 * @param error Optional error detail.
 * @return Categories JSON object on success, nullptr on failure.
 */
inline json_object* load_verified_categories_from_file(const std::filesystem::path& path,
                                                       std::string* error = nullptr,
                                                       uid_t expected_uid = kAnyUid) {
  std::string secret;
  if (!ensure_probe_secret(&secret)) {
    if (error != nullptr) {
      *error = "failed to read or create probe signing secret";
    }
    return nullptr;
  }

  const std::string payload = read_probe_payload(path);
  if (payload.empty()) {
    if (error != nullptr) {
      *error = "failed to read probe file";
    }
    return nullptr;
  }

  json_object* root = json_tokener_parse(payload.c_str());
  if (root == nullptr) {
    if (error != nullptr) {
      *error = "failed to parse probe file";
    }
    return nullptr;
  }

  json_object* categories = verified_categories_from_root(root, secret, error, expected_uid);
  json_object_put(root);
  return categories;
}

}  // namespace datacrumbs::probe_file

#endif
