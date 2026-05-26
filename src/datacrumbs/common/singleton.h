// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_config.h>
// other headers
#include <datacrumbs/common/logging.h>

// std headers
#include <memory>
#include <utility>

namespace datacrumbs {

/**
 * @brief Generic lazy singleton holder for shared ownership use-cases.
 *
 * @tparam T Singleton target type.
 */
template <typename T>
class Singleton {
 public:
  /**
  * @brief Get or create singleton instance.
  * @tparam Args Constructor argument types for T.
  * @param args Constructor arguments forwarded to T when first created.
  * @return Shared pointer to singleton instance; nullptr if finalized.
  */
  template <typename... Args>
  static std::shared_ptr<T> get_instance(Args... args) {
    DC_LOG_TRACE("Entering Singleton::get_instance");
    if (stop_creating_instances) {
      DC_LOG_WARN("Attempted to get instance after finalization");
      DC_LOG_TRACE("Exiting Singleton::get_instance");
      return nullptr;
    }
    if (instance == nullptr) {
      DC_LOG_DEBUG("Creating new instance of Singleton<%s>", typeid(T).name());
      instance = std::make_shared<T>(std::forward<Args>(args)...);
    } else {
      DC_LOG_DEBUG("Returning existing instance of Singleton<%s>", typeid(T).name());
    }
    DC_LOG_TRACE("Exiting Singleton::get_instance");
    return instance;
  }

  Singleton& operator=(const Singleton) = delete;
  Singleton(const Singleton&) = delete;

  /**
   * @brief Mark singleton as finalized and prevent further creation.
   */
  static void finalize() {
    DC_LOG_INFO("Finalizing Singleton<%s>, no further instances will be created", typeid(T).name());
    stop_creating_instances = true;
  }

 protected:
  /// Prevents new instance creation after finalize().
  static bool stop_creating_instances;
  /// Shared singleton instance.
  static std::shared_ptr<T> instance;

  Singleton() {}
};

}  // namespace datacrumbs
