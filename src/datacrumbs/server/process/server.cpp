// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/common/logging.h>
#include <datacrumbs/server/bpf/datacrumbs.skel.h>

#include <datacrumbs/server/process/server.impl.cpp>
#include <exception>

int main(int argc, char** argv) {
  try {
    return main_call(argc, argv);
  } catch (const std::exception& ex) {
    DC_LOG_ERROR("datacrumbs fatal exception: %s", ex.what());
    return 1;
  } catch (...) {
    DC_LOG_ERROR("datacrumbs fatal unknown exception");
    return 1;
  }
}