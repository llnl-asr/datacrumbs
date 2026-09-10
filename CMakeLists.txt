cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0075 NEW)
project(datacrumbs LANGUAGES C CXX)
include(CMakePackageConfigHelpers)

# ------------------------------------------------------------------------------
# Version information
# ------------------------------------------------------------------------------
set(DATACRUMBS_VERSION_MAJOR "1")
set(DATACRUMBS_VERSION_MINOR "0")
set(DATACRUMBS_VERSION_PATCH "0")
set(DATACRUMBS_PACKAGE ${PROJECT_NAME})
set(DATACRUMBS_PACKAGE_NAME ${PROJECT_NAME})
set(DATACRUMBS_PACKAGE_VERSION "${DATACRUMBS_VERSION_MAJOR}.${DATACRUMBS_VERSION_MINOR}.${DATACRUMBS_VERSION_PATCH}")
set(DATACRUMBS_PACKAGE_VERSION_MAJOR "${DATACRUMBS_VERSION_MAJOR}.${DATACRUMBS_VERSION_MINOR}")
set(DATACRUMBS_PACKAGE_VERSION_MINOR "${DATACRUMBS_VERSION_PATCH}")
set(DATACRUMBS_PACKAGE_STRING "${DATACRUMBS_PACKAGE_NAME} ${DATACRUMBS_PACKAGE_VERSION}")
set(DATACRUMBS_PACKAGE_TARNAME "${DATACRUMBS_PACKAGE}")

set(DATACRUMBS_RELEASE_VERSION_MAJOR "0")
set(DATACRUMBS_RELEASE_VERSION_MINOR "0")
set(DATACRUMBS_RELEASE_VERSION_PATCH "4")
set(DATACRUMBS_VERSION "(${DATACRUMBS_RELEASE_VERSION_MAJOR}, ${DATACRUMBS_RELEASE_VERSION_MINOR}, ${DATACRUMBS_RELEASE_VERSION_PATCH})")
set(DATACRUMBS_RELEASE_VERSION_STRING "${DATACRUMBS_RELEASE_VERSION_MAJOR}.${DATACRUMBS_RELEASE_VERSION_MINOR}.${DATACRUMBS_RELEASE_VERSION_PATCH}")
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/datacrumbs_utils_compatibility.cmake)

# Convenience defines
string(TOUPPER "${PROJECT_NAME}" UPPER_PROJECT_NAME)
string(TOLOWER "${PROJECT_NAME}" LOWER_PROJECT_NAME)

# This sets where to look for dependent library's cmake files
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR}/${DATACRUMBS_LIBDIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR}/share/cmake)
include(datacrumbs-utils)

# ------------------------------------------------------------------------------
# For building only the library without installation
# ------------------------------------------------------------------------------
option(DATACRUMBS_BUILD_ONLY "Build only the datacrumbs library without installation" OFF)

load_build_variables()

message(STATUS "[${UPPER_PROJECT_NAME}] DATACRUMBS_LIBDIR set to ${DATACRUMBS_LIBDIR}")
message(
  STATUS
    "[${UPPER_PROJECT_NAME}] Compatible datacrumbs-utils ref: ${DATACRUMBS_UTILS_COMPATIBLE_REPOSITORY}@${DATACRUMBS_UTILS_COMPATIBLE_REF}"
)

# ------------------------------------------------------------------------------
# Internal Paths for cmake libraries and Setup install and output Directories
# ------------------------------------------------------------------------------
# This sets where to look for dependent libraries
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_BINARY_DIR} ${CMAKE_INSTALL_PREFIX})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_BINARY_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/libexec)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# ------------------------------------------------------------------------------
# Options for CMake
# ------------------------------------------------------------------------------
option(DATACRUMBS_BPFTIME_COMPATIBLE "Enable compatibility with bpftime" OFF)
option(DATACRUMBS_ENABLE_OPT "Enable tracing" ON)
option(DATACRUMBS_TRACE_ALL_PROCESSES_OPT "Trace all processes" OFF)
option(DATACRUMBS_BPF_PRINT_ENABLE "Enable BPF print" OFF)
set(DATACRUMBS_MODE_STR "TRACE" CACHE STRING "Mode for datacrumbs (TRACE or PROFILE)")
set_property(CACHE DATACRUMBS_MODE_STR PROPERTY STRINGS TRACE PROFILE)

# options for managing installation
set(BPFTOOL_EXECUTABLE "NONE" CACHE STRING "Path to bpftool executable")

set(DATACRUMBS_INCLUSION_PATH "NONE" CACHE STRING "Inclusion path for datacrumbs")
set(DATACRUMBS_CONFIGURED_TRACE_DIR "/tmp" CACHE STRING "Trace directory for datacrumbs")
set(DATACRUMBS_CONFIGURED_LOG_DIR "/tmp" CACHE STRING "Log directory for datacrumbs")
set(DATACRUMBS_CONFIGURED_RUN_DIR "NONE" CACHE STRING "Run directory for datacrumbs")
set(DATACRUMBS_KERNEL_HEADERS_PATH "" CACHE PATH "Override path to the kernel headers for datacrumbs")
set(DATACRUMBS_HOST "NONE" CACHE STRING "Host name for datacrumbs")
set(DATACRUMBS_USER "$ENV{USER}" CACHE STRING "User name for datacrumbs")
set(DATACRUMBS_INSTALL_USER "$ENV{USER}" CACHE STRING "Installation user name for datacrumbs")
set(DATACRUMBS_SCHEDULER_TYPE "FLUX" CACHE STRING "Scheduler type for datacrumbs")
set_property(CACHE DATACRUMBS_SCHEDULER_TYPE PROPERTY STRINGS FLUX SLURM OPENMPI NONE)
set(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR "NONE" CACHE STRING "Scheduler job ID environment variable name")

# Tracing Options
set(DATACRUMBS_TRACE_RINGBUF_SIZE_MB "16" CACHE STRING "Ring buffer size in MB for BPF tracing")
set(DATACRUMBS_MAX_RUNTIME_FUNCTIONS "16384" CACHE STRING "Maximum number of runtime functions supported in one probes file")
set(DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS "1000" CACHE STRING "Threshold in microseconds for skipping events")

# Profiling Options
set(DATACRUMBS_TIME_INTERVAL_NS "1000000" CACHE STRING "Profiling time interval in nanosecond")

# Other options
set(DATACRUMBS_LOG_LEVEL_STR "INFO" CACHE STRING "Log Level for compiling ${UPPER_PROJECT_NAME}")
set_property(CACHE DATACRUMBS_LOG_LEVEL_STR PROPERTY STRINGS ERROR WARN INFO DEBUG TRACE)
option(DATACRUMBS_BUILD_ONLY "Build only the datacrumbs library without installation" OFF)
cmake_host_system_information(RESULT DATACRUMBS_DEFAULT_PROBE_MANAGER_TCP_HOST QUERY HOSTNAME)
set(DATACRUMBS_PROBE_MANAGER_TCP_HOST "${DATACRUMBS_DEFAULT_PROBE_MANAGER_TCP_HOST}" CACHE STRING "Host address for datacrumbs probe manager RPC service")
set(DATACRUMBS_PROBE_MANAGER_TCP_PORT "43123" CACHE STRING "TCP port for datacrumbs probe manager RPC service")
# Resource bounds for the probe manager RPC service. The read path runs before a
# caller is authenticated, so these limits are what stop an unauthenticated peer
# from starving the service.
set(DATACRUMBS_PROBE_MANAGER_MAX_REQUEST_BYTES "8388608" CACHE STRING "Maximum accepted request size in bytes for the probe manager")
set(DATACRUMBS_PROBE_MANAGER_REQUEST_TIMEOUT_SECONDS "30" CACHE STRING "Per-connection deadline in seconds for probe manager requests")
set(DATACRUMBS_PROBE_MANAGER_MAX_CONNECTIONS "32" CACHE STRING "Maximum concurrent probe manager connections")
set(DATACRUMBS_MAX_PROBE_CATEGORIES "4096" CACHE STRING "Maximum probe categories accepted in one signing payload")
# Lifetime of a probe signature. A signed probe file stops being accepted at load
# time once this elapses, bounding how long a leaked file remains usable.
set(DATACRUMBS_PROBE_SIGNATURE_TTL_SECONDS "604800" CACHE STRING "Seconds a datacrumbs probe signature remains valid")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/find_munge.cmake)

# ------------------------------------------------------------------------------
# Derive CMake variables based on options
# ------------------------------------------------------------------------------
derive_configurations()

# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Find system details
# ------------------------------------------------------------------------------
find_system_details()

# ------------------------------------------------------------------------------
set(DATACRUMBS_INSTALL_PREFIX_PATH "${CMAKE_INSTALL_PREFIX}")
set(DATACRUMBS_INSTALL_HOST "${DATACRUMBS_HOST}")
set(DATACRUMBS_INSTALL_CONFIGS_DIR "${DATACRUMBS_INSTALL_ETC_CONFIGSDIR}")
set(DATACRUMBS_INSTALL_SHARED_DATA_DIR "${CMAKE_INSTALL_PREFIX}/share/datacrumbs/data")
set(DATACRUMBS_INSTALL_DATA_DIR "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}")
set(DATACRUMBS_SYSTEM_PROBE_FILE
    "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/system-probe-${DATACRUMBS_INSTALL_USER}-${DATACRUMBS_HOST}.sqlite"
)
set(DATACRUMBS_PROBE_SECRET_FILE
    "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/.datacrumbs-probe-secret"
)
set(DATACRUMBS_PROBE_MANAGER_SOCKET_PATH
    "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/datacrumbs-probe-manager.sock"
)
set(DATACRUMBS_TRACE_DIR_PATTERN "${DATACRUMBS_CONFIGURED_TRACE_DIR}/%YY%/%MM%/%DD%")
set(DATACRUMBS_CLIENT_LIB "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/libdatacrumbs_client.so")
set(DATACRUMBS_JOB_SCHEDULER "${DATACRUMBS_SCHEDULER_TYPE}")
set(DATACRUMBS_JOB_ID_VAR "${DATACRUMBS_SCHEDULER_JOBID_ENV_VAR}")
if(DATACRUMBS_ENABLE_INCLUSION_PATH)
  set(DATACRUMBS_INCLUSION_PATHS "${DATACRUMBS_INCLUSION_PATH}")
else()
  set(DATACRUMBS_INCLUSION_PATHS "")
endif()
set(DATACRUMBS_SERVER_RUN_DIR "${DATACRUMBS_INSTALL_RUNSTATEDIR}/datacrumbs")
set(DATACRUMBS_SERVER_RUN_ID_FILE "${DATACRUMBS_SERVER_RUN_DIR}/datacrumbs.runid")

set(DATACRUMBS_SYSTEM_CONFIGURATION_DEFINE_KEYS
    DATACRUMBS_INSTALL_PREFIX
    DATACRUMBS_INSTALL_HOST
    DATACRUMBS_INSTALL_USER
    DATACRUMBS_INSTALL_BIN_DIR
    DATACRUMBS_INSTALL_SBIN_DIR
    DATACRUMBS_INSTALL_LIB_DIR
    DATACRUMBS_INSTALL_LIBEXEC_DIR
    DATACRUMBS_INSTALL_ETC_DIR
    DATACRUMBS_INSTALL_DATA_DIR
    DATACRUMBS_INSTALL_MODULES_DIR
    DATACRUMBS_INSTALL_PROBE_OBJECTS_DIR
    DATACRUMBS_CLIENT_LIB
    DATACRUMBS_JOB_SCHEDULER
    DATACRUMBS_JOB_ID_VAR
    DATACRUMBS_SERVER_RUN_DIR
    DATACRUMBS_CONFIGURED_TRACE_DIR
    DATACRUMBS_USER
    DATACRUMBS_INCLUSION_PATHS
    DATACRUMBS_KERNEL_UNAME_R
    DATACRUMBS_KERNEL_HEADERS_PATH
    DATACRUMBS_LIBC_SO
    DATACRUMBS_PROBE_MANAGER_TCP_HOST
    DATACRUMBS_PROBE_MANAGER_TCP_PORT
    DATACRUMBS_PROBE_MANAGER_MAX_REQUEST_BYTES
    DATACRUMBS_PROBE_MANAGER_REQUEST_TIMEOUT_SECONDS
    DATACRUMBS_PROBE_MANAGER_MAX_CONNECTIONS
    DATACRUMBS_MAX_PROBE_CATEGORIES
    DATACRUMBS_PROBE_SIGNATURE_TTL_SECONDS
)

set(DATACRUMBS_INSTALL_PREFIX "${DATACRUMBS_INSTALL_PREFIX_PATH}")
set(DATACRUMBS_INSTALL_BIN_DIR "${DATACRUMBS_INSTALL_BINARYDIR}")
set(DATACRUMBS_INSTALL_SBIN_DIR "${DATACRUMBS_INSTALL_SBINARYDIR}")
set(DATACRUMBS_INSTALL_LIBEXEC_DIR "${DATACRUMBS_INSTALL_LIBEXEC}")
set(DATACRUMBS_INSTALL_ETC_DIR "${DATACRUMBS_INSTALL_SYSCONFDIR}")
set(DATACRUMBS_INSTALL_MODULES_DIR "${DATACRUMBS_INSTALL_ETC_MODULESDIR}")
set(DATACRUMBS_INSTALL_PROBE_OBJECTS_DIR "${DATACRUMBS_INSTALL_LIBEXEC}/objects")

set(DATACRUMBS_SYSTEM_CONFIGURATION_DEFINES "")
foreach(_dc_key IN LISTS DATACRUMBS_SYSTEM_CONFIGURATION_DEFINE_KEYS)
  if(NOT DEFINED ${_dc_key})
    continue()
  endif()
  set(_dc_value "${${_dc_key}}")
  if("${_dc_value}" STREQUAL "")
    continue()
  endif()
  if(_dc_value MATCHES "^[+-]?[0-9]+$")
    string(APPEND DATACRUMBS_SYSTEM_CONFIGURATION_DEFINES "#define ${_dc_key} ${_dc_value}\n")
  else()
    string(REPLACE "\\" "\\\\" _dc_escaped "${_dc_value}")
    string(REPLACE "\"" "\\\"" _dc_escaped "${_dc_escaped}")
    string(APPEND DATACRUMBS_SYSTEM_CONFIGURATION_DEFINES "#define ${_dc_key} \"${_dc_escaped}\"\n")
  endif()
endforeach()

# ------------------------------------------------------------------------------
# Generate Header file for all sources with compile definitions
# ------------------------------------------------------------------------------
message(STATUS "[${UPPER_PROJECT_NAME}] Set Variables for CMake")
message(STATUS "             - DATACRUMBS_LOG_LEVEL: ${DATACRUMBS_LOG_LEVEL}")
message(STATUS "             - DATACRUMBS_BPFTIME_COMPATIBLE: ${DATACRUMBS_BPFTIME_COMPATIBLE}")
message(STATUS "             - DATACRUMBS_MODE: ${DATACRUMBS_MODE}")
message(STATUS "             - DATACRUMBS_ENABLE: ${DATACRUMBS_ENABLE}")
message(STATUS "             - DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS: ${DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS}")
message(STATUS "             - DATACRUMBS_MAX_RUNTIME_FUNCTIONS: ${DATACRUMBS_MAX_RUNTIME_FUNCTIONS}")
message(STATUS "             - DATACRUMBS_TRACE_ALL_PROCESSES: ${DATACRUMBS_TRACE_ALL_PROCESSES}")
message(STATUS "             - DATACRUMBS_TIME_INTERVAL_NS: ${DATACRUMBS_TIME_INTERVAL_NS}")
message(STATUS "             - DATACRUMBS_BPF_PRINT_ENABLE_FLAG: ${DATACRUMBS_BPF_PRINT_ENABLE_FLAG}")
message(STATUS "             - DATACRUMBS_TRACE_RINGBUF_SIZE_MB: ${DATACRUMBS_TRACE_RINGBUF_SIZE_MB}")

message(STATUS "             - DATACRUMBS_SRC_GEN_PATH: ${DATACRUMBS_SRC_GEN_PATH}")
message(STATUS "             - DATACRUMBS_LIBC_SO: ${DATACRUMBS_LIBC_SO}")

message(STATUS "             - DATACRUMBS_LOG_DIR: ${DATACRUMBS_LOG_DIR}")
message(STATUS "             - DATACRUMBS_DATA_DIR: ${DATACRUMBS_DATA_DIR}")
message(STATUS "             - DATACRUMBS_ENABLE_INCLUSION_PATH: ${DATACRUMBS_ENABLE_INCLUSION_PATH}")
message(STATUS "             - Kernel Version: ${KERNEL_VERSION_MAJOR}.${KERNEL_VERSION_MINOR}.${KERNEL_VERSION_PATCH}")
message(STATUS "             - DATACRUMBS_BUILD_ONLY: ${DATACRUMBS_BUILD_ONLY}")
message(STATUS "             - DATACRUMBS_INSTALL_USER: ${DATACRUMBS_INSTALL_USER}")
message(STATUS "             - DATACRUMBS_USER: ${DATACRUMBS_USER}")
message(STATUS "             - Found kernel headers at: ${DATACRUMBS_KERNEL_HEADERS_PATH}")
message(STATUS "             - DATACRUMBS_KERNEL_UNAME_R: ${DATACRUMBS_KERNEL_UNAME_R}")
message(STATUS "             - DATACRUMBS_CONFIGURED_TRACE_DIR: ${DATACRUMBS_CONFIGURED_TRACE_DIR}")
message(STATUS "             - DATACRUMBS_CONFIGURED_LOG_DIR: ${DATACRUMBS_CONFIGURED_LOG_DIR}")
message(STATUS "             - DATACRUMBS_LAUNCHER_TYPE: ${DATACRUMBS_LAUNCHER_TYPE}")
message(STATUS "             - DATACRUMBS_SCHEDULER_JOBID_ENV_VAR: ${DATACRUMBS_SCHEDULER_JOBID_ENV_VAR}")
message(STATUS "             - DATACRUMBS_SYSTEM_PROBE_FILE: ${DATACRUMBS_SYSTEM_PROBE_FILE}")
message(STATUS "             - DATACRUMBS_PROBE_SECRET_FILE: ${DATACRUMBS_PROBE_SECRET_FILE}")
message(STATUS "             - DATACRUMBS_PROBE_MANAGER_TCP_HOST: ${DATACRUMBS_PROBE_MANAGER_TCP_HOST}")
message(STATUS "             - DATACRUMBS_PROBE_MANAGER_TCP_PORT: ${DATACRUMBS_PROBE_MANAGER_TCP_PORT}")

# ------------------------------------------------------------------------------
# Configure output files for build
# ------------------------------------------------------------------------------
configure_file("${CMAKE_SOURCE_DIR}/cmake/configure_files/datacrumbs_config.h.in"
    "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs/datacrumbs_config.h" @ONLY)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/plugins/custom_probes/custom_probes.h.in"
    "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/custom_probes.h" @ONLY)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/plugins/custom_probes/custom_probes_process.h.in"
    "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/custom_probes_process.h" @ONLY)

# ------------------------------------------------------------------------------
# Make output directories
# ------------------------------------------------------------------------------
file(MAKE_DIRECTORY ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/server/process/)
file(MAKE_DIRECTORY ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/server/bpf/objects/)
file(MAKE_DIRECTORY ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/server/bpf/src/)
file(MAKE_DIRECTORY ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/objects/)

# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Find all dependencies
# ------------------------------------------------------------------------------
include_dependencies()

# print_all_variables()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Sources for Datacrumbs Components
# ------------------------------------------------------------------------------
set(DATACRUMBS_COMMON_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/data_structures.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/enumerations.h
)
set(DATACRUMBS_PUBLIC_COMMON_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/constants.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/data_structures.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/enumerations.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/logging.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/probe_file.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/singleton.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/typedefs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/utils.h
)
add_library(datacrumbs_common INTERFACE)
target_include_directories(
  datacrumbs_common
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_INCLUDE_OUTPUT_DIRECTORY}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)
install(
  TARGETS datacrumbs_common
  EXPORT datacrumbsTargets
)
install(FILES "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs/datacrumbs_config.h"
        DESTINATION "${DATACRUMBS_INSTALL_INCLUDE_DIR}/datacrumbs")
install(FILES ${DATACRUMBS_PUBLIC_COMMON_HEADERS}
        DESTINATION "${DATACRUMBS_INSTALL_INCLUDE_DIR}/datacrumbs/common")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/datacrumbsConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/datacrumbsConfig.cmake"
  INSTALL_DESTINATION "${DATACRUMBS_INSTALL_LIB_DIR}/cmake/datacrumbs"
  PATH_VARS
    DATACRUMBS_INSTALL_INCLUDE_DIR
    DATACRUMBS_INSTALL_LIB_DIR
    DATACRUMBS_INSTALL_BINARYDIR
    DATACRUMBS_INSTALL_SBINARYDIR
    DATACRUMBS_INSTALL_SYSCONFDIR
    DATACRUMBS_INSTALL_SHARED_DATA_DIR
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/datacrumbsConfigVersion.cmake"
  VERSION "${DATACRUMBS_PACKAGE_VERSION}"
  COMPATIBILITY SameMajorVersion
)
install(
  EXPORT datacrumbsTargets
  FILE datacrumbsTargets.cmake
  NAMESPACE datacrumbs::
  DESTINATION "${DATACRUMBS_INSTALL_LIB_DIR}/cmake/datacrumbs"
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/datacrumbsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/datacrumbsConfigVersion.cmake"
  DESTINATION "${DATACRUMBS_INSTALL_LIB_DIR}/cmake/datacrumbs"
)

set(DATACRUMBS_PROBE_MANAGER_SERVICE_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/manager/probe_manager_service_main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/manager/probe_manager_service.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/manager/probe_manager_service.h
)

add_executable(datacrumbs_probe_manager ${DATACRUMBS_PROBE_MANAGER_SERVICE_SRC} ${DATACRUMBS_COMMON_SRC})
target_link_libraries(datacrumbs_probe_manager ${DEPENDENCY_LIB} Munge::Munge)
install(TARGETS datacrumbs_probe_manager
    RUNTIME DESTINATION "${DATACRUMBS_INSTALL_SBINARYDIR}"
)

# Generate vmlinux.h from vmlinux BTF
set(VMLINUX_HEADER "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs/server/bpf/vmlinux.h")

add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs/server/bpf
    COMMAND ${BPFTOOL_EXECUTABLE} btf dump file ${VMLINUX_BTF_PATH} format c > ${VMLINUX_HEADER}
    DEPENDS ${VMLINUX_BTF_PATH}
    COMMENT "[${UPPER_PROJECT_NAME}] Generating vmlinux.h from ${VMLINUX_BTF_PATH} (timed)"
    VERBATIM
)
add_custom_target(vmlinux_header ALL DEPENDS ${VMLINUX_HEADER})

# Compile DataCrumbs BPF Code
set(DATACRUMBS_BPF_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/bpf/init.bpf.c
)
set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/bpf/main.bpf.c)
set(BPF_OUTPUT ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/objects/datacrumbs.bpf.o)

set(DATACRUMBS_BPF_INCLUDE_PATHS
    ${CMAKE_BINARY_DIR}/include
    ${LIBBPF_INCLUDEDIR}
    ${CMAKE_INCLUDE_OUTPUT_DIRECTORY}
    ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}
    ${DATACRUMBS_INSTALL_LIBEXEC}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/plugins/custom_probes
)

set(DATACRUMBS_MULTIARCH_INCLUDE_CANDIDATES
    /usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
    /usr/include/x86_64-linux-gnu
    /usr/include/aarch64-linux-gnu
)
foreach(path IN LISTS DATACRUMBS_MULTIARCH_INCLUDE_CANDIDATES)
    if(EXISTS "${path}/asm/errno.h")
        list(APPEND DATACRUMBS_BPF_INCLUDE_PATHS ${path})
        break()
    endif()
endforeach()

set(DATACRUMBS_BPF_INCLUDE_FLAGS "")

file(
    GLOB_RECURSE DATACRUMBS_CUSTOM_BPF_PLUGIN_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/plugins/custom_probes/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/plugins/custom_probes/*.c"
)

foreach(path IN LISTS DATACRUMBS_BPF_INCLUDE_PATHS)
    list(APPEND DATACRUMBS_BPF_INCLUDE_FLAGS -I${path})
endforeach()

list(APPEND DATACRUMBS_BPF_EXTRA_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/bpf/common.c)
list(APPEND DATACRUMBS_BPF_EXTRA_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/bpf/init.bpf.c)
list(APPEND DATACRUMBS_BPF_EXTRA_SOURCES ${BPF_SOURCE})

# Find all .c source files in ${CMAKE_BINARY_DIR}/libexec/datacrumbs/server/bpf
set(DATACRUMBS_BPF_OBJECTS "")

foreach(BPF_SRC_FILE ${DATACRUMBS_BPF_EXTRA_SOURCES})
    get_filename_component(BPF_SRC_NAME ${BPF_SRC_FILE} NAME_WE)
    set(BPF_OBJ_FILE "${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/server/bpf/objects/${BPF_SRC_NAME}.o")

    add_custom_command(
        OUTPUT ${BPF_OBJ_FILE}
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Compiling BPF object: ${BPF_OBJ_FILE} (timed)"
        COMMAND /usr/bin/time -f "Elapsed time for ${BPF_OBJ_FILE}: %E" ${CLANG_EXECUTABLE}
        -target bpf
        -D__TARGET_ARCH_${DATACRUMBS_ARCH}
        -Wall -g -O2
        ${DATACRUMBS_BPF_INCLUDE_FLAGS}
        -c ${BPF_SRC_FILE}
        -o ${BPF_OBJ_FILE}
        DEPENDS ${BPF_SRC_FILE} ${DATACRUMBS_CUSTOM_BPF_PLUGIN_FILES} vmlinux_header
        COMMENT "Compiling BPF object: ${BPF_OBJ_FILE} (timed)"
        VERBATIM
    )
    install(FILES ${BPF_OBJ_FILE}
        DESTINATION "${DATACRUMBS_INSTALL_LIBEXEC}/objects"
    )
    list(APPEND DATACRUMBS_BPF_OBJECTS ${BPF_OBJ_FILE})
endforeach()

string(REPLACE ";" " " DATACRUMBS_BPF_OBJECTS_STR "${DATACRUMBS_BPF_OBJECTS}")

add_custom_target(datacrumbs_bpf_force_clean
    COMMAND ${CMAKE_COMMAND} -E rm -f ${DATACRUMBS_BPF_OBJECTS} ${BPF_OUTPUT} ${BPF_SKEL_OUTPUT}
    COMMENT "Removing stale BPF objects and skeleton before rebuild"
)

# Link all object files into a single object file
add_custom_command(
    OUTPUT ${BPF_OUTPUT}
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Linking all BPF objects into ${BPF_OUTPUT} (timed)"
    COMMAND /usr/bin/time -f "Elapsed time for linking: %E" ${BPFTOOL_EXECUTABLE} gen object ${BPF_OUTPUT} ${DATACRUMBS_BPF_OBJECTS}
    DEPENDS ${DATACRUMBS_BPF_OBJECTS}
    COMMENT "Linking all BPF objects into ${BPF_OUTPUT} (timed)"
    VERBATIM
)

add_custom_target(datacrumbs_bpf ALL DEPENDS ${BPF_OUTPUT})

add_dependencies(datacrumbs_bpf vmlinux_header)
add_dependencies(datacrumbs_bpf datacrumbs_bpf_force_clean)

# Generate Skeleton header for Datacrumbs
set(BPF_SKEL_OUTPUT ${CMAKE_BINARY_DIR}/include/datacrumbs/server/bpf/datacrumbs.skel.h)
add_custom_command(
    OUTPUT ${BPF_SKEL_OUTPUT}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include/datacrumbs/server/bpf
    COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OUTPUT} > ${BPF_SKEL_OUTPUT}
    DEPENDS ${BPF_OUTPUT}
    COMMENT "Generating BPF skeleton: ${BPF_SKEL_OUTPUT}"
    VERBATIM
)
add_custom_target(datacrumbs_bpf_skel ALL DEPENDS ${BPF_SKEL_OUTPUT})
add_dependencies(datacrumbs_bpf_skel datacrumbs_bpf)

# Build object file with everything except server.cpp
set(DATACRUMBS_PROCESS_EVENTS_OBJ_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/runtime_configuration_manager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/common/runtime_configuration_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/process/writer/chrome_writer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/process/event_processor.cpp
    ${DATACRUMBS_COMMON_SRC}
)
set(DATACRUMBS_SERVER_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/server/process/server.cpp
)

include_directories(${CMAKE_INCLUDE_OUTPUT_DIRECTORY})

add_library(datacrumbs_obj SHARED ${DATACRUMBS_PROCESS_EVENTS_OBJ_SRC})
target_link_libraries(datacrumbs_obj ${DEPENDENCY_LIB})
install(TARGETS datacrumbs_obj
    LIBRARY DESTINATION ${DATACRUMBS_INSTALL_LIB_DIR}
)
add_dependencies(datacrumbs_obj datacrumbs_bpf_skel)

# Build the final executable by linking server.cpp and the object library
add_executable(${PROJECT_NAME} ${DATACRUMBS_SERVER_SRC})
target_link_libraries(${PROJECT_NAME} datacrumbs_obj ${DEPENDENCY_LIB})
add_dependencies(${PROJECT_NAME} datacrumbs_bpf_skel datacrumbs_obj)

# Install the main processing executable into DATACRUMBS_INSTALL_BINARYDIR
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "${DATACRUMBS_INSTALL_SBINARYDIR}"
)

# Install the main processing datacrumbs object into DATACRUMBS_INSTALL_LIBEXEC
install(FILES ${BPF_OUTPUT}
    DESTINATION "${DATACRUMBS_INSTALL_LIBEXEC}/objects"
)

# ------------------------------------------------------------------------------
# Custom executables for Datacrumbs
# ------------------------------------------------------------------------------
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E rm -rf
    ${BPF_OUTPUT}
    ${BPF_SKEL_OUTPUT}
    ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/datacrumbs
    COMMENT "Cleaning BPF build artifacts (ignoring if cannot remove)"
)

# flux cli plugin file
configure_file("${CMAKE_SOURCE_DIR}/etc/datacrumbs/flux/cli/plugins/datacrumbs.py"
    "${CMAKE_FLUX_OUTPUT_DIRECTORY}/cli/plugins/datacrumbs.py" @ONLY)

install(FILES "${CMAKE_FLUX_OUTPUT_DIRECTORY}/cli/plugins/datacrumbs.py"
    DESTINATION "${DATACRUMBS_INSTALL_ETC_FLUX}/cli/plugins"
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/systemd/datacrumbs@.service.in ${CMAKE_SYSTEMD_OUTPUT_DIRECTORY}/datacrumbs@.service @ONLY)
install(
    PROGRAMS
    ${CMAKE_SYSTEMD_OUTPUT_DIRECTORY}/datacrumbs@.service
    DESTINATION
    ${DATACRUMBS_INSTALL_ETC_SYSTEMD}
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/systemd/datacrumbs_probe_manager.service.in ${CMAKE_SYSTEMD_OUTPUT_DIRECTORY}/datacrumbs_probe_manager.service @ONLY)
install(
    PROGRAMS
    ${CMAKE_SYSTEMD_OUTPUT_DIRECTORY}/datacrumbs_probe_manager.service
    DESTINATION
    ${DATACRUMBS_INSTALL_ETC_SYSTEMD}
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_service_common.sh.in ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_common.sh @ONLY)
install(
    PROGRAMS
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_common.sh
    DESTINATION
    ${DATACRUMBS_INSTALL_SBINARYDIR}
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_service_run.sh.in ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_run.sh @ONLY)
install(
    PROGRAMS
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_run.sh
    DESTINATION
    ${DATACRUMBS_INSTALL_SBINARYDIR}
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_service_stop.sh.in ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_stop.sh @ONLY)
install(
    PROGRAMS
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_stop.sh
    DESTINATION
    ${DATACRUMBS_INSTALL_SBINARYDIR}
)

# Create an empty directory at install time
install(CODE "file(MAKE_DIRECTORY \"\${DATACRUMBS_INSTALL_LIBEXEC}/sbin\")")

add_test(NAME test_simple_dd
    COMMAND bash -c "dd if=/dev/zero of=/tmp/img_temp.bat bs=1M count=16"
)
