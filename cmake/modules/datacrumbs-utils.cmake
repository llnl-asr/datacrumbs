function(print_all_variables)
  message(STATUS "CMake Variables:")
  get_cmake_property(_variableNames VARIABLES)
  list(SORT _variableNames)

  foreach(_variableName ${_variableNames})
    message(STATUS "${_variableName}=${${_variableName}}")
  endforeach()
endfunction()

macro(include_dependencies)
  # ------------------------------------------------------------------------------
  # Find all dependencies
  # ------------------------------------------------------------------------------
  set(DEPENDENCY_LIBRARY_DIRS "")
  set(DEPENDENCY_LIB ${CMAKE_EXE_LINKER_FLAGS} $ENV{LDFLAGS} -lpthread)

  message(STATUS "[${UPPER_PROJECT_NAME}] Detecting dependencies")

  # find packages
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    execute_process(
      COMMAND ${PKG_CONFIG_EXECUTABLE} --version
      RESULT_VARIABLE _DATACRUMBS_PKGCONFIG_RESULT
      OUTPUT_QUIET ERROR_QUIET
    )
    if(_DATACRUMBS_PKGCONFIG_RESULT EQUAL 0)
      pkg_check_modules(LIBBPF QUIET libbpf)
    else()
      message(
        WARNING
          "[${UPPER_PROJECT_NAME}] pkg-config is present but not executable; falling back to direct libbpf lookup"
      )
      set(PkgConfig_FOUND FALSE)
    endif()
  endif()
  find_package(LLVM REQUIRED CONFIG COMPONENTS Clang)
  find_package(json-c REQUIRED)
  find_package(OpenSSL REQUIRED)
  find_package(SQLite3 REQUIRED)
  find_package(ZLIB REQUIRED)

  # all validator
  if(LIBBPF_VERSION VERSION_LESS "1.0.0")
    message(
      FATAL_ERROR
        "[${UPPER_PROJECT_NAME}] libbpf version 1.0.0 or newer is required, but found ${LIBBPF_VERSION}"
    )
  endif()

  set(PKG_CONFIG_PATH $ENV{PKG_CONFIG_PATH})

  # include all links
  if(LIBBPF_FOUND)
    include_directories(${LIBBPF_INCLUDEDIR})
    link_directories(${LIBBPF_LIBRARY_DIRS})

    # If LIBBPF_LIBRARY_DIRS is not set, try LIBBPF_LIBDIR, else get parent dir of
    # LIBBPF_LINK_LIBRARIES
    if(NOT LIBBPF_LIBRARY_DIRS)
      if(LIBBPF_LIBDIR)
        set(LIBBPF_LIBRARY_DIRS "${LIBBPF_LIBDIR}")
      elseif(LIBBPF_LINK_LIBRARIES)
        get_filename_component(_LIBBPF_LIB_PARENT "${LIBBPF_LINK_LIBRARIES}" DIRECTORY)
        set(LIBBPF_LIBRARY_DIRS "${_LIBBPF_LIB_PARENT}")
      endif()
    endif()

    list(APPEND DEPENDENCY_LIBRARY_DIRS ${LIBBPF_LIBRARY_DIRS})
    set(DEPENDENCY_LIB
        ${DEPENDENCY_LIB}
        -L${LIBBPF_LIBRARY_DIRS}
        -lbpf
        -lelf
    )
  else()
    find_path(LIBBPF_INCLUDEDIR bpf/libbpf.h)
    find_library(LIBBPF_LIBRARY bpf)
    find_library(LIBELF_LIBRARY elf)
    if(LIBBPF_INCLUDEDIR
       AND LIBBPF_LIBRARY
       AND LIBELF_LIBRARY
    )
      get_filename_component(LIBBPF_LIBRARY_DIRS "${LIBBPF_LIBRARY}" DIRECTORY)
      include_directories(${LIBBPF_INCLUDEDIR})
      link_directories(${LIBBPF_LIBRARY_DIRS})
      list(APPEND DEPENDENCY_LIBRARY_DIRS ${LIBBPF_LIBRARY_DIRS})
      set(DEPENDENCY_LIB
          ${DEPENDENCY_LIB}
          -L${LIBBPF_LIBRARY_DIRS}
          -lbpf
          -lelf
      )
      set(LIBBPF_FOUND TRUE)
      set(LIBBPF_VERSION "unknown")
    else()
      message(FATAL_ERROR "[${UPPER_PROJECT_NAME}] libbpf not found!")
    endif()
  endif()

  if(LLVM_FOUND)
    include_directories(${LLVM_INCLUDE_DIRS})
    link_directories(${LLVM_LIBRARY_DIRS})
    list(APPEND DEPENDENCY_LIBRARY_DIRS ${LLVM_LIBRARY_DIRS})
    set(DEPENDENCY_LIB ${DEPENDENCY_LIB} ${LLVM_LIBRARIES} -lclang)
    set(CLANG_EXECUTABLE ${LLVM_TOOLS_BINARY_DIR}/clang)

    if(NOT EXISTS ${CLANG_EXECUTABLE})
      message(
        FATAL_ERROR
          "clang executable not found at ${CLANG_EXECUTABLE}. Please check your LLVM installation."
      )
    else()
      execute_process(
        COMMAND ${CLANG_EXECUTABLE} --version
        OUTPUT_VARIABLE CLANG_VERSION_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        COMMAND_ECHO
        NONE
      )

      # message(STATUS "[${UPPER_PROJECT_NAME}] Found clang executable: ${CLANG_EXECUTABLE}")
      # message(STATUS "[${UPPER_PROJECT_NAME}] clang version: ${CLANG_VERSION_OUTPUT}")
    endif()
  else()
    message(FATAL_ERROR "-- [${UPPER_PROJECT_NAME}] LLVM is needed for ${PROJECT_NAME} build")
  endif()

  if(json-c_FOUND)
    get_filename_component(json-c_INCLUDE_DIR "${json-c_DIR}/../../../include" ABSOLUTE)
    get_filename_component(json-c_LIBRARY_DIR "${json-c_DIR}/../../" ABSOLUTE)
    include_directories(${json-c_INCLUDE_DIR})
    list(APPEND DEPENDENCY_LIBRARY_DIRS ${json-c_LIBRARY_DIR})
    set(DEPENDENCY_LIB ${DEPENDENCY_LIB} -ljson-c)
  else()
    message(FATAL_ERROR "-- [${UPPER_PROJECT_NAME}] json-c is needed for ${PROJECT_NAME} build")
  endif()

  if(OpenSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(DEPENDENCY_LIB ${DEPENDENCY_LIB} OpenSSL::Crypto)
  else()
    message(FATAL_ERROR "-- [${UPPER_PROJECT_NAME}] OpenSSL is needed for ${PROJECT_NAME} build")
  endif()

  if(SQLite3_FOUND)
    include_directories(${SQLite3_INCLUDE_DIRS})
    set(DEPENDENCY_LIB ${DEPENDENCY_LIB} SQLite::SQLite3)
  else()
    message(FATAL_ERROR "-- [${UPPER_PROJECT_NAME}] SQLite3 is needed for ${PROJECT_NAME} build")
  endif()

  if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
    get_filename_component(ZLIB_LIBRARY_DIRS "${ZLIB_LIBRARIES}/../" ABSOLUTE)
    list(APPEND DEPENDENCY_LIBRARY_DIRS ${ZLIB_LIBRARY_DIRS})
    set(DEPENDENCY_LIB ${DEPENDENCY_LIB} -lz)
  else()
    message(FATAL_ERROR "-- [${UPPER_PROJECT_NAME}] zlib is needed for ${PROJECT_NAME} build")
  endif()

  list(APPEND DEPENDENCY_LIBRARY_DIRS ${DATACRUMBS_INSTALL_LIB_DIR})
  list(REMOVE_DUPLICATES DEPENDENCY_LIBRARY_DIRS)

  # print found packages
  message(
    STATUS
      "             - Found libbpf:${LIBBPF_VERSION} at include:${LIBBPF_INCLUDEDIR} lib:${LIBBPF_LIBRARY_DIRS}"
  )
  message(
    STATUS
      "             - Found llvm:${LLVM_VERSION} at include:${LLVM_INCLUDE_DIRS} lib:${LLVM_LIBRARY_DIRS} clang:${CLANG_EXECUTABLE}"
  )
  message(
    STATUS
      "             - Found json-c:${json-c_CONSIDERED_VERSIONS} at include:${json-c_INCLUDE_DIR} lib:${json-c_LIBRARY_DIR}"
  )
  message(
    STATUS "             - Found sqlite3:${SQLite3_VERSION} at include:${SQLite3_INCLUDE_DIRS}"
  )
  message(
    STATUS
      "             - Found zlib:${ZLIB_VERSION} at include:${ZLIB_INCLUDE_DIRS} lib:${ZLIB_LIBRARY_DIRS}"
  )
  message(STATUS "             - DEPENDENCY_LIBRARY_DIRS for RPATH:${DEPENDENCY_LIBRARY_DIRS}")
  message(STATUS "             - DEPENDENCY_LIB for linking :${DEPENDENCY_LIB}")
  string(
    REPLACE ";"
            ":"
            DEPENDENCY_LIBRARY_DIRS_COLON
            "${DEPENDENCY_LIBRARY_DIRS}"
  )
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  set(CMAKE_INSTALL_RPATH "${DEPENDENCY_LIBRARY_DIRS}")
  set(CMAKE_BUILD_RPATH "${DEPENDENCY_LIBRARY_DIRS}")

  # print_all_variables()
endmacro(include_dependencies)

macro(derive_configurations)
  if(DATACRUMBS_BPFTIME_COMPATIBLE)
    set(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG 1)
  else()
    set(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG 0)
  endif()

  if(DATACRUMBS_LOG_LEVEL_STR STREQUAL "ERROR")
    set(DATACRUMBS_LOG_LEVEL 1)
  elseif(DATACRUMBS_LOG_LEVEL_STR STREQUAL "WARN")
    set(DATACRUMBS_LOG_LEVEL 2)
  elseif(DATACRUMBS_LOG_LEVEL_STR STREQUAL "INFO")
    set(DATACRUMBS_LOG_LEVEL 3)
  elseif(DATACRUMBS_LOG_LEVEL_STR STREQUAL "DEBUG")
    set(DATACRUMBS_LOG_LEVEL 4)
  elseif(DATACRUMBS_LOG_LEVEL_STR STREQUAL "TRACE")
    set(DATACRUMBS_LOG_LEVEL 5)
  endif()

  if(DATACRUMBS_MODE_STR AND DATACRUMBS_MODE_STR STREQUAL "TRACE")
    set(DATACRUMBS_MODE 1)
  else()
    set(DATACRUMBS_MODE 2)
  endif()

  if(DATACRUMBS_TRACE_ALL_PROCESSES_OPT AND DATACRUMBS_TRACE_ALL_PROCESSES_OPT STREQUAL "ON")
    set(DATACRUMBS_TRACE_ALL_PROCESSES 1)
  else()
    set(DATACRUMBS_TRACE_ALL_PROCESSES 0)
  endif()

  option(BPFTOOL_EXECUTABLE "Path to bpftool executable" "")

  if(BPFTOOL_EXECUTABLE STREQUAL "NONE")
    set(BPFTOOL_EXECUTABLE "")
  endif()

  if(DATACRUMBS_INCLUSION_PATH STREQUAL "NONE")
    set(DATACRUMBS_ENABLE_INCLUSION_PATH 0)
  else()
    set(DATACRUMBS_ENABLE_INCLUSION_PATH 1)
  endif()

  if(DATACRUMBS_BPF_PRINT_ENABLE)
    set(DATACRUMBS_BPF_PRINT_ENABLE_FLAG 1)
  else()
    set(DATACRUMBS_BPF_PRINT_ENABLE_FLAG 0)
  endif()

  set(DATACRUMBS_SRC_GEN_PATH ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY})
  if(DATACRUMBS_CONFIGURED_LOG_DIR
     AND NOT
         DATACRUMBS_CONFIGURED_LOG_DIR
         STREQUAL
         ""
     AND NOT
         DATACRUMBS_CONFIGURED_LOG_DIR
         STREQUAL
         "NONE"
  )
    set(DATACRUMBS_LOG_DIR ${DATACRUMBS_CONFIGURED_LOG_DIR})
  else()
    set(DATACRUMBS_LOG_DIR ${CMAKE_BINARY_DIR}/logs)
  endif()

  set(DATACRUMBS_VARS
      --user
      ${DATACRUMBS_USER}
      --data_dir
      ${CMAKE_DATA_OUTPUT_DIRECTORY}
      --trace_log_dir
      ${DATACRUMBS_LOG_DIR}
  )

  if(NOT
     DATACRUMBS_INCLUSION_PATH
     STREQUAL
     "NONE"
  )
    set(DATACRUMBS_VARS ${DATACRUMBS_VARS} --inclusion_path ${DATACRUMBS_INCLUSION_PATH})
  endif()

  set(DATACRUMBS_DATA_DIR ${CMAKE_DATA_OUTPUT_DIRECTORY})
  file(MAKE_DIRECTORY ${DATACRUMBS_LOG_DIR})

  if(DATACRUMBS_ENABLE_OPT AND DATACRUMBS_ENABLE_OPT STREQUAL "ON")
    set(DATACRUMBS_ENABLE 1)
  else()
    set(DATACRUMBS_ENABLE 0)
  endif()

  if(NOT DEFINED DATACRUMBS_PROJECT_PATH OR DATACRUMBS_PROJECT_PATH STREQUAL "")
    set(DATACRUMBS_PROJECT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
  endif()

  # Detect system kernel version: major, minor, patch
  execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE DATACRUMBS_KERNEL_UNAME_R
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  # Split kernel version string (e.g., "6.5.0-101-generic") into major, minor, patch
  string(
    REGEX MATCH
          "^([0-9]+)\\.([0-9]+)\\.([0-9]+)"
          KERNEL_VERSION_MATCH
          "${DATACRUMBS_KERNEL_UNAME_R}"
  )

  if(KERNEL_VERSION_MATCH)
    string(
      REGEX
      REPLACE "^([0-9]+)\\..*"
              "\\1"
              KERNEL_VERSION_MAJOR
              "${DATACRUMBS_KERNEL_UNAME_R}"
    )
    string(
      REGEX
      REPLACE "^[0-9]+\\.([0-9]+)\\..*"
              "\\1"
              KERNEL_VERSION_MINOR
              "${DATACRUMBS_KERNEL_UNAME_R}"
    )
    string(
      REGEX
      REPLACE "^[0-9]+\\.[0-9]+\\.([0-9]+).*"
              "\\1"
              KERNEL_VERSION_PATCH
              "${DATACRUMBS_KERNEL_UNAME_R}"
    )
  else()
    set(KERNEL_VERSION_MAJOR "0")
    set(KERNEL_VERSION_MINOR "0")
    set(KERNEL_VERSION_PATCH "0")
  endif()

  set(DATACRUMBS_CMAKE_KERNEL_VERSION
      "(${KERNEL_VERSION_MAJOR}, ${KERNEL_VERSION_MINOR}, ${KERNEL_VERSION_PATCH})"
  )

  if(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR STREQUAL "NONE" AND DATACRUMBS_SCHEDULER_TYPE STREQUAL
                                                            "NONE"
  )
    message(
      FATAL_ERROR
        "[${UPPER_PROJECT_NAME}] Incomplete scheduler configuration. Either use a predefined scheduler option by setting DATACRUMBS_SCHEDULER_TYPE, or set DATACRUMBS_SCHEDULER_JOBID_ENV_VAR"
    )
  endif()

  if(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR STREQUAL "NONE")
    if(DATACRUMBS_SCHEDULER_TYPE STREQUAL "SLURM")
      set(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR "SLURM_JOB_ID")
    elseif(DATACRUMBS_SCHEDULER_TYPE STREQUAL "OPENMPI")
      set(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR "OMPI_COMM_WORLD_RANK")
    elseif(DATACRUMBS_SCHEDULER_TYPE STREQUAL "FLUX")
      set(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR "FLUX_JOB_ID")
    endif()
  endif()

endmacro(derive_configurations)

macro(find_system_details)
  message(STATUS "[${UPPER_PROJECT_NAME}] Detecting system details")

  find_library(
    LIBC_SO
    NAMES libc.so.6 libc.so
    PATHS /lib
          /usr/lib
          /lib64
          /usr/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib/x86_64-linux-gnu
    NO_DEFAULT_PATH
  )

  if(LIBC_SO)
    message(STATUS "             - Found libc: ${LIBC_SO}")
    set(DATACRUMBS_LIBC_SO ${LIBC_SO})
  else()
    message(FATAL_ERROR "             - libc.so not found!")
  endif()

  if(DATACRUMBS_HOST STREQUAL "NONE")
    # Get the system hostname
    execute_process(
      COMMAND hostname
      OUTPUT_VARIABLE RAW_HOSTNAME
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Remove all numbers from the hostname
    string(
      REGEX
      REPLACE "[0-9]"
              ""
              DATACRUMBS_HOST
              "${RAW_HOSTNAME}"
    )
    message(STATUS "             - Derived hostname: ${DATACRUMBS_HOST}")
  else()
    message(STATUS "             - Using provided hostname: ${DATACRUMBS_HOST}")
  endif()

  # Generate vmlinux.h using bpftool before building datacrumbs_bpf
  if(BPFTOOL_EXECUTABLE
     AND NOT
         BPFTOOL_EXECUTABLE
         STREQUAL
         "NONE"
  )
    message(STATUS "             - Using provided bpftool executable: ${BPFTOOL_EXECUTABLE}")
  else()
    find_program(
      BPFTOOL_EXECUTABLE_SEARCH bpftool
      PATHS /usr/sbin/
            /usr/bin/
            /usr/local/bin/
            /usr/local/sbin/
    )
    set(BPFTOOL_EXECUTABLE ${BPFTOOL_EXECUTABLE_SEARCH})

    if(NOT BPFTOOL_EXECUTABLE)
      message(
        FATAL_ERROR
          "[${UPPER_PROJECT_NAME}] bpftool executable not found! Please install bpftool or specify its path via BPFTOOL_EXECUTABLE."
      )
    endif()

    message(STATUS "             - Found bpftool executable: ${BPFTOOL_EXECUTABLE}")
  endif()

  find_file(
    VMLINUX_BTF_PATH vmlinux
    PATHS /sys/kernel/btf
    NO_DEFAULT_PATH
  )

  if(NOT VMLINUX_BTF_PATH)
    message(
      FATAL_ERROR
        "[${UPPER_PROJECT_NAME}] vmlinux BTF file not found in /sys/kernel/btf. Please ensure your kernel provides BTF information at /sys/kernel/btf/vmlinux."
    )
  else()
    message(STATUS "             - Found vmlinux BTF file at: ${VMLINUX_BTF_PATH}")
  endif()

  if(CMAKE_SYSTEM_PROCESSOR)
    set(DATACRUMBS_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
  elseif(DEFINED ENV{ARCH})
    set(DATACRUMBS_ARCH "$ENV{ARCH}")
  else()
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE DATACRUMBS_ARCH
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  endif()

  if(DATACRUMBS_KERNEL_VERSION
     AND NOT
         DATACRUMBS_KERNEL_VERSION
         STREQUAL
         ""
  )
    set(DATACRUMBS_KERNEL_VERSION "${DATACRUMBS_KERNEL_VERSION}")
  else()
    set(DATACRUMBS_KERNEL_VERSION
        "${KERNEL_VERSION_MAJOR}.${KERNEL_VERSION_MINOR}.${KERNEL_VERSION_PATCH}"
    )
  endif()

  # Detect kernel headers path if not set or empty
  if(NOT DEFINED DATACRUMBS_KERNEL_HEADERS_PATH OR DATACRUMBS_KERNEL_HEADERS_PATH STREQUAL "")
    set(_kernel_headers_candidates "/usr/src/${DATACRUMBS_KERNEL_UNAME_R}"
                                   "/usr/src/kernels/${DATACRUMBS_KERNEL_UNAME_R}"
    )
    set(DATACRUMBS_KERNEL_HEADERS_PATH "")

    foreach(_candidate ${_kernel_headers_candidates})
      if(EXISTS "${_candidate}")
        set(DATACRUMBS_KERNEL_HEADERS_PATH "${_candidate}")
        break()
      endif()
    endforeach()

    if(DATACRUMBS_KERNEL_HEADERS_PATH STREQUAL "")
      message(
        WARNING
          "[${UPPER_PROJECT_NAME}] Kernel headers not found for ${DATACRUMBS_UNAME_R} in /usr/src or /usr/src/kernels."
      )
    endif()
  endif()

  # Normalize architecture names
  if(DATACRUMBS_ARCH STREQUAL "x86_64")
    set(DATACRUMBS_ARCH "x86")
  elseif(DATACRUMBS_ARCH STREQUAL "aarch64")
    set(DATACRUMBS_ARCH "arm64")
  endif()

  message(STATUS "             - Detected architecture: ${DATACRUMBS_ARCH}")
endmacro(find_system_details)

function(datacrumbs_composable_install_headers public_headers)
  # message("-- [${PROJECT_NAME}] " "installing headers ${public_headers}")
  foreach(header ${public_headers})
    file(
      RELATIVE_PATH
      header_file_path
      "${PROJECT_SOURCE_DIR}/src"
      "${header}"
    )
    get_filename_component(header_directory_path "${header_file_path}" DIRECTORY)

    # message(STATUS "             - Installing header ${header} to
    # ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/include/${header_directory_path}")
    # file(MAKE_DIRECTORY
    # "${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/include/${header_directory_path}")
    configure_file(
      ${header} "${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/include/${header_file_path}" @ONLY
    )
    install(FILES ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/include/${header_file_path}
            DESTINATION "${DATACRUMBS_INSTALL_LIBEXEC}/composable/include/${header_directory_path}"
    )
  endforeach()
endfunction()

function(datacrumbs_composable_install_src public_src)
  # message("-- [${PROJECT_NAME}] " "installing src files ${public_src}")
  foreach(src ${public_src})
    file(
      RELATIVE_PATH
      src_file_path
      "${PROJECT_SOURCE_DIR}/src"
      "${src}"
    )
    get_filename_component(src_directory_path "${src_file_path}" DIRECTORY)
    install(FILES ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/src/${src_file_path}
            DESTINATION "${DATACRUMBS_INSTALL_LIBEXEC}/composable/src/${src_directory_path}"
    )
    configure_file(${src} "${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/composable/src/${src_file_path}" @ONLY)
  endforeach()
endfunction()

macro(load_build_variables)
  if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/bin
        CACHE PATH "Single Directory for all Executables."
    )
  endif()
  if(NOT CMAKE_INCLUDE_OUTPUT_DIRECTORY)
    set(CMAKE_INCLUDE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/include
        CACHE PATH "Store the headers."
    )
  endif()
  if(NOT CMAKE_CONFIG_OUTPUT_DIRECTORY)
    set(CMAKE_CONFIG_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/configs
        CACHE PATH "Store the configuration generated."
    )
  endif()
  if(NOT CMAKE_DATA_OUTPUT_DIRECTORY)
    set(CMAKE_DATA_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/data
        CACHE PATH "Store the data generated."
    )
  endif()
  set(EXECUTABLE_OUTPUT_PATH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
  if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/${DATACRUMBS_LIBDIR}
        CACHE PATH "Single Directory for all Libraries"
    )
  endif()
  if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/${DATACRUMBS_LIBDIR}
        CACHE PATH "Single Directory for all static libraries."
    )
  endif()
  if(NOT CMAKE_LIBEXEC_OUTPUT_DIRECTORY)
    set(CMAKE_LIBEXEC_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/libexec/${PROJECT_NAME})
  endif()
  if(NOT CMAKE_ETC_OUTPUT_DIRECTORY)
    set(CMAKE_ETC_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/etc/${PROJECT_NAME})
  endif()
  if(NOT CMAKE_MODULES_OUTPUT_DIRECTORY)
    set(CMAKE_MODULES_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/etc/${PROJECT_NAME}/modulefiles)
  endif()
  if(NOT CMAKE_FLUX_OUTPUT_DIRECTORY)
    set(CMAKE_FLUX_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/etc/${PROJECT_NAME}/flux)
  endif()
  if(NOT CMAKE_SYSTEMD_OUTPUT_DIRECTORY)
    set(CMAKE_SYSTEMD_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/etc/${PROJECT_NAME}/systemd)
  endif()

  if(NOT DATACRUMBS_BUILD_ONLY)
    # Get installation directories -- these get used in various places; best to just make them
    # available
    option(DATACRUMBS_LIBDIR_AS_LIB OFF)

    if(NOT DATACRUMBS_LIBDIR_AS_LIB)
      include(GNUInstallDirs)
    endif()

    if(NOT CMAKE_INSTALL_LIBDIR OR DATACRUMBS_LIBDIR_AS_LIB)
      set(CMAKE_INSTALL_BINDIR bin)
      set(CMAKE_INSTALL_SBINDIR sbin)
      set(CMAKE_INSTALL_LIBDIR lib)
      set(CMAKE_INSTALL_INCLUDEDIR include)
      set(CMAKE_INSTALL_DOCDIR doc)
      set(CMAKE_INSTALL_SYSCONFDIR etc)
      set(CMAKE_INSTALL_LIBEXECDIR libexec)
      set(CMAKE_INSTALL_RUNSTATEDIR run)
    endif()

    set(DATACRUMBS_INSTALL_BINARYDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})
    set(DATACRUMBS_INSTALL_SBINARYDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SBINDIR})
    set(DATACRUMBS_LIBDIR ${CMAKE_INSTALL_LIBDIR})
    set(DATACRUMBS_INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
    set(DATACRUMBS_INSTALL_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
    set(DATACRUMBS_INSTALL_DOCDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DOCDIR})
    set(DATACRUMBS_INSTALL_SYSCONFDIR
        ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
    )
    set(DATACRUMBS_INSTALL_LIBEXEC
        ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBEXECDIR}/${PROJECT_NAME}
    )
  else()
    set(DATACRUMBS_INSTALL_BINARYDIR "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    set(DATACRUMBS_INSTALL_SBINARYDIR "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    set(DATACRUMBS_INSTALL_LIB_DIR "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
    set(DATACRUMBS_INSTALL_INCLUDE_DIR "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}")
    set(DATACRUMBS_INSTALL_DOCDIR "${CMAKE_BINARY_DIR}/doc")
    set(DATACRUMBS_INSTALL_SYSCONFDIR "${CMAKE_BINARY_DIR}/etc/${PROJECT_NAME}")
    set(DATACRUMBS_INSTALL_LIBEXEC ${CMAKE_LIBEXEC_OUTPUT_DIRECTORY})
    set(DATACRUMBS_RUNSTATEDIR "run")
  endif()
  set(CMAKE_INSTALL_CONFIGS_DIR configs)
  set(CMAKE_INSTALL_DATA_DIR data)
  set(CMAKE_INSTALL_MODULES_DIR lmod/modulefiles)

  set(DATACRUMBS_INSTALL_DATADIR ${DATACRUMBS_INSTALL_SYSCONFDIR}/${CMAKE_INSTALL_DATA_DIR})
  set(DATACRUMBS_INSTALL_ETC_CONFIGSDIR
      ${DATACRUMBS_INSTALL_SYSCONFDIR}/${CMAKE_INSTALL_CONFIGS_DIR}
  )
  set(DATACRUMBS_INSTALL_ETC_MODULESDIR
      ${DATACRUMBS_INSTALL_SYSCONFDIR}/${CMAKE_INSTALL_MODULES_DIR}
  )
  set(DATACRUMBS_INSTALL_ETC_DATADIR ${DATACRUMBS_INSTALL_SYSCONFDIR}/${CMAKE_INSTALL_DATA_DIR})
  set(DATACRUMBS_INSTALL_ETC_CMAKE ${DATACRUMBS_INSTALL_SYSCONFDIR}/cmake)
  set(DATACRUMBS_INSTALL_ETC_SYSTEMD ${DATACRUMBS_INSTALL_SYSCONFDIR}/systemd)
  set(DATACRUMBS_INSTALL_ETC_FLUX ${DATACRUMBS_INSTALL_SYSCONFDIR}/flux)
  if(DATACRUMBS_CONFIGURED_RUN_DIR
     AND NOT
         DATACRUMBS_CONFIGURED_RUN_DIR
         STREQUAL
         ""
     AND NOT
         DATACRUMBS_CONFIGURED_RUN_DIR
         STREQUAL
         "NONE"
  )
    set(DATACRUMBS_INSTALL_RUNSTATEDIR ${DATACRUMBS_CONFIGURED_RUN_DIR})
  else()
    set(DATACRUMBS_INSTALL_RUNSTATEDIR /${CMAKE_INSTALL_RUNSTATEDIR})
  endif()

  # Set this at the top level of your project, before any install commands
  set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)
endmacro(load_build_variables)
