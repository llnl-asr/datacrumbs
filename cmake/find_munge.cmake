# Locate munge, the credential service used to authenticate probe manager RPC callers.
#
# The probe manager runs as root on one node for the whole cluster, so it cannot
# use AF_UNIX peer credentials to learn who is calling. Munge supplies a uid/gid
# attested by the local munged against the cluster-wide key, which is the same
# mechanism Slurm relies on and is therefore already deployed and keyed on every
# node that can run a job.
#
# Defines the imported target Munge::Munge and sets DATACRUMBS_MUNGE_FOUND.

find_path(MUNGE_INCLUDE_DIR
  NAMES munge.h
  HINTS ${MUNGE_ROOT} ENV MUNGE_ROOT
  PATH_SUFFIXES include)

find_library(MUNGE_LIBRARY
  NAMES munge
  HINTS ${MUNGE_ROOT} ENV MUNGE_ROOT
  PATH_SUFFIXES lib lib64)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Munge
  REQUIRED_VARS MUNGE_LIBRARY MUNGE_INCLUDE_DIR)

if(Munge_FOUND AND NOT TARGET Munge::Munge)
  add_library(Munge::Munge UNKNOWN IMPORTED)
  set_target_properties(Munge::Munge PROPERTIES
    IMPORTED_LOCATION "${MUNGE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MUNGE_INCLUDE_DIR}")
endif()

set(DATACRUMBS_MUNGE_FOUND ${Munge_FOUND})
mark_as_advanced(MUNGE_INCLUDE_DIR MUNGE_LIBRARY)

if(NOT Munge_FOUND)
  message(FATAL_ERROR
    "munge not found (need munge.h and libmunge). The probe manager authenticates "
    "RPC callers with munge because it serves the whole cluster from one node. "
    "Install munge-devel, or set MUNGE_ROOT.")
endif()

# The manager can only authenticate callers if munged is actually running.
find_program(MUNGE_EXECUTABLE NAMES munge)
if(MUNGE_EXECUTABLE)
  execute_process(COMMAND ${MUNGE_EXECUTABLE} -n
                  OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE _dc_munge_rc)
  if(NOT _dc_munge_rc EQUAL 0)
    message(WARNING
      "munged does not appear to be running on this host; the probe manager and its "
      "clients will fail to authenticate until it is started.")
  endif()
endif()

message(STATUS "[${UPPER_PROJECT_NAME}] Found munge: ${MUNGE_LIBRARY}")
