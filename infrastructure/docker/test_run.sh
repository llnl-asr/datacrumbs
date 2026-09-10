#!/bin/bash

set -euo pipefail

REPO_ROOT="/opt/datacrumbs"
BUILD_DIR="${REPO_ROOT}/datacrumbs-build"
INSTALL_PREFIX="/opt/datacrumbs-install"
CONFIG_YAML="${INSTALL_PREFIX}/etc/datacrumbs/configs/docker.yaml"
PROBE_FILE="/tmp/datacrumbs-docker-probes.json.gz"
JOB_ID="1"
SERVICE_USER="docker"
OUT_FILE="/tmp/img_temp.bin"
READY_FILE="/var/run/datacrumbs/datacrumbs-${JOB_ID}.ready"
DATACRUMBS_PID=""

set +u
. /opt/rh/gcc-toolset-11/enable
set -u
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake -DDATACRUMBS_HOST=docker \
  -DDATACRUMBS_USER=root \
  -DDATACRUMBS_INSTALL_USER=docker \
  -DDATACRUMBS_KERNEL_HEADERS_PATH=/usr/src/kernels/4.18.0-348.7.1.el8_5.x86_64 \
  -DCMAKE_PREFIX_PATH=/usr/lib64/openmpi \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
  "${REPO_ROOT}"
cmake --build . -j"$(nproc)"
cmake --install .

test -f "${CONFIG_YAML}"

"${INSTALL_PREFIX}/bin/datacrumbs_probe_configurator" "${CONFIG_YAML}" "${PROBE_FILE}"
test -f "${PROBE_FILE}"

start_datacrumbs() {
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    "${INSTALL_PREFIX}/bin/datacrumbs_service_wrapper" start "${JOB_ID}" "${SERVICE_USER}" "${PROBE_FILE}"
    trap '"${INSTALL_PREFIX}/bin/datacrumbs_service_wrapper" stop "${JOB_ID}" "${SERVICE_USER}" "${PROBE_FILE}" || true' EXIT
    return 0
  fi

  rm -f "${READY_FILE}"
  "${INSTALL_PREFIX}/sbin/datacrumbs" "${PROBE_FILE}" "${JOB_ID}" &
  DATACRUMBS_PID="$!"
  trap 'if [[ -n "${DATACRUMBS_PID}" ]]; then kill -INT "${DATACRUMBS_PID}" 2>/dev/null || true; wait "${DATACRUMBS_PID}" 2>/dev/null || true; fi' EXIT

  for _ in $(seq 1 300); do
    [[ -f "${READY_FILE}" ]] && return 0
    sleep 1
  done
  echo "datacrumbs did not become ready" >&2
  return 1
}

stop_datacrumbs() {
  if [[ -n "${DATACRUMBS_PID}" ]]; then
    kill -INT "${DATACRUMBS_PID}" 2>/dev/null || true
    wait "${DATACRUMBS_PID}" 2>/dev/null || true
    DATACRUMBS_PID=""
    return 0
  fi
  "${INSTALL_PREFIX}/bin/datacrumbs_service_wrapper" stop "${JOB_ID}" "${SERVICE_USER}" "${PROBE_FILE}"
}

# start_datacrumbs

rm -f "${OUT_FILE}"
"${INSTALL_PREFIX}/bin/datacrumbs_wrap" \
  dd if=/dev/zero of="${OUT_FILE}" bs=1M count=16 status=none

test -f "${OUT_FILE}"
test "$(wc -c <"${OUT_FILE}")" = "16777216"

# stop_datacrumbs
trap - EXIT
