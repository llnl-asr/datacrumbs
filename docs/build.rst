===================
Building DataCrumbs
===================

This page describes the supported build flow after the `datacrumbs` and
`datacrumbs-utils` split.

What Gets Built Where
=====================

`datacrumbs` now owns:

- the runtime executable
- the BPF object and skeleton
- install-time system configuration generation
- the trusted probe-signing service and its systemd unit
- the systemd unit and scheduler service scripts

`datacrumbs-utils` now owns:

- `datacrumbs_probe_configurator`
- `libdatacrumbs_client.so`
- preload and patching wrappers
- test and tooling subdirectories

When you build `datacrumbs`, it bootstraps `datacrumbs-utils` with
`ExternalProject_Add` into the same install prefix.

Quick Start
===========

.. code-block:: bash

    git clone https://github.com/LLNL/datacrumbs.git
    cd datacrumbs

    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/path/to/install
    cmake --build build -j$(nproc)
    cmake --install build

The `datacrumbs-utils` source checkout and build tree are placed under:

- `build/_deps/datacrumbs-utils-src`
- `build/_deps/datacrumbs-utils-build`

Its runtime, library, include, and config outputs are redirected into the main
`datacrumbs/build` tree so both projects share one build artifact layout.

Important Configure Options
===========================

Common options include:

- `DATACRUMBS_HOST`
- `DATACRUMBS_USER`
- `DATACRUMBS_INSTALL_USER`
- `DATACRUMBS_KERNEL_HEADERS_PATH`
- `DATACRUMBS_TRACE_ALL_PROCESSES_OPT`
- `DATACRUMBS_MAX_RUNTIME_FUNCTIONS`
- `DATACRUMBS_UTILS_GIT_REPOSITORY`
- `DATACRUMBS_UTILS_GIT_REF`

Example:

.. code-block:: bash

    cmake -S . -B build \
      -DCMAKE_INSTALL_PREFIX=/opt/datacrumbs-install \
      -DDATACRUMBS_HOST=lead2 \
      -DDATACRUMBS_USER=root \
      -DDATACRUMBS_INSTALL_USER=haridev

Install-Time Configuration
==========================

`datacrumbs` and `datacrumbs-utils` now consume configure-time values directly
from installed headers and exported environment variables.

There is no separate system configurator executable in the install flow.

Generated file:

- `<install-prefix>/share/datacrumbs/data/.datacrumbs-probe-secret`

The secret is stored in `share/datacrumbs/data`, not under `etc`.
It is intended to be readable only by `root`.

Login-node manager service
==========================

Probe generation now relies on a trusted manager service on the login node:

- executable: `<install-prefix>/sbin/datacrumbs_probe_manager`
- unit: `<install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service`

That service runs as `root`, owns the secret, and signs probe
documents on behalf of `datacrumbs_probe_configurator`.
It only accepts requests from the installed `datacrumbs_probe_configurator_exec`
binary, and the HMAC covers the signed probe document metadata plus the
categories payload so post-sign tampering is detected. The configurator sends
only the canonical signing payload to the manager service and writes the final
probe document locally.

Dependencies
============

The `datacrumbs` runtime no longer depends on `yaml-cpp`.

The major runtime dependencies are:

- libbpf
- libelf
- zlib
- OpenSSL
- json-c

`datacrumbs-utils` still uses `yaml-cpp` for host YAML configuration handling.

Notes
=====

- `composable` runtime components are no longer part of the active build.
- `datacrumbs_explorer`, `datacrumbs_generator`, and `datacrumbs_client` are no
  longer built by `datacrumbs`.
- BPF changes are force-cleaned during the `datacrumbs` build to avoid stale
  skeleton issues.
