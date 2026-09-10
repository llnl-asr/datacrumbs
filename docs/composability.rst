=====================
Composable Probe Sets
=====================

DataCrumbs still supports composability, but the mechanism is different now.

Users no longer build composable runtime binaries. Instead, they compose probe
sets in YAML, run `datacrumbs_probe_configurator`, and produce a signed
`probes.json.gz` file that `datacrumbs` loads at runtime.

Composable flow
===============

The supported composition flow is:

1. write or copy a probe YAML
2. define the probe categories you want in `capture_probes`
3. run `datacrumbs_probe_configurator`
4. run `datacrumbs` with the generated signed probes file

Example:

.. code-block:: bash

    datacrumbs_probe_configurator \
      <install-prefix>/etc/datacrumbs/configs/lead.yaml \
      /tmp/lead-probes.json.gz

    datacrumbs /tmp/lead-probes.json.gz 1

What the YAML does
==================

The YAML is now the composition surface. It tells the probe configurator which
probe groups to discover and include in the signed runtime file.

The main top-level field is:

- `capture_probes`

Each entry defines one logical probe group, for example:

- a syscall set
- a kernel symbol set
- a userspace library symbol set
- a USDT provider
- a custom probe bundle

Minimal example
===============

This is a small uprobe-based composition:

.. code-block:: yaml

    name: example
    capture_probes:
      - name: libc
        probe: uprobe
        type: binary
        file: /usr/lib64/libc.so.6
        regex: (?!.*_)(?!.*cold).*

That tells the probe configurator to:

- inspect `libc.so.6`
- keep symbols matching the regex
- add them to the signed probes file under category `libc`

Common probe entry patterns
===========================

Userspace binary uprobes
------------------------

.. code-block:: yaml

    capture_probes:
      - name: libc
        probe: uprobe
        type: binary
        file: /usr/lib64/libc.so.6
        regex: "open.*|read.*|write.*"

Kernel probes
-------------

Header-backed kernel probes:

.. code-block:: yaml

    capture_probes:
      - name: os_page_cache
        probe: kprobe
        type: header
        file: /path/to/kernel/headers/include/linux/pagemap.h
        enable_explorer: false

Syscalls
--------

System call probe groups are defined as normal capture entries in the host YAML.
The configurator resolves syscall names and signatures into the runtime probes
file.

USDT probes
-----------

.. code-block:: yaml

    capture_probes:
      - name: python
        probe: usdt
        type: usdt
        binary_path: /lib64/libpython3.6m.so.1.0
        provider: python

Custom probes
-------------

Custom probe bundles can still be described in YAML for probe generation:

.. code-block:: yaml

    capture_probes:
      - name: custom1
        probe: custom
        type: custom
        file: /path/to/custom.bpf.c
        probes: /path/to/probes.json
        process_header: /path/to/custom_process.h
        event_type: 2

Custom probe plugin headers are currently scaffolded statically in the source
tree. The active default custom sys-io include remains commented out in the BPF
aggregator, so custom entries are part of probe generation, but not the default
runtime build path unless the site wires them in.

How to create your own composition
==================================

The practical way to create a custom composition is:

1. start from an installed host YAML such as:

   - `<install-prefix>/etc/datacrumbs/configs/docker.yaml`
   - `<install-prefix>/etc/datacrumbs/configs/lead.yaml`

2. copy it to a site- or workload-specific file
3. remove probe groups you do not want
4. tighten regex filters for the ones you do want
5. run the probe configurator

Example:

.. code-block:: bash

    cp <install-prefix>/etc/datacrumbs/configs/docker.yaml ./my-io.yaml

Edit `my-io.yaml`, then generate probes:

.. code-block:: bash

    systemctl status datacrumbs_probe_manager.service
    datacrumbs_probe_configurator ./my-io.yaml /tmp/my-io-probes.json.gz

Then run:

.. code-block:: bash

    datacrumbs /tmp/my-io-probes.json.gz myrun

Argument metadata
=================

The probe configurator now also derives `function_arguments` metadata where
possible:

- syscalls from headers
- uprobes from DWARF plus source parsing
- kprobes from BTF where available

That metadata is carried into the signed probes file and used by the generic
runtime capture path to populate `args:{...}` in output events.

Runtime limits
==============

Probe generation validates the total number of attachable runtime functions
against `DATACRUMBS_MAX_RUNTIME_FUNCTIONS`.

If the selection is too large:

- the probe configurator warns near the limit
- the probe configurator fails when over the limit
- runtime also rejects oversized probe files before attach

Runtime probe state carry-forward
=================================

Runtime-discovered attach results are stored in:

.. code-block:: text

    <install-prefix>/share/datacrumbs/data/probes-runtime-status-<install-user>-<config-name>.sqlite

That runtime-probe status database is reused so later runs do not keep retrying
known bad targets, while still preserving a queryable record of which targets
attached successfully.

Migration note
==============

If you still have scripts or notes referring to:

- `datacrumbs_compose`
- `datacrumbs_compose_run`
- generated composable binaries

replace them with:

- a YAML file
- `datacrumbs_probe_configurator`
- `datacrumbs_probe_manager.service` on the login node
- a signed `probes.json.gz`
- `datacrumbs <probes.json.gz> [run-id]`
