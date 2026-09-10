===============
Using DataCrumbs
===============

Supported usage now centers on three pieces:

- generate a signed probes file with `datacrumbs_probe_configurator`
- start `datacrumbs` directly or through `datacrumbs@<run-id>.service`
- launch workloads through `datacrumbs_wrap` or tracked binaries

Quick Start
===========

1. Generate probes:

.. code-block:: bash

    # login-node prerequisite
    systemctl status datacrumbs_probe_manager.service

    datacrumbs_probe_configurator \
      <install-prefix>/etc/datacrumbs/configs/<host>.yaml \
      /tmp/probes.json.gz

2. Start DataCrumbs:

.. code-block:: bash

    sudo datacrumbs /tmp/probes.json.gz myrun

3. Run an application through the client library:

.. code-block:: bash

    datacrumbs_wrap dd if=/dev/zero of=/tmp/out.bin bs=1M count=1 status=none

Direct Runtime Mode
===================

The supported CLI is:

.. code-block:: bash

    datacrumbs <signed-probes.json.gz> [run-id]

Example:

.. code-block:: bash

    sudo datacrumbs /home/user/lead-probes.json.gz 1

The output trace path is derived from the installed system configuration and the
active run id.

Because the probe-signing secret is root-owned and used again for runtime
verification, direct CLI execution is now a root-only path. Normal multi-user
deployments should prefer `datacrumbs@<run-id>.service`.

Application Integration Modes
=============================

Tracked ELF binaries
--------------------

Use `datacrumbs_track` to patch a dynamic executable so
`libdatacrumbs_client.so` is loaded automatically:

.. code-block:: bash

    datacrumbs_track --executable ./myapp
    ./myapp

Remove the patch with:

.. code-block:: bash

    datacrumbs_untrack --executable ./myapp

LD_PRELOAD wrapping
-------------------

Use `datacrumbs_wrap` for ad hoc execution:

.. code-block:: bash

    datacrumbs_wrap ./myapp arg1 arg2

`datacrumbs_wrap` is also the normal path for simple smoke tests and container
checks.

Systemd service mode
====================

The runtime is designed to work cleanly under:

.. code-block:: bash

    systemctl start datacrumbs@<run-id>.service
    systemctl stop datacrumbs@<run-id>.service

The unit waits for readiness through the ready file and stop does not return
until the unit becomes inactive.

Scheduler metadata
==================

Flux and SLURM now pass only one DataCrumbs-specific runtime input in their job
metadata:

.. code-block:: json

    {"datacrumbs":{"enable":"yes","probe_file":"/path/to/probes.json.gz"}}

The legacy `composite` and `probes` metadata fields are no longer part of the
supported flow.
