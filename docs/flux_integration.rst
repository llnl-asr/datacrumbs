========================
Flux Integration
========================

Flux integration is now based on job metadata carrying a signed probes file and
the `datacrumbs@<job-id>.service` systemd unit.

Current Flow
============

1. User generates a signed probes file.
2. User submits with:

   .. code-block:: bash

      flux run --datacrumbs-enable --datacrumbs-probe-file /path/to/probes.json.gz ...

3. The Flux plugin writes job metadata containing:

   .. code-block:: json

      {"datacrumbs":{"enable":"yes","probe_file":"/path/to/probes.json.gz"}}

4. Flux prolog runs `datacrumbs_service_run.sh`.
5. The script resolves the job id, user, and probe file, writes
   `datacrumbs-<jobid>.env`, and starts `datacrumbs@<jobid>.service`.
6. The systemd unit waits until the ready file exists.
7. Flux epilog runs `datacrumbs_service_stop.sh`, which stops the service and
   waits for it to exit.

Installed components
====================

- login node:
  - `<install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service`
- `<install-prefix>/etc/datacrumbs/systemd/datacrumbs@.service`
- `<install-prefix>/sbin/datacrumbs_service_run.sh`
- `<install-prefix>/sbin/datacrumbs_service_stop.sh`
- `<install-prefix>/etc/datacrumbs/flux/cli/plugins/datacrumbs.py`

Login-node prerequisite
=======================

Before users generate probe files for Flux jobs, the trusted signing service
must be running on the login node:

.. code-block:: bash

    sudo ln -sf <install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service \
      /etc/systemd/system/datacrumbs_probe_manager.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now datacrumbs_probe_manager.service

Deploying the unit
==================

.. code-block:: bash

    sudo ln -sf <install-prefix>/etc/datacrumbs/systemd/datacrumbs@.service \
      /etc/systemd/system/datacrumbs@.service
    sudo systemctl daemon-reload

Plugin behavior
===============

The Flux plugin now uses `probe_file`, not `composite`, as the runtime selector.

Expected CLI options:

- `--datacrumbs-enable`
- `--datacrumbs-probe-file PATH`

Testing without a real Flux prolog
==================================

Use the installed service wrapper:

.. code-block:: bash

    datacrumbs_service_wrapper start 1 <user> /path/to/probes.json.gz
    datacrumbs_service_wrapper stop 1 <user> /path/to/probes.json.gz

This fabricates the expected Flux metadata so the service-common path can be
tested without modifying the real prolog scripts.
