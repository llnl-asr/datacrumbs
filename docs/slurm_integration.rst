========================
SLURM Integration
========================

SLURM integration uses the same systemd service model as Flux, with job metadata
stored in the SLURM comment field.

Current Flow
============

1. User generates a signed probes file.
2. User submits through `datacrumbs_salloc` or `datacrumbs_sbatch`:

   .. code-block:: bash

      datacrumbs_salloc --datacrumbs-enable --datacrumbs-probe-file /path/to/probes.json.gz -N 2
      datacrumbs_sbatch --datacrumbs-enable --datacrumbs-probe-file /path/to/probes.json.gz job.sh

3. The wrapper injects JSON into `--comment`:

   .. code-block:: json

      {"datacrumbs":{"enable":"yes","probe_file":"/path/to/probes.json.gz"}}

4. SLURM prolog runs `datacrumbs_service_run.sh`.
5. The script parses the SLURM comment, validates that the probe file is
   readable by the submitting user, writes `datacrumbs-<jobid>.env`, and starts
   `datacrumbs@<jobid>.service`.
6. SLURM epilog runs `datacrumbs_service_stop.sh`, which stops the service and
   waits for it to exit.

Installed components
====================

- login node:
  - `<install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service`
- `<install-prefix>/etc/datacrumbs/systemd/datacrumbs@.service`
- `<install-prefix>/sbin/datacrumbs_service_run.sh`
- `<install-prefix>/sbin/datacrumbs_service_stop.sh`
- `<install-prefix>/bin/datacrumbs_salloc`
- `<install-prefix>/bin/datacrumbs_sbatch`

Login-node prerequisite
=======================

Before users generate probe files for SLURM jobs, the trusted signing service
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

Notes
=====

- The service scripts now support only `FLUX` and `SLURM`. Any other scheduler
  type is treated as an error.
- The job metadata must contain `probe_file`. The legacy `probes` key is no
  longer used.

Testing without a real SLURM prolog
===================================

Use the installed service wrapper:

.. code-block:: bash

    datacrumbs_service_wrapper start 1 <user> /path/to/probes.json.gz
    datacrumbs_service_wrapper stop 1 <user> /path/to/probes.json.gz

This fabricates the expected SLURM metadata and exercises the same
service-common path used by the real prolog and epilog scripts.
