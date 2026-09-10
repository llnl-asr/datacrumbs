==================
Deployment for HPC
==================

This page describes the supported deployment model after the runtime and utility
split.

Recommended deployment model
============================

The supported production path is scheduler-managed systemd service startup.

At a high level:

1. install `datacrumbs`
2. install `datacrumbs-utils` separately into the same prefix
3. register `datacrumbs@.service` on compute nodes
4. register `datacrumbs_probe_manager.service` on login nodes
5. install Flux or SLURM prolog and epilog hooks
6. generate signed probe files with `datacrumbs_probe_configurator`
7. submit jobs with DataCrumbs metadata containing `probe_file`

Installed runtime assets
========================

Key files provided by the install:

- `<install-prefix>/sbin/datacrumbs`
- `<install-prefix>/etc/datacrumbs/systemd/datacrumbs@.service`
- `<install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service`
- `<install-prefix>/sbin/datacrumbs_service_run.sh`
- `<install-prefix>/sbin/datacrumbs_service_stop.sh`
- `<install-prefix>/share/datacrumbs/data/system-probe-<install-user>-<host>.sqlite`
- `<install-prefix>/share/datacrumbs/data/.datacrumbs-probe-secret`

Key utility assets installed into the same prefix:

- `<install-prefix>/bin/datacrumbs_probe_configurator`
- `<install-prefix>/bin/datacrumbs_wrap`
- `<install-prefix>/bin/datacrumbs_track`
- `<install-prefix>/bin/datacrumbs_untrack`
- `<install-prefix>/bin/datacrumbs_salloc`
- `<install-prefix>/bin/datacrumbs_sbatch`
- `<install-prefix>/bin/datacrumbs_service_wrapper`

Systemd deployment
==================

Register the unit on each target node:

.. code-block:: bash

    sudo ln -sf <install-prefix>/etc/datacrumbs/systemd/datacrumbs@.service \
      /etc/systemd/system/datacrumbs@.service
    sudo systemctl daemon-reload

The unit:

- runs `datacrumbs` in the foreground with `Type=simple`
- waits for readiness through a ready file
- logs to `${DATACRUMBS_LOG_DIR}/datacrumbs_${DATACRUMBS_USER}_${DATACRUMBS_SERVICE_RUN_ID}_$(hostname).log`
- stops with `SIGINT`
- does not auto-restart on failure

Login-node signing deployment
=============================

Register the manager service on login nodes:

.. code-block:: bash

    sudo ln -sf <install-prefix>/etc/datacrumbs/systemd/datacrumbs_probe_manager.service \
      /etc/systemd/system/datacrumbs_probe_manager.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now datacrumbs_probe_manager.service

This service must be running before users call `datacrumbs_probe_configurator`.

Flux and SLURM deployment
=========================

Use the scheduler-specific pages for the full configuration:

- :doc:`flux_integration`
- :doc:`slurm_integration`

Both schedulers now use the same core model:

- job metadata contains `probe_file`
- prolog starts `datacrumbs@<jobid>.service`
- epilog stops `datacrumbs@<jobid>.service`

Interactive and test deployment
===============================

For testing outside a real scheduler:

.. code-block:: bash

    datacrumbs_service_wrapper start 1 <user> /path/to/probes.json.gz
    datacrumbs_service_wrapper stop 1 <user> /path/to/probes.json.gz

For direct single-node runs without systemd:

.. code-block:: bash

    datacrumbs /path/to/probes.json.gz 1
    datacrumbs_wrap ./myapp

What is no longer the deployment model
======================================

The following older approaches are no longer the supported deployment story:

- `sudo datacrumbs_server_run.sh`
- `sudo datacrumbs_server_stop.sh`
- composable runtime binaries
- explorer/generator-driven runtime composition

If a site still has wrappers around those paths, they should be migrated to the
systemd service plus signed probe file workflow.
