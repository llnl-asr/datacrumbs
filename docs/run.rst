==================
Running DataCrumbs
==================

This page shows the supported runtime flow after probe generation.

Single-node direct run
======================

Start DataCrumbs directly:

.. code-block:: bash

    sudo datacrumbs /path/to/probes.json.gz 1

Then run an application through the client library:

.. code-block:: bash

    datacrumbs_wrap dd if=/dev/zero of=/tmp/out.bin bs=1M count=16 status=none

Stop the runtime with `Ctrl-C` or:

.. code-block:: bash

    kill -INT <pid>

Systemd-managed run
===================

When using the installed `datacrumbs@.service`, first write the per-run
environment file through the scheduler service scripts or the test wrapper, then
start the unit:

.. code-block:: bash

    systemctl start datacrumbs@1.service

Logs for the service go to:

.. code-block:: text

    ${DATACRUMBS_LOG_DIR}/datacrumbs_${DATACRUMBS_USER}_${DATACRUMBS_SERVICE_RUN_ID}_$(hostname).log

Use standard systemd tools for debugging:

.. code-block:: bash

    systemctl status datacrumbs@1.service
    journalctl -u datacrumbs@1.service

Testing and smoke runs
======================

The active utility smoke test in `datacrumbs-utils` runs `dd` through
`datacrumbs_wrap`.

Example:

.. code-block:: bash

    ctest --test-dir <utils-build-dir> --output-on-failure -R datacrumbs_utils_dd_preload

IOR example
===========

Generate a probes file that includes the workload you care about, start the
runtime, and then launch IOR through the client library.

.. code-block:: bash

    sudo datacrumbs /tmp/ior-probes.json.gz ior-test
    datacrumbs_wrap ior -a POSIX -b 1m -t 256k -s 16 -F

Scheduler examples
==================

Flux:

.. code-block:: bash

    flux run --datacrumbs-enable --datacrumbs-probe-file /tmp/probes.json.gz -N 2 -n 4 ./myapp

SLURM interactive allocation:

.. code-block:: bash

    datacrumbs_salloc --datacrumbs-enable --datacrumbs-probe-file /tmp/probes.json.gz -N 2

SLURM batch:

.. code-block:: bash

    datacrumbs_sbatch --datacrumbs-enable --datacrumbs-probe-file /tmp/probes.json.gz job.sh
