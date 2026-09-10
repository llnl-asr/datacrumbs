=======================
Application Integration
=======================

DataCrumbs integrates with applications through the client library provided by
`datacrumbs-utils`.

Supported Integration Paths
===========================

1. `datacrumbs_wrap`
2. `datacrumbs_track`
3. scheduler-managed service startup plus wrapped or tracked applications

`datacrumbs_run` is no longer an automatic local wrapper around the daemon. It
is now a multi-node helper that starts `datacrumbs@<run-id>.service` over SSH
on a node list.

datacrumbs_wrap
===============

This is the simplest integration path:

.. code-block:: bash

    datacrumbs_wrap ./myapp arg1 arg2

It prepends `libdatacrumbs_client.so` to `LD_PRELOAD` and then executes the
command.

datacrumbs_track
================

For dynamic ELF executables you want to instrument persistently:

.. code-block:: bash

    datacrumbs_track --executable ./myapp

This adds `libdatacrumbs_client.so` to the binary's dependency list. The
application can still run normally when DataCrumbs is not active.

Undo the patch with:

.. code-block:: bash

    datacrumbs_untrack --executable ./myapp

Scheduler-managed service flow
==============================

On Flux and SLURM systems, the normal production path is:

1. generate a signed probes file
2. submit a job with DataCrumbs metadata containing `probe_file`
3. prolog starts `datacrumbs@<job-id>.service`
4. application runs through the client library
5. epilog stops the service

Testing the service flow without a real prolog is possible through:

.. code-block:: bash

    datacrumbs_service_wrapper start <job-id> <user> <probe-file>
    datacrumbs_service_wrapper stop <job-id> <user> <probe-file>

Multi-node service control
==========================

Use `datacrumbs_run` and `datacrumbs_stop` when you want to start or stop the
systemd service on a list of nodes directly:

.. code-block:: bash

    datacrumbs_run --node-list "node[1-4]" --probe-file /tmp/probes.json.gz --run-id myrun
    datacrumbs_stop --node-list "node[1-4]" --run-id myrun

These commands do not generate probes themselves and do not wrap the workload.
They only coordinate service lifecycle across nodes.
