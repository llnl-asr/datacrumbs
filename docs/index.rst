===============================================================================
DataCrumbs: eBPF-based I/O Profiling and Tracing for HPC Applications
===============================================================================

DataCrumbs is the runtime side of the DataCrumbs stack. It loads signed probe
descriptions, attaches generic BPF programs to runtime-selected functions, and
writes DFTracer output.

The current split is:

- `datacrumbs`: runtime daemon, BPF programs, system configuration generation,
  and scheduler service integration
- `datacrumbs-utils`: probe builder, client library, wrappers, tests, and
  developer tooling

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   introduction
   ebpf_background
   dependencies

.. toctree::
   :maxdepth: 2
   :caption: Build and Operation

   build
   setup
   usage
   integration
   run

.. toctree::
   :maxdepth: 2
   :caption: Scheduler Integration

   flux_integration
   slurm_integration

.. toctree::
   :maxdepth: 2
   :caption: Legacy Notes

   overview

==================
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
