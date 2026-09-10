// generic runtime probe handlers
#include "generic.bpf.c"

// site-local custom probes are wired through the generated aggregator header.
#include <custom_probes.h>
