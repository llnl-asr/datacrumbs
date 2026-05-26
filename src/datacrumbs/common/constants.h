// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef __DATACRUMBS_COMMON_CONSTANTS_H
#define __DATACRUMBS_COMMON_CONSTANTS_H

/// Generic begin/end trace event marker.
#define NORMAL_EVENT 'X'
/// Counter/aggregated metric event marker.
#define COUNTER_EVENT 'C'
/// Metadata event marker.
#define METADATA_EVENT 'M'

/// Category name used for datacrumbs synthetic events.
#define DATACRUMBS_PROBE_CATEGORY "DC"
/// Reserved synthetic start marker function name.
#define START_FUNCTION_NAME "start"
/// Reserved start event id.
#define START_EVENT_ID 1
/// Reserved synthetic end marker function name.
#define END_FUNCTION_NAME "end"
/// Reserved end event id.
#define END_EVENT_ID 2

#endif  // __DATACRUMBS_COMMON_CONSTANTS_H