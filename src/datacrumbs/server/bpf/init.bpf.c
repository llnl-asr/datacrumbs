#include <datacrumbs/server/bpf/common.h>

SEC("uprobe")
int BPF_UPROBE(trace_client_start) {
  return mark_current_pid_traced();
}

SEC("uprobe")
int BPF_UPROBE(trace_client_stop) {
  return unmark_current_pid_traced();
}
