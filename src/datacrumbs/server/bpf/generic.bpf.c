#include <datacrumbs/server/bpf/common.h>

SEC("kprobe")
int BPF_KPROBE(trace_generic_kprobe_entry) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("kprobe entry cookie=%llu", cookie);
  return generic_entry(ctx, cookie);
}

SEC("kretprobe")
int BPF_KRETPROBE(trace_generic_kprobe_exit) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("kprobe exit cookie=%llu", cookie);
  return generic_exit(ctx, cookie);
}

SEC("ksyscall")
int BPF_KSYSCALL(trace_generic_syscall_entry, unsigned long long arg0, unsigned long long arg1,
                 unsigned long long arg2, unsigned long long arg3, unsigned long long arg4) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("syscall entry cookie=%llu", cookie);
  return generic_syscall_entry(ctx, cookie, arg0, arg1, arg2, arg3, arg4);
}

SEC("ksyscall")
int BPF_KSYSCALL(trace_generic_syscall_exit, struct pt_regs* regs) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("syscall exit cookie=%llu", cookie);
  return generic_exit(ctx, cookie);
}

SEC("uprobe")
int BPF_UPROBE(trace_generic_uprobe_entry) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("uprobe entry cookie=%llu", cookie);
  return generic_entry(ctx, cookie);
}

SEC("uretprobe")
int BPF_URETPROBE(trace_generic_uprobe_exit) {
  const unsigned long long cookie = bpf_get_attach_cookie(ctx);
  DBG_PRINTK("uprobe exit cookie=%llu", cookie);
  return generic_exit(ctx, cookie);
}

SEC("usdt")
int BPF_USDT(trace_generic_usdt_entry, long clazz, long method) {
  const unsigned long long cookie = bpf_usdt_cookie(ctx);
  DBG_PRINTK("usdt entry cookie=%llu", cookie);
  return usdt_entry(ctx, cookie);
}

SEC("usdt")
int BPF_USDT(trace_generic_usdt_exit, long clazz, long method) {
  const unsigned long long cookie = bpf_usdt_cookie(ctx);
  DBG_PRINTK("usdt exit cookie=%llu", cookie);
  return usdt_exit(ctx, cookie, clazz, method);
}
