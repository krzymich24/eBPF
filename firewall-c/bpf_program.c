// bpf_program.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(long),
    .max_entries = 1024,
};

SEC("kprobe/sys_read")
int bpf_prog(struct pt_regs *ctx) {
    int key = 42;
    long *value;

    value = bpf_map_lookup_elem(&my_map, &key);
    if (value) {
        bpf_printk("Value in map: %ld\n", *value);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";