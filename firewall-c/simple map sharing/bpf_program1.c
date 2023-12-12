// bpf_program1.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");

SEC("xdp")
int bpf_program1(struct __sk_buff *skb) {
    // Key to lookup in the map
    __u32 key = 1;

    // Lookup the value associated with the key
    __u32 *value = bpf_map_lookup_elem(&my_map, &key);
    if (value) {
        // Increment the value by 1
        (*value)++;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";