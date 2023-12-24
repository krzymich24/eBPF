// map_manager_kern.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rule);  
    __uint(max_entries, 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_map SEC(".maps");

struct rule {
    char    name[64];
    int32_t action;
    int32_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t srcport;
    uint16_t destport;
};

SEC("xdp")
int bpf_program(struct __sk_buff *skb) {
    // Key to lookup in the map
    __u32 key = 1;

    // Lookup the value associated with the key
    __u32 *value = bpf_map_lookup_elem(&rule_map, &key);
    if (value) {
        // Increment the value by 1
        (*value)++;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";