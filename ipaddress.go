package main

import (
    "fmt"
    "os"
    "os/signal"
    bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
#define BPF_PROG_TYPE_XDP 1
*/
import "C"

const source string = `
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define IP_TO_BLOCK1 (uint32_t) 0xC0A8010F  // Replace with the actual IP address you want to block
#define IP_TO_BLOCK2 (uint32_t) 0xC0A80114  // Replace with the actual IP address you want to block

BPF_TABLE("array", int, long, dropcnt, 256);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

int xdp_prog1(struct __sk_buff *skb) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;
    struct ethhdr *eth = data;
    int rc = XDP_PASS;  // Change this to XDP_DROP to block packets by default

    if (data + sizeof(*eth) > data_end)
        return rc;

    uint16_t h_proto = eth->h_proto;
    uint64_t nh_off = sizeof(*eth);

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        int index = parse_ipv4(data, nh_off, data_end);

        if (index == IPPROTO_ICMP) {
            // Extract the source IP address from the IPv4 header
            struct iphdr *iph = data + nh_off;
            uint32_t src_ip = iph->saddr;

            // Check if the source IP is in the blocked IP addresses
            //if (src_ip == IP_TO_BLOCK1 || src_ip == IP_TO_BLOCK2) {
               return XDP_DROP;  // Drop the packet
            //}
        }
    }

    return rc;
}
`

func usage() {
    fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
    fmt.Printf("e.g.: %v eth0\n", os.Args[0])
    os.Exit(1)
}

func main() {
    var device string

    if len(os.Args) != 2 {
        usage()
    }

    device = os.Args[1]
    ret := "XDP_PASS"
    ctxtype := "__sk_buff"
    module := bpf.NewModule(source, []string{
        "-w",
        "-DRETURNCODE=" + ret,
        "-DCTXTYPE=" + ctxtype,
    })

    defer module.Close()

    fn, err := module.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP, 1, 65536)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
        os.Exit(1)
    }

    err = module.AttachXDP(device, fn)

    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
        os.Exit(1)
    }

    defer func() {
        if err := module.RemoveXDP(device); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
        }
    }()

    fmt.Println("Filtering packets, hit CTRL+C to stop")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)

    <-sig

    fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")

    for it := dropcnt.Iter(); it.Next(); {
        key := bpf.GetHostByteOrder().Uint32(it.Key())
        value := bpf.GetHostByteOrder().Uint64(it.Leaf())

        if value > 0 {
            fmt.Printf("%v: %v pkts\n", key, value)
        }
    }
}
