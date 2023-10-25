package main

import (
    "fmt" //Provides input/output functions for printing to the console.
    "os" //Offers access to the operating system, enabling functions for command-line arguments and error handling.
    "os/signal" //Provides functionality to handle signals, such as catching Ctrl+C (SIGINT) to exit the program gracefully.
    "time" // Offers functionality for measuring time intervals and scheduling events
    "net" //Provides functions for network-related operations
    bpf "github.com/iovisor/gobpf/bcc" //This is a third-party package, likely a library for working with Berkeley Packet Filters (BPF) in Go
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C" //This section contains C code comments that are used as build directives for the cgo tool. They specify C flags and linker flags for the C parts of the program. The C code appears to be related to BPF (Berkeley Packet Filter) and likely has some C functions that can be called from Go.

const source string = ` //Here, a constant string source is declared, which contains an embedded C source code snippet. This C code is used to define and load a BPF program into the kernel.
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_HASH(blocked_ips, u32, u32); //This line defines a BPF hash table named "blocked_ips." It specifies that the table is a hash table with a key and value of type u32

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) { //XDP responsible for parsing an IPv4 packet
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end){
        return 0;
    }

    return iph->protocol;
}

int xdp_prog1(struct CTXTYPE *ctx) { //eBPF program
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    int rc = RETURNCODE;
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    int index;
    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end){
        return rc;
    }

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);

        if (data + nh_off > data_end){
            return rc;    
        }

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);

        if (data + nh_off > data_end){
            return rc; 
        }

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        index = parse_ipv4(data, nh_off, data_end);
        if (index == 1) {
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
            u32 *value = blocked_ips.lookup(&src_ip);

            if (value) {
            return XDP_DROP; // Drop the packet from blocked IP address
            }else{
            return XDP_PASS; // Passing not blocker packets
            }
        }else{
            return XDP_DROP; //droping other packets than ICMP
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
    start := time.Now() //start recording time
    var device string //Declares a variable device to store the network device name that the XDP program will be attached to
    
    if len(os.Args) != 2 { //This conditional statement checks if the program is provided with exactly one command-line argument. If not, it calls the usage function and exits. The expected argument is the network device name.
        usage()
    }

    device = os.Args[1] //Assigns the first command-line argument (the network device name) to the device variable
    ret := "XDP_PASS" //Initializes the ret variable with the default action to take when a packet doesn't match any filtering criteria
    ctxtype := "xdp_md" //Initializes the ctxtype variable with the type of context used in the BPF program

    module := bpf.NewModule(source, []string{ //Creates a new BPF module by compiling the BPF source code
        "-w",
        "-DRETURNCODE=" + ret,
        "-DCTXTYPE=" + ctxtype,
    })

    defer module.Close() //statement ensures that the BPF module is closed and resources are released when the program exits

    fn, err := module.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP, 1, 65536) //Loads the BPF program named "xdp_prog1" into the kernel. It specifies that it's an XDP program (C.BPF_PROG_TYPE_XDP) and assigns it a priority of 1 and a maximum packet size of 65536 bytes.
    
    if err != nil { //Error handling for loading the BPF program is performed, and if there's an error, an error message is printed, and the program exits
        fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
        os.Exit(1)
    }

    err = module.AttachXDP(device, fn) //This line attaches the loaded BPF program to the specified network device. If there's an error, it prints an error message and exits.
    
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
        os.Exit(1)
    }
    defer func() {
        if err := module.RemoveXDP(device); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
        }
    }()
    fmt.Println("Blocking packets from specific IPv4 addresses, hit CTRL+C to stop")
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)
    blockedIPs := bpf.NewTable(module.TableId("blocked_ips"), module)
    // Add the IPv4 addresses you want to block to the 'blocked_ips' map
    blockIPs := []string{"192.168.1.10", "192.168.1.8"}
    for _, ip := range blockIPs {
        if parsedIP := net.ParseIP(ip); parsedIP != nil {
            blockedIPs.Set(parsedIP.To4(), []byte{0})
        }
    }
    <-sig
    elapsed := time.Since(start)
    seconds := elapsed.Seconds()
    fmt.Printf("\nNumbers of dropped IP packets by network protocol blocked by %.2f seconds\n", seconds)
}
