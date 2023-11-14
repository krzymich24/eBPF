package main

import (
    "bufio"
    "fmt"
    "os"
    "os/signal"
    "time"
    "net"
    "strings"
    "crypto/md5"
    "io"
    bpf "github.com/iovisor/gobpf/bcc"
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

BPF_HASH(blocked_icmp_src_ips, u32, u32); 
BPF_HASH(blocked_icmp_dest_ips, u32, u32);
BPF_HASH(blocked_tcp_src_ips, u32, u32);
BPF_HASH(blocked_tcp_dest_ips, u32, u32);
BPF_HASH(blocked_udp_src_ips, u32, u32);
BPF_HASH(blocked_udp_dest_ips, u32, u32);
BPF_HASH(blocked_tcp_src_src_ports, u16, u32);
BPF_HASH(blocked_tcp_src_dest_ports, u16, u32);
BPF_HASH(blocked_tcp_dest_src_ports, u16, u32);
BPF_HASH(blocked_tcp_dest_dest_ports, u16, u32);
BPF_HASH(blocked_udp_src_src_ports, u16, u32);
BPF_HASH(blocked_udp_src_dest_ports, u16, u32);
BPF_HASH(blocked_udp_dest_src_ports, u16, u32);
BPF_HASH(blocked_udp_dest_dest_ports, u16, u32);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) { //XDP responsible for parsing an IPv4 packet
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end){
        return 0;
    }

    return iph->protocol;
}

int xdp_prog1(struct CTXTYPE *ctx) { //eBPF program
    uint64_t timestamp = bpf_ktime_get_ns();
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

        if (index == 1 ) {

            struct iphdr *iph = data + nh_off;
			u32 src_ip = iph->saddr;  // Source IP address
			u32 *value_src = blocked_icmp_src_ips.lookup(&src_ip);
            u32 dest_ip = iph->daddr; // Destination IP address
			u32 *value_dest = blocked_icmp_dest_ips.lookup(&dest_ip);
			
            if (value_src) {
                bpf_trace_printk("%u: Blocked ICMP packet from source IP: %u, to destination IP: %u, blocked by source IP\n", timestamp, src_ip, dest_ip);
                return XDP_DROP; // Drop the packet from blocked IP address
            }else if (value_dest) {
                bpf_trace_printk("%u: Blocked ICMP packet from source IP: %u, to destination IP: %u, blocked by destination IP\n", timestamp, src_ip, dest_ip);
                return XDP_DROP; // Drop the packet from blocked IP address
            }else{
                bpf_trace_printk("%u: Pass ICMP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                return XDP_PASS;
            }

        } else if (index == 6 ) {

            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr; // Source IP address
            u32 *value_src_ip = blocked_tcp_src_ips.lookup(&src_ip);
            u32 dest_ip = iph->daddr; // Destination IP address
            u32 *value_dest_ip = blocked_tcp_dest_ips.lookup(&dest_ip);

            if(value_src_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                u32 *port_value_src_src = blocked_tcp_src_src_ports.lookup(&src_port);
                
                if (port_value_src_src) {
                    bpf_trace_printk("%u: Blocked TCP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by source IP: %u, source port: %u\n", timestamp, src_ip, src_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                u32 *port_value_src_dest = blocked_tcp_src_dest_ports.lookup(&dest_port);

                if (port_value_src_dest) {
                    bpf_trace_printk("%u: Blocked TCP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by source IP: %u, destination port: %u\n", timestamp, src_ip, dest_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                return XDP_PASS;
            } else if(value_dest_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                u32 *port_value_dest_src = blocked_tcp_dest_src_ports.lookup(&src_port);

                if (port_value_dest_src) {
                    bpf_trace_printk("%u: Blocked TCP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by destination IP: %u, source port: %u\n", timestamp, dest_ip, src_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }
                
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                u32 *port_value_dest_dest = blocked_tcp_dest_dest_ports.lookup(&dest_port);

                if (port_value_dest_dest) {
                    bpf_trace_printk("%u: Blocked TCP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by destination IP: %u, destination port: %u\n", timestamp, dest_ip, dest_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                return XDP_PASS;

            } else{
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                
                bpf_trace_printk("%u: Pass TCP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                bpf_trace_printk("%u: Pass TCP packet from source port: %u, to destination port: %u\n", timestamp, src_port, dest_port);
                return XDP_PASS;
            }

        } else if (index == 17 ) {

            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
            u32 *value_src_ip = blocked_udp_src_ips.lookup(&src_ip);
            u32 dest_ip = iph->daddr; // Destination IP address
            u32 *value_dest_ip = blocked_udp_dest_ips.lookup(&dest_ip);
            
            if(value_src_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                u32 *port_value_src_src = blocked_udp_src_src_ports.lookup(&src_port);
                
                if (port_value_src_src) {
                    bpf_trace_printk("%u: Blocked UDP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by source IP: %u, source port: %u\n", timestamp, src_ip, src_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                u32 *port_value_src_dest = blocked_udp_src_dest_ports.lookup(&dest_port);

                if (port_value_src_dest) {
                    bpf_trace_printk("%u: Blocked UDP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by source IP: %u, destination port: %u\n", timestamp, src_ip, src_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                return XDP_PASS;

            }else if(value_dest_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                u32 *port_value_dest_src = blocked_udp_dest_src_ports.lookup(&src_port);
                
                if (port_value_dest_src) {
                    bpf_trace_printk("%u: Blocked UDP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by destination IP: %u, source port: %u\n", timestamp, dest_ip, src_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                u32 *port_value_dest_dest = blocked_udp_dest_dest_ports.lookup(&dest_port);

                if (port_value_dest_dest) {
                    bpf_trace_printk("%u: Blocked UDP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                    bpf_trace_printk("%u: Blocked by destination IP: %u, destination port: %u\n", timestamp, dest_ip, dest_port);
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }

                return XDP_PASS;

            } else{
                data += sizeof(struct iphdr); // Skip the IPv4 header. 
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
    
                bpf_trace_printk("%u: Pass UDP packet from source IP: %u, to destination IP: %u\n", timestamp, src_ip, dest_ip);
                bpf_trace_printk("%u: Pass UDP packet from source port: %u, to destination port: %u\n", timestamp, src_port, dest_port);
                return XDP_PASS;
            }
            
        } else {
            bpf_trace_printk("%u: Pass diffrent packet", timestamp);
            return XDP_PASS;
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
    start := time.Now()
    var device string

    if len(os.Args) != 2 {
        usage()
    }

    device = os.Args[1]
    ret := "XDP_PASS"
    ctxtype := "xdp_md"

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

    //ICMP
    var lastIcmpSrcFileContent string
    blockedIcmpSrcIPs := bpf.NewTable(module.TableId("blocked_icmp_src_ips"), module)
    blockIcmpSrcIPsFile := "block_icmp_src_ips.txt"

    var lastIcmpDestFileContent string
    blockedIcmpDestIPs := bpf.NewTable(module.TableId("blocked_icmp_dest_ips"), module)
    blockIcmpDestIPsFile := "block_icmp_dest_ips.txt"
    
    //UDP
    var lastUdpSrcFileContent string
    blockedUdpSrcIPs := bpf.NewTable(module.TableId("blocked_udp_src_ips"), module)
    blockUdpSrcIPsFile := "block_udp_src_ips.txt"

    var lastUdpDestFileContent string
    blockedUdpDestIPs := bpf.NewTable(module.TableId("blocked_udp_dest_ips"), module)
    blockUdpDestIPsFile := "block_udp_dest_ips.txt"

    var lastUdpSrcSrcPortsFileContent string
    blockedUdpSrcSrcPorts := bpf.NewTable(module.TableId("blocked_udp_src_src_ports"), module)
    blockUdpSrcSrcPortsFile := "block_udp_src_src_ports.txt"

    var lastUdpSrcDestPortsFileContent string
    blockedUdpSrcDestPorts := bpf.NewTable(module.TableId("blocked_udp_src_dest_ports"), module)
    blockUdpSrcDestPortsFile := "block_udp_src_dest_ports.txt"

    var lastUdpDestSrcPortsFileContent string
    blockedUdpDestSrcPorts := bpf.NewTable(module.TableId("blocked_udp_dest_src_ports"), module)
    blockUdpDestSrcPortsFile := "block_udp_dest_src_ports.txt"

    var lastUdpDestDestPortsFileContent string
    blockedUdpDestDestPorts := bpf.NewTable(module.TableId("blocked_udp_dest_dest_ports"), module)
    blockUdpDestDestPortsFile := "block_udp_dest_dest_ports.txt"
    
    //TCP
    var lastTcpSrcFileContent string
    blockedTcpSrcIPs := bpf.NewTable(module.TableId("blocked_tcp_src_ips"), module)
    blockTcpSrcIPsFile := "block_tcp_src_ips.txt"
    
    var lastTcpDestFileContent string
    blockedTcpDestIPs := bpf.NewTable(module.TableId("blocked_tcp_dest_ips"), module)
    blockTcpDestIPsFile := "block_tcp_dest_ips.txt"

    var lastTcpSrcSrcPortsFileContent string
    blockedTcpSrcSrcPorts := bpf.NewTable(module.TableId("blocked_tcp_src_src_ports"), module)
    blockTcpSrcSrcPortsFile := "block_tcp_src_src_ports.txt"
    
    var lastTcpSrcDestPortsFileContent string
    blockedTcpSrcDestPorts := bpf.NewTable(module.TableId("blocked_tcp_src_dest_ports"), module)
    blockTcpSrcDestPortsFile := "block_tcp_src_dest_ports.txt"
   
    var lastTcpDestSrcPortsFileContent string
    blockedTcpDestSrcPorts := bpf.NewTable(module.TableId("blocked_tcp_dest_src_ports"), module)
    blockTcpDestSrcPortsFile := "block_tcp_dest_src_ports.txt"

    var lastTcpDestDestPortsFileContent string
    blockedTcpDestDestPorts := bpf.NewTable(module.TableId("blocked_tcp_dest_dest_ports"), module)
    blockTcpDestDestPortsFile := "block_tcp_dest_dest_ports.txt"

    fmt.Println("Blocking packets from specific IPv4 addresses, hit CTRL+C to stop")
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    for {
        //ICMP
        updateBlockedTableFromFile(blockIcmpSrcIPsFile, blockedIcmpSrcIPs, &lastIcmpSrcFileContent, displayBlockedSrcIcmpIPs)
        updateBlockedTableFromFile(blockIcmpDestIPsFile, blockedIcmpDestIPs, &lastIcmpDestFileContent, displayBlockedDestIcmpIPs)
        //UDP
        updateBlockedTableFromFile(blockUdpSrcIPsFile, blockedUdpSrcIPs, &lastUdpSrcFileContent, displayBlockedSrcUdpIPs)
        updateBlockedTableFromFile(blockUdpDestIPsFile, blockedUdpDestIPs, &lastUdpDestFileContent, displayBlockedDestUdpIPs)
        updateBlockedPortsTableFromFile(blockUdpSrcSrcPortsFile, blockedUdpSrcSrcPorts, &lastUdpSrcSrcPortsFileContent, displayBlockedUdpSrcSrcPorts)
        updateBlockedPortsTableFromFile(blockUdpSrcDestPortsFile, blockedUdpSrcDestPorts, &lastUdpSrcDestPortsFileContent, displayBlockedUdpSrcDestPorts)
        updateBlockedPortsTableFromFile(blockUdpDestSrcPortsFile, blockedUdpDestSrcPorts, &lastUdpDestSrcPortsFileContent, displayBlockedUdpDestSrcPorts)
        updateBlockedPortsTableFromFile(blockUdpDestDestPortsFile, blockedUdpDestDestPorts, &lastUdpDestDestPortsFileContent, displayBlockedUdpDestDestPorts)
        //TCP
        updateBlockedTableFromFile(blockTcpSrcIPsFile, blockedTcpSrcIPs, &lastTcpSrcFileContent, displayBlockedSrcTcpIPs)
        updateBlockedTableFromFile(blockTcpDestIPsFile, blockedTcpDestIPs, &lastTcpDestFileContent, displayBlockedDestTcpIPs)
        updateBlockedPortsTableFromFile(blockTcpSrcSrcPortsFile, blockedTcpSrcSrcPorts, &lastTcpSrcSrcPortsFileContent, displayBlockedTcpSrcSrcPorts)
        updateBlockedPortsTableFromFile(blockTcpSrcDestPortsFile, blockedTcpSrcDestPorts, &lastTcpSrcDestPortsFileContent, displayBlockedTcpSrcDestPorts)
        updateBlockedPortsTableFromFile(blockTcpDestSrcPortsFile, blockedTcpDestSrcPorts, &lastTcpDestSrcPortsFileContent, displayBlockedTcpDestSrcPorts)
        updateBlockedPortsTableFromFile(blockTcpDestDestPortsFile, blockedTcpDestDestPorts, &lastTcpDestDestPortsFileContent, displayBlockedTcpDestDestPorts)

        select {
        case <-sig:
            elapsed := time.Since(start)
            seconds := elapsed.Seconds()
            fmt.Printf("\nIP packets blocked by by %.2f seconds\n", seconds)
            return
        case <-time.After(5 * time.Second): // Check for changes every 5 seconds
        }
    }

}

//ICMP
func readIcmpSrcIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}

func readIcmpDestIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}
//UDP
func readUdpSrcIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}

func readUdpDestIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}
func readUdpSrcSrcPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readUdpSrcDestPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readUdpDestSrcPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readUdpDestDestPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}
//TCP
func readTcpSrcIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}

func readTcpDestIPsFromFile(filePath string) ([]string, error) {
    return readIPsFromFile(filePath)
}
func readTcpSrcSrcPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readTcpSrcDestPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readTcpDestSrcPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}

func readTcpDestDestPortsFromFile(filePath string) ([]string, error) {
    return readPortsFromFile(filePath)
}
//////////////////////////////////////////////
func computeFileHash(filePath string) string {
    file, err := os.Open(filePath)
    if err != nil {
        return ""
    }
    defer file.Close()

    hasher := md5.New()
    if _, err := io.Copy(hasher, file); err != nil {
        return ""
    }

    return fmt.Sprintf("%x", hasher.Sum(nil))
}

func clearTable(table *bpf.Table) {
    iter := table.Iter()
    for iter.Next() {
        key := iter.Key()
        err := table.Delete(key)
        if err != nil {
            fmt.Printf("Failed to delete entry from table: %v\n", err)
        }
    }
}
//ICMP
func displayBlockedSrcIcmpIPs(filePath string) {
    blockIcmpSrcIPs, err := readIcmpSrcIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked ICMP Source IP addresses:")
    for _, ip := range blockIcmpSrcIPs {
        fmt.Println(ip)
    }
}

func displayBlockedDestIcmpIPs(filePath string) {
    blockIcmpDestIPs, err := readIcmpDestIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked ICMP destination IP addresses:")
    for _, ip := range blockIcmpDestIPs {
        fmt.Println(ip)
    }
} 
//UDP
func displayBlockedSrcUdpIPs(filePath string) {
    blockUdpSrcIPs, err := readUdpSrcIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP source IP addresses:")
    for _, ip := range blockUdpSrcIPs {
        fmt.Println(ip)
    }
} 

func displayBlockedDestUdpIPs(filePath string) {
    blockUdpDestIPs, err := readUdpDestIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP destination IP addresses:")
    for _, ip := range blockUdpDestIPs {
        fmt.Println(ip)
    }
}    

func displayBlockedUdpSrcSrcPorts(filePath string) {
    blockUdpSrcSrcPorts, err := readUdpSrcSrcPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP source address source ports:")
    for _, ports := range blockUdpSrcSrcPorts {
        fmt.Println(ports)
    }
} 

func displayBlockedUdpSrcDestPorts(filePath string) {
    blockUdpSrcDestPorts, err := readUdpSrcDestPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP source address destination ports:")
    for _, ports := range blockUdpSrcDestPorts {
        fmt.Println(ports)
    }
} 

func displayBlockedUdpDestSrcPorts(filePath string) {
    blockUdpDestSrcPorts, err := readUdpDestSrcPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP destination address source ports:")
    for _, ports := range blockUdpDestSrcPorts {
        fmt.Println(ports)
    }
}

func displayBlockedUdpDestDestPorts(filePath string) {
    blockUdpDestDestPorts, err := readUdpDestDestPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP destination address destination ports:")
    for _, ports := range blockUdpDestDestPorts {
        fmt.Println(ports)
    }
}
//TCP
func displayBlockedSrcTcpIPs(filePath string) {
    blockTcpSrcIPs, err := readTcpSrcIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked Tcp source IP addresses:")
    for _, ip := range blockTcpSrcIPs {
        fmt.Println(ip)
    }
}  

func displayBlockedDestTcpIPs(filePath string) {
    blockTcpDestIPs, err := readTcpDestIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked Tcp destinatnion IP addresses:")
    for _, ip := range blockTcpDestIPs {
        fmt.Println(ip)
    }
} 

func displayBlockedTcpSrcSrcPorts(filePath string) {
    blockTcpSrcSrcPorts, err := readTcpSrcSrcPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP source address source ports:")
    for _, ports := range blockTcpSrcSrcPorts {
        fmt.Println(ports)
    }
}   

func displayBlockedTcpSrcDestPorts(filePath string) {
    blockTcpSrcDestPorts, err := readTcpSrcDestPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP source address destination ports:")
    for _, ports := range blockTcpSrcDestPorts {
        fmt.Println(ports)
    }
}

func displayBlockedTcpDestSrcPorts(filePath string) {
    blockTcpDestSrcPorts, err := readTcpDestSrcPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP destination address source ports:")
    for _, ports := range blockTcpDestSrcPorts {
        fmt.Println(ports)
    }
} 

func displayBlockedTcpDestDestPorts(filePath string) {
    blockTcpDestDestPorts, err := readTcpDestDestPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP destination address destination ports:")
    for _, ports := range blockTcpDestDestPorts {
        fmt.Println(ports)
    }
}

func updateBlockedTableFromFile(filePath string, table *bpf.Table, lastContent *string, displayFunc func(string)) {
    items, err := readItemsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read items from file: %v\n", err)
        os.Exit(1)
    }

    fileContent := strings.Join(items, "\n")

    if fileContent != *lastContent {
        // Content of the file has changed, update the BPF table
        clearTable(table) // Clear the existing entries
        for _, item := range items {
            if parsedItem := net.ParseIP(item); parsedItem != nil {
                key := parsedItem.To4()
                table.Set(key, []byte{0})
            }
        }
        *lastContent = fileContent

        // Display the updated blocked items
        displayFunc(filePath)
    }
}

func readItemsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var items []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        items = append(items, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return items, nil
}

func updateBlockedPortsTableFromFile(filePath string, table *bpf.Table, lastContent *string, displayFunc func(string)) {
    ports, err := readPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read ports from file: %v\n", err)
        os.Exit(1)
    }

    fileContent := strings.Join(ports, "\n")

    if fileContent != *lastContent {
        // Content of the file has changed, update the BPF table
        clearTable(table) // Clear the existing entries
        for _, port := range ports {
            key := []byte(port)
            table.Set(key, []byte{0})
        }
        *lastContent = fileContent

        // Display the updated blocked ports
        displayFunc(filePath)
    }
}

func readPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var ports []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        ports = append(ports, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return ports, nil
}

func readIPsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var blockIPs []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blockIPs = append(blockIPs, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return blockIPs, nil
}