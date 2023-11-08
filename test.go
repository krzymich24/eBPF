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
            u32 dest_ip = iph->daddr; // Destination IP address
            u32 *value_src = blocked_icmp_src_ips.lookup(&src_ip);
            u32 *value_dest = blocked_icmp_dest_ips.lookup(&dest_ip);

            if (value_src) {
                return XDP_DROP; // Drop the packet from blocked IP address
            }else{
                return XDP_PASS; // Passing not blocker packets
            }

            if (value_dest) {
                return XDP_DROP; // Drop the packet from blocked IP address
            }else{
                return XDP_PASS; // Passing not blocker packets
            }

        } else if (index == 6 ) {

            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr; // Source IP address
            u32 dest_ip = iph->daddr; // Destination IP address
            u32 *value_src_ip = blocked_tcp_src_ips.lookup(&src_ip);
            u32 *value_dest_ip = blocked_tcp_dest_ips.lookup(&dests_ip);

            if(value_src_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.

                u32 *port_value_src_src = blocked_tcp_src_src_ports.lookup(&src_port);
                u32 *port_value_src_dest = blocked_tcp_src_dest_ports.lookup(&dest_port);

                if (port_value_src_src) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                }  

                if (port_value_src_dest) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                } 

            }else{
                return XDP_PASS;
            }

            if(value_dest_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.

                u32 *port_value_dest_src = blocked_tcp_dest_src_ports.lookup(&src_port);
                u32 *port_value_dest_dest = blocked_tcp_dest_dest_ports.lookup(&dest_port);

                if (port_value_dest_src) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                }  

                if (port_value_dest_dest) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                } 

            }else{
                return XDP_PASS; 
            }

        } else if (index == 17 ) {

            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
            u32 dest_ip = iph->daddr; // Destination IP address
            u32 *value_src_ip = blocked_udp_ips.lookup(&src_ip);
            u32 *value_dest_ip = blocked_udp_ips.lookup(&dest_ip);

            if(value_src_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.

                u32 *port_value_src_src = blocked_udp_src_src_ports.lookup(&src_port);
                u32 *port_value_src_dest = blocked_udp_src_dest_ports.lookup(&dest_port);

                if (port_value_src_src) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                }  

                if (port_value_src_dest) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                } 

            }else{
                return XDP_PASS;
            }

            if(value_dest_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.

                u32 *port_value_dest_src = blocked_udp_dest_src_ports.lookup(&src_port);
                u32 *port_value_dest_dest = blocked_udp_dest_dest_ports.lookup(&dest_port);

                if (port_value_dest_src) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                }  

                if (port_value_dest_dest) {
                    return XDP_DROP; // Drop the packet from a blocked IP and port
                }else{
                    return XDP_PASS; // Passing non-blocked packets
                } 

            }else{
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
    blockIcmpSrcIPsFile := "block_icmp_src_ips.txt"
    lastIcmpSrcFileContent := "" // Store the last content of the file

    blockIcmpDestIPsFile := "block_icmp_dest_ips.txt"
    lastIcmpDestFileContent := "" // Store the last content of the file
    
    //UDP
    blockUdpSrcIPsFile := "block_udp_src_ips.txt"
    lastUdpSrcFileContent := "" // Store the last content of the file

    blockUdpDestIPsFile := "block_udp_dest_ips.txt"
    lastUdpDestFileContent := "" // Store the last content of the file

    blockUdpSrcSrcPortsFile := "block_udp_src_src_ports.txt"
    lastUdpSrcSrcPortsFileContent := "" // Store the last content of the file

    blockUdpSrcDestPortsFile := "block_udp_src_dest_ports.txt"
    lastUdpSrcDestPortsFileContent := "" // Store the last content of the file

    blockUdpDestSrcPortsFile := "block_udp_dest_src_ports.txt"
    lastUdpDestSrcPortsFileContent := "" // Store the last content of the file

    blockUdpDestDestPortsFile := "block_udp_dest_dest_ports.txt"
    lastUdpDestDestPortsFileContent := "" // Store the last content of the file

    //TCP
    blockTcpSrcIPsFile := "block_tcp_src_ips.txt"
    lastTcpSrcFileContent := "" // Store the last content of the file
    
    blockTcpDestIPsFile := "block_tcp_dest_ips.txt"
    lastTcpDestFileContent := "" // Store the last content of the file

    blockTcpSrcSrcPortsFile := "block_tcp_src_src_ports.txt"
    lastTcpSrcSrcPortsFileContent := "" // Store the last content of the file

    blockTcpSrcDestPortsFile := "block_tcp_src_dest_ports.txt"
    lastTcpSrcDestPortsFileContent := "" // Store the last content of the file

    blockTcpDestSrcPortsFile := "block_tcp_dest_src_ports.txt"
    lastTcpDestSrcPortsFileContent := "" // Store the last content of the file

    blockTcpDestDestPortsFile := "block_tcp_dest_dest_ports.txt"
    lastTcpDestDestPortsFileContent := "" // Store the last content of the file



    fmt.Println("Blocking packets from specific IPv4 addresses, hit CTRL+C to stop")
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    for {
        //ICMP
        blockIcmpSrcIPs, err := readIcmpSrcIPsFromFile(blockIcmpSrcIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileIcmpSrcContent := strings.Join(blockIcmpSrcIPs, "\n")

        if fileIcmpSrcContent != lastIcmpSrcFileContent {
            // Content of the file has changed, update the BPF table
            blockedIcmpSrcIPs := bpf.NewTable(module.TableId("blocked_icmp_src_ips"), module)
            clearTable(blockedIcmpSrcIPs) // Clear the existing entries
            for _, ip := range blockIcmpSrcIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedIcmpSrcIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastIcmpSrcFileContent = fileIcmpSrcContent

            // Display the updated blocked IP addresses
            displayBlockedSrcIcmpIPs(blockIcmpSrcIPsFile)
        }

        blockIcmpDestIPs, err := readIcmpDestIPsFromFile(blockIcmpDestIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileIcmpDestContent := strings.Join(blockIcmpDestIPs, "\n")

        if fileIcmpDestContent != lastIcmpDestFileContent {
            // Content of the file has changed, update the BPF table
            blockedIcmpDestIPs := bpf.NewTable(module.TableId("blocked_icmp_dest_ips"), module)
            clearTable(blockedIcmpDestIPs) // Clear the existing entries
            for _, ip := range blockIcmpDestIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedIcmpDestIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastIcmpDestFileContent = fileIcmpDestContent

            // Display the updated blocked IP addresses
            displayBlockedDestIcmpIPs(blockIcmpDestIPsFile)
        }
        //UDP
        blockUdpSrcIPs, err := readUdpSrcIPsFromFile(blockUdpSrcIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpSrcContent := strings.Join(blockUdpSrcIPs, "\n")

        if fileUdpSrcContent != lastUdpSrcFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpSrcIPs := bpf.NewTable(module.TableId("blocked_udp_src_ips"), module)
            clearTable(blockedUdpSrcIPs) // Clear the existing entries
            for _, ip := range blockUdpSrcIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedUdpSrcIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastUdpSrcFileContent = fileUdpSrcContent

            // Display the updated blocked IP addresses
            displayBlockedSrcUdpIPs(blockUdpSrcIPsFile)
        }

        blockUdpDestIPs, err := readUdpDestIPsFromFile(blockUdpDestIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpDestContent := strings.Join(blockUdpDestIPs, "\n")

        if fileUdpDestContent != lastUdpDestFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpDestIPs := bpf.NewTable(module.TableId("blocked_udp_dest_ips"), module)
            clearTable(blockedUdpDestIPs) // Clear the existing entries
            for _, ip := range blockUdpDestIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedUdpDestIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastUdpDestFileContent = fileUdpDestContent

            // Display the updated blocked IP addresses
            displayBlockedDestUdpIPs(blockUdpDestIPsFile)
        }

        blockUdpSrcSrcPorts, err := readUdpSrcSrcPortsFromFile(blockUdpSrcSrcPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpSrcSrcPortsContent := strings.Join(blockUdpSrcSrcPorts, "\n")

        if fileUdpSrcSrcPortsContent != lastUdpSrcSrcPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpSrcSrcPorts := bpf.NewTable(module.TableId("blocked_udp_src_src_ports"), module)
            clearTable(blockedUdpSrcSrcPorts) // Clear the existing entries
            for _, port := range blockUdpSrcSrcPorts {
                    blockedUdpSrcSrcPorts.Set([]byte(port), []byte{0})
            }
            lastUdpSrcSrcPortsFileContent = fileUdpSrcSrcPortsContent

            // Display the updated blocked IP addresses
            displayBlockedUdpSrcSrcPorts(blockUdpSrcSrcPortsFile)
        }

        blockUdpSrcDestPorts, err := readUdpSrcDestPortsFromFile(blockUdpSrcDestPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpSrcDestPortsContent := strings.Join(blockUdpSrcDestPorts, "\n")

        if fileUdpSrcDestPortsContent != lastUdpSrcDestPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpSrcDestPorts := bpf.NewTable(module.TableId("blocked_udp_src_dest_ports"), module)
            clearTable(blockedUdpSrcDestPorts) // Clear the existing entries
            for _, port := range blockUdpSrcDestPorts {
                    blockedUdpSrcDestPorts.Set([]byte(port), []byte{0})
            }
            lastUdpSrcDestPortsFileContent = fileUdpSrcDestPortsContent

            // Display the updated blocked IP addresses
            displayBlockedUdpSrcDestPorts(blockUdpSrcDestPortsFile)
        }

        blockUdpDestSrcPorts, err := readUdpDestSrcPortsFromFile(blockUdpDestSrcPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpDestSrcPortsContent := strings.Join(blockUdpDestSrcPorts, "\n")

        if fileUdpDestSrcPortsContent != lastUdpDestSrcPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpDestSrcPorts := bpf.NewTable(module.TableId("blocked_udp_dest_src_ports"), module)
            clearTable(blockedUdpDestSrcPorts) // Clear the existing entries
            for _, port := range blockUdpDestSrcPorts {
                    blockedUdpDestSrcPorts.Set([]byte(port), []byte{0})
            }
            lastUdpDestSrcPortsFileContent = fileUdpDestSrcPortsContent

            // Display the updated blocked IP addresses
            displayBlockedUdpDestSrcPorts(blockUdpDestSrcPortsFile)
        }

        blockUdpDestDestPorts, err := readUdpDestDestPortsFromFile(blockUdpDestDestPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpDestDestPortsContent := strings.Join(blockUdpDestDestPorts, "\n")

        if fileUdpDestDestPortsContent != lastUdpDestDestPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpDestDestPorts := bpf.NewTable(module.TableId("blocked_udp_dest_dest_ports"), module)
            clearTable(blockedUdpDestDestPorts) // Clear the existing entries
            for _, port := range blockUdpDestDestPorts {
                    blockedUdpDestDestPorts.Set([]byte(port), []byte{0})
            }
            lastUdpDestDestPortsFileContent = fileUdpDestDestPortsContent

            // Display the updated blocked IP addresses
            displayBlockedUdpDestDestPorts(blockUdpDestDestPortsFile)
        }

        //TCP
        blockTcpSrcIPs, err := readTcpSrcIPsFromFile(blockTcpSrcIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpSrcContent := strings.Join(blockTcpSrcIPs, "\n")

        if fileTcpSrcContent != lastTcpSrcFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpSrcIPs := bpf.NewTable(module.TableId("blocked_tcp_src_ips"), module)
            clearTable(blockedTcpSrcIPs) // Clear the existing entries
            for _, ip := range blockTcpSrcIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedTcpSrcIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastTcpSrcFileContent = fileTcpSrcContent

            // Display the updated blocked IP addresses
            displayBlockedSrcTcpIPs(blockTcpSrcIPsFile)
        }

        blockTcpDestIPs, err := readTcpDestIPsFromFile(blockTcpDestIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpDestContent := strings.Join(blockTcpDestIPs, "\n")

        if fileTcpDestContent != lastTcpDestFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpDestIPs := bpf.NewTable(module.TableId("blocked_tcp_dest_ips"), module)
            clearTable(blockedTcpDestIPs) // Clear the existing entries
            for _, ip := range blockTcpDestIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedTcpDestIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastTcpDestFileContent = fileTcpDestContent

            // Display the updated blocked IP addresses
            displayBlockedDestTcpIPs(blockTcpDestIPsFile)
        }

        blockTcpSrcSrcPorts, err := readTcpSrcSrcPortsFromFile(blockTcpSrcSrcPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpSrcSrcPortsContent := strings.Join(blockTcpSrcSrcPorts, "\n")

        if fileTcpSrcSrcPortsContent != lastTcpSrcSrcPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpSrcSrcPorts := bpf.NewTable(module.TableId("blocked_tcp_src_src_ports"), module)
            clearTable(blockedTcpSrcSrcPorts) // Clear the existing entries
            for _, port := range blockTcpSrcSrcPorts {
                    blockedTcpSrcSrcPorts.Set([]byte(port), []byte{0})
            }
            lastTcpSrcSrcPortsFileContent = fileTcpSrcSrcPortsContent

            // Display the updated blocked IP addresses
            displayBlockedTcpSrcSrcPorts(blockTcpSrcSrcPortsFile)
        }

        blockTcpSrcDestPorts, err := readTcpSrcDestPortsFromFile(blockTcpSrcDestPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpSrcDestPortsContent := strings.Join(blockTcpSrcDestPorts, "\n")

        if fileTcpSrcDestPortsContent != lastTcpSrcDestPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpSrcDestPorts := bpf.NewTable(module.TableId("blocked_tcp_src_dest_ports"), module)
            clearTable(blockedTcpSrcDestPorts) // Clear the existing entries
            for _, port := range blockTcpSrcDestPorts {
                    blockedTcpSrcDestPorts.Set([]byte(port), []byte{0})
            }
            lastTcpSrcDestPortsFileContent = fileTcpSrcDestPortsContent

            // Display the updated blocked IP addresses
            displayBlockedTcpSrcDestPorts(blockTcpSrcDestPortsFile)
        }

        blockTcpDestSrcPorts, err := readTcpDestSrcPortsFromFile(blockTcpDestSrcPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpDestSrcPortsContent := strings.Join(blockTcpDestSrcPorts, "\n")

        if fileTcpDestSrcPortsContent != lastTcpDestSrcPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpDestSrcPorts := bpf.NewTable(module.TableId("blocked_tcp_dest_src_ports"), module)
            clearTable(blockedTcpDestSrcPorts) // Clear the existing entries
            for _, port := range blockTcpDestSrcPorts {
                    blockedTcpDestSrcPorts.Set([]byte(port), []byte{0})
            }
            lastTcpDestSrcPortsFileContent = fileTcpDestSrcPortsContent

            // Display the updated blocked IP addresses
            displayBlockedTcpDestSrcPorts(blockTcpDestSrcPortsFile)
        }

        blockTcpDestDestPorts, err := readTcpDestDestPortsFromFile(blockTcpDestDestPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpDestDestPortsContent := strings.Join(blockTcpDestDestPorts, "\n")

        if fileTcpDestDestPortsContent != lastTcpDestDestPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpDestDestPorts := bpf.NewTable(module.TableId("blocked_tcp_dest_dest_ports"), module)
            clearTable(blockedTcpDestDestPorts) // Clear the existing entries
            for _, port := range blockTcpDestDestPorts {
                    blockedTcpDestDestPorts.Set([]byte(port), []byte{0})
            }
            lastTcpDestDestPortsFileContent = fileTcpDestDestPortsContent

            // Display the updated blocked IP addresses
            displayBlockedTcpDestDestPorts(blockTcpDestDestPortsFile)
        }

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
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockIcmpSrcIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockIcmpSrcIPs = append(blockIcmpSrcIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockIcmpSrcIPs, nil
}

func readIcmpDestIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockIcmpDestIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockIcmpDestIPs = append(blockIcmpDestIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockIcmpDestIPs, nil
}
//UDP
func readUdpSrcIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpSrcIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpSrcIPs = append(blockUdpSrcIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpSrcIPs, nil
}

func readUdpDestIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpDestIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpDestIPs = append(blockUdpDestIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpDestIPs, nil
}

func readUdpSrcSrcPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpSrcSrcPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpSrcSrcPorts = append(blockUdpSrcSrcPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpSrcSrcPorts, nil
}

func readUdpSrcDestPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpSrcDestPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpSrcDestPorts = append(blockUdpSrcDestPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpSrcDestPorts, nil
}

func readUdpDestSrcPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpDestSrcPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpDestSrcPorts = append(blockUdpDestSrcPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpDestSrcPorts, nil
}

func readUdpDestDestPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpDestDestPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpDestDestPorts = append(blockUdpDestDestPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpDestDestPorts, nil
}
//TCP
func readTcpSrcIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpSrcIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpSrcIPs = append(blockTcpSrcIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpSrcIPs, nil
}

func readTcpDestIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpDestIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpDestIPs = append(blockTcpDestIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpDestIPs, nil
}

func readTcpSrcSrcPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpSrcSrcPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpSrcSrcPorts = append(blockTcpSrcSrcPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpSrcSrcSrcSrcPorts, nil
}

func readTcpSrcDestPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpSrcDestPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpSrcDestPorts = append(blockTcpSrcDestPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpSrcDestPorts, nil
}

func readTcpDestSrcPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpDestSrcPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpDestSrcPorts = append(blockTcpDestSrcPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpDestSrcPorts, nil
}

func readTcpDestDestPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpDestDestPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpDestDestPorts = append(blockTcpDestDestPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpDestDestPorts, nil
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
    blockTcpSrcDestPorts, err := readTcpSrcSrcPortsFromFile(filePath)
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