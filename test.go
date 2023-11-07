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
            u32 *value = blocked_udp_ips.lookup(&src_ip);
            u32 *value = blocked_udp_ips.lookup(&src_ip);

            if(value_src_ip){
                data += sizeof(struct iphdr); // Skip the IPv4 header.
                uint16_t dest_port = *((uint16_t*)data); // Extract the destination port.
                uint16_t src_port = *((uint16_t*)data); // Extract the destination port.
                dest_port = ntohs(dest_port); // Convert to host byte order if necessary.
                src_port = ntohs(src_port); // Convert to host byte order if necessary.

                u32 *port_value_src_src = blocked_udo_src_src_ports.lookup(&src_port);
                u32 *port_value_src_dest = blocked_udo_src_dest_ports.lookup(&dest_port);

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
    blockIcmpIPsFile := "block_icmp_src_ips.txt"
    lastIcmpFileContent := "" // Store the last content of the file

    blockTcpIPsFile := "block_icmp_dest_ips.txt"
    lastTcpFileContent := "" // Store the last content of the file
    
    //UDP
    blockUdpIPsFile := "block_udp_src_ips.txt"
    lastUdpFileContent := "" // Store the last content of the file

    blockUdpPortsFile := "block_udp_dest_ips.txt"
    lastUdpPortsFileContent := "" // Store the last content of the file

    blockUdpIPsFile := "block_udp_src_src_ports.txt"
    lastUdpFileContent := "" // Store the last content of the file

    blockTcpIPsFile := "block_udp_src_dest_ports.txt"
    lastTcpFileContent := "" // Store the last content of the file

    blockUdpIPsFile := "block_udp_dest_src_ports.txt"
    lastUdpFileContent := "" // Store the last content of the file

    blockUdpPortsFile := "block_udp_dest_dest_ports.txt"
    lastUdpPortsFileContent := "" // Store the last content of the file

    //TCP
    blockIcmpIPsFile := "block_tcp_src_ips.txt"
    lastIcmpFileContent := "" // Store the last content of the file
    
    blockTcpPortsFile := "block_tcp_dest_ips.txt"
    lastTcpPortsFileContent := "" // Store the last content of the file

    blockUdpPortsFile := "block_tcp_src_src_ports.txt"
    lastUdpPortsFileContent := "" // Store the last content of the file

    blockTcpPortsFile := "block_tcp_src_dest_ports.txt"
    lastTcpPortsFileContent := "" // Store the last content of the file

    blockIcmpIPsFile := "block_tcp_dest_src_ports.txt"
    lastIcmpFileContent := "" // Store the last content of the file

    blockTcpIPsFile := "block_tcp_dest_dest_ports.txt"
    lastTcpFileContent := "" // Store the last content of the file



    fmt.Println("Blocking packets from specific IPv4 addresses, hit CTRL+C to stop")
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    for {
        blockIcmpIPs, err := readIcmpIPsFromFile(blockIcmpIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileIcmpContent := strings.Join(blockIcmpIPs, "\n")

        if fileIcmpContent != lastIcmpFileContent {
            // Content of the file has changed, update the BPF table
            blockedIcmpIPs := bpf.NewTable(module.TableId("blocked_icmp_ips"), module)
            clearTable(blockedIcmpIPs) // Clear the existing entries
            for _, ip := range blockIcmpIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedIcmpIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastIcmpFileContent = fileIcmpContent

            // Display the updated blocked IP addresses
            displayBlockedIcmpIPs(blockIcmpIPsFile)
        }

        blockTcpIPs, err := readTcpIPsFromFile(blockTcpIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpContent := strings.Join(blockTcpIPs, "\n")

        if fileTcpContent != lastTcpFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpIPs := bpf.NewTable(module.TableId("blocked_tcp_ips"), module)
            clearTable(blockedTcpIPs) // Clear the existing entries
            for _, ip := range blockTcpIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedTcpIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastTcpFileContent = fileTcpContent

            // Display the updated blocked IP addresses
            displayBlockedTcpIPs(blockTcpIPsFile)
        }

        blockUdpIPs, err := readUdpIPsFromFile(blockUdpIPsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpContent := strings.Join(blockUdpIPs, "\n")

        if fileUdpContent != lastUdpFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpIPs := bpf.NewTable(module.TableId("blocked_udp_ips"), module)
            clearTable(blockedUdpIPs) // Clear the existing entries
            for _, ip := range blockUdpIPs {
                if parsedIP := net.ParseIP(ip); parsedIP != nil {
                    blockedUdpIPs.Set(parsedIP.To4(), []byte{0})
                }
            }
            lastUdpFileContent = fileUdpContent

            // Display the updated blocked IP addresses
            displayBlockedUdpIPs(blockUdpIPsFile)
        }

        blockUdpPorts, err := readUdpPortsFromFile(blockUdpPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileUdpPortsContent := strings.Join(blockUdpPorts, "\n")

        if fileUdpPortsContent != lastUdpPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedUdpPorts := bpf.NewTable(module.TableId("blocked_udp_ports"), module)
            clearTable(blockedUdpPorts) // Clear the existing entries
            for _, port := range blockUdpPorts {
                    blockedUdpPorts.Set([]byte(port), []byte{0})
            }
            lastUdpPortsFileContent = fileUdpPortsContent

            // Display the updated blocked IP addresses
            displayBlockedUdpPorts(blockUdpPortsFile)
        }

        blockTcpPorts, err := readTcpPortsFromFile(blockTcpPortsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
            os.Exit(1)
        }

        fileTcpPortsContent := strings.Join(blockTcpPorts, "\n")

        if fileTcpPortsContent != lastTcpPortsFileContent {
            // Content of the file has changed, update the BPF table
            blockedTcpPorts := bpf.NewTable(module.TableId("blocked_tcp_ports"), module)
            clearTable(blockedTcpPorts) // Clear the existing entries
            for _, port := range blockTcpPorts {
                    blockedTcpPorts.Set([]byte(port), []byte{0})
            }
            lastTcpPortsFileContent = fileTcpPortsContent

            // Display the updated blocked IP addresses
            displayBlockedTcpPorts(blockTcpPortsFile)
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


func readIcmpIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockIcmpIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockIcmpIPs = append(blockIcmpIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockIcmpIPs, nil
}

func readTcpIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpIPs = append(blockTcpIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpIPs, nil
}

func readUdpIPsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpIPs []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpIPs = append(blockUdpIPs, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpIPs, nil
}

func readUdpPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockUdpPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockUdpPorts = append(blockUdpPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockUdpPorts, nil
}

func readTcpPortsFromFile(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var blockTcpPorts []string

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        blockTcpPorts = append(blockTcpPorts, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return blockTcpPorts, nil
}



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

func displayBlockedIcmpIPs(filePath string) {
    blockIcmpIPs, err := readIcmpIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked ICMP IP addresses:")
    for _, ip := range blockIcmpIPs {
        fmt.Println(ip)
    }
}

func displayBlockedTcpIPs(filePath string) {
    blockTcpIPs, err := readTcpIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP IP addresses:")
    for _, ip := range blockTcpIPs {
        fmt.Println(ip)
    }
}

func displayBlockedUdpIPs(filePath string) {
    blockUdpIPs, err := readUdpIPsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked Udp IP addresses:")
    for _, ip := range blockUdpIPs {
        fmt.Println(ip)
    }
}

func displayBlockedUdpPorts(filePath string) {
    blockUdpPorts, err := readUdpPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked UDP Ports:")
    for _, ports := range blockUdpPorts {
        fmt.Println(ports)
    }
}

func displayBlockedTcpPorts(filePath string) {
    blockTcpPorts, err := readTcpPortsFromFile(filePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read IP addresses from file: %v\n", err)
        return
    }

    fmt.Println("Blocked TCP Ports:")
    for _, ports := range blockTcpPorts {
        fmt.Println(ports)
    }
}