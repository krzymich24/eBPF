// xdp_drop.go Drop incoming packets on XDP layer and count for which
// protocol type. Based on:
// https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright (c) 2017 GustavoKatel
// Licensed under the Apache License, Version 2.0 (the "License")

package main

import (
        "fmt"
        "os"
        "os/signal"
	"time"
        bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
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

BPF_TABLE("array", int, long, dropcnt, 256);


static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    
        struct iphdr *iph = data + nh_off;

        if ((void*)&iph[1] > data_end){
                return 0;
        }

        return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    
        struct ipv6hdr *ip6h = data + nh_off;

        if ((void*)&ip6h[1] > data_end){
                return 0;
        }

        return ip6h->nexthdr;
}

int xdp_prog1(struct CTXTYPE *ctx) {

        void* data_end = (void*)(long)ctx->data_end;
        void* data = (void*)(long)ctx->data;

        struct ethhdr *eth = data;

        // drop packets
        int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
        long *value;
        uint16_t h_proto;
        uint64_t nh_off = 0;
        int index;
        nh_off = sizeof(*eth);

        if (data + nh_off  > data_end){
                return rc;
        }

        h_proto = eth->h_proto;

        // While the following code appears to be duplicated accidentally,
        // it's intentional to handle double tags in ethernet frames.
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
    
                // Check if the packet is an ICMP packet (protocol number 1)
                if (index == 1) {

                        return XDP_PASS;  // Drop the packet

                }
        } else if (h_proto == htons(ETH_P_IPV6)) {

                index = parse_ipv6(data, nh_off, data_end);
    
                // Check if the packet is an ICMPv6 packet (protocol number 58)
                if (index == 58) {

                        return XDP_DROP;  // Drop the packet

                }
        } else {

                index = 0;

        }

        value = dropcnt.lookup(&index);

        if (value) {

                lock_xadd(value, 1);

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

        ret := "XDP_DROP"
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

        fmt.Println("Dropping packets, hit CTRL+C to stop")

        sig := make(chan os.Signal, 1)
        signal.Notify(sig, os.Interrupt, os.Kill)

        dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)

        <-sig

        elapsed := time.Since(start)
    	seconds := elapsed.Seconds()

		fmt.Printf("\nNumbers of dropped IP packets by network protocol blocked by %.2f seconds\n", seconds)

        for it := dropcnt.Iter(); it.Next(); {
                key := bpf.GetHostByteOrder().Uint32(it.Key())
                value := bpf.GetHostByteOrder().Uint64(it.Leaf())

                if value > 0 {
                        switch key {
                        case 1:
								speed := float64(value)
								bp := speed/seconds 
								fmt.Printf("ICMP: %d times, avg: %.2f bps\n", value, bp)
                        case 2:
                            	speed := float64(value)
								bp := speed/seconds     
								fmt.Printf("IGMP: %d times, avg: %.2f bps\n", value, bp)
                        case 3:
                           		speed := float64(value)
								bp := speed/seconds     
								fmt.Printf("GGP: %d times, avg: %.2f bps\n", value, bp)
                        case 4:
								speed := float64(value)
								bp := speed/seconds 
                                fmt.Printf("IPv4: %d times, avg: %.2f bps\n", value, bp)
                        case 5:
								speed := float64(value)
								bp := speed/seconds    
								fmt.Printf("ST: %d times, avg: %.2f bps\n", value, bp)
                        case 6:
                            	speed := float64(value)
								bp := speed/seconds     
								fmt.Printf("TCP: %d times, avg: %.2f bps\n", value, bp)
                        case 7:
								speed := float64(value)
								bp := speed/seconds 
                                fmt.Printf("CBT: %d times, avg: %.2f bps\n", value, bp)
                        case 8:
								speed := float64(value)
								bp := speed/seconds 
                                fmt.Printf("EGP: %d times, avg: %.2f bps\n", value, bp)
                        case 9:
								speed := float64(value)
								bp := speed/seconds 
                                fmt.Printf("IGP: %d times, avg: %.2f bps\n", value, bp)
                        case 10:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("BBN-RCC-MON: %d times, avg: %.2f bps\n", value, bp)
                        case 11:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("NVP-II: %d times, avg: %.2f bps\n", value, bp)
                        case 12:
								speed := float64(value)
								bp := speed/seconds
								fmt.Printf("PUP: %d times, avg: %.2f bps\n", value, bp)
                        case 13:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ARGUS: %d times, avg: %.2f bps\n", value, bp)
                        case 14:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("EMCON: %d times, avg: %.2f bps\n", value, bp)
                        case 15:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("XNET: %d times, avg: %.2f bps\n", value, bp)
                        case 16:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CHAOS: %d times, avg: %.2f bps\n", value, bp)
                        case 17:
                            	speed := float64(value)
								bp := speed/seconds     
								fmt.Printf("UDP: %d times, avg: %.2f bps\n", value, bp)
                        case 18:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MUX: %d times, avg: %.2f bps\n", value, bp)
                        case 19:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DCN-MEAS: %d times, avg: %.2f bps\n", value, bp)
                        case 20:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("HMP: %d times, avg: %.2f bps\n", value, bp)
                        case 21:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PRM: %d times, avg: %.2f bps\n", value, bp)
                        case 22:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("XNS-IDP: %d times, avg: %.2f bps\n", value, bp)
                        case 23:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("TRUNK-1: %d times, avg: %.2f bps\n", value, bp)
                        case 24:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("TRUNK-2: %d times, avg: %.2f bps\n", value, bp)
                        case 25:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("LEAF-1: %d times, avg: %.2f bps\n", value, bp)
                        case 26:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("LEAF-2: %d times, avg: %.2f bps\n", value, bp)
                        case 27:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("RDP: %d times, avg: %.2f bps\n", value, bp)
                        case 28:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IRTP: %d times, avg: %.2f bps\n", value, bp)
                        case 29:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ISO-TP4: %d times, avg: %.2f bps\n", value, bp)
                        case 30:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("NETBLT: %d times, avg: %.2f bps\n", value, bp)
                        case 31:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MFE-NSP: %d times, avg: %.2f bps\n", value, bp)
                        case 32:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MERIT-INP: %d times, avg: %.2f bps\n", value, bp)
                        case 33:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DCCP: %d times, avg: %.2f bps\n", value, bp)
                        case 34:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("3PC: %d times, avg: %.2f bps\n", value, bp)
                        case 35:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IDPR: %d times, avg: %.2f bps\n", value, bp)
                        case 36:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("XTP: %d times, avg: %.2f bps\n", value, bp)
                        case 37:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DDP: %d times, avg: %.2f bps\n", value, bp)
                        case 38:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IDPR-CMTP: %d times, avg: %.2f bps\n", value, bp)
                        case 39:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("TP++: %d times, avg: %.2f bps\n", value, bp) 
                        case 40:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IL: %d times, avg: %.2f bps\n", value, bp)
                        case 41:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6: %d times, avg: %.2f bps\n", value, bp)
                        case 42:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SDRP: %d times, avg: %.2f bps\n", value, bp)
                        case 43:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6-Route: %d times, avg: %.2f bps\n", value, bp)
                        case 44:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6-Frag: %d times, avg: %.2f bps\n", value, bp)
                        case 45:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IDRP: %d times, avg: %.2f bps\n", value, bp)
                        case 46:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("RSVP: %d times, avg: %.2f bps\n", value, bp)
                        case 47:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("GRE: %d times, avg: %.2f bps\n", value, bp)
                        case 48:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DSR: %d times, avg: %.2f bps\n", value, bp)
                        case 49:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("BNA: %d times, avg: %.2f bps\n", value, bp)
                        case 50:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ESP: %d times, avg: %.2f bps\n", value, bp)
                        case 51:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("AH: %d times, avg: %.2f bps\n", value, bp)
                        case 52:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("I-NLSP: %d times, avg: %.2f bps\n", value, bp)
                        case 53:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SWIPE: %d times, avg: %.2f bps\n", value, bp)
                        case 54:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("NARP: %d times, avg: %.2f bps\n", value, bp)
                        case 55:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MOBILE: %d times, avg: %.2f bps\n", value, bp)
                        case 56:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("TLSP: %d times, avg: %.2f bps\n", value, bp)
                        case 57:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SKIP: %d times, avg: %.2f bps\n", value, bp)
                        case 58:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6-ICMP:%d times, avg: %.2f bps\n", value, bp)
                        case 59:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6-NoNxt: %d times, avg: %.2f bps\n", value, bp)
                        case 60:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPv6-Opts: %d times, avg: %.2f bps\n", value, bp)
                        case 61:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("any host internal protocol: %d times, avg: %.2f bps\n", value, bp)
                        case 62:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CFTP: %d times, avg: %.2f bps\n", value, bp)
                        case 63:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("any local network: %d times, avg: %.2f bps\n", value, bp)
                        case 64:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SAT-EXPAK: %d times, avg: %.2f bps\n", value, bp)
                        case 65:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("KRYPTOLAN: %d times, avg: %.2f bps\n", value, bp)
                        case 66:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("RVD: %d times, avg: %.2f bps\n", value, bp)
                        case 67:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPPC: %d times, avg: %.2f bps\n", value, bp)
                        case 68:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("any distributed file system: %d times, avg: %.2f bps\n", value, bp)
                        case 69:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SAT-MON: %d times, avg: %.2f bps\n", value, bp)
                        case 70:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("VISA: %d times, avg: %.2f bps\n", value, bp)
                        case 71:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPCV: %d times, avg: %.2f bps\n", value, bp)
                        case 72:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CPNX: %d times, avg: %.2f bps\n", value, bp)
                        case 73:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CPHB: %d times, avg: %.2f bps\n", value, bp)
                        case 74:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("WSN: %d times, avg: %.2f bps\n", value, bp)
                        case 75:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PVP: %d times, avg: %.2f bps\n", value, bp)
                        case 76:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("BR-SAT-MON: %d times, avg: %.2f bps\n", value, bp)
                        case 77:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SUN-ND: %d times, avg: %.2f bps\n", value, bp)
                        case 78:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("WB-MON: %d times, avg: %.2f bps\n", value, bp) 
                        case 79:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("WB-EXPAK: %d times, avg: %.2f bps\n", value, bp)
                        case 80:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ISO-IP: %d times, avg: %.2f bps\n", value, bp)
                        case 81:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("VMTP: %d times, avg: %.2f bps\n", value, bp)
                        case 82:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SECURE-VMTP: %d times, avg: %.2f bps\n", value, bp)
                        case 83:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("VINES: %d times, avg: %.2f bps\n", value, bp)
                        case 84:
                            	speed := float64(value)
								bp := speed/seconds    
								fmt.Printf("IPTM: %d times, avg: %.2f bps\n", value, bp)
                        case 85:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("NSFNET-IGP: %d times, avg: %.2f bps\n", value, bp)
                        case 86:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DGP: %d times, avg: %.2f bps\n", value, bp)
                        case 87:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("TCF: %d times, avg: %.2f bps\n", value, bp)
                        case 88:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("EIGRP: %d times, avg: %.2f bps\n", value, bp)
                        case 89:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("OSPFIGP: %d times, avg: %.2f bps\n", value, bp)
                        case 90:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("Sprite-RPC: %d times, avg: %.2f bps\n", value, bp)
                        case 91:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("LARP: %d times, avg: %.2f bps\n", value, bp)
                        case 92:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MTP: %d times, avg: %.2f bps\n", value, bp)
                        case 93:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("AX.25: %d times, avg: %.2f bps\n", value, bp)
                        case 94:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPIP: %d times, avg: %.2f bps\n", value, bp)
                        case 95:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MICP: %d times, avg: %.2f bps\n", value, bp)
                        case 96:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SCC-SP: %d times, avg: %.2f bps\n", value, bp)
                        case 97:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ETHERIP: %d times, avg: %.2f bps\n", value, bp)
                        case 98:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ENCAP: %d times, avg: %.2f bps\n", value, bp)
                        case 99:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("any private encryption scheme: %d times, avg: %.2f bps\n", value, bp)
                        case 100:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("GMTP: %d times, avg: %.2f bps\n", value, bp)
                        case 101:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IFMP: %d times, avg: %.2f bps\n", value, bp)
                        case 102:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PNNI: %d times, avg: %.2f bps\n", value, bp)
                        case 103:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PIM: %d times, avg: %.2f bps\n", value, bp)
                        case 104:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ARIS: %d times, avg: %.2f bps\n", value, bp)
                        case 105:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SCPS: %d times, avg: %.2f bps\n", value, bp)
                        case 106:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("QNX: %d times, avg: %.2f bps\n", value, bp)
                        case 107:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("A/N: %d times, avg: %.2f bps\n", value, bp)
                        case 108:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPComp: %d times, avg: %.2f bps\n", value, bp)
                        case 109:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SNP: %d times, avg: %.2f bps\n", value, bp)
                        case 110:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("Compaq-Peer: %d times, avg: %.2f bps\n", value, bp)
                        case 111:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPX-in-IP: %d times, avg: %.2f bps\n", value, bp)
                        case 112:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("VRRP: %d times, avg: %.2f bps\n", value, bp)
                        case 113:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PGM: %d times, avg: %.2f bps\n", value, bp)
                        case 114:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("any 0-hop protocol: %d times, avg: %.2f bps\n", value, bp)
                        case 115:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("L2TP: %d times, avg: %.2f bps\n", value, bp)
                        case 116:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("DDX: %d times, avg: %.2f bps\n", value, bp)
                        case 117:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IATP: %d times, avg: %.2f bps\n", value, bp) 
                        case 118:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("STP: %d times, avg: %.2f bps\n", value, bp)
                        case 119:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SRP: %d times, avg: %.2f bps\n", value, bp)
                        case 120:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("UTI: %d times, avg: %.2f bps\n", value, bp)
                        case 121:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SMP: %d times, avg: %.2f bps\n", value, bp)
                        case 122:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SM:  %d times, avg: %.2f bps\n", value, bp)
                        case 123:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PTP: %d times, avg: %.2f bps\n", value, bp)
                        case 124:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ISIS over IPv4: %d times, avg: %.2f bps\n", value, bp)
                        case 125:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("FIRE: %d times, avg: %.2f bps\n", value, bp)
						case 126:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CRTP: %d times, avg: %.2f bps\n", value, bp)
						case 127:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("CRUDP: %d times, avg: %.2f bps\n", value, bp)
                        case 128:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SSCOPMCE: %d times, avg: %.2f bps\n", value, bp)
                        case 129:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("IPLT: %d times, avg: %.2f bps\n", value, bp)
                        case 130:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SPS: %d times, avg: %.2f bps\n", value, bp)
                        case 131:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("PIPE: %d times, avg: %.2f bps\n", value, bp)
                        case 132:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("SCTP: %d times, avg: %.2f bps\n", value, bp)
                        case 133:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("FC: %d times, avg: %.2f bps\n", value, bp)
                        case 134:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("RSVP-E2E-IGNORE: %d times, avg: %.2f bps\n", value, bp)
                        case 135:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("Mobility Header: %d times, avg: %.2f bps\n", value, bp)
                        case 136:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("UDPLite: %d times, avg: %.2f bps\n", value, bp)
                        case 137:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("MPLS-in-IP: %d times, avg: %.2f bps\n", value, bp)
                        case 138:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("manet: %d times, avg: %.2f bps\n", value, bp)
                        case 139:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("HIP: %d times, avg: %.2f bps\n", value, bp)
                        case 140:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("Shim6: %d times, avg: %.2f bps\n", value, bp)
                        case 141:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("WESP: %d times, avg: %.2f bps\n", value, bp)
                        case 142:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("ROHC: %d times, avg: %.2f bps\n", value, bp)
                        case 143:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("Ethernet: %d times, avg: %.2f bps\n", value, bp)
                        case 144:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("AGGFRAG: %d times, avg: %.2f bps\n", value, bp)
                        case 145:
								speed := float64(value)
								bp := speed/seconds
                                fmt.Printf("NSH: %d times, avg: %.2f bps\n", value, bp)
                        default:
                                fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
                                fmt.Printf("%v: %v pkts\n", key, value)    
                        }
                }
        }
}
