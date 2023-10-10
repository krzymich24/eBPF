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
                if (index == 66) {

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

        fmt.Printf("\nNumbers of dropped IP packets by network protocol\n")
        for it := dropcnt.Iter(); it.Next(); {
                key := bpf.GetHostByteOrder().Uint32(it.Key())
                value := bpf.GetHostByteOrder().Uint64(it.Leaf())

                if value > 0 {
                        switch key {
                        case 0:
                                fmt.Printf("HOPOPT: %v times\n", value) 
                        case 1:
                                fmt.Printf("ICMP: %v times\n", value)
                        case 2:
                                fmt.Printf("IGMP: %v times\n", value)
                        case 3:
                                fmt.Printf("GGP: %v times\n", value)
                        case 4:
                                fmt.Printf("IPv4: %v times\n", value)
                        case 5:
                                fmt.Printf("ST: %v times\n", value)
                        case 6:
                                fmt.Printf("TCP: %v times\n", value)
                        case 7:
                                fmt.Printf("CBT: %v times\n", value)
                        case 8:
                                fmt.Printf("EGP: %v times\n", value)
                        case 9:
                                fmt.Printf("IGP: %v times\n", value)
                        case 10:
                                fmt.Printf("BBN-RCC-MON: %v times\n", value)
                        case 11:
                                fmt.Printf("NVP-II: %v times\n", value)
                        case 12:
                                fmt.Printf("PUP: %v times\n", value)
                        case 13:
                                fmt.Printf("ARGUS: %v times\n", value)
                        case 14:
                                fmt.Printf("EMCON: %v times\n", value)
                        case 15:
                                fmt.Printf("XNET: %v times\n", value)
                        case 16:
                                fmt.Printf("CHAOS: %v times\n", value)
                        case 17:
                                fmt.Printf("UDP: %v times\n", value)
                        case 18:
                                fmt.Printf("MUX: %v times\n", value)
                        case 19:
                                fmt.Printf("DCN-MEAS: %v times\n", value)
                        case 20:
                                fmt.Printf("HMP: %v times\n", value)
                        case 21:
                                fmt.Printf("PRM: %v times\n", value)
                        case 22:
                                fmt.Printf("XNS-IDP: %v times\n", value)
                        case 23:
                                fmt.Printf("TRUNK-1: %v times\n", value)
                        case 24:
                                fmt.Printf("TRUNK-2: %v times\n", value)
                        case 25:
                                fmt.Printf("LEAF-1: %v times\n", value)
                        case 26:
                                fmt.Printf("LEAF-2: %v times\n", value)
                        case 27:
                                fmt.Printf("RDP: %v times\n", value)
                        case 28:
                                fmt.Printf("IRTP: %v times\n", value)
                        case 29:
                                fmt.Printf("ISO-TP4: %v times\n", value)
                        case 30:
                                fmt.Printf("NETBLT: %v times\n", value)
                        case 31:
                                fmt.Printf("MFE-NSP: %v times\n", value)
                        case 32:
                                fmt.Printf("MERIT-INP: %v times\n", value)
                        case 33:
                                fmt.Printf("DCCP: %v times\n", value)
                        case 34:
                                fmt.Printf("3PC: %v times\n", value)
                        case 35:
                                fmt.Printf("IDPR: %v times\n", value)
                        case 36:
                                fmt.Printf("XTP: %v times\n", value)
                        case 37:
                                fmt.Printf("DDP: %v times\n", value)
                        case 38:
                                fmt.Printf("IDPR-CMTP: %v times\n", value)
                        case 39:
                                fmt.Printf("TP++: %v times\n", value) 
                        case 40:
                                fmt.Printf("IL: %v times\n", value)
                        case 41:
                                fmt.Printf("IPv6: %v times\n", value)
                        case 42:
                                fmt.Printf("SDRP: %v times\n", value)
                        case 43:
                                fmt.Printf("IPv6-Route: %v times\n", value)
                        case 44:
                                fmt.Printf("IPv6-Frag: %v times\n", value)
                        case 45:
                                fmt.Printf("IDRP: %v times\n", value)
                        case 46:
                                fmt.Printf("RSVP: %v times\n", value)
                        case 47:
                                fmt.Printf("GRE: %v times\n", value)
                        case 48:
                                fmt.Printf("DSR: %v times\n", value)
                        case 49:
                                fmt.Printf("BNA: %v times\n", value)
                        case 50:
                                fmt.Printf("ESP: %v times\n", value)
                        case 51:
                                fmt.Printf("AH: %v times\n", value)
                        case 52:
                                fmt.Printf("I-NLSP: %v times\n", value)
                        case 53:
                                fmt.Printf("SWIPE: %v times\n", value)
                        case 54:
                                fmt.Printf("NARP: %v times\n", value)
                        case 55:
                                fmt.Printf("MOBILE: %v times\n", value)
                        case 56:
                                fmt.Printf("TLSP: %v times\n", value)
                        case 57:
                                fmt.Printf("SKIP: %v times\n", value)
                        case 58:
                                fmt.Printf("IPv6-ICMP:%v times\n", value)
                        case 59:
                                fmt.Printf("IPv6-NoNxt: %v times\n", value)
                        case 60:
                                fmt.Printf("IPv6-Opts: %v times\n", value)
                        case 61:
                                fmt.Printf("any host internal protocol: %v times\n", value)
                        case 62:
                                fmt.Printf("CFTP: %v times\n", value)
                        case 63:
                                fmt.Printf("any local network: %v times\n", value)
                        case 64:
                                fmt.Printf("SAT-EXPAK: %v times\n", value)
                        case 65:
                                fmt.Printf("KRYPTOLAN: %v times\n", value)
                        case 66:
                                fmt.Printf("RVD: %v times\n", value)
                        case 67:
                                fmt.Printf("IPPC: %v times\n", value)
                        case 68:
                                fmt.Printf("any distributed file system: %v times\n", value)
                        case 69:
                                fmt.Printf("SAT-MON: %v times\n", value)
                        case 70:
                                fmt.Printf("VISA: %v times\n", value)
                        case 71:
                                fmt.Printf("IPCV: %v times\n", value)
                        case 72:
                                fmt.Printf("CPNX: %v times\n", value)
                        case 73:
                                fmt.Printf("CPHB: %v times\n", value)
                        case 74:
                                fmt.Printf("WSN: %v times\n", value)
                        case 75:
                                fmt.Printf("PVP: %v times\n", value)
                        case 76:
                                fmt.Printf("BR-SAT-MON: %v times\n", value)
                        case 77:
                                fmt.Printf("SUN-ND: %v times\n", value)
                        case 78:
                                fmt.Printf("WB-MON: %v times\n", value) 
                        case 79:
                                fmt.Printf("WB-EXPAK: %v times\n", value)
                        case 80:
                                fmt.Printf("ISO-IP: %v times\n", value)
                        case 81:
                                fmt.Printf("VMTP: %v times\n", value)
                        case 82:
                                fmt.Printf("SECURE-VMTP: %v times\n", value)
                        case 83:
                                fmt.Printf("VINES: %v times\n", value)
                        case 84:
                                fmt.Printf("IPTM: %v times\n", value)
                        case 85:
                                fmt.Printf("NSFNET-IGP: %v times\n", value)
                        case 86:
                                fmt.Printf("DGP: %v times\n", value)
                        case 87:
                                fmt.Printf("TCF: %v times\n", value)
                        case 88:
                                fmt.Printf("EIGRP: %v times\n", value)
                        case 89:
                                fmt.Printf("OSPFIGP: %v times\n", value)
                        case 90:
                                fmt.Printf("Sprite-RPC: %v times\n", value)
                       case 91:
                                fmt.Printf("LARP: %v times\n", value)
                        case 92:
                                fmt.Printf("MTP: %v times\n", value)
                        case 93:
                                fmt.Printf("AX.25: %v times\n", value)
                        case 94:
                                fmt.Printf("IPIP: %v times\n", value)
                        case 95:
                                fmt.Printf("MICP: %v times\n", value)
                        case 96:
                                fmt.Printf("SCC-SP: %v times\n", value)
                        case 97:
                                fmt.Printf("ETHERIP: %v times\n", value)
                        case 98:
                                fmt.Printf("ENCAP: %v times\n", value)
                        case 99:
                                fmt.Printf("any private encryption scheme: %v times\n", value)
                        case 100:
                                fmt.Printf("GMTP: %v times\n", value)
                        case 101:
                                fmt.Printf("IFMP: %v times\n", value)
                        case 102:
                                fmt.Printf("PNNI: %v times\n", value)
                        case 103:
                                fmt.Printf("PIM: %v times\n", value)
                        case 104:
                                fmt.Printf("ARIS: %v times\n", value)
                        case 105:
                                fmt.Printf("SCPS: %v times\n", value)
                        case 106:
                                fmt.Printf("QNX: %v times\n", value)
                        case 107:
                                fmt.Printf("A/N: %v times\n", value)
                        case 108:
                                fmt.Printf("IPComp: %v times\n", value)
                        case 109:
                                fmt.Printf("SNP: %v times\n", value)
                        case 110:
                                fmt.Printf("Compaq-Peer: %v times\n", value)
                        case 111:
                                fmt.Printf("IPX-in-IP: %v times\n", value)
                        case 112:
                                fmt.Printf("VRRP: %v times\n", value)
                        case 113:
                                fmt.Printf("PGM: %v times\n", value)
                        case 114:
                                fmt.Printf("any 0-hop protocol: %v times\n", value)
                        case 115:
                                fmt.Printf("L2TP: %v times\n", value)
                        case 116:
                                fmt.Printf("DDX: %v times\n", value)
                        case 117:
                                fmt.Printf("IATP: %v times\n", value) 
                        case 118:
                                fmt.Printf("STP: %v times\n", value)
                        case 119:
                                fmt.Printf("SRP: %v times\n", value)
                        case 120:
                                fmt.Printf("UTI: %v times\n", value)
                        case 121:
                                fmt.Printf("SMP: %v times\n", value)
                        case 122:
                                fmt.Printf("SM:  %v times\n", value)
                        case 123:
                                fmt.Printf("PTP: %v times\n", value)
                        case 124:
                                fmt.Printf("ISIS over IPv4: %v times\n", value)
                                fmt.Printf("ISIS over IPv4: %v times\n", value)
                        case 125:
                                fmt.Printf("FIRE: %v times\n", value)
                        case 127:
                                fmt.Printf("CRUDP: %v times\n", value)
                        case 128:
                                fmt.Printf("SSCOPMCE: %v times\n", value)
                        case 129:
                                fmt.Printf("IPLT: %v times\n", value)
                        case 130:
                                fmt.Printf("SPS: %v times\n", value)
                        case 131:
                                fmt.Printf("PIPE: %v times\n", value)
                        case 132:
                                fmt.Printf("SCTP: %v times\n", value)
                        case 133:
                                fmt.Printf("FC: %v times\n", value)
                        case 134:
                                fmt.Printf("RSVP-E2E-IGNORE: %v times\n", value)
                        case 135:
                                fmt.Printf("Mobility Header: %v times\n", value)
                        case 136:
                                fmt.Printf("UDPLite: %v times\n", value)
                        case 137:
                                fmt.Printf("MPLS-in-IP: %v times\n", value)
                        case 138:
                                fmt.Printf("manet: %v times\n", value)
                        case 139:
                                fmt.Printf("HIP: %v times\n", value)
                        case 140:
                                fmt.Printf("Shim6: %v times\n", value)
                        case 141:
                                fmt.Printf("WESP: %v times\n", value)
                        case 142:
                                fmt.Printf("ROHC: %v times\n", value)
                        case 143:
                                fmt.Printf("Ethernet: %v times\n", value)
                        case 144:
                                fmt.Printf("AGGFRAG: %v times\n", value)
                        case 145:
                                fmt.Printf("NSH: %v times\n", value)
                        default:
                                fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
                                fmt.Printf("%v: %v pkts\n", key, value)    
                        }
                }
        }
}
