/*
 * This file is part of the BCModule source code.
 * Copyright (c) 2025 MaxiHunter
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#ifndef __PKT_HEADERS_H__
#define __PKT_HEADERS_H__

#include <inttypes.h>
#include <string.h>
// EtherTypes

#define ETHERTYPE_IPV4 0x0008	//Internet Protocol version 4 (IPv4)
#define ETHERTYPE_ARP  0x0608	//Address Resolution Protocol(ARP)
#define ETHERTYPE_WAKEONLAN 0x0842 //	Wake - on - LAN[8]
#define ETHERTYPE_SRP  0x22EA	//Stream Reservation Protocol
#define ETHERTYPE_AVTP 0x22F0	//Audio Video Transport Protocol(AVTP)
#define ETHERTYPE_IETF 0x22F3	//IETF TRILL Protocol
#define ETHERTYPE_DEC_MOP 0x6002	//DEC MOP RC
#define ETHERTYPE_DECNET 0x6003	//DECnet Phase IV, DNA Routing
#define ETHERTYPE_DEC_LAT 0x6004	//DEC LAT
#define ETHERTYPE_RARP 0x8035	//Reverse Address Resolution Protocol(RARP)
#define ETHERTYPE_ETHTALK 0x809B	//AppleTalk(EtherTalk)
#define ETHERTYPE_LLC_PDU 0x80D5	//LLC PDU(in particular, IBM SNA), preceded by 2 bytes length and 1 byte padding[9]
#define ETHERTYPE_AARP 0x80F3	//AppleTalk Address Resolution Protocol(AARP)
#define ETHERTYPE_VLAN 0x8100	//VLAN - tagged frame(IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]
#define ETHERTYPE_SLPP 0x8102	//Simple Loop Prevention Protocol(SLPP)
#define ETHERTYPE_VLACP 0x8103	//Virtual Link Aggregation Control Protocol(VLACP)
#define ETHERTYPE_IPX  0x8137	//IPX
#define ETHERTYPE_QNXQ 0x8204	//QNX Qnet
#define ETHERTYPE_IPV6 0x86DD	//Internet Protocol Version 6 (IPv6)
#define ETHERTYPE_ETH_FLOW 0x8808	//Ethernet flow control
#define ETHERTYPE_LACP 0x8809	//Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol(LACP)
#define ETHERTYPE_COBRA 0x8819	//CobraNet
#define ETHERTYPE_MPLS_U 0x8847	//MPLS unicast
#define ETHERTYPE_MPLS_M 0x8848	//MPLS multicast
#define ETHERTYPE_PPPOE_DISCO 0x8863	//PPPoE Discovery Stage
#define ETHERTYPE_PPPOE_SESS 0x8864	//PPPoE Session Stage
#define ETHERTYPE_HOMEPL 0x887B	//HomePlug 1.0 MME
#define ETHERTYPE_EAPOL 0x888E	//EAP over LAN(IEEE 802.1X)
#define ETHERTYPE_PROFINET 0x8892	//PROFINET Protocol
#define ETHERTYPE_SCSI 0x889A	//HyperSCSI(SCSI over Ethernet)
#define ETHERTYPE_ATAOE 0x88A2	//ATA over Ethernet
#define ETHERTYPE_ETHERCAT 0x88A4	//EtherCAT Protocol
#define ETHERTYPE_SVLAN 0x88A8	//Service VLAN tag identifier(S - Tag) on Q - in - Q tunnel
#define ETHERTYPE_POWERLINK 0x88AB	//Ethernet Powerlink[citation needed]
#define ETHERTYPE_GOOSE 0x88B8	//GOOSE(Generic Object Oriented Substation event)
#define ETHERTYPE_GSE 0x88B9	//GSE(Generic Substation Events) Management Services
#define ETHERTYPE_SVT 0x88BA	//SV(Sampled Value Transmission)
#define ETHERTYPE_ROMON 0x88BF	//MikroTik RoMON(unofficial)
#define ETHERTYPE_LLDP 0x88CC	//Link Layer Discovery Protocol(LLDP)
#define ETHERTYPE_SERCOS3 0x88CD	//SERCOS III
#define ETHERTYPE_HOMEPL_PHY 0x88E1	//HomePlug Green PHY
#define ETHERTYPE_MRP 0x88E3	//Media Redundancy Protocol(IEC62439 - 2)
#define ETHERTYPE_MACSEC 0x88E5	//IEEE 802.1AE MAC security(MACsec)
#define ETHERTYPE_PBB 0x88E7	//Provider Backbone Bridges(PBB) (IEEE 802.1ah)
#define ETHERTYPE_PTP 0x88F7	//Precision Time Protocol(PTP) over IEEE 802.3 Ethernet
#define ETHERTYPE_NC_SI 0x88F8	//NC - SI
#define ETHERTYPE_PRP 0x88FB	//Parallel Redundancy Protocol(PRP)
#define ETHERTYPE_OAM 0x8902	//IEEE 802.1ag Connectivity Fault Management(CFM) Protocol / ITU - T Recommendation Y.1731 (OAM)
#define ETHERTYPE_FCOE 0x8906	//Fibre Channel over Ethernet(FCoE)
#define ETHERTYPE_FCOE_INIT 0x8914	//FCoE Initialization Protocol
#define ETHERTYPE_ROCE 0x8915	//RDMA over Converged Ethernet(RoCE)
#define ETHERTYPE_TTE 0x891D	//TTEthernet Protocol Control Frame(TTE)
#define ETHERTYPE_1905_IEEE 0x893a	//1905.1 IEEE Protocol
#define ETHERTYPE_HSR 0x892F	//High - availability Seamless Redundancy(HSR)
#define ETHERTYPE_ECTP 0x9000	//Ethernet Configuration Testing Protocol[12]
#define ETHERTYPE_RTP 0xF1C1	//Redundancy Tag(IEEE 802.1CB Frame Replication and Elimination for Reliability)

// IP types

#define IP_PROTO_TYPE_HOPOPT 0x00	//0	HOPOPT	IPv6 Hop - by - Hop Option	RFC 8200
#define IP_PROTO_TYPE_ICMP 0x01	//1	ICMP	Internet Control Message Protocol	RFC 792
#define IP_PROTO_TYPE_IGMP 0x02	//2	IGMP	Internet Group Management Protocol	RFC 1112
#define IP_PROTO_TYPE_GGP 0x03	//3	GGP	Gateway - to - Gateway Protocol	RFC 823
#define IP_PROTO_TYPE_IPIP 0x04	//4	IP - in - IP	IP in IP(encapsulation)	RFC 2003
#define IP_PROTO_TYPE_ISP  0x05	//5	ST	Internet Stream Protocol	RFC 1190, RFC 1819
#define IP_PROTO_TYPE_TCP 0x06	//6	TCP	Transmission Control Protocol	RFC 793
#define IP_PROTO_TYPE_CBT 0x07	//7	CBT	Core - based trees	RFC 2189
#define IP_PROTO_TYPE_EGP 0x08	//8	EGP	Exterior Gateway Protocol	RFC 888
#define IP_PROTO_TYPE_IGP 0x09	//9	IGP	Interior gateway protocol(any private interior gateway, for example Cisco's IGRP)	
#define IP_PROTO_TYPE_BBN 0x0A	//10	BBN - RCC - MON	BBN RCC Monitoring
#define IP_PROTO_TYPE_NVP 0x0B	//11	NVP - II	Network Voice Protocol	RFC 741
#define IP_PROTO_TYPE_PUP 0x0C	//12	PUP	Xerox PUP
#define IP_PROTO_TYPE_ARGUS 0x0D	//13	ARGUS	ARGUS
#define IP_PROTO_TYPE_EMCON 0x0E	//14	EMCON	EMCON
#define IP_PROTO_TYPE_XNET 0x0F	//15	XNET	Cross Net Debugger	IEN 158[2]
#define IP_PROTO_TYPE_CHAOS 0x10	//16	CHAOS	Chaos
#define IP_PROTO_TYPE_UDP 0x11	//17	UDP	User Datagram Protocol	RFC 768
#define IP_PROTO_TYPE_MUX 0x12	//18	MUX	Multiplexing	IEN 90[3]
#define IP_PROTO_TYPE_DCN 0x13	//19	DCN - MEAS	DCN Measurement Subsystems
#define IP_PROTO_TYPE_HMP 0x14	//20	HMP	Host Monitoring Protocol	RFC 869
#define IP_PROTO_TYPE_PRM 0x15	//21	PRM	Packet Radio Measurement
#define IP_PROTO_TYPE_XNS 0x16	//22	XNS - IDP	XEROX NS IDP
#define IP_PROTO_TYPE_TRUNK1 0x17	//23	TRUNK - 1	Trunk - 1
#define IP_PROTO_TYPE_TRUNK2 0x18	//24	TRUNK - 2	Trunk - 2
#define IP_PROTO_TYPE_LEAF1 0x19	//25	LEAF - 1	Leaf - 1
#define IP_PROTO_TYPE_LEAF2 0x1A	//26	LEAF - 2	Leaf - 2
#define IP_PROTO_TYPE_RDP 0x1B	//27	RDP	Reliable Data Protocol	RFC 908
#define IP_PROTO_TYPE_IRTP 0x1C	//28	IRTP	Internet Reliable Transaction Protocol	RFC 938
#define IP_PROTO_TYPE_ISO_TP4 0x1D	//29	ISO - TP4	ISO Transport Protocol Class 4	RFC 905
#define IP_PROTO_TYPE_NETBLT 0x1E	//30	NETBLT	Bulk Data Transfer Protocol	RFC 998
#define IP_PROTO_TYPE_MFE 0x1F	//31	MFE - NSP	MFE Network Services Protocol
#define IP_PROTO_TYPE_MERIT 0x20	//32	MERIT - INP	MERIT Internodal Protocol
#define IP_PROTO_TYPE_DCCPD 0x21	//33	DCCP	Datagram Congestion Control Protocol	RFC 4340
#define IP_PROTO_TYPE_3PC 0x22	//34	3PC	Third Party Connect Protocol
#define IP_PROTO_TYPE_IDPR 0x23	//35	IDPR	Inter - Domain Policy Routing Protocol	RFC 1479
#define IP_PROTO_TYPE_XTP 0x24	//36	XTP	Xpress Transport Protocol
#define IP_PROTO_TYPE_DDP 0x25	//37	DDP	Datagram Delivery Protocol
#define IP_PROTO_TYPE_IDPRC 0x26	//38	IDPR - CMTP	IDPR Control Message Transport Protocol
#define IP_PROTO_TYPE_TPPP 0x27	//39	TP++	TP++ Transport Protocol
#define IP_PROTO_TYPE_IL 0x28	//40	IL	IL Transport Protocol
#define IP_PROTO_TYPE_IPV6_ENC 0x29	//41	IPv6	IPv6 Encapsulation(6to4 and 6in4)	RFC 2473
#define IP_PROTO_TYPE_SDRP 0x2A	//42	SDRP	Source Demand Routing Protocol	RFC 1940
#define IP_PROTO_TYPE_IPV6_ROUTE 0x2B	//43	IPv6 - Route	Routing Header for IPv6	RFC 8200
#define IP_PROTO_TYPE_IPV6_FRAG 0x2C	//44	IPv6 - Frag	Fragment Header for IPv6	RFC 8200
#define IP_PROTO_TYPE_IDRP 0x2D	//45	IDRP	Inter - Domain Routing Protocol
#define IP_PROTO_TYPE_RSVP 0x2E	//46	RSVP	Resource Reservation Protocol	RFC 2205
#define IP_PROTO_TYPE_GRE 0x2F	//47	GRE	Generic Routing Encapsulation	RFC 2784, RFC 2890
#define IP_PROTO_TYPE_DSR 0x30	//48	DSR	Dynamic Source Routing Protocol	RFC 4728
#define IP_PROTO_TYPE_BNA 0x31	//49	BNA	Burroughs Network Architecture
#define IP_PROTO_TYPE_ESP 0x32	//50	ESP	Encapsulating Security Payload	RFC 4303
#define IP_PROTO_TYPE_AH 0x33	//51	AH	Authentication Header	RFC 4302
#define IP_PROTO_TYPE_INLSP 0x34	//52	I - NLSP	Integrated Net Layer Security Protocol	TUBA
#define IP_PROTO_TYPE_SWIPE 0x35	//53	SwIPe	SwIPe	RFC 5237
#define IP_PROTO_TYPE_NARP 0x36	//54	NARP	NBMA Address Resolution Protocol	RFC 1735
#define IP_PROTO_TYPE_MOBILE 0x37	//55	MOBILE	IP Mobility(Min Encap)	RFC 2004
#define IP_PROTO_TYPE_TLSP 0x38	//56	TLSP	Transport Layer Security Protocol(using Kryptonet key management)
#define IP_PROTO_TYPE_SKIP 0x39	//57	SKIP	Simple Key - Management for Internet Protocol	RFC 2356
#define IP_PROTO_TYPE_IPV6_ICMP 0x3A	//58	IPv6 - ICMP	ICMP for IPv6	RFC 4443, RFC 4884
#define IP_PROTO_TYPE_IPV6_NONEXT 0x3B	//59	IPv6 - NoNxt	No Next Header for IPv6	RFC 8200
#define IP_PROTO_TYPE_IPV6_OPTS 0x3C	//60	IPv6 - Opts	Destination Options for IPv6	RFC 8200
#define IP_PROTO_TYPE_AHIP 0x3D	//61		Any host internal protocol
#define IP_PROTO_TYPE_CFTP 0x3E	//62	CFTP	CFTP
#define IP_PROTO_TYPE_ALN 0x3F	//63		Any local network
#define IP_PROTO_TYPE_SAT_EX 0x40	//64	SAT - EXPAK	SATNET and Backroom EXPAK
#define IP_PROTO_TYPE_KRYPTOLAN 0x41	//65	KRYPTOLAN	Kryptolan
#define IP_PROTO_TYPE_RVD_MIT 0x42	//66	RVD	MIT Remote Virtual Disk Protocol
#define IP_PROTO_TYPE_IPPC 0x43	//67	IPPC	Internet Pluribus Packet Core
#define IP_PROTO_TYPE_ADFS 0x44	//68		Any distributed file system
#define IP_PROTO_TYPE_SATMON 0x45	//69	SAT - MON	SATNET Monitoring
#define IP_PROTO_TYPE_VISA 0x46	//70	VISA	VISA Protocol
#define IP_PROTO_TYPE_IPCU 0x47	//71	IPCU	Internet Packet Core Utility
#define IP_PROTO_TYPE_CPNX 0x48	//72	CPNX	Computer Protocol Network Executive
#define IP_PROTO_TYPE_CPHB 0x49	//73	CPHB	Computer Protocol Heart Beat
#define IP_PROTO_TYPE_WSN 0x4A	//74	WSN	Wang Span Network
#define IP_PROTO_TYPE_PVP 0x4B	//75	PVP	Packet Video Protocol
#define IP_PROTO_TYPE_BRSAT 0x4C	//76	BR - SAT - MON	Backroom SATNET Monitoring
#define IP_PROTO_TYPE_SUNND 0x4D	//77	SUN - ND	SUN ND PROTOCOL - Temporary
#define IP_PROTO_TYPE_WBMON 0x4E	//78	WB - MON	WIDEBAND Monitoring
#define IP_PROTO_TYPE_QNX 0x6A	//106	QNX	QNX
#define IP_PROTO_TYPE_L2TP 0x73	//115	L2TP	Layer Two Tunneling Protocol Version 3	RFC 3931
#define IP_PROTO_TYPE_RESERVED 0xFF	//255	Reserved

// TCP FLAGS Network order
#define TCP_HEADER_LEN (1 >> 4)
#define TCP_FLAG_FIN (1 << 8)
#define TCP_FLAG_SYN (1 << 9)
#define TCP_FLAG_RST (1 << 10)
#define TCP_FLAG_PSH (1 << 11)
#define TCP_FLAG_ACK (1 << 12)
#define TCP_FLAG_URG (1 << 13)
#define TCP_FLAG_ECH (1 << 14)
#define TCP_FLAG_CWR (1 << 15)
#define TCP_FLAG_ECN (1 << 0)

struct eth_header {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
//	uint8_t tag[4];
	uint16_t ethertype;
} __attribute__((packed));

#define IP_HDR_GET_VERS(x) ( x >> 4 )
#define IP_HDR_GET_IHL(x) ( x & 0x0f )

struct ip_header {
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint16_t total_len;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
} __attribute__((packed));

struct ip_opts {
	uint8_t opt_type;
	uint8_t opt_len;
	uint8_t *opt_data;
	uint16_t id;
	uint16_t frag_offset;
} __attribute__((packed));

struct tcpip_header {
	uint16_t sport;
	uint16_t dport;
	uint32_t sequence;
	uint32_t ack_num;
	uint16_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_ptr;
}__attribute__((packed));

inline void extract_eth_header(uint8_t* buff, struct eth_header* ethd) {
	memcpy((uint8_t*)ethd, buff, sizeof(struct eth_header));
}

inline void extract_ip_header(uint8_t* buff, struct ip_header* iphd) {
	memcpy((uint8_t*)iphd, buff+sizeof(struct eth_header), sizeof(struct ip_header));
}

inline struct eth_header* map_eth_header(uint8_t* buff) {
    return (struct eth_header*)buff;
}

inline struct ip_header* map_ip_header(uint8_t* buff) {
    return (struct ip_header*)(buff+sizeof(struct eth_header));
}

inline struct tcpip_header* map_tcpip_header(uint8_t* buff) {
    return (struct tcpip_header*)(buff+sizeof(struct eth_header)+sizeof(struct ip_header));
}

inline uint8_t* get_pkt_data(uint8_t* buff, const struct ip_header* iphd) {
	if (IP_HDR_GET_IHL(iphd->version_ihl) == 5) {
		return buff + sizeof(struct eth_header) + sizeof(struct ip_header);
	}
	return buff;
}

#endif // __PKT_HEADERS_H__

