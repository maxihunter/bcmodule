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

#include "net.h"
#include "iplayer.h"
#include "pkt_headers.h"
#include "enc28j60.h"
#include "dhcpd.h"
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

//#define PBUFF_LEN 400
static uint8_t *pbuf;
static uint32_t pbuf_len = 0;
static struct inet_addr *int_addr;

void fillEthHeader(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint8_t *dstmac, uint16_t ethtype) {
	struct eth_header* eth = map_eth_header(buff);
	memcpy((uint8_t*)&(eth->src_mac), inaddr->macaddr, 6);
	memcpy((uint8_t*)&(eth->dst_mac), dstmac, 6);
	eth->ethertype = ethtype;
}

void fillEthHeaderReply(uint8_t *buff, uint32_t len, struct inet_addr * inaddr) {
	struct eth_header* eth = map_eth_header(buff);
	fillEthHeader(buff, len, inaddr, eth->src_mac, eth->ethertype);
}

void fillEthHeaderBroadcast(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint16_t ethtype) {
	struct eth_header* eth = map_eth_header(buff);
	memcpy(eth->src_mac, inaddr->macaddr, 6);
	memset(eth->dst_mac, 0xff, 6);
	eth->ethertype = ethtype;
}

uint8_t isHostInLocalNetwork(uint32_t hostaddr, struct inet_addr * inaddr) {
	uint32_t oct1 = inaddr->mask&hostaddr;
	return ((inaddr->mask&inaddr->ipaddr) == oct1);
}

void prepareIpLayer(struct inet_addr * inaddr, uint8_t *buff, uint32_t pbuff_len) {
    pbuf = buff;
    pbuf_len = pbuff_len;
    int_addr = inaddr;
}

uint8_t arpCheckAndReply(uint8_t *buff, uint32_t len) {
	if (len<41){
		return(0);
	}
	if(buff[ETH_TYPE_H_P] != ETHTYPE_ARP_H_V || 
		buff[ETH_TYPE_L_P] != ETHTYPE_ARP_L_V){
			return(0);
	}
  
	if (memcmp(&buff[ETH_ARP_DST_IP_P], (uint8_t*)&(int_addr->ipaddr), 4)) {
		return 0;
	}
	if (buff[ETH_ARP_OPCODE_L_P] != ETH_ARP_OPCODE_REQ_L_V) {
		return 0;
	}

	fillEthHeaderReply(buff, len, int_addr);
	struct eth_header* eth = map_eth_header(buff);
	memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);
	memcpy((uint8_t*)&(eth->dst_mac), &buff[ETH_ARP_SRC_MAC_P], 6);
    //printf("fill header mac dst= %x:%x:%x:%x\r\n", eth->dst_mac[0],eth->dst_mac[1],eth->dst_mac[2],eth->dst_mac[3]);
	eth->ethertype = ETHERTYPE_ARP;
	
	buff[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REPLY_H_V;
	buff[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REPLY_L_V;
	
    buff[ETH_ARP_PROTTYPE]= 0x08;
	buff[ETH_ARP_PROTTYPE+1]= 0x00;
	// fill the mac addresses:
	memcpy(&buff[ETH_ARP_DST_MAC_P], &buff[ETH_ARP_SRC_MAC_P], 6);
	memcpy(&buff[ETH_ARP_SRC_MAC_P], int_addr->macaddr, 6);
	// fill the ip addresses
	memcpy(&buff[ETH_ARP_DST_IP_P], &buff[ETH_ARP_SRC_IP_P], 4);
	memcpy(&buff[ETH_ARP_SRC_IP_P], (uint8_t*)&(int_addr->ipaddr), 4);
	// eth+arp is 42 bytes:
	enc28j60PacketSend(42,buff);
	return 1;
}

void sendArpRequest(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	fillEthHeaderBroadcast(buff, len, int_addr, ETHERTYPE_ARP);
	
	buff[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REQ_H_V;
	buff[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REQ_L_V;
	// fill the mac addresses:
	memset(&buff[ETH_ARP_DST_MAC_P], 0xff, 6);
	memcpy(&buff[ETH_ARP_SRC_MAC_P], int_addr->macaddr, 6);
	// fill the ip addresses
	memcpy(&buff[ETH_ARP_DST_IP_P], (uint8_t*)&(hostaddr), 4);
	memcpy(&buff[ETH_ARP_SRC_IP_P], (uint8_t*)&(int_addr->ipaddr), 4);
	// eth+arp is 42 bytes:
	enc28j60PacketSend(42,buff);
}

static uint8_t waitHostArpReply(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	uint8_t gotMac = 0;
	long lastArpRequest = HAL_GetTick();
	uint8_t retries = 4;
    int plen = 0;
	while( !gotMac ) {
    // handle ping and wait for a tcp packet
		if (HAL_GetTick() > (lastArpRequest + 2000L)) {
			if (retries > 0) {
				sendArpRequest(buff, len, hostaddr, hostmac);
				retries--;
			} else {
				break;
			}
		}
		plen = enc28j60PacketReceive(pbuf_len, pbuf);
		if (buff[ETH_ARP_OPCODE_H_P] !=ETH_ARP_OPCODE_REPLY_H_V &&
			buff[ETH_ARP_OPCODE_L_P]!=ETH_ARP_OPCODE_REPLY_L_V) {
				continue;
		}
		if (memcmp(&buff[ETH_ARP_DST_MAC_P], int_addr->macaddr, 6) != 0 &&
			memcmp(&buff[ETH_ARP_DST_IP_P], int_addr->ipaddr, 4) != 0) {
				continue;
		}
		memcpy(hostmac, &buff[ETH_ARP_SRC_MAC_P], 6);
		gotMac = 1;
    }
	return gotMac;
}

uint8_t getHostMacByArp(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	sendArpRequest(buff, len, hostaddr, hostmac);
	return waitHostArpReply(buff, len, hostaddr, hostmac);
}

uint8_t icmpCheckAndReply(uint8_t *buff, uint32_t len) {
	if (len<41 || len > 300){
		return 0;
	}
	struct eth_header* eth = map_eth_header(buff);
    if (eth->ethertype != ETHERTYPE_IPV4) {
        return 0;
    }
    struct ip_header* iphdr = map_ip_header(buff);
    if (iphdr->protocol != IP_PROTO_TYPE_ICMP) {
        return 0;
    }

	if(buff[ICMP_TYPE_P] != ICMP_TYPE_ECHOREQUEST_V) {
	    return 0;
	}
	memcpy((uint8_t*)&(eth->dst_mac), &buff[ETH_SRC_MAC], 6);
	memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

	memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
	memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);

	buff[ICMP_TYPE_P] = ICMP_TYPE_ECHOREPLY_V;

    // we changed only the icmp.type field from request(=8) to reply(=0).
    // we can therefore easily correct the checksum:
    if (buff[ICMP_CHECKSUM_P] > (0xff-0x08)){
        buff[ICMP_CHECKSUM_P+1]++;
    }
    buff[ICMP_CHECKSUM_P]+=0x08;
	enc28j60PacketSend(len,buff);
	return 1;
}

