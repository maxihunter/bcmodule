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

#define PBUFF_LEN 400
static uint8_t pbuf[PBUFF_LEN] = {};

void fillEthHeader(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint8_t *dstmac, uint16_t ethtype) {
	struct eth_header* = map_eth_header(buff);
	memcpy(eth_header->src_mac, inaddr->macaddr, 6);
	memcpy(eth_header->dst_mac, dstmac, 6);
	eth_header->ethertype = ethtype;
}

void fillEthHeaderReply(uint8_t *buff, uint32_t len, struct inet_addr * inaddr) {
	struct eth_header* = map_eth_header(buff);
	fillEthHeader(buff, len, inaddr, eth_header->src_mac, eth_header->ethertype);
}

void fillEthHeaderBroadcast(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint16_t ethtype) {
	struct eth_header* = map_eth_header(buff);
	memcpy(eth_header->src_mac, inaddr->macaddr, 6);
	memset(eth_header->dst_mac, 0xff, 6);
	eth_header->ethertype = ethtype;
}

uint8_t isHostInLocalNetwork(uint32_t hostaddr, struct inet_addr * inaddr) {
	uint32_t oct1 = int_addr->mask&hostaddr;
	return ((int_addr->mask&int_addr->ipaddr) == oct1);
}

uint8_t arpCheckAndReply(uint8_t *buff, uint32_t len) {
	if (len<41){
		return(0);
	}
	if(buff[ETH_TYPE_H_P] != ETHTYPE_ARP_H_V || 
		buff[ETH_TYPE_L_P] != ETHTYPE_ARP_L_V){
			return(0);
	}
  
	if (memcmp(&buff[ETH_ARP_DST_IP_P], int_addr->ipaddr, 4)) {
		return 0;
	}
	if (buff[ETH_ARP_OPCODE_L_P] != ETH_ARP_OPCODE_REQ_L_V) {
		return 0;
	}
	fillEthHeaderReply(buff, len, int_addr);
	struct eth_header* = map_eth_header(buff);
	eth_header->ethertype = ETHERTYPE_ARP;
	
	buff[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REPLY_H_V;
	buff[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REPLY_L_V;
	// fill the mac addresses:
	memcpy(&buff[ETH_ARP_DST_MAC_P], &buff[ETH_ARP_SRC_MAC_P], 6);
	memcpy(&buff[ETH_ARP_SRC_MAC_P], int_addr->macaddr, 6);
	// fill the ip addresses
	memcpy(&buff[ETH_ARP_DST_IP_P], &buff[ETH_ARP_SRC_IP_P], 4);
	memcpy(&buff[ETH_ARP_SRC_IP_P], int_addr->ipaddr, 4);
	// eth+arp is 42 bytes:
	enc28j60PacketSend(42,buff);
	return 1;
}

static uint8_t waitHostArpReply(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	uint8_t gotMac = 0;
	long lastArpRequest = HAL_GetTick();
	uint8_t retries = 4;
	while( !gotMac ) {
    // handle ping and wait for a tcp packet
		if (HAL_GetTick() > (lastDhcpRequest + 10000L)) {
			if (retries > 0) {
				sendArpRequest(buff, len, hostaddr, hostmac);
				retries--;
			} else {
				break;
			}
		}
		plen = enc28j60PacketReceive(PBUFF_LEN, pbuf);
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

uint8_t sendArpRequest(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	fillEthHeaderBroadcast(buff, len, int_addr, ETHERTYPE_ARP);
	
	buff[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REQ_H_V;
	buff[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REQ_L_V;
	// fill the mac addresses:
	memset(&buff[ETH_ARP_DST_MAC_P], 0xff, 6);
	memcpy(&buff[ETH_ARP_SRC_MAC_P], int_addr->macaddr, 6);
	// fill the ip addresses
	memcpy(&buff[ETH_ARP_DST_IP_P], hostaddr, 4);
	memcpy(&buff[ETH_ARP_SRC_IP_P], int_addr->ipaddr, 4);
	// eth+arp is 42 bytes:
	enc28j60PacketSend(42,buff);
}

uint8_t getHostMacByArp(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac) {
	sendArpRequest(buff, len, hostaddr, hostmac);
	return waitHostArpReply(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac);
}

uint8_t icmpCheckAndReply(uint8_t *buff, uint32_t len) {
	if (len<41){
		return 0;
	}
	if(buff[ETH_TYPE_H_P] != ETHTYPE_ARP_H_V || 
		buff[ETH_TYPE_L_P] != ETHTYPE_ARP_L_V){
			return 0;
	}
  
	if (memcmp(&buff[ETH_ARP_DST_IP_P], int_addr->ipaddr, 4)) {
		return 0;
	}
	if (buff[ETH_ARP_OPCODE_L_P] != ETH_ARP_OPCODE_REQ_L_V) {
		return 0;
	}
	make_eth(buff);
	buff[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REPLY_H_V;
	buff[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REPLY_L_V;
	
	memcpy(&buff[ETH_ARP_DST_MAC_P], &buff[ETH_ARP_SRC_MAC_P], 6);
	memcpy(&buff[ETH_ARP_SRC_MAC_P], int_addr->macaddr, 6);
	
	memcpy(&buff[ETH_ARP_DST_IP_P], &buff[ETH_ARP_SRC_IP_P], 4);
	memcpy(&buff[ETH_ARP_SRC_IP_P], int_addr->ipaddr, 4);
	
	enc28j60PacketSend(42,buff);
	return 1;
}
/*
void make_echo_reply_from_request(uint8_t *buf,uint16_t len) {
	if (len<42){
		return 0;
	}
	if( buf[IP_PROTO_P] != IP_PROTO_ICMP_V) {
		return 0;
	}
	if ( buf[ICMP_TYPE_P] != ICMP_TYPE_ECHOREQUEST_V) {
		return 0;
	}
	if (memcmp(&buf[IP_DST_P], int_addr->ipaddr, 4)) {
		return 0;
	}
}*/

