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

static struct inet_addr *int_addr = NULL;
static struct socket socks[] = {
    {20, IP_PROTO_TYPE_TCP, SOCK_OPEN },
    {21, IP_PROTO_TYPE_TCP, SOCK_OPEN },
    {65535, 0, 0 } // EMPTY
};

uint8_t initDhcp(struct inet_addr *addr ) {
  int_addr = addr;
  int plen = 0;
  uint8_t dhcpState = 0;
  long lastDhcpRequest = HAL_GetTick();
  _Bool gotIp = false;
  uint8_t dhcpTries = 10;	// After 10 attempts fail gracefully so other action can be carried out

  dhcp_start( pbuf, addr );

  while( !gotIp ) {
    // handle ping and wait for a tcp packet
    plen = enc28j60PacketReceive(PBUFF_LEN, pbuf);
      check_for_dhcp_answer( pbuf, plen);
      dhcpState = dhcp_state();
      // we are idle here
      if( dhcpState != DHCP_STATE_OK ) {
          if (HAL_GetTick() > (lastDhcpRequest + 10000L) ){
              lastDhcpRequest = HAL_GetTick();
              if( dhcpTries <= 0 ) 
                  return 0;		// Failed to allocate address
                                // send dhcp
              dhcp_start( pbuf, addr);
              dhcpTries--;
          }
      } else {
          if( !gotIp ) {
              gotIp = true;
          }
      }
  }
  return 1;
}

uint8_t renewDhcp(struct inet_addr *addr) {
    return dhcp_check_for_renew();
}

uint8_t isHostInLocalNetwork(uint8_t *hostaddr) {
	uint8_t oct1 = int_addr->mask[0]&hostaddr[0];
	uint8_t oct2 = int_addr->mask[1]&hostaddr[1];
	uint8_t oct3 = int_addr->mask[2]&hostaddr[2];
	uint8_t oct4 = int_addr->mask[3]&hostaddr[3];
	return ( ((int_addr->mask[0]&int_addr->ipaddr[0]) == oct1) && 
			((int_addr->mask[1]&int_addr->ipaddr[1]) == oct2) && 
			((int_addr->mask[2]&int_addr->ipaddr[2]) == oct3) && 
			((int_addr->mask[3]&int_addr->ipaddr[3]) == oct4) );
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
	make_eth(buff);
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

uint8_t checkForSocket(uint8_t *buff, uint32_t len) {
    if (len < 60)
        return 0;
    return 0;
}

