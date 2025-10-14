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

#include <stdlib.h>
#include <string.h>

#include "dhcpd.h"
#include "enc28j60.h"
//#include "ip_arp_udp_tcp.h"
#include "pkt_headers.h"
#include "transportlayer.h"
#include "net.h"

static void dhcp_send_packet(uint8_t* buf, uint32_t len, uint8_t requestType);

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2
#define DHCPDISCOVER 0x01
#define DHCPOFFER 0x02
#define DHCPREQUEST 0x03
#define DHCPACK 0x05
 //#define DHCPNACK

 // size 236
typedef struct dhcpData {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
	//uint8_t ciaddr[4];
    uint32_t ciaddr;
    // 16-19 yiaddr
    uint32_t yiaddr;
	//uint8_t yiaddr[4];
    // 20-23 siaddr
    uint32_t siaddr;
	//uint8_t siaddr[4];
    // 24-27 giaddr
    uint32_t giaddr;
	//uint8_t giaddr[4];
    // 28-43 chaddr(16)
	uint8_t chaddr[16];
    // 44-107 sname (64)
    uint8_t sname[64];
    // 108-235 file(128)
    uint8_t file[128];
    // options
    // dont include as its variable size,
    // just tag onto end of structure
} __attribute__((packed)) dhcpData;

static uint8_t dhcptid_l = 0;  // a counter for transaction ID
// src port high byte must be a a0 or higher:
#define DHCPCLIENT_SRC_PORT_H 0xe0
#define DHCP_SRC_PORT 67
#define DHCP_DEST_PORT 68

static uint8_t dhcpState = DHCP_STATE_INIT;

static struct inet_addr * int_addr = NULL;

static char hostname[DHCP_HOSTNAME_LEN+4];
static uint8_t dhcp_ansError = 0;
static uint32_t currentXid = 0;
static uint16_t currentSecs = 0;
static long leaseStart = 0;
static uint32_t leaseTime = 0;
static uint8_t* bufPtr = NULL;
static uint8_t* pbuff = NULL;
static uint32_t bufLen = 0;

static inline void addToBuf(uint8_t b) { *bufPtr++ = b; };
static void send_udp_prepare(uint8_t *buf,uint16_t sport, uint8_t *dip, uint16_t dport);
static void send_udp_transmit(uint8_t *buf,uint16_t datalen);

uint8_t initDhcp(struct inet_addr *addr, uint8_t * buff, uint32_t buf_len) {
  bufLen = buf_len;
  int_addr = addr;
  bufPtr = buff;
  uint32_t plen = 0;
  uint8_t dhcpState = 0;
  long lastDhcpRequest = HAL_GetTick();
  uint8_t gotIp = 0;
  uint8_t dhcpTries = 10;	// After 10 attempts fail gracefully so other action can be carried out

  dhcp_start( buff, bufLen, addr );

  while( !gotIp ) {
    // handle ping and wait for a tcp packet
    plen = enc28j60PacketReceive(bufLen, buff);
      //check_for_dhcp_answer( bufPtr, plen);
      checkForDhcpReply(buff, plen);
      dhcpState = dhcp_state();
      // we are idle here
      if( dhcpState != DHCP_STATE_OK ) {
          if (HAL_GetTick() > (lastDhcpRequest + 5000L) ){
              lastDhcpRequest = HAL_GetTick();
              if( dhcpTries <= 0 ) 
                  return 0;		// Failed to allocate address
                                // send dhcp
              dhcp_start( buff, bufLen, addr);
              dhcpTries--;
          }
      } else {
          if( !gotIp ) {
              gotIp = 1;
          }
      }
  }
  return 1;
}

uint8_t dhcp_state(void) {
    // Check lease and request renew if currently OK and time
    // leaseStart - start time in millis
    // leaseTime - length of lease in millis
    //
    if (dhcpState == DHCP_STATE_OK && (leaseStart + leaseTime) <= HAL_GetTick()) {
        // Calling app needs to detect this and init renewal
        dhcpState = DHCP_STATE_RENEW;
    }
    return (dhcpState);
}

// Start request sequence, send DHCPDISCOVER
// Wait for DHCPOFFER
// Send DHCPREQUEST
// Wait for DHCPACK
// All configured
extern void dhcp_start(uint8_t* buf, uint32_t len, struct inet_addr * inaddr) {
    int_addr = inaddr;
    pbuff = buf;
    /*srand(analogRead(0));*/ srand(0x13);
    currentXid = 0x00654321 + rand();
    currentSecs = 0;
    //memset (int_addr, 0, sizeof (struct inet_addr));

    // Set a unique hostname, use DHCP_HOSTNAME- plus last octet of mac address
    // hostname[8] = 'A' + (macaddr[5] >> 4);
    // hostname[9] = 'A' + (macaddr[5] & 0x0F);
    for (int i = 0; i < DHCP_HOSTNAME_LEN; i++) {
        hostname[i] = DHCP_HOSTNAME[i];
    }

    hostname[DHCP_HOSTNAME_LEN] = '-';
    hostname[DHCP_HOSTNAME_LEN + 1] = 'A' + (int_addr->macaddr[5] >> 4);
    hostname[DHCP_HOSTNAME_LEN + 2] = 'A' + (int_addr->macaddr[5] & 0x0F);
    hostname[DHCP_HOSTNAME_LEN + 3] = '\0';

    // Reception of broadcast packets turned off by default, but
    // it has been shown that some routers send responses as
    // broadcasts. Enable here and disable later
    enc28j60EnableBroadcast();
    dhcp_send_packet(buf, len, DHCPDISCOVER);
    dhcpState = DHCP_STATE_DISCOVER;
}

void dhcp_request_ip(uint8_t* buf, uint32_t len) {
    dhcp_send_packet(buf, len, DHCPREQUEST);
    dhcpState = DHCP_STATE_REQUEST;
}

// Main DHCP message sending function, either DHCPDISCOVER or DHCPREQUEST
void dhcp_send_packet(uint8_t* buf, uint32_t len, uint8_t requestType) {
    if (int_addr == NULL)
        return;
    //bufPtr = buf;
    int i = 0;
    dhcp_ansError = 0;
    dhcptid_l++;  // increment for next request, finally wrap
    // destination IP gets replaced after this call

    memset(buf, 0, len);
    send_udp_prepare(buf, (DHCPCLIENT_SRC_PORT_H << 8) | (dhcptid_l & 0xff), (uint8_t*)&(int_addr->ipaddr), DHCP_DEST_PORT);

    memcpy(buf + ETH_SRC_MAC, int_addr->macaddr, 6);
    memset(buf + ETH_DST_MAC, 0xFF, 6);
    buf[IP_TOTLEN_L_P] = 0x82;
    buf[IP_PROTO_P] = IP_PROTO_UDP_V;
    if (requestType == DHCPREQUEST) {
        memcpy(buf + IP_SRC_P, (uint8_t*)&(int_addr->ipaddr), 4);
        memcpy(buf + IP_DST_P, (uint8_t*)&(int_addr->dhcpsrv), 4);
    } else {
        memset(buf + IP_SRC_P, 0x0, 4);
        memset(buf + IP_DST_P, 0xFF, 4);
    }
    buf[UDP_DST_PORT_L_P] = DHCP_SRC_PORT;
    buf[UDP_SRC_PORT_H_P] = 0;
    buf[UDP_SRC_PORT_L_P] = DHCP_DEST_PORT;

    // Build DHCP Packet from buf[UDP_DATA_P]
    // Make dhcpPtr start of UDP data buffer
    struct dhcpData* dhcpPtr = (struct dhcpData*)&buf[UDP_DATA_P];
    // 0-3 op, htype, hlen, hops
    dhcpPtr->op = DHCP_BOOTREQUEST;
    dhcpPtr->htype = 1;
    dhcpPtr->hlen = 6;
    dhcpPtr->hops = 0;
    // 4-7 xid
    memcpy(&dhcpPtr->xid, &currentXid, sizeof(currentXid));
    // 8-9 secs
    memcpy(&dhcpPtr->secs, &currentSecs, sizeof(currentSecs));
    // 16-19 yiaddr
    memset((uint8_t*)&(dhcpPtr->yiaddr), 0, 4);
    // 28-43 chaddr(16)
    memcpy((uint8_t*)&(dhcpPtr->chaddr), int_addr->macaddr, 6);

    // options defined as option, length, value
    bufPtr = buf + UDP_DATA_P + sizeof(struct dhcpData);
    // Magic cookie 99, 130, 83 and 99
    addToBuf(99);
    addToBuf(130);
    addToBuf(83);
    addToBuf(99);

    // Set correct options
    // Option 1 - DHCP message type
    addToBuf(53);           // DHCPDISCOVER, DHCPREQUEST
    addToBuf(1);            // Length
    addToBuf(requestType);  // Value

    // Client Identifier Option, this is the client mac address
    addToBuf(61);    // Client identifier
    addToBuf(7);     // Length
    addToBuf(0x01);  // Value
    for (i = 0; i < 6; i++) addToBuf(int_addr->macaddr[i]);

    // Host name Option
    addToBuf(12);             // Host name
    addToBuf(DHCP_HOSTNAME_LEN+4);  // Length
    for (i = 0; i < DHCP_HOSTNAME_LEN+4; i++) addToBuf(hostname[i]);

    if (requestType == DHCPREQUEST) {
        // Request IP address
        addToBuf(50);  // Requested IP address
        addToBuf(4);   // Length
        memcpy(bufPtr, (uint8_t*)&(int_addr->ipaddr), 4);
        bufPtr += 4;
        //for (i = 0; i < 4; i++) addToBuf(int_addr->ipaddr[i]);

        // Request using server ip address
        addToBuf(54);  // Server IP address
        addToBuf(4);   // Length
        //for (i = 0; i < 4; i++) addToBuf(int_addr->dhcpsrv[i]);
        memcpy(bufPtr, (uint8_t*)&(int_addr->dhcpsrv), 4);
        bufPtr += 4;
    }

    // Additional information in parameter list - minimal list for what we need
    addToBuf(55);  // Parameter request list
    addToBuf(3);   // Length
    addToBuf(1);   // Subnet mask
    addToBuf(3);   // Route/Gateway
    addToBuf(6);   // DNS Server

    // payload len should be around 300
    addToBuf(255);  // end option
    send_udp_transmit(buf, bufPtr - buf - UDP_DATA_P);
}

uint8_t checkForDhcpReply(uint8_t* buf, uint16_t plen) {
    // Map struct onto payload
    struct dhcpData* dhcpPtr = (struct dhcpData*)&buf[UDP_DATA_P];
    if (plen >= 70 && buf[UDP_SRC_PORT_L_P] == DHCP_SRC_PORT && dhcpPtr->op == DHCP_BOOTREPLY &&
        !memcmp(&dhcpPtr->xid, &currentXid, 4)) {
        // Check for lease expiry
        // uint32_t currentSecs = millis();
        int optionIndex = UDP_DATA_P + sizeof(struct dhcpData) + 4;
        if (buf[optionIndex] == 53) switch (buf[optionIndex + 2]) {
        case DHCPOFFER:
            return have_dhcpoffer(buf, plen);
        case DHCPACK:
            return have_dhcpack(buf, plen);
        }
    }
    return 0;
}

uint8_t have_dhcpoffer(uint8_t* buf, uint16_t plen) {
    // Map struct onto payload
    struct dhcpData* dhcpPtr = (struct dhcpData*)((uint8_t*)buf + UDP_DATA_P);
    // Offered IP address is in yiaddr
    memcpy((uint8_t*)&(int_addr->ipaddr), (uint8_t*)&(dhcpPtr->yiaddr), 4);
    // Scan through variable length option list identifying options we want
    uint8_t* ptr = (uint8_t*)(dhcpPtr + 1) + 4;
    do {
        uint8_t option = *ptr++;
        uint8_t optionLen = *ptr++;
        uint8_t i;
        switch (option) {
        case 1:
            memcpy((uint8_t*)&(int_addr->mask), ptr, 4);
            break;
        case 3:
            memcpy((uint8_t*)&(int_addr->gateway), ptr, 4);
            break;
        case 6:
            memcpy((uint8_t*)&(int_addr->dnssrv), ptr, 4);
            break;
        case 51:
            leaseTime = 0;
            for (i = 0; i < 4; i++) {
                leaseTime |= (ptr[i] << (8 * (3 - i)));
            }
            leaseTime *= 1000;  // milliseconds
            int_addr->dncp_lease_time = leaseTime;
            break;
        case 54:
            memcpy((uint8_t*)&(int_addr->dhcpsrv), ptr, 4);
            break;
        }
        ptr += optionLen;
    } while (ptr < buf + plen);
    dhcp_request_ip(buf, plen);
    return 1;
}

uint8_t have_dhcpack(uint8_t* buf, uint16_t plen) {
    dhcpState = DHCP_STATE_OK;
    int_addr->dncp_last_lease = HAL_GetTick();
    //printf("scheduled renew ll %ld next %ld\r\n", int_addr->dncp_last_lease, int_addr->dncp_last_lease + (int_addr->dncp_lease_time/2));
    // Turn off broadcast. Application if it needs it can re-enable it
    enc28j60DisableBroadcast();
    return 2;
}

uint8_t dhcpRenew() {
    if (int_addr == NULL || dhcpState != DHCP_STATE_OK )
        return -1;
    if (int_addr->dncp_last_lease + (int_addr->dncp_lease_time/2) < HAL_GetTick()) {
        //printf("send req for renew\r\n");
        dhcp_send_packet(pbuff, bufLen, DHCPREQUEST);
        //dhcpState = DHCP_STATE_REQUEST;
        int_addr->dncp_last_lease = HAL_GetTick();
    }
    return 2;
}


void send_udp_prepare(uint8_t *buf,uint16_t sport, uint8_t *dip, uint16_t dport)
{
  const char iphdr[] ={0x45,0,0,0x82,0,0,0x40,0,0x20}; // 0x82 is the total len on ip, 0x20 is ttl (time to live)
  //memcpy(&buf[ETH_DST_MAC], int_addr->gwmacaddr, 6);
  //memcpy(&buf[ETH_SRC_MAC], int_addr->macaddr, 6);
  buf[ETH_TYPE_H_P] = ETHTYPE_IP_H_V;
  buf[ETH_TYPE_L_P] = ETHTYPE_IP_L_V;
  //fill_buf_p(9,iphdr);
  memcpy(&buf[IP_P], iphdr, 9);

  // total length field in the IP header must be set:
  buf[IP_TOTLEN_H_P]=0;
  // done in transmit: buf[IP_TOTLEN_L_P]=IP_HEADER_LEN+UDP_HEADER_LEN+datalen;
  //buf[IP_PROTO_P]=IP_PROTO_UDP_V;
  //memcpy(&buf[IP_DST_P], dip, 4);
  //memcpy(&buf[IP_SRC_P], ipaddr, 4);

  // done in transmit: fill_ip_hdr_checksum(buf);
  buf[UDP_DST_PORT_H_P]=(dport>>8);
  buf[UDP_DST_PORT_L_P]=0xff&dport; 
  buf[UDP_SRC_PORT_H_P]=(sport>>8);
  buf[UDP_SRC_PORT_L_P]=sport&0xff; 
  buf[UDP_LEN_H_P]=0;
  // done in transmit: buf[UDP_LEN_L_P]=UDP_HEADER_LEN+datalen;
  // zero the checksum
  buf[UDP_CHECKSUM_H_P]=0;
  buf[UDP_CHECKSUM_L_P]=0;
  // copy the data:
  // now starting with the first byte at buf[UDP_DATA_P]
}

void send_udp_transmit(uint8_t *buf,uint16_t datalen)
{
  uint16_t ck;
  buf[IP_TOTLEN_H_P]=(IP_HEADER_LEN+UDP_HEADER_LEN+datalen) >> 8;
  buf[IP_TOTLEN_L_P]=(IP_HEADER_LEN+UDP_HEADER_LEN+datalen) & 0xff;
  //fill_ip_hdr_checksum(buf);
  ck = ipCalcChecksum(buf);
  *((uint16_t *)&buf[IP_CHECKSUM_P])=ck;
  //buf[UDP_LEN_L_P]=UDP_HEADER_LEN+datalen;
  buf[UDP_LEN_H_P]=(UDP_HEADER_LEN+datalen) >>8;
  buf[UDP_LEN_L_P]=(UDP_HEADER_LEN+datalen) & 0xff;

  //
  buf[UDP_CHECKSUM_H_P]=0;
  buf[UDP_CHECKSUM_L_P]=0;
  //ck=checksum(&buf[IP_SRC_P], 16 + datalen,1);
  ck = transportCalcChecksum(buf, ETH_HDR_BASE_LEN + IP_HDR_BASE_LEN + 8 + datalen); // ACK packet have no data
  *((uint16_t *)&buf[UDP_CHECKSUM_H_P])=ck;
  //buf[UDP_CHECKSUM_H_P]=ck>>8;
  //buf[UDP_CHECKSUM_L_P]=ck& 0xff;
  enc28j60PacketSend(UDP_HEADER_LEN+IP_HEADER_LEN+ETH_HEADER_LEN+datalen,buf);
}


