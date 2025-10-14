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

#ifndef __IPLAYER_H__
#define __IPLAYER_H__

//#include "dhcpd.h"
#include <stdint.h>

#define PRINTABLE_IPADDR(x) (uint8_t)(x), (uint8_t)(x >> 8), (uint8_t)(x >> 16), (uint8_t)(x >> 24)

struct inet_addr {
    uint8_t macaddr[6];
    uint32_t ipaddr;
    uint32_t mask;
    uint32_t gateway;
	uint8_t gw_macaddr[6];
    uint32_t dhcpsrv;
    uint32_t dnssrv;
    uint32_t dncp_lease_time;
    long dncp_last_lease;
};

/* Making headers */
void fillEthHeader(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint8_t *dstmac, uint16_t ethtype);
void fillEthHeaderReply(uint8_t *buff, uint32_t len, struct inet_addr * inaddr);
void fillEthHeaderBroadcast(uint8_t *buff, uint32_t len, struct inet_addr * inaddr, uint16_t ethtype);

/* IP */
void prepareIpLayer(struct inet_addr * inaddr, uint8_t *buff, uint32_t pbuff_len);
inline uint8_t isHostInLocalNetwork(uint32_t hostaddr, struct inet_addr * inaddr) {
	uint32_t oct1 = inaddr->mask&hostaddr;
	return ((inaddr->mask&inaddr->ipaddr) == oct1);
}

uint16_t ipCalcChecksum(uint8_t *buff);

/* ARP */
uint8_t arpCheckAndReply(uint8_t *buff, uint32_t len);
uint8_t icmpCheckAndReply(uint8_t *buff, uint32_t len);
uint8_t getHostMacByArp(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac);
uint8_t getHostMacByArpS(uint32_t hostaddr, uint8_t *hostmac);
uint8_t icmpPingHost(uint32_t hostaddr, uint8_t *hostmac);
uint32_t _inet_pton(uint8_t *buff);

/* SOCK */

#endif
