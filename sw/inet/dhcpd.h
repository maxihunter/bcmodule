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

#ifndef __DHCP_H__
#define __DHCP_H__

#include <stdint.h>
#include "iplayer.h"

#define DHCP_HOSTNAME "stm32bcmod"
#define DHCP_HOSTNAME_LEN 10

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTRESPONSE 2
#define DHCPDISCOVER 0x01
#define DHCPOFFER 0x02
#define DHCPREQUEST 0x03
#define DHCPACK 0x05
//#define DHCPNACK

/* DHCP */
uint8_t initDhcp(struct inet_addr *addr, uint8_t * buff, uint32_t buf_len);
uint8_t releaseDhcp(struct inet_addr *addr);

extern void dhcp_start(uint8_t* buf, uint32_t len, struct inet_addr * inaddr);

extern uint8_t dhcp_state(void);

uint8_t checkForDhcpReply(uint8_t* buf, uint16_t plen);

uint8_t have_dhcpoffer(uint8_t* buf, uint16_t plen);
uint8_t have_dhcpack(uint8_t* buf, uint16_t plen);
uint8_t dhcpRenew();

#endif // __DHCP_H__

