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
#include "enc28j60.h"
#include "dhcpd.h"
#include <inttypes.h>
#include <stdbool.h>

#define PBUFF_LEN 400
static uint8_t pbuf[PBUFF_LEN] = {};

uint8_t initDhcp(struct inet_addr *addr ) {
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
