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
#include "transportlayer.h"
#include "iplayer.h"
#include "pkt_headers.h"
#include "enc28j60.h"
#include "dhcpd.h"
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

static struct inet_addr *int_addr = NULL;
static struct socket socks[] = {
    {20, IP_PROTO_TYPE_TCP, SOCK_OPEN },
    {21, IP_PROTO_TYPE_TCP, SOCK_OPEN },
    {65535, 0, 0 } // EMPTY
};



uint8_t socketRoutine(uint8_t *buff, uint32_t len) {
    if (len < 60)
        return 0;
    return 0;
}

