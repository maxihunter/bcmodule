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

#ifndef __TRANSPORTLAYER_H__
#define __TRANSPORTLAYER_H__

#include "dhcpd.h"

enum {
    SOCK_OPEN,
    SOCK_CLOSED,
    SOCK_LISTEN,
    SOCK_SYN,
    SOCK_SYNACK,
    SOCK_ESTABLISHED,
    SOCK_FIN
};

struct socket {
    uint16_t port;
    uint8_t protocol;
    uint8_t state;
    uint32_t seq;
};

/* SOCK */
uint8_t getSockState(uint8_t id);
void prepareTransportLayer(struct inet_addr * inaddr, uint8_t *buff, uint32_t pbuff_len);
uint8_t socketRoutine(uint8_t *buff, uint32_t len);

#endif
