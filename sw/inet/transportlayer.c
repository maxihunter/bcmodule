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
static uint8_t *pbuf;
static uint32_t pbuf_len = 0;
static struct socket socks[] = {
    {0, 0, 0, 0 }, // Service socket. Do not use
    { 0x1400/*20 network order*/, IP_PROTO_TYPE_TCP, SOCK_LISTEN, 0 },
    { 0x1500/*21 network order*/, IP_PROTO_TYPE_TCP, SOCK_LISTEN, 0 },
    {65535, 0, 0 } // EMPTY
};

void prepareTransportLayer(struct inet_addr * inaddr, uint8_t *buff, uint32_t pbuff_len) {
    pbuf = buff;
    pbuf_len = pbuff_len;
    int_addr = inaddr;
}

uint8_t getSockState(uint8_t id) {
    return socks[id].state;
}

uint8_t socketRoutine(uint8_t *buff, uint32_t len) {
    if (len < 60)
        return 0;

    struct eth_header* eth = map_eth_header(buff);
    if (eth->ethertype != ETHERTYPE_IPV4) {
        return 0;
    }
    // TODO for UDP
    struct ip_header* iphdr = map_ip_header(buff);
    if (iphdr->protocol != IP_PROTO_TYPE_TCP) {
        return 0;
    }

    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    int i = 1;
    while (socks[i].port != 65535) {
        //printf("RUN SOCK %c, dp=%x\r\n", '0' + i, tcphdr->dport);
        if (socks[i].port != tcphdr->dport) {
            i++;
            continue;
        }
        printf("RUN SOCK %c, f=%x\r\n", '0' + i, tcphdr->flags);
        if ( (socks[i].state == SOCK_LISTEN || socks[i].state == SOCK_SYN) && tcphdr->flags & TCP_FLAG_SYN) {
            printf("RUN SOCK %d SYN s=%x\r\n", '0' + i, tcphdr->sequence);
            socks[i].state = SOCK_SYN;
            memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
            memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

            memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
            memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);

            tcphdr->dport = tcphdr->sport;
            tcphdr->sport = socks[i].port;
            tcphdr->flags |= TCP_FLAG_ACK;
            tcphdr->window = 2920; // make window size double of standard MTU 2 x 1460
            tcphdr->ack_num = tcphdr->sequence + 0x01000000; // +1 in network order
                                               //0xd2fb4eed
                                               //
            socks[i].seq = HAL_GetTick();
            tcphdr->sequence = socks[i].seq;
            enc28j60PacketSend(len,buff);
            return i;
        }
        if ( socks[i].state == SOCK_SYN && (tcphdr->flags & TCP_FLAG_ACK) && !(tcphdr->flags & TCP_FLAG_PSH)) {
            socks[i].state = SOCK_ESTABLISHED;
            return i;
        }
        if ( socks[i].state == SOCK_ESTABLISHED && tcphdr->flags & TCP_FLAG_FIN) {
            socks[i].state = SOCK_FIN;
            memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
            memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

            memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
            memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);
            tcphdr->dport = tcphdr->sport;
            tcphdr->sport = socks[i].port;
            tcphdr->flags |= TCP_FLAG_ACK;

            tcphdr->window = 2920; // make window size double of standard MTU 2 x 1460
            tcphdr->sequence = socks[i].seq;
            enc28j60PacketSend(len,buff);
            return i;
        }
        if ( socks[i].state == SOCK_FIN && tcphdr->flags & TCP_FLAG_ACK) {
            socks[i].state = SOCK_OPEN;
            socks[i].seq = 0;
            return i;
        }
        if ( socks[i].state == SOCK_ESTABLISHED && (tcphdr->flags & TCP_FLAG_ACK) && (tcphdr->flags & TCP_FLAG_PSH)) {
            socks[i].seq += (len - (sizeof(struct eth_header)+sizeof(struct ip_header)+sizeof(struct tcpip_header)));
            return i;
        }
        i++;
    }
    return 0;
}

