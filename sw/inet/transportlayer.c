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

static uint32_t sock_sendAck(uint8_t *buff, uint32_t p_len, uint16_t ldata);

static struct inet_addr *int_addr = NULL;
static uint8_t *pbuf;
static uint32_t pbuf_len = 0;
static struct socket socks[] = {
    {0, 0, 0, 0 }, // Service socket. Do not use
    { 0x1400/*20 network order*/, IP_PROTO_TYPE_TCP, SOCK_LISTEN, 0, 0 },
    { 0x1500/*21 network order*/, IP_PROTO_TYPE_TCP, SOCK_LISTEN, 0, 0 },
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

uint8_t getSockSeq(uint8_t id) {
    return socks[id].seq;
}

uint16_t getSockLastDataLen(uint8_t id) {
    return socks[id].last_data_len;
}

uint32_t getSockNextAck(uint8_t id) {
    return socks[id].next_ack;
}

void sockSendData(uint8_t *buff, uint32_t len, uint8_t id) {
    socks[id].seq += len - ETH_IP_TCP_HDR_BASE_LEN;
    enc28j60PacketSend(len,buff);
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
        //printf("RUN SOCK %c, f=%x\r\n", '0' + i, tcphdr->flags);
        if ( (socks[i].state == SOCK_LISTEN || socks[i].state == SOCK_SYN) && tcphdr->flags & TCP_FLAG_SYN) {
            //printf("RUN SOCK %d SYN s=%x\r\n", '0' + i, tcphdr->sequence);
            socks[i].state = SOCK_SYN;
            memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
            memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

            memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
            memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);
            iphdr->total_len = 0x2c00; // 52 in network order
            iphdr->id = 0;
            iphdr->checksum = 0;
            iphdr->checksum = ipCalcChecksum(buff);

            tcphdr->dport = tcphdr->sport;
            tcphdr->sport = socks[i].port;
            tcphdr->flags = 0x0060;
            tcphdr->flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
            tcphdr->window = 0x0005; // make window size double of standard MTU 1280
            tcphdr->ack_num = tcphdr->sequence + 0x01000000; // +1 in network order
                                               //
            socks[i].seq = HAL_GetTick() << 16;
            tcphdr->sequence = socks[i].seq;
            socks[i].seq += 0x01000000; // +1 in network order
            buff[ETH_IP_TCP_HDR_BASE_LEN]=2;
            buff[ETH_IP_TCP_HDR_BASE_LEN+1]=4;
            buff[ETH_IP_TCP_HDR_BASE_LEN+2]=0x05;
            buff[ETH_IP_TCP_HDR_BASE_LEN+3]=0x0;
            /* SACK PERM
             * buff[ETH_IP_TCP_HDR_BASE_LEN]=0x4;
            buff[ETH_IP_TCP_HDR_BASE_LEN+1]=0x2;
            buff[ETH_IP_TCP_HDR_BASE_LEN+2]=0x01;
            buff[ETH_IP_TCP_HDR_BASE_LEN+3]=0x01;*/

            /*
            buff[ETH_IP_TCP_HDR_BASE_LEN+4]=0x01;
            buff[ETH_IP_TCP_HDR_BASE_LEN+11]=0x01;*/
            tcphdr->checksum = 0;
            tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN+4);

            enc28j60PacketSend(ETH_IP_TCP_HDR_BASE_LEN+4,buff);
            return i;
        }
        if ( socks[i].state == SOCK_SYN && (tcphdr->flags & TCP_FLAG_ACK) && !(tcphdr->flags & TCP_FLAG_PSH)) {
            //printf("RUN SOCK %c ESTTT s=\r\n", '0' + i);
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
            tcphdr->sequence = socks[i].seq; //TCP_HDR_BASE_LEN
            tcphdr->checksum = 0;
            tcphdr->checksum = transportCalcChecksum(buff, len);
            enc28j60PacketSend(len,buff);
            return 0;
        }
        if ( socks[i].state == SOCK_FIN && tcphdr->flags & TCP_FLAG_ACK) {
            socks[i].state = SOCK_OPEN;
            socks[i].seq = 0;
            return 0;
        }
        if ( socks[i].state == SOCK_ESTABLISHED && (tcphdr->flags & TCP_FLAG_ACK) && (tcphdr->flags & TCP_FLAG_PSH)) {
            //socks[i].seq += (len - (sizeof(struct eth_header)+sizeof(struct ip_header)+sizeof(struct tcpip_header)));
            socks[i].last_data_len = (len - (sizeof(struct eth_header)+sizeof(struct ip_header)+sizeof(struct tcpip_header)));
            socks[i].next_ack = sock_sendAck(buff, len, socks[i].last_data_len);
            return i;
        }
        i++;
    }
    return 0;
}

uint16_t transportCalcChecksum(uint8_t *buff, uint32_t p_len) {
    uint32_t chcksum = 0;
    uint16_t res = 0;
    struct ip_header* iphdr = map_ip_header(buff);
    uint16_t buff_pos = ETH_HDR_BASE_LEN + (uint32_t)(&(((struct ip_header*)0)->src_ip));
    uint16_t chck_len = p_len - buff_pos;

    chcksum += iphdr->protocol;
    chcksum += chck_len - 8;
    while (buff_pos < p_len - 1) {
        //chcksum += *((uint16_t *)(buff + buff_pos)); // sht, need normal order, not network order...
        //printf("pos=%x;buf=%x;cch1=%x\r\n", buff_pos, *(buff+buff_pos), chcksum );
        chcksum += 0xFFFF & (((uint32_t)*(buff+buff_pos)<<8)|*(buff+1+buff_pos));
        buff_pos += 2;
    }
    if(buff_pos == chck_len - 1) {
        //printf("ex_pos=%x;buf=%x;cch1=%x\r\n", buff_pos, *(buff+buff_pos), chcksum );
        chcksum += 0xff00 & (*(buff + buff_pos+1) << 8);
    }
    while (chcksum >> 16) {
        chcksum = (chcksum & 0xffff) + (chcksum >> 16);
    }
    //printf("cch1=%x\r\n", ((uint16_t) chcksum ^ 0xFFFF));
    chcksum = (chcksum ^ 0xFFFF);
    res =  (chcksum << 8) | (chcksum >> 8);

    return res;
}

static uint32_t sock_sendAck(uint8_t *buff, uint32_t p_len, uint16_t ldata) {
    uint8_t abuff[ETH_IP_TCP_HDR_BASE_LEN] = {0};
    memcpy(abuff, buff, ETH_IP_TCP_HDR_BASE_LEN);
    struct eth_header* eth = map_eth_header(abuff);
    struct ip_header* iphdr = map_ip_header(abuff);
    struct tcpip_header* tcphdr = map_tcpip_header(abuff);

    memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
    memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

    memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
    memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);

    iphdr->total_len = 0x2800; // 40 in network order INT16_ITON

    iphdr->checksum = 0;
    iphdr->checksum = ipCalcChecksum(abuff);
    uint16_t dp = tcphdr->dport;
    tcphdr->dport = tcphdr->sport;
    tcphdr->sport = dp;
    tcphdr->flags = 0x0050;
    tcphdr->flags |= TCP_FLAG_ACK;

    //uint16_t ldata = getSockLastDataLen(id);
    uint32_t ack = tcphdr->ack_num;
    uint8_t *ack_ptr = (uint8_t*)&(tcphdr->sequence);
    uint8_t *ld_ptr = (uint8_t*)&(ldata);
    uint8_t overfl = 0;

    if (*(ack_ptr+3) + *(ld_ptr) > 255) {
        overfl = 1;
    }
    *(ack_ptr+3) += *(ld_ptr);
    if (*(ack_ptr+2) + *(ld_ptr+1) + overfl > 255) {
        if (*(ack_ptr+1) == 255)
            *(ack_ptr) += 1;
        *(ack_ptr+1) += 1;
    }
    tcphdr->ack_num = tcphdr->sequence;
    tcphdr->sequence = ack;

    tcphdr->window = 0xf601; // 502 NBO;
    tcphdr->window = 0xf601; // 502 NBO;
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(abuff, ETH_IP_TCP_HDR_BASE_LEN); // ACK packet have no data
    enc28j60PacketSend(ETH_IP_TCP_HDR_BASE_LEN,abuff);
    return tcphdr->ack_num;
}
