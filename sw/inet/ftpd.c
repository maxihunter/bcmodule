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

#include "ftpd.h"
#include <stddef.h>
#include "transportlayer.h"
#include "iplayer.h"
#include "pkt_headers.h"
#include "enc28j60.h"
#include <stdbool.h>
#include <string.h>

#define FTP_USERNAME "bcm"

struct ftpd_cmd {
    char * name;
    uint8_t id;
};

static uint8_t cmd_sock = 0;
static uint8_t data_sock = 0;
static struct inet_addr *int_addr = NULL;

struct ftpd_cmd ftp_cmd_list[] = {
    {"USER", USER_CMD},
    {"USER", ACCT_CMD},
    {"USER", PASS_CMD},
    {"USER", TYPE_CMD},
    {"USER", LIST_CMD},
    {"USER", CWD_CMD},
    {"USER", DELE_CMD},
    {"USER", NAME_CMD},
    {"USER", QUIT_CMD},
    {"USER", RETR_CMD},
    {"USER", STOR_CMD},
    {"USER", PORT_CMD},
    {"USER", NLST_CMD},
    {"USER", PWD_CMD},
    {"USER", XPWD_CMD},
    {"USER", MKD_CMD},
    {"USER", XMKD_CMD},
    {"USER", XRMD_CMD},
    {"USER", RMD_CMD},
    {"USER", STRU_CMD},
    {"USER", MODE_CMD},
    {"USER", SYST_CMD},
    {"USER", XMD5_CMD},
    {"USER", XCWD_CMD},
    {"USER", FEAT_CMD},
    {"USER", PASV_CMD},
    {"USER", SIZE_CMD},
    {"USER", MLSD_CMD},
    {"USER", APPE_CMD},
    {"USER", NO_CMD},
    { NULL , MAX_CMD},
};

static const char * passwd = NULL;

static struct ftp_data ftp_db;
/*struct ftp_data {
    char * username;
    unsigned long last_seen;
    char * curr_dir;
    uint8_t curr_cmd;
    uint8_t curr_state;
    uint8_t data_transfer;
};*/

void ftpd_set_user_password(const char * pass) {
    passwd = pass;
}

void ftpd_set_cmd_sock(uint8_t sock) {
    cmd_sock = sock;
}

void ftpd_set_data_sock(uint8_t sock) {
    data_sock = sock;
}

void ftpdSetAddr(struct inet_addr * inaddr) {
    int_addr = inaddr;
}

uint8_t ftpd_routine(uint8_t * buff, uint32_t len) {
    uint8_t sockid = socketRoutine(buff, len);
    if (sockid == 0)
        return 0;
    if(getSockState(sockid) != SOCK_ESTABLISHED) {
        return 0;
    }
    
    struct eth_header* eth = map_eth_header(buff);
    struct ip_header* iphdr = map_ip_header(buff);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);

    memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
    memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

    memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
    memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);
    uint16_t dp = tcphdr->dport;
    tcphdr->dport = tcphdr->sport;
    tcphdr->sport = dp;
    tcphdr->flags |= TCP_FLAG_ACK | TCP_FLAG_PSH;
    
    tcphdr->window = 502;
    memcpy((uint8_t*)(iphdr)+sizeof(struct tcpip_header), "220 bcmFTP\r\n", 12);
    enc28j60PacketSend(sizeof(struct eth_header)+sizeof(struct ip_header)+sizeof(struct tcpip_header) + 12,buff);
}

