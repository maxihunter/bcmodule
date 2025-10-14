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
#include <stdio.h>

#define FTP_USERNAME "bcmu"
// TODO make password reading from flash
#define FTP_PASSWORD "1234"

struct ftpd_cmd {
    char * name;
    uint8_t id;
};
struct ftp_data ftp_user = {0};

static uint8_t cmd_sock = 0;
static uint8_t data_sock = 0;
static struct inet_addr *int_addr = NULL;
//static uint16_t recv_data_len = 0;

struct ftpd_cmd ftp_cmd_list[] = {
    {"USER", USER_CMD},
    //{"ACCR", ACCT_CMD},
    {"PASS", PASS_CMD},
    {"TYPE", TYPE_CMD},
    {"LIST", LIST_CMD},
    {"CWD\r", CWD_CMD},
    {"DELE", DELE_CMD},
    {"NAME", NAME_CMD},
    {"QUIT", QUIT_CMD},
    {"RETR", RETR_CMD},
    {"STOR", STOR_CMD},
    //{"PORT", PORT_CMD}, Dows not support Active mode
    {"NLST", NLST_CMD},
    {"PWD\r", PWD_CMD},
    {"XPWD", XPWD_CMD},
    {"MKD\r", MKD_CMD},
    {"XMKD", XMKD_CMD},
    {"XRMD", XRMD_CMD},
    {"RMD\r", RMD_CMD},
    {"STRU", STRU_CMD},
    {"MODE", MODE_CMD},
    {"SYST", SYST_CMD},
    {"XMDS", XMD5_CMD},
    {"XCWD", XCWD_CMD},
    {"FEAT", FEAT_CMD},
    {"PASV", PASV_CMD},
    {"SIZE", SIZE_CMD},
    {"MLSD", MLSD_CMD},
    {"APPE", APPE_CMD},
    {"NO", NO_CMD},
    { NULL , MAX_CMD},
};

static const char * passwd = NULL;

/*struct ftp_data {
    char * username;
    unsigned long last_seen;
    char curr_dir[512];
    uint8_t seen;
    uint8_t authorized;
    uint8_t curr_cmd;
    uint8_t curr_state;
    uint8_t data_transfer;
};*/

static void ftpd_sendGreeting(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendCredRequired(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendPassRequired(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendLoginSuccessfull(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendSYST(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendFEAT(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendLIST(uint8_t *buff, uint32_t p_len, uint8_t id, uint8_t verbose);
static void ftpd_sendPASV(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendPWD(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendRETR(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendSTOR(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendTYPE(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendQUIT(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendCmdNotSupported(uint8_t *buff, uint32_t p_len, uint8_t id);

static void ftpd_processCommand(uint8_t *buff, uint32_t p_len, uint8_t id);
uint8_t ftpd_getCMD(uint8_t *buff, uint32_t p_len);

static inline uint8_t ftpd_4bcmp(uint8_t *cmd1, uint8_t *cmd2) {
    if ( *(cmd1) == *(cmd2)
        && *(cmd1+1) == *(cmd2+1)
        && *(cmd1+2) == *(cmd2+2)
        && *(cmd1+3) == *(cmd2+3))
        return 1;
    return 0;
}


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
    if (sockid == 0) {
        return 0;
    }
    if(getSockState(sockid) != SOCK_ESTABLISHED) {
        return 0;
    }
    
    if (!ftp_user.seen) {
        ftpd_sendGreeting(buff, len, sockid);
        ftp_user.seen = 1;
        return 1;
    }
    if (!ftp_user.authorized) {
        uint8_t cmd = ftpd_getCMD(buff, len);
        if (cmd == USER_CMD) {
            ftp_user.username[0] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 0];
            ftp_user.username[1] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 1];
            ftp_user.username[2] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 2];
            ftp_user.username[3] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 3];
            ftpd_sendPassRequired(buff, len, sockid);
            return 1;
        }
        if (cmd == PASS_CMD) {
            // no login yet
            if (ftp_user.username[0] == 0) {
                ftpd_sendCredRequired(buff, len, sockid);
                //printf("NONONO username zeroyy\r\n");
                return 1;
            }
            char pass[4];
            pass[0] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 0];
            pass[1] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 1];
            pass[2] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 2];
            pass[3] = buff[ETH_IP_TCP_HDR_BASE_LEN + 0x5 + 3];
            if(!ftpd_4bcmp(FTP_USERNAME, ftp_user.username) ||
                !ftpd_4bcmp(FTP_PASSWORD, pass)) {
                printf("NONONO username %s.%s. \r\n", ftp_user.username, pass);
                HAL_Delay(1000);
                ftpd_sendCredRequired(buff, len, sockid);
                return 1;
            }
            ftpd_sendLoginSuccessfull(buff, len, sockid);
            ftp_user.authorized = 1;
            ftp_user.curr_dir[0] = '/';
            ftp_user.curr_dir[1] = '\0';
            return 1;
        }
        ftpd_sendCredRequired(buff, len, sockid);
        return 1;
    }
    if (sockid == data_sock)
        return;
	ftpd_processCommand(buff, len, sockid);
    return 0;
}

static void ftpd_prepareHeaders(uint8_t *buff, uint32_t p_len, uint16_t data_len, uint8_t id) {
    struct eth_header* eth = map_eth_header(buff);
    struct ip_header* iphdr = map_ip_header(buff);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);

    memcpy((uint8_t*)&(eth->dst_mac), eth->src_mac, 6);
    memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);

    memcpy((uint8_t*)&(iphdr->dst_ip), (uint8_t*)&(iphdr->src_ip), 4);
    memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);

    //iphdr->total_len = 0x3400; // 52 in network order INT16_ITON
    iphdr->total_len = INT16_ITON(40+data_len); 

    iphdr->checksum = 0;
    iphdr->checksum = ipCalcChecksum(buff);
    uint16_t dp = tcphdr->dport;
    tcphdr->dport = tcphdr->sport;
    tcphdr->sport = dp;
    tcphdr->flags |= TCP_FLAG_ACK | TCP_FLAG_PSH;

    //uint16_t ldata = getSockLastDataLen(id);
    uint32_t ack = tcphdr->ack_num;
    /*uint8_t *ack_ptr = (uint8_t*)&(tcphdr->sequence);
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
    tcphdr->ack_num = tcphdr->sequence;*/
    tcphdr->ack_num = getSockNextAck(id);
    if (tcphdr->ack_num == 0)
        tcphdr->ack_num = tcphdr->sequence;
    tcphdr->sequence = ack;

    tcphdr->window = 0xf601; // 502 NBO;
}

void ftpd_sendGreeting(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 12, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_GREETINGS_OK" bcmFTP\r\n", 12);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 12);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 12, id);
    //enc28j60PacketSend(ETH_IP_TCP_HDR_BASE_LEN + 12,buff);
}

// 530
void ftpd_sendCredRequired(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 17, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_NOT_LOGGED_IN" unathorized\r\n", 17);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 17);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 17, id);
}

// 331
void ftpd_sendPassRequired(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 16, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_USER_PASS_REQ" need passw\r\n", 16);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 16);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 16, id);
}

void ftpd_sendLoginSuccessfull(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 8, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_USER_LOGIN_OK" OK\r\n", 8);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 8);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 8, id);
}

void ftpd_sendCmdNotSupported(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 14, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_COMMAND_NOT_SUPPORTED" Not impl\r\n", 14);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 14);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 14, id);
}

void ftpd_sendQUIT(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 9, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "221 Bye\r\n", 9);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 9);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 9, id);
    //Force finish
    sock_softCloseSock(buff, p_len, id);
}

void ftpd_sendSYST(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 20, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, FTP_SYSTEM_TYPE" STM32 Type: L8\r\n", 20);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 20);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 20, id);
}

void ftpd_sendFEAT(uint8_t *buff, uint32_t p_len, uint8_t id) {
    ftpd_prepareHeaders(buff, p_len, 15, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    char *data = "211-Features:\r\n";
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, data, 15);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 15);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 15, id);

    struct ip_header* iphdr = map_ip_header(buff);
    iphdr->total_len = INT16_ITON(40+16); 
    data = " PASV\r\n211 End\r\n";
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, data, 16);
    tcphdr->sequence += 0x0f000000;
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 16);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 16, id);
}

void ftpd_sendPASV(uint8_t *buff, uint32_t p_len, uint8_t id) {
    char msg[64] = {0};
    uint8_t ports[2] = {0};
    ports[0] = (getSockPort(data_sock) & 0xff);
    ports[1] = (getSockPort(data_sock) >> 8);
    snprintf(msg, 64, "227 Passive mod (%d,%d,%d,%d,%d,%d)\r\n", PRINTABLE_IPADDR(int_addr->ipaddr), ports[0], ports[1] );
    uint8_t msg_len = strlen(msg);
    ftpd_prepareHeaders(buff, p_len, msg_len, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, msg, msg_len);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len, id);
}

void ftpd_sendLIST(uint8_t *buff, uint32_t p_len, uint8_t id, uint8_t verbose) {
#if 0
	{
		fileInfo.lfname = (char*)sect;
		fileInfo.lfsize = sizeof(sect);
		result = f_opendir(&dir, "/");
		if (result == FR_OK)
		{
			while(1)
			{
				result = f_readdir(&dir, &fileInfo);
				if (result==FR_OK && fileInfo.fname[0])
				{
					fn = fileInfo.lfname;
					if(strlen(fn)) HAL_UART_Transmit(&huart1,(uint8_t*)fn,strlen(fn),0x1000);
					else HAL_UART_Transmit(&huart1,(uint8_t*)fileInfo.fname,strlen((char*)fileInfo.fname),0x1000);
					if(fileInfo.fattrib&AM_DIR)
					{
						HAL_UART_Transmit(&huart1,(uint8_t*)"  [DIR]",7,0x1000);
					}
				}
				else break;
				HAL_UART_Transmit(&huart1,(uint8_t*)"\r\n",2,0x1000);
			}
			f_closedir(&dir);
		}
	}
#endif
    ftpd_prepareHeaders(buff, p_len, 13, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "150 Sending\r\n", 13);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 13);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 13, id);
}

void ftpd_sendPWD(uint8_t *buff, uint32_t p_len, uint8_t id) {
    uint8_t msg_len = strlen(ftp_user.curr_dir);
    ftpd_prepareHeaders(buff, p_len, msg_len + 5 + 3, id);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "257 \"", 5);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN+5, ftp_user.curr_dir, msg_len);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN+5+msg_len, "\"\r\n", 3);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len + 5 + 3);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len + 5 + 3, id);
}

void ftpd_sendTYPE(uint8_t *buff, uint32_t p_len, uint8_t id) {
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    if (*(buff+0x3b) == 'I') {
        ftpd_prepareHeaders(buff, p_len, 8, id);
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "200 OK\r\n", 8);
        tcphdr->checksum = 0;
        tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 8);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 8, id);
        return;
    }
    ftpd_prepareHeaders(buff, p_len, 17, id);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "504 Not support\r\n", 17);
    tcphdr->checksum = 0;
    tcphdr->checksum = transportCalcChecksum(buff, ETH_IP_TCP_HDR_BASE_LEN + 17);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 17, id);
}

void ftpd_sendRETR(uint8_t *buff, uint32_t p_len, uint8_t id) {
	//read
	/*
	if(f_mount(&SDFatFs,(TCHAR const*)USERPath,0)!=FR_OK)
	{
		Error_Handler();
	}
	else
	{
		if(f_open(&MyFile,"123.txt",FA_READ)!=FR_OK)
		{
			Error_Handler();
		}
		else
		{
			ReadLongFile();
			f_close(&MyFile);
		}
	}
	*/
}

void ftpd_sendSTOR(uint8_t *buff, uint32_t p_len, uint8_t id) {
	//write
	/*
	if(f_mount(&SDFatFs,(TCHAR const*)USERPath,0)!=FR_OK)
	{
		Error_Handler();
	}
	else
	{
		if(f_open(&MyFile,"mywrite.txt",FA_CREATE_ALWAYS|FA_WRITE)!=FR_OK)
		{
			Error_Handler();
		}
		else
		{
			res=f_write(&MyFile,wtext,sizeof(wtext),(void*)&byteswritten);
			if((byteswritten==0)||(res!=FR_OK))
			{
				Error_Handler();
			}
			f_close(&MyFile);
		}
	}
	*/
}

void ftpd_processCommand(uint8_t *buff, uint32_t p_len, uint8_t id) {
	uint8_t cmd = ftpd_getCMD(buff, p_len);
	    /*
    //{"ACCR", ACCT_CMD},
    {"CWD\r", CWD_CMD},
    {"XPWD", XPWD_CMD},
    {"XMKD", XMKD_CMD},
    {"XRMD", XRMD_CMD},
    {"RMD\r", RMD_CMD},
    {"STRU", STRU_CMD},
    {"MODE", MODE_CMD},
    {"XMDS", XMD5_CMD},
    {"XCWD", XCWD_CMD},
    {"SIZE", SIZE_CMD},
    {"MLSD", MLSD_CMD},
    {"APPE", APPE_CMD},
    {"NO", NO_CMD},
    { NULL , MAX_CMD},*/
	switch(cmd) {
		case SYST_CMD:
            ftpd_sendSYST(buff, p_len, id);
			break;
		case FEAT_CMD:
            ftpd_sendCmdNotSupported(buff, p_len, id);
            //ftpd_sendFEAT(buff, p_len, id);
			break;
		case PWD_CMD:
            ftpd_sendPWD(buff, p_len, id);
			break;
		case PASV_CMD:
            ftpd_sendPASV(buff, p_len, id);
			break;
		case LIST_CMD:
            ftpd_sendLIST(buff, p_len, id, 1);
			break;
		case NLST_CMD:
            ftpd_sendLIST(buff, p_len, id, 0);
			break;
		case RETR_CMD:
            ftpd_sendRETR(buff, p_len, id);
			break;
		case STOR_CMD:
            ftpd_sendSTOR(buff, p_len, id);
			break;
		case TYPE_CMD:
            ftpd_sendTYPE(buff, p_len, id);
			break;
		case MKD_CMD:
			break;
		case DELE_CMD:
			break;
		case QUIT_CMD:
            ftpd_sendQUIT(buff, p_len, id);
			break;
		case SIZE_CMD:
        default:
            ftpd_sendCmdNotSupported(buff, p_len, id);
	}
}

uint8_t ftpd_getCMD(uint8_t *buff, uint32_t p_len) {
    if (p_len < ETH_IP_TCP_HDR_BASE_LEN) {
        return MAX_CMD; // error
    }
#define PKT_CMD (buff+ETH_IP_TCP_HDR_BASE_LEN)
    uint8_t id = 0;
    while (ftp_cmd_list[id].id != 255) {
        if (ftpd_4bcmp( PKT_CMD, ftp_cmd_list[id].name)) {
            return ftp_cmd_list[id].id;
        }
        id++;
    }
    return MAX_CMD; // error
}

