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
#include "fatfs.h"

#define FTP_USERNAME "bcmu"
// TODO make password reading from flash
#define FTP_PASSWORD "1234"

struct ftpd_cmd {
    char * name;
    uint8_t id;
};
struct ftp_data ftp_user = {0};

extern uint8_t sect[512];
static uint8_t file_transfer[512] = {0};
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
static void ftpd_sendSending(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendComplete(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendPASV(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendPWD(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendCCWD(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendTYPE(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendSIZE(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendQUIT(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_sendCmdNotSupported(uint8_t *buff, uint32_t p_len, uint8_t id);

static void ftpd_dataLIST(uint8_t *buff, uint32_t p_len, uint8_t id, uint8_t verbose);
static void ftpd_dataRETR(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_dataSTOR(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_processCommand(uint8_t *buff, uint32_t p_len, uint8_t id);
static void ftpd_handleDataStream(uint8_t *buff, uint32_t p_len, uint8_t id);
static uint8_t ftpd_getCMD(uint8_t *buff, uint32_t p_len);
static uint16_t ftpd_get_endline(uint8_t *buff, uint32_t p_len);

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

    if (ftp_user.curr_cmd && getSockState(data_sock) == SOCK_ESTABLISHED) {
        ftpd_handleDataStream(buff, len, sockid);
        return 0;
    }
    if (sockid == 0) {
        return 0;
    }
    if(getSockState(sockid) != SOCK_ESTABLISHED) {
        return 0;
    }
    
    if (HAL_GetTick() > ftp_user.last_seen + 60000L ) {
        ftp_user.authorized = 0;
        ftp_user.seen = 0;
    }
    if (!ftp_user.seen) {
        ftpd_sendGreeting(buff, len, sockid);
        ftp_user.last_seen = HAL_GetTick();
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
            ftp_user.last_seen = HAL_GetTick();
            ftp_user.curr_cmd = 0;
            ftp_user.curr_dir[0] = '/';
            ftp_user.curr_dir[1] = '\0';
            return 1;
        }
        ftpd_sendCredRequired(buff, len, sockid);
        return 1;
    }
    //ftpd_handleDataStream(buff, len, sockid);
    if (sockid == cmd_sock) {
        ftpd_processCommand(buff, len, sockid);
        ftp_user.last_seen = HAL_GetTick();
    }
    return 0;
}

/*static void ftpd_prepareHeaders(uint8_t *buff, uint32_t p_len, uint16_t data_len, uint8_t id) {
    struct eth_header* eth = map_eth_header(buff);
    struct ip_header* iphdr = map_ip_header(buff);
    struct tcpip_header* tcphdr = map_tcpip_header(buff);

    memcpy((uint8_t*)&(eth->dst_mac), getClientMac(id), 6);
    memcpy((uint8_t*)&(eth->src_mac), int_addr->macaddr, 6);
    eth->ethertype = ETHERTYPE_IPV4;

    uint16_t ip_id = iphdr->id;
    //fillIpDefaultHeader(buff, p_len, IP_PROTO_TYPE_TCP);

    memcpy((uint8_t*)&(iphdr->dst_ip), getClientAddr(id), 4);
    memcpy((uint8_t*)&(iphdr->src_ip), (uint8_t*)&(int_addr->ipaddr), 4);

    //iphdr->total_len = 0x3400; // 52 in network order INT16_ITON
    iphdr->total_len = INT16_ITON(40+data_len); 

    iphdr->checksum = 0;
    iphdr->checksum = ipCalcChecksum(buff);
    uint16_t dp = tcphdr->dport;
    tcphdr->dport = getClientPort(id);
    tcphdr->sport = getSockPort(id);
    tcphdr->flags = 0x0050;
    tcphdr->flags |= TCP_FLAG_ACK | TCP_FLAG_PSH;

    tcphdr->ack_num = getSockNextAck(id);
    if (tcphdr->ack_num == 0)
        tcphdr->ack_num = tcphdr->sequence;
    tcphdr->sequence = getSockSeq(id);

    tcphdr->window = 0xf601; // 502 NBO;
}*/

static void ftpd_sendGreeting(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "220 bcmFTP\r\n", 12);
    fillTcpPacket(buff, p_len, 12, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 12, id);
}

// 530
static void ftpd_sendCredRequired(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "530 unathorized\r\n", 17);
    fillTcpPacket(buff, p_len, 17, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 17, id);
}

// 331
static void ftpd_sendPassRequired(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "331 need passw\r\n", 16);
    fillTcpPacket(buff, p_len, 16, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 16, id);
}

static void ftpd_sendLoginSuccessfull(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "230 OK\r\n", 8);
    fillTcpPacket(buff, p_len, 8, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 8, id);
}

static void ftpd_sendCmdNotSupported(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "502 Not impl\r\n", 14);
    fillTcpPacket(buff, p_len, 14, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 14, id);
}

static void ftpd_sendQUIT(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "221 Bye\r\n", 9);
    fillTcpPacket(buff, p_len, 9, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 9, id);
    //Force finish
    sock_softCloseSock(buff, p_len, id);
}

static void ftpd_sendSYST(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "215 STM32 Type: L8\r\n", 20);
    fillTcpPacket(buff, p_len, 20, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 20, id);
}

static void ftpd_sendFEAT(uint8_t *buff, uint32_t p_len, uint8_t id) {
    char *data = "211-Features:\r\n PASV\r\n SIZE\r\n211 End\r\n";
    uint8_t msg_len = strlen(data);
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, data, msg_len);
    fillTcpPacket(buff, p_len, msg_len, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len, id);
}

static void ftpd_sendPASV(uint8_t *buff, uint32_t p_len, uint8_t id) {
    char msg[64] = {0};
    uint8_t ports[2] = {0};
    ports[0] = (getSockPort(data_sock) & 0xff);
    ports[1] = (getSockPort(data_sock) >> 8);
    snprintf(msg, 64, "227 Passive mod (%d,%d,%d,%d,%d,%d)\r\n", PRINTABLE_IPADDR(int_addr->ipaddr), ports[0], ports[1] );
    uint8_t msg_len = strlen(msg);

    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, msg, msg_len);
    fillTcpPacket(buff, p_len, msg_len, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len, id);
}

static void ftpd_sendSending(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "150 Sending\r\n", 13);
    fillTcpPacket(buff, p_len, 13, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 13, id);
}

static void ftpd_sendComplete(uint8_t *buff, uint32_t p_len, uint8_t id) {
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "226 Done\r\n", 10);
    fillTcpPacket(buff, p_len, 10, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 10, id);
}

static void ftpd_sendPWD(uint8_t *buff, uint32_t p_len, uint8_t id) {
    uint8_t msg_len = strlen(ftp_user.curr_dir);
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "257 \"", 5);
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN+5, ftp_user.curr_dir, msg_len);
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN+5+msg_len, "\"\r\n", 3);
    fillTcpPacket(buff, p_len, msg_len + 5 + 3, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + msg_len + 5 + 3, id);
}

static void ftpd_sendTYPE(uint8_t *buff, uint32_t p_len, uint8_t id) {
    if (*(buff+0x3b) == 'I') {
        memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "200 OK\r\n", 8);
        fillTcpPacket(buff, p_len, 8, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 8, id);
        return;
    }
    memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "504 Not support\r\n", 17);
    fillTcpPacket(buff, p_len, 17, id);
    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 17, id);
}

static void ftpd_dataLIST(uint8_t *buff, uint32_t p_len, uint8_t id, uint8_t verbose) {
	FRESULT result; //ðåçóëüòàò âûïîëíåíèÿ
	FILINFO fileInfo;
	char *fn;
	DIR dir;
	//DWORD fre_clust, fre_sect, tot_sect;
    fileInfo.lfname = (char*)sect;
    fileInfo.lfsize = sizeof(sect);
    result = f_opendir(&dir, ftp_user.curr_dir); //ftp_user.curr_dir
    if (result == FR_OK)
    {
        struct tcpip_header* tcphdr = map_tcpip_header(buff);
        char fbuf[256] = {0};
        char * flags;
        uint8_t len = 0;
        uint32_t flen = 0;
        uint16_t buff_ptr = 0;
        /*snprintf(fbuf, 512, "drwxrwxr-x   3   1000  1000  4096   Jul 1  2025  .\r\n");
        len = strlen(fbuf);
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN+buff_ptr, fbuf, len);
        buff_ptr += len;
        snprintf(fbuf, 512, "drwxrwxr-x   3   1000  1000  4096   Jul 1  2025  ..\r\n");
        len = strlen(fbuf);
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN+buff_ptr, fbuf, len);
        buff_ptr += len;*/
        while(1)
        {
            result = f_readdir(&dir, &fileInfo);
            if (result==FR_OK && fileInfo.fname[0])
            {
                printf("LIST SEND2 %ld:%ld\r\n", fileInfo.fsize, p_len);
                fn = fileInfo.lfname;
                flen = fileInfo.fsize;
                if(!strlen(fn)) {
                    fn = fileInfo.fname;
                    //flen = fileInfo.lfsize;
                }
                if (verbose) {
                    if(fileInfo.fattrib&AM_DIR)
                    {
                        flags = "drwxrwxr-x";
                        flen = 4096;
                    } else {
                        flags = "-rwxrwxr-x";
                    }
                    snprintf(fbuf, 512, "%s   3   1000  1000  %ld   Jul 1  2025  %s\r\n", flags, flen, fn);
                } else {
                    snprintf(fbuf, 512, "%s\r\n", fn);
                }
                len = strlen(fbuf);
                if (ETH_IP_TCP_HDR_BASE_LEN+buff_ptr+len > p_len) {
                    fillTcpPacket(buff, p_len, buff_ptr, id);
                    sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + buff_ptr, id);
                    buff_ptr = 0;
                }
                memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN+buff_ptr, fbuf, len);
                buff_ptr += len;
            }
            else break;
        }
        f_closedir(&dir);
        fillTcpPacket(buff, p_len, buff_ptr, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + buff_ptr, id);
    }
    struct ip_header* iphdr = map_ip_header(buff);
    sock_softCloseSock(buff, p_len, id);
    ftpd_sendComplete(buff, p_len, cmd_sock);
    ftp_user.data_transfer = FTP_DATA_IDLE;
    ftp_user.curr_cmd = 0;
}

static void ftpd_sendSIZE(uint8_t *buff, uint32_t p_len, uint8_t id) {
	FRESULT result;
	FILINFO fileInfo;
	char *fn;
	DIR dir;
    fileInfo.lfname = (char*)sect;
    fileInfo.lfsize = sizeof(sect);
    result = f_opendir(&dir, ftp_user.curr_dir);
    if (result == FR_OK)
    {
        struct tcpip_header* tcphdr = map_tcpip_header(buff);
        char fbuf[64] = {0};
        uint32_t flen = 0;
        uint16_t file_name_len = ftpd_get_endline(buff + ETH_IP_TCP_HDR_BASE_LEN + 5, p_len);
        *(buff+ETH_IP_TCP_HDR_BASE_LEN+5+file_name_len) = '\0';
        printf("SIZE FNAME %s\r\n", buff+ETH_IP_TCP_HDR_BASE_LEN+5);
        while(1)
        {
            result = f_readdir(&dir, &fileInfo);
            if (result==FR_OK && fileInfo.fname[0])
            {
                if (strcmp(fileInfo.fname, buff+ETH_IP_TCP_HDR_BASE_LEN+5) == 0) {
                    break;
                }
            } else {
                break;
            }
        }
        printf("SIZE SEND2 %ld:%ld\r\n", fileInfo.fsize, p_len);
        fn = fileInfo.lfname;
        flen = fileInfo.fsize;
        if(!strlen(fn)) {
            fn = fileInfo.fname;
            //flen = fileInfo.lfsize;
        }
        f_closedir(&dir);
        snprintf(fbuf, 64, "%ld\r\n", flen);
        uint8_t len = strlen(fbuf);
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, fbuf, len);
        fillTcpPacket(buff, p_len, len, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + len, id);
    }
}

static void ftpd_sendCCWD(uint8_t *buff, uint32_t p_len, uint8_t id) {
	FRESULT result;
	FILINFO fileInfo;
	DIR dir;
    fileInfo.lfname = (char*)sect;
    fileInfo.lfsize = sizeof(sect);
    char fbuf[512] = {0};
    struct tcpip_header* tcphdr = map_tcpip_header(buff);
    snprintf(fbuf, 512, "%s/%s\r\n", ftp_user.curr_dir, buff+ETH_IP_TCP_HDR_BASE_LEN+4);
    result = f_opendir(&dir, fbuf);
    if (result == FR_OK)
    {
        strcpy(ftp_user.curr_dir, fbuf);
        f_closedir(&dir);
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "250 OK\r\n", 8);
        fillTcpPacket(buff, p_len, 8, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 8, id);
    } else {
        memcpy((uint8_t*)(tcphdr)+TCP_HDR_BASE_LEN, "501 Failed\r\n", 12);
        fillTcpPacket(buff, p_len, 12, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 12, id);
    }
}

#define DATA_BUFFER 512
static void ftpd_dataSTOR(uint8_t *buff, uint32_t p_len, uint8_t id) {
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

static void ftpd_dataRETR(uint8_t *buff, uint32_t p_len, uint8_t id) {
	//read
    char fbuf[512] = {0};
    snprintf(fbuf, 512, "%s%s\r\n", ftp_user.curr_dir, file_transfer);
    printf("RETR fopen:%s\r\n", fbuf);
    FIL MyFile;

    if(f_open(&MyFile,fbuf,FA_READ)!=FR_OK)
    {
        memcpy(buff + ETH_IP_TCP_HDR_BASE_LEN, "501 Failed\r\n", 12);
        fillTcpPacket(buff, p_len, 12, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + 12, id);
        return;
    }
    printf("RETR SENDING\r\n");
    uint16_t data_to_read = 0;
    uint32_t index = 0;
    uint32_t bytesread = 0;
    uint32_t f_size = MyFile.fsize;
    //sprintf(str1,"fsize: %lu\r\n",(unsigned long)f_size);
    //HAL_UART_Transmit(&huart1,(uint8_t*)str1,strlen(str1),0x1000);
    do
    {
        data_to_read = DATA_BUFFER;
        if(f_size < DATA_BUFFER) {
            data_to_read = f_size;
        }
        f_size -= data_to_read;
        f_lseek(&MyFile, index);
        f_read(&MyFile, buff + ETH_IP_TCP_HDR_BASE_LEN, data_to_read, (UINT *)&bytesread);

        printf("RETR READED %ld\r\n", bytesread);
        fillTcpPacket(buff, p_len, bytesread, id);
        sockSendData(buff, ETH_IP_TCP_HDR_BASE_LEN + bytesread, id);

      //  for(i=0;i<bytesread;i++)
        {
        //    HAL_UART_Transmit(&huart1,sect+i,1,0x1000);
        }
        index += data_to_read;
    } while(f_size>0);
    //HAL_UART_Transmit(&huart1,(uint8_t*)"\r\n",2,0x1000);
    f_close(&MyFile);
    sock_softCloseSock(buff, p_len, id);
    ftpd_sendComplete(buff, p_len, cmd_sock);
    ftp_user.data_transfer = FTP_DATA_IDLE;
    ftp_user.curr_cmd = 0;

}

static void ftpd_processCommand(uint8_t *buff, uint32_t p_len, uint8_t id) {
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
		case CWD_CMD:
            ftpd_sendCCWD(buff, p_len, id);
			break;
		case FEAT_CMD:
            //ftpd_sendCmdNotSupported(buff, p_len, id);
            ftpd_sendFEAT(buff, p_len, id);
			break;
		case PWD_CMD:
            ftpd_sendPWD(buff, p_len, id);
			break;
		case PASV_CMD:
            ftpd_sendPASV(buff, p_len, id);
			break;
		case LIST_CMD:
		case NLST_CMD:
		case RETR_CMD:
		case STOR_CMD:
            ftp_user.curr_cmd = cmd;
            ftp_user.data_transfer = FTP_DATA_IDLE;
            ftp_user.data_transfer_ptr = 0;
            uint16_t flen = ftpd_get_endline(buff + ETH_IP_TCP_HDR_BASE_LEN + 5, p_len);
            memcpy(file_transfer, buff + ETH_IP_TCP_HDR_BASE_LEN + 5, flen);
            if(getSockState(data_sock) == SOCK_ESTABLISHED) {
                ftp_user.data_transfer = FTP_DATA_TRANSMIT;
                ftpd_sendSending(buff, p_len, id);
                HAL_Delay(20);
            }
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
            ftpd_sendSIZE(buff, p_len, id);
			break;
        default:
            ftpd_sendCmdNotSupported(buff, p_len, id);
	}
}

static void ftpd_handleDataStream(uint8_t *buff, uint32_t p_len, uint8_t id) {
    printf("DSSEND\r\n");
    uint8_t verb = 0;
    if (ftp_user.data_transfer == FTP_DATA_IDLE) {
        ftpd_sendSending(buff, p_len, cmd_sock);
        ftp_user.data_transfer = FTP_DATA_TRANSMIT;
        HAL_Delay(10);
        return;
    } else
    if (ftp_user.data_transfer == FTP_DATA_FINISHED) {
        printf("DSSEND COM\r\n");
        ftpd_sendComplete(buff, p_len, cmd_sock);
        ftp_user.data_transfer = FTP_DATA_IDLE;
        ftp_user.curr_cmd = 0;
        return;
    }
    //if (ftp_user.data_transfer != FTP_DATA_TRANSMIT) {
      //  return;
    //}
    switch(ftp_user.curr_cmd) {
		case LIST_CMD:
            verb = 1;
		case NLST_CMD:
            ftpd_dataLIST(buff, p_len, data_sock, verb);
            ftp_user.data_transfer = FTP_DATA_FINISHED;
			break;
		case RETR_CMD:
            ftpd_dataRETR(buff, p_len, data_sock);
            ftp_user.data_transfer = FTP_DATA_FINISHED;
			break;
		case STOR_CMD:
            ftpd_dataSTOR(buff, p_len, id);
            ftp_user.data_transfer = FTP_DATA_FINISHED;
			break;
		case MKD_CMD:
			break;
		case DELE_CMD:
			break;
        default:
            return;
    }
}

static uint8_t ftpd_getCMD(uint8_t *buff, uint32_t p_len) {
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

static uint16_t ftpd_get_endline(uint8_t *buff, uint32_t p_len) {
    uint16_t len = 0;
    do {
        len++;
    } while(*(buff+len) != '\r' && *(buff+len) != '\n');
    printf("GETL arg:%d\r\n", len);
    return len;
}

