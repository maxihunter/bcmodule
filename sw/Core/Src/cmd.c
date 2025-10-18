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

#include "cmd.h"
#include "inttypes.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "enc28j60.h"
#include "fatfs.h"
#include "sd_card.h"
#include "dhcpd.h"
#include "config.h"

extern struct inet_addr net_addr;
extern RTC_HandleTypeDef hrtc;
extern UART_HandleTypeDef huart1;
extern uint8_t sect[512];
extern FATFS *fs;

static uint8_t *pbuf;
static uint32_t pbuf_len = 0;

static void print_help(char *cmd);
static void print_version(char *cmd);
static void print_bell(char *cmd);
static void print_date(char *cmd);
static void print_link(char *cmd);
static void handle_link(char *cmd);
static void handle_ping(char *cmd);
static void handle_arp(char *cmd);
static void handle_switch1(char *cmd);
static void handle_switch2(char *cmd);
static void handle_switch3(char *cmd);
static void handle_reset(char *cmd);
static void print_sdfiles(char *cmd);

const struct cmd_description cmd_list[] = {
    {"arp", 0, &handle_arp},
    {"con1", 6, &handle_switch1},
    {"con2", 7, &handle_switch2},
    {"con3", 8, &handle_switch3},
	{"conf", 5, &config_show},
	{"bell", 9, &print_bell},
    {"date", 9, &print_date},
    {"help", 1, &print_help},
    {"ipaddr", 1, &print_ipaddr},
    {"link", 4, &handle_link},
    {"ftp", 3, &print_help},
    {"ping", 0, &handle_ping},
	{"reset", 0, &handle_reset},
	{"save", 5, &config_save},
    {"sdinf", 5, &print_sdcard},
    {"sdls", 5, &print_sdfiles},
	{"setdhcp", 5, &config_set_dhcp},
	{"setpass", 5, &config_set_ftp_pass},
	{"setgw", 5, &config_set_gwaddr},
	{"setip", 5, &config_set_ipaddr},
	{"setmask", 5, &config_set_mask},	
    {"usb", 2, &print_help},
    {"ver", 0, &print_version},
    {NULL, 255, NULL},
};

void cmd_init(uint8_t *buff, uint32_t pbuff_len) {
    pbuf = buff;
    pbuf_len = pbuff_len;
}

void cmd_process(char * cmd, uint8_t len) {
    char *cmd_ptr = cmd;
    for (int k = 0; k < len; k++) {
        if (*(cmd_ptr+k) == ' ') {
            cmd_ptr += k;
            *cmd_ptr = '\0';
            break;
        }
    }
    uint8_t found = 0;
    for (int i = 0; cmd_list[i].id != 255; i++) {
        if (strcmp(cmd_list[i].name, cmd) == 0) {
            if (cmd_ptr == cmd)
                (cmd_list[i].proc)(NULL);
            else
                (cmd_list[i].proc)(cmd_ptr+1);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("Unknown cmd\r\n");
    }
}

void print_help(char *cmd) {
    uint8_t cmd_id = 0;
    while (cmd_list[cmd_id].id != 255) {
        printf("\t%s\r\n", cmd_list[cmd_id].name);
        cmd_id++;
    }
}

void print_version(char *cmd) {
    printf("sw version: %d\r\n", SW_VER);
}

void print_bell(char *cmd) {
    printf("\a\r\n");
}

void print_date(char *cmd) {
  RTC_TimeTypeDef sTime;
  RTC_DateTypeDef sDate;
  if (HAL_RTC_GetTime(&hrtc, &sTime, RTC_FORMAT_BIN) != HAL_OK 
          || HAL_RTC_GetDate(&hrtc, &sDate, RTC_FORMAT_BIN) != HAL_OK)
  {
      printf("Internal error\r\n");
      return;
  }
  printf("System time is %02d-%02d-20%02d %02d:%02d:%02d\r\n", sDate.Date, sDate.Month, sDate.Year,
          sTime.Hours, sTime.Minutes, sTime.Seconds);
}

void print_ipaddr(char *cmd) {
  printf(
          "\tIP address: %d.%d.%d.%d\r\n"
          "\tIP netmask: %d.%d.%d.%d\r\n"
          "\tGW address: %d.%d.%d.%d\r\n"
          "\tDNS address: %d.%d.%d.%d\r\n",
          PRINTABLE_IPADDR(net_addr.ipaddr),
          PRINTABLE_IPADDR(net_addr.mask),
          PRINTABLE_IPADDR(net_addr.gateway),
          PRINTABLE_IPADDR(net_addr.dnssrv));
}

void handle_link(char *cmd) {
    // halt???? 
    /*if (cmd) {
        if (*cmd == '0') {
            enc28j60PowerDown();
        } else {
            enc28j60PowerUp();
        }
        printf("Switching ");
    }*/
    printf("PHY link: \r\n");
    /*
    if (enc28j60linkup()) {
        printf("UP\r\n");
    } else {
        printf("DOWN\r\n");
    }*/
}

void handle_ping(char *cmd) {
    printf("Ping: %s\r\n", cmd);

    uint32_t ip = _inet_pton(cmd);
    uint8_t mac[6] = {0};
    if (getHostMacByArp(pbuf, pbuf_len, ip, &mac)) {
        printf("Get MAC failed\r\n");
        return;
    }
    icmpPingHost(ip, &mac);
}

void handle_arp(char *cmd) {
    printf("ARP resolve: %s\r\n", cmd);

    /*
    uint8_t getHostMacByArp(uint8_t *buff, uint32_t len, uint32_t hostaddr, uint8_t *hostmac);
    if (enc28j60linkup()) {
        printf("UP\r\n");
    } else {
        printf("DOWN\r\n");
    }*/
}

void handle_switch1(char *cmd) {
    if (cmd) {
        if (*cmd == '0') {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);
        } else {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_SET);
        }
        printf("Switching ");
    }
    printf("SW1: ");
    if (HAL_GPIO_ReadPin(GPIOB, GPIO_PIN_12)) {
        printf("OPEN\r\n");
    } else {
        printf("CLOSE\r\n");
    }
}

void handle_switch2(char *cmd) {
    if (cmd) {
        if (*cmd == '0') {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);
        } else {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_SET);
        }
        printf("Switching ");
    }
    printf("SW1: ");
    if (HAL_GPIO_ReadPin(GPIOB, GPIO_PIN_12)) {
        printf("OPEN\r\n");
    } else {
        printf("CLOSE\r\n");
    }
}

void handle_switch3(char *cmd) {
    if (cmd) {
        if (*cmd == '0') {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);
        } else {
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_SET);
        }
        printf("Switching ");
    }
    printf("SW1: ");
    if (HAL_GPIO_ReadPin(GPIOB, GPIO_PIN_12)) {
        printf("OPEN\r\n");
    } else {
        printf("CLOSE\r\n");
    }
}

void handle_reset(char *cmd) {
	printf("System reset\r\n");
	HAL_Delay(500);
    HAL_NVIC_SystemReset();
}

void print_sdcard(char *cmd) {
    DWORD fre_clust, fre_sect, tot_sect;
    f_getfree("/", &fre_clust, &fs);
    printf("Free clusters: %lu\r\n",fre_clust);
    printf("FATent: %lu\r\n",fs->n_fatent);
    printf("FS csize: %d\r\n",fs->csize);
    tot_sect = (fs->n_fatent - 2) * fs->csize;
    printf("Total sectors: %lu\r\n",tot_sect);
    fre_sect = fre_clust * fs->csize;
    printf("Sectors free: %lu\r\n",fre_sect);
    printf( "%lu KB total drive space.\r\n%lu KB available.\r\n",
            fre_sect/2, tot_sect/2);
}

void print_sdfiles(char *cmd) {
    uint8_t result;
    FILINFO fileInfo;
    char *fn;
    DIR dir;
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
                if(fileInfo.fattrib&AM_DIR)
                {
                    HAL_UART_Transmit(&huart1,(uint8_t*)" [DIR] ",7,0x1000);
                } else {
                    //char csz[7] = {0};
                    uint32_t size = 0;
                    if(strlen(fn)) {
                        size = fileInfo.lfsize;
                    } else {
                        size = fileInfo.fsize;
                    }
                    if(size > 1000) {
                        size /= 1000;
                    }
                    printf("%lu", size);
                    HAL_UART_Transmit(&huart1,(uint8_t*)"  ---  ",7,0x1000);
                }
                HAL_UART_Transmit(&huart1, "  ", 2,0x1000);
                if(strlen(fn)) {
                    HAL_UART_Transmit(&huart1,(uint8_t*)fn,strlen(fn),0x1000);
                } else {
                    HAL_UART_Transmit(&huart1,(uint8_t*)fileInfo.fname,strlen((char*)fileInfo.fname),0x1000);
                }
            }
            else break;
            HAL_UART_Transmit(&huart1,(uint8_t*)"\r\n",2,0x1000);
        }
        f_closedir(&dir);
    }
}




