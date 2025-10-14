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


#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <inttypes.h>
#include <string.h>

#define CONFIG_RESERVED_SIZE 32

#define DHCP_FLAG_ENABLE (1 << 0)

extern uint8_t macAddr[6];

struct main_config {
	uint8_t dhcp_f;
	uint8_t ipaddr[4];
	uint8_t ipmask[4];
	uint8_t gwaddr[4];
	char ftp_pass[8];
} __attribute__((packed));

void config_show(char *cmd);
void config_save(char *cmd);

void config_set_dhcp(char *cmd);
void config_set_ipaddr(char *cmd);
void config_set_mask(char *cmd);
void config_set_gwaddr(char *cmd);
void config_set_ftp_pass(char *cmd);

#endif // __CONFIG_H__

