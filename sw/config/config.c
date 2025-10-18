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

#include "config.h"
#include <stdio.h>

struct main_config config_t;

void config_show(char *cmd) {
	printf("dhcp=%d\r\n", config_t.dhcp_f );
	printf(
          "ipaddr=%d.%d.%d.%d\r\n"
          "mask=%d.%d.%d.%d\r\n"
          "gwaddr=%d.%d.%d.%d\r\n",
          config_t.ipaddr[0],config_t.ipaddr[1],config_t.ipaddr[2],config_t.ipaddr[3],
          config_t.ipmask[0],config_t.ipmask[1],config_t.ipmask[2],config_t.ipmask[3],
          config_t.gwaddr[0],config_t.gwaddr[1],config_t.gwaddr[2],config_t.gwaddr[3]
          );

    printf("fpass=%s\r\n", config_t.ftp_pass );
}

void config_save(char *cmd) {
	// TODO save
	printf("OK\r\n");
}

void config_set_dhcp(char *cmd) 
{
	config_t.dhcp_f = '0' - *cmd;
}
void config_set_ipaddr(char *cmd) 
{
	memcpy(config_t.ipaddr, (uint8_t *)cmd, 4);
}

void config_set_mask(char *cmd)
{
	memcpy(config_t.ipmask, (uint8_t *)cmd, 4);
}

void config_set_gwaddr(char *cmd)
{
	memcpy(config_t.gwaddr, (uint8_t *)cmd, 4);
}

void config_set_ftp_pass(char *cmd)
{
	strncpy(config_t.ftp_pass, (uint8_t *)cmd, 4);
}
