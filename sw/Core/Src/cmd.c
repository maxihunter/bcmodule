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

extern struct inet_addr net_addr;

static void print_help(char *cmd);
static void print_version(char *cmd);

const struct cmd_description cmd_list[] = {
    {"ver", 0, "Print Version", &print_version},
    {"help", 1, "Print help", &print_help},
    {"usb", 2, "USB on/off", &print_help},
    {"ftp", 3, "FTP on/off", &print_help},
    {"link", 4, "Eth Link up/down", &print_help},
    {"sd_st", 5, "SD status", &print_help},
    {"con1", 6, "CON1 on/off", &print_help},
    {"con2", 7, "CON2 on/off", &print_help},
    {"con3", 8, "CON3 on/off", &print_help},
    {NULL, 255, NULL, NULL},
};
/*{
    char * name;
    uint8_t id;
    char * desc;
    cmdFunc proc;
}*/


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
        //printf("coll id=%d %s(%d)\r\n",i, cmd, len);
        if (strcmp(cmd_list[i].name, cmd) == 0) {
            //printf("coll id=%d\r\n",i);
            if (cmd_ptr == cmd)
                (cmd_list[i].proc)(NULL);
            else
                (cmd_list[i].proc)(cmd_ptr);
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
        printf("  %s - %s\r\n", cmd_list[cmd_id].name, cmd_list[cmd_id].desc);
        cmd_id++;
    }
}

void print_version(char *cmd) {
    printf("sw version: %d\r\n", SW_VER);
}

