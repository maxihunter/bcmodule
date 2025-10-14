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

#ifndef __FTPD_H__
#define __FTPD_H__

#include <inttypes.h>
#include "dhcpd.h"

#define FTP_FILE_STATUS_OK "150"
#define FTP_COMMAND_OK "200"
#define FTP_SYSTEM_TYPE "215"
#define FTP_GREETINGS_OK "220"
#define FTP_CLOSE_CONN "226"
#define FTP_USER_LOGIN_OK "230"
#define FTP_REQ_FILE_COMPLETE "250"
#define FTP_USER_PASS_REQ "331"
#define FTP_REQ_PENDING "350"

#define FTP_SERVICE_UNAVAILABLE "421"
#define FTP_OPEN_DATA_CONN_FAILED "425"
#define FTP_REQ_ACTION_NOT_TAKEN "450"

#define FTP_COMMAND_NOT_FOUND "500"
#define FTP_PARAMETERS_ERROR "501"
#define FTP_COMMAND_NOT_SUPPORTED "502"
#define FTP_NOT_LOGGED_IN "530"
#define FTP_FILE_UNAVAILABLE "550"


enum ftp_cmd {
	USER_CMD,
//	ACCT_CMD,
	PASS_CMD,
	TYPE_CMD,
	LIST_CMD,
	CWD_CMD,
	DELE_CMD,
	NAME_CMD,
	QUIT_CMD,
	RETR_CMD,
	STOR_CMD,
	PORT_CMD,
	NLST_CMD,
	PWD_CMD,
	XPWD_CMD,
	MKD_CMD,
	XMKD_CMD,
	XRMD_CMD,
	RMD_CMD,
	STRU_CMD,
	MODE_CMD,
	SYST_CMD,
	XMD5_CMD,
	XCWD_CMD,
	FEAT_CMD,
	PASV_CMD,
	SIZE_CMD,
	MLSD_CMD,
	APPE_CMD,
	NO_CMD,
	MAX_CMD = 255,
};

struct ftp_data {
    char username[4];
    unsigned long last_seen;
    char curr_dir[512];
    uint8_t seen;
    uint8_t authorized;
    uint8_t curr_cmd;
    uint8_t curr_state;
    uint8_t data_transfer;
};

void ftpd_set_user_password(const char * pass);

void ftpd_set_cmd_sock(uint8_t sock);

void ftpd_set_data_sock(uint8_t sock);

void ftpdSetAddr(struct inet_addr * inaddr);

uint8_t ftpd_routine(uint8_t * buff, uint32_t len);

#endif // __FTPD_H__
