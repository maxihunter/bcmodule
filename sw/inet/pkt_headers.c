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

#include "pkt_headers.h"

void extract_eth_header(uint8_t* buff, struct eth_header* ethd) {
	memcpy((uint8_t*)ethd, buff, sizeof(struct eth_header));
}

void extract_ip_header(uint8_t* buff, struct ip_header* iphd) {
	memcpy((uint8_t*)iphd, buff+sizeof(struct eth_header), sizeof(struct ip_header));
}

uint8_t* get_pkt_data(uint8_t* buff, const struct ip_header* iphd) {
	if (IP_HDR_GET_IHL(iphd->version_ihl) == 5) {
		return buff + sizeof(struct eth_header) + sizeof(struct ip_header);
	}
	return buff;
}
