#ifndef __IPLAYER_H__
#define __IPLAYER_H__

uint8_t initDhcp(uint8_t *buf, uint16_t buffer_size, uint8_t *mymac, uint8_t *myip, uint8_t *mynetmask, uint8_t *gwip, uint8_t *dnsip, uint8_t *dhcpsvrip );
uint8_t renewDhcp(uint8_t *buf, uint16_t buffer_size, uint8_t *mymac, uint8_t *myip, uint8_t *mynetmask, uint8_t *gwip, uint8_t *dnsip, uint8_t *dhcpsvrip );
uint8_t releaseDhcp(uint8_t *buf, uint16_t buffer_size, uint8_t *mymac, uint8_t *myip, uint8_t *mynetmask, uint8_t *gwip, uint8_t *dnsip, uint8_t *dhcpsvrip );

#endif
