
#include "dhcp.h"
#include "net.h"
#include "enc28j60.h"
#include <inttypes.h>
#include <stdbool.h>

uint8_t initDhcp(uint8_t *buf, uint16_t buffer_size, uint8_t *mymac, uint8_t *myip, uint8_t *mynetmask, uint8_t *gwip, uint8_t *dnsip, uint8_t *dhcpsvrip ) {
  int plen = 0;
  uint8_t dhcpState = 0;
  long lastDhcpRequest = HAL_GetTick();
  _Bool gotIp = false;
  uint8_t dhcpTries = 10;	// After 10 attempts fail gracefully so other action can be carried out

  dhcp_start( buf, mymac, myip, mynetmask,gwip, dnsip, dhcpsvrip );

  while( !gotIp ) {
    // handle ping and wait for a tcp packet
    plen = enc28j60PacketReceive(buffer_size, buf);
      check_for_dhcp_answer( buf, plen);
      dhcpState = dhcp_state();
      // we are idle here
      if( dhcpState != DHCP_STATE_OK ) {
          if (HAL_GetTick() > (lastDhcpRequest + 10000L) ){
              lastDhcpRequest = HAL_GetTick();
              if( dhcpTries <= 0 ) 
                  return 0;		// Failed to allocate address
                                // send dhcp
              dhcp_start( buf, mymac, myip, mynetmask,gwip, dnsip, dhcpsvrip );
              dhcpTries--;
          }
      } else {
          if( !gotIp ) {
              gotIp = true;
          }
      }
  }
  return 1;
}
