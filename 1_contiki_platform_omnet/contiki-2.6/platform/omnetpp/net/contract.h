#ifndef __CONTRACT_H__
#define __CONTRACT_H__

#include "net/netstack.h"
#include "net/uip.h"
#include "net/sicslowpan.h"

#define null 0

#if SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06
//0 is reserved
static int currentGlobalContextIndex = 1;
#endif

void (* bridge_mac_init)(void);

void (* bridge_mac_send)(mac_callback_t sent_callback , void *ptr);

void (* bridge_mac_input)(void);

int (* bridge_mac_on)(void);

int (* bridge_mac_off)(int keep_radio_on);

unsigned short (* bridge_mac_channel_check_interval)(void);

void (*bridge_netstack_input)(void);
#endif
