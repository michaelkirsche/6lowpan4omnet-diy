#include "contract.h"

static void init()
{
	if(bridge_mac_init != null)
		bridge_mac_init();
}

static void send(mac_callback_t sent_callback , void *ptr)
{
	if(bridge_mac_send != null)
		bridge_mac_send(sent_callback, ptr);
}

static void input()
{
	if(bridge_mac_input != null)
		bridge_mac_input();
}

static int on()
{
	if(bridge_mac_on != null)
		return bridge_mac_on();
	else
		return 0;
}

static int off(int keep_radio_on)
{
	if(bridge_mac_off != null)
		return bridge_mac_off(keep_radio_on);
	else
		return 0;
}

static unsigned short cci()
{
	if(bridge_mac_channel_check_interval != null)
		return bridge_mac_channel_check_interval();
	return 0;
}

const struct mac_driver omnet_mac_driver =
{
		"OMNeT++",
		init,//omnet_mac_init,
		send,//omnet_mac_send,
		input,//omnet_mac_input,
		on,//omnet_mac_on,
		off,//omnet_mac_off,
		cci//omnet_mac_channel_check_interval
};

void __wrap_tcpip_input()
{
	bridge_netstack_input();
}
