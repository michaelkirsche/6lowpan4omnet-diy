//
// Copyright (C) 2013 Jonas Hartwig and Michael Kirsche, BTU Cottbus
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
// How to use? 
// Have a look at: www-rnks.informatik.tu-cottbus.de/~6lowpan4omnet

#ifndef __INET__SixLoWPAN_H_
#define __INET__SixLoWPAN_H_

#define null 0

#include <omnetpp.h>
#include <assert.h>
#include "MACAddress.h"
#include "IPv6Datagram.h"
#include "_6lowpanDatagram_m.h"
#include <queue>
#include <string.h>
#include <list>

using namespace std;

// Disable 6LoWPAN with this switch
// packets will simply be forwarded
#ifndef USE_6LOWPAN
#define USE_6LOWPAN 1
#endif

#ifndef DEBUG
#define DEBUG 1
#endif

#if USE_6LOWPAN
extern "C" {
    #include "sicslowpan.h"
	#include "netstack.h"
	#include "uip.h"
	#include "tcpip.h"
	#include "uipopt.h"
	#include "uip-icmp6.h"
	#include "packetbuf.h"
	#include "queuebuf.h"
	#include "contract.h"
	#include "uip-nd6.h"

	void sicslowpan_init();

	clock_time_t (* omnet_simtime)(void);

#if SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06
	struct sicslowpan_addr_context addr_contexts[SICSLOWPAN_CONF_MAX_ADDR_CONTEXTS];
#endif /* SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06 */

#if SICSLOWPAN_CONF_FRAG
	// fragmentation related values we need to save!
	uint16_t sicslowpan_len;
	uint16_t processed_ip_len;
	uint16_t my_tag;
	uint16_t reass_tag;
	rimeaddr_t frag_sender;
	struct timer reass_timer;
	uip_buf_t sicslowpan_aligned_buf;
	uint8_t *rime_ptr;
#endif /* SICSLOWPAN_CONF_FRAG */
}

/** 
 * Definition of buffers (extracted from Contiki)
 *
 * \author Adam Dunkels <adam@dunkels.com>
 * Copyright (c) 2001-2012, Adam Dunkels.
 */
#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF                      ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP6_ERROR_BUF            ((struct uip_icmp6_error *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN])
#define UIP_TCP_BUF                        ((struct uip_tcp_hdr *)&uip_buf[UIP_LLH_LEN + UIP_IPH_LEN])
#define sicslowpan_buf                                            (sicslowpan_aligned_buf.u8)
#define SICSLOWPAN_IP_BUF		            ((struct uip_ip_hdr *)&sicslowpan_buf[UIP_LLH_LEN])
#define SICSLOWPAN_UDP_BUF                 ((struct uip_udp_hdr *)&sicslowpan_buf[UIP_LLIPH_LEN])
#define UIP_ND6_RS_BUF            	               ((uip_nd6_rs *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_RA_BUF            	               ((uip_nd6_ra *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_NS_BUF            	               ((uip_nd6_ns *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_NA_BUF            	               ((uip_nd6_na *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_REDIRECT_BUF      	         ((uip_nd6_redirect *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ND6_OPT_HDR_BUF  		          ((uip_nd6_opt_hdr *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
#define UIP_ND6_OPT_PREFIX_BUF 		  ((uip_nd6_opt_prefix_info *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])
#define UIP_ND6_OPT_MTU_BUF 		          ((uip_nd6_opt_mtu *)&uip_buf[uip_l2_l3_icmp_hdr_len + nd6_opt_offset])


/** 
 * Reassembly related code from Contiki
 *
 * \author Adam Dunkels <adam@dunkels.com>
 * Copyright (c) 2001-2012, Adam Dunkels.
 */
#if SICSLOWPAN_CONF_FRAG
#define RIME_FRAG_PTR           (rime_ptr)
#define RIME_FRAG_DISPATCH_SIZE 0   /* 16 bit */
#define RIME_FRAG_TAG           2   /* 16 bit */
#define RIME_FRAG_OFFSET        4   /* 8 bit */
#define GET16(ptr,index) (((uint16_t)((ptr)[index] << 8)) | ((ptr)[(index) + 1]))
#define SET16(ptr,index,value) do {     \
  (ptr)[index] = ((value) >> 8) & 0xff; \
  (ptr)[index + 1] = (value) & 0xff;    \
} while(0)
#endif /* SICSLOWPAN_CONF_FRAG */

/** 
 * Structures and definitions for TCP
 * taken from Contiki's uip6.c
 *
 * \author Adam Dunkels <adam@dunkels.com>
 * Copyright (c) 2001-2012, Adam Dunkels.
 */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#endif /* USE_6LOWPAN */

class _6lowpan : public cSimpleModule
{
  protected:
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    virtual int numInitStages() const  {return 2;}

  private:
    struct contiki_config
    {
#if USE_6LOWPAN
    	// Contiki related values
#if SICSLOWPAN_CONF_FRAG
    	uint16_t sicslowpan_len;
    	/**
    	 * Length of the ip packet already sent / received.
    	 * It includes IP and transport headers.
    	 */
    	uint16_t processed_ip_len;

    	/** Datagram tag to be put in the fragments I send. */
    	uint16_t my_tag;

    	/** When reassembling, the tag in the fragments being merged. */
    	uint16_t reass_tag;

    	/** When reassembling, the source address of the fragments being merged */
    	rimeaddr_t frag_sender;

    	/** Reassembly %process %timer. */
    	struct timer reass_timer;

    	uint8_t* lowpan_buf;
#endif /* SICSLOWPAN_CONF_FRAG */
#endif /* USE_6LOWPAN */
    };

    struct config
    {
    	// One memory element
    	bool connectedToLowpan;
    	// Our IPv6 link local address
        IPv6Address lladdr;
        // Our link layer address, can only be MAC
        MACAddress mac;
        struct contiki_config* contikiMemory;
        int interfaceId;
        // Our HC06 compression context id
        int contextSet;

        config()
        {
#if USE_6LOWPAN
        	connectedToLowpan = false;
        	contikiMemory = null;
        	interfaceId = -1;
        	contextSet = -1;
#endif /* USE_6LOWPAN */
        }
    };

#if USE_6LOWPAN
    // Management struct to save contiki generated packets
    struct contiki_packet
    {
    	// Simple as it is: a byte stream
    	uint16_t length;
    	uint8_t* payload;

    	contiki_packet(uint16_t l, uint8_t* payl)
    	{
    		length = l;
    		payload = new uint8_t[l];
    		memcpy(payload, payl, l);
    	}
    	contiki_packet()
    	{
    		length = 0;
    		payload = null;
    	}
    };

#if DEBUG
    static string artif_payl;
#endif /* DEBUG */
    static int fragmentCount;
    static queue< struct contiki_packet > packetQueue;
#endif /* USE_6LOWPAN */

    struct config** configuration;

#if USE_6LOWPAN
    // the implementation of the "bridge" between Contiki and OMNeT++/INET
	// does not need to do much, yet
    static void omnet_mac_init()
    {
    }

    // but to save the generated packets in the queue!
    static void omnet_mac_send(mac_callback_t sent_callback , void * ptr)
    {
    	fragmentCount++;
    	struct contiki_packet data(packetbuf_datalen(), (uint8_t*)packetbuf_dataptr());
    	packetQueue.push(data);
    }

    static void omnet_mac_input()
    {
    }

    static int omnet_mac_on()
    {
    	return 0;
    }

    static int omnet_mac_off(int keep_radio_on)
    {
    	return 0;
    }

    static unsigned short omnet_mac_channel_check_interval()
    {
    	return 0;
    }

    // And make Contiki's "clock count" available!
    static clock_time_t omnet_sim_time()
    {
    	return simTime().raw();
    }

    static void omnet_netstack_input()
    {
    }
#endif /* USE_6LOWPAN */

    void handleMessageFromHigher(cMessage *msg);
    void handleMessageFromLower(cMessage *msg);

    void switchContext(int context);
    void saveContext(int context);
    void registerContext(int context);
    list<cPacket*> processIPv6Packet(IPv6Datagram* packet, int gateIndex);
    IPv6Datagram* processLowpanPacket(_6lowpanDatagram* packet);
    bool isConnectedToLowpan(cGate *toMac);
};
#endif /* __INET__SixLoWPAN_H_ */
