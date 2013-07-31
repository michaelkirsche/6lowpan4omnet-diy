/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * @(#)$Id: contiki-conf.h,v 1.12 2009/09/09 21:11:24 adamdunkels Exp $
 *
 */

/**
 * \file
 *         	Configuration file for the OMNeT++ platform.
 *			Including a list of parameters for the 6LoWPAN protocol (and the associated protocols)
 * 			--> refer to the end of the file
 * \author
 *         Jonas Hartwig and Michael Kirsche <michael.kirsche@tu-cottbus.de>
 */

#ifndef __CONTIKI_CONF_H__
#define __CONTIKI_CONF_H__

#include <inttypes.h>

#define CC_CONF_REGISTER_ARGS          1
#define CC_CONF_FUNCTION_POINTER_ARGS  1
#define CC_CONF_FASTCALL
#define CC_CONF_VA_ARGS                1
/*#define CC_CONF_INLINE                 inline*/

#define CCIF
#define CLIF

/* Compatibility for older releases of Contiki */
typedef uint8_t   u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef  int32_t s32_t;
typedef unsigned short uip_stats_t;

/* Generic settings for the uIP stack */
#define UIP_CONF_UDP             	1
#define UIP_CONF_TCP             	1
#define UIP_CONF_MAX_CONNECTIONS 	40
#define UIP_CONF_MAX_LISTENPORTS 	40
//#define UIP_CONF_BUFFER_SIZE     	420		// let buffer size be determined by MTU + link level header length
#define UIP_CONF_BYTE_ORDER      	UIP_LITTLE_ENDIAN
#define UIP_CONF_TCP       			1
#define UIP_CONF_TCP_SPLIT       	1
#define UIP_CONF_UDP_CHECKSUMS   	1
#define UIP_CONF_LOGGING         	1
#define UIP_CONF_STATISTICS			1


/* Enable or disable IPv6 support (default: enabled) */
#define UIP_CONF_IPV6 	1

/* When using IPv6, then enable 6LoWPAN and the following options */
/* adjust as needed -> refer to the comment lists below for further descriptions */
#if UIP_CONF_IPV6
#define SICSLOWPAN_CONF_COMPRESSION_IPV6        0 
#define SICSLOWPAN_CONF_COMPRESSION_HC1         1 
#define SICSLOWPAN_CONF_COMPRESSION_HC06        2 
#define SICSLOWPAN_CONF_COMPRESSION             SICSLOWPAN_CONF_COMPRESSION_HC06
#define SICSLOWPAN_CONF_FRAG   					1
#define SICSLOWPAN_REASS_MAXAGE   				20
#define SICSLOWPAN_CONF_MAX_ADDR_CONTEXTS   	100
#define UIP_CONF_LL_802154 						1
#define UIP_CONF_IPV6_CHECKS     				1
#define UIP_CONF_IPV6_QUEUE_PKT  				1
#define UIP_CONF_IPV6_REASSEMBLY 				0
#define UIP_CONF_NETIF_MAX_ADDRESSES  			3
#define UIP_CONF_ND6_MAX_PREFIXES     			3
#define UIP_CONF_ND6_MAX_NEIGHBORS    			4
#define UIP_CONF_ND6_MAX_DEFROUTERS   			2
#define UIP_CONF_ICMP6           				1
#define NETSTACK_CONF_MAC 						omnet_mac_driver
#define NETSTACK_CONF_NETWORK 					sicslowpan_driver
#endif /* UIP_CONF_IPV6 */


/*	The following comments list available options for uIP, IPv6, 6LoWPAN, and the transport layer protocols */
/*  ------------------------------------------------------------------------------------------------------- */
/* uIP options
#define 	UIP_FIXEDADDR
 	Determines if uIP should use a fixed IP address or not.
#define 	UIP_PINGADDRCONF
 	Ping IP address assignment.
#define 	UIP_FIXEDETHADDR
	Specifies if the uIP ARP module should be compiled with a fixed Ethernet MAC address or not.
#define 	UIP_CONF_LL_802154 						1
	Specifies, what type of Layer2 addresses are used
	e.g., 0 = 802.11 6-Byte MAC addresses, 1 = 802.15.4 long (8-Byte) and short (2-Byte) addresses
*/

/* IPv6 options
#define 	UIP_LINK_MTU   1280
 	The maximum transmission unit at the IP Layer.
#define 	UIP_CONF_IPV6   1
 	Do we use IPv6 or not (default: yes).
#define 	UIP_CONF_IPV6_QUEUE_PKT   0
 	Do we do per neighbor queuing during address resolution (default: no).
#define 	UIP_CONF_IPV6_CHECKS   1
 	Do we do IPv6 consistency checks (highly recommended, default: yes).
#define 	UIP_CONF_IPV6_REASSEMBLY   0
 	Do we do IPv6 fragmentation (default: no).
#define 	UIP_CONF_NETIF_MAX_ADDRESSES   3
 	Default number of IPv6 addresses associated to the node's interface.
#define 	UIP_CONF_ND6_MAX_PREFIXES   3
 	Default number of IPv6 prefixes associated to the node's interface.
#define 	UIP_CONF_ND6_MAX_NEIGHBORS   4
 	Default number of neighbors that can be stored in the neighbor cache.
#define 	UIP_CONF_ND6_MAX_DEFROUTERS   2
 	Minimum number of default routers. 
*/

/* 6LoWPAN options
#define 	SICSLOWPAN_REASS_MAXAGE   20
 	Timeout for packet reassembly at the 6lowpan layer (should be < 60s).
#define 	SICSLOWPAN_CONF_COMPRESSION   0
 	Do we compress the IP header or not (default: no).
#define 	SICSLOWPAN_CONF_MAX_ADDR_CONTEXTS   1
 	If we use IPHC compression, how many address contexts do we support.
#define 	SICSLOWPAN_CONF_FRAG   0
 	Do we support 6lowpan fragmentation. 
#define SICSLOWPAN_CONF_COMPRESSION_IPV6        0 
#define SICSLOWPAN_CONF_COMPRESSION_HC1         1 
#define SICSLOWPAN_CONF_COMPRESSION_HC01        2 
#define SICSLOWPAN_CONF_COMPRESSION             SICSLOWPAN_COMPRESSION_HC06
*/

/* UDP options
#define 	UIP_UDP   1
 	Toggles whether UDP support should be compiled in or not.
#define 	UIP_UDP_CHECKSUMS
 	Toggles if UDP checksums should be used or not.
#define 	UIP_UDP_CONNS
 	The maximum amount of concurrent UDP connections. 
*/

/* TCP options
#define 	UIP_TCP
 	Toggles whether UDP support should be compiled in or not.
#define 	UIP_ACTIVE_OPEN
 	Determines if support for opening connections from uIP should be compiled in.
#define 	UIP_CONNS
 	The maximum number of simultaneously open TCP connections.
#define 	UIP_LISTENPORTS
 	The maximum number of simultaneously listening TCP ports.
#define 	UIP_URGDATA
 	Determines if support for TCP urgent data notification should be compiled in.
#define 	UIP_RTO   3
 	The initial retransmission timeout counted in timer pulses.
#define 	UIP_MAXRTX   8
 	The maximum number of times a segment should be retransmitted before the connection should be aborted.
#define 	UIP_MAXSYNRTX   5
 	The maximum number of times a SYN segment should be retransmitted before a connection request should be deemed to have been unsuccessful.
#define 	UIP_TCP_MSS   (UIP_BUFSIZE - UIP_LLH_LEN - UIP_TCPIP_HLEN)
 	The TCP maximum segment size.
#define 	UIP_RECEIVE_WINDOW
 	The size of the advertised receiver's window.
#define 	UIP_TIME_WAIT_TIMEOUT   120
 	How long a connection should stay in the TIME_WAIT state. 
*/

/* clock settings to synchronize with OMNeT's clock */
typedef unsigned long clock_time_t;

#define CLOCK_CONF_SECOND 1000000


#define LOG_CONF_ENABLED 1

/* Not part of C99 but actually present */
int strcasecmp(const char*, const char*);

#endif /* __CONTIKI_CONF_H__ */
