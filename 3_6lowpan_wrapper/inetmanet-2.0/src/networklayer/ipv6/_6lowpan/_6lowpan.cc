//
// Copyright (C) 2013 Jonas Hartwig and Michael Kirsche, BTU Cottbus
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//
// How to use? 
// Have a look at: www-rnks.informatik.tu-cottbus.de/~6lowpan4omnet
//

#include "_6lowpan.h"
#include <string.h>
#include <InterfaceTableAccess.h>
#include "IPassiveQueue.h"
#include "IPv6InterfaceData.h"
#include "IPv6Datagram.h"
#include "IPv6ControlInfo.h"
#include "IPv6Address.h"
#include "UDPPacket.h"
#include "TCPSegment.h"
#include "ICMPv6Message_m.h"
#include "IPv6NeighbourDiscovery.h"
#include "IPv6NeighbourDiscoveryAccess.h"
#include "RoutingTable6.h"
#include "RoutingTable6Access.h"
#include "InterfaceToken.h"

// Module Name _6lowpan to avoid naming conflict --> might be changed in the next release though
Define_Module(_6lowpan);

#if USE_6LOWPAN
    int _6lowpan::fragmentCount = 0;
    queue< struct _6lowpan::contiki_packet > _6lowpan::packetQueue;
#if DEBUG
    string _6lowpan::artif_payl = "this is my artificial payload which has to be rebuild correctly...0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzy0123456789abcdefghijklmnopqrstuvwxzythis is my artificial payload which has to be rebuild correctly...";
#endif /* DEBUG */
#endif /* USE_6LOWPAN */

void _6lowpan::initialize(int stage)
{
#if USE_6LOWPAN
	if(stage == 0)
	{
#if DEBUG
	    printf("Compression options: IPv6=%u \t HC1=%u \t HC06=%u\n", SICSLOWPAN_COMPRESSION_IPV6,SICSLOWPAN_COMPRESSION_HC1,SICSLOWPAN_COMPRESSION_HC06);
	    printf("Compression setting: %i\n", SICSLOWPAN_CONF_COMPRESSION);
#endif /* DEBUG */
		// Initialize Contiki
		queuebuf_init();
		sicslowpan_init();
		// Set the function pointer in Contiki's contract.c to static functions in OMNeT++
		if(bridge_mac_init == null)
			bridge_mac_init = omnet_mac_init;
		if(bridge_mac_send == null)
			bridge_mac_send = omnet_mac_send;
		if(bridge_mac_input == null)
			bridge_mac_input = omnet_mac_input;
		if(bridge_mac_on == null)
			bridge_mac_on = omnet_mac_on;
		if(bridge_mac_off == null)
			bridge_mac_off = omnet_mac_off;
		if(bridge_mac_channel_check_interval == null)
			bridge_mac_channel_check_interval = omnet_mac_channel_check_interval;
		if(omnet_simtime == null)
			omnet_simtime = omnet_sim_time;
		if(bridge_netstack_input == null)
			bridge_netstack_input = omnet_netstack_input;
	}

	if(stage == 1)
	{
		// initialize the memory to simulate multiple Contiki instances
		// memory gets identified by gate id
		configuration = new struct config*[gateSize("toMac")];
		IInterfaceTable *ift = InterfaceTableAccess().get();

			for (int i=0; i<gateSize("toMac"); i++)
			{
				if(ift != null)
				{
				configuration[i] = new struct config();
				cGate *toMac = gate("toMac", i);
				// Check if we are connected to a 802.15.4 interface
				if(isConnectedToLowpan(toMac))
				{
					InterfaceEntry* ie = ift->getInterfaceByNetworkLayerGateIndex(toMac->getIndex());
					if(ie != null)
					{
						// save the necessary data
						configuration[i]->connectedToLowpan = true;
						configuration[i]->contikiMemory = new contiki_config();
						configuration[i]->interfaceId = ie->getInterfaceId();
					}
				}
			}
		}
	}
#endif /* USE_6LOWPAN */
}

bool _6lowpan::isConnectedToLowpan(cGate *toMac)
{
	if(toMac != null)
	{
		if(toMac->isConnected())
		{
			// Are we connected to Mixnet (MiXiM + INET)??
			if(strcmp(toMac->getPathEndGate()->getOwnerModule()->getClassName(), "MixnetBridge") == 0)
			{
				cGate* mixnetBridgeLowerGateOut = toMac->getPathEndGate()->getOwnerModule()->gate("lowerGateOut");
				if(mixnetBridgeLowerGateOut != null)
				{
					if(mixnetBridgeLowerGateOut->isConnected())
					{
						// Connected to lowpan?
						if(strcmp(mixnetBridgeLowerGateOut->getPathEndGate()->getOwnerModule()->getClassName(), "CSMA802154") == 0)
						{
#if DEBUG
						    EV << "_6lowpan.cc:isConnectedToLowpan -> Connected to Mixnet \n";
#endif /* DEBUG */
						    return true;
						}
					}
				}
			}
			//Are we connected to INETMANET??
			if(dynamic_cast<IPassiveQueue*>(toMac->getPathEndGate()->getOwnerModule()) != null)
			{
				cGate* queueOutputGate = toMac->getPathEndGate()->getOwnerModule()->gate("out");
				if(queueOutputGate != null)
				{
					if(queueOutputGate->isConnected())
					{
						// Connected to lowpan?
						if(strcmp(queueOutputGate->getPathEndGate()->getOwnerModule()->getClassName(), "Ieee802154Mac") == 0
								||
							strcmp(queueOutputGate->getPathEndGate()->getOwnerModule()->getClassName(), "csma802154") == 0)
						{
#if DEBUG
						    EV << "_6lowpan.cc:isConnectedToLowpan -> Connected to INETMANET \n";
#endif /* DEBUG */
						    return true;
						}
					}
				}
			}
		}
	}
#if DEBUG
	EV << "_6lowpan.cc:isConnectedToLowpan -> isConnectedToLowpan = FALSE \n";
#endif /* DEBUG */
	return false;
}

void _6lowpan::switchContext(int context)
{
#if USE_6LOWPAN
#if DEBUG
	printf("\tSwitching context\n");
#endif /* DEBUG */
	// Reset the fragment counter back to 0
	fragmentCount = 0;
	// Clear the packet buffer
	packetbuf_clear();
	// Set own link local address, if it is not already set
	if(configuration[context]->lladdr.isUnspecified())
	{
		IInterfaceTable *ift = InterfaceTableAccess().get();
		InterfaceEntry* ie = ift->getInterfaceByNetworkLayerGateIndex(context);
		configuration[context]->mac = ie->getMacAddress();
	}
	// Set our own MAC address in Contiki if we have one
	// Check whether 48-Bit or EUI-64-Bit MAC addresses are used
	// INET 1.x & INET 2.x / INETMANET 1.x support only 48-Bit MAC addresses
	// INETMANET 2.0 support EUI-64-Bit MAC addresses (refer to /linklayer/contract/MACAddress.h)
	if(!configuration[context]->mac.isUnspecified())
	{
	    if(configuration[context]->mac.getAddressSize() == 8)
	    {
#if UIP_CONF_LL_802154 == 0
            error("6LoWPAN_Wrapper: Contiki's UIP Layer 2 address are set to 802.11 48-Bit but INET / INETMANET uses EUI-64-Bit");
#endif /* UIP_CONF_LL_802154 == 0*/
            // we use EUI-64-Bit MAC addresses
            uip_lladdr.addr[0] = (u8_t)configuration[context]->mac.getAddressByte(7);
            uip_lladdr.addr[1] = (u8_t)configuration[context]->mac.getAddressByte(6);
            uip_lladdr.addr[2] = (u8_t)configuration[context]->mac.getAddressByte(5);
            uip_lladdr.addr[3] = (u8_t)configuration[context]->mac.getAddressByte(4);
            uip_lladdr.addr[4] = (u8_t)configuration[context]->mac.getAddressByte(3);
            uip_lladdr.addr[5] = (u8_t)configuration[context]->mac.getAddressByte(2);
            uip_lladdr.addr[6] = (u8_t)configuration[context]->mac.getAddressByte(1);
            uip_lladdr.addr[7] = (u8_t)configuration[context]->mac.getAddressByte(0);
#if DEBUG
    printf("\tEUI-64-Bit MAC addresses used and set\n");
#endif /* DEBUG */
	    }
	    else if (configuration[context]->mac.getAddressSize() == 6) {
#if UIP_CONF_LL_802154 == 1
	        error("6LoWPAN_Wrapper: Contiki's UIP Layer 2 address are set to EUI-64-Bit but INET / INETMANET uses 48bit");
#endif /* UIP_CONF_LL_802154 == 1*/
	        // we use 48-Bit MAC addresses
	        uip_lladdr.addr[0] = (u8_t)configuration[context]->mac.getAddressByte(5);
            uip_lladdr.addr[1] = (u8_t)configuration[context]->mac.getAddressByte(4);
            uip_lladdr.addr[2] = (u8_t)configuration[context]->mac.getAddressByte(3);
            uip_lladdr.addr[3] = (u8_t)configuration[context]->mac.getAddressByte(2);
            uip_lladdr.addr[4] = (u8_t)configuration[context]->mac.getAddressByte(1);
            uip_lladdr.addr[5] = (u8_t)configuration[context]->mac.getAddressByte(0);
#if DEBUG
    printf("\t48-Bit MAC addresses used and set\n");
#endif /* DEBUG */
        }
	    else
	    {
	        error("6LoWPAN Wrapper: neither 48-Bit nor 64-Bit MAC addresses are used, this should never happen!");
	    }
	}

#if SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06
	// Set link local prefix to 6LoWPAN's context array (position 0)
	if(!configuration[context]->lladdr.isUnspecified())
	{
		const uint32* lladdr_raw = configuration[context]->lladdr.words();
		addr_contexts[0].prefix[0] = lladdr_raw[0] >> 24;
		addr_contexts[0].prefix[1] = lladdr_raw[0] >> 16;
		addr_contexts[0].prefix[2] = lladdr_raw[0] >> 8;
		addr_contexts[0].prefix[3] = lladdr_raw[0];
		addr_contexts[0].prefix[4] = lladdr_raw[1] >> 24;
		addr_contexts[0].prefix[5] = lladdr_raw[1] >> 16;
		addr_contexts[0].prefix[6] = lladdr_raw[1] >> 8;
		addr_contexts[0].prefix[7] = lladdr_raw[1];
	}
#endif /* SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06 */
#if SICSLOWPAN_CONF_FRAG
	// If we use fragmentation, reset all values
	sicslowpan_len = configuration[context]->contikiMemory->sicslowpan_len;
	frag_sender = configuration[context]->contikiMemory->frag_sender;
	my_tag = configuration[context]->contikiMemory->my_tag;
	processed_ip_len = configuration[context]->contikiMemory->processed_ip_len;
	reass_tag = configuration[context]->contikiMemory->reass_tag;
	reass_timer = configuration[context]->contikiMemory->reass_timer;
	if(configuration[context]->contikiMemory->lowpan_buf != null && processed_ip_len > 0)
		memcpy(SICSLOWPAN_IP_BUF, configuration[context]->contikiMemory->lowpan_buf, processed_ip_len);
#endif /* SICSLOWPAN_CONF_FRAG */
#if DEBUG
	printf("...done\n");
#endif /* DEBUG */
#endif /* USE_6LOWPAN */
}

void _6lowpan::saveContext(int context)
{
#if USE_6LOWPAN
#if DEBUG
	printf("\tsaving context\n");
#endif /* DEBUG */
#if SICSLOWPAN_CONF_FRAG
	// If we use fragmentation, then save variables to keep track
	configuration[context]->contikiMemory->sicslowpan_len = sicslowpan_len;
	configuration[context]->contikiMemory->frag_sender = frag_sender;
	configuration[context]->contikiMemory->my_tag = my_tag;
	configuration[context]->contikiMemory->processed_ip_len = processed_ip_len;
	configuration[context]->contikiMemory->reass_tag = reass_tag;
	configuration[context]->contikiMemory->reass_timer = reass_timer;
	if(configuration[context]->contikiMemory->lowpan_buf != null)
	{
		delete configuration[context]->contikiMemory->lowpan_buf;
		configuration[context]->contikiMemory->lowpan_buf = null;
	}
	if(processed_ip_len > 0)
	{
		configuration[context]->contikiMemory->lowpan_buf = new uint8_t[processed_ip_len];
		memcpy(configuration[context]->contikiMemory->lowpan_buf, SICSLOWPAN_IP_BUF, processed_ip_len);
	}
#endif /* SICSLOWPAN_CONF_FRAG */
#if DEBUG
	printf("...done\n");
#endif /* DEBUG */
#endif /* USE_6LOWPAN */
}

void _6lowpan::registerContext(int context)
{
#if USE_6LOWPAN
#if SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06
	// Did we already set our context information and do we have free slots left?
	if(configuration[context]->contextSet <= 0 && currentGlobalContextIndex < SICSLOWPAN_CONF_MAX_ADDR_CONTEXTS)
	{
		IInterfaceTable *ift = InterfaceTableAccess().get();
		if(ift != null)
		{
			InterfaceEntry* ie = ift->getInterfaceByNetworkLayerGateIndex(context);
			if(ie != null)
			{
				IPv6InterfaceData* id = ie->ipv6Data();
				if(id != null)
				{
					if(id->getNumAddresses() > 0)
					{
						for(int i = 0; i < id->getNumAddresses(); i++)
						{
							// Get our own address
							if(!id->getAddress(i).isLinkLocal() && !id->getAddress(i).isLoopback() && !id->getAddress(i).isUnspecified())
							{
#if DEBUG
								printf("\tsetting context %i\n", currentGlobalContextIndex);
#endif /* DEBUG */
								configuration[context]->contextSet = currentGlobalContextIndex;
								const uint32* raw = id->getAddress(i).words();

								// Add to the context
								addr_contexts[currentGlobalContextIndex].used = 1;
								addr_contexts[currentGlobalContextIndex].number = currentGlobalContextIndex;
								addr_contexts[currentGlobalContextIndex].prefix[0] = raw[0] >> 24;
								addr_contexts[currentGlobalContextIndex].prefix[1] = raw[0] >> 16;
								addr_contexts[currentGlobalContextIndex].prefix[2] = raw[0] >> 8;
								addr_contexts[currentGlobalContextIndex].prefix[3] = raw[0];
								addr_contexts[currentGlobalContextIndex].prefix[4] = raw[1] >> 24;
								addr_contexts[currentGlobalContextIndex].prefix[5] = raw[1] >> 16;
								addr_contexts[currentGlobalContextIndex].prefix[6] = raw[1] >> 8;
								addr_contexts[currentGlobalContextIndex].prefix[7] = raw[1];
#if DEBUG
								printf(": %x%x:%x%x:%x%x:%x%x", addr_contexts[currentGlobalContextIndex].prefix[0],
										addr_contexts[currentGlobalContextIndex].prefix[1],
										addr_contexts[currentGlobalContextIndex].prefix[2],
										addr_contexts[currentGlobalContextIndex].prefix[3],
										addr_contexts[currentGlobalContextIndex].prefix[4],
										addr_contexts[currentGlobalContextIndex].prefix[5],
										addr_contexts[currentGlobalContextIndex].prefix[6],
										addr_contexts[currentGlobalContextIndex].prefix[7]);
								printf(" from address: %s", id->getAddress(0).str().c_str());
								printf(" with lladdr: %s\n", id->getLinkLocalAddress().str().c_str());
#endif /* DEBUG */
								currentGlobalContextIndex++;
							}
						}
					}
				}
			}
		}
	}
#endif /* SICSLOWPAN_CONF_COMPRESSION == SICSLOWPAN_COMPRESSION_HC06 */
#endif /* USE_6LOWPAN */
}

void _6lowpan::handleMessage(cMessage *msg)
{
#if DEBUG
	printf("module %s (ID: %i) received a message %s (ID: %ld)\n", this->getOwner()->getOwner()->getName(), getId(), msg->getName(), msg->getId());
#endif /* DEBUG */
	if(msg->isSelfMessage())
	{
#if DEBUG
	printf("...from self\n");
#endif /* DEBUG */
	}
	else
	{
		if(msg->getArrivalGate()->isName("fromIPv6"))
		{
#if DEBUG
	printf("...from IPv6\n");
#endif /* DEBUG */
			// From higher layer --> IPv6: process and send out
			handleMessageFromHigher(msg);
		}
		if(msg->getArrivalGate()->isName("fromMac"))
		{
#if DEBUG
	printf("...from MAC\n");
#endif /* DEBUG */
			//from lower layer -> MAC: process and send out
			handleMessageFromLower(msg);
		}
	}
}

void _6lowpan::handleMessageFromHigher(cMessage *msg)
{
	// Identify the memory slot, necessary to simulate Contiki instances
	int gateIndex = msg->getArrivalGate()->getIndex();
#if USE_6LOWPAN

	// Check, if we are connected to 802.15.4?
	if(configuration[gateIndex]->connectedToLowpan)
	{
		// Are we handling an IPv6 paket?
		if(dynamic_cast<IPv6Datagram*>(msg) != null)
		{
#if DEBUG
		    printf("...handleMessageFromHigher\n");
#endif /* DEBUG */
		    // Register our IPv6 address
			registerContext(gateIndex);
			// Recreate the old values
			switchContext(gateIndex);
			// Process the packet
			list<cPacket*> datagrams = processIPv6Packet((IPv6Datagram*)msg, gateIndex);
			// Save the variables!
			saveContext(gateIndex);
#if DEBUG
			printf("...done\n");
			printf("\t%i datagrams to send\n", datagrams.size());
#endif /* DEBUG */
			// Send all generated packets
			int count = datagrams.size();
			for(int i = 0; i < count; i++)
			{
				// In case we have more than one packet? --> use a delay!
				cPacket* toSend = datagrams.front();
				this->sendDelayed(toSend, i * par("fragmentDelay").doubleValue() / simTime().getScale(), "toMac", gateIndex);;
#if DEBUG
				printf("\tsending fragment %i\n", i);
#endif /* DEBUG */
				datagrams.pop_front();
			}
		}
		else
		{
#if DEBUG
			printf(": non-IPv6 packet %s (should not happen), forwarding...\n", msg->getName());
#endif /* DEBUG */
			send(msg, "toMac", gateIndex);
		}
	}
	else
	{
		// When we are not connected to 802.15.4 but we register ipaddress anyway for compression
		registerContext(gateIndex);
#endif /* USE_6LOWPAN */
		send(msg, "toMac", gateIndex);
#if USE_6LOWPAN
	}
#endif /* USE_6LOWPAN */
}

void _6lowpan::handleMessageFromLower(cMessage *msg)
{
    // Identify the memory slot, necessary to simulate Contiki instances
	int gateIndex = msg->getArrivalGate()->getIndex();
#if USE_6LOWPAN
	if(configuration[gateIndex]->connectedToLowpan)
	{
		if(dynamic_cast<_6lowpanDatagram*>(msg) != null)
		{
#if DEBUG
			printf("...handleMEssageFromLower \n");
#endif /* DEBUG */
		    // Restore the old Contiki values
			switchContext(gateIndex);
			// Recreate an INET IPv6 packet
			IPv6Datagram* packet = processLowpanPacket((_6lowpanDatagram*)msg);
			// Save the modified values
			saveContext(gateIndex);

			// Did we actually get a packet?
			// Might not happen in case we were reassembling!
			if(packet != null)
				send(packet, "toIPv6", gateIndex);
		}
		else
#if DEBUG
		{
			printf("received non 6lowpan packet %s , forwarding...\n", msg->getName());
#endif /* DEBUG */
			send(msg, "toIPv6", gateIndex);
#if DEBUG
		}
#endif /* DEBUG */
	}
	else
#endif /* USE_6LOWPAN */
		send(msg, "toIPv6", gateIndex);
}

list<cPacket*> _6lowpan::processIPv6Packet(IPv6Datagram* ipPacket, int gateIndex)
{
	//we need a result list
	list<cPacket*> result;
#if USE_6LOWPAN
	cPacket* encapsulated = ipPacket->getEncapsulatedPacket();

	/* IP header
	struct uip_ip_hdr {
	  u8_t vtc;
	  u8_t tcflow;
	  u16_t flow;
	  u8_t len[2];
	  u8_t proto, ttl;
	  uip_ip6addr_t srcipaddr, destipaddr;
	};*/
	//set the currently known length of the ip packet
	uip_len = UIP_IPH_LEN;

	UIP_IP_BUF->vtc = 0x60;
	UIP_IP_BUF->tcflow = ipPacket->getTrafficClass();
	UIP_IP_BUF->flow = ipPacket->getFlowLabel();
	UIP_IP_BUF->ttl = ipPacket->getHopLimit();
	uip_ip6addr_t srcipaddr, destipaddr;

	const uint32* rawSrcAddress = ipPacket->getSrcAddress().words();
	uip_ip6addr(&srcipaddr,
			rawSrcAddress[0] >> 16, rawSrcAddress[0],
			rawSrcAddress[1] >> 16, rawSrcAddress[1],
			rawSrcAddress[2] >> 16, rawSrcAddress[2],
			rawSrcAddress[3] >> 16, rawSrcAddress[3]);
	UIP_IP_BUF->srcipaddr = srcipaddr;

	const uint32* rawDestAddress = ipPacket->getDestAddress().words();
	uip_ip6addr(&destipaddr,
			rawDestAddress[0] >> 16, rawDestAddress[0],
			rawDestAddress[1] >> 16, rawDestAddress[1],
			rawDestAddress[2] >> 16, rawDestAddress[2],
			rawDestAddress[3] >> 16, rawDestAddress[3]);
	UIP_IP_BUF->destipaddr = destipaddr;

	// TODO current implementation does not support extension headers :(
	if(ipPacket->getExtensionHeaderArraySize() > 0)
	    error("we don't support extension headers yet");

	//is the transport layer protocol icmpv6?
	if(dynamic_cast<ICMPv6Message*>(encapsulated) != null)
	{
#if DEBUG
		printf("\tprocessing ICMPv6 packet\n");
#endif /* DEBUG */
		/* ICMP header
		struct uip_icmp_hdr {
		u8_t type, icode;
		u16_t icmpchksum;
		};*/
		// increase the ip length by ICMP header length
		// if the length is wrong we will loose data in the process
		uip_len += UIP_ICMPH_LEN;

		ICMPv6Message* icmpPacket = (ICMPv6Message*)encapsulated;

		UIP_IP_BUF->proto = UIP_PROTO_ICMP6;
		UIP_ICMP_BUF->icode = 0;
		uint8_t nd6_opt_offset = 0;

		// process message type
		if(dynamic_cast<IPv6RouterSolicitation*>(encapsulated) != null)
		{
#if DEBUG
		    printf("(ND: RS)\n");
#endif /* DEBUG */
			/*
			typedef struct uip_nd6_rs {
			  uint32_t reserved;
			} uip_nd6_rs;
			 */
			uip_len += UIP_ND6_RS_LEN;
			nd6_opt_offset = UIP_ND6_RS_LEN;
			UIP_ICMP_BUF->type = ICMP6_RS;

			IPv6RouterSolicitation* rs = (IPv6RouterSolicitation*)encapsulated;

			// SLLAO
			if(!rs->getSourceLinkLayerAddress().isUnspecified())
			{
				UIP_ND6_OPT_HDR_BUF->type = UIP_ND6_OPT_SLLAO;
				UIP_ND6_OPT_HDR_BUF->len = UIP_ND6_OPT_LLAO_LEN >> 3;

				// ND-RouterSolicitation: check and switch between 48/64-Bit MAC addresses
				uint8_t addr[8];
				if(rs->getSourceLinkLayerAddress().getFlagEui64() == true)
				{
#if DEBUG
				    printf("(ND: RS) - getSourceLinkLayerAddress -> EUI-64 MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
                        addr[i] = rs->getSourceLinkLayerAddress().getAddressByte(i);
                    }
				} /* if (SourceLinkLayerAddress == EUI-64) */
				else
				{
#if DEBUG
				    printf("(ND: RS) - getSourceLinkLayerAddress -> 48-Bit MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE; i++) {
                        addr[i] = rs->getSourceLinkLayerAddress().getAddressByte(i);
                    }
				} /* if (SourceLinkLayerAddress == EUI-48) */

				memcpy((uint8_t*)UIP_ND6_OPT_HDR_BUF + UIP_ND6_OPT_DATA_OFFSET, addr, UIP_LLADDR_LEN);

				uip_len += UIP_ND6_OPT_LLAO_LEN;
				nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;//optional extension length, used to calculate offset for optional parts
			}
		}
		else if(dynamic_cast<IPv6RouterAdvertisement*>(encapsulated) != null)
		{
#if DEBUG
			printf("(ND: RA)\n");
#endif /* DEBUG */
			/*
			typedef struct uip_nd6_ra {
			  uint8_t cur_ttl;
			  uint8_t flags_reserved;
			  uint16_t router_lifetime;
			  uint32_t reachable_time;
			  uint32_t retrans_timer;
			} uip_nd6_ra;
			 */
			uip_len += UIP_ND6_RA_LEN;
			nd6_opt_offset = UIP_ND6_RA_LEN;
			UIP_ICMP_BUF->type = ICMP6_RA;

			IPv6RouterAdvertisement* ra = (IPv6RouterAdvertisement*)encapsulated;

			UIP_ND6_RA_BUF->cur_ttl = (uint8_t)ra->getCurHopLimit();
			UIP_ND6_RA_BUF->flags_reserved = 0;
			if(ra->getOtherStatefulConfFlag())
				UIP_ND6_RA_BUF->flags_reserved |= 0x80;
			if(ra->getManagedAddrConfFlag())
				UIP_ND6_RA_BUF->flags_reserved |= 0x40;
			UIP_ND6_RA_BUF->router_lifetime = uip_htons(ra->getRouterLifetime());
			UIP_ND6_RA_BUF->reachable_time = uip_htonl(ra->getReachableTime());
			UIP_ND6_RA_BUF->retrans_timer = uip_htonl(ra->getRetransTimer());

			//MTU
			if(ra->getMTU() > 0)
			{
				/*
				typedef struct uip_nd6_opt_mtu {
  	  	  	  	  uint8_t type;
 	  	  	  	  uint8_t len;
  	  	  	  	  uint16_t reserved;
  	  	  	  	  uint32_t mtu;
				} uip_nd6_opt_mtu;
				 */
				UIP_ND6_OPT_MTU_BUF->type = UIP_ND6_OPT_MTU;
				UIP_ND6_OPT_MTU_BUF->len = UIP_ND6_OPT_MTU_LEN >> 3;
				UIP_ND6_OPT_MTU_BUF->reserved = 0;
				UIP_ND6_OPT_MTU_BUF->mtu = uip_htonl(ra->getMTU());

				uip_len += UIP_ND6_OPT_MTU_LEN;
				nd6_opt_offset += UIP_ND6_OPT_MTU_LEN;
			}
			// SLLAO
			if(!ra->getSourceLinkLayerAddress().isUnspecified())
			{
				UIP_ND6_OPT_HDR_BUF->type = UIP_ND6_OPT_SLLAO;
				UIP_ND6_OPT_HDR_BUF->len = UIP_ND6_OPT_LLAO_LEN >> 3;

				// ND-RouteAnnouncement: check and switch between 48/64-Bit MAC address support
				uint8_t addr[8];
				if(ra->getSourceLinkLayerAddress().getFlagEui64() == true)
				{
#if DEBUG
				    printf("(ND: RA) - getSourceLinkLayerAddress -> EUI-64 MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
				        addr[i] = ra->getSourceLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-64) */
				else
				{
#if DEBUG
				    printf("(ND: RA) - getSourceLinkLayerAddress -> 48-Bit MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE; i++) {
				        addr[i] = ra->getSourceLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-48) */

				memcpy((uint8_t*)UIP_ND6_OPT_HDR_BUF + UIP_ND6_OPT_DATA_OFFSET, addr, UIP_LLADDR_LEN);

				uip_len += UIP_ND6_OPT_LLAO_LEN;
				nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
			}
			// Prefix
			if(ra->getPrefixInformationArraySize() > 0)
			{
				/*
				typedef struct uip_nd6_opt_prefix_info {
  	  	  	  	  uint8_t type;
 	  	  	  	  uint8_t len;
  	  	  	  	  uint8_t preflen;
  	  	  	  	  uint8_t flagsreserved1;
  	  	  	  	  uint32_t validlt;
  	  	  	  	  uint32_t preferredlt;
  	  	  	  	  uint32_t reserved2;
  	  	  	  	  uip_ipaddr_t prefix;
				} uip_nd6_opt_prefix_info ;
				 */
				for(unsigned int i = 0; i < ra->getPrefixInformationArraySize(); i++)
				{
					IPv6NDPrefixInformation info = ra->getPrefixInformation(i);
				    UIP_ND6_OPT_PREFIX_BUF->type = UIP_ND6_OPT_PREFIX_INFO;
				    UIP_ND6_OPT_PREFIX_BUF->len = UIP_ND6_OPT_PREFIX_INFO_LEN / 8;
				    UIP_ND6_OPT_PREFIX_BUF->preflen = (uint8_t)info.getPrefixLength();
				    UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 = 0;
				    if(info.getOnlinkFlag())
				    	UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 |= 0x80;
				    if(info.getAutoAddressConfFlag())
				    	UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 |= 0x40;
				    UIP_ND6_OPT_PREFIX_BUF->validlt = uip_htonl(info.getValidLifetime());
				    UIP_ND6_OPT_PREFIX_BUF->preferredlt = uip_htonl(info.getPreferredLifetime());
				    UIP_ND6_OPT_PREFIX_BUF->reserved2 = 0;

				    uip_ip6addr_t prefix;
					const uint32* raw = info.getPrefix().words();
					uip_ip6addr(&prefix,
							raw[0] >> 16, raw[0],
							raw[1] >> 16, raw[1],
							raw[2] >> 16, raw[2],
							raw[3] >> 16, raw[3]);
				    UIP_ND6_OPT_PREFIX_BUF->prefix = prefix;

				    nd6_opt_offset += UIP_ND6_OPT_PREFIX_INFO_LEN;
				    uip_len += UIP_ND6_OPT_PREFIX_INFO_LEN;
				  }
			}
		}
		else if(dynamic_cast<IPv6NeighbourSolicitation*>(encapsulated) != null)
		{
#if DEBUG
			printf("(ND: NS)");
#endif /* DEBUG */
			/*
			typedef struct uip_nd6_ns {
   	  	  	  uint32_t reserved;
  	  	  	  uip_ipaddr_t tgtipaddr;
			} uip_nd6_ns;
			 */
			uip_len += UIP_ND6_NS_LEN;
			nd6_opt_offset = UIP_ND6_NS_LEN;
			UIP_ICMP_BUF->type = ICMP6_NS;

			IPv6NeighbourSolicitation* ns = (IPv6NeighbourSolicitation*)encapsulated;

		    uip_ip6addr_t tgtipaddr;
			const uint32* raw = ns->getTargetAddress().words();
			uip_ip6addr(&tgtipaddr,
					raw[0] >> 16, raw[0],
					raw[1] >> 16, raw[1],
					raw[2] >> 16, raw[2],
					raw[3] >> 16, raw[3]);
			UIP_ND6_NS_BUF->tgtipaddr = tgtipaddr;

			// SLLAO
			if(!ns->getSourceLinkLayerAddress().isUnspecified())
			{
				UIP_ND6_OPT_HDR_BUF->type = UIP_ND6_OPT_SLLAO;
				UIP_ND6_OPT_HDR_BUF->len = UIP_ND6_OPT_LLAO_LEN >> 3;

				// ND-NeighborSolicitation -> Check and switch between 48/64-Bit MAC Address support
				uint8_t addr[8];
				if(ns->getSourceLinkLayerAddress().getFlagEui64() == true)
				{
#if DEBUG
				    printf("(ND: NS) - getSourceLinkLayerAddress -> EUI-64 MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
				        addr[i] = ns->getSourceLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-64) */
				else
				{
#if DEBUG
				    printf("(ND: NS) - getSourceLinkLayerAddress -> 48-Bit MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE; i++) {
				        addr[i] = ns->getSourceLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-48) */

				memcpy((uint8_t*)UIP_ND6_OPT_HDR_BUF + UIP_ND6_OPT_DATA_OFFSET, addr, UIP_LLADDR_LEN);

				uip_len += UIP_ND6_OPT_LLAO_LEN;
				nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
			}
			printf("\n");
		}
		else if(dynamic_cast<IPv6NeighbourAdvertisement*>(encapsulated) != null)
		{
#if DEBUG
			printf("(ND: NA)");
#endif /* DEBUG */
			/*
			typedef struct uip_nd6_na {
  	  	  	  uint8_t flagsreserved;
  	  	  	  uint8_t reserved[3];
 	  	  	  uip_ipaddr_t tgtipaddr;
			} uip_nd6_na;
			 */
			uip_len += UIP_ND6_NA_LEN;
			nd6_opt_offset = UIP_ND6_NA_LEN;
			UIP_ICMP_BUF->type = ICMP6_NA;

			IPv6NeighbourAdvertisement* na = (IPv6NeighbourAdvertisement*)encapsulated;

			UIP_ND6_NA_BUF->flagsreserved = 0;
			if(na->getRouterFlag())
				UIP_ND6_NA_BUF->flagsreserved |= 0x80;
			if(na->getSolicitedFlag())
				UIP_ND6_NA_BUF->flagsreserved |= 0x40;
			if(na->getOverrideFlag())
				UIP_ND6_NA_BUF->flagsreserved |= 0x20;
		    uip_ip6addr_t tgtipaddr;
			const uint32* raw = na->getTargetAddress().words();
			uip_ip6addr(&tgtipaddr,
					raw[0] >> 16, raw[0],
					raw[1] >> 16, raw[1],
					raw[2] >> 16, raw[2],
					raw[3] >> 16, raw[3]);
			UIP_ND6_NA_BUF->tgtipaddr = tgtipaddr;

			// TLLO
			if(!na->getTargetLinkLayerAddress().isUnspecified())
			{
				UIP_ND6_OPT_HDR_BUF->type = UIP_ND6_OPT_TLLAO;
				UIP_ND6_OPT_HDR_BUF->len = UIP_ND6_OPT_LLAO_LEN >> 3;

				// ND-NeighborAdvertisement -> Check and switch between 48/64-Bit MAC address support
				uint8_t addr[8];
				if(na->getTargetLinkLayerAddress().getFlagEui64() == true)
				{
#if DEBUG
				    printf("(ND: NA) - getTargetLinkLayerAddress -> EUI-64 MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
				        addr[i] = na->getTargetLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (TargetLinkLayerAddress == EUI-64) */
				else
				{
#if DEBUG
				    printf("(ND: NA) - getTargetLinkLayerAddress -> 48-Bit MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE; i++) {
				        addr[i] = na->getTargetLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (TargetLinkLayerAddress == EUI-48) */

				memcpy((uint8_t*)UIP_ND6_OPT_HDR_BUF + UIP_ND6_OPT_DATA_OFFSET, addr, UIP_LLADDR_LEN);

				uip_len += UIP_ND6_OPT_LLAO_LEN;
				nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
			}
		}
		else if(dynamic_cast<IPv6Redirect*>(encapsulated) != null)
		{
#if DEBUG
			printf("(ND: REDIRECT)");
#endif /* DEBUG */
			/*
			typedef struct uip_nd6_redirect {
  	  	  	  uint32_t reserved;
  	  	  	  uip_ipaddr_t tgtipaddress;
  	  	  	  uip_ipaddr_t destipaddress;
			} uip_nd6_redirect;
			 */
			uip_len += sizeof(uip_nd6_redirect);
			nd6_opt_offset = sizeof(uip_nd6_redirect);
			UIP_ICMP_BUF->type = ICMP6_REDIRECT;

			IPv6Redirect* redirect = (IPv6Redirect*)encapsulated;

			uip_ipaddr_t target;
			const uint32* targetraw = redirect->getTargetAddress().words();
			uip_ip6addr(&target,
					targetraw[0] >> 16, targetraw[0],
					targetraw[1] >> 16, targetraw[1],
					targetraw[2] >> 16, targetraw[2],
					targetraw[3] >> 16, targetraw[3]);
			UIP_ND6_REDIRECT_BUF->tgtipaddress = target;

			uip_ipaddr_t dest;
			const uint32* destraw = redirect->getDestinationAddress().words();
			uip_ip6addr(&dest,
					destraw[0] >> 16, destraw[0],
					destraw[1] >> 16, destraw[1],
					destraw[2] >> 16, destraw[2],
					destraw[3] >> 16, destraw[3]);
			UIP_ND6_REDIRECT_BUF->destipaddress = dest;

			// TLLO
			if(!redirect->getTargetLinkLayerAddress().isUnspecified())
			{
				UIP_ND6_OPT_HDR_BUF->type = UIP_ND6_OPT_TLLAO;
				UIP_ND6_OPT_HDR_BUF->len = UIP_ND6_OPT_LLAO_LEN >> 3;

				// ND-Redirect -> Check and switch between 48/64-Bit MAC address support
                uint8_t addr[8];
				if(redirect->getTargetLinkLayerAddress().getFlagEui64() == true)
				{
#if DEBUG
				    printf("(ND: Redirect) - getTargetLinkLayerAddress -> EUI-64 MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
				        addr[i] = redirect->getTargetLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-64) */
				else
				{
#if DEBUG
				    printf("(ND: Redirect) - getTargetLinkLayerAddress -> 48-Bit MAC\n");
#endif /* DEBUG */
				    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE; i++) {
				        addr[i] = redirect->getTargetLinkLayerAddress().getAddressByte(i);
				    }
				} /* if (SourceLinkLayerAddress == EUI-48) */

				memcpy((uint8_t*)UIP_ND6_OPT_HDR_BUF + UIP_ND6_OPT_DATA_OFFSET, addr, UIP_LLADDR_LEN);

				uip_len += UIP_ND6_OPT_LLAO_LEN;
				nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
			}
		}
		else if(dynamic_cast<ICMPv6DestUnreachableMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_DESTINATION_UNREACHABLE packet...\n");
#endif /* DEBUG */
			UIP_ICMP_BUF->type = ICMP6_DST_UNREACH;
			switch(icmpPacket->getType())
			{
				case NO_ROUTE_TO_DEST:
				{
					UIP_ICMP_BUF->icode = ICMP6_DST_UNREACH_NOROUTE;
					break;
				}
				case COMM_WITH_DEST_PROHIBITED:
				{
					UIP_ICMP_BUF->icode = ICMP6_DST_UNREACH_ADMIN;
					break;
				}
				case ADDRESS_UNREACHABLE:
				{
					UIP_ICMP_BUF->icode = ICMP6_DST_UNREACH_ADDR;
					break;
				}
				case PORT_UNREACHABLE:
				{
					UIP_ICMP_BUF->icode = ICMP6_DST_UNREACH_NOPORT;
					break;
				}
				default:
					break;
			}
		}
		else if(dynamic_cast<ICMPv6PacketTooBigMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_PACKET_TOO_BIG packet...\n");
#endif /* DEBUG */
			UIP_ICMP_BUF->type = ICMP6_PACKET_TOO_BIG;
			UIP_ICMP_BUF->icode = 0;
		}
		else if(dynamic_cast<ICMPv6TimeExceededMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_TIME_EXCEEDED packet...\n");
#endif /* DEBUG */
			UIP_ICMP_BUF->type = ICMP6_TIME_EXCEEDED;
			switch(icmpPacket->getType())
			{
				case ND_HOP_LIMIT_EXCEEDED:
				{
					UIP_ICMP_BUF->icode = ICMP6_TIME_EXCEED_TRANSIT;
					break;
				}
				case ND_FRAGMENT_REASSEMBLY_TIME:
				{
					UIP_ICMP_BUF->icode = ICMP6_TIME_EXCEED_REASSEMBLY;
					break;
				}
				default:
					break;
			}
		}
		else if(dynamic_cast<ICMPv6ParamProblemMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_PARAMETER_PROBLEM packet...\n");
#endif /* DEBUG */
		    UIP_ICMP_BUF->type = ICMP6_PARAM_PROB;
			switch(icmpPacket->getType())
			{
				case ERROREOUS_HDR_FIELD:
				{
					UIP_ICMP_BUF->icode = ICMP6_PARAMPROB_HEADER;
					break;
				}
				case UNRECOGNIZED_NEXT_HDR_TYPE:
				{
					UIP_ICMP_BUF->icode = ICMP6_PARAMPROB_NEXTHEADER;
					break;
				}
				case UNRECOGNIZED_IPV6_OPTION:
				{
					UIP_ICMP_BUF->icode = ICMP6_PARAMPROB_OPTION;
					break;
				}
				default:
					break;
			}
		}
		else if(dynamic_cast<ICMPv6EchoRequestMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_ECHO_REQUEST packet...\n");
#endif /* DEBUG */
		    UIP_ICMP_BUF->type = ICMP6_ECHO_REQUEST;
			UIP_ICMP_BUF->icode = ((ICMPv6EchoRequestMsg*)icmpPacket)->getCode();
		}
		else if(dynamic_cast<ICMPv6EchoReplyMsg*>(icmpPacket) != null)
		{
#if DEBUG
        printf("\tprocessing ICMPv6_ECHO_REPLY packet...\n");
#endif /* DEBUG */
			UIP_ICMP_BUF->type = ICMP6_ECHO_REPLY;
			UIP_ICMP_BUF->icode = ((ICMPv6EchoReplyMsg*)icmpPacket)->getCode();
		}

		UIP_ICMP_BUF->icmpchksum = 0;
		UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();
	}
	else if(dynamic_cast<UDPPacket*>(encapsulated) != null)
	{
#if DEBUG
		printf("\tprocessing UDP packet...\n");
#endif /* DEBUG */
		/* UDP header
		struct uip_udp_hdr {
		  u16_t srcport;
		  u16_t destport;
		  u16_t udplen;
		  u16_t udpchksum;
		};*/
		uip_len += UIP_UDPH_LEN;// TODO add payload length

		UDPPacket* udpPacket = (UDPPacket*)encapsulated;

		UIP_IP_BUF->proto = UIP_PROTO_UDP;

		UIP_UDP_BUF->srcport = UIP_HTONS(udpPacket->getSourcePort());
		UIP_UDP_BUF->destport = UIP_HTONS(udpPacket->getDestinationPort());
		UIP_UDP_BUF->udplen = 0;// TODO add payload length
		//because we use IPv6 and this is standard setting
		UIP_UDP_BUF->udpchksum = 0;
		UIP_UDP_BUF->udpchksum = ~(uip_udpchksum());
	}
	else if(dynamic_cast<TCPSegment*>(encapsulated) != null)
	{
#if DEBUG
		printf("\tprocessing TCP packet...\n");
#endif /* DEBUG */
		/* TCP header
		struct uip_tcp_hdr {
		  u16_t srcport;
		  u16_t destport;
		  u8_t seqno[4];
		  u8_t ackno[4];
		  u8_t tcpoffset;
		  u8_t flags;
		  u8_t  wnd[2];
		  u16_t tcpchksum;
		  u8_t urgp[2];
		  u8_t optdata[4];
		};*/
		uip_len += UIP_TCPH_LEN;// TODO add payload length

		TCPSegment* tcpPacket = (TCPSegment*)encapsulated;

		UIP_IP_BUF->proto = UIP_PROTO_TCP;

		UIP_TCP_BUF->srcport = UIP_HTONS(tcpPacket->getSrcPort());
		UIP_TCP_BUF->destport = UIP_HTONS(tcpPacket->getDestPort());
		UIP_TCP_BUF->ackno[0] = tcpPacket->getAckNo() >> 24;
		UIP_TCP_BUF->ackno[1] = tcpPacket->getAckNo() >> 16;
		UIP_TCP_BUF->ackno[2] = tcpPacket->getAckNo() >> 8;
		UIP_TCP_BUF->ackno[3] = tcpPacket->getAckNo();
		UIP_TCP_BUF->seqno[0] = tcpPacket->getSequenceNo() >> 24;
		UIP_TCP_BUF->seqno[1] = tcpPacket->getSequenceNo() >> 16;
		UIP_TCP_BUF->seqno[2] = tcpPacket->getSequenceNo() >> 8;
		UIP_TCP_BUF->seqno[3] = tcpPacket->getSequenceNo();
		UIP_TCP_BUF->urgp[0] = tcpPacket->getUrgentPointer() >> 8;
		UIP_TCP_BUF->urgp[1] = tcpPacket->getUrgentPointer();
		UIP_TCP_BUF->wnd[0] = tcpPacket->getWindow() >> 8;
		UIP_TCP_BUF->wnd[1] = tcpPacket->getWindow();

		if(tcpPacket->getOptionsArraySize() > 0)
		{
			u8_t* opt_ptr = UIP_TCP_BUF->optdata;
			u8_t bytecount = 0;
			for(unsigned int i = 0; i < tcpPacket->getOptionsArraySize(); i++)
			{
				TCPOption opt = tcpPacket->getOptions(i);
				*opt_ptr++ = (u8_t)opt.getKind();
				bytecount++;
				switch(opt.getKind())
				{
					case TCPOPTION_END_OF_OPTION_LIST: //RFC 793
					{
						break;
					}
					case TCPOPTION_NO_OPERATION: //RFC 793
					{
						break;
					}
					case TCPOPTION_MAXIMUM_SEGMENT_SIZE: //RFC 793
					{
						*opt_ptr++ = (u8_t)opt.getLength();
						*opt_ptr++ = (u8_t)(opt.getValues(0) >> 8);
						*opt_ptr++ = opt.getValues(0);
						bytecount += 3;
						break;
					}
					case TCPOPTION_WINDOW_SCALE: //RFC 1323
					{
						*opt_ptr++ = (u8_t)opt.getLength();
						*opt_ptr++ = (u8_t)opt.getValues(0);
						bytecount += 2;
						break;
					}
					case TCPOPTION_SACK_PERMITTED: //RFC 2018
					{
						*opt_ptr++ = (u8_t)opt.getLength();
						bytecount++;
						break;
					}
					case TCPOPTION_SACK: //RFC 2018
					{
						*opt_ptr++ = (u8_t)opt.getLength();
						for(unsigned int i = 0; i < opt.getValuesArraySize(); i++)
						{
							*opt_ptr++ = opt.getValues(i) >> 24;
							*opt_ptr++ = opt.getValues(i) >> 16;
							*opt_ptr++ = opt.getValues(i) >> 8;
							*opt_ptr++ = opt.getValues(i);
							bytecount += 4;
						}
						bytecount++;
						break;
					}
					case TCPOPTION_TIMESTAMP: //RFC 1323
					{
						*opt_ptr++ = (u8_t)opt.getLength();
						*opt_ptr++ = opt.getValues(0) >> 24;
						*opt_ptr++ = opt.getValues(0) >> 16;
						*opt_ptr++ = opt.getValues(0) >> 8;
						*opt_ptr++ = opt.getValues(0);
						*opt_ptr++ = opt.getValues(1) >> 24;
						*opt_ptr++ = opt.getValues(1) >> 16;
						*opt_ptr++ = opt.getValues(1) >> 8;
						*opt_ptr++ = opt.getValues(1);
						bytecount += 9;
						break;
					}
					default:
						error("ERROR - 6LoWPAN Wrapper: Unsupported TCP option field.");
				}
			}
			while(bytecount % 4 != 0)
			{
				*opt_ptr++ = 0;
				bytecount++;
			}
			uip_len += bytecount;
			UIP_TCP_BUF->tcpoffset = ((UIP_TCPH_LEN + bytecount) / 4) << 4;
		}
		else
			UIP_TCP_BUF->tcpoffset = (UIP_TCPH_LEN / 4) << 4;

		UIP_TCP_BUF->flags = 0;
		if(tcpPacket->getFinBit())
			UIP_TCP_BUF->flags |= TCP_FIN;
		if(tcpPacket->getSynBit())
			UIP_TCP_BUF->flags |= TCP_SYN;
		if(tcpPacket->getRstBit())
			UIP_TCP_BUF->flags |= TCP_RST;
		if(tcpPacket->getPshBit())
			UIP_TCP_BUF->flags |= TCP_PSH;
		if(tcpPacket->getAckBit())
			UIP_TCP_BUF->flags |= TCP_ACK;
		if(tcpPacket->getUrgBit())
			UIP_TCP_BUF->flags |= TCP_URG;

		// TODO check and rework the TCP Payload check
#if DEBUG
		//lets simulate some payload as long as the payload in omnets tcp packet
		if(tcpPacket->getPayloadLength() > 0 || tcpPacket->getEncapsulatedPacket() != null)
		{
			uint16_t length;
			// TODO what to do if payload length bigger than contikis? now: just cut length!
			if(tcpPacket->getPayloadLength() > UIP_TCP_MSS)
				length = UIP_TCP_MSS;
			else
				length = (uint16_t)tcpPacket->getPayloadLength();
			printf("%i %i\n", length, uip_len);
			uip_len += length; // simulated payload data
			memcpy((void*)(UIP_IP_BUF + ((UIP_TCP_BUF->tcpoffset >> 4) * 4)), artif_payl.c_str(), length);
#if DEBUG
			printf("\tadding artificial payload length: %i (uip_len: %d)\n", length, uip_len);
			printf("\t%s \n", (char*)(UIP_IP_BUF + ((UIP_TCP_BUF->tcpoffset >> 4) * 4)));
#endif /* DEBUG */
		}
#endif /* DEBUG */

		UIP_TCP_BUF->tcpchksum = 0;
		UIP_TCP_BUF->tcpchksum = ~(uip_tcpchksum());
	}
	else
	{
#if DEBUG
		printf("\n\tNOT SUPPORTED PACKET !!!\n");
		printf("...done\n");
#endif /* DEBUG */
		result.push_back(ipPacket);
		return result;
	}
	UIP_IP_BUF->len[0] = (u8_t)((uip_len - 40) >> 8);
	UIP_IP_BUF->len[1] = (u8_t)((uip_len - 40) & 0x00FF);

	// Get next hops link layer address
	RoutingTable6* rt6          = RoutingTable6Access().get();
	IPv6Address nextHop         = rt6->lookupDestCache(ipPacket->getDestAddress(), configuration[gateIndex]->interfaceId);
	IPv6NeighbourDiscovery* nd  = IPv6NeighbourDiscoveryAccess().get();
	MACAddress macNextHop       = nd->resolveNeighbour(nextHop, configuration[gateIndex]->interfaceId);

	uip_lladdr_t* addr          = new uip_lladdr_t();
	// Check for 48/64-Bit MAC address and enter the correct address size
	for (uint8_t i = 0; i < macNextHop.getAddressSize(); i++) {
	    addr->addr[i] = macNextHop.getAddressByte(i);
	}

	// par - localdest, the 48/64-Bit MAC address of the destination (next hop)
	tcpip_output(addr);

	printf("\tContiki is done, packets in queue: %i\n", packetQueue.size());
	int count = packetQueue.size();
	// Translate all generated packets into OMNeT++ / INET format
	for(int i = 0; i < count; i++)
	{
		struct contiki_packet data = packetQueue.front();
		_6lowpanDatagram *_6lowpanPacket;
		if(count > 1)
		{
			// generate an extended name
			// TODO optimize this
			char buff[strlen(ipPacket->getName()) + 10 + strlen(" fragment ")];
			sprintf(buff, "%s fragment %i", ipPacket->getName(), i);
			_6lowpanPacket = new _6lowpanDatagram(buff);
		}
		else
			_6lowpanPacket = new _6lowpanDatagram(ipPacket->getName());

		_6lowpanPacket->setPayloadArraySize(data.length);
		uint8_t* payl_ptr = data.payload;
		for(unsigned int i = 0; i < _6lowpanPacket->getPayloadArraySize(); i++)
		{
			_6lowpanPacket->setPayload(i, payl_ptr[i]);
		}

		// Set all values inherited from OMNeT++
		_6lowpanPacket->setByteLength(encapsulated->getByteLength());
		// Save the kind of the transport layer protocol
		_6lowpanPacket->setTransportMessageKind(encapsulated->getKind());
		_6lowpanPacket->setKind(ipPacket->getKind());

		// Do we have a packet transported by the transport layer? --> save it! We do not have serialization!
		if(encapsulated->getEncapsulatedPacket() != null)
			_6lowpanPacket->encapsulate(encapsulated->getEncapsulatedPacket()->dup());
		// Save the important control information!
		_6lowpanPacket->setControlInfo(ipPacket->getControlInfo()->dup());

		result.push_back(_6lowpanPacket);
		packetQueue.pop();
	}
	delete ipPacket;
#endif  /* USE_6LOWPAN */
	return result;
}

IPv6Datagram* _6lowpan::processLowpanPacket(_6lowpanDatagram* packet)
{
	// We do need a result type, might be null if we are in reassemble mode
	IPv6Datagram* ipPacket = null;
#if USE_6LOWPAN
#if DEBUG
	printf("\tdoing Contikis magic...\n");
#endif /* DEBUG */
	// Set the data length
	// This should not be bigger than the according parameter in Contiki, or else data will be cut!
	packetbuf_set_datalen(packet->getPayloadArraySize());
	uint8_t* payl_ptr = (uint8_t*)packetbuf_dataptr();
	for(unsigned int i = 0; i < packet->getPayloadArraySize(); i++)
	{
		payl_ptr[i] = packet->getPayload(i);
	}
	// Call Contiki to take care of the packet processing
	NETSTACK_NETWORK.input();

	// This source code is taken from Contiki, it simply checks the packets status
	// It is used to figure out what Contiki did with the packet
	// First check for reassemble mode
#if DEBUG
	printf("\tChecking for reassembling mode\n");
#endif /* DEBUG */
	if(rime_ptr == null)
		error("rime_ptr is null, did u forget to make it global accessible in Contiki? (i.e., remove the static)");
	if(processed_ip_len > 0)
	{
		// Check if Contiki did drop the packet!
		uint16_t frag_size = GET16(RIME_FRAG_PTR, RIME_FRAG_DISPATCH_SIZE) & 0x07ff;
		uint16_t frag_tag = GET16(RIME_FRAG_PTR, RIME_FRAG_TAG);
		if((frag_size > 0
				&&
				(frag_size != sicslowpan_len || reass_tag  != frag_tag || !rimeaddr_cmp(&frag_sender, packetbuf_addr(PACKETBUF_ADDR_SENDER))))
				||
				frag_size == 0) {
#if DEBUG
			printf("\tdropping packet not part of reassembling process\n");
#endif /* DEBUG */
			delete packet;
			return null;
		}
	}
	// If in reassemble mode then drop / delete the packet
	if(!(processed_ip_len == 0 || processed_ip_len == sicslowpan_len))
	{
#if DEBUG
		printf("\treceived packet in reassembling mode, no further processing (processed_ip_len: %i, sicslowpan_len: %i)\n", processed_ip_len, sicslowpan_len);
#endif /* DEBUG */
		delete packet;
		return null;
	}

	/* IP header
	struct uip_ip_hdr {
	  u8_t vtc;
	  u8_t tcflow;
	  u16_t flow;
	  u8_t len[2];
	  u8_t proto, ttl;
	  uip_ip6addr_t srcipaddr, destipaddr;
	};*/
	ipPacket = new IPv6Datagram(packet->getName());
	ipPacket->setTrafficClass(UIP_IP_BUF->tcflow);
	ipPacket->setFlowLabel(UIP_IP_BUF->flow);
	ipPacket->setHopLimit(UIP_IP_BUF->ttl);
	ipPacket->setKind(packet->getKind());

	IPv6Address srcAddress;
	srcAddress.set(uip_ntohl(UIP_IP_BUF->srcipaddr.u16[0] | UIP_IP_BUF->srcipaddr.u16[1] << 16),
				   uip_ntohl(UIP_IP_BUF->srcipaddr.u16[2] | UIP_IP_BUF->srcipaddr.u16[3] << 16),
				   uip_ntohl(UIP_IP_BUF->srcipaddr.u16[4] | UIP_IP_BUF->srcipaddr.u16[5] << 16),
				   uip_ntohl(UIP_IP_BUF->srcipaddr.u16[6] | UIP_IP_BUF->srcipaddr.u16[7] << 16));
	ipPacket->setSrcAddress(srcAddress);

	IPv6Address destAddress;
	destAddress.set(uip_ntohl(UIP_IP_BUF->destipaddr.u16[0] | UIP_IP_BUF->destipaddr.u16[1] << 16),
				    uip_ntohl(UIP_IP_BUF->destipaddr.u16[2] | UIP_IP_BUF->destipaddr.u16[3] << 16),
				    uip_ntohl(UIP_IP_BUF->destipaddr.u16[4] | UIP_IP_BUF->destipaddr.u16[5] << 16),
				    uip_ntohl(UIP_IP_BUF->destipaddr.u16[6] | UIP_IP_BUF->destipaddr.u16[7] << 16));
	ipPacket->setDestAddress(destAddress);

	if(UIP_IP_BUF->proto == UIP_PROTO_ICMP6)
	{
#if DEBUG
		printf("\tprocessing ICMPv6 packet\n");
#endif /* DEBUG */
		ipPacket->setTransportProtocol(IP_PROT_IPv6_ICMP);
		ICMPv6Message* encapsulate = null;
		uint8_t nd6_opt_offset = 0;

		if(UIP_ICMP_BUF->type == ICMP6_RS)
		{
#if DEBUG
			printf("(ND: RS)");
#endif /* DEBUG */
			encapsulate = new IPv6RouterSolicitation(packet->getName());
			encapsulate->setType(ICMPv6_ROUTER_SOL);
			nd6_opt_offset = UIP_ND6_RS_LEN;

			/*
			typedef struct uip_nd6_rs {
			  uint32_t reserved;
			} uip_nd6_rs;
			 */
			if(uip_len > UIP_IPH_LEN + UIP_ICMPH_LEN + nd6_opt_offset)
			{
				//SLLAO
				if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_SLLAO)
				{
					// ND-RouterSolicitation
				    MACAddress mac;
			        // Contiki's ND-module uses EUI-64 MAC addresses
				    mac.setFlagEui64(true);
			        for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
			            mac.setAddressByte(i, ((uint8_t*)UIP_ND6_OPT_HDR_BUF)[UIP_ND6_OPT_DATA_OFFSET + i]);
				    }

				    ((IPv6RouterSolicitation*)encapsulate)->setSourceLinkLayerAddress(mac);
					nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
				}
				else
					error("ND option which is not allowed\n");
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_RA)
		{
#if DEBUG
			printf("(ND: RA)");
#endif /* DEBUG */
			encapsulate = new IPv6RouterAdvertisement(packet->getName());
			encapsulate->setType(ICMPv6_ROUTER_AD);
			nd6_opt_offset = UIP_ND6_RA_LEN;

			/*
			typedef struct uip_nd6_ra {
			  uint8_t cur_ttl;
			  uint8_t flags_reserved;
			  uint16_t router_lifetime;
			  uint32_t reachable_time;
			  uint32_t retrans_timer;
			} uip_nd6_ra;
				 */
			((IPv6RouterAdvertisement*)encapsulate)->setCurHopLimit(UIP_ND6_RA_BUF->cur_ttl);
			((IPv6RouterAdvertisement*)encapsulate)->setReachableTime(uip_ntohl(UIP_ND6_RA_BUF->reachable_time));
			((IPv6RouterAdvertisement*)encapsulate)->setRouterLifetime(uip_ntohs(UIP_ND6_RA_BUF->router_lifetime));
			((IPv6RouterAdvertisement*)encapsulate)->setRetransTimer(uip_ntohl(UIP_ND6_RA_BUF->retrans_timer));
			((IPv6RouterAdvertisement*)encapsulate)->setOtherStatefulConfFlag(UIP_ND6_RA_BUF->flags_reserved & 0x80);
			((IPv6RouterAdvertisement*)encapsulate)->setManagedAddrConfFlag(UIP_ND6_RA_BUF->flags_reserved & 0x40);

			while(uip_len > UIP_IPH_LEN + UIP_ICMPH_LEN + nd6_opt_offset)
			{
				if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_MTU)
				{
					//MTU
					((IPv6RouterAdvertisement*)encapsulate)->setMTU(uip_ntohl(UIP_ND6_OPT_MTU_BUF->mtu));
					nd6_opt_offset += UIP_ND6_OPT_MTU_LEN;
				}
				else if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_SLLAO)
				{
					//SLLO
					// ND-RouterAdvertisement
                    MACAddress mac;
                    // Contiki's ND-module uses EUI-64 MAC addresses
                    mac.setFlagEui64(true);
                    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
                        mac.setAddressByte(i, ((uint8_t*)UIP_ND6_OPT_HDR_BUF)[UIP_ND6_OPT_DATA_OFFSET + i]);
                    }

					((IPv6RouterAdvertisement*)encapsulate)->setSourceLinkLayerAddress(mac);
					nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
				}
				else if(UIP_ND6_OPT_PREFIX_BUF->type == UIP_ND6_OPT_PREFIX_INFO)
				{
					IPv6NDPrefixInformation info;
					info.setPrefixLength(UIP_ND6_OPT_PREFIX_BUF->preflen);
					info.setValidLifetime(uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->validlt));
					info.setPreferredLifetime(uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->preferredlt));
					info.setOnlinkFlag(UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 & 0x80);
					info.setAutoAddressConfFlag(UIP_ND6_OPT_PREFIX_BUF->flagsreserved1 & 0x40);

					IPv6Address addr;
					addr.set(uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->prefix.u16[0] | UIP_ND6_OPT_PREFIX_BUF->prefix.u16[1] << 16),
								uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->prefix.u16[2] | UIP_ND6_OPT_PREFIX_BUF->prefix.u16[3] << 16),
								uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->prefix.u16[4] | UIP_ND6_OPT_PREFIX_BUF->prefix.u16[5] << 16),
								uip_ntohl(UIP_ND6_OPT_PREFIX_BUF->prefix.u16[6] | UIP_ND6_OPT_PREFIX_BUF->prefix.u16[7] << 16));
					info.setPrefix(addr);
					((IPv6RouterAdvertisement*)encapsulate)->setPrefixInformationArraySize(((IPv6RouterAdvertisement*)encapsulate)->getPrefixInformationArraySize() + 1);
					((IPv6RouterAdvertisement*)encapsulate)->setPrefixInformation(((IPv6RouterAdvertisement*)encapsulate)->getPrefixInformationArraySize() -1, info);
					nd6_opt_offset += UIP_ND6_OPT_PREFIX_INFO_LEN;
				}
				else
					error("ND option which is not allowed\n");
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_NS)
		{
#if DEBUG
			printf("(ND: NS)");
#endif /* DEBUG */
			encapsulate = new IPv6NeighbourSolicitation(packet->getName());
			encapsulate->setType(ICMPv6_NEIGHBOUR_SOL);
			nd6_opt_offset = UIP_ND6_NS_LEN;
			/*
			typedef struct uip_nd6_ns {
	  	  	  uint32_t reserved;
	  	  	  uip_ipaddr_t tgtipaddr;
			} uip_nd6_ns;
				 */
			IPv6Address addr;
			addr.set(uip_ntohl(UIP_ND6_NS_BUF->tgtipaddr.u16[0] | UIP_ND6_NS_BUF->tgtipaddr.u16[1] << 16),
					 uip_ntohl(UIP_ND6_NS_BUF->tgtipaddr.u16[2] | UIP_ND6_NS_BUF->tgtipaddr.u16[3] << 16),
					 uip_ntohl(UIP_ND6_NS_BUF->tgtipaddr.u16[4] | UIP_ND6_NS_BUF->tgtipaddr.u16[5] << 16),
					 uip_ntohl(UIP_ND6_NS_BUF->tgtipaddr.u16[6] | UIP_ND6_NS_BUF->tgtipaddr.u16[7] << 16));
			((IPv6NeighbourSolicitation*)encapsulate)->setTargetAddress(addr);

			if(uip_len > UIP_IPH_LEN + UIP_ICMPH_LEN + nd6_opt_offset)
			{
				//SLLAO
				if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_SLLAO)
				{
					//nd6_opt_offset += UIP_ND6_OPT_HDR_BUF;
					MACAddress mac;
					// ND-NeighborSolicitation
					// Contiki's ND-module uses EUI-64 MAC addresses
					mac.setFlagEui64(true);
					for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
					    mac.setAddressByte(i, ((uint8_t*)UIP_ND6_OPT_HDR_BUF)[UIP_ND6_OPT_DATA_OFFSET + i]);
					}

					((IPv6NeighbourSolicitation*)encapsulate)->setSourceLinkLayerAddress(mac);
					nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
				}
				else
					error("ND option which is not allowed\n");
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_NA)
		{
#if DEBUG
			printf("(ND: NA)");
#endif /* DEBUG */
			encapsulate = new IPv6NeighbourAdvertisement(packet->getName());
			encapsulate->setType(ICMPv6_NEIGHBOUR_AD);
			nd6_opt_offset +=  UIP_ND6_NA_LEN;

			/*
			typedef struct uip_nd6_na {
	  	  	  uint8_t flagsreserved;
	  	  	  uint8_t reserved[3];
	  	  	  uip_ipaddr_t tgtipaddr;
			} uip_nd6_na;
			 */
			IPv6Address addr;
			addr.set(uip_ntohl(UIP_ND6_NA_BUF->tgtipaddr.u16[0] | UIP_ND6_NA_BUF->tgtipaddr.u16[1] << 16),
						uip_ntohl(UIP_ND6_NA_BUF->tgtipaddr.u16[2] | UIP_ND6_NA_BUF->tgtipaddr.u16[3] << 16),
						uip_ntohl(UIP_ND6_NA_BUF->tgtipaddr.u16[4] | UIP_ND6_NA_BUF->tgtipaddr.u16[5] << 16),
						uip_ntohl(UIP_ND6_NA_BUF->tgtipaddr.u16[6] | UIP_ND6_NA_BUF->tgtipaddr.u16[7] << 16));
			((IPv6NeighbourAdvertisement*)encapsulate)->setTargetAddress(addr);
			((IPv6NeighbourAdvertisement*)encapsulate)->setRouterFlag(UIP_ND6_NA_BUF->flagsreserved & 80);
			((IPv6NeighbourAdvertisement*)encapsulate)->setSolicitedFlag(UIP_ND6_NA_BUF->flagsreserved & 40);
			((IPv6NeighbourAdvertisement*)encapsulate)->setOverrideFlag(UIP_ND6_NA_BUF->flagsreserved & 20);

			if(uip_len > UIP_IPH_LEN + UIP_ICMPH_LEN + nd6_opt_offset)
			{
				if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_TLLAO)
				{
					MACAddress mac;
					// ND-NeighborAdvertisement
                    // Contiki's ND-module uses EUI-64 MAC addresses
                    mac.setFlagEui64(true);
                    for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
                        mac.setAddressByte(i, ((uint8_t*)UIP_ND6_OPT_HDR_BUF)[UIP_ND6_OPT_DATA_OFFSET + i]);
                    }

					((IPv6NeighbourAdvertisement*)encapsulate)->setTargetLinkLayerAddress(mac);
					nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
				}
				else
					error("ND option which is not allowed\n");
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_REDIRECT)
		{
#if DEBUG
			printf("(ND: REDIRECT)");
#endif /* DEBUG */
			encapsulate = new IPv6Redirect(packet->getName());
			encapsulate->setType(ICMPv6_REDIRECT);
			nd6_opt_offset +=  sizeof(uip_nd6_redirect);
			/*
			typedef struct uip_nd6_redirect {
	  	  	  uint32_t reserved;
	  	  	  uip_ipaddr_t tgtipaddress;
	  	  	  uip_ipaddr_t destipaddress;
			} uip_nd6_redirect;
			*/

			IPv6Address t_addr(UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[0] << 16 | UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[1],
					           UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[2] << 16 | UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[3],
					           UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[4] << 16 | UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[5],
					           UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[6] << 16 | UIP_ND6_REDIRECT_BUF->tgtipaddress.u16[7]);
			((IPv6Redirect*)encapsulate)->setTargetAddress(t_addr);

			IPv6Address d_addr(UIP_ND6_REDIRECT_BUF->destipaddress.u16[0] << 16 | UIP_ND6_REDIRECT_BUF->destipaddress.u16[1],
					           UIP_ND6_REDIRECT_BUF->destipaddress.u16[2] << 16 | UIP_ND6_REDIRECT_BUF->destipaddress.u16[3],
                               UIP_ND6_REDIRECT_BUF->destipaddress.u16[4] << 16 | UIP_ND6_REDIRECT_BUF->destipaddress.u16[5],
                               UIP_ND6_REDIRECT_BUF->destipaddress.u16[6] << 16 | UIP_ND6_REDIRECT_BUF->destipaddress.u16[7]);
			((IPv6Redirect*)encapsulate)->setDestinationAddress(d_addr);

			if(uip_len > UIP_IPH_LEN + UIP_ICMPH_LEN + nd6_opt_offset)
			{
				//TLLO
				if(UIP_ND6_OPT_HDR_BUF->type == UIP_ND6_OPT_TLLAO)
				{
					MACAddress mac;
					// ND-Redirect
					// Contiki's ND-module uses EUI-64 MAC addresses
					mac.setFlagEui64(true);
					for (uint8_t i = 0; i < MAC_ADDRESS_SIZE64; i++) {
					    mac.setAddressByte(i, ((uint8_t*)UIP_ND6_OPT_HDR_BUF)[UIP_ND6_OPT_DATA_OFFSET + i]);
					}

					((IPv6Redirect*)encapsulate)->setTargetLinkLayerAddress(mac);
					nd6_opt_offset += UIP_ND6_OPT_LLAO_LEN;
				}
				error("ND option which is not allowed\n");
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_DST_UNREACH)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_DESTINATION_UNREACHABLE\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6DestUnreachableMsg(packet->getName());
			switch(UIP_ICMP_BUF->icode)
			{
				case ICMP6_DST_UNREACH_NOROUTE:
				{
					encapsulate->setType(NO_ROUTE_TO_DEST);
					break;
				}
				case ICMP6_DST_UNREACH_ADMIN:
				{
					encapsulate->setType(COMM_WITH_DEST_PROHIBITED);
					break;
				}
				case ICMP6_DST_UNREACH_ADDR:
				{
					encapsulate->setType(ADDRESS_UNREACHABLE);
					break;
				}
				case ICMP6_DST_UNREACH_NOPORT:
				{
					encapsulate->setType(PORT_UNREACHABLE);
					break;
				}
		    	default:
		    		break;
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_PACKET_TOO_BIG)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_PACKET_TOO_BIG\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6PacketTooBigMsg(packet->getName());
			encapsulate->setType(ICMPv6_PACKET_TOO_BIG);
		}
		else if(UIP_ICMP_BUF->type == ICMP6_TIME_EXCEEDED)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_TIME_EXCEEDED\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6TimeExceededMsg(packet->getName());
			switch(UIP_ICMP_BUF->icode)
			{
				case ICMP6_TIME_EXCEED_TRANSIT:
				{
					encapsulate->setType(ND_HOP_LIMIT_EXCEEDED);
					break;
				}
				case ICMP6_TIME_EXCEED_REASSEMBLY:
				{
					encapsulate->setType(ND_FRAGMENT_REASSEMBLY_TIME);
					break;
				}
				default:
					break;
				}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_PARAM_PROB)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_PARAMETER_PROBLEM\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6ParamProblemMsg(packet->getName());
			switch(UIP_ICMP_BUF->icode)
			{
				case ICMP6_PARAMPROB_HEADER:
				{
					encapsulate->setType(ERROREOUS_HDR_FIELD);
					break;
				}
				case ICMP6_PARAMPROB_NEXTHEADER:
				{
					encapsulate->setType(UNRECOGNIZED_NEXT_HDR_TYPE);
					break;
				}
				case ICMP6_PARAMPROB_OPTION:
				{
					encapsulate->setType(UNRECOGNIZED_IPV6_OPTION);
					break;
				}
				default:
					break;
			}
		}
		else if(UIP_ICMP_BUF->type == ICMP6_ECHO_REQUEST)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_ECHO_REQUEST\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6EchoRequestMsg(packet->getName());
			((ICMPv6EchoRequestMsg*)encapsulate)->setCode(UIP_ICMP_BUF->icode);
			encapsulate->setType(ICMPv6_ECHO_REQUEST);
		}
		else if(UIP_ICMP_BUF->type == ICMP6_ECHO_REPLY)
		{
#if DEBUG
            printf("\tprocessLowpanPacket: ICMPv6_ECHO_REPLY\n");
#endif /* DEBUG */
			encapsulate = new ICMPv6EchoReplyMsg(packet->getName());
			((ICMPv6EchoReplyMsg*)encapsulate)->setCode(UIP_ICMP_BUF->icode);
			encapsulate->setType(ICMPv6_ECHO_REPLY);
		}

		encapsulate->setKind(packet->getTransportMessageKind());

		if(packet->getEncapsulatedPacket() != null)
			encapsulate->encapsulate(packet->getEncapsulatedPacket()->dup());
		ipPacket->encapsulate(encapsulate);
		ipPacket->setByteLength(encapsulate->getByteLength());
	}else if(UIP_IP_BUF->proto == UIP_PROTO_UDP)
	{
#if DEBUG
		printf("\tprocessLowpanPacket: processing UDP packet\n");
#endif /* DEBUG */
		ipPacket->setTransportProtocol(IP_PROT_UDP);

		UDPPacket* encapsulate = new UDPPacket(packet->getName());
		/* UDP header
		struct uip_udp_hdr {
		  u16_t srcport;
		  u16_t destport;
		  u16_t udplen;
		  u16_t udpchksum;
		};*/
		encapsulate->setSourcePort(uip_ntohs(UIP_UDP_BUF->srcport));
		encapsulate->setDestinationPort(uip_ntohs(UIP_UDP_BUF->destport));

		encapsulate->setKind(packet->getTransportMessageKind());

		if(packet->getEncapsulatedPacket() != null)
			encapsulate->encapsulate(packet->getEncapsulatedPacket()->dup());
		ipPacket->encapsulate(encapsulate);
		ipPacket->setByteLength(encapsulate->getByteLength());
	}
	else if(UIP_IP_BUF->proto == UIP_PROTO_TCP)
	{
		ipPacket->setTransportProtocol(IP_PROT_TCP);

		TCPSegment* encapsulate = new TCPSegment(packet->getName());
		/* TCP header
		struct uip_tcp_hdr {
		  u16_t srcport;
		  u16_t destport;
		  u8_t seqno[4];
		  u8_t ackno[4];
		  u8_t tcpoffset;
		  u8_t flags;
		  u8_t  wnd[2];
		  u16_t tcpchksum;
		  u8_t urgp[2];
		  u8_t optdata[4];
		};*/

		encapsulate->setSrcPort(uip_ntohs(UIP_TCP_BUF->srcport));
		encapsulate->setDestPort(uip_ntohs(UIP_TCP_BUF->destport));
		encapsulate->setAckNo(UIP_TCP_BUF->ackno[0] << 24 | UIP_TCP_BUF->ackno[1] << 16 | UIP_TCP_BUF->ackno[2] << 8 | UIP_TCP_BUF->ackno[3]);
		encapsulate->setSequenceNo(UIP_TCP_BUF->seqno[0] << 24 | UIP_TCP_BUF->seqno[1] << 16 | UIP_TCP_BUF->seqno[2] << 8 | UIP_TCP_BUF->seqno[3]);
		encapsulate->setUrgentPointer(UIP_TCP_BUF->urgp[0] << 8 | UIP_TCP_BUF->urgp[1]);
		encapsulate->setWindow(UIP_TCP_BUF->wnd[0] << 8 | UIP_TCP_BUF->wnd[1]);
		encapsulate->setFinBit((UIP_TCP_BUF->flags & TCP_FIN) > 0);
		encapsulate->setSynBit((UIP_TCP_BUF->flags & TCP_SYN) > 0);
		encapsulate->setRstBit((UIP_TCP_BUF->flags & TCP_RST) > 0);
		encapsulate->setPshBit((UIP_TCP_BUF->flags & TCP_PSH) > 0);
		encapsulate->setAckBit((UIP_TCP_BUF->flags & TCP_ACK) > 0);
		encapsulate->setUrgBit((UIP_TCP_BUF->flags & TCP_URG) > 0);

		u8_t bytecount = ((UIP_TCP_BUF->tcpoffset >> 4) * 4) - UIP_TCPH_LEN;
		encapsulate->setHeaderLength(bytecount + UIP_TCPH_LEN);
		if(bytecount > 0)
		{
			u8_t* opt_ptr = UIP_TCP_BUF->optdata;
			while(bytecount > 3)
			{
				TCPOption opt;
				opt.setKind(*opt_ptr++);
				bytecount--;
				switch(opt.getKind())
				{
					case TCPOPTION_END_OF_OPTION_LIST: //RFC 793
					{
						break;
					}
					case TCPOPTION_NO_OPERATION: //RFC 793
					{
						break;
					}
					case TCPOPTION_MAXIMUM_SEGMENT_SIZE: //RFC 793
					{
						opt.setLength(*opt_ptr++);
						opt.setValuesArraySize(1);
						opt.setValues(0, (opt_ptr[0] << 8) + opt_ptr[1]);
						opt_ptr += 2;
						bytecount -= 3;
						break;
					}
					case TCPOPTION_WINDOW_SCALE: //RFC 1323
					{
						opt.setLength(*opt_ptr++);
						opt.setValuesArraySize(1);
						opt.setValues(0, *opt_ptr++);
						bytecount -= 2;
						break;
					}
					case TCPOPTION_SACK_PERMITTED: //RFC 2018
					{
						opt.setLength(*opt_ptr++);
						bytecount--;
						break;
					}
					case TCPOPTION_SACK: //RFC 2018
					{
						opt.setLength(*opt_ptr++);
						opt.setValuesArraySize((opt.getLength() - 2) / 4);
						for(unsigned int i = 0; i < opt.getValuesArraySize(); i++)
						{
							opt.setValues(i, (opt_ptr[0] << 24) | (opt_ptr[1] << 16) | (opt_ptr[2] << 8) | opt_ptr[3]);
							opt_ptr += 4;
							bytecount -= 4;
						}
						bytecount--;
						break;
					}
					case TCPOPTION_TIMESTAMP: //RFC 1323
					{
						opt.setLength(*opt_ptr++);
						opt.setValuesArraySize(2);
						opt.setValues(0, (opt_ptr[0] << 24) | (opt_ptr[1] << 16) | (opt_ptr[2] << 8) | opt_ptr[3]);
						opt_ptr += 4;
						opt.setValues(1, (opt_ptr[0] << 24) | (opt_ptr[1] << 16) | (opt_ptr[2] << 8) | opt_ptr[3]);
						opt_ptr += 4;
						bytecount -= 9;
						break;
					}
					default:
						error("Unsupported TCP option field.\n");
					}
				encapsulate->setOptionsArraySize(encapsulate->getOptionsArraySize() + 1);
				encapsulate->setOptions(encapsulate->getOptionsArraySize() - 1, opt);
			}
		}
#if DEBUG
		printf("\tprocessLowpanPacket: processing TCP packet uip_len: %i(%i)\n", uip_len, UIP_IPH_LEN + ((UIP_TCP_BUF->tcpoffset >> 4) * 4));
		if(uip_len > UIP_IPH_LEN + ((UIP_TCP_BUF->tcpoffset >> 4) * 4))
			printf("\tretr payload: %s\n", (char*)(UIP_IP_BUF + ((UIP_TCP_BUF->tcpoffset >> 4) * 4)));
#endif /* DEBUG */
		// Restore all values!
		encapsulate->setKind(packet->getTransportMessageKind());
		encapsulate->setPayloadLength(uip_len - encapsulate->getHeaderLength() - ipPacket->calculateHeaderByteLength());
		encapsulate->setByteLength(encapsulate->getHeaderLength() + encapsulate->getPayloadLength());

		// Restore packet in transport layer message
		if(packet->getEncapsulatedPacket() != null)
			encapsulate->encapsulate(packet->getEncapsulatedPacket()->dup());
		// Encapsulate transport layer packet
		ipPacket->encapsulate(encapsulate);
		// We do not need to set header length, it's calculated in the IPv6 packet
		ipPacket->setByteLength(encapsulate->getByteLength());
	}
	delete packet;
#endif /* USE_6LOWPAN */
	return ipPacket;
}
