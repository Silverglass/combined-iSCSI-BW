/***********************************************************************

  OCTEON TOOLKITS                                                         
  Copyright (c) 2007 Cavium Networks. All rights reserved.

  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
  contains proprietary and confidential information of Cavium Networks
  and in some cases its suppliers.

  Any licensed reproduction, distribution, modification, or other use of
  this file or confidential information embodied in this file is subject
  to your license agreement with Cavium Networks. The applicable license
  terms can be found by contacting Cavium Networks or the appropriate
  representative within your company.

  All other use and disclosure is prohibited.

  Contact Cavium Networks at info@caviumnetworks.com for more information.

 ************************************************************************/ 

/**
 * @file ip-config.h
 *
 *  Copy this file to the application/config directory
 *
 *  and customize the flags/settings as appropriate
 *
 * $Id: ip-config.h 32179 2008-02-23 01:55:51Z ssamanta $ $Name$
 *
 *
 */
 
#ifndef __IP_CONFIG_H__
#define __IP_CONFIG_H__

/* Uncomment this to disable ARPs (or define CVM_ENET_NO_ARP in the Makefile)
 */
//#define _CVM_ENET_NO_ARP

/*
 * some example flags:
 *
 * n/a
 */

/* Content below this point is only used by the cvmx-config tool, and is
 * not used by any C files as CAVIUM_COMPONENT_REQUIREMENT is never defined.
 */

#ifdef CAVIUM_COMPONENT_REQUIREMENT
 
 
        /* global resource requirement */
 
        cvmxconfig
        {
#ifdef _CVM_ENET_NO_ARP
           define CVM_ENET_NO_ARP
               value=1
               description = "ARP disabled";
#endif
           define CVM_IP_CACHE_LUT_SIZE
               value=65536
               description = "IP forwarding cache size (must be a power of two)";
           define CVM_IP6_CACHE_LUT_SIZE
               value=65536
               description = "IP6 forwarding cache size (must be a power of two)";


           fpa CVM_IP_128B_POOL
	      size = 1
	      description = "128-byte pool";

	   fpa CVM_IP_256B_POOL
	      size = 2
	      description = "256-byte pool";

	   scratch CVM_SCR_IP_CACHE_PTR
	      size = 8
	      iobdma = true
	      permanent = true
	      description = "Pointer to route entry";

       scratch CVM_SCR_IP6_CACHE_PTR
           size = 8
           iobdma = true
           permanent = true
           description = "Pointer to IP6 route entry";

	   scratch CVM_SCR_IP_IPID_COUNTER
	      size = 8
	      iobdma = true
	      permanent = true
	      description = "Pointer to route entry";

	   fau CVM_FAU_IP_IPID_COUNTER
	      size = 4
	      description = "32-bit counter used for IP ID";

	   fau CVM_FAU_IP_TOTAL_PACKETS
	      size = 8
	      description = "64-bit counter used for total IP packets rcvd";

	   fau CVM_FAU_IP_BAD_CKSUM
	      size = 8
	      description = "64-bit counter used for IP bad checksum";

	   fau CVM_FAU_IP_SHORT_PACKETS
	      size = 8
	      description = "64-bit counter used for short IP packets rcvd";

	   fau CVM_FAU_IP_BAD_HDR_LEN
	      size = 8
	      description = "64-bit counter used for IP packets with bad hdr len";

	   fau CVM_FAU_IP_BAD_LEN
	      size = 8
	      description = "64-bit counter used for IP packets with bad len";

	   fau CVM_FAU_IP_FRAGS_RCVD
	      size = 8
	      description = "64-bit counter used for IP frags rcvd";

	   fau CVM_FAU_IP_FRAGS_DROPPED
	      size = 8
	      description = "64-bit counter used for IP frags dropped";

	   fau CVM_FAU_IP_FRAGS_TIMEDOUT
	      size = 8
	      description = "64-bit counter used for IP frags timeout";

	   fau CVM_FAU_IP_PACKETS_FORWARDED
	      size = 8
	      description = "64-bit counter used for IP packets forwarded";

	   fau CVM_FAU_IP_PACKETS_FAST_FORWARDED
	      size = 8
	      description = "64-bit counter used for IP packets fast forwarded";

	   fau CVM_FAU_IP_PACKETS_CANT_FORWARD
	      size = 8
	      description = "64-bit counter used for IP packets that could not be forwarded";

	   fau CVM_FAU_IP_ICMP_REDIRECTS
	      size = 8
	      description = "64-bit counter used for ICMP redirects";

	   fau CVM_FAU_IP_UNKNOWN_PROTO
	      size = 8
	      description = "64-bit counter used for IP packets rcvd with unknown protocol";

	   fau CVM_FAU_IP_PACKETS_DELIVERED
	      size = 8
	      description = "64-bit counter used for IP packets delivered to application";

	   fau CVM_FAU_IP_PACKETS_GENERATED
	      size = 8
	      description = "64-bit counter used for IP packets generated";

	   fau CVM_FAU_IP_NOBUF_DROP
	      size = 8
	      description = "64-bit counter used for IP packets dropped du to no buffers";

	   fau CVM_FAU_IP_PACKETS_REASSEMBLED
	      size = 8
	      description = "64-bit counter used for IP packets reassembled";

	   fau CVM_FAU_IP_PACKETS_FRAGMENTED
	      size = 8
	      description = "64-bit counter used for IP packets fragmented";

	   fau CVM_FAU_IP_FRAGMENTS_CREATED
	      size = 8
	      description = "64-bit counter used for IP fragments created";

	   fau CVM_FAU_IP_CANT_FRAG
	      size = 8
	      description = "64-bit counter used for IP packets that can't be fragmented";

	   fau CVM_FAU_IP_PACKET_WITH_BAD_OPTION
	      size = 8
	      description = "64-bit counter used for IP packets rcvd with bad options";

	   fau CVM_FAU_IP_NOROUTE_DROP
	      size = 8
	      description = "64-bit counter used for IP packets dropped due to no route";

	   fau CVM_FAU_IP_BAD_VERSION
	      size = 8
	      description = "64-bit counter used for IP packets rcvd with bad version number";

	   fau CVM_FAU_IP_RAW_PKT
	      size = 8
	      description = "64-bit counter used for raw IP packets rcvd";

	   fau CVM_FAU_IP_PACKET_TOO_LONG
	      size = 8
	      description = "64-bit counter used for too long IP packets";

	   fau CVM_FAU_IP_NON_MEMBER
	      size = 8
	      description = "64-bit counter used for non member IP packets";

	   fau CVM_FAU_IP_NO_GIF
	      size = 8
	      description = "64-bit counter used for no GIF match";

	   fau CVM_FAU_IP_BAD_ADDR
	      size = 8
	      description = "64-bit counter used for IP packets rcvd with bad address";

	   fau CVM_FAU_ENET_INPUT_BYTES
	      size = 8
	      description = "64-bit counter used for total ethernet input bytes";

	   fau CVM_FAU_ENET_OUTPUT_BYTES
	      size = 8
	      description = "64-bit counter used for total ethernet output bytes";

	   fau CVM_FAU_ENET_INPUT_PACKETS
	      size = 8
	      description = "64-bit counter used for total ethernet input packets";

	   fau CVM_FAU_ENET_OUTPUT_PACKETS
	      size = 8
	      description = "64-bit counter used for total ethernet output packets";
	}
#endif
#endif  /* __IP_CONFIG_H__ */
