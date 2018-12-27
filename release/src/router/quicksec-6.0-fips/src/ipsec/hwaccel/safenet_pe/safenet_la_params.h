/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tunable configuration parameters for safenet_la.c.
*/

#ifndef SAFENET_LA_PARAMS_H
#define SAFENET_LA_PARAMS_H

/* Perform zero-copying handling of packet data if possible. This define
   should only be enabled on environments where packet data can be assumed
   to be from DMA'able memory. This parameter cannot be enabled on non-Linux
   platforms. */
#undef SSH_SAFENET_PACKET_IS_DMA
#define SSH_SAFENET_PACKET_IS_DMA

/* Define this to enable some extra heavy debugging. No not enable in
   production systems. */
#undef SAFENET_DEBUG_HEAVY

/****************** PLATFORM DEPENDENT DEFINITIONS ***************************/

/* Here follow definitions, whose actual values must be defined in the platform
   dependent file, for example, in safenet_pe_405EX_params.h */

#if defined(SAFENET_PE_PLATFORM_1742)
#include "safenet_pe_pec_1742_params.h"
#elif defined(SAFENET_PE_PLATFORM_1746)
#include "safenet_pe_pec_1746_params.h"
#elif defined(SAFENET_PE_PLATFORM_EIP93)
#include "safenet_pe_pec_eip93_params.h"
#else
#error Safenet Packet Engine API platform is not defined !!!
#endif /* SAFENET_PE_PLATFORM_1742 */

/* If endianess of the Packet Engine HW is different than that one of the CPU,
   then some data has to be swapped when preparing SA's for Packet Engine HW.
   This setting is used for data manipulation algorithms,
   when building SA data. */
#undef PE_REQUIRES_SWAP
#ifdef SAFENET_PE_PLATFORM_PE_REQUIRES_SWAP
#define PE_REQUIRES_SWAP
#endif

/* MAX PDR SIZE:
   The maximum number of operations allowed in the PDR queue ring. */
#define SSH_SAFENET_MAX_QUEUED_OPERATIONS \
  SAFENET_PE_PLATFORM_SSH_SAFENET_MAX_QUEUED_OPERATIONS

/* POLLING: Depending on the system properties it may be advisable to
   poll for results instead of receiving them from interrupts. This is
   true especially for the low CPU systems. */
#undef SSH_SAFENET_POLLING
#ifdef SAFENET_PE_PLATFORM_SSH_SAFENET_POLLING
  #define SSH_SAFENET_POLLING
#endif

/* CACHE ALIGNMENT: Some systems get considerable performance gain if
   the SA record is cache aligned so that UDM does not have to do
   this. Currently this only works for LINUX. */
/* Allocate non-cacheable memory buffers for SA records. This would
   remove data inconsistency between main memory and D-cache. */
#undef SSH_SAFENET_NOT_COHERENT_CACHE
#ifdef SAFENET_PE_PLATFORM_SSH_SAFENET_NOT_COHERENT_CACHE
  #define SSH_SAFENET_NOT_COHERENT_CACHE
#endif

/* The buffer for an SA passed to the SafeNet device driver will be allocated
   in memory cache-aligned and padded so that no other data resides
   in the same cache line.
   This can be defined together with UDM_NO_CACHE_ALIGN_CHECK in device
   driver which will prevent the driver from allocating bounce buffers.
   CAUTION: If defined application (Ethernet driver) should also supply
   properly allocated packet buffers for udm_pkt_put() call! */
#undef SSH_SAFENET_SA_CACHE_ALIGN
#if defined(L1_CACHE_BYTES) && defined(L1_CACHE_ALIGN)
#define SSH_SAFENET_SA_CACHE_ALIGN
#endif


/* Minimize the byte swapping performed by the driver for big endian
   CPUs with little endian packet engine that cannot perform endianness
   conversion in HW such as AMCC 440EPx with EIP94 v1.2 PLB */
#undef SSH_SAFENET_MIN_BYTE_SWAP
#ifdef SAFENET_PE_PLATFORM_SSH_SAFENET_MIN_BYTE_SWAP
  #define SSH_SAFENET_MIN_BYTE_SWAP
#endif

/* Utilize the internal SA cache of the packet engine. Packet engine must
 *    support this functionality before it can be enabled */
#undef SSH_SAFENET_PE_SA_CACHING
#ifdef SAFENET_PE_PLATFORM_SSH_SAFENET_PE_SA_CACHING
#define SSH_SAFENET_PE_SA_CACHING
#endif

/* PACKETS PER INTERRUPT:
   How many UDM_PKT packets should be processed by the packet engine until
   it generates an interrupt.
   This value cannot be greater than max PDR interrupt count
   defined in UDM driver (udm\driver\generic\udm_init.c).
   Currently this value is 0x3f (63) This is not checked during compile time
   but UDM driver initialization will fail if
   SSH_SAFENET_PDR_ENTRIES_PER_INTERRUPT > 63.
   */
#define SSH_SAFENET_PDR_ENTRIES_PER_INTERRUPT			\
  SAFENET_PE_PLATFORM_SSH_SAFENET_PDR_ENTRIES_PER_INTERRUPT


/* How many packet descriptors to retrieve when calling pkt_get.
*/
#define SSH_SAFENET_PDR_GET_COUNT		\
  SAFENET_PE_PLATFORM_SSH_SAFENET_PDR_GET_COUNT

/* POLLING BURST MODE: How many packets must be accumulated in the
   Quicksec glue layer, before pkt_put and corresponding pkt_get will
   be called. If this value is greater than 1, then glue layer
   implementation is switched to the so called buffering mode, when
   pkt_put is called more than 1 packets.  Sometimes it allows to
   achieve quite good performance optimization for some systems, up to
   100%. Especially this is true for the systems with small I-cache
   size, 16 KB or so.  The most appropriate value here is the buffer
   size of the Ethernet controller, in terms of the maximum number of
   packets (of MTU size, 1500B) the Ethernet controller can store
   internally.  For Linux kernel this is defined by the
   CONFIG_IBM_EMAC_POLL_WEIGHT constant.

   This setting must be less or equal than Ring Size used
   in the corresponding Look-aside HW accelerator driver
*/
#define SSH_SAFENET_PDR_BURST_COUNT			\
  SAFENET_PE_PLATFORM_SSH_SAFENET_PDR_BURST_COUNT

/* ANTI-LATENCY TIMER:
   A special polling timer to reduce packet latency by calling
   ssh_safenet_pdr_bh_cb() periodically to get processed packets from UDM
*/
#undef SSH_SAFENET_PKTGET_TIMER
#ifdef SSH_SAFENET_POLLING
#define SSH_SAFENET_PKTGET_TIMER
#endif

/* ANTI-LATENCY TIMER:
   Period for this special timer, in milliseconds
   This period defines, in fact, a desired packet latency in the system.
*/
#define SSH_SAFENET_PKTGET_TIMER_PERIOD 100
#endif /* SAFENET_LA_PARAMS_H */
