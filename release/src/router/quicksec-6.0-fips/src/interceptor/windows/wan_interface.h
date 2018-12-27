/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the type definitions and function declarations
   for SSH WAN Interface (i.e. dial-up interface) object.
*/

#ifndef SSH_WAN_INTERFACE_H
#define SSH_WAN_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  ENUMERATIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/


/* Forward declarations */
typedef struct SshAdapterRec *SshAdapter;


/*--------------------------------------------------------------------------
  SSHWanInterface

  Description:
  Type definition for a structure containing the information
  of WAN connection endpoint addresses.

  Notes:
  --------------------------------------------------------------------------*/
typedef struct SshWanInterfaceRec
{
  /* For book-keeping purposes */
  LIST_ENTRY link;

  /* Unique interface number (0...N) */
  ULONG ifnum;

  /* Connection specific MTU value */
  size_t link_mtu;

#ifdef NDIS60
  /* LUID of this WAN interface */
  SshUInt64 luid;
#endif /* NDIS60 */
 
  /* Local endpoint parameters */
  struct
    {
    SshIpAddrStruct ip_addr;
    unsigned long phys_addr_len;
    unsigned char phys_addr[16];
    }
  local;

  /* Remote endpoint parameters */
  struct
    {
    SshIpAddrStruct ip_addr;
    unsigned char phys_addr_len;
    unsigned char phys_addr[16];
    }
  remote;
} SshWanInterfaceStruct, *SshWanInterface;


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Extracts needed information from NDIS_WAN_LINE_UP indication and updates
  the contents of given adapter object accordingly.

  Notes:
    This function must be called _after_ the NDIS_WAN_LINE_UP has been 
    forwarded to upper layer protocols. (This is required, otherwise the
    protocol specific fields of NDIS_WAN_LINE_UP indication haven't been
    correctly updated)
  --------------------------------------------------------------------------*/
void
ssh_wan_line_up(SshAdapter adapter,
                PNDIS_WAN_LINE_UP line_up_ind);


/*--------------------------------------------------------------------------
  Extracts needed information from NDIS_WAN_LINE_UP indication and updates
  the contents of given adapter object accordingly.

  Notes:
    This function must be called _after_ the NDIS_WAN_LINE_UP has been 
    forwarded to upper layer protocols. (This is required, otherwise the
    protocol specific fields of NDIS_WAN_LINE_UP indication haven't been
    correctly updated)
  --------------------------------------------------------------------------*/
void 
ssh_wan_line_down(SshAdapter adapter,
                  PNDIS_WAN_LINE_DOWN line_down_ind);


/*--------------------------------------------------------------------------
  Removes Ethernet framing from packet and updates the corresponding SSH
  WAN interface object (associated to given adapter object) to contain
  enough information so the packet can be later directed to correct WAN 
  interface.
  --------------------------------------------------------------------------*/
Boolean
ssh_wan_packet_decapsulate(SshAdapter adapter,
                           SshInterceptorPacket pp);


/*--------------------------------------------------------------------------
  Adds Ethernet framing into given plain IP or IPv6. The plain packet has
  to be previolsly decapsulated by ssh_wan_packet_decapsulate() so the
  adapter object contains enough information to construct correctly
  formatted header.
  --------------------------------------------------------------------------*/
Boolean
ssh_wan_packet_encapsulate(SshAdapter adapter, 
                           SshInterceptorPacket pp);

#ifdef __cplusplus
}
#endif

#endif /* SSH_ADAPTER_H */

