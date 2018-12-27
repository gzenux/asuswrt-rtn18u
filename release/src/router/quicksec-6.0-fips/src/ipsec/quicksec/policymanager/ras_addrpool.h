/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address pool for allocating remote access IP addresses and
   parameters.
*/

#ifndef PM_REMOTE_ACCESS_ADDRPOOL_H
#define PM_REMOTE_ACCESS_ADDRPOOL_H

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

#include "quicksec_pm_low.h"

/* ************************* Types and definitions ***************************/

/** Internal address pool flag values. */
#define SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED               0x0001
#define SSH_PM_RAS_DHCP_ADDRPOOL                       0x0002
#define SSH_PM_RAS_DHCP_ADDRPOOL_ALLOC_CHECK_ENABLED   0x0004
#define SSH_PM_RAS_DHCP_ADDRPOOL_EXTRACT_CN            0x0008
#define SSH_PM_RAS_DHCP_ADDRPOOL_DESTROYED             0x0010
#define SSH_PM_RAS_DHCP_ADDRPOOL_STANDBY               0x0020
#define SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL           0x0040

/** Address pool ID type. */
typedef SshUInt32 SshPmAddrPoolId;


typedef struct SshPmAddressPoolDataRec
{
  SshPmAddrPoolId id;
  SshUInt32 num_addresses;
  void *data;
} *SshPmAddressPoolData, SshPmAddressPoolDataStruct;

/** Address Pool object. This is the common part of an Address Pool. The
    implementation is free to use whatever internal structure for storing
    the information. This part should not be modified by the address pool
    implementation. */

typedef struct SshPmAddressPoolRec
{
  /** Policy Manager reference. */
  SshPm pm;

  /** Address pool name. */
  char *address_pool_name;

  /** Address pool id. */
  SshPmAddrPoolId address_pool_id;

  /** Next address pool. */
  struct SshPmAddressPoolRec *next;

  /** Flags for Policy Manager. */
  SshUInt32 flags;

} SshPmAddressPoolStruct, *SshPmAddressPool;


/* Macro for address pool statistics. */
#define SSH_ADDRESS_POOL_UPDATE_STATS(a)  \
do                                        \
  {                                       \
    if (a < 0xffffffff)                   \
      a++;                                \
    else                                  \
      a = 1;                              \
  }                                       \
while (0)


/* ***************** Creating and destroying address pools *******************/

/** Create an address pool object.

    @return
    The function returns an address pool object, or NULL if the
    operation fails.

    */
SshPmAddressPool
ssh_pm_address_pool_create(void);

/** Destroy the address pool 'addrpool'.

    @param addrpool
    The address pool to be destroyed.

*/
void
ssh_pm_address_pool_destroy(SshPmAddressPool addrpool);

/** Compare address pools.

    @param ap1
    The first address pool to be compared.

    @param ap2
    The second address pool to be compared.

    @return
    Returns TRUE if the address pools are the same, else returns FALSE.

*/
Boolean
ssh_pm_address_pool_compare(SshPmAddressPool ap1,
                            SshPmAddressPool ap2);


/* ****************** Configuring attributes and addresses *******************/

/** Set the attributes for remote access clients. The address pool
    will include these attributes in the returned
    SshPmRemoteAccessAttrs of an allocation callback.

    @param own_ip_addr
    Specifies the gateway's own IP address used in PPP links. It can
    be left unspecified in which case the own IP address is not
    notified for PPP peers.

    @param own_ip_addr
    Own IP address.

    @param dns
    The address of the DNS server in the private network. This
    attribute can be left unspecified, in which case the attribute is
    not sent for clients.

    @param wins
    The address of the WINS server (NetBIOS name server) in the
    private network. This attribute can be left unspecified, in
    which case the attribute is not sent for clients.

    @param dhcp
    The address of the DHCP server in the private network. This
    attribute can be left unspecified, in which case the attribute is
    not sent for clients.

    @return
    The function returns TRUE if the the attributes were set, and
    FALSE if the operation failed.

    */
Boolean
ssh_pm_address_pool_set_attributes(SshPmAddressPool addrpool,
                                   const unsigned char *own_ip_addr,
                                   const unsigned char *dns,
                                   const unsigned char *wins,
                                   const unsigned char *dhcp);

/** Add an additional subnet that is protected by the gateway to an
    address pool.

    @param addrpool
    The address pool where the subnet is to be added.

    @param subnet
    Specifies the subnet prefix and netmask in string format.

    @return
    This returns TRUE if the subnet was successfully added to the
    address pool, and FALSE if an error occured.

    */
Boolean
ssh_pm_address_pool_add_subnet(SshPmAddressPool addrpool,
                               const unsigned char *subnet);

/** Remove a subnet from an Address Pool.

    @param addrpool
    The address pool from where the subnet is to be removed.

    @param subnet
    Specifies the subnet prefix and netmask in string format.

*/
Boolean
ssh_pm_address_pool_remove_subnet(SshPmAddressPool addrpool,
                                  const unsigned char *subnet);

/** Clear all subnets from an Address Pool.

    @param addrpool
    The address pool from where the subnets are to be removed.

*/
Boolean
ssh_pm_address_pool_clear_subnets(SshPmAddressPool addrpool);

/** Configure new addresses to the address pool 'addrpool'.

    @param addrpool
    The address pool where new addresses are to be configured.

    @param address
    Specifies the addresses to add. They can be given in the following
    formats:

    <TABLE>
    ADDR               a single IP address.
    ADDR1-ADDR2        address range from ADDR1 to ADDR2 (inclusive).
    ADDR/MASKBITS      addresses of the network.
    </TABLE>

    @param netmask
    Specifies the netmask for the addresses of 'address'. If the
    address specifies a network, the netmask argument can be omitted.
    In that case the netmask is taken from the network address
    specification.

    @return
    The function returns TRUE if the addresses were added, or
    FALSE otherwise. If the address pool already contains exactly
    the same addresses, this will not clear the existing range,
    and return TRUE. If the address overlaps in other ways with
    the existing ranges, this will fail.

    */
Boolean
ssh_pm_address_pool_add_range(SshPmAddressPool addrpool,
                              const unsigned char *address,
                              const unsigned char *netmask);

/** Remove addresses from the address pool 'addrpool'.

    @param addrpool
    The address pool from where addresses are to be removed.

    @param address
    Specifies the addresses to remove. They can be given in the
    following formats:

    <TABLE>
    ADDR               a single IP address.
    ADDR1-ADDR2        address range from ADDR1 to ADDR2.
    ADDR/MASKBITS      addresses of the network.
    </TABLE>

    @param netmask
    Specifies the netmask for the addresses of 'address'. If the
    address specifies a network, the netmask argument can be omitted.
    In that case the netmask is taken from the network address
    specification.

    @return
    The function returns TRUE if the addresses were removed, or FALSE
    otherwise. This will return FALSE if there are currently IP
    addresses allocated from the address pool matching the 'address'
    and 'netmask'.

    */
Boolean
ssh_pm_address_pool_remove_range(SshPmAddressPool addrpool,
                                 const unsigned char *address,
                                 const unsigned char *netmask);

/** Clear all addresses from the address pool 'addrpool'.

    @param addrpool
    The address pool from where addresses are to be cleared.

*/
Boolean
ssh_pm_address_pool_clear_ranges(SshPmAddressPool addrpool);





















/* ******************** Allocating and freeing addresses *********************/

/** Return the number of addresses currently allocated from this
    address pool.

    @param addrpool
    The address pool from where the number of addresses is calculated.

    */
SshUInt32
ssh_pm_address_pool_num_allocated_addresses(SshPmAddressPool addrpool);

/** Allocate an IP address from the address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is allocated.

    @param ike_exchange_data
    Contains the exchange data of the IKE negotiation.

    @param requested_attributes
    Contains the attributes requested by the remote access client.

    @param result_cb
    The callback to be called to pass the allocation result either
    synchronously or asynchronously.

    @return
    This returns an operation handle, or NULL if the operation
    completed synchronously.

    */
SshOperationHandle
ssh_pm_address_pool_alloc_address(SshPmAddressPool addrpool,
                                 SshPmAuthData ad,
                                 SshUInt32 flags,
                                 SshPmRemoteAccessAttrs requested_attributes,
                                 SshPmRemoteAccessAttrsAllocResultCB result_cb,
                                 void *result_cb_context);

/** Free IP address 'address' from the address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is to be freed.

    @param address
    The address to be freed.

    @return
    On error this return FALSE, and otherwise TRUE.

    */
Boolean
ssh_pm_address_pool_free_address(SshPmAddressPool addrpool,
                                 const SshIpAddr address);

/** Expose statistics from the generic address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is to be freed.

    @param stats
    The statistics output.
    */
void ssh_pm_address_pool_get_statistics(SshPmAddressPool addrpool,
                                        SshPmAddressPoolStats stats);

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* not PM_REMOTE_ACCESS_ADDRPOOL_H */
