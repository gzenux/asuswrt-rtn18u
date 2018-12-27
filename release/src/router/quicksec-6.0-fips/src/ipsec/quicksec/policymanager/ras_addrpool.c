/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   An IP address pool.
*/

#include "sshincludes.h"
#include "sshxml.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ras_addrpool.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmRemoteAccessAddrpool"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER


/************************** Types and definitions ***************************/

/* An address range. */
struct SshPmAddressPoolRangeRec
{
  struct SshPmAddressPoolRangeRec *next;

  /* The first address of this range. */
  SshIpAddrStruct base_address;

  /* Number of addresses in range. */
  SshUInt16 num_addrs;

  /* The length of the netmask of addresses of this range. */
  SshUInt16 masklen;

  /* Number of addresses allocated from this range. */
  SshUInt16 num_allocated;

  /* The number of words in the bitmask. */
  SshUInt32 num_words;

  /* Bitmask of available addresses.  The rest of the bitmap follows
     this structure. */
  SshUInt32 bitmask[1];
};

typedef struct SshPmAddressPoolRangeRec SshPmAddressPoolRangeStruct;
typedef struct SshPmAddressPoolRangeRec *SshPmAddressPoolRange;

/* An address pool object. */
typedef struct SshPmAddressPoolInternalRec
{
  /* Common part */
  SshPmAddressPoolStruct ap[1];

  /* Parameters. */

  SshIpAddrStruct own_ip_addr;

  SshUInt32 num_dns;
  SshIpAddrStruct dns[SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT];

  SshUInt32 num_wins;
  SshIpAddrStruct wins[SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT];

  SshIpAddrStruct dhcp;

  SshUInt32 num_subnets;
  SshIpAddrStruct subnets[SSH_PM_REMOTE_ACCESS_NUM_SUBNETS];

  /* The next address to allocate. */
  SshPmAddressPoolRange next_range;
  SshUInt32 next_ip;

  /* Configured addresses. */
  SshPmAddressPoolRange ranges;













  /* Statistics */
  SshUInt32 total_num_allocated;
  SshUInt32 addresses_freed;
  SshUInt32 failed_allocations;

} *SshPmAddressPoolInternal;































/*********** Creating and destroying Address Pool Objects *******************/

SshPmAddressPool
ssh_pm_address_pool_create(void)
{
  SshPmAddressPoolInternal pool;

  pool = ssh_calloc(1, sizeof(*pool));
  if (pool == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate address pool"));
      return NULL;
    }

  pool->ap->next = NULL;
  pool->ap->address_pool_name = NULL;























  return pool->ap;
}

void
ssh_pm_address_pool_destroy(SshPmAddressPool addrpool)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;

  if (addrpool == NULL)
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying address pool, name %s (id %d)",
                               addrpool->address_pool_name,
                               addrpool->address_pool_id));








  /* clear subnets */
  if (!ssh_pm_address_pool_clear_subnets(addrpool))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Address subnet clearing "
                                   "failed for pool '%s' (id %d).",
                                   pool->ap->address_pool_name,
                                   pool->ap->address_pool_id));
    }

  /* clear address ranges */
  if (!ssh_pm_address_pool_clear_ranges(addrpool))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Address range clearing "
                                   "failed for pool '%s' (id %d).",
                                   pool->ap->address_pool_name,
                                   pool->ap->address_pool_id));
    }

  ssh_free(pool->ap->address_pool_name);
  ssh_free(pool);
}


/********************* Address Pool Utility Functions ***********************/

/** Compare two Address Pools. */
Boolean
ssh_pm_address_pool_compare(SshPmAddressPool ap1, SshPmAddressPool ap2)
{
  SshPmAddressPoolInternal pool1 = (SshPmAddressPoolInternal) ap1;
  SshPmAddressPoolInternal pool2 = (SshPmAddressPoolInternal) ap2;
  SshPmAddressPoolRange r1;
  SshPmAddressPoolRange r2;
  int i = 0;







  if (ap1 == NULL || ap2 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid address pool arguments ap1 %p ap2 %p",
                             ap1, ap2));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Comparing address pools: '%s' <<>> '%s'",
             ap1->address_pool_name, ap2->address_pool_name));

  if (SSH_IP_CMP(&pool1->own_ip_addr, &pool2->own_ip_addr))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("own_ip_addr mismatch"));
      return FALSE;
    }

  if (pool1->num_dns != pool2->num_dns
      || memcmp(pool1->dns, pool2->dns, sizeof(*pool1->dns) * pool1->num_dns))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("dns mismatch"));
      return FALSE;
    }

  if (pool1->num_wins != pool2->num_wins
      || memcmp(pool1->wins, pool2->wins,
                sizeof(*pool1->wins) * pool1->num_wins))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("wins mismatch"));
      return FALSE;
    }

  if (SSH_IP_CMP(&pool1->dhcp, &pool2->dhcp))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("dhcp mismatch"));
      return FALSE;
    }








































  /* Compare address ranges */
  for (r1 = pool1->ranges, r2 = pool2->ranges;
       r1 && r2;
       r1 = r1->next, r2 = r2->next)
    {
      if (r1->num_addrs != r2->num_addrs)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("num_addrs mismatch"));
          return FALSE;
        }

      if (r1->masklen != r2->masklen)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("masklen mismatch"));
          return FALSE;
        }

      if (r1->num_words != r2->num_words)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("num_words mismatch"));
          return FALSE;
        }

      /* Check address, should be same */
      if (SSH_IP_CMP(&r1->base_address, &r2->base_address))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("base address mismatch"));
          return FALSE;
        }
    }

  if (r1 || r2)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("number of addresses mismatch"));
      return FALSE;
    }

  if (pool1->num_subnets != pool2->num_subnets)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("subnet mismatch"));
      return FALSE;
    }
  for (i = 0; i < pool1->num_subnets; i++)

    {
      if (SSH_IP_CMP(&pool1->subnets[i], &pool2->subnets[i]))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("subnet mismatch"));
          return FALSE;
        }
    }

  return TRUE;
}

SshUInt32
ssh_pm_address_pool_num_allocated_addresses(SshPmAddressPool addrpool)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshPmAddressPoolRange r;
  SshUInt32 num_allocated = 0;

  /* Loop over all ranges and count allocated addresses from each range. */
  for (r = pool->ranges; r != NULL; r = r->next)
    num_allocated += r->num_allocated;








  return num_allocated;
}


/********* Configuring attributes and addresses to Address Pool *************/

/** Set remote access attributes to an Address Pool. */
Boolean
ssh_pm_address_pool_set_attributes(SshPmAddressPool addrpool,
                                   const unsigned char *own_ip_addr,
                                   const unsigned char *dns,
                                   const unsigned char *wins,
                                   const unsigned char *dhcp)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  char *temp, *dns_copy, *wins_copy;
  SshUInt8 num_of_servers;

  if (own_ip_addr != NULL)
    {
      if (strlen(own_ip_addr) == 0
          || !ssh_ipaddr_parse(&pool->own_ip_addr, own_ip_addr))
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Malformed own IP address `%s'", own_ip_addr));
          return FALSE;
        }
    }

  num_of_servers = 0;
  if (dns != NULL)
    {
      if (strlen(dns) == 0
          || (dns_copy = ssh_strdup((const char *)dns)) == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed DNS address `%s'", dns));
          return FALSE;
        }

      temp = strtok(dns_copy, ";");
      do
        {
          SSH_DEBUG(SSH_D_MY, ("Adding DNS address `%s'", temp));

          if (num_of_servers >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Cannot specify more than %d DNS servers",
                         SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT));
              ssh_free(dns_copy);
              return FALSE;
            }

          if (temp == NULL
              || ssh_ipaddr_parse(&pool->dns[num_of_servers], temp) == FALSE)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Malformed DNS address `%s'", temp));
              ssh_free(dns_copy);
              return FALSE;
            }

          num_of_servers++;
          temp = strtok(NULL,";");
        }
      while (temp != NULL);

      ssh_free(dns_copy);
    }
  pool->num_dns = num_of_servers;

  num_of_servers = 0;
  if (wins != NULL)
    {
      if (strlen(wins) == 0
          || (wins_copy = ssh_strdup((const char *)wins)) == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed wins address `%s'", wins));
          return FALSE;
        }

      temp = strtok(wins_copy, ";");
      do
        {
          SSH_DEBUG(SSH_D_MY, ("Adding WINS address `%s'", temp));

          if (num_of_servers >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Cannot specify more than %d WINS servers",
                         SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT));
              ssh_free(wins_copy);
              return FALSE;
            }

          if (temp == NULL
              || ssh_ipaddr_parse(&pool->wins[num_of_servers], temp) == FALSE)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Malformed WINS address `%s'", temp));
              ssh_free(wins_copy);
              return FALSE;
            }

          /* RFC5996 removed support for INTERNAL_IP6_NBNS, fail address pool
             configuration if given WINS address is IPv6. */
          if (!SSH_IP_IS4(&pool->wins[num_of_servers]))
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("WINS address `%@' is not IPv4",
                         ssh_ipaddr_render, &pool->wins[num_of_servers]));
              ssh_free(wins_copy);
              return FALSE;
            }

          num_of_servers++;
          temp = strtok(NULL,";");
        }
      while (temp != NULL);

      ssh_free(wins_copy);
    }
  pool->num_wins = num_of_servers;

  if (dhcp != NULL)
    {
      if (strlen(dhcp) == 0
          || !ssh_ipaddr_parse(&pool->dhcp, dhcp))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed DHCP address `%s'", dhcp));
          return FALSE;
        }

      SSH_DEBUG(SSH_D_MY, ("Adding DHCP address `%s'", dhcp));
    }

  return TRUE;
}

/** Add a subnet to an Address Pool. */
Boolean
ssh_pm_address_pool_add_subnet(SshPmAddressPool addrpool,
                               const unsigned char *subnet)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshUInt32 i;
  SshIpAddrStruct ip;

  /* Is the sub-network already configured? */
  if (!ssh_ipaddr_parse_with_mask(&ip, subnet, NULL))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Malformed sub-network specification `%s'",
                              subnet));
      return FALSE;
    }
  for (i = 0; i < pool->num_subnets; i++)
    {
      if (SSH_IP_EQUAL(&ip, &pool->subnets[i])
          && SSH_IP_MASK_LEN(&ip) == SSH_IP_MASK_LEN(&pool->subnets[i]))
        /* Found it. */
        return TRUE;
    }

  /* Refuse to configure more subnets than what can be associated with
     an IPSec SA. */
  if (pool->num_subnets >= SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS
      || pool->num_subnets >= SSH_PM_REMOTE_ACCESS_NUM_SUBNETS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Max number of sub-network specifications "
                              "per address pool exceeded"));
      return FALSE;
    }

  /* Add the new sub-network. */
  pool->subnets[pool->num_subnets++] = ip;
  SSH_DEBUG(SSH_D_HIGHOK, ("Added subnet %s to addrpool '%s' (id %d)",
                           subnet, pool->ap->address_pool_name,
                           pool->ap->address_pool_id));

  return TRUE;
}

/** Remove a subnet from an Address Pool. */
Boolean
ssh_pm_address_pool_remove_subnet(SshPmAddressPool addrpool,
                                  const unsigned char *subnet)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshUInt32 i, j;
  SshIpAddrStruct ip;

  /* Parse the subnet. */
  if (!ssh_ipaddr_parse_with_mask(&ip, subnet, NULL))
    {
      /* It was invalid and therefore it can not be in our list of
         sub-networks. */
      return FALSE;
    }

  /* Do we know the subnet? */
  for (i = 0; i < pool->num_subnets; i++)
    {
      if (SSH_IP_EQUAL(&ip, &pool->subnets[i])
          && SSH_IP_MASK_LEN(&ip) == SSH_IP_MASK_LEN(&pool->subnets[i]))
        {
          /* Found it. */

          for (j = i; j < (pool->num_subnets - 1); j++)
            pool->subnets[j] = pool->subnets[j + 1];
          pool->num_subnets--;

          return TRUE;
        }
    }

  /* An unknown sub-network. */
  return FALSE;
}

/** Clear all subnets from an Address Pool. */
Boolean
ssh_pm_address_pool_clear_subnets(SshPmAddressPool addrpool)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshUInt32 i;

  for (i = 0; i < pool->num_subnets; i++)
    SSH_IP_UNDEFINE(&pool->subnets[i]);

  pool->num_subnets = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Cleared subnets from address pool, name '%s' (id %d)",
             pool->ap->address_pool_name, pool->ap->address_pool_id));

  return TRUE;
}

static Boolean
pm_addrpool_parse_with_optional_mask(SshIpAddr ip,
                                     const unsigned char *address,
                                     const unsigned char *netmask)
{
  if (ssh_ipaddr_parse_with_mask(ip, address, netmask))
    return TRUE;

  return ssh_ipaddr_parse(ip, address);
}

static Boolean
parse_address_pool_address(const unsigned char *address,
                           const unsigned char *netmask,
                           SshIpAddr start, SshIpAddr end,
                           SshUInt32 *masklen)
{
  const unsigned char *cp;
  unsigned char buf[SSH_IP_ADDR_STRING_SIZE];
  SshUInt32 num_addrs;
  SshIpAddrStruct tmp, mask;
  SshUInt32 len;

  if (netmask == NULL)
    {
      SSH_IP_UNDEFINE(&mask);
    }
  else
    {
      if (!ssh_ipaddr_parse(&mask, netmask))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid netmask `%s'", netmask));
          return FALSE;
        }
    }

  cp = ssh_ustrchr(address, '-');
  if (cp)
    {
      /* The netmask must be specified. */
      if (netmask == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("No netmask specified for an address range"));
          return FALSE;
        }

      /* An address range. */
      if (cp - address + 1 > sizeof(buf))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid address range `%s'", address));
          return FALSE;
        }

      memcpy(buf, address, cp - address);
      buf[cp - address] = '\0';

      if (!ssh_ipaddr_parse(start, buf))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid address range start `%s'", buf));
          return FALSE;
        }

      if (!pm_addrpool_parse_with_optional_mask(end, cp + 1, netmask))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid address range end `%s'", cp + 1));
          return FALSE;
        }

      *masklen = SSH_IP_MASK_LEN(end);
      SSH_IP_MASK_LEN(end) = SSH_IP_MASK_LEN(start);
    }
  else
    {
      /* A single IP address or a subnet. */
      if (!pm_addrpool_parse_with_optional_mask(start, address, NULL))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid IP address `%s'", address));
          return FALSE;
        }

      /* Resolve netmask. */
      if (netmask)
        {
          if (!pm_addrpool_parse_with_optional_mask(end,
                                                    (SSH_IP_IS4(start)
                                                     ? ssh_custr("0.0.0.0")
                                                     : ssh_custr("::")),
                                                    netmask))
            {
              SSH_DEBUG(SSH_D_ERROR, ("Invalid netmask `%s'", netmask));
              return FALSE;
            }

          *masklen = SSH_IP_MASK_LEN(end);
        }
      else
        {
          /* The address must have been given in `address/masklen'
             format. */
          if (SSH_IP_MASK_LEN(start) == SSH_IP_ADDR_LEN(start) * 8)
            {
              SSH_DEBUG(SSH_D_ERROR, ("No netmask specified for address `%s'",
                                      address));
              return FALSE;
            }

          *masklen = SSH_IP_MASK_LEN(start);

          ssh_ipaddr_set_bits(&mask, start, 0, 1);
          ssh_ipaddr_set_bits(&mask, &mask, *masklen, 0);
        }

      /* An IP address or a subnet. */
      if (SSH_IP_MASK_LEN(start) == SSH_IP_ADDR_LEN(start) * 8)
        {
          /* A single IP address. */
          *end = *start;
        }
      else
        {
          /* A subnet. */

          /* Construct range end address. */
          len = SSH_IP_MASK_LEN(start);
          ssh_ipaddr_set_bits(end, start, len, 1);

          /* Construct range start address. */
          tmp = *start;
          ssh_ipaddr_set_bits(start, &tmp, len, 0);
        }

      SSH_IP_MASK_LEN(start) = SSH_IP_ADDR_LEN(start) * 8;
      SSH_IP_MASK_LEN(end) = SSH_IP_MASK_LEN(start);
    }

  /* Check that start address is not the network address. */
  if (*masklen < (SSH_IP_ADDR_LEN(start) * 8))
    {
      ssh_ipaddr_set_bits(&tmp, start, *masklen, 0);
      if (SSH_IP_EQUAL(start, &tmp))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Removing network address `%@' from range start",
                     ssh_ipaddr_render, &tmp));
          ssh_ipaddr_set_bits(start, &tmp, SSH_IP_ADDR_LEN(&tmp) * 8 - 1, 1);
        }

      /* Check that end address is not the broadcast address. */
      ssh_ipaddr_set_bits(&tmp, end, *masklen, 1);
      if (SSH_IP_EQUAL(end, &tmp))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Removing broadcast address `%@' from range end",
                     ssh_ipaddr_render, &tmp));
          ssh_ipaddr_set_bits(end, &tmp, SSH_IP_ADDR_LEN(&tmp) * 8 - 1, 0);
        }
    }

  /* Sanity check address range. */
  if ((SSH_IP_IS4(start) && !SSH_IP_IS4(end))
      || (SSH_IP_IS6(start) && !SSH_IP_IS6(end))
      || (SSH_IP_IS4(start) && !SSH_IP_IS4(&mask))
      || (SSH_IP_IS6(start) && !SSH_IP_IS6(&mask)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid address specification `%s/%s'",
                              address, netmask));
      return FALSE;
    }

#ifdef WITH_IPV6
  /* Do not accept scope id. */
  if (SSH_IP_IS6(start) &&
      (SSH_IP6_SCOPE_ID(start) != 0 || SSH_IP6_SCOPE_ID(end) != 0
       ||SSH_IP6_SCOPE_ID(&mask) != 0))
    {
      SSH_DEBUG(SSH_D_ERROR, ("IPv6 address specifies scope id"));
      return FALSE;
    }
#endif /* WITH_IPV6 */

  if (SSH_IP_CMP(start, end) > 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid address range `%@-%@'",
                              ssh_ipaddr_render, start,
                              ssh_ipaddr_render, end));
      return FALSE;
    }

  /* Check that range is not larger than the netmask. */
  ssh_ipaddr_set_bits(&tmp, start, 0, 1);
  ssh_ipaddr_set_bits(&tmp, &tmp, *masklen, 0);
  if (!SSH_IP_WITH_MASK_EQUAL(start, end, &tmp))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Address range `%@-%@' does not fit to the netmask `%@'",
                 ssh_ipaddr_render, start,
                 ssh_ipaddr_render, end,
                 ssh_ipaddr_render, &tmp));
      return FALSE;
    }

  /* Check that the address range is not too big. */
  if (SSH_IP_IS6(start)
      && (SSH_IP6_WORD0_TO_INT(end) != SSH_IP6_WORD0_TO_INT(start)
          || SSH_IP6_WORD1_TO_INT(end) != SSH_IP6_WORD1_TO_INT(start)
          || SSH_IP6_WORD2_TO_INT(end) != SSH_IP6_WORD2_TO_INT(start)))
    goto too_big_range;

  /* Count the number of addresses in the range. */
  if (SSH_IP_IS4(start))
    num_addrs = SSH_IP4_TO_INT(end) - SSH_IP4_TO_INT(start) + 1;
  else
    num_addrs = SSH_IP6_WORD3_TO_INT(end) - SSH_IP6_WORD3_TO_INT(start) + 1;

  if (num_addrs > 0xffff)
    goto too_big_range;

  return TRUE;

 too_big_range:
  SSH_DEBUG(SSH_D_ERROR, ("Too big address range `%@-%@'",
                          ssh_ipaddr_render, start,
                          ssh_ipaddr_render, end));
  return FALSE;
}


/** Add an address range to an Address Pool. */
Boolean
ssh_pm_address_pool_add_range(SshPmAddressPool addrpool,
                              const unsigned char *address,
                              const unsigned char *netmask)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshIpAddrStruct start, end;
  SshUInt32 masklen;
  SshUInt32 num_addrs;
  SshPmAddressPoolRange range;
  SshUInt32 i;

  if (!parse_address_pool_address(address, netmask, &start,
                                  &end, &masklen))
    return FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Start address=%@, End address=%@",
                               ssh_ipaddr_render, &start,
                               ssh_ipaddr_render, &end));

  /* Count the number of addresses in the range. */
  if (SSH_IP_IS4(&start))
    num_addrs = SSH_IP4_TO_INT(&end) - SSH_IP4_TO_INT(&start) + 1;
  else
    num_addrs = SSH_IP6_WORD3_TO_INT(&end) - SSH_IP6_WORD3_TO_INT(&start) + 1;

  SSH_ASSERT(num_addrs <= 0xffff);
  SSH_ASSERT(num_addrs > 0);

  /* Check that it does not overlap with existing ranges. */
  for (range = pool->ranges; range; range = range->next)
    {
      SshIpAddrStruct range_end_address;

      /* Compare address families. */
      if ((SSH_IP_IS4(&start) && !SSH_IP_IS4(&range->base_address))
          || (SSH_IP_IS6(&start) && !SSH_IP_IS6(&range->base_address)))
        continue;

      /* Calculate last address in existing range. */
      if (SSH_IP_IS4(&range->base_address))
        SSH_INT_TO_IP4(&range_end_address,
                       SSH_IP4_TO_INT(&range->base_address) +
                       (range->num_addrs - 1));
      else
        {
          memcpy(&range_end_address, &range->base_address,
                 sizeof(range_end_address));
          SSH_IP6_INT_TO_WORD3(&range_end_address,
                               SSH_IP6_WORD3_TO_INT(&range->base_address) +
                               (range->num_addrs - 1));
        }

      /* Check if start of new range is after end of existing range. */
      if (SSH_IP_CMP(&start, &range_end_address) > 0)
        continue;

      /* Check if end of new range is before start of existing range. */
      if (SSH_IP_CMP(&end, &range->base_address) < 0)
        continue;

      /* New range overlaps the existing range. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Range '%@-%@' overlaps an existing range '%@-%@'",
                 ssh_ipaddr_render, &start, ssh_ipaddr_render, &end,
                 ssh_ipaddr_render, &range->base_address,
                 ssh_ipaddr_render, &range_end_address));

      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding range `%@-%@' with %d bit netmask, "
                               "containing %d addresses",
                               ssh_ipaddr_render, &start,
                               ssh_ipaddr_render, &end,
                               (int) masklen, (int) num_addrs));

  range = ssh_calloc(1, sizeof(*range)
                     + (num_addrs - 1) / 32 * sizeof(SshUInt32));
  if (range == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate new address range."));
      return FALSE;
    }

  range->base_address = start;
  range->masklen = masklen;
  range->num_addrs = num_addrs;
  range->num_words = (num_addrs - 1) / 32 + 1;

  /* Set all extra bits of the last word, e.g. mark them as
     reserved. */
  for (i = num_addrs; i / 32 < range->num_words; i++)
    range->bitmask[i / 32] |= (SshUInt32) 1 << (i % 32);

  range->next = pool->ranges;
  pool->ranges = range;

  /* Reset allocation to the beginning of the ranges. */
  pool->next_range = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Added address '%s'/'%s' to address pool '%s' (id %d)",
             address, netmask, pool->ap->address_pool_name,
             pool->ap->address_pool_id));

  return TRUE;
}

/** Remove an address range from an Address Pool. */
Boolean ssh_pm_address_pool_remove_range(SshPmAddressPool addrpool,
                                         const unsigned char *address,
                                         const unsigned char *netmask)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshIpAddrStruct start, end;
  SshUInt32 num_addrs;
  SshPmAddressPoolRange prev, range;
  SshUInt32 i, mask, masklen;

  if (!parse_address_pool_address(address, netmask, &start,
                                  &end, &masklen))
    return FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Start address=%@, End address=%@",
                               ssh_ipaddr_render, &start,
                               ssh_ipaddr_render, &end));

  /* Count the number of addresses in the range. */
  if (SSH_IP_IS4(&start))
    num_addrs = SSH_IP4_TO_INT(&end) - SSH_IP4_TO_INT(&start) + 1;
  else
    num_addrs = SSH_IP6_WORD3_TO_INT(&end) - SSH_IP6_WORD3_TO_INT(&start) + 1;

  SSH_ASSERT(num_addrs <= 0xffff);

  /* Check if this address range is currently configured. */
  prev = NULL;
  for (range = pool->ranges; range; range = range->next)
    {
      if (SSH_IP_EQUAL(&start, &range->base_address) &&
          range->num_addrs == num_addrs)
        {
          /* But only remove the address range if there are no addresses
             within that range currently in use. */
          for (i = 0; i < range->num_words - 1; i++)
            {
              if (range->bitmask[i] != 0)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Cannot remove address range with active "
                             "allocations"));
                  return FALSE;
                }
            }

          mask = 0;

          for (i = num_addrs; i / 32 < range->num_words; i++)
            mask |= (SshUInt32) 1 << (i % 32);

          mask ^= 0xffffffff;

          if (range->bitmask[range->num_words - 1] & mask)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Cannot remove address range with active "
                         "allocations"));
              return FALSE;
            }

          /* Remove range */
          if (prev)
            prev->next = range->next;
          else
            pool->ranges = range->next;

          ssh_free(range);

          return TRUE;
        }

      prev = range;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Address range '%s'/'%s' not found.", address, netmask));

  return FALSE;
}

/** Clear all address ranges from an Address Pool. */
Boolean
ssh_pm_address_pool_clear_ranges(SshPmAddressPool addrpool)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;

  while (pool->ranges)
    {
      SshPmAddressPoolRange range = pool->ranges;

      pool->ranges = range->next;
      ssh_free(range);
    }

  pool->next_range = NULL;
  pool->next_ip = 0;

  return TRUE;
}
























































/*************** Allocating addresses from Address Pools *********************/





































/* Subtract the address 'ip2' from 'ip1', 'ip2' must be less than 'ip1'.
   Returns 0xffffffff if their difference is equal to or larger
   than 2^32 - 1. */
static SshUInt32
pm_ip_addr_subtract(SshIpAddr ip1, SshIpAddr ip2)
{
  SSH_ASSERT(SSH_IP_CMP(ip1, ip2) >= 0);

  if (SSH_IP_IS4(ip1))
    {
      SSH_ASSERT(SSH_IP_IS4(ip2));

      return (SSH_IP4_TO_INT(ip1) - SSH_IP4_TO_INT(ip2));
    }
  else
    {
      SSH_ASSERT(SSH_IP_IS6(ip1));
      SSH_ASSERT(SSH_IP_IS6(ip2));

      if (SSH_IP6_WORD0_TO_INT(ip1) != SSH_IP6_WORD0_TO_INT(ip2)
          || SSH_IP6_WORD1_TO_INT(ip1) != SSH_IP6_WORD1_TO_INT(ip2)
          || SSH_IP6_WORD2_TO_INT(ip1) != SSH_IP6_WORD2_TO_INT(ip2))
        return 0xffffffff;

      return (SSH_IP6_WORD3_TO_INT(ip1) - SSH_IP6_WORD3_TO_INT(ip2));
    }
}

static Boolean
pm_address_pool_alloc_specific(SshPmAddressPoolInternal pool,
                               SshIpAddr addr_out,
                               SshIpAddr addr_requested)
{
  SshPmAddressPoolRange r;














  /* Over all ranges. */
  for (r = pool->ranges; r; r = r->next)
    {
      SshUInt32 diff;

      if ((SSH_IP_IS4(addr_requested) && !SSH_IP_IS4(&r->base_address)) ||
          (SSH_IP_IS6(addr_requested) && !SSH_IP_IS6(&r->base_address)))
        continue;

      /* Check if the requested address is in this address pool range. */
      if (SSH_IP_CMP(addr_requested, &r->base_address) < 0)
        continue;

      diff = pm_ip_addr_subtract(addr_requested, &r->base_address);

      if (diff > r->num_addrs)
        continue;

      /* The requested address is in this address pool range. Now see
         if the address is in use. */
      if ((r->bitmask[diff / 32] & ((SshUInt32) 1 << (diff % 32))) == 0)
        {
          *addr_out = *addr_requested;
          SSH_IP_MASK_LEN(addr_out) = (SshUInt8)r->masklen;

          /* Mark the address as in use. */
          r->bitmask[diff / 32] |= (SshUInt32) 1 << (diff % 32);

          r->num_allocated++;
          SSH_ASSERT(r->num_allocated <= r->num_addrs);
          SSH_ADDRESS_POOL_UPDATE_STATS(pool->total_num_allocated);

          return TRUE;
        }
    }

  return FALSE;
}

static Boolean
pm_address_pool_alloc_any(SshPmAddressPoolInternal pool,
                          SshIpAddr addr_out,
                          int addr_type)
{
  Boolean restart = FALSE;
  SshPmAddressPoolRange r;

  while (1)
    {
      if (pool->next_range == NULL)
        {
          pool->next_range = pool->ranges;
          pool->next_ip = 0;
        }

      /* Over all ranges. */
      for (; pool->next_range;
           (pool->next_range = pool->next_range->next,
            pool->next_ip = 0))
        {
          r = pool->next_range;

          if (addr_type != SSH_IP_TYPE_NONE &&
              r->base_address.type != addr_type)
            continue;

          /* Over all words. */
          for (; pool->next_ip / 32 < r->num_words; pool->next_ip++)
            if ((r->bitmask[pool->next_ip / 32]
                 & ((SshUInt32) 1 << (pool->next_ip % 32))) == 0)
              {
                SshUInt32 i;

                /* Found a free IP. */

                r->bitmask[pool->next_ip / 32]
                  |= (SshUInt32) 1 << (pool->next_ip % 32);

                if (SSH_IP_IS4(&r->base_address))
                  {
                    i = SSH_IP4_TO_INT(&r->base_address);
                    i += pool->next_ip;
                    SSH_INT_TO_IP4(addr_out, i);
                  }
                else
                  {
                    unsigned char buf[16];
                    int j;
                    SshUInt32 carry = pool->next_ip;

                    SSH_IP6_ENCODE(&r->base_address, buf);
                    for (j = 3; j >= 0; j--)
                      {
                        i = SSH_GET_32BIT(buf + j * 4);
                        i += carry;

                        if (i < SSH_GET_32BIT(buf + j * 4))
                          carry = 1;
                        else
                          carry = 0;

                        SSH_PUT_32BIT(buf + j * 4, i);

                        if (carry == 0)
                          break;
                      }

                    SSH_IP6_DECODE(addr_out, buf);
                  }

                pool->next_ip++;
                SSH_IP_MASK_LEN(addr_out) = (SshUInt8)r->masklen;

                r->num_allocated++;
                SSH_ASSERT(r->num_allocated <= r->num_addrs);
                SSH_ADDRESS_POOL_UPDATE_STATS(pool->total_num_allocated);

                return TRUE;
              }
        }

      if (restart)
        return FALSE;

      restart = 1;
    }

  return FALSE;
}

SshOperationHandle
ssh_pm_address_pool_alloc_address(SshPmAddressPool addrpool,
                                 SshPmAuthData ad,
                                 SshUInt32 flags,
                                 SshPmRemoteAccessAttrs requested_attributes,
                                 SshPmRemoteAccessAttrsAllocResultCB result_cb,
                                 void *result_cb_context)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshPmRemoteAccessAttrsStruct attrs[1];
  SshUInt32 i, num_ipv4 = 0, num_ipv6 = 0, count;

  memset(attrs, 0, sizeof(*attrs));

  /* Address renewal does not cause any action. */
  if (flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW)
    {
      if (result_cb != NULL_FNPTR)
        (*result_cb)(requested_attributes, result_cb_context);
      return NULL;
    }

  /* Allocate at most one IPv4 and one IPv6 address. */
  if (requested_attributes && requested_attributes->num_addresses > 0)
    {
      for (i = 0; i < requested_attributes->num_addresses; i++)
        {
          SshIpAddr addr_req = &requested_attributes->addresses[i];
          SshIpAddr addr_out = &attrs->addresses[attrs->num_addresses];
          int addr_type = SSH_IP_TYPE_NONE;

          switch (addr_req->type)
            {
            case SSH_IP_TYPE_IPV4:
              if (num_ipv4 == 0)
                addr_type = SSH_IP_TYPE_IPV4;
              else
                goto fail_and_continue;
              break;

            case SSH_IP_TYPE_IPV6:
              if (num_ipv6 == 0)
                addr_type = SSH_IP_TYPE_IPV6;
              else
                goto fail_and_continue;
              break;

            default:
              if (num_ipv4 == 0 && num_ipv6 == 0)
                addr_type = SSH_IP_TYPE_NONE;
              else if (num_ipv4 == 0)
                addr_type = SSH_IP_TYPE_IPV4;
              else if (num_ipv6 == 0)
                addr_type = SSH_IP_TYPE_IPV6;
              else
                goto fail_and_continue;
              break;
            }

          /* If the client has requested a specific address, then see
             if we can give out that address to the client. If that is
             not available or no specific address was requested, try
             allocating any address (taking into account the address
             family in the request, if any). */

          if ((SSH_IP_DEFINED(addr_req) && !SSH_IP_IS_NULLADDR(addr_req) &&
               pm_address_pool_alloc_specific(pool, addr_out, addr_req)) ||
              pm_address_pool_alloc_any(pool, addr_out, addr_type))
            {
              if (SSH_IP_IS4(addr_out))
                num_ipv4++;
              else
                num_ipv6++;

              if (attrs->num_addresses++ <
                  SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES)
                continue;
            }

        fail_and_continue:
          if (SSH_IP_DEFINED(addr_req) && !SSH_IP_IS_NULLADDR(addr_req))
            SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate address `%@'",
                                   ssh_ipaddr_render, addr_req));
          else if (SSH_IP_DEFINED(addr_req))
            SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate %s address",
                                   addr_type == SSH_IP_TYPE_IPV4 ?
                                   "IPv4" : "IPv6"));
          else
            SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate address"));
        }
    }
  else
    {
      if (pm_address_pool_alloc_any(pool, &attrs->addresses[0],
                                    SSH_IP_TYPE_IPV4))
        {
          attrs->num_addresses++;
          num_ipv4++;
        }

      if (attrs->num_addresses < SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES)
        {
          if (pm_address_pool_alloc_any(pool, &attrs->addresses[1],
                                        SSH_IP_TYPE_IPV6))
            {
              attrs->num_addresses++;
              num_ipv6++;
            }
        }
    }

  if (attrs->num_addresses == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate any addresses"));
      SSH_ADDRESS_POOL_UPDATE_STATS(pool->failed_allocations);

      (*result_cb)(NULL, result_cb_context);
      return NULL;
    }

#ifdef DEBUG_LIGHT
  for (i = 0; i < attrs->num_addresses; i++)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Allocated IP address `%@'",
                 ssh_ipaddr_render, &attrs->addresses[i]));
    }
#endif /* DEBUG_LIGHT */

  /* Set other attributes. Filter out dns, wins and dhcp servers and subnets
     that do not have the same address family as the remote access address
     allocated to the client. */

  attrs->own_address = pool->own_ip_addr;

  count = SSH_MIN(SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT, pool->num_dns);
  for (i = 0; i < count; i++)
    {
      if (SSH_IP_DEFINED(&pool->dns[i])
          && ((num_ipv4 && SSH_IP_IS4(&pool->dns[i]))
              || (num_ipv6 && SSH_IP_IS6(&pool->dns[i]))))
        attrs->dns[attrs->num_dns++] = pool->dns[i];
    }
  SSH_ASSERT(attrs->num_dns <= count);

  count = SSH_MIN(SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT, pool->num_wins);
  for (i = 0; i < count; i++)
    {
      if (SSH_IP_DEFINED(&pool->wins[i])
          && ((num_ipv4 && SSH_IP_IS4(&pool->wins[i]))
              || (num_ipv6 && SSH_IP_IS6(&pool->wins[i]))))
        attrs->wins[attrs->num_wins++] = pool->wins[i];
    }
  SSH_ASSERT(attrs->num_wins <= count);

  if (SSH_IP_DEFINED(&pool->dhcp)
      && ((num_ipv4 && SSH_IP_IS4(&pool->dhcp))
          || (num_ipv6 && SSH_IP_IS6(&pool->dhcp))))
    {
      attrs->num_dhcp = 1;
      attrs->dhcp[0] = pool->dhcp;
    }

  for (i = 0; i < pool->num_subnets; i++)
    {
      if ((num_ipv4 && SSH_IP_IS4(&pool->subnets[i]))
          || (num_ipv6 && SSH_IP_IS6(&pool->subnets[i])))
        attrs->subnets[attrs->num_subnets++] = pool->subnets[i];
    }
  SSH_ASSERT(attrs->num_subnets <= pool->num_subnets);

  /* Call result callback synchronously. */
  (*result_cb)(attrs, result_cb_context);

  return NULL;
}

/******************** Freeing address to Address Pool ***********************/






















Boolean
ssh_pm_address_pool_free_address(SshPmAddressPool addrpool,
                                 const SshIpAddr address)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;
  SshPmAddressPoolRange r;

  SSH_DEBUG(SSH_D_LOWOK, ("Returning address %@ to the address pool",
                          ssh_ipaddr_render, address));







  for (r = pool->ranges; r; r = r->next)
    {
      SshUInt32 delta;

      if ((SSH_IP_IS4(&r->base_address) && !SSH_IP_IS4(address))
          || (SSH_IP_IS6(&r->base_address) && !SSH_IP_IS6(address)))
        continue;

      /* Check if address is below start of this range. */
      if (SSH_IP_CMP(address, &r->base_address) < 0)
        continue;

      if (SSH_IP_IS4(address))
        {
          delta = SSH_IP4_TO_INT(address) - SSH_IP4_TO_INT(&r->base_address);
        }
      else
        {
          if (SSH_IP6_WORD0_TO_INT(address)
              != SSH_IP6_WORD0_TO_INT(&r->base_address))
            continue;
          if (SSH_IP6_WORD1_TO_INT(address)
              != SSH_IP6_WORD1_TO_INT(&r->base_address))
            continue;
          if (SSH_IP6_WORD2_TO_INT(address)
              != SSH_IP6_WORD2_TO_INT(&r->base_address))
            continue;

          delta = (SSH_IP6_WORD3_TO_INT(address)
                   - SSH_IP6_WORD3_TO_INT(&r->base_address));
        }

      /* Check if address is above end of this range. */
      if (delta >= r->num_addrs)
        continue;

      if (delta > 0xffff)
        continue;

      /* This must be the range from which the IP address was
         allocated. */
      if ((r->bitmask[delta / 32] & ((SshUInt32) 1 << (delta % 32))) == 0)
        {
          return FALSE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Freed IP address `%@'",
                     ssh_ipaddr_render, address));
          r->bitmask[delta / 32] &= ~((SshUInt32) 1 << (delta % 32));
          SSH_ASSERT(r->num_allocated > 0);
          r->num_allocated--;
          SSH_ADDRESS_POOL_UPDATE_STATS(pool->addresses_freed);
          return TRUE;
        }
    }

  return FALSE;
}

void ssh_pm_address_pool_get_statistics(SshPmAddressPool addrpool,
                                        SshPmAddressPoolStats stats)
{
  SshPmAddressPoolInternal pool = (SshPmAddressPoolInternal) addrpool;

  stats->current_num_allocated_addresses
    = ssh_pm_address_pool_num_allocated_addresses(addrpool);

  stats->total_num_allocated_addresses = pool->total_num_allocated;
  stats->num_freed_addresses = pool->addresses_freed;
  stats->num_failed_address_allocations = pool->failed_allocations;
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
