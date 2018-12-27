/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the Quicksec policy manager NAT functionality.
*/

#ifndef NAT_INTERNAL_H
#define NAT_INTERNAL_H

#include "sshincludes.h"

#ifdef SSHDIST_IPSEC_NAT

/** A NAT waiting for its interface to come up.  Once the interface is
   known, the NAT is installed and the record can be reused. */
struct SshPmIfaceNatRec
{
  /** Link field for list of pending operations. */
  struct SshPmIfaceNatRec *next;

  /** The name of the interface.  Keep this value in synchronization
     with `interceptor.h' interface name length. */
  char ifname[32];

  /** NAT type. */
  SshPmNatType type;

  /* Do we NAT packets with IPv6 addresses? */
  SshPmNatFlags flags;
};

typedef struct SshPmIfaceNatRec SshPmIfaceNatStruct;
typedef struct SshPmIfaceNatRec *SshPmIfaceNat;


/** Allocate a new interface NAT structure. */
SshPmIfaceNat ssh_pm_iface_nat_alloc(SshPm pm);

/** Free pending interface NAT `nat' and put it back to the policy
   manager's freelist. */
void ssh_pm_iface_nat_free(SshPm pm, SshPmIfaceNat nat);

#endif /* SSHDIST_IPSEC_NAT */
#endif /* not NAT_INTERNAL_H */
