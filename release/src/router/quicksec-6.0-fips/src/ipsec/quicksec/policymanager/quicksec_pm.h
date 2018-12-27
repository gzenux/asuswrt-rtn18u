/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Top-level policy management API for the flow-based IPsec/firewall/IPS
   implementation. (This header file consists of include directives.)
*/

#ifndef VPN_PM_H
#define VPN_PM_H

#include "ipsec_params.h"
#include "sshinet.h"
#include "sshcrypt.h"
#include "interceptor.h"
#include "sshaudit.h"

/** Shared functionality between Quicksec engine and policy manager. */
#include "quicksec_pm_shared.h"

/** Core Quicksec policy manager API */
#include "core_pm.h"

/** IPSec related Quicksec policy manager API */
#include "ipsec_pm.h"

/** Firewall related Quicksec policy manager API. */
#ifdef SSHDIST_IPSEC_FIREWALL
#include "firewall_pm.h"
#endif /* SSHDIST_IPSEC_FIREWALL */

#endif /* VPN_PM_H */
