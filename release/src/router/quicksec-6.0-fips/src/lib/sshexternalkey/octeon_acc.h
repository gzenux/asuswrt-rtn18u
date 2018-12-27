/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef OCTEON_ACC_H
#define OCTEON_ACC_H

#include "genaccprov.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_EXTERNALKEY_CAVIUM_OCTEON
extern struct SshAccDeviceDefRec ssh_acc_dev_octeon_ops;
#endif /* ENABLE_EXTERNALKEY_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#endif /* ! OCTEON_ACC_H */
