/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshexternalkey_internal.h"
#include "extkeyprov.h"

/* Type for provider ops/type mapping */

#include "dummyprov.h"
#include "genaccprovider.h"





#ifdef SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV
#include "softprovider.h"
#endif /* SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV */

#ifdef SSHDIST_EXTKEY_MSCAPI_PROV
#include "msprovider.h"
#endif /* SSHDIST_EXTKEY_MSCAPI_PROV */

#ifdef ENABLE_EXTERNALKEY_TILEGX
#include "tilegxprovider.h"
#endif /* ENABLE_EXTERNALKEY_TILEGX */

extern struct SshEkProviderOpsRec ssh_ek_fl_ops;

const SSH_DATA_INITONCE
SshEkProviderOps ssh_ek_supported_providers[] =
{

  (SshEkProviderOps) &ssh_ek_gen_acc_ops,

  (SshEkProviderOps) &ssh_ek_fl_ops,





#ifdef WIN32
#ifdef SSHDIST_EXTKEY_MSCAPI_PROV
  (SshEkProviderOps) &ssh_ek_ms_ops,
#endif /* SSHDIST_EXTKEY_MSCAPI_PROV */
#endif /* WIN32 */

#ifdef SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV
  (SshEkProviderOps) &ssh_ek_soft_ops,
#endif /* SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV */

#ifdef ENABLE_EXTERNALKEY_TILEGX
  (SshEkProviderOps) &ssh_ek_tilegx_ops,
#endif /* ENABLE_EXTERNALKEY_TILEGX */

  NULL,
};
