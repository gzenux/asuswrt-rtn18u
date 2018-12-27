/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to output structured object other than certificates,
   plain public and private keys, or certificate lists (on
   certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshmp.h"
#include "x509.h"
#include "x509cmp.h"
#include "x509scep.h"
#include "oid.h"
#include "iprintf.h"

#define SSH_DEBUG_MODULE "SshDumpCRL"

Boolean cu_dump_cmp(SshCmpMessage m, unsigned char *der, size_t der_len)
{
  ssh_warning("dump_cmp not implemented");
  return FALSE;
}

Boolean cu_dump_scep(void *m, unsigned char *der, size_t der_len)
{
  ssh_warning("dump_scep not implemented");
  return FALSE;
}
#endif /* SSHDIST_CERT */
