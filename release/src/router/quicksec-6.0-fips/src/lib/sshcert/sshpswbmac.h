/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the password based mac of RFC-2510.
*/

#ifndef SSHPSWBMAC_H
#define SSHPSWBMAC_H

#include "sshcrypt.h"
#include "sshasn1.h"

typedef struct
{
  unsigned char *salt;
  size_t         salt_length;

  /* Hash algorithm. */
  char          *hash_name;

  /* Iteration count. */
  unsigned int  iteration_count;

  /* Mac algorithm. */
  char         *mac_name;
} *SshPSWBMac, SshPSWBMacStruct;


/* This definition gives the maximum number of iterations that are
   spend in computing the salted key for the mac. Should be reasonably
   large, but not too large.

   This value is a guess, and it may be that larger value could be
   suitable. */
#define SSH_PSWBMAC_MAX_ITERATIONS 2048

/* The only defined OID for Password based MACS. It is possible that
   in future implementations different ways of handling the
   identification will be used. */
#define SSH_PSWBMAC_OID "1.2.840.113533.7.66.13"

/* Get the mac. The output mac is a reference to the internal mac
   algorithm allocated. It should not be freed nor used as several
   instances. */
SshMac ssh_pswbmac_allocate_mac(SshPSWBMac param,
                                const unsigned char *key,
                                size_t key_length);

/* Free an allocated param. This frees all the input fields. The
   "hash_name" and "mac_name" are also freed, and they cannot hence be
   constant strings. */
void ssh_pswbmac_free(SshPSWBMac param);

/* Encode/decode parameters into/from DER ASN.1. */

SshAsn1Node
ssh_pswbmac_encode_param(SshAsn1Context context, SshPSWBMac param);

SshPSWBMac
ssh_pswbmac_decode_param(SshAsn1Context context, SshAsn1Node node);

#endif /* SSHPSWBMAC_H */
