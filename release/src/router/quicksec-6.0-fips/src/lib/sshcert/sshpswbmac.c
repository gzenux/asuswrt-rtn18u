/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Password based MAC routine as in CRMF and CMP.
*/

#include "sshincludes.h"
#include "sshpswbmac.h"
#include "oid.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshPswbMac"

void ssh_pswbmac_free(SshPSWBMac param)
{
  if (param == NULL)
    return;

  ssh_free(param->salt);
  ssh_free(param->hash_name);
  ssh_free(param->mac_name);
  ssh_free(param);
}

SshMac ssh_pswbmac_allocate_mac(SshPSWBMac param,
                                const unsigned char *key,
                                size_t key_length)
{
  SshHash hash;
  SshMac  mac;
  unsigned int i;
  unsigned char basekey[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t basekey_length;

  /* Check the iteration count. */
  if (param->hash_name == NULL || param->mac_name == NULL ||
      param->iteration_count == 0)
    return NULL;

  if (ssh_hash_allocate(param->hash_name, &hash) != SSH_CRYPTO_OK)
    return NULL;

  /* Now work out the "BASEKEY". */
  basekey_length = ssh_hash_digest_length(param->hash_name);

  /* First round. */
  ssh_hash_reset(hash);
  ssh_hash_update(hash, key, key_length);
  ssh_hash_update(hash, param->salt, param->salt_length);
  ssh_hash_final(hash, basekey);

  for (i = 1; i < param->iteration_count &&
         i < SSH_PSWBMAC_MAX_ITERATIONS; i++)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, basekey, basekey_length);
      ssh_hash_final(hash, basekey);
    }
  if (i >= SSH_PSWBMAC_MAX_ITERATIONS)
    {
      /* This appears to be a attempt to spend a long time for nothing. */
      ssh_hash_free(hash);
      return NULL;
    }

  /* Remark. Our current implementatation of the message authentication
     code functions does not need to know the length of the key. That is,
     they work with arbitrary length keys. Thus we do not need to the
     cumbersome key expansion. */

  ssh_hash_free(hash);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
                    ("Base key for mac %s (%d bytes) is",
                     param->mac_name,
                     basekey_length),
                    basekey, basekey_length);

  if (ssh_mac_allocate(param->mac_name,
                       basekey, basekey_length,
                       &mac) != SSH_CRYPTO_OK)
    {
      return NULL;
    }
  return mac;
}

SshAsn1Node ssh_pswbmac_encode_param(SshAsn1Context context,
                                     SshPSWBMac param)
{
  SshAsn1Node node;
  SshAsn1Status status;
  const SshOidStruct *hash_oids, *mac_oids;

  SSH_DEBUG(8, ("hash name: %s, mac name: %s, iteration count: %lu",
                param->hash_name, param->mac_name,
                (unsigned long)param->iteration_count));

  /* Get the oids of the hash and the mac functions. */
  hash_oids = ssh_oid_find_by_alt_name_of_type(param->hash_name,
                                               SSH_OID_HASH);
  if (hash_oids == NULL)
    return NULL;
  mac_oids = ssh_oid_find_by_alt_name_of_type(param->mac_name,
                                              SSH_OID_MAC);
  if (mac_oids == NULL)
    return NULL;

  SSH_TRACE(8, ("hash OID: %s, mac OID: %s, iteration count: %lu",
                hash_oids->oid, mac_oids->oid, param->iteration_count));

  status = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (object-identifier ())"
                                "  (sequence ()"
                                "    (octet-string ())"
                                "    (sequence ()"
                                "      (object-identifier ()))"
                                "    (integer-short ())"
                                "    (sequence ()"
                                "      (object-identifier ()))))",
                                SSH_PSWBMAC_OID,
                                param->salt, param->salt_length,
                                hash_oids->oid,
                                (SshWord) param->iteration_count,
                                mac_oids->oid);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  SSH_DEBUG(5, ("encoded, %d", param->iteration_count));

  return node;
}

SshPSWBMac ssh_pswbmac_decode_param(SshAsn1Context context,
                                     SshAsn1Node node)
{
  SshAsn1Status status;
  SshPSWBMac param;
  char *hash_oid, *mac_oid;
  const SshOidStruct *hash_oids, *mac_oids;
  SshWord iter;

  if ((param = ssh_calloc(1, sizeof(*param))) == NULL)
    return NULL;

  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (octet-string ())"
                              "  (sequence ()"
                              "    (object-identifier ()))"
                              "  (integer-short ())"
                              "  (sequence ()"
                              "    (object-identifier ())))",
                              &param->salt, &param->salt_length,
                              &hash_oid,
                              &iter,
                              &mac_oid);
  param->iteration_count = (unsigned int)iter;

  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_free(param);
      return NULL;
    }

  /* Now wonder how to find the hash and mac names. */
  hash_oids = ssh_oid_find_by_oid(hash_oid);
  mac_oids  = ssh_oid_find_by_oid(mac_oid);
  if (hash_oids == NULL || mac_oids == NULL)
    {
      ssh_free(hash_oid);
      ssh_free(mac_oid);
      ssh_pswbmac_free(param);
      return NULL;
    }

  if ((param->hash_name = ssh_strdup(hash_oids->name)) == NULL ||
      (param->mac_name  = ssh_strdup(mac_oids->name)) == NULL)
    {
      ssh_pswbmac_free(param);
      return NULL;
    }

  ssh_free(hash_oid);
  ssh_free(mac_oid);

  return param;
}

/* sshpswbmac.c */
#endif /* SSHDIST_CERT */
