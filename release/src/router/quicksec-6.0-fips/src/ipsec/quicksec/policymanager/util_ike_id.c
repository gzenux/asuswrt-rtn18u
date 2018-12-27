/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKE identity utility functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshmatch.h"

#define SSH_DEBUG_MODULE "SshPmIkeId"

SshIkev2PayloadID
ssh_pm_decode_identity(SshPmIdentityType id_type,
                       const unsigned char *identity,
                       size_t identity_len,
                       Boolean *malformed_id_return)
{
  SshIkev2PayloadID id;
  SshIpAddrStruct ip;
  const unsigned char *cp;
#ifdef SSHDIST_CERT
  SshDNStruct dn;
#endif /* SSHDIST_CERT */
#ifdef WITH_MSCAPI
  SshIkev2PayloadID tmp_id;
#endif /* WITH_MSCAPI */
  *malformed_id_return = FALSE;


  if (identity == NULL)
    return NULL;

  id = ssh_calloc(1, sizeof(*id));
  if (id == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate IKE ID"));
      return NULL;
    }

  /* Decode identity. */
  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("Decoding identity of type %d", id_type),
                    identity, identity_len);

  switch (id_type)
    {
    case SSH_PM_IDENTITY_DN:
#ifdef SSHDIST_CERT
      id->id_type = SSH_IKEV2_ID_TYPE_ASN1_DN;

      ssh_dn_init(&dn);

      if (!ssh_dn_decode_ldap(identity, &dn))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Malformed DN identity `%s'", identity));
          *malformed_id_return = TRUE;
          ssh_dn_clear(&dn);
          goto error;
        }

      if (!ssh_dn_encode_der(&dn, &id->id_data, &id->id_data_size, NULL))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not store ASN.1 data"));
          ssh_dn_clear(&dn);
          goto error;
        }

      ssh_dn_clear(&dn);
      break;
#endif /* SSHDIST_CERT */
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
      if (!(tmp_id = ssh_pm_mscapi_str_to_dn(identity)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Malformed DN identity `%s'", identity));
          *malformed_id_return = TRUE;
          goto error;
        }
      memcpy(id, tmp_id, sizeof *id);
      ssh_free(tmp_id);
      break;
#endif /* WITH_MSCAPI */
#else /* SSHDIST_MSCAPI */
      goto error;

      break;
#endif /* SSHDIST_MSCAPI */

    case SSH_PM_IDENTITY_IP:
      if (!ssh_ipaddr_parse(&ip, identity))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed IP address `%s'", identity));
          *malformed_id_return = TRUE;
          goto error;
        }
      if (SSH_IP_IS4(&ip))
        {
          id->id_type = SSH_IKEV2_ID_TYPE_IPV4_ADDR;
          id->id_data_size = 4;
        }
      else
        {
          id->id_type = SSH_IKEV2_ID_TYPE_IPV6_ADDR;
          id->id_data_size = 16;
        }

      if ((id->id_data = ssh_malloc(id->id_data_size)) == NULL)
        goto error;

      SSH_IP_ENCODE(&ip, id->id_data, id->id_data_size);
      break;

    case SSH_PM_IDENTITY_FQDN:
      id->id_type = SSH_IKEV2_ID_TYPE_FQDN;
      id->id_data_size = identity_len;
      if ((id->id_data = ssh_memdup(identity, identity_len)) == NULL)
        goto error;

      break;

    case SSH_PM_IDENTITY_RFC822:
      id->id_type = SSH_IKEV2_ID_TYPE_RFC822_ADDR;

      cp = ssh_ustrchr(identity, '@');
      if (cp == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Malformed RFC822 identity `%s'", identity));
          *malformed_id_return = TRUE;
          goto error;
        }

      id->id_data_size = identity_len;
      if ((id->id_data = ssh_memdup(identity, identity_len)) == NULL)
        goto error;
      break;

    case SSH_PM_IDENTITY_KEY_ID:

      id->id_type =  SSH_IKEV2_ID_TYPE_KEY_ID;
      id->id_data_size = identity_len;
      if ((id->id_data = ssh_memdup(identity, identity_len)) == NULL)
        goto error;

      break;

#ifdef SSHDIST_IKE_ID_LIST
    case SSH_PM_IDENTITY_ID_LIST:
      id->id_type = (int) IPSEC_ID_LIST;
      id->id_data_size = identity_len;

      /* Just copy the input string repesentation of the ID. The fallback
         code will convert this to an IKEv1 ID data structure. */
      if ((id->id_data = ssh_memdup(identity, identity_len)) == NULL)
        goto error;
      break;
#endif /* SSHDIST_IKE_ID_LIST */

    default:
      ssh_free(id);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IKE ID %@", ssh_pm_ike_id_render, id));

  /* All done. */
  return id;

  /* Error handling. */

 error:
  ssh_pm_ikev2_payload_id_free(id);
  return NULL;
}

SshPmIdentityType
ssh_pm_ike_id_type_to_pm_id_type(SshIkev2IDType id_type)
{
  switch (id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      return SSH_PM_IDENTITY_IP;
    case SSH_IKEV2_ID_TYPE_FQDN:
      return SSH_PM_IDENTITY_FQDN;
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      return SSH_PM_IDENTITY_RFC822;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      return SSH_PM_IDENTITY_IP;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
      return SSH_PM_IDENTITY_DN;
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      return SSH_PM_IDENTITY_KEY_ID;
    default:
    SSH_NOTREACHED;
  }
   return SSH_PM_IDENTITY_ANY;
}


SshIkev2PayloadID
ssh_pm_ike_get_identity(SshPm pm, SshPmP1 p1, SshPmTunnel tunnel,
                        Boolean consider_ike_ip_identity)
{
  SshIkev2PayloadIDStruct id_struct;
  unsigned char buf[16];

  if (tunnel->local_identity)
    return ssh_pm_ikev2_payload_id_dup(tunnel->local_identity);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  if (tunnel->u.ike.local_cert_kid != NULL)
    {
      SshIkev2PayloadID *altnames, subject, id;
      size_t i, num_altnames = 0;
      SshCMCertificate cmcert;

      SshX509Certificate x509cert;

      cmcert = ssh_pm_get_certificate_by_kid(pm, tunnel->u.ike.local_cert_kid,
                                             tunnel->u.ike.local_cert_kid_len);
      if (!cmcert)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not find CM certificate."));
          return NULL;
        }

      if (ssh_cm_cert_get_x509(cmcert, &x509cert)
          != SSH_CM_STATUS_OK)
        return NULL;

      subject = ssh_pm_cert_x509_names(x509cert, &altnames, &num_altnames,
                                       NULL);
      ssh_x509_cert_free(x509cert);

      /* Use the subject name if no alternative names are present. */
      if (num_altnames == 0)
        return subject;

      /* Check if the tunnel indicates which identity type to use. */
      if (tunnel->id_type != SSH_PM_IDENTITY_ANY)
        {
          id = NULL;
          for (i = 0; i < num_altnames; i++)
            {
              if (tunnel->id_type ==
                  ssh_pm_ike_id_type_to_pm_id_type(altnames[i]->id_type))
                {
                  id = altnames[i];
                  altnames[i] = NULL;
                  break;
                }
            }
          /* No suitable identity found, use the subject name */
          if (id == NULL)
            {
              id = subject;
              subject = NULL;
            }
        }
      else
        {
          id = altnames[0];
          altnames[0] = NULL;
        }

      for (i = 0; i < num_altnames; i++)
        ssh_pm_ikev2_payload_id_free(altnames[i]);
      ssh_pm_ikev2_payload_id_free(subject);
      ssh_free(altnames);

      return id;
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (consider_ike_ip_identity && p1)
    {
      SshIpAddr ip = p1->ike_sa->server->ip_address;

      memset(&id_struct, 0, sizeof(id_struct));
      if (SSH_IP_IS4(ip))
        {
          id_struct.id_type = SSH_IKEV2_ID_TYPE_IPV4_ADDR;
          id_struct.id_data_size = 4;
        }
      else
        {
          id_struct.id_type = SSH_IKEV2_ID_TYPE_IPV6_ADDR;
          id_struct.id_data_size = 16;
        }

      id_struct.id_data = buf;

      SSH_IP_ENCODE(ip, id_struct.id_data, id_struct.id_data_size);
      return ssh_pm_ikev2_payload_id_dup(&id_struct);
    }

  return NULL;
}


/* Compare two IKE ID payloads. */
Boolean ssh_pm_ikev2_id_compare(SshIkev2PayloadID id1,
                                SshIkev2PayloadID id2)
{
  if (!id1 || !id2)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("both id's are not defined"));
      return FALSE;
    }

  if (id1->id_type != id2->id_type)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("id types differ: %s and %s",
                 ssh_ikev2_id_to_string(id1->id_type),
                 ssh_ikev2_id_to_string(id2->id_type)));
      return FALSE;
    }

  if (id1->id_type == SSH_IKEV2_ID_TYPE_RFC822_ADDR ||
      id1->id_type == SSH_IKEV2_ID_TYPE_FQDN)
    {
      if (id1->id_data_size != id2->id_data_size)
        return FALSE;

      if (strncasecmp((char *)id1->id_data,
                      (char *)id2->id_data,
                      id1->id_data_size))
        return FALSE;

      return TRUE;
    }
  else
    {
      if ((id1->id_data_size != id2->id_data_size) ||
          memcmp(id1->id_data, id2->id_data, id2->id_data_size))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("id data differs"));
          return FALSE;
        }
      return TRUE;
    }
}

Boolean
ssh_pm_ikev2_id_compare_pattern(SshIkev2PayloadID id,
                                SshPmIdentityType type, const char *pattern)
{
  if (!id || !pattern)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("both ID and PATTERN are needed"));
      return FALSE;
    }

  switch (id->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      if (type == SSH_PM_IDENTITY_IP)
        {
          SshIpAddrStruct addr[1];
          char buf[SSH_IP_ADDR_STRING_SIZE];

          SSH_IP_DECODE(addr, id->id_data, id->id_data_size);
          ssh_ipaddr_print(addr, buf, sizeof(buf));
          if (ssh_match_pattern(buf, pattern))
            return TRUE;
        }
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      if (type == SSH_PM_IDENTITY_RFC822 || type == SSH_PM_IDENTITY_FQDN)
        if (ssh_match_pattern(id->id_data, pattern))
          return TRUE;
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
      if (type == SSH_PM_IDENTITY_DN)
        {
#ifdef SSHDIST_CERT
          SshDNStruct dn[1];
          Boolean match = FALSE;
          char *buf;

          ssh_dn_init(dn);
          if (ssh_dn_decode_der(id->id_data, id->id_data_size, dn, NULL))
            {
              if (ssh_dn_encode_ldap(dn, &buf))
                {
                  if (ssh_match_pattern(buf, pattern))
                    match = TRUE;
                  ssh_free(buf);
                }
            }
          ssh_dn_clear(dn);
          return match;
#else /* SSHDIST_CERT */
#ifdef WITH_MSCAPI
          char *buf = NULL;
          if ((buf = ssh_pm_mscapi_dn_to_str(id)) != NULL)
            {
              if (ssh_match_pattern(buf, pattern))
                {
                  ssh_free(buf);
                  return TRUE;
                }
            }
#else /* WITH_MSCAPI */
          return FALSE;
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_CERT */
        }
      break;

    case SSH_IKEV2_ID_TYPE_KEY_ID:
      if (type == SSH_PM_IDENTITY_KEY_ID)
        {
          if (ssh_match_pattern(id->id_data, pattern))
            return TRUE;
        }
      break;
    }
  return FALSE;
}

void ssh_pm_ikev2_payload_id_free(SshIkev2PayloadID id)
{
  if (id)
    {
      ssh_free(id->id_data);
      ssh_free(id);
    }
}

SshIkev2PayloadID ssh_pm_ikev2_payload_id_dup(SshIkev2PayloadID id)
{
  SshIkev2PayloadID dup = NULL;

  if (id == NULL)
    return NULL;

  if ((dup = ssh_calloc(1, sizeof(*dup))) == NULL)
    return NULL;

  if ((dup->id_data = ssh_memdup(id->id_data, id->id_data_size)) == NULL)
    {
      ssh_free(dup);
      return NULL;
    }

  dup->id_type = id->id_type;
  dup->id_reserved = id->id_reserved;
  dup->id_data_size = id->id_data_size;
  return dup;
}


Boolean ssh_pm_ike_check_requested_identity(SshPm pm, SshPmP1 p1,
                                            SshIkev2PayloadID responder_id)
{
  SSH_PM_ASSERT_P1N(p1);

  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0)
    return TRUE;

  /* If the initiator has used the "you Tarzan, Me Jane" option
     and the tunnel->enforce_remote_identity flag is set, then verify
     the responder is actually using the identity "Tarzan". */
  if (p1->n->tunnel->remote_identity &&
      p1->n->tunnel->enforce_remote_id &&
      !ssh_pm_ikev2_id_compare(p1->n->tunnel->remote_identity,
                               responder_id))
    {
      SSH_DEBUG(SSH_D_FAIL, ("The responder has not used the identity "
                             "proposed by the initiator."));
      return FALSE;
    }
  return TRUE;
}


/************************* NAT-T utility functions **************************/

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
void
ssh_pm_ike_id_hash(SshPm pm, unsigned char hash[SSH_ENGINE_PEER_ID_SIZE],
                   SshIkev2PayloadID id)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];

  ssh_hash_reset(pm->hash);
  ssh_hash_update(pm->hash, (unsigned char *) &id->id_type,
                  sizeof(id->id_type));
  ssh_hash_update(pm->hash, id->id_data, id->id_data_size);

  memset(digest, 0, SSH_MAX_HASH_DIGEST_LENGTH);
  if (ssh_hash_final(pm->hash, digest) != SSH_CRYPTO_OK)
    SSH_DEBUG(SSH_D_ERROR, ("Hash failed"));

  /* Use the first bytes of the digest as the hash value. */
  SSH_ASSERT(SSH_ENGINE_PEER_ID_SIZE <= SSH_MAX_HASH_DIGEST_LENGTH);
  memcpy(hash, digest, SSH_ENGINE_PEER_ID_SIZE);
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
