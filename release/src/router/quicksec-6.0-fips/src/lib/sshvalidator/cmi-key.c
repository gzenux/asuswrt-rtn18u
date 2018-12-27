/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Validator search key handling routines.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMiKey"

/* We use here key types defined in cert-db.h and x509.h. These types
   are not compatible, and thus we need to glue them together here. It
   would be nice to have just one key type, but that is a bit
   difficult. */

static Boolean
cm_key_set_name_from_dn(SshCertDBKey **key, SshCMKeyType type, SshDN dn)
{
  unsigned char *der;
  size_t der_len;

  if (ssh_dn_encode_der_canonical(dn, &der, &der_len, NULL) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failure; can't encode DN to canonical DER."));
      ssh_dn_clear(dn);
      return FALSE;
    }
  ssh_dn_clear(dn);
  return ssh_certdb_key_push(key, type, der, der_len, FALSE);
}

Boolean
ssh_cm_key_set_ldap_dn(SshCertDBKey **key, const char *ldap_dn)
{
  SshDNStruct dn;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put LDAP DN to key list."));

  ssh_dn_init(&dn);
  if (ssh_dn_decode_ldap(ssh_custr(ldap_dn), &dn) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failure; can't decode LDAP name."));
      ssh_dn_clear(&dn);
      return FALSE;
    }
  return cm_key_set_name_from_dn(key, SSH_CM_KEY_TYPE_DISNAME, &dn);
}

Boolean
ssh_cm_key_set_dn(SshCertDBKey **key,
                  const unsigned char *der_dn, size_t der_dn_len)
{
  SshDNStruct dn;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put DN to key list."));

  ssh_dn_init(&dn);
  if (ssh_dn_decode_der(der_dn, der_dn_len, &dn, NULL) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failure; can't decode LDAP name."));
      ssh_dn_clear(&dn);
      return FALSE;
    }
  return cm_key_set_name_from_dn(key, SSH_CM_KEY_TYPE_DISNAME, &dn);
}

Boolean
ssh_cm_key_set_directory_name(SshCertDBKey **key, const char *ldap_dn)
{
  SshDNStruct dn;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put LDAP directory name to key list."));

  ssh_dn_init(&dn);
  if (ssh_dn_decode_ldap(ssh_custr(ldap_dn), &dn) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failure; can't encode LDAP name to DN."));
      ssh_dn_clear(&dn);
      return FALSE;
    }

  return cm_key_set_name_from_dn(key, SSH_CM_KEY_TYPE_DIRNAME, &dn);
}

Boolean
ssh_cm_key_set_directory_name_der(SshCertDBKey **key,
                                  const unsigned char *der_dn,
                                  size_t der_dn_len)
{
  SshDNStruct dn;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put directory name to key list."));

  ssh_dn_init(&dn);
  if (ssh_dn_decode_der(der_dn, der_dn_len, &dn, NULL) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failure; can't decode DER to DN."));
      ssh_dn_clear(&dn);
      return FALSE;
    }
  return cm_key_set_name_from_dn(key, SSH_CM_KEY_TYPE_DIRNAME, &dn);
}

Boolean ssh_cm_key_set_dns(SshCertDBKey **key,
                           const char *dns, size_t dns_len)
{
  unsigned char *buf;
  size_t i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put dns to key list."));

  if (dns_len == 0)
    dns_len = strlen(dns);

  if ((buf = ssh_memdup(dns, dns_len)) != NULL)
    {
      for (i = 0; i < dns_len; i++)
        {
          if (isupper(buf[i]))
            buf[i] = tolower(buf[i]);
        }

      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_DNS, buf, dns_len,
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_email(SshCertDBKey **key,
                     const char *email, size_t email_len)
{
  unsigned char *buf;
  size_t i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put email to key list."));

  if (email_len == 0)
    email_len = strlen(email);

  if ((buf = ssh_memdup(email, email_len)) != NULL)
    {
      for (i = 0; i < email_len; i++)
        {
          if (isupper(buf[i]))
            buf[i] = tolower(buf[i]);
        }

      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_RFC822, buf, email_len,
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_uri(SshCertDBKey **key,
                   const char *uri, size_t uri_len)
{
  unsigned char *buf;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put uri to key list."));

  if (uri_len == 0)
    uri_len = strlen(uri);

  if ((buf = ssh_memdup(uri, uri_len)) != NULL)
    {
      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_URI, buf, uri_len,
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_rid(SshCertDBKey **key,
                   const char *rid, size_t rid_len)
{
  unsigned char *buf;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put rid to key list."));

  if (rid_len == 0)
    rid_len = strlen(rid);

  if ((buf = ssh_memdup(rid, rid_len)) != NULL)
    {
      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_RID, buf, rid_len,
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_ip(SshCertDBKey **key,
                  const unsigned char *ip, size_t ip_len)
{
  unsigned char *buf;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put ip to key list."));

  if ((buf = ssh_memdup(ip, ip_len)) != NULL)
    {
      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_IP, buf, ip_len,
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_serial_no(SshCertDBKey **key, SshMPInteger serial_no)
{
  unsigned char *buf;
  size_t buf_len;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put serial no to key list."));

  buf_len = (ssh_mprz_get_size(serial_no, 2) + 7)/8;
  if (buf_len == 0)
    buf_len = 1;

  /* Function to get the serial number msb first the buffer is filled
     throughout. */

  if ((buf = ssh_calloc(1, buf_len)) != NULL)
    {
      ssh_mprz_get_buf(buf, buf_len, serial_no);
      return ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_SERIAL_NO, buf, buf_len,
                                 FALSE);
    }
  return FALSE;
}


/* Handles the local DB id number. */
Boolean
ssh_cm_key_set_cache_id(SshCertDBKey **key, unsigned int id)
{
  unsigned char *buf;

  if ((buf = ssh_calloc(1, sizeof(unsigned int))) != NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Put cache identifier to key list."));
      *((unsigned int *)buf) = id;
      return ssh_certdb_key_push(key,
                                 SSH_CM_KEY_TYPE_IDNUMBER,
                                 buf, sizeof(unsigned int),
                                 FALSE);
    }
  return FALSE;
}

Boolean
ssh_cm_key_set_cert_hash(SshCertDBKey **key,
                         const unsigned char *digest, size_t digest_len)
{
  unsigned char *buf;

  if ((buf = ssh_memdup(digest, digest_len)) != NULL)
    {
      return ssh_certdb_key_push(key,
                                 SSH_CM_KEY_TYPE_CERT_HASH,
                                 buf, digest_len, FALSE);
    }
  return FALSE;
}
/* Question: does the critical names weight more than the
   non-critical? This will return TRUE, if at least one of the names
   were assigned into keys */

Boolean
ssh_cm_key_convert_from_x509_name(SshCertDBKey **key, SshX509Name name,
                                  Boolean crl_uri)
{
  unsigned char *buf;
  size_t buf_len, nassigned = 0;
  Boolean rv;

  /* Push the names in X.509 name structure into the cert db format. */
  for (; name; name = name->next)
    {
      rv = FALSE;

      switch (name->type)
        {
        case SSH_X509_NAME_RFC822:
          /* Copy name and push to the list. */
          buf = ssh_str_get_canonical(name->name, &buf_len);
          rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_RFC822, buf, buf_len,
                                   FALSE);
          break;
        case SSH_X509_NAME_DNS:
          /* Copy name and push to the list. */
          buf = ssh_str_get_canonical(name->name, &buf_len);
          rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_DNS, buf, buf_len,
                                   FALSE);
          break;
        case SSH_X509_NAME_URI:
          /* Copy name and push to the list. */
          buf = ssh_str_get(name->name, &buf_len);
          rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_URI, buf, buf_len,
                                   crl_uri);
          break;
        case SSH_X509_NAME_IP:
          if (name->data_len)
            rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_IP,
                                     ssh_memdup(name->data, name->data_len),
                                     name->data_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_X400:
          if (name->data_len)
            rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_X400,
                                     ssh_memdup(name->data, name->data_len),
                                     name->data_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_OTHER:
          if (name->data_len)
            rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_OTHER,
                                     ssh_memdup(name->data, name->data_len),
                                     name->data_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_RID:
          if (name->data_len)
            rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_RID,
                                     ssh_memdup(name->data, name->data_len),
                                     name->data_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_DN:
          /* Push the name into the key stack after transformation,
             which makes the name as canonical as possible. */
          if ((buf = ssh_cm_get_canonical_dn_der(name, &buf_len)) != NULL)
            rv = ssh_certdb_key_push(key,
                                     SSH_CM_KEY_TYPE_DIRNAME, buf, buf_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_UNIQUE_ID:
          if (name->data_len)
            rv = ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_UNIQUE_ID,
                                     ssh_memdup(name->data, name->data_len),
                                     name->data_len,
                                     FALSE);
          break;
        case SSH_X509_NAME_DISTINGUISHED_NAME:
          /* Push the name into the key stack after transformation,
             which makes the name as canonical as possible. */
          if ((buf = ssh_cm_get_canonical_dn_der(name, &buf_len)) != NULL)
            rv = ssh_certdb_key_push(key,
                                     SSH_CM_KEY_TYPE_DISNAME, buf, buf_len,
                                     FALSE);
          break;
          /* Following names are not supported yet. */
        default:
          rv = FALSE;
          break;
        }

      if (rv)
        nassigned += 1;
    }

  return nassigned != 0;
}


unsigned char *
ssh_cm_get_canonical_dn_der(SshX509Name names, size_t *out_len)
{
  *out_len = 0;

  /* Search for the distinguished name. */
  for (; names; names = names->next)
    {
      if (names->type == SSH_X509_NAME_DISTINGUISHED_NAME)
        {
          unsigned char *der;

          if (names->canon_der == NULL)
            if ((names->canon_der =
                 cm_canon_der(names->ber, names->ber_len,
                              &names->canon_der_len)) == NULL)
              return NULL;

          if ((der = ssh_memdup(names->canon_der, names->canon_der_len))
              != NULL)
            *out_len = names->canon_der_len;
          return der;
        }
    }
  return NULL;
}

/* Returns a digest made using hash over serial_no and name_der, or
   NULL pointer if memory allocation for the operation fails. Input
   digest must be at last of length of output of hash, and output of
   hash first bytes will be filled. Hash will be reset at the
   beginning, but not after. */

unsigned char *
ssh_cm_get_issuer_serial_hash(SshHash hash,
                              SshMPInteger serial_no,
                              unsigned char *name_der, size_t name_der_len,
                              unsigned char *digest)

{
  unsigned char *buf;
  size_t         buf_len;

  buf_len = (ssh_mprz_get_size(serial_no, 2) + 7)/8;
  if (buf_len == 0)
    buf_len = 1;

  if ((buf = ssh_calloc(1, buf_len)) == NULL)
    return NULL;
  ssh_mprz_get_buf(buf, buf_len, serial_no);

  ssh_hash_reset(hash);
  ssh_hash_update(hash, buf, buf_len);
  ssh_hash_update(hash, name_der, name_der_len);
  ssh_hash_final(hash, digest);
  ssh_free(buf);

  return digest;
}

/* OID value for PKIX id-ad-caIssuers as specified in RFC5280 (RFC2459). */
#define SSH_CM_OID_PKIX_ID_AD_CAISSUERS "1.3.6.1.5.5.7.48.2"

Boolean
ssh_cm_key_set_from_cert(SshCertDBKey **key,
                         SshCMKeyClass classp, SshCMCertificate cm_cert)
{
  SshX509Certificate cert = cm_cert->cert;
  SshX509ExtInfoAccess aia, a;
  Boolean critical;
  unsigned char *buf;
  size_t nassigned = 0;
  unsigned char *issuer_name_der, digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t issuer_name_der_len, digest_len;
  SshHash hash;

  if (cert == NULL)
    return FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Put certificate (%s) names to key list.",
             (classp == SSH_CM_KEY_CLASS_SUBJECT ? "subject" : "issuer")));

  switch (classp)
    {
    case SSH_CM_KEY_CLASS_SUBJECT:
      /* Throw in only the subjects names. */
      if (ssh_cm_key_convert_from_x509_name(key, cert->subject_name, FALSE))
        nassigned += 1;

      if (ssh_cm_key_convert_from_x509_name(key,
                                            cert->
                                            extensions.subject_alt_names,
                                            FALSE))
        nassigned += 1;

      /* Also the serial number which is unique under the CA. */
      if (ssh_cm_key_set_serial_no(key, &cert->serial_number))
        nassigned += 1;

      /* Set also the public key for identification. */
      if (ssh_cm_key_set_public_key(key, cert->subject_pkey.public_key))
        nassigned += 1;

      if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) == SSH_CRYPTO_OK)
        {
          issuer_name_der = ssh_cm_get_canonical_dn_der(cert->issuer_name,
                                                        &issuer_name_der_len);

          /* Set also the SI_HASH and CERT_HASH */
          buf = ssh_cm_get_issuer_serial_hash(hash,
                                              &cert->serial_number,
                                              issuer_name_der,
                                              issuer_name_der_len,
                                              digest);
          digest_len = ssh_hash_digest_length(SSH_CM_HASH_ALGORITHM);

          if (buf)
            {
              if (ssh_certdb_key_push(key,
                                      SSH_CM_KEY_TYPE_SI_HASH,
                                      ssh_memdup(digest, digest_len),
                                      digest_len,
                                      FALSE))

                nassigned += 1;
            }

          if (cm_cert->ber)
            {
              ssh_hash_reset(hash);
              ssh_hash_update(hash, cm_cert->ber, cm_cert->ber_length);
              if (ssh_hash_final(hash, digest) == SSH_CRYPTO_OK)
                {
                  if (ssh_certdb_key_push(key,
                                          SSH_CM_KEY_TYPE_CERT_HASH,
                                          ssh_memdup(digest, digest_len),
                                          digest_len,
                                          FALSE))
                    nassigned += 1;
                }
            }
          ssh_hash_free(hash);
          ssh_free(issuer_name_der);
        }
      break;
    case SSH_CM_KEY_CLASS_ISSUER:
      /* Certs can be found from location given at authority info
         access, */
      if (ssh_x509_cert_get_auth_info_access(cert, &aia, &critical))
        {
          for (a = aia; a; a = a->next)
            {
              if (!strcmp(a->access_method, SSH_CM_OID_PKIX_ID_AD_CAISSUERS))
                {
                  if (ssh_cm_key_convert_from_x509_name(key,
                                                        a->access_location,
                                                        FALSE))
                    {
                      SSH_ASSERT((*key) != NULL
                                 && (*key)->type == SSH_CM_KEY_TYPE_URI);
                      (*key)->access_hint = TRUE;
                      nassigned += 1;
                    }
                }
            }
        }
      /* or from the issuer names. */
      if (ssh_cm_key_convert_from_x509_name(key, cert->issuer_name, FALSE))
        nassigned += 1;
      if (ssh_cm_key_convert_from_x509_name(key,
                                            cert->
                                            extensions.issuer_alt_names,
                                            FALSE))
        nassigned += 1;
      /* More? */
      break;
    default:
      ssh_fatal("error: key class %u not supported.", classp);
      break;
    }
  return nassigned != 0;
}

Boolean
ssh_cm_key_set_from_crl(SshCertDBKey **key, SshCMCrl cm_crl)
{
  SshX509ExtIssuingDistPoint point;
  Boolean critical;
  size_t nassigned = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Put CRL names to key list."));

  if (cm_crl->crl == NULL)
    return FALSE;

  /* Issuer */
  if (ssh_cm_key_convert_from_x509_name(key, cm_crl->crl->issuer_name, FALSE))
    nassigned += 1;
  if (ssh_cm_key_convert_from_x509_name(key,
                                        cm_crl->crl->
                                        extensions.issuer_alt_names, FALSE))
    nassigned += 1;

  /* Get the issuing distribution point. */
  if (ssh_x509_crl_get_issuing_dist_point(cm_crl->crl, &point, &critical))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Issuing CRL distribution point available."));

      if (point->full_name)
        {
          if (ssh_cm_key_convert_from_x509_name(key, point->full_name, TRUE))
            nassigned += 1;
        }
      /* Note. Ignores other fields of the distribution point for now.  */
    }

  return nassigned != 0;
}

Boolean ssh_cm_key_push_keys(SshCertDBKey **key, SshCertDBKey *list)
{
  Boolean rv = TRUE;

  for (; rv && list; list = list->next)
    {
      if (!ssh_certdb_key_push(key, list->type,
                               ssh_memdup(list->data, list->data_len),
                               list->data_len, list->crl_uri))
        rv = FALSE;
    }
  return rv;
}

Boolean ssh_cm_key_match(SshCertDBKey *op1, SshCertDBKey *op2)
{
  SshCertDBKey *tmp1, *tmp2;
  size_t match, no_match;
  Boolean some_found;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Match certificate keys."));

  match    = 0;
  no_match = 0;
  some_found = FALSE;

  for (tmp1 = op1; tmp1; tmp1 = tmp1->next)
    for (tmp2 = op2; tmp2; tmp2 = tmp2->next)
      {
        /* Check for same types. */
        if (tmp1->type == tmp2->type)
          {
            if (tmp1->data_len == tmp2->data_len &&
                memcmp(tmp1->data, tmp2->data, tmp1->data_len) == 0)
              {
                switch (tmp1->type)
                  {
                  case SSH_CM_KEY_TYPE_DISNAME:
                    return TRUE;
                  default:
                    match++;
                    break;
                  }
              }
            else
              {
                switch (tmp1->type)
                  {
                  case SSH_CM_KEY_TYPE_DISNAME:
                    return FALSE;
                  default:
                    no_match++;
                    break;
                  }
              }
            some_found = TRUE;
          }
      }

  /* No matches, nor misses. */
  if (some_found == FALSE || match == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Matching of certificate keys failed."));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Matching succeeded."));
  return TRUE;
}
#endif /* SSHDIST_CERT */
