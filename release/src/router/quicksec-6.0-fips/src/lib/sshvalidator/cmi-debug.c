/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Validator debug output routines.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "sshbuffer.h"
#include "oid.h"
#include "sshgetput.h"
#include "sshfingerprint.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMi"

static Boolean
ssh_cm_names_dump(SshBuffer buffer, SshX509Name names);

/* Debug stuff. */
SshBufferStatus ssh_buffer_append_str(SshBuffer buffer, char *str)
{
  return ssh_buffer_append_cstrs(buffer, str, NULL);
}

char *ssh_buffer_make_str(SshBuffer buffer)
{
  return ssh_memdup(ssh_buffer_ptr(buffer), ssh_buffer_len(buffer));
}

const SshKeywordStruct ssh_cm_debug_state_strs[] =
{
  { "certificate-algorithm-mismatch" ,SSH_CM_SSTATE_CERT_ALG_MISMATCH },
  { "certificate-key-usage-mismatch" ,SSH_CM_SSTATE_CERT_KEY_USAGE_MISMATCH },
  { "certificate-not-in-time-interval" ,SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL },
  { "certificate-was-invalid" ,SSH_CM_SSTATE_CERT_INVALID },
  { "certificate-signature-invalid" ,SSH_CM_SSTATE_CERT_INVALID_SIGNATURE },
  { "certificate-was-revoked" ,SSH_CM_SSTATE_CERT_REVOKED },
  { "certificate-was-not-added-to-the-cache",SSH_CM_SSTATE_CERT_NOT_ADDED },
  { "certificate-decoding-failed" ,SSH_CM_SSTATE_CERT_DECODE_FAILED },
  { "certificate-was-not-found" ,SSH_CM_SSTATE_CERT_NOT_FOUND },
  { "certificate-chain-looped" ,SSH_CM_SSTATE_CERT_CHAIN_LOOP },
  { "certificate-critical-extension" ,SSH_CM_SSTATE_CERT_CRITICAL_EXT },
  { "certificate-ca-invalid" ,SSH_CM_SSTATE_CERT_CA_INVALID },
  { "crl-was-too-old" ,SSH_CM_SSTATE_CRL_OLD },
  { "crl-was-invalid" ,SSH_CM_SSTATE_CRL_INVALID },
  { "crl-signature-invalid" ,SSH_CM_SSTATE_CRL_INVALID_SIGNATURE },
  { "crl-was-not-found" ,SSH_CM_SSTATE_CRL_NOT_FOUND },
  { "crl-was-not-added-to-the-cache" ,SSH_CM_SSTATE_CRL_NOT_ADDED },
  { "crl-decoding-failed" ,SSH_CM_SSTATE_CRL_DECODE_FAILED },
  { "crl-valid-only-in-future" ,SSH_CM_SSTATE_CRL_IN_FUTURE },
  { "crl-duplicate-serial-number" ,SSH_CM_SSTATE_CRL_DUPLICATE_SERIAL_NO },
  { "time-interval-was-invalid" ,SSH_CM_SSTATE_INTERVAL_NOT_VALID },
  { "time-information-unavailable" ,SSH_CM_SSTATE_TIMES_UNAVAILABLE },
  { "database-method-search-timeout" ,SSH_CM_SSTATE_DB_METHOD_TIMEOUT },
  { "database-method-search-failed" ,SSH_CM_SSTATE_DB_METHOD_FAILED },
  { "path-was-not-verified" ,SSH_CM_SSTATE_PATH_NOT_VERIFIED },
  { "maximum-path-length-reached" ,SSH_CM_SSTATE_PATH_LENGTH_REACHED },
  { "algorithm-not-allowed" ,SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED },
  { NULL },
};


SshCMStatus ssh_cm_sanity_check(SshCMContext cm)
{
#ifdef DEBUG_LIGHT
  ssh_certdb_sanity_check_dump(cm->db);
#endif /* DEBUG_LIGHT */
  return SSH_CM_STATUS_OK;
}

const SshKeywordStruct ssh_cm_edb_data_types[] = {
  { "Certificate" ,SSH_CM_DATA_TYPE_CERTIFICATE },
  { "CRL" ,SSH_CM_DATA_TYPE_CRL },
  { NULL },
};

const SshKeywordStruct ssh_cm_edb_key_types[] = {
  { "ID", SSH_CM_KEY_TYPE_IDNUMBER },
  { "BER hash", SSH_CM_KEY_TYPE_BER_HASH },
  { "DirName", SSH_CM_KEY_TYPE_DIRNAME },
  { "DisName", SSH_CM_KEY_TYPE_DISNAME },
  { "IP", SSH_CM_KEY_TYPE_IP },
  { "DNS", SSH_CM_KEY_TYPE_DNS },
  { "URI", SSH_CM_KEY_TYPE_URI },
  { "X.400", SSH_CM_KEY_TYPE_X400 },
  { "Serial", SSH_CM_KEY_TYPE_SERIAL_NO },
  { "UID", SSH_CM_KEY_TYPE_UNIQUE_ID },
  { "Email", SSH_CM_KEY_TYPE_RFC822 },
  { "Other", SSH_CM_KEY_TYPE_OTHER },
  { "RID", SSH_CM_KEY_TYPE_RID },
  { "KID", SSH_CM_KEY_TYPE_PUBLIC_KEY_ID },
  { "SerialIssuer hash", SSH_CM_KEY_TYPE_SI_HASH },
  { "UI", SSH_CM_KEY_TYPE_X509_KEY_IDENTIFIER },
  { "CertHash", SSH_CM_KEY_TYPE_CERT_HASH },
  { NULL },
};

static int
cm_edb_key_render(unsigned char *buf, int buf_size,
                  int precision, void *datum)
{
  int i, so_far = 0;
  unsigned char *key = datum;

  for (i = 0; i < precision && so_far < buf_size; i++)
    {
      if (ssh_snprintf(buf + so_far, buf_size - so_far, "%02x", key[i]) < 0)
        break;
      so_far += 2;
    }

  return so_far;
}

static void
cm_make_key_string(unsigned char *buf, size_t buf_size, int key_type,
                   unsigned char *key, size_t key_len)
{
  SshDNStruct dn;
  char *ldap;

  switch (key_type)
    {
    case SSH_CM_KEY_TYPE_DNS:
    case SSH_CM_KEY_TYPE_URI:
    case SSH_CM_KEY_TYPE_X400:
    case SSH_CM_KEY_TYPE_RFC822:
    case SSH_CM_KEY_TYPE_UNIQUE_ID:
      ssh_snprintf(buf, buf_size, "%s", key);
      break;

    case SSH_CM_KEY_TYPE_DIRNAME:
    case SSH_CM_KEY_TYPE_DISNAME:
      ssh_dn_init(&dn);
      if (ssh_dn_decode_der(key, key_len, &dn, NULL))
        {
          if (ssh_dn_encode_ldap(&dn, &ldap))
            {
              strncpy(ssh_sstr(buf), ldap, buf_size);
              ssh_free(ldap);
            }
        }
      ssh_dn_clear(&dn);
      break;

    case SSH_CM_KEY_TYPE_RID:
    case SSH_CM_KEY_TYPE_OTHER:
    case SSH_CM_KEY_TYPE_SERIAL_NO:
    case SSH_CM_KEY_TYPE_BER_HASH:
    case SSH_CM_KEY_TYPE_IDNUMBER:
    case SSH_CM_KEY_TYPE_PUBLIC_KEY_ID:
    case SSH_CM_KEY_TYPE_SI_HASH:
    case SSH_CM_KEY_TYPE_X509_KEY_IDENTIFIER:
    case SSH_CM_KEY_TYPE_CERT_HASH:
      ssh_snprintf(buf, buf_size, "%.*@",
                   key_len, cm_edb_key_render, key);
      break;
    default:
      buf[0] = '\0';
      break;
    }
}

int
ssh_cm_edb_distinguisher_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  SshCMDBDistinguisher *d = datum;
  unsigned char tmp[256];
  int nbytes;

  cm_make_key_string(tmp, sizeof(tmp), d->key_type, d->key, d->key_length);

  nbytes =
    ssh_snprintf(buf, buf_size, "%s by %s[%s]",
                 ssh_find_keyword_name(ssh_cm_edb_data_types, d->data_type),
                 ssh_find_keyword_name(ssh_cm_edb_key_types, d->key_type),
                 tmp);
  if (nbytes == -1)
    return buf_size + 1;
  else
    return nbytes;
}

int
ssh_cm_render_cert_db_key(unsigned char *buf, int buf_size, int precision,
                          void *datum)
{
  SshCertDBKey *k = datum;
  unsigned char tmp[256];
  int nbytes;

  cm_make_key_string(tmp, sizeof(tmp), k->type, k->data, k->data_len);

  if (k->type == SSH_CM_KEY_TYPE_URI)
    {
      nbytes =
        ssh_snprintf(buf, buf_size, "%s%s[%s]",
                     ((k->crl_uri == TRUE) ? "CRL-" : "CERT-"),
                     ssh_find_keyword_name(ssh_cm_edb_key_types, k->type),
                     tmp);
    }
  else
    {
      nbytes =
        ssh_snprintf(buf, buf_size, "%s[%s]",
                     ssh_find_keyword_name(ssh_cm_edb_key_types, k->type),
                     tmp);
    }

  if (nbytes == -1)
    return buf_size + 1;
  else
    return nbytes;

}

static Boolean
ssh_cm_names_dump(SshBuffer buffer, SshX509Name names)
{
  char *name;
  unsigned char tmp_str[512];
  unsigned char *buf;
  size_t buf_len;

  while (ssh_x509_name_pop_ip(names, &buf, &buf_len))
    {
      if (buf_len == 4)
        ssh_snprintf(tmp_str, sizeof(tmp_str), "%d.%d.%d.%d",
                     (int)buf[0], (int)buf[1], (int)buf[2],
                     (int)buf[3]);
      else
        {
          size_t len;
          int i;

          len = 0;
          for (i = 0; i < buf_len; i++)
            {
              ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len,
                           "%02x", buf[i]);
              len += ssh_ustrlen(tmp_str + len);
              if (i != buf_len - 1 && (i & 0x1) == 1)
                {
                  ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len, ":");
                  len++;
                }
            }
        }

      if (ssh_buffer_append_str(buffer, "    ip = ") != SSH_BUFFER_OK)
        {
          ssh_free(buf);
          return FALSE;
        }

      if (ssh_buffer_append_cstrs(buffer, tmp_str, NULL) != SSH_BUFFER_OK)
        {
          ssh_free(buf);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, "\n") != SSH_BUFFER_OK)
        {
          ssh_free(buf);
          return FALSE;
        }

      ssh_free(buf);
    }

  while (ssh_x509_name_pop_dns(names, &name))
    {
      if (ssh_buffer_append_str(buffer, "    dns = ") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, name) != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, "\n") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      ssh_free(name);
    }
  name = NULL;

  while (ssh_x509_name_pop_uri(names, &name))
    {
      if (ssh_buffer_append_str(buffer, "    uri = ") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, name) != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, "\n") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      ssh_free(name);
    }
  name = NULL;

  while (ssh_x509_name_pop_email(names, &name))
    {
      if (ssh_buffer_append_str(buffer, "    email = ") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, name) != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, "\n") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      ssh_free(name);
    }
  name = NULL;

  while (ssh_x509_name_pop_rid(names, &name))
    {
      if (ssh_buffer_append_str(buffer, "    rid = ") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }
      if (ssh_buffer_append_str(buffer, name) != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, "\n") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      ssh_free(name);
    }

  while (ssh_x509_name_pop_directory_name(names, &name))
    {
      if (ssh_buffer_append_str(buffer, "    directory-name = <")
          != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, name) != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      if (ssh_buffer_append_str(buffer, ">\n") != SSH_BUFFER_OK)
        {
          ssh_free(name);
          return FALSE;
        }

      ssh_free(name);
    }

  return TRUE;
}

static int
cm_debug_renderer_return(SshBuffer buffer, unsigned char *buf, int len)
{
  int l = ssh_buffer_len(buffer);

  if (l > len)
    {
      ssh_ustrncpy(buf, ssh_buffer_ptr(buffer), len - 1);
      ssh_buffer_uninit(buffer);
      return len + 1;
    }
  else
    {
      ssh_ustrncpy(buf, ssh_buffer_ptr(buffer), l);
      ssh_buffer_uninit(buffer);
      return l;
    }
}


int
ssh_cm_render_crl(unsigned char *buf, int len, int precision, void *datum)
{
  SshX509Crl crl = datum;
  char *name;
  SshBerTimeStruct this_update, next_update;
  SshBufferStruct buffer;
  SshBufferStatus buf_status;

  if (crl)
    {
      ssh_buffer_init(&buffer);

      if (ssh_buffer_append_str(&buffer, "\ncrl = { \n") != SSH_BUFFER_OK)
        goto fail;

      if (!ssh_x509_crl_get_issuer_name(crl, &name))
        {
          if (ssh_buffer_append_str(&buffer, "  missing-issuer-name\n")
              != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          buf_status = ssh_buffer_append_cstrs(&buffer,
                                               "  issuer-name = <",
                                               name, ">\n", NULL);
          ssh_free(name);

          if (buf_status != SSH_BUFFER_OK)
            goto fail;
        }

      if (!ssh_x509_crl_get_update_times(crl, &this_update, &next_update))
        {
          if (ssh_buffer_append_str(&buffer, "  missing-update-times\n")
              != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          if (ssh_ber_time_available(&this_update))
            {
              ssh_ber_time_to_string(&this_update, &name);

              buf_status = ssh_buffer_append_cstrs(&buffer,
                                                   "  this-update = ",
                                                   name, "\n", NULL);
              ssh_free(name);

              if (buf_status != SSH_BUFFER_OK)
                goto fail;
            }
          if (ssh_ber_time_available(&next_update))
            {
              ssh_ber_time_to_string(&next_update, &name);
              buf_status = ssh_buffer_append_cstrs(&buffer,
                                                   "  next-update = ",
                                                   name, "\n", NULL);
              ssh_free(name);

              if (buf_status != SSH_BUFFER_OK)
                goto fail;
            }
        }

      /* Finished. */
      if (ssh_buffer_append_str(&buffer, "}\n") != SSH_BUFFER_OK)
        goto fail;

      return cm_debug_renderer_return(&buffer, buf, len);
    }

  return 0;

 fail:
  ssh_buffer_uninit(&buffer);
  return 0;
}

int
ssh_cm_render_mp(unsigned char *buf, int len, int precision, void *datum)
{
  SshMPInteger mpint;
  char *tmp;
  SshBufferStruct buffer;

  mpint = datum;
  tmp = ssh_mprz_get_str(mpint, 10);
  if (tmp != NULL)
    {
      ssh_buffer_init(&buffer);
      if (ssh_buffer_append_str(&buffer, tmp) != SSH_BUFFER_OK)
        {
          ssh_free(tmp);
          ssh_buffer_uninit(&buffer);
          goto fail;
        }

      ssh_free(tmp);
      return cm_debug_renderer_return(&buffer, buf, len);
    }

  return 0;

 fail:
  return 0;
}

int
ssh_cm_render_state(unsigned char *buf, int len, int precision, void *datum)
{
  SshCMSearchState *state_p = (void *) &datum;
  SshCMSearchState state =  *state_p;
  int i;
  const char *name;
  SshBufferStruct buffer;
  SshBufferStatus buf_status;

  ssh_buffer_init(&buffer);
  buf_status = ssh_buffer_append_str(&buffer, "\nsearch-state = \n{\n");
  if (buf_status != SSH_BUFFER_OK)
    goto fail;

  if (state == 0)
    {
      buf_status = ssh_buffer_append_str(&buffer, "  nil\n");
      if (buf_status != SSH_BUFFER_OK)
        goto fail;
    }
  else
    {
      for (i = 0; i < 32; i++)
        {
          if (state & (1 << i))
            {
              name =
                ssh_find_keyword_name(ssh_cm_debug_state_strs, (1 << i));
              buf_status = ssh_buffer_append_cstrs(&buffer, "  ",
                                                   name, "\n", NULL);
              if (buf_status != SSH_BUFFER_OK)
                goto fail;
            }
        }
    }

  buf_status = ssh_buffer_append_str(&buffer, "}\n");
  if (buf_status != SSH_BUFFER_OK)
    goto fail;

  return cm_debug_renderer_return(&buffer, buf, len);

 fail:
  ssh_buffer_uninit(&buffer);
  return 0;
}

int
ssh_cm_render_certificate(unsigned char *buf, int len,
                          int precision, void *datum)
{

  SshX509Certificate cert = datum;
  char *name;
  unsigned char *t;
  SshX509Name names;
  SshMPIntegerStruct mp;
  SshBerTimeStruct not_before, not_after;
  SshBufferStruct buffer;
  SshX509OidList oid_list;
  const SshOidStruct *oids;
  Boolean critical;
  size_t kid_len;
  SshPublicKey pub;
  unsigned char *kid;
  SshBufferStatus bs;

  if (cert)
    {
      ssh_buffer_init(&buffer);
      bs = ssh_buffer_append_str(&buffer, "\ncertificate = { \n");
      if (bs != SSH_BUFFER_OK)
        goto fail;

      /* Add the serial number. */
      ssh_mprz_init(&mp);
      if (ssh_x509_cert_get_serial_number(cert, &mp) == FALSE)
        {
          bs = ssh_buffer_append_str(&buffer, "  missing-serial-number\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          t = (unsigned char *) ssh_mprz_get_str(&mp, 10);
          if (t != NULL)
            {
              bs = ssh_buffer_append_cstrs(
                      &buffer,
                      "  serial-number = ", t, "\n", NULL);
              ssh_mprz_clear(&mp);
              ssh_free(t);

              if (bs != SSH_BUFFER_OK)
                goto fail;
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Failed to get certificate serial number"));
              ssh_mprz_clear(&mp);
              goto fail;
            }
        }

      /* Add suitable names. */
      ssh_x509_name_reset(cert->subject_name);
      if (!ssh_x509_cert_get_subject_name(cert, &name))
        {
          bs = ssh_buffer_append_str(&buffer, "  missing-subject-name\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          bs = ssh_buffer_append_cstrs(&buffer,
                                       "  subject-name = <",
                                       name, ">\n", NULL);
          ssh_free(name);
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      ssh_x509_name_reset(cert->issuer_name);
      if (!ssh_x509_cert_get_issuer_name(cert, &name))
        {
          bs = ssh_buffer_append_str(&buffer, "  missing-issuer-name\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          bs = ssh_buffer_append_cstrs(&buffer,
                                  "  issuer-name = <", name, ">\n", NULL);
          ssh_free(name);
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      /* Validity period. */
      if (!ssh_x509_cert_get_validity(cert, &not_before, &not_after))
        {
          bs = ssh_buffer_append_str(&buffer, "  missing-validity-period\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }
      else
        {
          t = ssh_malloc(64);
          if (t != NULL)
            {
              if (ssh_ber_time_available(&not_before))
                {
                  ssh_snprintf(t, 64,
                               "%@", ssh_ber_time_render, &not_before);
                  bs = ssh_buffer_append_cstrs(&buffer,
                                          "  not-before = ", t, "\n", NULL);
                  if (bs != SSH_BUFFER_OK)
                    {
                      ssh_free(t);
                      goto fail;
                    }
                }

              if (ssh_ber_time_available(&not_after))
                {
                  ssh_snprintf(t, 64,
                               "%@", ssh_ber_time_render, &not_after);
                  bs = ssh_buffer_append_cstrs(&buffer,
                                               "  not-after = ",
                                               t, "\n", NULL);
                }

              ssh_free(t);
              if (bs != SSH_BUFFER_OK)
                goto fail;
            }
        }

      if (ssh_x509_cert_get_subject_key_id(cert, &kid, &kid_len, &critical))
        {
          unsigned char *fingerprint;

          fingerprint = (unsigned char *)
            ssh_fingerprint(kid, kid_len,  SSH_FINGERPRINT_HEX_UPPER);
          if (fingerprint != NULL)
            bs = ssh_buffer_append_cstrs(&buffer,
                                         "  subject-kid = ",
                                         fingerprint, "\n", NULL);
          ssh_free(fingerprint);
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      if (ssh_x509_cert_get_public_key(cert, &pub))
        {
          unsigned char *key_digest;
          size_t digest_len;

          if (ssh_cm_key_kid_create(pub, FALSE, &key_digest, &digest_len))
            {
              unsigned char *fingerprint;

              fingerprint =
                (unsigned char *)ssh_fingerprint(key_digest,
                                                 digest_len,
                                                 SSH_FINGERPRINT_HEX_UPPER);
              if (fingerprint)
                {
                  bs = ssh_buffer_append_cstrs(&buffer,
                                               "  pubkey-hash = ",
                                               ssh_sstr(fingerprint),
                                               "\n", NULL);

                }

              ssh_free(fingerprint);
              ssh_free(key_digest);

            }
          ssh_public_key_free(pub);

          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      /* Some alternate names. */
      if (ssh_x509_cert_get_subject_alternative_names(cert, &names, &critical))
        {
          ssh_x509_name_reset(names);

          bs = ssh_buffer_append_str(&buffer, "  subject-alt-names = { \n");
          if (bs != SSH_BUFFER_OK)
            goto fail;

          if (ssh_cm_names_dump(&buffer, names) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to dump certificate alt names"));
              goto fail;
            }

          bs = ssh_buffer_append_str(&buffer, "  }\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;

        }

      if (ssh_x509_cert_get_issuer_alternative_names(cert, &names, &critical))
        {
          ssh_x509_name_reset(names);

          bs = ssh_buffer_append_str(&buffer, "  issuer-alt-names = { \n");
          if (bs != SSH_BUFFER_OK)
            goto fail;

          if (ssh_cm_names_dump(&buffer, names) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Failed to dump certificate issuer names"));
              goto fail;
            }

          bs = ssh_buffer_append_str(&buffer, "  }\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      if (ssh_x509_cert_get_ext_key_usage(cert, &oid_list, &critical))
        {
          bs = ssh_buffer_append_str(&buffer, "  extended-key-usage = { \n");
          if (bs != SSH_BUFFER_OK)
            goto fail;

          while (oid_list != NULL)
            {
              oids = ssh_oid_find_by_oid_of_type(ssh_custr(oid_list->oid),
                                                 SSH_OID_EXT_KEY_USAGE);
              if (oids == NULL)
                bs = ssh_buffer_append_cstrs(&buffer,
                                             "    (", oid_list->oid, ")\n",
                                             NULL);
              else
                bs = ssh_buffer_append_cstrs(&buffer,
                                             "    ", oids->std_name,
                                             " (", oid_list->oid, ")\n",
                                             NULL);

              if (bs != SSH_BUFFER_OK)
                goto fail;

              oid_list = oid_list->next;
            }

          bs = ssh_buffer_append_str(&buffer, "  }\n");
          if (bs != SSH_BUFFER_OK)
            goto fail;
        }

      bs = ssh_buffer_append_str(&buffer, "}\n");
      if (bs != SSH_BUFFER_OK)
        goto fail;

      return cm_debug_renderer_return(&buffer, buf, len);
    }

  return 0;

 fail:
  if (bs != SSH_BUFFER_OK)
    SSH_DEBUG(SSH_D_FAIL,
              ("Failed to render certificate, buffer operation failed"));
  else
    SSH_DEBUG(SSH_D_FAIL, ("Failed to render certificate"));

  ssh_buffer_uninit(&buffer);
  return 0;
}

static const SshKeywordStruct cm_status_keywords[] =
{
  {"OK", SSH_CM_STATUS_OK},
  {"Item already exists", SSH_CM_STATUS_ALREADY_EXISTS},
  {"Item not found", SSH_CM_STATUS_NOT_FOUND},
  {"Search in progress", SSH_CM_STATUS_SEARCHING},
  {"Decode failed", SSH_CM_STATUS_DECODE_FAILED},
  {"Validity time too short", SSH_CM_STATUS_VALIDITY_TIME_TOO_SHORT},
  {"Certificate not valid", SSH_CM_STATUS_NOT_VALID},
  {"Certificate cannot be valid", SSH_CM_STATUS_CANNOT_BE_VALID},
  {"Memory allocation failed", SSH_CM_STATUS_COULD_NOT_ALLOCATE},
  {"Certificate class number too large", SSH_CM_STATUS_CLASS_TOO_LARGE},
  {"Certificate class number not changed", SSH_CM_STATUS_CLASS_UNCHANGED},
  {"Operation timed out", SSH_CM_STATUS_TIMEOUT},
  {"Operation failed", SSH_CM_STATUS_FAILURE},
  {NULL, 0},
};


const char*
ssh_cm_status_to_string(SshCMStatus status)
{
  const char *str;

  str = ssh_find_keyword_name(cm_status_keywords, status);

  if (str == NULL)
    str = "unknown";

  return str;
}

#endif /* SSHDIST_CERT */
