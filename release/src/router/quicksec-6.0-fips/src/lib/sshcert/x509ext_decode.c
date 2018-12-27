/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc decode routines, mostly extensions and pieces inside certificate or
   CRL.
*/

#include "sshincludes.h"
#include "x509.h"
#include "dn.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

/* Routines for reading the certificate values. */
Boolean
ssh_x509_cert_ext_available(SshX509Certificate c,
                            SshX509CertExtType type,
                            Boolean *critical)
{
  return ssh_x509_ext_info_available(c->extensions.ext_available,
                                     c->extensions.ext_critical,
                                     type,
                                     critical);
}

/* Routines for reading the CRL values. */
Boolean
ssh_x509_crl_ext_available(SshX509Crl crl,
                           SshX509CrlExtType type,
                           Boolean *critical)
{
  return ssh_x509_ext_info_available(crl->extensions.ext_available,
                                     crl->extensions.ext_critical,
                                     type,
                                     critical);
}

/* Revoked certs analysis. */
Boolean
ssh_x509_revoked_ext_available(SshX509RevokedCerts revoked,
                               SshX509CrlEntryExtType type,
                               Boolean *critical)
{
  return ssh_x509_ext_info_available(revoked->extensions.ext_available,
                                     revoked->extensions.ext_critical,
                                     type,
                                     critical);
}

/* Time */
SshX509Status ssh_x509_decode_time(SshAsn1Context context,
                                   SshAsn1Node    data,
                                   SshBerTime     my_time)
{
  unsigned int which;
  SshAsn1Status status;
  status =
    ssh_asn1_read_node(context, data,
                       "(choice"
                       "  (utc-time ())"
                       "  (generalized-time ()))",
                       &which, my_time, my_time);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;
  return SSH_X509_OK;
}

/* Basic constraints. */
SshX509Status ssh_x509_decode_basic_constraints(SshAsn1Context context,
                                                SshAsn1Node    data,
                                                Boolean       *ca,
                                                size_t        *path_len,
                                                SshX509Config  config)
{
  SshMPIntegerStruct t;
  SshAsn1Status status;
  Boolean ca_found, path_found;

  ssh_mprz_init(&t);

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (optional"
                       "    (boolean ()))"   /* ca */
                       "  (optional"
                       "    (integer ())))", /* path len */
                       &ca_found, ca,
                       &path_found, &t);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&t);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  if (ca_found == FALSE)
    *ca = FALSE;
  if (path_found)
    {
      *path_len = ssh_mprz_get_ui(&t);
      if (ssh_mprz_cmp_ui(&t, *path_len) != 0)
        {
          ssh_mprz_clear(&t);
          return SSH_X509_FAILURE;
        }
    }
  else
    *path_len = (size_t)-1;

  ssh_mprz_clear(&t);
  return SSH_X509_OK;
}

/* Decode key id */
SshX509Status ssh_x509_decode_key_id(SshAsn1Context   context,
                                     SshAsn1Node      data,
                                     SshX509ExtKeyId *k,
                                     SshX509Config    config)
{
  SshAsn1Status status;
  SshX509ExtKeyId id;
  SshAsn1Node   gen_name;
  Boolean key_id_found, gen_name_found, sn_found;

  if ((id = ssh_malloc(sizeof(*id))) == NULL)
    return SSH_X509_FAILURE;

  ssh_x509_key_id_init(id);

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (optional"
                       "    (octet-string (0)))"  /* key identifier */
                       "  (optional"
                       "    (any (1)))"           /* general name? */
                       "  (optional"
                       "    (integer (2))))",     /* serial number */
                       &key_id_found, &id->key_id, &id->key_id_len,
                       &gen_name_found, &gen_name,
                       &sn_found, &id->auth_cert_serial_number);
  if (status != SSH_ASN1_STATUS_OK)
    {
      id->key_id = NULL;
      id->key_id_len = 0;
      ssh_x509_key_id_free(id);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  if (!key_id_found)
    {
      id->key_id = NULL;
      id->key_id_len = 0;
    }
  if (!sn_found)
    ssh_mprz_set_si(&id->auth_cert_serial_number, -1);

  if (gen_name_found)
    {
      if (ssh_x509_decode_general_names(context, gen_name,
                                        &id->auth_cert_issuer,
                                        config)
          != SSH_X509_OK)
        {
          ssh_x509_key_id_free(id);
          return SSH_X509_FAILURE;
        }
    }

  *k = id;

  return SSH_X509_OK;
}

/* Decode subject key id */
SshX509Status ssh_x509_decode_subject_key_id(SshAsn1Context   context,
                                             SshAsn1Node      data,
                                             SshX509ExtKeyId *k)
{
  SshAsn1Status status;
  SshX509ExtKeyId id;

  if ((id = ssh_malloc(sizeof(*id))) == NULL)
    return SSH_X509_FAILURE;

  ssh_x509_key_id_init(id);

  status =
    ssh_asn1_read_node(context, data,
                       "(octet-string ())",
                       &id->key_id, &id->key_id_len);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_x509_key_id_free(id);
      return SSH_X509_FAILURE;
    }
  *k = id;
  return SSH_X509_OK;
}

/* Decode directory attributes */
SshX509Status ssh_x509_decode_directory_attribute(SshAsn1Context context,
                                                  SshAsn1Node data,
                                                  SshX509ExtDirAttribute *d)
{
  SshAsn1Status status;
  SshAsn1Node node, any;
  SshX509ExtDirAttribute table, prev, attr;
  char *oid;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Initialize. */
  table = NULL;
  prev = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (any ()))",
                       &node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  for (; node; node = ssh_asn1_node_next(node))
    {
      status =
        ssh_asn1_read_node(context, node,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (any ()))",
                           &oid, &any);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((attr = ssh_malloc(sizeof(*attr))) != NULL)
        {
          ssh_x509_directory_attribute_init(attr);
          attr->oid = oid;
          ssh_asn1_node_get_data(any,
                                 &attr->octet_string, &attr->octet_string_len);

          /* Handle the list. */
          if (table)
            prev->next = attr;
          else
            table = attr;
          prev = attr;
        }
      else
        goto failed;
    }

  rv = SSH_X509_OK;

 failed:
  *d = table;
  return rv;
}

/* Decode general subtree */
SshX509Status ssh_x509_decode_general_subtree(SshAsn1Context context,
                                              SshAsn1Node data,
                                              SshX509GeneralSubtree *g,
                                              SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node node, list;
  SshX509GeneralSubtree table, prev, subtree;
  SshMPIntegerStruct min, max;
  Boolean min_found, max_found;
  SshX509Status rv = SSH_X509_FAILURE;

  table = NULL;
  prev = NULL;
  ssh_mprz_init(&min);
  ssh_mprz_init(&max);

  list = ssh_asn1_node_child(data);
  for (; list; list = ssh_asn1_node_next(list))
    {
      status =
        ssh_asn1_read_node(context, list,
                           "(sequence ()"
                           "  (any ())"
                           "  (optional (integer (0)))"
                           "  (optional (integer (1))))",
                           &node,
                           &min_found, &min,
                           &max_found, &max);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((subtree = ssh_malloc(sizeof(*subtree))) == NULL)
        goto failed;

      ssh_x509_general_subtree_init(subtree);

      if (min_found)
        {
          if (ssh_mprz_get_size(&min, 2) > 24)
            {
              ssh_x509_general_subtree_clear(subtree);
              ssh_free(subtree);
              goto failed;
            }
          subtree->min_distance = ssh_mprz_get_ui(&min);
        }
      else
        subtree->min_distance = 0;
      if (max_found)
        {
          if (ssh_mprz_get_size(&max, 2) > 24)
            {
              ssh_x509_general_subtree_clear(subtree);
              ssh_free(subtree);
              goto failed;
            }
          subtree->max_distance = ssh_mprz_get_ui(&max);
        }
      else
        subtree->max_distance = SSH_X509_GENERAL_SUBTREE_VALUE_ABSENT;

      /* Decode the general name! */
      if (ssh_x509_decode_general_name(context,
                                       node, &subtree->name,
                                       config) != SSH_X509_OK)
        {
          ssh_x509_general_subtree_clear(subtree);
          ssh_free(subtree);
          goto failed;
        }

      /* Success! */

      /* Handle the list. */
      if (table)
        prev->next = subtree;
      else
        table = subtree;
      prev = subtree;
    }

  rv = SSH_X509_OK;
failed:
  *g = table;

  ssh_mprz_clear(&min);
  ssh_mprz_clear(&max);

  return rv;
}

/* Decode name constraints */
SshX509Status ssh_x509_decode_name_const(SshAsn1Context context,
                                         SshAsn1Node data,
                                         SshX509GeneralSubtree *permit,
                                         SshX509GeneralSubtree *exclude,
                                         SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node p_node, e_node;
  Boolean p_found, e_found;
  SshX509Status rv = SSH_X509_FAILURE;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (optional (any (0)))"
                       "  (optional (any (1))))",
                       &p_found, &p_node, &e_found, &e_node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  *permit = NULL;
  *exclude = NULL;

  if (p_found)
    {
      if (ssh_x509_decode_general_subtree(context, p_node, permit, config)
          != SSH_X509_OK)
        goto failed;
    }

  if (e_found)
    {
      if (ssh_x509_decode_general_subtree(context, e_node, exclude, config)
          != SSH_X509_OK)
        goto failed;
    }

  rv = SSH_X509_OK;
failed:
  return rv;
}

/* Decode CRL distribution points. */
SshX509Status
ssh_x509_decode_crl_dist_points(SshAsn1Context context,
                                SshAsn1Node data,
                                SshX509Name issuer_names,
                                SshX509ExtCRLDistPoints *c,
                                SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node node, dpn, gen_name, rdn_name, full_name;
  SshX509ExtCRLDistPoints table, prev, point;
  SshRDN relative_dn;
  Boolean dpn_found, r_found, gn_found;
  SshX509Status rv = SSH_X509_FAILURE;
  unsigned char *reason = NULL;
  size_t reason_len = 0;
  unsigned int which;

  table = NULL;
  prev = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (any ()))",
                       &node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  for (; node; node = ssh_asn1_node_next(node))
    {
      status =
        ssh_asn1_read_node(context, node,
                           "(sequence ()"
                           "  (optional"
                           "    (any (e 0)))"
                           "  (optional"
                           "    (bit-string (1)))"
                           "  (optional"
                           "    (any (2))))",
                           &dpn_found, &dpn,
                           &r_found,
                           &reason, &reason_len,
                           &gn_found, &gen_name);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((point = ssh_malloc(sizeof(*point))) == NULL)
        goto failed;

      ssh_x509_crl_dist_points_init(point);

      if (r_found)
        {
          point->reasons = ssh_x509_bs_to_ui(reason, reason_len);
          ssh_free(reason);
          reason = NULL;
        }

      if (dpn_found)
        {
          /* Check whether this is full name or relative to CRL issuer. */
          status =
            ssh_asn1_read_node(context, dpn,
                               "(choice"
                               "  (any (0))"
                               "  (any (1)))",
                               &which, &full_name, &rdn_name);
          if (status != SSH_ASN1_STATUS_OK)
            {
              ssh_x509_crl_dist_points_clear(point);
              ssh_free(point);
              goto failed;
            }

          if (which == 0)
            {
              if (ssh_x509_decode_general_names(context,
                                                full_name,
                                                &point->full_name,
                                                config)
                  != SSH_X509_OK)
                {
                  ssh_x509_crl_dist_points_clear(point);
                  ssh_free(point);
                  goto failed;
                }
              point->dn_relative_to_issuer = NULL;
            }
          else if (which == 1)
            {
              /* Decode the relative distinguished name. */
              relative_dn = NULL;

              if (ssh_dn_decode_rdn(context, rdn_name, &relative_dn, config)
                  == 0)
                {
                  ssh_x509_crl_dist_points_clear(point);
                  ssh_free(point);
                  goto failed;
                }
              /* Allocate a DN name. */
              if ((point->dn_relative_to_issuer =
                   ssh_malloc(sizeof(SshDNStruct))) == NULL)
                {
                  ssh_free(point);
                  goto failed;
                }

              ssh_dn_init(point->dn_relative_to_issuer);

              /* Build up the CRL distribution point. */
              if (!ssh_dn_put_rdn(point->dn_relative_to_issuer, relative_dn))
                {
                  ssh_x509_crl_dist_points_clear(point);
                  ssh_free(point);
                  ssh_rdn_free(relative_dn);
                  goto failed;
                }

              /* No full name it seems. */
              point->full_name = NULL;
            }
        }

      if (gn_found)
        if (ssh_x509_decode_general_names(context, gen_name,
                                          &point->crl_issuer,
                                          config) != SSH_X509_OK)
          {
            ssh_x509_crl_dist_points_clear(point);
            ssh_free(point);
            goto failed;
          }

      /* Handle the list. */
      if (table)
        prev->next = point;
      else
        table = point;
      prev = point;
    }

  /* Success. */
  rv = SSH_X509_OK;
failed:
  *c = table;
  return rv;
}

/* Decode Authority Information Access. */
SshX509Status ssh_x509_decode_info_access(SshAsn1Context context,
                                          SshAsn1Node data,
                                          SshX509ExtInfoAccess *access,
                                          SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node node, gen_name;
  SshX509ExtInfoAccess table, prev, ia;
  char *oid;
  SshX509Status rv = SSH_X509_FAILURE;

  table = NULL;
  prev  = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (any ()))",
                       &node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  for (; node; node = ssh_asn1_node_next(node))
    {
      status =
        ssh_asn1_read_node(context, node,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (any ()))",
                           &oid,
                           &gen_name);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((ia = ssh_malloc(sizeof(*ia))) == NULL)
        goto failed;

      ssh_x509_info_access_init(ia);

      ia->access_method = oid;

      if (ssh_x509_decode_general_name(context, gen_name,
                                       &ia->access_location, config)
          != SSH_X509_OK)
        {
          ssh_x509_info_access_clear(ia);
          ssh_free(ia);
          goto failed;
        }

      /* Handle the list. */
      if (table)
        prev->next = ia;
      else
        table = ia;
      prev = ia;
    }
  rv = SSH_X509_OK;
failed:
  *access = table;
  return rv;
}

/* Decode a Netscape comment */
SshX509Status
ssh_x509_decode_netscape_comment(SshAsn1Context context,
                                 SshAsn1Node data,
                                 SshStr *comment_ret)
{
  unsigned char *comment_string;
  size_t comment_length;
  SshStr comment;

  if (ssh_asn1_read_node(context, data, "(ia5-string())",
                         &comment_string, &comment_length) ==
      SSH_ASN1_STATUS_OK)
    {
      if (comment_length > 0)
        comment = ssh_str_make(SSH_CHARSET_US_ASCII,
                               comment_string, comment_length);
      else
        comment = ssh_str_make(SSH_CHARSET_US_ASCII, ssh_strdup(""), 1);

      if (comment)
        {
          *comment_ret = comment;
          return SSH_X509_OK;
        }
    }
  *comment_ret = NULL;
  return SSH_X509_FAILURE;
}

SshX509Status
ssh_x509_decode_cert_template_name(SshAsn1Context context,
                                   SshAsn1Node data,
                                   SshStr *tn_ret)
{
  unsigned char *str;
  size_t len;
  SshStr n;

  if (ssh_asn1_read_node(context, data, "(bmp-string())",
                         &str, &len) == SSH_ASN1_STATUS_OK)

    {
      if (len > 0)
        n = ssh_str_make(SSH_CHARSET_BMP, str, len);
      else
        n = ssh_str_make(SSH_CHARSET_BMP, ssh_strdup(""), 0);
      if (n)
        {
          *tn_ret = n;
          return SSH_X509_OK;
        }
    }
  *tn_ret = NULL;
  return SSH_X509_FAILURE;
}


/*
 * Dups oid, steals der. The return argument must point to NULL or to
 * a valid EXT_UNKNOWN node.
 */
SshX509Status ssh_x509_make_unknown_extension(const unsigned char *oid,
                                              const char *name,
                                              unsigned char *der,
                                              size_t der_len,
                                              Boolean critical,
                                              SshX509ExtUnknown *unknown_ret)
{
  SshX509ExtUnknown unknown;
  char *oiddup, *namedup = NULL;

  oiddup = ssh_strdup(oid);
  if (oiddup == NULL)
    return SSH_X509_FAILURE;

  if (name)
    {
      namedup = ssh_strdup(name);
      if (namedup == NULL)
        {
          ssh_free(oiddup);
          return SSH_X509_FAILURE;
        }
    }

  unknown = ssh_malloc(sizeof(*unknown));
  if (unknown == NULL)
    {
      *unknown_ret = NULL;
      ssh_free(oiddup);
      ssh_free(namedup);
      return SSH_X509_FAILURE;
    }

  ssh_x509_unknown_extension_init(unknown);
  unknown->next = *unknown_ret;
  unknown->oid = oiddup;
  unknown->name = namedup;
  unknown->der = der;
  unknown->der_length = der_len;
  unknown->critical = critical;
  *unknown_ret = unknown;
  return SSH_X509_OK;
}

/* Decode oid list */
SshX509Status ssh_x509_decode_oid_list(SshAsn1Context context,
                                       SshAsn1Node data,
                                       SshX509OidList *list)
{
  SshAsn1Status status;
  SshAsn1Node node;
  SshX509OidList table, prev, oid_list;
  char *oid;
  SshX509Status rv = SSH_X509_FAILURE;

  table = NULL;
  prev  = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (any ()))", &node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  for (; node; node = ssh_asn1_node_next(node))
    {
      status =
        ssh_asn1_read_node(context, node,
                           "(object-identifier ())",
                           &oid);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((oid_list = ssh_malloc(sizeof(*oid_list))) == NULL)
        goto failed;

      ssh_x509_oid_list_init(oid_list);

      oid_list->oid = oid;

      /* Handle the table. */
      if (table)
        prev->next = oid_list;
      else
        table = oid_list;
      prev = oid_list;
    }
  rv = SSH_X509_OK;
failed:
  *list = table;
  return rv;
}

/* Decode key usage */
SshX509Status ssh_x509_decode_key_usage(SshAsn1Context context,
                                        SshAsn1Node data,
                                        SshX509UsageFlags *flags)
{
  SshAsn1Status status;
  unsigned char *buf;
  size_t buf_len;

  status =
    ssh_asn1_read_node(context, data,
                       "(bit-string ())",
                       &buf, &buf_len);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  *flags = ssh_x509_bs_to_ui(buf, buf_len);
  ssh_free(buf);

  return SSH_X509_OK;
}

/* Decode Private key usage period. */
SshX509Status
ssh_x509_decode_private_key_period(SshAsn1Context context,
                                         SshAsn1Node    data,
                                         SshBerTime     not_before,
                                         SshBerTime     not_after)
{
  Boolean f_not_before, f_not_after;
  SshAsn1Status status;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (optional"
                       "    (generalized-time (0)))"
                       "  (optional"
                       "    (generalized-time (1))))",
                       &f_not_before,
                       not_before,
                       &f_not_after,
                       not_after);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  return SSH_X509_OK;
}

/* Decode the CRL number (trivial). */
SshX509Status ssh_x509_decode_number(SshAsn1Context context,
                                     SshAsn1Node    data,
                                     SshMPInteger        mp_int)
{
  SshAsn1Status status;

  status =
    ssh_asn1_read_node(context, data,
                       "(integer ())",
                       mp_int);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;
  return SSH_X509_OK;
}

/* Decode issuer distribution point */
SshX509Status
ssh_x509_decode_issuing_dist_point(SshAsn1Context context,
                                   SshAsn1Node    data,
                                   SshX509Name    issuer_names,
                                   SshX509ExtIssuingDistPoint *ip,
                                   SshX509Config  config)
{
  SshAsn1Status status;
  SshAsn1Node   node, full_name, rdn_name;
  Boolean f_name, f_uc, f_ca, f_sr, f_icrl, f_ac;
  SshX509ExtIssuingDistPoint point;
  SshRDN relative_dn;
  unsigned int which;
  unsigned char *reason;
  size_t reason_len;

  if ((point = ssh_malloc(sizeof(*point))) == NULL)
    return SSH_X509_FAILURE;

  ssh_x509_issuing_dist_point_init(point);

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "  (optional (any (e 0)))"
                       "  (optional (boolean (1)))"
                       "  (optional (boolean (2)))"
                       "  (optional (bit-string (3)))"
                       "  (optional (boolean (4)))"
                       "  (optional (boolean (5))))",
                       &f_name, &node,
                       &f_uc, &point->only_contains_user_certs,
                       &f_ca, &point->only_contains_ca_certs,
                       &f_sr, &reason, &reason_len,
                       &f_icrl, &point->indirect_crl,
                       &f_ac, &point->only_contains_attribute_certs);

  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_x509_issuing_dist_point_free(point);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  if (f_sr)
    {
      point->only_some_reasons =
        ssh_x509_bs_to_ui(reason, reason_len);
      ssh_free(reason);
    }

  if (f_name)
    {
      /* Handle distribution point name. */
      status =
        ssh_asn1_read_node(context, node,
                           "(choice"
                           "(any (0)) (any (1)))",
                           &which, &full_name, &rdn_name);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_x509_issuing_dist_point_free(point);
          return SSH_X509_FAILED_ASN1_DECODE;
        }

      switch (which)
        {
        case 0:
          if (ssh_x509_decode_general_names(context, full_name,
                                            &point->full_name,
                                            config) != SSH_X509_OK)
            {
              ssh_x509_issuing_dist_point_free(point);
              return SSH_X509_FAILURE;
            }
          point->dn_relative_to_issuer = NULL;
          break;
        case 1:
          /* Decode the relative distinguished name. */
          relative_dn = NULL;
          if (ssh_dn_decode_rdn(context, rdn_name, &relative_dn, config) == 0)
            {
              ssh_x509_issuing_dist_point_free(point);
              return SSH_X509_FAILURE;
            }

          /* Allocate a DN name. */
          if ((point->dn_relative_to_issuer = ssh_malloc(sizeof(SshDNStruct)))
              != NULL)
            {
              /* Initialize the DN structure. */
              ssh_dn_init(point->dn_relative_to_issuer);
              /* Build up the CRL distribution point. */
              if (!ssh_dn_put_rdn(point->dn_relative_to_issuer, relative_dn))
                {
                  ssh_x509_issuing_dist_point_free(point);
                  ssh_rdn_free(relative_dn);
                  return SSH_X509_FAILURE;
                }
              /* No full name it seems. */
              point->full_name = NULL;
            }
          else
            {
              ssh_x509_issuing_dist_point_free(point);
              ssh_rdn_free(relative_dn);
              return SSH_X509_FAILURE;
            }
          break;
        default:
          ssh_x509_issuing_dist_point_free(point);
          return SSH_X509_FAILURE;
        }
    }

  *ip = point;
  return SSH_X509_OK;
}

/* Decode revoked cert extensions. */
SshX509Status ssh_x509_decode_crl_reason_code(SshAsn1Context context,
                                              SshAsn1Node    data,
                                              SshX509CRLReasonCode *flags)
{
  SshAsn1Status status;
  SshMPIntegerStruct t;

  ssh_mprz_init(&t);

  status =
    ssh_asn1_read_node(context, data,
                       "(enum ())",
                       &t);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&t);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  /* Do the checking. */
  if (ssh_mprz_cmp_ui(&t, 0) >= 0 && ssh_mprz_cmp_ui(&t, 10) <= 0)
    {
      *flags = ssh_mprz_get_ui(&t);
      ssh_mprz_clear(&t);
      if (*flags == 7)
        return SSH_X509_FAILURE;
      return SSH_X509_OK;
    }
  ssh_mprz_clear(&t);
  return SSH_X509_FAILURE;
}

/* Decode hold instruction code. */
SshX509Status ssh_x509_decode_hold_inst_code(SshAsn1Context context,
                                             SshAsn1Node    data,
                                             char **code)
{
  SshAsn1Status status;
  status =
    ssh_asn1_read_node(context, data,
                       "(object-identifier ())",
                       code);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;
  return SSH_X509_OK;
}

/* Decode invalidity dates. */
SshX509Status ssh_x509_decode_invalidity_date(SshAsn1Context context,
                                              SshAsn1Node    data,
                                              SshBerTime     date)
{
  SshAsn1Status status;
  status =
    ssh_asn1_read_node(context, data,
                       "(generalized-time ())",
                       date);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;
  return SSH_X509_OK;
}

/* Decode policy information. */
SshX509Status ssh_x509_decode_policy_info(SshAsn1Context context,
                                          SshAsn1Node data,
                                          SshX509ExtPolicyInfo *i)
{
  SshAsn1Node node, pqnode, notice_node, text_node, pq, numbers_node, tmp;
  SshX509ExtPolicyInfo table, p, prev;
  SshX509ExtPolicyQualifierInfo pqinfo = NULL, pq_first = NULL, pq_prev;
  char *oid;
  unsigned char *oid_pq;
  unsigned char *buf;
  size_t buf_len;
  Boolean notice_found, text_found, pqnode_found;
  SshMPIntegerStruct mp_int;
  size_t nn_index;
  const SshOidStruct *ext_oids;
  unsigned int extension_type, which;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Incorrectly there seems to be certs with indefinite length
     encoding for sequences on this extension around. */

  /* Start to decode by opening the first sequence. */
  if (ssh_asn1_read_node(context, data,
                         "(sequence (l*)"
                         " (any ()))", &node) != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  /* Initialize now some variables. */
  table     = NULL;
  prev      = NULL;

  ssh_mprz_init(&mp_int);

  /* Main loop. */
  for (; node; node = ssh_asn1_node_next(node))
    {
      /* Decode the policy information. */
      if (ssh_asn1_read_node(context, node,
                             "(sequence (l*)"
                             " (object-identifier ())"
                             " (optional"
                             "   (sequence (l*)"
                             "     (any ()))))",
                             &oid,
                             &pqnode_found, &pqnode) != SSH_ASN1_STATUS_OK)
        goto failed;

      /* Was the pq node found? */
      if (!pqnode_found)
        {
          if ((p = ssh_malloc(sizeof(*p))) != NULL)
            {
              ssh_x509_policy_info_init(p);

              /* Set up the object identifier for each separately, is
                 this really necessary? */
              p->oid = oid;

              /* Handle the list. */
              if (table)
                prev->next = p;
              else
                table = p;
              prev = p;

              pqnode = NULL;
            }
          else
            {
              ssh_free(oid);
            }
          continue;
        }

      for (pq_first = NULL, pq_prev = NULL;
           pqnode;
           pqnode = ssh_asn1_node_next(pqnode))
        {
          if (ssh_asn1_read_node(context, pqnode,
                                 "(sequence ()"
                                 " (object-identifier ())"
                                 " (any ()))",
                                 &oid_pq,
                                 &pq) != SSH_ASN1_STATUS_OK)
            goto failed;

          /* Try to find the object identifier. */
          ext_oids = ssh_oid_find_by_oid_of_type(oid_pq, SSH_OID_POLICY);
          if (ext_oids == NULL)
            goto failed;

          if ((pqinfo = ssh_malloc(sizeof(*pqinfo))) == NULL)
            goto failed;

          ssh_x509_policy_qualifier_info_init(pqinfo);

          /* Set the oid first. */
          pqinfo->oid = oid_pq;

          extension_type = ext_oids->extra_int;
          switch (extension_type)
            {
            case SSH_X509_POLICY_QT_INTERNET_PQ:
              if (ssh_asn1_read_node(context, pq,
                                     "(ia5-string ())",
                                     &buf, &buf_len) != SSH_ASN1_STATUS_OK)
                goto failed;

              pqinfo->cpsuri =
                ssh_str_make(SSH_CHARSET_US_ASCII, buf, buf_len);
              break;
            case SSH_X509_POLICY_QT_UNOTICE:
              if (ssh_asn1_read_node(context, pq,
                                     "(sequence ()"
                                     " (optional (sequence () (any ())))"
                                     " (optional (any ())))",
                                     &notice_found, &notice_node,
                                     &text_found, &text_node)
                  != SSH_ASN1_STATUS_OK)
                goto failed;

              if (notice_found)
                {
                  if (ssh_asn1_read_node(context, notice_node,
                                         "(ia5-string ())"
                                         "(sequence ()"
                                         " (any ()))",
                                         &buf, &buf_len,
                                         &numbers_node) != SSH_ASN1_STATUS_OK)
                    goto failed;

                  pqinfo->organization =
                    ssh_str_make(SSH_CHARSET_US_ASCII,
                                 buf, buf_len);

                  /* Search the numbers. */
                  for (tmp = numbers_node, nn_index = 0;
                       tmp;
                       tmp = ssh_asn1_node_next(tmp), nn_index++)
                    ;

                  if ((pqinfo->notice_numbers =
                       ssh_calloc(nn_index, sizeof(unsigned int))) == NULL)
                    goto failed;

                  pqinfo->notice_numbers_count = nn_index;

                  for (nn_index = 0; numbers_node;
                       numbers_node = ssh_asn1_node_next(numbers_node))
                    {
                      if (ssh_asn1_read_node(context, numbers_node,
                                             "(integer ())",
                                             &mp_int) != SSH_ASN1_STATUS_OK)
                        goto failed;

                      if (ssh_mprz_get_size(&mp_int, 2) > 16
                          || nn_index > pqinfo->notice_numbers_count)
                        goto failed;

                      pqinfo->notice_numbers[nn_index++] =
                        ssh_mprz_get_ui(&mp_int);
                    }
                }

              if (text_found)
                {
                  if (ssh_asn1_read_node(context, text_node,
                                         "(choice"
                                         " (visible-string ())"
                                         " (bmp-string ())"
                                         " (utf8-string ()))",
                                         &which,
                                         &buf, &buf_len,
                                         &buf, &buf_len,
                                         &buf, &buf_len)
                      != SSH_ASN1_STATUS_OK)
                    goto failed;

                  switch (which)
                    {
                    case 0:
                      pqinfo->explicit_text =
                        ssh_str_make(SSH_CHARSET_VISIBLE, buf, buf_len);
                      break;
                    case 1:
                      pqinfo->explicit_text =
                        ssh_str_make(SSH_CHARSET_BMP, buf, buf_len);
                      break;
                    case 2:
                      pqinfo->explicit_text =
                        ssh_str_make(SSH_CHARSET_UTF8, buf, buf_len);
                      break;
                    default:
                      goto failed;
                    }
                }
              break;
            default:
              goto failed;
            }

          /* The qualifier info has now been parsed! */

          if (pq_first)
            {
              pq_prev->next = pqinfo;
              pq_prev = pqinfo;
            }
          else
            {
              pq_first = pqinfo;
              pq_prev  = pqinfo;
            }
        }

      if ((p = ssh_malloc(sizeof(*p))) != NULL)
        {
          ssh_x509_policy_info_init(p);

          /* Set up the object identifier for each separately, is this
             really necessary? */
          p->oid = oid;

          /* Lets add the qualifier here. */
          p->pq_list = pq_first;

          /* Handle the list. */
          if (table)
            prev->next = p;
          else
            table = p;
          prev = p;
        }
      else
        {
          ssh_free(oid);
        }
    }

  rv = SSH_X509_OK;

 failed:
  if (rv != SSH_X509_OK)
    {
      ssh_x509_policy_qualifier_info_free(pqinfo);
      if (pqinfo != pq_first)
        ssh_x509_policy_qualifier_info_free(pq_first);
    }

  /* Put the returned list into 'i' and free. */
  *i = table;
  ssh_mprz_clear(&mp_int);
  return rv;
}

/* Decode policy mappings. */
SshX509Status ssh_x509_decode_policy_mappings(SshAsn1Context context,
                                              SshAsn1Node data,
                                              SshX509ExtPolicyMappings *m)
{
  SshAsn1Status status;
  SshAsn1Node list;
  char *issuer, *subject;
  SshX509ExtPolicyMappings table, prev, policy;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Initialize. */
  table = NULL;
  prev  = NULL;
  *m    = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence ()"
                       "(any ()))",
                       &list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  for (; list; list = ssh_asn1_node_next(list))
    {
      status =
        ssh_asn1_read_node(context, list,
                           "(sequence ()"
                           " (object-identifier ())"
                           " (object-identifier ()))",
                           &issuer, &subject);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if ((policy = ssh_malloc(sizeof(*policy))) == NULL)
        goto failed;

      ssh_x509_policy_mappings_init(policy);
      policy->issuer_dp_oid = issuer;
      policy->subject_dp_oid = subject;

      /* Handle the list. */
      if (table)
        prev->next = policy;
      else
        table = policy;
      prev = policy;
    }

  rv = SSH_X509_OK;
failed:
  *m = table;
  return rv;
}

/* Decode policy constraints. */
SshX509Status ssh_x509_decode_policy_const(SshAsn1Context context,
                                           SshAsn1Node data,
                                           SshX509ExtPolicyConstraints *p)
{
  SshAsn1Status status;
  SshX509ExtPolicyConstraints policy;
  SshMPIntegerStruct t1, t2;
  SshX509Status rv = SSH_X509_FAILURE, r_found, i_found;

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  *p = NULL;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence (*)"
                       "  (optional (integer (0)))"
                       "  (optional (integer (1))))",
                       &r_found, &t1,
                       &i_found, &t2);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  if ((policy = ssh_malloc(sizeof(*policy))) == NULL)
    goto failed;

  ssh_x509_policy_const_init(policy);

  if (r_found)
    {
      if (ssh_mprz_get_size(&t1, 2) > 24)
        {
          ssh_x509_policy_const_clear(policy);
          ssh_free(policy);
          goto failed;
        }
      policy->require = ssh_mprz_get_ui(&t1);
    }
  else
    policy->require = SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT;

  if (i_found)
    {
      if (ssh_mprz_get_size(&t2, 2) > 24)
        {
          ssh_x509_policy_const_clear(policy);
          ssh_free(policy);
          goto failed;
        }
      policy->inhibit = ssh_mprz_get_ui(&t2);
    }
  else
    policy->inhibit = SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT;

  *p = policy;

  /* Success. */
  rv = SSH_X509_OK;

failed:

  /* Free the multiple precision integers. */
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  return rv;
}

SshX509Status ssh_x509_decode_qcstatements(SshAsn1Context context,
                                           SshAsn1Node data,
                                           SshX509ExtQCStatement *qcs_list,
                                           SshX509Config config)
{
  SshAsn1Status asn1status;
  SshX509ExtQCStatement qcs = NULL, tmpqcs = NULL;
  SshAsn1Node statement, content;
  Boolean content_found;
  unsigned char *ext_oid;
  const SshOidStruct *ext_oids;

  asn1status = ssh_asn1_read_node(context, data,
                              "(sequence ()"
                              "  (any ()))", &statement);
  if (asn1status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  for (; statement; statement = ssh_asn1_node_next(statement))
    {
      asn1status = ssh_asn1_read_node(context, statement,
                                  "(sequence ()"
                                  "  (object-identifier ())"
                                  "  (optional (any ())))",
                                  &ext_oid,
                                  &content_found, &content);
      if (asn1status != SSH_ASN1_STATUS_OK)
        goto failed;

      /* Allocate new qcs and add it to qcs list. */
      tmpqcs = ssh_calloc(1, sizeof(*tmpqcs));
      if (tmpqcs == NULL)
        goto failed;
      tmpqcs->next = qcs;
      qcs = tmpqcs;
      qcs->oid = ext_oid;

      ext_oids = ssh_oid_find_by_oid_of_type(ext_oid, SSH_OID_QCSTATEMENT);

      if (ext_oids == NULL)
        {

        unknown_qcstatement:

          /* Unknown statement oid. */
          if (content_found)
            {
              if (ssh_asn1_node_get_data(content, &qcs->der, &qcs->der_len)
                  != SSH_ASN1_STATUS_OK)
                goto failed;
            }
          continue;
        }

      switch (ext_oids->extra_int)
        {
        case SSH_X509_QCSTATEMENT_QCSYNTAXV1:
          {
            char *oid;
            SshAsn1Node value;
            SshX509Name names;

            if (!content_found)
              break;

            asn1status = ssh_asn1_read_node(context, content,
                                            "(sequence ()"
                                            "  (object-identifier ()))",
                                            &oid);
            if (asn1status == SSH_ASN1_STATUS_OK)
              {
                qcs->semantics_oid = oid;
              }
            else
              {
                asn1status = ssh_asn1_read_node(context, content,
                                            "(sequence ()"
                                            "  (any ()))",
                                            &value);
                if (asn1status != SSH_ASN1_STATUS_OK)
                  goto failed;

                names = NULL;
                if (ssh_x509_decode_general_names(context,
                                                  value, &names,
                                                  config)
                    != SSH_X509_OK)
                  goto failed;
                qcs->name_registration_authorities = names;
              }
            break;
          }

        case SSH_X509_QCSTATEMENT_QCCOMPLIANCE:
          /* No content in this one. */
          break;

        case SSH_X509_QCSTATEMENT_QCEULIMITVALUE:
          if (!content_found)
            goto failed;

          ssh_mprz_init(&qcs->amount);
          ssh_mprz_init(&qcs->exponent);

          asn1status = ssh_asn1_read_node(context, content,
                                      "(sequence ()"
                                      "  (integer-short ())"
                                      "  (integer ())"
                                      "  (integer ()))",
                                      &qcs->currency,
                                      &qcs->amount,
                                      &qcs->exponent);
          if (asn1status != SSH_ASN1_STATUS_OK)
            goto failed;
          break;

        case SSH_X509_QCSTATEMENT_RETENTIONPERIOD:
          if (!content_found)
            goto failed;

          ssh_mprz_init(&qcs->retention_period);

          asn1status = ssh_asn1_read_node(context, content,
                                      "(sequence ()"
                                      "  (integer ()))",
                                      &qcs->retention_period);
          if (asn1status != SSH_ASN1_STATUS_OK)
            goto failed;
          break;

        default:
          /* Unsupported but known oid. */
          goto unknown_qcstatement;
        }
    }

  (*qcs_list) = qcs;
  return SSH_X509_OK;

 failed:

  /* Free qcs_list and return with error. */
  ssh_x509_qcstatement_free(qcs);
  (*qcs_list) = NULL;
  return SSH_X509_FAILURE;
}


/**** The summing up part. */

/* Decode generic X509 extension. Logic here is to disallow unknown or
   invalid coding on critical extensions, but allow invalid coding on
   non criticals (we simply do not process those) */
SshX509Status
ssh_x509_cert_decode_extension(SshAsn1Context context,
                               SshAsn1Node node,
                               SshX509Certificate c)
{
  SshAsn1Status status;
  SshAsn1Node   extensions;
  SshX509CertExtensions e = &c->extensions;

  /* Clean the extension info array. */
  e->ext_available = e->ext_critical = 0L;

  /* Decode the extension framework. */
  status =
    ssh_asn1_read_node(context, node,
                       "(sequence ()"
                       "  (any ()))", &extensions);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  for (; extensions; extensions = ssh_asn1_node_next(extensions))
    {
      Boolean ext_critical, critical_found;
      SshAsn1Node extension_node;
      SshAsn1Tree vt;
      SshX509Status rv = SSH_X509_FAILURE;
      unsigned char *ext_oid;
      const SshOidStruct *ext_oids;
      size_t ext_value_len;
      unsigned char *ext_value;
      unsigned int extension_type;

      /* Decode the first extension. */
      status =
        ssh_asn1_read_node(context, extensions,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (optional"
                           "     (boolean ()))"
                           "  (octet-string ()))",
                           &ext_oid,
                           &critical_found, &ext_critical,
                           &ext_value, &ext_value_len);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;

      if (critical_found != TRUE)
        ext_critical = FALSE;

      /* Find the correct object type. */
      ext_oids = ssh_oid_find_by_oid_of_type(ext_oid, SSH_OID_EXT);

      if (ext_oids == NULL || ext_oids->extra_int == SSH_X509_EXT_UNKNOWN)
        {
          /* Only if the extension claims to be critical shall we
             fail! */
        make_unknown_extension:
          if (SSH_X509_OK !=
              ssh_x509_make_unknown_extension(ext_oid,
                                              ext_oids ?
                                              ext_oids->std_name :
                                              NULL,
                                              ext_value,
                                              ext_value_len,
                                              ext_critical,
                                              &e->unknown))
            {
              ssh_free(ext_oid);
              ssh_free(ext_value);
              return SSH_X509_FAILURE;
            }
          ssh_free(ext_oid);
          extension_type = SSH_X509_EXT_UNKNOWN;

          ssh_x509_ext_info_set(&e->ext_available,
                                &e->ext_critical,
                                extension_type, ext_critical);

          if (ext_critical)
            {
              return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
            }

          continue;
        }

      /* Decode the value. */
      vt = NULL;
      if (ssh_asn1_decode(context, ext_value, ext_value_len, &vt)
          != SSH_ASN1_STATUS_OK)
        {
          ssh_free(ext_oid);
          ssh_free(ext_value);
          return SSH_X509_FAILED_ASN1_DECODE;
        }

      extension_type = ext_oids->extra_int;

      /* Get a pointer to the root node of the ASN.1 tree. */
      if (vt)
        extension_node = ssh_asn1_get_root(vt);
      else
        extension_node = NULL;

      /* Set the extension information. It should be noted, that the
         OID code never returns 'extension_type' values which are
         incorrect.

         Also the extension information code never overwrites the
         values just or's them.  */

      if (ssh_x509_cert_ext_available(c, extension_type, NULL))
        {
          /* The extension appears twice! */
          ssh_free(ext_oid);
          ssh_free(ext_value);
          return SSH_X509_FAILED_DUPLICATE_EXTENSION;
        }

      /* Handle the specific extensions. If the extensions are not
         critical we do not worry if we can not parse it. */
      switch (extension_type)
        {
        case SSH_X509_EXT_AUTH_KEY_ID:
          rv = ssh_x509_decode_key_id(context, extension_node,
                                      &e->issuer_key_id,
                                      &c->config);
          break;
        case SSH_X509_EXT_SUBJECT_KEY_ID:
          rv = ssh_x509_decode_subject_key_id(context, extension_node,
                                              &e->subject_key_id);
          break;
        case SSH_X509_EXT_PRV_KEY_UP:
          rv = ssh_x509_decode_private_key_period(context,
                                                  extension_node,
                                                  &e->
                                                  private_key_usage_not_before,
                                                  &e->
                                                  private_key_usage_not_after);
          break;
        case SSH_X509_EXT_CERT_POLICIES:
          rv = ssh_x509_decode_policy_info(context, extension_node,
                                           &e->policy_info);
          break;
        case SSH_X509_EXT_POLICY_MAPPINGS:
          rv = ssh_x509_decode_policy_mappings(context, extension_node,
                                               &e->policy_mappings);
          break;
        case SSH_X509_EXT_SUBJECT_ALT_NAME:
          rv = ssh_x509_decode_general_names(context, extension_node,
                                             &e->subject_alt_names,
                                             &c->config);
          break;
        case SSH_X509_EXT_ISSUER_ALT_NAME:
          rv = ssh_x509_decode_general_names(context, extension_node,
                                             &e->issuer_alt_names,
                                             &c->config);
          break;
        case SSH_X509_EXT_SUBJECT_DIR_ATTR:
          rv = ssh_x509_decode_directory_attribute(context, extension_node,
                                                   &e->subject_directory_attr);
          break;
        case SSH_X509_EXT_BASIC_CNST:
          rv = ssh_x509_decode_basic_constraints(context, extension_node,
                                                 &e->ca, &e->path_len,
                                                 &c->config);
          break;
        case SSH_X509_EXT_NAME_CNST:
          rv = ssh_x509_decode_name_const(context, extension_node,
                                          &e->name_const_permitted,
                                          &e->name_const_excluded,
                                          &c->config);
          break;
        case SSH_X509_EXT_POLICY_CNST:
          rv = ssh_x509_decode_policy_const(context, extension_node,
                                            &e->policy_const);
          break;
        case SSH_X509_EXT_CRL_DIST_POINTS:
          rv = ssh_x509_decode_crl_dist_points(context, extension_node,
                                               e->issuer_alt_names,
                                               &e->crl_dp,
                                               &c->config);
          break;
        case SSH_X509_EXT_FRESHEST_CRL:
          /* See comment above */
          rv = ssh_x509_decode_crl_dist_points(context, extension_node,
                                               e->issuer_alt_names,
                                               &e->freshest_crl,
                                               &c->config);
          break;
        case SSH_X509_EXT_KEY_USAGE:
          rv = ssh_x509_decode_key_usage(context, extension_node,
                                         &e->key_usage);
          break;
        case SSH_X509_EXT_EXT_KEY_USAGE:
          rv = ssh_x509_decode_oid_list(context, extension_node,
                                        &e->ext_key_usage);
          break;
        case SSH_X509_EXT_PRV_INTERNET_EXT:
          /* None defined. */
          if (ext_critical == TRUE)
            rv = SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          break;
        case SSH_X509_EXT_AUTH_INFO_ACCESS:
          rv = ssh_x509_decode_info_access(context,
                                           extension_node,
                                           &e->auth_info_access,
                                           &c->config);
          break;
        case SSH_X509_EXT_NETSCAPE_COMMENT:
          rv = ssh_x509_decode_netscape_comment(context,
                                                extension_node,
                                                &e->netscape_comment);
          break;
        case SSH_X509_EXT_CERT_TEMPLATE_NAME:
          rv = ssh_x509_decode_cert_template_name(context,
                                                  extension_node,
                                                  &e->cert_template_name);
          break;
        case SSH_X509_EXT_QCSTATEMENTS:
          rv = ssh_x509_decode_qcstatements(context,
                                            extension_node,
                                            &e->qcstatements,
                                            &c->config);
          break;
        case SSH_X509_EXT_SUBJECT_INFO_ACCESS:
          rv = ssh_x509_decode_info_access(context,
                                           extension_node,
                                           &e->subject_info_access,
                                           &c->config);
          break;
        case SSH_X509_EXT_INHIBIT_ANY_POLICY:
          if (ssh_asn1_read_node(context, extension_node,
                                 "(integer-short ())",
                                 &e->inhibit_any_skip_certs)
              != SSH_ASN1_STATUS_OK)
            rv = SSH_X509_FAILED_INVALID_EXTENSION;
          else
            rv = SSH_X509_OK;
          break;
        default:
          goto make_unknown_extension;
#if 0
          if (ext_critical == TRUE)
            return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          else
            rv = SSH_X509_OK;
#endif
          break;
        }

      ssh_free(ext_oid);
      ssh_free(ext_value);

      if (rv == SSH_X509_OK)
        ssh_x509_ext_info_set(&e->ext_available,
                              &e->ext_critical,
                              extension_type, ext_critical);
      else if (ext_critical)
        {
          return SSH_X509_FAILED_INVALID_EXTENSION;
        }
    }
  return SSH_X509_OK;
}


/* Decode generic X509 crl extension */
SshX509Status
ssh_x509_crl_decode_extension(SshAsn1Context context,
                              SshAsn1Node node,
                              SshX509Crl c)
{
  SshAsn1Status status;
  SshAsn1Node   extensions;
  SshX509CrlExtensions e = &c->extensions;

  /* Clean the extension info array. */
  e->ext_available = e->ext_critical = 0L;

  /* Decode the extension framework. */
  status =
    ssh_asn1_read_node(context, node,
                       "(sequence ()"
                       "  (any ()))", &extensions);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  for (; extensions; extensions = ssh_asn1_node_next(extensions))
    {
      SshAsn1Tree vt;
      SshAsn1Node extension_node;
      unsigned char *ext_oid;
      const SshOidStruct *ext_oids;
      Boolean ext_critical, critical_found;
      unsigned char *ext_value;
      size_t ext_value_len;
      unsigned int extension_type;

      /* Decode the first extension. */
      status =
        ssh_asn1_read_node(context, extensions,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (optional"
                           "     (boolean ()))"
                           "  (octet-string ()))",
                           &ext_oid,
                           &critical_found, &ext_critical,
                           &ext_value, &ext_value_len);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;

      if (critical_found != TRUE)
        ext_critical = FALSE;

      /* Decode the value. */
      if (ssh_asn1_decode(context, ext_value, ext_value_len, &vt)
          != SSH_ASN1_STATUS_OK)
        {
          ssh_free(ext_oid);
          ssh_free(ext_value);
          return SSH_X509_FAILED_ASN1_DECODE;
        }

      /* Find the correct object type. */
      ext_oids = ssh_oid_find_by_oid_of_type(ext_oid, SSH_OID_CRL_EXT);

      /* Free the ASN.1 allocated oid and value. */
      ssh_free(ext_oid);
      ssh_free(ext_value);

      if (ext_oids == NULL)
        {
          /* Only if the extension claims to be critical shall
             we fail! */
          if (ext_critical)
            return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          continue;
        }

      extension_type = ext_oids->extra_int;

      /* Get a pointer to the root node of the ASN.1 tree. */
      extension_node = ssh_asn1_get_root(vt);

      /* Set the extension information. It should be noted, that
         the OID code never returns 'extension_type' values which
         are incorrect.

         Also the extension information code never overwrites the
         values just or's them.
         */

      if (ssh_x509_crl_ext_available(c, extension_type, NULL))
        {
          /* The extension appears twice! */
          if (extension_type != SSH_X509_CRL_EXT_MAX)
            return SSH_X509_FAILED_DUPLICATE_EXTENSION;

          /* Unknown extension nothing remarkable. */
        }
      ssh_x509_ext_info_set(&e->ext_available,
                            &e->ext_critical,
                            extension_type, ext_critical);

      switch (extension_type)
        {
        case SSH_X509_CRL_EXT_AUTH_KEY_ID:
          if (ssh_x509_decode_key_id(context, extension_node,
                                     &e->auth_key_id,
                                     &c->config) != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_EXT_ISSUER_ALT_NAME:
          if (ssh_x509_decode_general_names(context, extension_node,
                                            &e->issuer_alt_names,
                                            &c->config)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_EXT_CRL_NUMBER:
          if (ssh_x509_decode_number(context, extension_node,
                                     &e->crl_number) != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_EXT_ISSUING_DIST_POINT:
          if (ssh_x509_decode_issuing_dist_point(context, extension_node,
                                                 e->issuer_alt_names,
                                                 &e->dist_point,
                                                 &c->config)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_EXT_DELTA_CRL_IND:
          if (ssh_x509_decode_number(context, extension_node,
                                     &e->delta_crl_ind) != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        default:
          if (ext_critical == TRUE)
            return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          break;
        }


    }
  return SSH_X509_OK;
}

SshX509Status ssh_x509_crl_rev_decode_extension(SshAsn1Context context,
                                                SshAsn1Node node,
                                                SshX509RevokedCerts c,
                                                SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node   extensions;
  SshX509CrlRevExtensions e = &c->extensions;

  /* Clean the extension info array. */
  e->ext_available = e->ext_critical = 0L;

  /* Decode the extension framework. */
  status =
    ssh_asn1_read_node(context, node,
                       "(sequence ()"
                       "  (any ()))", &extensions);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  for (; extensions; extensions = ssh_asn1_node_next(extensions))
    {
      SshAsn1Tree vt;
      SshAsn1Node extension_node;
      unsigned char *ext_oid;
      const SshOidStruct *ext_oids;
      Boolean ext_critical, critical_found;
      unsigned char *ext_value;
      size_t ext_value_len;
      unsigned int extension_type;

      /* Decode the first extension. */
      status =
        ssh_asn1_read_node(context, extensions,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (optional"
                           "     (boolean ()))"
                           "  (octet-string ()))",
                           &ext_oid,
                           &critical_found, &ext_critical,
                           &ext_value, &ext_value_len);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;

      if (critical_found != TRUE)
        ext_critical = FALSE;

      /* Decode the value. */
      vt = NULL;
      if (ssh_asn1_decode(context, ext_value, ext_value_len, &vt)
          != SSH_ASN1_STATUS_OK)
        {
          ssh_free(ext_oid);
          ssh_free(ext_value);
          return SSH_X509_FAILED_ASN1_DECODE;
        }

      /* Find the correct object type. */
      ext_oids = ssh_oid_find_by_oid_of_type(ext_oid, SSH_OID_CRL_ENTRY_EXT);

      /* Free the ASN.1 allocated oid and value. */
      ssh_free(ext_oid);
      ssh_free(ext_value);

      if (ext_oids == NULL)
        {
          /* Only if the extension claims to be critical shall
             we fail! */
          if (ext_critical)
            return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          continue;
        }

      extension_type = ext_oids->extra_int;

      /* Get a pointer to the root node of the ASN.1 tree. */
      if (vt)
        extension_node = ssh_asn1_get_root(vt);
      else
        extension_node = NULL;

      /* Set the extension information. It should be noted, that
         the OID code never returns 'extension_type' values which
         are incorrect.

         Also the extension information code never overwrites the
         values just or's them.
         */

      if (ssh_x509_revoked_ext_available(c, extension_type, NULL))
        {
          /* The extension appears twice! */
          if (extension_type != SSH_X509_CRL_ENTRY_EXT_MAX)
            return SSH_X509_FAILED_DUPLICATE_EXTENSION;

          /* Unknown extension nothing remarkable. */
        }
      ssh_x509_ext_info_set(&e->ext_available,
                            &e->ext_critical,
                            extension_type, ext_critical);

      switch (extension_type)
        {
        case SSH_X509_CRL_ENTRY_EXT_REASON_CODE:
          if (ssh_x509_decode_crl_reason_code(context,
                                              extension_node,
                                              &e->reason_code)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE:
          if (ssh_x509_decode_hold_inst_code(context,
                                             extension_node,
                                             &e->hold_inst_code)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE:
          if (ssh_x509_decode_invalidity_date(context,
                                              extension_node,
                                              &e->
                                              invalidity_date)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        case SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER:
          if (ssh_x509_decode_general_names(context,
                                            extension_node,
                                            &e->certificate_issuer,
                                            config)
              != SSH_X509_OK)
            return SSH_X509_FAILED_INVALID_EXTENSION;
          break;
        default:
          if (ext_critical)
            return SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION;
          break;
        }
    }

  return SSH_X509_OK;
}
#endif /* SSHDIST_CERT */
