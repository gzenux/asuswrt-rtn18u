/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc encode routines, mostly extensions and pieces inside certificate or
   CRL.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"

#define SSH_DEBUG_MODULE "X509ExtEncode"

#ifdef SSHDIST_CERT

/* Validity. */
SshAsn1Node ssh_x509_encode_validity(SshAsn1Context context,
                                     SshBerTime not_before,
                                     SshBerTime not_after)
{
  SshAsn1Status status;
  SshAsn1Node validity;

  if (ssh_ber_time_available(not_before) == FALSE &&
      ssh_ber_time_available(not_after)  == FALSE)
    return NULL;

  /* Encode validity fields. This is approximately correct? */
  if (not_before->year >= 2050 || not_after->year >= 2050)
    {
      status =
        ssh_asn1_create_node(context, &validity,
                             "(sequence ()"
                             "  (generalized-time ())"
                             "  (generalized-time ()))",
                             not_before, not_after);
    }
  else
    {
      status =
        ssh_asn1_create_node(context, &validity,
                             "(sequence ()"
                             "  (utc-time ())"
                             "  (utc-time ()))",
                             not_before, not_after);
    }

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return validity;
}

/* Time */
SshAsn1Node ssh_x509_encode_time(SshAsn1Context context,
                                 SshBerTime my_time)
{
  SshAsn1Status status;
  SshAsn1Node out_time;

  if (ssh_ber_time_available(my_time) == FALSE)
    return NULL;

  /* Encode time field. This is approximately correct? */
  if (my_time->year >= 2050)
    {
      status =
        ssh_asn1_create_node(context, &out_time,
                             "(generalized-time ())",
                             my_time);
    }
  else
    {
      status =
        ssh_asn1_create_node(context, &out_time,
                             "(utc-time ())",
                             my_time);
    }

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return out_time;
}

/* Basic constraints. */
SshAsn1Node ssh_x509_encode_basic_constraints(SshAsn1Context context,
                                              Boolean ca,
                                              size_t path_len,
                                              SshX509Config config)
{
  SshMPIntegerStruct t;
  SshAsn1Node node;
  SshAsn1Status status;

  if (ca == FALSE && config->ec.allow_ee_basic_constraints == 0)
    return NULL;

  if (ca != FALSE && path_len != (size_t)-1)
    {
      ssh_mprz_init_set_ui(&t, path_len);
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (boolean ())"
                             "  (integer ()))",
                             ca, &t);
      ssh_mprz_clear(&t);
    }
  else
    if (ca != FALSE || config->ec.allow_ee_basic_constraints)
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (boolean ()))", ca);
    else
      return NULL;

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}


/* Encode key id */
SshAsn1Node ssh_x509_encode_key_id(SshAsn1Context   context,
                                   SshX509ExtKeyId k,
                                   SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node   key_id, gen_name, serial_number, list, node;

  if (k->auth_cert_issuer == NULL &&
      k->key_id_len == 0 &&
      ssh_mprz_cmp_ui(&k->auth_cert_serial_number, 0) < 0)
    return NULL;

  key_id = gen_name = serial_number = NULL;
  list = NULL;
  if (k->key_id)
    {
      status =
        ssh_asn1_create_node(context, &key_id,
                             "(octet-string (0))",
                             k->key_id, k->key_id_len);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      list = ssh_asn1_add_list(list, key_id);
    }

  if (k->auth_cert_issuer)
    {
      node =
        ssh_x509_encode_general_names(context, k->auth_cert_issuer, config);
      if (node == NULL)
        return NULL;

      status =
        ssh_asn1_create_node(context, &gen_name,
                             "(any (1))",
                             node);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      list = ssh_asn1_add_list(list, gen_name);

      if (ssh_mprz_cmp_si(&k->auth_cert_serial_number, -1) != 0)
        {
          status =
            ssh_asn1_create_node(context, &serial_number,
                             "(integer (2))",
                                 &k->auth_cert_serial_number);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
        }

      list = ssh_asn1_add_list(list, serial_number);
    }

  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}

/* Encode subject key id */
SshAsn1Node ssh_x509_encode_subject_key_id(SshAsn1Context context,
                                           SshX509ExtKeyId k)
{
  SshAsn1Status status;
  SshAsn1Node   key_id;

  if (k->key_id_len == 0)
    return NULL;

  status =
    ssh_asn1_create_node(context, &key_id,
                         "(octet-string ())",
                         k->key_id, k->key_id_len);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return key_id;
}

/* Encode directory attributes */
SshAsn1Node ssh_x509_encode_directory_attribute(SshAsn1Context context,
                                                SshX509ExtDirAttribute d)
{
  SshAsn1Status status;
  SshAsn1Node list, attr, node, any;
  SshAsn1Tree tr;
  SshX509ExtDirAttribute tmp;
  Boolean rv = FALSE;

  if (d == NULL)
    return NULL;

  list = NULL;

  for (tmp = d; tmp; tmp = tmp->next)
    {
      /* Check here the size of the octet string so that this won't
         take forever? */
      status =
        ssh_asn1_decode(context,
                        tmp->octet_string, tmp->octet_string_len,
                        &tr);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      /* Get the root node which contains the decode value for the
         any field. */
      any = ssh_asn1_get_root(tr);

      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (any ()))",
                             tmp->oid,
                             any);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, node);
    }

  /* Finished the attribute list. */

  status =
    ssh_asn1_create_node(context, &attr,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return attr;
  return NULL;
}

/* Encode general subtree */
SshAsn1Node ssh_x509_encode_general_subtree(SshAsn1Context context,
                                            SshX509GeneralSubtree g,
                                            SshX509Config config)
{
  SshAsn1Node list, node, base, int1, int2, gen;
  SshAsn1Status status;
  SshX509GeneralSubtree tmp;
  Boolean rv = FALSE;

  if (g == NULL)
    return NULL;

  list = NULL;

  for (tmp = g; tmp; tmp = tmp->next)
    {
      /* TODO: The code should only encode one name. */
      base = ssh_x509_encode_general_name(context, tmp->name, config);
      if (base == NULL)
        goto failed;

      /* Handle the integers here. For PKIX int1 is always zero and
         int2 is not present, but handle other cases as well.*/
      if (g->min_distance == 0)
        int1 = NULL;
      else
        {
          status = ssh_asn1_create_node(context, &int1,
                                        "(integer-short ())",
                                        (SshWord)g->min_distance);
          if (status != SSH_ASN1_STATUS_OK)
            goto failed;
        }

      if (g->max_distance == SSH_X509_GENERAL_SUBTREE_VALUE_ABSENT)
        {
          int2 = NULL;
        }
      else
        {
          status =
            ssh_asn1_create_node(context, &int2,
                                 "(integer-short ())",
                                 (SshWord)g->max_distance);
          if (status != SSH_ASN1_STATUS_OK)
            goto failed;
        }

      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (any ())"
                             "  (any (0))"
                             "  (any (1)))",
                             base, int1, int2);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, node);
    }

  /* Handle the higher layer of the sequence. */
  status =
    ssh_asn1_create_node(context, &gen,
                         "(sequence ()"
                         "  (any ()))", list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return gen;
  return NULL;
}

/* Encode name constraints */
SshAsn1Node ssh_x509_encode_name_const(SshAsn1Context context,
                                       SshX509GeneralSubtree permit,
                                       SshX509GeneralSubtree exclude,
                                       SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node node, p_node, e_node;
  Boolean rv = FALSE;

  if (permit == NULL && exclude == NULL)
    return NULL;

  /* Handle general subtrees first. */
  if (permit)
    {
      p_node = ssh_x509_encode_general_subtree(context, permit, config);
      if (p_node == NULL)
        goto failed;
    }
  else
    p_node = NULL;
  if (exclude)
    {
      e_node = ssh_x509_encode_general_subtree(context, exclude, config);
      if (e_node == NULL)
        goto failed;
    }
  else
    e_node = NULL;

  /* Now add them up. */
  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any (0))"
                         "  (any (1)))",
                         p_node, e_node);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return node;

  return NULL;
}

/* Encode CRL distribution points. */
SshAsn1Node ssh_x509_encode_crl_dist_points(SshAsn1Context context,
                                            SshX509ExtCRLDistPoints p,
                                            SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node list, cdp, node, tmp1, tmp2;
  SshX509ExtCRLDistPoints c;
  Boolean rv = FALSE;
  unsigned char *reason;
  size_t reason_len;

  if (p == NULL)
    return NULL;

  list = NULL;
  for (c = p; c; c = c->next)
    {
      if (c->full_name || c->dn_relative_to_issuer)
        {
          if (c->full_name)
            {
              tmp1 = ssh_x509_encode_general_names(context,
                                                   c->full_name, config);
              if (tmp1 == NULL)
                goto failed;

              status =
                ssh_asn1_create_node(context, &tmp2,
                                     "(any (0))", tmp1);
              if (status != SSH_ASN1_STATUS_OK)
                goto failed;
            }
          else
            {
              SshRDN relative_dn;

              /* Take the RDN out of the DN. */
              relative_dn = ssh_dn_take_last_rdn(c->dn_relative_to_issuer);

              /* Encode the last RDN of the DN. */
              tmp1 = ssh_dn_encode_rdn(context, relative_dn, FALSE, config);
              if (tmp1 == NULL)
                goto failed;

              status =
                ssh_asn1_create_node(context, &tmp2,
                                     "(any (1))", tmp1);
              if (status != SSH_ASN1_STATUS_OK)
                goto failed;
            }
        }
      else
        tmp2 = NULL;

      status =
        ssh_asn1_create_node(context, &node,
                             "(any (e 0))", tmp2);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      if (c->reasons)
        {
          reason = ssh_x509_ui_to_bs(c->reasons, &reason_len);
          status =
            ssh_asn1_create_node(context, &tmp1,
                                 "(bit-string (1))",
                                 reason, reason_len);
          ssh_free(reason);
          if (status != SSH_ASN1_STATUS_OK)
            goto failed;
        }
      else
        tmp1 = NULL;

      node = ssh_asn1_add_list(node, tmp1);

      if (c->crl_issuer)
        {
          tmp2 = ssh_x509_encode_general_names(context, c->crl_issuer, config);
          if (tmp2 == NULL)
            goto failed;

          status =
            ssh_asn1_create_node(context, &tmp1,
                                 "(any (2))", tmp2);
          if (status != SSH_ASN1_STATUS_OK)
            goto failed;
        }
      else
        tmp1 = NULL;

      node = ssh_asn1_add_list(node, tmp1);

      status =
        ssh_asn1_create_node(context, &tmp1,
                             "(sequence ()"
                             "  (any ()))", node);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, tmp1);
    }

  /* Handle the higher layer of the sequence. */
  status =
    ssh_asn1_create_node(context, &cdp,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return cdp;
  return NULL;
}

/* Encode Authority Information Access. */
SshAsn1Node ssh_x509_encode_info_access(SshAsn1Context context,
                                        SshX509ExtInfoAccess access,
                                        SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node list, aa, node, tmp;
  SshX509ExtInfoAccess c;
  Boolean rv = FALSE;

  if (access == NULL)
    return NULL;

  list = NULL;
  for (c = access; c; c = c->next)
    {
      tmp = ssh_x509_encode_general_name(context, c->access_location, config);
      if (tmp == NULL)
        goto failed;

      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (any ()))",
                             c->access_method,
                            tmp);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, node);
    }

  /* Handle the higher layer of the sequence. */
  status =
    ssh_asn1_create_node(context, &aa,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return aa;
  return NULL;
}

SshAsn1Node
ssh_x509_encode_unknown_extension(SshAsn1Context context,
                                  SshX509ExtUnknown unknown)
{
  SshAsn1Node node;
  SshAsn1Status status;

  if (!unknown)
    return NULL;

  if (unknown->critical)
    {
      status = ssh_asn1_create_node(context, &node,
                                    "(sequence ()"
                                    "(object-identifier ())"
                                    "(boolean ())"
                                    "(octet-string ()))",
                                    unknown->oid, unknown->critical,
                                    unknown->der, unknown->der_length);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    {
      status = ssh_asn1_create_node(context, &node,
                                    "(sequence ()"
                                    "(object-identifier ())"
                                    "(octet-string ()))",
                                    unknown->oid,
                                    unknown->der, unknown->der_length);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }

  return node;
}


SshAsn1Node
ssh_x509_encode_netscape_comment(SshAsn1Context context,
                                 SshStr comment)
{
  SshAsn1Node node;
  SshAsn1Status status;
  unsigned char *p;
  size_t len;

  if (!comment)
    return NULL;

  p = ssh_str_get(comment, &len);
  if (p == NULL)
    return NULL;

  status = ssh_asn1_create_node(context, &node, "(ia5-string ())", p, len);
  ssh_free(p);

  if (status == SSH_ASN1_STATUS_OK)
    return node;
  return NULL;
}

SshAsn1Node
ssh_x509_encode_cert_template_name(SshAsn1Context context,
                                   SshStr name)
{
  SshAsn1Node node;
  SshAsn1Status status;
  unsigned char *str;
  size_t len;

  if (name == NULL)
    return NULL;

  str = (unsigned char *)ssh_str_get(name, &len);
  status = ssh_asn1_create_node(context, &node, "(bmp-string ())", str, len);
  if (status == SSH_ASN1_STATUS_OK)
    return node;
  return NULL;
}

/* Encode oid list */
SshAsn1Node ssh_x509_encode_oid_list(SshAsn1Context context,
                                     SshX509OidList oid_list)
{
  SshAsn1Status status;
  SshAsn1Node list, node;
  SshX509OidList c;
  Boolean rv = FALSE;

  if (oid_list == NULL)
    return NULL;

  list = NULL;
  for (c = oid_list; c; c = c->next)
    {
      status =
        ssh_asn1_create_node(context, &node,
                             "(object-identifier ())",
                             c->oid);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, node);
    }

  /* Handle the higher layer of the sequence. */
  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return node;
  return NULL;
}

/* Encode key usage */
SshAsn1Node ssh_x509_encode_key_usage(SshAsn1Context context,
                                      SshX509UsageFlags flags)
{
  SshAsn1Status status;
  SshAsn1Node node;
  unsigned char *buf;
  size_t buf_len;

  if (flags == 0)
    return NULL;

  buf = ssh_x509_ui_to_bs(flags, &buf_len);
  status =
    ssh_asn1_create_node(context, &node,
                         "(bit-string ())",
                         buf, buf_len);
  ssh_free(buf);

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}

/* Encode Private key usage period. */
SshAsn1Node
ssh_x509_encode_private_key_usage_period(SshAsn1Context context,
                                         SshBerTime not_before,
                                         SshBerTime not_after)
{
  SshAsn1Status status;
  SshAsn1Node   nb, nf, node;

  nb = nf = NULL;

  if (ssh_ber_time_available(not_before))
    {
      status =
        ssh_asn1_create_node(context, &nb,
                             "(generalized-time (0))",
                             not_before);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }

  if (ssh_ber_time_available(not_after))
    {
      status =
        ssh_asn1_create_node(context, &nf,
                             "(generalized-time (1))",
                             not_after);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }

  if (nf == NULL && nb == NULL)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any ())"
                         "  (any ()))",
                         nb, nf);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}

/* Encode the CRL number (trivial). */
SshAsn1Node ssh_x509_encode_number(SshAsn1Context context,
                                   SshMPInteger       mp_int)
{
  SshAsn1Status status;
  SshAsn1Node   node;

  if (ssh_mprz_cmp_ui(mp_int, 0) < 0)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(integer ())",
                         mp_int);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}

/* Encode issuer distribution point */
SshAsn1Node
ssh_x509_encode_issuing_dist_point(SshAsn1Context context,
                                   SshX509ExtIssuingDistPoint ip,
                                   SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node   list, name, tmp;

  if (ip == NULL)
    return NULL;

  if (ip->full_name || ip->dn_relative_to_issuer)
    {
      if (ip->full_name)
        {
          tmp = ssh_x509_encode_general_names(context, ip->full_name, config);
          if (tmp == NULL)
            return NULL;
          status =
            ssh_asn1_create_node(context, &name,
                                 "(any (0))", tmp);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
        }
      else
        {
          SshRDN relative_dn;

          /* Take the RDN out of the DN. */
          relative_dn = ssh_dn_take_last_rdn(ip->dn_relative_to_issuer);

          /* Encode the last RDN of the DN. */
          tmp = ssh_dn_encode_rdn(context, relative_dn, FALSE, config);
          if (tmp == NULL)
            return NULL;

          status =
            ssh_asn1_create_node(context, &name,
                                 "(any (e 1))", tmp);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
        }
    }
  else
    name = NULL;

  status =
    ssh_asn1_create_node(context, &list,
                         "(any (e 0))", name);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  if (ip->only_contains_user_certs)
    {
      status =
        ssh_asn1_create_node(context, &tmp,
                             "(boolean (1))",
                             ip->only_contains_user_certs);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    tmp = NULL;
  list = ssh_asn1_add_list(list, tmp);

  if (ip->only_contains_ca_certs)
    {
      status =
        ssh_asn1_create_node(context, &tmp,
                             "(boolean (2))",
                             ip->only_contains_ca_certs);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    tmp = NULL;
  list = ssh_asn1_add_list(list, tmp);

  if (ip->only_some_reasons)
    {
      unsigned char *reason;
      size_t reason_len;

      reason = ssh_x509_ui_to_bs(ip->only_some_reasons, &reason_len);

      status =
        ssh_asn1_create_node(context, &tmp,
                             "(bit-string (3))",
                             reason, reason_len);
      ssh_free(reason);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    tmp = NULL;
  list = ssh_asn1_add_list(list, tmp);

  if (ip->indirect_crl)
    {
      status =
        ssh_asn1_create_node(context, &tmp,
                             "(boolean (4))",
                             ip->indirect_crl);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    tmp = NULL;
  list = ssh_asn1_add_list(list, tmp);

  if (ip->only_contains_attribute_certs)
    {
      status =
        ssh_asn1_create_node(context, &tmp,
                             "(boolean (5))",
                             ip->only_contains_attribute_certs);
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  else
    tmp = NULL;
  list = ssh_asn1_add_list(list, tmp);

  /* Encode for the final output. */
  status =
    ssh_asn1_create_node(context, &tmp,
                         "(sequence ()"
                         "  (any ()))",
                         list);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return tmp;
}

/* Encode revoked cert extensions. */
SshAsn1Node ssh_x509_encode_crl_reason_code(SshAsn1Context context,
                                            SshX509CRLReasonCode flags)
{
  SshAsn1Status status;
  SshAsn1Node   node;
  SshMPIntegerStruct        t;

  if (flags == 0)
    return NULL;

  ssh_mprz_init_set_ui(&t, flags);

  status =
    ssh_asn1_create_node(context, &node,
                         "(enum ())",
                         &t);
  ssh_mprz_clear(&t);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}

/* Encode hold instruction code. */
SshAsn1Node ssh_x509_encode_hold_inst_code(SshAsn1Context context,
                                           char *code)
{
  SshAsn1Status status;
  SshAsn1Node   node;

  if (code == NULL)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(object-identifier ())",
                         code);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  return node;
}

/* Encode invalidity dates. */
SshAsn1Node ssh_x509_encode_invalidity_date(SshAsn1Context context,
                                            SshBerTime date)
{
  SshAsn1Status status;
  SshAsn1Node   node;

  if (ssh_ber_time_available(date) == FALSE)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(generalized-time ())",
                         date);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}

/* Encode policy information. */
SshAsn1Node ssh_x509_encode_policy_info(SshAsn1Context context,
                                        SshX509ExtPolicyInfo p)
{
  SshAsn1Status status;
  SshAsn1Node list, cert_policy, node, tmp = NULL;
  SshAsn1Node tmp1, tmp2, tmp3, tmp4, tmp5;
  SshX509ExtPolicyInfo tmp_p;
  const char *oid_find_str;
  const SshOidStruct *ext_oid;
  Boolean rv = FALSE;

  if (p == NULL)
    return NULL;

  /* Initialize the main list. */
  list = NULL;

  /* Lets loop all the policy information structures through. The
     result node of this loop is stored at `list'. */
  for (tmp_p = p; tmp_p; tmp_p = tmp_p->next)
    {
      SshX509ExtPolicyQualifierInfo pq;

      /* Handle the policy qualifiers. The result node of this loop is
         stored at `tmp' */
      for (pq = tmp_p->pq_list; pq; pq = pq->next)
        {
          /* First determine which case do we have here. These blocks
             will result into tmp1 and oid_find_str to be filled. */
          tmp1 = NULL;

          if (pq->cpsuri)
            {
              /* CPSUri! TODO: Put these strings into the OID table. */
              oid_find_str = "pkix-id-qt-cps";

              if (ssh_str_get_der(context, pq->cpsuri, SSH_CHARSET_US_ASCII,
                                  &tmp1) == FALSE)
                goto failed;
            }
          else /* UNotice! */
            {
              oid_find_str = "pkix-id-qt-unotice";

              /* fills tmp2, uses tmp4 */
              if (pq->organization)
                {
                  if (ssh_str_get_der(context, pq->organization,
                                      SSH_CHARSET_US_ASCII, &tmp4) == FALSE)
                    goto failed;

                  status =
                    ssh_asn1_create_node(context, &tmp2, "(any ())", tmp4);

                  if (status != SSH_ASN1_STATUS_OK)
                    goto failed;
                }
              else
                tmp2 = NULL;

              /* fills tmp3 */
              if (pq->notice_numbers_count)
                {
                  unsigned int j;

                  tmp5 = NULL;
                  for (j = 0; j < pq->notice_numbers_count; j++)
                    {
                      status =
                        ssh_asn1_create_node(context, &tmp4,
                                             "(integer-short ())",
                                             (SshWord)pq->notice_numbers[j]);
                      if (status != SSH_ASN1_STATUS_OK)
                        goto failed;
                      tmp5 = ssh_asn1_add_list(tmp5, tmp4);
                    }

                  status =
                    ssh_asn1_create_node(context, &tmp3,
                                         "(sequence ()"
                                         "  (any ()))", tmp5);
                  if (status != SSH_ASN1_STATUS_OK)
                    goto failed;
                }
              else
                tmp3 = NULL;

              /* Create now the NoticeReference sequence by merging
                 tmp2 and tmp3 into tmp4. Both tmp2 and tmp3 are
                 mandatory. */
              if (tmp2 && tmp3)
                {
                  status =
                    ssh_asn1_create_node(context, &tmp4,
                                         "(sequence ()"
                                         "  (any ())"
                                         "  (any ()))",
                                         tmp2, tmp3);
                  if (status != SSH_ASN1_STATUS_OK)
                    goto failed;
                }
              else
                tmp4 = NULL;

              /* Handle now the DisplayText into tmp5 */
              if (pq->explicit_text)
                {
                  tmp2 = NULL;
                  if (ssh_str_get_der(context, pq->explicit_text,
                                      SSH_CHARSET_VISIBLE, &tmp2) == FALSE)
                    if (ssh_str_get_der(context, pq->explicit_text,
                                        SSH_CHARSET_BMP, &tmp2) == FALSE)
                      if (ssh_str_get_der(context, pq->explicit_text,
                                          SSH_CHARSET_UTF8, &tmp2) == FALSE)
                        goto failed;

                  status =
                    ssh_asn1_create_node(context, &tmp5, "(any ())", tmp2);
                  if (status != SSH_ASN1_STATUS_OK)
                    goto failed;
                }
              else
                tmp5 = NULL;

              /* Now build up the UserNotice by mergning NotifeRef and
                 DisplayText into tmp1 */
              status =
                ssh_asn1_create_node(context, &tmp1,
                                     "(sequence ()"
                                     "  (any ())"
                                     "  (any ()))",
                                     tmp4, tmp5);
              if (status != SSH_ASN1_STATUS_OK)
                goto failed;
            }

          /* Search the object identifier. */
          ext_oid =
            ssh_oid_find_by_std_name_of_type(oid_find_str, SSH_OID_POLICY);
          if (ext_oid == NULL)
            goto failed;

          status =
            ssh_asn1_create_node(context, &tmp2,
                                 "(sequence ()"
                                 "  (object-identifier ())"
                                 "  (any ()))",
                                 ext_oid->oid,
                                 tmp1);

          if (status != SSH_ASN1_STATUS_OK)
            goto failed;

          /* Add to the list of values. */
          tmp = ssh_asn1_add_list(tmp, tmp2);

        } /* end for policy qualifier loop */

      /* We have now a nice list of policy qualifier info's. */
      /* Build on policy info sequence. */
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (sequence () (any ())))",
                             tmp_p->oid,
                             tmp);

      tmp = NULL;
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      /* Build up the list for certificate policies. */
      list = ssh_asn1_add_list(list, node);
    } /* end for policy info loop */

  /* We have now finished the processing of lists. */

  /* Finish the certificate policies sequence. */
  status =
    ssh_asn1_create_node(context, &cert_policy,
                         "(sequence ()"
                         "  (any ()))", list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  /* We have succeeded! */
  rv = TRUE;

failed:
  if (rv)
    return cert_policy;
  return NULL;
}

/* Encode policy mappings. */
SshAsn1Node ssh_x509_encode_policy_mappings(SshAsn1Context context,
                                            SshX509ExtPolicyMappings m)
{
  SshAsn1Status status;
  SshAsn1Node list, node, out;
  SshX509ExtPolicyMappings tmp;
  Boolean rv = FALSE;

  if (m == NULL)
    return NULL;

  list = NULL;
  for (tmp = m; tmp; tmp = tmp->next)
    {
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (object-identifier ()))",
                             tmp->issuer_dp_oid,
                             tmp->subject_dp_oid);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      list = ssh_asn1_add_list(list, node);
    }

  /* Finished the list now happens the gathering. */
  status =
    ssh_asn1_create_node(context, &out,
                         "(sequence ()"
                         "  (any ()))", list);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:
  if (rv)
    return out;
  return NULL;
}

/* Encode policy constraints. */
SshAsn1Node ssh_x509_encode_policy_const(SshAsn1Context context,
                                         SshX509ExtPolicyConstraints p)
{
  SshAsn1Status status;
  SshAsn1Node pc, int1, int2;
  SshMPIntegerStruct t;
  Boolean rv = FALSE;

  if (p == NULL)
    return NULL;

  ssh_mprz_init(&t);

  if (p->require != SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT)
    {
      status =
        ssh_asn1_create_node(context, &int1,
                             "(integer-short (0))",
                             (SshWord)p->require);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
    }
  else
    int1 = NULL;

  if (p->inhibit != SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT)
    {
      status =
        ssh_asn1_create_node(context, &int2,
                             "(integer-short (1))",
                             (SshWord)p->inhibit);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
    }
  else
    int2 = NULL;

  status =
    ssh_asn1_create_node(context, &pc,
                         "(sequence ()"
                         "  (any ())"
                         "  (any ()))",
                         int1, int2);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  rv = TRUE;
failed:

  ssh_mprz_clear(&t);
  if (rv)
    return pc;
  return NULL;
}

/* Encode qualified certificate statement extensions. */
SshAsn1Node ssh_x509_encode_qcstatement(SshAsn1Context context,
                                        SshX509ExtQCStatement qcs_list,
                                        SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node list = NULL, node;
  SshX509ExtQCStatement qcs;
  const SshOidStruct *ext_oid;

  if (qcs_list == NULL)
    return NULL;

  /* Iterate all qcstatements in the qcs_list. */
  for (qcs = qcs_list; qcs; qcs = qcs->next)
    {
      node = NULL;

      /* Search the object identifier. */
      ext_oid = ssh_oid_find_by_oid_of_type(qcs->oid, SSH_OID_QCSTATEMENT);
      if (ext_oid == NULL)
        {
        unknown_qcstatement:
          /* Unknown oid, with or without data. */
          if (qcs->der)
            {
              status = ssh_asn1_create_node(context, &node,
                                            "(sequence ()"
                                            "(object-identifier ())"
                                            "(octet-string ()))",
                                            qcs->oid,
                                            qcs->der, qcs->der_len);
              if (status != SSH_ASN1_STATUS_OK)
                return NULL;
            }
          else
            {
              status = ssh_asn1_create_node(context, &node,
                                            "(sequence ()"
                                            "(object-identifier ()))",
                                            qcs->oid);
              if (status != SSH_ASN1_STATUS_OK)
                return NULL;
            }

          list = ssh_asn1_add_list(list, node);
          continue;
        }

      switch (ext_oid->extra_int)
        {
        case SSH_X509_QCSTATEMENT_QCSYNTAXV1:
          if (qcs->semantics_oid)
            {
              status = ssh_asn1_create_node(context, &node,
                                            "(sequence ()"
                                            "  (object-identifier ())"
                                            "  (sequence ()"
                                            "    (object-identifier ())))",
                                            ext_oid->oid,
                                            qcs->semantics_oid);
              if (status != SSH_ASN1_STATUS_OK)
                return NULL;
            }
          else if (qcs->name_registration_authorities)
            {
              SshAsn1Node namelist;

              namelist = ssh_x509_encode_general_names
                (context, qcs->name_registration_authorities, config);
              if (namelist == NULL)
                return NULL;

              status = ssh_asn1_create_node(context, &node,
                                            "(sequence ()"
                                            "  (object-identifier ())"
                                            "  (sequence ()"
                                            "    (any ())))",
                                            ext_oid->oid,
                                            namelist);
              if (status != SSH_ASN1_STATUS_OK)
                return NULL;
            }
          else
            {
              status = ssh_asn1_create_node(context, &node,
                                            "(sequence ()"
                                            "  (object-identifier ()))",
                                            qcs->oid);
              if (status != SSH_ASN1_STATUS_OK)
                return NULL;
            }
          break;

        case SSH_X509_QCSTATEMENT_QCCOMPLIANCE:
          status = ssh_asn1_create_node(context, &node,
                                        "(sequence ()"
                                        "  (object-identifier ()))",
                                        ext_oid->oid);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;

        case SSH_X509_QCSTATEMENT_QCEULIMITVALUE:
          status = ssh_asn1_create_node(context, &node,
                                        "(sequence ()"
                                        "  (object-identifier ())"
                                        "  (sequence ()"
                                        "    (integer-short ())"
                                        "    (integer ())"
                                        "    (integer ())))",
                                        ext_oid->oid,
                                        qcs->currency,
                                        &qcs->amount,
                                        &qcs->exponent);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;

        case SSH_X509_QCSTATEMENT_RETENTIONPERIOD:
          status = ssh_asn1_create_node(context, &node,
                                        "(sequence ()"
                                        "  (object-identifier ())"
                                        "  (sequence ()"
                                        "    (integer ())))",
                                        ext_oid->oid,
                                        &qcs->retention_period);
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;
          break;

        default:
          /* Unsupported but known oid. */
          goto unknown_qcstatement;
        }

      list = ssh_asn1_add_list(list, node);
    }

  /* Make a sequence out of qcs list. */
  status = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (any ()))", list);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}

/**** Some generic code summing up contents of this file. */

static SshAsn1Node
ssh_x509_encode_extension(SshAsn1Context context,
                          SshAsn1Node node,
                          const char *oid_str,
                          Boolean critical,
                          int oid_type)
{
  SshAsn1Status status;
  SshAsn1Node newp;
  unsigned char *buf;
  size_t buf_len;
  const SshOidStruct *oid_info = NULL;

  oid_info = ssh_oid_find_by_std_name_of_type(oid_str, oid_type);
  if (oid_info == NULL)
    return NULL;

  /* Convert into octet string. */
  status = ssh_asn1_encode_node(context, node);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED)
    return NULL;
  status = ssh_asn1_node_get_data(node, &buf, &buf_len);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  if (critical)
    {
      status =
        ssh_asn1_create_node(context, &newp,
                             "(sequence ()"
                             "(object-identifier ())"
                             "(boolean ())"
                             "(octet-string ()))",
                             oid_info->oid,
                             critical, buf, buf_len);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_free(buf);
          return NULL;
        }
    }
  else
    {
      status =
        ssh_asn1_create_node(context, &newp,
                             "(sequence ()"
                             "(object-identifier ())"
                             "(octet-string ()))",
                             oid_info->oid,
                             buf, buf_len);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_free(buf);
          return NULL;
        }
    }
  ssh_free(buf);
  return newp;
}

/* Encode certificate X509 extension. This function doesn't currently
   take into account the possibility that the actual encoding of the
   extension might fail. */
SshX509Status
ssh_x509_cert_encode_extension(SshAsn1Context context,
                               SshX509Certificate c,
                               SshAsn1Node *ret)
{
  SshAsn1Node list, node, tmp, extensions;
  SshX509CertExtType type;
  Boolean critical;
  SshX509Status rv = SSH_X509_FAILURE;
  SshX509CertExtensions e = &c->extensions;

  /* Encode extensions into a list. */
  list = NULL;

  /* The idea is to encode first the data, and the wrap into
     extension. */

  /* Authority key identifier. */
  type = SSH_X509_EXT_AUTH_KEY_ID;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_key_id(context, e->issuer_key_id, &c->config);
      if (node)
        {
          if ((tmp =
               ssh_x509_encode_extension(context, node,
                                         "authorityKeyIdentifier",
                                         critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }
  /* Subject key identifier. */
  type = SSH_X509_EXT_SUBJECT_KEY_ID;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_subject_key_id(context, e->subject_key_id);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "subjectKeyIdentifier",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Key usage. */
  type = SSH_X509_EXT_KEY_USAGE;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_key_usage(context, e->key_usage);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "keyUsage",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Private key usage period. */
  type = SSH_X509_EXT_PRV_KEY_UP;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node =
        ssh_x509_encode_private_key_usage_period
        (context,
         &e->private_key_usage_not_before,
         &e->private_key_usage_not_after);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "privateKeyUsagePeriod",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Certificate policy. */
  type = SSH_X509_EXT_CERT_POLICIES;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_policy_info(context, e->policy_info);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "certificatePolicies",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Policy mappings. */
  type = SSH_X509_EXT_POLICY_MAPPINGS;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_policy_mappings(context, e->policy_mappings);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "policyMappings",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Issuer alternative names. */
  type = SSH_X509_EXT_ISSUER_ALT_NAME;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_general_names(context,
                                           e->issuer_alt_names,
                                           &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "issuerAlternativeName",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Subject alternative names. */
  type = SSH_X509_EXT_SUBJECT_ALT_NAME;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_general_names(context,
                                           e->subject_alt_names,
                                           &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "subjectAlternativeName",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Subject directory attributes. */
  type = SSH_X509_EXT_SUBJECT_DIR_ATTR;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_directory_attribute(context,
                                                 e->subject_directory_attr);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "subjectDirectoryAttributes",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }
  /* Basic constraints. */
  type = SSH_X509_EXT_BASIC_CNST;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_basic_constraints(context,
                                               e->ca,
                                               e->path_len,
                                               &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "basicConstraints",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        {
          SSH_TRACE(3, ("Failed to encode basic constraints."));
          return rv;
        }
    }
  /* Name constraints. */
  type = SSH_X509_EXT_NAME_CNST;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_name_const(context,
                                        e->name_const_permitted,
                                        e->name_const_excluded,
                                        &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "nameConstraints",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Policy constraints. */
  type = SSH_X509_EXT_POLICY_CNST;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_policy_const(context,
                                          e->policy_const);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "policyConstraints",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }
  /* CRL distribution points. */
  type = SSH_X509_EXT_CRL_DIST_POINTS;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_crl_dist_points(context, e->crl_dp, &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "CRLDistributionPoints",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  type = SSH_X509_EXT_FRESHEST_CRL;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_crl_dist_points(context, e->freshest_crl,
                                             &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "freshestCRL",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Extended key usage. */
  type = SSH_X509_EXT_EXT_KEY_USAGE;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_oid_list(context,
                                      e->ext_key_usage);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "extendedKeyUsage",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Authority info access. */
  type = SSH_X509_EXT_AUTH_INFO_ACCESS;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_info_access(context,
                                         e->auth_info_access,
                                         &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "authorityInformationAccess",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Netscape comment. */
  type = SSH_X509_EXT_NETSCAPE_COMMENT;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_netscape_comment(context,
                                              e->netscape_comment);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "netscapeComment",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Certificate template name. */
  type = SSH_X509_EXT_CERT_TEMPLATE_NAME;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_cert_template_name(context,
                                                e->cert_template_name);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "windowsCertificateTemplate",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Qualified certificate statements. */
  type = SSH_X509_EXT_QCSTATEMENTS;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_qcstatement(context, e->qcstatements, &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "qcStatements",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  type = SSH_X509_EXT_SUBJECT_INFO_ACCESS;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_info_access(context,
                                         e->subject_info_access,
                                         &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "subjectInformationAccess",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  type = SSH_X509_EXT_INHIBIT_ANY_POLICY;
  if (ssh_x509_cert_ext_available(c, type, &critical))
    {
      if (ssh_asn1_create_node(context, &node,
                               "(integer-short ())", e->inhibit_any_skip_certs)
          == SSH_ASN1_STATUS_OK)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "inhibitAnyPolicy",
                                               critical, SSH_OID_EXT))
              != NULL)
            list = ssh_asn1_add_list(list, tmp);
        }
      else
        return rv;
    }

  /* Encode all unknown (custom) extensions. */
  {
    SshX509ExtUnknown unk;

    for (unk = e->unknown; unk != NULL; unk = unk->next)
      {
        node = ssh_x509_encode_unknown_extension(context, unk);
        if (node != NULL)
          list = ssh_asn1_add_list(list, node);
        else
          return rv;
      }
  }

 /* Finalize the list here. */
  if (list)
    {
      SshAsn1Status status;
      status =
        ssh_asn1_create_node(context, &extensions,
                             "(sequence ()"
                             "(any ()))", list);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;
    }
  else
    extensions = NULL;

  *ret = extensions;

  return SSH_X509_OK;
}


/* CRL extensions. */

SshX509Status
ssh_x509_crl_encode_extension(SshAsn1Context context,
                              SshX509Crl c,
                              SshAsn1Node *ret)
{
  SshAsn1Node   node, crl_list, tmp, crl_extensions;
  SshX509CrlExtType type;
  Boolean       critical;
  SshX509Status rv = SSH_X509_FAILURE;
  SshX509CrlExtensions e = &c->extensions;

  /* First handle the CRL extensions. */
  crl_list = NULL;

  /* Authority key identifier. */
  type = SSH_X509_CRL_EXT_AUTH_KEY_ID;
  if (ssh_x509_crl_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_key_id(context, e->auth_key_id, &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "authorityKeyIdentifier",
                                               critical, SSH_OID_CRL_EXT))
              != NULL)
            crl_list = ssh_asn1_add_list(crl_list, tmp);
        }
      else
        return rv;
    }
  /* Issuer alternative names */
  type = SSH_X509_CRL_EXT_ISSUER_ALT_NAME;
  if (ssh_x509_crl_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_general_names(context,
                                           e->issuer_alt_names,
                                           &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "issuerAlternativeName",
                                               critical, SSH_OID_CRL_EXT))
              != NULL)
            crl_list = ssh_asn1_add_list(crl_list, tmp);
        }
      else
        return rv;
    }
  /* CRL number */
  type = SSH_X509_CRL_EXT_CRL_NUMBER;
  if (ssh_x509_crl_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_number(context, &e->crl_number);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "crlNumber",
                                               critical, SSH_OID_CRL_EXT))
              != NULL)
            crl_list = ssh_asn1_add_list(crl_list, tmp);
        }
      else
        return rv;
    }
  /* Issuing distribution point */
  type = SSH_X509_CRL_EXT_ISSUING_DIST_POINT;
  if (ssh_x509_crl_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_issuing_dist_point(context,
                                                e->dist_point,
                                                &c->config);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "issuingDistributionPoint",
                                               critical, SSH_OID_CRL_EXT))
              != NULL)
            crl_list = ssh_asn1_add_list(crl_list, tmp);
        }
      else
        return rv;
    }
  /* Delta CRL indicator */
  type = SSH_X509_CRL_EXT_DELTA_CRL_IND;
  if (ssh_x509_crl_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_number(context, &e->delta_crl_ind);
      if (node)
        {
          if ((tmp = ssh_x509_encode_extension(context, node,
                                               "deltaCRLIndicator",
                                               critical, SSH_OID_CRL_EXT))
              != NULL)
            crl_list = ssh_asn1_add_list(crl_list, tmp);
        }
      else
        return rv;
    }

  /* Finalize the crl list here. */
  if (crl_list)
    {
      SshAsn1Status status;
      status =
        ssh_asn1_create_node(context, &crl_extensions,
                             "(sequence ()"
                             "  (any ()))", crl_list);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;
    }
  else
    crl_extensions = NULL;

  *ret = crl_extensions;

  return SSH_X509_OK;
}

/* Revoked cert. extensions. */

SshX509Status
ssh_x509_crl_rev_encode_extension(SshAsn1Context context,
                                  SshX509RevokedCerts c,
                                  SshAsn1Node *ret,
                                  SshX509Config config)
{
  SshAsn1Node    node, rl_ext_list, tmp, rl_ext;
  SshX509CrlEntryExtType type;
  Boolean        critical;
  SshX509Status  rv = SSH_X509_FAILURE;
  SshX509CrlRevExtensions e = &c->extensions;

  /* Handle the revoked certificate extensions. */
  rl_ext_list = NULL;

  /* Reason code. */
  type = SSH_X509_CRL_ENTRY_EXT_REASON_CODE;
  if (ssh_x509_revoked_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_crl_reason_code(context, e->reason_code);
      if (node)
        {
          if ((tmp =
               ssh_x509_encode_extension(context, node,
                                         "crlReason",
                                         critical, SSH_OID_CRL_ENTRY_EXT))
              != NULL)
            rl_ext_list = ssh_asn1_add_list(rl_ext_list, tmp);
        }
      else
        return rv;
    }
  /* Hold instruction code. */
  type = SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE;
  if (ssh_x509_revoked_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_hold_inst_code(context, e->hold_inst_code);
      if (node)
        {
          if ((tmp =
               ssh_x509_encode_extension(context, node,
                                         "holdInstructionCode",
                                         critical, SSH_OID_CRL_ENTRY_EXT))
              != NULL)
            rl_ext_list = ssh_asn1_add_list(rl_ext_list, tmp);
        }
      else
        return rv;
    }
  /* Invalidity date. */
  type = SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE;
  if (ssh_x509_revoked_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_invalidity_date(context, &e->invalidity_date);
      if (node)
        {
          if ((tmp =
               ssh_x509_encode_extension(context, node,
                                         "invalidityDate",
                                         critical, SSH_OID_CRL_ENTRY_EXT))
              != NULL)
            rl_ext_list = ssh_asn1_add_list(rl_ext_list, tmp);
        }
      else
        return rv;
    }
  /* Certificate issuer */
  type = SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER;
  if (ssh_x509_revoked_ext_available(c, type, &critical))
    {
      node = ssh_x509_encode_general_names(context,
                                           e->certificate_issuer,
                                           config);
      if (node)
        {
          if ((tmp =
               ssh_x509_encode_extension(context, node,
                                         "certificateIssuer",
                                         critical, SSH_OID_CRL_ENTRY_EXT))
              != NULL)
            rl_ext_list = ssh_asn1_add_list(rl_ext_list, tmp);
        }
      else
        return rv;
    }

  /* Finishing the extension list. */
  if (rl_ext_list)
    {
      SshAsn1Status status;
      status =
        ssh_asn1_create_node(context, &rl_ext,
                             "(sequence ()"
                             "(any ()))", rl_ext_list);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;
    }
  else
    rl_ext = NULL;

  *ret = rl_ext;

  return SSH_X509_OK;
}
#endif /* SSHDIST_CERT */
