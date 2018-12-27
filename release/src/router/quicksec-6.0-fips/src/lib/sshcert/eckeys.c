/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decode and encode routines for Elliptic curve keys.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"
#include "sshmp.h"
#include "ecpfix.h"
#include "eckeys.h"

#ifdef SSHDIST_CRYPT_ECP
#define SSH_DEBUG_MODULE "SshCertECPKeys"


SshX509Status ssh_x509_decode_ecp_curve(SshAsn1Context context,
                                        SshAsn1Node param,
                                        SshECPCurve E,
                                        SshECPPoint P,
                                        SshMPInteger n,
                                        const char **curve_name,
                                        size_t *field_len)
{
  unsigned int which;
  SshAsn1Node field_id, curve, field_param;
  unsigned char *curve_oid, *field_oid;
  unsigned char *base;
  unsigned char *curve_a = NULL, *curve_b = NULL;
  unsigned char *seed = NULL;
  size_t base_len;
  size_t curve_a_len, curve_b_len;
  Boolean seed_found;
  size_t seed_len, mod_len;
  SshAsn1Status status;
  SshMPIntegerStruct version, cofactor, order;
  SshMPIntegerStruct a,b,c,p;
  Boolean cofactor_found = FALSE;
  const SshOidStruct *oid;
  SshX509Status rv;
  const char *out_name = NULL;
  Boolean pc;

  *curve_name = NULL;
  *field_len = 0;

  if ((context == NULL) || (param == NULL))
    return SSH_X509_FAILED_ASN1_DECODE;

/* Initialize all multi precesion numbers */
  ssh_mprz_init(&version);
  ssh_mprz_init(&order);
  ssh_mprz_init(&cofactor);

  rv = SSH_X509_FAILED_ASN1_DECODE;

  status =
    ssh_asn1_read_node(context, param,
                       "(choice "
                       "  (sequence ()"
                       "     (integer ())"     /* ECP version should be 1*/
                       "     (any ())"         /* finite field */
                       "     (any ())"         /* Coefficient a and b */
                       "     (octet-string ())"/* Base point p on curve */
                       "     (integer ())"     /* Order n */
                       "     (optional"
                       "         (integer())))"/* cofactor */
                       "  (object-identifier ())" /* named curve identifier */
                       "  (null ()))",         /* Implicit CA */
                       &which, &version,
                       &field_id, &curve,
                       &base, &base_len,
                       &order,
                       &cofactor_found, &cofactor,
                       &curve_oid);
  if (status != SSH_ASN1_STATUS_OK || which == 2)
    {
      /* Implicit CA is not supported currently */
      SSH_DEBUG(SSH_D_FAIL, ("EC params read failed"));
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto fail;
    }
  if (which == 0)
    {
      ssh_mprz_init(&a);
      ssh_mprz_init(&b);
      ssh_mprz_init(&p);
      ssh_mprz_init(&c);
      /* Read the curve field first */
      status = ssh_asn1_read_node(context, field_id,
                                  "(sequence ()"
                                  "  (object-identifier())"
                                  "  (any ()))",
                                  &field_oid, &field_param);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail_2;

      oid = ssh_oid_find_by_oid_of_type(field_oid, SSH_OID_CURVE_FIELD);
      ssh_free(field_oid);

      if (oid == NULL)
        {
          /* Characteristic two field curves are not supported */
          rv = SSH_X509_FAILED_UNKNOWN_VALUE;
          goto fail_2;
        }
      /* Now we know that the curve is a prime field curve */
      status = ssh_asn1_read_node (context, field_param,
                                   "( integer ())", &p);
      if (status != SSH_ASN1_STATUS_OK ||
             (ssh_mprz_cmp_ui(&p, 0) == 0))
        goto fail_2;

      mod_len = ssh_mprz_byte_size(&p);
      status = ssh_asn1_read_node(context, curve,
                                  "(sequence ()"
                                  "   (octet-string())"
                                  "   (octet-string())"
                                  "   (optional"
                                  "      (bit-string ())))",
                                  &curve_a, &curve_a_len,
                                  &curve_b, &curve_b_len,
                                  &seed_found, &seed, &seed_len);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail_2;

      ssh_mprz_set_buf(&a, curve_a, curve_a_len);
      ssh_mprz_set_buf(&b, curve_b, curve_b_len);
      /* We do not know the cardinality of the curve. Computing
      would take a lot of time and hopefullly would not be needed. */
      ssh_mprz_set_ui(&c, 1);
      if (!ssh_ecp_set_curve(E, &p, &a, &b, &c))
        {
          ssh_ecp_clear_curve(E);
          goto fail_2;
        }
      ssh_ecp_init_point(P, E);
      if (!ssh_ecp_set_point_from_octet_str(P, E, mod_len, base,
                                        base_len * 8, &pc))
        {
          ssh_ecp_clear_curve(E);
          ssh_ecp_clear_point(P);
          rv = SSH_X509_FAILED_UNKNOWN_VALUE;
          goto fail_2;
        }
      ssh_mprz_init(n);
      ssh_mprz_set(n, &order);
      *curve_name = NULL;
      *field_len = mod_len;
      rv = SSH_X509_OK;
fail_2:
      ssh_free(curve_a);
      ssh_free(curve_b);
      ssh_mprz_clear(&a);
      ssh_mprz_clear(&b);
      ssh_mprz_clear(&c);
      ssh_mprz_clear(&p);
    }
  else
    {
      /* Figure out the curve */
      oid = ssh_oid_find_by_oid_of_type(curve_oid, SSH_OID_ECP_CURVE);
      ssh_free(curve_oid);

      if (oid == NULL)
        {
          rv = SSH_X509_FAILED_UNKNOWN_VALUE;
          goto fail;
        }
      if (!ssh_ecp_set_param(oid->std_name, &out_name, E, P, n, &pc))
        {
          rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
          goto fail;
        }
      *curve_name = out_name;
      *field_len = (size_t)oid->extra_int;
      rv = SSH_X509_OK;
    }
fail:
  ssh_mprz_clear(&version);
  ssh_mprz_clear(&order);
  ssh_mprz_clear(&cofactor);
  return rv;
}


Boolean ssh_x509_encode_ecp_private_key_internal(SshPrivateKey key,
                                                 SshUInt32 encode_flags,
                                                 unsigned char **buf,
                                                 size_t *buf_len)
{
  SshAsn1Context context = NULL;
  SshAsn1Node param_node = NULL;
  SshAsn1Tree tree = NULL;
  SshAsn1Status val;
  SshMPIntegerStruct x, version;
  unsigned char *prv_key = NULL;
  size_t prv_key_len;
  unsigned char *public_key_buf = NULL;
  size_t public_key_len = 0;
  unsigned char *key_param = NULL;
  size_t key_param_len;
  Boolean rv;
  SshCryptoStatus status;
  SshPublicKey public_key;

  ssh_mprz_init(&x);
  ssh_mprz_init(&version);
  ssh_mprz_set_ui(&version, 1);

  rv = FALSE;
  if (ssh_private_key_get_info(key,
                               SSH_PKF_SECRET_X, &x,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;

  prv_key_len = ssh_mprz_byte_size(&x);
  prv_key = ssh_malloc(prv_key_len *sizeof (unsigned char));
  if (prv_key == NULL)
    goto fail;

  if ((context = ssh_asn1_init()) == NULL)
    goto fail;

  if (ssh_mprz_get_buf(prv_key, prv_key_len, &x) == 0)
    goto fail;

  if (encode_flags & SSH_X509_ECP_ENCODE_PARAMS)
    {
      if (!ssh_x509_encode_ecp_key_params(key, FALSE,
                                          &key_param, &key_param_len))
        goto fail;

      if (ssh_asn1_decode_node(context, key_param,
                               key_param_len, &param_node)
                            != SSH_ASN1_STATUS_OK)
        goto fail;

    }
  if (encode_flags & SSH_X509_ECP_ENCODE_PUBLIC_KEY)
    {
      status = ssh_private_key_derive_public_key(key, &public_key);
      SSH_ASSERT(status == SSH_CRYPTO_OK);

      rv = ssh_x509_encode_ecp_public_key_internal(public_key,
                                                   &public_key_buf,
                                                   &public_key_len);
      ssh_public_key_free(public_key);
      if (!rv)
        goto fail;
    }


  rv = FALSE;

  if ((encode_flags & SSH_X509_ECP_ENCODE_ALL) ==
                                 SSH_X509_ECP_ENCODE_ALL)
    {
      val = ssh_asn1_create_tree(context, &tree,
                                 " (sequence ()"
                                 "   (integer ())"
                                 "   (octet-string ())"
                                 "   ( any (e 0))"
                                 "   ( bit-string (e 1)))",
                                 &version,
                                 prv_key, prv_key_len,
                                 param_node,
                                 public_key_buf, public_key_len * 8);
    }
  else if ((encode_flags & SSH_X509_ECP_ENCODE_PARAMS) ==
                                 SSH_X509_ECP_ENCODE_PARAMS)
    {
      val = ssh_asn1_create_tree(context, &tree,
                                 " (sequence ()"
                                 "   (integer ())"
                                 "   (octet-string ())"
                                 "   ( any (e 0)))",
                                 &version,
                                 prv_key, prv_key_len,
                                 param_node);
    }
  else if ((encode_flags & SSH_X509_ECP_ENCODE_PUBLIC_KEY) ==
                                 SSH_X509_ECP_ENCODE_PUBLIC_KEY)
    {
      val = ssh_asn1_create_tree(context, &tree,
                                 " (sequence ()"
                                 "   (integer ())"
                                 "   (octet-string ())"
                                 "   (bit-string (e 1)))",
                                 &version,
                                 prv_key, prv_key_len,
                                 public_key_buf, public_key_len * 8);
    }
  else
    {
      val = ssh_asn1_create_tree(context, &tree,
                                 " (sequence ()"
                                 "   (integer ())"
                                 "   (octet-string ()))",
                                 &version,
                                 prv_key, prv_key_len);
    }
  if (val != SSH_ASN1_STATUS_OK)
    goto fail;

  val = ssh_asn1_encode(context, tree);
  if (val != SSH_ASN1_STATUS_OK)
    goto fail;

  ssh_asn1_get_data(tree, buf, buf_len);
  if (*buf_len == 0)
    goto fail;
  rv = TRUE;
fail:
  if (public_key_buf)
    ssh_free(public_key_buf);
  if (prv_key)
    ssh_free(prv_key);
  if (context)
    ssh_asn1_free(context);
  if (key_param)
    ssh_free(key_param);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&version);
  return rv;
}

Boolean ssh_x509_encode_ecp_key_params(void *key,
                                       Boolean is_public,
                                       unsigned char **params,
                                       size_t *param_len)
{
  SshAsn1Context context;
  SshAsn1Node node;
  const SshOidStruct *oid;
  SshAsn1Status status;
  SshMPIntegerStruct a, b, gx, gy, p, q, version;
  char *curve_name = NULL;
  unsigned char * curve_a = NULL, *curve_b = NULL;
  unsigned char * base_point = NULL;
  size_t curve_a_len, curve_b_len, point_len, field_len;
  Boolean rv = FALSE;
  Boolean pc;
  SshAsn1Node curve, field_id;
  *params = NULL;
  *param_len = 0;

  if (is_public)
    {
      if (ssh_public_key_get_info((SshPublicKey)key,
                                  SSH_PKF_PREDEFINED_GROUP, &curve_name,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        return FALSE;

      if (curve_name == NULL)
        {
          ssh_mprz_init(&p);
          ssh_mprz_init(&q);
          ssh_mprz_init(&gx);
          ssh_mprz_init(&gy);
          ssh_mprz_init(&a);
          ssh_mprz_init(&b);

          if (ssh_public_key_get_info((SshPublicKey)key,
                                      SSH_PKF_PRIME_P, &p,
                                      SSH_PKF_GENERATOR_G, &gx, &gy,
                                      SSH_PKF_PRIME_Q, &q,
                                      SSH_PKF_CURVE_A, &a,
                                      SSH_PKF_CURVE_B, &b,
                                      SSH_PKF_POINT_COMPRESS, &pc,
                                      SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              ssh_mprz_clear(&p);
              ssh_mprz_clear(&q);
              ssh_mprz_clear(&gx);
              ssh_mprz_clear(&gy);
              ssh_mprz_clear(&a);
              ssh_mprz_clear(&b);
              return FALSE;
            }
        }
    }
  else
    {
      if (ssh_private_key_get_info((SshPrivateKey)key,
                                   SSH_PKF_PREDEFINED_GROUP, &curve_name,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        return FALSE;

      if (curve_name == NULL)
        {
          ssh_mprz_init(&p);
          ssh_mprz_init(&q);
          ssh_mprz_init(&gx);
          ssh_mprz_init(&gy);
          ssh_mprz_init(&a);
          ssh_mprz_init(&b);

          if (ssh_private_key_get_info((SshPrivateKey)key,
                                       SSH_PKF_PRIME_P, &p,
                                       SSH_PKF_GENERATOR_G, &gx, &gy,
                                       SSH_PKF_PRIME_Q, &q,
                                       SSH_PKF_CURVE_A, &a,
                                       SSH_PKF_CURVE_B, &b,
                                       SSH_PKF_POINT_COMPRESS, &pc,
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
            {
              ssh_mprz_clear(&p);
              ssh_mprz_clear(&q);
              ssh_mprz_clear(&gx);
              ssh_mprz_clear(&gy);
              ssh_mprz_clear(&a);
              ssh_mprz_clear(&b);
              return FALSE;
            }
        }
    }

  if ((context = ssh_asn1_init()) == NULL)
    goto fail;

  if (curve_name)
    {
      oid = ssh_oid_find_by_std_name_of_type(curve_name, SSH_OID_ECP_CURVE);
      if (oid == NULL)
        goto fail;

      status = ssh_asn1_create_node(context, &node,
                                    " (object-identifier ())",
                                    oid->oid);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail;
    }
  else
    {
      ssh_mprz_init(&version);
      ssh_mprz_set_ui(&version, 1);

      curve_a_len = ssh_mprz_byte_size(&a);
      curve_b_len = ssh_mprz_byte_size(&b);

      curve_a = ssh_malloc(curve_a_len * sizeof (unsigned char));
      curve_b = ssh_malloc(curve_b_len * sizeof (unsigned char));


      if (!curve_a || !curve_b)
        goto fail;

      if ((ssh_mprz_get_buf(curve_a, curve_a_len, &a) == 0) ||
             (ssh_mprz_get_buf(curve_b, curve_b_len, &b) == 0))
        goto fail;

      field_len = ssh_mprz_byte_size(&p);
      point_len = (pc == TRUE) ? field_len + 1:
                                2 * field_len + 1;

      base_point = ssh_calloc(1, point_len * sizeof (unsigned char));
      if (base_point == NULL)
        goto fail;

      if (ssh_mprz_get_buf(base_point + 1, field_len, &gx) == 0)
        goto fail;

      if (pc)
        {
          base_point[0] = SSH_ECP_CURVE_POINT_COMPRESSED;
          base_point[0] |= ssh_mprz_get_ui32(&gy) & 0x1;
        }
      else
        {
          base_point[0] = SSH_ECP_CURVE_POINT_UNCOMPRESSED;
          if (ssh_mprz_get_buf(base_point + 1 + field_len,
                           field_len, &gy) == 0)
            goto fail;
        }
      status = ssh_asn1_create_node(context, &curve,
                                    " (sequence ()"
                                    "   (octet-string())"
                                    "   (octet-string()))",
                                    curve_a, curve_a_len,
                                    curve_b, curve_b_len);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail;

      /* For now we know that we support curves defined over prime field
         only. This following code must change once we support ch two field
         curves as well */
      oid = ssh_oid_find_by_std_name_of_type("x9.62primefield",
                                             SSH_OID_CURVE_FIELD);
      SSH_ASSERT(oid != NULL);

      status = ssh_asn1_create_node(context, &field_id,
                                    " (sequence ()"
                                    "   (object-indentifier ())"
                                    "   (integer ()))",
                                    oid->oid, &p);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail;

      status = ssh_asn1_create_node(context, &node,
                                    " (sequence ()"
                                    "   ( integer ())"
                                    "   ( any ())"
                                    "   ( any ())"
                                    "   ( octet-string ())"
                                    "   ( integer ()))",
                                    &version, field_id,
                                    curve, base_point, point_len,
                                    &q);
      if (status != SSH_ASN1_STATUS_OK)
        goto fail;
    }

  if (ssh_asn1_encode_node(context, node) != SSH_ASN1_STATUS_OK)
    goto fail;

  status = ssh_asn1_node_get_data(node, params, param_len);
  if (status != SSH_ASN1_STATUS_OK)
    goto fail;
  rv = TRUE;
fail:
  if (curve_name == NULL)
    {
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&gx);
      ssh_mprz_clear(&gy);
      ssh_mprz_clear(&a);
      ssh_mprz_clear(&b);
      ssh_mprz_clear(&version);
      ssh_free(curve_a);
      ssh_free(curve_b);
      ssh_free(base_point);
    }
  ssh_asn1_free(context);
  return rv;
}

Boolean ssh_x509_encode_ecp_public_key_internal(SshPublicKey key,
                                                unsigned char **buf,
                                                size_t *buf_len)
{
  SshMPIntegerStruct y_x, y_y, p;
  unsigned char *public_key;
  size_t public_key_len, field_len;
  Boolean pc;
  Boolean rv;

  rv = FALSE;
  *buf = NULL;
  *buf_len = 0;

  ssh_mprz_init(&y_x);
  ssh_mprz_init(&y_y);
  ssh_mprz_init(&p);

  if (ssh_public_key_get_info(key,
                              SSH_PKF_PRIME_P, &p,
                              SSH_PKF_PUBLIC_Y, &y_x, &y_y,
                              SSH_PKF_POINT_COMPRESS, &pc,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;

  field_len = ssh_mprz_byte_size(&p);
  public_key_len = (pc == TRUE)? field_len + 1: 2 * field_len + 1;
  public_key = ssh_calloc(1, public_key_len);
  if (public_key == NULL)
    goto fail;

  if (ssh_mprz_get_buf(public_key + 1, field_len, &y_x) == 0)
    {
      ssh_free(public_key);
      goto fail;
    }

  if (pc)
    {
      public_key[0] = SSH_ECP_CURVE_POINT_COMPRESSED;
      public_key[0] |= ssh_mprz_get_ui32(&y_y) & 0x1;
    }
  else
    {
      public_key[0] = SSH_ECP_CURVE_POINT_UNCOMPRESSED;
      if (ssh_mprz_get_buf(public_key + 1 + field_len,
                           field_len, &y_y) == 0)
        {
          ssh_free(public_key);
          goto fail;
        }
    }
  *buf = public_key;
  *buf_len = public_key_len;
  rv = TRUE;
fail:
  ssh_mprz_clear(&y_x);
  ssh_mprz_clear(&y_y);
  ssh_mprz_clear(&p);
  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */
