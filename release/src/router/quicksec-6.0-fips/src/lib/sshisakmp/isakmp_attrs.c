/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp attribute handling functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "isakmp_util.h"

#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeAttrs"


/*                                                              shade{0.9}
 * ssh_ike_clear_isakmp_attrs
 * Reset SshIkeAttributes to default values.                    shade{1.0}
 */

void ssh_ike_clear_isakmp_attrs(SshIkeAttributes attrs)
{
  attrs->encryption_algorithm = 0;
  attrs->hash_algorithm = 0;
  attrs->auth_method = 0;
  attrs->group_desc = NULL;
  attrs->group_parameters = FALSE;
  attrs->prf_algorithm = 0;
  attrs->life_duration_kb = 0;
  attrs->life_duration_secs = 0;
  attrs->key_length = 0;
}

/*                                                              shade{0.9}
 * ssh_ike_clear_ipsec_attrs
 * Reset SshIkeIpsecAttributes to default values.               shade{1.0}
 */

void ssh_ike_clear_ipsec_attrs(SshIkeIpsecAttributes attrs)
{
  attrs->life_duration_kb = 0;
  attrs->life_duration_secs = 0;
  attrs->group_desc = 0;
  attrs->encapsulation_mode = 0;
  attrs->auth_algorithm = 0;
  attrs->key_length = 0;
  attrs->key_rounds = 0;
  attrs->longseq_size = 0;
}


/*                                                              shade{0.9}
 * ike_clear_grp_attrs
 * Reset SshIkeGrpAttributes to default values.                 shade{1.0}
 */

void ssh_ike_clear_grp_attrs(SshIkeGrpAttributes attrs)
{
  attrs->group_descriptor = 0;
  attrs->group_type = 0;
  attrs->p = NULL;
  attrs->g1 = NULL;
  attrs->g2 = NULL;
  attrs->ca = NULL;
  attrs->cb = NULL;
  attrs->order = NULL;
  attrs->cardinality = NULL;
}


/*                                                              shade{0.9}
 * ike_free_grp_attrs
 * Free SshIkeGrpAttributes structure.                          shade{1.0}
 */

void ssh_ike_free_grp_attrs(SshIkeGrpAttributes attrs)
{
  if (attrs->p != NULL)
    {
      ssh_mprz_clear(attrs->p);
      ssh_free(attrs->p);
      attrs->p = NULL;
    }
  if (attrs->g1 != NULL)
    {
      ssh_mprz_clear(attrs->g1);
      ssh_free(attrs->g1);
      attrs->g1 = NULL;
    }
  if (attrs->g2 != NULL)
    {
      ssh_mprz_clear(attrs->g2);
      ssh_free(attrs->g2);
      attrs->g2 = NULL;
    }
  if (attrs->ca != NULL)
    {
      ssh_mprz_clear(attrs->ca);
      ssh_free(attrs->ca);
      attrs->ca = NULL;
    }
  if (attrs->cb != NULL)
    {
      ssh_mprz_clear(attrs->cb);
      ssh_free(attrs->cb);
      attrs->cb = NULL;
    }
  if (attrs->order != NULL)
    {
      ssh_mprz_clear(attrs->order);
      ssh_free(attrs->order);
      attrs->order = NULL;
    }
  if (attrs->cardinality != NULL)
    {
      ssh_mprz_clear(attrs->cardinality);
      ssh_free(attrs->cardinality);
      attrs->cardinality = NULL;
    }
}


/*                                                              shade{0.9}
 * ike_read_grp_attrs
 * Read GrpAttributes from data attributes
 * of the transform payload and fill
 * attrs structure. Return FALSE if error
 * (== unsupported values in the data attributes).              shade{1.0}
 */
Boolean ssh_ike_read_grp_attrs(SshIkeNegotiation negotiation,
                               SshIkePayloadT trans,
                               SshIkeGrpAttributes attrs)
{
  SshIkeDataAttribute attr;
  SshMPInteger *value = NULL;
  SshUInt32 value32;
  int i;
  Boolean is_mp_int;
  Boolean value_given;
  SshUInt32 flags;

  value_given = FALSE;
  flags = 0;

  /* Read data from attributes, and fill them to attrs struct. This doesn't
     clear the attrs struct */
  for (i = 0; i < trans->number_of_sa_attributes; i++)
    {
      attr = &(trans->sa_attributes[i]);
      is_mp_int = FALSE;
      switch (attr->attribute_type)
        {
        case SSH_IKE_CLASSES_ENCR_ALG: /* Encryption algorithms (B) */
        case SSH_IKE_CLASSES_HASH_ALG: /* Hash algorithms (B) */
        case SSH_IKE_CLASSES_AUTH_METH: /* Authentication method (B) */
          is_mp_int = FALSE;
          break;
        case SSH_IKE_CLASSES_GRP_DESC: /* Group description (B) */
          is_mp_int = FALSE;
          if (!ssh_ike_get_data_attribute_int(attr, &value32, flags))
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Group descriptor not representable in 32 bits"));
              return FALSE;
            }
          attrs->group_descriptor = value32;
          break;
        case SSH_IKE_CLASSES_GRP_TYPE: /* Group type (B) */
          if (!ssh_ike_get_data_attribute_int(attr, &value32, flags))
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Group type not representable in 32 bits"));
              return FALSE;
            }
          attrs->group_type = value32;
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_PRIME: /* Group prime (V) */
          is_mp_int = TRUE;
          value = &(attrs->p);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_GEN1: /* Group generator one (V) */
          is_mp_int = TRUE;
          value = &(attrs->g1);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_GEN2: /* Group generator two (V) */
          is_mp_int = TRUE;
          value = &(attrs->g2);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_CURVEA: /* Group curve A (V) */
          is_mp_int = TRUE;
          value = &(attrs->ca);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_CURVEB: /* Group curve B (V) */
          is_mp_int = TRUE;
          value = &(attrs->cb);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_ORDER: /* Group order (V) */
          is_mp_int = TRUE;
          value = &(attrs->order);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_GRP_CARDINALITY: /* Group cardinality (V) */
          is_mp_int = TRUE;
          value = &(attrs->cardinality);
          value_given = TRUE;
          break;
        case SSH_IKE_CLASSES_LIFE_TYPE: /* Life type (B) */
        case SSH_IKE_CLASSES_LIFE_DURATION: /* Life duration (B/V) */
        case SSH_IKE_CLASSES_PRF: /* PRF (B) */
        case SSH_IKE_CLASSES_KEY_LEN: /* Key length (B) */
          is_mp_int = FALSE;
          break;
        default:
          SSH_IKE_DEBUG(3, negotiation, ("Invalid DA attribute: %04x",
                                         attr->attribute_type));
          return FALSE;
        }
      if (is_mp_int)
        {
          if (*value != NULL)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Same mp_int value given twice, attr = %04x",
                             attr->attribute_type));
              return FALSE;
            }
          *value = ssh_malloc(sizeof(**value));
          if (*value == NULL)
            return FALSE;
          ssh_mprz_init(*value);
          ssh_mprz_set_buf(*value, attr->attribute, attr->attribute_length);
        }
    }

  if (!value_given)
    return TRUE;
  if ((int) attrs->group_descriptor < 16386 && attrs->group_descriptor != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No valid group descriptor given %d",
                                     attrs->group_descriptor));
    }

  switch (attrs->group_type)
    {
    case SSH_IKE_VALUES_GRP_TYPE_MODP:
      if (!(attrs->p != NULL ||
            attrs->g1 != NULL ||
            attrs->g2 == NULL ||
            attrs->ca == NULL ||
            attrs->cb == NULL))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Required parameter for group missing"));
          return FALSE;
        }
      break;
    case SSH_IKE_VALUES_GRP_TYPE_ECP:
      if (!(attrs->p != NULL ||
            attrs->g1 != NULL ||
            attrs->g2 == NULL ||
            attrs->ca == NULL ||
            attrs->cb == NULL ||
            attrs->order == NULL))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Required parameter for group missing"));
          return FALSE;
        }
      break;
    case SSH_IKE_VALUES_GRP_TYPE_EC2N:
      if (!(attrs->p != NULL ||
            attrs->g1 != NULL ||
            attrs->g2 == NULL ||
            attrs->ca == NULL ||
            attrs->cb == NULL ||
            attrs->order == NULL))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Required parameter for group missing"));
          return FALSE;
        }
      break;
    }
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_read_isakmp_attrs
 * Read SshIkeAttributes from data attributes
 * of the transform payload and fill
 * attrs structure. Return FALSE if error
 * (== unsupported values in the data attributes).              shade{1.0}
 */
Boolean ssh_ike_read_isakmp_attrs(SshIkeNegotiation negotiation,
                                  SshIkePayloadT trans,
                                  SshIkeAttributes attrs)
{
  Boolean life_duration_secs_set, life_duration_kb_set;
  SshIkeAttributeLifeTypeValues life_type = 0;
  SshIkeDataAttribute attr;
  SshUInt32 value;
  int i;
  Boolean value_ok;
  SshUInt32 flags;
  const char *name;

  flags = 0;
  life_duration_secs_set = FALSE;
  life_duration_kb_set = FALSE;

  /* Read data from attributes, and fill them to attrs struct. This doesn't
     clear the attrs struct */
  for (i = 0; i < trans->number_of_sa_attributes; i++)
    {
      attr = &(trans->sa_attributes[i]);
      switch (attr->attribute_type)
        {
        case SSH_IKE_CLASSES_GRP_TYPE:
        case SSH_IKE_CLASSES_GRP_PRIME: /* Group prime (V) */
        case SSH_IKE_CLASSES_GRP_GEN1: /* Group generator one (V) */
        case SSH_IKE_CLASSES_GRP_GEN2: /* Group generator two (V) */
        case SSH_IKE_CLASSES_GRP_CURVEA: /* Group curve A (V) */
        case SSH_IKE_CLASSES_GRP_CURVEB: /* Group curve B (V) */
        case SSH_IKE_CLASSES_GRP_ORDER: /* Group order (V) */
        case SSH_IKE_CLASSES_GRP_CARDINALITY: /* Group cardinality (V) */
          /* Skip the group paramaters, as they are checked in
             isakmp_read_grp_attrs */
          attrs->group_parameters = TRUE;
          continue;
        }
      /* Check if the value can be represented as one 32 bit number */
      if (ssh_ike_get_data_attribute_int(attr, &value, flags))
        {
          /* Yes (most of the normal values should be representable in
             32 bits) */
          switch (attr->attribute_type)
            {
            case SSH_IKE_CLASSES_ENCR_ALG: /* Encryption algorithm */
              if (attrs->encryption_algorithm != 0 &&
                  attrs->encryption_algorithm != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Encryption alg given twice, "
                                 "old = %d, new = %d",
                                 attrs->encryption_algorithm,
                                 (int) value));
                  return FALSE;
                }
              attrs->encryption_algorithm = value;
              value_ok = TRUE;
              /* Map the number to name */
              name = ssh_find_keyword_name(ssh_ike_encryption_algorithms,
                                           value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation, ("Encryption alg = %d (%s)",
                                              attrs->encryption_algorithm,
                                              isakmp_name_or_unknown(name)));
              /* Check if that algorithm is supported */
              if (!value_ok || !ssh_cipher_supported(name))
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported encryption algorithm : %d (%s)",
                                 attrs->encryption_algorithm,
                                 isakmp_name_or_unknown(name)));
                  return FALSE;
                }
              break;
            case SSH_IKE_CLASSES_HASH_ALG: /* Hash algorithm */
              if (attrs->hash_algorithm != 0 &&
                  attrs->hash_algorithm != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Hash alg given twice, old = %d, new = %d",
                                 attrs->hash_algorithm,
                                 (int) value));
                  return FALSE;
                }
              attrs->hash_algorithm = value;
              value_ok = TRUE;
              /* Map the number to name */
              name = ssh_find_keyword_name(ssh_ike_hash_algorithms, value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation, ("Hash alg = %d (%s)",
                                              attrs->hash_algorithm,
                                              isakmp_name_or_unknown(name)));
              /* Check if that algorithm is supported */
              if (!value_ok || !ssh_hash_supported(name))
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported hash algorithm : %d (%s)",
                                 attrs->hash_algorithm,
                                 isakmp_name_or_unknown(name)));
                  return FALSE;
                }
              break;
            case SSH_IKE_CLASSES_AUTH_METH: /* Authentication method */
              if (attrs->auth_method != 0 &&
                  attrs->auth_method != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Auth method given twice, old = %d, new = %d",
                                 attrs->auth_method,
                                 (int) value));
                  return FALSE;
                }
              attrs->auth_method = value;
              /* Check if value is ok */
              switch (attrs->auth_method)
                {
                case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
                case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
#ifdef SSHDIST_IKE_XAUTH
                case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
#endif /* SSHDIST_IKE_XAUTH */
#ifdef SSHDIST_CRYPT_ECP
                case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
                case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
                case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
#endif /* SSHDIST_CRYPT_ECP */
                  value_ok = TRUE;
                  break;
                case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
                case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */

#ifdef REMOVED_BY_DOI_DRAFT_07
                case SSH_IKE_VALUES_AUTH_METH_GSSAPI:
#endif
                  value_ok = FALSE;
                  break;
                }
              SSH_IKE_DEBUG(10, negotiation, ("Auth method = %d",
                                              (int) value));
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported auth method : %d", (int) value));
                  return FALSE;
                }
              break;
            case SSH_IKE_CLASSES_GRP_DESC: /* Group descriptor number */
              if (attrs->group_desc != NULL &&
                  attrs->group_desc->descriptor != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Group descr given twice, old = %d, new = %d",
                                 attrs->group_desc->descriptor,
                                 (int) value));
                  return FALSE;
                }

              /* Find matching group */
              attrs->group_desc = ike_find_group(negotiation->sa, value);
              if (attrs->group_desc == NULL)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported group : %d", (int) value));
                  return FALSE;
                }
              else
                {
                  SSH_IKE_DEBUG(10, negotiation,
                                ("Group = %d, %p",
                                 attrs->group_desc->descriptor,
                                 attrs->group_desc));
                }
              break;
            case SSH_IKE_CLASSES_LIFE_TYPE: /* Life type selector */
              life_type = value;
              value_ok = FALSE;
              /* Check if the value is ok */
              switch (value)
                {
                case SSH_IKE_VALUES_LIFE_TYPE_SECONDS:
                case SSH_IKE_VALUES_LIFE_TYPE_KILOBYTES:
                  value_ok = TRUE;
                  break;
                }
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported life type : %d", (int) value));
                  return FALSE;
                }
              break;
            case SSH_IKE_CLASSES_LIFE_DURATION: /* Life type value */
              /* Check that life type have been already selected */
              if (life_type == 0)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("No life type given before life duration"));
                  return FALSE;
                }
              /* Store the value */
              switch (life_type)
                {
                case SSH_IKE_VALUES_LIFE_TYPE_SECONDS:
                  if (life_duration_secs_set &&
                      attrs->life_duration_secs != value)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Life duration seconds set twice with "
                                     "different values %d vs %d secs",
                                     (int) attrs->life_duration_secs,
                                     (int) value));
                      return FALSE;
                    }
                  else
                    {
                      attrs->life_duration_secs = value;
                      life_duration_secs_set = TRUE;
                      SSH_IKE_DEBUG(10, negotiation,
                                    ("Life duration %d secs", (int) value));
                    }
                  break;
                case SSH_IKE_VALUES_LIFE_TYPE_KILOBYTES:
                  if (life_duration_kb_set &&
                      attrs->life_duration_kb != value)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Life duration kb set twice with "
                                     "different values %d vs %d kb",
                                     (int) attrs->life_duration_kb,
                                     (int) value));
                      return FALSE;
                    }
                  else
                    {
                      attrs->life_duration_kb = value;
                      life_duration_kb_set = TRUE;
                      SSH_IKE_DEBUG(10, negotiation,
                                    ("Life duration %d kb", (int) value));
                    }
                  break;
                }
              break;
            case SSH_IKE_CLASSES_PRF: /* PRF function */
              if (attrs->prf_algorithm != 0 &&
                  attrs->prf_algorithm != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("PRF algorithm given twice, "
                                 "old = %d, new = %d",
                                 attrs->prf_algorithm,
                                 (int) value));
                  return FALSE;
                }
              attrs->prf_algorithm = value;
              value_ok = TRUE;
              /* Map number to string */
              name = ssh_find_keyword_name(ssh_ike_prf_algorithms, value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation, ("PRF alg = %d (%s)",
                                              attrs->prf_algorithm,
                                              isakmp_name_or_unknown(name)));
              /* Check if algorithm is supported */
              if (!value_ok || !ssh_mac_supported(name))
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported PRF algorithm : %d",
                                 (int) value));
                  return FALSE;
                }
              break;
            case SSH_IKE_CLASSES_KEY_LEN: /* Key length */
              if (attrs->key_length != 0 &&
                  attrs->key_length != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Key length given twice, old = %d, new = %d",
                                 (int) attrs->key_length,
                                 (int) value));
                  return FALSE;
                }
              attrs->key_length = value;
              SSH_IKE_DEBUG(10, negotiation, ("Key length = %d", (int) value));
              break;
            default:
              SSH_IKE_DEBUG(7, negotiation,
                            ("Unknown %sattribute = %d, value = %d",
                             attr->attribute_type > 16383 ? "private ": "",
                             attr->attribute_type, (int) value));
              if (attr->attribute_type > 16383)
                break;
              else
                return FALSE;
            }
        }
      else
        {
          /* Argument not representable in 32 bits, currently here none
             supported */
          SSH_IKE_DEBUG(7, negotiation,
                        ("Unknown %sattribute = %d, value = %d",
                         attr->attribute_type > 16383 ? "private ": "",
                         attr->attribute_type, (int) value));
          if (attr->attribute_type > 16383)
            break;
          else
            return FALSE;
        }
    }
  if (attrs->prf_algorithm == 0)
    {
      name = ssh_find_keyword_name(ssh_ike_hmac_prf_algorithms,
                                   attrs->hash_algorithm);
      if (name == NULL || !ssh_mac_supported(name))
        {
          SSH_IKE_DEBUG(8, negotiation, ("Unsupported prf algorithm : %d (%s)",
                                         attrs->prf_algorithm,
                                         isakmp_name_or_unknown(name)));
          return FALSE;
        }
    }
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_read_ipsec_attrs
 * Read SshIkeIpsecAttributes from data attributes
 * of the transform payload and fill
 * attrs structure. Return FALSE if error
 * (== unsupported values in the data attributes).              shade{1.0}
 */
Boolean ssh_ike_read_ipsec_attrs(SshIkeNegotiation negotiation,
                                 SshIkePayloadT trans,
                                 SshIkeIpsecAttributes attrs)
{
  Boolean life_duration_secs_set, life_duration_kb_set;
  SshIkeIpsecAttributeLifeTypeValues life_type = 0;
  SshIkeDataAttribute attr;
  SshUInt32 value;
  const char *name;
  int i;
  Boolean value_ok;
  SshUInt32 flags;

  flags = 0;
  life_duration_secs_set = FALSE;
  life_duration_kb_set = FALSE;

  SSH_IKE_DEBUG(10, negotiation, ("Transform id = %d",
                                  trans->transform_id.generic));
  /* Read data from attributes, and fill them to attrs struct. This doesn't
     clear the attrs struct */
  for (i = 0; i < trans->number_of_sa_attributes; i++)
    {
      attr = &(trans->sa_attributes[i]);

      /* Check if the value can be represented as one 32 bit number */
      if (ssh_ike_get_data_attribute_int(attr, &value, flags))
        {
          /* Yes (most of the normal values should be representable in
             32 bits) */
          switch (attr->attribute_type)
            {
            case IPSEC_CLASSES_ENCAPSULATION_MODE:
              if (attrs->encapsulation_mode != 0 &&
                  attrs->encapsulation_mode != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Encapsulation mode given twice, "
                                 "old = %d, new = %d",
                                 attrs->encapsulation_mode, (int) value));
                  return FALSE;
                }
              attrs->encapsulation_mode = value;
              value_ok = TRUE;
              /* Map the number to name */
              name = ssh_find_keyword_name(ssh_ike_ipsec_encapsulation_modes,
                                           value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation,
                            ("encapsulation mode = %d (%s)",
                             attrs->encapsulation_mode,
                             isakmp_name_or_unknown(name)));
              /* Check if that algorithm is supported */
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported encapsulation mode : %d (%s)",
                                 attrs->encapsulation_mode,
                                 isakmp_name_or_unknown(name)));
                  return FALSE;
                }
              break;
            case IPSEC_CLASSES_AUTH_ALGORITHM: /* Hash algorithm */
              if (attrs->auth_algorithm != 0 &&
                  attrs->auth_algorithm != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                               ("Auth alg given twice, old = %d, new = %d",
                                attrs->auth_algorithm,
                                (int) value));
                  return FALSE;
                }
              attrs->auth_algorithm = value;
              value_ok = TRUE;
              /* Map the number to name */
              name = ssh_find_keyword_name(ssh_ike_ipsec_auth_algorithms,
                                           value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation, ("Auth alg = %d (%s)",
                                              attrs->auth_algorithm,
                                              isakmp_name_or_unknown(name)));
              /* Check if that algorithm is supported */
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported auth algorithm : %d (%s)",
                                 attrs->auth_algorithm,
                                 isakmp_name_or_unknown(name)));
                  return FALSE;
                }
              break;
            case IPSEC_CLASSES_GRP_DESC: /* Group descriptor number */
              if (attrs->group_desc != 0 &&
                  attrs->group_desc != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Group descr given twice, old = %d, new = %d",
                                 attrs->group_desc, (int) value));
                  return FALSE;
                }

              attrs->group_desc = value;
              SSH_IKE_DEBUG(10, negotiation, ("Group = %d", (int) value));
              /* Find matching group */
              if (ike_find_group(negotiation->sa, value) == NULL)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported group : %d", (int) value));
                  return FALSE;
                }
              break;
            case IPSEC_CLASSES_SA_LIFE_TYPE: /* Life type selector */
              life_type = value;
              value_ok = FALSE;
              /* Check if the value is ok */
              switch (value)
                {
                case IPSEC_VALUES_LIFE_TYPE_SECONDS:
                case IPSEC_VALUES_LIFE_TYPE_KILOBYTES:
                  value_ok = TRUE;
                  break;
                }
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported life type : %d", (int) value));
                  return FALSE;
                }
              break;
            case IPSEC_CLASSES_SA_LIFE_DURATION: /* Life type value */
              /* Check that life type have been already selected */
              if (life_type == 0)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("No life type given before life duration"));
                  return FALSE;
                }
              /* Store the value */
              switch (life_type)
                {
                case IPSEC_VALUES_LIFE_TYPE_SECONDS:
                  if (life_duration_secs_set &&
                      attrs->life_duration_secs != value)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Life duration seconds set twice with "
                                     "different values %d vs %d secs",
                                     (int) attrs->life_duration_secs,
                                     (int) value));
                      return FALSE;
                    }
                  else
                    {
                      attrs->life_duration_secs = value;
                      life_duration_secs_set = TRUE;
                      SSH_IKE_DEBUG(10, negotiation,
                                    ("Life duration %d secs", (int) value));
                    }
                  break;
                case IPSEC_VALUES_LIFE_TYPE_KILOBYTES:
                  if (life_duration_kb_set &&
                      attrs->life_duration_kb != value)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Life duration kb set twice with "
                                     "different values %d vs %d kb",
                                     (int) attrs->life_duration_kb,
                                     (int) value));
                      return FALSE;
                    }
                  else
                    {
                      attrs->life_duration_kb = value;
                      life_duration_kb_set = TRUE;
                      SSH_IKE_DEBUG(10, negotiation,
                                    ("Life duration %d kb", (int) value));
                    }
                  break;
                }
              break;
            case IPSEC_CLASSES_KEY_LENGTH: /* Key length */
              if (attrs->key_length != 0 &&
                  attrs->key_length != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Key length given twice, old = %d, new = %d",
                                 attrs->key_length,
                                 (int) value));
                  return FALSE;
                }
              attrs->key_length = value;
              SSH_IKE_DEBUG(10, negotiation, ("Key length = %d", (int) value));
              break;
            case IPSEC_CLASSES_KEY_ROUNDS: /* Key rounds */
              if (attrs->key_rounds != 0 &&
                  attrs->key_rounds != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Key rounds given twice, old = %d, new = %d",
                                 attrs->key_rounds,
                                 (int) value));
                  return FALSE;
                }
              attrs->key_rounds = value;
              SSH_IKE_DEBUG(10, negotiation, ("Key rounds = %d", (int) value));
              break;
            case IPSEC_CLASSES_SA_LONGSEQ:
              if (attrs->longseq_size != 0 &&
                  attrs->longseq_size != value)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Extended sequnce value given twice, "
                                 "old = %d, new = %d",
                                 attrs->longseq_size, (int) value));
                  return FALSE;
                }
              attrs->longseq_size = value;
              value_ok = TRUE;
              /* Map the number to name */
              name = ssh_find_keyword_name(ssh_ike_ipsec_longseq_values,
                                           value);
              if (name == NULL)
                {
                  value_ok = FALSE;
                }
              SSH_IKE_DEBUG(10, negotiation,
                            ("longseq value = %d (%s)",
                             attrs->longseq_size,
                             isakmp_name_or_unknown(name)));
              /* Check if that extended sequence number size is supported */
              if (!value_ok)
                {
                  SSH_IKE_DEBUG(8, negotiation,
                                ("Unsupported extended sequence value:%d (%s)",
                                 attrs->longseq_size,
                                 isakmp_name_or_unknown(name)));
                  return FALSE;
                }
              break;
            default:
              SSH_IKE_DEBUG(7, negotiation,
                            ("Unknown attribute = %d, value = %d",
                             attr->attribute_type, (int) value));
              return FALSE;
              break;
            }
        }
      else
        {
          /* Argument not representable in 32 bits, currently none
             supported */
          SSH_IKE_DEBUG(7, negotiation,
                        ("Unknown attribute = %d",
                         attr->attribute_type));
          return FALSE;
        }
    }
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_compare_transforms_isakmp
 * Compare two given transforms and return TRUE
 * if they match. The first transform is the one given
 * by the initiator and the second one is the value
 * selected by the responder.                                   shade{1.0}
 */

Boolean ike_compare_transforms_isakmp(SshIkeNegotiation negotiation,
                                      SshIkePayloadT trans_i,
                                      SshIkePayloadT trans_r)
{
  struct SshIkeAttributesRec attr_i, attr_r;

  /* Clear attributes */
  ssh_ike_clear_isakmp_attrs(&attr_i);
  ssh_ike_clear_isakmp_attrs(&attr_r);

  /* Read attributes */
  if (!ssh_ike_read_isakmp_attrs(negotiation, trans_i, &attr_i))
    {
      ssh_warning("Unsupported transform value in our own sa packet!");
      return FALSE;
    }
  if (!ssh_ike_read_isakmp_attrs(negotiation, trans_r, &attr_r))
    {
      SSH_IKE_DEBUG(7, negotiation,
                    ("Unsupported attributes in the response sa"));
      return FALSE;
    }

  /* Compare attributes */
  if (attr_i.encryption_algorithm != attr_r.encryption_algorithm ||
      attr_i.hash_algorithm != attr_r.hash_algorithm ||
      attr_i.auth_method != attr_r.auth_method ||
      attr_i.group_desc != attr_r.group_desc ||
      attr_i.prf_algorithm != attr_r.prf_algorithm ||
      attr_i.life_duration_kb != attr_r.life_duration_kb ||
      attr_i.life_duration_secs != attr_r.life_duration_secs ||
      attr_i.key_length != attr_r.key_length ||
      attr_i.group_parameters != attr_r.group_parameters)
    {
      SSH_IKE_DEBUG(7, negotiation,
                   ("Attributes didn't match "
                    "(%d/%d, %d/%d, %d/%d, %p/%p, %d/%d, %d/%d, %d/%d, %d/%d, "
                    "%s/%s)",
                    attr_i.encryption_algorithm,
                    attr_r.encryption_algorithm,
                    attr_i.hash_algorithm,
                    attr_r.hash_algorithm,
                    attr_i.auth_method,
                    attr_r.auth_method,
                    attr_i.group_desc,
                    attr_r.group_desc,
                    attr_i.prf_algorithm,
                    attr_r.prf_algorithm,
                    (int) attr_i.life_duration_kb,
                    (int) attr_r.life_duration_kb,
                    (int) attr_i.life_duration_secs,
                    (int) attr_r.life_duration_secs,
                    (int) attr_i.key_length,
                    (int) attr_r.key_length,
                    attr_i.group_parameters ? "True" : "False",
                    attr_r.group_parameters ? "True" : "False"));
      return FALSE;
    }
  /* Check if it has group parameters */
  if (attr_i.group_parameters)
    {
      /* Check that they match */
      return ike_compare_transforms_ngm(negotiation, trans_i, trans_r);
    }
  return TRUE;
}


/*                                                              shade{0.9}
 * ike_compare_transforms_ipsec
 * Compare two given transforms and return TRUE
 * if they match. The first transform is the one given
 * by the initiator and the second one is the value
 * selected by the responder.                                   shade{1.0}
 */

Boolean ike_compare_transforms_ipsec(SshIkeNegotiation negotiation,
                                     SshIkePayloadT trans_i,
                                     SshIkePayloadT trans_r)
{
  struct SshIkeIpsecAttributesRec attr_i, attr_r;

  /* Clear attributes */
  ssh_ike_clear_ipsec_attrs(&attr_i);
  ssh_ike_clear_ipsec_attrs(&attr_r);

  /* Read attributes */
  if (!ssh_ike_read_ipsec_attrs(negotiation, trans_i, &attr_i))
    {
      ssh_warning("Unsupported transform value in our own sa packet!");
      return FALSE;
    }
  if (!ssh_ike_read_ipsec_attrs(negotiation, trans_r, &attr_r))
    {
      SSH_IKE_DEBUG(7, negotiation,
                    ("Unsupported attributes in the response sa"));
      return FALSE;
    }

  /* Compare attributes */
  if (attr_i.life_duration_kb != attr_r.life_duration_kb ||
      attr_i.life_duration_secs != attr_r.life_duration_secs ||
      attr_i.group_desc != attr_r.group_desc ||
      attr_i.encapsulation_mode != attr_r.encapsulation_mode ||
      attr_i.auth_algorithm != attr_r.auth_algorithm ||
      attr_i.key_length != attr_r.key_length ||
      attr_i.key_rounds != attr_r.key_rounds ||
      attr_i.longseq_size != attr_r.longseq_size)
    {
      SSH_IKE_DEBUG(7, negotiation,
                    ("Attributes didn't match "
                    "(%d/%d, %d/%d, %d/%d, %d/%d, %d/%d, %d/%d, %d/%d, %d/%d)",
                     (int) attr_i.life_duration_kb,
                     (int) attr_r.life_duration_kb,
                     (int) attr_i.life_duration_secs,
                     (int) attr_r.life_duration_secs,
                     attr_i.group_desc,
                     attr_r.group_desc,
                     attr_i.encapsulation_mode,
                     attr_r.encapsulation_mode,
                     attr_i.auth_algorithm,
                     attr_r.auth_algorithm,
                     attr_i.key_length,
                     attr_r.key_length,
                     attr_i.key_rounds,
                     attr_r.key_rounds,
                     attr_i.longseq_size,
                     attr_r.longseq_size));
      return FALSE;
    }
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_compare_transforms_ngm
 * Compare two given transforms and return TRUE
 * if they match. The first transform is the one given
 * by the initiator and the second one is the value
 * selected by the responder.                                   shade{1.0}
 */

Boolean ike_compare_transforms_ngm(SshIkeNegotiation negotiation,
                                   SshIkePayloadT trans_i,
                                   SshIkePayloadT trans_r)
{
  struct SshIkeGrpAttributesRec attr_i, attr_r;

  /* Clear attributes */
  ssh_ike_clear_grp_attrs(&attr_i);
  ssh_ike_clear_grp_attrs(&attr_r);

  /* Read attributes */
  if (!ssh_ike_read_grp_attrs(negotiation, trans_i, &attr_i))
    {
      ssh_warning("Unsupported transform value in our own sa packet!");
      ssh_ike_free_grp_attrs(&attr_i);
      return FALSE;
    }
  if (!ssh_ike_read_grp_attrs(negotiation, trans_r, &attr_r))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation,
                    ("Unsupported attributes in the response sa"));
      return FALSE;
    }

  /* Compare attributes */
  if (attr_i.group_descriptor != attr_r.group_descriptor ||
      attr_i.group_type != attr_r.group_type)
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation,
                    ("Basic Attributes didn't match (%d/%d, %d/%d)",
                    attr_i.group_descriptor,
                    attr_r.group_descriptor,
                    attr_i.group_type,
                    attr_r.group_type));
      return FALSE;
    }
  if (!(attr_i.p != NULL && attr_r.p != NULL &&
        ssh_mprz_cmp(attr_i.p, attr_r.p) == 0) &&
      !(attr_i.p == NULL && attr_r.p == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("P differs"));
      return FALSE;
    }
  if (!(attr_i.g1 != NULL && attr_r.g1 != NULL &&
        ssh_mprz_cmp(attr_i.g1, attr_r.g1) == 0) &&
      !(attr_i.g1 == NULL && attr_r.g1 == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("Generator 1 differs"));
      return FALSE;
    }
  if (!(attr_i.g2 != NULL && attr_r.g2 != NULL &&
        ssh_mprz_cmp(attr_i.g2, attr_r.g2) == 0) &&
      !(attr_i.g2 == NULL && attr_r.g2 == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("Generator 2 differs"));
      return FALSE;
    }
  if (!(attr_i.ca != NULL && attr_r.ca != NULL &&
        ssh_mprz_cmp(attr_i.ca, attr_r.ca) == 0) &&
      !(attr_i.ca == NULL && attr_r.ca == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("CurveA differs"));
      return FALSE;
    }
  if (!(attr_i.cb != NULL && attr_r.cb != NULL &&
        ssh_mprz_cmp(attr_i.cb, attr_r.cb) == 0) &&
      !(attr_i.cb == NULL && attr_r.cb == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("CurveB differs"));
      return FALSE;
    }
  if (!(attr_i.order != NULL && attr_r.order != NULL &&
        ssh_mprz_cmp(attr_i.order, attr_r.order) == 0) &&
      !(attr_i.order == NULL && attr_r.order == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("Order differs"));
      return FALSE;
    }
  if (!(attr_i.cardinality != NULL && attr_r.cardinality != NULL &&
        ssh_mprz_cmp(attr_i.cardinality, attr_r.cardinality) == 0) &&
      !(attr_i.cardinality == NULL && attr_r.cardinality == NULL))
    {
      ssh_ike_free_grp_attrs(&attr_i);
      ssh_ike_free_grp_attrs(&attr_r);
      SSH_IKE_DEBUG(7, negotiation, ("Cardinality differs"));
      return FALSE;
    }
  ssh_ike_free_grp_attrs(&attr_i);
  ssh_ike_free_grp_attrs(&attr_r);
  return TRUE;
}


/*                                                              shade{0.9}
 * ike_compare_propopsals
 * Compare two given proposals and return TRUE
 * if they match. The first proposal is the one given
 * by the initiator and the second one is the values
 * selected by the responder.                                   shade{1.0}
 */

Boolean ike_compare_proposals(SshIkeNegotiation negotiation,
                              SshIkePayloadP prop_i,
                              SshIkePayloadP prop_r,
                              Boolean (*trans_cmp)(SshIkeNegotiation
                                                   negotiation,
                                                   SshIkePayloadT trans_i,
                                                   SshIkePayloadT trans_r))
{
  int i, r, t;

  /* Check the protocols in proposal match */
  for (i = 0; i < prop_i->number_of_protocols; i++)
    {
      /* Check that there in't any protocols missing in reponse */
      for (r = 0; r < prop_r->number_of_protocols; r++)
        {
          if (prop_i->protocols[i].protocol_id ==
              prop_r->protocols[r].protocol_id)
            break;
        }
      if (r == prop_r->number_of_protocols)
        {
          /* Protocol missing in response, return error */
          SSH_IKE_DEBUG(3, negotiation, ("Protocol %d missing in response SA",
                                        prop_i->protocols[i].protocol_id));
          return FALSE;
        }
    }

  for (r = 0; r < prop_r->number_of_protocols; r++)
    {
      /* Check number of transforms in response, it must be 1 */
      if (prop_r->protocols[r].number_of_transforms != 1)
        {
          SSH_IKE_DEBUG(3, negotiation,
                       ("Multiple transforms (%d) in the response SA",
                        prop_r->protocols[r].number_of_transforms));
          return FALSE;
        }

      /* Check there isn't any extra protocols in response */
      for (i = 0; i < prop_i->number_of_protocols; i++)
        {
          if (prop_i->protocols[i].protocol_id ==
              prop_r->protocols[r].protocol_id)
            break;
        }
      if (i == prop_i->number_of_protocols)
        {
          /* Extra protocol in response, return error */
          SSH_IKE_DEBUG(3, negotiation, ("Unknown protocol %d in response SA",
                                        prop_r->protocols[r].protocol_id));
          return FALSE;
        }
      /* spi can be different */

      /* Find the matching transform */
      for (t = 0; t < prop_i->protocols[i].number_of_transforms; t++)
        {
          /* Check if the transform id match is found */
          if (prop_i->protocols[i].transforms[t].transform_number ==
              prop_r->protocols[r].transforms[0].transform_number &&
              prop_i->protocols[i].transforms[t].transform_id.generic ==
              prop_r->protocols[r].transforms[0].transform_id.generic)
            break;
        }
      /* Check if transform id match found and if so, check that the
         real transforms match */
      if (t == prop_i->protocols[i].number_of_transforms ||
          !(*trans_cmp)(negotiation, &prop_i->protocols[i].transforms[t],
                        &prop_r->protocols[r].transforms[0]))
        {
          /* Either no transform id match found, or the real transforms
             didn't match */

          /* Loop through all transforms and try to find match */
          for (t = 0; t < prop_i->protocols[i].number_of_transforms; t++)
            {
              if (prop_i->protocols[i].transforms[t].transform_id.generic ==
                  prop_r->protocols[r].transforms[0].transform_id.generic &&
                  (*trans_cmp)(negotiation,
                               &prop_i->protocols[i].transforms[t],
                               &prop_r->protocols[r].transforms[0]))
                break;
            }
          if (t == prop_i->protocols[i].number_of_transforms)
            {
              /* No matching transform found, return error */
              SSH_IKE_DEBUG(3, negotiation, ("No matching transform found"));
              return FALSE;
            }
        }
      /* Transforms matched, try next protocol */
    }
  return TRUE;
}
