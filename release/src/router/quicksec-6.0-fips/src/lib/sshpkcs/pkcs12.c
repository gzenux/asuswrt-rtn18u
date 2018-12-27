/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation for decoding and encoding PKCS#12 data.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshasn1.h"
#include "oid.h"

#include "sshpkcs5.h"
#include "sshpkcs8.h"
#include "sshpkcs12.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPKCS12"

#define DEFAULT_PKCS12_KEY_PBE "pbeWithSHAAnd3-KeyTripleDES-CBC"
#define DEFAULT_PKCS12_SAFE_PBE "pbeWithSHAAnd3-KeyTripleDES-CBC"

#define SSH_PKCS12_VERSION 3

typedef struct SshPkcs12MacDataRec {
  unsigned char *salt;
  size_t salt_len;
  SshUInt32 iterations;
  char *digest_alg;
  unsigned char *digest;
  size_t digest_len;
} *SshPkcs12MacData;

struct SshPkcs12PFXRec {
  SshUInt32 version;
  SshPkcs12IntegrityMode integrity;
  SshPkcs7 authSafe;
  SshPkcs12MacData mac;
  SshUInt32 num_safes, allocated_safes;
  SshPkcs12Safe *safes;
};

struct SshPkcs12SafeRec {
  SshPkcs7 content;
  SshPkcs12SafeProtectionType protection;
  union {
    struct {
      unsigned char *pbe_oid;
      SshStr password;
    } password;
    struct {
      char *data_encrypt_alg;
      SshPkcs7RecipientInfo recipient;
    } pubkey;
  } protect_params;
  SshUInt32 num_bags, allocated_bags;
  SshPkcs12Bag *bags;
};

struct SshPkcs12AttributeRec {
  SshPkcs12AttributeType type;
  union {
    SshStr name;
    struct {
      unsigned char *data;
      size_t len;
    } id;
    struct {
      char *oid;
      unsigned char *ber;
      size_t ber_len;
    } unknown;
  } v;
};

struct SshPkcs12BagRec {
  SshPkcs12BagType type;
  SshUInt32 num_attr, allocated_attr;
  SshPkcs12Attribute *attr;
  unsigned char *data;
  size_t data_len;
  union {
    char *oid;
    SshPkcs12Safe safe;
  } type_attr;
};


typedef struct Pkcs12EncodeCtxRec {
  SshOperationHandle op, sub_op;
  SshPkcs12PFX pfx;
  SshPkcs12PFXEncodeCB callback;
  SshPkcs12StatusCB status_callback;
  void *context;
} *Pkcs12EncodeCtx;


static unsigned char *
ssh_pkcs12_convert_to_unicode(SshStr str, size_t *len_ret)
{
  SshStr unicode;
  unsigned char *p, *ret = NULL;
  size_t p_len;

  *len_ret = 0;
  if ((unicode = ssh_str_charset_convert(str, SSH_CHARSET_BMP)) != NULL)
    {
      if ((p = ssh_str_get(unicode, &p_len)) != NULL)
        {
          *len_ret = p_len + 2;
          if ((ret = ssh_malloc(*len_ret)) != NULL)
            {
              memcpy(ret, p, *len_ret - 2);
              ret[*len_ret - 2] = 0x00;
              ret[*len_ret - 1] = 0x00;
            }
          ssh_free(p);
        }
      ssh_str_free(unicode);
    }
  return ret;
}

SshPkcs12PFX
ssh_pkcs12_pfx_create(void)
{
  SshPkcs12PFX r;

  r = ssh_calloc(1, sizeof(*r));
  return r;
}

static void
ssh_pkcs12_mac_data_destroy(SshPkcs12MacData mac)
{
  if (!mac) return;

  ssh_free(mac->salt);
  ssh_free(mac->digest);
  ssh_free(mac->digest_alg);
  ssh_free(mac);
}

static void
ssh_pkcs12_attr_destroy(SshPkcs12Attribute attr)
{
  if (!attr) return;

  switch (attr->type)
    {
    case SSH_PKCS12_ATTR_UNKNOWN:
      ssh_free(attr->v.unknown.oid);
      ssh_free(attr->v.unknown.ber);
      break;
    case SSH_PKCS12_ATTR_LOCAL_KEY_ID:
      ssh_free(attr->v.id.data);
      break;
    case SSH_PKCS12_ATTR_FRIENDLY_NAME:
      ssh_str_free(attr->v.name);
      break;
    default:
      SSH_NOTREACHED;
    }
  ssh_free(attr);
}

static void
ssh_pkcs12_safe_destroy(SshPkcs12Safe safe);

static void
ssh_pkcs12_bag_destroy(SshPkcs12Bag bag)
{
  int i;

  if (!bag) return;

  ssh_free(bag->data);
  switch (bag->type)
    {
    case SSH_PKCS12_BAG_SAFE:
      ssh_pkcs12_safe_destroy(bag->type_attr.safe);
      break;
    case SSH_PKCS12_BAG_CERT:
    case SSH_PKCS12_BAG_CRL:
    case SSH_PKCS12_BAG_SECRET:
      ssh_free(bag->type_attr.oid);
      break;
    default:
      ;
    }

  for (i = 0; i < bag->num_attr; i++)
    ssh_pkcs12_attr_destroy(bag->attr[i]);

  ssh_free(bag->attr);
  ssh_free(bag);
}

static void
ssh_pkcs12_safe_destroy(SshPkcs12Safe safe)
{
  int i;

  if (!safe) return;

  if (safe->content)
    ssh_pkcs7_free(safe->content);

  switch (safe->protection)
    {
    case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
      ssh_free(safe->protect_params.password.pbe_oid);
      ssh_str_free(safe->protect_params.password.password);
      break;
    case SSH_PKCS12_SAFE_ENCRYPT_PUBKEY:
      ssh_free(safe->protect_params.pubkey.data_encrypt_alg);
      ssh_pkcs7_free_recipient_info(safe->protect_params.pubkey.recipient);
      break;
    default:
      ;
    }

  for (i = 0; i < safe->num_bags; i++)
    ssh_pkcs12_bag_destroy(safe->bags[i]);
  ssh_free(safe->bags);

  ssh_free(safe);
}

static SshPkcs12Status
ssh_pkcs12_pfx_decode_mac(SshPkcs12PFX pfx,
                          SshAsn1Context asn1,
                          SshAsn1Node mac)
{
  unsigned char *oid_str;
  unsigned char *salt, *digest;
  size_t salt_len, digest_len;
  SshWord iterations;
  Boolean has_iterations;
  SshAsn1Node alg_param;
  SshPkcs12MacData mac_data;
  const SshOidStruct *oid;

  if (ssh_asn1_read_node(asn1,
                         mac,
                         "(sequence ()"
                         "  (sequence ()"
                         "    (sequence ()"
                         "      (object-identifier ())"
                         "      (any ()))"
                         "    (octet-string ()))"
                         "  (octet-string())"
                         "  (optional (integer-short())))",
                         &oid_str,
                         &alg_param,
                         &digest, &digest_len,
                         &salt, &salt_len,
                         &has_iterations, &iterations) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  if ((mac_data = ssh_calloc(1, sizeof(*mac_data))) != NULL)
    {
      mac_data->digest = digest;
      mac_data->digest_len = digest_len;
      oid = ssh_oid_find_by_oid_of_type(oid_str, SSH_OID_HASH);
      if (oid)
        mac_data->digest_alg = ssh_strdup(oid->name);
    }
  ssh_free(oid_str);

  if (mac_data == NULL || mac_data->digest_alg == NULL)
    {
      ssh_free(salt);
      ssh_free(digest);
      ssh_free(mac_data);
      return SSH_PKCS12_ERROR;
    }

  if (has_iterations)
    mac_data->iterations = iterations;
  else
    mac_data->iterations = 1;


  mac_data->salt = salt;
  mac_data->salt_len = salt_len;
  pfx->mac = mac_data;
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_pfx_encode_mac(SshPkcs12PFX pfx,
                          SshAsn1Context asn1,
                          SshAsn1Node *mac)
{
  SshAsn1Node iter = NULL;
  const SshOidStruct *oid;

  oid = ssh_oid_find_by_alt_name_of_type(pfx->mac->digest_alg, SSH_OID_HASH);
  if (!oid)
    {
      return SSH_PKCS12_ERROR;
    }

  if (pfx->mac->iterations != 1)
    {
      if ((ssh_asn1_create_node(asn1, &iter,
                                "(integer-short ())", pfx->mac->iterations))
          != SSH_ASN1_STATUS_OK)
        return SSH_PKCS12_ERROR;
    }

  if (ssh_asn1_create_node(asn1, mac,
                           "(sequence ()"
                           "  (sequence ()"
                           "    (sequence ()"
                           "      (object-identifier ())"
                           "      (null ()))"
                           "    (octet-string ()))"
                           "  (octet-string())"
                           "  (any ()))",
                           oid->oid,
                           pfx->mac->digest, pfx->mac->digest_len,
                           pfx->mac->salt, pfx->mac->salt_len,
                           iter) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  return SSH_PKCS12_OK;
}


/*
  Frees a PFX structure. All the contained Safes and SafeBags are
  destroyed also.
*/
void
ssh_pkcs12_pfx_free(SshPkcs12PFX pfx)
{
  int i;

  if (pfx->authSafe)
    ssh_pkcs7_free(pfx->authSafe);

  for (i = 0; i < pfx->num_safes; i++)
    ssh_pkcs12_safe_destroy(pfx->safes[i]);
  ssh_free(pfx->safes);

  ssh_pkcs12_mac_data_destroy(pfx->mac);

  ssh_free(pfx);
}

#define BAG_OID_PREFIX "1.2.840.113549.1.12.10.1"

static Boolean
ssh_pkcs12_get_bag_type_by_oid(const char *oid,
                               SshPkcs12BagType *type_ret)
{
  Boolean found = TRUE;

  if (!strcmp(oid, BAG_OID_PREFIX".1"))
     *type_ret = SSH_PKCS12_BAG_KEY;
  else if (!strcmp(oid, BAG_OID_PREFIX".2"))
    *type_ret = SSH_PKCS12_BAG_SHROUDED_KEY;
  else if (!strcmp(oid, BAG_OID_PREFIX".3"))
    *type_ret = SSH_PKCS12_BAG_CERT;
  else if (!strcmp(oid, BAG_OID_PREFIX".4"))
    *type_ret = SSH_PKCS12_BAG_CRL;
  else if (!strcmp(oid, BAG_OID_PREFIX".5"))
    *type_ret = SSH_PKCS12_BAG_SECRET;
  else if (!strcmp(oid, BAG_OID_PREFIX".6"))
    *type_ret = SSH_PKCS12_BAG_SAFE;
  else
    found = FALSE;

  return found;
}

static const char *
ssh_pkcs12_bag_get_oid(SshPkcs12Bag bag)
{
  switch (bag->type)
    {
    case SSH_PKCS12_BAG_KEY:
      return BAG_OID_PREFIX".1";
      break;
    case SSH_PKCS12_BAG_SHROUDED_KEY:
      return BAG_OID_PREFIX".2";
      break;
    case SSH_PKCS12_BAG_CERT:
      return BAG_OID_PREFIX".3";
      break;
    case SSH_PKCS12_BAG_CRL:
      return BAG_OID_PREFIX".4";
      break;
    case SSH_PKCS12_BAG_SECRET:
      return BAG_OID_PREFIX".5";
      break;
    case SSH_PKCS12_BAG_SAFE:
      return BAG_OID_PREFIX".6";
      break;
    default:
      SSH_NOTREACHED;
    }
  /* not reached */
  return NULL;
}

static SshPkcs12Status
ssh_pkcs12_safe_encode(SshAsn1Context asn1,
                       SshAsn1Node *node,
                       SshPkcs12Safe safe);



static SshPkcs12Status
ssh_pkcs12_decode_key_bag(SshAsn1Context asn1,
                          SshAsn1Node node,
                          SshPkcs12Bag bag)
{
  return ((ssh_asn1_node_get_data(
                            node,
                            &bag->data,
                            &bag->data_len) ==
                            SSH_ASN1_STATUS_OK)?
                            (SSH_PKCS12_OK):(SSH_PKCS12_ERROR));
}

static SshPkcs12Status
ssh_pkcs12_encode_key_bag(SshAsn1Context asn1,
                          SshAsn1Node *node,
                          SshPkcs12Bag bag)
{
  return ((ssh_asn1_decode_node(asn1,
                                bag->data,
                                bag->data_len,
                                node) ==
                            SSH_ASN1_STATUS_OK)?
                            (SSH_PKCS12_OK):(SSH_PKCS12_ERROR));
}


static SshPkcs12Status
ssh_pkcs12_decode_shrouded_key_bag(SshAsn1Context asn1,
                                   SshAsn1Node node,
                                   SshPkcs12Bag bag)
{
  return ((ssh_asn1_node_get_data(
                            node,
                            &bag->data,
                            &bag->data_len) ==
                            SSH_ASN1_STATUS_OK)?
                            (SSH_PKCS12_OK):(SSH_PKCS12_ERROR));
}

static SshPkcs12Status
ssh_pkcs12_encode_shrouded_key_bag(SshAsn1Context asn1,
                                   SshAsn1Node *node,
                                   SshPkcs12Bag bag)
{
  return ((ssh_asn1_decode_node(asn1,
                               bag->data,
                               bag->data_len,
                               node) ==
                              SSH_ASN1_STATUS_OK)?
                            (SSH_PKCS12_OK):(SSH_PKCS12_ERROR));
}


static SshPkcs12Status
ssh_pkcs12_decode_cert_bag(SshAsn1Context asn1,
                           SshAsn1Node node,
                           SshPkcs12Bag bag)
{
  if (ssh_asn1_read_node(asn1,
                         node,
                         "(sequence ()"
                         "  (object-identifier())"
                         "  (octet-string (e 0)))",
                         &bag->type_attr.oid,
                         &bag->data, &bag->data_len) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS12_ERROR;

  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_encode_cert_bag(SshAsn1Context asn1,
                           SshAsn1Node *node,
                           SshPkcs12Bag bag)
{
  if (ssh_asn1_create_node(asn1,
                           node,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (octet-string (e 0)))",
                           bag->type_attr.oid,
                           bag->data, bag->data_len) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS12_ERROR;

  return SSH_PKCS12_OK;
}


static SshPkcs12Status
ssh_pkcs12_decode_crl_bag(SshAsn1Context asn1,
                          SshAsn1Node node,
                          SshPkcs12Bag bag)
{
  if (ssh_asn1_read_node(asn1,
                         node,
                         "(sequence ()"
                         "  (object-identifier())"
                         "  (octet-string (e 0)))",
                         &bag->type_attr.oid,
                         &bag->data, &bag->data_len) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS12_ERROR;

  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_encode_crl_bag(SshAsn1Context asn1,
                          SshAsn1Node *node,
                          SshPkcs12Bag bag)
{
  if (ssh_asn1_create_node(asn1,
                           node,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (any (e 0)))",
                           bag->type_attr.oid,
                           bag->data, bag->data_len) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS12_ERROR;

  return SSH_PKCS12_OK;
}


static SshPkcs12Status
ssh_pkcs12_decode_secret_bag(SshAsn1Context asn1,
                             SshAsn1Node node,
                             SshPkcs12Bag bag)
{
  char *oid;
  SshAsn1Node value_node;

  if (ssh_asn1_read_node(asn1,
                         node,
                         "(sequence ()"
                         "  (object-identifier())"
                         "  (any (e 0)))",
                         &oid,
                         &value_node) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  if (ssh_asn1_node_get_data(value_node,
                             &bag->data,
                             &bag->data_len) != SSH_ASN1_STATUS_OK)
    {
      ssh_free(oid);
      return SSH_PKCS12_ERROR;
    }
  bag->type_attr.oid = oid;
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_encode_secret_bag(SshAsn1Context asn1,
                             SshAsn1Node *node,
                             SshPkcs12Bag bag)
{
  SshAsn1Node value_node;

  if (ssh_asn1_decode_node(asn1,
                           bag->data,
                           bag->data_len,
                           &value_node) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }


  if (ssh_asn1_create_node(asn1,
                           node,
                           "(sequence ()"
                           "  (object-identifier())"
                           "  (any (e 0)))",
                           bag->type_attr.oid,
                           value_node) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_decode_safe_bag(SshAsn1Context asn1,
                           SshAsn1Node node,
                           SshPkcs12Bag bag);


/* Adds attribute into bag. If it does not fit, frees attribute and
   leaves the bag as it was. */
static SshPkcs12Status
ssh_pkcs12_bag_add_attribute(SshPkcs12Bag bag,
                             SshPkcs12Attribute attr)
{
  SshPkcs12Attribute *tmp;
  size_t oldsize = bag->allocated_attr * sizeof(tmp);

  if (bag->num_attr + 1 >= bag->allocated_attr)
    {
      bag->allocated_attr += 5;
      if ((tmp =
           ssh_realloc(bag->attr, oldsize,
                       bag->allocated_attr * sizeof(SshPkcs12Attribute)))
          == NULL)
        {
          ssh_pkcs12_attr_destroy(attr);
          return SSH_PKCS12_ERROR;
        }
      bag->attr = tmp;
    }
  bag->attr[bag->num_attr++] = attr;
  bag->attr[bag->num_attr] = NULL; /* NULL marker */
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_bag_decode_friendly_name_attr(SshAsn1Context asn1,
                                         SshAsn1Node node,
                                         SshPkcs12Bag bag)
{
  SshPkcs12Attribute attr;
  unsigned char *str;
  size_t str_len;
  SshPkcs12Status status = SSH_PKCS12_OK;

  while (status == SSH_PKCS12_OK && node)
    {
      if (ssh_asn1_read_node(asn1,
                             node,
                             "(bmp-string())",
                             &str, &str_len) == SSH_ASN1_STATUS_OK)
        {
          if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
            {
              attr->type = SSH_PKCS12_ATTR_FRIENDLY_NAME;
              attr->v.name = ssh_str_make(SSH_CHARSET_BMP, str, str_len);
              status = ssh_pkcs12_bag_add_attribute(bag, attr);
            }
          else
            status = SSH_PKCS12_ERROR;
        }
      node = ssh_asn1_node_next(node);
    }
  return status;
}

static SshPkcs12Status
ssh_pkcs12_bag_encode_friendly_name_attr(SshAsn1Context asn1,
                                         SshAsn1Node *set,
                                         SshPkcs12Bag bag,
                                         SshUInt32 *index)
{
  SshPkcs12Attribute attr;
  SshPkcs12AttributeType type;
  unsigned char *str;
  size_t str_len;
  SshAsn1Status asn1_status;
  SshAsn1Node node, list = NULL;

  *set = NULL;
  while (TRUE)
    {
      attr = bag->attr[*index];
      type = attr->type;

      if ((str = ssh_pkcs12_convert_to_unicode(attr->v.name, &str_len))
          != NULL)
        {
          str_len -=2; /* remove the NULL marker */
          asn1_status = ssh_asn1_create_node(asn1, &node,
                                             "(bmp-string ())", str, str_len);
          ssh_free(str);
          if (asn1_status != SSH_ASN1_STATUS_OK)
            return SSH_PKCS12_ERROR;

          list = ssh_asn1_add_list(list, node);
          (*index)++;
          if (!bag->attr[*index] || type != bag->attr[*index]->type)
            break;
        }
      else
        return SSH_PKCS12_ERROR;
    }
  *set = list;
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_bag_decode_local_key_id_attr(SshAsn1Context asn1,
                                        SshAsn1Node node,
                                        SshPkcs12Bag bag)
{
  SshPkcs12Attribute attr;
  unsigned char *id;
  size_t id_len;
  SshPkcs12Status status = SSH_PKCS12_OK;

  while (status == SSH_PKCS12_OK && node)
    {
      if (ssh_asn1_read_node(asn1,
                             node,
                             "(octet-string())",
                             &id, &id_len) == SSH_ASN1_STATUS_OK)
        {
          if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
            {
              attr->type = SSH_PKCS12_ATTR_LOCAL_KEY_ID;
              attr->v.id.data = id;
              attr->v.id.len = id_len;
              status = ssh_pkcs12_bag_add_attribute(bag, attr);
            }
          else
            status = SSH_PKCS12_ERROR;
        }
      node = ssh_asn1_node_next(node);
    }
  return status;
}

static SshPkcs12Status
ssh_pkcs12_bag_encode_local_key_id_attr(SshAsn1Context asn1,
                                        SshAsn1Node *set,
                                        SshPkcs12Bag bag,
                                        SshUInt32 *index)
{
  SshAsn1Status asn1_status;
  SshPkcs12Attribute attr;
  SshPkcs12AttributeType type;
  SshAsn1Node node, list = NULL;

  type = bag->attr[*index]->type;

  while (bag->attr[*index] && type == bag->attr[*index]->type)
    {
      attr = bag->attr[*index];
      type = attr->type;

      asn1_status = ssh_asn1_create_node(asn1,
                                         &node,
                                         "(octet-string())",
                                         attr->v.id.data, attr->v.id.len);
      if (asn1_status != SSH_ASN1_STATUS_OK)
        return SSH_PKCS12_ERROR;

      list = ssh_asn1_add_list(list, node);

      (*index)++;
    }
  *set = list;

  return SSH_PKCS12_OK;

}

static SshPkcs12Status
ssh_pkcs12_bag_decode_unknown_attr(SshAsn1Context asn1,
                                   SshAsn1Node node,
                                   const char *oid,
                                   SshPkcs12Bag bag)
{
  SshPkcs12Attribute attr;
  unsigned char *data = NULL;
  size_t data_len = 0;

  if (node)
    {
      if (ssh_asn1_node_get_data(node, &data, &data_len))
        return SSH_PKCS12_FORMAT_ERROR;
    }

  if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
    {
      attr->type = SSH_PKCS12_ATTR_UNKNOWN;
      if ((attr->v.unknown.oid = ssh_strdup(oid)) != NULL)
        {
          attr->v.unknown.ber = data;
          attr->v.unknown.ber_len = data_len;
          return ssh_pkcs12_bag_add_attribute(bag, attr);
        }
    }
  ssh_free(data);
  ssh_free(attr);
  return SSH_PKCS12_ERROR;
}

static SshPkcs12Status
ssh_pkcs12_bag_encode_unknown_attr(SshAsn1Context asn1,
                                   SshAsn1Node *set,
                                   SshPkcs12Bag bag,
                                   SshUInt32 *index)
{
  SshAsn1Status asn1_status;
  SshPkcs12Attribute attr;
  SshPkcs12AttributeType type;
  SshAsn1Node node, list = NULL;

  while (1)
    {
      attr = bag->attr[*index];
      type = attr->type;

      asn1_status = ssh_asn1_decode_node(asn1,
                                         attr->v.unknown.ber,
                                         attr->v.unknown.ber_len,
                                         &node);

      if (asn1_status != SSH_ASN1_STATUS_OK)
        return SSH_PKCS12_ERROR;

      list = ssh_asn1_add_list(list, node);

      (*index)++;
      if (!bag->attr[*index] || type != bag->attr[*index]->type)
        break;
    }
  *set = list;
  return SSH_PKCS12_OK;

}

#define PKCS9_OID "1.2.840.113549.1.9"

static SshPkcs12Status
ssh_pkcs12_bag_decode_attribute(SshAsn1Context asn1,
                                 SshAsn1Node node,
                                 SshPkcs12Bag bag)
{
  SshAsn1Node value_node;
  char *oid;
  SshPkcs12Status status = SSH_PKCS12_OK;

  if (ssh_asn1_read_node(asn1,
                         node,
                         "(sequence ()"
                         "  (object-identifier())"
                         "  (set ()"
                         "    (any ())))",
                         &oid,
                         &value_node) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if (!strcmp(oid, PKCS9_OID".20"))
    {
      status = ssh_pkcs12_bag_decode_friendly_name_attr(asn1,
                                                        value_node,
                                                        bag);
    }
  else
  if (!strcmp(oid, PKCS9_OID".21"))
    {
      status = ssh_pkcs12_bag_decode_local_key_id_attr(asn1,
                                                       value_node,
                                                       bag);
    }
  else
    {
      status = ssh_pkcs12_bag_decode_unknown_attr(asn1,
                                                  value_node,
                                                  oid,
                                                  bag);
    }

  ssh_free(oid);
  return status;
}

static const char *
ssh_pkcs12_attr_get_oid(SshPkcs12Attribute attr)
{
  switch (attr->type)
    {
      case SSH_PKCS12_ATTR_FRIENDLY_NAME:
        return PKCS9_OID".20";
        break;
      case SSH_PKCS12_ATTR_LOCAL_KEY_ID:
        return PKCS9_OID".21";
        break;
      case SSH_PKCS12_ATTR_UNKNOWN:
        return attr->v.unknown.oid;
        break;
      default:
        SSH_NOTREACHED;
    }
  /* not reached */
  return NULL;
}

/* Create a PKCS12Attribute node */
static SshPkcs12Status
ssh_pkcs12_bag_encode_attribute(SshAsn1Context asn1,
                                SshAsn1Node *node,
                                SshPkcs12Bag bag,
                                SshUInt32 *index)
{
  SshAsn1Node value_node = NULL;
  SshPkcs12Status status = SSH_PKCS12_ERROR;
  SshPkcs12Attribute attr;
  const char *oid;

  attr = bag->attr[*index];
  switch (attr->type)
    {
    case SSH_PKCS12_ATTR_FRIENDLY_NAME:
      status = ssh_pkcs12_bag_encode_friendly_name_attr(asn1,
                                                        &value_node,
                                                        bag,
                                                        index);
      break;
    case SSH_PKCS12_ATTR_LOCAL_KEY_ID:
      status = ssh_pkcs12_bag_encode_local_key_id_attr(asn1,
                                                       &value_node,
                                                       bag,
                                                       index);
      break;
    case SSH_PKCS12_ATTR_UNKNOWN:
      status = ssh_pkcs12_bag_encode_unknown_attr(asn1,
                                                  &value_node,
                                                  bag,
                                                  index);
      break;
    default:
      SSH_NOTREACHED;
    }

  if (status != SSH_PKCS12_OK)
    return status;

  oid = ssh_pkcs12_attr_get_oid(attr);

  if (ssh_asn1_create_node(asn1,
                           node,
                           "(sequence ()"
                           "  (object-identifier())"
                           "  (set ()"
                           "    (any ())))",
                           oid,
                           value_node) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_bag_decode_attributes(SshAsn1Context asn1,
                                 SshAsn1Node node,
                                 SshPkcs12Bag bag)
{
  while (node)
    {
      ssh_pkcs12_bag_decode_attribute(asn1, node, bag);
      node = ssh_asn1_node_next(node);
    }

  return SSH_PKCS12_OK;
}

/* Creates a list of PKCS12Attribute nodes */
static SshPkcs12Status
ssh_pkcs12_bag_encode_attributes(SshAsn1Context asn1,
                                 SshAsn1Node *node,
                                 SshPkcs12Bag bag)
{
  SshUInt32 i = 0;
  SshAsn1Node list = NULL, attr;
  SshPkcs12Status status;

  while (bag->attr[i])
    {
      status = ssh_pkcs12_bag_encode_attribute(asn1,
                                               &attr,
                                               bag,
                                               &i);
      if (status != SSH_PKCS12_OK)
        return status;

      list = ssh_asn1_add_list(list, attr);
    }
  if (ssh_asn1_create_node(asn1, node, "(set () (any ()))", list))
    return SSH_PKCS12_ERROR;
  return SSH_PKCS12_OK;
}

/* In error the safe may still contain some bags, if they were not in
   error */
static SshPkcs12Status
ssh_pkcs12_safe_decode_content(SshPkcs12Safe safe)
{
  const unsigned char *data;
  char *oid;
  size_t data_len;
  SshAsn1Context asn1;
  SshAsn1Tree seq;
  SshAsn1Node bag_node, value_node, attr_set;
  Boolean has_attr;
  SshPkcs12BagType bag_type;
  SshPkcs7 content;

  if ((content = ssh_pkcs7_get_content(safe->content)) == NULL)
    content = safe->content;

  if (!ssh_pkcs7_content_data(content, &data, &data_len))
    return SSH_PKCS12_ERROR;

  if ((asn1 = ssh_asn1_init()) == NULL)
    return SSH_PKCS12_ERROR;

  if (ssh_asn1_decode(asn1,
                      data, data_len,
                      &seq) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }

  bag_node = ssh_asn1_get_current(seq);
  bag_node = ssh_asn1_node_child(bag_node);
  while (bag_node != NULL)
    {
      if (ssh_asn1_read_node(asn1,
                             bag_node,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (any (e 0))"
                             "  (optional (set () (any ()))))",
                             &oid,
                             &value_node,
                             &has_attr, &attr_set) != SSH_ASN1_STATUS_OK)
        {
          ssh_asn1_free(asn1);
          return SSH_PKCS12_ERROR;
        }
      if (ssh_pkcs12_get_bag_type_by_oid(oid, &bag_type))
        {
          SshPkcs12Status status = SSH_PKCS12_ERROR;
          SshPkcs12Bag bag;

          if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
            {
              ssh_asn1_free(asn1);
              return SSH_PKCS12_ERROR;
            }

          bag->type = bag_type;

          switch (bag_type)
            {
            case SSH_PKCS12_BAG_KEY:
              status = ssh_pkcs12_decode_key_bag(asn1, value_node, bag);
              break;
            case SSH_PKCS12_BAG_SHROUDED_KEY:
              status = ssh_pkcs12_decode_shrouded_key_bag(asn1,
                                                          value_node, bag);
              break;
            case SSH_PKCS12_BAG_CERT:
              status = ssh_pkcs12_decode_cert_bag(asn1, value_node, bag);
              break;
            case SSH_PKCS12_BAG_CRL:
              status = ssh_pkcs12_decode_crl_bag(asn1, value_node, bag);
              break;
            case SSH_PKCS12_BAG_SECRET:
              status = ssh_pkcs12_decode_secret_bag(asn1, value_node, bag);
              break;
            case SSH_PKCS12_BAG_SAFE:
              status = ssh_pkcs12_decode_safe_bag(asn1, value_node, bag);
              break;
            default:
              SSH_NOTREACHED;
            }
          if (status == SSH_PKCS12_OK && has_attr)
            status = ssh_pkcs12_bag_decode_attributes(asn1, attr_set, bag);

          if (status == SSH_PKCS12_OK)
            {
              ssh_pkcs12_safe_add_bag(safe, bag);
            }
          else
            {
              ssh_free(bag);
            }
        }
      ssh_free(oid);
      bag_node = ssh_asn1_node_next(bag_node);
    }
  ssh_asn1_free(asn1);
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_safe_decode(SshAsn1Context asn1,
                       SshAsn1Node node,
                       SshPkcs12Safe *safe_ret)
{
  unsigned char *content_data;
  size_t content_data_len;
  SshPkcs7 pkcs7_safe;
  SshPkcs12Safe safe;

  *safe_ret = NULL;

  if (ssh_asn1_node_get_data(node,
                             &content_data,
                             &content_data_len) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }
  if (ssh_pkcs7_decode(content_data,
                       content_data_len,
                       &pkcs7_safe) != SSH_PKCS7_OK)
    {
      ssh_free(content_data);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(content_data);

  if ((safe = ssh_calloc(1, sizeof(*safe))) == NULL)
    {
      ssh_pkcs7_free(pkcs7_safe);
      return SSH_PKCS12_ERROR;
    }

  safe->content = pkcs7_safe;
  switch (ssh_pkcs7_get_content_type(pkcs7_safe))
    {
    case SSH_PKCS7_DATA:
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_NONE;
      if (ssh_pkcs12_safe_decode_content(safe) != SSH_PKCS12_OK)
        {
          ssh_asn1_free(asn1);
          ssh_pkcs12_safe_destroy(safe);
          return SSH_PKCS12_ERROR;
        }
      break;
    case SSH_PKCS7_ENVELOPED_DATA:
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_PUBKEY;
      break;
    case SSH_PKCS7_ENCRYPTED_DATA:
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_PASSWORD;
      break;
    default:
      ssh_asn1_free(asn1);
      ssh_pkcs12_safe_destroy(safe);
      return SSH_PKCS12_ERROR;
    }
  *safe_ret = safe;
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_encode_safe_bag(SshAsn1Context asn1,
                           SshAsn1Node *node,
                           SshPkcs12Bag bag)
{
  return ssh_pkcs12_safe_encode(asn1, node, bag->type_attr.safe);
}

static SshPkcs12Status
ssh_pkcs12_safe_encode(SshAsn1Context asn1,
                       SshAsn1Node *node,
                       SshPkcs12Safe safe)
{
  SshPkcs12Status status = SSH_PKCS12_ERROR;
  SshPkcs7 pkcs7, pkcs7_prot;
  SshAsn1Node list = NULL, bag_value, bag_node, attr_node, seq;
  unsigned char *data, *p;
  const char *oid;
  size_t data_len, p_len;
  SshUInt32 i;

  for (i = 0; i < safe->num_bags; i++)
    {
      switch (safe->bags[i]->type)
        {
        case SSH_PKCS12_BAG_KEY:
          status = ssh_pkcs12_encode_key_bag(asn1,
                                             &bag_value,
                                             safe->bags[i]);
          break;
        case SSH_PKCS12_BAG_SHROUDED_KEY:
          status = ssh_pkcs12_encode_shrouded_key_bag(asn1,
                                                      &bag_value,
                                                      safe->bags[i]);
          break;
        case SSH_PKCS12_BAG_CERT:
          status = ssh_pkcs12_encode_cert_bag(asn1,
                                              &bag_value,
                                              safe->bags[i]);
          break;
        case SSH_PKCS12_BAG_CRL:
          status = ssh_pkcs12_encode_crl_bag(asn1,
                                             &bag_value,
                                             safe->bags[i]);
          break;
        case SSH_PKCS12_BAG_SECRET:
          status = ssh_pkcs12_encode_secret_bag(asn1,
                                                &bag_value,
                                                safe->bags[i]);
          break;
        case SSH_PKCS12_BAG_SAFE:
          status = ssh_pkcs12_encode_safe_bag(asn1,
                                              &bag_value,
                                              safe->bags[i]);
          break;
        }
      if (status != SSH_PKCS12_OK)
        {
          return SSH_PKCS12_ERROR;
        }
      oid = ssh_pkcs12_bag_get_oid(safe->bags[i]);

      if (safe->bags[i]->num_attr > 0)
        {
          status = ssh_pkcs12_bag_encode_attributes(asn1,
                                                    &attr_node,
                                                    safe->bags[i]);
          if (status != SSH_PKCS12_OK)
            return status;
        }
      else
        {
          attr_node = NULL;
        }

      if (ssh_asn1_create_node(asn1,
                               &bag_node,
                               "(sequence ()"
                               "  (object-identifier())"
                               "  (any (e 0))"
                               "  (any ()))",
                               oid,
                               bag_value,
                               attr_node) != SSH_ASN1_STATUS_OK)
        {
          return SSH_PKCS12_ERROR;
        }

      list = ssh_asn1_add_list(list, bag_node);
    }

  if (ssh_asn1_create_node(asn1,
                           &seq,
                           "(sequence () (any ()))",
                           list) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS12_ERROR;

  if (ssh_asn1_encode_node(asn1, seq) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }
  if (ssh_asn1_node_get_data(seq,
                             &data,
                             &data_len) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  pkcs7 = ssh_pkcs7_create_data(data, data_len);
  ssh_free(data);

  switch (safe->protection)
    {
    case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
      p = ssh_pkcs12_convert_to_unicode(
                    safe->protect_params.password.password, &p_len);

      pkcs7_prot = ssh_pkcs7_create_encrypted_data(
                                  pkcs7,
                                  safe->protect_params.password.pbe_oid,
                                  p, p_len);
      ssh_free(p);
      break;

    case SSH_PKCS12_SAFE_ENCRYPT_PUBKEY:
      pkcs7_prot = ssh_pkcs7_create_enveloped_data(pkcs7,
                    safe->protect_params.pubkey.data_encrypt_alg,
                    safe->protect_params.pubkey.recipient);
      /* set to NULL, because ssh_pkcs7_create_enveloped_data takes an
         ownership of the recipients and we don't want the
         safe destroy function to free the recipients twice.
         (ssh_pkcs7_free will destroy also the recipients). */
      safe->protect_params.pubkey.recipient = NULL;
      break;

    default:
      pkcs7_prot = pkcs7;
      break;
    }
  if (safe->content)
    ssh_pkcs7_free(safe->content);

  safe->content = pkcs7_prot;
  if (ssh_pkcs7_encode(pkcs7_prot, &data, &data_len) != SSH_PKCS7_OK)
    {
      return SSH_PKCS12_ERROR;
    }
  if (ssh_asn1_decode_node(asn1,
                           data, data_len,
                           node) != SSH_ASN1_STATUS_OK)
    {
      ssh_free(data);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(data);
  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_decode_safe_bag(SshAsn1Context asn1,
                           SshAsn1Node node,
                           SshPkcs12Bag bag)
{
  unsigned char *data;
  size_t data_len;
  SshPkcs12Safe safe;
  SshPkcs12Status status;

  if (ssh_asn1_node_get_data(node, &data, &data_len) != SSH_ASN1_STATUS_OK)
    {
      return SSH_PKCS12_ERROR;
    }

  status = ssh_pkcs12_safe_decode(asn1, node, &safe);
  if (status == SSH_PKCS12_OK)
    {
      bag->type_attr.safe = safe;
    }
  ssh_free(data);
  return status;
}

static SshPkcs12Status
ssh_pkcs12_pfx_decode_authenticated_safe(SshPkcs12PFX pfx)
{
  SshAsn1Context asn1;
  SshAsn1Tree seq;
  SshAsn1Node safe_node;
  SshPkcs7 signed_content;
  const unsigned char *data;
  size_t data_len;
  SshPkcs12Safe safe;

  switch (pfx->integrity)
    {
    case SSH_PKCS12_INTEGRITY_NONE:
    case SSH_PKCS12_INTEGRITY_PASSWORD:
      if (!ssh_pkcs7_content_data(pfx->authSafe, &data, &data_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("authSafe doesn't contain data."));
          return SSH_PKCS12_FORMAT_ERROR;
        }
      break;
    case SSH_PKCS12_INTEGRITY_PUBKEY:
      signed_content = ssh_pkcs7_get_content(pfx->authSafe);
      if (!signed_content ||
          !ssh_pkcs7_content_data(signed_content, &data, &data_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Signed authSafe doesn't contain data."));
          return SSH_PKCS12_FORMAT_ERROR;
        }
      break;
    default:
      SSH_NOTREACHED;
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if ((asn1 = ssh_asn1_init()) == NULL)
    return SSH_PKCS12_ERROR;

  if (ssh_asn1_decode(asn1,
                      data, data_len,
                      &seq) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_FORMAT_ERROR;
    }

  safe_node = ssh_asn1_get_current(seq);
  safe_node = ssh_asn1_node_child(safe_node);

  while (safe_node != NULL)
    {
      if (ssh_pkcs12_safe_decode(asn1, safe_node, &safe) == SSH_PKCS12_OK)
        ssh_pkcs12_pfx_add_safe(pfx, safe);
      safe_node = ssh_asn1_node_next(safe_node);
    }
  ssh_asn1_free(asn1);
  return SSH_PKCS12_OK;
}

/*
  Decodes the PFX structure.
*/
SshPkcs12Status
ssh_pkcs12_pfx_decode(const unsigned char *data,
                      size_t data_len,
                      SshPkcs12IntegrityMode *type_ret,
                      SshPkcs12PFX *pfx_ret)
{
  SshPkcs12Status status;
  SshPkcs12PFX pfx;
  SshAsn1Context asn1;
  SshAsn1Tree asn1_tree;
  SshAsn1Node content_info, mac_data;
  unsigned char *pkcs7_data;
  size_t pkcs7_data_len;
  SshWord version;
  Boolean has_mac;

  if ((pfx = ssh_calloc(1, sizeof(*pfx))) == NULL)
    return SSH_PKCS12_ERROR;

  if ((asn1 = ssh_asn1_init()) == NULL)
    {
      ssh_free(pfx);
    return SSH_PKCS12_ERROR;
    }

  if (ssh_asn1_decode(asn1,
                      data, data_len,
                      &asn1_tree) != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Couldn't ASN.1 decode the data."));
      status = SSH_PKCS12_FORMAT_ERROR;
      goto finish;
    }
  if (ssh_asn1_read_tree(asn1,
                         asn1_tree,
                         "(sequence (*)"
                         "  (integer-short ())"
                         "  (any ())"
                         "  (optional (any ())))",
                         &version,
                         &content_info,
                         &has_mac, &mac_data) != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Couldn't read the ASN.1 structure."));
      status = SSH_PKCS12_FORMAT_ERROR;
      goto finish;
    }

  if (ssh_asn1_node_get_data(content_info,
                             &pkcs7_data,
                             &pkcs7_data_len) != SSH_ASN1_STATUS_OK)
    {
      status = SSH_PKCS12_FORMAT_ERROR;
      goto finish;
    }

  if (ssh_pkcs7_decode(pkcs7_data,
                       pkcs7_data_len,
                       &pfx->authSafe) != SSH_PKCS7_OK)
    {
      ssh_free(pkcs7_data);
      status = SSH_PKCS12_FORMAT_ERROR;
      goto finish;
    }
  ssh_free(pkcs7_data);

  switch (ssh_pkcs7_get_content_type(pfx->authSafe))
    {
    case SSH_PKCS7_DATA:
      if (has_mac)
        {
          /* password integrity mode */
          pfx->integrity = SSH_PKCS12_INTEGRITY_PASSWORD;
          status = ssh_pkcs12_pfx_decode_mac(pfx, asn1, mac_data);
          if (status != SSH_PKCS12_OK)
            goto finish;
        }
      else
        {
          /* No integrity check */
          pfx->integrity = SSH_PKCS12_INTEGRITY_NONE;
        }
      break;
    case SSH_PKCS7_SIGNED_DATA:
      /* public key integrity mode */
      pfx->integrity = SSH_PKCS12_INTEGRITY_PUBKEY;
      break;
    default:
      status = SSH_PKCS12_FORMAT_ERROR;
      goto finish;
    }

  status = ssh_pkcs12_pfx_decode_authenticated_safe(pfx);

finish:
  ssh_asn1_free(asn1);
  if (status != SSH_PKCS12_OK)
    {
      ssh_pkcs12_pfx_free(pfx);
      pfx_ret = NULL;
    }
  else
    {
      if (pfx_ret)
        *pfx_ret = pfx;
      else
        ssh_pkcs12_pfx_free(pfx);
      if (type_ret)
        *type_ret = pfx->integrity;
    }
  return status;
}


SshPkcs12Status
ssh_pkcs12_pfx_get_recipients(SshPkcs12PFX pfx,
                              SshUInt32 *num_recipients,
                              SshPkcs7RecipientInfo **recipients)
{
  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PUBKEY)
    {
      SSH_DEBUG(SSH_D_ERROR, ("PFX isn't protected with public key."));
      return SSH_PKCS12_INVALID_TYPE;
    }
  *num_recipients = ssh_pkcs7_get_recipients(pfx->authSafe, recipients);
  return SSH_PKCS12_OK;
}

/*
  Returns all the signers of the PFX structure. Caller must free
  the returned pointer with ssh_free.
*/
SshPkcs12Status
ssh_pkcs12_pfx_get_signers(SshPkcs12PFX pfx,
                           SshUInt32 *num_signers,
                           SshPkcs7SignerInfo **signers)
{
  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PUBKEY)
    {
      SSH_DEBUG(SSH_D_ERROR, ("PFX isn't protected with public key."));
      return SSH_PKCS12_INVALID_TYPE;
    }

  *num_signers = ssh_pkcs7_get_signers(pfx->authSafe, signers);

  return SSH_PKCS12_OK;
}

/*
  Gets signers certificate. This can be used to get the public
  key of the signer. This public key is needed to verify
  the PFX contents.
*/
SshPkcs12Status
ssh_pkcs12_pfx_signer_get_certificate(SshPkcs12PFX pfx,
                                      SshPkcs7SignerInfo signer,
                                      unsigned char **cert_ret,
                                      size_t *cert_len_ret)
{
  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PUBKEY)
    {
      SSH_DEBUG(SSH_D_ERROR, ("PFX isn't protected with public key."));
      return SSH_PKCS12_INVALID_TYPE;
    }

  *cert_ret = ssh_pkcs7_signer_get_certificate(pfx->authSafe,
                                               signer,
                                               cert_len_ret);
  if (*cert_ret)
    return SSH_PKCS12_OK;
  else
    return SSH_PKCS12_ERROR;
}

/*
  Verifies the PFX contents with public key.
*/
SshPkcs12Status
ssh_pkcs12_pfx_verify(SshPkcs12PFX pfx,
                      SshPkcs7SignerInfo signer,
                      SshPublicKey pubkey)
{
  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PUBKEY)
    {
      SSH_DEBUG(SSH_D_ERROR, ("PFX isn't protected with public key."));
      return SSH_PKCS12_INVALID_TYPE;
    }

  if (ssh_pkcs7_content_verify(pfx->authSafe, signer, pubkey))
    return SSH_PKCS12_OK;
  else
   return SSH_PKCS12_ERROR;
}

static void
pkcs12_content_verify_destroy(Boolean aborted, void *context)
{
  ssh_free(context);
}

static void
pkcs12_content_verify_done(SshPkcs7Status status,
                           SshPkcs7 content,
                           void *context)
{
  Pkcs12EncodeCtx ec = context;

  (*ec->status_callback)((status == SSH_PKCS7_OK)
                         ? SSH_PKCS12_OK
                         : SSH_PKCS12_FORMAT_ERROR,
                         ec->context);
  ssh_free(ec);
}

SshOperationHandle
ssh_pkcs12_pfx_verify_async(SshPkcs12PFX pfx,
                            SshPkcs7SignerInfo signer,
                            SshPublicKey pubkey,
                            SshPkcs12StatusCB callback,
                            void *callback_context)
{
  SshOperationHandle op;
  Pkcs12EncodeCtx ec;

  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PUBKEY)
    {
      (*callback)(SSH_PKCS12_INVALID_TYPE, callback_context);
      return NULL;

    }

  if ((ec = ssh_calloc(1, sizeof(*ec))) == NULL)
    {
      (*callback)(SSH_PKCS12_INVALID_TYPE, callback_context);
      return NULL;
    }

  ec->op = NULL;
  ec->callback = NULL_FNPTR;
  ec->status_callback = callback;
  ec->context = callback_context;
  ec->pfx = pfx;

  op = ssh_pkcs7_content_verify_async(pfx->authSafe, signer, pubkey,
                                      pkcs12_content_verify_done,
                                      ec);
  ssh_operation_attach_destructor(op,
                                  pkcs12_content_verify_destroy, ec);
  return op;
}


#define SHA1_OUTPUT_SIZE 20

static SshPkcs12Status
ssh_pkcs12_create_hmac(const unsigned char *data,
                       size_t data_len,
                       SshStr passwd,
                       const char *digest_alg,
                       SshWord iterations,
                       const unsigned char *salt,
                       size_t salt_len,
                       unsigned char *digest_buf)

{


  SshMac mac;
  unsigned char key[SHA1_OUTPUT_SIZE], *p;
  size_t key_len, p_len;

  key_len = SHA1_OUTPUT_SIZE;

  p = ssh_pkcs12_convert_to_unicode(passwd, &p_len);
  if (!ssh_pkcs12_derive_random(key_len,
                                SSH_PKCS12_DIVERSIFY_MAC,
                                digest_alg,
                                iterations,
                                p, p_len,
                                salt, salt_len,
                                key))
    {
      ssh_free(p);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(p);

  if (ssh_mac_allocate("hmac-sha1",
                       key, key_len,
                       &mac) != SSH_CRYPTO_OK)
    {
      memset(&key, 0, sizeof(key));
      return SSH_PKCS12_ERROR;
    }
  memset(&key, 0, sizeof(key));

  ssh_mac_update(mac, data, data_len);
  ssh_mac_final(mac, digest_buf);
  ssh_mac_free(mac);
  return SSH_PKCS12_OK;
}

/*
  Verifies the PFX contets using HMAC.
*/
SshPkcs12Status
ssh_pkcs12_pfx_verify_hmac(SshPkcs12PFX pfx,
                           SshStr password)
{
  SshPkcs12Status status;
  const unsigned char *data;
  unsigned char digest[SHA1_OUTPUT_SIZE];
  size_t data_len;

  if (pfx->integrity != SSH_PKCS12_INTEGRITY_PASSWORD)
    {
      SSH_DEBUG(SSH_D_ERROR, ("PFX isn't protected with password."));
      return SSH_PKCS12_INVALID_TYPE;
    }

  if (!ssh_pkcs7_content_data(pfx->authSafe, &data, &data_len))
    {
      return SSH_PKCS12_ERROR;
    }

  status = ssh_pkcs12_create_hmac(data,
                                  data_len,
                                  password,
                                  pfx->mac->digest_alg,
                                  pfx->mac->iterations,
                                  pfx->mac->salt,
                                  pfx->mac->salt_len,
                                  digest);

  if (!status)
    {
      if (!memcmp(pfx->mac->digest, digest, SHA1_OUTPUT_SIZE))
        status = SSH_PKCS12_OK;
      else
        status = SSH_PKCS12_ERROR;
    }

  return status;
}

static SshPkcs12Status
ssh_pkcs12_pfx_build_hmac(SshPkcs12PFX pfx,
                          SshStr passwd)
{
  int i;
  const unsigned char *data;
  size_t data_len;
  SshPkcs12Status status;

  if (!ssh_pkcs7_content_data(pfx->authSafe,
                              &data,
                              &data_len))
    return SSH_PKCS12_ERROR;

  if (pfx->mac)
    ssh_pkcs12_mac_data_destroy(pfx->mac);

  if ((pfx->mac = ssh_calloc(1, sizeof(*pfx->mac))) == NULL)
    return SSH_PKCS12_ERROR;

  pfx->mac->iterations = 2000;
  if ((pfx->mac->digest_alg = ssh_strdup("sha1")) == NULL)
    {
      ssh_pkcs12_mac_data_destroy(pfx->mac);
      return SSH_PKCS12_ERROR;
    }

  pfx->mac->salt_len = 8;
  if ((pfx->mac->salt = ssh_malloc(pfx->mac->salt_len)) == NULL)
    {
      ssh_pkcs12_mac_data_destroy(pfx->mac);
      return SSH_PKCS12_ERROR;
    }
  for (i = 0; i < pfx->mac->salt_len; i++)
    pfx->mac->salt[i] = ssh_random_get_byte();
  pfx->mac->digest_len = SHA1_OUTPUT_SIZE;

  if ((pfx->mac->digest = ssh_malloc(pfx->mac->digest_len)) == NULL)
    {
      ssh_pkcs12_mac_data_destroy(pfx->mac);
      return SSH_PKCS12_ERROR;
    }

  status = ssh_pkcs12_create_hmac(data, data_len,
                                  passwd,
                                  pfx->mac->digest_alg,
                                  pfx->mac->iterations,
                                  pfx->mac->salt, pfx->mac->salt_len,
                                  pfx->mac->digest);
  if (status)
    {
      ssh_pkcs12_mac_data_destroy(pfx->mac);
      pfx->mac = NULL;
    }

  return status;
}


SshPkcs12Status
ssh_pkcs12_pfx_encode_content(SshPkcs12PFX pfx)
{
  SshPkcs12Status status;
  SshAsn1Context asn1;
  SshAsn1Node list = NULL, safe_node, seq;
  unsigned char *data;
  size_t data_len;
  SshUInt32 i;

  if ((asn1 = ssh_asn1_init()) == NULL)
    return SSH_PKCS12_ERROR;

  for (i = 0; i < pfx->num_safes; i++)
    {
      status = ssh_pkcs12_safe_encode(asn1, &safe_node, pfx->safes[i]);
      if (status != SSH_PKCS12_OK)
        {
          ssh_asn1_free(asn1);
          return SSH_PKCS12_ERROR;
        }
      list = ssh_asn1_add_list(list, safe_node);
    }

  if (ssh_asn1_create_node(asn1,
                           &seq,
                           "(sequence ()"
                           "  (any()))",
                           list) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }

  if (ssh_asn1_encode_node(asn1, seq) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }
  if (ssh_asn1_node_get_data(seq, &data, &data_len) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }

  if (pfx->authSafe)
    ssh_pkcs7_free(pfx->authSafe);

  pfx->authSafe = ssh_pkcs7_create_data(data, data_len);
  ssh_free(data);
  ssh_asn1_free(asn1);
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_encode_i(SshPkcs12PFX pfx,
                    unsigned char **data_ret,
                    size_t *data_len_ret)
{
  SshPkcs12Status status;
  unsigned char *pkcs7_data;
  size_t pkcs7_data_len;
  SshAsn1Context asn1;
  SshAsn1Node pkcs7_node, mac_node = NULL, pfx_node;

  if (ssh_pkcs7_encode(pfx->authSafe,
                       &pkcs7_data,
                       &pkcs7_data_len) != SSH_PKCS7_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Couldn't encode the PKCS7 content."));
      return SSH_PKCS12_ERROR;
    }

  if ((asn1 = ssh_asn1_init()) == NULL ||
      ssh_asn1_decode_node(asn1,
                           pkcs7_data, pkcs7_data_len,
                           &pkcs7_node) != SSH_ASN1_STATUS_OK)
    {
      ssh_free(pkcs7_data);
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(pkcs7_data);

  if (pfx->mac)
    {
      status = ssh_pkcs12_pfx_encode_mac(pfx, asn1, &mac_node);
      if (status != SSH_PKCS12_OK)
        {
          ssh_asn1_free(asn1);
          return status;
        }
    }

  if (ssh_asn1_create_node(asn1,
                           &pfx_node,
                           "(sequence ()"
                           "  (integer-short ())"
                           "  (any ())"
                           "  (any ()))",
                           SSH_PKCS12_VERSION,
                           pkcs7_node,
                           mac_node) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }
  if (ssh_asn1_encode_node(asn1, pfx_node) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }
  if (ssh_asn1_node_get_data(pfx_node,
                             data_ret,
                             data_len_ret) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1);
      return SSH_PKCS12_ERROR;
    }
  ssh_asn1_free(asn1);
  return SSH_PKCS12_OK;
}

static void
ssh_pkcs12_free_encode(Pkcs12EncodeCtx ctx, Boolean abort)
{
  if (abort)
    ssh_operation_abort(ctx->sub_op);
  else
    ssh_operation_unregister(ctx->op);
  ssh_free(ctx);
}

static void
ssh_pkcs12_abort_encode(void *context)
{
  ssh_pkcs12_free_encode(context, TRUE);
}

static void
ssh_pkcs12_encode_signed_data_done(SshPkcs7Status status,
                                   SshPkcs7 signed_content,
                                   void *context)
{
  Pkcs12EncodeCtx ctx = context;
  SshPkcs12PFX pfx = ctx->pfx;
  SshPkcs12Status pkcs12_status;
  unsigned char *data = NULL;
  size_t data_len = 0;

  if (status != SSH_PKCS7_OK)
    {
      (*ctx->callback)(SSH_PKCS12_ERROR, NULL, 0, ctx->context);
      ssh_pkcs12_free_encode(ctx, FALSE);
      return;
    }
  pfx->authSafe = signed_content;
  pkcs12_status = ssh_pkcs12_encode_i(pfx, &data, &data_len);
  (*ctx->callback)(pkcs12_status, data, data_len, ctx->context);
  if (pkcs12_status == SSH_PKCS12_OK)
    ssh_free(data);
  ssh_pkcs12_free_encode(ctx, FALSE);
}

/*
  Encodes the PFX using public key integrity protection.
*/
SshOperationHandle
ssh_pkcs12_pfx_encode_pubkey(SshPkcs12PFX pfx,
                             SshPkcs7SignerInfo signer,
                             SshPkcs12PFXEncodeCB callback,
                             void *context)
{
  SshPkcs12Status status;
  Pkcs12EncodeCtx ctx;
  SshOperationHandle op;

  status = ssh_pkcs12_pfx_encode_content(pfx);
  if (status)
    {
      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    {
      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  ctx->op = ssh_operation_register(ssh_pkcs12_abort_encode, ctx);
  ctx->callback = callback;
  ctx->context = context;
  ctx->pfx = pfx;

  op = ssh_pkcs7_create_signed_data_async(pfx->authSafe,
                                          signer,
                                          ssh_pkcs12_encode_signed_data_done,
                                          ctx);
  if (op)
    {
      ctx->sub_op = op;
      return ctx->op;
    }
  return NULL;
}

/*
  Encodes the PFX using the HMAC integrity protection.
*/
SshPkcs12Status
ssh_pkcs12_encode_hmac(SshPkcs12PFX pfx,
                       SshStr password,
                       unsigned char **data_ret,
                       size_t *data_len_ret)
{
  SshPkcs12Status status;

  status = ssh_pkcs12_pfx_encode_content(pfx);
  if (!status)
    status = ssh_pkcs12_pfx_build_hmac(pfx, password);
  if (!status)
    status = ssh_pkcs12_encode_i(pfx, data_ret, data_len_ret);
  return status;
}

/*
  Adds a Safe to the PFX. Safe is owned by the PFX after this call
  and is destroyed when PFX is destroyed.
*/
SshUInt32
ssh_pkcs12_pfx_add_safe(SshPkcs12PFX pfx, SshPkcs12Safe safe)
{
  SshPkcs12Safe *tmp;
  size_t oldsize = pfx->allocated_safes * sizeof(tmp);

  if (pfx->num_safes == pfx->allocated_safes)
    {
      pfx->allocated_safes += 5;
      if ((tmp =
           ssh_realloc(pfx->safes, oldsize,
                       pfx->allocated_safes * sizeof(SshPkcs12Safe))) == NULL)
        {
          ssh_pkcs12_safe_destroy(safe);
          return pfx->num_safes;
        }
      pfx->safes = tmp;
    }
  pfx->safes[pfx->num_safes++] = safe;
  return pfx->num_safes;
}

/*
  Gets the number of Safes the PFX contains.
*/
SshUInt32
ssh_pkcs12_pfx_get_num_safe(SshPkcs12PFX pfx)
{
  return pfx->num_safes;
}

/*
  Returns one of the Safes contained by the PFX. Index has to
  be from zero to N-1, where N is a value obtained by
  calling ssh_pkcs12_pfx_get_num_safe function. */
SshPkcs12Status
ssh_pkcs12_pfx_get_safe(SshPkcs12PFX pfx,
                        SshUInt32 index,
                        SshPkcs12SafeProtectionType *prot_type_ret,
                        SshPkcs12Safe *safe_ret)
{
  if (index >= pfx->num_safes)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Too big safe index."));
      return SSH_PKCS12_INVALID_INDEX;
    }
  *prot_type_ret = pfx->safes[index]->protection;
  *safe_ret = pfx->safes[index];
  return SSH_PKCS12_OK;
}

/*
  Returns the protection type of a safe
*/
SshPkcs12SafeProtectionType
ssh_pkcs12_safe_get_protection_type(SshPkcs12Safe safe)
{
  return safe->protection;
}

/*
  Creates a safe with no protection (plaintext).
*/
SshPkcs12Safe
ssh_pkcs12_create_safe(void)
{
  SshPkcs12Safe safe;

  if ((safe = ssh_calloc(1, sizeof(*safe))) != NULL)
    safe->protection = SSH_PKCS12_SAFE_ENCRYPT_NONE;
  return safe;
}

/*
  Creates a password protected safe. Pbe is given as standard name and can
  be one of the following: 'pbeWithSHAAnd3-KeyTripleDES-CBC',
  'pbeWithSHAAnd2-KeyTripleDES-CBC'.
*/
SshPkcs12Safe
ssh_pkcs12_create_password_protected_safe(const char *pkcs12_pbe,
                                          SshStr password)
{
  const SshOidStruct *oid;
  SshPkcs12Safe safe;

  oid = ssh_oid_find_by_std_name_of_type(
                (pkcs12_pbe)?(pkcs12_pbe):(DEFAULT_PKCS12_SAFE_PBE),
                SSH_OID_PKCS12);
  if (!oid)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unsupported PBE type: %s", pkcs12_pbe));
      return NULL;
    }

  if ((safe = ssh_calloc(1, sizeof(*safe))) != NULL)
    {
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_PASSWORD;
      if ((safe->protect_params.password.pbe_oid = ssh_strdup(oid->oid))
          == NULL)
        {
          ssh_free(safe);
          return NULL;
        }
      safe->protect_params.password.password =  ssh_str_dup(password);
    }
  return safe;
}
/*
  Creates a public key protected safe.
*/
SshPkcs12Safe
ssh_pkcs12_create_pubkey_protected_safe(const char *data_encryption_alg,
                                        SshPkcs7RecipientInfo recipient)
{
  SshPkcs12Safe safe;

  if ((safe = ssh_calloc(1, sizeof(*safe))) != NULL)
    {
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_PUBKEY;

      if ((safe->protect_params.pubkey.data_encrypt_alg =
           ssh_strdup(data_encryption_alg)) == NULL)
        {
          ssh_free(safe);
          return NULL;
        }
      safe->protect_params.pubkey.recipient = recipient;
    }
  return safe;
}

/*
  Gets recipients from public key protected safe
*/
SshPkcs12Status
ssh_pkcs12_safe_get_recipient(SshPkcs12Safe safe,
                              SshUInt32 *recipient_count,
                              SshPkcs7RecipientInfo **recipients)
{
  if (safe->protection != SSH_PKCS12_SAFE_ENCRYPT_PUBKEY)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Safe is not protected with public key."));
      return SSH_PKCS12_INVALID_TYPE;
    }
  *recipient_count = ssh_pkcs7_get_recipients(safe->content, recipients);
  return SSH_PKCS12_OK;
}

typedef struct SafeDecryptCtxRec {
  SshOperationHandle op, sub_op;
  SshPkcs12StatusCB callback;
  void *context;
  SshPkcs12Safe safe;
} *SafeDecryptCtx;

static void
safe_decrypt_free(SafeDecryptCtx ctx, Boolean abort)
{
  if (abort)
    ssh_operation_abort(ctx->sub_op);
  else
    ssh_operation_unregister(ctx->op);
  ssh_free(ctx);
}

static void
safe_decrypt_abort(void *context)
{
  safe_decrypt_free(context, TRUE);
}

static void
decrypt_done_cb(SshPkcs7Status status,
                SshPkcs7 content,
                void *context)
{
  SshPkcs12Status pkcs12_status;
  SafeDecryptCtx ctx = context;

  if (status == SSH_PKCS7_OK)
    {
      if (ctx->safe->content != content)
        ssh_pkcs7_free(ctx->safe->content);
      ctx->safe->protection = SSH_PKCS12_SAFE_ENCRYPT_NONE;
      ctx->safe->content = content;
      pkcs12_status = ssh_pkcs12_safe_decode_content(ctx->safe);
    }
  else
    pkcs12_status = SSH_PKCS12_ERROR;

  if (ctx->callback)
    (*ctx->callback)(pkcs12_status, ctx->context);
  safe_decrypt_free(ctx, FALSE);
}


SshOperationHandle
ssh_pkcs12_safe_decrypt_private_key(SshPkcs12Safe safe,
                                    SshPkcs7RecipientInfo recipient,
                                    const SshPrivateKey privatekey,
                                    SshPkcs12StatusCB callback,
                                    void *context)
{
  SshOperationHandle op;
  SafeDecryptCtx ctx;

  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    {
    error:
      (*callback)(SSH_PKCS12_ERROR, context);
      ssh_free(ctx);
      return NULL;
    }

  if ((ctx->op = ssh_operation_register(safe_decrypt_abort, ctx)) == NULL)
    goto error;

  ctx->callback = callback;
  ctx->context = context;
  ctx->safe = safe;
  op = ssh_pkcs7_content_decrypt_async(safe->content,
                                       recipient,
                                       privatekey,
                                       decrypt_done_cb,
                                       ctx);
  if (op)
    {
      ctx->sub_op = op;
      return ctx->op;
    }
  return NULL;
}


SshPkcs12Status
ssh_pkcs12_safe_decrypt_password(SshPkcs12Safe safe,
                                 SshStr password)
{
  unsigned char *p;
  size_t p_len;

  p = ssh_pkcs12_convert_to_unicode(password, &p_len);

  if (ssh_pkcs7_content_decrypt_data(safe->content,
                                     p,
                                     p_len))
    {
      safe->protection = SSH_PKCS12_SAFE_ENCRYPT_NONE;
      ssh_free(p);
      return ssh_pkcs12_safe_decode_content(safe);
    }
  ssh_free(p);
  return SSH_PKCS12_ERROR;
}
/*
  Adds a SafeBag to the safe. Bag is owned by the safe after this
  call and is destroyed, when the safe is destroyed.
*/
SshUInt32
ssh_pkcs12_safe_add_bag(SshPkcs12Safe safe, SshPkcs12Bag bag)
{
  SshPkcs12Bag *tmp;
  size_t oldsize = safe->allocated_bags * sizeof(tmp);

  if (safe->num_bags == safe->allocated_bags)
    {
      safe->allocated_bags += 5;
      if ((tmp = ssh_realloc(safe->bags, oldsize,
                             safe->allocated_bags*sizeof(SshPkcs12Bag)))
          == NULL)
        {
          ssh_pkcs12_bag_destroy(bag);
          return safe->num_bags;
        }
      safe->bags = tmp;
    }
  safe->bags[safe->num_bags++] = bag;
  return safe->num_bags;
}

/*
  Returns the number of SafeBags contained by the safe
*/
SshUInt32
ssh_pkcs12_safe_get_num_bags(SshPkcs12Safe safe)
{
  return safe->num_bags;
}

/*
  Gets the SafeBag from the safe with an index. Index is from
  zero to N-1, where N is the number returned by
  ssh_pkcs12_safe_get_num_bags function. Also returns the
  bag type.
*/
SshPkcs12Status
ssh_pkcs12_safe_get_bag(SshPkcs12Safe safe,
                        SshUInt32 index,
                        SshPkcs12BagType *type_ret,
                        SshPkcs12Bag *bag_ret)
{
  if (index >= safe->num_bags)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid bag index."));
      return SSH_PKCS12_INVALID_INDEX;
    }
  *bag_ret = safe->bags[index];
  *type_ret = safe->bags[index]->type;
  return SSH_PKCS12_OK;
}

void
ssh_pkcs12_bag_add_friendly_name_attr(SshPkcs12Bag bag,
                                      SshStr name)
{
  SshPkcs12Attribute attr;

  if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
    {
      attr->type = SSH_PKCS12_ATTR_FRIENDLY_NAME;
      attr->v.name = ssh_str_charset_convert(name, SSH_CHARSET_BMP);
      (void) ssh_pkcs12_bag_add_attribute(bag, attr);
    }
}

void
ssh_pkcs12_bag_add_local_key_id_attr(SshPkcs12Bag bag,
                                     const unsigned char *kid,
                                     size_t kid_len)
{
  SshPkcs12Attribute attr;

  if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
    {
      attr->type = SSH_PKCS12_ATTR_LOCAL_KEY_ID;
      if ((attr->v.id.data = ssh_memdup(kid, kid_len)) != NULL)
        attr->v.id.len = kid_len;
      (void)ssh_pkcs12_bag_add_attribute(bag, attr);
    }
}

void
ssh_pkcs12_bag_add_unknown_attr(SshPkcs12Bag bag,
                                const char *oid,
                                const unsigned char *data,
                                size_t data_len)
{
  SshPkcs12Attribute attr;

  if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
    {
      attr->type = SSH_PKCS12_ATTR_UNKNOWN;
      if ((attr->v.unknown.oid = ssh_strdup(oid)) == NULL ||
          (attr->v.unknown.ber = ssh_memdup(data, data_len)) == NULL)
        {
          ssh_free(attr->v.unknown.oid);
          ssh_free(attr->v.unknown.ber);
          ssh_free(attr);
        }
      else
        {
          attr->v.unknown.ber_len = data_len;
          (void)ssh_pkcs12_bag_add_attribute(bag, attr);
        }
    }
}


SshUInt32
ssh_pkcs12_bag_get_num_attributes(SshPkcs12Bag bag)
{
  return bag->num_attr;
}

SshPkcs12Status
ssh_pkcs12_bag_get_attribute(SshPkcs12Bag bag,
                             SshUInt32 index,
                             SshPkcs12AttributeType *type_ret,
                             SshPkcs12Attribute *attr_ret)
{
  if (index >= bag->num_attr)
    {
      return SSH_PKCS12_INVALID_INDEX;
    }
  *attr_ret = bag->attr[index];
  *type_ret = bag->attr[index]->type;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_attr_get_friendly_name(SshPkcs12Attribute attr,
                                  SshStr *name_ret)
{
  if (attr->type != SSH_PKCS12_ATTR_FRIENDLY_NAME)
    {
      return SSH_PKCS12_INVALID_TYPE;
    }
  *name_ret = attr->v.name;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_attr_get_local_key_id(SshPkcs12Attribute attr,
                                 unsigned char const **kid_ret,
                                 size_t *kid_len_ret)
{
  if (attr->type != SSH_PKCS12_ATTR_LOCAL_KEY_ID)
    {
      return SSH_PKCS12_INVALID_TYPE;
    }
  *kid_ret = attr->v.id.data;
  *kid_len_ret = attr->v.id.len;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_attr_get_unknown(SshPkcs12Attribute attr,
                            char const **oid_ret,
                            unsigned char const **data_ret,
                            size_t *data_len_ret)
{
  if (attr->type != SSH_PKCS12_ATTR_UNKNOWN)
    {
      return SSH_PKCS12_INVALID_TYPE;
    }
  *oid_ret = attr->v.unknown.oid;
  *data_ret = attr->v.unknown.ber;
  *data_len_ret = attr->v.unknown.ber_len;
  return SSH_PKCS12_OK;
}



/*
  Creates a key bag. Bag contains the private key in PKCS#8 format.
*/
SshPkcs12Status
ssh_pkcs12_create_key_bag(SshPrivateKey key,
                          SshPkcs12Bag *bag_ret)
{
  SshPkcs12Bag bag;

  if ((bag = ssh_calloc(1, sizeof(*bag))) != NULL)
    {
      bag->type = SSH_PKCS12_BAG_KEY;

      if (ssh_pkcs8_encode_private_key(key, &bag->data, &bag->data_len)
          != SSH_X509_OK)
        {
          ssh_free(bag);
          return SSH_PKCS12_ERROR;
        }
      *bag_ret = bag;
      return SSH_PKCS12_OK;
    }
  return SSH_PKCS12_ERROR;
}

/*
  Creates a bag which contains a PKCS#8 shrouded private key.
  Pbe is given as standard name and can be one of the following:
  'pbeWithSHAAnd3-KeyTripleDES-CBC', 'pbeWithSHAAnd2-KeyTripleDES-CBC'
*/
SshPkcs12Status
ssh_pkcs12_create_shrouded_key_bag(SshPrivateKey key,
                                   const char *pkcs12_pbe,
                                   SshStr password,
                                   SshPkcs12Bag *bag_ret)
{
  SshPkcs12Bag bag;
  unsigned char *p;
  size_t p_len;
  const SshOidStruct *oid;

  oid = ssh_oid_find_by_std_name_of_type(
            (pkcs12_pbe)?(pkcs12_pbe):(DEFAULT_PKCS12_KEY_PBE),
            SSH_OID_PKCS12);
  if (!oid)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unsupported PBE type: %s", pkcs12_pbe));
      return SSH_PKCS12_ERROR;
    }

  if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
    return SSH_PKCS12_ERROR;

  bag->type = SSH_PKCS12_BAG_SHROUDED_KEY;

  p = ssh_pkcs12_convert_to_unicode(password, &p_len);
  if (ssh_pkcs8_encrypt_private_key(ssh_custr(oid->oid),
                                    NULL,
                                    p, p_len,
                                    key,
                                    &bag->data, &bag->data_len) != SSH_X509_OK)
    {
      ssh_free(p);
      ssh_free(bag);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(p);
  *bag_ret = bag;
  return SSH_PKCS12_OK;
}

/*
  Creates a bag containing a certificate. Only X.509
  certificates are supported for now.
*/
SshPkcs12Status
ssh_pkcs12_create_cert_bag(const unsigned char *data,
                           size_t data_len,
                           SshPkcs12Bag *bag_ret)
{
#define PKCS9_CERT_OID "1.2.840.113549.1.9.22"

  SshPkcs12Bag bag;

  if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
    return SSH_PKCS12_ERROR;

  bag->type = SSH_PKCS12_BAG_CERT;
  bag->type_attr.oid = ssh_strdup(PKCS9_CERT_OID".1");
  bag->data = ssh_memdup(data, data_len);
  if (bag->data == NULL || bag->type_attr.oid == NULL)
    {
      ssh_free(bag->type_attr.oid);
      ssh_free(bag->data);
      ssh_free(bag);
      return SSH_PKCS12_ERROR;
    }

  bag->data_len = data_len;
  *bag_ret = bag;
  return SSH_PKCS12_OK;
}

/*
  Creates a bag containing a Certificate Revocation List.
  Only X.509 CRLs are supported for now.
*/
SshPkcs12Status
ssh_pkcs12_create_crl_bag(const unsigned char *data,
                          size_t data_len,
                          SshPkcs12Bag *bag_ret)
{
#define PKCS9_CRL_OID "1.2.840.113549.1.9.23"
  SshPkcs12Bag bag;

  if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
    return SSH_PKCS12_ERROR;

  bag->type = SSH_PKCS12_BAG_CRL;
  bag->type_attr.oid = ssh_strdup(PKCS9_CRL_OID".1");
  bag->data = ssh_memdup(data, data_len);
  if (bag->data == NULL || bag->type_attr.oid == NULL)
    {
      ssh_free(bag->type_attr.oid);
      ssh_free(bag->data);
      ssh_free(bag);
      return SSH_PKCS12_ERROR;
    }
  bag->data_len = data_len;
  *bag_ret = bag;
  return SSH_PKCS12_OK;
}

/*
  Creates a bag that contains  user's miscellaneous personal secret.
*/
SshPkcs12Status
ssh_pkcs12_create_secret_bag(const char *oid,
                             const unsigned char *data,
                             size_t data_len,
                             SshPkcs12Bag *bag_ret)
{
  SshPkcs12Bag bag;

  if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
    return SSH_PKCS12_ERROR;

  bag->type = SSH_PKCS12_BAG_SECRET;
  if ((bag->data = ssh_memdup(data, data_len)) == NULL)
    {
      ssh_free(bag);
      return SSH_PKCS12_ERROR;
    }

  bag->data_len = data_len;
  if (oid)
    {
      if ((bag->type_attr.oid = ssh_strdup(oid)) == NULL)
        {
          ssh_free(bag->data);
          ssh_free(bag);
          return SSH_PKCS12_ERROR;
        }
    }

  *bag_ret = bag;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_create_safe_bag(SshPkcs12Safe safe,
                           SshPkcs12Bag *bag_ret)
{
  SshPkcs12Bag bag;

  if ((bag = ssh_calloc(1, sizeof(*bag))) == NULL)
    return SSH_PKCS12_ERROR;

  bag->type = SSH_PKCS12_BAG_SAFE;
  bag->type_attr.safe = safe;
  *bag_ret = bag;
  return SSH_PKCS12_OK;
}

#define CHECK_BAG_TYPE(TYPE) do {       \
  if (bag->type != TYPE)                \
    return SSH_PKCS12_INVALID_BAG_TYPE; \
} while(0)

SshPkcs12Status
ssh_pkcs12_bag_get_key(SshPkcs12Bag bag,
                       SshPrivateKey *key_ret)
{
  CHECK_BAG_TYPE(SSH_PKCS12_BAG_KEY);
  if (ssh_pkcs8_decode_private_key(bag->data,
                                   bag->data_len,
                                   key_ret) != SSH_X509_OK)
    return SSH_PKCS12_ERROR;

  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_bag_get_shrouded_key(SshPkcs12Bag bag,
                                SshStr password,
                                SshPrivateKey *key_ret)
{
  unsigned char *p;
  size_t p_len;

  CHECK_BAG_TYPE(SSH_PKCS12_BAG_SHROUDED_KEY);

  p = ssh_pkcs12_convert_to_unicode(password, &p_len);

  if (ssh_pkcs8_decrypt_private_key(p, p_len,
                                    bag->data, bag->data_len,
                                    key_ret) != SSH_X509_OK)
    {
      ssh_free(p);
      return SSH_PKCS12_ERROR;
    }
  ssh_free(p);
  return SSH_PKCS12_OK;

}

SshPkcs12Status
ssh_pkcs12_bag_get_cert(SshPkcs12Bag bag,
                        unsigned char const **cert_ret,
                        size_t *cert_len_ret)
{
  CHECK_BAG_TYPE(SSH_PKCS12_BAG_CERT);
  *cert_ret = bag->data;
  *cert_len_ret = bag->data_len;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_bag_get_crl(SshPkcs12Bag bag,
                       unsigned char const **crl_ret,
                       size_t *crl_len_ret)
{
  CHECK_BAG_TYPE(SSH_PKCS12_BAG_CRL);
  *crl_ret = bag->data;
  *crl_len_ret = bag->data_len;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_bag_get_secret(SshPkcs12Bag bag,
                          char const **oid_ret,
                          unsigned char const **data_ret,
                          size_t *data_len_ret)
{
  CHECK_BAG_TYPE(SSH_PKCS12_BAG_SECRET);
  *oid_ret = bag->type_attr.oid;
  *data_ret = bag->data;
  *data_len_ret = bag->data_len;
  return SSH_PKCS12_OK;
}

SshPkcs12Status
ssh_pkcs12_bag_get_safe(SshPkcs12Bag bag,
                        SshPkcs12SafeProtectionType *prot_type_ret,
                        SshPkcs12Safe * const safe_ret)
{
  CHECK_BAG_TYPE(SSH_PKCS12_BAG_SAFE);
  *safe_ret = bag->type_attr.safe;
  *prot_type_ret = bag->type_attr.safe->protection;
  return SSH_PKCS12_OK;
}
#endif /* SSHDIST_CERT */
