/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains generic stuff, mainly for hadling lists, extensions (not
   including encoding and decoding) etc.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshmp.h"
#include "sshbuffer.h"
#include "x509.h"
#include "x509internal.h"
#include "sshglobals.h"
#include "oid.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertX509"

SSH_GLOBAL_DEFINE(SshX509ConfigStruct, ssh_x509_library_configuration);
SSH_GLOBAL_DECLARE(SshX509ConfigStruct, ssh_x509_library_configuration);

#define ssh_x509_library_configuration \
  SSH_GLOBAL_USE(ssh_x509_library_configuration)

SshX509Config ssh_x509_get_configuration(void)
{
  return &ssh_x509_library_configuration;
}

void ssh_x509_library_set_default_config(SshX509Config config)
{
  SSH_PRECOND(config != NULL);

  config->cs.treat_printable_as_latin1 = 1;
  config->cs.treat_t61_as_latin1 = 1;
  config->cs.enable_visible_string = 0;
  config->cs.enable_bmp_string = 0;
  config->cs.enable_printable_within_bitstring = 0;

  config->ec.allow_ee_basic_constraints = 0;
}


Boolean ssh_x509_library_initialize_framework(SshX509Config config)
{
  SshX509ConfigStruct c, *cp;

  memset(&c, 0, sizeof(c));

  if (config)
    {
      SSH_GLOBAL_INIT(ssh_x509_library_configuration, *config);
    }
  else
    {
      ssh_x509_library_set_default_config(&c);
      SSH_GLOBAL_INIT(ssh_x509_library_configuration, c);
    }

  cp = ssh_x509_get_configuration();
  memset(cp->encoders, 0, sizeof(cp->encoders));
  return ssh_crypto_system_initialize() == SSH_CRYPTO_OK;
}

Boolean
ssh_x509_library_register_functions(SshX509CertType type,
                                    SshX509CertDecoder decode,
                                    SshX509CertEncoder encode)
{
  SshX509Config conf =  ssh_x509_get_configuration();
  int i;

  for (i = 0; i < SSH_X509_CERT_TYPE_MAX; i++)
    {
      if (conf->encoders[i].type == type)
        return FALSE; /* Already registered */

      if (conf->encoders[i].type == 0)
        {
          conf->encoders[i].type = type;
          conf->encoders[i].decoder = decode;
          conf->encoders[i].encoder = encode;

          return TRUE;
        }
    }
  return FALSE;
}

void ssh_x509_library_uninitialize(void)
{
  ssh_crypto_system_uninitialize();
  return;
}

/* Some routines for handling the extension information. */

void ssh_x509_ext_info_set(SshUInt32 *ext_available,
                           SshUInt32 *ext_critical,
                           unsigned int type,
                           Boolean critical)
{
  *ext_available |= (1 << type);
  if (critical) *ext_critical |= (1 << type);
}

Boolean
ssh_x509_ext_info_available(SshUInt32 ext_available,
                            SshUInt32 ext_critical,
                            unsigned int type,
                            Boolean *critical)
{
  Boolean rv = FALSE;

  if (ext_available & (1 << type))
    {
      rv = TRUE;
      if (critical)
        *critical = !!(ext_critical & (1 << type));
    }
  return rv;
}

/* Some routines for handling lists of names. */

/* Allocate a name. In case of failure return NULL and frees its
   arguments. In success this steals its arguments. */

SshX509Name
ssh_x509_name_alloc(SshX509NameType type,
                    SshDN dn, SshStr name,
                    void *data, size_t data_len,
                    unsigned char *ber_name, size_t ber_name_len)
{
  SshX509Name created   = ssh_malloc(sizeof(*created));

  if (created)
    {
      created->type          = type;
      created->next          = NULL;
      created->dirty         = FALSE;

      created->dn            = dn;
      created->name          = name;
      created->data          = data;
      created->data_len      = data_len;
      created->ber           = ber_name;
      created->ber_len       = ber_name_len;
      created->canon_der     = NULL;
      created->canon_der_len = 0;
    }
  else
    {
      if (dn) { ssh_dn_clear(dn); ssh_free(dn); }
      if (name) ssh_str_free(name);
      if (data && data_len > 0) ssh_free(data);
      if (ber_name && ber_name_len > 0) ssh_free(ber_name);
    }
  return created;
}

/* Copies the namelist pointed by name. The copy will be verbatim
   (e.g. the if the source is dirty, the destination will be dirty as
   well). */
SshX509Name ssh_x509_name_copy(SshX509Name name)
{
  SshX509Name c = NULL, list = NULL;
  SshX509Config config = NULL;

  while (name)
    {
      SshDN dn_copy = NULL;

      if (name->ber == NULL)
        {
          ssh_x509_name_free(list);
          return NULL;
        }

      if (name->ber && name->ber_len)
        dn_copy = ssh_dn_create(name->ber, name->ber_len, config);

      if ((c = ssh_x509_name_alloc(name->type,
                                   dn_copy,
                                   ssh_str_dup(name->name),
                                   ssh_memdup(name->data, name->data_len),
                                   name->data_len,
                                   ssh_memdup(name->ber, name->ber_len),
                                   name->ber_len)) != NULL)
        {
          c->dirty = name->dirty;
          ssh_x509_name_push(&list, c);
        }
      else
        {
          ssh_x509_name_free(c);
          ssh_x509_name_free(list);
          return NULL;
        }

      name = name->next;
    }
  return c;
}

void ssh_x509_name_push(SshX509Name *list,
                        SshX509Name name)
{
  SshX509Name s = name;

  if (name == NULL)
    return;

  for (; name->next; name = name->next)
    ;

  name->next = *list;
  *list = s;
}

SshX509Name ssh_x509_name_pop(SshX509Name *list)
{
  SshX509Name popped = *list;

  if (popped != NULL)
    {
      *list = popped->next;
      /* Remove from the list. */
      popped->next = NULL;
    }
  return popped;
}

/* Free the name and the full list if possible. */
void ssh_x509_name_free(SshX509Name name)
{
  SshX509Name next;

  while (name)
    {
      ssh_str_free(name->name);
      if (name->dn)
        {
          ssh_dn_clear(name->dn);
          ssh_free(name->dn);
        }
      ssh_free(name->data);
      ssh_free((void *) name->ber);
      ssh_free((void *) name->canon_der);
      next = name->next;
      ssh_free(name);
      name = next;
    }
}

/* This is O(n) algorithm for find an entry from the list. This is not
   efficient, however, currently it seems that the name lists will not
   be long. And they cannot be very long due to reasonable space
   limitations of the certificates. */
SshX509Name ssh_x509_name_find(SshX509Name list, SshX509NameType type)
{
  while (list)
    {
      if (list->dirty == FALSE && list->type == type)
        {
          return list;
        }
      list = list->next;
    }
  return NULL;
}

SshX509Name ssh_x509_name_find_i(SshX509Name list, SshX509NameType type)
{
  SshX509Name nlist;
  nlist = ssh_x509_name_find(list, type);
  if (nlist)
    nlist->dirty = TRUE;
  return nlist;
}

SshX509Name ssh_x509_name_find_all(SshX509Name list, SshX509NameType type)
{
  while (list)
    {
      if (list->type == type)
        return list;
      list = list->next;
    }
  return NULL;
}

/* Undirtyfy the list. */
void ssh_x509_name_reset(SshX509Name list)
{
  while (list)
    {
      list->dirty = FALSE;
      list = list->next;
    }
}

/* Public key, and private key routines. */

/* List of all supported algorithms (that is algorithms that are supported
   by PKIX). */

const SshX509PkAlgorithmDefStruct ssh_x509_pk_algorithm_def[] =
{
  /* Ways to use RSA. */
  { "if-modn", "rsa-pkcs1-sha256", NULL,
    "rsaEncryption", "sha256WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-sha384", NULL,
    "rsaEncryption", "sha384WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-sha512", NULL,
    "rsaEncryption", "sha512WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-sha224", NULL,
    "rsaEncryption", "sha224WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-sha1", NULL,
    "rsaEncryption", "sha1WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-md5", NULL,
    "rsaEncryption", "md5WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-md4", NULL,
    "rsaEncryption", "md4WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-md2", NULL,
    "rsaEncryption", "md2WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-ripemd160", NULL,
    "rsaEncryption", "ripemd160WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pkcs1-ripemd128", NULL,
    "rsaEncryption", "ripemd128WithRSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { "if-modn", "rsa-pss-sha1", NULL,
    "rsaEncryption", "sha1WithRSAPSS", NULL,
    SSH_X509_PKALG_PSS },
  /* Ways to use DSA. */
  { "dl-modp", "dsa-nist-sha1", NULL,
    "dsaEncryption", "dsaWithSHA-1", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa-nist-sha", NULL,
    "dsaEncryption", "dsaWithSHA", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa", NULL,
    "dsaEncryption", "dsa", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa-nist-sha224", NULL,
    "dsaEncryption", "dsaWithSHA224", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa-nist-sha256", NULL,
    "dsaEncryption", "dsaWithSHA256", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa-nist-sha384", NULL,
    "dsaEncryption", "dsaWithSHA384", NULL,
    SSH_X509_PKALG_DSA },
  { "dl-modp", "dsa-nist-sha512", NULL,
    "dsaEncryption", "dsaWithSHA512", NULL,
    SSH_X509_PKALG_DSA },
  /* Ways to use Diffie-Hellman. */
  { "dl-modp", NULL, "dh-none",
    "dhEncryption", NULL, NULL,
    SSH_X509_PKALG_DH },
  /* Ways to use ECDSA */
  { "ec-modp", "dsa-none-sha1", NULL,
    "ecdsaEncryption", "ecdsaWithSHA1", NULL,
     SSH_X509_PKALG_ECDSA },
  { "ec-modp", "dsa-none-sha224", NULL,
    "ecdsaEncryption", "ecdsaWithSHA224", NULL,
     SSH_X509_PKALG_ECDSA },
  { "ec-modp", "dsa-none-sha256", NULL,
    "ecdsaEncryption", "ecdsaWithSHA256", NULL,
     SSH_X509_PKALG_ECDSA },
  { "ec-modp", "dsa-none-sha384", NULL,
    "ecdsaEncryption", "ecdsaWithSHA384", NULL,
     SSH_X509_PKALG_ECDSA },
  { "ec-modp", "dsa-none-sha512", NULL,
    "ecdsaEncryption", "ecdsaWithSHA512", NULL,
     SSH_X509_PKALG_ECDSA },
  /* This is here only to satisfy needs of crypto library where the
     keys have no default scheme. Keep it last resort. */
  { "if-modn", "rsa-pkcs1-none", NULL,
    "rsaEncryption", "RSAEncryption", NULL,
    SSH_X509_PKALG_RSA },
  { NULL }
};

const SshX509PkAlgorithmDefStruct *
ssh_x509_match_algorithm(const char *name, const char *sign, const char *dh)
{
  unsigned int i, ok;

  if (name == NULL && sign == NULL)
    return NULL;
  for (i = 0; ssh_x509_pk_algorithm_def[i].name; i++)
    {
      ok = 0;
      if (name)
        {
          ok++;
          if (ssh_x509_pk_algorithm_def[i].name != NULL &&
              strcmp(name, ssh_x509_pk_algorithm_def[i].name) == 0)
            ok--;
        }
      if (sign)
        {
          ok++;
          if (ssh_x509_pk_algorithm_def[i].sign != NULL &&
              strcmp(sign, ssh_x509_pk_algorithm_def[i].sign) == 0)
            ok--;
        }
      if (dh)
        {
          ok++;
          if (ssh_x509_pk_algorithm_def[i].dh != NULL &&
              strcmp(dh, ssh_x509_pk_algorithm_def[i].dh) == 0)
            ok--;
        }

      /* Match found? */
      if (ok == 0)
        return &ssh_x509_pk_algorithm_def[i];
    }
  return NULL;
}

const SshX509PkAlgorithmDefStruct *
ssh_x509_private_key_algorithm(SshPrivateKey key)
{
  char *name, *sign;

  if (key)
    {
      if (ssh_private_key_get_info(key,
                                   SSH_PKF_KEY_TYPE, &name,
                                   SSH_PKF_SIGN,     &sign,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        return NULL;
      return ssh_x509_match_algorithm(name, sign, NULL);
    }
  return NULL;
}

const SshX509PkAlgorithmDefStruct *
ssh_x509_public_key_algorithm(SshPublicKey key)
{
  char *name, *sign;

  if (ssh_public_key_get_info(key,
                              SSH_PKF_KEY_TYPE, &name,
                              SSH_PKF_SIGN,     &sign,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    return NULL;
  return ssh_x509_match_algorithm(name, sign, NULL);
}

const SshX509PkAlgorithmDefStruct *
ssh_x509_public_group_algorithm(SshPkGroup pk_group)
{
  char *name, *dh;

  if (ssh_pk_group_get_info(pk_group,
                            SSH_PKF_KEY_TYPE, &name,
                            SSH_PKF_DH, &dh,
                            SSH_PKF_END) != SSH_CRYPTO_OK)
    return NULL;
  return ssh_x509_match_algorithm(name, NULL, dh);
}

const char *ssh_x509_find_signature_algorithm(SshX509Certificate cert)
{
  if (cert == NULL)
    return NULL;

  return cert->pop.signature.pk_algorithm;
}

const char *ssh_x509_find_ssh_key_type(const char *name)
{
  const SshOidStruct *oid;

  oid = ssh_oid_find_by_std_name_of_type(name, SSH_OID_PK);
  if (oid == NULL)
    return NULL;
  return oid->name;
}

SshX509Status ssh_x509_private_key_set_sign_algorithm(SshPrivateKey key,
                                                      char *algorithm)
{
  const SshOidStruct *oid;

  oid = ssh_oid_find_by_std_name_of_type(algorithm, SSH_OID_SIG);
  if (oid == NULL)
    return SSH_X509_FAILED_UNKNOWN_VALUE;

  if (ssh_private_key_select_scheme(key,
                                    SSH_PKF_SIGN, oid->name,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    return SSH_X509_FAILED_PRIVATE_KEY_OPS;
  return SSH_X509_OK;
}


/* Find the algorithm defined by the given algorithm identifier. The
   return string is in SSH format. */
const char *ssh_x509_find_algorithm(SshAsn1Context context,
                                    SshAsn1Node algorithm_identifier,
                                    SshX509PkAlgorithm *type)
{
  SshAsn1Node params;
  unsigned char *pk_oid;
  const SshOidStruct *oid_entry;
  SshAsn1Status status;

  status =
    ssh_asn1_read_node(context, algorithm_identifier,
                       "(sequence ()"
                       "  (object-identifier ())"  /* object identifier */
                       "  (any ()))",       /* any defined by algorithm */
                       &pk_oid,
                       &params);

  if (status != SSH_ASN1_STATUS_OK)
    {
      /* Maybe it is a crmf */
      SshAsn1Node tmp = ssh_asn1_node_child(algorithm_identifier);
      if (tmp == NULL ||
          ssh_asn1_read_node(context, tmp,
                             "(object-identifier ()) (any ())",
                             &pk_oid, &params) != SSH_ASN1_STATUS_OK)
        return NULL;
    }






  oid_entry = ssh_oid_find_by_oid_of_type(pk_oid, SSH_OID_SIG);
  ssh_free(pk_oid);

  if (oid_entry == NULL)
    return NULL;

  *type = oid_entry->extra_int;
  return oid_entry->name;
}


/****************************************************************/

/* Routines for handling the name type with "nice" interface.
   */

/* Pushing. */
Boolean ssh_x509_name_push_ip(SshX509Name *list,
                              const unsigned char *ip, size_t ip_len)
{
  SshX509Name node;

  if (ip_len == 4 || ip_len == 16)
    {
      if ((node = ssh_x509_name_alloc(SSH_X509_NAME_IP,
                                      NULL, NULL,
                                      ssh_memdup(ip, ip_len), ip_len,
                                      NULL, 0))
          == NULL)
        return FALSE;

      ssh_x509_name_push(list, node);
      return TRUE;
    }
  else
    return FALSE;
}

static Boolean
x509_name_push_string(SshX509Name *list, SshX509NameType kind, const char *s)
{
  SshStr str;
  SshX509Name node;

  if ((str =
       ssh_str_make(SSH_CHARSET_US_ASCII, ssh_strdup(s), strlen(s))) != NULL)
    {
      if ((node = ssh_x509_name_alloc(kind, NULL, str, NULL, 0, NULL, 0))
          != NULL)
        {
          ssh_x509_name_push(list, node);
          return TRUE;
        }
      ssh_str_free(str);
    }
  return FALSE;
}

Boolean ssh_x509_name_push_dns(SshX509Name *list, const char *dns)
{
  return x509_name_push_string(list, SSH_X509_NAME_DNS, dns);
}

Boolean ssh_x509_name_push_email(SshX509Name *list, const char *email)
{
  return x509_name_push_string(list, SSH_X509_NAME_RFC822, email);
}

Boolean ssh_x509_name_push_uri(SshX509Name *list, const char *uri)
{
  return x509_name_push_string(list, SSH_X509_NAME_URI, uri);
}

Boolean ssh_x509_name_push_rid(SshX509Name *list, const char *rid)
{
  SshX509Name node;
  char *tmprid = ssh_strdup(rid);
  if (tmprid == NULL)
    return FALSE;
  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_RID,
                                  NULL, NULL,
                                  tmprid, 0,
                                  NULL, 0))
      == NULL)
    {
      ssh_free(tmprid);
      return FALSE;
    }

  ssh_x509_name_push(list, node);
  return TRUE;
}

Boolean ssh_x509_name_push_principal_name_str(SshX509Name *list,
                                              const SshStr upn)
{
  SshX509Name node;
  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_PRINCIPAL_NAME,
                                  NULL, upn,
                                  NULL, 0, NULL, 0)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  return FALSE;
}

Boolean ssh_x509_name_push_guid(SshX509Name *list,
                                unsigned char *data, size_t len)
{
  SshX509Name node;
  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_GUID,
                                  NULL, NULL,
                                  data, len, NULL, 0)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  return FALSE;
}


static SshDN
x509_name_to_dn(const unsigned char *name,
                unsigned char **der, size_t *der_len,
                SshX509Config config)
{
  SshDN dn;

  if ((dn = ssh_malloc(sizeof(*dn))) == NULL)
    return FALSE;
  ssh_dn_init(dn);

  if (!ssh_dn_decode_ldap(name, dn))
    {
      ssh_dn_clear(dn);
      ssh_free(dn);
      return NULL;
    }
  if (!ssh_dn_encode_der(dn, der, der_len, config))
    {
      ssh_dn_clear(dn);
      ssh_free(dn);
      return NULL;
    }
  return dn;
}

static SshDN
x509_name_string_to_dn(const SshStr name,
                       unsigned char **der, size_t *der_len,
                       SshX509Config config)
{
  SshDN dn;

  if ((dn = ssh_malloc(sizeof(*dn))) == NULL)
    return FALSE;
  ssh_dn_init(dn);

  if (!ssh_dn_decode_ldap_str(name, dn))
    {
      ssh_dn_clear(dn);
      ssh_free(dn);
      return NULL;
    }
  if (!ssh_dn_encode_der(dn, der, der_len, config))
    {
      ssh_dn_clear(dn);
      ssh_free(dn);
      return NULL;
    }
  return dn;
}


Boolean ssh_x509_name_push_directory_name(SshX509Name *list,
                                          const unsigned char *name)
{
  SshDN dn;
  SshX509Name node;
  unsigned char *der;
  size_t der_len;
  SshX509Config config = NULL;

  if ((dn = x509_name_to_dn(name, &der, &der_len, config)) == NULL)
    return FALSE;

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DN,
                                  dn, NULL, NULL, 0,
                                  der, der_len)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }

  ssh_dn_clear(dn); ssh_free(dn);
  ssh_free(der);
  return FALSE;
}

Boolean
ssh_x509_name_push_directory_name_str(SshX509Name *list,
                                      const SshStr str)
{
  SshDN dn;
  SshX509Name node;
  unsigned char *der;
  size_t der_len;
  SshX509Config config = NULL;

  if ((dn = x509_name_string_to_dn(str, &der, &der_len, config)) == NULL)
    return FALSE;

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DN,
                                  dn, ssh_str_dup(str),
                                  NULL, 0, der, der_len)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  ssh_dn_clear(dn); ssh_free(dn);
  ssh_free(der);
  return FALSE;
}

Boolean
ssh_x509_name_push_directory_name_der(SshX509Name *list,
                                      const unsigned char *der,
                                      size_t der_len)
{
  SshX509Name node;
  SshDN dn;
  unsigned char *copy_der;
  SshX509Config config = NULL;

  if ((dn = ssh_dn_create(der, der_len, config)) == NULL)
    return FALSE;

  copy_der = ssh_memdup(der, der_len);

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DN,
                                  dn, NULL,
                                  NULL, 0,
                                  copy_der, der_len))
      != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  ssh_free(copy_der);
  return FALSE;
}

Boolean
ssh_x509_name_push_der_dn(SshX509Name *list,
                          const unsigned char *der,
                          size_t der_len)
{
  SshX509Name node;
  SshDN dn;
  unsigned char *copy_der;
  SshX509Config config = NULL;

  if ((dn = ssh_dn_create(der, der_len, config)) == NULL)
    return FALSE;

  copy_der = ssh_memdup(der, der_len);
  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DISTINGUISHED_NAME,
                                  dn, NULL, NULL, 0,
                                  copy_der, der_len)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  return FALSE;
}

Boolean
ssh_x509_name_push_ldap_dn(SshX509Name *list, const unsigned char *name)
{
  SshDN dn;
  SshX509Name node;
  unsigned char *der;
  size_t der_len;
  SshX509Config config = NULL;

  if ((dn = x509_name_to_dn(name, &der, &der_len, config)) == NULL)
    return FALSE;

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DISTINGUISHED_NAME,
                                  dn, NULL, NULL, 0, der, der_len))
      != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  ssh_dn_clear(dn); ssh_free(dn);
  ssh_free(der);
  return FALSE;
}

Boolean
ssh_x509_name_push_str_dn(SshX509Name *list, const SshStr str)
{
  SshDN dn;
  SshX509Name node;
  unsigned char *der;
  size_t der_len;
  SshX509Config config = NULL;

  if ((dn = x509_name_string_to_dn(str, &der, &der_len, config)) == NULL)
    return FALSE;

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_DISTINGUISHED_NAME,
                                  dn, NULL, NULL, 0, der, der_len))
      != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  return FALSE;
}

Boolean
ssh_x509_name_push_unique_identifier(SshX509Name *list,
                                     const unsigned char *buf,
                                     size_t buf_len)
{
  SshX509Name node;

  if ((node = ssh_x509_name_alloc(SSH_X509_NAME_UNIQUE_ID,
                                  NULL, NULL,
                                  ssh_memdup(buf, buf_len), buf_len,
                                  NULL, 0)) != NULL)
    {
      ssh_x509_name_push(list, node);
      return TRUE;
    }
  return FALSE;
}

Boolean ssh_x509_name_push_other_name(SshX509Name *list,
                                      char **other_name_oid,
                                      unsigned char *der,
                                      size_t der_len)
{
  return FALSE;
}


/* Popping. */
Boolean
ssh_x509_name_pop_ip(SshX509Name list,
                     unsigned char **address, size_t *address_len)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_IP);

  *address     = NULL;
  *address_len = 0;
  if (name == NULL)
    return FALSE;
  if (name->data_len != 4 && name->data_len != 16)
    return FALSE;
  *address_len = name->data_len;
  if ((*address = ssh_memdup(name->data, name->data_len)) == NULL)
    *address_len = 0;

  return TRUE;
}

static Boolean
x509_name_pop_string(SshX509Name list, SshX509NameType kind,
                     char **string)
{
  SshX509Name name = ssh_x509_name_find_i(list, kind);
  size_t len;

  *string = NULL;
  if (name == NULL || name->name == NULL)
    return FALSE;

  if ((*string = (char *)ssh_str_get(name->name, &len)) != NULL)
    return TRUE;
  else
    return FALSE;
}

Boolean ssh_x509_name_pop_email(SshX509Name list, char **email)
{
  return x509_name_pop_string(list, SSH_X509_NAME_RFC822, email);
}

Boolean ssh_x509_name_pop_dns(SshX509Name list, char **dns)
{
  return x509_name_pop_string(list, SSH_X509_NAME_DNS, dns);
}

Boolean ssh_x509_name_pop_uri(SshX509Name list, char **uri)
{
  return x509_name_pop_string(list, SSH_X509_NAME_URI, uri);
}

Boolean ssh_x509_name_pop_rid(SshX509Name list, char **rid)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_RID);

  *rid = NULL;
  if (name == NULL || name->data == NULL)
    return FALSE;
  if ((*rid = ssh_strdup(name->data)) == NULL)
    return FALSE;
  return TRUE;
}

Boolean ssh_x509_name_pop_principal_name_str(SshX509Name list, SshStr *upn)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_PRINCIPAL_NAME);
  *upn = NULL;
  if (name == NULL || name->name == NULL)
    return FALSE;
  *upn = ssh_str_dup(name->name);
  return TRUE;
}

Boolean ssh_x509_name_pop_guid(SshX509Name list,
                               unsigned char **data, size_t *len)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_GUID);

  *data = NULL;
  *len = 0;

  if (name == NULL || name->data == NULL)
    return FALSE;
  if ((*data = ssh_memdup(name->data, name->data_len)) == NULL)
    return FALSE;

  *len = name->data_len;
  return TRUE;
}

Boolean ssh_x509_name_pop_directory_name(SshX509Name list, char **ret_dn)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_DN);
  size_t len;
  Boolean rv = FALSE;
  SshX509Config config = NULL;

  *ret_dn = NULL;
  if (name == NULL)
    return FALSE;

  if (name->name == NULL)
    {
      SshDNStruct dns, *dn = &dns;

      if (name->dn)
        dn = name->dn;
      else
        {
          ssh_dn_init(&dns);
          if (!ssh_dn_decode_der(name->ber, name->ber_len, &dns, config))
            {
              ssh_dn_clear(&dns);
              return FALSE;
            }
        }
      if (ssh_dn_encode_ldap(dn, ret_dn))
        rv = TRUE;

      if (dn == &dns) ssh_dn_clear(&dns);
      return rv;
    }
  *ret_dn = (char *)ssh_str_get(name->name, &len);
  return TRUE;
}

Boolean
ssh_x509_name_pop_directory_name_der(SshX509Name list,
                                     unsigned char **der,
                                     size_t *der_len)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_DN);

  *der     = NULL;
  *der_len = 0;

  if (name == NULL)
    return FALSE;

  *der_len = name->ber_len;
  if ((*der = ssh_memdup(name->ber, name->ber_len)) == NULL)
    *der_len = 0;
  return TRUE;
}

Boolean ssh_x509_name_pop_directory_name_str(SshX509Name list, SshStr *ret_str)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_DN);

  *ret_str = NULL;
  if (name == NULL)
    return FALSE;

  if (!ssh_dn_encode_ldap_str(name->dn, ret_str))
    return FALSE;
  return TRUE;
}

Boolean ssh_x509_name_pop_other_name(SshX509Name list,
                                     char **other_name_oid,
                                     unsigned char **der,
                                     size_t *der_len)
{
  size_t ignored_len;
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_OTHER);

  *der     = NULL;
  *der_len = 0;

  if (name == NULL || name->ber == NULL || name->name == NULL)
    return FALSE;
  SSH_ASSERT(ssh_str_charset_get(name->name) == SSH_CHARSET_US_ASCII);
  if ((*other_name_oid =
       (char *)ssh_str_get_data(name->name, &ignored_len)) == NULL)
    return FALSE;

  if ((*der = ssh_memdup(name->ber, name->ber_len)) == NULL)
    *der_len = 0;
  *der_len = name->ber_len;
  return TRUE;
}


Boolean ssh_x509_name_pop_ldap_dn(SshX509Name list, char **ret_dn)
{
  SshX509Name name =
    ssh_x509_name_find_i(list, SSH_X509_NAME_DISTINGUISHED_NAME);
  SshX509Config config = NULL;
  SshDNStruct dn;

  *ret_dn = NULL;
  if (name == NULL)
    return FALSE;

  ssh_dn_init(&dn);
  if (!ssh_dn_decode_der(name->ber, name->ber_len, &dn, config))
    {
      ssh_dn_clear(&dn);
      return FALSE;
    }
  if (!ssh_dn_encode_ldap(&dn, ret_dn))
    {
      ssh_dn_clear(&dn);
      return FALSE;
    }
  ssh_dn_clear(&dn);
  return TRUE;
}

Boolean ssh_x509_name_pop_der_dn(SshX509Name list, unsigned char **der,
                                 size_t *der_len)
{
  SshX509Name name =
    ssh_x509_name_find_i(list, SSH_X509_NAME_DISTINGUISHED_NAME);

  *der     = NULL;
  *der_len = 0;

  if (name == NULL)
    if ((name = ssh_x509_name_find_i(list, SSH_X509_NAME_DN)) == NULL)
      return FALSE;

  *der_len = name->ber_len;
  if ((*der = ssh_memdup(name->ber, name->ber_len)) == NULL)
    *der_len = 0;
  return TRUE;
}

Boolean ssh_x509_name_pop_str_dn(SshX509Name list, SshStr *ret_str)
{
  SshX509Name name =
    ssh_x509_name_find_i(list, SSH_X509_NAME_DISTINGUISHED_NAME);
  SshDNStruct dns, *dn = &dns;
  SshX509Config config = NULL;

  *ret_str = NULL;
  if (name == NULL)
    return FALSE;

  if (name->dn)
    dn = name->dn;
  else
    {
      ssh_dn_init(&dns);
      if (!ssh_dn_decode_der(name->ber, name->ber_len, &dns, config))
        {
          ssh_dn_clear(&dns);
          return FALSE;
        }
    }

  if (!ssh_dn_encode_ldap_str(dn, ret_str))
    {
      if (dn == &dns) ssh_dn_clear(&dns);
      return FALSE;
    }
  if (dn == &dns) ssh_dn_clear(&dns);
  return TRUE;
}

Boolean
ssh_x509_name_pop_unique_identifier(SshX509Name list,
                                    unsigned char **buf, size_t *buf_len)
{
  SshX509Name name = ssh_x509_name_find_i(list, SSH_X509_NAME_UNIQUE_ID);

  *buf     = NULL;
  *buf_len = 0;
  if (name == NULL)
    return FALSE;

  if ((*buf = ssh_memdup(name->data, name->data_len)) == NULL)
    return FALSE;

  *buf_len = name->data_len;
  return TRUE;
}

/* Encoding a certificate structure. */
SshX509AsyncCallStatus
ssh_x509_cert_encode_internal(SshX509CertEncodeContext encode_context)
{
  SshX509Config conf =  ssh_x509_get_configuration();
  int i;

  /* Initialize the ASN.1 allocation context, that we're using. */
  if ((encode_context->asn1_context = ssh_asn1_init()) == NULL)
    {
      encode_context->rv = SSH_X509_NO_MEMORY;
      return SSH_X509_ASYNC_CALL_ERROR;
    }

  for (i = 0; i < SSH_X509_CERT_TYPE_MAX; i++)
    {
      if (conf->encoders[i].type == encode_context->cert->type &&
          conf->encoders[i].encoder != NULL_FNPTR)
        {
          return (*conf->encoders[i].encoder)(encode_context);
        }
    }
  encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
  return SSH_X509_ASYNC_CALL_ERROR;
}

void ssh_x509_cert_encode_async_abort(void *context)
{
  SshX509CertEncodeContext encode_context = context;

  ssh_asn1_free(encode_context->asn1_context);
  /* Abort the crypto handle. */
  ssh_operation_abort(encode_context->crypto_handle);
  ssh_free(context);
}

/* This starts an asynchronous encoding. */
SshOperationHandle ssh_x509_cert_encode_async(SshX509Certificate c,
                                              SshPrivateKey issuer_key,
                                              SshX509EncodeCB encode_cb,
                                              void *context)
{
  SshX509CertEncodeContext encode_context;
  SshX509AsyncCallStatus call_status;

  SSH_ASSERT(encode_cb != NULL_FNPTR);

  if ((encode_context = ssh_calloc(1, sizeof(*encode_context))) == NULL)
    {
      (*encode_cb)(SSH_X509_FAILURE, NULL, 0, context);
      return NULL;
    }

  encode_context->cert = c;
  encode_context->issuer_key = issuer_key;
  encode_context->rv = SSH_X509_OK;
  encode_context->user_context = context;
  encode_context->user_encode_cb = encode_cb;

  if ((encode_context->operation_handle =
       ssh_operation_register(ssh_x509_cert_encode_async_abort,
                              encode_context)) == NULL)
    {
      (*encode_cb)(SSH_X509_FAILURE, NULL, 0, context);
      return NULL;
    }

  call_status = ssh_x509_cert_encode_internal(encode_context);

  switch (call_status)
    {
    case SSH_X509_ASYNC_CALL_COMPLETED:
    default:
      return NULL;
    case SSH_X509_ASYNC_CALL_PENDING:
      return encode_context->operation_handle;
    case SSH_X509_ASYNC_CALL_ERROR:
      /* internal encode returned error. Abort all. */
      (*encode_cb)(encode_context->rv, NULL, 0, context);
      ssh_x509_cert_encode_async_abort(encode_context);
      return NULL;
    }
}
SshX509Status ssh_x509_cert_decode(const unsigned char *buf, size_t len,
                                   SshX509Certificate c)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  SshX509Status rv = SSH_X509_FAILURE;
  SshX509Config conf =  ssh_x509_get_configuration();
  int i;

  /* Initialize the ASN.1 parser mallocation. */
  if ((context = ssh_asn1_init()) == NULL)
    return rv;

  ssh_asn1_set_limits(context, len, 0);

  /* Decode the BER buffer. */
  status = ssh_asn1_decode(context, buf, len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      /* Return with an error. */
      ssh_asn1_free(context);
      return SSH_X509_FAILURE;
    }

  rv = SSH_X509_FAILED_UNKNOWN_STYLE;
  for (i = 0; i < SSH_X509_CERT_TYPE_MAX; i++)
    {
      if (c->type == conf->encoders[i].type &&
          conf->encoders[i].decoder != NULL_FNPTR)
        {
          rv = (*conf->encoders[i].decoder)(context,
                                            ssh_asn1_get_root(tree),
                                            c);
          break;
        }
    }

  /* Free the ASN.1 context. */
  ssh_asn1_free(context);

  return rv;
}

/* x509.c */
#endif /* SSHDIST_CERT */
