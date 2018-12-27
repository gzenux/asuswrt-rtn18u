/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The routines for handling the decoding of the form for generating
   X.509 certificates, crl's and certificate requests.

   Simply said, this file contains the functionality to convert the ascii
   definitions (of PSystem format) into C structures, ready for converting
   in to X.509v3 ASN.1 in DER encoding.
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshmp.h"
#include "sshasn1.h"
#include "x509.h"
#include "dn.h"
#include "oid.h"
#include "sshpsystem.h"
#include "sshexternalkey.h"
#include "parse-x509-forms.h"
#include "sshenum.h"
#include "sshfileio.h"

#define SSH_DEBUG_MODULE "SshCertScriptParser"

static SshCharset input_encoding = SSH_CHARSET_UTF8;

/* Software EK provider prefix */
static const char *ssh_x509_form_software_prefix = "software://0/prvkeyfile=";

typedef struct SshX509FormStateRec {
  SshPSystemNode node;
  SshPSystemStatus status;
  SshX509FormList list;
  SshX509FormContainer container;
} *SshX509FormState;

/* Allocate and link a new container */
SshX509FormContainer ssh_x509_container_alloc(SshX509FormContainer prev)
{
  SshX509FormContainer newp = ssh_xmalloc(sizeof(*newp));
  newp->prev = prev;

  newp->type = SSH_X509_FORM_LIST_TYPE_NONE;
  newp->current.cert    = NULL;
  newp->current.crl     = NULL;
  newp->subject_key = NULL;
  newp->issuer_prv_key  = NULL;

  newp->input_request_file   = NULL;
  newp->output_file          = NULL;

  /* Assume false, because we are very pessimistic. */
  newp->self_signed          = FALSE;

  newp->request_extension_style = SSH_X509_REQ_EXTENSION_PKCS9_REQ;
  newp->copy_from_request    = 0;
  return newp;
}

static void ssh_x509_form_free_key_fields(SshX509FormPrivateKey pk)
{
  SshX509FormECPPrvKeyAttr attr;
  ssh_xfree(pk->name);
  ssh_xfree(pk->key_path);
  ssh_xfree(pk->auth_code);
  if (pk->key_attrs)
    {
      attr = pk->key_attrs;
      ssh_xfree(attr->curve_name);
      ssh_xfree(pk->key_attrs);
    }
}

/* Free a container and its contents. Returns previous container. */
SshX509FormContainer ssh_x509_container_free(SshX509FormContainer c)
{
  SshX509FormContainer prev = c->prev;

  /* Free stuff. */
  ssh_xfree(c->input_request_file);
  ssh_xfree(c->output_file);
  ssh_xfree(c->issuer_prv_key);
  ssh_xfree(c->subject_key);

  switch (c->type)
    {
    case SSH_X509_FORM_LIST_TYPE_NONE:
      break;
    case SSH_X509_FORM_LIST_TYPE_CERT:
    case SSH_X509_FORM_LIST_TYPE_REQUEST:
      if (c->current.cert)
        ssh_x509_cert_free(c->current.cert);
      break;
    case SSH_X509_FORM_LIST_TYPE_CRL:
      if (c->current.crl)
        ssh_x509_crl_free(c->current.crl);
      break;
    case SSH_X509_FORM_LIST_TYPE_PROVIDER:
      if (c->current.provider)
        {
          SshX509FormAddProvider ap = c->current.provider;
          ssh_xfree(ap->type);
          ssh_xfree(ap->init_str);
          ssh_xfree(ap);
        }
      break;

    case SSH_X509_FORM_LIST_TYPE_KEY:
      if (c->current.pkey)
        {
          SshX509FormPrivateKey pk = c->current.pkey;
          ssh_x509_form_free_key_fields(pk);
          ssh_xfree(pk);
        }
      break;

    case SSH_X509_FORM_LIST_TYPE_GEN_KEY:
      if (c->current.gen_pkey)
        {
          SshX509FormGenPrivateKey gk = c->current.gen_pkey;
          ssh_x509_form_free_key_fields(&gk->key);
          ssh_xfree(gk->output_file);
          ssh_xfree(gk);
        }
      break;
    }

  ssh_xfree(c);
  return prev;
}

/* Simple form routines. */
void ssh_x509_form_list_init(SshX509FormList list, SshCharset encoding)
{
  input_encoding = encoding;
  list->head = list->tail = NULL;
}

/* Routines for handling form lists. */
SshX509FormNode ssh_x509_form_list_node_alloc(void)
{
  SshX509FormNode newp = ssh_xmalloc(sizeof(*newp));
  newp->type = SSH_X509_FORM_LIST_TYPE_NONE;
  newp->next = NULL;
  newp->container = NULL;
  return newp;
}

void ssh_x509_form_list_add(SshX509FormList list, SshX509FormNode node)
{
  if (list->tail == NULL)
    {
      list->head = list->tail = node;
    }
  else
    {
      list->tail->next = node;
      list->tail = node;
    }
  list->current = node;
}

SshX509FormNode ssh_x509_form_list_add_new(SshX509FormList list,
                                           SshX509FormContainer container)
{
  SshX509FormNode node = ssh_xmalloc(sizeof(*node));
  node->next = NULL;
  node->type = container->type;
  node->container = container;
  list->current = node;
  ssh_x509_form_list_add(list, node);
  return node;
}

void ssh_x509_form_list_free(SshX509FormList list)
{
  SshX509FormNode node = list->head;
  while (node)
    {
      SshX509FormNode next = node->next;

      /* Free all the small containers also. */
      ssh_x509_container_free(node->container);
      ssh_xfree(node);
      node = next;
    }

  list->head = list->tail = NULL;
}

/* See if STR represents a valid date/time. If it does, set BER_TIME. */
Boolean ssh_validate_time_string(SshBerTime ber_time, const char *str)
{
  static const int days_in_month[2][12] = {
    { 31, 28, 31, 30, 31, 30,  31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30,  31, 31, 30, 31, 30, 31 }
  };

  SshBerTimeStruct time;
  int leap_year = 0;

  if (!ssh_ber_time_set_from_string(&time, str))
    return FALSE;

  /* ssh_ber_time_set_from_string checks the time and date for
     basic consistency. One problem is that it accepts for example
     29.2.2001 and 31.11 (any year) */
  if ((time.year % 4) == 0)
    if ((time.year % 100) != 0 || (time.year % 400) == 0)
      leap_year = 1;

  if (time.day > days_in_month[leap_year][time.month - 1])
    return FALSE;

  ssh_ber_time_set(ber_time, &time);
  return TRUE;
}

char *ssh_x509_form_alloc_software_key_path(char *file_name)
{
  char *str = ssh_xmalloc(strlen(file_name) +
                          strlen(ssh_x509_form_software_prefix) + 1);
  strcpy(str, ssh_x509_form_software_prefix);
  strcat(str, file_name);
  return str;
}

SshPublicKey ssh_x509_form_alloc_software_pub_key(char *file_name)
{
  unsigned char *buf;
  size_t buf_len;
  SshPublicKey key;

  if (ssh_read_gen_file(file_name, &buf, &buf_len) == FALSE)
      ssh_fatal("Can not read %s", file_name);
  if (ssh_public_key_import(buf, buf_len, &key) != SSH_CRYPTO_OK)
    ssh_fatal("Can not import %s as public key", file_name);
  return key;
}

void ssh_x509_form_add_software_private_key(SshX509FormState state,
                                            char *file_name)
{
  SshX509FormContainer container;
  SshX509FormPrivateKey pk;

  /* Try to find a PrivateKey/GeneratePrivateKey entry */
  SshX509FormList list = state->list;
  SshX509FormNode node;
  for (node = list->head; node; node = node->next)
    {
      container = node->container;
      if ((container->type == SSH_X509_FORM_LIST_TYPE_KEY ||
           container->type == SSH_X509_FORM_LIST_TYPE_GEN_KEY) &&
          strcmp(file_name, container->current.pkey->name) == 0)
        return;
    }

  /* Not found, create a key entry */
  pk = ssh_xcalloc(1, sizeof(*pk));
  pk->name = ssh_xstrdup(file_name);
  pk->key_path = ssh_x509_form_alloc_software_key_path(file_name);

  container = ssh_x509_container_alloc(NULL);
  container->type = SSH_X509_FORM_LIST_TYPE_KEY;
  container->current.pkey = pk;
  ssh_x509_form_list_add_new(list, container);
}

void ssh_x509_form_add_software_public_key(SshX509FormState state,
                                           char *file_name)
{
  SshX509FormContainer container;
  SshX509FormPrivateKey pk;

  /* Try to find a PrivateKey/GeneratePrivateKey entry */
  SshX509FormList list = state->list;
  SshX509FormNode node;
  for (node = list->head; node; node = node->next)
    {
      container = node->container;
      if ((container->type == SSH_X509_FORM_LIST_TYPE_KEY ||
           container->type == SSH_X509_FORM_LIST_TYPE_GEN_KEY) &&
          strcmp(file_name, container->current.pkey->name) == 0)
        return;
    }

  /* Not found, create a key entry */
  pk = ssh_xcalloc(1, sizeof(*pk));
  pk->name = ssh_xstrdup(file_name);
  pk->pub_key = ssh_x509_form_alloc_software_pub_key(file_name);

  container = ssh_x509_container_alloc(NULL);
  container->type = SSH_X509_FORM_LIST_TYPE_KEY;
  container->current.pkey = pk;
  ssh_x509_form_list_add_new(list, container);
}


/***************************************************************/

































/********************* Process certificate extensions *********************/

static Boolean
ssh_x509_form_finish(SshPSystemNode node, SshX509FormState state)
{
  return !ssh_psystem_find_error(node, &state->node, &state->status);
}


static Boolean
ssh_x509_form_get_name(SshPSystemNode node,
                       const char *name1, const char *name2, char **str)
{
  /* Try both alternatives */
  if (ssh_psystem_get_name(node, name1, str, NULL))
    return TRUE;
  if (ssh_psystem_get_name(node, name2, str, NULL))
    return TRUE;
  return FALSE;
}

/* Handle the various alternate names */
Boolean
ssh_x509_form_alt_names(SshPSystemNode alt_node, SshX509Name *names,
                        Boolean* critical, SshX509FormState state)
{
  unsigned char *buf;
  size_t buf_len;
  char *cstr;

  *names = NULL;

  /* We might not allow Critical flag in all cases. */
  if (critical != NULL)
    *critical = ssh_psystem_get_void(alt_node, "Critical", NULL);

  while (ssh_psystem_get_ip(alt_node, "IP", &buf, &buf_len, NULL) ||
         ssh_psystem_get_ip(alt_node, "InternetProtocolAddress",
                            &buf, &buf_len, NULL))
    {
      if (buf_len == 4)
        {
          SSH_DEBUG(3, ("  Ip = %d.%d.%d.%d",
                        (int) buf[0],
                        (int) buf[1],
                        (int) buf[2],
                        (int) buf[3]));
        }
      else
        {
          /* Dump IPv6 addresses correctly */
          char tmp_str[512];
          size_t len;
          int i;

          len = 0;
          for (i = 0; i < buf_len; i++)
            {
              ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len,
                           "%02x", buf[i]);
              len += strlen(tmp_str + len);
              if (i != buf_len - 1 && (i & 0x1) == 1)
                {
                  ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len, ":");
                  len++;
                }
            }
          SSH_DEBUG(3, ("  Ip = %s", tmp_str));
        }

      ssh_x509_name_push_ip(names, buf, buf_len);
    }

  while (ssh_x509_form_get_name(alt_node,
                                "DNS", "DomainNameServerName",
                                &cstr))
    {
      SSH_DEBUG(3, ("  Dns = %s", cstr));
      ssh_x509_name_push_dns(names, cstr);
    }

  while (ssh_x509_form_get_name(alt_node,
                                "EMAIL", "ElectronicMailAddress",
                                &cstr))
    {
      SSH_DEBUG(3, ("  Email = %s", cstr));
      ssh_x509_name_push_email(names, cstr);
    }


  while (ssh_x509_form_get_name(alt_node,
                                "URI", "UniformResourceIdentifier",
                                &cstr))
    {
      SSH_DEBUG(3, ("  URI = %s", cstr));
      ssh_x509_name_push_uri(names, cstr);
    }

  while (ssh_x509_form_get_name(alt_node,
                                "RID", "RegisteredIdentifier",
                                &cstr))
    {
      const SshOidStruct *oids;
      SSH_DEBUG(3, ("  RID = %s", cstr));
      oids = ssh_oid_find_by_std_name(cstr);
      if (oids)
        ssh_x509_name_push_rid(names, oids->oid);
      else
        ssh_x509_name_push_rid(names, cstr);
    }

  while (ssh_psystem_get_ldap(alt_node, "DN", &cstr, NULL) ||
         ssh_psystem_get_ldap(alt_node, "DirectoryName", &cstr, NULL))
    {
      SshStr str;
      unsigned char *dup = NULL;

      if (cstr)
        dup = ssh_strdup(cstr);
      if (dup &&
          (str = ssh_str_make(input_encoding, dup, strlen(dup))) != NULL)
        {
          ssh_x509_name_push_directory_name_str(names, str);
          ssh_str_free(str);
        }
      SSH_DEBUG(3, ("  DN = %s", cstr));
    }

  if (!ssh_x509_form_finish(alt_node, state))
    {
      if (*names)
        {
          ssh_x509_name_free(*names);
          *names = NULL;
        }
      return FALSE;
    }
  return TRUE;
}

/* Key usage extension */
static const SshKeywordStruct ssh_x509_form_key_usage_flags[] =
{
  { "DigitalSignature",  SSH_X509_UF_DIGITAL_SIGNATURE },
  { "NonRepudiation",    SSH_X509_UF_NON_REPUDIATION },
  { "KeyEncipherment",   SSH_X509_UF_KEY_ENCIPHERMENT },
  { "DataEncipherment",  SSH_X509_UF_DATA_ENCIPHERMENT },
  { "KeyAgreement",      SSH_X509_UF_KEY_AGREEMENT },
  { "KeyCertSign",       SSH_X509_UF_KEY_CERT_SIGN },
  { "CRLSign",           SSH_X509_UF_CRL_SIGN },
  { "EncipherOnly",      SSH_X509_UF_ENCIPHER_ONLY },
  { "DecipherOnly",      SSH_X509_UF_DECIPHER_ONLY },
  { NULL }
};

Boolean ssh_x509_form_key_usage(SshPSystemNode node,
                                SshX509Certificate c,
                                SshX509FormState state)
{
  const SshKeywordStruct *key = ssh_x509_form_key_usage_flags;
  SshX509UsageFlags flags = 0;
  Boolean critical;

  critical = ssh_psystem_get_void(node, "Critical", NULL);
  for (; key->name; key++)
    {
      if (ssh_psystem_get_void(node, key->name, NULL))
        flags |= key->code;
    }

  if (!ssh_x509_form_finish(node, state))
    return FALSE;

  ssh_x509_cert_set_key_usage(c, flags, critical);
  return TRUE;
}

/* Extended key usage extension */
static const struct SshX509FormMapOid
{
  const char *name; /* Node name */
  const char *oid;  /* Oid name */
} ssh_x509_form_map_oid[] =
{
  { "ServerAuth",      "serverAuth" },
  { "ClientAuth",      "clientAuth" },
  { "CodeSigning",     "codeSigning" },
  { "EmailProtection", "emailProtection" },
  { "TimeStamping",    "timeStamping" },
  { "IkeIntermediate", "ikeIntermediate" },
  { NULL }
};

/* Return TRUE if string S resembles an object identifier */
Boolean ssh_x509_form_is_oid(const char* s)
{
  char c;
  while ((c = *s++) != 0)
    {
      if (!isdigit((unsigned char)c) && c != '.')
        return FALSE;
    }
  return TRUE;
}

Boolean ssh_x509_form_ext_key_usage(SshPSystemNode node,
                                    SshX509Certificate c,
                                    SshX509FormState state)
{
  const struct SshX509FormMapOid *map;
  SshX509OidList oid_list = NULL;
  SshX509OidList* last = &oid_list;
  const SshOidStruct *oid;
  SshPSystemNode cnode;
  char *str;
  SshX509OidList cur;

  Boolean critical = ssh_psystem_get_void(node, "Critical", NULL);

  for (map = ssh_x509_form_map_oid; map->name != NULL; map++)
    {
      if (ssh_psystem_get_void(node, map->name, NULL))
        {
          cur = ssh_xcalloc(1, sizeof(*cur));
          *last = cur;
          last = &cur->next;

          oid = ssh_oid_find_by_std_name(map->oid);
          if (oid == NULL)
            return FALSE;

          cur->oid = ssh_xstrdup(oid->oid);
        }
    }

  /* Add any arbitrary OID we didn't ask for yet */
  while (ssh_psystem_get_name(node, "*OID", &str, &cnode))
    {
      if (!ssh_x509_form_is_oid(str))
        {
          ssh_xfree(str);
          state->status = SSH_PSYSTEM_ADD_FAILED;
          state->node   = cnode;
          return FALSE;
        }

      cur = ssh_xcalloc(1, sizeof(*cur));
      cur->oid = str;
      *last = cur;
      last = &cur->next;
    }

  ssh_x509_cert_set_ext_key_usage(c, oid_list, critical);
  return ssh_x509_form_finish(node, state);
}

/* CRL distribution points extension */
static const SshKeywordStruct ssh_x509_form_crl_reason_map[] =
{
  { "KeyCompromise",        SSH_X509_RF_KEY_COMPROMISE },
  { "CaCompromise",         SSH_X509_RF_CA_COMPROMISE },
  { "AffiliationChanged",   SSH_X509_RF_AFFILIATION_CHANGED },
  { "Superseded",           SSH_X509_RF_SUPERSEDED },
  { "CessationOfOperation", SSH_X509_RF_CESSATION_OF_OPERATION },
  { "CertificateHold",      SSH_X509_RF_CERTIFICATE_HOLD },
  { NULL }
};

Boolean ssh_x509_form_crl_dist_points(SshPSystemNode dist_node,
                                      SshX509Certificate c,
                                      SshX509FormState state)
{
  SshPSystemNode node;
  Boolean critical = FALSE;

  while (ssh_psystem_get_any(dist_node, &node))
    {
      SshX509ExtCRLDistPoints dp;
      SshPSystemNode name_node;
      char *name;
      const SshKeywordStruct *key;

      dp = ssh_xcalloc(1, sizeof(*dp));

      /* Specifying critical within one environment turns
         the entire extension critical. */
      if (ssh_psystem_get_void(node, "Critical", NULL))
        critical = TRUE;

      /* Attach the DP structure to certificate. This way the cert
         library will clean up if we happen to fail. */
      ssh_x509_cert_set_crl_dist_points(c, dp, critical);

      /* Handle CRL issuer name environment */
      if (ssh_psystem_get_env(node, "CRLIssuer", &name_node))
        if (!ssh_x509_form_alt_names(name_node, &dp->crl_issuer, NULL, state))
          return FALSE;

      /* Handle the full name environment; name relative to CRL issuer
         can be used only if there's no FullName. */
      if (ssh_psystem_get_env(node, "FullName", &name_node))
        {
          if (!ssh_x509_form_alt_names(name_node, &dp->full_name, NULL, state))
            return FALSE;
        }
      else if (ssh_psystem_get_ldap(node, "IssuerRelativeDN", &name, NULL))
        {
          dp->dn_relative_to_issuer = ssh_xcalloc(1, sizeof(SshDNStruct));
          ssh_dn_init(dp->dn_relative_to_issuer);
          ssh_dn_decode_ldap((unsigned char *)name, dp->dn_relative_to_issuer);
        }

      /* Handle the reason flags */
      for (key = ssh_x509_form_crl_reason_map; key->name; key++)
        {
          if (ssh_psystem_get_void(node, key->name, NULL))
            dp->reasons |= key->code;
        }

      /* We're finished with this environment */
      if (!ssh_x509_form_finish(node, state))
        return FALSE;
    }

  return TRUE;
}

/* Parse the given form for authority key identifier extension.
   This code is used both for certificates and for CRLs. */
Boolean ssh_x509_form_auth_key_identifier(SshPSystemNode id_node,
                                          SshX509ExtKeyId *ext_key_id,
                                          SshX509FormState state)
{
  SshPSystemNode node;
  SshX509Name cert_issuer = NULL;
  SshMPInteger cert_serial_num = NULL;
  SshX509ExtKeyId keyid;
  char *str;
  unsigned char* key_id = NULL;
  size_t key_id_len = 0;

  SSH_DEBUG(3, ("# Authority key identifier\n"));

  /* KeyIdentifier must be specified */
  if (ssh_psystem_get_string(id_node, "KeyIdentifier", &str, &node))
    {
      key_id     = node->data;
      key_id_len = node->data_len;
    }
  else
    {
      state->status = SSH_PSYSTEM_ADD_FAILED;
      state->node = id_node;
      return FALSE;
    }

  if (ssh_psystem_get_env(id_node, "AuthorityCertIssuer", &node))
    if (!ssh_x509_form_alt_names(node, &cert_issuer, NULL, state))
      return FALSE;

  ssh_psystem_get_int(id_node, "SerialNumber", &cert_serial_num, NULL);

  keyid = ssh_xcalloc(1, sizeof(*keyid));
  keyid->key_id = ssh_xmemdup(key_id, key_id_len);
  keyid->key_id_len = key_id_len;
  keyid->auth_cert_issuer = cert_issuer;
  if (cert_serial_num != NULL)
    ssh_mprz_init_set(&keyid->auth_cert_serial_number, cert_serial_num);
  else
    {
      /* It seems that -1 is used to indicate missing serial number. */
      ssh_mprz_init_set_si(&keyid->auth_cert_serial_number, -1);
    }

  *ext_key_id = keyid;
  return TRUE;
}

/* Authority/subject key identifier extensions (non-critical) */
Boolean ssh_x509_form_key_identifier(SshPSystemNode id_node,
                                     SshX509Certificate c,
                                     SshX509FormState state)
{
  unsigned char* key_id = NULL;
  size_t key_id_len = 0;
  SshPSystemNode node;
  char* str;

  if (strcmp(id_node->name, "AuthKeyIdentifier") == 0)
    {
      /* Handle attributes specific to AuthKeyIdentifier */
      SshX509ExtKeyId keyid;

      if (!ssh_x509_form_auth_key_identifier(id_node, &keyid, state))
        return FALSE;

      /* This extension MUST NOT be critical */
      ssh_x509_cert_set_authority_key_id(c, keyid, FALSE);
    }
  else
    {
      /* Set the subject key identifier (MUST NOT be critical) */
      SSH_DEBUG(3, ("# Subject key identifier\n"));

      /* KeyIdentifier must be specified */
      if (ssh_psystem_get_string(id_node, "KeyIdentifier", &str, &node))
        {
          key_id     = node->data;
          key_id_len = node->data_len;
        }
      else
        {
          state->status = SSH_PSYSTEM_ADD_FAILED;
          state->node = id_node;
          return FALSE;
        }

      ssh_x509_cert_set_subject_key_id(c, key_id, key_id_len, FALSE);
    }

  return ssh_x509_form_finish(id_node, state);
}

/* Basic constraints extension */
Boolean
ssh_x509_form_basic_constraints(SshPSystemNode node, SshX509Certificate c,
                                SshX509FormState state)
{
  size_t path_length = (size_t) -1;
  Boolean ca_cert;
  Boolean critical;
  SshMPInteger mp_int;

  critical = ssh_psystem_get_void(node, "Critical", NULL);
  ca_cert  = ssh_psystem_get_void(node, "CA", NULL);
  if (ssh_psystem_get_int(node, "PathLength", &mp_int, NULL))
    path_length = ssh_mprz_get_ui(mp_int);

  /* Force CA certificates to be critical */
  if (ca_cert)
    critical = TRUE;

  ssh_x509_cert_set_basic_constraints(c, path_length, ca_cert, critical);
  return ssh_x509_form_finish(node, state);
}

/* Policy constraints extension */
static Boolean
ssh_x509_form_pc_number(SshPSystemNode node, const char* name,
                        unsigned int* number, SshX509FormState state)
{
  SshMPInteger mp;
  SshPSystemNode mp_node;

  if (!ssh_psystem_get_int(node, name, &mp, &mp_node))
    return TRUE;

  if (ssh_mprz_cmp_ui(mp, 0) < 0)
    goto error;
  *number = ssh_mprz_get_ui(mp);
  if (ssh_mprz_cmp_ui(mp, *number) > 0)  /* not representable? */
    goto error;
  return TRUE;

 error:
  state->status = SSH_PSYSTEM_ADD_FAILED;
  state->node   = mp_node;
  return FALSE;
}

Boolean
ssh_x509_form_policy_constraints(SshPSystemNode node, SshX509Certificate c,
                                 SshX509FormState state)
{
  SshX509ExtPolicyConstraints pc;
  Boolean critical;

  SSH_DEBUG(3, ("# Policy constraints\n"));
  pc = ssh_xmalloc(sizeof(*pc));
  pc->require = SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT;
  pc->inhibit = SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT;

  critical = ssh_psystem_get_void(node, "Critical", NULL);

  if (!ssh_x509_form_pc_number(node, "Require", &pc->require, state) ||
      !ssh_x509_form_pc_number(node, "Inhibit", &pc->inhibit, state))
    return FALSE;

  ssh_x509_cert_set_policy_constraints(c, pc, critical);
  return ssh_x509_form_finish(node, state);
}

/* Subject alternative names extension */
Boolean
ssh_x509_form_subj_alt_names(SshPSystemNode node, SshX509Certificate c,
                             SshX509FormState state)
{
  Boolean critical;
  SshX509Name names;

  SSH_DEBUG(3, ("# Subject alternative names\n"));
  if (!ssh_x509_form_alt_names(node, &names, &critical, state))
    return FALSE;
  ssh_x509_cert_set_subject_alternative_names(c, names, critical);
  return TRUE;
}

/* Issuer alternative names extension */
Boolean
ssh_x509_form_issuer_alt_names(SshPSystemNode node, SshX509Certificate c,
                               SshX509FormState state)
{
  Boolean critical;
  SshX509Name names;

  SSH_DEBUG(3, ("# Issuer alternative names\n"));
  if (!ssh_x509_form_alt_names(node, &names, &critical, state))
    return FALSE;
  ssh_x509_cert_set_issuer_alternative_names(c, names, critical);
  return TRUE;
}

/* Name constraints extension */
void
ssh_x509_form_free_gst_list(SshX509GeneralSubtree gst_chain)
{
  SshX509GeneralSubtree gst = gst_chain;
  while (gst)
    {
      SshX509GeneralSubtree next = gst->next;

      ssh_x509_name_free(gst->name);
      ssh_xfree(gst);
      gst = next;
    }
}

/* Handle a list of general subtree entries */
Boolean
ssh_x509_form_name_constraint_list(SshPSystemNode list_node,
                                   SshX509GeneralSubtree *list,
                                   SshX509FormState state)
{
  SshPSystemNode node;
  SshX509GeneralSubtree gst_chain = NULL;
  SshX509GeneralSubtree *gst_last = &gst_chain;

  while (ssh_psystem_get_any(list_node, &node))
    {
      SshX509GeneralSubtree gst;
      gst = ssh_xmalloc(sizeof(*gst));

      /* Add to the list of gst structures */
      *gst_last = gst;
      gst_last = &gst->next;

      /* Initialize the fields. RFC2459 mandates the values of
         min_distance and max_distance. */
      gst->next = NULL;
      gst->name = NULL;
      gst->min_distance = 0;
      gst->max_distance = SSH_X509_GENERAL_SUBTREE_VALUE_ABSENT;

      if (!ssh_x509_form_alt_names(node, &gst->name, NULL, state))
        {
          ssh_x509_form_free_gst_list(gst_chain);
          return FALSE;
        }
    }

  *list = gst_chain;
  return TRUE;
}

Boolean
ssh_x509_form_name_constraints(SshPSystemNode nc_node, SshX509Certificate c,
                               SshX509FormState state)
{
  SshPSystemNode node;
  SshX509GeneralSubtree gst_permitted = NULL;
  SshX509GeneralSubtree gst_excluded = NULL;
  Boolean critical;

  SSH_DEBUG(3, ("# Name constraints\n"));
  critical = ssh_psystem_get_void(nc_node, "Critical", NULL);

  if (ssh_psystem_get_list(nc_node, "Permitted", &node))
    {
      if (!ssh_x509_form_name_constraint_list(node, &gst_permitted, state))
        return FALSE;
    }
  if (ssh_psystem_get_list(nc_node, "Excluded", &node))
    {
      if (!ssh_x509_form_name_constraint_list(node, &gst_excluded, state))
        {
          ssh_x509_form_free_gst_list(gst_permitted);
          return FALSE;
        }
    }

  ssh_x509_cert_set_name_constraints(c, gst_permitted, gst_excluded, critical);
  return ssh_x509_form_finish(nc_node, state);
}

/* Authority information access extension */
Boolean
ssh_x509_form_auth_info_access(SshPSystemNode acc_node, SshX509Certificate c,
                               SshX509FormState state)
{
  SshX509ExtInfoAccess acc;
  SshPSystemNode node;
  SshPSystemNode cnode;
  char* str;

  SSH_DEBUG(3, ("# Authority info access\n"));

  while (ssh_psystem_get_any(acc_node, &node))
    {
      acc = ssh_xcalloc(1, sizeof(*acc));
      if (ssh_psystem_get_env(node, "AccessLocation", &cnode))
        {
          if (!ssh_x509_form_alt_names(cnode, &acc->access_location,
                                       NULL, state))
            {
              ssh_free(acc);
              return FALSE;
            }
        }

      if (ssh_psystem_get_name(node, "*AccessMethod", &str, &cnode))
        {
          /* This OID is not in sshcert/oid.c */
          if (strcmp(str, "caIssuers") == 0)
            {
              ssh_xfree(str);
              str = ssh_xstrdup("1.3.6.1.5.5.7.48.2");
            }
          else if (ssh_x509_form_is_oid(str))
            {
              /* Use STR as it is. This OID will not be freed by the
                 cert library, so it leaks. */
            }
          else
            {
              ssh_x509_name_free(acc->access_location);
              ssh_xfree(acc);
              ssh_xfree(str);
              state->status = SSH_PSYSTEM_ADD_FAILED;
              state->node   = cnode;
              return FALSE;
            }

          acc->access_method = str;
        }

      /* This extension MUST be non-critical */
      ssh_x509_cert_set_auth_info_access(c, acc, FALSE);

      if (!ssh_x509_form_finish(node, state))
        return FALSE;
    }
  return TRUE;
}

/* Netscape Comment */

Boolean
ssh_x509_form_netscape_comment(SshPSystemNode nc_node, SshX509Certificate c,
                               SshX509FormState state)
{
  SshStr nc;
  SshPSystemNode node;
  char *str;

  SSH_DEBUG(3, ("# Netscape Comment\n"));
  if (ssh_psystem_get_string(nc_node, "Comment", &str, &node))
    {
      nc = ssh_str_make(SSH_CHARSET_US_ASCII, ssh_xstrdup(str), strlen(str));
      ssh_x509_cert_set_netscape_comment(c, nc, FALSE);
    }
  else
    {
      state->status = SSH_PSYSTEM_ADD_FAILED;
      state->node = nc_node;
      return FALSE;
     }

  return TRUE;
}

/* Parse a series of comma-separated notice numbers. */
static void
ssh_x509_form_notice_numbers(SshX509ExtPolicyQualifierInfo pqi, char *str)
{
  char* tok;
  unsigned int *num_array;
  int acount = 16; /* Allocated count */
  int count = 0;

  num_array = ssh_xmalloc(acount * sizeof(unsigned int));

  tok = (char *)(strtok(str, ", "));
  for (; tok; tok = (char *)(strtok(NULL, ", ")))
    {
      unsigned int num = strtoul(tok, NULL, 10);
      if (count >= acount)
        {
          acount *= 2;
          num_array = ssh_xrealloc(num_array,
                                   acount * sizeof(unsigned int));
        }
      num_array[count++] = num;
    }

  /* Contract the block to actual size */
  if (count == 0)
      ssh_xfree(num_array);
  else
    {
      pqi->notice_numbers = ssh_xrealloc(num_array,
                                         count * sizeof(unsigned int));
      pqi->notice_numbers_count = count;
    }
}

Boolean
ssh_x509_form_policy_info(SshPSystemNode list_node, SshX509Certificate c,
                          SshX509FormState state)
{
  SshPSystemNode node, cnode;
  const SshOidStruct *oids;
  char* str;
  Boolean critical = FALSE;

  while (ssh_psystem_get_any(list_node, &node))
    {
      /* Create a new policy info structure and add it to the certificate. */
      SshX509ExtPolicyQualifierInfo pqi;
      SshX509ExtPolicyQualifierInfo *pqi_last;
      SshX509ExtPolicyInfo pi;

      if (ssh_psystem_get_void(node, "Critical", NULL))
        critical = TRUE;

      pi  = ssh_xcalloc(1, sizeof(*pi));
      pqi_last = &pi->pq_list;

      ssh_x509_cert_set_policy_info(c, pi, critical);

      if (ssh_psystem_get_name(node, "*PolicyIdentifier", &str, NULL))
        pi->oid = str;

      if (ssh_psystem_get_env(node, "UserNotice", &cnode))
        {
          pqi = ssh_xcalloc(1, sizeof(*pqi));
          *pqi_last = pqi;
          pqi_last = &pqi->next;

          oids = ssh_oid_find_by_std_name_of_type("pkix-id-qt-unotice",
                                                  SSH_OID_POLICY);

          /* These OIDs will be freed by the cert library */
          pqi->oid = ssh_xstrdup(oids->oid);

          /* The charset choice is a sort of a lowest-common denominator. */
          if (ssh_psystem_get_string(cnode, "*Organization", &str, NULL))
            pqi->organization = ssh_str_make(SSH_CHARSET_US_ASCII,
                                             (unsigned char *)str,
                                             strlen(str));
          if (ssh_psystem_get_string(cnode, "*ExplicitText", &str, NULL))
            pqi->explicit_text = ssh_str_make(SSH_CHARSET_US_ASCII,
                                              (unsigned char *)str,
                                              strlen(str));
          if (ssh_psystem_get_string(cnode, "*NoticeNumbers",
                                     &str, NULL))
            ssh_x509_form_notice_numbers(pqi, str);
        }
      if (ssh_psystem_get_string(node, "*CPSuri", &str, NULL))
        {
          pqi = ssh_xcalloc(1, sizeof(*pqi));
          *pqi_last = pqi;

          oids = ssh_oid_find_by_std_name_of_type("pkix-id-qt-cps",
                                                  SSH_OID_POLICY);
          pqi->oid = ssh_xstrdup(oids->oid);
          pqi->cpsuri = ssh_str_make(SSH_CHARSET_US_ASCII,
                                     (unsigned char *)str, strlen(str));
        }

      if (!ssh_x509_form_finish(node, state))
        return FALSE;
    }

  return TRUE;
}

Boolean
ssh_x509_form_policy_mapping(SshPSystemNode list_node, SshX509Certificate c,
                             SshX509FormState state)
{
  SshPSystemNode node;

  while (ssh_psystem_get_any(list_node, &node))
    {
      /* Create a new policy mapping structure and
         add it to the certificate. */
      SshX509ExtPolicyMappings pm;
      char *str;

      pm = ssh_xcalloc(1, sizeof(*pm));

      /* This extension MUST be non-critical. */
      ssh_x509_cert_set_policy_mappings(c, pm, FALSE);

      if (ssh_psystem_get_name(node, "*IssuerDomainPolicy", &str, NULL))
        pm->issuer_dp_oid = str;

      if (ssh_psystem_get_name(node, "*SubjectDomainPolicy", &str, NULL))
        pm->subject_dp_oid = str;

      /* Both policy OIDs must be included */
      if (!pm->issuer_dp_oid || !pm->subject_dp_oid)
        {
          state->node = node;
          state->status = SSH_PSYSTEM_ADD_FAILED;
          return FALSE;
        }
    }
  return TRUE;
}

/* Table of extension environments and their handler functions */
static struct SshX509FormExtHandler {
  const char* name;
  Boolean (*handler)(SshPSystemNode, SshX509Certificate, SshX509FormState);
} ssh_x509_form_ext_handlers[] =
{
  /* The various extensions appear here in the order they are listed
     in section 4.2 of RFC 2459. If the name begins with '#', the
     extension is a list, not a simple environment. */
  { "AuthKeyIdentifier",         ssh_x509_form_key_identifier },
  { "SubjectKeyIdentifier",      ssh_x509_form_key_identifier },
  { "KeyUsage",                  ssh_x509_form_key_usage },
  /* PrivateKeyUsage */
  { "#PolicyInformation",        ssh_x509_form_policy_info },
  { "#PolicyMappings",           ssh_x509_form_policy_mapping },
  { "SubjectAltNames",           ssh_x509_form_subj_alt_names },
  { "IssuerAltNames",            ssh_x509_form_issuer_alt_names },
  /* Subject directory attributes */
  { "BasicConstraints",          ssh_x509_form_basic_constraints },
  { "NameConstraints",           ssh_x509_form_name_constraints },
  { "PolicyConstraints",         ssh_x509_form_policy_constraints },
  { "ExtendedKeyUsage",          ssh_x509_form_ext_key_usage },
  { "#CRLDistributionPoints",    ssh_x509_form_crl_dist_points },
  { "#AuthInfoAccess",           ssh_x509_form_auth_info_access },
  { "NetscapeComment",           ssh_x509_form_netscape_comment },
  { NULL }
};

/* Handle the "Extensions" environment */
Boolean
ssh_x509_form_cert_extensions(SshPSystemNode ext_node, SshX509Certificate c,
                              SshX509FormState state)
{
  SshPSystemNode node;
  struct SshX509FormExtHandler* h;

  for (h = ssh_x509_form_ext_handlers; h->name != NULL; h++)
    {
      Boolean found;
      if (h->name[0] == '#')
        found = ssh_psystem_get_list(ext_node, h->name + 1, &node);
      else
        found = ssh_psystem_get_env(ext_node, h->name, &node);

      if (found)
        {
          /* Found an environment, call its handler */
          if (!(*h->handler)(node, c, state))
            return FALSE;
        }
    }

  return ssh_x509_form_finish(ext_node, state);
}

/******************* Process certificate environments *********************/

/* Handle the "validity" block */
Boolean ssh_x509_form_cert_validity(SshPSystemNode val_node,
                                    SshX509Certificate c,
                                    SshX509FormState state)
{
  char *str;
  SshPSystemNode node;

  if (ssh_psystem_get_string(val_node, "NotBefore", &str, &node))
    {
      if (!ssh_validate_time_string(&c->not_before, str))
        goto error;
    }
  if (ssh_psystem_get_string(val_node, "NotAfter", &str, &node))
    {
      if (!ssh_validate_time_string(&c->not_after, str))
        goto error;
    }
  return !ssh_psystem_find_error(val_node, &state->node, &state->status);

 error:
  state->status = SSH_PSYSTEM_ADD_FAILED;
  state->node   = node;
  return FALSE;
}

/* Handle the "PublicKeyInfo" block */
Boolean ssh_x509_form_cert_public_key(SshPSystemNode pk_node,
                                      SshX509Certificate c,
                                      SshX509FormState state)
{
  SshX509FormContainer container = state->container;
  const SshOidPkStruct *pk_extra = NULL;
  const char *pk_type = NULL;
  unsigned int key_bits = 0;
  SshPSystemNode node;
  SshMPInteger mp_int;
  char* str;
  Boolean ecp_key = FALSE;
  char * curve_name = NULL;









  /* Read the key generation parameters (which may be ignored). */

  if (ssh_psystem_get_int(pk_node, "Size", &mp_int, &node))
    {
      /* Verify that the range is reasonable for any use */
      if (ssh_mprz_cmp_ui(mp_int, (1 << 24)) > 0 ||
          ssh_mprz_cmp_ui(mp_int, 256) < 0)
        goto error;

      key_bits = ssh_mprz_get_ui(mp_int);
    }
  if (ssh_psystem_get_name(pk_node, "Type", &str, &node))
    {
      const SshOidStruct *oids;
      oids = ssh_oid_find_by_std_name_of_type(str, SSH_OID_PK);
      if (!oids)
        goto error;
      pk_type = oids->name;
      pk_extra = oids->extra;
      if (strncmp(str, "ecdsaEncryption",
                           strlen("ecdsaEncryption")) == 0)
        {
          if (ssh_psystem_get_name(pk_node, "Curve", &curve_name, &node))
            {
              const SshOidStruct *c_oid;
              c_oid = ssh_oid_find_by_std_name_of_type(curve_name,
                                                       SSH_OID_ECP_CURVE);
              if (!c_oid)
                goto error;
            }
          else
            {
              goto error;
            }
          ecp_key = TRUE;
        }
    }

  if (ssh_psystem_get_string(pk_node, "*InputPublicKeyFile", &str, NULL))
    {
      ssh_x509_form_add_software_public_key(state, str);
      container->subject_key = str;
    }

  /* Handle PrivateKeyFile or InputPrivateKeyFile for compatibility,
     creating a GeneratePrivateKey{} or PrivateKey{} environment,
     respectively. */

  if (ssh_psystem_get_string(pk_node, "*InputPrivateKeyFile", &str, NULL))
    {
      ssh_x509_form_add_software_private_key(state, str);
      container->subject_key = str;
    }
  else if (ssh_psystem_get_string(pk_node, "*PrivateKeyFile", &str, NULL))
    {
      SshX509FormGenPrivateKey gk = ssh_xcalloc(1, sizeof(*gk));
      gk->key.name = str;
      gk->key.key_path = ssh_x509_form_alloc_software_key_path(str);
      if (ecp_key)
        {
          SshX509FormECPPrvKeyAttr attr = ssh_xcalloc(1, sizeof (*attr));
          attr->curve_name = ssh_xstrdup(curve_name);
          attr->curve_encoding = SSH_X509_ECP_CURVE_ENCODING_NAMED;
          attr->point_encoding = SSH_X509_ECP_POINT_ENCODING_UNCOMPRESSED;
          gk->key.key_attrs = attr;
        }
      gk->output_file = ssh_xstrdup(str);
      gk->pk_key_bits = key_bits;
      gk->pk_type = pk_type;
      gk->pk_extra = pk_extra;

      container->subject_key = ssh_xstrdup(str);

      container = ssh_x509_container_alloc(NULL);
      container->type = SSH_X509_FORM_LIST_TYPE_GEN_KEY;
      container->current.gen_pkey = gk;
      ssh_x509_form_list_add_new(state->list, container);
    }

  return ssh_x509_form_finish(pk_node, state);


























 error:
  state->status = SSH_PSYSTEM_ADD_FAILED;
  state->node   = node;
  return FALSE;
}

/* Handle the "signature" block for certificates and CRLs */
Boolean ssh_x509_form_signature(SshPSystemNode sign_node,
                                SshX509FormState state)
{
  SshX509Signature signature;
  SshX509FormContainer container = state->container;
  char *str;
  const SshOidStruct *oid;
  SshPSystemNode node;

  /* Find the signature block to modify */
  if (container->type == SSH_X509_FORM_LIST_TYPE_CRL)
    signature = &container->current.crl->pop.signature;
  else
    signature = &container->current.cert->pop.signature;

  /* Only certificates can be self-signed. */
  if (container->type != SSH_X509_FORM_LIST_TYPE_CRL &&
      ssh_psystem_get_void(sign_node, "SelfSigned", NULL))
    container->self_signed = TRUE;

  /* Signature algorithm */
  if (ssh_psystem_get_name(sign_node, "SignatureAlgorithm", &str, &node))
    {
      SSH_DEBUG(3, ("# Signature algorithm: %s\n", str));
      oid = ssh_oid_find_by_std_name_of_type(str, SSH_OID_SIG);
      if (oid == NULL)
        {
          state->node = node;
          state->status = SSH_PSYSTEM_NOT_SUPPORTED_NAME;
          return FALSE;
        }
      else
        {
          signature->pk_type      = oid->extra_int;
          signature->pk_algorithm = oid->name;
        }
    }

  /* Issuer key name */
  if (ssh_psystem_get_string(sign_node, "*IssuerKeyName", &str, NULL))
      container->issuer_prv_key = str;

  else if (ssh_psystem_get_string(sign_node, "*IssuerKeyFile", &str, NULL))
    {
      ssh_x509_form_add_software_private_key(state, str);
      container->issuer_prv_key = str;
    }

  /* Check for errors */
  return !ssh_psystem_find_error(sign_node, &state->node, &state->status);
}

/********************* Process certificate variables **********************/

/* Handle the common input/output fields of a certificate */
void ssh_x509_form_cert_io_var(SshPSystemNode node,
                               SshX509FormContainer container)
{
  char *str;

  /* '*' means to detach the data from the parse tree so its
     ownership can be transferred to the container. */
  if (ssh_psystem_get_string(node, "*OutputFile", &str, NULL))
    {
      container->output_file = str;
    }
#if 0
  if (ssh_psystem_get_int(node, "OutputID", &mp_int, NULL))
    {
      container->output_id = ssh_mprz_get_ui(mp_int);
    }
#endif
  if (container->type != SSH_X509_FORM_LIST_TYPE_CRL &&
      ssh_psystem_get_string(node, "*InputCertificateRequestFile", &str, NULL))
    {
      container->input_request_file = str;
    }
}

static const SshKeywordStruct ssh_x509_form_copy_map[] =
{
  { "CopySubjectNameFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_SUBJECT_NAME },
  { "CopySubjectAltNameIPExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_IP },
  { "CopySubjectAltNameEMAILExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_EMAIL },
  { "CopySubjectAltNameDNSExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DNS },
  { "CopySubjectAltNameURIExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_URI },
  { "CopySubjectAltNameRIDExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_RID },
  { "CopySubjectAltNameDNExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DN },
  { "CopyKeyUsageExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_KEY_USAGE },
  { "CopyBasicConstraintsExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_BASIC_CONSTRAINTS },
  { "CopyCRLDistributionPointExtFromRequest",
    SSH_X509_FORM_COPY_FROM_REQ_EXT_CRL_DIST_POINT },
  { 0 }
};

/* Handle the various "copy-from-request" flags */
void
ssh_x509_form_cert_copy_var(SshPSystemNode node,
                            SshX509FormContainer container)
{
  const SshKeywordStruct *map;
  map = ssh_x509_form_copy_map;
  for (; map->name != NULL; map++)
    {
      if (ssh_psystem_get_void(node, map->name, NULL))
        {
          container->copy_from_request |= map->code;
          SSH_DEBUG(3, (" ## %s\n", map->name));
        }
    }
}

/* Handle certificate (and certificate request) variables/environments */
Boolean
ssh_x509_form_cert_var(SshPSystemNode cert_node, SshX509Certificate c,
                       SshX509FormState state)
{
  SshMPInteger mp_int;
  char *cstr;
  SshStr str;
  Boolean rv;
  SshPSystemNode p;
  SshX509FormContainer container = state->container;

  /* Handle the "infrastructure" fields first. */
  ssh_x509_form_cert_io_var(cert_node, container);

  /* Version (ignored) */
  if (ssh_psystem_get_int(cert_node, "Version", &mp_int, &p))
    {
    }

  /* Serial number */
  if (ssh_psystem_get_int(cert_node, "SerialNumber", &mp_int, &p))
    {
      SSH_DEBUG(3, (" ## serial number\n"));
      if (ssh_mprz_cmp_ui(mp_int, 0) < 0)
        goto error;
      else
        ssh_mprz_set(&c->serial_number, mp_int);
    }

  /* Subject name */
  if (ssh_psystem_get_ldap(cert_node, "SubjectName", &cstr, &p))
    {
      SSH_DEBUG(3, (" ## subject name : %s\n", cstr));
      if ((str = ssh_str_make(input_encoding,
                              ssh_strdup(cstr), strlen(cstr))) == NULL)
        goto error;
      if (!ssh_x509_cert_set_subject_name_str(c, str))
        {
          ssh_str_free(str);
          goto error;
        }
      ssh_str_free(str);
    }

  /* Issuer name */
  if (ssh_psystem_get_ldap(cert_node, "IssuerName", &cstr, &p))
    {
      SSH_DEBUG(3, (" ## issuer name : %s\n", cstr));
      if ((str = ssh_str_make(input_encoding,
                              ssh_strdup(cstr), strlen(cstr))) == NULL)
        goto error;
      if (!ssh_x509_cert_set_issuer_name_str(c, str))
        {
          ssh_str_free(str);
          goto error;
        }
      ssh_str_free(str);
    }

  /* Issuer & subject unique IDs */
  if (ssh_psystem_get_string(cert_node, "IssuerUniqueID", &cstr, &p))
    {
      ssh_x509_cert_set_issuer_unique_identifier(c, p->data, p->data_len);
    }
  if (ssh_psystem_get_string(cert_node, "SubjectUniqueID", &cstr, &p))
    {
      ssh_x509_cert_set_subject_unique_identifier(c, p->data, p->data_len);
    }

  /* Specify the key name (which refers to a PrivateKey environment
     elsewhere) for subject private key. */
  if (ssh_psystem_get_string(cert_node, "*SubjectKeyName", &cstr, &p))
    container->subject_key = cstr;

  /* Copy various things from the certificate request. */
  ssh_x509_form_cert_copy_var(cert_node, container);

  /* Handle nested environments */
  rv = TRUE;
  if (ssh_psystem_get_env(cert_node, "Validity", &p))
    rv = ssh_x509_form_cert_validity(p, c, state);

  if (rv && ssh_psystem_get_env(cert_node, "Signature", &p))
    rv = ssh_x509_form_signature(p, state);

  if (rv && ssh_psystem_get_env(cert_node, "PublicKeyInfo", &p))
    rv = ssh_x509_form_cert_public_key(p, c, state);

  if (rv && ssh_psystem_get_env(cert_node, "Extensions", &p))
    rv = ssh_x509_form_cert_extensions(p, c, state);

  if (!rv)
    return FALSE;

  /* Everything has been processed, so any leftover nodes are errors */
  if (ssh_psystem_find_error(cert_node, &state->node, &state->status))
    return FALSE;

  return TRUE;

 error:

  ssh_warning("String conversion failed due to invalid input character set.");
  state->node = p;
  state->status = SSH_PSYSTEM_ADD_FAILED;
  return FALSE;
}

/*************************** Processing CRLs ******************************/

/* CRL reason code entry extension */
static const SshKeywordStruct ssh_x509_form_crl_entry_reason_map[] =
{
  { "keyCompromise",        SSH_X509_CRLF_KEY_COMPROMISE },
  { "cACompromise",         SSH_X509_CRLF_CA_COMPROMISE },
  { "affiliationChanged",   SSH_X509_CRLF_AFFILIATION_CHANGED },
  { "superseded",           SSH_X509_CRLF_SUPERSEDED },
  { "cessationOfOperation", SSH_X509_CRLF_CESSATION_OF_OPERATION },
  { "certificateHold",      SSH_X509_CRLF_CERTIFICATE_HOLD },
  { "removeFromCRL",        SSH_X509_CRLF_REMOVE_FROM_CRL },
  { NULL }
};

/* Handle the revoked certificates list */
Boolean
ssh_x509_form_revoked_certs(SshPSystemNode rvk_node,
                            SshX509Crl c, SshX509FormState state)
{
  SshPSystemNode node, rnode;

  while (ssh_psystem_get_any(rvk_node, &node))
    {
      /* Each NODE is a list entry, an unnamed environment */
      SshX509RevokedCerts r = ssh_x509_revoked_allocate ();
      SshMPInteger mp_int;
      SshBerTimeStruct ber_time;
      char* str;

      SSH_DEBUG(3, ("## Revoked cert\n"));

      /* Add the new entry at tail of list */
      ssh_x509_crl_add_revoked(c, r);

      /* Process the fields */
      if (ssh_psystem_get_int(node, "SerialNumber", &mp_int, &rnode))
        {
          SSH_DEBUG(3, (" **** serial number\n"));
          if (ssh_mprz_cmp_ui(mp_int, 0) < 0)
            goto error;
          ssh_x509_revoked_set_serial_number(r, mp_int);
        }

      if (ssh_psystem_get_string(node, "RevocationDate", &str, &rnode))
        {
          SSH_DEBUG(3, (" **** revocation date: %s\n", str));
          if (!ssh_validate_time_string(&ber_time, str))
            goto error;
          ssh_x509_revoked_set_revocation_date(r, &ber_time);
        }

      if (ssh_psystem_get_env(node, "Extensions", &rnode))
        {
          SshPSystemNode ext_node = rnode;

          if (ssh_psystem_get_name(ext_node, "Reason", &str, &rnode))
            {
              const SshKeywordStruct* map;
              long reason = -1;

              /* Convert the reason name into number */
              for (map = ssh_x509_form_crl_entry_reason_map;
                   map->name != NULL && reason < 0;
                   map++)
                {
                  if (strcmp(str, map->name) == 0)
                      reason = map->code;
                }
              if (reason < 0)
                goto error;
              SSH_DEBUG(3, ("**** CRL reason code %ld\n", reason));
              ssh_x509_revoked_set_reason_code(r,
                                               (SshX509CRLReasonCode) reason,
                                               FALSE);
            }
          if (ssh_psystem_get_name(ext_node, "HoldInstruction",
                                   &str, &rnode))
            {
              const char* hold_inst;
              if (strcmp(str, "none") == 0)
                hold_inst = SSH_X509_HOLD_INST_CODE_NONE;
              else if (strcmp(str, "callIssuer") == 0)
                hold_inst = SSH_X509_HOLD_INST_CODE_CALLISSUER;
              else if (strcmp(str, "reject") == 0)
                hold_inst = SSH_X509_HOLD_INST_CODE_REJECT;
              else
                goto error;

              SSH_DEBUG(3, ("**** CRL hold inst code %s\n", hold_inst));
              ssh_x509_revoked_set_hold_instruction_code(r, hold_inst, FALSE);
            }
          if (ssh_psystem_get_string(ext_node, "InvalidityDate",
                                     &str, &rnode))
            {
              if (!ssh_validate_time_string(&ber_time, str))
                goto error;
              ssh_x509_revoked_set_invalidity_date(r, &ber_time, FALSE);
            }
          if (ssh_psystem_get_env(ext_node, "CertificateIssuer", &rnode))
            {
              SshX509Name issuer_names;
              Boolean critical;

              if (!ssh_x509_form_alt_names(rnode,
                                           &issuer_names,
                                           &critical, state))
                return FALSE;

              ssh_x509_revoked_set_certificate_issuer(r, issuer_names,
                                                      critical);
            }
          if (!ssh_x509_form_finish(ext_node, state))
            return FALSE;
        }

      if (!ssh_x509_form_finish (node, state))
        return FALSE;
    }
  return TRUE;

 error:
  state->node = rnode;
  state->status = SSH_PSYSTEM_ADD_FAILED;
  return FALSE;
}

/* Handle the issuing distribution point CRL extension */
Boolean
ssh_x509_form_issuing_dist_point(SshPSystemNode dp_node,
                                 SshX509Crl c, SshX509FormState state)
{
  SshX509ExtIssuingDistPoint dp;
  SshPSystemNode node;
  char *name;
  const SshKeywordStruct *key;
  Boolean critical;

  SSH_DEBUG(3, ("## CRL issuing distribution point\n"));
  dp = ssh_xcalloc(1, sizeof(*dp));
  critical = ssh_psystem_get_void(dp_node, "Critical", NULL);

  /* Attach the DP structure to the CRL. This way the cert
     library will clean up if we happen to fail. */
  ssh_x509_crl_set_issuing_dist_point(c, dp, critical);

  /* Handle the full name environment; name relative to CRL issuer
     can be used only if there's no FullName. */
  if (ssh_psystem_get_env(dp_node, "FullName", &node))
    {
      if (!ssh_x509_form_alt_names(node, &dp->full_name, NULL, state))
        return FALSE;
    }
  else if (ssh_psystem_get_ldap(dp_node, "IssuerRelativeDN", &name, NULL))
    {
      dp->dn_relative_to_issuer = ssh_xcalloc(1, sizeof(SshDNStruct));
      ssh_dn_init(dp->dn_relative_to_issuer);
      ssh_dn_decode_ldap((unsigned char *)name, dp->dn_relative_to_issuer);
    }

  /* Handle the reason flags */
  for (key = ssh_x509_form_crl_reason_map; key->name; key++)
    {
      if (ssh_psystem_get_void(dp_node, key->name, NULL))
        dp->only_some_reasons |= key->code;
    }

  /* Handle the other flags */
  if (ssh_psystem_get_void(dp_node, "OnlyContainsCACerts", NULL))
    dp->only_contains_ca_certs = TRUE;
  if (ssh_psystem_get_void(dp_node, "OnlyContainsUserCerts", NULL))
    dp->only_contains_user_certs = TRUE;
  if (ssh_psystem_get_void(dp_node, "IndirectCRL", NULL))
    dp->indirect_crl = TRUE;

  /* We're finished with this environment */
  return ssh_x509_form_finish(dp_node, state);
}


/* Handle CRL extensions */
Boolean
ssh_x509_form_crl_extensions(SshPSystemNode ext_node,
                             SshX509Crl c, SshX509FormState state)
{
  SshPSystemNode node;
  SshX509Name names;
  Boolean critical;
  SshMPInteger mp;

  SSH_DEBUG(3, ("## CRL extensions\n"));

  if (ssh_psystem_get_env(ext_node, "AuthKeyIdentifier", &node))
    {
      SshX509ExtKeyId key_id;

      if (!ssh_x509_form_auth_key_identifier(node, &key_id, state))
        return FALSE;
      critical = ssh_psystem_get_void(node, "Critical", NULL);
      ssh_x509_crl_set_authority_key_id(c, key_id, critical);
    }

  if (ssh_psystem_get_env(ext_node, "IssuerAltNames", &node))
    {
      if (!ssh_x509_form_alt_names(node, &names, &critical, state))
        return FALSE;
      ssh_x509_crl_set_issuer_alternative_names(c, names, critical);
    }

  if (ssh_psystem_get_env(ext_node, "IssuingDistributionPoint", &node))
    if (!ssh_x509_form_issuing_dist_point(node, c, state))
      return FALSE;

  if (ssh_psystem_get_int(ext_node, "CRLNumber", &mp, &node))
    ssh_x509_crl_set_crl_number(c, mp, FALSE);

  /* Delta CRL number must be critical */
  if (ssh_psystem_get_int(ext_node, "DeltaCRLNumber", &mp, &node))
    ssh_x509_crl_set_delta_crl_indicator(c, mp, TRUE);

  return ssh_x509_form_finish(ext_node, state);
}

/******************* Processing top-level structures **********************/

void
ssh_x509_form_new_cert(SshX509FormState state, SshX509CertType cert_type)
{
  /* Allocate a new container */
  state->container = ssh_x509_container_alloc(NULL);
  if (cert_type == SSH_X509_PKIX_CERT)
    state->container->type = SSH_X509_FORM_LIST_TYPE_CERT;
  else
    state->container->type = SSH_X509_FORM_LIST_TYPE_REQUEST;

  /* Allocate a certificate or certificate request */
  state->container->current.cert = ssh_x509_cert_allocate(cert_type);
}

void
ssh_x509_form_new_crl(SshX509FormState state)
{
  state->container = ssh_x509_container_alloc(NULL);
  state->container->type = SSH_X509_FORM_LIST_TYPE_CRL;
  state->container->current.crl = ssh_x509_crl_allocate();
}

/* Allocate certificate structure and process certificate fields */
Boolean
ssh_x509_form_certificate(SshPSystemNode root,
                          SshX509FormState state)
{
  SshX509Certificate c;

  ssh_x509_form_new_cert(state, SSH_X509_PKIX_CERT);
  c = state->container->current.cert;

  if (!ssh_x509_form_cert_var(root, c, state))
    return FALSE;

  return TRUE;
}

/* Allocate certificate request structure and process certificate fields */
Boolean
ssh_x509_form_cert_req(SshPSystemNode root, SshX509CertType type,
                       SshX509FormState state)
{
  SshX509Certificate c;
  SshX509FormContainer container;

  ssh_x509_form_new_cert(state, type);
  container = state->container;

  c = container->current.cert;

  if (type == SSH_X509_PKCS_10)
    container->request_extension_style = SSH_X509_REQ_EXTENSION_PKCS9_REQ;

  if (!ssh_x509_form_cert_var(root, c, state))
    return FALSE;
  return TRUE;
}

/* Allocate CRL structure and process CRL fields */
Boolean
ssh_x509_form_crl(SshPSystemNode crl_node, SshX509FormState state)
{
  SshX509Crl c;
  char *cstr;
  SshStr str;
  SshPSystemNode node = NULL;

  ssh_x509_form_new_crl(state);
  c = state->container->current.crl;


  /* Handle the "infrastructure" (output file etc.) fields first. */
  ssh_x509_form_cert_io_var(crl_node, state->container);

  /* Name of CRL issuer */
  if (ssh_psystem_get_ldap(crl_node, "IssuerName", &cstr, NULL))
    {
      if ((str = ssh_str_make(input_encoding,
                              ssh_strdup(cstr), strlen(cstr))) == NULL)
        goto error;
      if (!ssh_x509_crl_set_issuer_name_str(c, str))
        {
          ssh_str_free(str);
          goto error;
        }
      ssh_str_free(str);
    }

  /* Time of current update */
  if (ssh_psystem_get_string(crl_node, "ThisUpdate", &cstr, &node))
    if (!ssh_validate_time_string(&c->this_update, cstr))
      goto error;

  /* Time of next update */
  if (ssh_psystem_get_string(crl_node, "NextUpdate", &cstr, &node))
    {
      if (ssh_validate_time_string(&c->next_update, cstr))
        c->use_next_update = TRUE;
      else
        goto error;
    }

  /* List of revoked certificates */
  if (ssh_psystem_get_list(crl_node, "RevokedCertificates", &node))
    if (!ssh_x509_form_revoked_certs(node, c, state))
      return FALSE;

  /* Signature */
  if (ssh_psystem_get_env(crl_node, "Signature", &node))
    if (!ssh_x509_form_signature(node, state))
      return FALSE;

  /* Extensions */
  if (ssh_psystem_get_env(crl_node, "Extensions", &node))
    if (!ssh_x509_form_crl_extensions(node, c, state))
      return FALSE;

  return ssh_x509_form_finish(crl_node, state);

 error:
  state->status = SSH_PSYSTEM_ADD_FAILED;
  state->node = node;
  return FALSE;
}

/* Handle key provider/generation environments */
Boolean
ssh_x509_form_add_provider(SshPSystemNode root, SshX509FormState state)
{
  SshX509FormAddProvider ap;
  char *str;
  SshMPInteger mp;

  state->container = ssh_x509_container_alloc(NULL);
  state->container->type = SSH_X509_FORM_LIST_TYPE_PROVIDER;

  ap = ssh_xcalloc(1, sizeof(*ap));
  state->container->current.provider = ap;

  /* Type is mandatory, other fields are optional. */
  if (!ssh_psystem_get_string(root, "*Type", &str, NULL))
    {
      state->status = SSH_PSYSTEM_COULD_NOT_ADD;
      state->node   = root;
      return FALSE;
    }

  ap->type = str;

  if (ssh_psystem_get_string(root, "*Initialization", &str, NULL))
    ap->init_str = str;

  if (ssh_psystem_get_void(root, "Accelerator", NULL))
    ap->flags = SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR;

  if (ssh_psystem_get_int(root, "Timeout", &mp, NULL))
    ap->timeout_sec = ssh_mprz_get_ui(mp);

  return ssh_x509_form_finish(root, state);
}

Boolean
ssh_x509_form_private_key(SshPSystemNode root, SshX509FormState state)
{
  SshX509FormPrivateKey pk;
  char *str;

  state->container = ssh_x509_container_alloc(NULL);
  state->container->type = SSH_X509_FORM_LIST_TYPE_KEY;

  pk = ssh_xcalloc(1, sizeof(*pk));
  state->container->current.pkey = pk;

  /* Name and path are mandatory, other fields are optional. */
  if (!ssh_psystem_get_string(root, "*Name", &str, NULL))
    goto error;

  pk->name = str;

  if (ssh_psystem_get_string(root, "*Path", &str, NULL))
    pk->key_path = str;

  /* Let's help the user a tiny bit here. */
  if (ssh_psystem_get_string(root, "PrivateKeyFile", &str, NULL))
    {
      int n = strlen(str);
      int nprefix = strlen(ssh_x509_form_software_prefix);
      SshMPInteger mp;

      pk->key_path = ssh_xmalloc(n + nprefix + 1);
      strcpy(pk->key_path, ssh_x509_form_software_prefix);
      strcat(pk->key_path, str);

      /* Ignore the following */
      ssh_psystem_get_int(root, "Size", &mp, NULL);
      ssh_psystem_get_name(root, "Type", &str, NULL);
    }

  if (!pk->key_path)
    goto error;

  if (ssh_psystem_get_string(root, "*AuthenticationCode", &str, NULL))
    pk->auth_code = str;

  return ssh_x509_form_finish(root, state);

 error:
  state->status = SSH_PSYSTEM_COULD_NOT_ADD;
  state->node   = root;
  return FALSE;
}

Boolean
ssh_x509_form_gen_private_key(SshPSystemNode root, SshX509FormState state)
{
  SshX509FormGenPrivateKey pk;
  SshPSystemNode node = root;
  SshMPInteger mp_int;
  char* str;

  state->container = ssh_x509_container_alloc(NULL);
  state->container->type = SSH_X509_FORM_LIST_TYPE_GEN_KEY;

  pk = ssh_xcalloc(1, sizeof(*pk));
  state->container->current.gen_pkey = pk;

  /* Name and path are mandatory, other fields are optional. */
  if (!ssh_psystem_get_string(root, "*Name", &str, NULL))
    goto error;

  pk->key.name = str;

  /* Output file name */
  if (!ssh_psystem_get_string(root, "*PrivateKeyFile", &str, NULL))
    goto error;

  pk->output_file = str;
  pk->key.key_path = ssh_x509_form_alloc_software_key_path(str);

  /* Key size */
  if (ssh_psystem_get_int(root, "Size", &mp_int, &node))
    {
      /* Verify that the range is reasonable */
      if (ssh_mprz_cmp_ui(mp_int, (1 << 24)) > 0 ||
          ssh_mprz_cmp_ui(mp_int, 256) < 0)
        goto error;

      pk->pk_key_bits = ssh_mprz_get_ui(mp_int);
    }
  if (ssh_psystem_get_name(root, "Type", &str, &node))
    {
      const SshOidStruct *oids;
      oids = ssh_oid_find_by_std_name_of_type(str, SSH_OID_PK);
      if (!oids)
        goto error;
      pk->pk_type = oids->name;
      pk->pk_extra = oids->extra;
    }

  return TRUE;

 error:
  state->status = SSH_PSYSTEM_COULD_NOT_ADD;
  state->node   = node;
  return FALSE;
}

Boolean
ssh_x509_form_root(SshPSystemNode root, SshX509FormState state)
{
  SshPSystemNode node;
  Boolean r;

  /* The order of the various entries is important, so we
     walk the list with match_any. */
  while (ssh_psystem_get_any(root, &node))
    {
      if (ssh_psystem_match_env_node(node, "Certificate"))
        r = ssh_x509_form_certificate(node, state);

      else if (ssh_psystem_match_env_node(node, "CertificateRequest") ||
               ssh_psystem_match_env_node(node, "CertificateRequestPkcs10"))
        r = ssh_x509_form_cert_req(node, SSH_X509_PKCS_10, state);

      else if (ssh_psystem_match_env_node(node, "CertificateRequestCrmf"))
        r = ssh_x509_form_cert_req(node, SSH_X509_PKIX_CRMF, state);

      else if (ssh_psystem_match_env_node(node, "CRL"))
        r = ssh_x509_form_crl(node, state);

      else if (ssh_psystem_match_env_node(node, "AddProvider"))
        r = ssh_x509_form_add_provider(node, state);

      else if (ssh_psystem_match_env_node(node, "PrivateKey"))
        r = ssh_x509_form_private_key(node, state);

      else if (ssh_psystem_match_env_node(node, "GeneratePrivateKey"))
        r = ssh_x509_form_gen_private_key(node, state);

      else
        {
          /* Unknown environment */
          state->node = node;
          state->status = SSH_PSYSTEM_UNKNOWN_LANGUAGE;
          return FALSE;
        }

      /* Add to form list if the creation succeeded. If it failed,
         destroy the container (and any certificate with it). */
      if (r == TRUE)
        {
          ssh_x509_form_list_add_new(state->list, state->container);
          state->container = NULL;
        }
      else
        {
          if (state->container)
            {
              ssh_x509_container_free(state->container);
              state->container = NULL;
            }
          return FALSE;
        }
    }
  return TRUE;
}

/********************************************************************/

/* Helper function to provide the parse system with input */
typedef struct
{
  unsigned char *buf;
  size_t buf_len;
} SshX509FormString;

int ssh_x509_form_read_more(void *context, unsigned char **buf,
                            size_t *buf_len)
{
  SshX509FormString *str = context;

  if (str->buf == NULL || str->buf_len == 0)
    return 1;

  /* Copy. */
  *buf = ssh_xmalloc(str->buf_len);
  memcpy(*buf, str->buf, str->buf_len);
  *buf_len = str->buf_len;

  str->buf_len = 0;
  str->buf = NULL;
  return 0;
}

void ssh_x509_form_parse(unsigned char *buf, size_t buf_len,
                         SshX509FormList forms,
                         SshPSystemError error)
{
  SshPSystemDefStruct def;
  SshX509FormString str;
  SshPSystemNode node;
  struct SshX509FormStateRec state;

  /* Set up the string. */
  str.buf     = buf;
  str.buf_len = buf_len;

  /* Set up the form parsing. */
  def.root            = NULL; /*ssh_x509_form_root_def;*/
  def.feeding         = forms;
  def.assign_operator = "::=";
  def.more            = ssh_x509_form_read_more;
  def.more_context    = &str;

  /* Run the parse system. */
  ssh_psystem_parse_tree(&def, error, &node);
  if (error->status == SSH_PSYSTEM_OK && node != 0)
    {
      state.status = SSH_PSYSTEM_OK;
      state.node = node;
      state.list = forms;
      state.container = NULL;

      ssh_x509_form_root(node, &state);
      error->status = state.status;
      if (state.status != SSH_PSYSTEM_OK)
        {
          error->line = state.node->line;
          error->pos  = state.node->column;
        }

      ssh_psystem_free_node(node);
    }
}

/* End. */

/******************************************************/
#endif /* SSHDIST_CERT */
