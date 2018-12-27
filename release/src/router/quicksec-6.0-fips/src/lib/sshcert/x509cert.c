/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic certificate handling functions (allocation, freeing etc).
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCert"

/**** Initialization and clearing routines. */

/* The X.509 signature structure. */

void ssh_x509_signature_init(SshX509Signature s)
{
  s->pk_type       = SSH_X509_PKALG_UNKNOWN;
  s->pk_algorithm  = NULL;
  s->signature     = NULL;
  s->signature_len = 0;
}

void ssh_x509_signature_clear(SshX509Signature s)
{
  if (s == NULL)
    return;
  ssh_free(s->signature);
  ssh_x509_signature_init(s);
}

/* The Mac value structure. */
void ssh_x509_mac_value_init(SshX509MacValue m)
{
  m->pswbmac       = NULL;
  m->value         = NULL;
  m->value_len     = 0;
}

void ssh_x509_mac_value_clear(SshX509MacValue m)
{
  if (m == NULL)
    return;
  if (m->pswbmac)
    ssh_free(m->pswbmac);

  ssh_free(m->value);
  ssh_x509_mac_value_init(m);
}

/* Public key type. */
void ssh_x509_public_key_init(SshX509PublicKey p)
{
  p->pk_type                = SSH_X509_PKALG_UNKNOWN;
  p->subject_key_usage_mask = 0;
  p->ca_key_usage_mask      = 0;
  p->public_key             = NULL;
  p->public_group           = NULL;
}

void ssh_x509_public_key_clear(SshX509PublicKey p)
{
  if (p == NULL)
    return;
  if (p->public_key)
    ssh_public_key_free(p->public_key);
  if (p->public_group)
    ssh_pk_group_free(p->public_group);
  ssh_x509_public_key_init(p);
}

/* Pop information. */
void ssh_x509_pop_init(SshX509Pop p)
{
  p->proved_message     = NULL;
  p->proved_message_len = 0;

  p->ra_verified        = FALSE;

  /* Sender names. */
  p->sender             = NULL;

  /* Clean the signature. */
  ssh_x509_signature_init(&p->signature);
  ssh_x509_mac_value_init(&p->mac);
  ssh_x509_public_key_init(&p->pkey);

  p->this_message     = NULL;
  p->this_message_len = 0;

  p->subsequent_message = SSH_X509_POP_SUBSEQ_UNDEF;
}

void ssh_x509_pop_clear(SshX509Pop p)
{
  if (p == NULL)
    return;

  ssh_free(p->proved_message);
  p->proved_message     = NULL;
  p->proved_message_len = 0;

  p->ra_verified        = FALSE;

  /* Sender names. */
  if (p->sender != NULL)
    ssh_x509_name_free(p->sender);
  p->sender             = NULL;

  /* Clean the signature. */
  ssh_x509_signature_clear(&p->signature);
  ssh_x509_mac_value_clear(&p->mac);
  ssh_x509_public_key_clear(&p->pkey);

  ssh_free(p->this_message);
  p->this_message     = NULL;
  p->this_message_len = 0;

  p->subsequent_message = SSH_X509_POP_SUBSEQ_UNDEF;
}

/* Handle the publication info. */
void ssh_x509_publication_info_init(SshX509PublicationInfo p)
{
  p->action = SSH_X509_PUB_ACTION_DO_NOT_PUBLISH;
  p->nodes  = NULL;
}

/* Publication nodes. */
void ssh_x509_publication_info_node_init(SshX509PublicationInfoNode p)
{
  p->next = NULL;
  p->publication_method = SSH_X509_PUB_METHOD_DONT_CARE;
  p->location = NULL;
}

void ssh_x509_publication_info_node_clear(SshX509PublicationInfoNode p)
{
  if (p == NULL)
    return;

  p->next = NULL;
  p->publication_method = SSH_X509_PUB_METHOD_DONT_CARE;
  if (p->location != NULL)
    ssh_x509_name_free(p->location);
  p->location = NULL;
}

void ssh_x509_publication_info_clear(SshX509PublicationInfo p)
{
  SshX509PublicationInfoNode node, next_node;

  if (p == NULL)
    return;

  p->action = SSH_X509_PUB_ACTION_DO_NOT_PUBLISH;
  for (node = p->nodes; node; node = next_node)
    {
      next_node = node->next;

      ssh_x509_publication_info_node_clear(node);
      ssh_free(node);
    }
  p->nodes  = NULL;
}

/* Encrypted value. */
void ssh_x509_encrypted_value_init(SshX509EncryptedValue e)
{
  e->intended_alg  = NULL;
  e->symmetric_alg = NULL;
  e->symmetric_alg_iv      = NULL;
  e->symmetric_alg_iv_len  = 0;
  e->key_alg       = NULL;

  e->encrypted_sym_key     = NULL;
  e->encrypted_sym_key_len = 0;

  e->value_hint     = NULL;
  e->value_hint_len = 0;

  e->encrypted_value     = NULL;
  e->encrypted_value_len = 0;
}

void ssh_x509_encrypted_value_clear(SshX509EncryptedValue e)
{
  if (e == NULL)
    return;

  ssh_free(e->intended_alg);
  ssh_free(e->symmetric_alg);
  ssh_free(e->symmetric_alg_iv);
  ssh_free(e->key_alg);

  ssh_free(e->encrypted_sym_key);
  ssh_free(e->value_hint);
  ssh_free(e->encrypted_value);
}

/* Archive options. */
void ssh_x509_archive_options_init(SshX509ArchiveOptions a)
{
  a->archive_prv_key = FALSE;
  a->encrypted_value = NULL;
  a->keygen_parameters     = NULL;
  a->keygen_parameters_len = 0;
}

void ssh_x509_archive_options_clear(SshX509ArchiveOptions a)
{
  if (a == NULL)
    return;

  ssh_x509_encrypted_value_clear(a->encrypted_value);
  ssh_free(a->encrypted_value);
  ssh_free(a->keygen_parameters);
  ssh_x509_archive_options_init(a);
}

/* Handling of the certificate id. */
void ssh_x509_cert_id_init(SshX509CertId c)
{
  c->issuer = NULL;
  ssh_mprz_init_set_si(&c->serial_no, -1);
}

void ssh_x509_cert_id_clear(SshX509CertId c)
{
  if (c == NULL)
    return;

  if (c->issuer != NULL)
    ssh_x509_name_free(c->issuer);
  c->issuer = NULL;
  ssh_mprz_clear(&c->serial_no);
}

/* Controls. */
void ssh_x509_controls_init(SshX509Controls c)
{
  c->node    = NULL;
  c->unknown = 0;
}

void ssh_x509_controls_node_init(SshX509ControlsNode n)
{
  n->next = NULL;
  n->type = SSH_X509_CTRL_NONE;
}

void ssh_x509_controls_node_clear(SshX509ControlsNode n)
{
  if (n == NULL)
    return;

  switch (n->type)
    {
    case SSH_X509_CTRL_NONE:
      break;
    case SSH_X509_CTRL_REG_TOKEN:
      ssh_str_free(n->s.reg_token);
      break;
    case SSH_X509_CTRL_AUTHENTICATOR:
      ssh_str_free(n->s.authenticator);
      break;
    case SSH_X509_CTRL_PKI_INFO:
      ssh_x509_publication_info_clear(&n->s.pki_info);
      break;
    case SSH_X509_CTRL_PKI_OPTIONS:
      ssh_x509_archive_options_clear(&n->s.pki_options);
      break;
    case SSH_X509_CTRL_OLD_CERT_ID:
      ssh_x509_cert_id_clear(&n->s.old_cert_id);
      break;
    case SSH_X509_CTRL_PUBLIC_KEY:
      ssh_x509_public_key_clear(&n->s.public_key);
      break;
    }
  /* Clean the node. */
  n->type = SSH_X509_CTRL_NONE;
  n->next = NULL;
}

void ssh_x509_controls_clear(SshX509Controls c)
{
  SshX509ControlsNode node, next_node;

  if (c == NULL)
    return;

  for (node = c->node; node; node = next_node)
    {
      next_node = node->next;

      ssh_x509_controls_node_clear(node);
      ssh_free(node);
    }

  c->unknown = 0;
}

/* Key identifiers. */
void ssh_x509_key_id_init(SshX509ExtKeyId k)
{
  k->key_id           = NULL;
  k->key_id_len       = 0;
  k->auth_cert_issuer = NULL;
  ssh_mprz_init_set_si(&k->auth_cert_serial_number, -1);
}

void ssh_x509_key_id_clear(SshX509ExtKeyId k)
{
  if (k == NULL)
    return;

  ssh_free(k->key_id);
  k->key_id     = NULL;
  k->key_id_len = 0;
  if (k->auth_cert_issuer != NULL)
    ssh_x509_name_free(k->auth_cert_issuer);
  k->auth_cert_issuer = NULL;
  ssh_mprz_clear(&k->auth_cert_serial_number);
}

void ssh_x509_key_id_free(SshX509ExtKeyId k)
{
  ssh_x509_key_id_clear(k);
  ssh_free(k);
}

/* Policy information. */

void ssh_x509_policy_qualifier_info_init(SshX509ExtPolicyQualifierInfo i)
{
  /* Clean the list pointer. */
  i->next = NULL;

  /* Init OID */
  i->oid = NULL;

  /* Initialize strings. */
  i->cpsuri = NULL;
  i->organization = NULL;
  i->explicit_text = NULL;

  /* Initialize notice numbers. */
  i->notice_numbers_count = 0;
  i->notice_numbers       = NULL;
}

void ssh_x509_policy_qualifier_info_clear(SshX509ExtPolicyQualifierInfo i)
{
  if (i == NULL)
    return;

  /* Clean the list pointer. */
  i->next = NULL;

  /* Free oid. */
  ssh_free(i->oid);
  i->oid = NULL;

  /* Free cpsuri */
  ssh_str_free(i->cpsuri);
  i->cpsuri = NULL;

  ssh_str_free(i->organization);
  i->organization = NULL;

  /* Free notice numbers. */
  ssh_free(i->notice_numbers);
  i->notice_numbers = NULL;
  i->notice_numbers_count = 0;

  /* Free explicit names. */
  ssh_str_free(i->explicit_text);
  i->explicit_text = NULL;
  /* Done. */
}

void ssh_x509_policy_qualifier_info_free(SshX509ExtPolicyQualifierInfo i)
{
  SshX509ExtPolicyQualifierInfo n;

  while (i)
    {
      n = i->next;
      ssh_x509_policy_qualifier_info_clear(i);
      ssh_free(i);
      i = n;
    }
}

/* Handle the policy information structures. */
void ssh_x509_policy_info_init(SshX509ExtPolicyInfo i)
{
  i->next = NULL;

  /* Clean the oid. */
  i->oid = NULL;

  /* Clean the policy qualifier list. */
  i->pq_list = NULL;
}

void ssh_x509_policy_info_clear(SshX509ExtPolicyInfo i)
{
  if (i == NULL)
    return;

  /* Assume that the list is held together by some higher
     party. */
  i->next = NULL;

  ssh_free(i->oid);
  i->oid = NULL;

  ssh_x509_policy_qualifier_info_free(i->pq_list);
  i->pq_list = NULL;
}

/* Free all policy info's. */
void ssh_x509_policy_info_free(SshX509ExtPolicyInfo i)
{
  SshX509ExtPolicyInfo n;

  while (i)
    {
      n = i->next;
      ssh_x509_policy_info_clear(i);
      ssh_free(i);
      i = n;
    }
}


/* Policy mappings. These are here to help us later. */
void ssh_x509_policy_mappings_init(SshX509ExtPolicyMappings m)
{
  m->next           = NULL;
  m->issuer_dp_oid  = NULL;
  m->subject_dp_oid = NULL;
}

void ssh_x509_policy_mappings_clear(SshX509ExtPolicyMappings m)
{
  if (m == NULL)
    return;

  ssh_free(m->issuer_dp_oid);
  ssh_free(m->subject_dp_oid);
  m->issuer_dp_oid = NULL;
  m->subject_dp_oid = NULL;
}

void ssh_x509_policy_mappings_free(SshX509ExtPolicyMappings m)
{
  SshX509ExtPolicyMappings n;

  while (m)
    {
      n = m->next;
      ssh_x509_policy_mappings_clear(m);
      ssh_free(m);
      m = n;
    }
}

/* Attributes. */
void ssh_x509_directory_attribute_init(SshX509ExtDirAttribute d)
{
  d->next = NULL;
  d->oid = NULL;
  d->octet_string = NULL;
  d->octet_string = 0;
}

void ssh_x509_directory_attribute_clear(SshX509ExtDirAttribute d)
{
  if (d == NULL)
    return;

  ssh_free(d->oid);
  ssh_free(d->octet_string);
  d->next = NULL;
  d->oid = NULL;
  d->octet_string = NULL;
  d->octet_string = 0;
}

void ssh_x509_directory_attribute_free(SshX509ExtDirAttribute d)
{
  SshX509ExtDirAttribute n;

  while (d)
    {
      n = d->next;
      ssh_x509_directory_attribute_clear(d);
      ssh_free(d);
      d = n;
    }
}

/* First routines for general subtrees. */
void ssh_x509_general_subtree_init(SshX509GeneralSubtree g)
{
  g->next = NULL;
  g->name = NULL;
  g->min_distance = 0;
  g->max_distance = 0;
}

void ssh_x509_general_subtree_clear(SshX509GeneralSubtree g)
{
  if (g == NULL)
    return;

  /* Assume that the list is handled by some higher authority. */
  g->next = NULL;
  if (g->name != NULL)
    ssh_x509_name_free(g->name);
  g->min_distance = 0;
  g->max_distance = 0;
  g->name = NULL;
}

void ssh_x509_general_subtree_free(SshX509GeneralSubtree g)
{
  SshX509GeneralSubtree n;

  while (g)
    {
      n = g->next;
      ssh_x509_general_subtree_clear(g);
      ssh_free(g);
      g = n;
    }
}

/* Policy constraints. */
void ssh_x509_policy_const_init(SshX509ExtPolicyConstraints p)
{
  p->require = 0;
  p->inhibit = 0;
}

void ssh_x509_policy_const_clear(SshX509ExtPolicyConstraints p)
{
  if (p == NULL)
    return;

  p->require = 0;
  p->inhibit = 0;
}

void ssh_x509_policy_const_free(SshX509ExtPolicyConstraints p)
{
  ssh_x509_policy_const_clear(p);
  ssh_free(p);
}

/* CRL distribution points. */

void ssh_x509_crl_dist_points_init(SshX509ExtCRLDistPoints dp)
{
  dp->next = NULL;
  dp->full_name = NULL;
  dp->dn_relative_to_issuer = NULL;
  dp->reasons = 0;
  dp->crl_issuer = NULL;
}

void ssh_x509_crl_dist_points_clear(SshX509ExtCRLDistPoints dp)
{
  if (dp == NULL)
    return;

  if (dp->full_name != NULL)
    ssh_x509_name_free(dp->full_name);
  if (dp->crl_issuer != NULL)
    ssh_x509_name_free(dp->crl_issuer);

  if (dp->dn_relative_to_issuer != NULL)
    {
      ssh_dn_clear(dp->dn_relative_to_issuer);
      ssh_free(dp->dn_relative_to_issuer);
    }

  dp->next = NULL;
  dp->full_name = NULL;
  dp->dn_relative_to_issuer = NULL;
  dp->reasons = 0;
  dp->crl_issuer = NULL;
}

void ssh_x509_crl_dist_points_free(SshX509ExtCRLDistPoints c)
{
  SshX509ExtCRLDistPoints n;

  while (c)
    {
      n = c->next;
      ssh_x509_crl_dist_points_clear(c);
      ssh_free(c);
      c = n;
    }
}

/* Handle bit strings. */

/* Find first bit set from the lsb end */
int ssh_x509_find_number_of_bits_used(unsigned char c)
{
  int i;
  for (i = 8; i > 0; i--)
    {
      if (c & 0x1)
        return i;
      c = c >> 1;
    }
  return 0;
}

/* Convert from bitstring to unsigned int. The buffer length must
   be in bits. */
unsigned int ssh_x509_bs_to_ui(unsigned char *buf, size_t buf_len)
{
  unsigned int value;
  size_t       i;

  /* Note. Buf len is in bits. */
  for (i = 0, value = 0; i < buf_len && i < 32; i += 8)
    value |= ((unsigned int)buf[i/8]) << i;
  return value;
}

/* Convert from unsigned int to bitstring. The buffer length will be
   returned in bits. */
unsigned char *
ssh_x509_ui_to_bs(unsigned int value, size_t *buf_len)
{
  size_t i;
  size_t len;
  unsigned char *buf;

  /* The buffer cannot be any longer than this. */
  if ((buf = ssh_calloc(1, sizeof(unsigned int))) == NULL)
    {
      *buf_len = 0;
      return NULL;
    }

  /* Convert exactly. */
  for (i = 0, len = 0; value; i++, len += 8)
    {
      buf[i] = value & 0xff;
      value >>= 8;
      if (value == 0)
        {
          len += ssh_x509_find_number_of_bits_used(buf[i]);
          break;
        }
    }

  *buf_len = len;
  return buf;
}

/* Information access. */
void ssh_x509_info_access_init(SshX509ExtInfoAccess aa)
{
  aa->next = NULL;
  aa->access_method = NULL;
  aa->access_location = NULL;
}

void ssh_x509_info_access_clear(SshX509ExtInfoAccess aa)
{
  if (aa == NULL)
    return;

  if (aa->access_location != NULL)
    {
      ssh_x509_name_free(aa->access_location);
      aa->access_location = NULL;
    }

  ssh_free(aa->access_method);
  aa->access_method = NULL;

  aa->next = NULL;
}

void ssh_x509_info_access_free(SshX509ExtInfoAccess a)
{
  SshX509ExtInfoAccess n;

  while (a)
    {
      n = a->next;
      ssh_x509_info_access_clear(a);
      ssh_free(a);
      a = n;
    }
}

void ssh_x509_qcstatement_init(SshX509ExtQCStatement s)
{
  memset(s, 0, sizeof(*s));
}

void ssh_x509_qcstatement_clear(SshX509ExtQCStatement s)
{
  if (s->oid)
    ssh_free(s->oid);
  if (s->semantics_oid)
    ssh_free(s->semantics_oid);
  ssh_mprz_clear(&s->amount);
  ssh_mprz_clear(&s->exponent);
  ssh_mprz_clear(&s->retention_period);
  if (s->der)
    ssh_free(s->der);
  ssh_x509_qcstatement_init(s);
}

void ssh_x509_qcstatement_free(SshX509ExtQCStatement s)
{
  SshX509ExtQCStatement tmp;

  while (s)
    {
      tmp = s;
      s = tmp->next;
      ssh_x509_qcstatement_clear(tmp);
      ssh_free(tmp);
    }
}

void ssh_x509_unknown_extension_init(SshX509ExtUnknown unknown)
{
  unknown->next = NULL;
  unknown->oid = NULL;
  unknown->name = NULL;
  unknown->der = NULL;
  unknown->der_length = 0;
}

void ssh_x509_unknown_extension_clear(SshX509ExtUnknown unknown)
{
  if (unknown == NULL)
    return;
  ssh_free(unknown->oid);
  ssh_free(unknown->name);
  ssh_free(unknown->der);
  ssh_x509_unknown_extension_init(unknown);

}

void ssh_x509_unknown_extension_free(SshX509ExtUnknown unknown)
{
  SshX509ExtUnknown next;

  while (unknown)
    {
      next = unknown->next;
      ssh_x509_unknown_extension_clear(unknown);
      ssh_free(unknown);
      unknown = next;
    }
}

/* Extended key usage field (handled by oid list routines). */

/* Handle oid lists. */
void ssh_x509_oid_list_init(SshX509OidList list)
{
  list->next    = NULL;
  list->oid     = NULL;
}

void ssh_x509_oid_list_clear(SshX509OidList list)
{
  if (list == NULL)
    return;

  ssh_free(list->oid);
  list->oid     = NULL;
  list->next    = NULL;
}

void ssh_x509_oid_list_free(SshX509OidList list)
{
  SshX509OidList n;
  while (list)
    {
      n = list->next;
      ssh_x509_oid_list_clear(list);
      ssh_free(list);
      list = n;
    }
}

/* Private key usage period encoding, decoding. */

/* Handle the issuer distribution point decoding and encoding. */
void ssh_x509_issuing_dist_point_init(SshX509ExtIssuingDistPoint ip)
{
  ip->full_name                = NULL;
  ip->dn_relative_to_issuer    = NULL;

  ip->only_contains_user_certs = FALSE;
  ip->only_contains_ca_certs   = FALSE;
  ip->only_some_reasons        = 0;
  ip->indirect_crl             = FALSE;
  ip->only_contains_attribute_certs = FALSE;
}

void ssh_x509_issuing_dist_point_clear(SshX509ExtIssuingDistPoint ip)
{
  if (ip == NULL)
    return;

  if (ip->full_name != NULL)
    ssh_x509_name_free(ip->full_name);

  if (ip->dn_relative_to_issuer != NULL)
    {
      ssh_dn_clear(ip->dn_relative_to_issuer);
      ssh_free(ip->dn_relative_to_issuer);
    }
  ssh_x509_issuing_dist_point_init(ip);
}

void ssh_x509_issuing_dist_point_free(SshX509ExtIssuingDistPoint ip)
{
  ssh_x509_issuing_dist_point_clear(ip);
  ssh_free(ip);
}

/* The extensions. */

/* Certificate extensions. */
void ssh_x509_cert_extensions_init(SshX509CertExtensions e)
{
  /* Zero the extension information. */
  e->ext_available = 0L;
  e->ext_critical = 0L;

  e->subject_alt_names = NULL;
  e->issuer_alt_names  = NULL;

  e->subject_key_id = NULL;
  e->issuer_key_id  = NULL;

  ssh_ber_time_zero(&e->private_key_usage_not_before);
  ssh_ber_time_zero(&e->private_key_usage_not_after);

  e->key_usage = 0;
  e->policy_info = NULL;
  e->policy_mappings = NULL;
  e->path_len = SSH_X509_MAX_PATH_LEN;
  e->ca       = FALSE;
  e->subject_directory_attr = NULL;
  e->name_const_permitted = NULL;
  e->name_const_excluded  = NULL;
  e->policy_const = NULL;
  e->crl_dp = NULL;
  e->freshest_crl = NULL;
  e->ext_key_usage = NULL;
  e->auth_info_access = NULL;
  e->netscape_comment = NULL;
  e->cert_template_name = NULL;

  e->subject_info_access = NULL;
}

void ssh_x509_cert_extensions_clear(SshX509CertExtensions e)
{
  if (e == NULL)
    return;

  /* Alternate names. */
  if (e->issuer_alt_names)
    ssh_x509_name_free(e->issuer_alt_names);
  if (e->subject_alt_names)
    ssh_x509_name_free(e->subject_alt_names);

  /* Key identifiers. */
  ssh_x509_key_id_free(e->subject_key_id);
  ssh_x509_key_id_free(e->issuer_key_id);

  /* Policy info. */
  ssh_x509_policy_info_free(e->policy_info);
  /* Policy mappings. */
  ssh_x509_policy_mappings_free(e->policy_mappings);
  /* Directory attributes. */
  ssh_x509_directory_attribute_free(e->subject_directory_attr);
  /* Name constraints. */
  ssh_x509_general_subtree_free(e->name_const_permitted);
  ssh_x509_general_subtree_free(e->name_const_excluded);
  /* Policy constraints. */
  ssh_x509_policy_const_free(e->policy_const);
  /* CRL distribution points. */
  ssh_x509_crl_dist_points_free(e->crl_dp);
  ssh_x509_crl_dist_points_free(e->freshest_crl);

  /* Authentication information access. */

  ssh_x509_info_access_free(e->auth_info_access);
  ssh_str_free(e->netscape_comment);
  ssh_str_free(e->cert_template_name);
  ssh_x509_qcstatement_free(e->qcstatements);
  /* Extended key usage. */
  ssh_x509_oid_list_free(e->ext_key_usage);
  ssh_x509_unknown_extension_free(e->unknown);

  ssh_x509_info_access_free(e->subject_info_access);

  /* Now clean up.
     NOTE: if the init allocates data it must be duplicated here without
     those allocations.
   */
  ssh_x509_cert_extensions_init(e);
}

SshX509Certificate ssh_x509_cert_allocate(SshX509CertType type)
{
  SshX509Certificate c;
  SshX509Config pc;

  /* Allocate the certificate. */
  if ((c = ssh_calloc(1, sizeof(*c))) != NULL)
    {
      c->refcount = 1;

      /* Set up the certificate type. */
      c->type = type;

      /* Initialize to some dummy values. */
      c->version = SSH_X509_VERSION_UNKNOWN;
      ssh_mprz_init_set_ui(&c->serial_number, 0);
      ssh_mprz_init_set_ui(&c->request_id, 0);

      if (ssh_mprz_isnan(&c->serial_number) || ssh_mprz_isnan(&c->request_id))
        {
          /* This actually never happens, as ssh_mprz_init_set_ui()
             does not allocate if value is zero, but let it be for
             sake of completeness. */
          ssh_free(c);
          return NULL;
        }
      /* Clear for safety all values. */
      c->issuer_name = c->subject_name = NULL;

      /* Initialize the public key. */
      ssh_x509_public_key_init(&c->subject_pkey);
      /* Initialize pop. */
      ssh_x509_pop_init(&c->pop);
      /* Initialize controls. */
      ssh_x509_controls_init(&c->controls);

      ssh_ber_time_zero(&c->not_before);
      ssh_ber_time_zero(&c->not_after);

      /* Initialize the extensions. */
      ssh_x509_cert_extensions_init(&c->extensions);

      c->attributes = NULL;

      pc = ssh_x509_get_configuration();
      memmove(&c->config, pc, sizeof(*pc));
    }
  return c;
}

void ssh_x509_cert_reset(SshX509Certificate c)
{
  ssh_x509_name_reset(c->subject_name);
  ssh_x509_name_reset(c->issuer_name);
  ssh_x509_name_reset(c->extensions.subject_alt_names);
  ssh_x509_name_reset(c->extensions.issuer_alt_names);
}

void ssh_x509_verify_async_free(void *context)
{
  SshX509VerifyContext ctx = context;

  /* Clean the context. */
  memset(ctx, 0, sizeof(*ctx));

  ssh_free(ctx);
}

void ssh_x509_verify_async_abort(void *context)
{
  SshX509VerifyContext ctx = context;

  /* We need to abort the crypto operation, note that crypt_handle will be
     valid, because we cannot be here unless the crypto operation was really
     asyncronous (the caller cannot get handle to use to cancel this
     otherwise). */
  ssh_operation_abort(ctx->crypto_handle);
  ssh_x509_verify_async_free(ctx);
}

void ssh_x509_verify_async_finish(SshCryptoStatus status,
                                  void *context)
{
  SshX509Status rv = SSH_X509_OK;
  SshX509VerifyContext ctx = context;

  if (status != SSH_CRYPTO_OK)
    rv = SSH_X509_FAILED_SIGNATURE_CHECK;

  /* Return the issuer signature scheme to where it originally was. */

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(ctx->issuer_key,
                                   SSH_PKF_SIGN, ctx->sign,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    /* We're not really interested in this, but just return an error
       anyway. */
    rv = SSH_X509_FAILURE;

  /* Now explain the situation. */
  (*ctx->verify_cb)(rv, ctx->verify_ctx);

  /* Make sure that the context is freed properly. */
  ssh_operation_unregister(ctx->op_handle);
  ssh_x509_verify_async_free(ctx);
}

SshOperationHandle ssh_x509_cert_verify_async(SshX509Certificate c,
                                              SshPublicKey issuer_key,
                                              SshX509VerifyCB verify_cb,
                                              void *context)
{
  char *sign, *key_type;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshX509VerifyContext ctx;
  SshOperationHandle handle;

  if (verify_cb == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Asynchronous validation called without callback to "
                 "receive certificate status."));
      return NULL;
    }

  if (issuer_key == NULL)
    goto failed;

  if (c->version == SSH_X509_VERSION_UNKNOWN)
    goto failed;

  /* Set the algorithm of the issuer key to correspond the subject. */

  /* Get the signature algorithm type so that we can look very transparent
     to the application. */
  if (ssh_public_key_get_info(issuer_key,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_SIGN, &sign,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    goto failed;

  /* Check that this implementation supports the given algorithm and
     key type pair. */
  algorithm = ssh_x509_match_algorithm(key_type,
                                       c->pop.signature.pk_algorithm, NULL);
  if (algorithm == NULL)
    goto failed;

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(issuer_key,
                                   SSH_PKF_SIGN, c->pop.signature.pk_algorithm,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    goto failed;

  /* Set up the verification context. */
  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    goto failed;

  ctx->sign       = sign;
  ctx->issuer_key = issuer_key;
  ctx->verify_cb  = verify_cb;
  ctx->verify_ctx = context;

  ctx->op_handle = ssh_operation_register(ssh_x509_verify_async_abort, ctx);
  handle =
    ssh_public_key_verify_async(issuer_key,
                                c->pop.signature.signature,
                                c->pop.signature.signature_len,
                                c->pop.proved_message,
                                c->pop.proved_message_len,
                                ssh_x509_verify_async_finish,
                                ctx);

  if (handle == NULL)
    {
      /* Operation already done, the context has already been freed, thus we
         just return NULL here */
      return NULL;
    }
  ctx->crypto_handle = handle;

  return ctx->op_handle;

failed:
  /* Failure case. */
  (*verify_cb)(SSH_X509_FAILURE, context);
  return NULL;
}


void ssh_x509_cert_take_ref(SshX509Certificate c)
{
  SSH_DEBUG(SSH_D_MIDOK,
            ("Increasing reference count of certificate %p to %ld",
             c, c->refcount + 1));
  c->refcount++;
}

void ssh_x509_cert_free(SshX509Certificate c)
{
  SshX509Attribute attr, prev;

  /* Nothing to do? */
  if (c == NULL)
    return;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Decreasing reference count of certificate %p to %ld",
             c, c->refcount - 1));

  if (--c->refcount > 0)
    return;

  /* We assume the if the version is unknown the nothing is allocated. */
  ssh_mprz_clear(&c->serial_number);
  ssh_mprz_clear(&c->request_id);

  /* Free the names (automatically with this routine). */
  if (c->issuer_name)
    ssh_x509_name_free(c->issuer_name);
  if (c->subject_name)
    ssh_x509_name_free(c->subject_name);

  c->issuer_name  = NULL;
  c->subject_name = NULL;

  /* Free public key, pop, controls, extensions and attributes if present */
  ssh_x509_public_key_clear(&c->subject_pkey);
  ssh_x509_pop_clear(&c->pop);
  ssh_x509_controls_clear(&c->controls);
  ssh_x509_cert_extensions_clear(&c->extensions);

  prev = attr = c->attributes;
  while (attr)
    {
      attr = attr->next;
      if (prev->data) ssh_free(prev->data);
      if (prev->oid)  ssh_free(prev->oid);
      ssh_free(prev);
      prev = attr;
    }
  ssh_free(c);
}
#endif /* SSHDIST_CERT */
