/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate & CRL set routines.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

#define LIST_APPEND(node_type, x, y)    \
do {                                    \
  node_type *tmp, *prev;                \
  for (tmp = (x), prev = NULL;          \
       tmp != NULL;                     \
       prev = tmp, tmp = tmp->next)     \
    ;                                   \
  if (prev == NULL)                     \
    (x) = (y);                          \
  else                                  \
    prev->next = (y);                   \
} while (0)

/* Routines for setting the certificate values. */

void ssh_x509_cert_set_serial_number(SshX509Certificate c, SshMPIntegerConst s)
{
  ssh_mprz_set(&c->serial_number, s);
}

Boolean ssh_x509_cert_set_subject_name(SshX509Certificate c,
                                       const unsigned char *name)
{
  return ssh_x509_name_push_ldap_dn(&c->subject_name, name);
}

Boolean ssh_x509_cert_set_subject_name_der(SshX509Certificate c,
                                           const unsigned char *der,
                                           size_t der_len)
{
  return ssh_x509_name_push_der_dn(&c->subject_name, der, der_len);
}


Boolean ssh_x509_cert_set_subject_name_str(SshX509Certificate c,
                                           const SshStr str)
{
  return ssh_x509_name_push_str_dn(&c->subject_name, str);
}

Boolean ssh_x509_cert_set_issuer_name(SshX509Certificate c,
                                      const unsigned char *name)
{
  return ssh_x509_name_push_ldap_dn(&c->issuer_name, name);
}

Boolean ssh_x509_cert_set_issuer_name_der(SshX509Certificate c,
                                          const unsigned char *der,
                                          size_t der_len)
{
  return ssh_x509_name_push_der_dn(&c->issuer_name, der, der_len);
}

Boolean ssh_x509_cert_set_issuer_name_str(SshX509Certificate c,
                                          const SshStr str)
{
  return ssh_x509_name_push_str_dn(&c->issuer_name, str);
}

void ssh_x509_cert_set_validity(SshX509Certificate c,
                                const SshBerTime not_before,
                                const SshBerTime not_after)
{
  if (not_before)
    ssh_ber_time_set(&c->not_before, not_before);
  if (not_after)
    ssh_ber_time_set(&c->not_after, not_after);
}

Boolean ssh_x509_cert_set_public_key(SshX509Certificate c,
                                     const SshPublicKey public_key)
{
  const SshX509PkAlgorithmDefStruct *algorithm;

  if (public_key == NULL)
    return FALSE;

  algorithm = ssh_x509_public_key_algorithm(public_key);
  if (algorithm == NULL)
    return FALSE;

  /* If resetting it */
  if (c->subject_pkey.public_key)
    ssh_public_key_free(c->subject_pkey.public_key);

  if (ssh_public_key_copy(public_key,
                          &c->subject_pkey.public_key) != SSH_CRYPTO_OK)
    return FALSE;

  c->subject_pkey.pk_type = algorithm->algorithm;
  return TRUE;
}

void ssh_x509_cert_set_subject_unique_identifier(SshX509Certificate c,
                                                 const unsigned char *buf,
                                                 size_t buf_len)
{
  ssh_x509_name_push_unique_identifier(&c->subject_name, buf, buf_len);
}

void ssh_x509_cert_set_issuer_unique_identifier(SshX509Certificate c,
                                                const unsigned char *buf,
                                                size_t buf_len)
{
  ssh_x509_name_push_unique_identifier(&c->issuer_name, buf, buf_len);
}

/* Setting up extensions. */

void
ssh_x509_cert_set_subject_alternative_names(SshX509Certificate c,
                                            SshX509Name names,
                                            Boolean critical)
{
  ssh_x509_name_push(&c->extensions.subject_alt_names, names);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_SUBJECT_ALT_NAME, critical);
}

void
ssh_x509_cert_set_issuer_alternative_names(SshX509Certificate c,
                                           SshX509Name names,
                                           Boolean critical)
{
  ssh_x509_name_push(&c->extensions.issuer_alt_names, names);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_ISSUER_ALT_NAME, critical);
}

void
ssh_x509_cert_set_private_key_usage_period(SshX509Certificate c,
                                           const SshBerTime not_before,
                                           const SshBerTime not_after,
                                           Boolean critical)
{
  if (not_before)
    ssh_ber_time_set(&c->extensions.private_key_usage_not_before, not_before);
  if (not_after)
    ssh_ber_time_set(&c->extensions.private_key_usage_not_after, not_after);

  if (not_after || not_before)
    ssh_x509_ext_info_set(&c->extensions.ext_available,
                          &c->extensions.ext_critical,
                          SSH_X509_EXT_PRV_KEY_UP, critical);
}

void
ssh_x509_cert_set_key_usage(SshX509Certificate c,
                            SshX509UsageFlags flags,
                            Boolean critical)
{
  c->extensions.key_usage          = flags;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_KEY_USAGE, critical);
}


void
ssh_x509_cert_set_inhibit_any_policy(SshX509Certificate c,
                                     SshUInt32 ncerts,
                                     Boolean critical)
{
  c->extensions.inhibit_any_skip_certs = ncerts;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_INHIBIT_ANY_POLICY, critical);
}

void
ssh_x509_cert_set_basic_constraints(SshX509Certificate c,
                                    size_t path_length,
                                    Boolean ca,
                                    Boolean critical)
{
  c->extensions.ca = ca;
  c->extensions.path_len = path_length;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_BASIC_CNST, critical);
}

/* Authority key identifier should be set according the policy of the
   CA. There is quite a lot of variation possible here. */
void
ssh_x509_cert_set_authority_key_id(SshX509Certificate c,
                                   SshX509ExtKeyId id,
                                   Boolean critical)
{
  if (c->extensions.issuer_key_id != NULL)
    ssh_x509_key_id_free(c->extensions.issuer_key_id);
  c->extensions.issuer_key_id = id;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_AUTH_KEY_ID, critical);
}

/* For a self-signed certificates the subject identifier should match
   the value in the authority key id, if present. */
void
ssh_x509_cert_set_subject_key_id(SshX509Certificate c,
                                 const unsigned char *key_id,
                                 size_t key_id_len,
                                 Boolean critical)
{
  SshX509ExtKeyId subject_id;

  /* Build the subject key id. */
  if ((subject_id = ssh_malloc(sizeof(*subject_id))) != NULL)
    {
      ssh_x509_key_id_init(subject_id);
      if ((subject_id->key_id = ssh_memdup(key_id, key_id_len)) != NULL)
        {
          subject_id->key_id_len = key_id_len;
          if (c->extensions.subject_key_id != NULL)
            ssh_x509_key_id_free(c->extensions.subject_key_id);
          c->extensions.subject_key_id = subject_id;
          ssh_x509_ext_info_set(&c->extensions.ext_available,
                                &c->extensions.ext_critical,
                                SSH_X509_EXT_SUBJECT_KEY_ID, critical);
        }
      else
        ssh_free(subject_id);
    }
}

void
ssh_x509_cert_set_policy_info(SshX509Certificate c,
                              SshX509ExtPolicyInfo pinfo,
                              Boolean critical)
{
  LIST_APPEND(SshX509ExtPolicyInfoStruct, c->extensions.policy_info, pinfo);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_CERT_POLICIES, critical);
}

void
ssh_x509_cert_set_crl_dist_points(SshX509Certificate c,
                                  SshX509ExtCRLDistPoints dps,
                                  Boolean critical)
{
  LIST_APPEND(SshX509ExtCRLDistPointsStruct, c->extensions.crl_dp, dps);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_CRL_DIST_POINTS, critical);
}

void
ssh_x509_cert_set_freshest_crl(SshX509Certificate c,
                               SshX509ExtCRLDistPoints fresh,
                               Boolean critical)
{
  LIST_APPEND(SshX509ExtCRLDistPointsStruct,
              c->extensions.freshest_crl, fresh);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_FRESHEST_CRL, critical);
}

void
ssh_x509_cert_set_policy_mappings(SshX509Certificate c,
                                  SshX509ExtPolicyMappings pmappings,
                                  Boolean critical)
{
  LIST_APPEND(SshX509ExtPolicyMappingsStruct,
              c->extensions.policy_mappings, pmappings);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_POLICY_MAPPINGS, critical);
}


void
ssh_x509_cert_set_auth_info_access(SshX509Certificate c,
                                   SshX509ExtInfoAccess access,
                                   Boolean critical)
{
  LIST_APPEND(SshX509ExtInfoAccessStruct,
              c->extensions.auth_info_access, access);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_AUTH_INFO_ACCESS, critical);
}

void
ssh_x509_cert_set_subject_info_access(SshX509Certificate c,
                                      SshX509ExtInfoAccess access,
                                      Boolean critical)
{
  LIST_APPEND(SshX509ExtInfoAccessStruct,
              c->extensions.subject_info_access, access);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_SUBJECT_INFO_ACCESS, critical);
}

void
ssh_x509_cert_set_netscape_comment(SshX509Certificate c,
                                   SshStr comment,
                                   Boolean critical)
{
  if (c->extensions.netscape_comment) /* Only one comment is allowed */
    ssh_str_free(c->extensions.netscape_comment);
  c->extensions.netscape_comment = comment;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_NETSCAPE_COMMENT, critical);
}

void
ssh_x509_cert_set_cert_template_name(SshX509Certificate c,
                                     SshStr name,
                                     Boolean critical)
{
  if (c->extensions.cert_template_name)
    ssh_str_free(c->extensions.cert_template_name);
  c->extensions.cert_template_name = name;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_CERT_TEMPLATE_NAME, critical);
}

void
ssh_x509_cert_set_qcstatements(SshX509Certificate c,
                               SshX509ExtQCStatement qcs,
                               Boolean critical)
{
  if (c->extensions.qcstatements)
    ssh_x509_qcstatement_free(c->extensions.qcstatements);
  c->extensions.qcstatements = qcs;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_QCSTATEMENTS, critical);
}

void
ssh_x509_cert_set_subject_dir_attributes(SshX509Certificate c,
                                         SshX509ExtDirAttribute attr,
                                         Boolean critical)
{
  if (c->extensions.subject_directory_attr)
    ssh_x509_directory_attribute_free(c->extensions.subject_directory_attr);
  c->extensions.subject_directory_attr = attr;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_SUBJECT_DIR_ATTR, critical);
}

void
ssh_x509_cert_set_unknown_extension(SshX509Certificate c,
                                    SshX509ExtUnknown unknown)
{
  Boolean critical;

  LIST_APPEND(SshX509ExtUnknownStruct, c->extensions.unknown, unknown);
  /* Get existing criticality bit and 'or' it with criticality bit from
     this extension. */
  if (!ssh_x509_cert_ext_available(c, SSH_X509_EXT_UNKNOWN, &critical))
    critical = FALSE;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_UNKNOWN,
                        critical ? TRUE : unknown->critical);
}

/* Either of the permitted or excluded subtree pointers may be NULL, to
   be considered undefined. */
void
ssh_x509_cert_set_name_constraints(SshX509Certificate c,
                                   SshX509GeneralSubtree permitted,
                                   SshX509GeneralSubtree excluded,
                                   Boolean critical)
{
  if (permitted)
    LIST_APPEND(SshX509GeneralSubtreeStruct,
                c->extensions.name_const_permitted, permitted);
  if (excluded)
    LIST_APPEND(SshX509GeneralSubtreeStruct,
                c->extensions.name_const_excluded, excluded);
  if (permitted || excluded)
    ssh_x509_ext_info_set(&c->extensions.ext_available,
                          &c->extensions.ext_critical,
                          SSH_X509_EXT_NAME_CNST, critical);
}


void
ssh_x509_cert_set_policy_constraints(SshX509Certificate c,
                                     SshX509ExtPolicyConstraints policy,
                                     Boolean critical)
{
  c->extensions.policy_const = policy;
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_POLICY_CNST, critical);
}

void
ssh_x509_cert_set_subject_directory_attr(SshX509Certificate c,
                                         SshX509ExtDirAttribute subject_dattr,
                                         Boolean critical)
{
  LIST_APPEND(SshX509ExtDirAttributeStruct,
              c->extensions.subject_directory_attr, subject_dattr);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_SUBJECT_DIR_ATTR, critical);
}

void
ssh_x509_cert_set_ext_key_usage(SshX509Certificate c,
                                SshX509OidList ext_key_usage,
                                Boolean critical)
{
  LIST_APPEND(SshX509OidListStruct,
              c->extensions.ext_key_usage, ext_key_usage);
  ssh_x509_ext_info_set(&c->extensions.ext_available,
                        &c->extensions.ext_critical,
                        SSH_X509_EXT_EXT_KEY_USAGE, critical);
}

void ssh_x509_cert_set_attribute(SshX509Certificate c,
                                 SshX509Attribute attribute)
{
  const SshOidStruct *oid;

  /* Magic; if it is known and oid is not set, map it here. Also, if
     the type is not set, but we know the oid, do the reverse. */
  if (attribute->type == SSH_X509_ATTR_UNKNOWN &&
      attribute->oid)
    {
      if ((oid = ssh_oid_find_by_std_name("challengePassword")) != NULL &&
          strcmp(oid->oid, attribute->oid) == 0)
        attribute->type = SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD;
      /* Ad inf... */
    }
  if (attribute->type == SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD &&
      attribute->oid == NULL)
    {
      if ((oid = ssh_oid_find_by_std_name("challengePassword")) != NULL)
        attribute->oid = ssh_strdup(oid->oid);
    }

  LIST_APPEND(SshX509AttributeStruct, c->attributes, attribute);
}

/* Routines for setting the CRL values. */
Boolean ssh_x509_crl_set_issuer_name(SshX509Crl crl,
                                     const unsigned char *name)
{
  return ssh_x509_name_push_ldap_dn(&crl->issuer_name, name);
}

Boolean ssh_x509_crl_set_issuer_name_der(SshX509Crl crl,
                                         const unsigned char *der,
                                         size_t der_len)
{
  return ssh_x509_name_push_der_dn(&crl->issuer_name, der, der_len);
}

Boolean ssh_x509_crl_set_issuer_name_str(SshX509Crl crl,
                                         const SshStr str)
{
  return ssh_x509_name_push_str_dn(&crl->issuer_name, str);
}

void ssh_x509_crl_set_update_times(SshX509Crl crl,
                                   const SshBerTime this_update,
                                   const SshBerTime next_update)
{
  if (this_update)
    ssh_ber_time_set(&crl->this_update, this_update);
  if (next_update)
    {
      ssh_ber_time_set(&crl->next_update, next_update);
      if (ssh_ber_time_available(&crl->next_update))
        crl->use_next_update = TRUE;
    }
}

void ssh_x509_crl_set_issuer_alternative_names(SshX509Crl crl,
                                               SshX509Name names,
                                               Boolean critical)
{
  ssh_x509_name_push(&crl->extensions.issuer_alt_names, names);
  ssh_x509_ext_info_set(&crl->extensions.ext_available,
                        &crl->extensions.ext_critical,
                        SSH_X509_CRL_EXT_ISSUER_ALT_NAME,
                        critical);
}

void
ssh_x509_crl_set_authority_key_id(SshX509Crl crl,
                                  SshX509ExtKeyId key_id,
                                  Boolean critical)
{
  crl->extensions.auth_key_id = key_id;
  ssh_x509_ext_info_set(&crl->extensions.ext_available,
                        &crl->extensions.ext_critical,
                        SSH_X509_CRL_EXT_AUTH_KEY_ID, critical);
}

void ssh_x509_crl_set_crl_number(SshX509Crl crl,
                                 SshMPIntegerConst crl_number,
                                 Boolean critical)
{
  ssh_mprz_set(&crl->extensions.crl_number, crl_number);
  ssh_x509_ext_info_set(&crl->extensions.ext_available,
                        &crl->extensions.ext_critical,
                        SSH_X509_CRL_EXT_CRL_NUMBER,
                        critical);
}

void ssh_x509_crl_set_delta_crl_indicator(SshX509Crl crl,
                                          SshMPIntegerConst delta,
                                          Boolean critical)
{
  ssh_mprz_set(&crl->extensions.delta_crl_ind, delta);
  ssh_x509_ext_info_set(&crl->extensions.ext_available,
                        &crl->extensions.ext_critical,
                        SSH_X509_CRL_EXT_DELTA_CRL_IND,
                        critical);
}

void
ssh_x509_crl_set_issuing_dist_point(SshX509Crl crl,
                                    SshX509ExtIssuingDistPoint dist_point,
                                    Boolean critical)
{
  crl->extensions.dist_point = dist_point;
  ssh_x509_ext_info_set(&crl->extensions.ext_available,
                        &crl->extensions.ext_critical,
                        SSH_X509_CRL_EXT_ISSUING_DIST_POINT,
                        critical);
}

/* Revoked certs. */
void ssh_x509_crl_add_revoked(SshX509Crl crl,
                              SshX509RevokedCerts revoked)
{
  SshX509RevokedCerts tmp;

  /* Nothing to add.  */
  if (revoked == NULL)
    return;

  /* Find last in the list, add new entries, and scan to their end. */
  if (crl->last_revoked)
    {
      tmp = crl->last_revoked;
      tmp->next = revoked;
    }
  else
    {
      crl->revoked = revoked;
      tmp = crl->revoked;
    }

  while (tmp->next) tmp = tmp->next;
  crl->last_revoked = tmp;
}

void ssh_x509_revoked_set_serial_number(SshX509RevokedCerts revoked,
                                        SshMPIntegerConst s)
{
  ssh_mprz_set(&revoked->serial_number, s);
}

void ssh_x509_revoked_set_revocation_date(SshX509RevokedCerts revoked,
                                          const SshBerTime ber_time)
{
  ssh_ber_time_set(&revoked->revocation_date, ber_time);
}

void ssh_x509_revoked_set_certificate_issuer(SshX509RevokedCerts revoked,
                                             SshX509Name names,
                                             Boolean critical)
{
  ssh_x509_name_push(&revoked->extensions.certificate_issuer, names);
  ssh_x509_ext_info_set(&revoked->extensions.ext_available,
                        &revoked->extensions.ext_critical,
                        SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER,
                        critical);
}

void ssh_x509_revoked_set_reason_code(SshX509RevokedCerts revoked,
                                      SshX509CRLReasonCode reason_code,
                                      Boolean critical)
{
  revoked->extensions.reason_code = reason_code;
  ssh_x509_ext_info_set(&revoked->extensions.ext_available,
                        &revoked->extensions.ext_critical,
                        SSH_X509_CRL_ENTRY_EXT_REASON_CODE,
                        critical);
}

void ssh_x509_revoked_set_hold_instruction_code(SshX509RevokedCerts revoked,
                                                const char *object_identifier,
                                                Boolean critical)
{
  revoked->extensions.hold_inst_code = ssh_strdup(object_identifier);
  ssh_x509_ext_info_set(&revoked->extensions.ext_available,
                        &revoked->extensions.ext_critical,
                        SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE,
                        critical);
}

void ssh_x509_revoked_set_invalidity_date(SshX509RevokedCerts revoked,
                                          const SshBerTime date,
                                          Boolean critical)
{
  ssh_ber_time_set(&revoked->extensions.invalidity_date, date);
  ssh_x509_ext_info_set(&revoked->extensions.ext_available,
                        &revoked->extensions.ext_critical,
                        SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE,
                        critical);
}


/* end. */
#endif /* SSHDIST_CERT */
