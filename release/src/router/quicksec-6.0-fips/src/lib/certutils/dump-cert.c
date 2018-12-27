/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to output certificates (on certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshdsprintf.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "oid.h"
#include "x509.h"
#include "sshbase16.h"
#include "iprintf.h"
#include "sshdsprintf.h"
#include "sshbase16.h"

#define SSH_DEBUG_MODULE "SshDumpCert"

/* Converts str_in to charset or to #hex presentation
   if the charset conversion is not possible.
*/

static
char *showable_string(SshStr str_in, SshCharset charset)
{
  SshStr str_tmp;
  char *ret;
  size_t len;

  if (str_in == NULL)
    return NULL;

  str_tmp = str_in ? ssh_str_charset_convert(str_in, charset) : NULL;
  if (NULL == str_tmp)
    {
      unsigned char *buf, *tmp;
      char *tmp2;

      buf = ssh_str_get(str_in, &len);
      tmp2 = ssh_buf_to_base16(buf, len);
      ssh_dsprintf(&tmp, "#%s", tmp2);
      ssh_free(tmp2);
      ssh_xfree(buf);

      for (buf = tmp; *buf; buf++)
        if (isupper(*buf))
          *buf = tolower(*buf);

      str_tmp = ssh_str_make(charset, tmp, ssh_ustrlen(tmp));

      ret = showable_string(str_tmp, charset);
      ssh_str_free(str_tmp);
    }
  else
    {
      ret = (char *)ssh_str_get(str_tmp, &len);
      ssh_str_free(str_tmp);
    }
  return ret;
}

Boolean dump_ber(unsigned char *buf, size_t buf_size, size_t offset,
                 int print_level, int no_string_decode);

CuCertKind cu_determine_cert_kind(SshX509Certificate cert)
{
  CuCertKind rv = 0;
  Boolean ca, critical;
  size_t pathlen;
  SshStr issuer, subject;
  SshX509UsageFlags usage = 0;

  /* User or CA? */
  rv = CU_CERT_KIND_USER;
  if (ssh_x509_cert_get_basic_constraints(cert, &pathlen, &ca, &critical))
    {
      if (ca)
        rv = CU_CERT_KIND_CA;
    }

  /* Self-issued? */
  issuer = subject = NULL;
  if (ssh_x509_cert_get_issuer_name_str(cert, &issuer) &&
      ssh_x509_cert_get_subject_name_str(cert, &subject))
    {
      if (ssh_str_cmp(issuer, subject) == SSH_STR_ORDREL_EQ)
        rv |= CU_CERT_KIND_TOPLEVEL;
    }
  ssh_str_free(issuer);
  ssh_str_free(subject);

  /* Applicaple operation areas? */
  if (ssh_x509_cert_get_key_usage(cert, &usage, &critical))
    {
      if (usage & SSH_X509_UF_DIGITAL_SIGNATURE ||
          usage & SSH_X509_UF_NON_REPUDIATION ||
          usage & SSH_X509_UF_KEY_CERT_SIGN ||
          usage & SSH_X509_UF_CRL_SIGN)
        rv |= CU_CERT_KIND_SIGNATURE;

      if (usage & SSH_X509_UF_KEY_ENCIPHERMENT ||
          usage & SSH_X509_UF_DATA_ENCIPHERMENT)
        rv |= CU_CERT_KIND_ENCRYPTION;
    }
  return rv;
}

static const char *get_ext(unsigned int ext, int type)
{
  const SshOidStruct *oid;
  oid = ssh_oid_find_by_ext_ident_of_type(ext, type);
  if (oid)
    return oid->name;
  return "failure";
}

void dump_time(SshBerTime ber_time)
{
  char *name;
  ssh_ber_time_to_string(ber_time, &name);
  iprintf("%s", name);
  ssh_xfree(name);
  iprintf("\n");
  return;
}


void cu_dump_reason(SshX509ReasonFlags flags)
{
  if (flags & SSH_X509_RF_AA_COMPROMIZE)
    iprintf("AACompromize ");
  if (flags & SSH_X509_RF_PRIVILEGE_WITHDRAWN)
    iprintf("PrivilegeWithdrawn ");
  if (flags & SSH_X509_RF_UNSPECIFIED)
    iprintf("Unspecified ");
  if (flags & SSH_X509_RF_KEY_COMPROMISE)
    iprintf("KeyCompromise ");
  if (flags & SSH_X509_RF_CA_COMPROMISE)
    iprintf("CACompromise ");
  if (flags & SSH_X509_RF_AFFILIATION_CHANGED)
    iprintf("AffiliationChanged ");
  if (flags & SSH_X509_RF_SUPERSEDED)
    iprintf("Superseded ");
  if (flags & SSH_X509_RF_CESSATION_OF_OPERATION)
    iprintf("CessationOfOperation ");
  if (flags & SSH_X509_RF_CERTIFICATE_HOLD)
    iprintf("CertificateHold ");
  iprintf("\n");
  return;
}

void
cu_dump_name(SshStr name_str, SshCharset charset, Boolean ldap)
{
  unsigned char *der = NULL;
  char *new_name;
  size_t  new_name_len;
  SshStr new_name_str = NULL;
  Boolean data_in_hex_string = FALSE;

  if ((new_name_str = ssh_str_charset_convert(name_str, charset))
      == NULL)
    {
      SshDNStruct tmp_dn;

      ssh_dn_init(&tmp_dn);
      /* The name cannot be presented in the current charset.  Plan B
       * is to display RDN's in Latin1 if possible, and in #hex
       * -notation if not. This is rather reasonable as long as we
       * have only Latin1 and UTF-8 charsets to deal with.
       */
      if (!ssh_dn_decode_ldap_str(name_str, &tmp_dn))
        {
          iprintf("#I<charset conversion failed>#i\n"); /* Plan C */
          ssh_dn_clear(&tmp_dn);
          return;
        }
      ssh_dn_encode_ldap(&tmp_dn, &new_name);
      ssh_dn_clear(&tmp_dn);
      data_in_hex_string = TRUE;
    }

  if (ldap)
    {
      SshDNStruct dn;
      size_t der_len;

      ssh_dn_init(&dn);
      if (data_in_hex_string)
        ssh_dn_decode_ldap((unsigned char *)new_name, &dn);
      else
        ssh_dn_decode_ldap_str(name_str, &dn);
      ssh_dn_encode_der(&dn, &der, &der_len, NULL);
      ssh_dn_clear(&dn);

      ssh_dn_init(&dn);
      ssh_dn_decode_der(der, der_len, &dn, NULL);
      ssh_dn_reverse(&dn);
      if (data_in_hex_string)
        ssh_dn_encode_ldap(&dn, &new_name);
      else
        ssh_dn_encode_ldap_str(&dn, &new_name_str);
      ssh_dn_clear(&dn);
    }

  if (data_in_hex_string == FALSE)
    {
      new_name = (char *)ssh_str_get(new_name_str, &new_name_len);
      if (new_name_len != strlen(new_name))
        iprintf("(Warning, name is encoded incorrectly)");
    }

  iprintf("#I<%s>#i\n", new_name);
  ssh_xfree(new_name);
  ssh_str_free(new_name_str);
  ssh_xfree(der);
}

static void
dump_ext_availability(SshX509Certificate c)
{
  int i, k;
  Boolean critical;

  iprintf("Available = #I");

  for (i = 0, k = 0; i < SSH_X509_EXT_MAX; i++)
    {
      if (ssh_x509_cert_ext_available(c, i, &critical))
        {
          if (k > 0)
            iprintf(", ");
          iprintf("%s", get_ext(i, SSH_OID_EXT));
          if (critical)
            iprintf("(critical)");
          k++;
        }
    }
  if (k == 0)
    iprintf("(not available)");
  iprintf("#i\n");
  return;
}

char *name_types[13] =
{
  "distinguished name",
  "unique id",
  "EMAIL (rfc822)",
  "DNS (domain name server name)",
  "IP (ip address)",
  "DN (directory name)",
  "X400 (X.400 name)",
  "EDI (EDI party name)",
  "URI (uniform resource indicator)",
  "RID (registered identifier)",
  "UPN (principal name)",
  "GUID (Global Unique ID)",
  "OTHER (other name)"
};

Boolean
cu_dump_names(SshX509Name names, SshCharset charset, Boolean ldap)
{
  char *name;
  SshStr dname;
  unsigned char *buf;
  size_t buf_len;
  Boolean rv, ret = FALSE;
  SshX509Name list;
  int i;

  iprintf("Following names detected = #I\n");
  for (list = names, i = 0; list; list = list->next, i++)
    {
      if (i > 0)
        iprintf(", ");
      iprintf("%s", name_types[list->type]);
    }
  if (names == NULL)
    iprintf("n/a");
  iprintf("#i\n");

  iprintf("Viewing specific name types = #I\n");
  do
    {
      rv = ssh_x509_name_pop_ip(names, &buf, &buf_len);
      if (rv == TRUE)
        {
          if (buf_len == 4)
            {
              iprintf("IP = %d.%d.%d.%d\n",
                      (int)buf[0], (int)buf[1], (int)buf[2], (int)buf[3]);
            }
          else
            {
              char tmp_str[512];
              size_t len;
              int i;

              len = 0;
              for (i = 0; i < buf_len; i++)
                {
                  ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len, "%02x",
                               buf[i]);
                  len += strlen(tmp_str + len);
                  if (i != buf_len - 1 && (i & 0x1) == 1)
                    {
                      ssh_snprintf(tmp_str + len, sizeof(tmp_str) - len, ":");
                      len++;
                    }
                }
              iprintf("IP  = %s\n", tmp_str);
            }
          ret = TRUE;
        }
      ssh_xfree(buf);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_dns(names, &name);
      if (rv == TRUE)
        {
          iprintf("DNS = %s\n", name);
          ret = TRUE;
        }
      ssh_xfree(name);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_uri(names, &name);
      if (rv == TRUE)
        {
          iprintf("URI = #I%s#i\n", name);
          ret = TRUE;
        }
      ssh_xfree(name);
    }
  while (rv == TRUE);


  do
    {
      rv = ssh_x509_name_pop_email(names, &name);
      if (rv == TRUE)
        {
          iprintf("EMAIL = %s\n", name);
          ret = TRUE;
        }
      ssh_xfree(name);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_rid(names, &name);
      if (rv == TRUE)
        {
          iprintf("RID = %s\n", name);
          ret = TRUE;
        }
      ssh_xfree(name);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_principal_name_str(names, &dname);
      if (rv == TRUE)
        {
          iprintf("UPN = ");
          ret = TRUE;
          cu_dump_name(dname, charset, ldap);
        }
      ssh_str_free(dname);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_directory_name_str(names, &dname);
      if (rv == TRUE)
        {
          iprintf("DN = ");
          cu_dump_name(dname, charset, ldap);
          ret = TRUE;
        }
      ssh_str_free(dname);
    }
  while (rv == TRUE);

  do
    {
      rv = ssh_x509_name_pop_guid(names, &buf, &buf_len);
      if (rv == TRUE)
        {
          iprintf("GUID = ");
          cu_dump_hex_and_text(buf, buf_len);
          ssh_xfree(buf);
          ret = TRUE;
        }
      ssh_str_free(dname);
    }
  while (rv == TRUE);

  do
    {
      char *othername_oid;
      unsigned char *der;
      size_t der_len;

      othername_oid = NULL;
      rv = ssh_x509_name_pop_other_name(names, &othername_oid,
                                        &der, &der_len);
      if (rv == TRUE)
        {
          iprintf("Othername %s = #I\n", othername_oid);
          cu_dump_hex_and_text(der, der_len);
          ssh_xfree(der);
          iprintf("#i");
          ret = TRUE;
        }
    }
  while (rv == TRUE);

  iprintf("#i");

  if (ret != TRUE)
    iprintf("No names of type "
            "IP, DNS, URI, EMAIL, RID, UPN, GUID or DN detected.\n");

  return ret;
}

void
cu_dump_subtree(SshX509GeneralSubtree tree,
                SshCharset charset, Boolean ldap)
{
  while (tree)
    {
      iprintf("Distance [%u-%u]\n", tree->min_distance, tree->max_distance);
      cu_dump_names(tree->name, charset, ldap);

      tree = tree->next;
    }
}

void cu_dump_critical(Boolean critical)
{
  if (critical)
    iprintf("#I[CRITICAL]#i\n");
}

void cu_dump_time(SshBerTime ber_time)
{
  char *name;
  ssh_ber_time_to_string(ber_time, &name);
  iprintf("%s", name);
  ssh_xfree(name);
  iprintf("\n");
  return;
}

static void dump_usage(SshX509UsageFlags flags)
{
  if (flags & SSH_X509_UF_DIGITAL_SIGNATURE)
    iprintf("DigitalSignature ");
  if (flags & SSH_X509_UF_NON_REPUDIATION)
    iprintf("NonRepudiation ");
  if (flags & SSH_X509_UF_KEY_ENCIPHERMENT)
    iprintf("KeyEncipherment ");
  if (flags & SSH_X509_UF_DATA_ENCIPHERMENT)
    iprintf("DataEncipherment ");
  if (flags & SSH_X509_UF_KEY_AGREEMENT)
    iprintf("KeyAgreement ");
  if (flags & SSH_X509_UF_KEY_CERT_SIGN)
    iprintf("KeyCertSign ");
  if (flags & SSH_X509_UF_CRL_SIGN)
    iprintf("CRLSign ");
  if (flags & SSH_X509_UF_ENCIPHER_ONLY)
    iprintf("EncipherOnly ");
  if (flags & SSH_X509_UF_DECIPHER_ONLY)
    iprintf("DecipherOnly ");
  iprintf("\n");
  return;
}

static void dump_hex(unsigned char *str, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      if (i > 0)
        iprintf(":");
      if (i > 0 && (i % 20) == 0)
        iprintf("\n");
      iprintf("%02x", str[i]);
    }
  iprintf("\n");
  return;
}


Boolean
cu_dump_key_id(SshX509ExtKeyId key_id,
               SshCharset charset, Boolean ldap, int base)
{
  if (key_id->key_id && key_id->key_id_len != 0)
    {
      iprintf("KeyID = #I\n");
      dump_hex(key_id->key_id, key_id->key_id_len);
      iprintf("#i");
    }
  if (key_id->auth_cert_issuer)
    {
      iprintf("AuthorityCertificateIssuer = #I\n");
      (void)cu_dump_names(key_id->auth_cert_issuer, charset, ldap);
      iprintf("#i");
    }
  if (ssh_mprz_cmp_ui(&key_id->auth_cert_serial_number, 0) >= 0)
    {
      iprintf("AuthorityCertificateSerialNumber = #I");
      if (!cu_dump_number(&key_id->auth_cert_serial_number, base))
        return FALSE;
      iprintf("#i");
    }
  return TRUE;
}

Boolean
dump_policy_qualifier(SshX509ExtPolicyQualifierInfo p, SshCharset charset)
{
  const SshOidStruct *oids;
  char *str;
  size_t i;

  oids = ssh_oid_find_by_std_name_of_type("pkix-id-qt-cps", SSH_OID_POLICY);
  if (ssh_usstrcmp(p->oid, oids->oid) == 0)
    {
      str = showable_string(p->cpsuri, charset);
      iprintf("CPSuri = %s\n", str);
      ssh_xfree(str);
      return TRUE;
    }

  oids = ssh_oid_find_by_std_name_of_type("pkix-id-qt-unotice",
                                          SSH_OID_POLICY);
  if (oids != NULL && ssh_usstrcmp(p->oid, oids->oid) == 0)
    {
      if (p->organization)
        {
          str = showable_string(p->organization, charset);
          iprintf("Organization = %s\n", str);
          ssh_xfree(str);
        }
      if (p->notice_numbers_count > 0)
        {
          iprintf("NoticeNumbers = ");
          for (i = 0; i < p->notice_numbers_count; i++)
            iprintf("%u ", p->notice_numbers[i]);
          iprintf("\n");
        }
      if (p->explicit_text)
        {
          str = showable_string(p->explicit_text, charset);
          iprintf("ExplicitText = %s\n", str);
          ssh_xfree(str);
        }
      return TRUE;
    }

  iprintf("Unknown policy qualifer: %s\n", p->oid);
  return TRUE;
}

Boolean dump_qcstatements(SshX509ExtQCStatement s,
                          SshCharset charset, Boolean ldap)
{
  const SshOidStruct *oid;

  for (; s; s = s->next)
    {
      oid = ssh_oid_find_by_oid_of_type(s->oid, SSH_OID_QCSTATEMENT);
      if (oid == NULL)
        {
        unknown_qcstatement:
          if (s->der)
            {
              iprintf("%s = #I\n", s->oid);
              cu_dump_hex_and_text(s->der, s->der_len);
              iprintf("#i");
            }
          else
            iprintf("%s\n", s->oid);
          continue;
        }

      switch (oid->extra_int)
        {
        case SSH_X509_QCSTATEMENT_QCSYNTAXV1:
          if (s->semantics_oid)
            iprintf("pkixQCSyntax-v1 = (semantics) %s\n", s->semantics_oid);
          else if (s->name_registration_authorities)
            {
              iprintf("pkixQCSyntax-v1 = (name registration authorities)\n#I");
              (void)cu_dump_names(s->name_registration_authorities,
                                  charset, ldap);
              iprintf("#i");
            }
          else
            iprintf("pkixQCSyntax-v1\n");
          break;

        case SSH_X509_QCSTATEMENT_QCCOMPLIANCE:
          iprintf("QcCompliance (according to Annex I and II of "
                  "the EU directive 1999/93/EC)\n");
          break;

        case SSH_X509_QCSTATEMENT_QCEULIMITVALUE:
          {
            SshMPIntegerStruct mp, exp, g;

            ssh_mprz_init(&mp);
            ssh_mprz_init(&exp);
            ssh_mprz_init(&g);

            ssh_mprz_set(&mp, &s->amount);
            ssh_mprz_set_ui(&g, 10);
            ssh_mprz_pow(&exp, &g, &s->exponent);
            ssh_mprz_mul(&mp, &s->amount, &exp);

            iprintf("QcEuLimitValue = #I\ncurrency = %d\namount = ",
                    s->currency);
            cu_dump_number(&mp, 10);
            iprintf("#i");

            ssh_mprz_clear(&mp);
            ssh_mprz_clear(&exp);
            ssh_mprz_clear(&g);
            break;
          }

        case SSH_X509_QCSTATEMENT_RETENTIONPERIOD:
          iprintf("QcEuRetentionPeriod = ");
          cu_dump_number(&s->retention_period, 10);
          break;

        default:
          /* Unsupported but known oid. */
          goto unknown_qcstatement;
        }
    }

  return TRUE;
}

static void
dump_points(SshX509ExtCRLDistPoints dist_points,
            SshCharset charset,
            Boolean ldap)
{
  SshX509ExtCRLDistPoints tmp;
  int number;

  number = 0;
  for (tmp = dist_points; tmp; tmp = tmp->next)
    number++;
  number = number < 1 ? -1 : 1;

  for (; dist_points; dist_points = dist_points->next)
    {
      if (number > 0)
        iprintf("%% Entry %u\n", number++);

      if (dist_points->full_name)
        {
          iprintf("FullName = #I\n");
          (void)cu_dump_names(dist_points->full_name, charset, ldap);
          iprintf("#i");
        }
      if (dist_points->dn_relative_to_issuer)
        {
          SshStr name_str;

          ssh_dn_encode_ldap_str(dist_points->dn_relative_to_issuer,
                                 &name_str);
          iprintf("DNRelativeToIssuer = ");
          cu_dump_name(name_str, charset, ldap);
          ssh_str_free(name_str);
        }
      if (dist_points->reasons)
        {
          iprintf("Reasons = #I");
          cu_dump_reason(dist_points->reasons);
          iprintf("#i");
        }
      if (dist_points->crl_issuer)
        {
          iprintf("CRLIssuer = #I\n");
          (void)cu_dump_names(dist_points->crl_issuer, charset, ldap);
          iprintf("#i");
        }
    }
}

static Boolean dump_cert_ext(SshX509Certificate c,
                             SshCharset charset, Boolean ldap,
                             int base)
{
  SshBerTimeStruct not_before, not_after;
  Boolean critical;
  SshX509Name names;
  SshX509UsageFlags usage;
  size_t path_length;
  Boolean ca;
  Boolean rv = TRUE;

  iprintf("Extensions = #I\n");

  dump_ext_availability(c);

  /* Alternative names. */
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_ALT_NAME, &critical))
    {
      iprintf("SubjectAlternativeNames = #I\n");
      if ((rv &=
           ssh_x509_cert_get_subject_alternative_names(c, &names, &critical))
          && cu_dump_names(names, charset, ldap)
          && critical)
        cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_ISSUER_ALT_NAME, &critical))
    {
      iprintf("IssuerAlternativeNames = #I\n");
      if ((rv &=
           ssh_x509_cert_get_issuer_alternative_names(c, &names, &critical))
          && cu_dump_names(names, charset, ldap)
          && critical)
        cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_DIR_ATTR, &critical))
    {
      SshX509ExtDirAttribute attr = c->extensions.subject_directory_attr;
      const char *attrname;
      char *attrvalue;
      const SshOidStruct *oids;
      SshAsn1Context asn1c;
      SshAsn1Node node;

      asn1c = ssh_asn1_init();
      if (asn1c == NULL)
        return FALSE;

      iprintf("SubjectDirectoryAttributes = #I\n");
      while (attr)
        {



          oids = ssh_oid_find_by_oid_of_type(ssh_custr(attr->oid),
                                             SSH_OID_DIRECTORYATTR);
          if (oids)
            {
              attrname = oids->std_name;

              if (ssh_asn1_decode_node(asn1c,
                                       attr->octet_string,
                                       attr->octet_string_len, &node)
                  == SSH_ASN1_STATUS_OK)
                {
                  size_t which, str_len;
                  unsigned char *str;
                  SshBerTimeStruct bertime;
                  SshAsn1Node value_node;
                  SshAsn1Status status;

                  if (ssh_asn1_read_node(asn1c, node,
                                         "(set (*)"
                                         "  (any ()))",
                                         &value_node) != SSH_ASN1_STATUS_OK ||
                      value_node == NULL)
                    {
                      iprintf("#I%s = can't decode value set#i\n",
                              attrname);
                    }
                  else
                    {
                     while (value_node)
                        {
                          status =
                            ssh_asn1_read_node(asn1c, value_node,
                                               "(choice"
                                               "  (generalized-time ())"
                                               "  (printable-string ())"
                                               "  (ia5-string ())"
                                               "  (utf8-string ()))",
                                               &which,
                                               &bertime,
                                               &str, &str_len,
                                               &str, &str_len,
                                               &str, &str_len);
                          if (status != SSH_ASN1_STATUS_OK)
                            {
                              iprintf("#I%s = can't decode value#i\n",
                                      attrname);
                            }
                          else if (which == 0)
                            {
                              ssh_ber_time_to_string(&bertime, &attrvalue);
                              iprintf("#I%s = %s#i\n", attrname, attrvalue);
                            }
                          else
                            {
                              SshStr s;
                              s = ssh_str_make(SSH_CHARSET_UTF8, str, str_len);
                              attrvalue = showable_string(s, charset);
                              ssh_str_free(s);
                              iprintf("#I%s = %s#i\n", attrname, attrvalue);
                              ssh_xfree(attrvalue);
                            }
                          value_node = ssh_asn1_node_next(value_node);
                        }
                    }
                }
              else
                {
                  iprintf("#I%s = can't decode attribute contents#i\n",
                          attrname);
                }
            }
          else
            {
              attrname = attr->oid;
              iprintf("#I%s = attribute value omitted#i\n", attrname);
            }

          attr = attr->next;
        }

      ssh_asn1_free(asn1c);
      iprintf("#i");
    }

  /* Private key usage period */
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_PRV_KEY_UP, &critical))
    {
      iprintf("PrivateKeyUsagePeriod = #I\n");
      rv &= ssh_x509_cert_get_private_key_usage_period(c,
                                                       &not_before, &not_after,
                                                       &critical);
      if (ssh_ber_time_available(&not_before) == TRUE)
        {
          iprintf("NotBefore = ");
          dump_time(&not_before);
        }
      if (ssh_ber_time_available(&not_after) == TRUE)
        {
          iprintf("NotAfter  = ");
          dump_time(&not_after);
        }
      cu_dump_critical(critical);
      iprintf("#i");
    }

  /* Key usage. */
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_KEY_USAGE, &critical))
    {
      rv &= ssh_x509_cert_get_key_usage(c, &usage, &critical);
      iprintf("KeyUsage = #I");
      dump_usage(usage);
      cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_BASIC_CNST, &critical))
    {
      iprintf("BasicConstraints = #I\n");
      rv &=
        ssh_x509_cert_get_basic_constraints(c, &path_length, &ca, &critical);
      if (path_length != SSH_X509_MAX_PATH_LEN)
        iprintf("PathLength = %u\n", path_length);
      iprintf("cA         = %s\n", (ca == TRUE ? "TRUE" : "FALSE"));
      cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_NAME_CNST, &critical))
    {
      SshX509GeneralSubtree p, e;

      iprintf("NameConstraints = #I\n");
      rv &= ssh_x509_cert_get_name_constraints(c, &p, &e, &critical);

      if (p)
        {
          iprintf("Permitted = #I\n");
          cu_dump_subtree(p, charset, ldap);
          iprintf("#i");
        }
      if (e)
        {
          iprintf("Excluded = #I\n");
          cu_dump_subtree(e, charset, ldap);
          iprintf("#i");
        }
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_CRL_DIST_POINTS, &critical))
    {
      SshX509ExtCRLDistPoints dist_points;

      iprintf("CRLDistributionPoints = #I\n");
      rv &=
        ssh_x509_cert_get_crl_dist_points(c, &dist_points, &critical);

      dump_points(dist_points, charset, ldap);
      cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_FRESHEST_CRL, &critical))
    {
      SshX509ExtCRLDistPoints dist_points;

      iprintf("FreshestCRL = #I\n");
      rv &= ssh_x509_cert_get_freshest_crl(c, &dist_points, &critical);

      dump_points(dist_points, charset, ldap);
      cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_AUTH_KEY_ID, &critical))
    {
      SshX509ExtKeyId key_id;
      iprintf("AuthorityKeyID = #I\n");
      rv &= ssh_x509_cert_get_authority_key_id(c, &key_id, &critical);
      (void)cu_dump_key_id(key_id, charset, ldap, base);
      cu_dump_critical(critical);
      iprintf("#i");
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_KEY_ID, &critical))
    {
      unsigned char *key_id;
      size_t key_id_len;
      rv &=
        ssh_x509_cert_get_subject_key_id(c, &key_id, &key_id_len, &critical);
      if (key_id && key_id_len != 0)
        {
          iprintf("SubjectKeyID = #I\n");
          iprintf("KeyId = #I\n");
          dump_hex(key_id, key_id_len);
          cu_dump_critical(critical);
          iprintf("#i#i");
        }
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_CERT_POLICIES, &critical))
    {
      SshX509ExtPolicyInfo p_info;
      if (ssh_x509_cert_get_policy_info(c, &p_info, &critical))
        {
          iprintf("PolicyInformation = #I\n");
          for (; p_info; p_info = p_info->next)
            {
              iprintf("PolicyIdentifier = %s\n", p_info->oid);
              if (p_info->pq_list)
                {
                  SshX509ExtPolicyQualifierInfo p;
                  iprintf("PolicyQualifiers = #I\n");
                  for (p = p_info->pq_list; p; p = p->next)
                    dump_policy_qualifier(p, charset);
                  iprintf("#i");
                }
            }
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_POLICY_MAPPINGS, &critical))
    {
      SshX509ExtPolicyMappings p_map;
      if (ssh_x509_cert_get_policy_mappings(c, &p_map, &critical))
        {
          iprintf("PolicyMappings = #I\n");
          for (; p_map; p_map = p_map->next)
            {
              iprintf("IssuerDomainPolicy  = %s\n",
                      p_map->issuer_dp_oid);
              iprintf("SubjectDomainPolicy = %s\n",
                      p_map->subject_dp_oid);
            }
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_POLICY_CNST, &critical))
    {
      SshX509ExtPolicyConstraints policy;
      if (ssh_x509_cert_get_policy_constraints(c, &policy, &critical) == TRUE)
        {
          iprintf("PolicyConstraints = #I\n");
          if (policy->require != SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT)
            iprintf("Require = %u\n", policy->require);
          if (policy->inhibit != SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT)
            iprintf("Inhibit = %u\n", policy->inhibit);
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_INHIBIT_ANY_POLICY,
                                  &critical))
    {
      SshUInt32 ncerts;
      if (ssh_x509_cert_get_inhibit_any_policy(c, &ncerts, &critical))
        {
          iprintf("InhibitAnyPolicy = %d #I", ncerts);
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_EXT_KEY_USAGE, &critical))
    {
      SshX509OidList oid_list;
      const SshOidStruct *oids;

      rv &= ssh_x509_cert_get_ext_key_usage(c, &oid_list, &critical);
      iprintf("ExtendedKeyUsage = #I\n");
      if (oid_list != NULL)
        {
          while (oid_list != NULL)
            {



              oids = ssh_oid_find_by_oid_of_type(ssh_custr(oid_list->oid),
                                                 SSH_OID_EXT_KEY_USAGE);
              if (oids == NULL)
                iprintf("(%s)\n", oid_list->oid);
              else
                iprintf("%s (%s)\n", oids->std_name, oid_list->oid);
              oid_list = oid_list->next;
            }
        }
      cu_dump_critical(critical);
      iprintf("#i");
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_AUTH_INFO_ACCESS, &critical))
    {
      SshX509ExtInfoAccess access;
      if (rv &= ssh_x509_cert_get_auth_info_access(c, &access, &critical))
        {
          iprintf("AuthorityInfoAccess = #I\n");
          for (; access; access = access->next)
            {
              iprintf("AccessMethod = %s\n", access->access_method);
              iprintf("AccessLocation = #I\n");
              (void)cu_dump_names(access->access_location, charset, ldap);
              iprintf("#i");
            }
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }
  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_NETSCAPE_COMMENT, &critical))
    {
      SshStr comment;
      if (rv &= ssh_x509_cert_get_netscape_comment(c, &comment, &critical))
        {
          iprintf("NetscapeComment = ");
          cu_dump_name(comment, charset, ldap);
          cu_dump_critical(critical);
        }
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_CERT_TEMPLATE_NAME,
                                  &critical))
    {
      SshStr ctn;
      if (rv &= ssh_x509_cert_get_cert_template_name(c, &ctn, &critical))
        {
          iprintf("WindowsCertificateTemplateName = ");
          cu_dump_name(ctn, charset, ldap);
          cu_dump_critical(critical);
        }
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_QCSTATEMENTS,
                                  &critical))
    {
      SshX509ExtQCStatement s;
      if (rv &= ssh_x509_cert_get_qcstatements(c, &s, &critical))
        {
          iprintf("QualifiedCertificateStatements = #I\n");
          dump_qcstatements(s, charset, ldap);
          cu_dump_critical(critical);
          iprintf("#i");
        }
    }

  if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_UNKNOWN, &critical))
    {
      SshX509ExtUnknown unknown;

      if (rv &= ssh_x509_cert_get_unknown_extension(c, &unknown, &critical))
        {
          for (; unknown; unknown = unknown->next)
            {
              int width_bak, indent_bak, indent_step_bak;

              iprintf("Unknown %s", unknown->oid);
              if (unknown->name)
                iprintf(" (%s)", unknown->name);
              iprintf(" = #I\n");
              iprintf_get(&width_bak, &indent_bak, &indent_step_bak);
              iprintf_set(width_bak, indent_bak/indent_step_bak,
                          indent_step_bak);
              if (!cu_dump_ber(unknown->der, unknown->der_length,
                               0, TRUE, FALSE))
                {
                  iprintf_set(width_bak, indent_bak, indent_step_bak);
                  cu_dump_hex_and_text(unknown->der, unknown->der_length);
                }
              iprintf_set(width_bak, indent_bak, indent_step_bak);
            }
          cu_dump_critical(critical);
        }
    }

  iprintf("#i");
  return rv;
}

void
cu_dump_fingerprints(const unsigned char *der, size_t der_len)
{
  int i, j;
  char *digits = "0123456789abcdef";
  unsigned char fingerprint[20];
  static char printout[64];

  iprintf("Fingerprints = #I\n");
  ssh_hash_of_buffer("md5", der, der_len, fingerprint);
  memset(printout, 0, sizeof(printout));

  for (j = 0, i = 1; i < 17; i++)
    {
      printout[j+0] = digits[(fingerprint[i-1] >> 4) & 0xf];
      printout[j+1] = digits[(fingerprint[i-1]     ) & 0xf];
      j += 2;
      printout[j++] = ':';
    }
  printout[j-1]='\0';
  iprintf("MD5 = %s\n", printout);

  ssh_hash_of_buffer("sha1", der, der_len, fingerprint);
  memset(printout, 0, sizeof(printout));

  for (j = 0, i = 1; i < 21; i++)
    {
      printout[j+0] = digits[(fingerprint[i-1] >> 4) & 0xf];
      printout[j+1] = digits[(fingerprint[i-1]     ) & 0xf];
      j += 2;
      printout[j++] = ':';
    }
  printout[j-1]='\0';
  iprintf("SHA-1 = %s\n#i", printout);


  return;
}

Boolean
cu_dump_cert(SshX509Certificate c,
             const unsigned char *der, size_t der_len,
             SshX509CertType cert_type,
             SshCharset charset, Boolean ldap, int base, Boolean verify)
{
  SshMPIntegerStruct s;
  Boolean rv;
  SshPublicKey public_key;
  SshStr name = NULL, other_name = NULL;
  Boolean sig_check = TRUE;
  SshBerTimeStruct not_before, not_after;
  unsigned char *uidbuf;
  size_t uidbuf_len;

  ssh_mprz_init(&s);

  switch (cert_type)
    {
    case SSH_X509_PKIX_CERT:
      iprintf("Certificate = #I\n");
      break;
    case SSH_X509_PKIX_CRMF:
      iprintf("CRMF certificate request = #I\n");
      break;
    case SSH_X509_PKCS_10:
      iprintf("PKCS10 certificate request = #I\n");
      break;

    default:
      SSH_ASSERT(0);
    }

  /* Distinguished names. */
  iprintf("SubjectName = ");
  rv = ssh_x509_cert_get_subject_name_str(c, &name);
  if (rv == FALSE)
    iprintf("[N/A]\n");
  else
    cu_dump_name(name, charset, ldap);

  iprintf("IssuerName = ");
  rv = ssh_x509_cert_get_issuer_name_str(c, &other_name);
  if (rv == FALSE)
    {
      if (cert_type == SSH_X509_PKIX_CERT)
        {
          iprintf("[N/A]#I\n");
          iprintf("(It is usually an error if "
                  "the IssuerName is not present.)#i\n");
        }
      else
        iprintf("[N/A]\n");
    }
  else
    {
      cu_dump_name(other_name, charset, ldap);
    }

  rv = ssh_x509_cert_get_serial_number(c, &s);
  if (rv == TRUE)
    {
      iprintf("SerialNumber= ");
      if (!cu_dump_number(&s, base))
        {
          ssh_str_free(other_name);
          ssh_str_free(name);
          return FALSE;
        }
    }
  else
    {
      if (cert_type == SSH_X509_PKIX_CERT)
        {
          ssh_warning("Certificate has no serial number.");
          exit(2);



        }
    }

  if (cert_type == SSH_X509_PKIX_CERT && verify)
    {
      iprintf("SignatureAlgorithm = %s\n", c->pop.signature.pk_algorithm);
      if (name && other_name &&
          ssh_str_cmp(name, other_name) == SSH_STR_ORDREL_EQ)
        {
          iprintf("Certificate seems to be self-signed.#I\n");
          if (ssh_x509_cert_verify(c, c->subject_pkey.public_key) == FALSE)
            {
              iprintf("  * Signature verification failed.\n");
              sig_check = FALSE;
              if (c->subject_pkey.public_key == NULL)
                iprintf("  * The key is not for signatures.\n");
            }
          else
            iprintf("  * Signature verification success.\n");
          iprintf("#i");
        }
    }   /* SSH_X509_PKIX_CERT */

  ssh_str_free(other_name);
  ssh_str_free(name);

  /* Validity times. */
  iprintf("Validity = #I\n");
  rv = ssh_x509_cert_get_validity(c, &not_before, &not_after);
  if (rv == FALSE)
    {
      if (cert_type == SSH_X509_PKIX_CERT)
        goto failed;
    }
  else
    {
      iprintf("NotBefore = ");
      dump_time(&not_before);
      iprintf("NotAfter  = ");
      dump_time(&not_after);
      iprintf("#i");
    }

  /* Unique identifiers */
  rv = ssh_x509_cert_get_subject_unique_identifier(c, &uidbuf, &uidbuf_len);
  if (rv == TRUE)
    {
      iprintf("SubjectUniqueIdentifier = #I\n");
      dump_hex(uidbuf, uidbuf_len);
      ssh_xfree(uidbuf);
      iprintf("#i");
    }
  rv = ssh_x509_cert_get_issuer_unique_identifier(c, &uidbuf, &uidbuf_len);
  if (rv == TRUE)
    {
      iprintf("IssuerUniqueIdentifier = #I\n");
      dump_hex(uidbuf, uidbuf_len);
      ssh_xfree(uidbuf);
      iprintf("#i");
    }

  /* Public key */
  iprintf("PublicKeyInfo = #I\n");
  if ((rv = ssh_x509_cert_get_public_key(c, &public_key)) != TRUE)
    goto failed;

  if (!cu_dump_pub(public_key, base))
    return FALSE;
  ssh_public_key_free(public_key);
  iprintf("#i");

  if (verify &&
      (cert_type == SSH_X509_PKIX_CRMF || cert_type == SSH_X509_PKCS_10))
    {
      iprintf("#IChecking the signature of the request.\n");
      if (ssh_x509_cert_verify(c, c->subject_pkey.public_key) == FALSE)
        {
          iprintf("  * Signature verification failed.\n");
          sig_check = FALSE;
        }
      else
        iprintf("  * Signature verification success.\n");
      iprintf("#i");
      if (sig_check)
        rv = TRUE;
    }

  if (!dump_cert_ext(c, charset, ldap, base))
    return FALSE;

  {
    unsigned char *kid; size_t kid_len;
    int i, j;
    char printout[64];
    char *digits = "0123456789abcdef";
    if ((kid =
         ssh_x509_cert_compute_key_identifier(c, "sha1", &kid_len))
        != NULL)
      {
        for (j = 0, i = 1; i <= kid_len; i++)
          {
            printout[j+0] = digits[(kid[i-1] >> 4) & 0xf];
            printout[j+1] = digits[(kid[i-1]     ) & 0xf];
            j += 2;
            printout[j++] = ':';
          }
        printout[j-1]='\0';
        iprintf("Public key SHA1 hash = #I%s\n#i", printout);
        ssh_free(kid);
      }
  }
  {
    unsigned char *kid; size_t kid_len;
    int i, j;
    char printout[64];
    char *digits = "0123456789abcdef";
    if ((kid =
         ssh_x509_cert_compute_key_identifier_ike(c, "sha1", &kid_len))
        != NULL)
      {
        for (j = 0, i = 1; i <= kid_len; i++)
          {
            printout[j+0] = digits[(kid[i-1] >> 4) & 0xf];
            printout[j+1] = digits[(kid[i-1]     ) & 0xf];
            j += 2;
            printout[j++] = ':';
          }
        printout[j-1]='\0';
        iprintf("IKE Certificate hash = #I%s\n#i", printout);
        ssh_free(kid);
      }
  }
  cu_dump_fingerprints(der, der_len);
failed:
  if (rv == FALSE)
    iprintf("#I[error]#i\n");
  iprintf("#i");
  ssh_mprz_clear(&s);
  return rv;
}
#endif /* SSHDIST_CERT */
