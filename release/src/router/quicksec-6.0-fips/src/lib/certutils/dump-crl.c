/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to output certificate lists (on certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshmp.h"
#include "oid.h"
#include "x509.h"
#include "iprintf.h"

#define SSH_DEBUG_MODULE "SshDumpCRL"

static const char *get_ext(unsigned int ext, int type)
{
  const SshOidStruct *oid;
  oid = ssh_oid_find_by_ext_ident_of_type(ext, type);
  if (oid)
    return oid->name;
  return "failure";
}


void dump_crl_ext(SshX509Crl c)
{
  int i, k;
  Boolean critical;

  iprintf("Available = #I");
  for (i = 0, k = 0; i < SSH_X509_CRL_EXT_MAX; i++)
    {
      if (ssh_x509_crl_ext_available(c, i, &critical))
        {
          if (k > 0)
            iprintf(", ");
          iprintf("%s", get_ext(i, SSH_OID_CRL_EXT));
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

void dump_revoked_ext(SshX509RevokedCerts c)
{
  int i, k;
  Boolean critical;

  iprintf("Available = #I");

  for (i = 0, k = 0; i < SSH_X509_CRL_ENTRY_EXT_MAX; i++)
    {
      if (ssh_x509_revoked_ext_available(c, i, &critical))
        {
          if (k > 0)
            iprintf(", ");
          iprintf("%s", get_ext(i, SSH_OID_CRL_ENTRY_EXT));
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


Boolean dump_crl_reason(SshX509CRLReasonCode code)
{
  char *str[] =
  {
    "Unspecified\n",
    "KeyCompromise\n",
    "CACompromise\n",
    "AffiliationChanged\n",
    "Superseded\n",
    "CessationOfOperation\n",
    "CertificateHold\n",
    "\n",
    "RemoveFromCRL\n",
    "PrivilegeWithdrawn\n",
    "AACompromise\n"
  };

  if (code > 10 || code == 7)
    return FALSE;
  iprintf("%s", str[code]);
  return TRUE;
}


static Boolean
dump_revoked(SshX509RevokedCerts revoked,
             SshCharset output, Boolean ldap, int base)
{
  char *name = NULL;
  SshBerTimeStruct date;
  Boolean rv;
  int number;
  SshMPIntegerStruct s;
  SshX509ReasonFlags reason;
  Boolean critical;


  iprintf("RevokedCertList = #I\n");

  if (revoked == NULL)
    iprintf("(not present)\n");

  number = 1;
  while (revoked)
    {
      iprintf("%% Entry %u\n", number);

      ssh_mprz_init(&s);
      if ((rv = ssh_x509_revoked_get_serial_number(revoked, &s))
          == FALSE)
        {
          ssh_mprz_clear(&s);
          goto failed;
        }

      iprintf("SerialNumber = ");
      cu_dump_number(&s, base);
      ssh_mprz_clear(&s);

      rv = ssh_x509_revoked_get_revocation_date(revoked, &date);
      if (rv == FALSE)
        goto failed;
      iprintf("RevocationDate = ");
      cu_dump_time(&date);

      iprintf("Extensions = #I\n");

      dump_revoked_ext(revoked);

      if (ssh_x509_revoked_ext_available(revoked,
                                         SSH_X509_CRL_ENTRY_EXT_REASON_CODE,
                                         &critical))
        {
          rv = ssh_x509_revoked_get_reason_code(revoked, &reason, &critical);
          if (rv == FALSE)
            {
              iprintf("#i");
              goto failed;
            }
          iprintf("ReasonCode = ");
          if (FALSE == dump_crl_reason(reason))
            return TRUE;
          cu_dump_critical(critical);
        }

      if (ssh_x509_revoked_ext_available(revoked,
                                        SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE,
                                         &critical))
        {
          rv = ssh_x509_revoked_get_hold_instruction_code(revoked, &name,
                                                          &critical);
          if (rv == FALSE)
            {
              if (name)
                ssh_free(name);

              iprintf("#i");
              goto failed;
            }
          iprintf("HoldInstCode = #I");

          if (strcmp(SSH_X509_HOLD_INST_CODE_NONE, name) == 0)
            iprintf("None\n");
          else if (strcmp(SSH_X509_HOLD_INST_CODE_CALLISSUER, name) == 0)
            iprintf("CallIssuer\n");
          else if (strcmp(SSH_X509_HOLD_INST_CODE_REJECT, name) == 0)
            iprintf("Reject\n");
          else
            iprintf("\nOID = %s\n", name);
          cu_dump_critical(critical);
          iprintf("#i");

          if (name)
            ssh_free(name);
        }

      if (ssh_x509_revoked_ext_available(revoked,
                                        SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE,
                                         &critical))
        {
          rv = ssh_x509_revoked_get_invalidity_date(revoked, &date, &critical);
          if (rv == FALSE)
            {
              iprintf("#i");
              goto failed;
            }
          iprintf("InvalidityDate = ");
          cu_dump_time(&date);
          cu_dump_critical(critical);
        }
      if (ssh_x509_revoked_ext_available(revoked,
                                         SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER,
                                         &critical))
        {
          SshX509Name names;
          if (ssh_x509_revoked_get_certificate_issuer(revoked, &names,
                                                      &critical))
            {
              iprintf("CertificateIssuer = #I\n");
              (void)cu_dump_names(names, output, ldap);
              cu_dump_critical(critical);
              iprintf("#i");
            }
        }

      iprintf("#i");

      number++;
      revoked = ssh_x509_revoked_get_next(revoked);
    }
  rv = TRUE;
failed:
  if (rv == FALSE)
    iprintf("#I[error]#i\n");
  iprintf("#i");
  return !rv;
}

Boolean
cu_dump_crl(SshX509Crl crl,
            SshCharset output, Boolean ldap, int base)
{
  SshStr name;
  SshBerTimeStruct this_update, next_update;
  Boolean rv;
  SshMPIntegerStruct s;
  SshX509Name names;
  Boolean critical;

  iprintf("CRL = #I\n");

  /* Issuer name */
  rv = ssh_x509_crl_get_issuer_name_str(crl, &name);
  if (rv == FALSE)
    goto failed;
  iprintf("IssuerName = ");
  cu_dump_name(name, output, ldap);
  ssh_str_free(name);

  /* Update times */
  rv = ssh_x509_crl_get_update_times(crl, &this_update, &next_update);
  if (rv == FALSE)
    goto failed;
  if (ssh_ber_time_available(&this_update))
    {
      iprintf("ThisUpdate = ");
      cu_dump_time(&this_update);
    }
  if (ssh_ber_time_available(&next_update))
    {
      iprintf("NextUpdate = ");
      cu_dump_time(&next_update);
    }

  iprintf("Extensions = #I\n");

  dump_crl_ext(crl);

  /* Dump authority key ID */
  if (ssh_x509_crl_ext_available(crl, SSH_X509_CRL_EXT_AUTH_KEY_ID, &critical))
    {
      SshX509ExtKeyId key_id;

      iprintf("AuthorityKeyID = #I\n");
      rv = ssh_x509_crl_get_authority_key_id(crl, &key_id, &critical);
      (void)cu_dump_key_id(key_id, output, ldap, base);
      if (critical)
        iprintf("#I[CRITICAL]#i\n");
      iprintf("#i");
    }

  /* Dump issuer alt names. */
  if (ssh_x509_crl_ext_available(crl,
                                 SSH_X509_CRL_EXT_ISSUER_ALT_NAME,
                                 &critical))
    {
      iprintf("IssuerAltNames = \n");
      rv = ssh_x509_crl_get_issuer_alternative_names(crl, &names, &critical);
      if (cu_dump_names(names, output, ldap) && critical)
        iprintf("#I[CRITICAL]#i\n");
    }

  /* CRL number */
  if (ssh_x509_crl_ext_available(crl,
                                 SSH_X509_CRL_EXT_CRL_NUMBER,
                                 &critical))
    {
      ssh_mprz_init(&s);
      rv = ssh_x509_crl_get_crl_number(crl, &s, &critical);
      iprintf("CRLNumber = ");
      if (!cu_dump_number(&s, base))
        {
          ssh_mprz_clear(&s);
          return FALSE;
        }
      cu_dump_critical(critical);
      ssh_mprz_clear(&s);
    }

  /* Delta CRL indicator number */
  if (ssh_x509_crl_ext_available(crl,
                                 SSH_X509_CRL_EXT_DELTA_CRL_IND,
                                 &critical))
    {
      ssh_mprz_init(&s);
      rv = ssh_x509_crl_get_delta_crl_indicator(crl, &s, &critical);
      iprintf("DeltaCRLIndicator = ");
      if (!cu_dump_number(&s, base))
        {
          ssh_mprz_clear(&s);
          return FALSE;
        }
      cu_dump_critical(critical);
      ssh_mprz_clear(&s);
    }

  /* Issuing distribution point */
  if (ssh_x509_crl_ext_available(crl,
                                 SSH_X509_CRL_EXT_ISSUING_DIST_POINT,
                                 &critical))
    {
      SshX509ExtIssuingDistPoint dp;
      rv = ssh_x509_crl_get_issuing_dist_point(crl, &dp, &critical);
      iprintf("IssuingDistributionPoint = #I\n");

      if (dp->full_name)
        {
          iprintf("FullName = #I\n");
          (void)cu_dump_names(dp->full_name, output, ldap);
          iprintf("#i");
        }
      if (dp->dn_relative_to_issuer)
        {
          SshStr name_str;

          ssh_dn_encode_ldap_str(dp->dn_relative_to_issuer,
                             &name_str);
          iprintf("DNRelativeToIssuer = ");
          cu_dump_name(name_str, output, ldap);
          ssh_str_free(name_str);
        }
      if (dp->only_contains_user_certs)
        iprintf("OnlyContainsUserCerts\n");
      if (dp->only_contains_ca_certs)
        iprintf("OnlyContainsCACerts\n");
      if (dp->only_some_reasons)
        {
          iprintf("OnlySomeReasons = #I");
          cu_dump_reason(dp->only_some_reasons);
          iprintf("#i");
        }
      if (dp->indirect_crl)
        iprintf("IndirectCRL");
      cu_dump_critical(critical);
      iprintf("#i");
    }

  /* Now dump the revocation list. */
  iprintf("#i");
  if (dump_revoked(ssh_x509_crl_get_revoked(crl),
                   output, ldap, base))
    return FALSE;

  rv = TRUE;

failed:
  if (rv == FALSE)
    iprintf("#I[error]#i\n");

  iprintf("#i");
  return rv;
}
#endif /* SSHDIST_CERT */
