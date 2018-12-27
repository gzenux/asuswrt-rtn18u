/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate revocation list decode routines (not including extensions).
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

SshX509Status ssh_x509_crl_decode_asn1(SshAsn1Context context,
                                       SshAsn1Node    crl_node,
                                       SshX509Crl     crl)
{
  SshAsn1Status status;
  SshAsn1Node tbs_certlist, sig_alg1, sig_alg2, issuer_name,
    rc_list, ext_list, revoc_date_node, rc_ext;
  unsigned char *signature;
  size_t signature_len;
  Boolean version_found, ext_found, rc_ext_found,
    nu_found, rc_list_found;
  SshMPIntegerStruct version, serial_number;
  SshX509PkAlgorithm tmp_pk_type;
  const char *tmp_algorithm;
  unsigned int which1, which2;
  SshX509RevokedCerts rc, prev_rc;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Initialize everything we need. */
  ssh_mprz_init(&version);
  ssh_mprz_init(&serial_number);

  signature = NULL;

  /* Decode the CRL. */
  status =
    ssh_asn1_read_node(context, crl_node,
                       "(sequence ()"
                       "  (any ())"          /* TBSCertList */
                       "  (any ())"          /* Algorithm identifier */
                       "  (bit-string ()))", /* Signature */
                       &tbs_certlist,
                       &sig_alg1,
                       &signature, &signature_len);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Zero some basic fields. */
  ssh_ber_time_zero(&crl->this_update);
  ssh_ber_time_zero(&crl->next_update);

  /* Read the main level of the TBSCertList.  We need somewhat
     complicated choice and optional constructs here.  */
  status =
    ssh_asn1_read_node(context, tbs_certlist,
                       "(sequence ()"
                       "  (optional"
                       "    (integer ()))" /* Version (Optional) */
                       "  (any ())"        /* algorithm identifier */
                       "  (any ())"        /* Issuer distinguished name */
                       "  (choice "
                       "    (generalized-time ())"
                       "    (utc-time ()))"   /* ChoiceOfTime thisUpdate */
                       "  (optional"
                       "    (choice"
                       "      (generalized-time ())"
                       "      (utc-time ())))"/* ChoiceOfTime nextUpdate */
                       "  (optional"
                       "    (sequence ()"
                       "      (any ())))"     /* Revoked certificates */
                       "  (optional"
                       "    (any (e 0))))",   /* Extensions */
                       &version_found, &version,
                       &sig_alg2,
                       &issuer_name,
                       &which1, &crl->this_update, &crl->this_update,
                       &nu_found,
                       &which2, &crl->next_update, &crl->next_update,
                       &rc_list_found, &rc_list, &ext_found, &ext_list);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Handle version number. */
  if (version_found)
    {
      /* This should not happen. */
      if (ssh_mprz_cmp_ui(&version, 0) == 0)
        {
          rv = SSH_X509_FAILED_VERSION_CHECK;
          goto failed;
        }
      if (ssh_mprz_cmp_ui(&version, 1) == 0)
        crl->version = SSH_X509_VERSION_2;
      else
        {
          /* This should not happen. */
          rv = SSH_X509_FAILED_VERSION_CHECK;
          goto failed;
        }
    }
  else
    crl->version = SSH_X509_VERSION_1;

  /* Handle signature algorithm. */
  crl->pop.signature.pk_algorithm =
    ssh_x509_find_algorithm(context, sig_alg1,
                            &crl->pop.signature.pk_type);

  /* Verify that algorithm identifiers are equal. */
  tmp_algorithm = ssh_x509_find_algorithm(context, sig_alg1,
                                          &tmp_pk_type);

  if (crl->pop.signature.pk_algorithm == NULL || tmp_algorithm == NULL)
    {
      rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
      goto failed;
    }

  if (tmp_pk_type != crl->pop.signature.pk_type)
    {
      rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
      goto failed;
    }

  /* Get the data out of the TBS (To Be Signed) certificate list. */
  ssh_asn1_node_get_data(tbs_certlist,
                         &crl->pop.proved_message,
                         &crl->pop.proved_message_len);

  /* Manipulate the signature if necessary. */
  crl->pop.signature.signature =
    ssh_x509_decode_signature(context,
                              signature,
                              signature_len,
                              crl->pop.signature.pk_type,
                              &crl->pop.signature.signature_len);

  if (crl->pop.signature.signature == NULL)
    {
      rv = SSH_X509_FAILED_SIGNATURE_CHECK;
      goto failed;
    }

  ssh_free(signature);
  signature = NULL;

  /* Handle issuer distinguished name. */
  if (ssh_x509_decode_dn_name(context,
                              issuer_name,
                              SSH_X509_NAME_DISTINGUISHED_NAME,
                              &crl->issuer_name,
                              &crl->config) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_DN_NAME_CHECK;
      goto failed;
    }

  /* Handle revoked list. */
  if (rc_list_found && rc_list != NULL)
    {
      /* Initialize the looping. */
      rc = NULL;
      prev_rc = NULL;

      for (; rc_list; rc_list = ssh_asn1_node_next(rc_list))
        {
          /* Parse it. */
          status =
            ssh_asn1_read_node(context, rc_list,
                               "(sequence ()"
                               "  (integer ())" /* serial number */
                               "  (any ())"     /* revocation date */
                               "  (optional"
                               "    (any ())))",  /* extensions */
                               &serial_number,
                               &revoc_date_node,
                               &rc_ext_found, &rc_ext);
          if (status != SSH_ASN1_STATUS_OK)
            {
              rv = SSH_X509_FAILED_ASN1_DECODE;
              goto failed;
            }

          prev_rc = rc;
          if ((rc = ssh_x509_revoked_allocate()) == NULL)
            {
              rv = SSH_X509_FAILED_ASN1_DECODE;
              goto failed;
            }
          ssh_mprz_set(&rc->serial_number, &serial_number);

          if (ssh_x509_decode_time(context, revoc_date_node,
                                   &rc->revocation_date) != SSH_X509_OK)
            {
              rv = SSH_X509_FAILED_TIME_DECODE;
              ssh_x509_revoked_free(rc);
              goto failed;
            }

          if (rc_ext_found)
            {
              rv = ssh_x509_crl_rev_decode_extension(context,
                                                     rc_ext, rc,
                                                     &crl->config);
              if (rv != SSH_X509_OK)
                {
                  ssh_x509_revoked_free(rc);
                  goto failed;
                }
            }

          if (prev_rc)
            prev_rc->next = rc;
          else
            crl->revoked = rc;

          crl->last_revoked = rc;
        }
    }

  /* Handle extensions. */
  if (ext_found)
    {
      rv = ssh_x509_crl_decode_extension(context, ext_list, crl);
      if (rv != SSH_X509_OK)
        goto failed;
    }


  /* Finished decoding successfully. */
  rv = SSH_X509_OK;
failed:
  if (rv != SSH_X509_OK)
    {
      if (crl)
        {
          ssh_x509_revoked_free(crl->revoked);
          crl->revoked = crl->last_revoked = NULL;
          crl->version = SSH_X509_VERSION_UNKNOWN;
        }
    }

  /* Free everything we have needed. */
  ssh_free(signature);
  ssh_mprz_clear(&version);
  ssh_mprz_clear(&serial_number);
  return rv;
}

SshX509Status ssh_x509_crl_decode(const unsigned char *buf, size_t len,
                                  SshX509Crl crl)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Decode the BER/DER encoded ASN.1 blob. */
  if ((context = ssh_asn1_init()) == NULL)
    return rv;
  ssh_asn1_set_limits(context, len, 0);

  status = ssh_asn1_decode(context, buf, len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      ssh_asn1_free(context);
      return rv;
    }

  rv = ssh_x509_crl_decode_asn1(context, ssh_asn1_get_root(tree), crl);

  /* Free everything we have needed. */
  ssh_asn1_free(context);

  return rv;
}

/* x509crl_decode.c */
#endif /* SSHDIST_CERT */
