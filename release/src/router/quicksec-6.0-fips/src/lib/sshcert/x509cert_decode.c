/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate decode routines, not including specific extensions.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

SshX509Status ssh_x509_cert_decode_asn1(SshAsn1Context     context,
                                        SshAsn1Node        cert_node,
                                        SshX509Certificate c)
{
  SshMPIntegerStruct version, serial_number;
  unsigned char *signature;
  size_t signature_len;
  SshX509PkAlgorithm issuer_pk_type;
  const char *tmp_algorithm;
  SshAsn1Node tbs_certificate,
    sig_alg1, sig_alg2,
    validity,
    issuer_dn_name, subject_dn_name,
    subject_pk_info, extensions;
  unsigned char *issuer_ui, *subject_ui;
  size_t issuer_ui_len, subject_ui_len;
  SshX509Name new_name;
  Boolean ext_found, version_found, iu_found, su_found;
  SshAsn1Status status;
  unsigned int which1, which2;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Initialize temporary multiple precision integers. */
  ssh_mprz_init(&version);
  ssh_mprz_init(&serial_number);

  /* Clean some pointers. */
  signature  = NULL;
  issuer_ui  = NULL;
  subject_ui = NULL;

  /* Read the certificate */
  status =
    ssh_asn1_read_node(context, cert_node,
                       "(sequence ()"
                       "  (any ())"          /* TBSCertificate */
                       "  (any ())"          /* sigalg identifier */
                       "  (bit-string ()))", /* signature */
                       &tbs_certificate,
                       &sig_alg1,
                       &signature, &signature_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Read the decoded signature. Following code assumes that if a
     field is not found then nothing is done and returned pointers contain
     NULLs. */
  status =
    ssh_asn1_read_node(context, tbs_certificate,
                       "(sequence ()"
                       "  (optional"
                       "    (integer (e 0)))"  /* version */
                       "  (integer ())"        /* serial number */
                       "  (any ())"            /* signature algorithm id */
                       "  (any ())"            /* issuer distinguished name */
                       "  (any ())"            /* Validity */
                       "  (any ())"            /* subject distinguished name */
                       "  (any ())"            /* subject public key info */
                       "  (optional"
                       "    (bit-string (1)))" /* issuer unique identifier */
                       "  (optional"
                       "    (bit-string (2)))" /* subject unique identifier */
                       "  (optional"
                       "    (any (e 3))))",    /* extensions */
                       &version_found, &version, &serial_number,
                       &sig_alg2, &issuer_dn_name,
                       &validity, &subject_dn_name,
                       &subject_pk_info,
                       &iu_found, &issuer_ui, &issuer_ui_len,
                       &su_found, &subject_ui, &subject_ui_len,
                       &ext_found, &extensions);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  if (version_found == FALSE)
    ssh_mprz_set_ui(&version, 0);

  /* Verify the version of the certificate. */
  if (ssh_mprz_cmp_ui(&version, 0) < 0 || ssh_mprz_cmp_ui(&version, 2) > 0)
    {
      rv = SSH_X509_FAILED_VERSION_CHECK;
      goto failed;
    }

  /* Handle versions and possible errors. */
  if (ssh_mprz_cmp_ui(&version, 0) == 0)
    {
      c->version = SSH_X509_VERSION_1;
      if (iu_found || su_found || ext_found)
        {
          rv = SSH_X509_FAILED_VERSION_CHECK;
          goto failed;
        }
    }
  if (ssh_mprz_cmp_ui(&version, 1) == 0)
    {
      c->version = SSH_X509_VERSION_2;
      if (ext_found)
        {
          rv = SSH_X509_FAILED_VERSION_CHECK;
          goto failed;
        }
    }
  if (ssh_mprz_cmp_ui(&version, 2) == 0)
    c->version = SSH_X509_VERSION_3;

  /* Start working with nodes extracted from the certificate body. */

  /* Set serial number. */
  ssh_mprz_set(&c->serial_number, &serial_number);

  /* Find out the type and mode of the signature algorithm. */
  c->pop.signature.pk_algorithm =
    ssh_x509_find_algorithm(context, sig_alg1,
                            &c->pop.signature.pk_type);

  /* Verify that algorithm identifier are equal. */
  tmp_algorithm =
    ssh_x509_find_algorithm(context, sig_alg2, &issuer_pk_type);

  if (c->pop.signature.pk_algorithm == NULL || tmp_algorithm == NULL)
    {
      rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
      goto failed;
    }

  if (c->pop.signature.pk_type != issuer_pk_type)
    {
      rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
      goto failed;
    }

  /* Get the signed data (e.g. proved message) */
  if (ssh_asn1_node_get_data(tbs_certificate,
                             &c->pop.proved_message,
                             &c->pop.proved_message_len)
      != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Get the public key from certificate. */
  if (ssh_x509_decode_asn1_public_key(context, subject_pk_info,
                                      &c->subject_pkey) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto failed;
    }

  /* Serialize the signature (hiding key type differencies) into octet
     string accepted by the cryptographic library. This also sanity
     checks the signature structure. */
  c->pop.signature.signature =
    ssh_x509_decode_signature(context,
                              signature,
                              signature_len,
                              c->pop.signature.pk_type,
                              &c->pop.signature.signature_len);

  if (c->pop.signature.signature == NULL)
    {
      rv = SSH_X509_FAILED_SIGNATURE_CHECK;
      goto failed;
    }

  /* Free the temporary signature object */
  ssh_free(signature);
  signature = NULL;

  /* Decode validity period. */
  status =
    ssh_asn1_read_node(context, validity,
                       "(sequence ()"
                       "  (choice "
                       "    (utc-time ())"
                       "    (generalized-time ()))" /* not before */
                       "  (choice "
                       "    (utc-time ())"
                       "    (generalized-time ())))",/* not after  */
                       &which1, &c->not_before, &c->not_before,
                       &which2, &c->not_after, &c->not_after);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Deserialize the issuer name */
  if (ssh_x509_decode_dn_name(context,
                              issuer_dn_name,
                              SSH_X509_NAME_DISTINGUISHED_NAME,
                              &c->issuer_name,
                              &c->config) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_DN_NAME_CHECK;
      goto failed;
    }

  /* and subject name */
  if (ssh_x509_decode_dn_name(context,
                              subject_dn_name,
                              SSH_X509_NAME_DISTINGUISHED_NAME,
                              &c->subject_name,
                              &c->config) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_DN_NAME_CHECK;
      goto failed;
    }

  /* Get unique identifiers (iu=issuer unique, su=subject unique), if
     any */
  if (iu_found)
    {
      size_t issuer_ui_byte_length = (issuer_ui_len + 7) / 8;

      new_name = ssh_x509_name_alloc(SSH_X509_NAME_UNIQUE_ID,
                                     NULL, NULL,
                                     issuer_ui,
                                     issuer_ui_byte_length,
                                     NULL, 0);
      ssh_x509_name_push(&c->issuer_name, new_name);
      issuer_ui = NULL;
    }
  if (su_found)
    {
      size_t subject_ui_byte_length = (subject_ui_len + 7) / 8;

      new_name = ssh_x509_name_alloc(SSH_X509_NAME_UNIQUE_ID,
                                     NULL, NULL,
                                     subject_ui,
                                     subject_ui_byte_length,
                                     NULL, 0);
      ssh_x509_name_push(&c->subject_name, new_name);
      subject_ui = NULL;
    }

  /* Decode extensions if any */
  if (ext_found)
    {
      rv = ssh_x509_cert_decode_extension(context, extensions, c);
      if (rv != SSH_X509_OK)
        goto failed;
    }

  /* We are done. Mark as success */
  rv = SSH_X509_OK;

 failed:
  if (rv != SSH_X509_OK)
    c->version = SSH_X509_VERSION_UNKNOWN;

  /* free temporary data */
  ssh_free(signature);
  ssh_free(issuer_ui);
  ssh_free(subject_ui);

  ssh_mprz_clear(&version);
  ssh_mprz_clear(&serial_number);

  return rv;
}
#endif /* SSHDIST_CERT */
