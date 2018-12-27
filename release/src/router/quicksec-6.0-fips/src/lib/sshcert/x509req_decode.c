/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate request (PKCS#10) decoding routines.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

/* NOTE: In the following PKCS #10 parsing and encoding codes we have
   not been able yet to support all possible ways to handle alternate
   names. However, there doesn't seem to be a general consensus on
   this anyway so this should not matter much. However, when a
   suitable format is defined and generally used we will of course
   implement it. */

SshX509Status ssh_x509_pkcs10_decode_asn1(SshAsn1Context context,
                                          SshAsn1Node cert_request_node,
                                          SshX509Certificate c)
{
  SshAsn1Tree vt;
  SshAsn1Node request_node, subject_public_key,
    sig_alg, subject_name, attributes, attribute, node;
  unsigned char *signature;
  size_t signature_len;
  unsigned char *t61;
  size_t t61_len;
  Boolean version_found, attributes_found;
  SshAsn1Status status;
  const SshOidStruct *found_oid;
  unsigned char *oid;
  unsigned int extra_int = 0;
  SshMPIntegerStruct version;
  SshX509Status rv = SSH_X509_FAILURE;

  /* We need a version number later. */
  ssh_mprz_init(&version);
  signature = NULL;

  /* The structure of PKCS#10 request. */

  /* Read the CertificationRequest. */
  status =
    ssh_asn1_read_node(context, cert_request_node,
                       "(sequence (*)"
                       "  (any ())" /* CertificateRequestInfo */
                       "  (any ())" /* signature algorithm identifier */
                       "  (bit-string ()))", /* signature */
                       &request_node,
                       &sig_alg,
                       &signature, &signature_len);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Decode the request info part. */
  status =
    ssh_asn1_read_node(context, request_node,
                       "(sequence ()"
                       "  (optional"
                       "    (integer ()))" /* version number */
                       "  (any ())"        /* subject name */
                       "  (any ())"        /* subject public key info. */
                       "  (optional"
                       "    (any (0))))",  /* implicit attributes. */
                       &version_found,
                       &version, /* This seems to be always present. */
                       &subject_name,
                       &subject_public_key,
                       &attributes_found, &attributes);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  if (version_found == FALSE)
    ssh_mprz_set_ui(&version, 0);

  /* Version test. */
  if (ssh_mprz_cmp_ui(&version, 0) < 0 || ssh_mprz_cmp_ui(&version, 3) > 0)
    {
      rv = SSH_X509_FAILED_VERSION_CHECK;
      goto failed;
    }


  /* Find the algorithm which is used here. */
  c->pop.signature.pk_algorithm =
    ssh_x509_find_algorithm(context, sig_alg,
                            &c->pop.signature.pk_type);
  if (c->pop.signature.pk_algorithm == NULL)
    {
      rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
      goto failed;
    }

  /* Get the data which was in the signed part. */
  ssh_asn1_node_get_data(request_node,
                         &c->pop.proved_message,
                         &c->pop.proved_message_len);

  /* Manipulate the signature if necessary. */
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

  ssh_free(signature);
  signature = NULL;

  /* Decode the public key. */
  if (ssh_x509_decode_asn1_public_key(context, subject_public_key,
                                 &c->subject_pkey) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto failed;
    }

  /* Decode distinguished name. */
  if (ssh_x509_decode_dn_name(context,
                              subject_name,
                              SSH_X509_NAME_DISTINGUISHED_NAME,
                              &c->subject_name,
                              &c->config) != SSH_X509_OK)
    {
      rv = SSH_X509_FAILED_DN_NAME_CHECK;
      goto failed;
    }

  /* Handle attributes. */
  if (attributes_found)
    {
      /* Lets duplicate some code.
         Here we do the work needed to find out the attributes and in
         particular the X.509v3 extension for subject alternate name.
         This version might not be entirely compatible with versions
         that are more commonly used. */
      status =
        ssh_asn1_read_node(context, attributes,
                           "(set (0) (any ()))",
                           &attribute);
      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto failed;
        }

      for (; attribute; attribute = ssh_asn1_node_next(attribute))
        {
          Boolean t_found, e_found;
          SshAsn1Node temp_node;
          SshX509Attribute attr;
          int which;

          status =
            ssh_asn1_read_node(context, attribute,
                               "(sequence ()"
                               "  (object-identifier ())"
                               "  (any ()))",
                               &oid, &node);
          if (status != SSH_ASN1_STATUS_OK)
            {
              rv = SSH_X509_FAILED_ASN1_DECODE;
              goto failed;
            }

          /* Find the oid information. Either PKCS#9 or m$CAT */
          found_oid = ssh_oid_find_by_oid_of_type(oid, SSH_OID_PKCS9);
          if (found_oid)
            extra_int = SSH_OID_PKCS9;
          else
            {
              found_oid = ssh_oid_find_by_oid_of_type(oid, SSH_OID_CAT);
              if (found_oid)
                extra_int = SSH_OID_CAT;
            }
          ssh_free(oid);
          oid = NULL;
          if (found_oid == NULL)
            continue;

          extra_int += found_oid->extra_int * SSH_OID_NONE;
          switch (extra_int)
            {
            case 0 *SSH_OID_NONE + SSH_OID_CAT  : /* catExtension */
            case 8 *SSH_OID_NONE + SSH_OID_PKCS9: /* extendedCertAttr */
            case 13*SSH_OID_NONE + SSH_OID_PKCS9: /* ExtensionReq */
              /* The approach currently seems to be that these are all
                 equivalent, although there were some questions
                 before. */
              status = ssh_asn1_read_node(context, node,
                                          "(set ()"
                                          "  (optional (teletex-string ()))"
                                          "  (optional (any ())))",
                                          &t_found, &t61, &t61_len,
                                          &e_found, &temp_node);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  rv = SSH_X509_FAILED_ASN1_DECODE;
                  goto failed;
                }

              if (t_found && e_found)
                {
                  ssh_free(t61);
                  t61 = NULL;
                  rv = SSH_X509_FAILED_UNKNOWN_VALUE;
                  goto failed;
                }

              if (t_found)
                {
                  (void)ssh_asn1_decode(context, t61, t61_len, &vt);
                  temp_node = ssh_asn1_get_root(vt);
                  ssh_free(t61);
                  t61 = NULL;
                }

              rv = ssh_x509_cert_decode_extension(context, temp_node, c);
              if (rv != SSH_X509_OK)
                goto failed;
              break;

            case 1*SSH_OID_NONE + SSH_OID_PKCS9: /* unstructuredName */
              if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
                {
                  attr->type = SSH_X509_PKCS9_ATTR_UNSTRUCTURED_NAME;
                  goto readit;
                }
              else
                goto failed;

            case 6*SSH_OID_NONE + SSH_OID_PKCS9: /* challengePassword */
              if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
                {
                  attr->type = SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD;
                  goto readit;
                }
              else
                goto failed;

            case 7*SSH_OID_NONE + SSH_OID_PKCS9: /* unstructuredAddress */
              if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
                attr->type = SSH_X509_PKCS9_ATTR_UNSTRUCTURED_ADDRESS;
              else
                goto failed;

            readit:
              status = ssh_asn1_read_node(context, node,
                                          "(set ()"
                                          "  (choice"
                                          "     (universal-string ())"
                                          "     (printable-string ())"
                                          "     (teletex-string ())))",
                                          &which,
                                          &attr->data, &attr->len,
                                          &attr->data, &attr->len,
                                          &attr->data, &attr->len);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  ssh_free(attr);
                  rv = SSH_X509_FAILED_ASN1_DECODE;
                  goto failed;
                }
              attr->oid = ssh_strdup(found_oid->oid);
              ssh_x509_cert_set_attribute(c, attr);
              break;

            default:
              /* Add attribute as unknown; e.g. store its oid and ber
                 presentation into attribute list. */
              if ((attr = ssh_calloc(1, sizeof(*attr))) != NULL)
                {
                  attr->type = SSH_X509_ATTR_UNKNOWN;
                  attr->oid = ssh_strdup(found_oid->oid);
                  if (ssh_asn1_node_get_data(node, &attr->data, &attr->len) !=
                      SSH_ASN1_STATUS_OK)
                    {
                      ssh_free(attr);
                      continue;
                    }
                  ssh_x509_cert_set_attribute(c, attr);
                }
              break;
            }
        }
    }
  c->version = ssh_mprz_get_ui(&version);

  rv = SSH_X509_OK;
failed:
  if (rv != SSH_X509_OK)
    c->version = SSH_X509_VERSION_UNKNOWN;

  ssh_free(signature);
  ssh_mprz_clear(&version);

  return rv;
}
#endif /* SSHDIST_CERT */
