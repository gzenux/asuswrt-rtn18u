/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file initializes certificate library in the compatible, full
   featured mode, that is, it initializes itself, underlying
   cryptography and registers encoders and decoders for X509
   certificates, and certificate lists, as well as for CRMF and PKCS#10
   certificate requests.
*/

#include "sshincludes.h"
#include "x509.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertX509"

Boolean ssh_x509_library_initialize(SshX509Config config)
{
  if (ssh_x509_library_initialize_framework(config))
    {
      ssh_x509_library_register_functions(SSH_X509_PKIX_CERT,
                                          ssh_x509_cert_decode_asn1,
                                          ssh_x509_cert_encode_asn1);

#ifdef SSHDIST_CERT_CRMF
      ssh_x509_library_register_functions(SSH_X509_PKIX_CRMF,
                                          ssh_x509_crmf_decode_asn1,
                                          ssh_x509_crmf_encode_asn1);
#endif /* SSHDIST_CERT_CRMF */

#ifdef SSHDIST_CERT_PKCS10
      ssh_x509_library_register_functions(SSH_X509_PKCS_10,
                                          ssh_x509_pkcs10_decode_asn1,
                                          ssh_x509_pkcs10_encode_asn1);
#endif /* SSHDIST_CERT_PKCS10 */

      return TRUE;
    }
  return FALSE;
}
/* x509init.c */
#endif /* SSHDIST_CERT */
