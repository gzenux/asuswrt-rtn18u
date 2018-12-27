/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   PKCS6 extended certificates API.
*/

#ifndef SSHPKCS6_H
#define SSHPKCS6_H

#include "sshglist.h"

/* We need the basic PKCS-6 data structure. */

typedef enum
{
  SSH_PKCS6_OK,
  SSH_PKCS6_ASN1_DECODING_FAILED,
  SSH_PKCS6_ASN1_ENCODING_FAILED,
  SSH_PKCS6_OID_NOT_FOUND,

  SSH_PKCS6_SIGN_METHOD_NIL,
  SSH_PKCS6_SIGNATURE_INPUT_SIZE_TOO_SHORT,
  SSH_PKCS6_SIGNING_FAILED,

  SSH_PKCS6_SIGNATURE_ENCODING_FAILED,

  SSH_PKCS6_SIGNATURE_NOT_DEFINED,

  SSH_PKCS6_CERTIFICATE_DECODE_FAILED,

  SSH_PKCS6_FAILURE
} SshPkcs6Status;


typedef struct SshPkcs6CertRec
{
  /* Is the certificate extended? */
  Boolean extended;

  SshX509Certificate certificate;

  /* The signature algorithm to use in the signing operation. */
  const char *signature_algorithm;
  SshX509PkAlgorithm issuer_pk_type;

  /* The attributes used. */
  SshGList attr;

  /* The signature of the certificate information. */
  unsigned char *signature;
  size_t         signature_length;

  /* The encoded form. */
  unsigned char *ber_buf;
  size_t         ber_length;
} *SshPkcs6Cert;

/* This is not really PKCS6, but looks better when written that way. */
typedef struct SshPkcs6CrlRec
{
  SshX509Crl crl;

  /* The encoded form. */
  unsigned char *ber_buf;
  size_t         ber_length;
} *SshPkcs6Crl;

/* Init and Free extented certificates and crl's. Only exported for
   use of the pkcs#7 module. */
void ssh_pkcs6_crl_init(SshPkcs6Crl crl);
void ssh_pkcs6_crl_free(SshPkcs6Crl crl);
void ssh_pkcs6_cert_init(SshPkcs6Cert cert);
void ssh_pkcs6_cert_free(SshPkcs6Cert cert);

/* Decode the PKCS-6 extended certificate given as a ASN.1 tree node. */
SshPkcs6Status ssh_pkcs6_cert_decode_asn1(SshAsn1Context context,
                                          SshAsn1Node node,
                                          SshPkcs6Cert cert);


void ssh_glist_free_pkcs6_attr(SshGList list);

SshPkcs6Status
ssh_pkcs6_attr_decode(unsigned char *ber, size_t ber_length,
                      SshGList *attr);
SshPkcs6Status
ssh_pkcs6_attr_decode_asn1(SshAsn1Context context,
                           SshAsn1Node node_input,
                           SshGList *list_return);
SshPkcs6Status
ssh_pkcs6_attr_encode(SshGList attr,
                      unsigned char **ber, size_t *ber_length);
SshPkcs6Status
ssh_pkcs6_attr_encode_asn1(SshAsn1Context context,
                           SshGList glist,
                           SshAsn1Node *node_return);

/* Create an extended certificate. The buffer containing the 'cert' is
   a valid X.509 certificate, and the attributes 'attr' are validly
   defined X.509 attributes. The private key 'key' is used to sign the
   BER encoded certificate information.

   If the 'attr' is NULL then no attributes are present, but even in
   this case the the extended certificate is created. Note, that this
   function creates also the extended certificate, and doesn't
   optimize if not attributes are present.  */
SshPkcs6Status
ssh_pkcs6_cert_encode(unsigned char *cert, size_t cert_length,
                      SshGList attr,
                      SshPrivateKey key,
                      unsigned char **ber_bUf, size_t *ber_length);

/* Decode the PKCS-6 extended certificate blob. */
SshPkcs6Status
ssh_pkcs6_cert_decode(unsigned char *ber_buf, size_t ber_length,
                      SshPkcs6Cert cert);

#endif /* SSHPKCS6_H */
