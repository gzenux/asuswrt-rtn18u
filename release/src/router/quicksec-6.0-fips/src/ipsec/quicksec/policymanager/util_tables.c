/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Various value to name SshKeyword tables.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"


/* Mapping between SshIkev2ProtocolIdentifiers and their names. */
const SshKeywordStruct ssh_pm_ike_protocol_identifiers[] =
  {
    {"None", SSH_IKEV2_PROTOCOL_ID_NONE},
    {"IKE",  SSH_IKEV2_PROTOCOL_ID_IKE},
    {"AH",   SSH_IKEV2_PROTOCOL_ID_AH},
    {"ESP",   SSH_IKEV2_PROTOCOL_ID_ESP},
    {NULL, 0},
  };


/* Mapping between SshPmAuthMethod and their names. */
const SshKeywordStruct ssh_pm_ike_authentication_methods[] =
{
  {"Reserved",              SSH_PM_AUTH_NONE},
  {"Pre-shared key",         SSH_PM_AUTH_PSK},
#ifdef SSHDIST_IKE_CERT_AUTH
  {"RSA signature",          SSH_PM_AUTH_RSA},
  {"DSS signature",          SSH_PM_AUTH_DSA},
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
  {"EAP MD5 challenge",      SSH_PM_AUTH_EAP_MD5_CHALLENGE},
  {"EAP MSCHAPv2",           SSH_PM_AUTH_EAP_MSCHAP_V2},
  {"EAP SIM",                SSH_PM_AUTH_EAP_SIM},
  {"EAP AKA",                SSH_PM_AUTH_EAP_AKA},






  {"EAP TLS",                SSH_PM_AUTH_EAP_TLS},
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CRYPT_ECP
  {"DSA Elliptic Curve ECP signature", SSH_PM_AUTH_ECP_DSA},
#endif /* SSHDIST_CRYPT_ECP */
#endif /* SSHDIST_IKE_CERT_AUTH */
  {NULL, 0},
};

#ifdef SSHDIST_IKE_CERT_AUTH

/* Mapping between SshIkev2CertEncoding and their names. */
const SshKeywordStruct ssh_pm_ike_certificate_encodings[] =
{
  {"None",                      0},
  {"PKCS#7",                    SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509},
  {"PGP",                       SSH_IKEV2_CERT_PGP},
  {"DNS",                       SSH_IKEV2_CERT_DNS_SIGNED_KEY},
  {"X.509 Signature",           SSH_IKEV2_CERT_X_509},
  {"Kerberos Tokens",           SSH_IKEV2_CERT_KERBEROS_TOKEN},
  {"CRL",                       SSH_IKEV2_CERT_CRL},
  {"ARL",                       SSH_IKEV2_CERT_ARL},
  {"SPKI",                      SSH_IKEV2_CERT_SPKI},
  {"X.509 Attribute",           SSH_IKEV2_CERT_X_509_ATTRIBUTE},
  {"Raw RSA Key",               SSH_IKEV2_CERT_RAW_RSA_KEY},
  {"Hash and URL Cert",         SSH_IKEV2_CERT_HASH_AND_URL_X509},
  {"Hash and URL Bundle",       SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE},
  {NULL, 0},
};

#endif /* SSHDIST_IKE_CERT_AUTH */

/* Mapping between SshIkeErrorCodes and their names. */
const SshKeywordStruct ssh_pm_ike_error_codes[] =
{
  {"OK",                           SSH_IKEV2_ERROR_OK},
  {"Unsupported critical payload",
   SSH_IKEV2_ERROR_UNSUPPORTED_CRITICAL_PAYLOAD},
  {"Invalid major version",        SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION},
  {"Invalid syntax",               SSH_IKEV2_ERROR_INVALID_SYNTAX},
  {"No proposal chosen",           SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN},
  {"Invalid Key Exchange payload", SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD},
  {"Authentication failed",        SSH_IKEV2_ERROR_AUTHENTICATION_FAILED},
  {"Traffic selector unacceptable",SSH_IKEV2_ERROR_TS_UNACCEPTABLE},
  {"Out of memory",                SSH_IKEV2_ERROR_OUT_OF_MEMORY},
  {"Invalid argument",             SSH_IKEV2_ERROR_INVALID_ARGUMENT},
  {"Crypto error",                 SSH_IKEV2_ERROR_CRYPTO_FAIL},
  {"Timeout",                      SSH_IKEV2_ERROR_TIMEOUT},
  {"Transmit error",               SSH_IKEV2_ERROR_XMIT_ERROR},
  {"Cookie required",              SSH_IKEV2_ERROR_COOKIE_REQUIRED},
  {"Use IKEv1",                    SSH_IKEV2_ERROR_USE_IKEV1},
  {"Shutdown pending",             SSH_IKEV2_ERROR_GOING_DOWN},
  {"Peer window full",             SSH_IKEV2_ERROR_WINDOW_FULL},
  {"SA unusable (deleted)",        SSH_IKEV2_ERROR_SA_UNUSABLE},
  {NULL, 0},
};
