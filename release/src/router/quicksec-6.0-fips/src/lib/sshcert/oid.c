/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Object identifier routines.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "x509.h"
#include "dn.h"
#include "oid.h"

#ifdef SSHDIST_CERT

/* To get numbers for PKCS#7 oids. */
#include "sshpkcs7.h"

#define UCL     "0.9.2342.19200300.100.1"
#define PKI     "1.3.6.1.5.5.7"
#define RSA     "1.2.840.113549"
#define OIW     "1.3.14.3"
#define NIST    "2.16.840.1.101.3.4"
#define MICROSOFT "1.3.6.1.4.1.311"
#define TTHASH  "1.3.36.3.2" /* Teletrust hash algorithms */
#define ETSI    "0.4.0"
#define ELLIPTICCURVE "1.3.132.0"
#define BRAINPOOLCURVE "1.3.36.3.3.2.8.1.1"

#define SSH_DEBUG_MODULE "SshCertOid"

/* A list of all supported Oids. */

/***************** Oids for the Distinguished names. *******************/

/* The public key systems that are supported. */
const SshOidPkStruct ssh_oid_pk_table[] =
{
  { SSH_X509_PKALG_RSA,
    /* user */
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION   |
    SSH_X509_UF_KEY_ENCIPHERMENT  |
    SSH_X509_UF_DATA_ENCIPHERMENT,
    /* CA */
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION   |
    SSH_X509_UF_KEY_ENCIPHERMENT  |
    SSH_X509_UF_DATA_ENCIPHERMENT |
    SSH_X509_UF_KEY_CERT_SIGN     |
    SSH_X509_UF_CRL_SIGN
  },
  { SSH_X509_PKALG_DSA,
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION,
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION   |
    SSH_X509_UF_KEY_CERT_SIGN     |
    SSH_X509_UF_CRL_SIGN
  },
  { SSH_X509_PKALG_DSA,
    SSH_X509_UF_KEY_AGREEMENT |
    SSH_X509_UF_ENCIPHER_ONLY |
    SSH_X509_UF_DECIPHER_ONLY,
    SSH_X509_UF_KEY_AGREEMENT |
    SSH_X509_UF_ENCIPHER_ONLY |
    SSH_X509_UF_DECIPHER_ONLY
  },
  {
    SSH_X509_PKALG_ECDSA,
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION |
    SSH_X509_UF_KEY_AGREEMENT |
    SSH_X509_UF_ENCIPHER_ONLY |
    SSH_X509_UF_DECIPHER_ONLY,
    SSH_X509_UF_DIGITAL_SIGNATURE |
    SSH_X509_UF_NON_REPUDIATION |
    SSH_X509_UF_KEY_AGREEMENT |
    SSH_X509_UF_ENCIPHER_ONLY |
    SSH_X509_UF_DECIPHER_ONLY |
    SSH_X509_UF_KEY_CERT_SIGN |
    SSH_X509_UF_CRL_SIGN
  }
};

const SshOidStruct ssh_oid_list_pk[] =
{
    /* Define the PK Oids. */
  { RSA ".1.1.1",
    "rsaEncryption",
    "if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}",
    &ssh_oid_pk_table[0], 0 },
  { "2.5.8.1",
    "rsa",
    "if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}",
    &ssh_oid_pk_table[0], 0 },
  { "2.5.8.1.1",
    "rsa",
    "if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}",
    &ssh_oid_pk_table[0], 0 },
  { "1.2.840.10040.4.1",
    "dsaEncryption",
    "dl-modp{sign{dsa}}",
    &ssh_oid_pk_table[1], 0 },
  { "1.2.840.10040.4.3",
    "dsaWithSHA-1",
    "dl-modp{sign{dsa-nist-sha1}}",
    &ssh_oid_pk_table[1], 0 },
  { OIW  ".2.12",
    "dsaWithSHA-1",
    "dl-modp{sign{dsa-nist-sha1}}",
    &ssh_oid_pk_table[1], 0 },
  { "1.2.840.10046.2.1",
    "diffieHellman", "dl-modp{dh}",
    &ssh_oid_pk_table[2], 0 },
  { "1.2.840.10045.2.1",
    "ecdsaEncryption",
    "ec-modp{sign{dsa-none-sha1}}",
    &ssh_oid_pk_table[3], 0 },
  { NULL }
};

const SshOidStruct ssh_oid_list_sig[] =
{
  /* Define the signature Oids. We shouldn't be using these 1.3.14.7.2.*
     numbers, because they are from the company that is out of business */
  { "1.3.14.7.2.3.2",
    "elgamalWithMD2", "elgamal-none-md2",
    "dl-modp{sign{elgamal-none-md2}}", SSH_X509_PKALG_ELGAMAL },
  { OIW  ".2.29",
    "rsaWithSHA-1", "rsa-nist-sha1",
    "if-modn{sign{rsa-nist-sha1}}", SSH_X509_PKALG_RSA },
  { OIW  ".2.29",
    "rsaWithSHA", "rsa-nist-sha",
    "if-modn{sign{rsa-nist-sha}}", SSH_X509_PKALG_RSA },
  { "1.2.840.10040.4.3",
    "dsaWithSHA-1", "dsa-nist-sha1",
    "dl-modp{sign{dsa-nist-sha1}}", SSH_X509_PKALG_DSA },
  { OIW  ".2.27",
    "dsaWithSHA-1", "dsa-nist-sha1",
    "dl-modp{sign{dsa-nist-sha1}}", SSH_X509_PKALG_DSA },
  { OIW  ".2.13",
    "dsaWithSHA", "dsa-nist-sha",
    "dl-modp{sign{dsa-nist-sha}}", SSH_X509_PKALG_DSA },

  { NIST  ".3.1",
    "dsaWithSHA224", "dsa-nist-sha224",
    "dl-modp{sign{dsa-nist-sha224}}", SSH_X509_PKALG_DSA },
  { NIST  ".3.2",
    "dsaWithSHA256", "dsa-nist-sha256",
    "dl-modp{sign{dsa-nist-sha256}}", SSH_X509_PKALG_DSA },

  { RSA  ".1.1.2",
    "md2WithRSAEncryption", "rsa-pkcs1-md2",
    "if-modn{sign{rsa-pkcs1-md2},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA  ".1.1.3",
    "md4WithRSAEncryption", "rsa-pkcs1-md4",
    "if-modn{sign{rsa-pkcs1-md4},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA  ".1.1.4",
    "md5WithRSAEncryption", "rsa-pkcs1-md5",
    "if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA  ".1.1.5",
    "sha1WithRSAEncryption", "rsa-pkcs1-sha1",
    "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA ".1.1.10",
    "RSASSA-PSS", "rsa-pss-any",
    "if-modn{sign{rsa-pss-any}}",
    SSH_X509_PKALG_PSS },
  { RSA ".1.1.11",
    "sha256WithRSAEncryption", "rsa-pkcs1-sha256",
    "if-modn{sign{rsa-pkcs1-sha256},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA ".1.1.12",
    "sha384WithRSAEncryption", "rsa-pkcs1-sha384",
    "if-modn{sign{rsa-pkcs1-sha384},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA ".1.1.13",
    "sha512WithRSAEncryption", "rsa-pkcs1-sha512",
    "if-modn{sign{rsa-pkcs1-sha512},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { RSA ".1.1.14",
    "sha224WithRSAEncryption", "rsa-pkcs1-sha224",
    "if-modn{sign{rsa-pkcs1-sha224},encrypt{rsa-pkcs1-none}}",
    SSH_X509_PKALG_RSA },
  { "1.3.36.3.3.1.2",
    "ripemd160WithRSAEncryption", "rsa-pkcs1-ripemd160",
    "if-modn{sign{rsa-pkcs1-ripemd160},encrypt{rsa-pkcs1-ripemd16}}",
    SSH_X509_PKALG_RSA },
  { "1.3.36.3.3.1.3",
    "ripemd128WithRSAEncryption", "rsa-pkcs1-ripemd128",
    "if-modn{sign{rsa-pkcs1-ripemd128},encrypt{rsa-pkcs1-ripemd128}}",
    SSH_X509_PKALG_RSA },
  { "1.2.840.10045.4.1",
    "ecdsaWithSHA1", "dsa-none-sha1",
    "ec-modp{sign{dsa-none-sha1}}",
    SSH_X509_PKALG_ECDSA },
  { "1.2.840.10045.4.3.1",
    "ecdsaWithSHA224", "dsa-none-sha224",
    "ec-modp{sign{dsa-none-sha224}}",
    SSH_X509_PKALG_ECDSA },
  { "1.2.840.10045.4.3.2",
    "ecdsaWithSHA256", "dsa-none-sha256",
    "ec-modp{sign{dsa-none-sha256}}",
    SSH_X509_PKALG_ECDSA },
  { "1.2.840.10045.4.3.3",
    "ecdsaWithSHA384", "dsa-none-sha384",
    "ec-modp{sign{dsa-none-sha384}}",
    SSH_X509_PKALG_ECDSA },
  { "1.2.840.10045.4.3.4",
    "ecdsaWithSHA512", "dsa-none-sha512",
    "ec-modp{sign{dsa-none-sha512}}",
    SSH_X509_PKALG_ECDSA },

  { NULL }
};

const SshOidStruct ssh_oid_list_ext_key_usage[] =
{
  /* The extended key usage oids. */
  { PKI  ".3.1", "serverAuth", "server auth", NULL, 0 },
  { PKI  ".3.2", "clientAuth", "client auth", NULL, 0 },
  { PKI  ".3.3", "codeSigning", "code signing", NULL, 0 },
  { PKI  ".3.4", "emailProtection", "email protection", NULL, 0 },
  /* These three are not supposed to be used */
  { PKI  ".3.5", "ipsecEndSystem", "ipsec end system", NULL, 0 },
  { PKI  ".3.6", "ipsecTunnel", "ipsec tunnel", NULL, 0 },
  { PKI  ".3.7", "ipsecUser", "ipsec user", NULL, 0 },

  { PKI  ".3.8", "timeStamping", "time stamping", NULL, 0 },
  /* This is the one for IKE */
  { "1.3.6.1.5.5.8.2.2", "ikeIntermediate", "ike intermediate", NULL, 0 },
  /* Windows 2000 logon */
  { MICROSOFT ".20.2.2", "smartCardLogon", "Smart Card Logon", NULL, 0 },
  { "1.3.6.1.4.1.4449.1.2.4.1.1", "rASignature", "RA signature", NULL, 0 },
  { NULL }
};

const SshOidStruct ssh_oid_list_pkix_crmf[] =
{
  { PKI  ".5.1.1", "regToken",
    "->utf8string", NULL, SSH_X509_CTRL_REG_TOKEN },
  { PKI  ".5.1.2", "authenticator",
    "->utf8string", NULL, SSH_X509_CTRL_AUTHENTICATOR },
  { PKI  ".5.1.3", "pkiPublicationInfo",
    "->pkiPubInfo", NULL, SSH_X509_CTRL_PKI_INFO },
  { PKI  ".5.1.4", "pkiArchiveOptions",
    "->ArchiveOptions", NULL, SSH_X509_CTRL_PKI_OPTIONS },
  { PKI  ".5.1.5", "oldCertID",
    "->CertId", NULL, SSH_X509_CTRL_OLD_CERT_ID },
  { PKI  ".5.1.6", "protocolEncrKey",
    "->PubKeyInfo", NULL, SSH_X509_CTRL_PUBLIC_KEY },
  { PKI  ".5.2.1", "utf8Pairs",
    "->utf8string", NULL, 0 },
  { PKI  ".5.2.2", "certReq",
    "->certreq", NULL, 0 },
  { NULL }
};


const SshOidStruct ssh_oid_list_pkix_cmp[] =
{
  { PKI  ".4.1",   "CAProtEncCert",     "->certificate", NULL, 1 },
  { PKI  ".4.2",   "SignKeyPairTypes",  "->sequence of oid", NULL, 1 },
  { PKI  ".4.3",   "EncKeyPairTypes",   "->sequence of oid", NULL, 1 },
  { PKI  ".4.4",   "PreferredSymmAlg",  "->oid", NULL, 1 },
  { PKI  ".4.5",   "CAKeyUpdInfo",      "->cakeyupdanncont", NULL, 1 },
  { PKI  ".4.6",   "CurrentCRL",        "->crl", NULL, 1 },
  { PKI  ".4.7",   "UnsupportedOids",   "->sequence of oid", NULL, 1 },
  { PKI  ".4.10",  "KeyPairParamReq",   "->oid", NULL, 1 },
  { PKI  ".4.11",  "KeyPairParamRep",   "->alg id", NULL, 1 },
  { PKI  ".4.12",  "RevPassPhrase",     "->encryptedvalue", NULL, 1 },
  { PKI  ".4.13",  "ImplicitConfirm",   "->NULL", NULL, 1 },
  { PKI  ".4.14",  "ConfirmWaitTime",   "->generaltime", NULL, 1 },
  { PKI  ".4.15",  "OrigPkiMessage",    "->pkimessage", NULL, 1 },
  { NULL }
};

const SshOidStruct ssh_oid_list_ext[] =
{
    /* The extensions. */
  { "2.5.29.35",
    "authorityKeyIdentifier",
    "authority key identifier",
    NULL,
    SSH_X509_EXT_AUTH_KEY_ID },
  { "2.5.29.14",
    "subjectKeyIdentifier",
    "subject key identifier",
    NULL,
    SSH_X509_EXT_SUBJECT_KEY_ID },
  { "2.5.29.15",
    "keyUsage",
    "key usage",
    NULL,
    SSH_X509_EXT_KEY_USAGE },
  { "2.5.29.16",
    "privateKeyUsagePeriod",
    "private key usage period",
    NULL,
    SSH_X509_EXT_PRV_KEY_UP },
  { "2.5.29.32",
    "certificatePolicies",
    "certificate policies",
    NULL,
    SSH_X509_EXT_CERT_POLICIES },
  { "2.5.29.33",
    "policyMappings",
    "policy mappings",
    NULL,
    SSH_X509_EXT_POLICY_MAPPINGS },
  { "2.5.29.17",
    "subjectAlternativeName",
    "subject alternative name",
    NULL,
    SSH_X509_EXT_SUBJECT_ALT_NAME },
  { "2.5.29.18",
    "issuerAlternativeName",
    "issuer alternative name",
    NULL,
    SSH_X509_EXT_ISSUER_ALT_NAME },
  { "2.5.29.9",
    "subjectDirectoryAttributes",
    "subject directory attributes",
    NULL,
    SSH_X509_EXT_SUBJECT_DIR_ATTR },
  { "2.5.29.19",
    "basicConstraints",
    "basic constraints",
    NULL,
    SSH_X509_EXT_BASIC_CNST },
  { "2.5.29.30",
    "nameConstraints",
    "name constraints",
    NULL,
    SSH_X509_EXT_NAME_CNST },
  { "2.5.29.36",
    "policyConstraints",
    "policy constraints",
    NULL,
    SSH_X509_EXT_POLICY_CNST },
  { PKI  ".1",
    "privateInternetExtensions",
    "private internet extensions",
    NULL,
    SSH_X509_EXT_PRV_INTERNET_EXT },

  { PKI  ".1.1",
    "authorityInformationAccess",
    "authority information access",
    NULL,
    SSH_X509_EXT_AUTH_INFO_ACCESS },

  { PKI  ".1.11",
    "subjectInformationAccess",
    "subject information access",
    NULL,
    SSH_X509_EXT_SUBJECT_INFO_ACCESS },

  { "2.5.29.31",
    "CRLDistributionPoints",
    "CRL distribution points",
    NULL,
    SSH_X509_EXT_CRL_DIST_POINTS },

  { "2.5.29.37",
    "extendedKeyUsage",
    "extended key usage",
    NULL,
    SSH_X509_EXT_EXT_KEY_USAGE },

  { "2.5.29.46",
    "freshestCRL", "freshest crl",
    NULL, SSH_X509_EXT_FRESHEST_CRL },

  { "2.5.29.54",
    "inhibitAnyPolicy", "inhibit anyPolicy",
    NULL, SSH_X509_EXT_INHIBIT_ANY_POLICY },

  { "2.16.840.1.113730.1.13",
    "netscapeComment", "netscape-comment",
    NULL, SSH_X509_EXT_NETSCAPE_COMMENT },

  /* Unknown meanings. Following oids are given for identification
     purposes. If you find an oid in extensions and would like it
     to be identified always when encountered add it here. */
  { "2.16.840.1.113730.1.1",
    "unknown (certificate type)", "unknown",
    NULL, SSH_X509_EXT_UNKNOWN },
  { "2.16.840.1.113730.1.3",
    "unknown (revocation URL)", "unknown",
    NULL, SSH_X509_EXT_UNKNOWN },
  { "2.16.840.1.113730.1.4",
    "unknown (CA revocation URL)", "unknown",
    NULL, SSH_X509_EXT_UNKNOWN },
  { "2.16.840.1.113730.1.7",
    "unknown (renewal URL)", "unknown",
    NULL, SSH_X509_EXT_UNKNOWN },
  { "2.16.840.1.113730.1.8",
    "unknown (CA policy URL)", "unknown",
    NULL, SSH_X509_EXT_UNKNOWN },
  { "2.5.29.1",
    "unknown (old authority key identifier)", "unknown", NULL,
    SSH_X509_EXT_UNKNOWN },
  { "2.5.29.2",
    "unknown (old primary key attributes)", "unknown", NULL,
    SSH_X509_EXT_UNKNOWN },
  { "2.5.29.10",
    "unknown (Entrust ANX)", "unknown",  NULL,
    SSH_X509_EXT_UNKNOWN },
  { "2.5.29.25",
    "unknown (Entrust ANX)", "unknown", NULL,
    SSH_X509_EXT_UNKNOWN },
  { "1.2.840.113533.7.65.0",
    "unknown (Entrust ANX version)", "unknown", NULL,
    SSH_X509_EXT_UNKNOWN },
  { "2.5.4.45", /* See also "UI" in the dn oid list below */
    "FINUID", "FINUID", NULL,
    SSH_X509_EXT_UNKNOWN },
  { "1.2.840.113549.1.9.15",
    "S/MIME capabilities", "unknown", NULL,
    SSH_X509_EXT_UNKNOWN },
  { MICROSOFT ".20.2", "windowsCertificateTemplate",
    "Windows Certificate Template", NULL, SSH_X509_EXT_CERT_TEMPLATE_NAME },
  { PKI ".48.1.5", "ocspNoCheck", "Certificate is trusted for its lifetime",
    NULL, SSH_X509_EXT_UNKNOWN },
  { PKI ".1.3", "qcStatements",
    "Qualified Certificate Statements", NULL, SSH_X509_EXT_QCSTATEMENTS },
   { NULL }
};


const SshOidStruct ssh_oid_list_qcstatement[] =
{
  /* QCStatement extensions */
  { PKI ".11.1", "pkixQCSyntax-v1", "qcsyntax v1",
    NULL, SSH_X509_QCSTATEMENT_QCSYNTAXV1 },
  { ETSI ".1862.1.1", "QcCompliance",
    "compliance with EU directive 1999/93/EC",
    NULL, SSH_X509_QCSTATEMENT_QCCOMPLIANCE },
  { ETSI ".1862.1.2", "QcEuLimitValue", "monetary transaction value limit",
    NULL, SSH_X509_QCSTATEMENT_QCEULIMITVALUE },
  { ETSI ".1862.1.3", "QcEuRetentionPeriod", "retention period",
    NULL, SSH_X509_QCSTATEMENT_RETENTIONPERIOD },
  { NULL }
};

const SshOidStruct ssh_oid_list_crl_ext[] =
{
  /* CRL extensions */
  { "2.5.29.20",
    "crlNumber", "crl number",
    NULL, SSH_X509_CRL_EXT_CRL_NUMBER },
  { "2.5.29.28",
    "issuingDistributionPoint", "issuing distribution point",
    NULL, SSH_X509_CRL_EXT_ISSUING_DIST_POINT },
  { "2.5.29.27",
    "deltaCRLIndicator", "delta crl indicator",
    NULL, SSH_X509_CRL_EXT_DELTA_CRL_IND },
  { "2.5.29.35", /* Also in oid_list_ext[] */
    "authorityKeyIdentifier",
    "authority key identifier",
    NULL,
    SSH_X509_CRL_EXT_AUTH_KEY_ID },
  { "2.5.29.18", /* Also in oid_list_ext[] */
    "issuerAlternativeName",
    "issuer alternative name",
    NULL,
    SSH_X509_CRL_EXT_ISSUER_ALT_NAME },
  { NULL }
};

const SshOidStruct ssh_oid_list_crl_entry_ext[] =
{
  /* CRL entry extensions */
  { "2.5.29.29",
    "certificateIssuer", "certificate issuer",
    NULL, SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER },
  { "2.5.29.21",
    "crlReason", "crl reason",
    NULL, SSH_X509_CRL_ENTRY_EXT_REASON_CODE },
  { "2.5.29.23",
    "holdInstructionCode", "hold instruction code",
    NULL, SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE },
  { "2.5.29.24",
    "invalidityDate", "invalidity date",
    NULL, SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE },
   { NULL }
};

const SshOidStruct ssh_oid_list_dn[] =
{
  /* Define the DN Oids. */
  { "2.5.4.6",     "C", "country", NULL, 0 },
  { "2.5.4.7",     "L", "locality name", NULL, 1 },
  { "2.5.4.5",     "serialNumber", "serial number", NULL, 2 },
  { "2.5.4.9",     "STREET", "street address", NULL, 3 },
  { "2.5.4.8",     "ST", "state or province name", NULL, 4 },
  { "2.5.4.10",    "O", "organization", NULL, 5 },
  { "2.5.4.11",    "OU", "organizational unit", NULL, 6 },
  { "2.5.4.3",     "CN", "common name", NULL, 7 },
  { RSA  ".1.9.1", "MAILTO", "PKCS 9 email address", NULL, 8 },
  { RSA  ".1.9.2", "unstructuredName", "PKCS 9 unname", NULL, 9 },
  { "2.5.4.4",     "SN", "surname", NULL, 10 },
  { "2.5.4.12",    "title", "title", NULL, 11 },
  { "2.5.4.41",    "name", "name", NULL, 12 },
  { "2.5.4.42",    "givenName", "given name", NULL, 13 },
  { "2.5.4.43",    "initials", "initials", NULL, 14 },
  { "2.5.4.44",    "generationQualifier", "generation qualifier", NULL, 15 },
  { "2.5.4.45",    "x500UniqueIdentifier", "X.500 UI", NULL, 16 },
  { "2.5.4.46",    "dnQualifier", "DN qualifier", NULL, 17 },
  { "1.3.6.1.4.1.1466.115.121.1.26", "brokenDC",
    "broken domain component", NULL, 18 }, /* Bug compatibility. */

  { RSA  ".1.9.8", "unstructuredAddress", "PKCS 9 unaddr", NULL, 19 },
  { "2.5.4.65",    "pseudonym", "Pseudonym", NULL, 21 },
  /* Postal address is not encoded/decoded properly in RDNs or anywhere */
  { "2.5.4.16",    "postalAddress", "Postal Address", NULL, 22 },
  { NULL }
};

const SshOidStruct ssh_oid_ucl_directory_pilot[] =
{
  { UCL ".1",  "UID", "UserId", NULL, 1 },
  { UCL ".3",  "uclMailTo", "rfc822Mailbox", NULL, 3 }, /* IA5 */
  { UCL ".4",  "genInfo", "info", NULL, 4 },
  { UCL ".5",  "favouriteDrink", "favourite drink", NULL, 5},
  { UCL ".6",  "roomNumber", "room number", NULL, 6 },
  { UCL ".8",  "userClass", "user class", NULL, 8 },
  { UCL ".9",  "host", "host name or address", NULL, 9 },
  { UCL ".10", "manager", "DN of the Manager", NULL, 10 },
  { UCL ".11", "documentIdentifier", "", NULL, 11 },
  { UCL ".12", "documentTitle", "", NULL, 12 },
  { UCL ".13", "documentVersion", "", NULL, 13 },
  { UCL ".25", "DC", "domainComponent", NULL, 25 }, /* IA5 */
  { UCL ".44", "uclUniqueIdentifier", "uniqueIdentifier", NULL, 44 },
  { NULL }
};

const SshOidStruct ssh_oid_subject_directory_attribute[] =
{
  { PKI  ".9.1", "dateOfBirth", "DateOfBirth", NULL, 0 },
  { PKI  ".9.2", "placeOfBirth", "PlaceOfBirth", NULL, 0 },
  { PKI  ".9.3", "gender", "Gender", NULL, 0 },
  { PKI  ".9.4", "countryOfCitizenship", "CountryOfCitizenship", NULL, 0 },
  { PKI  ".9.5", "countryOfResidence", "CountryOfResidence", NULL, 0 },
  { "2.5.4.12", "title", "Title", NULL, 0 },
  { NULL }
};

const SshOidStruct ssh_oid_other_name[] =
{
  { MICROSOFT ".20.2.3", "UPN", "Principal Name", NULL, 0},
  { MICROSOFT ".25.1", "GUID", "Global Unique Identifier", NULL, 0},
  { NULL }
};

const SshOidPkcs5Struct ssh_oid_pkcs5_table[] =
{
  { "md2", "des-cbc",  8 },
  { "md5", "des-cbc",  8 },
  { "md2", "rc2-cbc",  5 },
  { "md5", "rc2-cbc",  5 },
  { "sha1", "des-cbc", 8 },
  { "sha1", "rc2-cbc", 5 },
};

const SshOidStruct ssh_oid_list_pkcs5[] =
{
  /* PKCS5v2 for PBE1 */
  { RSA  ".1.5.1",
    "pbeWithMD2AndDES-CBC", "pbe-md2-des",   &ssh_oid_pkcs5_table[0], 0 },
  { RSA  ".1.5.3",
    "pbeWithMD5AndDES-CBC", "pbe-md5-des",   &ssh_oid_pkcs5_table[1], 0 },
  { RSA  ".1.5.4",
    "pbeWithMD2AndRC2-CBC", "pbe-md2-rc2",   &ssh_oid_pkcs5_table[2], 0 },
  { RSA  ".1.5.6",
    "pbeWithMD5AndRC2-CBC", "pbe-md5-rc2",   &ssh_oid_pkcs5_table[3], 0 },
  { RSA  ".1.5.10",
    "pbeWithSHA1AndDES-CBC", "pbe-sha1-des", &ssh_oid_pkcs5_table[4], 0 },
  { RSA  ".1.5.11",
    "pbeWithSHA1AndRC2-CBC", "pbe-sha1-rc2", &ssh_oid_pkcs5_table[5], 0 },

  /* PKCS#5 Version 2 */
  { RSA  ".1.5.12", "pbKDF2", "pb-kdf-2", NULL, 0 },
  { RSA  ".1.5.13", "pbES2", "pb-es-2", NULL, 0 },
  { RSA  ".1.5.14", "pbMAC1", "pb-mac-1", NULL, 0 },

  { NULL }
};

const SshOidStruct ssh_oid_list_pkcs7[] =
{
  /* PKCS-7 */
  { RSA  ".1.7.1", "data",
    "PKCS 7 data content type",
    NULL, SSH_PKCS7_DATA },
  { RSA  ".1.7.2", "signedData",
    "PKCS 7 signed data content type",
    NULL, SSH_PKCS7_SIGNED_DATA },
  { RSA  ".1.7.3", "envelopedData",
    "PKCS 7 enveloped data content type",
    NULL, SSH_PKCS7_ENVELOPED_DATA },
  { RSA  ".1.7.4", "signedAndEnvelopedData",
    "PKCS 7 signed and enveloped data content type",
    NULL, SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA },
  { RSA  ".1.7.5", "digestedData",
    "PKCS 7 digested data content type",
    NULL, SSH_PKCS7_DIGESTED_DATA },
  { RSA  ".1.7.6", "encryptedData",
    "PKCS 7 encrypted data content type",
    NULL, SSH_PKCS7_ENCRYPTED_DATA },

  /* End. */
  { NULL }
};

const SshOidStruct ssh_oid_list_pkcs9[] =
{
    /* PKCS-9 */
  { RSA  ".1.9.1", "emailAddress",
    "PKCS 9 email address",
    NULL, 0  },
  { RSA  ".1.9.2", "unstructuredName",
    "PKCS 9 unstructured name",
    NULL, 1 },
  { RSA  ".1.9.3", "contentType",
    "PKCS 9 content type",
    NULL, 2 },
  { RSA  ".1.9.4", "messageDigest",
    "PKCS 9 message digest",
    NULL, 3 },
  { RSA  ".1.9.5", "signingTime",
    "PKCS 9 signature creation time",
    NULL, 4 },
  { RSA  ".1.9.6", "counterSignature",
    "PKCS 9 counter signature",
    NULL, 5 },
  { RSA  ".1.9.7", "challengePassword",
    "PKCS 9 challenge password",
    NULL, 6 },
  { RSA  ".1.9.8", "unstructuredAddress",
    "PKCS 9 unstructured address",
    NULL, 7 },
  { RSA  ".1.9.9", "extendedCertificateAttributes",
    "PKCS 9 extended certificate attributes",
    NULL, 8 },                /* If you modify this, remember to update magic
                                 numbers in the x509.c certificate request
                                 decoding routine. */
  { RSA  ".1.9.14", "extensionReq",
    "PKCS 9 extension request",
    NULL, 13 },               /* If you modify this, remember to update magic
                                 numbers in the x509.c certificate request
                                 decoding routine. */

  { NULL }
};

const SshOidStruct ssh_oid_list_cat[] =
{
  /* The Microsoft CAT extension(s) for PKCS #10. */
  { MICROSOFT ".2.1.14",
    "catExtension", "Microsoft Cat Extension",
    NULL, 0 },                  /* If you modify this, remember to update magic
                                 numbers in the x509.c certificate request
                                 decoding routine. */

  { NULL }
};

const SshOidStruct ssh_oid_list_hold_inst_code[] =
{
  /* Some extra oids. */
  { "1.2.840.10040.2",
    "holdInstruction", "hold instruction",
    NULL, 0 },
  { "1.2.840.10040.2.1",
    "holdInstructionNone", "hold instruction none",
    NULL, 0 },
  { "1.2.840.10040.2.2",
    "holdInstructionCallIssuer", "hold instruction call issuer",
    NULL, 0 },
  { "1.2.840.10040.2.3",
    "holdInstructionReject", "hold instruction reject",
    NULL, 0 },

  { NULL }
};

const SshOidStruct ssh_oid_list_policy[] =
{
  /* Policy information. */
  { PKI  ".2",
    "pkix-id-qt", "policy qualifier type",
    NULL, SSH_X509_POLICY_QT },
  { PKI  ".2.1",
    "pkix-id-qt-cps", "policy qualifier id",
    NULL, SSH_X509_POLICY_QT_INTERNET_PQ },
  { PKI  ".2.2",
    "pkix-id-qt-unotice", "user notice",
    NULL, SSH_X509_POLICY_QT_UNOTICE },
  { NULL }
};

const SshOidStruct ssh_oid_list_hash[] =
{
  { OIW  ".2.26", "Sha-1", "sha1", NULL, SSH_X509_HASHALG_SHA1 },
  { RSA  ".2.5", "MD-5", "md5", NULL, SSH_X509_HASHALG_MD5 },
  { TTHASH ".1", "RipeMD-160", "ripemd160", NULL, SSH_X509_HASHALG_RIPE160 },
  { TTHASH ".2", "RipeMD-128", "ripemd128", NULL, SSH_X509_HASHALG_RIPE128 },
  { TTHASH ".3", "RipeMD-256", "ripemd256", NULL, SSH_X509_HASHALG_RIPE256 },
  { RSA  ".2.2", "MD-2", "md2", NULL, SSH_X509_HASHALG_MD2 },
  { NIST ".2.1", "Sha-256", "sha256", NULL, SSH_X509_HASHALG_SHA256 },
  { NIST ".2.2", "Sha-384", "sha384", NULL, SSH_X509_HASHALG_SHA384 },
  { NIST ".2.3", "Sha-512", "sha512", NULL, SSH_X509_HASHALG_SHA512 },
  { NIST ".2.4", "Sha-224", "sha224", NULL, SSH_X509_HASHALG_SHA224 },
  { NULL }
};

const SshOidStruct ssh_oid_list_mac[] =
{
  { "1.3.6.1.5.5.8.1.2",
    "HMac-Sha-1", "hmac-sha1", NULL, SSH_X509_MACALG_SHA1 },
  { RSA ".2.8",
    "HMac-Sha-224", "hmac-sha224", NULL, SSH_X509_MACALG_SHA224 },
  { RSA ".2.9",
    "HMac-Sha-256", "hmac-sha256", NULL, SSH_X509_MACALG_SHA256 },
  { RSA ".2.10",
    "HMac-Sha-384", "hmac-sha384", NULL, SSH_X509_MACALG_SHA384 },
  { RSA ".2.11",
    "HMac-Sha-512", "hmac-sha512", NULL, SSH_X509_MACALG_SHA512 },
  { NULL }
};

const SshOidStruct ssh_oid_list_cipher[] =
{
  /* These are RSADSI oids.
     Remark. Most of these are not supported by our libraries. */
  { RSA  ".3.2",   "rc2CBC",       "rc2-cbc",      NULL, 0 },
  { RSA  ".3.3",   "rc2ECB",       "rc2-ecb",      NULL, 0 },
  { RSA  ".3.4",   "rc4",          "arcfour",      NULL, 0 },
  { RSA  ".3.5",   "rc4WithMAC",   "rc4-mac",      NULL, 0 },
  { RSA  ".3.6",   "DESX-CBC",     "desx-cbc",     NULL, 0 },
  { RSA  ".3.7",   "DES-EDE3-CBC", "3des-cbc",     NULL, 0 },
  { RSA  ".3.7",   "DES-EDE3-CBC", "3des",         NULL, 0 },
  { RSA  ".3.8",   "RC5CBC",       "rc5-cbc",      NULL, 0 },
  { RSA  ".3.9",   "RC5CBCPad",    "rc5-cbc-pad",  NULL, 0 },
  { RSA  ".3.10",  "CDMFCBCPad",   "cdmf-cbc-pad", NULL, 0 },

  /* Standard DES. */
  { OIW  ".2.7",   "DES-CBC",      "des-cbc",      NULL, 0 },
  { OIW  ".2.7",   "DES",          "des",          NULL, 0 },

  /* AES per NIST http://csrc.nist.gov/csor/aes1.asn date 21.2.2001 */
  { NIST  ".1.1",  "aes-128-ECB",  "aes128-ecb",   NULL, 128 },
  { NIST  ".1.2",  "aes-128-CBC",  "aes128-cbc",   NULL, 128 },
  { NIST  ".1.3",  "aes-128-OFB",  "aes128-ofb",   NULL, 128 },
  { NIST  ".1.4",  "aes-128-CFB",  "aes128-cfb",   NULL, 128 },
  { NIST  ".1.21", "aes-192-ECB",  "aes192-ecb",   NULL, 128 },
  { NIST  ".1.22", "aes-192-CBC",  "aes192-cbc",   NULL, 192 },
  { NIST  ".1.23", "aes-192-OFB",  "aes192-ofb",   NULL, 192 },
  { NIST  ".1.24", "aes-192-CFB",  "aes192-cfb",   NULL, 192 },
  { NIST  ".1.41", "aes-256-ECB",  "aes256-ecb",   NULL, 256 },
  { NIST  ".1.42", "aes-256-CBC",  "aes256-cbc",   NULL, 256 },
  { NIST  ".1.43", "aes-256-OFB",  "aes256-ofb",   NULL, 256 },
  { NIST  ".1.44", "aes-256-CFB",  "aes256-cfb",   NULL, 256 },
  { NULL }
};

const SshOidPkcs5Struct ssh_oid_pkcs12_table[] =
{
  { "sha1", "arcfour",  16 },
  { "sha1", "arcfour",   5 },
  { "sha1", "3des-cbc", 24 },
  { "sha1", "3des-cbc", 16 },
  { "sha1", "rc2-cbc",  16 },
  { "sha1", "rc2-cbc",   5 },
  { NULL }
};

const SshOidStruct ssh_oid_list_pkcs12[] =
{
  { RSA  ".1.12.1.1",
    "pbeWithSHAAnd128BitRC4", "pbe-sha-rc4",
    &ssh_oid_pkcs12_table[0], 0 },
  { RSA  ".1.12.1.2",
    "pbeWithSHAAnd40BitRC4", "pbe-sha-rc4",
    &ssh_oid_pkcs12_table[1], 0 },
  { RSA  ".1.12.1.3",
    "pbeWithSHAAnd3-KeyTripleDES-CBC", "pbe-sha-3des",
    &ssh_oid_pkcs12_table[2], 0 },
  { RSA  ".1.12.1.4",
    "pbeWithSHAAnd2-KeyTripleDES-CBC", "pbe-sha-3des",
    &ssh_oid_pkcs12_table[3], 0 },
  { RSA  ".1.12.1.5",
    "pbeWithSHAAnd128BitRC2-CBC", "pbe-sha-rc2",
    &ssh_oid_pkcs12_table[4], 0 },
  { RSA  ".1.12.1.6",
    "pbeWithSHAAnd40BitRC2-CBC", "pbe-sha-rc2",
    &ssh_oid_pkcs12_table[5], 0 },
  { NULL }
};

const SshOidStruct ssh_oid_list_ecp_fixed_curve[] =
{
  /* Define the fixed elliptic curves */
  { ELLIPTICCURVE ".8",
    "secp160r1", "secp160r1",
    NULL, 20 },
  { "1.2.840.10045.3.1.1",
    "secp192r1", "secp192r1",
    NULL, 24 },
  { ELLIPTICCURVE ".33",
    "secp224r1", "secp224r1",
    NULL, 28 },
  { "1.2.840.10045.3.1.7",
    "prime256v1", "secp256r1, NIST P-256",
    NULL, 32 },
  { ELLIPTICCURVE ".34",
    "secp384r1", "NIST P-384",
    NULL, 48 },
  { ELLIPTICCURVE ".35",
    "secp521r1", "NIST P-521",
    NULL, 66 },
  { BRAINPOOLCURVE ".1",  "brainpoolP160r1", "Brainpool P160 r1", NULL, 20 },
  { BRAINPOOLCURVE ".2",  "brainpoolP160t1", "Brainpool P160 t1", NULL, 20 },
  { BRAINPOOLCURVE ".3",  "brainpoolP192r1", "Brainpool P192 r1", NULL, 24 },
  { BRAINPOOLCURVE ".4",  "brainpoolP192r1", "Brainpool P192 t1", NULL, 24 },
  { BRAINPOOLCURVE ".5",  "brainpoolP224r1", "Brainpool P224 r1", NULL, 28 },
  { BRAINPOOLCURVE ".6",  "brainpoolP224t1", "Brainpool P224 t1", NULL, 28 },
  { BRAINPOOLCURVE ".7",  "brainpoolP256r1", "Brainpool P256 r1", NULL, 32 },
  { BRAINPOOLCURVE ".8",  "brainpoolP256t1", "Brainpool P256 t1", NULL, 32 },
  { BRAINPOOLCURVE ".9",  "brainpoolP320r1", "Brainpool P320 r1", NULL, 40 },
  { BRAINPOOLCURVE ".10", "brainpoolP320t1", "Brainpool P320 t1", NULL, 40 },
  { BRAINPOOLCURVE ".11", "brainpoolP384r1", "Brainpool P384 r1", NULL, 48 },
  { BRAINPOOLCURVE ".12", "brainpoolP384t1", "Brainpool P384 t1", NULL, 48 },
  { BRAINPOOLCURVE ".13", "brainpoolP512r1", "Brainpool P512 r1", NULL, 64 },
  { BRAINPOOLCURVE ".14", "brainpoolP512t1", "Brainpool P512 t1", NULL, 64 },
  { NULL }
};


const SshOidStruct ssh_oid_list_ec_field[] =
{
  { "1.2.840.10045.1.1",
    "x9.62primefield", "x9.62primefield",
    NULL, 0 },
#if 0
  { "1.2.840.10045.1.2",
    "x9.62characteristicstwofield", "x9.62characteristicstwofield",
    NULL, 0 },
#endif
  { NULL }
};

/* Note that this table must be in the order specified in the oid.h
   (same order that SSH_OID_* defines). */
const SshOidListingStruct ssh_oid_listing_by_type[] =
{
  { SSH_OID_PK,            ssh_oid_list_pk },
  { SSH_OID_SIG,           ssh_oid_list_sig },
  { SSH_OID_DN,            ssh_oid_list_dn },
  { SSH_OID_EXT,           ssh_oid_list_ext },
  { SSH_OID_CRL_EXT,       ssh_oid_list_crl_ext },
  { SSH_OID_CRL_ENTRY_EXT, ssh_oid_list_crl_entry_ext },
  { SSH_OID_PKCS9,         ssh_oid_list_pkcs9 },
  { SSH_OID_CAT,           ssh_oid_list_cat },
  { SSH_OID_HOLD_INST,     ssh_oid_list_hold_inst_code },
  { SSH_OID_POLICY,        ssh_oid_list_policy },
  { SSH_OID_PKCS7,         ssh_oid_list_pkcs7 },
  { SSH_OID_HASH,          ssh_oid_list_hash },
  { SSH_OID_MAC,           ssh_oid_list_mac },
  { SSH_OID_CIPHER,        ssh_oid_list_cipher },
  { SSH_OID_EXT_KEY_USAGE, ssh_oid_list_ext_key_usage },
  { SSH_OID_CONTROLS,      ssh_oid_list_pkix_crmf },
  { SSH_OID_CMP,           ssh_oid_list_pkix_cmp },
  { SSH_OID_PKCS5,         ssh_oid_list_pkcs5 },
  { SSH_OID_PKCS12,        ssh_oid_list_pkcs12 },
  { SSH_OID_DIRECTORYATTR, ssh_oid_subject_directory_attribute },
  { SSH_OID_OTHERNAME,     ssh_oid_other_name },
  { SSH_OID_UCL,           ssh_oid_ucl_directory_pilot },
  { SSH_OID_QCSTATEMENT,   ssh_oid_list_qcstatement },
  { SSH_OID_ECP_CURVE,     ssh_oid_list_ecp_fixed_curve } ,
  { SSH_OID_CURVE_FIELD,   ssh_oid_list_ec_field },
  /* End. */
  { SSH_OID_NONE,          NULL }
};

const SshOidStruct *ssh_oid_find_by_oid(const char *oid)
{
  unsigned int i, j;
  const SshOidStruct *list;

  for (i = 0; ssh_oid_listing_by_type[i].type != SSH_OID_NONE; i++)
    {
      list = ssh_oid_listing_by_type[i].oid_list;
      if (list == NULL)
        continue;
      /* Loop through all the Oids until a match has been found. */
      for (j = 0; list[j].oid != NULL; j++)
        if (strcmp(list[j].oid, oid) == 0)
          return &list[j];
    }
  return NULL;
}

/* This is just to ensure that the given format for the Oids before
   allows inserting multiple same oids in different Oid
   categories. This of course is not exactly necessary, because the
   extra field allows inserting as much information as
   needed. However, this might be useful. If not it will be removed
   later. */
const SshOidStruct *ssh_oid_find_by_oid_of_type(const unsigned char *oid,
                                                int type)
{
  unsigned int i;
  const SshOidStruct *list;

  if (oid == NULL || type < 0 || type >= SSH_OID_NONE)
    return NULL;

  list = ssh_oid_listing_by_type[type].oid_list;
  if (list == NULL)
    return NULL;

  /* Loop through all the Oids until a match has been found. */
  for (i = 0; list[i].oid != NULL; i++)
    if (ssh_usstrcmp(oid, list[i].oid) == 0)
      return &list[i];
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_std_name(const char *name)
{
  unsigned int i, j;
  const SshOidStruct *list;
  for (i = 0; ssh_oid_listing_by_type[i].type != SSH_OID_NONE; i++)
    {
      list = ssh_oid_listing_by_type[i].oid_list;
      if (list == NULL)
        continue;
      for (j = 0; list[j].oid != NULL; j++)
        if (strcasecmp(name, list[j].std_name) == 0)
          return &list[j];
    }
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_std_name_of_type(const char *name,
                                                     int type)
{
  unsigned int i;
  const SshOidStruct *list;

  if (type < 0 || type >= SSH_OID_NONE)
    return NULL;

  list = ssh_oid_listing_by_type[type].oid_list;
  if (list == NULL)
    return NULL;

  for (i = 0; list[i].oid != NULL; i++)
    if (strcasecmp(name, list[i].std_name) == 0)
      return &list[i];
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_alt_name(const char *name)
{
  unsigned int i, j;
  const SshOidStruct *list;
  for (i = 0; ssh_oid_listing_by_type[i].type != SSH_OID_NONE; i++)
    {
      list = ssh_oid_listing_by_type[i].oid_list;
      if (list == NULL)
        continue;
      for (j = 0; list[j].oid != NULL; j++)
        if (strcasecmp(name, list[j].name) == 0)
          return &list[j];
    }
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_alt_name_of_type(const char *name,
                                                     int type)
{
  unsigned int i;
  const SshOidStruct *list;

  if (type < 0 || type >= SSH_OID_NONE)
    return NULL;

  list = ssh_oid_listing_by_type[type].oid_list;
  if (list == NULL)
    return NULL;

  for (i = 0; list[i].oid; i++)
    if (strcasecmp(name, list[i].name) == 0)
      return &list[i];
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_ext_name(const char *name)
{
  unsigned int i, j;
  const SshOidStruct *list;
  for (i = 0; ssh_oid_listing_by_type[i].type != SSH_OID_NONE; i++)
    switch (ssh_oid_listing_by_type[i].type)
      {
      case SSH_OID_SIG:
        list = ssh_oid_listing_by_type[i].oid_list;
        if (list == NULL)
          break;
        for (j = 0; list[j].oid; j++)
          if (strcasecmp((const char *)list[j].extra, name) == 0)
            return &list[j];
        break;
      default:
        break;
      }
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_ext_name_of_type(const char *name,
                                                     int type)
{
  unsigned int i;
  const SshOidStruct *list;

  if (type < 0 || type >= SSH_OID_NONE)
    return NULL;

  list = ssh_oid_listing_by_type[type].oid_list;
  if (list == NULL)
    return NULL;

  switch (type)
    {
    case SSH_OID_SIG:
      for (i = 0; list[i].oid; i++)
        if (strcasecmp((const char *)list[i].extra, name) == 0)
          return &list[i];
      break;
    default:
      break;
    }
  return NULL;
}

const SshOidStruct *ssh_oid_find_by_ext_ident_of_type(int ident, int type)
{
  unsigned int i;
  const SshOidStruct *list;

  if (type < 0
      || type >= SSH_OID_NONE
      || (list = ssh_oid_listing_by_type[type].oid_list) == NULL)
    return NULL;

  for (i = 0; list[i].oid; i++)
    if (list[i].extra_int == ident)
      return &list[i];
  return NULL;
}

/* Checks if oid is syntaxically valid. Returns TRUE if valid, FALSE
   otherwise. */
Boolean ssh_oid_check_str(const unsigned char *oid_str)
{
  size_t i, len;

  /* Sanity check. */
  if (oid_str == NULL)
    return FALSE;

  /* Check that the oid contains only numbers and dots and the first
     and the last char must not be a dot. */
  len = ssh_ustrlen(oid_str);

  if (len == 0)
    return FALSE;

  /* ... valid chars. */
  for (i = 0; i < len; i ++)
    if (!(isdigit(oid_str[i]) || oid_str[i] == '.'))
      return FALSE;

  /* .. first char. */
  if (oid_str[0] == '.')
    return FALSE;

  /* ... last char */
  if (oid_str[len - 1] == '.')
    return FALSE;

  /* OID is valid. */
  return TRUE;
}

/* oid.c */
#endif /* SSHDIST_CERT */
