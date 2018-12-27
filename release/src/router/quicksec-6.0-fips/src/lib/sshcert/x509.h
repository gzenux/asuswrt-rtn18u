/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple interface into X.509 certificates. This interface allows to
   encode and verify X.509 certificates.
   Further, this interface allows handling of CRL's.
*/

#ifndef X509_H
#define X509_H


#include "sshcrypt.h"
#include "sshstr.h"
#include "sshpswbmac.h"

/* Configuration handle is needed on the X.509 includes. */
typedef struct SshX509ConfigRec *SshX509Config, SshX509ConfigStruct;

#include "dn.h"

typedef struct SshX509CertificateRec *SshX509Certificate;
typedef struct SshX509CertificateRec  SshX509CertificateStruct;

typedef struct SshX509CrlRec         *SshX509Crl;
typedef struct SshX509CrlRec          SshX509CrlStruct;

typedef enum
{
  /* A genuine certificate. */
  SSH_X509_PKIX_CERT = 1,
  /* A PKIX CRMF request. */
  SSH_X509_PKIX_CRMF = 2,
  /* A PKCS-10 request. */
  SSH_X509_PKCS_10   = 3,

  /* Maximum number of certificate types. */
  SSH_X509_CERT_TYPE_MAX = 10
} SshX509CertType;

typedef enum
{
  SSH_X509_OK       = 0,  /* This indicates that everything is in order. */
  SSH_X509_FAILURE  = 1,  /* Every occurence of a problem causes this. */

  /* Private key operations failed. */
  SSH_X509_FAILED_PRIVATE_KEY_OPS,
  /* Public key operations failed. */
  SSH_X509_FAILED_PUBLIC_KEY_OPS,

  /* Some general ASN.1 error messages. */
  SSH_X509_FAILED_ASN1_DECODE,
  SSH_X509_FAILED_ASN1_ENCODE,

  /* X.509 certificate and CRL special errors. */

  /* Version number checking and handling errors. */
  SSH_X509_FAILED_VERSION_CHECK,
  SSH_X509_FAILED_VERSION_ENCODE,

  /* Distinguished name errors. */
  SSH_X509_FAILED_DN_NAME_CHECK,
  SSH_X509_FAILED_DN_NAME_ENCODE,

  /* Errors occurring during unique identifier checks. */
  SSH_X509_FAILED_UNIQUE_ID_ENCODE,

  /* Signature algorithm and related errors. */
  SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK,
  SSH_X509_FAILED_SIGNATURE_ALGORITHM_ENCODE,
  SSH_X509_FAILED_SIGNATURE_CHECK,
  SSH_X509_FAILED_SIGNATURE_OPS,

  /* Time and validity handling errors. */
  SSH_X509_FAILED_VALIDITY_ENCODE,
  SSH_X509_FAILED_TIME_DECODE,
  SSH_X509_FAILED_TIME_ENCODE,

  /* Detected duplicate extension. */
  SSH_X509_FAILED_DUPLICATE_EXTENSION,
  /* Detected invalid extension. */
  SSH_X509_FAILED_INVALID_EXTENSION,

  /* Failed in encoding extension. */
  SSH_X509_FAILED_EXTENSION_ENCODE,

  /* Errors that happen due to unknown ASN.1 and related. */
  SSH_X509_FAILED_UNKNOWN_STYLE,
  SSH_X509_FAILED_UNKNOWN_CRITICAL_EXTENSION,
  SSH_X509_FAILED_UNKNOWN_VALUE,

  /* Passphrase needed for operation */
  SSH_X509_PASSPHRASE_NEEDED,


  SSH_X509_NO_MEMORY /* Out of Memory */


} SshX509Status;

typedef enum
{
  SSH_X509_VERSION_UNKNOWN,
  SSH_X509_VERSION_1,
  SSH_X509_VERSION_2,
  SSH_X509_VERSION_3
} SshX509Version;

/****************************************************************************
 * Encoder and decoder configuration issues. Both global and per certificate.
 * The global value is inherited by certificates.
 */

/* Encoding functions need to return a status of this type, for the
   calling routine to know whether it needs free the context and/or handle
   errors or not in the asynchronous case. */
typedef enum
{
  SSH_X509_ASYNC_CALL_COMPLETED,
  SSH_X509_ASYNC_CALL_PENDING,
  SSH_X509_ASYNC_CALL_ERROR
} SshX509AsyncCallStatus;

/* Prototype for certificate encoding implementation function */
typedef SshX509AsyncCallStatus (*SshX509CertEncoder)(void *async_context);

/* Prototype for certificate decoding implementation function */
typedef SshX509Status
(*SshX509CertDecoder)(SshAsn1Context asn1, SshAsn1Node root,
                      SshX509Certificate c);

struct SshX509ConfigRec
{
  /* Options for encoding and decoding strings. */
  struct {
    /* Decoder options. */
    unsigned int treat_printable_as_latin1:1;           /* On */
    unsigned int treat_t61_as_latin1:1;                 /* On */

    /* Encoder options. */
    unsigned int enable_visible_string:1;               /* Off */
    unsigned int enable_bmp_string:1;                   /* Off */

    /* Both encoding and decoding. This is VRK pilot card compatibility
       and should not normally be enabled. Off by default. */
    unsigned int enable_printable_within_bitstring:1;
  } cs;

  /* Options for encoding certificates. */
  struct {
    unsigned int allow_ee_basic_constraints:1;        /* Off */
  } ec;

  /* Encoders and decoders for certificate types. */
  struct {
    SshX509CertType    type;
    SshX509CertDecoder decoder;
    SshX509CertEncoder encoder;
  } encoders[SSH_X509_CERT_TYPE_MAX];
};

/* Returns pointer to current library configuration. Note! this is not
   a copy, thus do not free the pointer returned. */
SshX509Config ssh_x509_get_configuration(void);


/* Few of the many ways to encode X.509 v3 extensions to the PKCS #10
   certificate requests. This library supports encoding of all of these,
   but decode only some. Usual choice is the PKCS9 REQ. */
typedef enum
{
  SSH_X509_REQ_EXTENSION_PKCS9_CERT_ATTR,
  SSH_X509_REQ_EXTENSION_PKCS9_REQ,
  SSH_X509_REQ_EXTENSION_CAT
} SshX509ReqExtensionStyle;

/*--------------------------------------------------------------------*/
/* Public algorithms                                                  */
/*--------------------------------------------------------------------*/
typedef enum
{
  SSH_X509_PKALG_UNKNOWN = 0,
  SSH_X509_PKALG_RSA     = 1,
  SSH_X509_PKALG_DSA     = 2,
  SSH_X509_PKALG_ELGAMAL = 3,
  SSH_X509_PKALG_DH      = 4,
  SSH_X509_PKALG_ECDSA   = 5,
  SSH_X509_PKALG_PSS     = 6,
  SSH_X509_PKALG_OAEP    = 7
} SshX509PkAlgorithm;

/*--------------------------------------------------------------------*/
/* Public key algorithm parameters                                    */
/*--------------------------------------------------------------------*/
struct SshX509PkParamsRec
{
  union {



    struct {
      /* Add ecParameters here */
      char *curveoid;
    } ecdsa;
    /* RSA-PSS */
    struct {
      char *hashoid;
      char *mgfoid;
      SshUInt16 salt_len;
      SshUInt16 trailer_len;
    } pss;



    struct {
      char *hashoid;
      char *mgfoid;
      unsigned char *psourcefunc;
    } oaep;
  } u;
};
typedef struct SshX509PkParamsRec SshX509PkParamsStruct;
typedef struct SshX509PkParamsRec *SshX509PkParams;


typedef enum
{
  SSH_X509_MACALG_SHA1    = 0,
  SSH_X509_MACALG_MD5     = 1,
  SSH_X509_MACALG_DESMAC  = 2,
  SSH_X509_MACALG_3DESMAC = 3,
  SSH_X509_MACALG_SHA224  = 4,
  SSH_X509_MACALG_SHA256  = 5,
  SSH_X509_MACALG_SHA384  = 6,
  SSH_X509_MACALG_SHA512  = 7,
  SSH_X509_MACALG_UNKNOWN
} SshX509MacAlgorithm;

typedef enum
{
  SSH_X509_HASHALG_SHA1    = 0,
  SSH_X509_HASHALG_MD5     = 1,
  SSH_X509_HASHALG_MD2     = 2,
  SSH_X509_HASHALG_RIPE128 = 3,
  SSH_X509_HASHALG_RIPE160 = 4,
  SSH_X509_HASHALG_RIPE256 = 5,
  SSH_X509_HASHALG_SHA224  = 6,
  SSH_X509_HASHALG_SHA256  = 7,
  SSH_X509_HASHALG_SHA384  = 8,
  SSH_X509_HASHALG_SHA512  = 9,
  SSH_X509_HASHALG_UNKNOWN
} SshX509HashAlgorithm;

typedef enum
{
  SSH_X509_CIPHERALG_UNKNOWN = 0
} SshX509CipherAlgorithm;

/* Definition for a structure containing algorithm definitions. */
struct SshX509PkAlgorithmDefRec
{
  /* SSH naming. */
  char *name;
  char *sign;
  char *dh;
  /* Generally known naming. */
  char *known_name;
  char *sign_name;
  char *dh_name;
  /* Algorithm type. */
  SshX509PkAlgorithm algorithm;
};
typedef struct SshX509PkAlgorithmDefRec *SshX509PkAlgorithmDef;
typedef struct SshX509PkAlgorithmDefRec  SshX509PkAlgorithmDefStruct;

typedef unsigned int SshX509UsageFlags;
/* Define here usage bits. */
#define SSH_X509_UF_DIGITAL_SIGNATURE 128   /* 0 */
#define SSH_X509_UF_NON_REPUDIATION    64   /* 1 */
#define SSH_X509_UF_KEY_ENCIPHERMENT   32   /* 2 */
#define SSH_X509_UF_DATA_ENCIPHERMENT  16   /* 3 */
#define SSH_X509_UF_KEY_AGREEMENT       8   /* 4 */
#define SSH_X509_UF_KEY_CERT_SIGN       4   /* 5 */
#define SSH_X509_UF_CRL_SIGN            2   /* 6 */
#define SSH_X509_UF_ENCIPHER_ONLY       1   /* 7 */
#define SSH_X509_UF_DECIPHER_ONLY   32768   /* 8 */
/* Continue from 65536 decreasing by multiple of 2. */
#define SSH_X509_UF_BITS 9

typedef unsigned int SshX509ReasonFlags;
#define SSH_X509_RF_UNSPECIFIED            128   /* 0 */
#define SSH_X509_RF_KEY_COMPROMISE          64   /* 1 */
#define SSH_X509_RF_CA_COMPROMISE           32   /* 2 */
#define SSH_X509_RF_AFFILIATION_CHANGED     16   /* 3 */
#define SSH_X509_RF_SUPERSEDED               8   /* 4 */
#define SSH_X509_RF_CESSATION_OF_OPERATION   4   /* 5 */
#define SSH_X509_RF_CERTIFICATE_HOLD         2   /* 6 */
#define SSH_X509_RF_PRIVILEGE_WITHDRAWN      1   /* 7 */
/* Continue from 65536 decreasing by multiple of 2.   */
#define SSH_X509_RF_AA_COMPROMIZE        32768   /* 8 */

#define SSH_X509_RF_BITS                     9

typedef unsigned int SshX509CRLReasonCode;
#define SSH_X509_CRLF_UNSPECIFIED             0
#define SSH_X509_CRLF_KEY_COMPROMISE          1
#define SSH_X509_CRLF_CA_COMPROMISE           2
#define SSH_X509_CRLF_AFFILIATION_CHANGED     3
#define SSH_X509_CRLF_SUPERSEDED              4
#define SSH_X509_CRLF_CESSATION_OF_OPERATION  5
#define SSH_X509_CRLF_CERTIFICATE_HOLD        6
#define SSH_X509_CRLF_REMOVE_FROM_CRL         8
#define SSH_X509_CRLF_PRIVILEGE_WITHDRAWN     9
#define SSH_X509_CRLF_AACOMPROMISE           10

typedef unsigned int SshX509DistPointSyntax;
#define SSH_X509_DPS_DISTRIBUTION_POINT              1   /* 0 */
#define SSH_X509_DPS_ONLY_CONTAINS_USER_CERTS        2   /* 1 */
#define SSH_X509_DPS_ONLY_CONTAINS_CA_CERTS          4   /* 2 */
#define SSH_X509_DPS_ONLY_SOME_REASONS               8   /* 3 */
#define SSH_X509_DPS_INDIRECT_CRL                   16   /* 4 */

/* Certificate extensions. */
typedef enum {
  SSH_X509_EXT_AUTH_KEY_ID = 0,    /* authority key identifier */
  SSH_X509_EXT_SUBJECT_KEY_ID,     /* subject key identifier */
  SSH_X509_EXT_KEY_USAGE,          /* key usage */
  SSH_X509_EXT_PRV_KEY_UP,         /* private key usage period */
  SSH_X509_EXT_CERT_POLICIES,      /* certificate policies */
  SSH_X509_EXT_POLICY_MAPPINGS,    /* policy mappings */
  SSH_X509_EXT_SUBJECT_ALT_NAME,   /* subject alternative name */
  SSH_X509_EXT_ISSUER_ALT_NAME,    /* issuer alternative name */
  SSH_X509_EXT_SUBJECT_DIR_ATTR,   /* subject directory attributes */
  SSH_X509_EXT_BASIC_CNST,         /* basic constraints */
  SSH_X509_EXT_NAME_CNST,          /* name constraints */
  SSH_X509_EXT_POLICY_CNST,        /* policy constraints */
  SSH_X509_EXT_PRV_INTERNET_EXT,   /* private internet extensions */
  SSH_X509_EXT_AUTH_INFO_ACCESS,   /* authority information access */
  SSH_X509_EXT_CRL_DIST_POINTS,    /* CRL distribution points */
  SSH_X509_EXT_EXT_KEY_USAGE,      /* extended key usage */
  SSH_X509_EXT_NETSCAPE_COMMENT,   /* comment to be shown to user */
  SSH_X509_EXT_CERT_TEMPLATE_NAME, /* certificate template name; MS ext */
  SSH_X509_EXT_QCSTATEMENTS,       /* qualified certificate statements */
  SSH_X509_EXT_SUBJECT_INFO_ACCESS,/* subject information access */
  SSH_X509_EXT_FRESHEST_CRL,       /* access location for the fresh CRL */
  SSH_X509_EXT_INHIBIT_ANY_POLICY, /* inhibit any indicator */
  SSH_X509_EXT_UNKNOWN,            /* unknown non-critical extension */
  SSH_X509_EXT_MAX
} SshX509CertExtType;

/* CRL extensions. */
typedef enum {
  SSH_X509_CRL_EXT_CRL_NUMBER = 0,     /* CRL number */
  SSH_X509_CRL_EXT_ISSUING_DIST_POINT, /* issuing distribution point */
  SSH_X509_CRL_EXT_DELTA_CRL_IND,      /* delta CRL indicator */
  SSH_X509_CRL_EXT_AUTH_KEY_ID,        /* authority key id */
  SSH_X509_CRL_EXT_ISSUER_ALT_NAME,    /* issuer alternative name */
  SSH_X509_CRL_EXT_MAX
} SshX509CrlExtType;

/* Revoked entry extensions. */
typedef enum {
  SSH_X509_CRL_ENTRY_EXT_REASON_CODE = 0,    /* CRL reason code. */
  SSH_X509_CRL_ENTRY_EXT_HOLD_INST_CODE,     /* Hold instruction code. */
  SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE,    /* Invalidity date */
  SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER,        /* Certificate issuer */
  SSH_X509_CRL_ENTRY_EXT_MAX
} SshX509CrlEntryExtType;


typedef enum
{
  SSH_X509_NAME_DISTINGUISHED_NAME = 0, /* distinguished name */
  SSH_X509_NAME_UNIQUE_ID          = 1, /* unique identifier */
  SSH_X509_NAME_RFC822             = 2, /* rfc822 name */
  SSH_X509_NAME_DNS                = 3, /* dns name */
  SSH_X509_NAME_IP                 = 4, /* ip address */
  SSH_X509_NAME_DN                 = 5, /* directory name */
  SSH_X509_NAME_X400               = 6, /* x400 name */
  SSH_X509_NAME_EDI                = 7, /* EDI party name */
  SSH_X509_NAME_URI                = 8, /* uniform resource identifier */
  SSH_X509_NAME_RID                = 9, /* registered identifier */
  SSH_X509_NAME_PRINCIPAL_NAME     = 10,/* OtherName: Principal Name.
                                         * Microsoftian invention. */
  SSH_X509_NAME_GUID               = 11,/* OtherName: Global Unique ID.
                                         * Microsoftian invention. */
  SSH_X509_NAME_OTHER              = 12 /* Some other OtherName */
} SshX509NameType;

/* Hold instruction codes. */
#define SSH_X509_HOLD_INST_CODE_NONE       "1.2.840.10040.2.1"
#define SSH_X509_HOLD_INST_CODE_CALLISSUER "1.2.840.10040.2.2"
#define SSH_X509_HOLD_INST_CODE_REJECT     "1.2.840.10040.2.3"

/***********************************************************************
 * Type for presenting X.509 names
 */
struct SshX509NameRec
{
  struct SshX509NameRec *next;
  SshX509NameType type;
  Boolean         dirty;

  /* The subject DN name opened. */
  SshDN           dn;
  SshStr          name;

  /* Decoded version of the name, if cannot be represented in a string.
     Data length is in bits. Data can be of any supported type. */
  void  *data;
  size_t data_len;

  /* If possible or suitable then this points to the ASN.1 BER
     of the name. */
  const unsigned char *ber, *canon_der;
  size_t         ber_len, canon_der_len;
};
typedef struct SshX509NameRec *SshX509Name;
typedef struct SshX509NameRec  SshX509NameStruct;

/* The types of attributes that are identified. */

typedef enum
{
  /* The attribute is unknown. */
  SSH_X509_ATTR_UNKNOWN = 0,
  SSH_X509_PKCS9_ATTR_UNSTRUCTURED_NAME,    /* PKCS#9 unstructured Name */
  SSH_X509_PKCS9_ATTR_UNSTRUCTURED_ADDRESS, /* PKCS#9 unstructured Address */
  SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD,   /* PKCS#9 challenge password */
  SSH_X509_ATTR_MAX
} SshX509AttributeType;

/***********************************************************************
 * The general framework for the attributes. It is a list of tuples
 * (oid . value)
 */
struct SshX509AttributeRec
{
  struct SshX509AttributeRec *next;

  SshX509AttributeType type;

  /* The identifier and the payload of the attribute. */
  char *oid;

  /* Depending on the type, the data/len will contain type specific
     information, or pointer to BER and BER-length if attribute is of
     type UNKNOWN. */
  unsigned char *data;
  size_t len;
};
typedef struct SshX509AttributeRec *SshX509Attribute;
typedef struct SshX509AttributeRec  SshX509AttributeStruct;

/***********************************************************************
 * Signature algorithm and value
 */


struct SshX509SignatureRec
{
  /* The signature algorithm and its parameters. */
  SshX509PkAlgorithm pk_type;
  SshX509PkParams    pk_params;
  const char        *pk_algorithm;

  /* This contains the signature. */
  unsigned char *signature;
  size_t         signature_len;
};
typedef struct SshX509SignatureRec *SshX509Signature;
typedef struct SshX509SignatureRec  SshX509SignatureStruct;

/***********************************************************************
 * Public key and parameters.
 */
struct SshX509PublicKeyRec
{
  /* The algorithm type for the X.509 library. */
  SshX509PkAlgorithm pk_type;

  /* Key usage masks. */
  SshX509UsageFlags subject_key_usage_mask;
  SshX509UsageFlags ca_key_usage_mask;

  /* The SSH context for the public key. */
  SshPublicKey  public_key;
  SshPkGroup    public_group;
};
typedef struct SshX509PublicKeyRec *SshX509PublicKey;
typedef struct SshX509PublicKeyRec  SshX509PublicKeyStruct;

/***********************************************************************
 * Message authentication code and value
 */
struct SshX509MacValueRec
{
  SshPSWBMac     pswbmac;

  /* The Mac result value. */
  unsigned char *value;
  size_t         value_len;
};
typedef struct SshX509MacValueRec *SshX509MacValue;
typedef struct SshX509MacValueRec  SshX509MacValueStruct;

/***********************************************************************
 * The proof-of-possession.
 */
struct SshX509PopRec
{
  /* Message that is proved. */
  unsigned char *proved_message;
  size_t         proved_message_len;

  /* RA based POP. Either RA has generated the key, or verified
     posession of it by some other means. */
  Boolean        ra_verified;

  /* If nor the private key or signature is present as a pop of it,
     this will indicate if the requestor would like to do implicit
     (encrypt-cert) pop, or a challenge-response based protocol (not
     supported yet). */
  SshUInt8       subsequent_message;
#define SSH_X509_POP_SUBSEQ_ENCRYPT_CERT   0
#define SSH_X509_POP_SUBSEQ_CHALLENGE_RESP 1
#define SSH_X509_POP_SUBSEQ_UNDEF          2

  /* Signature based POP */

  /* If the public key and subject are present at the certificate
     request, sender and pkey must be left as NULL's, and the
     signature must contain the signature calculated over the certReq.

     If no keys present at the request, the signature must be left
     empty (will be calculated internally), the public key must be
     provided. The sender may be provided if one already has valid
     certificate with the CA. */
  SshX509Name      sender;

  SshX509SignatureStruct signature;
  SshX509MacValueStruct  mac;
  SshX509PublicKeyStruct pkey;

  /* Private key based POP */

  /* If `this_message' is filled, it will contain the
     SshX509EncryptedValue containing the private key. The DER of this
     will be encapsulated into bit-string. */
  unsigned char   *this_message;
  size_t           this_message_len;
};
typedef struct SshX509PopRec *SshX509Pop;
typedef struct SshX509PopRec  SshX509PopStruct;

/***********************************************************************
 * CRMF Certificate identifier.
 */
struct SshX509CertIdRec
{
  SshX509Name issuer;
  SshMPIntegerStruct serial_no;
};
typedef struct SshX509CertIdRec *SshX509CertId;
typedef struct SshX509CertIdRec  SshX509CertIdStruct;

/***********************************************************************
 * CRMF Publication information.
 */
struct SshX509PublicationInfoNodeRec
{
  struct SshX509PublicationInfoNodeRec *next;
  /* The method of publication. */
  unsigned int publication_method;
#define SSH_X509_PUB_METHOD_DONT_CARE 0
#define SSH_X509_PUB_METHOD_X500      1
#define SSH_X509_PUB_METHOD_WEB       2
#define SSH_X509_PUB_METHOD_LDAP      3

  /* The requested location for the publication. */
  SshX509Name  location;
};
typedef struct SshX509PublicationInfoNodeRec *SshX509PublicationInfoNode;
typedef struct SshX509PublicationInfoNodeRec  SshX509PublicationInfoNodeStruct;

struct SshX509PublicationInfoRec
{
  unsigned int action;
#define SSH_X509_PUB_ACTION_PLEASE_PUBLISH 0
#define SSH_X509_PUB_ACTION_DO_NOT_PUBLISH 1
  SshX509PublicationInfoNode nodes;
};
typedef struct SshX509PublicationInfoRec *SshX509PublicationInfo;
typedef struct SshX509PublicationInfoRec  SshX509PublicationInfoStruct;

/***********************************************************************
 * CRMF encrypted data
 */
struct SshX509EncryptedValueRec
{
  /* algorithm (if any) which may utilize the contents of the
     encrypted value (the field, not the struct). */
  char *intended_alg;

  /* The encrypted value is encrypted using this symmetric cipher algorithm
     with the given IV. */
  char *symmetric_alg;
  unsigned char *symmetric_alg_iv;
  size_t symmetric_alg_iv_len;

  /* The symmetric key is encrypted using this public key algorithm. */
  char *key_alg;

  /* The encrypted key (using key_alg) of the symmetric algorithm. */
  unsigned char *encrypted_sym_key;
  size_t         encrypted_sym_key_len;

  /* Value hint, this may be displayed to the user, or something. */
  unsigned char *value_hint;
  size_t         value_hint_len;

  /* Encrypted value. */
  unsigned char *encrypted_value;
  size_t         encrypted_value_len;
};
typedef struct SshX509EncryptedValueRec *SshX509EncryptedValue;
typedef struct SshX509EncryptedValueRec  SshX509EncryptedValueStruct;

/***********************************************************************
 * CRMF private key archive control
 */
struct SshX509ArchiveOptionsRec
{
  /* Request the CA to archive the private key it generated. */
  Boolean archive_prv_key;

  /* The encrypted key. */
  SshX509EncryptedValue encrypted_value;

  /* Enveloped data. TODO: use the PKCS-7 stuff here. */

  /* Key generation parameters. */
  unsigned char *keygen_parameters;
  size_t         keygen_parameters_len;
};
typedef struct SshX509ArchiveOptionsRec *SshX509ArchiveOptions;
typedef struct SshX509ArchiveOptionsRec  SshX509ArchiveOptionsStruct;

/****************************************************************************
 * Types and contents for CRMF controls above. See RFC2511.
 */
typedef enum
{
  SSH_X509_CTRL_NONE,
  SSH_X509_CTRL_REG_TOKEN,
  SSH_X509_CTRL_AUTHENTICATOR,
  SSH_X509_CTRL_PKI_INFO,
  SSH_X509_CTRL_PKI_OPTIONS,
  SSH_X509_CTRL_OLD_CERT_ID,
  SSH_X509_CTRL_PUBLIC_KEY
} SshX509ControlsType;

struct SshX509ControlsNodeRec
{
  struct SshX509ControlsNodeRec *next;

  /* The contents. */
  SshX509ControlsType type;
  union {
    SshStr                       reg_token;
    SshStr                       authenticator;
    SshX509PublicationInfoStruct pki_info;
    SshX509ArchiveOptionsStruct  pki_options;
    SshX509CertIdStruct          old_cert_id;
    SshX509PublicKeyStruct       public_key;
  } s;
};
typedef struct SshX509ControlsNodeRec *SshX509ControlsNode;
typedef struct SshX509ControlsNodeRec  SshX509ControlsNodeStruct;

struct SshX509ControlsRec
{
  SshX509ControlsNodeStruct *node;
  /* Number of unknown controls detected. */
  unsigned int unknown;
};
typedef struct SshX509ControlsRec *SshX509Controls;
typedef struct SshX509ControlsRec  SshX509ControlsStruct;

/****************************************************************************
 *  Definitions for the certificate extensions.
 */

/***********************************************************************
 * Authority and subject key identifiers.
 */
struct SshX509ExtKeyIdRec
{
  /* Typically both subject and authority key identifiers are octet
     strings. */
  unsigned char *key_id;
  size_t         key_id_len;

  /* For subject key identifier, values of 'auth_cert_issuer' and
     'auth_cert_serial_number' are zero, e.g. these are sometimes used
     as authority key identifiers. */
  SshX509Name    auth_cert_issuer;
  SshMPIntegerStruct auth_cert_serial_number;
};
typedef struct SshX509ExtKeyIdRec *SshX509ExtKeyId;
typedef struct SshX509ExtKeyIdRec  SshX509ExtKeyIdStruct;

typedef enum {
  /* These are miscellaneous oid flags for extensions. */
  SSH_X509_POLICY_QT,
  SSH_X509_POLICY_QT_INTERNET_PQ,
  SSH_X509_POLICY_QT_UNOTICE
} SshX509NamedOids;

struct SshX509ExtPolicyQualifierInfoRec
{
  struct SshX509ExtPolicyQualifierInfoRec *next;

  /* The identifier. */
  unsigned char *oid;

  /* Currently two exclusive possibilities; CPSuri points to
     Certification Practice Statement, or UserNotice that identifies
     the issuer using organization string and the CPS message for that
     issuer using the notice number. Optionally some fallback message
     may be given at explicit_text. */

  /* CPSUri */
  SshStr cpsuri;

  /* UNotice */
  /* Both organization and notice numbers must be given. */
  SshStr        organization;
  unsigned int  notice_numbers_count;
  unsigned int *notice_numbers;

  /* ExplicitText */
  SshStr explicit_text;
};
typedef struct SshX509ExtPolicyQualifierInfoRec *SshX509ExtPolicyQualifierInfo,
  SshX509ExtPolicyQualifierInfoStruct;

#define SSH_X509_POLICY_ANY_POLICY "2.5.29.32.0"

struct SshX509ExtPolicyInfoRec
{
  struct SshX509ExtPolicyInfoRec *next;

  /* Policy identifier */
  char *oid;

  /* Policy qualifiers. */
  SshX509ExtPolicyQualifierInfo pq_list;
};
typedef struct SshX509ExtPolicyInfoRec *SshX509ExtPolicyInfo;
typedef struct SshX509ExtPolicyInfoRec  SshX509ExtPolicyInfoStruct;

struct SshX509ExtPolicyMappingsRec
{
  struct SshX509ExtPolicyMappingsRec *next;

  /* Issuer domain policy OID */
  char *issuer_dp_oid;

  /* Subject domain policy OID */
  char *subject_dp_oid;
};
typedef struct SshX509ExtPolicyMappingsRec *SshX509ExtPolicyMappings;
typedef struct SshX509ExtPolicyMappingsRec  SshX509ExtPolicyMappingsStruct;

struct SshX509ExtCRLDistPointsRec
{
  struct SshX509ExtCRLDistPointsRec *next;

  /* Either; full_name or relative_dn! */
  SshX509Name  full_name;
  SshDN       dn_relative_to_issuer;
  /* Other fields. */
  SshX509ReasonFlags reasons;
  SshX509Name        crl_issuer;
};
typedef struct SshX509ExtCRLDistPointsRec *SshX509ExtCRLDistPoints;
typedef struct SshX509ExtCRLDistPointsRec  SshX509ExtCRLDistPointsStruct;

struct SshX509ExtIssuingDistPointRec
{
  SshX509Name        full_name;
  SshDN              dn_relative_to_issuer;

  Boolean            only_contains_user_certs;
  Boolean            only_contains_ca_certs;
  SshX509ReasonFlags only_some_reasons;
  Boolean            only_contains_attribute_certs;
  Boolean            indirect_crl;
};
typedef struct SshX509ExtIssuingDistPointRec *SshX509ExtIssuingDistPoint;
typedef struct SshX509ExtIssuingDistPointRec  SshX509ExtIssuingDistPointStruct;

typedef struct SshX509OidListRec
{
  struct SshX509OidListRec *next;
  /* The object identifier */
  char *oid;                    /* As a string like "1.2.3.4" */
} *SshX509OidList, SshX509OidListStruct;

/* Information access extension, shared for authority and subject
   information. Subject information is defined at RFC3280. */
struct SshX509ExtInfoAccessRec
{
  struct SshX509ExtInfoAccessRec *next;

  /* Object identifier for access method. */
  char        *access_method;

  /* Access location name. One element, typically URI for http, ftp
     ldap, directory name for DAPm rfc822Name for email */
  SshX509Name  access_location;
};
typedef struct SshX509ExtInfoAccessRec *SshX509ExtInfoAccess;
typedef struct SshX509ExtInfoAccessRec  SshX509ExtInfoAccessStruct;

struct SshX509ExtDirAttributeRec
{
  struct SshX509ExtDirAttributeRec *next;

  /* Object identifier. */
  char *oid;

  unsigned char *octet_string;
  size_t         octet_string_len;
};
typedef struct SshX509ExtDirAttributeRec *SshX509ExtDirAttribute;
typedef struct SshX509ExtDirAttributeRec  SshX509ExtDirAttributeStruct;

struct SshX509GeneralSubtreeRec
{
  struct SshX509GeneralSubtreeRec *next;

  /* This name list should contain only one name according to PKIX
     draft standards. */
  SshX509Name name;
  /* RFC2459: min_distance should always be zero, and max_distance
     absent. */
  unsigned int min_distance, max_distance;
#define SSH_X509_GENERAL_SUBTREE_VALUE_ABSENT ((unsigned int)-1)
};
typedef struct SshX509GeneralSubtreeRec *SshX509GeneralSubtree;
typedef struct SshX509GeneralSubtreeRec  SshX509GeneralSubtreeStruct;

struct SshX509ExtPolicyConstraintsRec
{
  unsigned int require;
  unsigned int inhibit;
#define SSH_X509_POLICY_CONST_VALUE_NOT_PRESENT ((unsigned int)-1)
};
typedef struct SshX509ExtPolicyConstraintsRec *SshX509ExtPolicyConstraints,
  SshX509ExtPolicyConstraintsStruct;

/* Oid names for supported qc statements. */
typedef enum {
  SSH_X509_QCSTATEMENT_QCSYNTAXV1,
  SSH_X509_QCSTATEMENT_QCCOMPLIANCE,
  SSH_X509_QCSTATEMENT_QCEULIMITVALUE,
  SSH_X509_QCSTATEMENT_RETENTIONPERIOD
} SshX509QCStatementOids;

struct SshX509ExtQCStatementRec
{
  struct SshX509ExtQCStatementRec *next;

  /* Object identifier. */
  unsigned char *oid;

  /* Semantics info (RFC3039). */
  char *semantics_oid;
  SshX509Name name_registration_authorities;

  /* QcCompliance (ETSI TS 101 862 V1.1.1). */

  /* QcEuLimitValue (ETSI TS 101 862 V1.1.1). */
  unsigned int currency;
  SshMPIntegerStruct amount;
  SshMPIntegerStruct exponent;

  /* QcRetentionPeriod (ETSI TS 101 862 V1.1.1). */
  SshMPIntegerStruct retention_period;

  /* Unknown qcStatements. */
  unsigned char *der;
  size_t         der_len;
};
typedef struct SshX509ExtQCStatementRec *SshX509ExtQCStatement;
typedef struct SshX509ExtQCStatementRec  SshX509ExtQCStatementStruct;

struct SshX509ExtUnknownRec
{
  struct SshX509ExtUnknownRec *next;
  char *oid;
  char *name; /* Optional friendly name for the oid. */
  unsigned char *der;
  size_t der_length;
  Boolean critical;
};
typedef struct SshX509ExtUnknownRec *SshX509ExtUnknown;
typedef struct SshX509ExtUnknownRec  SshX509ExtUnknownStruct;

/* X.509v3 Extensions data structure for certificates. */
struct SshX509CertExtensionsRec
{
  /* Necessary information for the application on the availability of
     extensions. The application should always check whether there are
     critical extensions available. */
  SshUInt32 ext_available;
  SshUInt32 ext_critical;

  /* Version 3 specific extension fields. */

  /* Names. */
  SshX509Name subject_alt_names;
  SshX509Name issuer_alt_names;

  /* Key identifiers. */
  SshX509ExtKeyId subject_key_id;
  SshX509ExtKeyId issuer_key_id;

  /* Private key usage periods. */
  SshBerTimeStruct private_key_usage_not_before;
  SshBerTimeStruct private_key_usage_not_after;

  /* Public key usage flags. */
  SshX509UsageFlags key_usage;

  /* Policy Info */
  SshX509ExtPolicyInfo policy_info;

  /* Policy Mappings */
  SshX509ExtPolicyMappings policy_mappings;

  /* Basic constraints. The SSH_X509_MAX_PATH_LEN is returned when no path
     length has been defined. (Otherwise it is very rare that so long paths
     are specified.) */
#define SSH_X509_MAX_PATH_LEN  ((size_t)-1)
  size_t path_len;
  Boolean ca;

  /* Subject directory attributes. */
  SshX509ExtDirAttribute subject_directory_attr;

  /* Name constraints. */
  SshX509GeneralSubtree name_const_permitted;
  SshX509GeneralSubtree name_const_excluded;

  /* Policy Constraints */
  SshX509ExtPolicyConstraints policy_const;

  /* CRL distribution points */
  SshX509ExtCRLDistPoints crl_dp;

  /* Extended key usage! */
  SshX509OidList ext_key_usage;

  /* Authority info access */
  SshX509ExtInfoAccess auth_info_access;

  SshStr netscape_comment;
  SshStr cert_template_name;

  /* Qualified certificate statements */
  SshX509ExtQCStatement qcstatements;

  /* RFC3280 adds the following three. */
  SshX509ExtInfoAccess subject_info_access;
  SshUInt32 inhibit_any_skip_certs;
  SshX509ExtCRLDistPoints freshest_crl;

  /* Unknown non-critical extensions. They will not get encoded. */
  SshX509ExtUnknown unknown;
};
typedef struct SshX509CertExtensionsRec *SshX509CertExtensions;
typedef struct SshX509CertExtensionsRec  SshX509CertExtensionsStruct;

/***********************************************************************
 * X.509v2 Extensions data structure for CRLs.
 */
struct SshX509CrlExtensionsRec
{
  /* Necessary information for the application on the availability of
     extensions. The application should always check whether there are
     critical extensions available. This is done by masking. */
  SshUInt32 ext_available;
  SshUInt32 ext_critical;


  /* Version 2 extensions for the issuer. */

  /* Names. */
  SshX509Name issuer_alt_names;

  /* The authority key identifier. */
  SshX509ExtKeyId auth_key_id;

  /* Monotonically increasing number for all certificates. All older
     certificates are less than this for the CA. */
  SshMPIntegerStruct  crl_number;

  /* Distribution point */
  SshX509ExtIssuingDistPoint dist_point;

  /* Delta CRL indicator. */
  SshMPIntegerStruct delta_crl_ind;
};
typedef struct SshX509CrlExtensionsRec *SshX509CrlExtensions;
typedef struct SshX509CrlExtensionsRec  SshX509CrlExtensionsStruct;


struct SshX509CrlRevExtensionsRec
{
  /* Necessary information for the application on the availability of
     extensions. The application should always check whether there are
     critical extensions available. This is done by masking. */
  SshUInt32 ext_available;
  SshUInt32 ext_critical;

  SshX509CRLReasonCode reason_code;

  /* Hold instruction code. */
  char *hold_inst_code;

  /* The invalidity date. */
  SshBerTimeStruct invalidity_date;

  /* Certificate issuer in an indirect CRL. */
  SshX509Name certificate_issuer;

  /* Future extension (for version 3). */

};
typedef struct SshX509CrlRevExtensionsRec *SshX509CrlRevExtensions;
typedef struct SshX509CrlRevExtensionsRec  SshX509CrlRevExtensionsStruct;


/* The certificate data structure. */
struct SshX509CertificateRec
{
  /* If version is unknown then following fields are not defined. */
  SshX509Version version;

  /* The template type. Possible types;

     X.509     certificate (version 1,2, or 3)
     PKIX CRMF certificate request
     PKCS-10   certificate request
   */
  SshX509CertType type;

  /* The basic information in a X.509 certificate. */

  /* Serial number, given by issuing CA. */
  SshMPIntegerStruct serial_number;

  /* The request identifier. */
  SshMPIntegerStruct request_id;

  /* Distinguished names. */
  SshX509Name issuer_name;
  SshX509Name subject_name;

  /* Validity */
  SshBerTimeStruct not_before;
  SshBerTimeStruct not_after;

  /* The public key of the subject. Either the public key or a group
     is available. */
  SshX509PublicKeyStruct subject_pkey;

  /* Version 3 specific extension fields. */
  SshX509CertExtensionsStruct extensions;

  /* List of other attributes */
  SshX509Attribute attributes;

  /* The control information. */
  SshX509ControlsStruct controls;

  /* The proof-of-possession information. */
  SshX509PopStruct pop;

  SshX509ConfigStruct config;

  /* Number of references onto this certificate. */
  SshUInt32 refcount;
};


/* Following two structures define the Certificate Revocation Lists and
   are used for that purpose only. */

struct SshX509RevokedCertsRec
{
  /* This is a list of revoked certs. */
  struct SshX509RevokedCertsRec *next;

  /* Serial number of the revoked certificate. */
  SshMPIntegerStruct serial_number;

  /* Date of revocation. */
  SshBerTimeStruct revocation_date;

  /* Extensions. */
  SshX509CrlRevExtensionsStruct extensions;
};

typedef struct SshX509RevokedCertsRec *SshX509RevokedCerts;
typedef struct SshX509RevokedCertsRec  SshX509RevokedCertsStruct;

struct SshX509CrlRec
{
  /* Version of the certificate, supported at the moment only versions
     1 and 2. */
  SshX509Version version;

  /* Issuing CA's names. */
  SshX509Name issuer_name;

  /* Time information. */
  SshBerTimeStruct this_update;
  Boolean use_next_update;
  SshBerTimeStruct next_update;

  /* Version 2 extensions for the issuer. */
  SshX509CrlExtensionsStruct extensions;

  /* A list of revoked certificates. */
  SshX509RevokedCerts revoked;
  SshX509RevokedCerts last_revoked;

  /* Signature information. */

  /* Proof-of-possession. */
  SshX509PopStruct pop;

  SshX509ConfigStruct config;
};

/****************************************************************************
 * Initialization:
 */

void ssh_x509_library_set_default_config(SshX509Config config);

/* Normal way of library initialization is to call this function.
   This registers encoders and decoders for all known certificate
   formats, and CRL's. If smaller footprint is desired, one should
   however use ssh_x509_library_initialize_framework call followed by
   calls ssh_x509_library_register_functions. */
Boolean ssh_x509_library_initialize(SshX509Config params);


/* Initialize certificate library framework. */
Boolean ssh_x509_library_initialize_framework(SshX509Config params);

/* Register encoder and decoder functions (e.g. give linkage to them).
   Functions are introduced just below this function. */
Boolean ssh_x509_library_register_functions(SshX509CertType type,
                                            SshX509CertDecoder decode,
                                            SshX509CertEncoder encode);

/* Known encoders */

extern SshX509AsyncCallStatus ssh_x509_cert_encode_asn1(void *context);
extern SshX509AsyncCallStatus ssh_x509_crmf_encode_asn1(void *context);
extern SshX509AsyncCallStatus ssh_x509_pkcs10_encode_asn1(void *context);

/* Known decoders */
extern SshX509Status
ssh_x509_cert_decode_asn1(SshAsn1Context, SshAsn1Node, SshX509Certificate);
extern SshX509Status
ssh_x509_crmf_decode_asn1(SshAsn1Context, SshAsn1Node, SshX509Certificate);
extern SshX509Status
ssh_x509_pkcs10_decode_asn1(SshAsn1Context, SshAsn1Node, SshX509Certificate);

void ssh_x509_library_uninitialize(void);

/****************************************************************************
 * Basic certificate operations.
 */

/* Allocate a certificate structure. One structure should be used for
   only one certificate. This function initializes all fields of the
   certificate, and makes it contain nothing.

   The type field denotes the type of the certificate (or request)
   that is read/created. It cannot be changed.

   After allocate the certificate has one reference, that can be
   dropped with ssh_x509_cert_free(). */
SshX509Certificate ssh_x509_cert_allocate(SshX509CertType type);

/* Take a reference to the certificate. The reference is dropped by
   one with call to ssh_x509_cert_free(), and when it reaches zero,
   the certificate is freed.  */
void ssh_x509_cert_take_ref(SshX509Certificate c);

/* This function resets the certificate fields to the state they are
   after decoding the BER blob. This includes resetting the dirty flags
   in the key lists. */
void ssh_x509_cert_reset(SshX509Certificate c);

/* A decoder function for X.509v3 certificates. Given encoded
   certificate in buffer 'buf' of length 'len' this results in
   certificate which shall be set to suitable values. */
SshX509Status ssh_x509_cert_decode(const unsigned char *buf, size_t len,
                                   SshX509Certificate c);

/* An encoder function for X.509v3 certificates. */
SshX509Status ssh_x509_cert_encode(SshX509Certificate c,
                                   SshPrivateKey issuer_key,
                                   unsigned char **buf, size_t *buf_len);

/* The callback to be used with ssh_x509_cert_encode_async and
   ssh_x509_crl_encode_async. This is called with the data and
   the context when the encoding is done. The buffer given is
   constant buffer, and it is freed when the callback returns. */
typedef void (*SshX509EncodeCB)(SshX509Status status,
                                const unsigned char *buf_return,
                                size_t buf_return_len,
                                void *context);

/* Asynchronously encodes the certificate/request. This functions returns the
   operations handle which with the operation may be aborted. Calls the
   encode_cb with data and the context when the operation finishes. The
   returned data must be copied in the callback, because it is freed,
   when the callback returns. The caller must keep the certificate data
   constant during this call. */
SshOperationHandle ssh_x509_cert_encode_async(SshX509Certificate c,
                                              SshPrivateKey issuer_key,
                                              SshX509EncodeCB encode_cb,
                                              void *context);

/* Verify a X.509v3 certificate. This verifies the signature in the
   certificate. One should always do this in order to have some faith in
   the origin of the certificate. */
Boolean ssh_x509_cert_verify(SshX509Certificate c,
                             SshPublicKey issuer_key);

/* This callback is called after the asynchronous verification has
   finished. The status is SSH_X509_OK if the verification succeeded
   and the signature was ok. Otherwise, some error value is given.
   */

/* Remark. The public key used may get its schemes changed for the duration
   of the verification. This is because the signature in the certificate
   contains explicit methods used for signature. However, this usually
   does not cause problems as the public key is used mainly for one
   signature scheme anyway. */

typedef void (*SshX509VerifyCB)(SshX509Status status,
                                void *context);

SshOperationHandle ssh_x509_cert_verify_async(SshX509Certificate c,
                                              SshPublicKey issuer_key,
                                              SshX509VerifyCB verify_cb,
                                              void *context);

/* Free a X.509v3 certificate. After this the certificate structure cannot
   be used, if used the operation is undefined. */
void ssh_x509_cert_free(SshX509Certificate c);

/* Interface for build a certificate from code. */

/* Note that most routines make a copy for themselves of the input,
   and thus you don't have to make a copy yourself.

   The outputs may be ignored, however, for some functions they give
   important information about the success of the routine. */

/* Set the serial number of the certificate. Every certificate should
   have one. */
void ssh_x509_cert_set_serial_number(SshX509Certificate c,
                                     SshMPIntegerConst s);
/* Set the subject DN name of the certificate. Given in LDAP DN format.
   Necessary if subject alternative names are not used. */
Boolean ssh_x509_cert_set_subject_name(SshX509Certificate c,
                                       const unsigned char *name);
/* Set the issuer DN name of the certificate. Given in LDAP DN format.
   Every certificate should have one. */
Boolean ssh_x509_cert_set_issuer_name(SshX509Certificate c,
                                      const unsigned char *name);

/* Set the subject DN name of the certificate. Given in SshStr structure.
   Necessary if subject alternative names are not used. */
Boolean ssh_x509_cert_set_subject_name_str(SshX509Certificate c,
                                           const SshStr str);
/* Set the issuer DN name of the certificate. Given in SshStr structure.
   Every certificate should have one. */
Boolean ssh_x509_cert_set_issuer_name_str(SshX509Certificate c,
                                          const SshStr str);

/* Set the validity of the certificate. Both times should be set for
   valid certificate. */
void ssh_x509_cert_set_validity(SshX509Certificate c,
                                const SshBerTime not_before,
                                const SshBerTime not_after);
/* Set the public, pregenerated, to the certificate. A copy is taken and
   thus you have to free 'key' by yourself. */
Boolean ssh_x509_cert_set_public_key(SshX509Certificate c,
                                     const SshPublicKey key);

/* This function computes standard PKIX key identifier for the
   certificate. The method is as RFC2459 section 4.2.1.2 suggests.
   The function returns NULL if the certificate does not contain
   public key. For PKIX the hash algorithm should be sha1, but other
   algorithms may also be useable. */
unsigned char *
ssh_x509_cert_compute_key_identifier(SshX509Certificate c,
                                     const char *hash_algorithm,
                                     size_t *kid_len);
unsigned char *
ssh_x509_cert_compute_key_identifier_ike(SshX509Certificate c,
                                         const char *hash_algorithm,
                                         size_t *kid_len);

/* Unique identifier of the subject. Not necessary. */
void ssh_x509_cert_set_subject_unique_identifier(SshX509Certificate c,
                                                 const unsigned char *buf,
                                                 size_t buf_len);
/* Unique identifier of the issuer. Not necessary. */
void ssh_x509_cert_set_issuer_unique_identifier(SshX509Certificate c,
                                                const unsigned char *buf,
                                                size_t buf_len);
/* Extensions */

/* Extensions have always a critical flag possibility. However, a extension
   should be set only to critical if it is critical for some reason. E.g.
   subject alternative names are critical only if no subject DN name is
   set. */

/* Set the subject alternative names of the certificate. The name list
   is not copied, instead just added to the list in the certificate. Thus
   you have to forget the list there, e.g. not free it yourself. However,
   this should not be of any trouble. */
void
ssh_x509_cert_set_subject_alternative_names(SshX509Certificate c,
                                            SshX509Name names,
                                            Boolean critical);
/* Same as with subject alternative names. */
void
ssh_x509_cert_set_issuer_alternative_names(SshX509Certificate c,
                                           SshX509Name names,
                                           Boolean critical);

/* Sets the private key usage period, not both 'not_before' or
   'not_after' need to be given. Either can be NULL. The RFC2459
   Section 4.2.1.4 does NOT recommend using this extension. */
void
ssh_x509_cert_set_private_key_usage_period(SshX509Certificate c,
                                           const SshBerTime not_before,
                                           const SshBerTime not_after,
                                           Boolean critical);
/* Private key usage flags. */
void
ssh_x509_cert_set_key_usage(SshX509Certificate c,
                            SshX509UsageFlags flags,
                            Boolean critical);

/* Basic constraints, these define whether the CA below is authorized
   to act as an CA. Also the maximum certificate list path length is
   given.  Should be critical if 'ca' is TRUE.  */
void
ssh_x509_cert_set_basic_constraints(SshX509Certificate c,
                                    size_t path_length,
                                    Boolean ca,
                                    Boolean critical);

/* Authority key identifier should be set according the policy of the
   CA. There is quite a lot of variation possible here. */
void
ssh_x509_cert_set_authority_key_id(SshX509Certificate c,
                                   SshX509ExtKeyId id,
                                   Boolean critical);

/* For a self-signed certificates the subject identifier should match the
   value in the authority key id, if present. */
void
ssh_x509_cert_set_subject_key_id(SshX509Certificate c,
                                 const unsigned char *key_id,
                                 size_t key_id_len,
                                 Boolean critical);

/* Set the policy information. */
void
ssh_x509_cert_set_policy_info(SshX509Certificate c,
                              SshX509ExtPolicyInfo pinfo,
                              Boolean critical);

/* Set the CRL distribution point. */
void
ssh_x509_cert_set_crl_dist_points(SshX509Certificate c,
                                  SshX509ExtCRLDistPoints dps,
                                  Boolean critical);

void
ssh_x509_cert_set_freshest_crl(SshX509Certificate c,
                               SshX509ExtCRLDistPoints fresh,
                               Boolean critical);

/* Set the policy mappings. Only valid for CA certificates and MUST
   not be critical according to RFC2459.*/
void
ssh_x509_cert_set_policy_mappings(SshX509Certificate c,
                                  SshX509ExtPolicyMappings pmappings,
                                  Boolean critical);

/* Set the authorization access information. */
void
ssh_x509_cert_set_auth_info_access(SshX509Certificate c,
                                   SshX509ExtInfoAccess access,
                                   Boolean critical);

/* Set the subject access information. */
void
ssh_x509_cert_set_subject_info_access(SshX509Certificate c,
                                      SshX509ExtInfoAccess access,
                                      Boolean critical);

/* Set the netscape comment. */
void
ssh_x509_cert_set_netscape_comment(SshX509Certificate c,
                                   SshStr comment,
                                   Boolean critical);

/* Set the windows certificate template name. */
void
ssh_x509_cert_set_cert_template_name(SshX509Certificate c,
                                     SshStr n,
                                     Boolean critical);

/* Set qualified certificate statement extension. */
void
ssh_x509_cert_set_qcstatements(SshX509Certificate c,
                               SshX509ExtQCStatement qcs,
                               Boolean critical);

/* Set the directory attribute extension. */
void
ssh_x509_cert_set_subject_dir_attributes(SshX509Certificate c,
                                         SshX509ExtDirAttribute attr,
                                         Boolean critical);

void
ssh_x509_cert_set_inhibit_any_policy(SshX509Certificate c,
                                     SshUInt32 ncerts,
                                     Boolean critical);

/* Set unknown (custom) extension. */
void
ssh_x509_cert_set_unknown_extension(SshX509Certificate c,
                                    SshX509ExtUnknown unknown);

/* Either of the permitted or excluded subtree pointers may be NULL,
   to be considered undefined. This extension MUST not be used on
   End-Entity certificates. */
void
ssh_x509_cert_set_name_constraints(SshX509Certificate c,
                                   SshX509GeneralSubtree permitted,
                                   SshX509GeneralSubtree excluded,
                                   Boolean critical);

/* Policy contraints. */
void
ssh_x509_cert_set_policy_constraints(SshX509Certificate c,
                                     SshX509ExtPolicyConstraints policy,
                                     Boolean critical);

/* Set the extended key usage. */
void
ssh_x509_cert_set_ext_key_usage(SshX509Certificate c,
                                SshX509OidList ext_key_usage,
                                Boolean critical);

/* This function sets/adds `attribute' to the certificate. This
   function should not be called for PKIX type certificates as that
   profile does not utilize attributes. The attribute is allocated by
   caller, and the library will free it, as well as the
   attribute->data field when the certificate is freed.  */
void
ssh_x509_cert_set_attribute(SshX509Certificate c,
                            SshX509Attribute attribute);

/* Reading information from the certificate. */

/* Find out which extensions are present in the certificate. Also see
   whether this extension is critical. These functions are to be used
   always when studying certificates to see whether your system doesn't
   understand (cannot handle) some of the extensions or whether there
   are unknown extensions flagged critical. */
Boolean
ssh_x509_cert_ext_available(SshX509Certificate c,
                            SshX509CertExtType type,
                            Boolean *critical);

/* Routines return TRUE if the given value was found and read. FALSE
   otherwise. In some cases the FALSE also means that not present, in
   which case it is ok to continue. */

/* Get the serial number of the certificate into SshMPInteger
   allocated by the caller. The function returns TRUE, if there was
   enough space to copy the bits of serial number to MP-integer
   's'. */
Boolean
ssh_x509_cert_get_serial_number(SshX509Certificate c, SshMPInteger s);

/* Get the subject DN names of the certificate.

   The first form returns LDAPv3 encoded character string representing
   the name. The second form returns SshStr encoded name, and the last
   form returns DER encoded name. In all cases the call allocates the
   data and the calling application shall free it, using ssh_free,
   ssh_str_free, and ssh_free respectively.

   The functions returns TRUE, if the certificate contains
   subject-name, the subject name can be encoded and decoded by the
   library, and there is enough space for the copy.

   Side effects: resets subject_name namelist from the certificate, see
   ssh_x509_name_reset(). */

Boolean
ssh_x509_cert_get_subject_name(SshX509Certificate c, char **name);
Boolean
ssh_x509_cert_get_subject_name_str(SshX509Certificate c, SshStr *str);
Boolean
ssh_x509_cert_get_subject_name_der(SshX509Certificate c,
                                   unsigned char **der, size_t *der_len);

/* Get the issuer DN names of the certificate.

   The first form returns LDAPv3 encoded character string representing
   the name. The second form returns SshStr encoded name, and the last
   form returns DER encoded name. In all cases the call allocates the
   data and the calling application shall free it, using ssh_free,
   ssh_str_free, and ssh_free respectively.

   The functions returns TRUE, if the certificate contains
   subject-name, the subject name can be encoded and decoded by the
   library, and there is enough space for the copy.

   Side effects: resets issuer_name namelist from the certificate, see
   ssh_x509_name_reset(). */
Boolean
ssh_x509_cert_get_issuer_name(SshX509Certificate c, char **name);
Boolean
ssh_x509_cert_get_issuer_name_str(SshX509Certificate c, SshStr *str);
Boolean
ssh_x509_cert_get_issuer_name_der(SshX509Certificate c,
                                  unsigned char **der, size_t *der_len);

/* Get the validity period of the certificate.

   The function fills validity period start and end times into
   'not_before' and 'not_after' respectively. Either of these may be a
   NULL pointer, or they have to point to space of at least
   sizeof(SshBerTimeStruct). The function returns TRUE, if the
   certificate contains both validity times (e.g. is of valid
   format). */
Boolean
ssh_x509_cert_get_validity(SshX509Certificate c,
                           SshBerTime not_before, SshBerTime not_after);

/* Get the public key from a certificate.

   This function extracts a copy of public key from given certificate.
   The function returns TRUE, if the certificate is a public key
   certificate and there was enough space for the copy.

   Freeing the certificate does not free the public key extracted.
   The calling application has to free the public key when it no
   longer needs it. */
Boolean
ssh_x509_cert_get_public_key(SshX509Certificate c, SshPublicKey *key);

/* Get the subject unique identifier from the certificate.

   This function extracts a copy of subject unique identifier from
   given certificate. The function returns TRUE, if the certificate
   contains unique identifier and there was enough space for the copy.

   Side effects: resets subject_name namelist from the certificate,
   see ssh_x509_name_reset().

   The calling application has to free the return identifier 'buf'. */
Boolean
ssh_x509_cert_get_subject_unique_identifier(SshX509Certificate c,
                                            unsigned char **buf,
                                            size_t *buf_len);

/* Get the issuer unique identifier from the certificate.

   This function extracts a copy of issuer unique identifier from
   given certificate. The function returns TRUE, if the certificate
   contains unique identifier and there was enough space for the copy.

   Side effects: resets issuer_name namelist from the certificate,
   see ssh_x509_name_reset().

   The calling application has to free the return identifier 'buf'. */

Boolean
ssh_x509_cert_get_issuer_unique_identifier(SshX509Certificate c,
                                           unsigned char **buf,
                                           size_t *buf_len);

/* Extensions */

/* It should be noted that return value FALSE is returned usually because
   such an extension is not supported. */

/* Get the subject alternative names as a SshX509Name list. */
Boolean
ssh_x509_cert_get_subject_alternative_names(SshX509Certificate c,
                                            SshX509Name *names,
                                            Boolean *critical);
/* Get the issuer alternative names as a SshX509Name list. */
Boolean
ssh_x509_cert_get_issuer_alternative_names(SshX509Certificate c,
                                           SshX509Name *names,
                                           Boolean *critical);
/* Get the private key usage period. Pointers `not_before' and
   `not_after' may be NULL if this information is not needed. */
Boolean
ssh_x509_cert_get_private_key_usage_period(SshX509Certificate c,
                                           SshBerTime not_before,
                                           SshBerTime not_after,
                                           Boolean *critical);
/* Get the key usage flags. Note that some flags are always given,
   however, if the certificate doesn't explicitly specify some then this
   returns also flags = 0. */
Boolean
ssh_x509_cert_get_key_usage(SshX509Certificate c,
                            SshX509UsageFlags *flags,
                            Boolean *critical);
/* Get the basic constraints. */
Boolean
ssh_x509_cert_get_basic_constraints(SshX509Certificate c,
                                    size_t *path_length,
                                    Boolean *ca,
                                    Boolean *critical);

/* Get the authority key identifier. */
Boolean
ssh_x509_cert_get_authority_key_id(SshX509Certificate c,
                                   SshX509ExtKeyId *id,
                                   Boolean *critical);

/* Get the subject key identifier. */
Boolean
ssh_x509_cert_get_subject_key_id(SshX509Certificate c,
                                 unsigned char **key_id,
                                 size_t *key_id_len,
                                 Boolean *critical);

/* Get the policy info. */
Boolean
ssh_x509_cert_get_policy_info(SshX509Certificate c,
                              SshX509ExtPolicyInfo *pinfo,
                              Boolean *critical);

/* Get the CRL distribution point. */
Boolean
ssh_x509_cert_get_crl_dist_points(SshX509Certificate c,
                                  SshX509ExtCRLDistPoints *dist_points,
                                  Boolean *critical);
Boolean
ssh_x509_cert_get_freshest_crl(SshX509Certificate c,
                               SshX509ExtCRLDistPoints *fresh,
                               Boolean *critical);

/* Get the policy mappings. */
Boolean
ssh_x509_cert_get_policy_mappings(SshX509Certificate c,
                                  SshX509ExtPolicyMappings *pmappings,
                                  Boolean *critical);

/* Get the authority information access. */
Boolean
ssh_x509_cert_get_auth_info_access(SshX509Certificate c,
                                   SshX509ExtInfoAccess *access,
                                   Boolean *critical);

/* Get the subject information access. */
Boolean
ssh_x509_cert_get_subject_info_access(SshX509Certificate c,
                                      SshX509ExtInfoAccess *access,
                                      Boolean *critical);

/* Get the netscape comment */
Boolean
ssh_x509_cert_get_netscape_comment(SshX509Certificate c,
                                   SshStr *comment,
                                   Boolean *critical);

/* Get the windows certificate template name. */
Boolean
ssh_x509_cert_get_cert_template_name(SshX509Certificate c,
                                     SshStr *n,
                                     Boolean *critical);

/* Get qualified certificate statement extensions. */
Boolean
ssh_x509_cert_get_qcstatements(SshX509Certificate c,
                               SshX509ExtQCStatement *qcs,
                               Boolean *critical);

/* Get the directory attribute extension. */
Boolean
ssh_x509_cert_get_subject_dir_attributes(SshX509Certificate c,
                                         SshX509ExtDirAttribute *attr,
                                         Boolean *critical);

Boolean
ssh_x509_cert_get_inhibit_any_policy(SshX509Certificate c,
                                     SshUInt32 *ncerts,
                                     Boolean *critical);

/* Get the unknown extension.  Criticality will always be FALSE */
Boolean
ssh_x509_cert_get_unknown_extension(SshX509Certificate c,
                                    SshX509ExtUnknown *unknown,
                                    Boolean *critical);

/* Get the name constraints. Both permitted and excluded must be
   valid, non null pointers. */
Boolean
ssh_x509_cert_get_name_constraints(SshX509Certificate c,
                                   SshX509GeneralSubtree *permitted,
                                   SshX509GeneralSubtree *excluded,
                                   Boolean *critical);

/* Get the policy constraints. */
Boolean
ssh_x509_cert_get_policy_constraints(SshX509Certificate c,
                                     SshX509ExtPolicyConstraints *policy,
                                     Boolean *critical);

/* Get the extended key usage field. */
Boolean
ssh_x509_cert_get_ext_key_usage(SshX509Certificate c,
                                SshX509OidList *ext_key_usage,
                                Boolean *critical);

/* Retrieve attributes from the certificate. If the certificate is of
   PKCS#10 type, this returns the attributes not of type extensionReq */
Boolean
ssh_x509_cert_get_attribute(SshX509Certificate c,
                            SshX509Attribute *attribute);


/* Certificate revocation list functions. */

/* Certificate Revocation Lists (CRL's) are used to revoke certificates
   that are compromised, or for some other reason must be revoked before
   their validity period has expired. */

/* Allocate a new CRL structure. */
SshX509Crl ssh_x509_crl_allocate(void);

/* This function resets the CRL fields to the state they are
   after decoding the BER blob. This includes resetting the dirty flags
   in the key lists. */
void ssh_x509_crl_reset(SshX509Crl c);

/* Decode a given DER encoded buffer of CRL information. */
SshX509Status ssh_x509_crl_decode(const unsigned char *buf, size_t len,
                                  SshX509Crl c);

/* Encode a CRL structure into a buffer of DER encoded octets. */
SshX509Status ssh_x509_crl_encode(SshX509Crl c,
                                  SshPrivateKey issuer_key,
                                  unsigned char **buf, size_t *buf_len);


/* Asyncronously encode a CRL structure into a buffer of DER encoded octets.
   The buffer is given in the callback and it must be copied away in the
   callback if it is needed later since it is freed, when this call returns.
   CRL structure and issuer key must be kept constant during this call.

   The operation may be cancelled using the returned handle. */
SshOperationHandle ssh_x509_crl_encode_async(SshX509Crl c,
                                              SshPrivateKey issuer_key,
                                              SshX509EncodeCB encode_cb,
                                              void *context);

/* Verify the CRL signature with issuer's public key. */
Boolean ssh_x509_crl_verify(SshX509Crl c,
                            SshPublicKey issuer_key);

SshOperationHandle ssh_x509_crl_verify_async(SshX509Crl c,
                                             SshPublicKey issuer_key,
                                             SshX509VerifyCB verify_cb,
                                             void *context);

/* Free CRL structure. */
void ssh_x509_crl_free(SshX509Crl c);

/* Interface for building CRL's. */

/* Set the issuer DN name of the CRL. */
Boolean ssh_x509_crl_set_issuer_name(SshX509Crl crl,
                                     const unsigned char *name);
Boolean ssh_x509_crl_set_issuer_name_str(SshX509Crl crl,
                                         const SshStr str);
/* Set the update times, e.g. 'this_update' and 'next_update'
   times. The 'this_update' time is necessary, the 'next_update' is
   not. This may be called with NULL as either time, in that case only
   the non-null time is set, and the old time for the other remains as
   is. */
void ssh_x509_crl_set_update_times(SshX509Crl crl,
                                   const SshBerTime this_update,
                                   const SshBerTime next_update);
/* Extensions. */

/* Set the authority key identifier. RFC2459 says this is a must in
   CRL's issued by a conforming CA. */
void ssh_x509_crl_set_authority_key_id(SshX509Crl crl,
                                       SshX509ExtKeyId id,
                                       Boolean critical);
/* Set the issuer alternative names. If present the issuer DN name not
   need to be. */
void ssh_x509_crl_set_issuer_alternative_names(SshX509Crl crl,
                                               SshX509Name names,
                                               Boolean critical);
/* Put in the certificate CRL number. This number is an increasing number
   for all CRL's given by the CA. Should be present in a CRL. */
void ssh_x509_crl_set_crl_number(SshX509Crl crl,
                                 SshMPIntegerConst crl_number,
                                 Boolean critical);
/* The CRL distribution point name. */
void
ssh_x509_crl_set_issuing_dist_point(SshX509Crl crl,
                                    SshX509ExtIssuingDistPoint dist_point,
                                    Boolean critical);

/* The delta CRL indicator, which gives the CRL number for which it is
   the delta of. This extension, if present, must be critical. */
void ssh_x509_crl_set_delta_crl_indicator(SshX509Crl crl,
                                          SshMPIntegerConst delta,
                                          Boolean critical);

/* Revoked certs. */

/* Revokation list node allocation. */
SshX509RevokedCerts ssh_x509_revoked_allocate(void);

/* Revokation list node free. If node is put into the CRL, it will be
   automatically freed when the CRL is freed using function
   ssh_x509_crl_free. */
void ssh_x509_revoked_free(SshX509RevokedCerts rc);

/* Add revoked certs entry to the CRL. Typical use will be:

   allocate CRL for CA and set extensions
   for each revoked certificate in CA
     allocate revoked entry
     fill revoked entry
     add revoked entry into CRL
   encode, sign and publish CRL
   free CRL

   Above, the revoked may be single revoked certificate, or a
   pre-composed list of revoked certificates. */

void ssh_x509_crl_add_revoked(SshX509Crl crl,
                              SshX509RevokedCerts revoked);

/* Set the fields of the revoked cert entry. */

/* Set the serial number of the revoked certificate. */
void ssh_x509_revoked_set_serial_number(SshX509RevokedCerts revoked,
                                        SshMPIntegerConst s);
/* Set the revocation date of the revoked certificate. */
void ssh_x509_revoked_set_revocation_date(SshX509RevokedCerts revoked,
                                          const SshBerTime when);
/* Extensions */
/* Set the certificate issuer */
void ssh_x509_revoked_set_certificate_issuer(SshX509RevokedCerts revoked,
                                             SshX509Name issuer_name,
                                             Boolean critical);

/* Set the reason code for the revocation. */
void ssh_x509_revoked_set_reason_code(SshX509RevokedCerts revoked,
                                      SshX509CRLReasonCode reason_code,
                                      Boolean critical);
/* Set the hold instruction code type. Can be any object identifier, but
   PKIX defines only the ones defined above. */
void ssh_x509_revoked_set_hold_instruction_code(SshX509RevokedCerts revoked,
                                                const char *object_identifier,
                                                Boolean critical);
/* Set the invalidity date of the revoked certificate. */
void ssh_x509_revoked_set_invalidity_date(SshX509RevokedCerts revoked,
                                          const SshBerTime when,
                                          Boolean critical);

/* Reading information from the CRL. */

/* Get the knowledge of the available extensions in the CRL data structure.
   Also you can query whether this extension is critical or not. */
Boolean
ssh_x509_crl_ext_available(SshX509Crl crl,
                           SshX509CrlExtType type,
                           Boolean *critical);

/* Return value FALSE doesn't necessarily mean in the following that
   the CRL is bad, but that the value one tried to find doesn't exist
   in the certificate. */

/* Get the issuer DN name out of the CRL. Return FALSE if the CRL is bad. */
Boolean ssh_x509_crl_get_issuer_name(SshX509Crl crl,
                                     char **name);
Boolean ssh_x509_crl_get_issuer_name_der(SshX509Crl crl,
                                         unsigned char **der,
                                         size_t *der_len);
Boolean ssh_x509_crl_get_issuer_name_str(SshX509Crl crl,
                                         SshStr *name_str);

/* Get the update times of the CRL. The 'next_update' field might not be
   present. Returns FALSE is the CRL is bad. */
Boolean ssh_x509_crl_get_update_times(SshX509Crl crl,
                                      SshBerTime this_update,
                                      SshBerTime next_update);
/* Extensions. */

/*  Read the authority key id.  */
Boolean
ssh_x509_crl_get_authority_key_id(SshX509Crl crl,
                                  SshX509ExtKeyId *key_id,
                                  Boolean *critical);

/* Get the issuer alternative names as a SshX509Name list. */
Boolean ssh_x509_crl_get_issuer_alternative_names(SshX509Crl crl,
                                                  SshX509Name *names,
                                                  Boolean *critical);
/* Get the CRL number from the CRL. */
Boolean ssh_x509_crl_get_crl_number(SshX509Crl crl,
                                    SshMPInteger crl_number,
                                    Boolean *critical);
/* Get the issuing distribution point.  */
Boolean
ssh_x509_crl_get_issuing_dist_point(SshX509Crl crl,
                                    SshX509ExtIssuingDistPoint *point,
                                    Boolean *critical);
/* Get the delta CRL indicator. */
Boolean ssh_x509_crl_get_delta_crl_indicator(SshX509Crl crl,
                                             SshMPInteger delta,
                                             Boolean *critical);

/***** Revoked certs analysis. */

/* Routines for traversing the revoked list, without pointer operations. */

/* Functions to check the extensions available in this revocation
   entry. */
Boolean
ssh_x509_revoked_ext_available(SshX509RevokedCerts revoked,
                               SshX509CrlEntryExtType type,
                               Boolean *critical);

/* Get the revoked certificate list from the CRL for easy traversal. The
   order you get the revoked certificates is the order they appear in the
   CRL encoded blob. */
SshX509RevokedCerts ssh_x509_crl_get_revoked(SshX509Crl crl);
/* Get next of the current revoked certificate in the list. One can also
   use the pointer arithmetic needed. */
SshX509RevokedCerts ssh_x509_revoked_get_next(SshX509RevokedCerts revoked);

/* Get the revoked certificate serial number. Must be present in
   valid revocation lists. */
Boolean ssh_x509_revoked_get_serial_number(SshX509RevokedCerts revoked,
                                           SshMPInteger s);
/* Get the revoked certificate revocation date. Must be present in
   valid revocation lists. */
Boolean ssh_x509_revoked_get_revocation_date(SshX509RevokedCerts revoked,
                                             SshBerTime when);
/* Get the certificate issuer associated with the revoked certificate entry. */
Boolean ssh_x509_revoked_get_certificate_issuer(SshX509RevokedCerts revoked,
                                                SshX509Name *names,
                                                Boolean *critical);
/* Get the reason code of the revoked certificate. */
Boolean ssh_x509_revoked_get_reason_code(SshX509RevokedCerts revoked,
                                         SshX509CRLReasonCode *reason_code,
                                         Boolean *critical);
/* Get the hold instruction code of the revoked certificate. Match the
   value to the defined OID's for the hold instruction code above. */
Boolean ssh_x509_revoked_get_hold_instruction_code(SshX509RevokedCerts revoked,
                                                   char **object_identifier,
                                                   Boolean *critical);
/* Get the invalidity date of the revoked certificate. */
Boolean ssh_x509_revoked_get_invalidity_date(SshX509RevokedCerts revoked,
                                             SshBerTime when,
                                             Boolean *critical);

/* X.509 names handling. */

/* Duplicates a name list. */
SshX509Name ssh_x509_name_copy(SshX509Name name);

/* Free a name list. */
void ssh_x509_name_free(SshX509Name name);

/* Useful routines for easy pushing and popping of specific names. */

/* The following routines make copies of the names, and thus you should
   free or whatever, after this call them yourself. */

/* Push an IP name to the list. */
Boolean ssh_x509_name_push_ip(SshX509Name *list,
                              const unsigned char *ip,
                              size_t ip_len);
/* Push a email name to the list. */
Boolean ssh_x509_name_push_email(SshX509Name *list, const char *email);
/* Push a DNS name to the list. */
Boolean ssh_x509_name_push_dns(SshX509Name *list, const char *dns);
/* Push a URI to the list. */
Boolean ssh_x509_name_push_uri(SshX509Name *list, const char *uri);
/* Push a RID to the list. */
Boolean ssh_x509_name_push_rid(SshX509Name *list, const char *rid);
/* Push a Principal Name to the list .*/
Boolean ssh_x509_name_push_principal_name_str(SshX509Name *list,
                                              const SshStr upn);
/* Push a Global Unique Identifier to the list. */
Boolean ssh_x509_name_push_guid(SshX509Name *list,
                                unsigned char *data, size_t len);
/* Push a Directory name to the list. */
Boolean ssh_x509_name_push_directory_name(SshX509Name *list,
                                          const unsigned char *dn);
/* Push a Directory name to the list. */
Boolean ssh_x509_name_push_directory_name_der(SshX509Name *list,
                                              const unsigned char *der,
                                              size_t der_len);
/* Push a Directory name to the list. */
Boolean ssh_x509_name_push_directory_name_str(SshX509Name *list,
                                              const SshStr str);

Boolean ssh_x509_name_push_unique_identifier(SshX509Name *list,
                                             const unsigned char *buf,
                                             size_t buf_len);

Boolean ssh_x509_name_push_ldap_dn(SshX509Name *list,
                                   const unsigned char *name);
Boolean ssh_x509_name_push_der_dn(SshX509Name *list,
                                  const unsigned char *der,
                                  size_t der_len);
Boolean ssh_x509_name_push_str_dn(SshX509Name *list, const SshStr str);

Boolean ssh_x509_name_push_other_name(SshX509Name *list,
                                      char **other_name_oid,
                                      unsigned char *der,
                                      size_t der_len);

/* The stack property of the name list is show in the popping phase.
   That is, you can pop a name out only once without "reset". The following
   function resets the name list, and allows you to run through all the
   names again. */
void ssh_x509_name_reset(SshX509Name list);

/* Following routines return TRUE if success (e.g. name found from the list),
   FALSE if not.

   Following routines make copies of the names for you. You need to
   free them with ssh_xfree.

   The names given are in ASCII, and usually are good for applications
   for display etc.
   */

/* Pop a IP name from the list. */
Boolean ssh_x509_name_pop_ip(SshX509Name list,
                             unsigned char **ip, size_t *ip_len);
/* Pop a email name from the list. */
Boolean ssh_x509_name_pop_email(SshX509Name list, char **email);
/* Pop a DNS name from the list. */
Boolean ssh_x509_name_pop_dns(SshX509Name list, char **dns);
/* Pop a URI name from the list. */
Boolean ssh_x509_name_pop_uri(SshX509Name list, char **uri);
/* Pop a RID name from the list. */
Boolean ssh_x509_name_pop_rid(SshX509Name list, char **rid);
/* Pop a Principal Name from the list. */
Boolean ssh_x509_name_pop_principal_name_str(SshX509Name list,
                                             SshStr *upn);
/* Pop a Global Unique Identifier from the list. */
Boolean ssh_x509_name_pop_guid(SshX509Name list,
                               unsigned char **data, size_t *len);
/* Pop a Directory name (LDAP encoded) from the list. */
Boolean ssh_x509_name_pop_directory_name(SshX509Name list, char **dn);
/* Pop a Directory name (ASN.1 DER encoded) from the list. */
Boolean ssh_x509_name_pop_directory_name_der(SshX509Name list,
                                             unsigned char **der,
                                             size_t *der_len);
/* Pop a Directory name (LDAP encoded SshStr struct) from the list. */
Boolean ssh_x509_name_pop_directory_name_str(SshX509Name list,
                                             SshStr *ret_str);

Boolean ssh_x509_name_pop_unique_identifier(SshX509Name list,
                                            unsigned char **buf,
                                            size_t *buf_len);

Boolean ssh_x509_name_pop_other_name(SshX509Name list,
                                     char **other_name_oid,
                                     unsigned char **der,
                                     size_t *der_len);

/* Special routines for cases where you have distinguished names in
   extensions. */
Boolean ssh_x509_name_pop_ldap_dn(SshX509Name list, char **ret_dn);
Boolean ssh_x509_name_pop_der_dn(SshX509Name list,
                                 unsigned char **der,
                                 size_t *der_len);
Boolean ssh_x509_name_pop_str_dn(SshX509Name list, SshStr *ret_str);

/* Pop one name entry out of the name list. */
SshX509Name ssh_x509_name_pop(SshX509Name *list);

/* This is O(n) algorithm for find an entry from the list. This is not
   efficient, however, currently it seems that the name lists will not
   be long. And they cannot be very long due to reasonable space
   limitations of the certificates.

   This can be used for example in the following way;

   url = NULL;
   name_uri = ssh_x509_name_find(name_list, SSH_X509_NAME_URI);
   if (name_uri != NULL)
     {
       ssh_x509_name_pop_uri(name_uri, &url);
       ssh_x509_name_reset(name_uri);
     }

   which implements name finding in O(1) time with the benefit of
   resetting the list after finding an URL.
*/
SshX509Name ssh_x509_name_find(SshX509Name list, SshX509NameType type);

/* Method for walking thru names on certificate. */
SshX509Name ssh_x509_name_enumerate_start(SshX509Name list);
SshX509Name ssh_x509_name_enumerate_next(SshX509Name list, SshX509Name cursor);

/***** Miscellaneous functions. */

/* Routine which maps the X.509 name type to SSH one. */
const char *ssh_x509_find_ssh_key_type(const char *name);

/* Matching routine for name,sign pair to a algorithm definition. One should
   use this only if the list, which is in x509.c, is familiar. */
const SshX509PkAlgorithmDefStruct *
ssh_x509_match_algorithm(const char *name, const char *sign, const char *dh);

/* Find the algorithm definition for the public key type. */
const SshX509PkAlgorithmDefStruct *
ssh_x509_public_key_algorithm(SshPublicKey key);

/* Same for private key. */
const SshX509PkAlgorithmDefStruct *
ssh_x509_private_key_algorithm(SshPrivateKey key);

/* Same for public key groups. */
const SshX509PkAlgorithmDefStruct *
ssh_x509_public_group_algorithm(SshPkGroup pk_group);

const char *ssh_x509_find_signature_algorithm(SshX509Certificate cert);

/* Set the private key type to the X.509 style signature algorithm. */
SshX509Status ssh_x509_private_key_set_sign_algorithm(SshPrivateKey key,
                                                      char *algorithm);

/* Private key encode and decode routines. */

/* Make a X.509 style private key blob. */
SshX509Status ssh_x509_encode_private_key(SshPrivateKey private_key,
                                          unsigned char **buf,
                                          size_t *buf_len);

/* Return a SSH private key from X.509 style private key blob.  */
SshPrivateKey ssh_x509_decode_private_key(const unsigned char *buf,
                                          size_t buf_len);

/* Public key decode from X.509 blob */
SshPublicKey ssh_x509_decode_public_key(const unsigned char *buf,
                                        size_t buf_len);

/* Encrypted value handing (from CRMF) */

SshX509EncryptedValue ssh_crmf_encrypted_value_allocate(void);
void ssh_crmf_encrypted_value_free(SshX509EncryptedValue value);

SshX509Status
ssh_crmf_decode_encrypted_value(const unsigned char *buf, size_t len,
                                SshX509EncryptedValue *value_return);

SshX509Status
ssh_crmf_encode_encrypted_value(const SshX509EncryptedValue value,
                                unsigned char **buf, size_t *buf_len);


/* Functions for setting controls. */
void
ssh_x509_cert_set_controls_nodes(SshX509Certificate c,
                                 SshX509ControlsNode nodes);

void
ssh_x509_control_push(SshX509ControlsNode *list,
                      SshX509ControlsNode node);

Boolean
ssh_x509_control_push_oldcert(SshX509ControlsNode *list,
                              SshX509Name issuer,
                              SshMPIntegerConst serial);

#endif /* X509_H */
