/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 payload-specific structures.
*/

#ifndef SSH_IKEV2_PAYLOADS_H
#define SSH_IKEV2_PAYLOADS_H

/**
   Set the maximum number of proposal per SA. This affect also
   IKEv1. Some implementations send many proposals for example for IKE
   SA. Only SSH_IKEV2_SA_MAX_PROPOSALS proposals are decoded and taken
   into account in the negotiation the rest are ignored. Value affects
   also size of SshIkev2PayloadSA structure.
*/
#ifndef SSH_IKEV2_SA_MAX_PROPOSALS
#define SSH_IKEV2_SA_MAX_PROPOSALS   20
#endif /* SSH_IKEV2_SA_MAX_PROPOSALS */

/** 2 octets unsigned integer */
#define SSH_IKEV2_MAX_PAYLOAD_SIZE 65535

/** Payload types. */
typedef enum {
  SSH_IKEV2_PAYLOAD_TYPE_NONE = 0,      /** Payload type: none. */
  SSH_IKEV2_PAYLOAD_TYPE_SA = 33, /** Payload type: Security Association.*/
  SSH_IKEV2_PAYLOAD_TYPE_KE = 34,       /** Payload type: Key Exchange. */
  SSH_IKEV2_PAYLOAD_TYPE_ID_I = 35,     /** Payload type: initiator ID. */
  SSH_IKEV2_PAYLOAD_TYPE_ID_R = 36,     /** Payload type: responder ID. */
  SSH_IKEV2_PAYLOAD_TYPE_CERT = 37,     /** Payload type: certificate. */
  /** Payload type: certifiqate request */
  SSH_IKEV2_PAYLOAD_TYPE_CERT_REQ = 38,
  SSH_IKEV2_PAYLOAD_TYPE_AUTH = 39,     /** Payload type: authentication. */
  SSH_IKEV2_PAYLOAD_TYPE_NONCE = 40,    /** Payload type: nonce.  */
  SSH_IKEV2_PAYLOAD_TYPE_NOTIFY = 41,   /** Payload type: notification. */
  SSH_IKEV2_PAYLOAD_TYPE_DELETE = 42,   /** Payload type: deletion. */
  SSH_IKEV2_PAYLOAD_TYPE_VID = 43,      /** Payload type: vendor ID. */
  /** Payload type: initiator's traffic selector. */
  SSH_IKEV2_PAYLOAD_TYPE_TS_I = 44,
  /** Payload type: responder's traffic selector. */
  SSH_IKEV2_PAYLOAD_TYPE_TS_R = 45,
  /** Payload type: encrypted content. */
  SSH_IKEV2_PAYLOAD_TYPE_ENCRYPTED = 46,
  SSH_IKEV2_PAYLOAD_TYPE_CONF = 47,     /** Payload type: configuration. */
  SSH_IKEV2_PAYLOAD_TYPE_EAP = 48       /** Payload type: EAP. */
} SshIkev2PayloadType;

/** Exchange types. */
typedef enum  {
  /** IKEv2 exchange: Security Association initialization. */
  SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT = 34,
  /** IKEv2 exchange: authentication. */
  SSH_IKEV2_EXCH_TYPE_IKE_AUTH = 35,
  /** IKEv2 exchange: creation of a child SA. */
  SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA = 36,
  /** IKEv2 exchange: informational. */
  SSH_IKEV2_EXCH_TYPE_INFORMATIONAL = 37
} SshIkev2ExchangeType;

/*--------------------------------------------------------------------*/
/** SA payload. This is reference counted and allocated using
    utility functions. None of the data is in obstack. */
/*--------------------------------------------------------------------*/

/** Protocol ID for IKEv2. */
typedef enum {
  SSH_IKEV2_PROTOCOL_ID_NONE = 0,       /** No protocol ID. */
  SSH_IKEV2_PROTOCOL_ID_IKE = 1,        /** IKE protocol. */
  SSH_IKEV2_PROTOCOL_ID_AH = 2,         /** Authentication Header. */
  /** Encapsulating Security Payload. */
  SSH_IKEV2_PROTOCOL_ID_ESP = 3
} SshIkev2ProtocolIdentifiers;

/** Transform type for IKEv2. */
typedef enum {
  SSH_IKEV2_TRANSFORM_TYPE_ENCR = 1,    /** IKE and ESP */
  SSH_IKEV2_TRANSFORM_TYPE_PRF = 2,     /** IKE */
  SSH_IKEV2_TRANSFORM_TYPE_INTEG = 3,   /** IKE, AH [and ESP] */
  SSH_IKEV2_TRANSFORM_TYPE_D_H = 4,     /** IKE, [AH and ESP] */
  SSH_IKEV2_TRANSFORM_TYPE_ESN = 5,     /** [AH and ESP] */
  SSH_IKEV2_TRANSFORM_TYPE_MAX = 6      /** IPComp */
} SshIkev2TransformType;

/** Transform IDs for IKEv2. */
typedef enum {
  /** Encryption Algorithm (ENCR) transform: DES IV64 */
  SSH_IKEV2_TRANSFORM_ENCR_DES_IV64 = 1,
  /** Encryption Algorithm (ENCR) transform: DES */
  SSH_IKEV2_TRANSFORM_ENCR_DES = 2,
  /** Encryption Algorithm (ENCR) transform: 3DES */
  SSH_IKEV2_TRANSFORM_ENCR_3DES = 3,
  /** Encryption Algorithm (ENCR) transform: RC5 */
  SSH_IKEV2_TRANSFORM_ENCR_RC5 = 4,
  /** Encryption Algorithm (ENCR) transform: IDEA */
  SSH_IKEV2_TRANSFORM_ENCR_IDEA = 5,
  /** Encryption Algorithm (ENCR) transform: CAST */
  SSH_IKEV2_TRANSFORM_ENCR_CAST = 6,
  /** Encryption Algorithm (ENCR) transform: Blowfish */
  SSH_IKEV2_TRANSFORM_ENCR_BLOWFISH = 7,
  /** Encryption Algorithm (ENCR) transform: 3IDEA */
  SSH_IKEV2_TRANSFORM_ENCR_3IDEA = 8,
  /** Encryption Algorithm (ENCR) transform: DES IV32 */
  SSH_IKEV2_TRANSFORM_ENCR_DES_IV32 = 9,
  /** Encryption Algorithm (ENCR) transform: null */
  SSH_IKEV2_TRANSFORM_ENCR_NULL = 11,
  /** Encryption Algorithm (ENCR) transform: AES CBC */
  SSH_IKEV2_TRANSFORM_ENCR_AES_CBC = 12,
  /** Encryption Algorithm (ENCR) transform: AES CTR */
  SSH_IKEV2_TRANSFORM_ENCR_AES_CTR = 13,
  /** Encryption Algorithm (ENCR) transform: AES CCM.
      Different identifiers for three possible
      ICV lengths (8, 12 and 16 octets). */
  SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8 = 14,
  SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12 = 15,
  SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16 = 16,
  /** Encryption Algorithm (ENCR) transform: AES GCM.
      Different identifiers for three possible
      ICV lengths (8, 12 and 16 octets). */
  SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8 = 18,
  SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12 = 19,
  SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16 = 20,

  /** Encryption Algorithm (ENCR) transform: AES GMAC.
      Notice: This only provides integrity, no confidentiality.
   */
  SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC = 21,

  /** Encryption Algorithm (ENCR) transform: Camellia */
  SSH_IKEV2_TRANSFORM_ENCR_CAMELLIA     = 1024,

  /** Pseudo-Random Function (PRF) transform: HMAC MD5 */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_MD5 = 1,
  /** Pseudo-Random Function (PRF) transform: HMAC SHA1 */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA1 = 2,
  /** Pseudo-Random Function (PRF) transform: HMAC Tiger */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_TIGER = 3,
  /** Pseudo-Random Function (PRF) transform: AES 128 CBC */
  SSH_IKEV2_TRANSFORM_PRF_AES128_CBC = 4,
  /** Pseudo-Random Function (PRF) transform: HMAC SHA256 */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA256 = 5,
  /** Pseudo-Random Function (PRF) transform: HMAC SHA384 */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA384 = 6,
  /** Pseudo-Random Function (PRF) transform: HMAC SHA512 */
  SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA512 = 7,

  /** Integrity algorithm (INTEG) transform: none */
  SSH_IKEV2_TRANSFORM_AUTH_NONE = 0,
  /** Integrity algorithm (INTEG) transform: HMAC MD5 96*/
  SSH_IKEV2_TRANSFORM_AUTH_HMAC_MD5_96 = 1,
  /** Integrity algorithm (INTEG) transform: HMAC SHA1 96 */
  SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96 = 2,
  /** Integrity algorithm (INTEG) transform: AUTH DES MAC*/
  SSH_IKEV2_TRANSFORM_AUTH_DES_MAC = 3,
  /** Integrity algorithm (INTEG) transform: AUTH KPDK MD5 */
  SSH_IKEV2_TRANSFORM_AUTH_KPDK_MD5 = 4,
  /** Integrity algorithm (INTEG) transform: AUTH AES XCBC 96 */
  SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96 = 5,
  /** Integrity algorithm (INTEG) transform: AUTH AES GMAC */
  SSH_IKEV2_TRANSFORM_AUTH_AES_128_GMAC_128 = 9,
  SSH_IKEV2_TRANSFORM_AUTH_AES_192_GMAC_128 = 10,
  SSH_IKEV2_TRANSFORM_AUTH_AES_256_GMAC_128 = 11,
  /** Integrity algorithm (INTEG) transform: HMAC SHA256 128 */
  SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128 = 12,
  /** Integrity algorithm (INTEG) transform: HMAC SHA384 192 */
  SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192 = 13,
  /** Integrity algorithm (INTEG) transform: HMAC SHA512 256 */
  SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256 = 14,

  /** Diffie-Hellman Group transform: none */
  SSH_IKEV2_TRANSFORM_D_H_NONE = 0,
  /** Diffie-Hellman Group transform: MODP 768 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_768 = 1,
  /** Diffie-Hellman Group transform: MODP 1024 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_1024 = 2,
  /** Diffie-Hellman Group transform: EC2N 155 */
  SSH_IKEV2_TRANSFORM_D_H_EC2N_155 = 3,
  /** Diffie-Hellman Group transform: EC2N 185 */
  SSH_IKEV2_TRANSFORM_D_H_EC2N_185 = 4,
  /** Diffie-Hellman Group transform: MODP 1536 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_1536 = 5,
  /** Diffie-Hellman Group transform: MODP 2048 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_2048 = 14,
  /** Diffie-Hellman Group transform: MODP 3072 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_3072 = 15,
  /** Diffie-Hellman Group transform: MODP 4096 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_4096 = 16,
  /** Diffie-Hellman Group transform: MODP 6144 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_6144 = 17,
  /** Diffie-Hellman Group transform: MODP 8192 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_8192 = 18,
  /** Diffie-Hellman Group transform: EC-MODP 256 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_256 = 19,
  /** Diffie-Hellman Group transform: EC-MODP 384 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_384 = 20,
  /** Diffie-Hellman Group transform: EC-MODP 521 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_521 = 21,
  /** Diffie-Hellman RFC5114 Group transform: MODP 1024-160 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_1024_160 = 22,
  /** Diffie-Hellman RFC5114 Group transform: MODP 2048-224 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_2048_224 = 23,
  /** Diffie-Hellman RFC5114 Group transform: MODP 2048-256 */
  SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_2048_256 = 24,
  /** Diffie-Hellman RFC5114 Group transform: EC-MODP 192 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC5114_192 = 25,
  /** Diffie-Hellman RFC5114 Group transform: EC-MODP 224 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC5114_224 = 26,
  /** Diffie-Hellman RFC6932 Group transform: EC-MODP 224, only for IKEv2 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_224 = 27,
  /** Diffie-Hellman RFC6932 Group transform: EC-MODP 256, only for IKEv2 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_256 = 28,
  /** Diffie-Hellman RFC6932 Group transform: EC-MODP 384, only for IKEv2 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_384 = 29,
  /** Diffie-Hellman RFC6932 Group transform: EC-MODP 512, only for IKEv2 */
  SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_512 = 30,
  /** Diffie-Hellman Group transform: maximum */
  SSH_IKEV2_TRANSFORM_D_H_MAX = 31,

  /** Extended Sequence Numbers (ESN) not used */
  SSH_IKEV2_TRANSFORM_ESN_NO_ESN = 0,
  /** Extended Sequence Numbers (ESN) used */
  SSH_IKEV2_TRANSFORM_ESN_ESN = 1
} SshIkev2TransformID;

/** Transforms. */
typedef struct SshIkev2PayloadTransformRec {
  SshIkev2TransformType type;   /** Transform ID type. */
  SshIkev2TransformID id;       /** Transform ID. */
  SshUInt32 transform_attribute;  /** Attribute associated
     with the transform - currently only
     one attribute is defined, and that is the key length for
     the variable-length ciphers (this field is the full TV
     format value of the transform attribute, meaning that the most
     significant bit must be set and the top 15 bits after
     that bit specify the type, and the lower 16 bits specify the
     value); for key length attributes this is always (0x800e
     << 16) | actual_key_length. */
} *SshIkev2PayloadTransform, SshIkev2PayloadTransformStruct;


/** SA payload. An SA payload contains a list of transforms.
   Transforms are grouped to proposals, so that each transform
   having the same proposal number belong to the same proposal. For
   each proposal there can be multiple transforms with the same
   type, and the responder selects one of those transforms
   with the same type, and it must select exactly one transform
   per each type. Each SA is for one specific protocol (IKE,
   AH or ESP). */
typedef struct SshIkev2PayloadSARec {
  /** Free list ADT header. */
  SshADTListHeaderStruct free_list_header;

  /** The proposal number of the incoming SA reply, only
      used internally when processing (or generating) SAr
      packets from the responder - they must contain only
      one proposal, but the proposal number can be anything;
      this is NOT an index to the ipsec_spis / protocol_id /
      number_of_transforms / proposals array, but this is
      the index + 1 (proposal numbers start from 1). */
  SshUInt8 proposal_number;

  /** SPIs for the proposal - this is only filled in on the
      incoming SA payload; for the outgoing SA payloads, SPIs
      are taken from the SshIkev2Sa and SshIkev2IPsecSa
      structures. */
  union SshIkev2PayloadSASPIUnion {
    /** Remote SPIs for the proposals. */
    SshUInt32 ipsec_spis[SSH_IKEV2_SA_MAX_PROPOSALS];
    /** There can be only IKE SPI, in the rekeying case. */
    unsigned char ike_spi[8];
  } spis;
  size_t spi_len;       /** SPI length. */

  /** Protocol identifier for proposals - if this is 0, then
      no proposal. */
  SshIkev2ProtocolIdentifiers protocol_id[SSH_IKEV2_SA_MAX_PROPOSALS];
  /** The number of transforms inside each proposal. */
  SshUInt32 number_of_transforms[SSH_IKEV2_SA_MAX_PROPOSALS];
  /** Pointer to the first transform of that proposal - this
      is a direct pointer to the transforms array. */
  SshIkev2PayloadTransform proposals[SSH_IKEV2_SA_MAX_PROPOSALS];

  /** Transforms for this SA - each transform has a
      proposal_number value which is a number starting from 1 and
      incrementing by one for each new proposal. */
  SshIkev2PayloadTransform transforms;
  /** Number of allocated transforms. */
  SshUInt32 number_of_transforms_allocated;
  /** Number of used transforms. */
  SshUInt32 number_of_transforms_used;

  /** Reference count of this object. */
  int ref_cnt;
} *SshIkev2PayloadSA, SshIkev2PayloadSAStruct;


/*--------------------------------------------------------------------*/
/**
  Key exchange payload. This structure is allocated from
  obstack, and the key exchange data pointed by this
  structure is also allocated from obstack.
*/
typedef struct SshIkev2PayloadKERec {
  SshUInt32 dh_group;           /** Diffie-Hellman group. */
  size_t key_exchange_len;      /** Key exchange length. */
  /** Key exchange data - allocated from obstack. */
  void *key_exchange_data;
} *SshIkev2PayloadKE, SshIkev2PayloadKEStruct;

/*--------------------------------------------------------------------*/
/**
  Identification payload. This structure is allocated from
  the obstack, and the identification data pointed by this
  structure is also allocated from obstack.
*/
typedef enum {
  /** Identification payload ID type: IPv4 address. */
  SSH_IKEV2_ID_TYPE_IPV4_ADDR   = 1,
  /** Identification payload ID type: Fully Qualified Domain Name. */
  SSH_IKEV2_ID_TYPE_FQDN        = 2,
  /** Identification payload ID type: RFC #822 compliant address. */
  SSH_IKEV2_ID_TYPE_RFC822_ADDR = 3,
  /** Identification payload ID type: IPv6 address. */
  SSH_IKEV2_ID_TYPE_IPV6_ADDR   = 5,
  /** Identification payload ID type: ASN.1 X.500 Distinguished Name
      [X.501]. */
  SSH_IKEV2_ID_TYPE_ASN1_DN     = 9,
  /** Identification payload ID type: ASN.1 X.500 General Name
      [X.509]. */
  SSH_IKEV2_ID_TYPE_ASN1_GN     = 10,
  /** Identification payload ID type: key ID. */
  SSH_IKEV2_ID_TYPE_KEY_ID      = 11
} SshIkev2IDType;

/** Identification payload. */
typedef struct SshIkev2PayloadIDRec {
  SshIkev2IDType id_type;       /** ID type. */
  size_t id_data_size;          /** This must always be valid, even for
                                   IPV4_ADDR etc types.  */
  unsigned char *id_data;       /** ID data - allocated from obstack. */
  SshUInt32 id_reserved;       /** Value of the RESERVED field of ID */
} *SshIkev2PayloadID, SshIkev2PayloadIDStruct;


#ifdef SSHDIST_IKE_CERT_AUTH
/*--------------------------------------------------------------------*/
/**
  Certificate payload. This structure is allocated from
  obstack, and the certificate data pointed by this
  structure is also allocated from obstack.
*/
/** Certificate encoding types, used by both the certificate
   payload and the certificate request payload. */
typedef enum {
  /** Certificate encoding type: PKCS #7 wrapper X.509. */
  SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509    = 1,
  /** Certificate encoding type: Pretty Good Privacy (PGP). */
  SSH_IKEV2_CERT_PGP                    = 2,
  /** Certificate encoding type: DNS signed key. */
  SSH_IKEV2_CERT_DNS_SIGNED_KEY         = 3,
  /** Certificate encoding type: X.509. */
  SSH_IKEV2_CERT_X_509                  = 4,
  /** Certificate encoding type: Kerberos token. */
  SSH_IKEV2_CERT_KERBEROS_TOKEN         = 6,
  /** Certificate encoding type: Certificate Revocation List (CRL). */
  SSH_IKEV2_CERT_CRL                    = 7,
  /** Certificate encoding type: Authority Revocation List (ARL). */
  SSH_IKEV2_CERT_ARL                    = 8,
  /** Certificate encoding type: Simple public key infrastructure
      (SPKI). */
  SSH_IKEV2_CERT_SPKI                   = 9,
  /** Certificate encoding type: X.509 attribute. */
  SSH_IKEV2_CERT_X_509_ATTRIBUTE        = 10,
  /** Certificate encoding type: RSA key. */
  SSH_IKEV2_CERT_RAW_RSA_KEY            = 11,
  /** Certificate encoding type: hash and URL X.509. */
  SSH_IKEV2_CERT_HASH_AND_URL_X509      = 12,
  /** Certificate encoding type: hash and URL X.509 bundle. */
  SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE= 13
} SshIkev2CertEncoding;

/** Certificate payload. */
typedef struct SshIkev2PayloadCertRec {
  SshIkev2CertEncoding cert_encoding;   /** Certificate encoding. */
  size_t cert_size;                     /** Certificate size. */
  /** Certificate data - allocated from obstack */
  unsigned char *cert_data;
} *SshIkev2PayloadCert, SshIkev2PayloadCertStruct;

/*--------------------------------------------------------------------*/
/**
  Certificate request payload. This structure is allocated
  from obstack, and the certificate authority data
  pointed by this structure is also allocated from obstack.
*/
typedef struct SshIkev2PayloadCertReqRec {
  /** Certificate encoding. */
  SshIkev2CertEncoding cert_encoding;
  /** Authority size. */
  size_t authority_size;
  /** Authority data - allocated from obstack. */
  unsigned char *authority_data;
} *SshIkev2PayloadCertReq, SshIkev2PayloadCertReqStruct;
#endif /* SSHDIST_IKE_CERT_AUTH */


/*--------------------------------------------------------------------*/
/**
  Authentication payload. This structure is allocated from
  obstack, and the authentication data pointed by this
  structure is also allocated from obstack.
*/
typedef enum {
  /** Authentication method: RSA signature. */
  SSH_IKEV2_AUTH_METHOD_RSA_SIG         = 1,
  /** Authentication method: shared key. */
  SSH_IKEV2_AUTH_METHOD_SHARED_KEY      = 2,
  /** Authentication method: DSS signature. */
  SSH_IKEV2_AUTH_METHOD_DSS_SIG         = 3

#ifdef SSHDIST_CRYPT_ECP
  , SSH_IKEV2_AUTH_METHOD_ECP_DSA_256   = 9
  , SSH_IKEV2_AUTH_METHOD_ECP_DSA_384   = 10
  , SSH_IKEV2_AUTH_METHOD_ECP_DSA_521   = 11
#endif /* SSHDIST_CRYPT_ECP  */

} SshIkev2AuthMethod;

/** Authentication payload. */
typedef struct SshIkev2PayloadAuthRec {
  SshIkev2AuthMethod auth_method;       /** Authentication method. */
  size_t authentication_size;           /** Authentication size. */
  /** Authentication data - allocated from obstack. */
  unsigned char *authentication_data;
} *SshIkev2PayloadAuth, SshIkev2PayloadAuthStruct;


/*--------------------------------------------------------------------*/
/**
  Nonce payload. This structure is allocated from the
  obstack, and the nonce data pointed by this structure is
  also allocated from obstack.
*/
typedef struct SshIkev2PayloadNonceRec {
  size_t nonce_size;            /** Nonce size. */
  /** Nonce data - allocated from obstack. */
  unsigned char *nonce_data;
} *SshIkev2PayloadNonce, SshIkev2PayloadNonceStruct;

/** The size of the nonce payload we are sending. */
#define SSH_IKEV2_NONCE_SIZE 32

/*--------------------------------------------------------------------*/
/**
  Notify payload. This structure is allocated from
  obstack, and the SPI and notification data pointed by this
  structure is also allocated from obstack.

  Notify message types are the following:
  * Informal => can be sent as a separate informational exchange.
  * policymanager => Policy Manager should take care of handling this.
  * IKE => IKE library will handle this internally.
  * Fail exchange => Current exchange is failed, but the IKE SA is valid.
  * Fatal, delete IKE SA => Fatal error, current IKE SA is deleted.

*/
typedef enum {
  SSH_IKEV2_NOTIFY_RESERVED                     = 0, /** Reserved. */
  SSH_IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD = 1, /** Fail exchange */
  SSH_IKEV2_NOTIFY_INVALID_IKE_SPI              = 4, /** Fatal, delete SA */
  SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION        = 5, /** Fatal, delete SA */
  SSH_IKEV2_NOTIFY_INVALID_SYNTAX               = 7, /** Fatal, delete SA */
  SSH_IKEV2_NOTIFY_INVALID_MESSAGE_ID           = 9, /** Informal */
  SSH_IKEV2_NOTIFY_INVALID_SPI                  = 11,/** Informal,
                                                         Policy Manager */
  SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN           = 14,/** Fail exchange */
  SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD           = 17,/** IKE */
  SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED        = 24,/** Fatal, delete SA */
  SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED         = 34,/** Fail exchange */
  SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS            = 35,/** Fail exchange */
  SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE     = 36,/** Fail exchange */
  SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED           = 37,/** Fail exchange */
  SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE              = 38,/** Fail exchange */
  SSH_IKEV2_NOTIFY_INVALID_SELECTORS            = 39,/** Informal,
                                                         Policy Manager*/
  SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS         = 40, /** Fail exchange */
  SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED      = 41, /** Fail exchange */

  SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE            = 43, /** Informal */
  SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND           = 44, /** Informal */
  SSH_IKEV2_NOTIFY_INITIAL_CONTACT              = 16384, /** Informal,
                                                             Policy Manager */
  SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE              = 16385, /** Informal,
                                                            IKE */
  SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE       = 16386, /** Policy Manager */
  SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED             = 16387, /** Policy Manager */
  SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP      = 16388, /** IKE */
  SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389, /** IKE */
  SSH_IKEV2_NOTIFY_COOKIE                       = 16390, /** IKE */
  SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE           = 16391, /** Policy Manager */
  SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED   = 16392, /** Policy Manager */
  SSH_IKEV2_NOTIFY_REKEY_SA                     = 16393, /** IKE */
  SSH_IKEV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED= 16394, /** Policy Manager */
  SSH_IKEV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO     = 16395, /** Policy Manager */
  SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED             = 16396, /** IKE */
  SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS       = 16397, /** IKE */
  SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS       = 16398, /** IKE */
  SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES      = 16399, /** IKE */
  SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES          = 16400, /** Policy Manager */
  SSH_IKEV2_NOTIFY_COOKIE2                      = 16401, /** IKE */
  SSH_IKEV2_NOTIFY_NO_NATS_ALLOWED              = 16402, /** IKE */
  SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED      = 16404, /** IKE */
  SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS         = 16405, /** IKE */
#ifdef SSHDIST_IKE_REDIRECT
  SSH_IKEV2_NOTIFY_REDIRECT_SUPPORTED           = 16406, /** IKE */
  SSH_IKEV2_NOTIFY_REDIRECT                     = 16407, /** IKE */
  SSH_IKEV2_NOTIFY_REDIRECTED_FROM              = 16408, /** IKE */
#endif /* SSHDIST_IKE_REDIRECT */
  SSH_IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION      = 16417, /** Policy Manager */
  SSH_IKEV2_NOTIFY_FRAGMENTATION_SUPPORTED      = 16430  /** Policy Manager */
} SshIkev2NotifyMessageType;

/** Maximum window size we promise to keep. Window size set for larger
    value is considered as an fatal error. */
#define SSH_IKEV2_MAX_WINDOW_SIZE   32

/** IPComp algorithms. */
typedef enum {
  SSH_IKEV2_IPCOMP_OUI          = 1,    /** IPComp algorithm: OUI. */
  SSH_IKEV2_IPCOMP_DEFLATE      = 2,    /** IPComp algorithm: deflate. */
  SSH_IKEV2_IPCOMP_LZS          = 3,    /** IPComp algorithm: LZS. */
  SSH_IKEV2_IPCOMP_LZJH         = 4     /** IPComp algorithm: LZJH. */
} SshIkev2IPCompTypes;

/** Notification payload. */
typedef struct SshIkev2PayloadNotifyRec
{
  /** Protocol. */
  SshIkev2ProtocolIdentifiers protocol;
  /** Notify message type. */
  SshIkev2NotifyMessageType notify_message_type;
  /** Authentication status. */
  Boolean authenticated;
  /** SPI size. */
  size_t spi_size;
  /** SPI data - allocated from obstack. */
  unsigned char *spi_data;
  /** Notification size. */
  size_t notification_size;
  /** Notification data - allocated from obstack. */
  unsigned char *notification_data;
  /** Pointer to the next notify payload. */
  struct SshIkev2PayloadNotifyRec *next_notify;
} *SshIkev2PayloadNotify, SshIkev2PayloadNotifyStruct;


/*--------------------------------------------------------------------*/
/**
  Delete payload. This structure is allocated from
  obstack, and the SPI table pointed by this structure is
  also allocated from obstack.
*/
typedef struct SshIkev2PayloadDeleteRec {
  SshIkev2ProtocolIdentifiers protocol;         /** Protocol. */
  size_t spi_size;                              /** SPI size. */
  SshUInt16 number_of_spis;                     /** Number of SPIs. */
  union {
    /** Allocated from obstack or ike_sa->ike_spi_* */
    unsigned char *spi_table;
    /** In case spi_size == 4, note this is in host byte order. */
    SshUInt32 *spi_array;
  } spi;
  /** Pointer to the next delete payload. */
  struct SshIkev2PayloadDeleteRec *next_delete;
} *SshIkev2PayloadDelete, SshIkev2PayloadDeleteStruct;


/*--------------------------------------------------------------------*/
/**
  Vendor ID payload. This structure is allocated from
  obstack, and the vendor ID pointed by this structure is
  also allocated from obstack.
*/
typedef struct SshIkev2PayloadVendorIDRec
{
  /** VID data length in octets. */
  size_t vendorid_size;
  /** VID data value - allocated from obstack. */
  unsigned char *vendorid_data;
  /** Pointer to the next vendor ID payload.  */
  struct SshIkev2PayloadVendorIDRec *next_vid;
} *SshIkev2PayloadVendorID, SshIkev2PayloadVendorIDStruct;


/*--------------------------------------------------------------------*/
/**
  Traffic selector payload. This is reference counted and
  allocated using util functions, none of the data is in
  obstack.
*/
/** Traffic selector types. */
typedef enum {
  SSH_IKEV2_TS_IPV4_ADDR_RANGE          = 7,    /** IPv4 address range. */
  SSH_IKEV2_TS_IPV6_ADDR_RANGE          = 8     /** IPv6 address range. */
} SshIkev2TSType;

/** Traffic selector item structure. */
typedef struct SshIkev2PayloadTSItemRec {
  SshIkev2TSType ts_type;               /** Traffic selector type. */
  SshInetIPProtocolID proto;            /** Protocol. */
  SshIpAddrStruct start_address[1];     /** Start address of a range. */
  SshIpAddrStruct end_address[1];       /** End address of a range. */
  SshUInt16 start_port;                 /** Start port of a range. */
  SshUInt16 end_port;                   /** End port of a range. */
} *SshIkev2PayloadTSItem, SshIkev2PayloadTSItemStruct;

/** Traffic selector structure. */
typedef struct SshIkev2PayloadTSRec {
  /** Free list ADT header. */
  SshADTListHeaderStruct free_list_header;

  /** Allocated array of items. */
  SshIkev2PayloadTSItem items;

  /** The number of items allocated. */
  SshUInt32 number_of_items_allocated;
  /** The number of items actually in use. */
  SshUInt32 number_of_items_used;

  /** Reference count of this object. */
  int ref_cnt;
} *SshIkev2PayloadTS, SshIkev2PayloadTSStruct;


/*--------------------------------------------------------------------*/
/**
  Configuration payload. This is reference counted and
  allocated using util functions, none of the data is in
  obstack.
*/
/** Configuration payload type. */
typedef enum {
  SSH_IKEV2_CFG_REQUEST         = 1,    /** Configuration request. */
  SSH_IKEV2_CFG_REPLY           = 2,    /** Configuration reply. */
  SSH_IKEV2_CFG_SET             = 3,    /** Not used. */
  SSH_IKEV2_CFG_ACK             = 4     /** Not used. */
} SshIkev2ConfType;

/** The preallocated attribute value size.  If attribute length
    is longer than this the attribute is stored in dynamically
    allocated buffer.

    Normal IKEv2 attributes are at maximum 17 bytes long
    (INTERNAL_IP6_ADDRESS).

    There are 2 variable length IKEv2 attributes:

    The SUPPORTED_ATTRIBUTES could be 28 bytes long, as we have
    14 IKEv2 attributes now.

    The APPLICATION_VERSION can be any length.

    So by allocating 32 bytes for each attribute we should
    have enough preallocated space.

    Some proprietary IKEv1 attributes may be variable length. */
#define SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE 32

/** Configuration payload attributes. */
typedef enum {
  /** Configuration payload: IPv4 address. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS          = 1,
  /** Configuration payload: IPv4 netmask. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK          = 2,
  /** Configuration payload: IPv4 Domain Name Service. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS              = 3,
  /** Configuration payload: IPv4 NetBios Name Service. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS             = 4,
  /** Configuration payload: address expiry. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY       = 5,
  /** Configuration payload: IPv4 Dynamic Host Configuration Protocol. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP             = 6,
  /** Configuration payload: Application version. */
  SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION           = 7,
  /** Configuration payload: IPv6 address. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS          = 8,
  /** Configuration payload: IPv6 Domain Name Service. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS              = 10,
  /** Configuration payload: IPv6 NetBios Name Service. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS             = 11,
  /** Configuration payload: IPv6 Dynamic Host Configuration Protocol. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP             = 12,
  /** Configuration payload: IPv4 subnet. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET           = 13,
  /** Configuration payload: Supported attributes. */
  SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES          = 14,
  /** Configuration payload: IPv6 subnet. */
  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET           = 15,
  /** Cisco UNITY banner PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BANNER            = 28672,
  /** Cisco UNITY save password PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SAVE_PASSWD       = 28673,
  /** Cisco UNITY default domain PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DEFAULT_DOMAIN    = 28674,
  /** Cisco UNITY split DNS name PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_DNS_NAME    = 28675,
  /** Cisco UNITY split network include PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_NET_INCLUDE = 28676,
  /** Cisco UNITY NAT-T port PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_NATT_PORT         = 28677,
  /** Cisco UNITY Local LAN PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_LOCAL_LAN         = 28678,
  /** Cisco UNITY PFS PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_PFS               = 28679,
  /** Cisco UNITY FW type PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_FW_TYPE           = 28680,
  /** Cisco UNITY backup servers PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BACKUP_SERVERS    = 28681,
  /** Cisco UNITY DDNS hostname PRIVATE ATTRIBUTE */
  SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DDNS_HOSTNAME     = 28682
} SshIkev2ConfAttributeType;

/** Configuration payload attribute. */
typedef struct SshIkev2ConfAttributeRec {
  SshIkev2ConfAttributeType attribute_type;     /** Attribute type. */
  size_t length;                                /** Attribute length. */
  unsigned char *value;

  /** We allocate a fixed-size space for the attribute.  */
  unsigned char buffer[SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE];

  /** Attributes that do not fit into static buffer are
      memdup'ed here. */
  unsigned char *dynamic_buffer;
} *SshIkev2ConfAttribute, SshIkev2ConfAttributeStruct;

/** Configuration structure. */
typedef struct SshIkev2PayloadConfRec {
  /** Free list ADT header. */
  SshADTListHeaderStruct free_list_header;

  /** Type of the configuration payload. */
  SshIkev2ConfType conf_type;

  /** Allocated array of items. */
  SshIkev2ConfAttribute conf_attributes;
  /** The number of items allocated. */
  SshUInt32 number_of_conf_attributes_allocated;
  /** The number of items actually in use. */
  SshUInt32 number_of_conf_attributes_used;
  /** The reference count of this object. */
  int ref_cnt;
} *SshIkev2PayloadConf, SshIkev2PayloadConfStruct;


#ifdef SSHDIST_IKE_EAP_AUTH
/*--------------------------------------------------------------------*/
/**
  EAP payload. This structure is allocated from obstack,
  and the EAP data pointed by this structure is also
  allocated from obstack.
*/
typedef struct SshIkev2PayloadEapRec {
  size_t eap_size;      /** EAP size. */
  /** EAP data - allocated from obstack. */
  unsigned char *eap_data;
} *SshIkev2PayloadEap, SshIkev2PayloadEapStruct;
#endif /* SSHDIST_IKE_EAP_AUTH */

#endif /* SSH_IKEV2_PAYLOADS_H */
