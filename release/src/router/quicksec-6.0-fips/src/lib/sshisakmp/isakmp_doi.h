/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Doi specific defines etc.
*/

#ifndef ISAKMP_DOI_H
#define ISAKMP_DOI_H

#include "sshmp.h"
#include "sshinet.h"

#ifndef ISAKMP_H
/* Global isakmp context structure. Common data for all isakmp functions */
typedef struct SshIkeContextRec *SshIkeContext;
/* Isakmp SA used for isakmp message encryption etc */
typedef struct SshIkeSARec *SshIkeSA;
/* Isakmp or ipsec negotiation struct/union */
typedef struct SshIkeNegotiationRec *SshIkeNegotiation;
/* Isakmp packet */
typedef struct SshIkePacketRec *SshIkePacket;
/* Generic isakmp payload packet */
typedef struct SshIkePayloadRec *SshIkePayload;
#endif /* ISAKMP_H */

/*                                                              shade{0.9}
 *
 * Isakmp & oakley data structures
 *                                                              shade{1.0}
 */

/* Doi = draft-ietf-ipsec-ipsec-doi-03,04,05,06,07,08,09,10.txt */
/* Isakmp = draft-ietf-ipsec-isakmp-08,09,10.txt */
/* Oakley = draft-ietf-ipsec-oakley-02.txt */
/* ike = draft-ietf-ipsec-isakmp-oakley-04,05,06,07,08.txt */
/* revised-enc = draft-ietf-ipsec-revised-enc-mode-00,01.txt */
/* isakmp-cfg = draft-ietf-ipsec-isakmp-mode-cfg-00,01,02,03,04.txt */
/* isakmp-xauth = draft-ietf-ipsec-isakmp-xauth-02.txt */

/* Major and minor version numbers of isakmp */
#define SSH_IKE_MAJOR_VERSION 1
#define SSH_IKE_MINOR_VERSION 0

/* Domain of interpretation (from doi) */
typedef enum {
  SSH_IKE_DOI_RESERVED = 0,     /* Reserved */
  SSH_IKE_DOI_IPSEC = 1         /* IP Security */
} SshIkeDOI;

/* Situation bitmask values (32 bits) (from doi) */
#define SSH_IKE_SIT_IDENTITY_ONLY       0x01
#define SSH_IKE_SIT_SECRECY             0x02
#define SSH_IKE_SIT_INTEGRITY           0x04

/* Isakmp protocol identifiers (from doi) */
typedef enum {
  SSH_IKE_PROTOCOL_RESERVED     = 0,
  SSH_IKE_PROTOCOL_ISAKMP       = 1, /* MUST */
  SSH_IKE_PROTOCOL_IPSEC_AH     = 2,
  SSH_IKE_PROTOCOL_IPSEC_ESP    = 3,
  SSH_IKE_PROTOCOL_IPCOMP       = 4
} SshIkeProtocolIdentifiers;

/* Isakmp isakmp protocol transform identifiers (from doi) */
typedef enum {
  SSH_IKE_ISAKMP_TRANSFORM_KEY_RESERVED = 0,
  SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE      = 1 /* MUST */
#ifdef REMOVED_BY_DOI_DRAFT_04
  , SSH_IKE_ISAKMP_TRANSFORM_KEY_MANUAL = 2,
  SSH_IKE_ISAKMP_TRANSFORM_KEY_KDC      = 3
#endif
} SshIkeIsakmpTransformIdentifiers;

/* Isakmp ipsec ah protocol transform identifiers (from doi) */
typedef enum {
  /* SSH_IKE_IPSEC_AH_TRANSFORM_AH_RESERVED     = 0, */
#ifdef REMOVED_BY_DOI_DRAFT_05
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_MD5_KPDK        = 1,
#endif
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_MD5      = 2, /* MUST (hmac-md5) */
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA      = 3,
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_DES      = 4, /* (from doi 04) */
  /* Next three from draft-kelly-ipsec-ciph-sha2-01 */
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_256 = 5,
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_384 = 6,
  SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_512 = 7
#ifdef SSHDIST_CRYPT_XCBCMAC
  , SSH_IKE_IPSEC_AH_TRANSFORM_AH_XCBC_AES = 9
#endif /* SSHDIST_CRYPT_XCBCMAC */
#ifdef SSHDIST_CRYPT_MODE_GCM
  , SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_128_GMAC = 11 /* RFC 4543 */
  , SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_192_GMAC = 12 /* RFC 4543 */
  , SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_256_GMAC = 13 /* RFC 4543 */
#endif /* SSHDIST_CRYPT_MODE_GCM */
} SshIkeIpsecAHTransformIdentifiers;

/* Isakmp ipsec esp protocol transform identifiers (from doi) */
typedef enum {
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RESERVED      = 0,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV64      = 1,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES           = 2, /* MUST (+hmac-md5) */
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3DES          = 3,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC5           = 4,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_IDEA          = 5,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAST          = 6,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH      = 7,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3IDEA         = 8,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV32      = 9,
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC4           = 10, /* (from doi 04, renamed
                                                         in 07) */
  SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL          = 11 /* (from doi, renumberd
                                                         in doi 08) */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES          = 12 /* IANA */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CTR      = 13 /* RFC 3686 */

#ifdef SSHDIST_CRYPT_MODE_CCM
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_8    = 14 /* RFC 4309 */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_12   = 15 /* RFC 4309 */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_16   = 16 /* RFC 4309 */
#endif /* SSHDIST_CRYPT_MODE_CCM */

#ifdef SSHDIST_CRYPT_MODE_GCM
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_8    = 18 /* RFC 4106 */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_12   = 19 /* RFC 4106 */
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_16   = 20 /* RFC 4106 */
#endif /* SSHDIST_CRYPT_MODE_GCM */

  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAMELLIA     = 22 /* RFC 4312 */

#ifdef SSHDIST_CRYPT_MODE_GCM
  ,SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL_AUTH_AES_GMAC = 23 /* RFC 4543 */
#endif /* SSHDIST_CRYPT_MODE_GCM */
} SshIkeIpsecESPTransformIdentifiers;

/* Isakmp ipcomp compression transform identifiers (from doi) */
typedef enum {
  SSH_IKE_IPCOMP_TRANSFORM_RESERVED     = 0,
  SSH_IKE_IPCOMP_TRANSFORM_OUI          = 1,
  SSH_IKE_IPCOMP_TRANSFORM_DEFLAT       = 2,
  SSH_IKE_IPCOMP_TRANSFORM_LZS          = 3,
  SSH_IKE_IPCOMP_TRANSFORM_V42BIS       = 4
} SshIkeIpcompTransformIdentifiers;

/* Isakmp generic transform identifiers (from doi) */
typedef union SshIkeTransformIdentifiersUnion {
  int generic;                  /* Generic identifier */
  SshIkeIsakmpTransformIdentifiers isakmp;
  SshIkeIpsecAHTransformIdentifiers ipsec_ah;
  SshIkeIpsecESPTransformIdentifiers ipsec_esp;
  SshIkeIpcompTransformIdentifiers ipcomp;
} *SshIkeTransformIdentifiers;

/* Ipsec attribute Classes (from doi) */
/* B = basic, V = Variable */
typedef enum {
  IPSEC_CLASSES_SA_LIFE_TYPE            = 1, /* SA life type (B) MUST */
  IPSEC_CLASSES_SA_LIFE_DURATION        = 2, /* SA life duration (B/V) MUST */
  IPSEC_CLASSES_GRP_DESC                = 3, /* Group description (B) */
  IPSEC_CLASSES_ENCAPSULATION_MODE      = 4, /* Encapsulation mode (B) */
  IPSEC_CLASSES_AUTH_ALGORITHM          = 5, /* Auth algorithm (B) MUST */
  IPSEC_CLASSES_KEY_LENGTH              = 6, /* Key length (B) */
  IPSEC_CLASSES_KEY_ROUNDS              = 7, /* Rounds (B) */
  IPSEC_CLASSES_COMP_DICT_SIZE          = 8, /* Compression dictionary
                                                size (B) */
  IPSEC_CLASSES_COMP_PRIV_ALG           = 9, /* Compression private
                                                algorithm  (B/V) */
  IPSEC_CLASSES_SA_LONGSEQ              = 11 /* SA uses extended sequence
                                                   numbers (B) */
} SshIkeIpsecAttributeClasses;


/* Ipsec attribute class IPSEC_CLASSES_*_LIFE_TYPE values (from doi) */
typedef enum {
  /* IPSEC_VALUES_LIFE_TYPE_RESERVED    = 0, */
  IPSEC_VALUES_LIFE_TYPE_SECONDS        = 1,
  IPSEC_VALUES_LIFE_TYPE_KILOBYTES      = 2
} SshIkeIpsecAttributeLifeTypeValues;

/* Ipsec attribute class IPSEC_CLASSES_GRP_DESC values (from doi)
   Doi 05 forwards this to be defined same is in ike.
   (from doi 05) (from ike 05) */
typedef enum {
  /* IPSEC_VALUES_GRP_DESC_RESERVED     = 0, */
  IPSEC_VALUES_GRP_DESC_DEFAULT_768     = 1,
  IPSEC_VALUES_GRP_DESC_DEFAULT_1024    = 2, /* (from doi 05) */
  IPSEC_VALUES_GRP_DESC_DEFAULT_EC2N_155 = 3, /* (from doi 05)
                                                 (from ike 05) */
  IPSEC_VALUES_GRP_DESC_DEFAULT_EC2N_185 = 4, /* (from doi 05)
                                                 (from ike 05) */
  /* IPSEC_VALUES_GRP_DESC_DEFAULT_2048 = 3, */ /* (from doi 04) */
  IPSEC_VALUES_GRP_DESC_DEFAULT_1536 = 5 /* (from rfc) */
} SshIkeIpsecAttributeGrpDescValues;

/* Ipsec attribute class IPSEC_CLASSES_ENCAPSULATION_MODE values (from doi) */
typedef enum {
  /* IPSEC_VALUES_ENCAPSULATION_MODE_RESERVED   = 0, */
  IPSEC_VALUES_ENCAPSULATION_MODE_TUNNEL        = 1,
  IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT     = 2,
  IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TUNNEL    = 3,
  IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT = 4,

  /* CPUDPENCAP */
  IPSEC_VALUES_ENCAPSULATION_MODE_UDPENCAP_TUNNEL = 61440,
  IPSEC_VALUES_ENCAPSULATION_MODE_UDPENCAP_TRANSPORT = 61441,

  /* draft-ietf-ipsec-nat-t-ike */
  IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TUNNEL = 61443,
  IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT = 61444
} SshIkeIpsecAttributeEncapsulationModeValues;

/* Ipsec attribute class IPSEC_CLASSES_AUTH_ALGORITHM values (from doi) */
typedef enum {
  /* IPSEC_VALUES_AUTH_ALGORITHM_RESERVED       = 0, */
  IPSEC_VALUES_AUTH_ALGORITHM_HMAC_MD5          = 1,
  IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA_1        = 2,
  IPSEC_VALUES_AUTH_ALGORITHM_DES_MAC           = 3, /* (from doi 04) */
  IPSEC_VALUES_AUTH_ALGORITHM_KPDK              = 4, /* (from doi 05) */
  IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_256     = 5,
  IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_384     = 6,
  IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_512     = 7
#ifdef SSHDIST_CRYPT_XCBCMAC
  , IPSEC_VALUES_AUTH_ALGORITHM_XCBC_AES          = 9
#endif /* SSHDIST_CRYPT_XCBCMAC */
#ifdef SSHDIST_CRYPT_MODE_GCM
  , IPSEC_VALUES_AUTH_ALGORITHM_AES_128_GMAC = 11 /* RFC 4543 */
  , IPSEC_VALUES_AUTH_ALGORITHM_AES_192_GMAC = 12 /* RFC 4543 */
  , IPSEC_VALUES_AUTH_ALGORITHM_AES_256_GMAC = 13 /* RFC 4543 */
#endif /* SSHDIST_CRYPT_MODE_GCM */
} SshIkeIpsecAttributeAuthAlgorithmValues;

/* Ipsec attribute class IPSEC_CLASSES_SA_LONGSEQ values */
typedef enum {
  /* IPSEC_VALUES_SA_LONGSEQ_RESERVED    = 0, */
  IPSEC_VALUES_SA_LONGSEQ_64        = 1 /* Use 64 bit sequence numbers */
} SshIkeIpsecAttributeLongSequenceValues;

/* IKE Attribute Classes (from ike) */
typedef enum {
  SSH_IKE_CLASSES_ENCR_ALG = 1, /* Encryption algorithms (B) */
  SSH_IKE_CLASSES_HASH_ALG = 2, /* Hash algorithms (B) */
  SSH_IKE_CLASSES_AUTH_METH = 3, /* Authentication method (B) */
  SSH_IKE_CLASSES_GRP_DESC = 4, /* Group description (B) */
  SSH_IKE_CLASSES_GRP_TYPE = 5, /* Group type (B) */
  SSH_IKE_CLASSES_GRP_PRIME = 6,        /* Group prime (V) */
  SSH_IKE_CLASSES_GRP_GEN1 = 7, /* Group generator one (V) */
  SSH_IKE_CLASSES_GRP_GEN2 = 8, /* Group generator two (V) */
  SSH_IKE_CLASSES_GRP_CURVEA = 9, /* Group curve A (V) */
  SSH_IKE_CLASSES_GRP_CURVEB = 10, /* Group curve B (V) */
  SSH_IKE_CLASSES_LIFE_TYPE = 11, /* Life type (B) */
  SSH_IKE_CLASSES_LIFE_DURATION = 12, /* Life duration (B/V) */
  SSH_IKE_CLASSES_PRF = 13,     /* PRF (B) */
  SSH_IKE_CLASSES_KEY_LEN = 14, /* Key length (B) */
  SSH_IKE_CLASSES_FIELD_ELEM_SIZE = 15, /* Field element size (B)
                                          (from ike 05) */
  SSH_IKE_CLASSES_GRP_ORDER = 16, /* (V) (from ike 07),
                                    was GSS identity name
                                    (from ike 05) */
  SSH_IKE_CLASSES_GRP_CARDINALITY = 16384



} SshIkeAttributeClasses;

/* IKE attribute class SSH_IKE_CLASSES_ENCR_ALG values
   (from ike) */
typedef enum {
  /* SSH_IKE_VALUES_ENCR_ALG_RESERVED = 0, */
  SSH_IKE_VALUES_ENCR_ALG_DES_CBC = 1,
  SSH_IKE_VALUES_ENCR_ALG_IDEA_CBC = 2,
  SSH_IKE_VALUES_ENCR_ALG_BLOWFISH_CBC = 3,
  SSH_IKE_VALUES_ENCR_ALG_RC5_R16_B64_CBC = 4,
  SSH_IKE_VALUES_ENCR_ALG_3DES_CBC = 5,
  SSH_IKE_VALUES_ENCR_ALG_CAST_CBC = 6
  ,SSH_IKE_VALUES_ENCR_ALG_AES_CBC = 7
  ,SSH_IKE_VALUES_ENCR_ALG_CAMELLIA_CBC = 8  /* RFC 4312 */

} SshIkeAttributeEncrAlgValues;

/* IKE attribute class SSH_IKE_CLASSES_HASH_ALG values
   (from ike) */
typedef enum {
  /* SSH_IKE_VALUES_HASH_ALG_RESERVED = 0, */
  SSH_IKE_VALUES_HASH_ALG_MD5 = 1,
  SSH_IKE_VALUES_HASH_ALG_SHA = 2,
  SSH_IKE_VALUES_HASH_ALG_TIGER = 3,
  SSH_IKE_VALUES_HASH_ALG_SHA2_256 = 4,
  SSH_IKE_VALUES_HASH_ALG_SHA2_384 = 5,
  SSH_IKE_VALUES_HASH_ALG_SHA2_512 = 6,
  SSH_IKE_VALUES_HASH_ALG_RIPEMD160 = 0xff09



} SshIkeAttributeHashAlgValues;

/* IKE attribute class SSH_IKE_CLASSES_AUTH_METH values
   (from ike) (from revised-enc) */
typedef enum {
  /* SSH_IKE_VALUES_AUTH_METH_RESERVED = 0, */
  SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY = 1,
  SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES = 2,
  SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES = 3,
  SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION = 4,
  SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED = 5
#ifdef REMOVED_BY_DOI_DRAFT_07
  , SSH_IKE_VALUES_AUTH_METH_GSSAPI = 6 /* (from ike 05) */
#endif
#ifdef SSHDIST_CRYPT_ECP
  , SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256        = 9
  , SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384        = 10
  , SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521        = 11
#endif /* SSHDIST_CRYPT_ECP */


#ifdef SSHDIST_IKE_XAUTH
  ,
  SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES = 64221,
  SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES = 64222,
  SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES = 64223,
  SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES = 64224,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED = 65001,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED = 65002,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES = 65003,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES = 65004,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES = 65005,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES = 65006,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION = 65007,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION = 65008,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED = 65009,
  SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED = 65010
#endif /* SSHDIST_IKE_XAUTH */
} SshIkeAttributeAuthMethValues;

/* IKE attribute class SSH_IKE_CLASSES_GRP_DESC values
   (from ike) */
typedef enum {
  /* SSH_IKE_VALUES_GRP_DESC_RESERVED = 0, */
  SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_768 = 1,
  SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024 = 2, /* (from ike 05) */
  SSH_IKE_VALUES_GRP_DESC_DEFAULT_EC2N_155 = 3, /* (from ike 05) */
  SSH_IKE_VALUES_GRP_DESC_DEFAULT_EC2N_185 = 4, /* (from ike 05) */
  SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536 = 5, /* (from rodney) */
  SSH_IKE_VALUES_GRP_DESC_MODP_2048 = 14,
  SSH_IKE_VALUES_GRP_DESC_MODP_3072 = 15,
  SSH_IKE_VALUES_GRP_DESC_MODP_4096 = 16,
  SSH_IKE_VALUES_GRP_DESC_MODP_6144 = 17,
  SSH_IKE_VALUES_GRP_DESC_MODP_8192 = 18,
#ifdef SSHDIST_CRYPT_ECP
  SSH_IKE_VALUES_GRP_DESC_EC_MODP_256 = 19,
  SSH_IKE_VALUES_GRP_DESC_EC_MODP_384 = 20,
  SSH_IKE_VALUES_GRP_DESC_EC_MODP_521 = 21,
#endif /* SSHDIST_CRYPT_ECP */
  SSH_IKE_VALUES_GRP_DESC_MODP_RFC5114_1024_160 = 22,
  SSH_IKE_VALUES_GRP_DESC_MODP_RFC5114_2048_224 = 23,
  SSH_IKE_VALUES_GRP_DESC_MODP_RFC5114_2048_256 = 24,
#ifdef SSHDIST_CRYPT_ECP
  SSH_IKE_VALUES_GRP_DESC_EC_MODP_RFC5114_192 = 25,
  SSH_IKE_VALUES_GRP_DESC_EC_MODP_RFC5114_224 = 26
#endif /* SSHDIST_CRYPT_ECP */

} SshIkeAttributeGrpDescValues;

/* IKE attribute class SSH_IKE_CLASSES_GRP_TYPE values
   (from ike) */
typedef enum {
  /* SSH_IKE_VALUES_GRP_TYPE_RESERVED = 0, */
  SSH_IKE_VALUES_GRP_TYPE_MODP = 1, /* Modular exponentiation group */
  SSH_IKE_VALUES_GRP_TYPE_ECP = 2, /* Elliptic curve group over GF[P] */
  SSH_IKE_VALUES_GRP_TYPE_EC2N = 3 /* Elliptic curve group over GF[2^N] */
} SshIkeAttributeGrpTypeValues;

/* IKE attribute class SSH_IKE_CLASSES_GRP_* values
   (from ike) */
typedef SshMPInteger SshIkeAttributePrimeValues;
typedef SshMPInteger SshIkeAttributeGen1Values;
typedef SshMPInteger SshIkeAttributeGen2Values;
typedef SshMPInteger SshIkeAttributeCurveaValues;
typedef SshMPInteger SshIkeAttributeCurvebValues;
typedef SshMPInteger SshIkeAttributeOrderValues;
typedef SshMPInteger SshIkeAttributeCardinalityValues;

/* IKE attribute class SSH_IKE_CLASSES_LIFE_TYPE values
   (from ike) */
typedef enum {
  /* SSH_IKE_VALUES_LIFE_TYPE_RESERVED = 0, */
  SSH_IKE_VALUES_LIFE_TYPE_SECONDS = 1,
  SSH_IKE_VALUES_LIFE_TYPE_KILOBYTES = 2
} SshIkeAttributeLifeTypeValues;

/* IKE attribute class SSH_IKE_CLASSES_LIFE_DURATION values
   (from ike) */
typedef SshUInt32 SshIkeAttributeLifeDurationValues;

/* IKE attribute class SSH_IKE_CLASSES_PRF values (from ike) */
typedef enum {
  SSH_IKE_VALUES_PRF_RESERVED = 0
#ifdef REMOVED_BY_DOI_DRAFT_07
  , SSH_IKE_VALUES_PRF_3DES_CBC_MAC = 1
#endif
} SshIkeAttributePrfValues;

/* IKE attribute class SSH_IKE_CLASSES_KEY_LEN values (from ike) */
typedef SshUInt32 SshIkeAttributeKeyLenValues;

/* Isakmp and oakley exchange types (from isakmp) (from ike)
   (from isakmp-cfg) */
typedef enum {
  SSH_IKE_XCHG_TYPE_NONE = 0,   /* None */
  SSH_IKE_XCHG_TYPE_BASE = 1,   /* Base */
  SSH_IKE_XCHG_TYPE_IP = 2,     /* Identity protection (oakley main mode) */
  SSH_IKE_XCHG_TYPE_AO = 3,     /* Authentication Only */
  SSH_IKE_XCHG_TYPE_AGGR = 4,   /* Aggressive (oakley aggressive mode) */
  SSH_IKE_XCHG_TYPE_INFO = 5,   /* Informal */
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_IKE_XCHG_TYPE_CFG = 6,    /* Configuration mode (from isakmp-cfg) */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SSH_IKE_XCHG_TYPE_QM = 32,    /* Quick Mode */
  SSH_IKE_XCHG_TYPE_NGM = 33,   /* New Group Mode */
  SSH_IKE_XCHG_TYPE_ANY = 256   /* Any mode */
} SshIkeExchangeType;

/* Isakmp payload packet types (from isakmp) */
typedef enum {
  SSH_IKE_PAYLOAD_TYPE_NONE = 0,
  SSH_IKE_PAYLOAD_TYPE_SA = 1,  /* Security Association */
  SSH_IKE_PAYLOAD_TYPE_P = 2,   /* Proposal */
  SSH_IKE_PAYLOAD_TYPE_T = 3,   /* Transform */
  SSH_IKE_PAYLOAD_TYPE_KE = 4,  /* Key Exchange */
  SSH_IKE_PAYLOAD_TYPE_ID = 5,  /* Identification */
  SSH_IKE_PAYLOAD_TYPE_CERT = 6, /* Certificate */
  SSH_IKE_PAYLOAD_TYPE_CR = 7,  /* Certificate request */
  SSH_IKE_PAYLOAD_TYPE_HASH = 8, /* Hash */
  SSH_IKE_PAYLOAD_TYPE_SIG = 9, /* Signature */
  SSH_IKE_PAYLOAD_TYPE_NONCE = 10, /* Nonce */
  SSH_IKE_PAYLOAD_TYPE_N = 11,  /* Notification */
  SSH_IKE_PAYLOAD_TYPE_D = 12,  /* Delete */
  SSH_IKE_PAYLOAD_TYPE_VID = 13, /* Vendor ID */
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_IKE_PAYLOAD_TYPE_ATTR = 14, /* Attribute payload (from isakmp-cfg) */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SSH_IKE_PAYLOAD_TYPE_MAX,     /* Number of payload types */
  SSH_IKE_PAYLOAD_TYPE_PRV = 256 /* Special number used for all private
                                    payloads (payload type > type_max). */
} SshIkePayloadType;

/* Isakmp data attribute structure (from isakmp) */
typedef struct SshIkeDataAttributeRec {
  SshUInt16 attribute_type;     /* Type of attribute */
  size_t attribute_length;      /* Length of attribute */
  unsigned char *attribute;     /* Pointer to attribute */
} *SshIkeDataAttribute, SshIkeDataAttributeStruct;

/* Transform payload packet (from isakmp) */
typedef struct SshIkePayloadTRec {
  int transform_number;
  union SshIkeTransformIdentifiersUnion transform_id;
  int number_of_sa_attributes;
  SshIkeDataAttribute sa_attributes; /* (mallocated, but data items that are
                                        inside the attributes are assumed to be
                                        freed automatically (either this table
                                        contains them at the end, or they point
                                        to somewhere else where they are
                                        freed) */
} *SshIkePayloadT;

/* Protocol info of proposal payload packet (from isakmp) */
typedef struct SshIkePayloadPProtocolRec {
  SshIkeProtocolIdentifiers protocol_id; /* Protocol id */
  size_t spi_size;
  unsigned char *spi;           /* (mallocated) */
  int number_of_transforms;     /* Number of transforms in this protocol */
  SshIkePayloadT transforms;    /* Transforms in this protocol (malloc) */
} *SshIkePayloadPProtocol;

/* Proposal payload packet (from isakmp) */
typedef struct SshIkePayloadPRec {
  int proposal_number;          /* This proposal number */
  int number_of_protocols;      /* Number of protocols in this proposal */
  SshIkePayloadPProtocol protocols; /* Protocols in this proposal (malloc) */
} *SshIkePayloadP;

/* Ipsec situation format (from doi) */
typedef struct SshIkeIpsecSituationPacketRec {
  SshUInt32 situation_flags;
  SshUInt32 labeled_domain_identifier; /* Always 0 == reserved */
  SshUInt16 secrecy_level_length;       /* In bytes */
  unsigned char *secrecy_level_data; /* (mallocated) */
  SshUInt16 secrecy_category_bitmap_length; /* In bits */
  unsigned char *secrecy_category_bitmap_data; /* (mallocated) */
  SshUInt16 integrity_level_length;     /* In bytes */
  unsigned char *integrity_level_data; /* (mallocated) */
  SshUInt16 integrity_category_bitmap_length; /* In bits */
  unsigned char *integrity_category_bitmap_data; /* (mallocated) */
} *SshIkeIpsecSituationPacket;

/* Security Association payload packet (from isakmp) */
typedef struct SshIkePayloadSARec {
  SshIkeDOI doi;                /* Domain of interpretation */
  struct SshIkeIpsecSituationPacketRec situation; /* Doi-specific situation */
  int number_of_proposals;      /* Number of proposals */
  SshIkePayloadP proposals;     /* Proposals (mallocated) */
} *SshIkePayloadSA;

/* Key exchange payload packet (from isakmp) */
typedef struct SshIkePayloadKERec {
  size_t key_exchange_data_len; /* Length of key exchange data in bytes */
  unsigned char *key_exchange_data;
} *SshIkePayloadKE;

/* Ipsec identification type values (from doi) */
typedef enum {
  /* IPSEC_ID_RESERVED                  = 0, */
  IPSEC_ID_IPV4_ADDR                    = 1,
  IPSEC_ID_FQDN                         = 2,
  IPSEC_ID_USER_FQDN                    = 3,
  IPSEC_ID_IPV4_ADDR_SUBNET             = 4,
  IPSEC_ID_IPV6_ADDR                    = 5,
  IPSEC_ID_IPV6_ADDR_SUBNET             = 6,
  IPSEC_ID_IPV4_ADDR_RANGE              = 7,
  IPSEC_ID_IPV6_ADDR_RANGE              = 8,
  IPSEC_ID_DER_ASN1_DN                  = 9,
  IPSEC_ID_DER_ASN1_GN                  = 10,
  IPSEC_ID_KEY_ID                       = 11 /* (from doi 04) */
#ifdef SSHDIST_IKE_ID_LIST
  ,
  IPSEC_ID_LIST                         = 12 /* (from rfc3554) */
#endif /* SSHDIST_IKE_ID_LIST */
} SshIkeIpsecIdentificationType;

/* Ipsec identification packet data (from doi) */
typedef union SshIkeIpsecIdentificationDataUnion {
  unsigned char ipv4_addr[4];   /* IPSEC_ID_IPV4_ADDR, network byte order */

  unsigned char *fqdn;          /* IPSEC_ID_FQDN, Note! NOT null terminated
                                   (mallocated)  */

  unsigned char *user_fqdn;     /* IPSEC_ID_USER_FQDN, Note! NOT null
                                   terminated (mallocated) */

  struct {      /* IPSEC_ID_IPV4_ADDR_SUBNET */
    unsigned char _ipv4_addr_subnet[4]; /* Network byte order */
    unsigned char _ipv4_addr_netmask[4]; /* Network byte order */
  } ipv4_addr_subnet_and_netmask;
#define ipv4_addr_subnet ipv4_addr_subnet_and_netmask._ipv4_addr_subnet
#define ipv4_addr_netmask ipv4_addr_subnet_and_netmask._ipv4_addr_netmask

  unsigned char ipv6_addr[16];  /* IPSEC_ID_IPV6_ADDR */

  struct {      /* IPSEC_ID_IPV6_ADDR_SUBNET */
    unsigned char _ipv6_addr_subnet[16]; /* Network byte order */
    unsigned char _ipv6_addr_netmask[16]; /* Network byte order */
  } ipv6_addr_subnet_and_netmask;
#define ipv6_addr_subnet ipv6_addr_subnet_and_netmask._ipv6_addr_subnet
#define ipv6_addr_netmask ipv6_addr_subnet_and_netmask._ipv6_addr_netmask

  struct {      /* IPSEC_ID_IPV4_ADDR_RANGE */
    unsigned char _ipv4_addr_range1[4]; /* Network byte order */
    unsigned char _ipv4_addr_range2[4]; /* Network byte order */
  } ipv4_addr_range;
#define ipv4_addr_range1 ipv4_addr_range._ipv4_addr_range1
#define ipv4_addr_range2 ipv4_addr_range._ipv4_addr_range2

  struct {      /* IPSEC_ID_IPV6_ADDR_RANGE */
    unsigned char _ipv6_addr_range1[16]; /* Network byte order */
    unsigned char _ipv6_addr_range2[16]; /* Network byte order */
  } ipv6_addr_range;
#define ipv6_addr_range1 ipv6_addr_range._ipv6_addr_range1
#define ipv6_addr_range2 ipv6_addr_range._ipv6_addr_range2

  unsigned char *asn1_data;     /* IPSEC_ID_DER_ASN1_* (mallocated) */
  unsigned char *key_id;        /* IPSEC_ID_KEY_ID (mallocated) */

#ifdef SSHDIST_IKE_ID_LIST
  struct {      /* IPSEC_ID_LIST */
    /* Number of items in the list. */
    int _number_of_items;
    /* Array of struct SshIkePayloadIDRec structures, the array will contain
       number_of_items items, and it is allocted with one malloc, i.e it is not
       array of pointers. */
    struct SshIkePayloadIDRec *_items;
  } id_list;
#define id_list_number_of_items id_list._number_of_items
#define id_list_items id_list._items
#endif /* SSHDIST_IKE_ID_LIST */
} *SshIkeIpsecIdentificationData;

typedef SshInetIPProtocolID SshIkeIpsecIPProtocolID;

/* Identification payload packet (from isakmp) (from doi) */
typedef struct SshIkePayloadIDRec {
  SshIkeIpsecIdentificationType id_type;
  SshIkeIpsecIPProtocolID protocol_id;
  SshUInt16 port_number;        /* port number or 0 for any */
  SshUInt16 port_range_end;     /* The end of a port range.  Note that
                                   the IKE does not use or modify this
                                   field at all. */
  size_t identification_len;    /* Length of identification data */
  union SshIkeIpsecIdentificationDataUnion identification; /* Doi-specific
                                                        identification. */
  unsigned char *raw_id_packet; /* Raw id_packet from/to packet
                                   encode/decode. This packet may already be
                                   encrypted with rsa. (mallocated) */
} *SshIkePayloadID;

/* Certificate encoding types (from isakmp) */
typedef enum {
  SSH_IKE_CERTIFICATE_ENCODING_NONE = 0,      /* None */
  SSH_IKE_CERTIFICATE_ENCODING_PKCS7 = 1,     /* PKCS #7 wrapped X.509  */
  SSH_IKE_CERTIFICATE_ENCODING_PGP = 2,       /* PGP */
  SSH_IKE_CERTIFICATE_ENCODING_DNS = 3,       /* DNS signed key */
  SSH_IKE_CERTIFICATE_ENCODING_X509_SIG = 4,  /* X.509 - signature */
  SSH_IKE_CERTIFICATE_ENCODING_X509_KE = 5,   /* X.509 - key exchange */
  SSH_IKE_CERTIFICATE_ENCODING_KERBEROS = 6,  /* Kerberos tokens */
  SSH_IKE_CERTIFICATE_ENCODING_CRL = 7,       /* Certificate revocation list */
  SSH_IKE_CERTIFICATE_ENCODING_ARL = 8,       /* Authority revocation list */
  SSH_IKE_CERTIFICATE_ENCODING_SPKI = 9,      /* Simple public key infra */
  SSH_IKE_CERTIFICATE_ENCODING_X509_ATTR = 10 /* X.509 - Attribute */
} SshIkeCertificateEncodingType;

/* Certificate payload packet (from isakmp) */
typedef struct SshIkePayloadCERTRec {
  SshIkeCertificateEncodingType cert_encoding;
  size_t certificate_data_len;
  unsigned char *certificate_data;
} *SshIkePayloadCERT;

/* Certificate request payload packet (from isakmp) */
typedef struct SshIkePayloadCRRec {
  SshIkeCertificateEncodingType certificate_type;
  size_t certificate_authority_len;
  unsigned char *certificate_authority;
} *SshIkePayloadCR;

/* Hash payload packet (from isakmp) */
typedef struct SshIkePayloadHASHRec {
  unsigned char *hash_data;
} *SshIkePayloadHASH;

/* Signature payload packet (from isakmp) */
typedef struct SshIkePayloadSIGRec {
  unsigned char *signature_data;
} *SshIkePayloadSIG;

/* Nonce payload packet (from isakmp) */
typedef struct SshIkePayloadNONCERec {
  unsigned char *raw_nonce_packet;
  unsigned char *nonce_data;
  size_t nonce_data_len;
} *SshIkePayloadNONCE;

/* Notify message types (from isakmp) (from doi 05) */
typedef enum {
  /* Error types (1-16383) */
  SSH_IKE_NOTIFY_MESSAGE_RESERVED                               = 0,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE                   = 1,
  SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED                      = 2,
  SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED                = 3,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_COOKIE                         = 4,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_MAJOR_VERSION                  = 5,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_MINOR_VERSION                  = 6,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_EXCHANGE_TYPE                  = 7,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_FLAGS                          = 8,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_MESSAGE_ID                     = 9,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_PROTOCOL_ID                    = 10,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI                            = 11,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_TRANSFORM_ID                   = 12,
  SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED               = 13,
  SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN                     = 14,
  SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX                    = 15,
  SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED                      = 16,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_KEY_INFORMATION                = 17,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION                 = 18,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_CERT_ENCODING                  = 19,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_CERTIFICATE                    = 20,
  SSH_IKE_NOTIFY_MESSAGE_CERT_TYPE_UNSUPPORTED                  = 21,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_CERT_AUTHORITY                 = 22,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION               = 23,
  SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED                  = 24,
  SSH_IKE_NOTIFY_MESSAGE_INVALID_SIGNATURE                      = 25,
  SSH_IKE_NOTIFY_MESSAGE_ADDRESS_NOTIFICATION                   = 26,
  SSH_IKE_NOTIFY_MESSAGE_SA_LIFETIME                            = 27,
  SSH_IKE_NOTIFY_MESSAGE_CERTIFICATE_UNAVAILABLE                = 28,
  SSH_IKE_NOTIFY_MESSAGE_UNSUPPORTED_EXCHANGE_TYPE              = 29,
  SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS                = 30,
  /* Internal errors == drop packet without nofify */
  SSH_IKE_NOTIFY_MESSAGE_NO_SA_ESTABLISHED                      = 8194,
  SSH_IKE_NOTIFY_MESSAGE_NO_STATE_MATCHED                       = 8195,
  SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING                  = 8196,
  /* Negotiation timed out, the other end didn't respond */
  SSH_IKE_NOTIFY_MESSAGE_TIMEOUT                                = 8197,
  /* Other end requested delete */
  SSH_IKE_NOTIFY_MESSAGE_DELETED                                = 8198,
  /* Negotiation was aborted because of the isakmp sa was removed or because of
     the policy manager requested it using ssh_ike_abort_negotiation or
     ssh_ike_remove_* */
  SSH_IKE_NOTIFY_MESSAGE_ABORTED                                = 8199,
  /* Other end sent UDP host/port unreachable */
  SSH_IKE_NOTIFY_MESSAGE_UDP_HOST_UNREACHABLE                   = 8200,
  SSH_IKE_NOTIFY_MESSAGE_UDP_PORT_UNREACHABLE                   = 8201,
  /* Memory allocation error */
  SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY                          = 8202,
  /* Status types (16384-32767) */
  SSH_IKE_NOTIFY_MESSAGE_CONNECTED                              = 16384,
  /* IKE status types (from doi 05) */
  SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME                     = 24576,
  SSH_IKE_NOTIFY_MESSAGE_REPLAY_STATUS                          = 24577,
  SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT                        = 24578,

  /* Notify messages from draft-ietf-ipsec-dpd-01.txt */
  SSH_IKE_NOTIFY_MESSAGE_R_U_THERE                              = 36136,
  SSH_IKE_NOTIFY_MESSAGE_R_U_THERE_ACK                          = 36137,

  /* Cisco pre-shared key hash for hybrid auth */
  SSH_IKE_NOTIFY_MESSAGE_CISCO_PSK_HASH                         = 40503,

  /* Special status, not shown outside the state machine. */
  /* Retry later means that the packet is rerun through the state machine again
     starting from the same state from the same function. This can be used to
     in input and output filters so that they start some query to policy
     manager and return this status. This means, that no packet is sent, and no
     timers are set etc. When the policy manager finishes it will call
     ssh_isakmp_state_restart_packet that will feed the packet through state
     machine again and continue from the input function that returned this
     status, this time the policy managers answer should be stored somewhere in
     the negotiation structure and the same function that returned this status
     last time can now prosess that data. All functions called to process
     policy managers respond must check that the negotiation->current_state is
     not SSH_IKE_ST_DELETED, and if it is then they should assume the
     negotiation is already deleted, and do nothing, but just call to
     ssh_isakmp_state_restart_packet. The ssh_isakmp_state_restart_packet will
     free then negotiation as soon as it is called if current_state is
     SSH_IKE_ST_DELETED. */
  SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER                            = -1,
  /* Output function can return this meaning that retry this packet through
     state machine code immediately after this state is finished. */
  SSH_IKE_NOTIFY_MESSAGE_RETRY_NOW                              = -2
} SshIkeNotifyMessageType;

/* Notification payload packet (from isakmp) */
typedef struct SshIkePayloadNRec {
  SshIkeDOI doi;                /* Domain of interpretation */
  SshIkeProtocolIdentifiers protocol_id;
  size_t spi_size;
  SshIkeNotifyMessageType notify_message_type;
  unsigned char *spi;
  size_t notification_data_size;
  unsigned char *notification_data;
} *SshIkePayloadN;

/* Delete payload packet (from isakmp) */
typedef struct SshIkePayloadDRec {
  SshIkeDOI doi;                /* Domain of interpretation */
  SshIkeProtocolIdentifiers protocol_id;
  size_t spi_size;
  int number_of_spis;           /* Number of SPIs */
  unsigned char **spis;         /* Array of SPIs */
} *SshIkePayloadD;

/* Vendor ID payload packet (from isakmp) */
typedef struct SshIkePayloadVIDRec {
  unsigned char *vid_data;
} *SshIkePayloadVID;

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Configuration mode message types (from isakmp-cfg) */
typedef enum {
  SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST = 1,
  SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY = 2,
  SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET = 3,
  SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK = 4
} SshIkeCfgMessageType;

/* Configuration mode attribute classes (from isakmp-cfg) */
typedef enum {
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_ADDRESS = 1,   /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NETMASK = 2,   /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DNS = 3,       /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NBNS = 4,      /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY = 5, /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_DHCP = 6,      /* 0 or 4 octects */
  SSH_IKE_CFG_ATTR_APPLICATION_VERSION = 7,     /* variable */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS = 8,   /* 0 or 16 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NETMASK = 9,   /* 0 or 16 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_DNS = 10,      /* 0 or 16 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NBNS = 11,     /* 0 or 16 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_DHCP = 12,     /* 0 or 16 octects */
  SSH_IKE_CFG_ATTR_INTERNAL_IPV4_SUBNET = 13,   /* 0 or 8 octects */
  SSH_IKE_CFG_ATTR_SUPPORTED_ATTRIBUTES = 14,   /* 0 or multiple of 2 octects*/
  SSH_IKE_CFG_ATTR_INTERNAL_IPV6_SUBNET = 15,   /* 0 or 17 octects */
  SSH_IKE_CFG_ATTR_XAUTH_TYPE = 16520,          /* See SshIkeXauthType */
  SSH_IKE_CFG_ATTR_XAUTH_USER_NAME = 16521,     /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD = 16522, /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_PASSCODE = 16523,      /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_MESSAGE = 16524,       /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_CHALLENGE = 16525,     /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_DOMAIN = 16526,        /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_STATUS = 16527,        /* basic */
  SSH_IKE_CFG_ATTR_XAUTH_NEXT_PIN = 16528,      /* variable */
  SSH_IKE_CFG_ATTR_XAUTH_ANSWER = 16529         /* variable */
} SshIkeCfgAttributeClasses;

/* Extended authentication type (from draft-beaulieu-ike-xauth-02) */
typedef enum {
  SSH_IKE_XAUTH_TYPE_GENERIC = 0,               /* Generic */
  SSH_IKE_XAUTH_TYPE_RADIUS_CHAP = 1,           /* name,password+others */
  SSH_IKE_XAUTH_TYPE_OTP = 2,                   /* name,password,[challenge] */
  SSH_IKE_XAUTH_TYPE_S_KEY = 3                  /* name,password,[challenge] */
} SshIkeXauthType;

/* Attribute payload packet (from isakmp-cfg) */
typedef struct SshIkePayloadAttrRec {
  SshIkeCfgMessageType type;    /* Configuration message type */
  SshUInt16 identifier;         /* Identifier */
  int number_of_attributes;     /* Number of data attributes */
  SshIkeDataAttribute attributes; /* Array of attributes */
} *SshIkePayloadAttr;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#define SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_D      20
#define SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_OA     21

/* Private payload packet */
typedef struct SshIkePayloadPrivateRec {
  int prv_payload_id;           /* Private payload id */
  unsigned char *data;          /* Data */
} *SshIkePayloadPrivate;

/* Encoding finalizing function. This function is called to update isakmp
   packet just before it is encrypted (qm_hashs). */

typedef SshIkeNotifyMessageType (*SshIkeFinalizeEncodingFunc)
     (SshIkeContext context,
      SshIkeSA sa,
      SshIkeNegotiation negotiation,
      SshIkePacket isakmp_packet,
      int payload_index,
      SshIkePayload payload);

/* Generic isakmp payload packet (from isakmp) */
struct SshIkePayloadRec {
  SshIkePayloadType type;       /* Payload type */
  size_t payload_length;        /* Real payload length (without generic
                                   header), note this will be automatically
                                   calculated when encoding, for some
                                   payloads, but hash, sig, nonce, and vid
                                   will require correct size. */
  struct SshIkePayloadRec *next_same_payload; /* Pointer to next payload of
                                                 same type. */
  size_t payload_offset;        /* Offset of generic header of the payload
                                   from the start of the first payload
                                   (after isakmp header).
                                   This will be automatically updated when
                                   encoding. */
  unsigned char *payload_start; /* Pointer to start of generic header of
                                   the payload
                                   This will be automatically updated when
                                   encoding. This pointer will always
                                   point to encoded_packet data in packet
                                   struct. */
  /* Payload data */
  union {
    struct SshIkePayloadSARec sa;       /* Security Association */
    struct SshIkePayloadKERec ke;       /* Key Exchange */
    struct SshIkePayloadIDRec id;       /* Identification */
    struct SshIkePayloadCERTRec cert;   /* Certificate */
    struct SshIkePayloadCRRec cr;       /* Certificate request */
    struct SshIkePayloadHASHRec hash;   /* Hash */
    struct SshIkePayloadSIGRec sig;     /* Signature */
    struct SshIkePayloadNONCERec nonce; /* Nonce */
    struct SshIkePayloadNRec n;         /* Notification */
    struct SshIkePayloadDRec d;         /* Delete */
    struct SshIkePayloadVIDRec vid;     /* Vendor ID */
#ifdef SSHDIST_ISAKMP_CFG_MODE
    struct SshIkePayloadAttrRec attr;   /* Attribute payload */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    struct SshIkePayloadPrivateRec prv; /* Private payload */
  } pl;
  SshIkeFinalizeEncodingFunc func; /* Function to be called to finalize the
                                      encoding. This is called after all packet
                                      processing is done, but before encryption
                                      (and its padding).
                                      Payload finalize encoding functions are
                                      called in same order where payloads are
                                      in the packet. */
};

/* Isakmp flags (from isakmp) */
#define SSH_IKE_FLAGS_ENCRYPTION                0x01
#define SSH_IKE_FLAGS_COMMIT                    0x02
#define SSH_IKE_FLAGS_AUTHENTICATION_ONLY       0x04 /* (from isakmp 09) */
#define SSH_IKE_FLAGS_SUPPORTED \
       (SSH_IKE_FLAGS_ENCRYPTION | SSH_IKE_FLAGS_COMMIT)

#define SSH_IKE_COOKIE_LENGTH           8

#define SSH_IKE_PACKET_GENERIC_HEADER_LEN       28
#define SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN      4

/* Max number of packets that one isakmp exchange can have. */

#define SSH_IKE_MAX_NUMBER_OF_PACKETS 4
#endif /* ISAKMP_DOI_H */
