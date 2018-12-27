/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp doi to name tables.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshinet.h"

/* Mapping between error codes and error strings. */
const SshKeywordStruct ssh_ike_status_keywords[] = {
  { "Invalid payload type", SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE },
  { "DOI not supported", SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED },
  { "Situation not supported",
    SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED },
  { "Invalid Cookie", SSH_IKE_NOTIFY_MESSAGE_INVALID_COOKIE },
  { "Invalid IKE major version",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_MAJOR_VERSION },
  { "Invalid IKE minor version",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_MINOR_VERSION },
  { "Invalid exchange type", SSH_IKE_NOTIFY_MESSAGE_INVALID_EXCHANGE_TYPE },
  { "Invalid flags", SSH_IKE_NOTIFY_MESSAGE_INVALID_FLAGS },
  { "Invalid message ID", SSH_IKE_NOTIFY_MESSAGE_INVALID_MESSAGE_ID },
  { "Invalid protocol ID", SSH_IKE_NOTIFY_MESSAGE_INVALID_PROTOCOL_ID },
  { "Invalid SPI", SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI },
  { "Invalid transform ID", SSH_IKE_NOTIFY_MESSAGE_INVALID_TRANSFORM_ID },
  { "Attributes not supported",
    SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED },
  { "No proposal chosen", SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN },
  { "Bad proposal syntax", SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX },
  { "Payload malformed", SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED },
  { "Invalid key information",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_KEY_INFORMATION },
  { "Invalid ID information", SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION },
  { "Invalid certificate encoding",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_CERT_ENCODING },
  { "Invalid certificate", SSH_IKE_NOTIFY_MESSAGE_INVALID_CERTIFICATE },
  { "Certificate type unsupported",
    SSH_IKE_NOTIFY_MESSAGE_CERT_TYPE_UNSUPPORTED },
  { "Invalid certificate authority",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_CERT_AUTHORITY },
  { "Invalid hash information",
    SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION },
  { "Authentication failed", SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED },
  { "Invalid signature", SSH_IKE_NOTIFY_MESSAGE_INVALID_SIGNATURE },
  { "Address notification (not used)",
    SSH_IKE_NOTIFY_MESSAGE_ADDRESS_NOTIFICATION },
  { "SA Lifetime (not used)", SSH_IKE_NOTIFY_MESSAGE_SA_LIFETIME },
  { "Certificate unavailable",
    SSH_IKE_NOTIFY_MESSAGE_CERTIFICATE_UNAVAILABLE },
  { "Unsupported exchange type",
    SSH_IKE_NOTIFY_MESSAGE_UNSUPPORTED_EXCHANGE_TYPE },
  { "Payload lengths do not match",
    SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS },
  { "No SA established", SSH_IKE_NOTIFY_MESSAGE_NO_SA_ESTABLISHED },
  { "State not matched", SSH_IKE_NOTIFY_MESSAGE_NO_STATE_MATCHED },
  { "Exchange data missing", SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING },
  { "Timeout", SSH_IKE_NOTIFY_MESSAGE_TIMEOUT },
  { "Delete notification", SSH_IKE_NOTIFY_MESSAGE_DELETED },
  { "Aborted notification", SSH_IKE_NOTIFY_MESSAGE_ABORTED },
  { "UDP host unreachable", SSH_IKE_NOTIFY_MESSAGE_UDP_HOST_UNREACHABLE },
  { "UDP port unreachable", SSH_IKE_NOTIFY_MESSAGE_UDP_PORT_UNREACHABLE },
  { "Out of memory", SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY },
  { "Connected notification", SSH_IKE_NOTIFY_MESSAGE_CONNECTED },
  { "Responder lifetime notification",
    SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME },
  { "Replay status notification", SSH_IKE_NOTIFY_MESSAGE_REPLAY_STATUS },
  { "Initial contact notification", SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT },
  { "DPD Are You There", SSH_IKE_NOTIFY_MESSAGE_R_U_THERE },
  { "DPD I Am Here", SSH_IKE_NOTIFY_MESSAGE_R_U_THERE_ACK },

  { NULL, 0 }
};

/* Mapping from encryption algorithm name to default key length in bytes */
const SshKeywordStruct ssh_ike_encryption_key_lengths_keywords[] = {
  { "blowfish-cbc", 16 },
  { "rc5-16-cbc", 16 },
  { "cast128-cbc", 16 },
  { "twofish-cbc", 16 },
  { "rc6-cbc", 16 },
  { "mars-cbc", 16 },
  { "rijndael-cbc", 16 },
  { "aes-cbc", 16 },
  { "serpent-cbc", 16 },
  { NULL, 0 }




};

/* Mapping from encryption algorithm name to weak key check status */
const SshKeywordStruct ssh_ike_encryption_weak_key_check_keywords[] = {
  { "des-cbc", TRUE },
  { NULL, 0 }
};

/* Mapping between encryption algorithm name and ike encryption algorithm
   number */
const SshKeywordStruct ssh_ike_encryption_algorithms[] = {
  { "des-cbc", SSH_IKE_VALUES_ENCR_ALG_DES_CBC },
  { "idea-cbc", SSH_IKE_VALUES_ENCR_ALG_IDEA_CBC },
  { "blowfish-cbc", SSH_IKE_VALUES_ENCR_ALG_BLOWFISH_CBC },
  { "camellia-cbc", SSH_IKE_VALUES_ENCR_ALG_CAMELLIA_CBC },
  { "rc5-16-cbc", SSH_IKE_VALUES_ENCR_ALG_RC5_R16_B64_CBC },
  { "3des-cbc", SSH_IKE_VALUES_ENCR_ALG_3DES_CBC },
  { "cast128-cbc", SSH_IKE_VALUES_ENCR_ALG_CAST_CBC },
  { "aes-cbc", SSH_IKE_VALUES_ENCR_ALG_AES_CBC },
  { "rijndael-cbc", SSH_IKE_VALUES_ENCR_ALG_AES_CBC },

  { NULL, 0 }
};

/* Mapping between hash algorithm name and ike hash algorithm number */
const SshKeywordStruct ssh_ike_hash_algorithms[] = {
  { "md5", SSH_IKE_VALUES_HASH_ALG_MD5 },
  { "sha1", SSH_IKE_VALUES_HASH_ALG_SHA },
  { "tiger192", SSH_IKE_VALUES_HASH_ALG_TIGER },
  { "ripemd160", SSH_IKE_VALUES_HASH_ALG_RIPEMD160 },
  { "sha256", SSH_IKE_VALUES_HASH_ALG_SHA2_256 },
  { "sha384", SSH_IKE_VALUES_HASH_ALG_SHA2_384 },
  { "sha512", SSH_IKE_VALUES_HASH_ALG_SHA2_512 },
  { NULL, 0 }
};

/* Mapping between mac algorithm name and corresponding ike hash algorithm
   number */
const SshKeywordStruct ssh_ike_hmac_prf_algorithms[] = {
  { "hmac-md5", SSH_IKE_VALUES_HASH_ALG_MD5 },
  { "hmac-sha1", SSH_IKE_VALUES_HASH_ALG_SHA },
  { "hmac-tiger192", SSH_IKE_VALUES_HASH_ALG_TIGER },
  { "hmac-ripemd160", SSH_IKE_VALUES_HASH_ALG_RIPEMD160 },
  { "hmac-sha256", SSH_IKE_VALUES_HASH_ALG_SHA2_256 },
  { "hmac-sha384", SSH_IKE_VALUES_HASH_ALG_SHA2_384 },
  { "hmac-sha512", SSH_IKE_VALUES_HASH_ALG_SHA2_512 },
  { NULL, 0 }
};

/* Mapping between prf algorithm name and ike prf algorithm number */
const SshKeywordStruct ssh_ike_prf_algorithms[] = {
#ifdef REMOVED_BY_DOI_DRAFT_07
  { "3des-cbc-mac", SSH_IKE_VALUES_PRF_3DES_CBC_MAC },
#endif
  { NULL, 0 }
};

/* Mapping between encapsulation name and doi encapsulation number */
const SshKeywordStruct ssh_ike_ipsec_encapsulation_modes[] = {
  { "tunnel", IPSEC_VALUES_ENCAPSULATION_MODE_TUNNEL },
  { "transport", IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT },
  { "udp-transport", IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT },
  { "udp-tunnel", IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TUNNEL },
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  { "udpencap-tunnel", IPSEC_VALUES_ENCAPSULATION_MODE_UDPENCAP_TUNNEL },
  { "udpencap-transport", IPSEC_VALUES_ENCAPSULATION_MODE_UDPENCAP_TRANSPORT },
  { "udp-transport", IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT },
  { "udp-tunnel", IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TUNNEL },
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  { NULL, 0 }
};

const SshKeywordStruct ssh_ike_ipsec_longseq_values[] = {
  { "64bit-seq", IPSEC_VALUES_SA_LONGSEQ_64},
  { NULL, 0 }
};

/* Mapping between mac name and doi auth algorithm number */
const SshKeywordStruct ssh_ike_ipsec_auth_algorithms[] = {
  { "hmac-md5-96", IPSEC_VALUES_AUTH_ALGORITHM_HMAC_MD5 },
  { "hmac-sha1-96", IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA_1 },
  { "des-mac", IPSEC_VALUES_AUTH_ALGORITHM_DES_MAC },
#ifdef SSHDIST_CRYPT_XCBCMAC
  { "xcbc-aes", IPSEC_VALUES_AUTH_ALGORITHM_XCBC_AES },
#endif /* SSHDIST_CRYPT_XCBCMAC */
  { "hmac-sha256-128", IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_256 },
  { "hmac-sha384-192", IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_384 },
  { "hmac-sha512-256", IPSEC_VALUES_AUTH_ALGORITHM_HMAC_SHA2_512 },
#ifdef SSHDIST_CRYPT_MODE_GCM
  { "hmac-aes-gmac-128", IPSEC_VALUES_AUTH_ALGORITHM_AES_128_GMAC },
  { "hmac-aes-gmac-192", IPSEC_VALUES_AUTH_ALGORITHM_AES_192_GMAC },
  { "hmac-aes-gmac-256", IPSEC_VALUES_AUTH_ALGORITHM_AES_256_GMAC },
#endif /* SSHDIST_CRYPT_MODE_GCM */
  { NULL, 0 }
};

const SshKeywordStruct ssh_ike_ipsec_ah_transforms[] = {
  { "md5", SSH_IKE_IPSEC_AH_TRANSFORM_AH_MD5 },
  { "sha", SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA },
  { "sha256", SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_256 },
  { "sha384", SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_384 },
  { "sha512", SSH_IKE_IPSEC_AH_TRANSFORM_AH_SHA2_512 },
  { "des", SSH_IKE_IPSEC_AH_TRANSFORM_AH_DES },
#ifdef SSHDIST_CRYPT_XCBCMAC
  { "xcbc-aes", SSH_IKE_IPSEC_AH_TRANSFORM_AH_XCBC_AES },
#endif /* SSHDIST_CRYPT_XCBCMAC */
#ifdef SSHDIST_CRYPT_MODE_GCM
  { "gmac-aes-128", SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_128_GMAC },
  { "gmac-aes-192", SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_192_GMAC },
  { "gmac-aes-256", SSH_IKE_IPSEC_AH_TRANSFORM_AH_AES_256_GMAC },
#endif /* SSHDIST_CRYPT_MODE_GCM */
  { NULL, 0 }
};

const SshKeywordStruct ssh_ike_ipsec_esp_transforms[] = {
  { "des-iv64", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV64 },
  { "des", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES },
  { "3des", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_3DES },
  { "rc5", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC5 },
  { "idea", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_IDEA },
  { "cast", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAST },
  { "blowfish", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_BLOWFISH },
  { "camellia", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_CAMELLIA },
  { "des-iv32", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_DES_IV32 },
  { "rc4", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_RC4 },
  { "null", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL },


  { "aes", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES },
  { "rijndael", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES },
  { "aes-ctr", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CTR },
#ifdef SSHDIST_CRYPT_MODE_GCM
  { "aes-gcm", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_16 },
  { "aes-gcm-96", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_12 },
  { "aes-gcm-64", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_GCM_8 },
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
  { "aes-ccm", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_16 },
  { "aes-ccm-96", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_12 },
  { "aes-ccm-64", SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_AES_CCM_8 },
#endif /* SSHDIST_CRYPT_MODE_CCM */

  { NULL, 0 }
};

const SshKeywordStruct ssh_ike_ipsec_ipcomp_transforms[] = {
  { "oui", SSH_IKE_IPCOMP_TRANSFORM_OUI },
  { "deflate", SSH_IKE_IPCOMP_TRANSFORM_DEFLAT },
  { "lzs", SSH_IKE_IPCOMP_TRANSFORM_LZS },
  { "v42bis", SSH_IKE_IPCOMP_TRANSFORM_V42BIS },
  { NULL, 0 }
};


/* Mapping between identity type name and doi identity type number */
const SshKeywordStruct ssh_ike_id_type_keywords[] = {
  { "fqdn", IPSEC_ID_FQDN },
  { "usr@fqdn", IPSEC_ID_USER_FQDN },
  { "ipv4", IPSEC_ID_IPV4_ADDR },
  { "ipv4_subnet", IPSEC_ID_IPV4_ADDR_SUBNET },
  { "ipv4_range", IPSEC_ID_IPV4_ADDR_RANGE },
  { "ipv6", IPSEC_ID_IPV6_ADDR },
  { "ipv6_subnet", IPSEC_ID_IPV6_ADDR_SUBNET },
  { "ipv6_range", IPSEC_ID_IPV6_ADDR_RANGE },
  { "der_asn1_dn", IPSEC_ID_DER_ASN1_DN },
  { "der_asn1_gn", IPSEC_ID_DER_ASN1_GN },
  { "key_id", IPSEC_ID_KEY_ID },
#ifdef SSHDIST_IKE_ID_LIST
  { "list", IPSEC_ID_LIST },
#endif /* SSHDIST_IKE_ID_LIST */
  { NULL, 0 }
};

/* Mapping between exchange name and doi exchange number */
const SshKeywordStruct ssh_ike_xchg_type_keywords[] = {
  { "none", SSH_IKE_XCHG_TYPE_NONE },
  { "Base", SSH_IKE_XCHG_TYPE_BASE },
  { "IP", SSH_IKE_XCHG_TYPE_IP },
  { "AO", SSH_IKE_XCHG_TYPE_AO },
  { "Aggr", SSH_IKE_XCHG_TYPE_AGGR },
#ifdef SSHDIST_ISAKMP_CFG_MODE
  { "CFG", SSH_IKE_XCHG_TYPE_CFG },
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  { "Info", SSH_IKE_XCHG_TYPE_INFO },
  { "QM", SSH_IKE_XCHG_TYPE_QM },
  { "NGM", SSH_IKE_XCHG_TYPE_NGM },
  { "any", SSH_IKE_XCHG_TYPE_ANY },
  { NULL, 0 }
};

#ifdef DEBUG_LIGHT
/* Mapping from state name to state number */
const SshKeywordStruct ssh_ike_state_name_keywords[] = {
  { "Any", SSH_IKE_ST_ANY },
  { "Start sa negotiation I", SSH_IKE_ST_START_SA_NEGOTIATION_I },
  { "Start sa negotiation R", SSH_IKE_ST_START_SA_NEGOTIATION_R },
  { "MM SA I", SSH_IKE_ST_MM_SA_I },
  { "MM SA R", SSH_IKE_ST_MM_SA_R },
  { "MM KE I", SSH_IKE_ST_MM_KE_I },
  { "MM KE R", SSH_IKE_ST_MM_KE_R },
  { "MM final I", SSH_IKE_ST_MM_FINAL_I },
  { "MM final R", SSH_IKE_ST_MM_FINAL_R },
  { "MM done I", SSH_IKE_ST_MM_DONE_I },
  { "AM SA I", SSH_IKE_ST_AM_SA_I },
  { "AM SA R", SSH_IKE_ST_AM_SA_R },
  { "AM final I", SSH_IKE_ST_AM_FINAL_I },
  { "AM done R", SSH_IKE_ST_AM_DONE_R },
  { "Start QM I", SSH_IKE_ST_START_QM_I },
  { "Start QM R", SSH_IKE_ST_START_QM_R },
  { "QM HASH SA I", SSH_IKE_ST_QM_HASH_SA_I },
  { "QM HASH SA R", SSH_IKE_ST_QM_HASH_SA_R },
  { "QM HASH I", SSH_IKE_ST_QM_HASH_I },
  { "QM done R", SSH_IKE_ST_QM_DONE_R },
  { "Start NGM I", SSH_IKE_ST_START_NGM_I },
  { "Start NGM R", SSH_IKE_ST_START_NGM_R },
  { "NGM HASH SA I", SSH_IKE_ST_NGM_HASH_SA_I },
  { "NGM HASH SA R", SSH_IKE_ST_NGM_HASH_SA_R },
  { "NGM done I", SSH_IKE_ST_NGM_DONE_I },
#ifdef SSHDIST_ISAKMP_CFG_MODE
  { "Start CFG I", SSH_IKE_ST_START_CFG_I },
  { "Start CFG R", SSH_IKE_ST_START_CFG_R },
  { "CFG HASH ATTR I", SSH_IKE_ST_CFG_HASH_ATTR_I },
  { "CFG HASH ATTR SA R", SSH_IKE_ST_CFG_HASH_ATTR_R },
  { "CFG done I", SSH_IKE_ST_CFG_DONE_I },
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  { "Done", SSH_IKE_ST_DONE },
  { "Deleted", SSH_IKE_ST_DELETED },
  { NULL, 0 }
};

/* Mapping between input functions and their names */

#define I_F(x) { #x, (unsigned long) x },

const SshKeywordStruct ssh_ike_state_input_funcs_keywords[] = {
I_F(ike_st_i_sa_proposal)
I_F(ike_st_i_sa_value)
I_F(ike_st_i_ke)
I_F(ike_st_i_id)
I_F(ike_st_i_cert)
I_F(ike_st_i_cr)
I_F(ike_st_i_hash)
#ifdef SSHDIST_IKE_CERT_AUTH
I_F(ike_st_i_hash_key)
I_F(ike_st_i_sig)
#endif /* SSHDIST_IKE_CERT_AUTH */
I_F(ike_st_i_nonce)
I_F(ike_st_i_qm_hash_1)
I_F(ike_st_i_qm_hash_2)
I_F(ike_st_i_qm_hash_3)
I_F(ike_st_i_qm_sa_proposals)
I_F(ike_st_i_qm_sa_values)
I_F(ike_st_i_qm_ids)
I_F(ike_st_i_qm_ke)
I_F(ike_st_i_qm_nonce)
I_F(ike_st_i_gen_hash)
I_F(ike_st_i_ngm_sa_proposal)
I_F(ike_st_i_ngm_sa_values)
I_F(ike_st_i_status_n)
I_F(ike_st_i_n)
I_F(ike_st_i_d)
I_F(ike_st_i_vid)
I_F(ike_st_i_encrypt)
I_F(ike_st_i_retry_now)
#ifdef SSHDIST_ISAKMP_CFG_MODE
I_F(ike_st_i_cfg_attr)
I_F(ike_st_i_cfg_restart)
#endif /* SSHDIST_ISAKMP_CFG_MODE */
I_F(ike_st_i_private)
{ NULL, 0 }
};
#undef I_F

/* Mapping between input functions and their names */

#define O_F(x) { #x, (unsigned long) x },

const SshKeywordStruct ssh_ike_state_output_funcs_keywords[] = {
O_F(ike_st_o_sa_proposal)
O_F(ike_st_o_sa_values)
O_F(ike_st_o_ke)
O_F(ike_st_o_nonce)
O_F(ike_st_o_id)
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_sig)
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_sig_or_hash)
O_F(ike_st_o_hash)
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_cr)
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_vids)
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_certs)
O_F(ike_st_o_optional_certs)
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_encrypt)
O_F(ike_st_o_calc_skeyid)
O_F(ike_st_o_optional_encrypt)
O_F(ike_st_o_get_pre_shared_key)
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_hash_key)
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_status_n)
O_F(ike_st_o_qm_hash_1)
O_F(ike_st_o_qm_hash_2)
O_F(ike_st_o_qm_hash_3)
O_F(ike_st_o_qm_sa_proposals)
O_F(ike_st_o_qm_sa_values)
O_F(ike_st_o_qm_nonce)
O_F(ike_st_o_qm_optional_ke)
O_F(ike_st_o_qm_optional_ids)
O_F(ike_st_o_qm_optional_responder_lifetime_n)
O_F(ike_st_o_gen_hash)
O_F(ike_st_o_ngm_sa_proposal)
O_F(ike_st_o_ngm_sa_values)
O_F(ike_st_o_rerun)
O_F(ike_st_o_wait_done)
O_F(ike_st_o_copy_iv)
O_F(ike_st_o_done)
O_F(ike_st_o_qm_done)
O_F(ike_st_o_qm_wait_done)
O_F(ike_st_o_ngm_done)
O_F(ike_st_o_ngm_wait_done)
O_F(ike_st_o_n_done)
O_F(ike_st_o_d_done)
#ifdef SSHDIST_ISAKMP_CFG_MODE
O_F(ike_st_o_cfg_attr)
O_F(ike_st_o_cfg_done)
O_F(ike_st_o_cfg_wait_done)
#endif /* SSHDIST_ISAKMP_CFG_MODE */
O_F(ike_st_o_private)
{ NULL, 0 }
};
#undef O_F

#endif /* DEBUG_LIGHT */
