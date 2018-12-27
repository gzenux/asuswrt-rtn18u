/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_PACKET_H

#define SSH_EAP_PACKET_H 1

/* Message subtype definitions. */
#ifdef SSHDIST_EAP_AKA
#define SSH_EAP_AKA_CHALLENGE           1
#define SSH_EAP_AKA_AUTH_REJECT         2
#define SSH_EAP_AKA_SYNCH_FAILURE       4
#define SSH_EAP_AKA_IDENTITY            5
#endif /* SSHDIST_EAP_AKA */
#ifdef SSHDIST_EAP_SIM
#define SSH_EAP_SIM_START              10
#define SSH_EAP_SIM_CHALLENGE          11
#endif /* SSHDIST_EAP_SIM */
#define SSH_EAP_NOTIFICATION           12
#define SSH_EAP_REAUTHENTICATION       13
#define SSH_EAP_CLIENT_ERROR           14

/* Defines for AT attributes found in EAP messages. */
#define SSH_EAP_AT_RAND               1
#define SSH_EAP_AT_AUTN               2
#define SSH_EAP_AT_RES                3
#define SSH_EAP_AT_AUTS               4
#define SSH_EAP_AT_PADDING            6
#define SSH_EAP_AT_NONCE_MT           7
#define SSH_EAP_AT_PERMANENT_ID_REQ   10
#define SSH_EAP_AT_MAC                11
#define SSH_EAP_AT_NOTIFICATION       12
#define SSH_EAP_AT_ANY_ID_REQ         13
#define SSH_EAP_AT_IDENTITY           14
#define SSH_EAP_AT_VERSION_LIST       15
#define SSH_EAP_AT_SELECTED_VERSION   16
#define SSH_EAP_AT_FULLAUTH_ID_REQ    17
#define SSH_EAP_AT_COUNTER            19
#define SSH_EAP_AT_COUNTER_TOO_SMALL  20
#define SSH_EAP_AT_NONCE_S            21
#define SSH_EAP_AT_CLIENT_ERROR_CODE  22
#define SSH_EAP_AT_IV                 129
#define SSH_EAP_AT_ENCR_DATA          130
#define SSH_EAP_AT_NEXT_PSEUDONYM     132
#define SSH_EAP_AT_NEXT_REAUTH_ID     133
#define SSH_EAP_AT_CHECKCODE          134
#define SSH_EAP_AT_RESULT_IND         135
/* Skippable attribute for EAP-AKA.*/
#define SSH_EAP_AT_BIDDING            136
/* Attribute for EAP-AKA-DASH in non-skippable range */
#define SSH_EAP_AT_KDF_INPUT          23
#define SSH_EAP_AT_KDF                24

/* Returns the real length of AT attribute in message. */
#define SSH_EAP_AT_LEN(buf, offset)  \
                       ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) * 4)


/* Macro for inserting the "val" in Big Endian format into sizeof a[2] */
#define SSH_EAP_PUT_BIGENDIAN16(a, val)     \
do {                                        \
     (a)[0] = ((SshUInt16) (val)) >> 8;     \
     (a)[1] = ((SshUInt16) (val)) & 0xff;   \
} while(0)

/* Error codes for MAC calculation functions. */
#define SSH_EAP_MAC_OK            0
#define SSH_EAP_MAC_ALLOC_FAIL    1
#define SSH_EAP_MAC_CALC_FAIL     2
#define SSH_EAP_MAC_VERIFY_FAIL   3
#define SSH_EAP_MAC_GENERIC_FAIL  4

/* Return string for MAC error code. */
const char*
ssh_eap_packet_mac_code_to_string(SshUInt8 code);

/* Calculate MAC for EAP message with HMAC-SHA256. */
SshUInt8
ssh_eap_packet_calculate_hmac_sha256(SshBuffer pkt,
                                     unsigned char *aut_key,
                                     unsigned char *add_data,
                                     SshUInt16 add_data_len,
                                     Boolean verify);
/* Calculate MAC for EAP message with HMAC-SHA1. */
SshUInt8
ssh_eap_packet_calculate_hmac_sha(SshBuffer pkt,
                                  unsigned char *aut_key,
                                  unsigned char *add_data,
                                  SshUInt16 add_data_len,
                                  Boolean verify);

SshBuffer
ssh_eap_packet_append_res_attr(SshBuffer pkt,
                               SshUInt8 *res,
                               SshUInt8 res_len);

/* This function returns a pointer to the start
   of the MAC value in the packet. */
unsigned char *
ssh_eap_packet_append_empty_mac_attr(SshBuffer pkt);

SshBuffer
ssh_eap_packet_append_auts_attr(SshBuffer pkt, SshUInt8 *auts);

SshBuffer
ssh_eap_packet_append_nonce_attr(SshBuffer pkt,
                                 SshUInt8 *nonce);

SshBuffer
ssh_eap_packet_append_selected_version_attr(SshBuffer pkt,
                                            SshUInt8 *version);

SshBuffer
ssh_eap_packet_append_identity_attr(SshBuffer pkt,
                                    const SshUInt8 *id,
                                    SshUInt8 id_len);

SshUInt8
ssh_eap_packet_get_code(SshBuffer buf);

SshUInt8
ssh_eap_packet_get_identifier(SshBuffer buf);

SshUInt16
ssh_eap_packet_get_length(SshBuffer buf);

void
ssh_eap_packet_strip_pad(SshBuffer buf);

SshUInt8
ssh_eap_packet_get_type(SshBuffer buf);

Boolean
ssh_eap_packet_isvalid(SshBuffer buf);

Boolean
ssh_eap_packet_isvalid_ptr(SshUInt8 *buf, unsigned long len);

void
ssh_eap_packet_skip_hdr(SshBuffer buf);

Boolean
ssh_eap_packet_build_hdr(SshBuffer buf,
                         SshUInt8 code,
                         SshUInt8 id,
                         SshUInt16 length);

Boolean
ssh_eap_packet_build_hdr_with_type(SshBuffer buf,
                                   SshUInt8 code,
                                   SshUInt8 id,
                                   SshUInt16 length,
                                   SshUInt8 type);
#endif
