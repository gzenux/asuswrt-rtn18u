/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ECP (fixed curves) helper routines
*/

#ifndef EC_KEYS_H
#define EC_KEYS_H

#ifdef SSHDIST_CRYPT_ECP
/** Flags for controlling options encoded with private key */
#define SSH_X509_ECP_ENCODE_PARAMS      0x00000001
#define SSH_X509_ECP_ENCODE_PUBLIC_KEY  0x00000002
#define SSH_X509_ECP_ENCODE_ALL         0X00000003


/** Decode the ASN.1 sequence to get the curve properties. */
SshX509Status ssh_x509_decode_ecp_curve(SshAsn1Context context,
                                        SshAsn1Node param,
                                        SshECPCurve E,
                                        SshECPPoint P,
                                        SshMPInteger order,
                                        const char **curve_name,
                                        size_t *field_len);

/** DER Encode the elliptic curve private key. The memory for the
    encoding is allocated by the routine which must be freed by the
    caller*/

Boolean ssh_x509_encode_ecp_private_key_internal(SshPrivateKey key,
                                                 SshUInt32 encode_flags,
                                                 unsigned char **buf,
                                                 size_t *buf_len);

/** DER Encode the elliptic curve public key. The memory for the
    encoding is allocated by the routine which must be freed by the
    caller*/
Boolean ssh_x509_encode_ecp_public_key_internal(SshPublicKey key,
                                                unsigned char **buf,
                                                size_t *buf_len);

/** Returns the ASN1 node encapsulating ECP key params. The ASN1
    node must be freed by the caller */
Boolean ssh_x509_encode_ecp_key_params(void * key,
                                       Boolean is_public,
                                       unsigned char **params,
                                       size_t *param_len);

#endif /* SSHDIST_CRYPT_ECP */
#endif /* EC_KEYS_H */
