/**
   @copyright
   Copyright (c) 2014 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_HASH_OID_H
#define SSH_HASH_OID_H

size_t
ssh_hash_oid_asn1_compare_md5(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_md5(size_t *len);

size_t
ssh_hash_oid_asn1_compare_sha(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_sha(size_t *len);

size_t
ssh_hash_oid_asn1_compare_sha224(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_sha224(size_t *len);

size_t
ssh_hash_oid_asn1_compare_sha256(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_sha256(size_t *len);

size_t
ssh_hash_oid_asn1_compare_sha384(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_sha384(size_t *len);

size_t
ssh_hash_oid_asn1_compare_sha512(const unsigned char *oid, size_t max_len);

const unsigned char *
ssh_hash_oid_asn1_generate_sha512(size_t *len);

#endif /* SSH_HASH_OID_H */
