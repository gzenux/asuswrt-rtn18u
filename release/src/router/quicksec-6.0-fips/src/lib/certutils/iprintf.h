/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   iprintf.h
*/

#ifndef IPRINTF_H
#define IPRINTF_H

#include "sshmp.h"
#include "x509.h"

void iprintf_set(int line_width, int indent_level, int indent_step);
void iprintf_get(int *line_width, int *indent_level, int *indent_step);
void iprintf(const char *str, ...);

void cu_dump_critical(Boolean critical);
void cu_dump_time(SshBerTime ber_time);
void cu_dump_reason(SshX509ReasonFlags flags);
void cu_dump_fingerprints(const unsigned char *der, size_t der_len);

Boolean cu_dump_number(SshMPInteger number, int base);
Boolean cu_dump_pub(SshPublicKey pub, int base);
Boolean cu_dump_prv(SshPrivateKey prv, int base);

void cu_dump_hex_and_text(unsigned char *buf, size_t len);

void
cu_dump_name(SshStr name_str, SshCharset output, Boolean ldap);

Boolean cu_dump_ber(unsigned char *buf, size_t buf_size, size_t offset,
                    Boolean no_string_decode, Boolean print_offsets);

Boolean
cu_dump_names(SshX509Name names, SshCharset output, Boolean ldap);

Boolean
cu_dump_key_id(SshX509ExtKeyId key_id,
               SshCharset output, Boolean ldap, int base);


Boolean
cu_dump_cert(SshX509Certificate c,
             const unsigned char *der, size_t der_len,
             SshX509CertType cert_type,
             SshCharset output, Boolean ldap, int base, Boolean verify);

Boolean
cu_dump_crl(SshX509Crl crl,
            SshCharset output, Boolean ldap, int base);

typedef enum {
  CU_CERT_KIND_USER       = (1 << 0),
  CU_CERT_KIND_CA         = (1 << 1),
  CU_CERT_KIND_TOPLEVEL   = (1 << 2),
  CU_CERT_KIND_SIGNATURE  = (1 << 3),
  CU_CERT_KIND_ENCRYPTION = (1 << 4)
} CuCertKind;
CuCertKind cu_determine_cert_kind(SshX509Certificate cert);

#endif /* IPRINTF_H */
