/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initialize CA engine's external key providers.
*/

#ifndef _AU_EK_H_
#define _AU_EK_H_

typedef struct SshAuProviderRec
{
  char *type;
  char *info;
} *SshAuProvider, SshAuProviderRec;

typedef void (*SshAuEKStartCB)(SshExternalKey ek, void *context);
void
ssh_au_ek_init(SshAuProvider providers,
               int numproviders,
               SshEkAuthenticationCB auth,
               SshEkNotifyCB notify,
               void *ek_context,
               SshAuEKStartCB done, void *done_context);

typedef void (*SshAuEKKeyCB)(SshEkStatus status,
                             SshPrivateKey prv, SshPublicKey pub,
                             const unsigned char *cert, size_t cert_len,
                             void *context);

SshOperationHandle
au_ek_get_keypair(SshExternalKey ek,
                  const char *private_key_path,
                  const char *public_key_path,
                  SshAuEKKeyCB callback, void *callback_context);

Boolean
au_read_certificate(const char *path,
                    unsigned char **der, size_t *der_len,
                    SshX509Certificate *opencert);
void
au_cert_set_subject(SshX509Certificate t,
                    SshCharset subject_charset, const char *subject);
void
au_cert_set_key_usage(SshX509Certificate t, const char *usestr);
void
au_cert_set_ext_key_usage(SshX509Certificate t, const char *usestr);

void au_help_subject(void);
void au_help_keytypes(void);
void au_help_extensions(void);

#endif /* _AU_EK_H_ */
