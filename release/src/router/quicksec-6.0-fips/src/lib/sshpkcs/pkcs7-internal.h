/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding
   and decoding.

   This library is low level one, meaning that knowledge of
   cryptography is kept in minimum, though PKCS #7 is very much tied to
   cryptography.  (This library may perform some conversion from SSH
   cryptographic names to ASN.1 OIDs defined in PKCS standards.)

   This library can handle BER or DER encoded PKCS #7 messages,
   however, it produces DER messages. This is because the underlaying
   ASN.1 BER/DER code is biased towards DER.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "sshber.h"
#include "sshgetput.h"
#include "sshglist.h"

#include "x509.h"
#include "x509internal.h"
#include "oid.h"

typedef struct SshPkcs7CipherInfoRec
{
  /* Note; hash, salt and salt_len are for PKCS12 which is not
     nice. */
  unsigned char *name;
  char *hash;
  unsigned char *iv, *salt;
  size_t iv_len, salt_len;
  SshUInt32 block_length;
  SshUInt32 key_length;
  SshUInt32 rounds;
} *SshPkcs7CipherInfo;

/* Implementation of datatypes at pkcs7.h */
struct SshPkcs7SignerInfoRec
{
  struct SshPkcs7SignerInfoRec *next;

  /* The issuer distinguished name and serial number */
  SshX509Name issuer_name;
  SshMPIntegerStruct   serial_number;

  /* The digesting and signature algorithm names. */
  unsigned char *digest_algorithm;
  unsigned char *digest_encryption_algorithm;

  /* Authenticated and unauthenticated attributes. */
  SshGList auth_attributes;
  SshGList unauth_attributes;

  /* Encrypted digest and digest encryption key */
  SshPrivateKey  private_key;
  unsigned char *encrypted_digest;
  size_t         encrypted_digest_length;

  /* For detached signature created by this signer. */
  Boolean        detached;
};

struct SshPkcs7RecipientInfoRec
{
  struct SshPkcs7RecipientInfoRec *next;

  /* The issuer distinguished name and serial number */
  SshX509Name issuer_name;
  SshMPIntegerStruct   serial_number;

  /* Key encryption algorithm name. */
  unsigned char *key_encryption_algorithm;

  /* Encrypted key and the key encryption key. */
  SshPublicKey   public_key;
  unsigned char *encrypted_key;
  size_t         encrypted_key_length;
};

struct SshPkcs7Rec
{
  SshPkcs7ContentType type;
  SshWord version;

  /* The content type of the encrypted data inside the content */
  SshPkcs7ContentType encrypted_type;
  SshPkcs7 content;

  /* The plain or encrypted data. */
  unsigned char *data;
  size_t         data_length;

  /* Certificate and CRL lists for signed data contents */
  SshGList certificates;
  SshGList crls;

  /* List of digest algorithm OIDs. */
  SshGList digest_algorithms;

  /* List of signer and recipient informations. */
  SshGList signer_infos;
  SshGList recipient_infos;

  /* Content encryption algorithm for enveloped and encrypted types */
  struct SshPkcs7CipherInfoRec cipher_info;
#define content_encryption_algorithm cipher_info.name
#define content_encryption_iv        cipher_info.iv
#define content_encryption_iv_len    cipher_info.iv_len
#define content_encryption_key_len   cipher_info.key_length
#define content_encryption_salt      cipher_info.salt
#define content_encryption_salt_len  cipher_info.salt_len

  /* The digesting algorithm and the digest */
  unsigned char *content_digest_algorithm;
  unsigned char *content_digest;
  size_t         content_digest_length;

  /* The BER encoding of the PKCS7 blob. */
  unsigned char *ber;
  size_t         ber_length;
};




typedef struct SshPkcs7AsyncOpContextRec *SshPkcs7AsyncOpContext;

typedef struct SshPkcs7AsyncSubOpContextRec
{
  struct SshPkcs7AsyncSubOpContextRec *next;
  SshPkcs7AsyncOpContext parentop;
  SshOperationHandle op;
  void *info;
} *SshPkcs7AsyncSubOpContext, SshPkcs7AsyncSubOpContextStruct;

struct SshPkcs7AsyncOpContextRec
{
  SshOperationHandle op;

  SshPkcs7AsyncSubOpContext subops;
  SshUInt16 numops;
  SshUInt16 numsuccess;
  SshPkcs7Status status;
  SshPkcs7 content;
  SshPkcs7AsyncCB done_callback;
  void *done_callback_context;
};

void pkcs7_async_abort(void *context);
void
pkcs7_select_signature_scheme(SshPkcs7SignerInfo signer,
                              SshPublicKey public_key);
unsigned char *
pkcs7_get_digested_data(unsigned char *ber, size_t ber_len,
                        size_t *data_len);

void ssh_pkcs7_glist_oid_free(SshGListNode node, void *context);
void ssh_pkcs7_glist_certificate_free(SshGListNode node, void *context);
void ssh_pkcs7_glist_crl_free(SshGListNode node, void *context);
void ssh_pkcs7_glist_signer_info_free(SshGListNode node, void *context);
void ssh_pkcs7_glist_recipient_info_free(SshGListNode node, void *context);

void ssh_pkcs7_signer_info_init(SshPkcs7SignerInfo info);
void ssh_pkcs7_recipient_info_init(SshPkcs7RecipientInfo info);

const char *ssh_pkcs7_content_type_oids(SshPkcs7ContentType type);
const char *ssh_pkcs7_algorithm_oids(const unsigned char *name);

SshPkcs7 ssh_pkcs7_allocate(void);
void ssh_pkcs7_free(SshPkcs7 pkcs7);

SshPkcs7Status
ssh_pkcs7_encode_data(SshPkcs7 pkcs7,
                      unsigned char **data, size_t *data_length);

SshPkcs7
pkcs7_decrypt_content(const unsigned char *data_encryption,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *iv, size_t iv_len,
                      unsigned char *data, size_t data_len,
                      SshPkcs7ContentType subtype);
unsigned char *
pkcs7_encrypt_content(SshPkcs7 content,
                      const unsigned char *algorithm,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *salt, size_t salt_len,
                      size_t *encrypted_len);

unsigned char *
pkcs7_digest_content(SshPkcs7 content,
                     unsigned char *algorithm,
                     SshPkcs7SignerInfo signer,
                     size_t *digest_len);
unsigned char *
pkcs7_verify_content(SshPkcs7 content,
                     const unsigned char *algorithm,
                     SshPkcs7SignerInfo signer,
                     const unsigned char *expected_digest,
                     size_t *digest_len);
SshPkcs7
pkcs7_create_signed_data(SshPkcs7 content);

SshPkcs7
pkcs7_create_enveloped_data(SshPkcs7 content,
                            const char *data_encryption,
                            const unsigned char *key,
                            size_t key_len);

unsigned char *
pkcs7_generate_iv(const unsigned char *ciphername,
                  const unsigned char *key, size_t key_len,
                  char **hash, SshUInt32 *rounds,
                  unsigned char **salt, size_t *salt_len,
                  size_t *len);

#define ADDOID(_list, _name)                                            \
do {                                                                    \
  const char *o, *oids = ssh_pkcs7_algorithm_oids((_name));             \
  Boolean foundoid = FALSE;                                             \
  SshGListNode gnode;                                                   \
                                                                        \
  if (oids)                                                             \
    {                                                                   \
      for (gnode = (_list)->head; gnode; gnode = gnode->next)           \
        {                                                               \
          o = gnode->data;                                              \
          if (strcmp(o, oids) == 0)                                     \
            foundoid = TRUE;                                            \
        }                                                               \
      if (!foundoid)                                                    \
        ssh_glist_add_item((_list), ssh_strdup(oids), SSH_GLIST_TAIL);  \
    }                                                                   \
} while (0)
