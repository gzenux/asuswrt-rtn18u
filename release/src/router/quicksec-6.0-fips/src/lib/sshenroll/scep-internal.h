/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

typedef struct ScepUserQueryContextRec
{
  /* The response top level node. */
  SshPkcs7 top;
  SshPkcs7 content;
  SshPkcs7RecipientInfo recipient;
  SshPkcs7SignerInfo signer;

  SshScepClientCertAndKeyReq client_request_callback;
  SshScepClientResultCB client_result_callback;
  void *result_callback_context;

  /* the original response received. */
  const unsigned char *data;
  size_t data_len;
  struct SshScepTransactionAndNonceRec txnonce;
  unsigned char *enveloping_certificate;
  size_t enveloping_certificate_len;

  SshPublicKey ca_public_key;
  SshPrivateKey private_key;
  SshFSM fsm;
  SshFSMThreadStruct thread;
} *ScepUserQueryContext;

#define SCEP_TXTYPE "2.16.840.1.113733.1.9.2"
#define SCEP_STATUS "2.16.840.1.113733.1.9.3"
#define SCEP_FINFO  "2.16.840.1.113733.1.9.4"
#define SCEP_SNONCE "2.16.840.1.113733.1.9.5"
#define SCEP_RNONCE "2.16.840.1.113733.1.9.6"
#define SCEP_TXID   "2.16.840.1.113733.1.9.7"

SshX509Attribute
scep_add_attribute(SshX509Attribute next,
                   unsigned int ber_tag_type,
                   const char *oid,
                   const unsigned char *data, size_t data_len);

SshX509Attribute
scep_add_attributes(char *type,
                    char *status, char *failure,
                    unsigned char *snonce, size_t snonce_len,
                    unsigned char *rnonce, size_t rnonce_len,
                    unsigned char *txid, size_t txid_len);


Boolean scep_decode_string_attribute(SshAsn1Context context,
                                     SshX509Attribute attr,
                                     unsigned char **str,
                                     size_t *strlen);

#define DECODE_STRING(context, attr, str, strlen)                         \
  do {                                                                    \
    if (!scep_decode_string_attribute((context), (attr),                  \
                      (unsigned char **)((unsigned char *)&str),          \
                      (strlen)))                                          \
      goto failure;                                                       \
  } while (0)
