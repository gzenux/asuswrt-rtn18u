/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for parsing x509 form's.
*/

#ifndef PARSE_X509_FORMS_H
#define PARSE_X509_FORMS_H

#include "sshexternalkey.h"

typedef enum
{
  SSH_X509_FORM_LIST_TYPE_NONE,
  SSH_X509_FORM_LIST_TYPE_CERT,
  SSH_X509_FORM_LIST_TYPE_CRL,
  SSH_X509_FORM_LIST_TYPE_REQUEST,
  SSH_X509_FORM_LIST_TYPE_PROVIDER,
  SSH_X509_FORM_LIST_TYPE_KEY,
  SSH_X509_FORM_LIST_TYPE_GEN_KEY
} SshX509FormListType;

/* Information for adding an external key provider */
typedef struct SshX509FormAddProviderRec
{
  /* Provider type */
  char *type;

  /* Optional initialization string */
  char *init_str;

  /* Provider flags */
  SshEkProviderFlags flags;

  /* Number of seconds we should wait for this provider */
  unsigned int timeout_sec;
} SshX509FormAddProviderStruct, *SshX509FormAddProvider;


typedef enum
{
  /* Named curve  */
  SSH_X509_ECP_CURVE_ENCODING_NAMED,
  /* Explicit */
  SSH_X509_ECP_CURVE_ENCODING_EXPLICIT,
  /* Implicit CA */
  SSH_X509_ECP_CURVE_ENCODING_IMPLICIT_CA
}SshX509ECPCurveEncoding;

typedef enum
{
  /* Compressed */
  SSH_X509_ECP_POINT_ENCODING_COMPRESSED,
  /* Uncompressed */
  SSH_X509_ECP_POINT_ENCODING_UNCOMPRESSED,
  /* Hybrid */
  SSH_X509_ECP_POINT_ENCODING_HYBRID,
}SshX509ECPPointEncoding;


typedef struct SshX509FormECPPrvKeyAttrRec
{
  /* Name of the ECP fixed curve */
  char * curve_name;
  /* Encoding type of the curve */
  SshX509ECPCurveEncoding curve_encoding;
  /* Point encoding */
  SshX509ECPPointEncoding point_encoding;
}SshX509FormECPPrvKeyAttrStruct, *SshX509FormECPPrvKeyAttr;

/* Information about private key */
typedef struct SshX509FormPrivateKeyRec
{
  /* Internal name of this key, which is used by Certmake
     to locate the key information. */
  char *name;

  /* Key attributes. This is used for ecdsa keys only for now */
  void * key_attrs;

  /* Keypath (for example, "software://0/my-key-file.prv") */
  char *key_path;

  /* Authentication string (optional). Will be returned
     if EK provider calls the authentication callback */
  char *auth_code;

  /* Keys are kept in a linked list */
  struct SshX509FormPrivateKeyRec *next;

  /* Private key object */
  SshPrivateKey prv_key;

  /* Public Key object. */
  SshPublicKey pub_key;
} SshX509FormPrivateKeyStruct, *SshX509FormPrivateKey;

/* Certmake supports the creation of software keys */
typedef struct SshX509FormGenPrivateKeyRec
{
  SshX509FormPrivateKeyStruct key;

  /* File where the created private key will be written */
  char *output_file;

  /* Key generation parameters */
  const char *pk_type;
  const SshOidPkStruct *pk_extra;
  unsigned int pk_key_bits;
} SshX509FormGenPrivateKeyStruct, *SshX509FormGenPrivateKey;


/* The container for internal data handling. */
typedef struct SshX509FormContainerRec
{
  struct SshX509FormContainerRec *prev;

  /* Indicates which field of CURRENT is used */
  SshX509FormListType type;
  union {
    SshX509Certificate       cert;
    SshX509Crl               crl;
    SshX509FormAddProvider   provider;
    SshX509FormPrivateKey    pkey;
    SshX509FormGenPrivateKey gen_pkey;
  } current;

  /* Subject private key name */
  char *subject_key;

  /* Private key name certificate issuer */
  char *issuer_prv_key;

  /* Alternatively, a certificate may be self-signed */
  Boolean self_signed;

  char *input_request_file;
  char *output_file;

  /* Some extra data, used in processing the input. */
  SshX509ReqExtensionStyle request_extension_style;
  SshUInt32 copy_from_request;
#define SSH_X509_FORM_COPY_FROM_REQ_SUBJECT_NAME                0x00000001
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_IP              0x00000010
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_EMAIL           0x00000020
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DNS             0x00000040
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_URI             0x00000080
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_RID             0x00000100
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DN              0x00000200
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_KEY_USAGE               0x00001000
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_BASIC_CONSTRAINTS       0x00002000
#define SSH_X509_FORM_COPY_FROM_REQ_EXT_CRL_DIST_POINT          0x00004000
  /* Add more when more extensions are supported */
} *SshX509FormContainer, SshX509FormContainerStruct;

typedef struct SshX509FormNodeRec
{
  struct SshX509FormNodeRec *next;
  /* The type of the data in the context. */
  SshX509FormListType type;
  /* Context containing either: certificate, crl or certificate request. */
  SshX509FormContainer container;
} *SshX509FormNode, SshX509FormNodeStruct;

typedef struct SshX509FormListRec
{
  SshX509FormNode head, tail, current;
  /* Issuer private key given for all signing operations.
     (If not self-signed.) */
  /*SshPrivateKey issuer_prv_key;*/
} *SshX509FormList, SshX509FormListStruct;

/* Routines for handling form lists. */

/* Allocate a form list. */
void ssh_x509_form_list_init(SshX509FormList list, SshCharset encoding);

/* Allocate a form list node. */
SshX509FormNode ssh_x509_form_list_node_alloc(void);

/* Add an entry to the rest of the list. */
void ssh_x509_form_list_add(SshX509FormList list, SshX509FormNode node);

/* Free the list entries, but don't free the actual contexts. */
void ssh_x509_form_list_free(SshX509FormList list);

/* Free the list entries, and free the actual contexts. */
void ssh_x509_form_list_free_all(SshX509FormList list);

/* Parse the form given in buf, buf_size and add all the certificates,
   crls, and certificate requests to the respective form lists. Application
   should make sure that everything gets free'd nicely. */
void ssh_x509_form_parse(unsigned char *buf, size_t buf_len,
                         SshX509FormList forms,
                         SshPSystemError error);

#endif /* PARSE_X509_FORMS_H */
