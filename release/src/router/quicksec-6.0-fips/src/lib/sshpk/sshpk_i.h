/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for internal use of sshpk library.
*/

#ifndef SSHPK_I_H
#define SSHPK_I_H

#include "sshcrypt.h"
#ifdef SSHDIST_MATH
#include "sshmp.h"
#endif /* SSHDIST_MATH */
#include "sshcrypt_i.h"
#include "sshhash_i.h"
#include "sshrgf.h"
#include "sshglobals.h"

/* SSH public key methods, that are visible through the generic
   interface, are defined here. The motivation for this system is to
   support discrete logarithm (dl), integer factorization (if) and
   elliptic curve (ec) based systems with equal ease.

   We represent a public key cryptosystem with

   key types:

     which stand for the underlying cryptosystem. For example, cryptosystems
     which are based on integer factorization modulo an integer n, have the
     key type if-modn, of which the prime example is RSA. For cryptosystems
     based on the discrete logarithm modulo a prime we have the key type
     dl-modp. The Diffie-Hellman key exchange and the DSA signature
     algorithm are both examples of algorithms which use the underlying key
     type dl-modp (although Diffie-Hellman can also be performed for other
     key types such as elliptic curve based cryptosystems).

     The key types are the highest structure of the public key cryptosystem.
     A public key/private key/group must be of some key type (although not
     neccessarily either of dl-modp or if-modn).

     Currently supported key types are:

       if-modn
       dl-modp
       ec-modp
       ec-gf2n

     it is also possible to add e.g.

       lu-modp (Lucas functions over finite field (mod p))

     Key types are defined as large structures containing function
     pointers. This style is used in all algorithm definitions here.


   schemes:

     which stand for some specific method or algorithm. Note that there
     are possibly many variations of one algorithm, thus exact naming of
     an algorithm is a must. Obviously all algorithms must have a unique name.

     We have divided schemes into three scheme classes:

       sign    = signature schemes
       encrypt = encryption schemes
       dh      = Diffie-Hellman schemes (there seems to be just one)

     A particular scheme will then be defined by the scheme class and the
     algorithm (or scheme) name in that particular scheme class. For example
     the scheme sign{dsa-nist-sha1} corresponds to the DSA NIST signature
     scheme, and the scheme encrypt{rsa-pkcs1v2-oaep} corresponds to RSA
     encryption with PKCS1v2 OAEP padding. For a fixed key type and scheme
     class, the algorithm names usually correspond to the different hashing or
     padding operations that are applied to data before (or after) the
     underlying operation.

     Schemes are defined as large structures (of many different types)
     containing function pointers. The defined scheme types are

       SshPkSignature
       SshPkEncryption
       SshPkDiffieHellman

     We see no need at present to add any new scheme types although the
     following have been considered

       SshPkOneWayAuthentication
       SshPkTwoWayAuthentication
       SshPkMenezesQuVanstoneProtocol

   key names:

     SSH public keys, private keys and groups have names which specify their
     underlying key type and their scheme.

     The naming format is of the following form

       key-type{scheme-class{algorithm-name},scheme-class{algorithm-name},...}

     which are listed in a comma separated list. The {algorithm-name}
     following the scheme-class can be optionally omitted. In this case
     algorithm-name is internally expanded to "plain", e.g. the names
     2) and 3) below are equivalent.

     The following are valid key names (as an example):

     1)  if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}},
     2)  dl-modp{sign{dsa-nist-sha1},dh{plain}}
     3)  dl-modp{sign{dsa-nist-sha1},dh}
     4)  dl-modp{dh}
     5)  dl-modp     (No schemes have been defined for such a key)



    Here we define a default name, that can be used to indicate that a name
    like dl-modp{scheme-name} is also valid. This is expanded to
    dl-modp{scheme-name{plain}}  */
#define SSH_PK_USUAL_NAME "plain"

/*
   actions:

     Actions are used to extract or place context information (such
     as multiple precision integers which define the public or private
     key parameters) into key structures.

     The following flag is used with actions to indicate that

     - action can be used to extract or place information into
       keys structures.
     - action is used to extract the key type information.
     - defines for which type (private key/public key/group) for which
       this action may be used for.

   */

typedef unsigned int SshPkActionFlag;
#define SSH_PK_ACTION_FLAG_GET_PUT       1
#define SSH_PK_ACTION_FLAG_KEY_TYPE      2
#define SSH_PK_ACTION_FLAG_PRIVATE_KEY   4
#define SSH_PK_ACTION_FLAG_PUBLIC_KEY    8
#define SSH_PK_ACTION_FLAG_PK_GROUP      16

/* The action functions (get/put). These format argument decides how
   the vararg list at ap is processed. The action function shall
   return a string describing what the function did. The return is a
   string containing characters:

     `b' boolean,
     `c' character,
     `s' short, `i' integer, `l' long or
     `p' pointer.

   indicating what kind of data the function did process from the
   argument list. E.g. "bpip" as return value indicates the function
   processed four arguments, in order boolean, pointer, integer,
   pointer. If the action function fails for some reason, it must
   return NULL.
*/

/* PUT function reads from ap and fills in the private key type
   specific context (for example prime value can be set using this
   function). 'input_context' is unused and may be ignored. */
typedef const char * (*SshPkActionPut)(void *context,
                                       va_list ap,
                                       void *input_context,
                                       SshPkFormat format);

/* GET function fills into the varible pointed by va_arg(ap) the value
   specified by format from key specific context. 'output_context' is
   unused and may be ignored. */
typedef const char * (*SshPkActionGet)(void *context,
                                       va_list ap,
                                       void **output_context,
                                       SshPkFormat format);

typedef struct SshPkActionRec
{
  /* Type of this action. */
  SshPkFormat format;

  /* Flags to define what this action contains and where it can be used. */
  SshPkActionFlag flags;

  /* Action functions. Functions to put and take information from
     contexts.

     The main idea is, as explained before, when generating either a
     private key or group, to generate a temporary context to where
     action_put can add key information. action_put will not be used
     elsewhere.

     action_get on the otherhand will work with the actual
     private key/public key/group contexts. That is it is allowed to
     take out even "secret" information. */

  SshPkActionPut action_put;
  SshPkActionGet action_get;
} SshPkAction;

/* Scheme structure definition.

   NOTE! All following structures MUST start with const char *name, this
   is assumed in the following code. */

/* Signature schemes */
typedef struct
{
  /* Names can contain any ascii characters except for  ",{}" which are
     used to separate them in the key names. All signature algorithm names
     should be unique. */
  const char *name;

  /* RGF to use with this scheme. */
  const SshRGFDefStruct *rgf_def;

  /* Maximum lengths for signature output/input. */
  size_t (*private_key_max_signature_input_len)(const void *private_key,
                                                SshRGF rgf);
  size_t (*private_key_max_signature_output_len)(const void *private_key,
                                                 SshRGF rgf);

  SshCryptoStatus (*public_key_verify)(const void *public_key,
                                       const unsigned char *signature,
                                       size_t signature_len,
                                       SshRGF rgf);

  SshOperationHandle (*public_key_verify_async)(const void *public_key,
                                                const unsigned char *signature,
                                                size_t signature_len,
                                                SshRGF rgf,
                                                SshPublicKeyVerifyCB callback,
                                                void *context);

  SshCryptoStatus (*private_key_sign)(const void *private_key,
                                      SshRGF rgf,
                                      unsigned char *signature_buffer,
                                      size_t signature_buffer_len,
                                      size_t *signature_length_return);

  SshOperationHandle (*private_key_sign_async)(const void *private_key,
                                               SshRGF rgf,
                                               SshPrivateKeySignCB callback,
                                               void *context);
} SshPkSignature;

/* Encryption schemes */
typedef struct
{
  /* Names can contain any ascii characters except for  ",{}" which are
     used to separate them in the key names. All encryption algorithm names
     should be unique. */
  const char *name;

  /* RGF for padding and redundancy. */
  const SshRGFDefStruct *rgf_def;

  /* Decryption input/output maximum buffer lengths. */
  size_t (*private_key_max_decrypt_input_len)(const void *private_key,
                                              SshRGF rgf);
  size_t (*private_key_max_decrypt_output_len)(const void *private_key,
                                               SshRGF rgf);

  /* Private key decryption. */
  SshCryptoStatus (*private_key_decrypt)(const void *private_key,
                                         const unsigned char *ciphertext,
                                         size_t ciphertext_len,
                                         unsigned char *plaintext_buffer,
                                         size_t plaintext_buffer_len,
                                         size_t *plaintext_length_return,
                                         SshRGF rgf);

  /* Private key decrypt async. */
  SshOperationHandle
    (*private_key_decrypt_async)(const void *private_key,
                                 const unsigned char *ciphertext,
                                 size_t ciphertext_len,
                                 SshRGF rgf,
                                 SshPrivateKeyDecryptCB callback,
                                 void *context);

  /* Maximum encryption output/input buffer lengths. */
  size_t (*public_key_max_encrypt_input_len)(const void *public_key,
                                             SshRGF rgf);
  size_t (*public_key_max_encrypt_output_len)(const void *public_key,
                                              SshRGF rgf);

  /* Encryption with the public key. */
  SshCryptoStatus (*public_key_encrypt)(const void *public_key,
                                        const unsigned char *plaintext,
                                        size_t plaintext_len,
                                        unsigned char *ciphertext_buffer,
                                        size_t ciphertext_buffer_len,
                                        size_t *ciphertext_len_return,
                                        SshRGF rgf);

  SshOperationHandle
    (*public_key_encrypt_async)(const void *public_key,
                                const unsigned char *plaintext,
                                size_t plaintext_len,
                                SshRGF rgf,
                                SshPublicKeyEncryptCB callback,
                                void *context);
} SshPkEncryption;


/* The structure used to store Diffie-Hellman secret data. */
struct SshPkGroupDHSecretRec
{
  /* The length in bytes of the secret data. */
  size_t len;
  /* The secret data. */
  unsigned char *buf;
};


/* Diffie-Hellman */
typedef struct
{
  /* Names can contain any ascii characters except for  ",{}" which are
     used to separate them in the key names. All DH algorithm names
     should be unique. */
  const char *name;

  /* Diffie-Hellman internal interface definitions */

  size_t (*diffie_hellman_exchange_max_length)(const void *pk_group);
  size_t (*diffie_hellman_secret_value_max_length)(const void *pk_group);

  SshCryptoStatus (*diffie_hellman_setup)(const void *pk_group,
                                          SshPkGroupDHSecret *secret,
                                          unsigned char *exchange_buffer,
                                          size_t exchange_buffer_length,
                                          size_t *return_length);

  SshOperationHandle (*diffie_hellman_setup_async)(void *pk_group,
                                                   SshPkGroupDHSetup callback,
                                                   void *context);

  SshCryptoStatus (*diffie_hellman_agree)(const void *pk_group,
                                          SshPkGroupDHSecret secret,
                                          const unsigned char *exchange_buffer,
                                          size_t exchange_buffer_length,
                                          unsigned char *secret_value_buffer,
                                          size_t secret_value_buffer_length,
                                          size_t *return_length);


  SshOperationHandle
    (*diffie_hellman_agree_async)(const void *pk_group,
                                  SshPkGroupDHSecret secret,
                                  const unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  SshPkGroupDHAgree callback,
                                  void *context);
} SshPkDiffieHellman;

/* General main key type structure. This structure defines the most
   important part, the handling of internal key/group contexts. */


/* When generating keys or groups, the init, make (define or
   generate for private keys) and free functions in the key type
   definition below are used in conjunction with actions.
   The init function is used to create a temporary context where
   input (key information) will be stacked. The key information is
   passed in using the vararg list and the SshPkActionPut functions.
   Then when the vararg list is fully traversed, the make is
   invoked to generate the actual context which will be included to
   private/public key or pk group. The free function is then called
   to release the temporary context.
 */
struct SshPkTypeRec
{
  /* Name for key-type. Key typess are named/typed as follows:

       if-modn    for RSA etc.
       dl-modp    for DSA, etc.
       ec-modp    for ECDSA, etc.
       ec-gf2n    for ECDSA, etc.
     */
  const char *name;

  /* Actions, for inserting and extracting key parameters. */
  const SshPkAction *action_list;

  /* List of supported schemes. */
  const SshPkSignature *signature_list;
  const SshPkEncryption *encryption_list;
  const SshPkDiffieHellman *diffie_hellman_list;

  /********************************************************************
   * 1. Group actions
   ********************************************************************/
  SshCryptoStatus (*pk_group_action_init)(void **context);
  SshCryptoStatus (*pk_group_action_make)(void *context, void **group_ctx);
  void            (*pk_group_action_free)(void *context);

  SshCryptoStatus (*pk_group_import)(const unsigned char *buf,
                                     size_t length,
                                     void **pk_group);
  SshCryptoStatus (*pk_group_export)(const void *pk_group,
                                     unsigned char **buf,
                                     size_t *length_return);
  void            (*pk_group_free)(void *pk_group);
  SshCryptoStatus (*pk_group_copy)(void *op_src, void **op_dest);

  char *          (*pk_group_get_predefined_groups)(void);
  SshCryptoStatus (*pk_group_precompute)(void *context);

  /* Randomizer handling. */
  unsigned int (*pk_group_count_randomizers)(void *pk_group);

  void (*pk_group_dh_return_randomizer)(void *pk_group,
                                        SshPkGroupDHSecret secret,
                                        const unsigned char *exchange_buf,
                                        size_t exchange_buf_len);

  SshCryptoStatus (*pk_group_generate_randomizer)(void *pk_group);
  SshCryptoStatus (*pk_group_export_randomizer)(void *pk_group,
                                                unsigned char **buf,
                                                size_t *length_return);
  SshCryptoStatus (*pk_group_import_randomizer)(void *pk_group,
                                                const unsigned char *buf,
                                                size_t length);

  /********************************************************************
   * 2. Public key actions
   ********************************************************************/
  SshCryptoStatus (*public_key_action_init)(void **context);
  SshCryptoStatus (*public_key_action_make)(void *context, void **key_ctx);
  void            (*public_key_action_free)(void *context);

  SshCryptoStatus (*public_key_import)(const unsigned char *buf,
                                       size_t len,
                                       void **public_key);
  SshCryptoStatus (*public_key_export)(const void *public_key,
                                       unsigned char **buf,
                                       size_t *length_return);
  void            (*public_key_free)(void *public_key);
  SshCryptoStatus (*public_key_copy)(void *op_src, void **op_dest);

  SshCryptoStatus (*public_key_derive_pk_group)(void *public_key,
                                                void **pk_group);
  SshCryptoStatus (*public_key_precompute)(void *context);

  /********************************************************************
   * 3. Private key actions
   ********************************************************************/
  SshCryptoStatus (*private_key_action_init)(void **context);
  SshCryptoStatus (*private_key_action_define)(void *context, void **key_ctx);
  SshCryptoStatus (*private_key_action_generate)(void *context,
                                                 void **key_ctx);
  void            (*private_key_action_free)(void *context);

  SshCryptoStatus (*private_key_import)(const unsigned char *buf,
                                        size_t len,
                                        void **private_key);
  SshCryptoStatus (*private_key_export)(const void *private_key,
                                        unsigned char **buf,
                                        size_t *length_return);
  void            (*private_key_free)(void *private_key);
  SshCryptoStatus (*private_key_derive_public_key)(const void *private_key,
                                                   void **public_key);

  SshCryptoStatus (*private_key_copy)(void *op_src, void **op_dest);

  SshCryptoStatus (*private_key_derive_pk_group)(void *private_key,
                                                 void **pk_group);
  SshCryptoStatus (*private_key_precompute)(void *context);

  SshCryptoStatus (*set_key_pointer_to_context)(void *key, void *context);
};


/* Maximum of provider slots. It is assumed that SSH modules will not
   add very many providers. */

#define SSH_PK_TYPE_MAX_SLOTS 16

typedef SshPkType const * SshPkTypeConstPtrArray[SSH_PK_TYPE_MAX_SLOTS];
SSH_GLOBAL_DECLARE(SshPkTypeConstPtrArray, ssh_pk_type_slots);
#define ssh_pk_type_slots SSH_GLOBAL_USE_INIT(ssh_pk_type_slots)

/* Register a public key provider. */
SshCryptoStatus ssh_pk_provider_register(const SshPkType *type);


/* Context that contain all information needed in the generic code. */
typedef struct SshPkGroupObjectRec
{
  SSH_CRYPTO_OBJECT_HEADER

  /* General information (which are supported with just parameters) */
  const SshPkType *type;

  /* Scheme supported. */
  const SshPkDiffieHellman *diffie_hellman;

  /* The key dependent context information. */
  void *context;
} *SshPkGroupObject, SshPkGroupObjectStruct;

typedef struct SshPublicKeyObjectRec
{
  SSH_CRYPTO_OBJECT_HEADER

  /* General information */
  const SshPkType *type;

  /* Schemes */
  const SshPkSignature *signature;
  const SshPkEncryption *encryption;
  const SshPkDiffieHellman *diffie_hellman;

  /* The key dependent context information. */
  void *context;
} *SshPublicKeyObject, SshPublicKeyObjectStruct;

typedef struct SshPrivateKeyObjectRec
{
  SSH_CRYPTO_OBJECT_HEADER

  /* General information */
  const SshPkType *type;

  /* Schemes */
  SshPkSignature *signature;
  SshPkEncryption *encryption;
  const SshPkDiffieHellman *diffie_hellman;

  /* The key dependent context information. */
  void *context;
} *SshPrivateKeyObject, SshPrivateKeyObjectStruct;

/****** End of public key defines (internal utility functions follow). ******/


 /* Some generally handy definitions, which bear no general meaning
    outside some particular context. */

typedef unsigned int SshCryptoType;
#define SSH_CRYPTO_TYPE_PUBLIC_KEY     1
#define SSH_CRYPTO_TYPE_PRIVATE_KEY    2
#define SSH_CRYPTO_TYPE_PK_GROUP       4
#define SSH_CRYPTO_TYPE_CIPHER         8
#define SSH_CRYPTO_TYPE_HASH           16
#define SSH_CRYPTO_TYPE_MAC            32
#define SSH_CRYPTO_TYPE_SECRET_SHARING 64



/* This macro will reprocess the newly opened ap with instructions given
   at fmt. Each character at fmt indicates the size which must be
   consumed from the ap. E.g. fmt 'isp' would consume one integer, one
   short integer and one pointer from the ap. */
#define PROCESS(ap, fmt)                                \
do {                                                    \
  int _i = 0;                                           \
  while ((fmt)[_i] != '\000')                           \
    {                                                   \
      switch ((fmt)[_i])                                \
        {                                               \
        case 'b': (void)va_arg((ap), Boolean); break;   \
        case 'c': (void)va_arg((ap), int); break;       \
        case 's': (void)va_arg((ap), int); break;       \
        case 'i': (void)va_arg((ap), int); break;       \
        case 'l': (void)va_arg((ap), long); break;      \
        case 'p': (void)va_arg((ap), void *); break;    \
        }                                               \
      _i++;                                             \
    }                                                   \
} while (0)


/* Search from action list an entry with the given format and
   that has at least 'flags'. */
const SshPkAction *ssh_pk_find_action(const SshPkAction *list,
                                      SshPkFormat format,
                                      SshPkActionFlag flags);

/* Searches the supported schemes in the SshPkType object, type, for a
   scheme whose scheme class is determined by format (which should be either
   SSH_PKF_SIGN, SSH_PKF_ENCRYPT or SSH_PKF_DH) and with scheme name
   equal to scheme_name. Returns a pointer to the scheme or NULL if no
   such scheme exists. */
void * ssh_pk_find_scheme(const SshPkType *type, SshPkFormat format,
                          const char *scheme_name);

/* Parse the key name, key_name, to return the scheme name corresponding
   to scheme_class (scheme_class should be either "sign", "encrypt" or "dh"),
   caller shall free this. */
char * ssh_pk_get_scheme_name(const char *key_name, const char *scheme_class);

SshCryptoStatus
ssh_private_key_get_scheme_name(SshPrivateKeyObject key,
                                SshPkFormat format,
                                const char **name);

SshCryptoStatus
ssh_pk_group_get_scheme_name(SshPkGroupObject group,
                             SshPkFormat format,
                             const char **name);

/* Functions to set the scheme for particular key or group from
   the scheme name. */
SshCryptoStatus
ssh_private_key_set_scheme(SshPrivateKeyObject key, SshPkFormat format,
                           const char *scheme);
SshCryptoStatus
ssh_public_key_set_scheme(SshPublicKeyObject key, SshPkFormat format,
                          const char *scheme);
SshCryptoStatus
ssh_pk_group_set_scheme(SshPkGroupObject group, SshPkFormat format,
                        const char *scheme);

/* Functions to set the scheme for a particular key or group from
   the key name (the scheme information is contained in key_name). */
SshCryptoStatus
ssh_private_key_set_scheme_from_key_name(SshPrivateKeyObject key,
                                         const char *key_name);
SshCryptoStatus
ssh_public_key_set_scheme_from_key_name(SshPublicKeyObject key,
                                        const char *key_name);
SshCryptoStatus
ssh_pk_group_set_scheme_from_key_name(SshPkGroupObject group,
                                      const char *key_name);

const char * ssh_private_key_find_default_scheme(SshPrivateKeyObject key,
                                                 SshPkFormat format);

const char * ssh_pk_group_find_default_scheme(SshPkGroupObject group,
                                              SshPkFormat format);

/* Return copy of group name, caller shall free this. */
char *ssh_pk_group_name(SshPkGroup group);

/* Return the key type from the key name (the key type is always
   the prefix of the key name). Caller shall free this. */
char * ssh_pk_get_key_type(const char *key_name);

/* Internal public key derivation. This *does not* do key consistency
   test (as the public one does). */
SshCryptoStatus
ssh_private_key_derive_public_key_internal(SshPrivateKeyObject key,
                                           SshPublicKeyObject *public_ret);

SshCryptoStatus
ssh_public_key_object_allocate(const char *type, SshPublicKeyObject *key);
SshCryptoStatus
ssh_private_key_object_allocate(const char *type, SshPrivateKeyObject *key);
SshCryptoStatus
ssh_pk_group_object_allocate(const char *type, SshPkGroupObject *key);

SshCryptoStatus
ssh_private_key_object_define(SshPrivateKeyObject *key_ret,
                              const char *key_type, ...);
SshCryptoStatus
ssh_pk_group_object_generate(SshPkGroupObject *key_ret,
                             const char *key_type, ...);

void
ssh_public_key_object_free(SshPublicKeyObject key);
void
ssh_private_key_object_free(SshPrivateKeyObject key);
void
ssh_pk_group_object_free(SshPkGroupObject key);

size_t
ssh_public_key_object_max_encrypt_input_len(SshPublicKeyObject key);
size_t
ssh_public_key_object_max_encrypt_output_len(SshPublicKeyObject key);
SshCryptoStatus
ssh_public_key_object_encrypt(SshPublicKeyObject key,
                              const unsigned char *plaintext,
                              size_t plaintext_len,
                              unsigned char *ciphertext_buffer,
                              size_t ciphertext_buffer_len,
                              size_t *ciphertext_len_return);
size_t
ssh_private_key_object_max_decrypt_input_len(SshPrivateKeyObject key);
size_t
ssh_private_key_object_max_decrypt_output_len(SshPrivateKeyObject key);

SshCryptoStatus
ssh_private_key_object_decrypt(SshPrivateKeyObject key,
                               const unsigned char *ciphertext,
                               size_t ciphertext_len,
                               unsigned char *plaintext_buffer,
                               size_t plaintext_buffer_len,
                               size_t *plaintext_length_return);
size_t
ssh_private_key_object_max_signature_input_len(SshPrivateKeyObject key);
size_t
ssh_private_key_object_max_signature_output_len(SshPrivateKeyObject key);

SshCryptoStatus
ssh_private_key_object_sign(SshPrivateKeyObject key,
                            const unsigned char *data,
                            size_t data_len,
                            unsigned char *signature_buffer,
                            size_t signature_buffer_len,
                            size_t *signature_length_return);

SshCryptoStatus
ssh_private_key_object_sign_digest(SshPrivateKeyObject key,
                                   const unsigned char *digest,
                                   size_t digest_len,
                                   unsigned char *signature_buffer,
                                   size_t signature_buffer_len,
                                   size_t *signature_length_return);

SshCryptoStatus
ssh_public_key_object_verify_signature(SshPublicKeyObject key,
                                       const unsigned char *signature,
                                       size_t signature_len,
                                       const unsigned char *data,
                                       size_t data_len);

SshCryptoStatus
ssh_pk_group_object_copy(SshPkGroupObject group_src,
                         SshPkGroupObject *group_dest);

size_t
ssh_pk_group_object_dh_setup_max_output_length(SshPkGroupObject group);

size_t
ssh_pk_group_object_dh_agree_max_output_length(SshPkGroupObject group);

SshCryptoStatus
ssh_pk_group_object_dh_setup(SshPkGroupObject group,
                             SshPkGroupDHSecret *secret,
                             unsigned char *exchange_buffer,
                             size_t exchange_buffer_length,
                             size_t *return_length);

SshCryptoStatus
ssh_pk_group_object_dh_agree(SshPkGroupObject group,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange_buffer,
                             size_t exchange_buffer_length,
                             unsigned char *secret_value_buffer,
                             size_t secret_value_buffer_length,
                             size_t *return_length);

char *
ssh_private_key_object_name(SshPrivateKeyObject key);
char *
ssh_public_key_object_name(SshPublicKeyObject key);
char *
ssh_pk_group_object_name(SshPkGroupObject key);

#ifdef SSHDIST_MATH
SshPkGroupDHSecret
ssh_mprz_to_dh_secret(SshMPIntegerConst k);

void
ssh_dh_secret_to_mprz(SshMPInteger k, SshPkGroupDHSecret secret);
#endif /* SSHDIST_MATH */

SshPkGroupDHSecret ssh_buf_to_dh_secret(const unsigned char *secret,
                                        size_t secret_len);

SshPkGroupDHSecret
ssh_pk_group_dup_dh_secret(SshPkGroupDHSecret secret);

#endif /* SSHPK_I_H */
