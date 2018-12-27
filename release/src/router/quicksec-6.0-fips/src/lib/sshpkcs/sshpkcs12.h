/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation for decoding and encoding PKCS#12 data.

   PFX is the top level container. PFX can contain any number of Safe's
   which in turn can contain any number of Bags. Bags can contain only
   one item which can be key, shrouded key, certificate, CRL, user data
   or another safe (recursive structure).  Bags can also contain
   attributes. Safes can be protected with password or with public key
   encryption. The PFX integrity can be protected with password or with
   private key signature.
*/

#ifndef SSH_PKCS12_H
#define SSH_PKCS12_H

#include "x509.h"
#include "sshpkcs7.h"
#include "sshstr.h"

typedef enum {
  SSH_PKCS12_OK,    /* OK */
  SSH_PKCS12_FORMAT_ERROR, /* encoded blob is corrupted,
                              or invalid PKCS12 blob */
  SSH_PKCS12_INVALID_BAG_TYPE,
  SSH_PKCS12_INVALID_INDEX,
  SSH_PKCS12_INVALID_TYPE,
  SSH_PKCS12_ERROR
} SshPkcs12Status;

typedef struct SshPkcs12PFXRec        *SshPkcs12PFX;
typedef struct SshPkcs12SafeRec       *SshPkcs12Safe;
typedef struct SshPkcs12BagRec        *SshPkcs12Bag;
typedef struct SshPkcs12AttributeRec  *SshPkcs12Attribute;

typedef void (*SshPkcs12PFXEncodeCB)(SshPkcs12Status status,
                                     const unsigned char *data,
                                     size_t data_len,
                                     void *context);

typedef void (*SshPkcs12StatusCB)(SshPkcs12Status status,
                                  void *context);

typedef enum {
  SSH_PKCS12_INTEGRITY_NONE,
  SSH_PKCS12_INTEGRITY_PUBKEY,
  SSH_PKCS12_INTEGRITY_PASSWORD
} SshPkcs12IntegrityMode;

typedef enum {
  SSH_PKCS12_BAG_KEY,
  SSH_PKCS12_BAG_SHROUDED_KEY,
  SSH_PKCS12_BAG_CERT,
  SSH_PKCS12_BAG_CRL,
  SSH_PKCS12_BAG_SECRET,
  SSH_PKCS12_BAG_SAFE
} SshPkcs12BagType;

SshPkcs12PFX
ssh_pkcs12_pfx_create(void);

/*
  Frees a PFX structure. All the contained Safes and SafeBags are
  destroyed also.
*/
void
ssh_pkcs12_pfx_free(SshPkcs12PFX pfx);


/*
  Decodes the PFX structure.
*/
SshPkcs12Status
ssh_pkcs12_pfx_decode(const unsigned char *data,
                      size_t data_len,
                      SshPkcs12IntegrityMode *type_ret,
                      SshPkcs12PFX *pfx_ret);

/*
  Returns all the recipients of the PFX structure. Caller must free
  the returned pointer with ssh_xfree.
*/
SshPkcs12Status
ssh_pkcs12_pfx_get_recipients(SshPkcs12PFX pfx,
                              SshUInt32 *num_recipients,
                              SshPkcs7RecipientInfo **recipients);
/*
  Returns all the signers of the PFX structure. Caller must free
  the returned pointer with ssh_xfree.
*/
SshPkcs12Status
ssh_pkcs12_pfx_get_signers(SshPkcs12PFX pfx,
                           SshUInt32 *num_signers,
                           SshPkcs7SignerInfo **signers);

/*
  Gets signers certificate. This can be used to get the public
  key of the signer. This public key is needed to verify
  the PFX contents.
*/
SshPkcs12Status
ssh_pkcs12_pfx_signer_get_certificate(SshPkcs12PFX pfx,
                                      SshPkcs7SignerInfo signer,
                                      unsigned char **cert_ret,
                                      size_t *cert_len_ret);

/*
  Verifies the PFX contents with public key.
*/
SshPkcs12Status
ssh_pkcs12_pfx_verify(SshPkcs12PFX pfx,
                      SshPkcs7SignerInfo signer,
                      SshPublicKey pubkey);

SshOperationHandle
ssh_pkcs12_pfx_verify_async(SshPkcs12PFX pfx,
                            SshPkcs7SignerInfo signer,
                            SshPublicKey pubkey,
                            SshPkcs12StatusCB callback,
                            void *callback_context);

/*
  Verifies the PFX contets using HMAC.
*/
SshPkcs12Status
ssh_pkcs12_pfx_verify_hmac(SshPkcs12PFX pfx,
                           SshStr password);

/*
  Encodes the PFX using public key integrity protection.
*/
SshOperationHandle
ssh_pkcs12_pfx_encode_pubkey(SshPkcs12PFX pfx,
                             SshPkcs7SignerInfo signer,
                             SshPkcs12PFXEncodeCB callback,
                             void *context);

/*
  Encodes the PFX using the HMAC integrity protection.
*/
SshPkcs12Status
ssh_pkcs12_encode_hmac(SshPkcs12PFX pfx,
                       SshStr password,
                       unsigned char **data_ret,
                       size_t *data_len_ret);


/*
  Adds a Safe to the PFX. Safe is owned by the PFX after this call
  and is destroyed when PFX is destroyed.
*/
SshUInt32
ssh_pkcs12_pfx_add_safe(SshPkcs12PFX pfx,
                        SshPkcs12Safe safe);

/*
  Gets the number of Safes the PFX contains.
*/
SshUInt32
ssh_pkcs12_pfx_get_num_safe(SshPkcs12PFX pfx);

typedef enum {
  SSH_PKCS12_SAFE_ENCRYPT_NONE,
  SSH_PKCS12_SAFE_ENCRYPT_PASSWORD,
  SSH_PKCS12_SAFE_ENCRYPT_PUBKEY
} SshPkcs12SafeProtectionType;

/*
  Returns one of the Safes contained by the PFX. Index has to
  be from zero to N-1, where N is a value obtained by
  calling ssh_pkcs12_pfx_get_num_safe function. */

SshPkcs12Status
ssh_pkcs12_pfx_get_safe(SshPkcs12PFX pfx,
                        SshUInt32 index,
                        SshPkcs12SafeProtectionType *prot_type_ret,
                        SshPkcs12Safe *safe_ret);


/*
  Creates a safe with no protection (plaintext).
*/
SshPkcs12Safe
ssh_pkcs12_create_safe(void);

/*
  Creates a password protected safe. Pbe is given as standard name and can
  be one of the following: 'pbeWithSHAAnd3-KeyTripleDES-CBC',
  'pbeWithSHAAnd2-KeyTripleDES-CBC'.
*/
SshPkcs12Safe
ssh_pkcs12_create_password_protected_safe(const char *pkcs12_pbe,
                                          SshStr password);
/*
  Creates a public key protected safe. Recipient is owned by the
  safe after this call and must not be freed.
*/
SshPkcs12Safe
ssh_pkcs12_create_pubkey_protected_safe(const char *data_encrypt_alg,
                                        SshPkcs7RecipientInfo recipient);

/*
  Gets recipients from public key protected safe
*/
SshPkcs12Status
ssh_pkcs12_safe_get_recipient(SshPkcs12Safe safe,
                              SshUInt32 *recipient_count,
                              SshPkcs7RecipientInfo **recipients);

/* Descrypts the safe with private key. The protection type of the
   safe must be SSH_PKCS12_SAFE_ENCRYPT_PUBKEY. */
SshOperationHandle
ssh_pkcs12_safe_decrypt_private_key(SshPkcs12Safe safe,
                                    SshPkcs7RecipientInfo recipient,
                                    const SshPrivateKey privatekey,
                                    SshPkcs12StatusCB callback,
                                    void *context);

/* Descrypts the safe with symmetric key. This key is derived from
   the password and salt. The protection type of the
   safe must be SSH_PKCS12_SAFE_ENCRYPT_PASSWORD. */
SshPkcs12Status
ssh_pkcs12_safe_decrypt_password(SshPkcs12Safe safe,
                                 SshStr password);

/*
  Adds a SafeBag to the safe. Bag is owned by the safe after this
  call and is destroyed, when the safe is destroyed.
*/
SshUInt32
ssh_pkcs12_safe_add_bag(SshPkcs12Safe safe, SshPkcs12Bag bag);

/*
  Returns the number of SafeBags contained by the safe
*/
SshUInt32
ssh_pkcs12_safe_get_num_bags(SshPkcs12Safe safe);

/*
  Gets the SafeBag from the safe with an index. Index is from
  zero to N-1, where N is the number returned by
  ssh_pkcs12_safe_get_num_bags function. Also returns the
  bag type.
*/
SshPkcs12Status
ssh_pkcs12_safe_get_bag(SshPkcs12Safe safe,
                        SshUInt32 index,
                        SshPkcs12BagType *type_ret,
                        SshPkcs12Bag *bag_ret);

typedef enum {
  SSH_PKCS12_ATTR_UNKNOWN,
  SSH_PKCS12_ATTR_FRIENDLY_NAME,
  SSH_PKCS12_ATTR_LOCAL_KEY_ID
} SshPkcs12AttributeType;

/* Adds a friendly name attribute to bag */
void
ssh_pkcs12_bag_add_friendly_name_attr(SshPkcs12Bag bag,
                                      SshStr name);

/* Adds a local key identifier attribute to bag */
void
ssh_pkcs12_bag_add_local_key_id_attr(SshPkcs12Bag bag,
                                     const unsigned char *kid,
                                     size_t kid_len);

void
ssh_pkcs12_bag_add_unknown_attr(SshPkcs12Bag bag,
                                const char *oid,
                                const unsigned char *data,
                                size_t data_len);

/* Returns the number of attributes in bag */
SshUInt32
ssh_pkcs12_bag_get_num_attributes(SshPkcs12Bag bag);

/* Gets attribute from a bag */
SshPkcs12Status
ssh_pkcs12_bag_get_attribute(SshPkcs12Bag bag,
                             SshUInt32 index,
                             SshPkcs12AttributeType *type_ret,
                             SshPkcs12Attribute *attr_ret);

/* Gets a friendly name from an attribute. Returned SshStr is
   owned by the attribute. Do not free it! */
SshPkcs12Status
ssh_pkcs12_attr_get_friendly_name(SshPkcs12Attribute attr,
                                  SshStr *name_ret);

/* Gets a local key identifier from an attribute. Do NOT return
   the data pointed by the returned pointer. */
SshPkcs12Status
ssh_pkcs12_attr_get_local_key_id(SshPkcs12Attribute attr,
                                 unsigned char const **kid_ret,
                                 size_t *kid_len_ret);

/*
  Gets an attribute (not recocnized by the library). Application can
  try to recocnize it with the returned oid and decode it. Do NOT
  free the data pointed by the returned pointers. */
SshPkcs12Status
ssh_pkcs12_attr_get_unknown(SshPkcs12Attribute attr,
                            char const **oid_ret,
                            unsigned char const **data_ret,
                            size_t *data_len_ret);

/*
  Creates a key bag. Bag contains the private key in PKCS#8 format.
*/
SshPkcs12Status
ssh_pkcs12_create_key_bag(SshPrivateKey key,
                          SshPkcs12Bag *bag_ret);

/*
  Creates a bag which contains a PKCS#8 shrouded private key
*/
SshPkcs12Status
ssh_pkcs12_create_shrouded_key_bag(SshPrivateKey key,
                                   const char *pkcs12_pbe,
                                   SshStr password,
                                   SshPkcs12Bag *bag_ret);

/*
  Creates a bag containing a certificate. If the type is
  X509, data must contain a DER encoded X.509 certificate. If
  the type is SDSI, the data must containa base64 encoded
  SDSI certificate.
*/
SshPkcs12Status
ssh_pkcs12_create_cert_bag(const unsigned char *data,
                           size_t data_len,
                           SshPkcs12Bag *bag_ret);


/*
  Creates a bag containing a Certificate Revocation List
*/
SshPkcs12Status
ssh_pkcs12_create_crl_bag(const unsigned char *data,
                          size_t data_len,
                          SshPkcs12Bag *bag_ret);

/*
  Creates a bag that contains  user's miscellaneous personal secret.
*/
SshPkcs12Status
ssh_pkcs12_create_secret_bag(const char *oid,
                             const unsigned char *data,
                             size_t data_len,
                             SshPkcs12Bag *bag_ret);

/*
  Creates a bag which contains a Safe (recursive structure).
*/
SshPkcs12Status
ssh_pkcs12_create_safe_bag(SshPkcs12Safe safe,
                           SshPkcs12Bag *bag_ret);

/*
  Gets a private key from a key bag. Caller MUST use
  ssh_private_key_free to destroy the return private
  key object.
*/
SshPkcs12Status
ssh_pkcs12_bag_get_key(SshPkcs12Bag bag,
                       SshPrivateKey *key_ret);

/*
  Gets a private key which is shrouded from a bag. Caller
  must use ssh_private_key_free to destroy the return
  private key object.
*/
SshPkcs12Status
ssh_pkcs12_bag_get_shrouded_key(SshPkcs12Bag bag,
                                SshStr password,
                                SshPrivateKey *key_ret);

/*
  Returns a pointer to certificate contained by the bag.
  Do NOT free the returned data. */
SshPkcs12Status
ssh_pkcs12_bag_get_cert(SshPkcs12Bag bag,
                        unsigned char const **cert_ret,
                        size_t *cert_len_ret);

/*
  Returns a pointer to CRL contained by the bag. Do NOT
  free the returned data. */
SshPkcs12Status
ssh_pkcs12_bag_get_crl(SshPkcs12Bag bag,
                       unsigned char const **crl_ret,
                       size_t *crl_len_ret);

/*
  Gets user secret data from bag. Do NOT free
  the returned data. */
SshPkcs12Status
ssh_pkcs12_bag_get_secret(SshPkcs12Bag bag,
                          char const **oid_ret,
                          unsigned char const **data_ret,
                          size_t *data_len_ret);

/*
  Gets safe from a bag.
*/
SshPkcs12Status
ssh_pkcs12_bag_get_safe(SshPkcs12Bag bag,
                        SshPkcs12SafeProtectionType *prot_type_ret,
                        SshPkcs12Safe * const safe_ret);


#endif /* SSH_PKCS12_H */
