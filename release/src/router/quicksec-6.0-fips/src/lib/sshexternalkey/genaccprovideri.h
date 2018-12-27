/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header file for the generic accelerator provider.
*/

#ifndef GEN_ACC_PROVIDER_I_H
#define GEN_ACC_PROVIDER_I_H


/* The pointer type that represents the accelerated key. */
typedef struct SshAccKeyRec *SshAccKey;

#include "genaccdevicei.h"
#include "sshoperation.h"

/* Some object types follow which contain software key material,
   which is used when constructing accelerated keys. */


/************** The RSA Info Structures**************/

/* Structures for holding the key material. */

typedef struct SshRSAPrivateKeyInfoRec
{
  /* n is the RSA modulus and d the private exponent. p and q are
     the RSA primes with p < q,  (n = pq). d is the secret exponent,
     and u is the multiplicative inverse of p mod q, assuming p < q,
     i.e. p ^{-1} mod q = u.  The integers dp and dq are d mod(p - 1)
     and d mod(q - 1) respectively. */

  SshMPIntegerStruct n, d, p, q, u, dp, dq;
} SshRSAPrivateKeyInfoStruct, *SshRSAPrivateKeyInfo;


typedef struct SshRSAPublicKeyInfoRec
{
  /* n is the RSA modulus, and e the public exponent. */
  SshMPIntegerStruct n, e;
} SshRSAPublicKeyInfoStruct, *SshRSAPublicKeyInfo;


/************** The DSA Info Structures**************/

typedef struct SshDSAPrivateKeyInfoRec
{
  /* p is the number of elements in the group, q the order of the
     generator and g is the generator. x is the DSA private key
     parameter. */
  SshMPIntegerStruct  p, q, g, x;

  /* This can be safely set to zero, if non-zero it should be at
     least 160, see sshcrypt.h (SSH_PKF_RANDOMIZER_ENTROPY) for
     more information on this. */
  unsigned int exponent_entropy;
} SshDSAPrivateKeyInfoStruct, *SshDSAPrivateKeyInfo;


typedef struct SshDSAPublicKeyInfoRec
{
  /* p is the number of elements in the group, q the order of the
     generator and g is the generator. y is the DSA public key
     parameter. */
  SshMPIntegerStruct  p, q, g, y;

  /* This can be safely set to zero, if non-zero it should be at least
     160, see sshcrypt.h  (SSH_PKF_RANDOMIZER_ENTROPY) for more
     information on this. */
  unsigned int exponent_entropy;
} SshDSAPublicKeyInfoStruct, *SshDSAPublicKeyInfo;

/************* The ECDSA Info Structures*************/

typedef struct SshECDSAPrivateKeyInfoRec
{
  SshMPIntegerStruct x, px, py;

  char *fixed_curve;

  unsigned int exponent_entropy;
} SshECDSAPrivateKeyInfoStruct, *SshECDSAPrivateKeyInfo;


typedef struct SshECDSAPublicKeyInfoRec
{
  SshMPIntegerStruct px, py;

  char *fixed_curve;

  unsigned int exponent_entropy;
} SshECDSAPublicKeyInfoStruct, *SshECDSAPublicKeyInfo;



/************** The Group Info Structure **************/

typedef struct SshDHGroupInfoRec
{
  /* The group name can be specified instead of the group parameters
     (p, q, and g) for fixed predefined groups such as the IKE groups. */
  const char *group_name;
  Boolean predefined;

  /* p is the number of elements in the group, q the order of the
     generator and g is the generator. */
  SshMPIntegerStruct  p, q, g;

  /* This can be safely set to zero, if non-zero it should be at least
     160, see sshcrypt.h  (SSH_PKF_RANDOMIZER_ENTROPY) for more
     information on this. */
  unsigned int exponent_entropy;

  /* The size (in bits) of the group prime p. */
  unsigned int group_size;

  /* The group element p-1 which has order 2. In Diffie_Hellman we check
     the exchange value received from the other side is not this value. */
  unsigned char *p_minus1;
  size_t p_minus1_len;


} SshDHGroupInfoStruct, *SshDHGroupInfo;


/* Structure that describes an accelerated key. */
struct SshAccKeyRec
{
  /* The accelerator device used with this key. */
  SshAccDevice device;

  /* The key info structure. */
  union
  {
    SshRSAPrivateKeyInfoStruct   rsa_prv;
    SshRSAPublicKeyInfoStruct    rsa_pub;
    SshDSAPrivateKeyInfoStruct   dsa_prv;
    SshDSAPublicKeyInfoStruct    dsa_pub;
    SshECDSAPrivateKeyInfoStruct ecdsa_prv;
    SshDHGroupInfoStruct         dh_group;
  } u;

  size_t key_size;

  /* TRUE if this is an RSA key and uses CRT */
  Boolean rsa_crt;

  /* Reference to a key that may be stored in the device.
     This is unused at present. */
  void *key_handle;
};

#endif /* GEN_ACC_PROVIDER_I_H */

