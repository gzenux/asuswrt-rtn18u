/**
   @copyright
   Copyright (c) 2012 - 2013, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains declarations of internal FIPS library
   functions and datatypes that are used in the fl_sign_raw
   module.
*/

#ifndef FL_SIGN_RAW_INTERNAL_H
#define FL_SIGN_RAW_INTERNAL_H 1

#include <fl.h>

/* These declarations are from FIPS library 1.0.3 */

/* flg_types.h */
#define FLMWord uint32_t

/* flp.h */
typedef union
{
  void *dummy;
} FLPRSAPrivateKey_t;

typedef union
{
  void *dummy;
} FLPRSAPublicKey_t;

typedef union
{
  void *dummy;
} FLPDSAPrivateKey_t;

typedef union
{
  void *dummy;
} FLPDSAPublicKey_t;

typedef union
{
  void *dummy;
} FLP_ECDSAPrivateKey_t;

typedef union
{
  void *dummy;
} FLP_ECDSAPublicKey_t;

typedef FLMWord FLPMessage_t;

FL_RV
FLPRSACheckDecryptRaw(
        const FLPRSAPrivateKey_t *PrivKey,
        FLPMessage_t Input_Words[/* n */],
        FLPMessage_t Output_Words[/* n */]);

FL_RV
FLPRSACheckEncryptRaw(
        const FLPRSAPublicKey_t *PubKey,
        FLPMessage_t Input_Words[/* n */],
        FLPMessage_t Output_Words[/* n */]);

FL_RV
FLPDSASign(
        const FLPDSAPrivateKey_t *PrivKey,
        FLPMessage_t Z[/* HashValueNBytes / sizeof(FLPMessage_t) */],
        FLPMessage_t *Signature);

FL_RV
FLPDSAVerify(
        const FLPDSAPublicKey_t *PubKey,
        FLPMessage_t Z[/* HashValueNBytes / sizeof(FLPMessage_t) */],
        FLPMessage_t *Signature);

FL_RV
FLPECDSASign(
        const FLP_ECDSAPrivateKey_t *PrivKey,
        FLPMessage_t Z[/* HashValueNBytes / sizeof(FLPMessage_t) */],
        FLPMessage_t *Signature);

FL_RV
FLPECDSAVerify(
        const FLP_ECDSAPublicKey_t *PubKey,
        FLPMessage_t Z[/* HashValueNBytes / sizeof(FLPMessage_t) */],
        FLPMessage_t  *Signature);


/* fld.h */
typedef uint32_t FLDId_t;
typedef struct FLDResource_t *FLDPtr_t;

FLDPtr_t FLDResource(FLDId_t id);

/* Offset of field 'Data' in 'FLDResource_t' */
#define FL_UTIL_FLDPTR_T_DATA_OFFSET \
  ((2 * sizeof(uint16_t)) + (4 * sizeof(uint32_t)))

/* Accessor for field 'Data' in 'FLDResource_t' */
#define FL_UTIL_FLDPTR_T_DATA(res) \
  ((void *) (((char *) (res)) + FL_UTIL_FLDPTR_T_DATA_OFFSET))

#endif /* FL_SIGN_RAW_INTERNAL_H */
