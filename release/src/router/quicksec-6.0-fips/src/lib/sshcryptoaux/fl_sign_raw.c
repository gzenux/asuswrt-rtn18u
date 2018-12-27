/**
   @copyright
   Copyright (c) 2012 - 2013, INSIDE Secure Oy. All rights reserved.
*/

#include "fl_sign_raw_internal.h"

FL_RV FL_Util_DecryptRawRSA(FL_KeyAsset_t PrivateKey,
                            FL_DataInPtr_t FL_DI Data_p,
                            FL_DataLen_t DataNBytes,
                            FL_DataOutPtr_t FL_DO Signature_p,
                            FL_DataLen_t SignatureNBytes)
{
  FL_RV rv = FLR_OK;
  FLDPtr_t KeyResource;
  const FLPRSAPrivateKey_t *pk;

  if (DataNBytes != SignatureNBytes)
    return FLR_INVALID_ARGUMENTS;

  /* Only 1024, 2048 and 3072 bit keys supported */
  if ((DataNBytes != 128) &&
      (DataNBytes != 256) &&
      (DataNBytes != 384))
    return FLR_INVALID_ARGUMENTS;

  KeyResource = FLDResource(PrivateKey);

  pk = (const FLPRSAPrivateKey_t *) FL_UTIL_FLDPTR_T_DATA(KeyResource);

  rv = FLPRSACheckDecryptRaw(pk,
                             (FLPMessage_t *)Data_p,
                             (FLPMessage_t *)Signature_p);

  return rv;
}

FL_RV FL_Util_EncryptRawRSA(FL_KeyAsset_t PublicKey,
                            FL_DataInPtr_t FL_DI Data_p,
                            FL_DataLen_t DataNBytes,
                            FL_DataOutPtr_t FL_DO Output_p,
                            FL_DataLen_t OutputNBytes)
{
  FL_RV rv = FLR_OK;
  FLDPtr_t KeyResource;
  const FLPRSAPublicKey_t *pk;

  if (DataNBytes != OutputNBytes)
    return FLR_INVALID_ARGUMENTS;

  /* Only 1024, 2048 and 3072 bit keys supported */
  if ((DataNBytes != 128) &&
      (DataNBytes != 256) &&
      (DataNBytes != 384))
    return FLR_INVALID_ARGUMENTS;

  KeyResource = FLDResource(PublicKey);

  pk = (const FLPRSAPublicKey_t *) FL_UTIL_FLDPTR_T_DATA(KeyResource);

  rv = FLPRSACheckEncryptRaw(pk,
                             (FLPMessage_t *)Data_p,
                             (FLPMessage_t *)Output_p);

  return rv;
}
