/**
   @copyright
   Copyright (c) 2012 - 2013, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_FL_SIGN_RAW_H
#define SSH_FL_SIGN_RAW_H


#include "fl.h"

/* Perform raw private key signing operations. Note that the
   buffer sizes must be correct and that 521-bit ECDSA key
   input buffer must be at least 68-bytes long containing
   zero-padding after hash output. */

FL_RV FL_Util_DecryptRawRSA(FL_KeyAsset_t PrivateKey,
                            FL_DataInPtr_t FL_DI Data_p,
                            FL_DataLen_t DataNBytes,
                            FL_DataOutPtr_t FL_DO Signature_p,
                            FL_DataLen_t SignatureNBytes);

FL_RV FL_Util_EncryptRawRSA(FL_KeyAsset_t PrivateKey,
                            FL_DataInPtr_t FL_DI Data_p,
                            FL_DataLen_t DataNBytes,
                            FL_DataOutPtr_t FL_DO Output_p,
                            FL_DataLen_t OutputNBytes);

#endif /* SSH_FL_SIGN_RAW_H */
