/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Internal Header
*/

#ifndef DL_INTERNAL_H
#define DL_INTERNAL_H

#include "dl-stack.h"


typedef struct SshDlpInitCtxRec
{
  SshMPIntegerStruct p, g, q, x, y;
  unsigned int size;
  unsigned int q_size;
  unsigned int exponent_entropy;
  const char *predefined;

} SshDLPInitCtx;

typedef struct SshDLParamRec
{
  struct SshDLParamRec *next, *prev;
  unsigned int reference_count;

  /* For storing randomizers. */
  SshCStack stack;

  /* State for incremently computing randomizers. */
  SshMPMontPowState randomizer_state;
  SshMPMontIntIdealStruct ideal;
  SshMPInteger k;

  /* Predefined parameter sets have this defined. */
  const char *predefined;

  /* Actual parameter information. */
  SshMPIntegerStruct p;
  SshMPIntegerStruct g;
  SshMPIntegerStruct q;

  /* Precomputed. */
  Boolean base_defined;
  void *base;   /*  SshMPIntModPowPrecomp pointer */

  /* Information about the policy when generating random numbers. */
  unsigned int exponent_entropy;
} *SshDLParam, SshDLParamStruct;

/* Discrete Logarithm key structures. */

/* Public key:

   parameters and
   y - public key (g^x mod p)
   */

typedef struct SshDLPublicKeyRec
{
  SshDLParam param;
  SshMPIntegerStruct y;
} SshDLPublicKey;

/* Private key:

   parameters and
   y - public key (g^x mod p)
   x - private key
   */

typedef struct SshDLPrivateKeyRec
{
  SshDLParam param;
  SshMPIntegerStruct x;
  SshMPIntegerStruct y;
} SshDLPrivateKey;


void ssh_dlp_init_param(SshDLParam param);
void ssh_dlp_init_public_key(SshDLPublicKey *pub_key, SshDLParam param);
void ssh_dlp_init_private_key(SshDLPrivateKey *prv_key, SshDLParam param);

void ssh_dlp_clear_param(SshDLParam param);
void ssh_dlp_clear_public_key(SshDLPublicKey *pub_key);
void ssh_dlp_clear_private_key(SshDLPrivateKey *prv_key);

SshDLParam ssh_dlp_param_list_add(SshDLParam param);
SshDLParam ssh_dlp_param_create_predefined(const char *predefined);
SshDLParam ssh_dlp_param_create(SshMPIntegerConst p,
                                SshMPIntegerConst q,
                                SshMPIntegerConst g);

SshCryptoStatus ssh_dlp_action_make(SshDLPInitCtx *ctx,
                                    SshDLParam param,
                                    int type,
                                    void **return_ctx);

#endif /* DL_INTERNAL_H */
