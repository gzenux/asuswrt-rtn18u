/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "engine_hwaccel.h"
#include "interceptor.h"


#define SSH_DEBUG_MODULE "SshEngineHwaccelNone"

/* Allocates a hardware acceleration context for IPSEC transformations
   (or more generally, encryption and/or message authentication
   transformations).  The allocated context can be used for
   encryption/decryption, message authentication, or both in a single
   operation.  If both are performed in a single operation, encryption
   is always performed before message authentication, and decryption
   after message authentication. */
SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
                                   Boolean  encrypt,
                                   const char *cipher_name,
                                   const unsigned char *cipher_key,
                                   size_t cipher_key_len,
                                   const unsigned char *cipher_iv,
                                   size_t cipher_iv_len,
                                   Boolean ah_style_mac,
                                   const char *mac_name,
                                   const unsigned char *mac_key,
                                   size_t mac_key_len)
{
  return NULL;
}

/* Allocates a hardware acceleration context for
   compression/decompression using algorithm specified at
   `compression_name' This context is assumed to be used for the
   IPCOMP transformation. */

SshHWAccel ssh_hwaccel_alloc_ipcomp(SshInterceptor interceptor,
                                    Boolean compress,
                                    const char *compression_name)
{
  return NULL;
}

/* Frees the hardware acceleration context.  The engine guarantees
   that no operations will be in progress using the context when this
   is called. */

void ssh_hwaccel_free(SshHWAccel accel)
{
}



/* Performs `hardware-accelerated' processing for an IPSEC
   transformation.  */
void ssh_hwaccel_perform_ipsec(SshHWAccel accel,
                               SshInterceptorPacket pp,
                               size_t encrypt_iv_offset,
                               size_t encrypt_len_incl_iv,
                               size_t mac_start_offset,
                               size_t mac_len,
                               size_t icv_offset,
                               SshHWAccelCompletion completion,
                               void *completion_context)
{
  SSH_NOTREACHED;
}

/*  Performs hardware-accelerated compression/decompression.  This
    function compresses/decompresses a portion of `pp' as specified by
    the hardware acceleration context.  */

void ssh_hwaccel_perform_ipcomp(SshHWAccel accel,
                                SshInterceptorPacket pp,
                                size_t offset,
                                size_t len,
                                SshHWAccelCompletion completion,
                                void *completion_context)
{
  SSH_NOTREACHED;
}


/* Allocates a hardware acceleration context for combination of IPsec
   transformations. The `flags' determines whether the instance is to
   be used for decapsulation or encapsulation, as well as the types of
   transforms to perform. Ther order of transforms is fixed, in
   decryption order AH->ESP->IPcomp->IPIP (and reverse encryption order).
   The {ah,esp,ipcomp,ipip}_ parameters should be only used
   if the relevant bit is set in the `flags' bitmask.
*/
SshHWAccel
ssh_hwaccel_alloc_combined(SshInterceptor interceptor,

                           SshUInt32 requested_ops,
			   SshUInt32 *provided_ops,

                           SshUInt32 ah_spi,
                           const char *ah_macname,
                           const unsigned char *ah_authkey,
                           size_t ah_authkeylen,

                           SshUInt32 esp_spi,
                           const char *esp_macname,
                           const char *esp_ciphname,
                           const unsigned char *esp_authkey,
                           size_t esp_authkeylen,
                           const unsigned char *esp_ciphkey,
                           size_t esp_ciphkeylen,
                           const unsigned char *esp_iv,
                           size_t esp_ivlen,

                           SshUInt32 ipcomp_cpi,
                           const char *ipcomp_compname,

                           SshIpAddr ipip_src, SshIpAddr ipip_dst,
                           SshUInt32 seq_num_low,
                           SshUInt32 seq_num_high,
			   SshUInt16 natt_remote_port,
			   const unsigned char *natt_oa_l,
			   const unsigned char *natt_oa_r)
{
  *provided_ops = 0;
  return NULL;
}

void ssh_hwaccel_perform_combined(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  SshHWAccelCompletion completion,
                                  void *completion_context)
{
  SSH_NOTREACHED;
}

SshHWAccelResultCode
ssh_hwaccel_update_combined(SshHWAccel accel,
                            SshIpAddr ipip_src,
                            SshIpAddr ipip_dst,
			    SshUInt16 natt_remote_port)
{
  SSH_NOTREACHED;
  return SSH_HWACCEL_UNSUPPORTED;
}


void ssh_hwaccel_free_combined(SshHWAccel accel)
{
  SSH_NOTREACHED;
}

void ssh_hwaccel_perform_modp(const SshHWAccelBigInt b,
                              const SshHWAccelBigInt e,
                              const SshHWAccelBigInt m,
                              SshHWAccelModPCompletion callback,
                              void *callback_context)
{
  (*callback)(NULL, callback_context);
}


void ssh_hwaccel_get_random_bytes(size_t bytes_requested,
                                  SshHWAccelRandomBytesCompletion callback,
                                  void *callback_context)
{
  (*callback)(NULL, 0, callback_context);
}

/* Dummy stubs to enable interceptor module to work properly. */
Boolean ssh_hwaccel_init()
{
  return FALSE;
}

void ssh_hwaccel_uninit()
{

}
