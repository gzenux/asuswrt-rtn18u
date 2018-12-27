/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is an asycronous stub software implementation for netbsd
   that takes care of setting the process run levels and
   demonstrates how the packet is returned to the engine.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "kernel_timeouts.h"
#include "engine_hwaccel.h"


#define SSH_DEBUG_MODULE "SshHWAccelAsync"

struct SshHWAccelRec
{
  Boolean for_ah;
  Boolean for_encryption;
  SshCipher cipher;
  SshMac mac;
  size_t iv_len;
  unsigned char iv[16];
};

/* Allocates a hardware acceleration context for IPSEC transformations
   with cipher idea-cbc and with mac hmac-md5-96, or without a mac. It
   Fails for other ciphers and macs. The allocated accelerator is
   syncronous. */
SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
                                   Boolean  encrypt,
                                   const char *cipher_name,
                                   const unsigned char *cipher_key,
                                   size_t cipher_key_len,
                                   Boolean ah_style_mac,
                                   const char *mac_name,
                                   const unsigned char *mac_key,
                                   size_t mac_key_len)
{
  SshHWAccel accel = NULL;
  SshCryptoStatus status;
  SshMac mac;

  if (ah_style_mac)
    {
      if (mac_name && strcmp(mac_name, "none"))
        {
          status = ssh_mac_allocate(mac_name, mac_key, mac_key_len, &mac);
          if (status != SSH_CRYPTO_OK)
            return NULL;

          accel = ssh_malloc(sizeof(*accel));

          if (!accel)
            return NULL;

          accel->for_ah = TRUE;
          accel->mac = mac;
          accel->cipher = NULL;
          accel->for_encryption = FALSE;
          accel->iv_len = 0;
        }
      return accel;
    }

  if ((cipher_name &&
       (!strcmp(cipher_name, "idea-cbc") &&
        ssh_cipher_supported(cipher_name))) &&
      (!mac_name ||
       (mac_name && !strcmp(mac_name, "hmac-md5-96") &&
        ssh_mac_supported(mac_name))))
    {
      accel = ssh_malloc(sizeof(*accel));

      if (!accel)
        return NULL;

      accel->for_encryption = encrypt;
      accel->for_ah = FALSE;
      /* Crypto must be idea. */
      status = ssh_cipher_allocate_and_test_weak_keys(cipher_name,
                                                      cipher_key,
                                                      cipher_key_len,
                                                      encrypt,
                                                      &accel->cipher);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(accel);
          return NULL;
        }
      else
        {
          int i;

          accel->iv_len = ssh_cipher_get_iv_length(accel->cipher);
          for (i = 0; i < accel->iv_len; i++)
            accel->iv[i] = 10 + i;
        }

      /* Mac may be NULL (none), or it must be supported (and hmac-md5-96) */
      if (mac_name && strcmp(mac_name, "none"))
        status = ssh_mac_allocate(mac_name, mac_key, mac_key_len, &accel->mac);
      else
        {
          status = SSH_CRYPTO_OK;
          accel->mac = NULL;
        }
      if (status != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(accel->cipher);
          ssh_free(accel);
          return NULL;
        }
    }

  return accel;
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
  if (accel->cipher)
    ssh_cipher_free(accel->cipher);
  if (accel->mac)
    ssh_mac_free(accel->mac);
  ssh_free(accel);
}

typedef struct SshHWAccelFinishRec
{
  SshInterceptorPacket pp;
  SshHWAccelCompletion completion;
  void *completion_context;
} *SshHWAccelFinish;

/* This function is called after the hardware has finished cipher/MAC
   operation (this might be the interrupt routine of the hardware or
   some polling routine done from a timeout). The implementation
   totally depends on the hardware and its driver. */

static void ssh_hwaccel_finish_ipsec(void *context)
{
  SshHWAccelFinish hf = (SshHWAccelFinish)context;
  SshHWAccelCompletion completion = hf->completion;
  SshInterceptorPacket pp = hf->pp;
  void *completion_context = hf->completion_context;

  ssh_free(context);
  (completion)(pp, completion_context);
}

void ssh_hwaccel_perform_ipsec_ah(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  size_t mac_start_offset,
                                  size_t mac_len,
                                  size_t icv_offset,
                                  SshHWAccelCompletion completion,
                                  void *completion_context)
{
  size_t packet_len, hlen;
  unsigned char *packet, copy[SSH_IPH4_MAX_HEADER_LEN];
  SshHWAccelFinish hf;
  unsigned int i, opttype, optlen, offset;
  SshIpAddrStruct ipaddr;

  /* Get contiguous packet */
  packet_len = ssh_interceptor_packet_len(pp);
  if ((packet = ssh_malloc(packet_len)) == NULL)
    goto fail;
  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);

  /* MAC processing; mutable fields. */
  hlen = SSH_IPH4_HLEN(packet) << 2;

  memmove(copy, packet, hlen);
  SSH_IPH4_SET_TOS(copy, 0);
  SSH_IPH4_SET_FRAGOFF(copy, 0);
  SSH_IPH4_SET_TTL(copy, 0);
  SSH_IPH4_SET_CHECKSUM(copy, 0);

  for (i = SSH_IPH4_HDRLEN; i < hlen; i += optlen)
    {
      opttype = copy[i];
      if (opttype == SSH_IPOPT_EOL || opttype == SSH_IPOPT_NOP)
        optlen = 1;
      else
        optlen = copy[i + 1];
      if (optlen > hlen - i || optlen < 1)
        break;

      switch (opttype)
        {
        case SSH_IPOPT_EOL:
          goto end_of_options;
        case SSH_IPOPT_NOP:
        case SSH_IPOPT_BSO:
        case SSH_IPOPT_ESO:
        case SSH_IPOPT_CIPSO:
        case SSH_IPOPT_ROUTERALERT:
        case SSH_IPOPT_SNDMULTIDEST:
        case SSH_IPOPT_SATID:
          break;
        case SSH_IPOPT_LSRR:
        case SSH_IPOPT_SSRR:
          offset = copy[i + 2];
          if (offset < 4 || optlen < 3)
            break;
          offset--;
          if (offset + 4 <= optlen)
            {
              offset += ((optlen - offset - 4) / 4) * 4;
              SSH_IP4_DECODE(&ipaddr, copy + i + offset);
              SSH_IPH4_SET_DST(&ipaddr, copy);
            }
          memset(copy + i, 0, optlen);
          break;
        case SSH_IPOPT_RR:
        case SSH_IPOPT_TS:
          memset(copy + i, 0, optlen);
          break;
        default:
          memset(copy + i, 0, optlen);
          break;
        }
    }

 end_of_options:
  ssh_mac_reset(accel->mac);
  ssh_mac_update(accel->mac, copy, hlen);
  ssh_mac_update(accel->mac, packet + hlen, mac_len - hlen);
  ssh_mac_final(accel->mac, packet + icv_offset);

  if (!ssh_interceptor_packet_copyin(pp, 0, packet, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      ssh_free(packet);
      goto drop_already_freed;
    }

  ssh_free(packet);

  hf = ssh_malloc(sizeof(*hf));
  if (hf == NULL)
    goto fail;

  hf->completion = completion;
  hf->completion_context = completion_context;
  hf->pp = pp;

  ssh_kernel_timeout_register(0, 1000L, ssh_hwaccel_finish_ipsec, hf);
  return;

 fail:
  ssh_interceptor_packet_free(pp);
drop_already_freed:
  (*completion)(NULL, completion_context);
  return;
}

/* Performs `hardware-accelerated' processing for an IPSEC
   transformation. We really do crypto now, then we'll register a
   timeout to finish the processing and return the status to the
   Engine. The timeout context will contain information neccessary to
   restore the run level. */
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
  size_t packet_len;
  unsigned char *packet, *crstart;
  SshCryptoStatus status;
  SshHWAccelFinish hf;

  /* AH accelerate on separate function. */
  if (accel->for_ah)
    {
      ssh_hwaccel_perform_ipsec_ah(accel,
                                   pp,
                                   mac_start_offset, mac_len, icv_offset,
                                   completion, completion_context);
      return;
    }

  /* Get contiguous packet */
  packet_len = ssh_interceptor_packet_len(pp);
  if ((packet = ssh_malloc(packet_len)) == NULL)
    goto fail;

  crstart = packet + encrypt_iv_offset + accel->iv_len;
  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);

  if (accel->for_encryption)
    {
      memmove(packet + encrypt_iv_offset, accel->iv, accel->iv_len);

      status =
        ssh_cipher_transform_with_iv(accel->cipher,
                                     crstart, crstart,
                                     encrypt_len_incl_iv - accel->iv_len,
                                     accel->iv);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(packet);
          goto fail;
        }
      memmove(accel->iv, packet + (packet_len - accel->iv_len), accel->iv_len);

      if (accel->mac)
        {
          ssh_mac_reset(accel->mac);
          ssh_mac_update(accel->mac, packet + mac_start_offset, mac_len);
          ssh_mac_final(accel->mac, packet + icv_offset);
        }
    }
  else
    {
      if (accel->mac)
        {
          ssh_mac_reset(accel->mac);
          ssh_mac_update(accel->mac, packet + mac_start_offset, mac_len);
          ssh_mac_final(accel->mac, packet + icv_offset);
        }

      status =
        ssh_cipher_transform_with_iv(accel->cipher,
                                     crstart, crstart,
                                     encrypt_len_incl_iv - accel->iv_len,
                                     packet + encrypt_iv_offset);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(packet);
          goto fail;
        }

    }
  if (!ssh_interceptor_packet_copyin(pp, 0, packet, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      ssh_free(packet);
      goto drop_already_freed;
    }
  ssh_free(packet);

  hf = ssh_malloc(sizeof(*hf));
  if (hf == NULL)
    goto fail;

  hf->completion = completion;
  hf->completion_context = completion_context;
  hf->pp = pp;

  ssh_kernel_timeout_register(0, 10000L, ssh_hwaccel_finish_ipsec, hf);
  return;

 fail:
  ssh_interceptor_packet_free(pp);
drop_already_freed:
  (*completion)(NULL, completion_context);
  return;
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
  ssh_interceptor_packet_free(pp);
  (*completion)(NULL, completion_context);
}

/* eof */
