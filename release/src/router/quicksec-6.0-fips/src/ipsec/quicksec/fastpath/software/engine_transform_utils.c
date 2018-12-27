/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Miscellaneous utility functions used by transforms and/or other
   parts of the code.  These functions are frequently used and likely
   to remain in the processor cache.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */
#ifdef SSHDIST_IPSEC_IPCOMP
#include "engine_ipcomp_glue.h"
#endif /* SSHDIST_IPSEC_IPCOMP */

#include "fastpath_swi.h"

#include "engine_transform_crypto.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformUtils"


#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE












#ifdef SSHDIST_ZLIB
SSH_RODATA_IN_TEXT
SshCompressDefStruct ssh_fastpath_compress_deflate =
  {
    "deflate",
    ssh_compression_deflate_maxbuf,
    ssh_compression_deflate_get_context,
    ssh_compression_deflate_release_context,
    ssh_compression_deflate_transform
  };

#endif /* SSHDIST_ZLIB */
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

void
fastpath_crypto_init(void)
{
  transform_crypto_init();
}

Boolean
fastpath_get_mac_name(
        SshEngineTransformRun trr,
        SshPmTransform transform,
                      const char **mac_p)
{
  const char *macname = NULL;
  Boolean found = FALSE;

  macname = "none";

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      macname = "hmac-md5-96";
      found = TRUE;
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      macname = "hmac-sha1-96";
      found = TRUE;
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      macname = "hmac-sha256-128";
      found = TRUE;
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      macname = "hmac-sha384-192";
      found = TRUE;
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      macname = "hmac-sha512-256";
      found = TRUE;
    }
#endif /* SSHDIST_CRYPT_SHA512 */
  else if ((transform & SSH_PM_MAC_HMAC_SHA2))
    {
      SSH_ASSERT(0); /* Unsupported sha2 key size requested... */
    }
#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_MAC_XCBC_AES)
    {
      macname = "xcbc-aes-96";
      found = TRUE;
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
      return FALSE;
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
      return FALSE;
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }

  *mac_p = macname;
  return found;
}



Boolean
fastpath_get_cipher_name(
        SshEngineTransformRun trr,
        SshPmTransform transform,
        const char **cipher_p)
{
  const char *ciphername = NULL;
  Boolean found = FALSE;
  ciphername = "none";

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      ciphername = "aes-cbc";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      ciphername = "aes-ctr";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      ciphername = "aes-gcm";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      ciphername = "aes-gcm-64";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_12)
    {
      ciphername = "aes-gcm-96";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      ciphername = "null-auth-aes-gmac";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
  else if (transform & SSH_PM_CRYPT_AES_CCM)
    {
      ciphername = "aes-ccm";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_8)
    {
      ciphername = "aes-ccm-64";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_12)
    {
      ciphername = "aes-ccm-96";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      ciphername = "3des-cbc";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      ciphername = "des-cbc";
      found = TRUE;
      SSH_ASSERT(trr->cipher_key_size == 8);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
      ssh_warning("EXT1 cipher not configured");
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {
      ssh_warning("EXT2 cipher not configured");
    }
  else
    {
      /* No cipher configured. */
      SSH_ASSERT(trr->cipher_key_size == 0);
    }

   *cipher_p = ciphername;

  return found;
}


#ifdef DEBUG_HEAVY
int
fastpath_compute_tc_lru_list_size(SshFastpath fastpath, unsigned int cpu)
{
  SshUInt32 lru;
  int count;
  SshFastpathTransformContext tc;

  SSH_ASSERT(cpu <= fastpath->num_cpus);

  for (count = 0, lru = fastpath->tc_head[cpu];
       lru != SSH_IPSEC_INVALID_INDEX;
       tc = SSH_FASTPATH_GET_TRC(fastpath, lru),
         lru = tc->lru_next)
    count++;

  return count;
}
#endif /* DEBUG_HEAVY */

/* Removes the given transform context from the LRU list of transform
   contexts. */
void ssh_fastpath_tc_lru_remove(SshFastpath fastpath,
                                SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Removing tc=%p on CPU=%d from the LRU list",
                       tc, tc->cpu));

#ifdef DEBUG_HEAVY
  SSH_DEBUG(SSH_D_MY + 10, ("LRU list on CPU %d has %d elements",
                            tc->cpu,
                            fastpath_compute_tc_lru_list_size(fastpath,
                                                              tc->cpu)));
#endif /* DEBUG_HEAVY */

  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);

  if (tc->lru_prev != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc->lru_prev);
      tc2->lru_next = tc->lru_next;
    }
  else
    {
      SSH_ASSERT(tc->self_index == fastpath->tc_head[tc->cpu]);
      fastpath->tc_head[tc->cpu] = tc->lru_next;
    }
  if (tc->lru_next != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc->lru_next);
      tc2->lru_prev = tc->lru_prev;
    }
  else
    {
      SSH_ASSERT(tc->self_index == fastpath->tc_tail[tc->cpu]);
      fastpath->tc_tail[tc->cpu] = tc->lru_prev;
    }
}

/* Adds the given transform context at the head of the LRU list of
   transform contexts.  */
void ssh_fastpath_tc_lru_insert(SshFastpath fastpath,
                                SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the LRU list",
                       tc, tc->cpu));

  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);

  tc->lru_prev = SSH_IPSEC_INVALID_INDEX;
  tc->lru_next = fastpath->tc_head[tc->cpu];
  if (fastpath->tc_head[tc->cpu] != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, fastpath->tc_head[tc->cpu]);
      tc2->lru_prev = tc->self_index;
    }
  fastpath->tc_head[tc->cpu] = tc->self_index;
  if (fastpath->tc_tail[tc->cpu] == SSH_IPSEC_INVALID_INDEX)
    fastpath->tc_tail[tc->cpu] = tc->self_index;
}

/* Adds the given transform context at the tail of the LRU list.  This
   means that it will be a preferred candidate for reuse.  This
   function is also called from initialization code. */
void ssh_fastpath_tc_lru_insert_tail(SshFastpath fastpath,
                                     SshFastpathTransformContext tc)
{
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the tail of the LRU list",
                       tc, tc->cpu));

  /* Transform level hardware accelerators are not on the LRU list. */
  SSH_ASSERT(tc->transform_accel == NULL);

  tc->lru_next = SSH_IPSEC_INVALID_INDEX;
  tc->lru_prev = fastpath->tc_tail[tc->cpu];
  if (fastpath->tc_tail[tc->cpu] != SSH_IPSEC_INVALID_INDEX)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, fastpath->tc_tail[tc->cpu]);
      tc2->lru_next = tc->self_index;
    }
  fastpath->tc_tail[tc->cpu] = tc->self_index;
  if (fastpath->tc_head[tc->cpu] == SSH_IPSEC_INVALID_INDEX)
    fastpath->tc_head[tc->cpu] = tc->self_index;
}

/* Macro for calculating hashvalue for a transform context. */
#define SSH_FASTPATH_TC_HASH(keymat, esp_spi, ah_spi)                   \
  ((SSH_GET_32BIT((keymat)) ^                                           \
    SSH_GET_32BIT((keymat) + SSH_IPSEC_MAX_ESP_KEY_BITS / 8) ^          \
    (esp_spi) ^ (ah_spi)) % SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE)

#define SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc)                         \
  SSH_FASTPATH_TC_HASH((tc)->keymat, (tc)->esp_spi, (tc)->ah_spi)

/* Removes tc from the hash table.  The tc must be in the table. */
void ssh_fastpath_tc_hash_remove(SshFastpath fastpath,
                                 SshFastpathTransformContext tc)
{
  SshUInt32 hashvalue, *tc_indexp;
  SshFastpathTransformContext tc2;

  SSH_DEBUG(SSH_D_MY, ("Removing tc=%p on CPU=%d from the hash list",
                       tc, tc->cpu));

  hashvalue = SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc);
  for (tc_indexp = &fastpath->tc_hash[tc->cpu][hashvalue];
       *tc_indexp != SSH_IPSEC_INVALID_INDEX && *tc_indexp != tc->self_index;
       tc_indexp = &tc2->hash_next)
    tc2 = SSH_FASTPATH_GET_TRC(fastpath, *tc_indexp);
  SSH_ASSERT(*tc_indexp == tc->self_index);
  *tc_indexp = tc->hash_next;
}

/* Adds the tc to the hash table.  This funtion is also called from
   initialization code. */
void ssh_fastpath_tc_hash_insert(SshFastpath fastpath,
                                 SshFastpathTransformContext tc)
{
  SshUInt32 hashvalue;
#ifdef DEBUG_LIGHT
  SshUInt32 tc_index;
  SshFastpathTransformContext tc2;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_MY, ("Adding tc=%p on CPU=%d to the hash list",
                       tc, tc->cpu));

  /* Compute hash slot index for it. */
  hashvalue = SSH_FASTPATH_TRANSFORM_CONTEXT_HASH(tc);

#ifdef DEBUG_LIGHT
  /* Sanity check that it is not already in the hash table. */
  for (tc_index = fastpath->tc_hash[tc->cpu][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc2->hash_next)
    {
      tc2 = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      SSH_ASSERT(tc != tc2);
    }
#endif /* DEBUG_LIGHT */

  /* Add the transform context in the hash list in the slot. */
  tc->hash_next = fastpath->tc_hash[tc->cpu][hashvalue];
  fastpath->tc_hash[tc->cpu][hashvalue] = tc->self_index;
}


#ifdef SSHDIST_IPSEC_IPCOMP
/* Notation on distdefines:

   SSHDIST_IPSEC_COMPRESSION_* indicates if a particular compression
   algorithm may be used by the system.

   SSHDIST_IPSEC_COMPRESS_* or SSHDIST_ZLIB indicates if a software
   implementation of a particular compression algorithm is present.

   It may be so that a compression algorithm may only be used in hardware. */

static const
SshCompressDefStruct * fastpath_get_compress_def(SshEngineTransformRun trr,
                                                 SshPmTransform transform,
                                                 const char **name)
{
  const char *compress_name = NULL;
  const SshCompressDefStruct *compress;

  compress_name = "none";
  compress = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_IPSEC_COMPRESSION_LZS is undefined */
    }
#ifdef SSHDIST_IPSEC_COMPRESSION_LZS
  else if (transform & SSH_PM_COMPRESS_LZS)
    {
      compress_name = "lzs";





    }
#endif /*SSHDIST_IPSEC_COMPRESSION_LZS */
#ifdef SSHDIST_IPSEC_COMPRESSION_DEFLATE
  else if (transform & SSH_PM_COMPRESS_DEFLATE)
    {
      compress_name = "deflate";
#ifdef SSHDIST_ZLIB
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
      compress = &ssh_fastpath_compress_deflate;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_ZLIB */
    }
#endif /* SSHDIST_IPSEC_COMPRESSION_DEFLATE */
  else
    {
      /* No compression algorithm negotiated */
    }

  if (name)
    *name = compress_name;
  return compress;
}
#endif  /* SSHDIST_IPSEC_IPCOMP */

/* Initialize the transform context 'tc'. The crypto contexts in 'tc' have
   already been initialized when this is called. */
static void
ssh_fastpath_init_transform_context(SshFastpath fastpath,
                                    SshFastpathTransformContext tc,
                                    SshEngineTransformRun trr,
                                    SshPmTransform transform,
                                    Boolean for_output,
                                    Boolean inner_is_ipv6,
                                    Boolean outer_is_ipv6)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Entered tc=%p, self_index=%d", tc,
                          (int) tc->self_index));
  /* Initialize tc. */
  tc->transform = transform;
  memcpy(tc->keymat, trr->mykeymat, sizeof(tc->keymat));
  tc->ah_spi = trr->myspis[SSH_PME_SPI_AH_IN];
  tc->esp_spi = trr->myspis[SSH_PME_SPI_ESP_IN];
#ifdef SSHDIST_IPSEC_IPCOMP
  tc->ipcomp_cpi = (SshUInt16)trr->myspis[SSH_PME_SPI_IPCOMP_IN];
#endif /* SSHDIST_IPSEC_IPCOMP */

  tc->ipv6 = (outer_is_ipv6 ? 1 : 0);
  tc->for_output = (for_output ? 1 : 0);
  tc->tr_index = trr->tr_index;
  tc->iphdrlen = outer_is_ipv6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;

  /* Resolve IP's next header. */
  if (transform & SSH_PM_IPSEC_NATT)
    tc->ip_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_AH)
    tc->ip_nh = SSH_IPPROTO_AH;
  else if (transform & SSH_PM_IPSEC_ESP)
    tc->ip_nh = SSH_IPPROTO_ESP;
  else if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->ip_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->ip_nh = SSH_IPPROTO_UDP;
  else
    tc->ip_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;

  if (transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP))
    {
      tc->prefix_at_0 = 1;
      tc->natt_ofs = outer_is_ipv6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;
    }
  else
    {
      tc->prefix_at_0 = 0;
      tc->natt_ofs = 0;
    }
  tc->natt_len = 0;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    tc->natt_len = 8;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_AH
  tc->ah_ofs = tc->natt_ofs + tc->natt_len;

  /* Resolve AH's next header. */
  if (transform & SSH_PM_IPSEC_ESP)
    tc->ah_nh = SSH_IPPROTO_ESP;
  else if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->ah_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->ah_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_TUNNEL)
    tc->ah_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
  else
    tc->ah_nh = 0;              /* Copy from original IP header. */
#endif /* SSH_IPSEC_AH */

  tc->esp_ofs = tc->natt_ofs + tc->natt_len;

#ifdef SSH_IPSEC_AH
  /* Add AH len to esp ofs. */
  if (transform & SSH_PM_IPSEC_AH)
    {
      if (tc->ipv6)
        {
          /* Should be 64 bit aligned */




          tc->ah_hdr_pad_len = (12 + tc->icv_len) % 8;
          if (tc->ah_hdr_pad_len != 0)
            tc->ah_hdr_pad_len = 8 - tc->ah_hdr_pad_len;
        }
      else
        {
          /* Should be 32 bit aligned */




          tc->ah_hdr_pad_len = (12 + tc->icv_len) % 4;
          if (tc->ah_hdr_pad_len != 0)
            tc->ah_hdr_pad_len = 4 - tc->ah_hdr_pad_len;
        }

      tc->esp_ofs += 12 + tc->icv_len + tc->ah_hdr_pad_len;
    }
#endif /* SSH_IPSEC_AH */

  /* Resolve ESP's next header. */
  if (transform & SSH_PM_IPSEC_IPCOMP)
    tc->esp_nh = SSH_IPPROTO_IPPCP;
  else if (transform & SSH_PM_IPSEC_L2TP)
    tc->esp_nh = SSH_IPPROTO_UDP;
  else if (transform & SSH_PM_IPSEC_TUNNEL)
    tc->esp_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
  else
    tc->esp_nh = 0;             /* Copy from original IP header. */

  if (transform & SSH_PM_IPSEC_ESP)
    tc->esp_len = 8 + tc->cipher_iv_len;
  else
    tc->esp_len = 0;

#ifdef SSHDIST_IPSEC_IPCOMP
  /* Resolve IPCOMP's next header */
  if (transform & SSH_PM_IPSEC_IPCOMP)
    {
      if (transform & SSH_PM_IPSEC_L2TP)
        tc->ipcomp_nh = SSH_IPPROTO_UDP;
      else if (transform & SSH_PM_IPSEC_TUNNEL)
        tc->ipcomp_nh = inner_is_ipv6 ? SSH_IPPROTO_IPV6 : SSH_IPPROTO_IPIP;
      else
        tc->ipcomp_nh = 0;             /* Copy from original IP header. */

      tc->ipcomp_ofs = tc->esp_ofs + tc->esp_len;
      tc->prefix_len = tc->ipcomp_ofs + 4;
    }
  else
#endif /* SSHDIST_IPSEC_IPCOMP */
    tc->prefix_len = tc->esp_ofs + tc->esp_len;

#ifdef SSHDIST_L2TP
  if (transform & SSH_PM_IPSEC_L2TP)
    {
      tc->l2tp_ofs = tc->prefix_len;
      tc->prefix_len += SSH_UDP_HEADER_LEN + 8 + 1;
      if (trr->l2tp_flags & SSH_ENGINE_L2TP_SEQ)
        tc->prefix_len += 4;
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_ACFC) == 0)
        tc->prefix_len += 2;
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_PFC) == 0)
        tc->prefix_len++;
    }
#endif /* SSHDIST_L2TP */
  SSH_ASSERT(tc->prefix_len <= SSH_ENGINE_MAX_TRANSFORM_PREFIX);

  tc->trailer_len = (transform & SSH_PM_IPSEC_ESP) ? 2 : 0;
  if ((transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)) ==
      SSH_PM_IPSEC_ESP)
    tc->trailer_len += tc->icv_len;

#ifdef SSH_IPSEC_TCPENCAP
  if (trr->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
    tc->tcp_encaps_len = SSH_TCPH_HDRLEN + SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN;
  else
    tc->tcp_encaps_len = 0;
#endif /* SSH_IPSEC_TCPENCAP */

  /* Counter mode is really a stream cipher and does not require padding
     to the cipher block length */
  tc->pad_boundary = (tc->counter_mode == 1) ? 0 : tc->cipher_block_len;

  if (tc->pad_boundary < 4)
    tc->pad_boundary = 4;
}

/* This function allocate new cypto contexts for the transform 'tc' from the
   information contained in 'trr' and sets the crypto contexts to 'tc'.
   Returns TRUE on success and FALSE on failure. */
static Boolean
fastpath_alloc_crypto_transform_context(SshFastpath fastpath,
                                        SshFastpathTransformContext tc,
                                        SshEngineTransformRun trr,
                                        SshEnginePacketContext pc,
                                        Boolean for_output,
                                        Boolean inner_is_ipv6,
                                        Boolean outer_is_ipv6)
{
  SshEngine engine = fastpath->engine;
  SshPmTransform transform;
  SshUInt32 requested_ops;
  SshUInt32 provided_ops = 0;
  SshHWAccel transform_accel, encmac_accel, enc_accel, mac_accel;
  unsigned char esp_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  const char *ciphername = NULL, *macname = NULL, *ipcompname = NULL;
#ifdef SSHDIST_IPSEC_IPCOMP
  const SshCompressDefStruct *compress;
#endif /* SSHDIST_IPSEC_IPCOMP */
  size_t esp_ivlen;
  Boolean with_cipher;
  Boolean with_mac;
  transform = pc->transform;

  SSH_DEBUG(SSH_D_MIDOK, ("Allocating new transform context"));

  /* We now try to obtain hardware acceleration contexts for the
     transforms.  First we convert the internal representation of
     algorithm names to the format used by the current hardware acceleration
     API, and and then try to obtain acceleration contexts of various
     kinds.  If we don't get acceleration contexts, then we try to allocate
     software contexts.  We don't modify the transform context in any
     way until we have allocated the required contexts; this way we know
     that when we destroy the old context, initializing the new one will
     succeed. */

  /* Determine the cipher and mac algorithm to use. */
  with_cipher = fastpath_get_cipher_name(trr, transform, &ciphername);
  with_mac = fastpath_get_mac_name(trr, transform, &macname);

  /* Check that the cipher and mac were found. */
  if (((transform & SSH_PM_CRYPT_MASK) &&
       ((transform & SSH_PM_CRYPT_MASK) != SSH_PM_CRYPT_NULL)) &&
      !with_cipher)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cipher algorithm not found, transform=0x%x",
                             (unsigned int) transform));
      return FALSE;
    }

  if (with_cipher && (transform & SSH_PM_COMBINED_MASK) != 0)
    {
      if (with_mac)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot use mac algorithm with combined "
                                 "cipher, transform=0x%x",
                                 (unsigned int) transform));
          return FALSE;
        }
    }
  else if ((transform & SSH_PM_MAC_MASK) && !with_mac)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Mac algorithm not found, transform=0x%x",
                             (unsigned int) transform));
      return FALSE;
    }

#ifdef SSHDIST_IPSEC_IPCOMP
  compress = fastpath_get_compress_def(trr, transform, &ipcompname);
  if ((transform & SSH_PM_IPSEC_IPCOMP) && !strcmp(ipcompname, "none"))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Compression algorithm not found, "
                             "transform=0x%x",(unsigned int)transform));
      return FALSE;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Sanity check key lengths. */
  SSH_ASSERT(trr->cipher_key_size + trr->cipher_nonce_size <=
             SSH_IPSEC_MAX_ESP_KEY_BITS / 8);
  SSH_ASSERT(trr->mac_key_size <= SSH_IPSEC_MAX_MAC_KEY_BITS / 8);

  /* Initialize the context variables to NULL so that we can easily free
     the already allocated ones on error. */
  transform_accel = NULL;
  encmac_accel = NULL;
  enc_accel = NULL;
  mac_accel = NULL;

  tc->for_output = (SshUInt8) for_output;

  /* Determine cipher IV length. */
  tc->cipher_iv_len = trr->cipher_iv_size;


  /* If using counter mode, we need to give the cipher nonce to the
     hardware acceleration context. Do this via the 'esp_iv' parameter.
     For cbc mode the 'esp_iv' parameter is unused. */
  SSH_ASSERT(trr->cipher_nonce_size <= SSH_CIPHER_MAX_BLOCK_SIZE);
  memset(esp_iv, 0, SSH_CIPHER_MAX_BLOCK_SIZE);
  esp_ivlen = trr->cipher_nonce_size;
  if (esp_ivlen)
    memcpy(esp_iv, trr->mykeymat + trr->cipher_key_size, esp_ivlen);

  /* Construct flags for combined transform acceleration. */
  if (for_output)
    requested_ops = SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE;
  else
    requested_ops = SSH_HWACCEL_COMBINED_FLAG_DECAPSULATE;
#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_AH;
#endif /* SSH_IPSEC_AH */
  if (transform & SSH_PM_IPSEC_ESP)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_ESP;
#ifdef SSHDIST_IPSEC_IPCOMP
  if (transform & SSH_PM_IPSEC_IPCOMP)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_IPCOMP;
#endif /* SSHDIST_IPSEC_IPCOMP */
  if (transform & SSH_PM_IPSEC_TUNNEL)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_IPIP;
  if (outer_is_ipv6)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_REQUIRE_IPV6;
  if (transform & SSH_PM_IPSEC_LONGSEQ)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_LONGSEQ;
  if (transform & SSH_PM_IPSEC_ANTIREPLAY)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_NATT;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  if (trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_DF_CLEAR;
  else if (trr->df_bit_processing == SSH_ENGINE_DF_SET)
    requested_ops |= SSH_HWACCEL_COMBINED_FLAG_DF_SET;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocating a combined transform context"));

  /* Allocate a "combined" transform acceleration context.  Note that
     the API does not allow initializing the sequence number; this is
     because some acceleration hardware devices do not allow
     retrieving or setting the sequence numbers.  Consequently, when
     combined transform acceleration devices are in use, the number of
     transform contexts should be configured in ipsec_params.h to be
     twice the maximum number of tunnels plus some for rekeying. */
#ifdef SSHDIST_L2TP
  if (transform & SSH_PM_IPSEC_L2TP ||
      pc->flags & SSH_ENGINE_FLOW_D_IGNORE_L2TP)
    transform_accel = NULL;
  else
#endif /* SSHDIST_L2TP */
    transform_accel =
      ssh_hwaccel_alloc_combined(engine->interceptor,
                                 requested_ops,
                                 &provided_ops,
                                 trr->myspis[SSH_PME_SPI_AH_IN],
                                 (transform & SSH_PM_IPSEC_AH) ?
                                 macname : NULL,
                                 trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                                 trr->mac_key_size,
                                 trr->myspis[SSH_PME_SPI_ESP_IN],
                                 (transform & SSH_PM_IPSEC_AH) ? NULL :
                                 macname,
                                 ciphername,
                                 trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                                 trr->mac_key_size,
                                 trr->mykeymat,
                                 trr->cipher_key_size,
                                 esp_iv, esp_ivlen,
                                 trr->myspis[SSH_PME_SPI_IPCOMP_IN],
                                 ipcompname,
                                 &trr->local_addr, &trr->gw_addr,
                                 trr->mycount_low,
                                 trr->mycount_high,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
                                 trr->remote_port,
                                 trr->natt_oa_l, trr->natt_oa_r
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                                 0, NULL, NULL
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                                 );
  if ((requested_ops & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY) &&
      !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY))
    {
      tc->accel_unsupported_mask |= SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY;
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Set unsupported_mask for those parts that we can compensate on
     software. */
  if ((requested_ops & SSH_HWACCEL_COMBINED_FLAG_NATT) &&
      !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_NATT))
    {
      tc->accel_unsupported_mask |= SSH_HWACCEL_COMBINED_FLAG_NATT;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSHDIST_IPSEC_IPCOMP
  if (transform_accel
      && (requested_ops & SSH_HWACCEL_COMBINED_FLAG_IPCOMP
          && !(provided_ops & SSH_HWACCEL_COMBINED_FLAG_IPCOMP)))
    {
      /* IPCOMP was requested but we could not allocate combined
         transform with it. Do everything in software for now */
      SSH_DEBUG(SSH_D_HIGHOK, ("IPCOMP negotiated but failed to allocate "
                               "combined transform accelerator"));
      ssh_hwaccel_free_combined(transform_accel);
      transform_accel = NULL;
    }
  /* If the IPCOMP support is not compiled into software as well then
     fail the operation */
  if (!transform_accel && (transform & SSH_PM_IPSEC_IPCOMP) && !compress)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Compression algorithm not found, "
                             "transform=0x%x",(unsigned int)transform));
      return FALSE;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */
  /* Try getting hardware acceleration for both encryption and MAC
     computation. The HWAccel API is broken for IPsec level acceleration
     with AH and must be disabled. */






  if (!transform_accel && with_mac && with_cipher &&
      (transform & SSH_PM_IPSEC_AH) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Allocating a IPsec Encryption/MAC transform context"));
      encmac_accel =
        ssh_hwaccel_alloc_ipsec(engine->interceptor,
                                for_output, ciphername, trr->mykeymat,
                                trr->cipher_key_size,
                                esp_iv, esp_ivlen,
                                FALSE,
                                macname,
                                trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
                                trr->mac_key_size);
    }
  else
    {
      encmac_accel = NULL;
    }

  /* If getting hardware acceleration for the whole thing failed, try
     getting it for the encryption part only. The HWAccel API is broken
     for IPsec level acceleration with AH and must be disabled. */
  if (!transform_accel && !encmac_accel && with_cipher
      && (transform & SSH_PM_IPSEC_AH) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Allocating a IPsec Encryption transform context"));
      enc_accel =
        ssh_hwaccel_alloc_ipsec(engine->interceptor,
                                for_output, ciphername, trr->mykeymat,
                                trr->cipher_key_size,
                                esp_iv, esp_ivlen,
                                FALSE, NULL, NULL, 0);
    }
  else
    {
      enc_accel = NULL;
    }

  /* If getting hardware acceleration for the encryption part failed, try
     getting it for the MAC part only. The HWAccel API is broken for IPsec
     level acceleration  with AH and must be disabled. */
  if (!transform_accel && !encmac_accel && !enc_accel && with_mac
      && (transform & SSH_PM_IPSEC_AH) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Allocating a IPsec MAC transform context"));
      mac_accel =
        ssh_hwaccel_alloc_ipsec(engine->interceptor,
                                for_output, NULL, NULL, 0, NULL, 0,
                                FALSE,
                                macname,
                                trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
                                trr->mac_key_size);
    }
  else
    {
      mac_accel = NULL;
    }

#ifdef DEBUG_LIGHT
  if (transform_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using transform-level acceleration"));
  if (encmac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using encryption+mac acceleration"));
  if (enc_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using acceleration for encryption"));
  if (mac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using acceleration for MAC"));
  if (!transform_accel && !encmac_accel && !enc_accel && !mac_accel)
    SSH_DEBUG(SSH_D_HIGHOK, ("Using software crypto"));
#endif /* DEBUG_LIGHT */

  /* Allocate software encryption context if we need one and can't do
     the encryption in hardware. */
  if (!transform_accel && !encmac_accel && !enc_accel && with_cipher)
    {
      tc->with_sw_cipher = TRUE;
      if ((transform & SSH_PM_COMBINED_MASK) != 0)
        {
          tc->with_sw_auth_cipher = TRUE;
        }
      else
        {
          tc->with_sw_auth_cipher = FALSE;
        }
    }
  else
    {
      tc->with_sw_auth_cipher = FALSE;
      tc->with_sw_cipher = FALSE;
    }

  /* Allocate software MAC context if we need one and can't do the
     MAC computation in hardware. */
  if (!transform_accel && !encmac_accel && !mac_accel && with_mac)
    {
      tc->with_sw_mac = TRUE;
    }
  else
    {
      tc->with_sw_mac = FALSE;
    }

  transform_crypto_free(tc);

  if (transform_crypto_alloc(tc, trr, transform) != SSH_TRANSFORM_SUCCESS)
    {
      goto error;
    }

  /* We now know that creating the new tc will be successful.  Free old
     contexts. */
  if (tc->transform_accel)
    ssh_hwaccel_free_combined(tc->transform_accel);
  if (tc->encmac_accel)
    ssh_hwaccel_free(tc->encmac_accel);
  if (tc->enc_accel)
    ssh_hwaccel_free(tc->enc_accel);
  if (tc->mac_accel)
    ssh_hwaccel_free(tc->mac_accel);

  tc->transform_accel = transform_accel;
  tc->encmac_accel = encmac_accel;
  tc->enc_accel = enc_accel;
  tc->mac_accel = mac_accel;
#ifdef SSHDIST_IPSEC_IPCOMP
  tc->compress = compress;
#endif /* SSHDIST_IPSEC_IPCOMP */
  /* This statistic measures the total number of times a crypto context has
     been allocated (in software or using hardware acceleration). */
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].total_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

  return TRUE;

 error:
  /* An error occurred while allocating the new cipher/mac contexts. */
  if (transform_accel)
    ssh_hwaccel_free_combined(transform_accel);
  if (encmac_accel)
    ssh_hwaccel_free(encmac_accel);
  if (enc_accel)
    ssh_hwaccel_free(enc_accel);
  if (mac_accel)
    ssh_hwaccel_free(mac_accel);

  return FALSE;
}

/* Allocates a transform context for the transform.  This maintains a
   cache of recently used encryption context (a simple hash table is
   used to find the appropriate context efficiently).  This also keeps
   the context on an LRU list, and if the context is not found, the
   least recently used entry is taken from the LRU list.  Entries that
   are currently being used are not on the LRU list.  Also, entries
   that are assigned transform-level hardware acceleration contexts
   are not on the LRU list (such contexts must live for the full
   lifetime of the SA).  This returns the allocated transform context,
   or NULL if all transform contexts are currently in use. */
SshFastpathTransformContext
ssh_fastpath_get_transform_context(SshFastpath fastpath,
                                   SshEngineTransformRun trr,
                                   SshEnginePacketContext pc,
                                   Boolean for_output,
                                   Boolean inner_is_ipv6,
                                   Boolean outer_is_ipv6)
{
  SshFastpathTransformContext tc;
  SshUInt32 hashvalue, tc_index;
#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  unsigned int cpu;
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

#ifndef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      ssh_warning("ssh_fastpath_get_transform_context: AH not compiled in");
      return NULL;
    }
#endif /* SSH_IPSEC_AH */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Searching for a transform context"));

  /* We use the xor of the first four bytes of encryption and MAC keys as
     the hash value for transform contexts.  The hash value is never given
     out, and the hash should normally be a good distinguisher (especially
     for automatically negotiated keys).  We use both keys because some
     transforms don't have both encryption and authentication. */
  hashvalue = SSH_FASTPATH_TC_HASH(trr->mykeymat,
                                   trr->myspis[SSH_PME_SPI_ESP_IN],
                                   trr->myspis[SSH_PME_SPI_AH_IN]);

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  /* First search the hash list on the local CPU */
  ssh_kernel_critical_section_start(fastpath->tc_critical_section);

  cpu = ssh_kernel_get_cpu();
  SSH_ASSERT(cpu < fastpath->num_cpus);

  SSH_DEBUG(SSH_D_LOWOK, ("Searching for an available transform context "
                          "on the local hash list CPU=%d", cpu));

  /* Iterate over the hash list to verify whether we have a suitable context
     already available. */
  for (tc_index = fastpath->tc_hash[cpu][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc->hash_next)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      /* Verify that the key material and SPIs really do match. */
      if (tc->destroy_pending ||
          tc->tr_index != trr->tr_index ||
          tc->transform != pc->transform ||
          tc->esp_spi != trr->myspis[SSH_PME_SPI_ESP_IN] ||
          tc->ah_spi != trr->myspis[SSH_PME_SPI_AH_IN] ||
          memcmp(tc->keymat, trr->mykeymat, sizeof(tc->keymat)) != 0 ||
          tc->ipv6 != outer_is_ipv6 || tc->for_output != for_output)
        continue;

      /* Only contexts with transform level hardware acceleration can be used
         by more than one concurrent thread. */
      SSH_ASSERT(tc->cpu == cpu && tc->transform_accel == NULL);
      if (tc->refcnt > 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Skipping inuse transform"));
          continue;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Found a suitable cached transform context"));

      /* Remove the context from the hash and LRU list. */
      ssh_fastpath_tc_lru_remove(fastpath, tc);
      ssh_fastpath_tc_hash_remove(fastpath, tc);
      tc->refcnt++;
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
      goto found;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Searching the LRU list for a transform context "
                          "on the local CPU=%d", cpu));

  /* Try getting one from the LRU on the local CPU.  Note that the LRU does
     not contain contexts that are in use or that have transform-level
     acceleration, so if we get one from the LRU, it is always one that
     we can use. */
  tc_index = fastpath->tc_tail[cpu];
  if (tc_index != SSH_IPSEC_INVALID_INDEX)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
      SSH_ASSERT(tc->refcnt == 0);

      /* Allocate new crypto contexts for 'tc' */
      if (!fastpath_alloc_crypto_transform_context(fastpath, tc, trr, pc,
                                                   for_output,
                                                   inner_is_ipv6,
                                                   outer_is_ipv6))
        {
          ssh_kernel_critical_section_end(fastpath->tc_critical_section);
          goto failed;
        }

      SSH_ASSERT(tc->cpu == cpu && tc->transform_accel == NULL);
      /* Remove the old transform context from the hash and LRU list */
      ssh_fastpath_tc_lru_remove(fastpath, tc);
      ssh_fastpath_tc_hash_remove(fastpath, tc);
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);

      /* Initialize the transform context */
      ssh_fastpath_init_transform_context(fastpath, tc, trr, pc->transform,
                                          for_output, inner_is_ipv6,
                                          outer_is_ipv6);
      tc->refcnt++;
      goto found;
    }

  ssh_kernel_critical_section_end(fastpath->tc_critical_section);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  /* Now try the shared hash list, we need to take a lock */
  ssh_kernel_mutex_lock(fastpath->tc_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("Searching for an available transform context "
                          "on the shared hash list"));

  /* Iterate over the hash list to verify whether we have a suitable context
     already available. */
  for (tc_index = fastpath->tc_hash[fastpath->num_cpus][hashvalue];
       tc_index != SSH_IPSEC_INVALID_INDEX;
       tc_index = tc->hash_next)
    {
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);

      SSH_DEBUG(SSH_D_MY, ("Considering tc=%p", tc));

      /* Verify that the key material and SPIs really do match.
         Skip contexts that are currently being used by another thread. */
      if (tc->destroy_pending ||
          tc->tr_index != trr->tr_index ||
          tc->transform != pc->transform ||
          tc->esp_spi != trr->myspis[SSH_PME_SPI_ESP_IN] ||
          tc->ah_spi != trr->myspis[SSH_PME_SPI_AH_IN] ||
          memcmp(tc->keymat, trr->mykeymat, sizeof(tc->keymat)) != 0 ||
          tc->ipv6 != outer_is_ipv6 || tc->for_output != for_output)
        continue;

      /* Only contexts with transform level hardware acceleration can be used
         by more than one concurrent thread. */
      if (tc->refcnt > 0 && tc->transform_accel == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Skipping inuse transform"));
          continue;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Found a suitable cached transform "
                                   "context"));

      SSH_ASSERT(tc->cpu == fastpath->num_cpus);

      if (tc->transform_accel == NULL)
        ssh_fastpath_tc_lru_remove(fastpath, tc);
#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
      tc->cpu = ssh_kernel_get_cpu();
      ssh_fastpath_tc_hash_remove(fastpath, tc);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

      tc->refcnt++;
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto found;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Searching the shared LRU list for a transform context "));

  /* Try getting one from the LRU.  Note that the LRU does not contain
     contexts that are in use or that have transform-level acceleration,
     so if we get one from the LRU, it is always one that we can use. */
  tc_index = fastpath->tc_tail[fastpath->num_cpus];
  if (tc_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of transform contexts"));
      SSH_DEBUG(SSH_D_FAIL,
                ("Check SSH_ENGINE_MAX_TRANSFORM_CONTEXTS (now %d)",
                 SSH_ENGINE_MAX_TRANSFORM_CONTEXTS));
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto failed;
    }

  /* Got a transform context from the LRU. */
  tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);
  SSH_ASSERT(tc->refcnt == 0);

  /* Remove the old tc from the hash and LRU list. */
  ssh_fastpath_tc_lru_remove(fastpath, tc);
  ssh_fastpath_tc_hash_remove(fastpath, tc);

  /* Allocate new crypto contexts for 'tc' */
  if (!fastpath_alloc_crypto_transform_context(fastpath, tc, trr,
                                               pc, for_output,
                                               inner_is_ipv6, outer_is_ipv6))
    {
      ssh_fastpath_tc_hash_insert(fastpath, tc);
      ssh_fastpath_tc_lru_insert_tail(fastpath, tc);
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      goto failed;
    }

  SSH_ASSERT(tc->cpu == fastpath->num_cpus);

  /* Initialize the transform context */
  ssh_fastpath_init_transform_context(fastpath, tc, trr,
                                      pc->transform, for_output,
                                      inner_is_ipv6, outer_is_ipv6);

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  tc->cpu = ssh_kernel_get_cpu();
#else /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
  ssh_fastpath_tc_hash_insert(fastpath, tc);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  tc->refcnt++;
  ssh_kernel_mutex_unlock(fastpath->tc_lock);

 found:
#ifdef SSH_IPSEC_STATISTICS
  /* This statistic measures the number of active crypto contexts.*/
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].active_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */
#ifdef SSHDIST_IPSEC_IPCOMP
  if (tc->transform & SSH_PM_IPSEC_IPCOMP
      && !tc->transform_accel
      && tc->compress)
    {
      if ((tc->compression_context = (*tc->compress->get_context)(fastpath,
                                                                  for_output))
          == NULL)
        {
          ssh_fastpath_release_transform_context(fastpath, tc);
          goto failed;
        }
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

  return tc;

 failed:
  SSH_DEBUG(SSH_D_FAIL, ("Failed to get transform context"));
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].out_of_transform_contexts++;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */
  return NULL;
}


#ifndef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
/* Destroys the transform context immediately.  When this is called, the
   transform context must not be in the hash table or on the LRU list. */
static void
ssh_fastpath_destroy_tc_now(SshFastpath fastpath,
                            SshFastpathTransformContext tc)
{
  ssh_kernel_mutex_assert_is_locked(fastpath->tc_lock);

  SSH_ASSERT(tc->refcnt == 0);
  SSH_ASSERT(tc->cpu == fastpath->num_cpus);

  /* Free and clear any hardware acceleration contexts. */
  if (tc->transform_accel)
    {
      ssh_hwaccel_free_combined(tc->transform_accel);
      tc->transform_accel = NULL;
    }
  if (tc->encmac_accel)
    {
      ssh_hwaccel_free(tc->encmac_accel);
      tc->encmac_accel = NULL;
    }
  if (tc->enc_accel)
    {
      ssh_hwaccel_free(tc->enc_accel);
      tc->enc_accel = NULL;
    }
  if (tc->mac_accel)
    {
      ssh_hwaccel_free(tc->mac_accel);
      tc->mac_accel = NULL;
    }

  transform_crypto_free(tc);

  /* Randomize its location in the hash table, so that we don't get
     excessively long lists. */
  tc->transform = 0; /* Invalid transform value */
  memset(tc->keymat, 0, sizeof(tc->keymat));
  SSH_PUT_32BIT(tc->keymat, tc->self_index);

  /* Add it into the hash table. */
  ssh_fastpath_tc_hash_insert(fastpath, tc);

  /* Add it onto the LRU list (at the tail of the list, because this is
     a preferred candidate for reuse).  Note that it can no longer have
     a transform-level acceleration, so it will always go on the LRU. */
  ssh_fastpath_tc_lru_insert_tail(fastpath, tc);

  /* Deletion is now completed */
  tc->destroy_pending = 0;
}
#endif /* !SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

/* Returns the transform context to the system for reuse.  The
   transform context is returned to the cache of available contexts,
   and may be reused if another packet is received for the same
   security association.  All allocated contexts must be released
   after they have been used.  This marks the context as not in use,
   and puts it at the head of the LRU list. */

void ssh_fastpath_release_transform_context(SshFastpath fastpath,
                                            SshFastpathTransformContext tc)
{
  SSH_DEBUG(SSH_D_MY, ("Releasing transform context tc=%p allocated from "
                       "CPU=%d", tc, tc->cpu));

  /* This statistic measures the number of available crypto contexts.*/
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].active_transform_contexts--;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IPSEC_IPCOMP
  if (tc->compress && tc->compression_context)
    {
      (*tc->compress->release_context)(fastpath,
                                       tc->compression_context);
      tc->compression_context = NULL;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  ssh_kernel_critical_section_start(fastpath->tc_critical_section);

  SSH_ASSERT(tc->refcnt == 1);
  tc->refcnt--;

  SSH_DEBUG(SSH_D_MY, ("Currently executing CPU is %d",
                       ssh_kernel_get_cpu()));

  /* Put the transform back to the local CPU list if it came from the same
     CPU as it was allocated from. */
  if (tc->cpu == ssh_kernel_get_cpu())
    {
      SSH_DEBUG(SSH_D_MY, ("Returning transform context tc=%p to local CPU "
                           "list", tc));

      SSH_ASSERT(tc->transform_accel == NULL);
      ssh_fastpath_tc_lru_insert(fastpath, tc);
      ssh_fastpath_tc_hash_insert(fastpath, tc);
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
    }
  else
    {
      ssh_kernel_critical_section_end(fastpath->tc_critical_section);
      ssh_kernel_mutex_lock(fastpath->tc_lock);

      tc->cpu = fastpath->num_cpus;
      ssh_fastpath_tc_lru_insert(fastpath, tc);
      ssh_fastpath_tc_hash_insert(fastpath, tc);

      ssh_kernel_mutex_unlock(fastpath->tc_lock);
    }
  return;
#else /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */

  ssh_kernel_mutex_lock(fastpath->tc_lock);

  SSH_ASSERT(tc->cpu == fastpath->num_cpus);
  SSH_ASSERT(tc->refcnt != 0);
  if (--tc->refcnt > 0)
    {
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      return;
    }

  if (tc->destroy_pending)
    {
      /* Remove the transform context from the hash table. */
      ssh_fastpath_tc_hash_remove(fastpath, tc);

      /* The transform was in active use when this function was
         called.  Therefore it can not be on the LRU list. */

      /* Destroy the transform context immediately. */
      ssh_fastpath_destroy_tc_now(fastpath, tc);
      ssh_kernel_mutex_unlock(fastpath->tc_lock);
      return;
    }

  /* Put the transform back to the shared CPU list */
  if (tc->transform_accel == NULL)
    ssh_fastpath_tc_lru_insert(fastpath, tc);

  ssh_kernel_mutex_unlock(fastpath->tc_lock);
#endif /* SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
}

/* Uninit the transform context by freeing memory allocated for it. */
void ssh_fastpath_uninit_transform_context(SshFastpathTransformContext tc)
{
  if (tc->transform_accel)
    {
      ssh_hwaccel_free_combined(tc->transform_accel);
      tc->transform_accel = NULL;
    }
  if (tc->encmac_accel)
    {
      ssh_hwaccel_free(tc->encmac_accel);
      tc->encmac_accel = NULL;
    }
  if (tc->enc_accel)
    {
      ssh_hwaccel_free(tc->enc_accel);
      tc->enc_accel = NULL;
    }
  if (tc->mac_accel)
    {
      ssh_hwaccel_free(tc->mac_accel);
      tc->mac_accel = NULL;
    }

  transform_crypto_free(tc);
}

/* Updates the transform context for the given SA, if any.  This
   should be called whenever the IP addresses or NAT-T remote port in a
   security association changes. The new addresses and remote NAT-T port
   are provided by 'local_ip', 'remote_ip', and 'remote_natt_port'.
   The remaining paraters are provided to look up the correct transform
   context. */
void
ssh_fastpath_update_sa_tc(SshFastpath fastpath, SshPmTransform transform,
                          const unsigned char *keymat,
                          SshUInt32 ah_spi, SshUInt32 esp_spi,
                          Boolean for_output, Boolean ipv6,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshUInt16 remote_port)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Update SA transform context with AH SPI=0x%08lx, "
                          "ESP SPI=0x%08lx, transform=0x%x, for_output=%d",
                          (unsigned long) ah_spi,
                          (unsigned long) esp_spi,
                          (unsigned int) transform, for_output));

  SSH_DEBUG(SSH_D_LOWOK, ("Local IP=%@, Remote IP=%@, NATT remote port=%d",
                          ssh_ipaddr_render, local_ip,
                          ssh_ipaddr_render, remote_ip, remote_port));







  ssh_fastpath_destroy_sa_tc(fastpath, transform, keymat,
                             ah_spi, esp_spi, for_output, ipv6);
}


/* Destroys the transform context for the given SA, if any.  This
   should be called whenever a security association might become
   invalid (i.e., when a transform is destroyed, when the outbound
   direction is rekeyed, when rekeyed inbound SA expires, or when old
   rekeyed inbound SA is still valid when a new inbound rekey
   occurs). */
void
ssh_fastpath_destroy_sa_tc(SshFastpath fastpath, SshPmTransform transform,
                           const unsigned char *keymat,
                           SshUInt32 ah_spi, SshUInt32 esp_spi,
                           Boolean for_output, Boolean ipv6)
{
#ifndef SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
  SshUInt32 hashvalue, tc_index, *tc_indexp;
  SshFastpathTransformContext tc;
  unsigned int cpu = fastpath->num_cpus;

  SSH_DEBUG(SSH_D_LOWOK, ("Destroy SA transform context with AH SPI=%x, "
                          "ESP SPI=%x, transform=%x, for_output=%d",
                          ah_spi, esp_spi, transform, for_output));

#ifdef SSHDIST_L2TP
  /* Destroy first the IPsec SA context protecting L2TP control
     traffic.  After that we destroy the L2TP version of the
     transform. */
  if (transform & SSH_PM_IPSEC_L2TP)
    ssh_fastpath_destroy_sa_tc(fastpath, transform & ~SSH_PM_IPSEC_L2TP,
                               keymat, ah_spi, esp_spi, for_output, ipv6);
#endif /* SSHDIST_L2TP */

  ssh_kernel_mutex_lock(fastpath->tc_lock);

  /* Compute hash slot index. */
  hashvalue = SSH_FASTPATH_TC_HASH(keymat, esp_spi, ah_spi);

  /* Iterate over the hash list to verify whether we have a suitable
     context already available. */
  for (tc_indexp = &fastpath->tc_hash[cpu][hashvalue];
       *tc_indexp != SSH_IPSEC_INVALID_INDEX; )
    {
      tc_index = *tc_indexp;
      tc = SSH_FASTPATH_GET_TRC(fastpath, tc_index);

      /* Verify that the key material and SPIs really match and that
         the transform context is not already deleted. */
      if (memcmp(tc->keymat, keymat, sizeof(tc->keymat)) != 0 ||
          tc->esp_spi != esp_spi || tc->ah_spi != ah_spi ||
          tc->transform != transform ||
          tc->ipv6 != ipv6 || tc->for_output != for_output ||
          tc->destroy_pending)
        {
          /* Move ahead in the list. */
          tc_indexp = &tc->hash_next;
          continue;
        }

      /* Destroy the transform context if it has no references (or destroy
         it when the last reference goes away). */
      SSH_DEBUG(SSH_D_MIDOK, ("Destroying tc %d on SA deletion",
                              (int)tc_index));

      /* Mark the transform context as deleted. */
      tc->destroy_pending = 1;

      /* If it has no references, destroy it now.  Otherwise it will
         get destroyed later. */
      if (tc->refcnt == 0)
        {
          /* Remove the transform context from the hash table. */
          *tc_indexp = tc->hash_next;

          /* Remove the transform context from the LRU list (unless it
             uses transform-level acceleration, in which case it is
             not on the list at all). */
          if (tc->transform_accel == NULL)
            ssh_fastpath_tc_lru_remove(fastpath, tc);

          /* Destroy the transform context now. */
          ssh_fastpath_destroy_tc_now(fastpath, tc);
        }
      else
        {
          /* The transform has references.  Move ahead in the list. */
          tc_indexp = &tc->hash_next;
        }
    }
  ssh_kernel_mutex_unlock(fastpath->tc_lock);
#endif /* !SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS */
}

/* Performs the blocked transform identified by `cipher' on a range of the
   packet. This does modify the buffer chain. The packet may consist of an
   arbitrary chain of blocks. This function can be called concurrently for
   different packets. This return TRUE if successfull and FALSE in case of
   error. If error occurs then the pp is already freed. */

static Boolean
ssh_ipsec_esp_transform(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len)
{
  unsigned char partial_block[SSH_CIPHER_MAX_BLOCK_SIZE];
  size_t partial_bytes, seglen, len;
  unsigned char *seg;
  unsigned char *prev_block_start[SSH_CIPHER_MAX_BLOCK_SIZE];
  size_t prev_block_bytes[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshUInt32 num_prev, i;
  int block_len = tc->cipher_block_len;

  SSH_ASSERT((tc->counter_mode != FALSE) || (crypt_len % block_len == 0));

  SSH_DEBUG(SSH_D_LOWSTART,
            ("(de)ciphering packet offset %zd length %zd blocksize %zd",
             crypt_offset, crypt_len, block_len));

  /* Loop over all segments of the packet.  Initialize to a state where there
     is no data left over from previous segments. */
  num_prev = 0;
  partial_bytes = 0;
  ssh_interceptor_packet_reset_iteration(pc->pp, crypt_offset, crypt_len);
  while (ssh_interceptor_packet_next_iteration(pc->pp, &seg, &seglen))
    {
      if (seglen == 0)
        {
          ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
        continue;
        }

      /* If we have a partial block, complete it first. */
      if (partial_bytes > 0)
        {
          /* Add bytes to complete the partial block. */
          SSH_ASSERT(partial_bytes < block_len);
          len = block_len - partial_bytes;
          if (len > seglen)
            len = seglen;
          prev_block_start[num_prev] = seg;
          prev_block_bytes[num_prev] = len;
          num_prev++;
          SSH_ASSERT(num_prev <= SSH_CIPHER_MAX_BLOCK_SIZE);
          SSH_ASSERT(partial_bytes + len <= sizeof(partial_block));
          memcpy(partial_block + partial_bytes, seg, len);
          partial_bytes += len;
          seg += len;
          seglen -= len;

          /* If block still not complete, move to next segment. */
          if (partial_bytes != block_len)
            {
              ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
              SSH_ASSERT(partial_bytes < block_len && seglen == 0);
              continue;
            }


          if (transform_esp_cipher_update(tc, partial_block,
                                          partial_block, partial_bytes)
              != SSH_TRANSFORM_SUCCESS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed"));
              ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
              ssh_interceptor_packet_free(pc->pp);
              pc->pp = NULL;
              return FALSE;
            }

          /* Copy data back into the original buffers. */
          len = 0;
          for (i = 0; i < num_prev; i++)
            {
              memcpy(prev_block_start[i], partial_block + len,
                     prev_block_bytes[i]);
              len += prev_block_bytes[i];
            }
          SSH_ASSERT(len == partial_bytes && partial_bytes == block_len);
          num_prev = 0;
          partial_bytes = 0;
        }

      /* Process full blocks. */
      len = seglen & ~(block_len - 1);


      if (transform_esp_cipher_update(tc, seg, seg, len)
          != SSH_TRANSFORM_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed: "));
          ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
          ssh_interceptor_packet_free(pc->pp);
          pc->pp = NULL;
          return FALSE;
        }

      seg += len;
      seglen -= len;
      if (seglen == 0)
        {
          ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
        continue;
        }

      /* Process any remaining data. */
      if (seglen > 0)
        {
          SSH_ASSERT(seglen < block_len && seglen <= sizeof(partial_block));
          memcpy(partial_block, seg, seglen);
          partial_bytes = seglen;
          prev_block_start[0] = seg;
          prev_block_bytes[0] = seglen;
          num_prev = 1;
        }

      ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
    }
  if (seg != NULL)
    {
      /* Error occurred while iterating, pp is already freed. */
      return FALSE;
    }

  if (tc->counter_mode && partial_bytes)
    {
      if (transform_esp_cipher_update_remaining(tc, partial_block,
                                                partial_block, partial_bytes)
          != SSH_TRANSFORM_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed"));
          ssh_interceptor_packet_free(pc->pp);
          pc->pp = NULL;
          return FALSE;
        }

      /* Copy data back into the original buffers. */
      len = 0;
      for (i = 0; i < num_prev; i++)
        {
          memcpy(prev_block_start[i], partial_block + len,
                 prev_block_bytes[i]);
          len += prev_block_bytes[i];
        }
    }
  return TRUE;
}

/* Decrypts the ESP packet and validates the ESP packet's ICV when combined
   mode ciphers are used. */
Boolean
ssh_fastpath_esp_transform_combined_in(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len,
        Boolean *icv_failure)
{
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  int iv_len = tc->cipher_iv_len;
  SshTransformResult result;

  SSH_ASSERT(tc->counter_mode);

  *icv_failure = FALSE;

  /* Copy IV from ESP packet. */
  ssh_interceptor_packet_copyout(pc->pp, crypt_offset, iv, iv_len);

  /* Don't decrypt IV. */
  crypt_offset += iv_len;
  crypt_len -= iv_len;

  /* Start decryption. */
  result = transform_esp_cipher_start_decrypt(tc, pc->u.flow.seq_num_low,
                                              pc->u.flow.seq_num_high, iv,
                                              iv_len, crypt_len);

  if (result != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Decryption start failed for ESP (combined mode)"));
      ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* Perform the decryption. */
  if (ssh_ipsec_esp_transform(tc, pc, crypt_offset, crypt_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decryption failed for ESP (combined mode)"));
      return FALSE;
    }

  /* Verify the computed ICV. */
  result = transform_esp_icv_verify(tc, pc->u.flow.packet_icv, tc->icv_len);

  if (result!= SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ICV verify failed for ESP (combined mode)"));

      *icv_failure = TRUE;
      return FALSE;
    }

  /* Mark that ICV succesfully verified. */
  pc->pp->flags |= SSH_PACKET_AUTHENTIC;

  return TRUE;
}

/* Encrypts the ESP packet and computes the ICV for the ESP packet when
   combined mode ciphers are used. */
Boolean
ssh_fastpath_esp_transform_combined_out(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len,
        size_t icv_offset)
{
  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH + 8];
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  int iv_len = tc->cipher_iv_len;
  SshTransformResult result;
  size_t iv_offset;

  SSH_ASSERT(tc->counter_mode);

  /* Set IV offset. */
  iv_offset = crypt_offset;

  /* Don't encrypt bytes reserved for IV. */
  crypt_offset += iv_len;
  crypt_len -= iv_len;

  /* Start encryption. */
  result = transform_esp_cipher_start_encrypt(tc, pc->u.flow.seq_num_low,
                                              pc->u.flow.seq_num_high,
                                              crypt_len, iv, iv_len);

  if (result != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Encryption start failed for ESP (combined mode)"));
      ssh_interceptor_packet_free(pc->pp);
      goto error;
    }

  /* Perform the encryption in software. */
  if (ssh_ipsec_esp_transform(tc, pc, crypt_offset, crypt_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Encryption failed for ESP (combined mode)"));
      goto error;
    }

  SSH_ASSERT(tc->icv_len <= sizeof icv);

  /* Get the resulting ICV. */
  result = transform_esp_icv_result(tc, icv, tc->icv_len);

  if (result != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get ICV for ESP (combined mode)"));
      ssh_interceptor_packet_free(pc->pp);
      goto error;
    }

  /* Copy ICV into the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, icv_offset, icv, tc->icv_len))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Cannot copy ICV into ESP packet (combined mode)"));
      goto error;
    }

  /* Copy IV into the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, iv_offset, iv, iv_len))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Cannot copy IV into ESP packet (combined mode)"));
      goto error;
    }

  return TRUE;

 error:

  pc->pp = NULL;

  return FALSE;
}

/* Decrypts the ESP packet when normal mode ciphers are used. Function returns
   TRUE on success, and FALSE on error, in which case `pc->pp' has been freed.
 */
Boolean
ssh_fastpath_esp_transform_in(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len)
{
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  int iv_len = tc->cipher_iv_len;
  SshTransformResult result;

  /* Copy IV from ESP packet. */
  ssh_interceptor_packet_copyout(pc->pp, crypt_offset, iv, iv_len);

  /* Don't decrypt IV. */
  crypt_offset += iv_len;
  crypt_len -= iv_len;

  /* Start decryption. */
  result = transform_esp_cipher_start_decrypt(tc, pc->u.flow.seq_num_low,
                                              pc->u.flow.seq_num_high, iv,
                                              iv_len, crypt_len);

  if (result != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decryption start failed for ESP"));
      ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* Perform the decryption in software. */
  if (ssh_ipsec_esp_transform(tc, pc, crypt_offset, crypt_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decryption failed for ESP"));
      return FALSE;
    }

  return TRUE;
}

/* Encrypts the ESP packet when normal mode ciphers are used. Function returns
   TRUE on success, and FALSE on error, in which case `pc->pp' has been freed.
*/
Boolean
ssh_fastpath_esp_transform_out(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len)
{
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  int iv_len = tc->cipher_iv_len;
  SshTransformResult result;
  size_t iv_offset;

  /* Set IV offset. */
  iv_offset = crypt_offset;

  /* Don't encrypt bytes reserved to IV. */
  crypt_offset += iv_len;
  crypt_len -= iv_len;

  /* Start encryption. */
  result = transform_esp_cipher_start_encrypt(tc, pc->u.flow.seq_num_low,
                                              pc->u.flow.seq_num_high,
                                              crypt_len, iv, iv_len);

  if (result != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Encryption start failed for ESP"));
      ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* Perform the encryption in software. */
  if (ssh_ipsec_esp_transform(tc, pc, crypt_offset, crypt_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Encryption failed for ESP"));
      return FALSE;
    }

  /* Copy IV into the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, iv_offset, iv, iv_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot copy IV into ESP packet"));
      return FALSE;
    }

  return TRUE;
}

/* Computes ESP MAC over the specified byte range of the packet.  This stores
   the MAC in `icv'.  This returns TRUE on success, and FALSE on error, in
   which case `pp' has been freed. */

static Boolean
fastpath_esp_compute_mac(
        SshEnginePacketContext pc,
        SshFastpathTransformContext tc,
        size_t mac_offset,
        size_t mac_len)
{
  SshInterceptorPacket pp = pc->pp;
  size_t long_seq_offset = 0;
  const unsigned char *seg;
  size_t seglen;

  /* If using 64 bit sequence numbers, insert the most significant
     32 bits of the sequence number to the packet. This gets included
     in the ICV computation. */
  if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
    {
      unsigned char *ucpw;

      long_seq_offset = pc->packet_len - tc->icv_len;

      ucpw = ssh_interceptor_packet_insert(pc->pp, long_seq_offset, 4);
      if (ucpw == NULL)
        {
          return FALSE;
        }

      SSH_PUT_32BIT(ucpw, pc->u.flow.seq_num_high);
      mac_len += 4;
      pc->packet_len += 4;
    }

  /* Iterate all segments of the packet. */
  ssh_interceptor_packet_reset_iteration(pp, mac_offset, mac_len);
  while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &seglen))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("adding %zd bytes to MAC:", seglen),
                        seg, seglen);
      transform_esp_mac_update(tc, seg, seglen);
      ssh_interceptor_packet_done_iteration_read(pp, &seg, &seglen);
    }

  if (seg != NULL)
    {
      /* Mac failed */
      SSH_DEBUG(SSH_D_ERROR, ("Iteration failed calculating ESP MAC"));
      return FALSE;
    }

  /* Remove the most significant 32 bits of the sequence number if that
     was previously inserted to the packet. */
  if (long_seq_offset > 0)
    {
      if (!ssh_interceptor_packet_delete(pc->pp, long_seq_offset, 4))
        {
          return FALSE;
        }

      pc->packet_len -= 4;
    }

  return TRUE;
}

/* Compute ICV and copy it into the ESP packet. Function returns TRUE on
   success, and FALSE on error, in which case `pc->pp' has been freed. */
Boolean
ssh_fastpath_esp_compute_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t mac_offset,
        size_t mac_len,
        size_t icv_offset)
{
  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];

  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_ESP);
  SSH_ASSERT(tc->icv_len <= sizeof icv);

  /* Start ICV computation. */
  transform_esp_mac_start(tc);

  /* Add the range from the packet that is to be included in MAC. */
  if (fastpath_esp_compute_mac(pc, tc, mac_offset, mac_len) == FALSE)
    {
      goto error;
    }

  /* Get the ICV. */
  if (transform_esp_icv_result(tc, icv, tc->icv_len) != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get ICV for ESP"));
      ssh_interceptor_packet_free(pc->pp);
      goto error;
    }

  /* Copy ICV into the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, icv_offset, icv, tc->icv_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot copy ICV into ESP packet"));
      goto error;
    }

  return TRUE;

 error:
  pc->pp = NULL;
  return FALSE;
}

/* Verify ICV for the ESP packet. Function returns FALSE if an error occurs.
   Argument 'icv_failure' is set to FALSE if there was error during computation
   and in which case pc->pp has been freed. Argument 'icv_failure' is set to
   TRUE if received ICV from packet has not valid and in which case pc->pp has
   not been freed. In successful case function returns TRUE.
 */
Boolean
ssh_fastpath_esp_verify_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t mac_offset,
        size_t mac_len,
        Boolean *icv_failure)
{
  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_ESP);

  *icv_failure = FALSE;

  /* Start ICV computation. */
  transform_esp_mac_start(tc);

  /* Add the range from the packet that is to be included in ICV. */
  if (fastpath_esp_compute_mac(pc, tc, mac_offset, mac_len) == FALSE)
    {
      return FALSE;
    }

  /* Verify ICV. */
  if (transform_esp_icv_verify(tc, pc->u.flow.packet_icv, tc->icv_len)
      != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ICV verify failed for ESP"));

      *icv_failure = TRUE;
      return FALSE;
    }

  /* Mark that ICV succesfully verified. */
  pc->pp->flags |= SSH_PACKET_AUTHENTIC;

  return TRUE;
}


#ifdef SSH_IPSEC_AH

/* Updates the mac by adding the IPv4 header, including options.  This
   will consider all mutable options as zero, and will replace mutable
   but predictable options by their final values for the purposes of
   updating the mac. */

static Boolean
fastpath_ah_compute_mac_header4(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta)
{
  SshInterceptorPacket pp = pc->pp;
  size_t hlen = pc->hdrlen;
  unsigned char copy[SSH_IPH4_MAX_HEADER_LEN];
  SshUInt16 i, opttype, optlen, offset, len;
  SshIpAddrStruct ipaddr;

  /* Copy the header and clear mutable fields. */
  SSH_ASSERT(hlen <= SSH_IPH4_MAX_HEADER_LEN);
  ssh_interceptor_packet_copyout(pp, 0, copy, hlen);
  SSH_ASSERT(hlen == 4 * SSH_IPH4_HLEN(copy));
  SSH_IPH4_SET_TOS(copy, 0);
  SSH_IPH4_SET_FRAGOFF(copy, 0); /* Includes flags */
  SSH_IPH4_SET_TTL(copy, 0);
  SSH_IPH4_SET_CHECKSUM(copy, 0);
  len = SSH_IPH4_LEN(copy);
  SSH_IPH4_SET_LEN(copy, len + len_delta);
  SSH_IPH4_SET_PROTO(copy, SSH_IPPROTO_AH);

  /* Process options, if any.  This may update DST in the IP header.
     Mutable options are zeroed. */
  for (i = SSH_IPH4_HDRLEN; i < hlen; i += optlen)
    {
      opttype = copy[i];
      if (opttype == SSH_IPOPT_EOL ||
          opttype == SSH_IPOPT_NOP)
        optlen = 1;
      else
        optlen = copy[i + 1];
      if (optlen > hlen - i || optlen < 1)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("bad ip option length %d encountered opt %d offset %d",
                     optlen, opttype, i));
          return FALSE;
        }
      switch (opttype)
        {
        case SSH_IPOPT_EOL: /* End of option list */
          goto end_of_options;

        case SSH_IPOPT_NOP: /* No operation */
        case SSH_IPOPT_BSO: /* Basic security option */
        case SSH_IPOPT_ESO: /* Extended security option */
        case SSH_IPOPT_CIPSO: /* Commercial ip security option? */
        case SSH_IPOPT_ROUTERALERT: /* Router alert */
        case SSH_IPOPT_SNDMULTIDEST: /* Sender directed
                                        multi-destination delivery */
          /* These options are immutable in transit, and are kept for
             the purposes of ICV computation. */
          break;

        case SSH_IPOPT_LSRR: /* Loose source route */
        case SSH_IPOPT_SSRR: /* Strict source route */
          /* Need to take the last address and store it in dst.  The option
             itself is zeroed. */
          offset = copy[i + 2];
          if (offset < 4 || optlen < 3)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("source route ptr too small: %d at %d of %d",
                         copy[i + 2], i + 2, optlen));
              break;
            }
          offset--;
          if (offset + 4 <= optlen)
            {
              /* At least one address left (i.e., at least 4 bytes left. */
              offset += ((optlen - offset - 4) / 4) * 4;
              SSH_IP4_DECODE(&ipaddr, copy + i + offset);
              SSH_IPH4_SET_DST(&ipaddr, copy);
              SSH_DEBUG(SSH_D_HIGHOK, ("replaced dst from source route"));
            }
          /* Zero the source route option.  Note that in IPv4, the entire
             option is zeroed. */
          SSH_DEBUG(SSH_D_HIGHOK, ("zeroing route option (%d)", opttype));
          memset(copy + i, 0, optlen);
          break;

        case SSH_IPOPT_SATID: /* SATNET stream identifier */
        case SSH_IPOPT_RR:   /* record route */
        case SSH_IPOPT_TS:   /* timestamp */
          memset(copy + i, 0, optlen);
          break;

        default:
          /* All other options are assumed mutable and are zeroed. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("unknown option %d len %d zeroed", opttype, optlen));
          memset(copy + i, 0, optlen);
          break;
        }
    }
 end_of_options:

  /* Update the MAC. */
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("header computed in icv as follows:"), copy, hlen);

  transform_ah_update(tc, copy, hlen);

  return TRUE;
}


#if defined (WITH_IPV6)

/* Same for IPv6.  `pp' and `hlen' are computed by the routine itself
   from `pc'. */

static Boolean
fastpath_ah_compute_mac_header6(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc)
{
  unsigned char buf[256+2];     /* This is long enough to hold the
                                   maximum length option + its type +
                                   its length fields. */
  SshInterceptorPacket pp = pc->pp;
  size_t hlen = pc->hdrlen;
  SshUInt16 offset, next, header_length, header_offset, option_length;
  SshUInt32 n_addrs, n_segs, i;

  ssh_interceptor_packet_copyout(pp, 0, buf, SSH_IPH6_HDRLEN);
  /* Clear the mutable fields. */
  SSH_IPH6_SET_CLASS(buf, 0);
  SSH_IPH6_SET_FLOW(buf, 0);
  SSH_IPH6_SET_HL(buf, 0);
  /* Copy the final destination into the header.  Note that because of
     routing headers it may be different from the one in the first
     IPv6 header. */
  SSH_IPH6_SET_DST(&pc->dst, buf);

  /* Update the MAC. */
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("Header computed in ICV as follows:"),
                    buf, SSH_IPH6_HDRLEN);

  transform_ah_update(tc, buf, SSH_IPH6_HDRLEN);

  /* Traverse the extension headers. */
  next = SSH_IPH6_NH(buf);
  offset = SSH_IPH6_HDRLEN;
  while (offset < hlen)
    switch (next)
      {
      case 0:                   /* hop-by-hop header */
      case SSH_IPPROTO_IPV6OPTS:
        /* The length has already been checked in
           `engine_fastpath.c'. */
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_COMMON_HDRLEN);
        next = SSH_IP6_EXT_COMMON_NH(buf);

        header_length = SSH_IP6_EXT_COMMON_LENB(buf);
        SSH_ASSERT(offset + header_length <= hlen);

        /* Update the common part of this extension header to ICV. */
        SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                          ("Common part of the ext hdr to ICV as follows:"),
                          buf, SSH_IP6_EXT_COMMON_HDRLEN);

        transform_ah_update(tc, buf, SSH_IP6_EXT_COMMON_HDRLEN);

        /* Scan through options. */
        header_offset = 2;
        while (header_offset < header_length)
          {
            SshUInt8 type;
            int n = (header_offset + 2 <= header_length) ? 2 : 1;

            /* Copy out the option header. */
            ssh_interceptor_packet_copyout(pp, offset + header_offset, buf, n);
            type = SSH_GET_8BIT(buf);
            if (type == 0)
              {
                /* A Pad1 option. */
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Adding option Pad1:"),
                                  buf, 1);

                transform_ah_update(tc, buf, 1);

                header_offset++;
                continue;
              }

            if (n == 1)
              {
                /* The extension header is too short to contain this
                   option. */
              too_short_option:
                SSH_DEBUG(SSH_D_ERROR,
                          ("The options ext hdr is too short to contain "
                           "all of its options."));
                ssh_engine_send_icmp_error(pc->engine, pc,
                                           SSH_ICMP6_TYPE_PARAMPROB,
                                           SSH_ICMP6_CODE_PARAMPROB_HEADER,
                                           (offset
                                            + SSH_IP6_EXT_COMMON_OFS_LEN));
                return FALSE;
              }

            /* Fetch the option. */
            option_length = 2 + SSH_GET_8BIT(buf + 1);
            if (header_offset + option_length > header_length)
              goto too_short_option;
            ssh_interceptor_packet_copyout(pp, offset + header_offset,
                                           buf, option_length);

            /* Can the option data change en-route? */
            if (type & 0x20)
              {
                /* Yes it can. */
                SSH_DEBUG(SSH_D_HIGHOK, ("Zeroing option %d", type));
                memset(buf + 2, 0, option_length - 2);
              }

            /* Update MAC. */
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding option %d:", type),
                              buf, option_length);

            transform_ah_update(tc, buf, option_length);

            /* Move forward to next option. */
            header_offset += option_length;
          }








        SSH_ASSERT(header_offset == header_length);
        offset += header_length;
        break;

      case SSH_IPPROTO_IPV6ROUTE:
        /* The length and validity of the routing header has been
           checked in `fastpath.c' */
        ssh_interceptor_packet_copyout(pp, offset, buf,
                                       SSH_IP6_EXT_ROUTING_HDRLEN);

        next = SSH_IP6_EXT_ROUTING_NH(buf);
        header_length = SSH_IP6_EXT_ROUTING_LENB(buf);
        i = SSH_IP6_EXT_ROUTING_LEN(buf);
        n_addrs = i >> 1;
        n_segs = SSH_IP6_EXT_ROUTING_SEGMENTS(buf);

        /* Should have already been checked in `fastpath.c'. */
        SSH_ASSERT(SSH_IP6_EXT_ROUTING_TYPE(buf) == 0);
        SSH_ASSERT((i & 0x1) == 0);
        SSH_ASSERT(n_segs <= n_addrs);
        SSH_ASSERT(offset + header_length <= hlen);

        /* Count the MAC of the beginning of the header.  At the final
           destination, the Segments Left is 0. */
        SSH_IP6_EXT_ROUTING_SET_SEGMENTS(buf, 0);
        /* Copy the "Reserved" field. */
        ssh_interceptor_packet_copyout(pp, offset + 4, buf + 4, 4);
        SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                          ("Adding beginning of the routing header:"),
                          buf, 8);
        transform_ah_update(tc, buf, 8);

        /* Count the MAC values of the addresses. */
        for (i = 0; i < n_addrs - n_segs; i++)
          {
            SSH_ASSERT(8 + i * 16 + 16 <= header_length);
            ssh_interceptor_packet_copyout(pp, offset + 8 + i * 16,
                                           buf, 16);
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding address from the routing header:"),
                              buf, 16);
            transform_ah_update(tc, buf, 16);
          }
        if (n_segs > 0)
          {
            /* The i:th address is the destination address at the IP
               header. */
            ssh_interceptor_packet_copyout(pp, SSH_IPH6_OFS_DST,
                                           buf, 16);
            SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                              ("Adding address from the routing header:"),
                              buf, 16);
            transform_ah_update(tc, buf, 16);

            for (; i < n_addrs - 1; i++)
              {
                SSH_ASSERT(8 + i * 16 + 16 <= header_length);
                ssh_interceptor_packet_copyout(pp, offset + 8 + i * 16,
                                               buf, 16);
                SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                  ("Adding address from the routing header:"),
                                  buf, 16);
                transform_ah_update(tc, buf, 16);
              }
          }
        /* Move to the next extension header. */
        offset += header_length;
        break;

      default:
        /* This shouldn't happen. */
        SSH_NOTREACHED;
        break;
      }
  SSH_ASSERT(offset == hlen);

  return TRUE;
}

#endif /* (WITH_IPV6) */

/* Computes AH MAC over the IP header This returns TRUE on success, and FALSE
   on error, in which case `pc->pp' has been freed.
 */
static Boolean
fastpath_ah_compute_mac_header(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta)
{
  Boolean ok;

  /* Add IP header for AH (with adjustments). */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      ok = fastpath_ah_compute_mac_header6(tc, pc);
      if (ok == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("MAC calculation over IPv6 header failed for AH"));
        }
    }
  else
#endif /* WITH_IPV6 */
    {
      ok = fastpath_ah_compute_mac_header4(tc, pc, len_delta);
      if (ok == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("MAC calculation over IPv4 header failed for AH"));
        }
    }

  if (ok == FALSE)
    {
      if (pc->pp != NULL)
        {
          ssh_interceptor_packet_free(pc->pp);
          pc->pp = NULL;
        }
    }

  return ok;
}


/* Computes AH MAC over the specified byte range of the packet. This returns
   TRUE on success, and FALSE on error, in which case `pc->pp' has been freed.
 */

static Boolean
fastpath_ah_compute_mac_range(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t mac_offset,
        size_t mac_len)
{
  SshInterceptorPacket pp = pc->pp;
  const unsigned char *seg;
  size_t seglen;

  /* Iterate all segments of the packet. */
  ssh_interceptor_packet_reset_iteration(pp, mac_offset, mac_len);
  while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &seglen))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("adding %zd bytes to MAC:", seglen),
                        seg, seglen);
      transform_ah_update(tc, seg, seglen);
      ssh_interceptor_packet_done_iteration_read(pp, &seg, &seglen);
    }

  if (seg != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("MAC calculation over packet failed for AH"));

      pc->pp = NULL;
      return FALSE;
    }

  return TRUE;
}

/* Compute AH MAC of the packet. Function returns TRUE on success, and FALSE
   on error, in which case `pc->pp' has been freed. */
static Boolean
fastpath_ah_compute_mac(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta,
        size_t mac_offset,
        size_t mac_len)
{
  Boolean ok;

  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_AH);

  /* Add IP header for AH (with adjustments). */
  ok = fastpath_ah_compute_mac_header(tc, pc, len_delta);

  if (ok == TRUE)
    {
      /* Add the range from the packet that is to be included in MAC. */
      ok = fastpath_ah_compute_mac_range(tc, pc, mac_offset, mac_len);

      if (ok == TRUE)
        {
          /* If using 64 bit sequence numbers, include the most significant
             32 bits to MAC calculation. */
          if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
            {
              unsigned char buf[4];

              SSH_PUT_32BIT(buf, pc->u.flow.seq_num_high);

              SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                ("adding %zd bytes to MAC:", 4),
                                buf, 4);
              transform_ah_update(tc, buf, 4);
            }
        }
    }

  return ok;
}

/* Compute ICV and copy it into the AH packet. Function returns TRUE on
   success, and FALSE on error, in which case `pc->pp' has been freed. */
Boolean
ssh_fastpath_ah_compute_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta,
        size_t mac_offset,
        size_t mac_len,
        size_t icv_offset)
{
  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH + 8];

  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_AH);
  SSH_ASSERT(tc->icv_len <= sizeof icv);

  /* Start ICV computation. */
  transform_ah_start_computation(tc, pc->u.flow.seq_num_low,
                                 pc->u.flow.seq_num_high);

  /* Compute ICV of AH packet. */
  if (fastpath_ah_compute_mac(tc, pc, len_delta, mac_offset, mac_len) == FALSE)
    {
      goto error;
    }

  /* Get the ICV. */
  if (transform_ah_result(tc, icv, tc->icv_len) != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get ICV for AH"));
      ssh_interceptor_packet_free(pc->pp);
      goto error;
    }

  /* Copy ICV into the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, icv_offset, icv, tc->icv_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot copy ICV into AH packet"));
      goto error;
    }

  return TRUE;

 error:
  pc->pp = NULL;
  return FALSE;
}

/* Verify ICV for the AH packet. Function returns FALSE if an error occurs.
   Argument 'icv_failure' is set to FALSE if there was error during computation
   and in which case pc->pp has been freed. Argument 'icv_failure' is set to
   TRUE if received ICV from packet has not valid and in which case pc->pp has
   not been freed. In successful case function returns TRUE.
 */
Boolean
ssh_fastpath_ah_verify_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta,
        size_t mac_offset,
        size_t mac_len,
        Boolean *icv_failure)
{
  *icv_failure = FALSE;

  /* Start ICV verify. */
  transform_ah_start_verify(tc, pc->u.flow.packet_icv, tc->icv_len);

  /* Compute ICV of AH packet. */
  if (fastpath_ah_compute_mac(tc, pc, len_delta, mac_offset, mac_len) == FALSE)
    {
      return FALSE;
    }

  /* Verify ICV. */
  if (transform_ah_verify(tc) != SSH_TRANSFORM_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ICV verify failed for AH"));

      *icv_failure = TRUE;
      return FALSE;
    }

  /* Mark that ICV succesfully verified. */
  pc->pp->flags |= SSH_PACKET_AUTHENTIC;

  return TRUE;
}

#endif /* SSH_IPSEC_AH */
