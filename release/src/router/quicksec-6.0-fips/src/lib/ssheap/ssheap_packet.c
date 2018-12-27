/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "sshenum.h"

#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_packet.h"

#define SSH_DEBUG_MODULE "SshEapPacket"

static const SshKeywordStruct ssheap_mac_code_keywords[] =
{
  {"ok",                    SSH_EAP_MAC_OK},
  {"allocation failed",     SSH_EAP_MAC_ALLOC_FAIL},
  {"calculation failed",    SSH_EAP_MAC_CALC_FAIL},
  {"verification failed",   SSH_EAP_MAC_VERIFY_FAIL},
  {"generic failure",       SSH_EAP_MAC_GENERIC_FAIL},
  {NULL, 0},
};

const char*
ssh_eap_packet_mac_code_to_string(SshUInt8 code)
{
  const char *str;

  str = ssh_find_keyword_name(ssheap_mac_code_keywords, code);

  if (str == NULL)
    str = "unknown";

  return str;
}

/* This function is used either to verify mac on existing
   packet or calculating new mac to the packet. Used
   algorithm is HMAC-SHA256 and protocol is EAP. As a input
   pkt, aut_key and verify parameters has to be given. add_data
   and it's len can be either 0 or actual values. Returns
   SSH_EAP_MAC_OK  on mac generation / verification is successful
   and error code on error. */
SshUInt8
ssh_eap_packet_calculate_hmac_sha256(SshBuffer pkt,
                                     unsigned char *aut_key,
                                     unsigned char *add_data,
                                     SshUInt16 add_data_len,
                                     Boolean verify)
{
  SshUInt16      offset      = 0;
  SshMac         mac         = NULL;
  unsigned char *mac_ptr     = NULL;
  unsigned char *buf         = NULL;
  unsigned char  old_mac[20] = "";
  unsigned char  result[32]  = "";

  SSH_ASSERT(aut_key != NULL);
  SSH_ASSERT(pkt != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap calculating hmac sha256"));

  /* Find the place for MAC. The packet has already been
     verified / created by us, so it has to be OK. */
  for (offset = 8; offset < ssh_buffer_len(pkt);)
    {
      if ((buf = ssh_buffer_ptr(pkt)) == NULL)
        return SSH_EAP_MAC_GENERIC_FAIL;

      if (buf[offset] == SSH_EAP_AT_MAC)
        {
          mac_ptr = buf + offset + 4;

          if (verify)
            {
              memcpy(old_mac, mac_ptr, 16);
              memset(mac_ptr, 0x0, 16);
            }
          break;
        }

      offset += SSH_EAP_AT_LEN(pkt, offset);
    }

  if (ssh_mac_allocate("hmac-sha256", aut_key, 32, &mac) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("eap mac allocation failed."));
      return SSH_EAP_MAC_ALLOC_FAIL;
    }

  if ((buf = ssh_buffer_ptr(pkt)) == NULL)
    {
      ssh_mac_free(mac);
      return SSH_EAP_MAC_GENERIC_FAIL;
    }

  ssh_mac_update(mac, buf, ssh_buffer_len(pkt));

  if (add_data)
    ssh_mac_update(mac, add_data, add_data_len);

  if (ssh_mac_final(mac, result) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("eap mac calculation failed."));
      ssh_mac_free(mac);
      return SSH_EAP_MAC_CALC_FAIL;
    }

  if (verify)
    {
      if (memcmp(old_mac, result, 16))
        {
          SSH_DEBUG(SSH_D_FAIL, ("eap mac verification failed."));
          ssh_mac_free(mac);
          return SSH_EAP_MAC_VERIFY_FAIL;
        }
    }
  else
    {
      if (mac_ptr == NULL)
        {
          ssh_mac_free(mac);
          return SSH_EAP_MAC_GENERIC_FAIL;
        }
      SSH_DEBUG(SSH_D_LOWOK, ("eap mac copied to packet"));
      memcpy(mac_ptr, result, 16);
    }

  ssh_mac_free(mac);
  return SSH_EAP_MAC_OK;
}

/* This function is used either to verify mac on existing
   packet or calculating new mac to the packet. Used
   algorithm is HMAC-SHA1 and protocol is EAP. As a input
   pkt, aut_key and verify parameters has to be given. add_data
   and it's len can be either 0 or actual values. Returns
   SSH_EAP_MAC_OK  on mac generation / verification is successful
   and error code on error. */
SshUInt8
ssh_eap_packet_calculate_hmac_sha(SshBuffer pkt,
                                  unsigned char *aut_key,
                                  unsigned char *add_data,
                                  SshUInt16 add_data_len,
                                  Boolean verify)
{
  SshUInt16      offset      = 0;
  SshMac         mac         = NULL;
  unsigned char *mac_ptr     = NULL;
  unsigned char *buf         = NULL;
  unsigned char  old_mac[20] = "";
  unsigned char  result[20]  = "";

  SSH_ASSERT(aut_key != NULL);
  SSH_ASSERT(pkt != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap calculating hmac sha"));

  /* Find the place for MAC. The packet has already been
     verified / created by us, so it has to be OK. */
  for (offset = 8; offset < ssh_buffer_len(pkt);)
    {
      if ((buf = ssh_buffer_ptr(pkt)) == NULL)
        return SSH_EAP_MAC_GENERIC_FAIL;

      if (buf[offset] == SSH_EAP_AT_MAC)
        {
          mac_ptr = buf + offset + 4;

          if (verify)
            {
              memcpy(old_mac, mac_ptr, 16);
              memset(mac_ptr, 0x0, 16);
            }
          break;
        }

      offset += SSH_EAP_AT_LEN(pkt, offset);
    }

  if (ssh_mac_allocate("hmac-sha1", aut_key, 16, &mac) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("eap mac allocation failed."));
      return SSH_EAP_MAC_ALLOC_FAIL;
    }

  if ((buf = ssh_buffer_ptr(pkt)) == NULL)
    {
      ssh_mac_free(mac);
      return SSH_EAP_MAC_GENERIC_FAIL;
    }

  ssh_mac_update(mac, buf, ssh_buffer_len(pkt));

  if (add_data)
    ssh_mac_update(mac, add_data, add_data_len);

  if (ssh_mac_final(mac, result) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("eap mac calculation failed."));
      ssh_mac_free(mac);
      return SSH_EAP_MAC_CALC_FAIL;
    }

  if (verify)
    {
      if (memcmp(old_mac, result, 16))
        {
          SSH_DEBUG(SSH_D_FAIL, ("eap mac verification failed."));
          ssh_mac_free(mac);
          return SSH_EAP_MAC_VERIFY_FAIL;
        }
    }
  else
    {
      if (mac_ptr == NULL)
        {
          ssh_mac_free(mac);
          return SSH_EAP_MAC_GENERIC_FAIL;
        }
      SSH_DEBUG(SSH_D_LOWOK, ("eap mac copied to packet"));
      memcpy(mac_ptr, result, 16);
    }

  ssh_mac_free(mac);
  return SSH_EAP_MAC_OK;
}

SshBuffer
ssh_eap_packet_append_res_attr(SshBuffer pkt,
                               SshUInt8 *res,
                               SshUInt8 res_len)
{
  SshUInt8 shdr[4]  = "";
  SshUInt8 pad_size = 0;
  SshUInt32 res_byte_len;

  res_byte_len = (res_len / 8) + ((res_len % 8) ? 1 : 0);

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_RES;
  shdr[1] = 1 + (res_byte_len / 4);

  pad_size = 4 - (res_byte_len % 4);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Generating AT_RES res_byte_len %u.",
                               res_byte_len));

  /* If we had to make padding, we'll have to increase
     the total length also. */
  if (pad_size != 4)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Padded AT_RES with %d bytes.", pad_size));
      shdr[1] += 1;
    }

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  shdr[0] = 0;
  shdr[1] = (res_len & 0xFF);

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  if (ssh_buffer_append(pkt, res, res_byte_len) != SSH_BUFFER_OK)
    return NULL;

  if (pad_size != 4)
    {
      memset (shdr, 0x0, sizeof(shdr));

      if (ssh_buffer_append(pkt, shdr, pad_size) != SSH_BUFFER_OK)
        return NULL;
    }

  return pkt;
}

SshBuffer
ssh_eap_packet_append_auts_attr(SshBuffer pkt, SshUInt8 *auts)
{
  SshUInt8 shdr[2] = "";

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_AUTS;
  shdr[1] = 4; /* For auts is always 4. */

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  if (ssh_buffer_append(pkt, auts, 14) != SSH_BUFFER_OK)
    return NULL;

  return pkt;
}

SshBuffer
ssh_eap_packet_append_nonce_attr(SshBuffer pkt,
                                 SshUInt8 *nonce)
{
  SshUInt8 shdr[4] = "";

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_NONCE_MT;
  shdr[1] = 5; /* For nonce is always 5. */
  shdr[2] = shdr[3] = 0x00;

  if (ssh_buffer_append(pkt, shdr, 4) != SSH_BUFFER_OK)
    {
      return NULL;
    }

  if (ssh_buffer_append(pkt, nonce, 16) != SSH_BUFFER_OK)
    {
      return NULL;
    }

  return pkt;
}

SshBuffer
ssh_eap_packet_append_selected_version_attr(SshBuffer pkt,
                                            SshUInt8 *version)
{
  SshUInt8 shdr[2] = "";

  SSH_ASSERT(version != NULL);

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_SELECTED_VERSION;
  shdr[1] = 1; /* For selected version is always 1. */

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  if (ssh_buffer_append(pkt, version, 2) != SSH_BUFFER_OK)
    return NULL;

  return pkt;
}

unsigned char *
ssh_eap_packet_append_empty_mac_attr(SshBuffer pkt)
{
  SshUInt8  shdr[20] = "";
  SshUInt16 insert_place = (SshUInt16)ssh_buffer_len(pkt);

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_MAC;
  shdr[1] = 5; /* For MAC is always 1. */

  if (ssh_buffer_append(pkt, shdr, 20) != SSH_BUFFER_OK)
    return NULL;

  return &ssh_buffer_ptr(pkt)[insert_place + 4];
}

SshBuffer
ssh_eap_packet_append_identity_attr(SshBuffer pkt,
                                    const SshUInt8 *id,
                                    SshUInt8 id_len)
{
  SshUInt8 shdr[4]  = "";
  SshUInt8 pad_size = 0;

  /* Static header portion, never changes. */
  shdr[0] = SSH_EAP_AT_IDENTITY;
  shdr[1] = 1 + (id_len / 4);

  pad_size = (id_len % 4);

  /* If we had to make padding, we'll have to increase
     the total length also. */
  if (pad_size)
    shdr[1] += 1;

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  shdr[0] = 0;
  shdr[1] = (id_len & 0xFF);

  if (ssh_buffer_append(pkt, shdr, 2) != SSH_BUFFER_OK)
    return NULL;

  if (ssh_buffer_append(pkt, id, id_len) != SSH_BUFFER_OK)
    return NULL;

  if (pad_size)
    {
      memset (shdr, 0x0, sizeof(shdr));
      pad_size = 4 - pad_size;

      if (ssh_buffer_append(pkt, shdr, pad_size) != SSH_BUFFER_OK)
        return NULL;
    }

  return pkt;
}

SshUInt8
ssh_eap_packet_get_code(SshBuffer buf)
{
  SshUInt8 *ptr = ssh_buffer_ptr(buf);

  if (!ptr)
    {
      SSH_NOTREACHED;
      return 0;
    }

  return ptr[0];
}

SshUInt8
ssh_eap_packet_get_identifier(SshBuffer buf)
{
  SshUInt8 *ptr = ssh_buffer_ptr(buf);

  if (!ptr)
    {
      SSH_NOTREACHED;
      return 0;
    }
  return ptr[1];
}

SshUInt16
ssh_eap_packet_get_length(SshBuffer buf)
{
  SshUInt8 *ptr = ssh_buffer_ptr(buf);

  if (!ptr)
    {
      SSH_NOTREACHED;
      return 0;
    }

  return SSH_GET_16BIT(ptr + 2);
}

void
ssh_eap_packet_strip_pad(SshBuffer buf)
{
  unsigned long len;
  unsigned long real_len;

  len = ssh_eap_packet_get_length(buf);
  real_len = (unsigned long)ssh_buffer_len(buf);

  SSH_ASSERT(real_len >= len);

  ssh_buffer_consume_end(buf, real_len - len);
}

SshUInt8
ssh_eap_packet_get_type(SshBuffer buf)
{
  SshUInt8 *ptr = ssh_buffer_ptr(buf);

  if (!ptr)
    {
      SSH_NOTREACHED;
      return 0;
    }
  return ptr[4];
}

Boolean
ssh_eap_packet_isvalid(SshBuffer buf)
{
  SshUInt8 code;
  SshUInt8 *ptr;
  unsigned long len;

  if (buf == NULL)
    return FALSE;

  ptr = ssh_buffer_ptr(buf);
  len = (unsigned long)ssh_buffer_len(buf);

  /* Make sure there is enough space in the buffer for a packet */

  if (ptr == NULL || len < 4)
    return FALSE;

  SSH_ASSERT(ptr != NULL);

  /* Make sure that the buffer contains at least the packet */

  if (ssh_eap_packet_get_length(buf) > len)
    return FALSE;

  /* Make sure the length of the packet in the header is
     at least as large as the header */

  if (ssh_eap_packet_get_length(buf) < 4)
    return FALSE;

  /* Make sure that if this is an EAP request or response,
     then the packet contains the EAP type field */

  code = ptr[0];

  if ((code == SSH_EAP_CODE_REQUEST || code == SSH_EAP_CODE_REPLY)
      && (ssh_eap_packet_get_length(buf) < 5))
    return FALSE;

  /* Ok for further processing */

  return TRUE;

}

Boolean
ssh_eap_packet_isvalid_ptr(SshUInt8 *buffer, unsigned long len)
{
  SshBufferStruct tmp;

  tmp.alloc = len;
  tmp.offset = 0;
  tmp.end = len;
  tmp.buf = buffer;
  tmp.dynamic = FALSE;

  return ssh_eap_packet_isvalid(&tmp);
}

void
ssh_eap_packet_skip_hdr(SshBuffer buf)
{
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Assume existence of "type" field, which
     is not present in success or failure messages */

  SSH_ASSERT(ssh_eap_packet_get_length(buf) >= 5);

  ssh_buffer_consume(buf, 5);
}

Boolean
ssh_eap_packet_build_hdr(SshBuffer buf,
                         SshUInt8 code,
                         SshUInt8 id,
                         SshUInt16 length)
{
  SshUInt8 hdr[4];

  ssh_buffer_clear(buf);

  hdr[0] = code;
  hdr[1] = id;
  hdr[2] = ((length + 4) >> 8);
  hdr[3] = (length + 4) & 0xFF;

  if (ssh_buffer_append(buf, hdr, 4) == SSH_BUFFER_OK)
    return TRUE;
  return FALSE;
}

Boolean
ssh_eap_packet_build_hdr_with_type(SshBuffer buf,
                                   SshUInt8 code,
                                   SshUInt8 id,
                                   SshUInt16 length,
                                   SshUInt8 type)
{
  SshUInt8 hdr[5];

  ssh_buffer_clear(buf);

  hdr[0] = code;
  hdr[1] = id;
  hdr[2] = ((length + 5) >> 8);
  hdr[3] = (length + 5) & 0xFF;
  hdr[4] = type;

  if (ssh_buffer_append(buf, hdr, 5) == SSH_BUFFER_OK)
    return TRUE;
  return FALSE;
}
