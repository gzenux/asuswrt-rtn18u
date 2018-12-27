/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements functionality regarding the record layer of
   the TLS protocol. ssh_tls_extra_room calculates the additional room
   that is required for padding and MAC. ssh_tls_decrypt_check_mac and
   ssh_tls_encrypt_make_mac perform the cryptographic transforms.
   ssh_tls_flush takes any partially built packet from the
   outgoing_raw_data buffer and creates an encrypted, full TLS packet
   of it. ssh_tls_unfragment_timeout is a timeout that will cause
   ssh_tls_flush to be called. ssh_tls_cancel_unfragment_timeout can
   be used to cancel the timeout. ssh_tls_parse_incoming looks at the
   incoming_raw_data buffer, finds out full packets and sends them to
   the corresponding higher-layer protocol handlers.
   ssh_tls_start_building is used to start building a record-layer
   packet of a new type. If a packet of the same type is already being
   built, the new data will be just appended.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"
#include "tls_accel.h"

#define SSH_DEBUG_MODULE "SshTlsRecord"

int ssh_tls_extra_room(SshTlsProtocolState s, int len, int iv_len)
{
  int l;
  int pad;

  if (s->conn.outgoing.cipher == NULL || s->conn.outgoing.is_stream_cipher)
    return s->conn.outgoing.mac_length;

  /* The added `1' is the padding_length field. */
  l = len + s->conn.outgoing.mac_length + 1 + iv_len;

  /* Calculate the minimum amount of actual padding. */
  pad = s->conn.outgoing.block_length -
    (l % s->conn.outgoing.block_length);

  if (pad == s->conn.outgoing.block_length)
    pad = 0;

  /* The return value is the length of padding, plus one for the
     padding length field, plus the MAC field. */
  return s->conn.outgoing.mac_length + pad + 1 + iv_len;
}

/* Decrypt incoming packet */
int ssh_tls_decrypt(SshTlsProtocolState s, unsigned char *packet,
                    int packet_len)
{
  if (packet_len < 1)
    {
      SSH_DEBUG(2, ("Trying to decrypt a too short packet."));
      return SSH_TLS_ALERT_DECODE_ERROR;
    }

  s->conn.incoming.current_len = packet_len;

  SSH_DEBUG(8, ("Content length: %d bytes (full packet %d bytes)",
                packet_len, packet_len + SSH_TLS_HEADER_SIZE));

  if (s->conn.incoming.cipher == NULL)
    return 0;

  /* For block ciphers, check that the ciphertext block is
     indeed a multiple of the block length. */
  if (!(s->conn.incoming.is_stream_cipher) &&
       (packet_len % (s->conn.incoming.block_length) != 0))
    {
      SSH_DEBUG(2, ("Got a block encrypted packet with invalid "
                    "ciphertext length."));
      return SSH_TLS_ALERT_DECRYPT_ERROR;
    }

  /* Decrypt */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  /* Use hardware acceleration if it's available */
  if (s->conn.incoming.accel_ctx)
    {
      if (tls_accel_cipher(s->conn.incoming.accel_ctx, s,
        packet + SSH_TLS_HEADER_SIZE, packet_len))
        {
          s->conn.incoming.ops_pending++;
          return 0;
        }
      else
        {
          SSH_DEBUG(2, ("Accelerated cipher failed"));
          return SSH_TLS_ALERT_INTERNAL_ERROR;
        }
    }
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  if (ssh_cipher_start(s->conn.incoming.cipher) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("cipher start operation failed"));
      return SSH_TLS_ALERT_DECRYPT_ERROR;
    }

  if (ssh_cipher_transform(s->conn.incoming.cipher,
                           packet + SSH_TLS_HEADER_SIZE,
                           packet + SSH_TLS_HEADER_SIZE,
                           packet_len) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("cipher transform operation failed"));
      return SSH_TLS_ALERT_DECRYPT_ERROR;
    }

  /* TLS 1.1 and Block cipher: ignore first block */
  if ((s->conn.incoming.cipher) && !s->conn.incoming.is_stream_cipher
                  && (SSH_TLS_VER_TLS1_1 == ssh_tls_version(s)))
    {
      memmove(packet + SSH_TLS_HEADER_SIZE, packet + SSH_TLS_HEADER_SIZE
            + s->conn.incoming.block_length,
            packet_len - s->conn.incoming.block_length);
      s->conn.incoming.current_len -= s->conn.incoming.block_length;
    }
  SSH_DEBUG_HEXDUMP(8, ("Decrypted packet."),
                         packet,  packet_len + SSH_TLS_HEADER_SIZE);

  return 0;
}

/* Check padding of incoming packet */
int ssh_tls_check_padding(SshTlsProtocolState s, unsigned char *packet)
{
  unsigned char *ptr;
  int packet_len = s->conn.incoming.current_len;
  int i;
  int pad;

  if (s->conn.incoming.cipher == NULL || s->conn.incoming.is_stream_cipher)
    return 0;

  /* We know that packet_len > 0, thus ptr will point to valid
     data: */
  ptr = packet + SSH_TLS_HEADER_SIZE + packet_len - 1;
  pad = *ptr;

  SSH_DEBUG(8, ("Amount of padding: %d bytes", pad));

  /* Check that the actual padding bytes are all equivalent to
     the padding length. This is dictated by the TLSv1 protocol... */

  for(i = 0; i < pad; i++)
    {
      ptr--;
      if (ptr < packet + SSH_TLS_HEADER_SIZE)
        {
          SSH_DEBUG(2, ("Invalid padding length field."));
          /*In case of TLS1.1, send decode error */
          if (SSH_TLS_VER_TLS1_1 == ssh_tls_version(s))
            s->conn.incoming.flags |= SSH_TLS_ALERT_DECODE_ERROR;
          else
            s->conn.incoming.flags |= SSH_TLS_DECRYPT_PAD_ERR;
          return 0;
        }
#ifdef SSH_TLS_SSL_3_0_COMPAT /* ...but not by the SSL3 protocol */
      if (!(s->protocol_version.major == 3 &&
            s->protocol_version.minor == 0))
#endif
        if (*ptr != pad)
          {
            SSH_DEBUG(2, ("Invalid padding in a received packet."));
            SSH_DEBUG_HEXDUMP(2, ("Here is the padding data: "),
                              packet + SSH_TLS_HEADER_SIZE + packet_len
                              - 1 - pad, pad + 1);
            /* February 2003. There was an announcement about
               timing based attack against protocol. Here
               we'll spend some time maccing in case padding
               goes wrong, so the attacker does not get
               information what kind of error occured.

               The time spend is approximately same as it
               would be in case of mac being really
               computed. Exact timing is not important, as
               streams mechanims with its timeouts helps with
               timing attacks.

               In case of TLS1.1, send decode error */
            if (SSH_TLS_VER_TLS1_1 == ssh_tls_version(s))
              s->conn.incoming.flags |= SSH_TLS_ALERT_DECODE_ERROR;
            else
              s->conn.incoming.flags |= SSH_TLS_DECRYPT_PAD_ERR;
            return 0;
          }
    }

  /* Remove the padding from the content length */
  s->conn.incoming.current_len -= (pad + 1);

  SSH_DEBUG(8, ("Content length after padding removed: %d bytes",
                s->conn.incoming.current_len));
  return 0;
}

/* SHA hash just fits into a buffer of length 20.  Could be larger,
   but we want for now to trap with SSH_ASSERT any change that someone
   does to the protocol. */
#define TEMP_MAC_BUF_LEN 20

int ssh_tls_check_mac(SshTlsProtocolState s, unsigned char *packet)
{
  SshMac mac;
  unsigned char mac_buf[TEMP_MAC_BUF_LEN];
  unsigned char temp_buf[8 + 1 + 2 + 2]; /* seq num + type + version + length*/
  int tmp_index = 0;

  SSH_ASSERT(s->conn.incoming.current_len >= 0);

  if (s->conn.incoming.mac == NULL)
    return 0;

  SSH_ASSERT(s->conn.incoming.mac_length > 0);
  SSH_ASSERT(sizeof(mac_buf) >= s->conn.incoming.mac_length);

  s->conn.incoming.current_len -= s->conn.incoming.mac_length;

  if (s->conn.incoming.current_len < 0)
    {
      SSH_DEBUG(2, ("Received a malformed packet."));
      return SSH_TLS_ALERT_DECODE_ERROR;
    }

  SSH_DEBUG(8, ("Content length after MAC removed: %d bytes",
                s->conn.incoming.current_len));

  mac = s->conn.incoming.mac;

  ssh_mac_reset(mac);

  /* Sequence number. */
  SSH_TLS_PUT_SEQ(temp_buf, s->conn.incoming.seq);
  tmp_index += 8;

#ifdef SSHUINT64_IS_64BITS
  SSH_DEBUG(8, ("Sequence number: %lld", s->conn.incoming.seq));
#else
  SSH_DEBUG_HEXDUMP(8, ("Seq no:"), temp_buf, 8);
#endif

  /* Header and content */

  /* Type + protocol version */

  /* SSL3 does not include the protocol version in the MAC. */
#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
      temp_buf[tmp_index++] = *packet;
  else
#endif
  {
    memcpy(&temp_buf[tmp_index], packet, SSH_TLS_HEADER_SIZE - 2);
    tmp_index += SSH_TLS_HEADER_SIZE - 2;
  }

  SSH_DEBUG_HEXDUMP(8, ("Header (1)"), packet, SSH_TLS_HEADER_SIZE - 2);
  /* Length field --- must do "manually" because the length field
     used in the calculations does not include MAC nor padding */
  SSH_PUT_16BIT(&temp_buf[tmp_index], s->conn.incoming.current_len);
  tmp_index += 2;

  ssh_mac_update(mac, temp_buf, tmp_index);


  SSH_DEBUG_HEXDUMP(8, ("Header (2)"), temp_buf, 2);

  SSH_DEBUG_HEXDUMP(8, ("Content:"), packet + SSH_TLS_HEADER_SIZE,
    s->conn.incoming.current_len);
  ssh_mac_update(mac, packet + SSH_TLS_HEADER_SIZE,
    s->conn.incoming.current_len);

  if (ssh_mac_final(mac, mac_buf) != SSH_CRYPTO_OK)
    return SSH_TLS_ALERT_INTERNAL_ERROR;

  if (memcmp(mac_buf,
    packet + SSH_TLS_HEADER_SIZE + s->conn.incoming.current_len,
    s->conn.incoming.mac_length) != 0)
    {
      SSH_DEBUG(2, ("Invalid MAC in a received packet"));
      SSH_DEBUG_HEXDUMP(5, ("Received MAC:"),
        packet + SSH_TLS_HEADER_SIZE + s->conn.incoming.current_len,
        s->conn.incoming.mac_length);
      SSH_DEBUG_HEXDUMP(5, ("Locally calculated MAC:"),
        mac_buf,
        s->conn.incoming.mac_length);
      return SSH_TLS_ALERT_BAD_RECORD_MAC;
    }

  SSH_DEBUG_HEXDUMP(5, ("Received MAC:"),
    packet + SSH_TLS_HEADER_SIZE + s->conn.incoming.current_len,
    s->conn.incoming.mac_length);
  SSH_DEBUG_HEXDUMP(5, ("Locally calculated MAC:"), mac_buf,
    s->conn.incoming.mac_length);

  /* content_len has already its correct value. We can return.  The
     packet is ready for consumption. */
  return 0;
}

#undef TEMP_MAC_BUF_LEN

Boolean ssh_tls_make_mac(SshTlsProtocolState s, unsigned char *header,
                         unsigned char *packet, int packet_len)
{
  SshMac mac;
  unsigned char temp_buf[8 + 1 + 2 + 2]; /*seq num + type + version + length*/
  int tmp_index = 0;
  unsigned char *ptr;

  SSH_DEBUG_HEXDUMP(8, ("Make MAC:"), packet, packet_len);

  if (s->conn.outgoing.mac == NULL)
    return TRUE;

  /* Calculate MAC. */
  SSH_ASSERT(s->conn.outgoing.mac_length > 0);
  mac = s->conn.outgoing.mac;

  ssh_mac_reset(mac);

  /* Sequence number */
  SSH_TLS_PUT_SEQ(temp_buf, s->conn.outgoing.seq);
  tmp_index += 8;

#ifdef SSHUINT64_IS_64BITS
  SSH_DEBUG(8, ("Sequence number: %lld", s->conn.outgoing.seq));
#endif

  /* Header and content */
#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    temp_buf[tmp_index++] = *header;
  else
#endif
    {
      memcpy(&temp_buf[tmp_index], header, SSH_TLS_HEADER_SIZE - 2);
      tmp_index += SSH_TLS_HEADER_SIZE - 2;
    }

  SSH_PUT_16BIT(&temp_buf[tmp_index], packet_len);
  tmp_index += 2;
  ssh_mac_update(mac, temp_buf, tmp_index);
  ssh_mac_update(mac, packet,
                 packet_len);

  /* The room for MAC already exists! */

  ptr = packet + packet_len;

  /* Get MAC. */
  if (ssh_mac_final(mac, ptr) != SSH_CRYPTO_OK)
    return FALSE;

  /* Packet has grown. */
  s->conn.outgoing.current_len += s->conn.outgoing.mac_length;
  return TRUE;
}

/* Encrypt TLS frame */
Boolean ssh_tls_encrypt(SshTlsProtocolState s, unsigned char *packet,
                        int packet_len)
{
  unsigned char *ptr;

  SSH_DEBUG_HEXDUMP(8, ("Encrypting:"), packet, s->conn.outgoing.current_len);

  /* Encrypt if encrypting. */

  if (s->conn.outgoing.cipher == NULL)
    {
      SSH_PUT_16BIT(&packet[3],
        s->conn.outgoing.current_len - SSH_TLS_HEADER_SIZE);
      SSH_DEBUG(8, ("NULL cipher"));
      return TRUE;
    }

  if (s->conn.outgoing.is_stream_cipher)
    {
      int len = packet_len - SSH_TLS_HEADER_SIZE + s->conn.outgoing.mac_length;
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      if (s->conn.outgoing.accel_ctx)
        {
          if (tls_accel_cipher(s->conn.outgoing.accel_ctx, s,
                packet + SSH_TLS_HEADER_SIZE, len))
            {
              s->conn.outgoing.ops_pending++;
              s->pend_len += len;
            }
          else
            {
              SSH_DEBUG(2, ("Accelerated cipher failed"));
              return FALSE;
            }
        }
      else
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
        {
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
          /* Make sure that if we do software encryption, there are no
             hardware encrypt operations pending */
          SSH_ASSERT(s->pend_len == 0);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

          if (ssh_cipher_start(s->conn.outgoing.cipher) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(2, ("cipher start operation failed"));
              return FALSE;
            }

          if (ssh_cipher_transform(s->conn.outgoing.cipher,
                                   packet + SSH_TLS_HEADER_SIZE,
                                   packet + SSH_TLS_HEADER_SIZE,
                                   len) !=  SSH_CRYPTO_OK)
            {
              SSH_DEBUG(2, ("cipher transform operation failed"));
              return FALSE;
            }
        }
    }
  else
    {
      int l;
      int pad;

      /* Perform padding. */

      /* The added `1' is the padding_length field. */
      /* l denotes the length of the encrypted portion. */
      l = (packet_len - SSH_TLS_HEADER_SIZE) + s->conn.outgoing.mac_length + 1;

      /* Calculate the minimum amount of actual padding. */
      pad =
        s->conn.outgoing.block_length - (l % s->conn.outgoing.block_length);

      if (pad == s->conn.outgoing.block_length)
        pad = 0;

      ptr = packet + s->conn.outgoing.current_len;

      for(l = 0; l < pad + 1; l++)
        ptr[l] = (unsigned char)pad;

      /* Then encrypt. */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      if (s->conn.outgoing.accel_ctx)
        {
          int len = packet_len - SSH_TLS_HEADER_SIZE +
            s->conn.outgoing.mac_length + 1 + pad;
          if (tls_accel_cipher(s->conn.outgoing.accel_ctx, s,
              packet + SSH_TLS_HEADER_SIZE, len))
            {
              s->conn.outgoing.ops_pending++;
              s->pend_len += len;
            }
          else
            {
              SSH_DEBUG(2, ("Accelerated cipher failed"));
              return FALSE;
            }
        }
      else
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
        {
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
          /* Make sure that if we do software encryption, there are no
             hardware encrypt operations pending */
          SSH_ASSERT(s->pend_len == 0);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

          if (ssh_cipher_start(s->conn.outgoing.cipher) != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(2, ("cipher start operation failed"));
              return FALSE;
            }

          if (ssh_cipher_transform(s->conn.outgoing.cipher,
                                   packet + SSH_TLS_HEADER_SIZE,
                                   packet + SSH_TLS_HEADER_SIZE,
                                   packet_len - SSH_TLS_HEADER_SIZE +
                                   s->conn.outgoing.mac_length + 1 + pad)
              !=  SSH_CRYPTO_OK)
            {
              SSH_DEBUG(2, ("cipher transform operation failed"));
              return FALSE;
            }
        }

      /* Packet has grown again. */
      s->conn.outgoing.current_len += 1 + pad;
    }

  SSH_DEBUG(7, ("Packet encrypted and MAC calculated. Total length %d bytes.",
                s->conn.outgoing.current_len));

  SSH_PUT_16BIT(&packet[3],
    s->conn.outgoing.current_len - SSH_TLS_HEADER_SIZE);

  SSH_DEBUG_HEXDUMP(8, ("Result: "),
                    packet, s->conn.outgoing.current_len);

  return TRUE;
}

void ssh_tls_flush(SshTlsProtocolState s)
{
  int extra_room;
  int total_len;
  unsigned char *ptr;
  int iv_len = 0;

  if ((s->built_len == 0) &&
      (s->built_content_type != SSH_TLS_CTYPE_APPDATA ||
       !(s->conf.flags & SSH_TLS_FIX_IV_LEAK)))
    {
      SSH_DEBUG(7, ("Nothing built, so do nothing."));
      return;
    }

  if (s->flags & SSH_TLS_FLAG_STREAM_WRITE_CLOSED)
    {
      /* We couldn't send this packet anyway, so let's discard it. */
      ssh_buffer_clear(s->outgoing_raw_data);
      s->built_len = 0;
      return;
    }

#ifdef DEBUG_LIGHT
  if ((s->built_len == SSH_TLS_HEADER_SIZE) &&
      !(s->conf.flags & SSH_TLS_FIX_IV_LEAK))
    {
      SSH_DEBUG(7, ("For some mysterious reason, only the header "
                    "is present!"));
      SSH_NOTREACHED;
    }
#endif

  SSH_ASSERT(s->built_len >= SSH_TLS_HEADER_SIZE);
  SSH_DEBUG(7, ("Sending a packet (%d bytes).", s->built_len));

  if ((NULL != s->conn.outgoing.cipher) && !s->conn.outgoing.is_stream_cipher
                  && (SSH_TLS_VER_TLS1_1 == ssh_tls_version(s)))
    {
      iv_len = s->conn.outgoing.block_length;
      SSH_DEBUG(6,("Handling CBCATT, iv_len=%d", iv_len));
    }

  /* There are s->built_len - SSH_TLS_HEADER_SIZE payload bytes. */
  extra_room = ssh_tls_extra_room(s, s->built_len - SSH_TLS_HEADER_SIZE,
                  iv_len);

  if (ssh_buffer_append_space(s->outgoing_raw_data, &ptr, extra_room)
      != SSH_BUFFER_OK)
    {
      s->built_len = 0; /* nothing is built now. */
      ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  SSH_ASSERT(s->built_len + iv_len <= SSH_TLS_MAX_RECORD_LENGTH
             + SSH_TLS_HEADER_SIZE);

  /* Move to the beginning of the packet. */
  ptr -= s->built_len;

  if (iv_len)
    {
      int l = 0;
      /*TLS 1.1: Insert random IV before compressed text before encryption*/
      memmove(ptr + SSH_TLS_HEADER_SIZE + iv_len,
                    ptr + SSH_TLS_HEADER_SIZE, s->built_len);
      for (l = 0; l < iv_len; l++)
        {
          ptr[SSH_TLS_HEADER_SIZE + l] = ssh_random_get_byte();
        }
    }

  /* Write the header */
  ptr[0] = s->built_content_type;
  /* Write TLS 1.1 header if the protocol version is unknown */
  if (s->protocol_version.major == 0)
    {
      ptr[1] = 3; ptr[2] = 2;
    }
  else
    {
      ptr[1] = s->protocol_version.major;
      ptr[2] = s->protocol_version.minor;
    }
  SSH_PUT_16BIT(&ptr[3], s->built_len - SSH_TLS_HEADER_SIZE + iv_len);

  s->conn.outgoing.current_len =  s->built_len + iv_len;

  if (!ssh_tls_make_mac(s, ptr, ptr + SSH_TLS_HEADER_SIZE + iv_len,
                        s->built_len - SSH_TLS_HEADER_SIZE))
    {
      s->built_len = 0; /* nothing is built now. */
      /* Cannot send alert if crypto failed */
      ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  if (!ssh_tls_encrypt(s, ptr, s->built_len + iv_len))
    {
      s->built_len = 0; /* nothing is built now. */
      /* Cannot send alert if crypto failed */
      ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }
  total_len = s->conn.outgoing.current_len;

  SSH_ASSERT(total_len == s->built_len + extra_room);

  /* Done. Increment sequence number. */

  SSH_TLS_INCREMENT_SEQ(s->conn.outgoing.seq);

  if (SSH_TLS_IS_ZERO_SEQ(s->conn.outgoing.seq)) /* Wrap around? Prohibited. */
    {
      /* Prohibiting the sequence number from wrapping around is
         specified in the protocol */
      SSH_DEBUG(2, ("Sequence number wrapped around!"));
      /* Cannot send alert packet! */
      ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  /* Nothing is built now. */
  s->built_len = 0;

  /* Increment statistics... */
  s->stats.packets_sent++;

  /* Write something out, now that we have a packet. */
  ssh_tls_try_write_out(s);
}

void ssh_tls_unfragment_timeout(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(7, ("Got unfragment timeout."));
  SSH_ASSERT(s->flags & SSH_TLS_FLAG_REQUESTED_TIMEOUT);
  s->flags &= ~SSH_TLS_FLAG_REQUESTED_TIMEOUT;
  ssh_tls_flush(s);
}

void ssh_tls_cancel_unfragment_timeout(SshTlsProtocolState s)
{
  ssh_cancel_timeouts(ssh_tls_unfragment_timeout, s);
  s->flags &= ~SSH_TLS_FLAG_REQUESTED_TIMEOUT;
}

void ssh_tls_parse_incoming(SshTlsProtocolState s)
{
  int l;
  int packet_len;
  int content_len;
  unsigned char *ptr;
  int major, minor;
  SshTlsContentType type;

#ifdef SSH_TLS_SSL_2_0_COMPAT
  /* `converted' will contain and ssh_malloc()ated datum that is
     a 3.x packet in the case that we have received a 2.x packet;
     it is converted to a version 3 packet and removed from the input
     stream immediately. */

  unsigned char *converted = NULL;
  int converted_length;
#endif

parse_next_packet:
  converted = NULL;

  if (s->flags & SSH_TLS_FLAG_FROZEN)
    {
      SSH_DEBUG(6,
                ("Protocol %p frozen, so do not parse incoming data now.", s));
      return;
    }

  l = ssh_buffer_len(s->incoming_raw_data);

  /* Stop parsing immediately if we have for some reason
     a failed status or have been deleted. */
  if (SSH_TLS_IS_FAILED_STATUS(s->status))
    {
      if (l > 0)
        {
          ssh_buffer_clear(s->incoming_raw_data);
          s->packet_feed_len = 0;
          s->trailer_len = -1;
        }
      SSH_DEBUG(7, ("Protocol %p is in error condition, "
                    "so do not parse anything.", s));
      return;
    }

  /* If we are feeding a packet to the upper layer the start of
     s->incoming_raw_data is not necessarily the start of a new
     packet. As long as we are feeding we do not parse packets
     further. Instead, we wait until the current application data has
     been consumed. */
  if (s->packet_feed_len > 0)
    {
      SSH_DEBUG(7, ("Feeding a packet to the upper layer, so do not "
                    "parse further packets yet."));
      return;
    }

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  /* If decrypt is in progress, wait */
    if (s->conn.incoming.ops_pending)
      return;

  {
    /* We use fixed size buffer when hw-acceleration is configured. Call
       ssh_buffer_append_space() with huge length. It will fail but move
       data at the beginning of SshBuffer. This ensures that data does not
       move while hardware is performing a crypto operation.
    */
    unsigned char *data;
    ssh_buffer_append_space(s->incoming_raw_data, &data, 0x1000000);
  }
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  if ((s->flags & SSH_TLS_FLAG_GOT_CLOSE_NOTIFY) && l > 0)
    {
      SSH_DEBUG(7, ("Extraneous data after close_notify!"));
      ssh_buffer_clear(s->incoming_raw_data);
      l = 0;

      /* This is not an error according to the standard, but the
         remaining data is discarded. */
      return;
    }

  SSH_DEBUG(9, ("Trying to parse incoming packets for %p "
                "(%d bytes in the buffer).", s, l));

  SSH_DEBUG_HEXDUMP(9, ("Buffer contents (%s):",
                        l < 500 ? "full" : "500 first bytes"),
                    ssh_buffer_ptr(s->incoming_raw_data),
                    l < 500 ? l : 500);

  if (l < SSH_TLS_HEADER_SIZE)
    {
      if (s->flags & SSH_TLS_FLAG_STREAM_EOF)
        goto eof_encountered;

      /* Otherwise return now. */
      return;
    }

  ptr = ssh_buffer_ptr(s->incoming_raw_data);

#ifdef SSH_TLS_SSL_2_0_COMPAT
  /* If the protocol version is unknown check if the first packet is
     an SSL v. 2.0 packet and proceed accordingly. */
  if (s->protocol_version.major == 0 &&
      (ptr[0] == 0x80))
    {
      if (s->conf.flags & SSH_TLS_SSL2)
        {
          int reclen;
          int challenge_len;
          int sessid_len;
          int num_ciphers;
          unsigned char *tptr, *tptr2;
          int i;
          int count;

          reclen = ((ptr[0] & 0x7f) << 8) | (ptr[1]);
          SSH_DEBUG(8, ("Seems like an SSL v 2.0 packet, %d byte record.",
                        reclen));

          if (l + 2 < reclen)
            {
              SSH_DEBUG(8, ("V 2.0 packet not fully received."));
              return;
            }

          /* As the protocol version was unknown this should be a
             client hello message. */
          if (reclen < 9 || ptr[2] != 0x01)
            {
              SSH_DEBUG(8, ("Invalid v 2.0 (handshake) packet."));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
              return;
            }

          /* As long as v 2.0 is not fully supported, the remaining
             thing is to convert the handshake message into the version
             three format. */
          converted_length = SSH_TLS_HEADER_SIZE
            + 4 /* handshake protocol header */
            + 2 /* client version */
            + 32 /* random */
            + 1 /* zero-length session identifier */
            + 2 /* number of cipher suites */
            /* cipher suites */
            + (num_ciphers = (((ptr[5] << 8) | ptr[6]) / 3)) * 2
            + 1 /* number of compression methods */
            + 1; /* the NULL compression method */

          challenge_len = SSH_GET_16BIT(&ptr[9]);
          if (challenge_len < 16)
            {
              SSH_DEBUG(8, ("Too short challenge, I will reject this "
                            "handshake packet."));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INSUFFICIENT_SECURITY);
              return;
            }

          sessid_len = SSH_GET_16BIT(&ptr[7]);

          if (sessid_len + num_ciphers * 3 + challenge_len + 9 !=
              reclen)
            {
              SSH_DEBUG(8, ("Invalid length fields in a v 2.0 packet: "
                            "Session identifier %d bytes, cipher specs "
                            "%d bytes, challenge %d bytes, header %d bytes "
                            "summing up to %d bytes but the record is %d "
                            "bytes long.",
                            sessid_len, num_ciphers * 3,
                            challenge_len, 9,
                            sessid_len + num_ciphers * 3 + challenge_len
                            + 9, reclen));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_DECODE_ERROR);
              return;
            }

          if ((converted = ssh_calloc(1, converted_length)) == NULL)
            {
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
              return;
            }

          /* Record layer header */
          converted[0] = SSH_TLS_CTYPE_HANDSHAKE;
          converted[1] = ptr[3]; /* major version */
          converted[2] = ptr[4]; /* minor version */

          /* Handshake protocol header will be written last when
             the actual length is known. */

          /* Start of the ClientHello: client_version */
          converted[9] = ptr[3]; /* version, again */
          converted[10] = ptr[4];

          /* Convert the cipher suites */
          tptr = &ptr[11];
          tptr2 = &converted[46];
          count = 0;

          for (i = 0; i < num_ciphers; i++)
            {
              if (tptr[0] != 0x00)
                {
                  SSH_DEBUG(8, ("Skipping v 2.0 cipher suite "
                                "{%02x,%02x,%02x}.",
                                tptr[0], tptr[1], tptr[2]));
                  /* This suite was also counted to `num_ciphers'
                     so decrease the length of the actual converted
                     packet now. */
                  converted_length -= 2;
                }
              else
                {
                  SSH_DEBUG(8, ("TLS cipher suite {%02x,%02x} found.",
                                tptr[1], tptr[2]));
                  count++;
                  tptr2[0] = tptr[1];
                  tptr2[1] = tptr[2];
                  tptr2 += 2;
                }
              tptr += 3;
            }
          SSH_PUT_16BIT(&converted[44], count * 2);
          SSH_DEBUG(8, ("Got %d cipher suites.", count));

          /* Write the NULL compression method. */
          tptr2[0] = 1;
          tptr2[1] = 0;
          tptr2 += 2;

          /* Sanity check. */
          SSH_ASSERT(tptr2 == converted + converted_length);

          /* What is missing is the random data. */
          /* `tptr' is at the end of cipher specs of the v 2.0 packet.
             Jump over the possible session identifier. */
          tptr += sessid_len;
          if (challenge_len < 32)
            {
              memset(&converted[11], 0, 32 - challenge_len);
              memcpy(&converted[11 + 32 - challenge_len],
                     tptr, challenge_len);
            }
          else
            {
              memcpy(&converted[11], tptr + (challenge_len - 32),
                     32);
            }

          /* Empty session identifier. */
          converted[43] = 0;

          /* Length fields can be written only now as the actual length
             is known. */
          /* Record layer length */
          SSH_PUT_16BIT(&converted[3], converted_length - SSH_TLS_HEADER_SIZE);

          /* Handshake layer length */
          converted[6] =
            ((converted_length - SSH_TLS_HEADER_SIZE - 4) >> 16) & 0xff;
          converted[7] =
            ((converted_length - SSH_TLS_HEADER_SIZE - 4) >> 8) & 0xff;
          converted[8] =
            (converted_length - SSH_TLS_HEADER_SIZE - 4) & 0xff;

          /* Handshake layer message type */
          converted[5] = SSH_TLS_HS_CLIENT_HELLO;

          /* Done */
          SSH_DEBUG_HEXDUMP(8, ("Converted packet:"),
                            converted, converted_length);

          /* Consume the old v 2.0 packet now. */
          SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data)
                     >= 2 + reclen);
          ssh_buffer_consume(s->incoming_raw_data,
                             2 + reclen);

          /* Add to the key exchange history. */
          SSH_ASSERT(s->kex.handshake_history == NULL);

          s->kex.flags |= SSH_TLS_KEX_CONVERTED_CLIENT_HELLO;

          s->kex.handshake_history = ssh_buffer_allocate();

          if (s->kex.handshake_history == NULL)
            {
              /* Internal error. Don't try to send alert. */
              ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
              return;
            }

          if (ssh_buffer_append(s->kex.handshake_history, ptr + 2,
                                reclen) != SSH_BUFFER_OK)
            {
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
              return;
            }

          ptr = converted;
          l = converted_length;
        }
      else
        {
          SSH_DEBUG(2, ("SSL2 connection dropped"));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_PROTOCOL_VERSION);

        }
    }
#endif /* SSH_TLS_SSL_2_0_COMPAT */

  major = ptr[1];
  minor = ptr[2];

  /* Check that the record layer protocol version does not change on
     the fly. */
  if (s->flags & SSH_TLS_FLAG_VERSION_FIXED)
    {
      if ((major != s->protocol_version.major) ||
          (minor != s->protocol_version.minor))
        {
#ifdef SSH_TLS_SSL_2_0_COMPAT
          if (converted != NULL) ssh_free(converted);
#endif
          SSH_DEBUG(2, ("The protocol version has changed on the "
                        "fly from %d.%d to %d.%d (not tolerated).",
                        s->protocol_version.major,
                        s->protocol_version.minor,
                        major, minor));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
          return;
        }
    }

  /* Get the initial version number if this is the first packet got
     from the client (and we are the server). */
  if (s->protocol_version.major == 0)
    {
      s->protocol_version.major = major;
      s->protocol_version.minor = minor;
    }

  packet_len = (ptr[3] << 8) + ptr[4];

  /* This won't be true if we have a converted packet. */
  if (packet_len > l - SSH_TLS_HEADER_SIZE)
    {
      if (s->flags & SSH_TLS_FLAG_STREAM_EOF)
        goto eof_encountered;
      return;
    }

  type = ptr[0];

  SSH_DEBUG(7, ("Got a full packet of type `%s'.",
                ssh_tls_content_type_str(type)));

  /* Perform cryptographic transformations and check the MAC. */

    {
      int alert_msg;

      /* If decrypt is complete, proceed without decrypt */
      if (s->conn.incoming.flags & SSH_TLS_DECRYPT_DONE)
        s->conn.incoming.flags &= ~SSH_TLS_DECRYPT_DONE;
      else
        {
          if ((alert_msg = ssh_tls_decrypt(s, ptr, packet_len)) != 0)
            {
              SSH_DEBUG(2, ("Decryption failed."));
              if (alert_msg == SSH_TLS_ALERT_INTERNAL_ERROR)
                /* Internal error. Don't try to send alert. */
                ssh_tls_immediate_kill(s, alert_msg);
              else
                ssh_tls_alert_and_kill(s, alert_msg);
              return;
          }
        }

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      /* If decrypt was started, wait */
      if (s->conn.incoming.ops_pending)
        return;
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

      if ((alert_msg = ssh_tls_check_padding(s, ptr)) != 0)
        {
          SSH_DEBUG(2, ("Check padding failed."));
          ssh_tls_alert_and_kill(s, alert_msg);
          return;
        }
      if ((alert_msg = ssh_tls_check_mac(s, ptr)) != 0)
        {
          SSH_DEBUG(2, ("MAC check failed."));
          ssh_tls_alert_and_kill(s, alert_msg);
          return;
        }
      if (s->conn.incoming.flags & SSH_TLS_DECRYPT_PAD_ERR)
        {
          SSH_DEBUG(2, ("Padding error."));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_DECODE_ERROR);
          return;
        }
      content_len = s->conn.incoming.current_len;
    }

  SSH_DEBUG(7, ("Packet processed, content length %d bytes.",
                content_len));

  SSH_TLS_INCREMENT_SEQ(s->conn.incoming.seq);

  if (SSH_TLS_IS_ZERO_SEQ(s->conn.incoming.seq)) /* Wrap around? Prohibited. */
    {
      /* Prohibiting the sequence number from wrapping around is
         specified in the protocol */
      SSH_DEBUG(2, ("Sequence number wrapped around!"));
      ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  /* Increment counter. */
  s->stats.packets_received++;

  /* Dispatch on the packet type.
     First check for application data. */
  if (type == SSH_TLS_CTYPE_APPDATA)
    {
      /* If the stream has been deleted do not process application data
         any more. */
      if (s->flags & SSH_TLS_FLAG_DELETED)
        {
          SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data)
                     >= SSH_TLS_HEADER_SIZE + packet_len);
          ssh_buffer_consume(s->incoming_raw_data, SSH_TLS_HEADER_SIZE +
                             packet_len);
          return;
        }

      if (!(s->flags & SSH_TLS_FLAG_INITIAL_KEX_DONE))
        {
          SSH_DEBUG(4, ("Got application data before the initial "
                        "key exchange was finished."));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
          return;
        }

      SSH_ASSERT(s->packet_feed_len == 0);
      SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data)
                 >= SSH_TLS_HEADER_SIZE);
      ssh_buffer_consume(s->incoming_raw_data, SSH_TLS_HEADER_SIZE);
      s->packet_feed_len = content_len;
      s->trailer_len = packet_len - content_len;
      SSH_ASSERT(s->trailer_len >= 0);
      ssh_tls_ready_for_reading(s);

      /* We return so that the packet does not get removed
         from the stream. */
      return;
    }
  else
    {
      /* Otherwise find a higher-level protocol record that
         contains a function that processes this packet. */
      SshTlsHigherProtocol i;
      for (i = s->protocols; i != NULL; i = i->next)
        {
          if (i->type == type)
            {

              if (ssh_buffer_append(i->data, ptr + SSH_TLS_HEADER_SIZE,
                                    content_len) != SSH_BUFFER_OK)
                {
                  ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
                  return;
                }

#ifdef SSH_TLS_SSL_2_0_COMPAT
              /* Delete the current packet from the stream. */
              if (converted == NULL)
                {
#endif /* SSH_TLS_SSL_2_0_COMPAT */

                  SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >=
                             packet_len + SSH_TLS_HEADER_SIZE);
                  ssh_buffer_consume(s->incoming_raw_data,
                                     packet_len + SSH_TLS_HEADER_SIZE);
#ifdef SSH_TLS_SSL_2_0_COMPAT
                }
              else
                {
                  SSH_DEBUG(9, ("Freeing the converted packet."));
                  ssh_free(converted);
                }
#endif /* SSH_TLS_SSL_2_0_COMPAT */

              /* Call the function */
              l = (*(i->func))(s, i);

              if (l < 0)
                {
                  SSH_DEBUG(5, ("Higher layer protocol failed."));
                  /* ssh_tls_immediate_kill() has been already called. */
                  return;
                }

              /* Remove the processed data. */
              SSH_ASSERT(l <= ssh_buffer_len(i->data));
              SSH_ASSERT(ssh_buffer_len(i->data) >= l);
              ssh_buffer_consume(i->data, l);
              break;
            }
        }

      /* Unrecognized content type? Barf. */
      if (i == NULL)
        {
          SSH_DEBUG(2, ("Unrecognized packet type %d.", type));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
          return;
        }
    }

  SSH_DEBUG(7, ("%d bytes in the incoming_raw_data buffer.",
                ssh_buffer_len(s->incoming_raw_data)));

  /* There might be more packets to parse... */
  goto parse_next_packet;

eof_encountered:
  SSH_DEBUG(7, ("EOF from the underlying stream detected."));

  if (l > 0)
    {
      SSH_DEBUG(4, ("Partial packet in the input buffer, this is an error."));
      if (SSH_TLS_VER_TLS1_1 == ssh_tls_version(s)) {
        /* as per TLS1.1, in this case cached session should not be
         * invalidated*/
        ssh_tls_kill_failed_state(s, SSH_TLS_FAIL_PREMATURE_EOF);
      }
      else
        ssh_tls_immediate_kill(s, SSH_TLS_FAIL_PREMATURE_EOF);
      return;
    }

  if (!(s->flags & SSH_TLS_FLAG_GOT_CLOSE_NOTIFY))
    {
      SSH_DEBUG(4, ("%p Got EOF but not close notify. This is an error --- "
                    "the protocol has not been closed properly.", s));

      if (ssh_tls_version(s) == SSH_TLS_VER_TLS1_1)
        {
          /* For TLS 1.1 the cached session should not be invalidated */
          ssh_tls_kill_failed_state(s, SSH_TLS_FAIL_PREMATURE_EOF);
        }
      else
        ssh_tls_immediate_kill(s, SSH_TLS_FAIL_PREMATURE_EOF);

      return;
    }

  /* EOF got, there is nothing in the buffer and we have got
     the close notify. Everything is all right. */
}

void ssh_tls_start_building(SshTlsProtocolState s, SshTlsContentType type)
{
  unsigned char *ptr;

  SSH_DEBUG(6, ("Starting to build a packet of the type `%s'.",
                ssh_tls_content_type_str(type)));

  if (type != s->built_content_type && s->built_len > 0)
    {
      SSH_DEBUG(6, ("There was a packet being built of the content type "
                    "`%s', so send it first.",
                    ssh_tls_content_type_str(s->built_content_type)));
      ssh_tls_flush(s);
    }

  SSH_ASSERT(type == s->built_content_type || s->built_len == 0);

  if (s->built_len == 0)
    {
      if (ssh_buffer_append_space(s->outgoing_raw_data, &ptr,
                                  SSH_TLS_HEADER_SIZE) != SSH_BUFFER_OK)
        {
          /* Dont try sending an alert on memory failure, just kill
             the state immediately */
          ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
          return;
        }

      s->built_len = SSH_TLS_HEADER_SIZE;
      s->built_content_type = type;
    }

  SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_DESTROY_SCHEDULED));

  if (!(s->flags & SSH_TLS_FLAG_REQUESTED_TIMEOUT))
    {
      SSH_DEBUG(7, ("Registering unfragment timeout after "
                    "%ld microseconds.",
                    (unsigned long) s->conf.unfragment_delay));
      ssh_xregister_timeout(0L, (long) s->conf.unfragment_delay,
                           ssh_tls_unfragment_timeout, s);
      s->flags |= SSH_TLS_FLAG_REQUESTED_TIMEOUT;
    }
  else
    {
      SSH_DEBUG(7, ("Unfragment timeout is already coming."));
    }
}
