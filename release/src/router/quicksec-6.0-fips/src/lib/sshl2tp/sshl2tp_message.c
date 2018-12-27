/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encoding and decoding of L2TP messages and AVP (Attribute Value
   Pair) handling.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpMessage"


/************************ AVP Encoding and Decoding *************************/

/* Set result code `result' and error code `error' to the L2TP module
   `l2tp'.  The argument `text' can specify human readable description
   about the error. */
#define SSH_L2TP_SET_ERROR(l2tp, result, error, text)           \
do                                                              \
  {                                                             \
    if (!(l2tp)->result_code)                                   \
      {                                                         \
        (l2tp)->result_code = (result);                         \
        (l2tp)->error_code = (error);                           \
                                                                \
        if (text)                                               \
          {                                                     \
            /* temporary casts until library API is changed */  \
            ssh_snprintf(ssh_sstr((l2tp)->error_message_buf),   \
                         sizeof((l2tp)->error_message_buf),     \
                         "%s", (text));                         \
            (l2tp)->error_message = (l2tp)->error_message_buf;  \
            (l2tp)->error_message_len                           \
              = ssh_ustrlen((l2tp)->error_message_buf);         \
          }                                                     \
      }                                                         \
  }                                                             \
while (0)

/* Set result code `result' and error code `error' to the L2TP module
   `l2tp'.  A human readable error description is already formatted to
   `l2tp->error_message_buf'. */
#define SSH_L2TP_SET_ERROR_FMT(l2tp, result, error)                     \
do                                                                      \
  {                                                                     \
    if (!(l2tp)->result_code)                                           \
      {                                                                 \
        (l2tp)->result_code = (result);                                 \
        (l2tp)->error_code = (error);                                   \
        (l2tp)->error_message = (l2tp)->error_message_buf;              \
        (l2tp)->error_message_len =                                     \
          ssh_ustrlen((l2tp)->error_message_buf);                       \
      }                                                                 \
  }                                                                     \
while (0)

/* Decode a variable length attribute and store its dynamically
   allocated value to `message->_attribute'.  The attribute's length
   is stored in `message->_attribute ## _len'. */
#define SSH_L2TP_AVP_DECODE_DYNAMIC(_attribute)                         \
do                                                                      \
  {                                                                     \
    ssh_free(message->_attribute);                                      \
    message->_attribute = ssh_memdup(SSH_L2TP_AVP_VALUE,                \
                                     SSH_L2TP_AVP_VALUE_LEN);           \
    if (message->_attribute == NULL)                                    \
      {                                                                 \
        SSH_DEBUG(SSH_D_ERROR, ("Out of memory"));                      \
        SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,          \
                           SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,       \
                           "Out of memory");                            \
        return SSH_AVP_DECODE_ERROR_MEMORY;                             \
      }                                                                 \
    message->_attribute ## _len = SSH_L2TP_AVP_VALUE_LEN;               \
  }                                                                     \
while (0)

typedef enum
{
  SSH_AVP_DECODE_OK,
  SSH_AVP_DECODE_SKIP_MESSAGE,
  SSH_AVP_DECODE_ERROR_PROTOCOL,
  SSH_AVP_DECODE_ERROR_MEMORY,
  SSH_AVP_DECODE_ERROR
} SshL2tpAvpDecodeResult;

#define SSH_L2TP_AVP(name, mandatory, hidden, min_len, max_len) \
{ssh_l2tp_avp_encode_ ## name, ssh_l2tp_avp_decode_ ## name,    \
 mandatory, hidden, min_len, max_len},

#define SSH_L2TP_D_NAME(name) ssh_l2tp_avp_decode_ ## name
#define SSH_L2TP_E_NAME(name) ssh_l2tp_avp_encode_ ## name

#define SSH_L2TP_AVP_DECODER(name)                              \
static SshL2tpAvpDecodeResult                                   \
SSH_L2TP_D_NAME(name)(SshL2tp l2tp,                             \
                      const unsigned char *avp, size_t avp_len, \
                      SshUInt32 avp_count, Boolean mandatory,   \
                      SshL2tpControlMessage message)

typedef SshL2tpAvpDecodeResult (*SshAvpDecoder)(SshL2tp l2tp,
                                                const unsigned char *avp,
                                                size_t avp_len,
                                                SshUInt32 avp_count,
                                                Boolean mandatory,
                                                SshL2tpControlMessage message);


typedef enum
{
  SSH_AVP_ENCODE_OK,
  SSH_AVP_ENCODE_NOT_PRESENT,
  SSH_AVP_ENCODE_ERROR
} SshL2tpAvpEncodeResult;

#define SSH_L2TP_AVP_ENCODER(name)                              \
static SshL2tpAvpEncodeResult                                   \
SSH_L2TP_E_NAME(name)(SshL2tp l2tp, SshL2tpTunnel tunnel,       \
                      SshL2tpSession session,                   \
                      SshL2tpControlMsgType message_type,       \
                      Boolean hidden,                           \
                      unsigned char *avp, size_t *avp_len_return)

typedef SshL2tpAvpEncodeResult (*SshAvpEncoder)(
                                        SshL2tp l2tp,
                                        SshL2tpTunnel tunnel,
                                        SshL2tpSession session,
                                        SshL2tpControlMsgType message_type,
                                        Boolean hidden,
                                        unsigned char *avp,
                                        size_t *avp_len_return);

/* Some handy macros for encoders and decoders. */
#define SSH_L2TP_AVP_VALUE (avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE)
#define SSH_L2TP_AVP_VALUE_LEN (avp_len - SSH_L2TP_AVP_HDRLEN)


SSH_L2TP_AVP_ENCODER(message_type)
{
  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, message_type);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Message Type %s (%d)",
             ssh_find_keyword_name(ssh_l2tp_control_msg_types, message_type),
             message_type));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(message_type)
{
  if (avp_count != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Message Type MUST be the first AVP"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "Message Type AVP was not the first AVP");
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  message->type = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Message Type %s (%d)",
             ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                   message->type),
             message->type));

  if (message->type >= SSH_L2TP_CTRL_MSG_NUM_MESSAGES)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Uknown message type: mandatory=%d",
                                mandatory));
      if (mandatory)
        {



          ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                       sizeof(l2tp->error_message_buf),
                       "Unknown mandatory message type %d", message->type);
          SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                 SSH_L2TP_ERROR_INVALID_VALUE);
          return SSH_AVP_DECODE_ERROR;
        }
      else
        {
          return SSH_AVP_DECODE_SKIP_MESSAGE;
        }
    }

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(result_code)
{
  if (l2tp->result_code == 0)
    {
      /* No result code to report. */
      return SSH_AVP_ENCODE_NOT_PRESENT;
    }

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, l2tp->result_code);

  if (l2tp->result_code == SSH_L2TP_TUNNEL_RESULT_ERROR)
    {
      /* We have also the error code. */
      SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE + 2, l2tp->error_code);
    }
  else
    {
      /* Some other result code without an optional error code.  Note
         that the error code would be optional in this case but there
         seems to be some implementations out there which always
         require the error code, so let's add this extra two bytes and
         interoperate with them. */
      SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE + 2, 0);
    }

  if (message_type == SSH_L2TP_CTRL_MSG_STOPCCN)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Result Code `%s - %s' (%d %d)",
               ssh_find_keyword_name(ssh_l2tp_tunnel_result_codes,
                                     l2tp->result_code),
               ssh_find_keyword_name(ssh_l2tp_error_codes,
                                     l2tp->error_code),
               (int) l2tp->result_code,
               (int) l2tp->error_code));
  else
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Result Code `%s - %s' (%d %d)",
               ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                     l2tp->result_code),
               ssh_find_keyword_name(ssh_l2tp_error_codes,
                                     l2tp->error_code),
               (int) l2tp->result_code,
               (int) l2tp->error_code));

  if (l2tp->error_message)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Error Message: %.*s",
                                   (int) l2tp->error_message_len,
                                   l2tp->error_message));

      memcpy(SSH_L2TP_AVP_VALUE + 4, l2tp->error_message,
             l2tp->error_message_len);
      *avp_len_return = 4 + l2tp->error_message_len;
    }
  else
    {
      *avp_len_return = 4;
    }

  *avp_len_return += SSH_L2TP_AVP_HDRLEN;

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(result_code)
{
  message->result_code = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  if (avp_len == SSH_L2TP_AVP_HDRLEN + 2)
    {
      /* All done. */
      if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code `%s' (%d)",
                   ssh_find_keyword_name(ssh_l2tp_tunnel_result_codes,
                                         message->result_code),
                   (int) message->result_code));
      else if (message->type == SSH_L2TP_CTRL_MSG_CDN)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code `%s' (%d)",
                   ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                         message->result_code),
                   (int) message->result_code));
      else
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code %d",
                   (int) message->result_code));
    }
  else if (avp_len < SSH_L2TP_AVP_HDRLEN + 4)
    {



      ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                   sizeof(l2tp->error_message_buf),
                   "Result Code AVP is too short for Error Code: "
                   "Length=%d", avp_len);
      SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_LENGTH_IS_WRONG);
      return SSH_AVP_DECODE_ERROR;
    }
  else
    {
      message->error_code = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE + 2);

      if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code `%s - %s' (%d %d)",
                   ssh_find_keyword_name(ssh_l2tp_tunnel_result_codes,
                                         message->result_code),
                   ssh_find_keyword_name(ssh_l2tp_error_codes,
                                         message->error_code),
                   (int) message->result_code,
                   (int) message->error_code));
      else if (message->type == SSH_L2TP_CTRL_MSG_CDN)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code `%s - %s' (%d %d)",
                   ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                         message->result_code),
                   ssh_find_keyword_name(ssh_l2tp_error_codes,
                                         message->error_code),
                   (int) message->result_code,
                   (int) message->error_code));
      else
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Result Code %d %d",
                   (int) message->result_code,
                   (int) message->error_code));


      if (avp_len > SSH_L2TP_AVP_HDRLEN + 4)
        {
          message->error_message_len = avp_len - (SSH_L2TP_AVP_HDRLEN + 4);
          memcpy(message->error_message_buf, SSH_L2TP_AVP_VALUE + 4,
                 message->error_message_len);

          message->error_message = message->error_message_buf;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Error Message: %.*s",
                     (int) message->error_message_len,
                     message->error_message));
        }
    }

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(protocol_version)
{
  SSH_PUT_8BIT(SSH_L2TP_AVP_VALUE, SSH_L2TP_PROTOCOL_VERSION);
  SSH_PUT_8BIT(SSH_L2TP_AVP_VALUE + 1, SSH_L2TP_PROTOCOL_REVISION);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Protocol Version %d.%d",
                               SSH_L2TP_PROTOCOL_VERSION,
                               SSH_L2TP_PROTOCOL_REVISION));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(protocol_version)
{
  SshUInt8 ver, rev;

  ver = SSH_GET_8BIT(SSH_L2TP_AVP_VALUE);
  rev = SSH_GET_8BIT(SSH_L2TP_AVP_VALUE + 1);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Protocol Version %d.%d",
                               (int) ver, (int) rev));
  if (ver != SSH_L2TP_PROTOCOL_VERSION || rev != SSH_L2TP_PROTOCOL_REVISION)
    {
      SshUInt16 highest_supported = ((SSH_L2TP_PROTOCOL_VERSION << 8)
                                     | SSH_L2TP_PROTOCOL_REVISION);

      SSH_DEBUG(SSH_D_NETFAULT, ("Unsupported protocol version %d.%d",
                                 (int) ver, (int) rev));



      ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                   sizeof(l2tp->error_message_buf),
                   "Unsupported protocol version %d.%d: "
                   "the supported version is %d.%d",
                   ver, rev,
                   SSH_L2TP_PROTOCOL_VERSION,
                   SSH_L2TP_PROTOCOL_REVISION);
      SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_UNSUPPORTED_PROTOCOL,
                             highest_supported);
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(framing_capabilities)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, l2tp->params.framing_capabilities);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Framing Capabilities 0x%08lx",
             (unsigned long) l2tp->params.framing_capabilities));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(framing_capabilities)
{
  message->tunnel_attributes.framing_capabilities
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Framing Capabilities 0x%08lx",
             (unsigned long) message->tunnel_attributes.framing_capabilities));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(bearer_capabilities)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, l2tp->params.bearer_capabilities);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Bearer Capabilities 0x%08lx",
             (unsigned long) l2tp->params.bearer_capabilities));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(bearer_capabilities)
{
  message->tunnel_attributes.bearer_capabilities
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Bearer Capabilities 0x%08lx",
             (unsigned long) message->tunnel_attributes.bearer_capabilities));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(tie_breaker)
{
  /* TODO: Handling of simultaneous tunnel establishment is not
     implemented yet. */
  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(tie_breaker)
{
  memcpy(message->tie_breaker, SSH_L2TP_AVP_VALUE, 8);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Tie Breaker 0x%08lx%08lx",
                               SSH_GET_32BIT(message->tie_breaker),
                               SSH_GET_32BIT(message->tie_breaker + 4)));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(firmware_revision)
{
  SshUInt16 value = (4 << 8) | 1;

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, value);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Firmware Revision 0x%x", (unsigned int) value));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(firmware_revision)
{
  message->tunnel_attributes.firmware_revision
    = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Firmware Revision 0x%x",
             (unsigned int) message->tunnel_attributes.firmware_revision));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(host_name)
{
  memcpy(SSH_L2TP_AVP_VALUE, l2tp->params.hostname, l2tp->params.hostname_len);
  *avp_len_return = SSH_L2TP_AVP_HDRLEN + l2tp->params.hostname_len;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Host Name: %.*s",
                               (int) l2tp->params.hostname_len,
                               l2tp->params.hostname));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(host_name)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(tunnel_attributes.host_name);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Host Name: %.*s",
             message->tunnel_attributes.host_name_len,
             message->tunnel_attributes.host_name));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(vendor_name)
{
  const char *vendor_name = "INSIDE Secure";
  size_t vendor_name_len = strlen(vendor_name);

  memcpy(SSH_L2TP_AVP_VALUE, vendor_name, vendor_name_len);
  *avp_len_return = SSH_L2TP_AVP_HDRLEN + vendor_name_len;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Vendor Name: %s", vendor_name));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(vendor_name)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(tunnel_attributes.vendor_name);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Vendor Name: %.*s",
             message->tunnel_attributes.vendor_name_len,
             message->tunnel_attributes.vendor_name));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(assigned_tunnel_id)
{
  SshUInt16 value;

  if (tunnel)
    {
      value = tunnel->info.local_id;
    }
  else if (l2tp->message && l2tp->message->tunnel_id)
    {
      /* Take if from the message header.  The remote peer did provide
         it for us. */
      value = l2tp->message->tunnel_id;
    }
  else
    {
      SshL2tpTunnelStruct tunnel_rec;

      /* Allocate a fresh tunnel ID.  This is the case if we are
         sending StopCCN without having real tunnel. */
      SSH_ASSERT(message_type == SSH_L2TP_CTRL_MSG_STOPCCN);

      ssh_l2tp_tunnel_id_alloc(l2tp, &tunnel_rec);

      value = tunnel_rec.info.local_id;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Assigned Tunnel ID %d", (int) value));

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, value);

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(assigned_tunnel_id)
{
  message->assigned_tunnel_id = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  if (message->assigned_tunnel_id == 0)
    {
      /* We could be nice here and not complain about zero Tunnel IDs
         for StopCCN messages.  This might be a valid case, for
         example, if the remote peer stops a new control connection
         establishment after seeing our first packet.  He might just
         send StopCCN and without allocating a tunnel and a tunnel ID.
         On the other hand, the RFC 2661 says that the value of the
         Assigned Tunnel ID AVP is a non-zero integer.  So, let's keep
         it this way... */
      SSH_DEBUG(SSH_D_NETGARB, ("Assigned Tunnel ID is zero"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "Assigned Tunnel ID is zero");
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Assigned Tunnel ID %d",
                               (int) message->assigned_tunnel_id));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(receive_window_size)
{
  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, l2tp->params.receive_window_size);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Receive Window Size %d",
                               (int) l2tp->params.receive_window_size));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(receive_window_size)
{
  message->receive_window_size = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  if (message->receive_window_size == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Receive Window Size is zero"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "Receive Window Size is zero");
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }
  if (message->receive_window_size > l2tp->params.max_send_window_size)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Limiting receive window size to configured maximum: "
                 "%d vs requested %d",
                 (int) l2tp->params.max_send_window_size,
                 message->receive_window_size));
      message->receive_window_size = l2tp->params.max_send_window_size;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Receive Window Size %d",
                               (int) message->receive_window_size));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(challenge)
{
  if (tunnel->shared_secret)
    {
      size_t i;

      ssh_free(tunnel->sent_challenge);

      tunnel->sent_challenge = ssh_malloc(l2tp->params.challenge_len);
      if (tunnel->sent_challenge == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for challenge"));
          return SSH_AVP_ENCODE_ERROR;
        }
      tunnel->sent_challenge_len = l2tp->params.challenge_len;

      for (i = 0; i < l2tp->params.challenge_len; i++)
        tunnel->sent_challenge[i] = (unsigned char) ssh_random_get_byte();

      memcpy(SSH_L2TP_AVP_VALUE, tunnel->sent_challenge,
             tunnel->sent_challenge_len);

      *avp_len_return = SSH_L2TP_AVP_HDRLEN + l2tp->params.challenge_len;

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Challenge:"),
                        tunnel->sent_challenge, tunnel->sent_challenge_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(challenge)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(challenge);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Challenge:"),
                    message->challenge, message->challenge_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(q931_cause_code)
{
  if (session == NULL || session->info.q931_cause_code == 0)
    return SSH_AVP_ENCODE_NOT_PRESENT;

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, session->info.q931_cause_code);
  SSH_PUT_8BIT(SSH_L2TP_AVP_VALUE + 2, session->info.q931_cause_msg);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Q.931 Cause Code %d %d",
             (int) session->info.q931_cause_code,
             (int) session->info.q931_cause_msg));

  if (session->info.q931_advisory_message)
    {
      memcpy(SSH_L2TP_AVP_VALUE + 3,
             session->info.q931_advisory_message,
             session->info.q931_advisory_message_len);
      *avp_len_return = 3 + session->info.q931_advisory_message_len;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Advisory Message: %.*s",
                 (int) session->info.q931_advisory_message_len,
                 session->info.q931_advisory_message));
    }
  else
    {
      *avp_len_return = 3;
    }

  *avp_len_return += SSH_L2TP_AVP_HDRLEN;

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(q931_cause_code)
{
  message->q931_cause_code = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);
  message->q931_cause_msg = SSH_GET_8BIT(SSH_L2TP_AVP_VALUE + 2);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Q.931 Cause Code %d %d",
             (int) message->q931_cause_code,
             (int) message->q931_cause_msg));

  if (avp_len > SSH_L2TP_AVP_HDRLEN + 3)
    {
      message->q931_advisory_message_len = avp_len - (SSH_L2TP_AVP_HDRLEN + 3);
      memcpy(message->q931_advisory_message_buf, SSH_L2TP_AVP_VALUE + 3,
             message->q931_advisory_message_len);

      message->q931_advisory_message
        = (unsigned char *) message->q931_advisory_message_buf;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Advisory Message: %.*s",
                 (int) message->q931_advisory_message_len,
                 message->q931_advisory_message));
    }

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(challenge_response)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];

  if (tunnel->received_challenge == NULL)
    return SSH_AVP_ENCODE_NOT_PRESENT;

  ssh_l2tp_tunnel_authentication_compute(l2tp,
                                         message_type,
                                         tunnel->received_challenge,
                                         tunnel->received_challenge_len,
                                         tunnel->shared_secret,
                                         tunnel->shared_secret_len,
                                         digest);

  SSH_ASSERT(l2tp->hash_digest_length == 16);
  memcpy(SSH_L2TP_AVP_VALUE, digest, l2tp->hash_digest_length);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Challenge Response:"),
                    digest, l2tp->hash_digest_length);

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(challenge_response)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(challenge_response);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Challenge Response:"),
                    message->challenge_response,
                    message->challenge_response_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(assigned_session_id)
{
  SshUInt16 value;

  if (session)
    value = session->info.local_id;
  else if (l2tp->message)
    value = l2tp->message->session_id;
  else
    value = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Assigned Session ID %d", (int) value));

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, value);

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(assigned_session_id)
{
  message->assigned_session_id = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  if (message->assigned_session_id == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Assigned Session ID is zero"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "Assigned Session ID is zero");
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Assigned Session ID %d",
                               (int) message->assigned_session_id));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(call_serial_number)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, l2tp->call_serial_number);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Call Serial Number %u",
             (unsigned int) l2tp->call_serial_number));

  l2tp->call_serial_number++;

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(call_serial_number)
{
  message->session_attributes.call_serial_number
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Call Serial Number %u",
             (unsigned int) message->session_attributes.call_serial_number));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(minimum_bps)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, session->info.attributes.minimum_bps);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Minimum BPS %u",
             (unsigned int) session->info.attributes.minimum_bps));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(minimum_bps)
{
  message->session_attributes.minimum_bps
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Minimum BPS %u",
             (unsigned int) message->session_attributes.minimum_bps));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(maximum_bps)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, session->info.attributes.maximum_bps);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Maximum BPS %u",
             (unsigned int) session->info.attributes.maximum_bps));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(maximum_bps)
{
  message->session_attributes.maximum_bps
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Maximum BPS %u",
             (unsigned int) message->session_attributes.maximum_bps));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(bearer_type)
{
  SshUInt32 value;

  if (message_type == SSH_L2TP_CTRL_MSG_ICRQ)
    {
      SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, session->info.attributes.bearer_type);
    }
  else
    {
      /* Set only those bits which were received from the LAC in
         Bearer Capabilities AVP. */
      value = (tunnel->info.attributes.bearer_capabilities
               & session->info.attributes.bearer_type);
      SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, value);
    }

#ifdef DEBUG_LIGHT
  value = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Bearer Type 0x%08x", (unsigned int) value));
#endif /* DEBUG_LIGHT */

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(bearer_type)
{
  message->session_attributes.bearer_type = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Bearer Type 0x%08x",
             (unsigned int) message->session_attributes.bearer_type));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(framing_type)
{
  SshUInt32 value;

  if (message_type == SSH_L2TP_CTRL_MSG_OCRQ)
    {
      /* Set only those bits which were received from the LAC in
         Framing Capabilities AVP. */
      value = (tunnel->info.attributes.framing_capabilities
               & session->info.attributes.framing_type);
      SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, value);
    }
  else
    {
      SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, session->info.attributes.framing_type);
    }

#ifdef DEBUG_LIGHT
  value = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Framing Type 0x%08x", (unsigned int) value));
#endif /* DEBUG_LIGHT */

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(framing_type)
{
  message->session_attributes.framing_type = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Framing Type 0x%08x",
             (unsigned int) message->session_attributes.framing_type));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(unspecified20)
{
  SSH_NOTREACHED;
  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(unspecified20)
{
  SSH_DEBUG(SSH_D_NETGARB, ("Received Unspecified AVP 20"));

  return SSH_AVP_DECODE_ERROR_PROTOCOL;
}

SSH_L2TP_AVP_ENCODER(called_number)
{
  if (session->info.attributes.called_number)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.called_number,
             session->info.attributes.called_number_len);
      *avp_len_return = (SSH_L2TP_AVP_HDRLEN
                         + session->info.attributes.called_number_len);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Called Number %.*s",
                 session->info.attributes.called_number_len,
                 session->info.attributes.called_number));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(called_number)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.called_number);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Called Number %.*s",
             message->session_attributes.called_number_len,
             message->session_attributes.called_number));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(calling_number)
{
  if (session->info.attributes.calling_number)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.calling_number,
             session->info.attributes.calling_number_len);
      *avp_len_return = (SSH_L2TP_AVP_HDRLEN
                         + session->info.attributes.calling_number_len);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Calling Number %.*s",
                 session->info.attributes.calling_number_len,
                 session->info.attributes.calling_number));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(calling_number)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.calling_number);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Calling Number %.*s",
             message->session_attributes.calling_number_len,
             message->session_attributes.calling_number));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(sub_address)
{
  if (session->info.attributes.sub_address)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.sub_address,
             session->info.attributes.sub_address_len);
      *avp_len_return = (SSH_L2TP_AVP_HDRLEN
                         + session->info.attributes.sub_address_len);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Sub-Address %.*s",
                 session->info.attributes.sub_address_len,
                 session->info.attributes.sub_address));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(sub_address)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.sub_address);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Sub-Address %.*s",
             message->session_attributes.sub_address_len,
             message->session_attributes.sub_address));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(connect_speed)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE, session->info.attributes.tx_connect_speed);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("(Tx) Connect Speed %u",
             (unsigned int) session->info.attributes.tx_connect_speed));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(connect_speed)
{
  message->session_attributes.tx_connect_speed
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("(Tx) Connect Speed %u",
             (unsigned int) message->session_attributes.tx_connect_speed));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(physical_channel_id)
{
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE,
                session->info.attributes.physical_channel_id);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Physical Channel ID %u",
             (unsigned int) session->info.attributes.physical_channel_id));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(physical_channel_id)
{
  message->session_attributes.physical_channel_id
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Physical Channel ID %u",
             (unsigned int) message->session_attributes.physical_channel_id));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(initial_rcvd_lcp_confreq)
{
  if (session->info.attributes.initial_rcvd_lcp_confreq)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.initial_rcvd_lcp_confreq,
             session->info.attributes.initial_rcvd_lcp_confreq_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.initial_rcvd_lcp_confreq_len);

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Initial Received LCP CONFREQ:"),
                        session->info.attributes.initial_rcvd_lcp_confreq,
                        session->info.attributes.initial_rcvd_lcp_confreq_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(initial_rcvd_lcp_confreq)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.initial_rcvd_lcp_confreq);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Initial Received LCP CONFREQ:"),
                    message->session_attributes.initial_rcvd_lcp_confreq,
                    message->session_attributes.initial_rcvd_lcp_confreq_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(last_sent_lcp_confreq)
{
  if (session->info.attributes.last_sent_lcp_confreq)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.last_sent_lcp_confreq,
             session->info.attributes.last_sent_lcp_confreq_len);
      *avp_len_return = (SSH_L2TP_AVP_HDRLEN
                         + session->info.attributes.last_sent_lcp_confreq_len);

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Last Sent LCP CONFREQ:"),
                        session->info.attributes.last_sent_lcp_confreq,
                        session->info.attributes.last_sent_lcp_confreq_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(last_sent_lcp_confreq)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.last_sent_lcp_confreq);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Last Sent LCP CONFREQ:"),
                    message->session_attributes.last_sent_lcp_confreq,
                    message->session_attributes.last_sent_lcp_confreq_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(last_rcvd_lcp_confreq)
{
  if (session->info.attributes.last_rcvd_lcp_confreq)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.last_rcvd_lcp_confreq,
             session->info.attributes.last_rcvd_lcp_confreq_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.last_rcvd_lcp_confreq_len);

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Last Received LCP CONFREQ:"),
                        session->info.attributes.last_rcvd_lcp_confreq,
                        session->info.attributes.last_rcvd_lcp_confreq_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(last_rcvd_lcp_confreq)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.last_rcvd_lcp_confreq);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Last Received LCP CONFREQ:"),
                    message->session_attributes.last_rcvd_lcp_confreq,
                    message->session_attributes.last_rcvd_lcp_confreq_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(proxy_authen_type)
{
  if (session->info.attributes.proxy_authen_type)
    {
      SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE,
                    session->info.attributes.proxy_authen_type);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Proxy Authen Type `%s' (%d)",
                 ssh_find_keyword_name(
                                ssh_l2tp_proxy_authen_types,
                                session->info.attributes.proxy_authen_type),
                 session->info.attributes.proxy_authen_type));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(proxy_authen_type)
{
  message->session_attributes.proxy_authen_type
    = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  if (message->session_attributes.proxy_authen_type == 0
      || (message->session_attributes.proxy_authen_type
          >= SSH_L2TP_PROXY_AUTHEN_NUM_TYPES))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Unknown Proxy Authen Type %d",
                 message->session_attributes.proxy_authen_type));




      ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                   sizeof(l2tp->error_message_buf),
                   "Unknown Proxy Authen Type %d",
                   message->session_attributes.proxy_authen_type);
      SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE);

      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Proxy Authen Type `%s' (%d)",
             ssh_find_keyword_name(
                        ssh_l2tp_proxy_authen_types,
                        message->session_attributes.proxy_authen_type),
             message->session_attributes.proxy_authen_type));

  return SSH_AVP_DECODE_OK;

}

SSH_L2TP_AVP_ENCODER(proxy_authen_name)
{
  if (session->info.attributes.proxy_authen_name)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.proxy_authen_name,
             session->info.attributes.proxy_authen_name_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.proxy_authen_name_len);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Proxy Authen Name %.*s",
                 session->info.attributes.proxy_authen_name_len,
                 session->info.attributes.proxy_authen_name));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(proxy_authen_name)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.proxy_authen_name);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Proxy Authen Name %.*s",
             message->session_attributes.proxy_authen_name_len,
             message->session_attributes.proxy_authen_name));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(proxy_authen_challenge)
{
  if (session->info.attributes.proxy_authen_challenge)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.proxy_authen_challenge,
             session->info.attributes.proxy_authen_challenge_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.proxy_authen_challenge_len);

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Proxy Authen Challenge:"),
                        session->info.attributes.proxy_authen_challenge,
                        session->info.attributes.proxy_authen_challenge_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(proxy_authen_challenge)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.proxy_authen_challenge);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Proxy Authen Challenge:"),
                    message->session_attributes.proxy_authen_challenge,
                    message->session_attributes.proxy_authen_challenge_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(proxy_authen_id)
{
  /* Add it only if we are doing proxy authentication. */
  if (session->info.attributes.proxy_authen_type)
    {
      SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE,
                    session->info.attributes.proxy_authen_id);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Proxy Authen ID %u",
                 (unsigned int) session->info.attributes.proxy_authen_id));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(proxy_authen_id)
{
  message->session_attributes.proxy_authen_id
    = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Proxy Authen ID %u",
             (unsigned int) message->session_attributes.proxy_authen_id));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(proxy_authen_response)
{
  if (session->info.attributes.proxy_authen_response)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.proxy_authen_response,
             session->info.attributes.proxy_authen_response_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.proxy_authen_response_len);

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Proxy Authen Response:"),
                        session->info.attributes.proxy_authen_response,
                        session->info.attributes.proxy_authen_response_len);

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(proxy_authen_response)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.proxy_authen_response);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("Proxy Authen Response:"),
                    message->session_attributes.proxy_authen_response,
                    message->session_attributes.proxy_authen_response_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(call_errors)
{
  SshL2tpCallErrors ce = l2tp->call_errors;

  if (ce == NULL)
    return SSH_AVP_ENCODE_NOT_PRESENT;

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, 0);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 2,  ce->crc_errors);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 6,  ce->framing_errors);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 10, ce->hardware_overruns);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 14, ce->buffer_overruns);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 18, ce->time_out_errors);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 22, ce->alignment_errors);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Call Errors: crc=%d, framing=%d, hardware_overruns=%d, "
             "buffer_overruns=%d, time_out=%d, alignment=%d",
             (int) ce->crc_errors,
             (int) ce->framing_errors,
             (int) ce->hardware_overruns,
             (int) ce->buffer_overruns,
             (int) ce->time_out_errors,
             (int) ce->alignment_errors));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(call_errors)
{
  SshUInt16 value = SSH_GET_16BIT(SSH_L2TP_AVP_VALUE);
  SshL2tpCallErrors ce = &message->call_errors;

  if (value != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Reserved is not 0"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "WEN Reserved was not 0");
      return SSH_AVP_DECODE_ERROR_PROTOCOL;
    }

  ce->crc_errors        = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 2);
  ce->framing_errors    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 6);
  ce->hardware_overruns = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 10);
  ce->buffer_overruns   = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 14);
  ce->time_out_errors   = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 18);
  ce->alignment_errors  = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 22);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Call Errors: crc=%d, framing=%d, hardware_overruns=%d, "
             "buffer_overruns=%d, time_out=%d, alignment=%d",
             (int) ce->crc_errors,
             (int) ce->framing_errors,
             (int) ce->hardware_overruns,
             (int) ce->buffer_overruns,
             (int) ce->time_out_errors,
             (int) ce->alignment_errors));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(accm)
{
  if (l2tp->accm == NULL)
    return SSH_AVP_ENCODE_NOT_PRESENT;

  SSH_PUT_16BIT(SSH_L2TP_AVP_VALUE, 0);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 2, l2tp->accm->send_accm);
  SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE + 6, l2tp->accm->receive_accm);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ACCM: send_accm=0x%08lx, receive_accm=0x%08lx",
             (unsigned long) l2tp->accm->send_accm,
             (unsigned long) l2tp->accm->receive_accm));

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(accm)
{
  /* RFC 2661 does not say anything about the value of the reserved 2
     octect quantity. */

  message->accm.send_accm       = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 2);
  message->accm.receive_accm    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE + 6);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ACCM: send_accm=0x%08lx, receive_accm=0x%08lx",
             (unsigned long) message->accm.send_accm,
             (unsigned long) message->accm.receive_accm));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(random_vector)
{
  size_t i;

  /* Create a fresh random vector. */
  for (i = 0; i < l2tp->params.random_vector_len; i++)
    l2tp->random_vector[i] = (unsigned char) ssh_random_get_byte();

  l2tp->random_vector_set = 1;

  memcpy(SSH_L2TP_AVP_VALUE, l2tp->random_vector,
         l2tp->params.random_vector_len);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Random Vector:"),
                    l2tp->random_vector, l2tp->params.random_vector_len);

  *avp_len_return = SSH_L2TP_AVP_HDRLEN + l2tp->params.random_vector_len;

  return SSH_AVP_ENCODE_OK;
}

SSH_L2TP_AVP_DECODER(random_vector)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(random_vector);

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Random Vector:"),
                    message->random_vector, message->random_vector_len);

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(private_group_id)
{
  if (session->info.attributes.private_group_id)
    {
      memcpy(SSH_L2TP_AVP_VALUE,
             session->info.attributes.private_group_id,
             session->info.attributes.private_group_id_len);
      *avp_len_return
        = (SSH_L2TP_AVP_HDRLEN
           + session->info.attributes.private_group_id_len);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Private Group ID %.*s",
                 session->info.attributes.private_group_id_len,
                 session->info.attributes.private_group_id));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(private_group_id)
{
  SSH_L2TP_AVP_DECODE_DYNAMIC(session_attributes.private_group_id);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Private Group ID %.*s",
             message->session_attributes.private_group_id_len,
             message->session_attributes.private_group_id));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(rx_connect_speed)
{
  if (session->info.attributes.rx_connect_speed)
    {
      SSH_PUT_32BIT(SSH_L2TP_AVP_VALUE,
                    session->info.attributes.rx_connect_speed);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Rx Connect Speed %u",
                 (unsigned int) session->info.attributes.rx_connect_speed));

      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(rx_connect_speed)
{
  message->session_attributes.rx_connect_speed
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Rx Connect Speed %u",
             (unsigned int) message->session_attributes.rx_connect_speed));

  return SSH_AVP_DECODE_OK;
}

SSH_L2TP_AVP_ENCODER(sequencing_required)
{
  if (session->info.attributes.sequencing_required)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Sequencing Required"));
      return SSH_AVP_ENCODE_OK;
    }

  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(sequencing_required)
{
  message->session_attributes.sequencing_required = TRUE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Sequencing Required"));

  return SSH_AVP_DECODE_OK;
}


/************************* SSH defined private AVPs *************************/

SSH_L2TP_AVP_ENCODER(ssh_transform_index)
{
  return SSH_AVP_ENCODE_NOT_PRESENT;
}

SSH_L2TP_AVP_DECODER(ssh_transform_index)
{
  message->tunnel_attributes.ssh_transform_index
    = SSH_GET_32BIT(SSH_L2TP_AVP_VALUE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("SSH Transform Index 0x%x",
             (unsigned int) message->tunnel_attributes.ssh_transform_index));

  return SSH_AVP_DECODE_OK;
}


/****************** AVP Encoding and Decoding definitions *******************/

typedef enum
{
  SSH_L2TP_1,
  SSH_L2TP_X,
  SSH_L2TP_0
} SshL2tpAvpBitValue;

#define SSH_L2TP_AVP_MIN        SSH_L2TP_AVP_HDRLEN
#define SSH_L2TP_AVP_MAX        1023

struct SshL2tpAvpPropertiesRec
{
  SshAvpEncoder encoder;
  SshAvpDecoder decoder;

  SshL2tpAvpBitValue mandatory;
  SshL2tpAvpBitValue hidden;
  SshUInt32 min_len;
  SshUInt32 max_len;
};

typedef struct SshL2tpAvpPropertiesRec SshL2tpAvpPropertiesStruct;
typedef struct SshL2tpAvpPropertiesRec *SshL2tpAvpProperties;
typedef const struct SshL2tpAvpPropertiesRec *SshL2tpAvpPropertiesConst;

static const SshL2tpAvpPropertiesStruct ietf_avp_table[
                                                SSH_L2TP_AVP_NUM_TYPES] =
{
  SSH_L2TP_AVP(message_type,    SSH_L2TP_X, SSH_L2TP_0, 8, 8)
  SSH_L2TP_AVP(result_code,     SSH_L2TP_1, SSH_L2TP_0, 8, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(protocol_version,        SSH_L2TP_1, SSH_L2TP_0, 8, 8)
  SSH_L2TP_AVP(framing_capabilities,    SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(bearer_capabilities,     SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(tie_breaker,             SSH_L2TP_0, SSH_L2TP_0, 14, 14)
  SSH_L2TP_AVP(firmware_revision,       SSH_L2TP_0, SSH_L2TP_X, 8, 8)

  SSH_L2TP_AVP(host_name,       SSH_L2TP_1, SSH_L2TP_0, 7, SSH_L2TP_AVP_MAX)

  /* Note: by RFC 2661, Vendor name may be empty whereas hostname MUST
     have at least one octet. */
  SSH_L2TP_AVP(vendor_name,     SSH_L2TP_0, SSH_L2TP_X, 6, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(assigned_tunnel_id,      SSH_L2TP_1, SSH_L2TP_X, 8, 8)
  SSH_L2TP_AVP(receive_window_size,     SSH_L2TP_1, SSH_L2TP_0, 8, 8)
  SSH_L2TP_AVP(challenge,       SSH_L2TP_1, SSH_L2TP_X, 7, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(q931_cause_code, SSH_L2TP_1, SSH_L2TP_0, 9, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(challenge_response,      SSH_L2TP_1, SSH_L2TP_X, 22, 22)
  SSH_L2TP_AVP(assigned_session_id,     SSH_L2TP_1, SSH_L2TP_X, 8, 8)
  SSH_L2TP_AVP(call_serial_number,      SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(minimum_bps,             SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(maximum_bps,             SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(bearer_type,             SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(framing_type,            SSH_L2TP_1, SSH_L2TP_X, 10, 10)

  SSH_L2TP_AVP(unspecified20,
               SSH_L2TP_X, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(called_number,
               SSH_L2TP_1, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(calling_number,
               SSH_L2TP_1, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(sub_address,
               SSH_L2TP_1, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(connect_speed,           SSH_L2TP_1, SSH_L2TP_X, 10, 10)
  SSH_L2TP_AVP(physical_channel_id,     SSH_L2TP_0, SSH_L2TP_X, 10, 10)

  SSH_L2TP_AVP(initial_rcvd_lcp_confreq,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(last_sent_lcp_confreq,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(last_rcvd_lcp_confreq,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(proxy_authen_type,       SSH_L2TP_0, SSH_L2TP_X, 8, 8)

  SSH_L2TP_AVP(proxy_authen_name,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)
  SSH_L2TP_AVP(proxy_authen_challenge,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(proxy_authen_id,         SSH_L2TP_0, SSH_L2TP_X, 8, 8)

  SSH_L2TP_AVP(proxy_authen_response,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(call_errors,             SSH_L2TP_1, SSH_L2TP_X, 32, 32)
  SSH_L2TP_AVP(accm,                    SSH_L2TP_1, SSH_L2TP_X, 16, 16)

  SSH_L2TP_AVP(random_vector,
               SSH_L2TP_1, SSH_L2TP_0, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(private_group_id,
               SSH_L2TP_0, SSH_L2TP_X, SSH_L2TP_AVP_MIN, SSH_L2TP_AVP_MAX)

  SSH_L2TP_AVP(rx_connect_speed,        SSH_L2TP_0, SSH_L2TP_X, 10, 10)

  SSH_L2TP_AVP(sequencing_required,     SSH_L2TP_1, SSH_L2TP_0, 6, 6)
};

static const SshL2tpAvpPropertiesStruct ssh_avp_table[
                                                SSH_L2TP_SSH_AVP_NUM_TYPES] =
{
  SSH_L2TP_AVP(ssh_transform_index,     SSH_L2TP_0, SSH_L2TP_0, 10, 10)
};

/* Known AVP Vendor IDs. */

struct SshL2tpKnownVendorIdRec
{
  SshUInt16 vendor_id;
  SshUInt16 num_attributes;
  SshL2tpAvpPropertiesConst avp_properties;
};

typedef struct SshL2tpKnownVendorIdRec SshL2tpKnownVendorIdStruct;
typedef struct SshL2tpKnownVendorIdRec *SshL2tpKnownVendorId;
typedef const struct SshL2tpKnownVendorIdRec *SshL2tpKnownVendorIdConst;

static const SshL2tpKnownVendorIdStruct known_vendor_ids[] =
{
  {0,                           SSH_L2TP_AVP_NUM_TYPES,        ietf_avp_table},
  {SSH_PRIVATE_ENTERPRISE_CODE, SSH_L2TP_SSH_AVP_NUM_TYPES,    ssh_avp_table},
};

static const size_t num_known_vendor_ids = (sizeof(known_vendor_ids)
                                            / sizeof(known_vendor_ids[0]));


/**************** Message encoding and decoding definitions *****************/

/* Mandatory and optional AVPs for different control messages.  The
   array sizes are tuned so that the maximum array just fits in
   them. */
struct SshL2tpMessageAvps
{
  SshL2tpAvpType mandatory[9];
  SshL2tpAvpType optional[12];
};

typedef struct SshL2tpMessageAvps SshL2tpMessageAvpsStruct;
typedef struct SshL2tpMessageAvps *SshL2tpMessageAvps;

static const SshL2tpMessageAvpsStruct message_table[
                                        SSH_L2TP_CTRL_MSG_NUM_MESSAGES] =
{
  /* Reserved */
  {{SSH_L2TP_AVP_END}, {SSH_L2TP_AVP_END}},

  /* SCCRQ */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_PROTOCOL_VERSION,
    SSH_L2TP_AVP_HOST_NAME,
    SSH_L2TP_AVP_FRAMING_CAPABILITIES,
    SSH_L2TP_AVP_ASSIGNED_TUNNEL_ID,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_BEARER_CAPABILITIES,
    SSH_L2TP_AVP_RECEIVE_WINDOW_SIZE,
    SSH_L2TP_AVP_CHALLENGE,
    SSH_L2TP_AVP_TIE_BREAKER,
    SSH_L2TP_AVP_FIRMWARE_REVISION,
    SSH_L2TP_AVP_VENDOR_NAME,
    SSH_L2TP_AVP_END}},

  /* SCCRP */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_PROTOCOL_VERSION,
    SSH_L2TP_AVP_FRAMING_CAPABILITIES,
    SSH_L2TP_AVP_HOST_NAME,
    SSH_L2TP_AVP_ASSIGNED_TUNNEL_ID,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_BEARER_CAPABILITIES,
    SSH_L2TP_AVP_FIRMWARE_REVISION,
    SSH_L2TP_AVP_VENDOR_NAME,
    SSH_L2TP_AVP_RECEIVE_WINDOW_SIZE,
    SSH_L2TP_AVP_CHALLENGE,
    SSH_L2TP_AVP_CHALLENGE_RESPONSE,
    SSH_L2TP_AVP_END}},

  /* SCCCN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_CHALLENGE_RESPONSE,
    SSH_L2TP_AVP_END}},

  /* StopCCN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ASSIGNED_TUNNEL_ID,
    SSH_L2TP_AVP_RESULT_CODE,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_END}},

  /* Reserved */
  {{SSH_L2TP_AVP_END}, {SSH_L2TP_AVP_END}},

  /* HELLO */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_END}},

  /* OCRQ */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ASSIGNED_SESSION_ID,
    SSH_L2TP_AVP_CALL_SERIAL_NUMBER,
    SSH_L2TP_AVP_MINIMUM_BPS,
    SSH_L2TP_AVP_MAXIMUM_BPS,
    SSH_L2TP_AVP_BEARER_TYPE,
    SSH_L2TP_AVP_FRAMING_TYPE,
    SSH_L2TP_AVP_CALLED_NUMBER,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_SUB_ADDRESS,
    SSH_L2TP_AVP_END}},

  /* OCRP */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ASSIGNED_SESSION_ID,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_PHYSICAL_CHANNEL_ID,
    SSH_L2TP_AVP_END}},

  /* OCCN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_CONNECT_SPEED,
    SSH_L2TP_AVP_FRAMING_TYPE,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_RX_CONNECT_SPEED,
    SSH_L2TP_AVP_SEQUENCING_REQUIRED,
    SSH_L2TP_AVP_END}},

  /* ICRQ */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ASSIGNED_SESSION_ID,
    SSH_L2TP_AVP_CALL_SERIAL_NUMBER,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_BEARER_TYPE,
    SSH_L2TP_AVP_PHYSICAL_CHANNEL_ID,
    SSH_L2TP_AVP_CALLING_NUMBER,
    SSH_L2TP_AVP_CALLED_NUMBER,
    SSH_L2TP_AVP_SUB_ADDRESS,
    SSH_L2TP_AVP_END}},

  /* ICRP */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ASSIGNED_SESSION_ID,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_END}},

  /* ICCN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_CONNECT_SPEED,
    SSH_L2TP_AVP_FRAMING_TYPE,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_INITIAL_RECEIVED_LCP_CONFREQ,
    SSH_L2TP_AVP_LAST_SENT_LCP_CONFREQ,
    SSH_L2TP_AVP_LAST_RESEIVED_LCP_CONFREQ,
    SSH_L2TP_AVP_PROXY_AUTHEN_TYPE,
    SSH_L2TP_AVP_PROXY_AUTHEN_NAME,
    SSH_L2TP_AVP_PROXY_AUTHEN_CHALLENGE,
    SSH_L2TP_AVP_PROXY_AUTHEN_ID,
    SSH_L2TP_AVP_PROXY_AUTHEN_RESPONSE,
    SSH_L2TP_AVP_PRIVATE_GROUP_ID,
    SSH_L2TP_AVP_RX_CONNECT_SPEED,
    SSH_L2TP_AVP_SEQUENCING_REQUIRED,
    SSH_L2TP_AVP_END}},

  /* Reserved */
  {{SSH_L2TP_AVP_END}, {SSH_L2TP_AVP_END}},

  /* CDN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_RESULT_CODE,
    SSH_L2TP_AVP_ASSIGNED_SESSION_ID,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_Q931_CAUSE_CODE,
    SSH_L2TP_AVP_END}},

  /* WEN */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_CALL_ERRORS,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_END}},

  /* SLI */
  {{SSH_L2TP_AVP_MESSAGE_TYPE,
    SSH_L2TP_AVP_ACCM,
    SSH_L2TP_AVP_END},

   {SSH_L2TP_AVP_END}},
};

/********************** Hiding of AVP Attribute Values **********************/

/* Hide the `len' bytes of AVP in `cp' using the AVP hiding algorithm.
   The hiding operation uses the HASH algorithm `hash' (MD5).  The
   argument `hide' specifies whether we are hiding or unhiding the
   value.  The type of the AVP to hide is in `type_number'.  It must
   point to 2 bytes of network byte-order data.  The arguments
   `secret' and `secret_len' specify the shared secret between LAC and
   LNS.  The arguments `random_vector' and `random_vector_len' specify
   the random vector to use. */
static void
do_hide(SshL2tp l2tp, Boolean hide, const unsigned char *type_number,
        const unsigned char *secret, size_t secret_len,
        const unsigned char *random_vector, size_t random_vector_len,
        unsigned char *cp, size_t len)
{
  size_t i;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t digest_length = l2tp->hash_digest_length;

  /* Count the initial digest. */
  ssh_hash_reset(l2tp->hash);
  ssh_hash_update(l2tp->hash, type_number, 2);
  ssh_hash_update(l2tp->hash, secret, secret_len);
  ssh_hash_update(l2tp->hash, random_vector, random_vector_len);

  /* Hide the data. */
  while (1)
    {
      ssh_hash_final(l2tp->hash, digest);

      if (!hide && len > digest_length)
        {
          /* Unhiding.  Create the next digest. */
          ssh_hash_reset(l2tp->hash);
          ssh_hash_update(l2tp->hash, secret, secret_len);
          ssh_hash_update(l2tp->hash, cp, digest_length);
        }

      for (i = 0; i < digest_length && len > 0; i++)
        {
          *cp = *cp ^ digest[i];
          cp++;
          len--;
        }
      if (len <= 0)
        /* All done. */
        break;

      if (hide)
        {
          /* Hiding.  Create the next digest. */
          ssh_hash_reset(l2tp->hash);
          ssh_hash_update(l2tp->hash, secret, secret_len);
          ssh_hash_update(l2tp->hash, cp - digest_length, digest_length);
        }
    }
}

/* Hides the AVP `avp' of length `avp_len' using the AVP hiding
   algorithm.  The field `hash' of the argument `l2tp' specifies the
   hash algorithm to use (MD5).  The arguments `secret' and
   `secret_len' specify the shared secret between LAC and LNS.  The
   arguments `random_vector' and `random_vector_len' specify the
   latest random vector value. The hiding adds `padding_len' bytes of
   padding for the AVP value before the hiding operation.  The hidden
   value is returned in `hidden_avp' that must have `2 + avp_len +
   padding_len' bytes space for the hidden value. */
static void
ssh_l2tp_hide(SshL2tp l2tp,
              const unsigned char *secret, size_t secret_len,
              const unsigned char *random_vector, size_t random_vector_len,
              size_t padding_len,
              const unsigned char *avp, size_t avp_len,
              unsigned char *hidden_avp)
{
  size_t i;
  SshUInt16 value;

  /* Prepare the hidden AVP. */

  /* Copy AVP header. */
  memcpy(hidden_avp, avp, SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE);

  /* Set the Hidden bit. */

  value = SSH_L2TP_AVP_BITS(avp);
  SSH_ASSERT((value & SSH_L2TP_AVP_F_HIDDEN) == 0);
  value |= SSH_L2TP_AVP_F_HIDDEN;

  SSH_L2TP_AVP_SET_BITS(hidden_avp, value);

  /* Store original length of the unhidden AVP value. */

  value = SSH_L2TP_AVP_LENGTH(avp);
  value -= SSH_L2TP_AVP_HDRLEN;

  SSH_PUT_16BIT(hidden_avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE, value);

  /* Copy the original AVP value. */
  memcpy(hidden_avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE + 2,
         avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE, value);

  /* Add padding. */
  for (i = 0; i < padding_len; i++)
    hidden_avp[SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE + 2 + value + i]
      = (unsigned char) ssh_random_get_byte();

  /* Store the new length to the header of the hidden AVP. */
  value += SSH_L2TP_AVP_HDRLEN + 2 + padding_len;

  SSH_L2TP_AVP_SET_LENGTH(hidden_avp, value);

  /* Hide the value field. */
  do_hide(l2tp, TRUE, hidden_avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_TYPE,
          secret, secret_len, random_vector, random_vector_len,
          hidden_avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE,
          value - SSH_L2TP_AVP_HDRLEN);
}

/* Unhides the hidden AVP `avp' of length `*avp_len' using the AVP
   unhiding algorithm.  The field `hash' of the argument `l2tp'
   specifies the hash algorithm to use (MD5).  The arguments `secret'
   and `secret_len' sepcify the shared secret between LAC and LNS.
   The arguments `random_vector' and `random_vector_len' specify the
   latest random vector value.  The AVP is modified in place so after
   the operation, the buffer `avp' contains the unhidden value.  The
   length of the unhidden AVP is returned in `*avp_len'.  The function
   returns FALSE if the unhiding operation fails and TRUE otherwise.
   If the operation failed, the AVP `avp' might be modified. */
static Boolean
ssh_l2tp_unhide(SshL2tp l2tp,
                const unsigned char *secret, size_t secret_len,
                const unsigned char *random_vector, size_t random_vector_len,
                unsigned char *avp, size_t *avp_len)
{
  SshUInt16 value;

  /* Unhide the attribute value. */
  do_hide(l2tp, FALSE, avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_TYPE,
          secret, secret_len, random_vector, random_vector_len,
          avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE,
          *avp_len - SSH_L2TP_AVP_HDRLEN);

  /* Fetch the length of the original value. */
  value = SSH_GET_16BIT(avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE);
  if (value > *avp_len - 2)
    {
      /* The length in the hidden value is too big. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("The length of the hidden value is too big: "
                 "len=%d, avp_len=%d", (int) value, *avp_len));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_LENGTH_IS_WRONG,
                         "The length of a hidden AVP is too big: "
                         "Maybe the LAC-LNS shared secret is wrong");
      return FALSE;
    }

  /* Update the length in the AVP header. */
  SSH_L2TP_AVP_SET_LENGTH(avp, value + SSH_L2TP_AVP_HDRLEN);

  /* Return the length to the caller. */
  *avp_len = value + SSH_L2TP_AVP_HDRLEN;

  /* Remove the original length from the attribute value. */
  memmove(avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE,
          avp + SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE + 2, value);

  /* Clear the Hidden bit from the AVP header. */
  value = SSH_L2TP_AVP_BITS(avp);
  SSH_ASSERT(value & SSH_L2TP_AVP_F_HIDDEN);
  value &= ~SSH_L2TP_AVP_F_HIDDEN;
  SSH_L2TP_AVP_SET_BITS(avp, value);

  return TRUE;
}

/*************************** Parsing L2TP packets ***************************/

/* Debug print the message `message'.  If the message is a data
   message, the arguments `data', `data_len' give the payload data. */
static void
print_message(SshL2tpControlMessage message, const unsigned char *data,
              size_t data_len)
{
  char bitstring[10];
  int i = 0;

  if (message->f_type)
    bitstring[i++] = 'T';
  if (message->f_length)
    bitstring[i++] = 'L';
  if (message->f_sequence)
    bitstring[i++] = 'S';
  if (message->f_offset)
    bitstring[i++] = 'O';
  if (message->f_priority)
    bitstring[i++] = 'P';
  bitstring[i] = '\0';

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("%s Message: bits=%s, version=%d, tunnel_id=%d"
             ", session_id=%d, ns=%d, nr=%d",
             message->f_type ? "Control" : "Data",
             bitstring,
             (int) message->version,
             (int) message->tunnel_id,
             (int) message->session_id,
             (int) message->ns,
             (int) message->nr));

  if (data)
    SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Payload data:"), data, data_len);
}

/* Set the bit `num' to bitmap `bitmap'. */
#define SSH_L2TP_BM_SET_BIT(bitmap, num)                \
do                                                      \
  {                                                     \
    int index = (num) / (sizeof((bitmap)[0]) * 8);      \
    int pos = (num) - (index * sizeof((bitmap)[0]));    \
                                                        \
    (bitmap)[index] |= ((unsigned long) 1 << pos);      \
  }                                                     \
while (0)

/* Check if the bit `num' is set in bitmap `bitmap'.  The result is
   returned in `result'. */
#define SSH_L2TP_BM_IS_SET(bitmap, num, result)         \
do                                                      \
  {                                                     \
    int index = (num) / (sizeof((bitmap)[0]) * 8);      \
    int pos = (num) - (index * sizeof((bitmap)[0]));    \
                                                        \
    if ((bitmap)[index] & ((unsigned long) 1 << pos))   \
      (result) = TRUE;                                  \
    else                                                \
      (result) = FALSE;                                 \
  }                                                     \
while (0)

Boolean
ssh_l2tp_decode_packet(SshL2tp l2tp, SshL2tpControlMessage message,
                       SshL2tpTunnel tunnel,
                       unsigned char *packet, size_t packet_len,
                       const unsigned char *remote_addr,
                       const unsigned char *remote_port,
                       size_t *data_offset_return, size_t *data_len_return)
{
  SshUInt32 value;
  size_t parse_pos;
  size_t message_length = packet_len;
  SshUInt32 bitmap[SSH_L2TP_AVP_NUM_TYPES / (sizeof(SshUInt32) * 8) + 1] = {0};
  SshL2tpTunnelStruct tunnel_struct;
  SshADTHandle h;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Incoming packet:"), packet, packet_len);

  if (packet_len < SSH_L2TPH_MIN_HDRLEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet too short to contain L2TP header: %d vs %d",
                 packet_len, SSH_L2TPH_MIN_HDRLEN));
      return FALSE;
    }

  if (!ssh_ipaddr_parse(&message->remote_addr, remote_addr))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not parse remote end's IP address `%s': "
                              "packet discarded",
                              remote_addr));
      return FALSE;
    }
  message->remote_port = ssh_uatoi(remote_port);

  /* Header bits. */

  value = SSH_L2TPH_BITS(packet);

  if (value & SSH_L2TPH_F_TYPE)
    message->f_type = 1;
  if (value & SSH_L2TPH_F_LENGTH)
    message->f_length = 1;
  if (value & SSH_L2TPH_F_SEQUENCE)
    message->f_sequence = 1;
  if (value & SSH_L2TPH_F_OFFSET)
    message->f_offset = 1;
  if (value & SSH_L2TPH_F_PRIORITY)
    message->f_priority = 1;

#if SSH_L2TP_PEDANTIC
  if ((value & SSH_L2TPH_F_RESERVED) != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Some of the reserved bits are set: 0x%lx",
                                value));




      ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                   sizeof(l2tp->error_message_buf),
                   "Some of the header's reserved bits are set: 0x%lx",
                   value);
      SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE);
    }
#endif /* SSH_L2TP_PEDANTIC */

  message->version = SSH_L2TPH_VERSION(packet);
  if (message->version != SSH_L2TP_DATA_MESSAGE_HEADER_VERSION)
    {
      if (message->version == 1)
        {
          /* This is an L2F packet.  We must silently discard this. */
#if SSH_L2TP_PEDANTIC
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Discarding L2F packet"));
#endif /* SSH_L2TP_PEDANTIC */
          return FALSE;
        }
      SSH_DEBUG(SSH_D_NETFAULT,
                ("Unknown header version number %d: packet discarded",
                 message->version));
      return FALSE;
    }

  /* Parse rest of the header. */
  parse_pos = 2;

  if (message->f_length)
    {
      message_length = SSH_GET_16BIT(packet + parse_pos);
      parse_pos += 2;

      /* Sanity check for the length. */
      if (message_length > packet_len)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Length exceeds physical length: %d vs %d",
                     message_length, packet_len));




          ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                       sizeof(l2tp->error_message_buf),
                       "Length exceeds physical length: %d vs %d",
                       message_length, packet_len);
          SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                 SSH_L2TP_ERROR_LENGTH_IS_WRONG);
          message_length = packet_len;
        }
    }
  else
    {
      if (message->f_type)
        {
          /* Length must be set for control messages. */
          SSH_DEBUG(SSH_D_NETGARB, ("Length bit not set"));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE,
                             "Length bit is not set");
        }
    }

  if (parse_pos + 4 > packet_len)
    goto truncated_packet;

  message->tunnel_id = SSH_GET_16BIT(packet + parse_pos);
  parse_pos += 2;

  message->session_id = SSH_GET_16BIT(packet + parse_pos);
  parse_pos += 2;

  if (message->f_sequence)
    {
      if (parse_pos + 4 > packet_len)
        goto truncated_packet;

      message->ns = SSH_GET_16BIT(packet + parse_pos);
      parse_pos += 2;

      message->nr = SSH_GET_16BIT(packet + parse_pos);
      parse_pos += 2;
    }
  else
    {
      if (message->f_type)
        {
          /* Sequence numbers must be set for control messages. */
          SSH_DEBUG(SSH_D_NETGARB, ("Sequence bit not set"));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE,
                             "Sequence bit is not set");
        }
    }

  if (message->f_offset)
    {
      size_t length;

      if (message->f_type)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Offset bit set"));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE,
                             "Offset bit is set");
        }

      if (parse_pos + 2 > packet_len)
        goto truncated_packet;

      length = SSH_GET_16BIT(packet + parse_pos);
      parse_pos += 2;

      if (parse_pos + length > packet_len)
        goto truncated_packet;

      parse_pos += length;
    }

  /* Was this a data message? */
  if (message->f_type == 0)
    {
      *data_offset_return = parse_pos;
      *data_len_return = message_length - parse_pos;

      print_message(message,
                    packet + *data_offset_return,
                    *data_len_return);

      return TRUE;
    }

  /* The priority bit must be 0 for control messages. */
  if (message->f_priority)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Priority bit set"));
      SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                         SSH_L2TP_ERROR_INVALID_VALUE,
                         "Priority bit is set");
    }

  /* Parse AVPs. */
  while (parse_pos < packet_len)
    {
      Boolean mandatory = FALSE;
      Boolean hidden = FALSE;
      Boolean reserved_set = FALSE;
      size_t length;
      size_t avp_length;
      SshUInt16 vendor_id;
      SshL2tpAvpType avp_type;
      SshL2tpAvpPropertiesConst avp_prop;
      SshL2tpAvpDecodeResult decode_result;
      SshL2tpKnownVendorIdConst vendor = NULL;
      size_t vendor_index;

      if (parse_pos + SSH_L2TP_AVP_HDRLEN > packet_len)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Garbage at the end of packet: tail too short to contain "
                     "AVP header"));
          goto truncated_packet;
        }

      /* Parse AVP header. */

      value = SSH_L2TP_AVP_BITS(packet + parse_pos);
      if (value & SSH_L2TP_AVP_F_MANDATORY)
        mandatory = TRUE;
      if (value & SSH_L2TP_AVP_F_HIDDEN)
        hidden = TRUE;
      if (value & SSH_L2TP_AVP_F_RESERVED)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Some of the reserved bits are set: 0x%lx",
                     (value & SSH_L2TP_AVP_F_RESERVED)));
          /* The error is reported later. */
          reserved_set = TRUE;
        }

      length = SSH_L2TP_AVP_LENGTH(packet + parse_pos);
      if (parse_pos + length > packet_len)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Packet too short for the last AVP"));
          goto truncated_packet;
        }

      vendor_id = SSH_L2TP_AVP_VENDOR_ID(packet + parse_pos);
      avp_type = SSH_L2TP_AVP_ATTRIBUTE_TYPE(packet + parse_pos);

      /* Check if we know the vendor. */
      for (vendor_index = 0;
           vendor_index < num_known_vendor_ids;
           vendor_index++)
        if (known_vendor_ids[vendor_index].vendor_id == vendor_id)
          {
            vendor = &known_vendor_ids[vendor_index];
            break;
          }

      if (vendor == NULL
          || avp_type >= vendor->num_attributes
          || reserved_set)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("Unrecognized AVP: "
                     "vendor_id=%d, attribute_type=%d, reserved_set=%d, "
                     "mandatory=%d",
                     vendor_id, avp_type, reserved_set, mandatory));

          if (mandatory)
            {
              /* Tear down the session or tunnel.  We just format the
                 error code here.  The message dispatcher takes care
                 of destroying tunnel when it finds an error from
                 `l2tp'. */
              if (vendor_id || avp_type >= SSH_L2TP_AVP_NUM_TYPES)
                {
                  l2tp->error_code = SSH_L2TP_ERROR_UNKNOWN_MANDATORY_AVP;



                  ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                               sizeof(l2tp->error_message_buf),
                               "Vendor ID %d AVP Type %d",
                               vendor_id, avp_type);
                }
              else
                {
                  l2tp->error_code = SSH_L2TP_ERROR_INVALID_VALUE;



                  ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                               sizeof(l2tp->error_message_buf),
                               "Some of the reserved bits are set: 0x%lx",
                               (value & SSH_L2TP_AVP_F_RESERVED));
                }
              l2tp->error_message = l2tp->error_message_buf;
              l2tp->error_message_len =
                ssh_ustrlen(l2tp->error_message_buf);
            }

          /* And finally, skip this AVP. */
          goto next_avp;
        }

      /* Fetch AVP properties into a local variable. */
      avp_prop = &vendor->avp_properties[avp_type];

      /* Mark this AVP seen. */
      SSH_L2TP_BM_SET_BIT(bitmap, avp_type);

      /* Check some things from the AVP registry. */
      if ((avp_prop->mandatory == SSH_L2TP_1 && !mandatory)
          || (avp_prop->mandatory == SSH_L2TP_0 && mandatory))
        {
          char *vendor_name;
          size_t vendor_name_len;

          /* The status of the mandatory bit does not match RFC. */

          if (tunnel == NULL)
            {
              /* We do not know the tunnel yet.  Let's try to lookup
                 the tunnel now. */
              if (message->tunnel_id)
                {
                  /* We know the tunnel. */
                  tunnel_struct.info.local_id = message->tunnel_id;
                  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id,
                                                  &tunnel_struct);
                  if (h != SSH_ADT_INVALID)
                    tunnel = ssh_adt_get(l2tp->tunnels_id, h);
                }
            }
          if (tunnel && tunnel->info.attributes.vendor_name)
            {
              vendor_name = (char *) tunnel->info.attributes.vendor_name;
              vendor_name_len = tunnel->info.attributes.vendor_name_len;
            }
          else if (message->tunnel_attributes.vendor_name)
            {
              vendor_name = (char *) message->tunnel_attributes.vendor_name;
              vendor_name_len = message->tunnel_attributes.vendor_name_len;
            }
          else
            {
              vendor_name = "Unknown";
              vendor_name_len = 7;
            }

          SSH_DEBUG(SSH_D_NETGARB, ("Mandatory bit does not match RFC 2661"));
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                        "Remote L2TP implementation (Vendor Name `%.*s') is "
                        "not standard-compliant: "
                        "the Mandatory bit (%s) of the AVP `%s' (%d) "
                        "does not match RFC 2661",
                        (int) vendor_name_len, vendor_name,
                        mandatory ? "Set" : "Unset",
                        ssh_find_keyword_name(ssh_l2tp_avp_types, avp_type),
                        avp_type);
        }
      if ((avp_prop->hidden == SSH_L2TP_1 && !hidden)
          || (avp_prop->hidden == SSH_L2TP_0 && hidden))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Hidden bit does not mach RFC 2661"));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INVALID_VALUE,
                             "State of Hidden bit does not match RFC 2661");
        }

      /* As a default, the real length of the AVP is the physical
         length.  However, this can change if the AVP is hidden. */
      avp_length = length;

      /* Handle hidden fields. */
      if (hidden)
        {
          if (tunnel == NULL)
            {
              /* We haven't resolved the tunnel yet.  We cache the
                 resolved tunnel to the `tunnel' local variable so we
                 do not have to do the hash lookups for each hidden
                 AVP. */

              /* We must lookup the corresponding tunnel to get our
                 shared secret for this LAC-LNS pair.  We have the
                 tunnel if the message's tunnel ID is set.  We might
                 also have the tunnel if this is a retransmit for
                 initiator's first packet.  Otherwise, this must be
                 the initial initiator's first packet and we must
                 suspend the message parsing until we have called our
                 user callback to retrieve the secret. */
              if (message->tunnel_id)
                {
                  /* We know the tunnel. */
                  tunnel_struct.info.local_id = message->tunnel_id;
                  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id,
                                                  &tunnel_struct);
                  if (h == SSH_ADT_INVALID)
                    {
                      SSH_DEBUG(SSH_D_NETGARB,
                                ("Received a message with hidden AVP for "
                                 "unknown Tunnel ID %d",
                                 message->tunnel_id));

                      /* Just move to the next AVP.  The message
                         dispatching will send an appropriate error
                         message. */
                      goto next_avp;
                    }

                  /* Found it. */
                  tunnel = ssh_adt_get(l2tp->tunnels_id, h);
                }
              else if (message->assigned_tunnel_id)
                {
                  /* Check if this is a retransmission.  We know the
                     remote address, port, and its assigned ID. */

                  tunnel_struct.remote_addr = message->remote_addr;
                  tunnel_struct.remote_port = message->remote_port;
                  tunnel_struct.info.remote_id = message->assigned_tunnel_id;

                  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_addr_port_id,
                                                  &tunnel_struct);
                  if (h != SSH_ADT_INVALID)
                    /* Found it. */
                    tunnel = ssh_adt_get(l2tp->tunnels_addr_port_id, h);
                }
            }

          /* Did we find the tunnel? */
          if (tunnel)
            {
              /* Yes we did.  Now we are almost ready to unhide this
                 attribute. */

              /* Do we have a random vector? */
              if (message->random_vector == NULL)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("Random vector did not precede hidden AVP"));
                  SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                     SSH_L2TP_ERROR_INVALID_VALUE,
                                     "Random vector did not precede "
                                     "hidden AVP");

                  /* Move to the next AVP. */
                  goto next_avp;
                }
              else
                {
                  /* Now, just unhide the attribute value. */
                  if (!ssh_l2tp_unhide(l2tp, tunnel->shared_secret,
                                       tunnel->shared_secret_len,
                                       message->random_vector,
                                       message->random_vector_len,
                                       packet + parse_pos, &avp_length))
                    {
                      /* The unhiding failed.  The function did set an
                         appropriate error message so we will send
                         error to our peer in the message
                         dispatching.  Now, just skip this AVP. */
                      goto next_avp;
                    }
                }
              /* Now the AVP is in clear-text. */
            }
          else
            {
              /* We did not find the tunnel.  This is the initiator's
                 first packet.  We must suspend the message parsing
                 and call user to return the shared secret for us. */
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Suspending packet decoding because the initiator's "
                         "first packet contains hidden AVPs"));

              message->suspended_packet = ssh_memdup(packet, packet_len);
              if (message->suspended_packet == NULL)
                {
                  SSH_DEBUG(SSH_D_ERROR, ("Out of memory"));
                  SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                     SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                                     "Out of memory");

                  /* We dispatch the message so we get correct error
                     code to our peer. */
                }
              else
                {
                  message->suspended_packet_len = packet_len;
                }

              /* Just return successfully.  We will re-enter to this
                 packet decoding when we have created a new tunnel and
                 received the shared secret from our user. */
              return TRUE;
            }
        }

      /* And check some more things. */
      if (avp_length < avp_prop->min_len)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Truncated AVP: %zd vs %d",
                                    avp_length, (int) avp_prop->min_len));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_LENGTH_IS_WRONG,
                             "Truncated AVP");
          goto truncated_packet;
        }
      else if (avp_length > avp_prop->max_len)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Too long AVP: %zd vs %d",
                                    avp_length, (int) avp_prop->max_len));
          SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_LENGTH_IS_WRONG,
                             "Too long AVP");
        }
      else
        {
          /* Parse AVP. */
          decode_result = (*avp_prop->decoder)(l2tp,
                                               packet + parse_pos, avp_length,
                                               message->avp_count,
                                               mandatory, message);

          switch (decode_result)
            {
            case SSH_AVP_DECODE_OK:
              /* Nothing here. */
              break;

            case SSH_AVP_DECODE_SKIP_MESSAGE:
              /* Let's just skip this message. */
              return FALSE;
              break;

            case SSH_AVP_DECODE_ERROR:
            case SSH_AVP_DECODE_ERROR_PROTOCOL:
            case SSH_AVP_DECODE_ERROR_MEMORY:
              /* Error in AVP decoding.  The decoder has already set
                 the error code and description. */
              break;
            }
        }

      /* Move to the next AVP. */
    next_avp:
      message->avp_count++;
      parse_pos += length;
    }

  print_message(message, NULL, 0);

  /* Check that all required AVPs were present.  We can resolve it
     from the control connection message type.  But only if we have
     not seen any errors yet.  One error is that we have received an
     invalid message type. */
  if (l2tp->result_code == 0)
    {
      int i;
      SshL2tpMessageAvps avps;

      SSH_ASSERT(message->type < SSH_L2TP_CTRL_MSG_NUM_MESSAGES);

      avps = (SshL2tpMessageAvps) &message_table[message->type];
      for (i = 0; avps->mandatory[i] != SSH_L2TP_AVP_END; i++)
        {
          Boolean is_set;

          SSH_L2TP_BM_IS_SET(bitmap, avps->mandatory[i], is_set);

          if (!is_set)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Mandatory AVP `%s' (%d) is not set for control "
                         "message `%s' (%d)",
                         ssh_find_keyword_name(ssh_l2tp_avp_types,
                                               avps->mandatory[i]),
                         avps->mandatory[i],
                         ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                               message->type),
                         message->type));



              ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                           sizeof(l2tp->error_message_buf),
                           "Mandatory AVP %d is not set for control "
                           "message %d",
                           avps->mandatory[i], message->type);
              SSH_L2TP_SET_ERROR_FMT(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                     SSH_L2TP_ERROR_INVALID_VALUE);

              break;
            }
        }
    }


  /* All done. */
  return TRUE;


  /* Error handling. */

 truncated_packet:

  SSH_DEBUG(SSH_D_NETGARB, ("Truncated packet"));
  SSH_L2TP_SET_ERROR(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                     SSH_L2TP_ERROR_LENGTH_IS_WRONG,
                     "The message was truncated");

  return TRUE;
}


static Boolean
encode_avp(SshL2tp l2tp, SshL2tpTunnel tunnel, SshL2tpSession session,
           SshL2tpControlMsgType message_type, SshL2tpAvpType avp_type,
           unsigned char *avp, size_t avp_len, size_t *bytes_consumed)
{
  SshL2tpAvpEncodeResult encode_result;
  SshUInt16 value;
  SshL2tpAvpProperties avp_prop;
  Boolean hidden = FALSE;

  SSH_ASSERT(avp_type < SSH_L2TP_AVP_NUM_TYPES);

  avp_prop = (SshL2tpAvpProperties) &ietf_avp_table[avp_type];

  SSH_ASSERT(avp_prop->encoder != NULL);
  SSH_ASSERT(avp_prop->decoder != NULL);
  SSH_ASSERT(avp_len >= avp_prop->max_len);

  /* Encode AVP header. */

  value = 0;
  if (avp_prop->mandatory != SSH_L2TP_0)
    value |= SSH_L2TP_AVP_F_MANDATORY;

  SSH_L2TP_AVP_SET_BITS(avp, value);

  /* Length is set when we know it. */

  SSH_L2TP_AVP_SET_VENDOR_ID(avp, 0);
  SSH_L2TP_AVP_SET_ATTRIBUTE_TYPE(avp, avp_type);

  /* Encode AVP value */
  if (avp_prop->min_len == avp_prop->max_len)
    *bytes_consumed = avp_prop->min_len;
  else
    *bytes_consumed = 0;

  /* Will this AVP be hidden? */
  if (avp_prop->hidden != SSH_L2TP_0 && !l2tp->params.dont_hide
      && tunnel && tunnel->shared_secret && !tunnel->dont_hide)
    hidden = TRUE;

  encode_result = (*avp_prop->encoder)(l2tp, tunnel, session, message_type,
                                       hidden, avp, bytes_consumed);
  switch (encode_result)
    {
    case SSH_AVP_ENCODE_OK:
      /* Nothing here. */
      SSH_ASSERT(*bytes_consumed >= avp_prop->min_len);
      SSH_ASSERT(*bytes_consumed <= avp_prop->max_len);
      break;

    case SSH_AVP_ENCODE_NOT_PRESENT:
      *bytes_consumed = 0;
      return TRUE;
      break;

    case SSH_AVP_ENCODE_ERROR:
      return FALSE;
      break;
    }

  /* Set length. */
  SSH_L2TP_AVP_SET_LENGTH(avp, *bytes_consumed);

  /* Now we have a valid AVP.  Hide it if needed. */
  if (hidden)
    {
      size_t tmp_avp_len;

      /* Save the current AVP to `l2tp's temporary buffer. */
      memcpy(l2tp->avp_buf, avp, *bytes_consumed);
      tmp_avp_len = *bytes_consumed;

      /* Add random vector if needed. */
      if (!l2tp->random_vector_set || l2tp->params.separate_random_vectors)
        {
          /* Encode random vector.  This sets the random vector's
             length to `bytes_consumed'. */
          (void) encode_avp(l2tp, tunnel, session, message_type,
                            SSH_L2TP_AVP_RANDOM_VECTOR,
                            avp, avp_len, bytes_consumed);

          SSH_ASSERT(l2tp->random_vector_set);
        }
      else
        {
          /* No we don't.  We haven't consumed any bytes from the
             original AVP buffer. */
          *bytes_consumed = 0;
        }

      /* Hide the value.  The component `+ 0' is the padding
         length. */
      SSH_ASSERT(avp_len >= *bytes_consumed + 2 + tmp_avp_len + 0);

      ssh_l2tp_hide(l2tp,
                    tunnel->shared_secret, tunnel->shared_secret_len,
                    l2tp->random_vector, l2tp->params.random_vector_len,
                    0,  /* padding length */
                    l2tp->avp_buf, tmp_avp_len,
                    avp + *bytes_consumed);

      /* And we consumed some more data. */
      *bytes_consumed += 2 + tmp_avp_len + 0;
    }

  return TRUE;
}


Boolean
ssh_l2tp_encode_packet(SshL2tp l2tp, SshL2tpTunnel tunnel,
                       SshL2tpSession session,
                       unsigned char *datagram, size_t datagram_len,
                       size_t *datagram_len_return,
                       SshL2tpControlMsgType message_type)
{
  unsigned char *cp = datagram;
  size_t len = datagram_len;
  SshUInt32 value;
  size_t bytes_consumed;

  /* Clear old encoding information from `l2tp'. */
  l2tp->random_vector_set = 0;

  /* Create control message header. */

  SSH_ASSERT(datagram_len >= SSH_L2TPH_CTRL_HDRLEN);

  SSH_L2TPH_SET_VERSION_AND_BITS(
          cp,
          SSH_L2TP_DATA_MESSAGE_HEADER_VERSION,
          (SSH_L2TPH_F_TYPE | SSH_L2TPH_F_LENGTH | SSH_L2TPH_F_SEQUENCE));

  if (tunnel)
    value = tunnel->info.remote_id;
  else if (l2tp->message)
    value = l2tp->message->assigned_tunnel_id;
  else
    value = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID %lu", (unsigned long) value));

  SSH_PUT_16BIT(cp + 4, value);

  if (session)
    value = session->info.remote_id;
  else if (l2tp->message)
    value = l2tp->message->assigned_session_id;
  else
    value = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Session ID %lu", (unsigned long) value));

  SSH_PUT_16BIT(cp + 6, value);

  /* Ns and Nr are set by the transport level. */

  cp += SSH_L2TPH_CTRL_HDRLEN;

  /* Encode AVPs.  The Zero-Length Body (ZLB) messages does not have
     any AVPs. */
  if (message_type != SSH_L2TP_CTRL_MSG_ZLB)
    {
      int i;
      SshL2tpMessageAvps avps;

      SSH_ASSERT(message_type < SSH_L2TP_CTRL_MSG_NUM_MESSAGES);

      avps = (SshL2tpMessageAvps) &message_table[message_type];

      /* Mandatory AVPs. */
      for (i = 0; avps->mandatory[i] != SSH_L2TP_AVP_END; i++)
        if (!encode_avp(l2tp, tunnel, session, message_type,
                        avps->mandatory[i],
                        cp, len, &bytes_consumed))
          {
            return FALSE;
          }
        else
          {
            cp += bytes_consumed;
            len -= bytes_consumed;
          }

      /* Optional AVPs. */
      for (i = 0; avps->optional[i] != SSH_L2TP_AVP_END; i++)
        if (!encode_avp(l2tp, tunnel, session, message_type,
                        avps->optional[i],
                        cp, len, &bytes_consumed))
          {
            return FALSE;
          }
        else
          {
            cp += bytes_consumed;
            len -= bytes_consumed;
          }
    }

  /* Return the length of the final datagram. */
  *datagram_len_return = cp - datagram;

  /* And store it to the packet header. */
  SSH_PUT_16BIT(datagram + 2, *datagram_len_return);

  /* All done. */
  return TRUE;
}
