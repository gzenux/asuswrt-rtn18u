/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "ansi_x962.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"
#include "ssheap_sim.h"

#define SSH_DEBUG_MODULE "SshEapSim"

#ifdef SSHDIST_EAP_SIM
static SshUInt8
ssh_eap_sim_decode_start(SshEapProtocol protocol,
                         SshBuffer buf)
{
  SshUInt8  id_cnt      = 0;
  SshUInt8  vers_ok     = 0;
  SshUInt16 count       = 0;
  SshUInt16 offset      = 8;
  SshUInt16 version     = 0;
  SshUInt16 act_ver_len = 0;
  size_t    attr_len    = 0;
  SshEapSimState state  = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  state = ssh_eap_protocol_get_state(protocol);

  state->start_msg_cnt++;

  if (state->start_msg_cnt > SSH_EAP_SIM_MAX_START_MESSAGES)
    return SSH_EAP_SIM_ERR_INVALID_STATE;

  if (state->start_msg_cnt > 1 &&
      (state->sim_proto_flags & SSH_EAP_SIM_PERMID_RCVD ||
       (!(state->sim_proto_flags & SSH_EAP_SIM_FULLID_RCVD) ||
        !(state->sim_proto_flags & SSH_EAP_SIM_ANYID_RCVD))))
    return SSH_EAP_SIM_ERR_INVALID_STATE;

  while (offset < ssh_buffer_len(buf) && SSH_EAP_AT_LEN(buf, offset))
    {
      attr_len = SSH_EAP_AT_LEN(buf, offset);

      if (attr_len > SSH_EAP_SIM_PKT_AT_LEN_MAX)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("EAP SIM packet attribute too large: %u bytes, max %u",
                     (unsigned int) attr_len,
                     SSH_EAP_SIM_PKT_AT_LEN_MAX));
          return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;
        }

      switch (ssh_buffer_ptr(buf)[offset])
        {
        case SSH_EAP_AT_VERSION_LIST:
          /* just check that the server request's for protocol
             version 1. We do not support anything else at the
             moment. */
          if (vers_ok)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          if ((offset + attr_len) > ssh_buffer_len(buf))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Corrupted EAP SIM packet"));
              return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;
            }

          act_ver_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + offset + 2);

          if ((act_ver_len == 0) ||
              (((act_ver_len * 2) + 4) != attr_len))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Corrupted EAP SIM packet"));
              return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;
            }

          SSH_ASSERT(act_ver_len != 0);
          SSH_ASSERT(act_ver_len <= ((SSH_EAP_SIM_PKT_AT_LEN_MAX - 4) / 2));

          for (count = 0; count < act_ver_len; count++)
            {
              version = SSH_GET_16BIT(ssh_buffer_ptr(buf) +
                                      offset + 4 +
                                      (count * 2));

              if (version == SSH_EAP_SIM_VERSION_1)
                  vers_ok = 1;
            }

          /* We may have multiple of these request, so free the old
             reference. */
          if (state->version_list)
            {
              ssh_buffer_free(state->version_list);
              state->version_list = NULL;
            }

          state->version_list = ssh_buffer_allocate();
          if (!state->version_list)
            return SSH_EAP_SIM_ERR_MEMALLOC_FAILED;

          if (ssh_buffer_append(state->version_list,
                                &ssh_buffer_ptr(buf)[offset + 4],
                                act_ver_len) != SSH_BUFFER_OK)
            {
              ssh_buffer_free(state->version_list);
              state->version_list = NULL;

              return SSH_EAP_SIM_ERR_MEMALLOC_FAILED;
            }
          state->version_list_len = (SshUInt8)act_ver_len;

          offset += attr_len;
          break;

        case SSH_EAP_AT_ANY_ID_REQ:

          if (state->sim_proto_flags & SSH_EAP_SIM_ANYID_RCVD ||
              state->sim_proto_flags & SSH_EAP_SIM_PERMID_RCVD ||
              state->sim_proto_flags & SSH_EAP_SIM_FULLID_RCVD ||
              state->start_msg_cnt > 1)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          offset += attr_len;
          id_cnt++;
          break;

        case SSH_EAP_AT_FULLAUTH_ID_REQ:

          if (state->sim_proto_flags & SSH_EAP_SIM_PERMID_RCVD)
            return SSH_EAP_SIM_ERR_INVALID_STATE;

          state->sim_proto_flags |= SSH_EAP_SIM_FULLID_RCVD;

          offset += attr_len;
          id_cnt++;
          break;

        case SSH_EAP_AT_PERMANENT_ID_REQ:

          if (state->sim_proto_flags & SSH_EAP_SIM_PERMID_RCVD)
            return SSH_EAP_SIM_ERR_INVALID_STATE;

          state->sim_proto_flags |= SSH_EAP_SIM_PERMID_RCVD;

          offset += attr_len;
          id_cnt++;
          break;

        default:
          SSH_DEBUG(SSH_D_FAIL, ("eap sim invalid ie detected (ie %x)",
                                 ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_SIM_ERR_INVALID_IE;
        }
    }

  state->sim_proto_flags |= SSH_EAP_SIM_ANYID_RCVD;

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;

  if (id_cnt == 1 && vers_ok == 1)
    {
      state->sim_proto_flags |= SSH_EAP_SIM_START_INC_ID;
      return SSH_EAP_SIM_DEC_OK;
    }

  if (!id_cnt && vers_ok == 1)
    return SSH_EAP_SIM_DEC_OK;

  if (!vers_ok)
    return SSH_EAP_SIM_ERR_INVALID_VERSION;

  return SSH_EAP_SIM_ERR_GENERAL;
}

static SshUInt8
ssh_eap_sim_decode_challenge(SshEapProtocol protocol,
                             SshBuffer buf, SshEapSimTriplet trip,
                             SshUInt8 *trip_cnt)
{
  SshUInt8  copied_cnt    = 0;
  SshUInt8  mac_found     = 0;
  SshUInt8  ativ_cnt      = 0;
  SshUInt8  encrdata_cnt  = 0;
  SshUInt8  rand_found    = 0;
  SshUInt8  resultind_cnt = 0;
  SshUInt16 offset        = 8;
  SshEapSimState state    = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(trip != NULL);
  SSH_ASSERT(trip_cnt != 0);

  state = ssh_eap_protocol_get_state(protocol);

  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    {
      switch(ssh_buffer_ptr(buf)[offset])
        {
        case SSH_EAP_AT_IV:

          ativ_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_ENCR_DATA:

          encrdata_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_RESULT_IND:

          /* We just log and set flag to the protocol flags
             that server has requested for protected success
             messaging. We do not support it at least in this
             version. */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim server indicated it want's"
                                       " to use protected success messages"));

          resultind_cnt++;

          state->sim_proto_flags |= SSH_EAP_SIM_PROT_SUCCESS;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_MAC:

          if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          offset += SSH_EAP_AT_LEN(buf, offset);
          mac_found++;
          break;

        case SSH_EAP_AT_RAND:

          rand_found++;

          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf))
            {
              return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;
            }

          /* The rand count is calculated from the length field.
             It is 1 + x * 4, where x is the amount of the rand's. */
          *trip_cnt = ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) - 1) / 4;

          if (*trip_cnt < 2 || *trip_cnt > 3)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          for (copied_cnt = 0; copied_cnt < *trip_cnt; copied_cnt++)
            {
              SshUInt8 *msgp = &ssh_buffer_ptr(buf)[offset + 4 +
                                (copied_cnt * SSH_EAP_SIM_RAND_LEN)];

              memcpy(trip[copied_cnt].rand, msgp, SSH_EAP_SIM_RAND_LEN);
            }

          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        default:

          SSH_DEBUG(SSH_D_FAIL, ("eap sim invalid ie detected (ie %x)",
                                  ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_SIM_ERR_INVALID_IE;
        }
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || resultind_cnt > 1)
    return SSH_EAP_SIM_ERR_INVALID_IE;

  if (mac_found == 1 && rand_found == 1)
    return SSH_EAP_SIM_DEC_OK;

  return SSH_EAP_SIM_ERR_GENERAL;
}

static SshUInt8
ssh_eap_sim_decode_notification(SshEapProtocol protocol,
                                SshBuffer buf,
                                SshUInt16 *notif_val)
{
  SshUInt8  mac_cnt       = 0;
  SshUInt8  ativ_cnt      = 0;
  SshUInt8  notif_cnt     = 0;
  SshUInt8  counter_cnt   = 0;
  SshUInt8  encrdata_cnt  = 0;
  SshUInt16 offset        = 8;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(notif_val != NULL);

  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    {
      switch(ssh_buffer_ptr(buf)[offset])
        {
        case SSH_EAP_AT_IV:

          ativ_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_ENCR_DATA:

          encrdata_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_MAC:

          mac_cnt++;
          if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_COUNTER:

          counter_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_NOTIFICATION:

          notif_cnt++;
          if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_SIM_ERR_INVALID_IE;

          *notif_val = SSH_GET_16BIT(ssh_buffer_ptr(buf) + offset + 2);
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        default:

          SSH_DEBUG(SSH_D_FAIL, ("eap sim invalid ie detected (%x)",
                                  ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_SIM_ERR_INVALID_IE;
        }
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_SIM_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || mac_cnt > 1 ||
      counter_cnt > 1 || notif_cnt > 1)
    return SSH_EAP_SIM_ERR_GENERAL;

  if (notif_cnt == 1)
    return SSH_EAP_SIM_DEC_OK;

  return SSH_EAP_SIM_ERR_GENERAL;
}

static void
ssh_eap_sim_send_client_error(SshEapProtocol protocol, SshEap eap,
                              SshUInt16 err_code)
{
  SshBuffer pkt     = NULL;
  SshUInt16 pkt_len = SSH_EAP_SIM_CLIENT_ERROR_BASE_LEN;
  SshUInt8  buf[7]  = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_CLIENT_ERROR;
  buf[1] = buf[2] = 0;

  buf[3] = SSH_EAP_AT_CLIENT_ERROR_CODE;
  buf[4] = 1;
  buf[5] = (err_code & 0xFF00) >> 8;
  buf[6] = (err_code & 0xFF);

  if (ssh_buffer_append(pkt, buf, 7) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

/* Handle all possible error cases here. In short, all errors are
   treated as fatal and always terminate authentication. */
static void
ssh_eap_sim_client_error(SshEapProtocol protocol, SshEap eap,
                         SshUInt8 error)
{
  SshEapSimState state = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim processing client error of type"
                               " %u", error));

  state = ssh_eap_protocol_get_state(protocol);
  state->sim_proto_flags |= SSH_EAP_SIM_STATE_FAILED;

  switch(error)
    {
      /* We shouldn't be entering here with these values. */
    case SSH_EAP_SIM_DEC_OK:

      SSH_ASSERT(0);
      break;

    case SSH_EAP_SIM_ERR_GENERAL:
    case SSH_EAP_SIM_ERR_INVALID_IE:
    case SSH_EAP_SIM_ERR_INVALID_STATE:
    case SSH_EAP_SIM_ERR_MEMALLOC_FAILED:
    case SSH_EAP_SIM_ERR_PACKET_CORRUPTED:

      ssh_eap_sim_send_client_error(protocol, eap, 0);
      break;

    case SSH_EAP_SIM_ERR_INVALID_VERSION:

      ssh_eap_sim_send_client_error(protocol, eap, 1);
      break;

      /* Don't wan't to get here either. */
    default:

      SSH_ASSERT(0);
      break;
    }

  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
}

static void
ssh_eap_sim_send_start_reply(SshEapProtocol protocol,
                             SshEap eap)
{
  SshEapSimState state   = NULL;
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_SIM_START_REPLY_BASE_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim sending start reply"));

  state = ssh_eap_protocol_get_state(protocol);

  if (state->sim_proto_flags & SSH_EAP_SIM_START_INC_ID)
    {
      /* The length of name is always multiple of 4 and
         4 bytes of attribute header. */
      if (state->user_len % 4)
        pkt_len += 4 + state->user_len + (4 - (state->user_len % 4));
      else
        pkt_len += 4 + state->user_len;
    }

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_SIM_START;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_append_nonce_attr(pkt, state->nonce))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_append_selected_version_attr(pkt,
                                                   state->selected_version))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (state->sim_proto_flags & SSH_EAP_SIM_START_INC_ID)
    {
      if (!ssh_eap_packet_append_identity_attr(pkt,
                                               ssh_buffer_ptr(state->user),
                                               state->user_len))
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
          return;
        }
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_sim_send_challenge_reply(SshEapProtocol protocol,
                                 SshEap eap)
{
  SshEapSimState state     = NULL;
  SshBuffer      pkt       = NULL;
  SshUInt8       buf[3]    = "";
  SshUInt8       sres_cnt  = 0;
  SshUInt16      pkt_len   = SSH_EAP_SIM_CHALLENGE_REPLY_BASE_LEN;
  unsigned char  mac_inp[3 * SSH_EAP_SIM_SRES_LEN] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim sending challenge reply"));

  state = ssh_eap_protocol_get_state(protocol);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_SIM_CHALLENGE;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!(ssh_eap_packet_append_empty_mac_attr(pkt)))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  for (sres_cnt = 0; sres_cnt < state->triplet_cnt; sres_cnt++)
    {
      memcpy(&mac_inp[sres_cnt * SSH_EAP_SIM_SRES_LEN],
             state->triplet[sres_cnt].sres, SSH_EAP_SIM_SRES_LEN);
    }

  if (ssh_eap_packet_calculate_hmac_sha(pkt, state->K_aut, mac_inp,
                                        state->triplet_cnt *
                                        SSH_EAP_SIM_SRES_LEN,
                                        FALSE) != SSH_EAP_MAC_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "eap sim could not calculate mac for"
                    " challenge response");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_sim_send_notification_reply(SshEapProtocol protocol,
                                    SshEap eap, SshUInt8 include_mac)
{
  SshEapSimState state     = NULL;
  SshBuffer      pkt       = NULL;
  SshUInt8       buf[3]    = "";
  SshUInt16      pkt_len   = SSH_EAP_SIM_NOTIF_REPLY_BASE_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim sending notification reply"));

  state = ssh_eap_protocol_get_state(protocol);

  if (include_mac)
    pkt_len += 20;

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_NOTIFICATION;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (include_mac)
    {
      if (!(ssh_eap_packet_append_empty_mac_attr(pkt)))
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
          return;
        }

      if (ssh_eap_packet_calculate_hmac_sha(pkt, state->K_aut,
                                            NULL, 0, FALSE) != SSH_EAP_MAC_OK)
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "eap sim could not calculate mac for"
                        " nofitication response");
          return;
        }
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_sim_client_recv_start(SshEapProtocol protocol,
                              SshEap eap,
                              SshBuffer buf)
{
  SshEapSimState state = NULL;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim processing start message"));

  state = ssh_eap_protocol_get_state(protocol);
  state->sim_proto_flags &= ~SSH_EAP_SIM_START_INC_ID;

  if (state->sim_proto_flags & SSH_EAP_SIM_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim start message"
                             " received when we are already entered state"
                             " for processing challenges");
      ssh_eap_sim_client_error(protocol, eap,
                               SSH_EAP_SIM_ERR_INVALID_STATE);
      return;
    }

  if ((rval = ssh_eap_sim_decode_start(protocol, buf)))
    {
      /* We encountered a problem and in certain cases we signal
         it back to the AAA server depending on the return value. */
      SSH_DEBUG(SSH_D_FAIL, ("eap sim start message decoding "
                             "failed, reason: %u", rval));

      ssh_eap_discard_packet(eap, protocol, buf, "eap sim"
                             " decoding error, authentication terminated");
      ssh_eap_sim_client_error(protocol, eap, rval);
      return;
    }

  state->sim_proto_flags |= SSH_EAP_SIM_START_RCVD;
  state->response_id      = ssh_eap_packet_get_identifier(buf);
  state->selected_version[1] = 0x01; /* Only version and hard coded. */

  /* Generate the nonce. */
  for (rval = 0; rval < SSH_EAP_SIM_NONCE_LEN; rval++)
    {
      state->nonce[rval] = ssh_random_get_byte();
    }

  ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                 SSH_EAP_TOKEN_USERNAME);
}

static void
ssh_eap_sim_client_recv_challenge(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshBuffer buf)
{
  SshEapSimState   state     = NULL;
  SshUInt8         rval      = 0;
  SshUInt8         rand_cnt  = 0;
  unsigned char    rands[48] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  SSH_DEBUG(SSH_D_NICETOKNOW,("eap sim, processing client"
                              " challenge request message."));

  /* Really invalid state. Server tries to send challenges without
     even starting the session. Terminate immediately. */
  if (!(state->sim_proto_flags & SSH_EAP_SIM_START_RCVD))
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim challenge"
                             " received altough start message has not"
                             " been received, authentication terminated");
      ssh_eap_sim_client_error(protocol, eap,
                               SSH_EAP_SIM_ERR_INVALID_STATE);
      return;
    }

  /* Freeradius 1.1.4 and below seem to be answering with new challenge
     message altough client-error message has been sent to it. This is
     totally against RFC 4186. */
  if (state->sim_proto_flags & SSH_EAP_SIM_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim multiple challenge"
                             " messages received");
      ssh_eap_sim_client_error(protocol, eap,
                               SSH_EAP_SIM_ERR_INVALID_STATE);
      return;
    }

  state->sim_proto_flags |= SSH_EAP_SIM_CHALLENGE_RCVD;

  /* Probably a retransmission of RAND challenge? Anyway
     discard it silently. Only done when we are actually
     processing the RAND's. If we receive this message when
     we are already setup, we'll send an error message... */
  if (state->sim_proto_flags & SSH_EAP_SIM_PROCESSING_RAND)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim"
                             " already waiting for SIM's response"
                             " for RAND challenge.");
      return;
    }

  rval = ssh_eap_sim_decode_challenge(protocol, buf, state->triplet,
                                      &state->triplet_cnt);
  if (rval != SSH_EAP_SIM_DEC_OK)
    {
      ssh_eap_sim_client_error(protocol, eap, rval);
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim"
                             " decoding error, authentication terminated");
      return;
    }

  /* Save the last received packet, since we will be needing it
     later on when we are verifying the MAC. The RFC 4186 states
     that MAC is only allowed to be verified after the RAND's
     have been succefully processed by SIM. */
  if (!(state->last_pkt = ssh_buffer_allocate()))
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  if (ssh_buffer_append(state->last_pkt, ssh_buffer_ptr(buf),
                        ssh_buffer_len(buf)) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      ssh_eap_discard_packet(eap, protocol, buf, "eap sim fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  state->sim_proto_flags |= SSH_EAP_SIM_PROCESSING_RAND;

  for (rand_cnt = 0; rand_cnt < state->triplet_cnt; rand_cnt++)
    {
      memcpy(&rands[rand_cnt * SSH_EAP_SIM_RAND_LEN],
             state->triplet[rand_cnt].rand, SSH_EAP_SIM_RAND_LEN);
    }

  ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                           SSH_EAP_TOKEN_SIM_CHALLENGE,
                                           rands, state->triplet_cnt * 16);
}

static void
ssh_eap_sim_client_recv_notification(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshEapSimState state = NULL;
  SshUInt16      ret   = 0;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("processing eap sim notification"));

  state = ssh_eap_protocol_get_state(protocol);

  if ((rval = ssh_eap_sim_decode_notification(protocol, buf, &ret)) !=
      SSH_EAP_SIM_DEC_OK)
    {
      ssh_eap_sim_client_error(protocol, eap, rval);
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim invalid packet");
      return;
    }

  /* Do we have to verify the MAC? */
  if (!(ret & 0x4000))
    {
      if (ssh_eap_packet_calculate_hmac_sha(buf, state->K_aut,
                                            NULL, 0, TRUE) != SSH_EAP_MAC_OK)
        {
          ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_INVALID_IE);
          ssh_eap_discard_packet(eap, protocol, buf, "eap sim server sent"
                                 " sim notify with invalid mac");
          return;
        }
    }

  if (ret & 0x8000)
    {
      /* Success message. Discard and send error. Shouldn't be
         getting these since we did not approve protected successes. */
      ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim server sent"
                             " sim success");
      return;
    }

  /* The next two if's are checking that the P bit is correctly set.
     If it isn't, log the error, but still send the client error in
     order to terminate the authentication. in these cases we don't
     send the notification reply since these are error cases. */
  if ((ret & 0x4000) &&
      state->sim_proto_flags & SSH_EAP_SIM_CHALLENGE_RCVD)
    {
      ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim server sent"
                             " sim nofitication with invalid phase bit");
      return;
    }

  if (!(ret & 0x4000) &&
      !(state->sim_proto_flags & SSH_EAP_SIM_CHALLENGE_RCVD))
    {
      ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_GENERAL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim server sent"
                             " sim nofitication with invalid phase bit");
      return;
    }

  ssh_eap_sim_send_notification_reply(protocol, eap, !(ret & 0x4000));

  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
}

static void
ssh_eap_sim_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapSimState state   = NULL;
  SshUInt16      msg_len = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP SIM state uninitialized");
      return;
    }

  /* Here we handle only EAP-SIM specific messages. some notifications
     and Identity requests etc... are handled in ssheap_common. */
  if (ssh_buffer_len(buf) < 6)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet too short to be eap sim request");
      return;
    }

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);
  if (msg_len != ssh_buffer_len(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP SIM msg length invalid");
      return;
    }

  switch (ssh_buffer_ptr(buf)[5])
    {
    case SSH_EAP_SIM_START:

      ssh_eap_sim_client_recv_start(protocol, eap, buf);
      break;

    case SSH_EAP_SIM_CHALLENGE:

      ssh_eap_sim_client_recv_challenge(protocol, eap, buf);
      break;

    case SSH_EAP_REAUTHENTICATION:
      /* The AAA server is really misbehaving. We really do
         not wan't these messages, because we always indicate we
         do not support fast reauthentication. Discard the message, send
         error and tear everything down. */
      ssh_eap_discard_packet(eap, protocol, buf, "eap sim reauthentication"
                             " requested by server, authentication"
                             " terminated");
      ssh_eap_sim_client_error(protocol, eap,
                               SSH_EAP_SIM_ERR_INVALID_STATE);
      break;

    case SSH_EAP_NOTIFICATION:

      ssh_eap_sim_client_recv_notification(protocol, eap, buf);
      break;

    default:

      /* By default if we see something we don't know,
         send client error and terminate the authentication. */
      ssh_eap_discard_packet(eap, protocol, buf,
                             "Invalid EAP SIM subtype");
      ssh_eap_sim_client_error(protocol, eap,
                               SSH_EAP_SIM_ERR_GENERAL);
      break;
    }
}

SshUInt8
ssh_eap_sim_calculate_keys(SshEapProtocol protocol, SshEap eap,
                           unsigned char *generated_keys)
{
  SshAnsiX962        x962         = NULL;
  SshEapSimState     state        = NULL;
  SshHash            hash         = NULL;
  SshUInt8           rands        = 0;
  unsigned char      mk[20]       = "";
  unsigned char      *key_buf     = generated_keys;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(generated_keys != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim calculating keys"));

  if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
    return 1;

  ssh_hash_reset(hash);

  /* Generate the MK. */
  ssh_hash_update(hash, ssh_buffer_ptr(state->user), state->user_len);

  for (rands = 0; rands < state->triplet_cnt; rands++)
    {
      ssh_hash_update(hash, state->triplet[rands].kc, SSH_EAP_SIM_KC_LEN);
    }

  ssh_hash_update(hash, state->nonce, SSH_EAP_SIM_NONCE_LEN);
  ssh_hash_update(hash, ssh_buffer_ptr(state->version_list),
                  state->version_list_len);
  ssh_hash_update(hash, (SshUInt8 *)&state->selected_version, 2);

  if (ssh_hash_final(hash, mk) != SSH_CRYPTO_OK)
    goto fail_hash;

  /* Generate the MSK, EMSK, K_aut and K_encr keys. */
  x962 = ssh_ansi_x962_init();

  if (x962 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail_hash;
    }

  if (ssh_ansi_x962_add_entropy(x962, mk, 20) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ansi-x9.62 entropy addition failed"));
      goto fail_hash;
    }

  if (ssh_ansi_x962_get_bytes(x962, key_buf, 160) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ansi-x9.62 operation failed"));
      goto fail_hash;
    }

  ssh_ansi_x962_uninit(x962);
  ssh_hash_free(hash);

  return 0;

 fail_hash:
  if (x962 != NULL)
    ssh_ansi_x962_uninit(x962);

  ssh_hash_free(hash);
  SSH_DEBUG(SSH_D_FAIL, ("Key generation failed"));

  return 1;
}

static void
ssh_eap_sim_recv_token_rand(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapSimState   state     = NULL;
  SshUInt8         rnd       = 0;
  unsigned char   *trip_p    = NULL;
  unsigned char    keys[160] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim received token rand "
                               "response from pm"));

  token = (SshEapToken)ssh_buffer_ptr(buf);

  if (!(state->sim_proto_flags & SSH_EAP_SIM_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim, received rand"
                                                 " response from pm "
                                                 "altough not requested"));
      return;
    }

  if ((token->token.buffer.len % 12) ||
      (token->token.buffer.len / 12) > 3 ||
      (token->token.buffer.len / 12) < 2 ||
      (token->token.buffer.len / 12) != state->triplet_cnt)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim, received invalid"
                                                 " length rand"
                                                 " response from pm "));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->sim_proto_flags &= ~SSH_EAP_SIM_PROCESSING_RAND;
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
      return;
    }

  trip_p = token->token.buffer.dptr;

  /* Copy the token values (SRES's and Kc's). */
  for (rnd = 0; rnd < state->triplet_cnt; rnd++)
    {
      memcpy(state->triplet[rnd].sres, &trip_p[rnd * 12],
             SSH_EAP_SIM_SRES_LEN);

      memcpy(state->triplet[rnd].kc, &trip_p[(rnd * 12) + 4],
             SSH_EAP_SIM_KC_LEN);
    }

  if (ssh_eap_sim_calculate_keys(protocol, eap, keys))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim, key generation"
                                                 " failed, dropping token"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      state->sim_proto_flags &= ~SSH_EAP_SIM_PROCESSING_RAND;
      ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_GENERAL);
      return;
    }

  if (ssh_eap_packet_calculate_hmac_sha(state->last_pkt, &keys[16],
                                        state->nonce, SSH_EAP_SIM_NONCE_LEN,
                                        TRUE) != SSH_EAP_MAC_OK)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim message mac "
                                                 "verification"
                                                 " failed, dropping token"));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      state->sim_proto_flags &= ~SSH_EAP_SIM_PROCESSING_RAND;
      ssh_eap_sim_client_error(protocol, eap, SSH_EAP_SIM_ERR_INVALID_IE);
      return;
    }

  /* Copy the keys, everything should be fine. */
  memcpy(state->K_encr, keys, SSH_EAP_SIM_KENCR_LEN);
  memcpy(state->K_aut, &keys[16], SSH_EAP_SIM_KAUT_LEN);
  memcpy(state->msk, &keys[32], SSH_EAP_SIM_MSK_LEN);
  memcpy(state->emsk, &keys[96], SSH_EAP_SIM_EMSK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("MSK"), state->msk, SSH_EAP_SIM_MSK_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->sim_proto_flags &= ~SSH_EAP_SIM_PROCESSING_RAND;

  eap->msk = ssh_memdup(state->msk, SSH_EAP_SIM_MSK_LEN);
  eap->msk_len = SSH_EAP_SIM_MSK_LEN;

  ssh_eap_sim_send_challenge_reply(protocol, eap);
  ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
}

static void
ssh_eap_sim_recv_token_username(SshEapProtocol protocol,
                                SshEap eap,
                                SshBuffer buf)
{
  SshEapToken    token   = NULL;
  SshEapSimState state;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  /* Wipe out the old stuff if required. */
  if (state->user)
    {
      ssh_buffer_free(state->user);
      state->user = NULL;
    }

  token = (SshEapToken)ssh_buffer_ptr(buf);

  if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim did not receive"
                                                 " valid username"));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
      return;
    }

  state->user = ssh_buffer_allocate();
  if (!state->user)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap sim buffer"
                                                 " allocation failed"));
      return;
    }

  if (ssh_buffer_append(state->user, token->token.buffer.dptr,
                        token->token.buffer.len) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->user);
      state->user = NULL;

      ssh_eap_discard_token(eap, protocol, buf, ("eap sim buffer"
                                                 " allocation failed"));
      return;
    }

  state->user_len = (SshUInt8)token->token.buffer.len;

  ssh_eap_sim_send_start_reply(protocol, eap);
}

static void
ssh_eap_sim_recv_token(SshEapProtocol protocol,
                       SshEap eap, SshBuffer buf)
{
  SshUInt8 token_type = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      ssh_eap_sim_recv_token_username(protocol, eap, buf);
      break;

    case SSH_EAP_TOKEN_SIM_CHALLENGE:
      ssh_eap_sim_recv_token_rand(protocol, eap, buf);
      break;

    default:

      ssh_eap_discard_token(eap, protocol, buf,
                            ("unexpected token type"));
      return;
    }
}
#endif /* SSHDIST_EAP_SIM */


void* ssh_eap_sim_create(SshEapProtocol protocol,
                         SshEap eap, SshUInt8 type)
{
#ifdef SSHDIST_EAP_SIM
  SshEapSimState state;

  state = ssh_malloc(sizeof(*state));
  if (state == NULL)
    return NULL;

  memset(state, 0, sizeof(SshEapSimStateStruct));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("created eap sim auth state"));

  return state;
#else /* SSHDIST_EAP_SIM */
  return NULL;
#endif /* SSHDIST_EAP_SIM */
}

void
ssh_eap_sim_destroy(SshEapProtocol protocol,
                    SshUInt8 type, void *state)
{
#ifdef SSHDIST_EAP_SIM
  SshEapSimState statex;

  statex = ssh_eap_protocol_get_state(protocol);

  if (statex)
    {
      if (statex->user)
        ssh_buffer_free(statex->user);

      if (statex->version_list)
        ssh_buffer_free(statex->version_list);

      if (statex->last_pkt)
        ssh_buffer_free(statex->last_pkt);

      ssh_free(protocol->state);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim state destroyed"));
#endif /* SSHDIST_EAP_SIM */
}

SshEapOpStatus
ssh_eap_sim_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshBuffer buf)
{
#ifdef SSHDIST_EAP_SIM
  if (ssh_eap_isauthenticator(eap) == TRUE)
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          SSH_ASSERT(buf != NULL);
          break;

        default:
          SSH_NOTREACHED;
        }
    }
  else
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim signal protocol reset"));
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap sim signal protocol begin"));
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_sim_client_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          ssh_eap_sim_recv_token(protocol, eap, buf);
          break;

        default:
          SSH_NOTREACHED;
        }
    }

#endif /* SSHDIST_EAP_SIM */
  return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_sim_key(SshEapProtocol protocol,
                SshEap eap, SshUInt8 type)
{
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->is_authenticator == TRUE);

  if (eap->mppe_send_keylen < 32 || eap->mppe_recv_keylen < 32)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Keys too short %d %d",
                             eap->mppe_send_keylen,
                             eap->mppe_recv_keylen));
      return SSH_EAP_OPSTATUS_FAILURE;
    }

  if ((eap->msk = ssh_malloc(64)) == NULL)
    return SSH_EAP_OPSTATUS_FAILURE;

  eap->msk_len = 64;

  memcpy(eap->msk, eap->mppe_recv_key, 32);
  memcpy(eap->msk + 32, eap->mppe_send_key, 32);

  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-SIM MSK"),
                    eap->msk, eap->msk_len);

  return SSH_EAP_OPSTATUS_SUCCESS;
}

