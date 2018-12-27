/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "ansi_x962.h"
#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_packet.h"
#include "ssheap_aka.h"

#define SSH_DEBUG_MODULE "SshEapAka"

#ifdef SSHDIST_EAP_AKA

/********************* Forward Declarations ****************************/
static void
ssh_eap_aka_auth_reject(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf,
                        const char *cause_str);







static SshUInt8
ssh_eap_aka_decode_identity(SshEapProtocol protocol,
                            SshBuffer buf)
{
  SshUInt8  id_cnt      = 0;
  SshUInt16 offset      = 8;
  SshEapAkaState state  = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  state->identity_msg_cnt++;

  if (state->identity_msg_cnt > SSH_EAP_AKA_MAX_IDENTITY_MSGS)
    return SSH_EAP_AKA_ERR_INVALID_STATE;

  /* RFC 4187 prohibits sending any more identity requests
     if permanent ID request has already been received. */
  if (state->aka_proto_flags & SSH_EAP_AKA_PERMID_RCVD)
    return SSH_EAP_AKA_ERR_INVALID_STATE;

  for (; offset < ssh_buffer_len(buf) &&
         SSH_EAP_AT_LEN(buf, offset); )
    {
      switch(ssh_buffer_ptr(buf)[offset])
        {
        case SSH_EAP_AT_ANY_ID_REQ:

          if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD ||
              state->aka_proto_flags & SSH_EAP_AKA_ANYID_RCVD)
            return SSH_EAP_AKA_ERR_INVALID_STATE;

          state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;

          offset += SSH_EAP_AT_LEN(buf, offset);
          id_cnt++;
          break;

        case SSH_EAP_AT_FULLAUTH_ID_REQ:

          if (state->aka_proto_flags & SSH_EAP_AKA_FULLID_RCVD)
            return SSH_EAP_AKA_ERR_INVALID_STATE;

          state->aka_proto_flags |= SSH_EAP_AKA_FULLID_RCVD;

          offset += SSH_EAP_AT_LEN(buf, offset);
          id_cnt++;
          break;

        case SSH_EAP_AT_PERMANENT_ID_REQ:

          state->aka_proto_flags |= SSH_EAP_AKA_PERMID_RCVD;

          offset += SSH_EAP_AT_LEN(buf, offset);
          id_cnt++;
          break;

        default:
          if (ssh_buffer_ptr(buf)[offset] > 127)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }

          SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (ie %x)",
                                 ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_AKA_ERR_INVALID_IE;
        }
    }

  state->aka_proto_flags |= SSH_EAP_AKA_ANYID_RCVD;

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (id_cnt == 1)
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}

static SshUInt8
ssh_eap_aka_decode_challenge(SshEapProtocol protocol,
                             SshBuffer buf,
                             unsigned char *rand,
                             unsigned char *autn)
{
  SshUInt8  mac_found     = 0;
  SshUInt8  ativ_cnt      = 0;
  SshUInt8  check_cnt     = 0;
  SshUInt8  autn_cnt      = 0;
  SshUInt8  encrdata_cnt  = 0;
  SshUInt8  rand_found    = 0;
  SshUInt8  resultind_cnt = 0;
  SshUInt8  bidding_cnt   = 0;
  SshUInt16 bidding_val   = 0;
  SshUInt16 offset        = 8;
  SshEapAkaState state    = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(rand != NULL);
  SSH_ASSERT(autn != NULL);

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

        case SSH_EAP_AT_CHECKCODE:

          check_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server requested "
                                       "checkcode, ignored."));
          break;

        case SSH_EAP_AT_RESULT_IND:

          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server indicated it want's"
                                       " to use protected success messages"));

          resultind_cnt++;

          state->aka_proto_flags |= SSH_EAP_AKA_PROT_SUCCESS;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_MAC:

          if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 5)
            return SSH_EAP_AKA_ERR_INVALID_IE;

          offset += SSH_EAP_AT_LEN(buf, offset);
          mac_found++;
          break;

        case SSH_EAP_AT_AUTN:

          autn_cnt++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
            {
              return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
            }

          memcpy(autn, &ssh_buffer_ptr(buf)[offset + 4],
                 SSH_EAP_AKA_AUTN_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);

          break;

        case SSH_EAP_AT_RAND:

          rand_found++;
          if ((SSH_EAP_AT_LEN(buf, offset) + offset) > ssh_buffer_len(buf) ||
              SSH_EAP_AT_LEN(buf, offset) != 20)
            {
              return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;
            }

          memcpy(rand, &ssh_buffer_ptr(buf)[offset + 4],
                 SSH_EAP_AKA_RAND_LEN);
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_BIDDING:

          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka server sent us AT_BIDDING "));
          bidding_cnt++;

          /* If multiple bidding attribute is sent from server in the
             challenge message, this case will be treated as error. */
          if (bidding_cnt > 1)
            return SSH_EAP_AKA_ERR_GENERAL;

          /* Check the attribute length is 4 bytes */
          if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

          /* Check that the Length field of the attribute is 1(MUST) */
          if ((ssh_buffer_ptr(buf)[offset + 1] & 0xFF) != 1)
            return SSH_EAP_AKA_ERR_INVALID_IE;

          state->aka_proto_flags |= SSH_EAP_AKA_BIDDING_REQ_RCVD;

          bidding_val = SSH_GET_16BIT(ssh_buffer_ptr(buf) + offset + 2);

          /* Check whether server indicated us to use the AKA-DASH, and
             prefers it over AKA */
          if (bidding_val & 8000)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("eap aka server indicated it's willing"
                               " to use AKA-DASH, and prefers it over AKA"));
              /* Check do we support AKA-DASH */
              if (state->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256)
                return SSH_EAP_AKA_ERR_USE_AKA_DASH;
            }

          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        default:
          if (ssh_buffer_ptr(buf)[offset] > 127)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }


          SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (ie %x)",
                                  ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_AKA_ERR_INVALID_IE;
        }
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || resultind_cnt > 1 ||
      autn_cnt > 1 || check_cnt > 1 || bidding_cnt > 1)
    return SSH_EAP_AKA_ERR_GENERAL;

  if (mac_found == 1 && rand_found == 1)
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}

static SshUInt8
ssh_eap_aka_decode_notification(SshEapProtocol protocol,
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
            return SSH_EAP_AKA_ERR_INVALID_IE;

          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_COUNTER:

          counter_cnt++;
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        case SSH_EAP_AT_NOTIFICATION:

          notif_cnt++;
          if (SSH_EAP_AT_LEN(buf, offset) != 4)
            return SSH_EAP_AKA_ERR_INVALID_IE;

          *notif_val = SSH_GET_16BIT(ssh_buffer_ptr(buf) + offset + 2);
          offset += SSH_EAP_AT_LEN(buf, offset);
          break;

        default:
          if (ssh_buffer_ptr(buf)[offset] > 127 &&
              ssh_buffer_ptr(buf)[offset] < 255)
            {
              offset += SSH_EAP_AT_LEN(buf, offset);
              SSH_DEBUG(SSH_D_FAIL, ("eap aka skippable attribute detected"
                                     " (ie %x)", ssh_buffer_ptr(buf)[offset]));
              break;
            }

          SSH_DEBUG(SSH_D_FAIL, ("eap aka invalid ie detected (%x)",
                                  ssh_buffer_ptr(buf)[offset]));
          return SSH_EAP_AKA_ERR_INVALID_IE;
        }
    }

  if (offset != ssh_buffer_len(buf))
    return SSH_EAP_AKA_ERR_PACKET_CORRUPTED;

  if (ativ_cnt > 1 || encrdata_cnt > 1 || mac_cnt > 1 ||
      counter_cnt > 1 || notif_cnt > 1)
    return SSH_EAP_AKA_ERR_GENERAL;

  if (notif_cnt == 1)
    return SSH_EAP_AKA_DEC_OK;

  return SSH_EAP_AKA_ERR_GENERAL;
}

/* Pass information to the upper layer. */
static void
ssh_eap_aka_auth_fail(SshEapProtocol protocol, SshEap eap,
                      SshEapSignal sig, const char *cause_str,
                      const char *additional_str)
{
  SshBufferStruct dummy;
  SshBuffer dummy_p = NULL;
  char *combined_str = NULL;

  if (cause_str != NULL)
    {
      if (additional_str != NULL)
        {
          size_t len = strlen(cause_str) + strlen(additional_str) + 3;

          combined_str = ssh_malloc(len);
          if (combined_str != NULL)
            {
              ssh_snprintf(combined_str, len, "%s, %s", cause_str,
                           additional_str);
            }
        }
      else
        {
          combined_str = ssh_memdup(cause_str, strlen(cause_str));
        }

      if (combined_str != NULL)
        {
          dummy.dynamic = FALSE;
          dummy.offset = 0;
          dummy.alloc = strlen(combined_str);
          dummy.end = dummy.alloc;
          dummy.buf = (unsigned char *) combined_str;

          dummy_p = &dummy;
        }
    }

  /* Pass information the upper layer. */
  ssh_eap_protocol_auth_fail(protocol, eap, sig, dummy_p);

  if (combined_str != NULL)
    ssh_free(combined_str);
}

static void
ssh_eap_aka_send_client_error(SshEapProtocol protocol, SshEap eap,
                              SshUInt16 err_code)
{
  SshBuffer pkt     = NULL;
  SshUInt16 pkt_len = SSH_EAP_AKA_CLIENT_ERROR_REPLY_LEN;
  SshUInt8  buf[7] = "";

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
ssh_eap_aka_client_error(SshEapProtocol protocol, SshEap eap,
                         SshUInt8 error, const char *error_str,
                         const char *additional_str)
{
  SshEapAkaState state;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka processing client error of type"
                               " %u", error));

  state = ssh_eap_protocol_get_state(protocol);
  state->aka_proto_flags |= SSH_EAP_AKA_STATE_FAILED;

  switch(error)
    {
      /* We shouldn't be entering here with these values. */
    case SSH_EAP_AKA_DEC_OK:

      SSH_ASSERT(0);
      break;

    case SSH_EAP_AKA_ERR_GENERAL:
    case SSH_EAP_AKA_ERR_INVALID_IE:
    case SSH_EAP_AKA_ERR_PACKET_CORRUPTED:
    case SSH_EAP_AKA_ERR_MEMALLOC_FAILED:
    case SSH_EAP_AKA_ERR_INVALID_STATE:

      ssh_eap_aka_send_client_error(protocol, eap, 0);
      break;

      /* Don't wan't to get here either. */
    default:

      SSH_ASSERT(0);
      break;
    }

  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_aka_auth_fail(protocol, eap, SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                        error_str, additional_str);
}

static void
ssh_eap_aka_send_identity_reply(SshEapProtocol protocol,
                                SshEap eap)
{
  SshEapAkaState state   = NULL;
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_IDENTITY_REPLY_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending identity reply"));

  state = ssh_eap_protocol_get_state(protocol);

  /* Calculate the real packet length. */
  if (state->user_len % 4)
    pkt_len += 4 + state->user_len + (4 - (state->user_len % 4));
  else
    pkt_len += 4 + state->user_len;

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_AKA_IDENTITY;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_append_identity_attr(pkt,
                                           ssh_buffer_ptr(state->user),
                                           state->user_len))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_synch_fail_reply(SshEapProtocol protocol,
                                  SshEap eap)
{
  SshEapAkaState state   = NULL;
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_SYNCH_REPLY_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending synchronisation "
                               "failed reply"));

  state = ssh_eap_protocol_get_state(protocol);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_AKA_SYNCH_FAILURE;
  buf[1] = buf[2] = 0;

  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_append_auts_attr(pkt, state->aka_id.auts))
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_auth_reject_reply(SshEapProtocol protocol,
                                   SshEap eap)
{
  SshBuffer      pkt     = NULL;
  SshUInt8       buf[3]  = "";
  SshUInt16      pkt_len = SSH_EAP_AKA_AUTH_REJ_REPLY_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending authorisation "
                               "reject reply"));

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_AKA_AUTH_REJECT;
  buf[1] = buf[2] = 0;
  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_challenge_reply(SshEapProtocol protocol,
                                 SshEap eap)
{
  SshEapAkaState state        = NULL;
  SshBuffer      pkt          = NULL;
  SshUInt8       buf[3]       = "";
  SshUInt8       rval         = 0;
  SshUInt16      pkt_len      = 0;
  SshUInt16      res_byte_len = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_ASSERT(state != NULL);

  res_byte_len = (state->aka_id.res_len / 8) +
    ((state->aka_id.res_len % 8) ? 1 : 0);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending challenge reply"));

  /* The SSH_EAP_AKA_CHALLENGE_REPLY_LEN is the maximum length of
     challenge reply. If the RES is not 16 bytes, well need to reduce
     the packet length. */
  pkt_len = SSH_EAP_AKA_CHALLENGE_REPLY_LEN - (16 - res_byte_len);

  pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                             protocol->impl->id);
  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  buf[0] = SSH_EAP_AKA_CHALLENGE;
  buf[1] = buf[2] = 0;
  if (ssh_buffer_append(pkt, buf, 3) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);

      ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_append_res_attr(pkt, state->aka_id.res,
                                      state->aka_id.res_len))
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

  if (protocol->impl->id == SSH_EAP_TYPE_AKA)
    {
      rval = ssh_eap_packet_calculate_hmac_sha(pkt, state->aut.K_aut,
                                               NULL, 0, FALSE);
    }
  if (rval != SSH_EAP_MAC_OK)
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, protocol, "eap aka could not calculate mac for"
                    " challenge response");
      return;
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_send_notification_reply(SshEapProtocol protocol,
                                    SshEap eap, SshUInt8 include_mac)
{
  SshEapAkaState state     = NULL;
  SshBuffer      pkt       = NULL;
  SshUInt8       buf[3]    = "";
  SshUInt16      pkt_len   = SSH_EAP_AKA_NOTIF_REPLY_LEN;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka sending notification reply"));

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
      SshUInt8 rval = 0;

      if (!(ssh_eap_packet_append_empty_mac_attr(pkt)))
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "Out of memory. Can not send reply.");
          return;
        }

      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        {
          rval = ssh_eap_packet_calculate_hmac_sha(pkt, state->aut.K_aut,
                                                   NULL, 0, FALSE);
        }

      if (rval != SSH_EAP_MAC_OK)
        {
          ssh_buffer_free(pkt);

          ssh_eap_fatal(eap, protocol, "eap aka could not calculate mac for"
                        " nofitication response");
          return;
        }
    }

  ssh_eap_protocol_send_response(protocol, eap, pkt);
}

static void
ssh_eap_aka_client_recv_identity(SshEapProtocol protocol,
                                 SshEap eap,
                                 SshBuffer buf)
{
  SshEapAkaState state = NULL;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka processing start message"));

  state = ssh_eap_protocol_get_state(protocol);

  if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka identity message"
                             " received when we are already entered state"
                             " for processing challenges");
      ssh_eap_aka_client_error(protocol, eap,
                               SSH_EAP_AKA_ERR_INVALID_STATE,
                               "EAP-AKA, AKA-Identity received after "
                               "AKA-Challenge exchange completed", NULL);
      return;
    }

  if ((rval = ssh_eap_aka_decode_identity(protocol, buf)) != 0)
    {
      /* We encountered a problem and in certain cases we signal
         it back to the AAA server depending on the return value. */
      SSH_DEBUG(SSH_D_FAIL, ("eap aka start message decoding "
                             "failed, reason: %u", rval));

      ssh_eap_discard_packet(eap, protocol, buf, "eap aka"
                             " decoding error, authentication terminated");
      ssh_eap_aka_client_error(protocol, eap, rval,
                               "EAP-AKA, decoding AKA-Identity failed", NULL);
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_IDENTITY_RCVD;
  state->response_id      = ssh_eap_packet_get_identifier(buf);

  ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                 SSH_EAP_TOKEN_USERNAME);
}

static void
ssh_eap_aka_client_recv_challenge(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshBuffer buf)
{
  SshEapAkaState   state    = NULL;
  SshUInt8         rval     = 0;
  unsigned char    chal[32] = "";

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  SSH_DEBUG(SSH_D_NICETOKNOW,("eap aka, processing client"
                              " challenge request message."));

  /* Freeradius 1.1.4 and below seem to be answering with new challenge
     message altough client-error message has been sent to it. This is
     totally against RFC 4187. */
  if (state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka multiple challenge"
                             " messages received");
      ssh_eap_aka_client_error(protocol, eap,
                               SSH_EAP_AKA_ERR_INVALID_STATE,
                               "EAP-AKA, AKA-Challenge received after "
                               "AKA-Challenge exchange completed", NULL);
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_CHALLENGE_RCVD;

  /* Probably a retransmission of RAND challenge? Anyway
     discard it silently. Only done when we are actually
     processing the RAND's. If we receive this message when
     we are already setup, we'll send an error message... */
  if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka"
                             " already waiting for PM's response"
                             " for RAND challenge.");
      return;
    }

  rval = ssh_eap_aka_decode_challenge(protocol, buf, state->aka_id.rand,
                                      state->aka_id.autn);
  if (rval != SSH_EAP_AKA_DEC_OK)
    {
      ssh_eap_aka_client_error(protocol, eap, rval,
                               "EAP-AKA, decoding AKA-Challenge failed", NULL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka"
                             " decoding error, authentication terminated");
      return;
    }

  if ((state->last_pkt = ssh_buffer_allocate()) == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  if (ssh_buffer_append(state->last_pkt, ssh_buffer_ptr(buf),
                        ssh_buffer_len(buf)) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      ssh_eap_discard_packet(eap, protocol, buf, "eap aka fatal error,"
                             " memory allocation for packet failed.");
      return;
    }

  state->aka_proto_flags |= SSH_EAP_AKA_PROCESSING_RAND;

  /* If we have got the username from identity round,
     use it, otherwise first request for username and
     after that send token for challenge. */
  if (state->user)
    {
      memcpy(chal, state->aka_id.rand, 16);
      memcpy(&chal[16], state->aka_id.autn, 16);

      ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                               SSH_EAP_TOKEN_AKA_CHALLENGE,
                                               chal, 32);
    }
  else
    {
      ssh_eap_protocol_request_token(eap, protocol->impl->id,
                                     SSH_EAP_TOKEN_USERNAME);
    }
}

static void
ssh_eap_aka_client_recv_notification(SshEapProtocol protocol,
                                     SshEap eap,
                                     SshBuffer buf)
{
  SshEapAkaState state = NULL;
  SshUInt16      ret   = 0;
  SshUInt8       rval  = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("processing eap aka notification"));

  state = ssh_eap_protocol_get_state(protocol);

  if ((rval = ssh_eap_aka_decode_notification(protocol, buf, &ret)) !=
      SSH_EAP_AKA_DEC_OK)
    {
      ssh_eap_aka_client_error(protocol, eap, rval,
                               "EAP-AKA, decoding AKA-Notification failed",
                               NULL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka invalid packet");
      return;
    }

  /* Do we have to verify the MAC? */
  if (!(ret & 0x4000))
    {
      SshUInt8 result = 0;

      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        {
          result = ssh_eap_packet_calculate_hmac_sha(buf, state->aut.K_aut,
                                                     NULL, 0, TRUE);
        }
      if (result != SSH_EAP_MAC_OK)
        {
          ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE,
                                   "EAP-AKA, invalid MAC in AKA-Notification",
                                   ssh_eap_packet_mac_code_to_string(result));
          ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                                 " aka notify with invalid mac");
          return;
        }
    }

  if (ret & 0x8000)
    {
      /* Success message. Discard and send error. Shouldn't be
         getting these since we did not approve protected successes. */
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, AKA-Notification with Status bit "
                               "received",
                               NULL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka success");
      return;
    }

  if ((ret & 0x4000) &&
      state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD)
    {
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, AKA-Notification with Phase bit "
                               "received after AKA-Challenge exchange "
                               "completed",
                               NULL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka nofitication with invalid phase bit");
      return;
    }

  if (!(ret & 0x4000) &&
      !(state->aka_proto_flags & SSH_EAP_AKA_CHALLENGE_RCVD))
    {
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, AKA-Notification without Phase bit "
                               "received before AKA-Challenge exchange",
                               NULL);
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka server sent"
                             " aka nofitication with invalid phase bit");
      return;
    }

  ssh_eap_aka_send_notification_reply(protocol, eap, !(ret & 0x4000));

  /* Inform the upper layer that something has gone bad here. */
  ssh_eap_aka_auth_fail(protocol, eap,
                        SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL, NULL);
}

static void
ssh_eap_aka_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapAkaState state   = NULL;
  SshUInt16      msg_len = 0;
  SshUInt8       msg_subtype;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP AKA state uninitialized");
      return;
    }

  /* Here we handle only EAP-AKA specific messages. some notifications
     and Identity requests etc... are handled in ssheap_common. */
  if (ssh_buffer_len(buf) < 6)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet too short to be eap aka request");
      return;
    }

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);
  if (msg_len != ssh_buffer_len(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP AKA msg length invalid");
      return;
    }

  msg_subtype = ssh_buffer_ptr(buf)[5];
  switch (msg_subtype)
    {
    case SSH_EAP_AKA_IDENTITY:

      ssh_eap_aka_client_recv_identity(protocol, eap, buf);
      break;

    case SSH_EAP_AKA_CHALLENGE:

      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        ssh_eap_aka_client_recv_challenge(protocol, eap, buf);
      break;

    case SSH_EAP_REAUTHENTICATION:
      /* The AAA server is really misbehaving. We really do
         not wan't these messages, because we always indicate we
         do not support fast reauthentication. Discard the message, send
         error and tear everything down. */
      ssh_eap_discard_packet(eap, protocol, buf, "eap aka reauthentication"
                             " requested by server, authentication"
                             " terminated");
      ssh_eap_aka_client_error(protocol, eap,
                               SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, AKA-Reauthentication received, "
                               "Fast Re-Authentication not supported", NULL);
      break;

    case SSH_EAP_NOTIFICATION:

      ssh_eap_aka_client_recv_notification(protocol, eap, buf);
      break;

    default:
      {
        char error_buf[64] = { 0 };

        ssh_eap_discard_packet(eap, protocol, buf,
                               "Invalid EAP AKA subtype");

        ssh_snprintf(error_buf, sizeof(error_buf),
                     "EAP-AKA, unknown message type %d", msg_subtype);
        ssh_eap_aka_client_error(protocol, eap,
                                 SSH_EAP_AKA_ERR_GENERAL, error_buf, NULL);
      }
      break;
    }
}

SshUInt8
ssh_eap_aka_calculate_keys(SshEapProtocol protocol, SshEap eap,
                           unsigned char *generated_keys)
{
  SshAnsiX962        x962         = NULL;
  SshEapAkaState     state        = NULL;
  SshHash            hash         = NULL;
  unsigned char      mk[20]       = "";
  unsigned char      *key_buf     = generated_keys;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(generated_keys != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka calculating keys"));

  if (ssh_hash_allocate("sha1", &hash) != SSH_CRYPTO_OK)
    return 1;

  ssh_hash_reset(hash);

  /* MK generation section.
     MK = SHA1(Identity, IK, CK) */
  ssh_hash_update(hash, ssh_buffer_ptr(state->user), state->user_len);

  ssh_hash_update(hash, state->aka_id.IK, SSH_EAP_AKA_IK_LEN);
  ssh_hash_update(hash, state->aka_id.CK, SSH_EAP_AKA_CK_LEN);

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
ssh_eap_aka_auth_reject(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf,
                        const char *cause_str)
{
  ssh_eap_aka_send_auth_reject_reply(protocol, eap);

  ssh_eap_aka_auth_fail(protocol, eap, SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                        cause_str, NULL);
}

static void
ssh_eap_aka_recv_token_auth_reject(SshEapProtocol protocol,
                                   SshEap eap,
                                   SshBuffer buf)
{
  ssh_eap_aka_auth_reject(protocol, eap, buf,
                          "EAP-AKA, unacceptable AUTN parameter, sending "
                          "AKA-Authentication-Reject");
}

static void
ssh_eap_aka_recv_token_synch_required(SshEapProtocol protocol,
                                      SshEap eap,
                                      SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapAkaState   state     = NULL;
  SshUInt8        *auts_ptr  = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka received token auts"));

  token = (SshEapToken)ssh_buffer_ptr(buf);
  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received sync req"
                                                 " token altough not "
                                                 "requested one"));
      return;
    }

  if (token->token.buffer.len != SSH_EAP_AKA_AUTS_LEN)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid"
                                                 " length AUTS token"));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;

    }

  if (state->aka_proto_flags & SSH_EAP_AKA_SYNCH_REQ_SENT)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, multiple synch "
                                                 "requests, terminating "
                                                 "authorisation"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, multiple synchronization requests "
                               "triggered", NULL);
      return;
    }

  /* Copy the outputs from token. */
  auts_ptr = token->token.buffer.dptr;
  memcpy(state->aka_id.auts, auts_ptr, SSH_EAP_AKA_AUTS_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
  state->aka_proto_flags &= ~SSH_EAP_AKA_CHALLENGE_RCVD;
  state->aka_proto_flags |=  SSH_EAP_AKA_SYNCH_REQ_SENT;

  ssh_eap_aka_send_synch_fail_reply(protocol, eap);
}

static void
ssh_eap_aka_recv_token_challenge_response(SshEapProtocol protocol,
                                          SshEap eap,
                                          SshBuffer buf)
{
  SshEapToken      token     = NULL;
  SshEapAkaState   state     = NULL;
  SshUInt8        *chal_ptr  = NULL;
  unsigned char    keys[160] = "";
  SshUInt32        res_byte_len;
  SshUInt8         rval;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka received token rand"));

  token = (SshEapToken)ssh_buffer_ptr(buf);
  if (!(state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received challenge"
                                                 " token altough not"
                                                 " requested one"));
      return;
    }

  if (token->token.buffer.len > ((2 * SSH_EAP_AKA_IK_LEN) + 17) ||
      token->token.buffer.len < ((2 * SSH_EAP_AKA_IK_LEN) + 5))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid"
                                                 " length token"));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;

    }

  /* Copy the outputs from token. */
  chal_ptr = token->token.buffer.dptr;
  memcpy(state->aka_id.IK, chal_ptr, SSH_EAP_AKA_IK_LEN);

  chal_ptr += SSH_EAP_AKA_IK_LEN;
  memcpy(state->aka_id.CK, chal_ptr, SSH_EAP_AKA_CK_LEN);

  chal_ptr += SSH_EAP_AKA_CK_LEN;
  state->aka_id.res_len = *chal_ptr & 0xff;
  res_byte_len = (state->aka_id.res_len / 8) +
    ((state->aka_id.res_len % 8) ? 1 : 0);

  if (state->aka_id.res_len > 128 || state->aka_id.res_len < 32)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, received invalid"
                                                 " length challenge token"));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;
      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      return;

    }

  memset(state->aka_id.res, 0x0, sizeof(state->aka_id.res));
  memcpy(state->aka_id.res, &chal_ptr[1], res_byte_len);

  if (ssh_eap_aka_calculate_keys(protocol, eap, keys))
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka, key generation"
                                                 " failed, dropping token"));
      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_GENERAL,
                               "EAP-AKA, key material generation for session "
                               "keys failed", NULL);
      return;
    }

  rval = ssh_eap_packet_calculate_hmac_sha(state->last_pkt, &keys[16],
                                           NULL, 0, TRUE);
  if (rval != SSH_EAP_MAC_OK)
    {

      ssh_eap_discard_token(eap, protocol, buf, ("eap aka message mac "
                                                 "verification"
                                                 " failed, dropping token"));

      ssh_buffer_free(state->last_pkt);
      state->last_pkt = NULL;

      state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;
      ssh_eap_aka_client_error(protocol, eap, SSH_EAP_AKA_ERR_INVALID_IE,
                               "EAP-AKA, MAC error",
                               ssh_eap_packet_mac_code_to_string(rval));
      return;
    }

  /* Copy the keys, everything should be fine. */
  memcpy(state->K_encr, keys, SSH_EAP_AKA_KENCR_LEN);
  memcpy(state->aut.K_aut, &keys[16], SSH_EAP_AKA_KAUT_LEN);
  memcpy(state->msk, &keys[32], SSH_EAP_AKA_MSK_LEN);
  memcpy(state->emsk, &keys[96], SSH_EAP_AKA_EMSK_LEN);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("MSK"), state->msk, SSH_EAP_AKA_MSK_LEN);

  ssh_buffer_free(state->last_pkt);
  state->last_pkt = NULL;

  state->aka_proto_flags &= ~SSH_EAP_AKA_PROCESSING_RAND;

  eap->msk = ssh_memdup(state->msk, SSH_EAP_AKA_MSK_LEN);
  eap->msk_len = SSH_EAP_AKA_MSK_LEN;

  ssh_eap_aka_send_challenge_reply(protocol, eap);
  ssh_eap_protocol_auth_ok(protocol, eap, SSH_EAP_SIGNAL_NONE, NULL);
}

static void
ssh_eap_aka_recv_token_username(SshEapProtocol protocol,
                                SshEap eap,
                                SshBuffer buf)
{
  SshEapToken    token   = NULL;
  SshEapAkaState state   = NULL;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(eap != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  token = (SshEapToken)ssh_buffer_ptr(buf);

  /* Wipe out the old stuff if required. */
  if (state->user)
    {
      ssh_buffer_free(state->user);
      state->user = NULL;
    }

  if (!token->token.buffer.dptr || token->token.buffer.len <= 0)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka did not receive"
                                                 " valid username"));
      ssh_eap_aka_auth_fail(protocol, eap,
                            SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                            "EAP-AKA, mandatory user name missing", NULL);
      return;
    }

  state->user = ssh_buffer_allocate();
  if (!state->user)
    {
      ssh_eap_discard_token(eap, protocol, buf, ("eap aka buffer"
                                                 " allocation failed"));
      return;
    }

  if (ssh_buffer_append(state->user, token->token.buffer.dptr,
                        token->token.buffer.len) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->user);
      state->user = NULL;

      ssh_eap_discard_token(eap, protocol, buf, ("eap aka buffer"
                                                 " allocation failed"));
      return;
    }

  state->user_len = (SshUInt8)token->token.buffer.len;

  /* If we have entered already for processing rand, the server
     obviously skipped the identity round and therefore we had
     to first ask for username and after that only we can
     proceed with processing the rand (so request
     token AKA_CHALLENGE). */
  if (state->aka_proto_flags & SSH_EAP_AKA_PROCESSING_RAND)
    {
      unsigned char chal[32] = "";

      memcpy(chal, state->aka_id.rand, 16);
      memcpy(&chal[16], state->aka_id.autn, 16);

      ssh_eap_protocol_request_token_with_args(eap, protocol->impl->id,
                                               SSH_EAP_TOKEN_AKA_CHALLENGE,
                                               chal, 32);
    }
  else
    {
      ssh_eap_aka_send_identity_reply(protocol, eap);
    }
}

static void
ssh_eap_aka_recv_token(SshEapProtocol protocol,
                       SshEap eap, SshBuffer buf)
{
  SshUInt8 token_type = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      SSH_ASSERT(buf != NULL);
      ssh_eap_aka_recv_token_username(protocol, eap, buf);
      break;

    case SSH_EAP_TOKEN_AKA_CHALLENGE:
      SSH_ASSERT(buf != NULL);
      if (protocol->impl->id == SSH_EAP_TYPE_AKA)
        ssh_eap_aka_recv_token_challenge_response(protocol, eap, buf);
      break;

    case SSH_EAP_TOKEN_AKA_SYNCH_REQ:
      SSH_ASSERT(buf != NULL);
      ssh_eap_aka_recv_token_synch_required(protocol, eap, buf);
      break;

    case SSH_EAP_TOKEN_AKA_AUTH_REJECT:
      ssh_eap_aka_recv_token_auth_reject(protocol, eap, buf);
      break;
    default:

      ssh_eap_discard_token(eap, protocol, buf,
                            ("unexpected token type"));
      return;
    }
}
#endif /* SSHDIST_EAP_AKA */

void
ssh_eap_aka_recv_params(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState aka;
  SshEapAkaParams params;

  aka = ssh_eap_protocol_get_state(protocol);

  params = (SshEapAkaParams)ssh_buffer_ptr(buf);

  if (ssh_buffer_len(buf) != sizeof(*params))
    {
      SSH_DEBUG(SSH_D_FAIL,("Received params struct of incorrect size"));
      return;
    }

  aka->transform = params->transform;
  SSH_ASSERT((aka->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA1) ||
             (aka->transform & SSH_EAP_TRANSFORM_PRF_HMAC_SHA256));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Set transform for AKA to %x",
                              aka->transform));

#endif /* SSHDIST_EAP_AKA */
}

void* ssh_eap_aka_create(SshEapProtocol protocol,
                         SshEap eap, SshUInt8 type)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState state;

  state = ssh_malloc(sizeof(*state));
  if (state == NULL)
    return NULL;

  memset(state, 0, sizeof(SshEapAkaStateStruct));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("created eap aka auth state"));

  return state;
#else /* SSHDIST_EAP_AKA */
  return NULL;
#endif /* SSHDIST_EAP_AKA */
}

void
ssh_eap_aka_destroy(SshEapProtocol protocol,
                    SshUInt8 type, void *state)
{
#ifdef SSHDIST_EAP_AKA
  SshEapAkaState statex;

  statex = ssh_eap_protocol_get_state(protocol);

  if (statex)
    {
      if (statex->user)
        ssh_buffer_free(statex->user);

      if (statex->last_pkt)
        ssh_buffer_free(statex->last_pkt);

      ssh_free(protocol->state);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka state destroyed"));
#endif /* SSHDIST_EAP_AKA */
}

SshEapOpStatus
ssh_eap_aka_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshBuffer buf)
{
#ifdef SSHDIST_EAP_AKA
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

        case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_ASSERT(buf != NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka receive params"));
          ssh_eap_aka_recv_params(protocol, eap, buf);
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
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka signal protocol reset"));
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka signal protocol begin"));
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_aka_client_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          ssh_eap_aka_recv_token(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_ASSERT(buf != NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap aka receive params"));
          ssh_eap_aka_recv_params(protocol, eap, buf);
          break;

        default:
          SSH_NOTREACHED;
        }
    }
#endif /* SSHDIST_EAP_AKA */
  return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol,
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

  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-AKA MSK"),
                    eap->msk, eap->msk_len);

  return SSH_EAP_OPSTATUS_SUCCESS;
}
