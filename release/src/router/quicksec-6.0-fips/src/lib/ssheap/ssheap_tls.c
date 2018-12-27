/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshhash.h"
#ifdef SSHDIST_EAP_TLS
#include "sshstreampair.h"
#include "sshfilterstream.h"
#include "sshtls.h"
#endif /* SSHDIST_EAP_TLS */

#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_tls.h"

#define SSH_DEBUG_MODULE "SshEapTls"

#ifdef SSHDIST_EAP_TLS

#define SSH_EAP_TLS_IE_LENGTH_LEN 4
#define SSH_EAP_TLS_PKT_BASE_LEN  6

/* Flags in the EAP-TLS specific message. */
#define SSH_EAP_TLS_FLAGS_LENGTH_BIT     0x80
#define SSH_EAP_TLS_FLAGS_MF_BIT         0x40
#define SSH_EAP_TLS_FLAGS_S_BIT          0x20
#define SSH_EAP_TLS_FLAGS_RESERVED       0x1F

#define SSH_TLS_MSG_HDR_LEN 5

/* States in the EAP-TLS. */
#define SSH_EAP_TLS_STATE_INITIAL            0 /* Initial state */
#define SSH_EAP_TLS_STATE_TLS_CLIENT_HELLO   1 /* Sending client hello */
#define SSH_EAP_TLS_STATE_TLS_SERVER_HELLO   2 /* TLS server hello received
                                                  (now sending response) */
#define SSH_EAP_TLS_STATE_FINISHED           3 /* Only waiting for response
                                                  from other end. */

#define SSH_EAP_TLS_FRAGMENT_SIZE          1024

typedef struct SshEapTlsStateRec {
  SshEap eap;
  SshEapProtocol protocol;

  /* Handle to the certificate manager */
  SshCMContext cm;
  SshPrivateKey prvkey;
  unsigned char *id_data;
  size_t id_data_size;

  /* Streams used for conversion of EAP to TLS messages */
  SshStream tls_wrapped_stream;
  SshStream eap_filter_stream;
  SshStream tls_streampair;
  SshStream eap_streampair;

  /* The CA's allocated for this TLS session.
     These must be freed here, since the TLS lib
     does not free these. */
  unsigned char **tls_cas;
  SshUInt32 crl_check_pol;

  /* A buffer containing TLS records for sending to the EAP loyer layer. */
  SshBuffer out_buffer;

  /* Couple of items for tracking sending state. */
  SshUInt16 record_length;
  SshUInt16 sent_bytes;
  SshUInt16 sent_fragments;

  /* Total length of the current TLS record being parsed. */
  Boolean more_records;
  Boolean change_cipher_seen;
  Boolean out_waiting_ack;

  /* TRUE if TLS alert has been received from server, in reality
     this EAP-TLS session has to be torn down soon. */
  Boolean alert_received;

  /* Input buffer and receiving state. */
  SshBuffer in_buffer;
  SshUInt8  in_receiving_frags;

  /* The conversation state in the library. */
  SshUInt8  conversation_state;

} *SshEapTlsState, SshEapTlsStateStruct;


/* Forward declarations */

/* Wrap a complete TLS record in an EAP packet and send out the
   EAP packet. The resulting packet may be sent as multiple fragments. */
void
ssh_eap_tls_output_tls_record(SshEapTlsState state,
                              const unsigned char *record,
                              size_t record_len,
                              Boolean buffer_only);

Boolean
ssh_eap_tls_continue_tlsrecord_send(SshEapProtocol protocol,
                                    SshEap eap);

Boolean
ssh_eap_tls_send_message(SshEapProtocol protocol,
                         SshEap eap,
                         SshBuffer tls_buf,
                         SshUInt32 length,
                         SshUInt8 flags,
                         SshUInt32 total_length);

/* ***************************************************************** */

/* This function checks that EAP-TLS message reserved
   flags are correct, i.e. the reserved flags is 0. */
static Boolean
ssh_eap_tls_check_reserved_flags(SshBuffer buf)
{
  SshUInt8 buf_flags;

  buf_flags = ssh_buffer_ptr(buf)[5];

  if (buf_flags & SSH_EAP_TLS_FLAGS_RESERVED)
    return FALSE;

  return TRUE;
}


/****** Application Hook to the TLS library **************/
void
ssh_eap_tls_app_hook(SshStream tls_stream,
                     SshTlsAppNotification notification,
                     void *app_context)
{
  SshEapTlsState state = (SshEapTlsState)app_context;

  SSH_DEBUG(SSH_D_HIGHOK, ("TLS application hook entered"));

  switch (notification)
    {
    case SSH_TLS_NEW_CONNECTION_REQUEST:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS new connection request"));
      /* Nothing here */
      break;

    case SSH_TLS_PEER_CERTS:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS peer certificates available"));
      /* Nothing here */
      break;

    case SSH_TLS_AUTH_REQUEST:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS authentication request"));






      SSH_DEBUG(SSH_D_NICETOKNOW, ("Requesting a private key token"));
      ssh_eap_protocol_request_token(state->eap, state->protocol->impl->id,
                                     SSH_EAP_TOKEN_PRIVATE_KEY);
      break;

    case SSH_TLS_NEGOTIATED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS negotiated"));

      /* Client must ack. */
      if (ssh_eap_isauthenticator(state->eap) == FALSE)
        ssh_eap_tls_send_message(state->protocol, state->eap, NULL, 0, 0, 0);

      /* Get master key here. This key will be input to the EAP library. */
      if (!ssh_tls_get_eap_master_key(tls_stream,
                                      &state->eap->msk,
                                      &state->eap->msk_len))
        {
          ssh_eap_fatal(state->eap, state->protocol,
                        "Out of memory, cannot get TLS master key");
          return;
        }

      if (!ssh_tls_get_eap_session_id(tls_stream,
                                      &state->eap->session_id,
                                      &state->eap->session_id_len))
        {
          ssh_eap_fatal(state->eap, state->protocol,
                        ("Out of memory, cannot get TLS session id"));
          return;
        }

     SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("MSK from TLS"),
                        state->eap->msk, state->eap->msk_len);

      /* Considering client, everything seems to be ok. Now we'll
         have to wait for EAP-SUCCESS on client side. On server side
         we'll wait for the ACK for the last message we sent. */
      if (ssh_eap_isauthenticator(state->eap) == FALSE)
        ssh_eap_protocol_auth_ok(state->protocol, state->eap,
                                 SSH_EAP_SIGNAL_NONE, NULL);
      else
        state->conversation_state = SSH_EAP_TLS_STATE_FINISHED;

      break;
    case SSH_TLS_RENEGOTIATED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS renegotiated"));
      /* Nothing here */
      break;

    case SSH_TLS_VANISHED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS vanished"));
      break;

    case SSH_TLS_ERROR:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TLS error"));
      {
        /* Send failure message in the case of errors caused by
           receiving an alert from the peer. If the error is locally
           generated by the TLS module, then the TLS module will send an
           alert to the server and we should not send an empty EAP-TLS
           packet to the EAP server in this case. */
        if (state->alert_received && !ssh_eap_isauthenticator(state->eap))
          ssh_eap_tls_send_message(state->protocol, state->eap, NULL, 0, 0, 0);

        /* If we are authenticator, indicate the failure to upper
           layer. If we are supplicant, mark the method as done,
           since we are only waiting for failure message from
           the authenticator. */
        if (ssh_eap_isauthenticator(state->eap))
          ssh_eap_protocol_auth_fail(state->protocol, state->eap,
                                     SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR,
                                     NULL);
        else
          state->eap->method_done = 1;

        state->conversation_state = SSH_EAP_TLS_STATE_FINISHED;

        break;
      }
    }
}

/* Pass data coming from TLS stream to EAP side. */
void
ssh_eap_to_stream_client_filter(void *context, SshFilterGetCB get_data,
                                SshFilterCompletionCB completed,
                                void *internal_context)
{
  SshEapTlsState state = (SshEapTlsState)context;
  unsigned char *ptr, *data_ptr;
  int len, msg_len, msg_offset;
  SshBuffer data;
  size_t offset;
  Boolean eof_received;
  Boolean buffer_only = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Entered ssh_eap_to_stream_client_filter"));

  get_data(internal_context, &data, &offset, &eof_received);
  len = (int)(ssh_buffer_len(data) - offset);
  if (len <= 0)
    {
      completed(internal_context, SSH_FILTER_HOLD);
      return;
    }

  ptr = ssh_buffer_ptr(data) + offset;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("%d bytes from TLS lib", len));





  if (!state || !state->eap || !state->eap->con)
    {
      /* If we've lost connection, just consume TLS lib data. */
      completed(internal_context, SSH_FILTER_ACCEPT(len));
      return;
    }

  SSH_ASSERT(state->sent_bytes == 0);
  SSH_ASSERT(state->sent_fragments == 0);










  switch (state->conversation_state)
    {
    case SSH_EAP_TLS_STATE_TLS_CLIENT_HELLO:

      /* Client hello message is at maximum 66 bytes, so we'll
         receive it on one go. If we don't receive it on one go,
         we can fail the EAP-TLS negotiation, because we are
         anyway running out of memory. */
      state->more_records = FALSE;

      /* Check that we received a complete TLS record */
      if (SSH_GET_16BIT(ptr + 3) + 5 != len)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Received incomplete TLS record "
                                  "received=%d expected=%d",
                                  len, SSH_GET_16BIT(ptr + 3)));
          goto tls_parse_error;
        }

      state->record_length = len;

      if (ptr[0] == 22) /* 22 is handshake */
        {
          if (ptr[5] != 1)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Handshake type is not ClientHello"));
              goto tls_parse_error;
            }

          SSH_DEBUG(SSH_D_LOWOK, ("Parsed TLS record length %d", len));
        }
      else if (ptr[0] != 21)     /* 21 is alert and is the only other message
                                  type that should be seen here. */
        {
          SSH_DEBUG(SSH_D_FAIL, ("Received unexpected TLS record type (%d)",
                                 ptr[0]));
          goto tls_parse_error;
        }
      break;

      /* Here we expect that the TLS library sends one packet i.e. TLS
         record protocol message in one buffer. This parsing will otherwise
         fail. */
    case SSH_EAP_TLS_STATE_TLS_SERVER_HELLO:
      data_ptr = ptr;
      state->more_records = TRUE;

      for (msg_offset = 0;
           msg_offset < len && state->more_records;
           msg_offset += msg_len, data_ptr += msg_len)
        {
          msg_len = SSH_GET_16BIT(data_ptr + 3) + 5;
          if (msg_len > (len - msg_offset))
              goto tls_parse_error;

          switch (data_ptr[0])
            {
            case 20: /* ChangeCipherSpec */
              SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS ChangeCipherSpec "
                                           "message seen"));
              state->change_cipher_seen = TRUE;
              break;

            case 21: /* Alert */
              SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS Alert "
                                           "message seen"));
              state->more_records = FALSE;
              state->record_length = len;
              state->conversation_state = SSH_EAP_TLS_STATE_FINISHED;
              goto send_now;

            case 22: /* Handshake */
              SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS Handshake "
                                           "message seen"));
              if (state->change_cipher_seen)
                  state->more_records = FALSE;
              break;

            case 23: /* Application, results in breaking up the connection */
            default: /* Break the conversation, not known TLS message type
                        so nothing can be done. */
              SSH_DEBUG(SSH_D_ERROR, ("Invalid TLS message type %x",
                                      data_ptr[0]));
              break;
            }
        }

      if (state->more_records == FALSE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Client certificate ready and change "
                                       "cipher has been seen. Sending the"
                                       " message to server."));

          state->conversation_state = SSH_EAP_TLS_STATE_FINISHED;
          state->record_length = ssh_buffer_len(state->out_buffer) + len;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiting for more messages."));
          buffer_only = TRUE;
        }

      break;
    case SSH_EAP_TLS_STATE_FINISHED:
    case SSH_EAP_TLS_STATE_INITIAL:
    default:
      SSH_DEBUG(SSH_D_ERROR, ("Message from TLS library in state %u",
                              state->conversation_state));
      state->more_records = FALSE;
      state->record_length = len;
      break;
    }


 send_now:
  ssh_eap_tls_output_tls_record(state, ptr, len, buffer_only);
  completed(internal_context, SSH_FILTER_ACCEPT(len));
  return;

 tls_parse_error:
  SSH_DEBUG(SSH_D_FAIL, ("Cannot parse TLS message"));
  completed(internal_context, SSH_FILTER_ACCEPT(len));
  ssh_eap_fatal(state->eap, state->protocol, "Error parsing TLS record");
  return;
}

/* Pass data coming from TLS stream to EAP side. */
void
ssh_eap_to_stream_server_filter(void *context, SshFilterGetCB get_data,
                                SshFilterCompletionCB completed,
                                void *internal_context)
{
  SshEapTlsState state = (SshEapTlsState)context;
  unsigned char *ptr   = NULL;
  int len, msg_len;
  SshBuffer data;
  size_t offset;
  Boolean eof_received;
  Boolean buffer_only = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Entered ssh_eap_to_stream_server_filter"));

  get_data(internal_context, &data, &offset, &eof_received);
  len = ssh_buffer_len(data) - offset;
  if (len <= 0)
    {
      completed(internal_context, SSH_FILTER_HOLD);
      return;
    }

  ptr = ssh_buffer_ptr(data) + offset;





  if (!state || !state->eap || !state->eap->con)
    {
      /* If we've lost connection, just consume TLS lib data. */
      completed(internal_context, SSH_FILTER_ACCEPT(len));
      return;
    }

  if (state->more_records == FALSE)
    {
      /* Not very nice if we have sent some bytes when we receive
         a new message from TLS. Fatal internal error. Our state
         is really messed up. */
      SSH_ASSERT(state->sent_bytes == 0);

      /* This is first piece of the TLS message. */
      msg_len = SSH_GET_16BIT(ptr + 3) + SSH_TLS_MSG_HDR_LEN;

      /* Does this message fit into one EAP-TLS message and
         did we read the whole message already? */
      if (msg_len > SSH_EAP_TLS_FRAGMENT_SIZE &&
          len != msg_len)
        {
          buffer_only = TRUE;
          state->more_records = TRUE;
        }

      state->record_length = len > msg_len ? len : msg_len;
    }
  else
    {
      SSH_ASSERT(state->more_records != TRUE);
      SSH_ASSERT(state->record_length > 0);

      /* Do we have whole message (i.e. we aren't waiting for
         more parts). */
      if ((state->sent_bytes + len) == state->record_length)
        state->more_records = FALSE;
    }

  if (state->conversation_state == SSH_EAP_TLS_STATE_FINISHED)
    {
      if (ptr[0] == 20)
        buffer_only = TRUE;

      if (state->out_buffer)
        {
          /* Well have to maintain the record_length here. In case
             we are requesting to buffer only packets. */
          state->record_length = ssh_buffer_len(state->out_buffer) +
            state->record_length;
        }
    }

  ssh_eap_tls_output_tls_record(state, ptr, len, buffer_only);

  completed(internal_context, SSH_FILTER_ACCEPT(len));
  return;
}

/* *********** Stream callbacks *********************** */

void
ssh_eap_eap_stream_callback(SshStreamNotification notification,
                            void *context)
{
  SshEapTlsState state = context;
  unsigned char dummy[128];
  int dummy_bytes_read, bytes_written;

  SSH_ASSERT(state != NULL);

  if (notification == SSH_STREAM_INPUT_AVAILABLE)
    {
      SSH_DEBUG(SSH_D_MY, ("Input available"));

      /* Drain the input buffers. The input data is already processed by
         ssh_eap_to_stream_XXX_filter(), so this is only called for
         clearing the internal buffers in the eap_filter_stream */
      dummy_bytes_read = 1;
      while (dummy_bytes_read > 0)
        {
          dummy_bytes_read = ssh_stream_read(state->eap_filter_stream,
                                             dummy, sizeof(dummy));

          SSH_DEBUG(SSH_D_MY, ("Read %d bytes", dummy_bytes_read));
        }
    }

  /* Write more data to the EAP filter stream. This will eventually to
     passed to the TLS module. */
  if (notification == SSH_STREAM_CAN_OUTPUT)
    {
      SSH_DEBUG(SSH_D_MY, ("Can output, continuing writing to TLS."));

      if (state->in_buffer && !state->in_receiving_frags)
        {
          bytes_written = ssh_stream_write(state->eap_filter_stream,
                                           ssh_buffer_ptr(state->in_buffer),
                                           ssh_buffer_len(state->in_buffer));

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Wrote %d bytes to TLS. Buffer "
                                       "length %u.", bytes_written,
                                       ssh_buffer_len(state->in_buffer)));

          if (bytes_written < ssh_buffer_len(state->in_buffer))
            {
              /* Some bytes were left pending... */
              ssh_buffer_consume(state->in_buffer, bytes_written);
            }
          else
            {
              /* All pending data has been written to the stream. */
              ssh_buffer_free(state->in_buffer);
              state->in_buffer = NULL;
            }
        }
    }

  if (notification == SSH_STREAM_DISCONNECTED)
    {
      SSH_DEBUG(SSH_D_MY, ("Disconnected"));
    }
}

/* *********** TLS context initialization *********************** */

Boolean ssh_eap_tls_open(SshEapTlsState state, unsigned char **cas)
{
  SshTlsConfigurationStruct configuration;
  SshEap eap = state->eap;
  unsigned char dummy[16];
  int dummy_bytes_read = 1;

  /* Create a stream pair to connect EAP and TLS flows */
  ssh_stream_pair_create(&state->tls_streampair, &state->eap_streampair);

  if (state->tls_streampair == NULL || state->eap_streampair == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Stream pair create operation failed"));
      return FALSE;
    }

  if (ssh_eap_isauthenticator(eap) == TRUE)
    {
      SSH_ASSERT(cas != NULL);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating server streams"));

      /* Create stream filters to intercept packets going in/out of EAP */
      state->eap_filter_stream =
        ssh_stream_filter_create(state->eap_streampair,
                                 16384, /* the max size of a TLS record */
                                 NULL_FNPTR,
                                 ssh_eap_to_stream_server_filter,
                                 NULL_FNPTR, state);
    }
  else
    {
      SSH_ASSERT(cas == NULL);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating client streams"));

      /* Create stream filters to intercept packets going in/out of EAP */
      state->eap_filter_stream =
        ssh_stream_filter_create(state->eap_streampair,
                                 16384, /* the max size of a TLS record */
                                 NULL_FNPTR,
                                 ssh_eap_to_stream_client_filter,
                                 NULL_FNPTR, state);
    }

  if (state->eap_filter_stream == NULL)
    {
      ssh_stream_destroy(state->eap_streampair);
      ssh_stream_destroy(state->tls_streampair);
      state->eap_streampair = NULL;
      state->tls_streampair = NULL;
      return FALSE;
    }

  ssh_stream_set_callback(state->eap_filter_stream,
                          ssh_eap_eap_stream_callback,
                          state);

  /* Read from the EAP filter stream until failure so that
     ssh_eap_to_stream_XXX_filter() will be called as soon as input data
     is available */
  while (dummy_bytes_read > 0)
    {
      dummy_bytes_read = ssh_stream_read(state->eap_filter_stream,
                                         dummy, sizeof(dummy));

      SSH_DEBUG(SSH_D_MY, ("Read %d bytes", dummy_bytes_read));
    }

  ssh_tls_configuration_defaults(&configuration);
  /* Must use TLS version v1.0 or higher. */
  configuration.flags |= (SSH_TLS_TLS | SSH_TLS_TLS1_1);
  configuration.flags &= ~(SSH_TLS_SSL2 | SSH_TLS_SSL3);

  if (state->crl_check_pol)
    configuration.crl_check_policy = state->crl_check_pol;

  SSH_DEBUG(SSH_D_HIGHOK, ("CM is handle is %p, crl checking %x", state->cm,
                           configuration.crl_check_policy));

  if (state->cm == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("No certificate manager available, cannot continue"));
      return FALSE;
    }

  /* Integration with external certificate libraries e.g. MSCAPI is not yet
     supported. */
  configuration.cert_manager = state->cm;
  configuration.private_key = NULL;
  configuration.app_callback = ssh_eap_tls_app_hook;
  configuration.app_callback_context = state;

  if (ssh_eap_isauthenticator(eap) == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Making server wrap"));

      configuration.is_server = TRUE;
      configuration.flags |= (SSH_TLS_CLIENTAUTH | SSH_TLS_STRICTAUTH);
      configuration.suggested_ca_distinguished_names = cas;

      state->tls_wrapped_stream = ssh_tls_server_wrap(state->tls_streampair,
                                                      &configuration);
    }
  else
    {
      configuration.is_server = FALSE;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Making client wrap"));

      state->tls_wrapped_stream = ssh_tls_client_wrap(state->tls_streampair,
                                                      &configuration);
    }


  if (state->tls_wrapped_stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("TLS client stream wrapping failed"));
      return FALSE;
    }

  return TRUE;
}


/* ********************************************************************* */

/* Routines for encapsulating TLS records in EAP and forwarding them to
   the EAP state machine. */

/* ********************************************************************* */

/* Encapsulate the TLS record encoded in the 'record' buffer in one or more
   EAP packets and arrange for the sending of the EAP packets. */
void
ssh_eap_tls_output_tls_record(SshEapTlsState state,
                              const unsigned char *record,
                              size_t record_len,
                              Boolean buffer_only)
{
  SSH_ASSERT(state != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS output record"));

  if (!state->out_buffer)
    {
      SSH_ASSERT(state->sent_bytes == 0);
      state->out_buffer = ssh_buffer_allocate();
    }

  if (!state->out_buffer)
    goto fail;

  if (ssh_buffer_append(state->out_buffer, record, record_len)
      != SSH_BUFFER_OK)
    {
      ssh_buffer_free(state->out_buffer);
      state->out_buffer = NULL;
      goto fail;
    }

  if (buffer_only == TRUE)
    {
      /* Caller requested us to buffer only the packet. Wait for
         a while then. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Buffered packet."));
      return;
    }

  /* No need to go sending, we are already waiting for
     ack from AAA server. */
  if (state->out_waiting_ack)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiting for EAP-TLS ack from remote end, "
                                   "not sending until ack received."));
      return;
    }

  /* Wait for a while until we get a buffer sized of full fragment (of course
     only when we are expecting for more records to come). */
  if ((ssh_buffer_len(state->out_buffer) < SSH_EAP_TLS_FRAGMENT_SIZE) &&
      state->more_records)
    return;

  ssh_eap_tls_continue_tlsrecord_send(state->protocol, state->eap);
  return;

 fail:
  ssh_eap_fatal(state->eap,
                state->protocol,
                "Out of memory, cannot output TLS record");
}

Boolean
ssh_eap_tls_continue_tlsrecord_send(SshEapProtocol protocol,
                                    SshEap eap)
{
  SshEapTlsState state = NULL;
  SshUInt8 flags = 0;
  SshUInt16 send_len = 0;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(protocol != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  SSH_ASSERT(state != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending TLS record length %d",
                               ssh_buffer_len(state->out_buffer)));

  if ((ssh_buffer_len(state->out_buffer) > SSH_EAP_TLS_FRAGMENT_SIZE) ||
      state->more_records)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Fragmenting EAP-TLS packet (length=%d)",
                                   ssh_buffer_len(state->out_buffer)));

      /* Either fragmentation is needed since the buffer length
         is more than our fragment size, or else we have still
         more data to send even though the length did not exceed
         the fragment size. In both cases we set the MF bit to the
         EAP-TLS message. */
      flags |= SSH_EAP_TLS_FLAGS_MF_BIT;
      state->out_waiting_ack = TRUE;

      if (state->sent_fragments == 0)
        flags |= SSH_EAP_TLS_FLAGS_LENGTH_BIT;

      state->sent_fragments++;

      if (ssh_buffer_len(state->out_buffer) > SSH_EAP_TLS_FRAGMENT_SIZE)
        send_len = SSH_EAP_TLS_FRAGMENT_SIZE;
      else
        send_len = (SshUInt16)ssh_buffer_len(state->out_buffer);
    }
  else   /* Otherwise this is the last packet to the authenticator. */
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Non-fragmented EAP-TLS packet (length=%d)",
                                   ssh_buffer_len(state->out_buffer)));

      state->out_waiting_ack = FALSE;
      send_len = (SshUInt16)ssh_buffer_len(state->out_buffer);
    }

  ssh_eap_tls_send_message(protocol, eap, state->out_buffer,
                           send_len, flags, state->record_length);

  state->sent_bytes += send_len;
  ssh_buffer_consume(state->out_buffer, send_len);

  /* Is this buffer ended? */
  if (!ssh_buffer_len(state->out_buffer))
    {
      SSH_ASSERT(state->sent_bytes == state->record_length);

      state->sent_bytes = 0;
      state->sent_fragments = 0;
      state->record_length = 0;
      ssh_buffer_free(state->out_buffer);
      state->out_buffer = NULL;
    }
  return TRUE;
}


/* Generic function to send TLS replies.
   Common arguments which has to always exist:
   protocol and eap
   Arguments which vary by reply are:
   tls_buf - contains TLS library response to the
             previous message
   flags   - flags that has to be included in the message
   length  - only set when length is required by the flags
             in the message.
   As a return value:
   0 for indicating failure
   1 for indicating success sending the reply.
*/
Boolean
ssh_eap_tls_send_message(SshEapProtocol protocol,
                         SshEap eap,
                         SshBuffer tls_buf,
                         SshUInt32 length,
                         SshUInt8 flags,
                         SshUInt32 total_length)
{
  SshBuffer pkt     = NULL;
  SshUInt16 pkt_len = SSH_EAP_TLS_PKT_BASE_LEN;

  SSH_ASSERT(!(flags & SSH_EAP_TLS_FLAGS_RESERVED));
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(protocol != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP TLS send message processing (len %u)",
                               length));

  if (tls_buf)
    pkt_len += ((flags & SSH_EAP_TLS_FLAGS_LENGTH_BIT) ?
                length + 4 : length);

  if (!ssh_eap_isauthenticator(eap))
    pkt = ssh_eap_create_reply(eap, (SshUInt16)(pkt_len - 5),
                               protocol->impl->id);
  else
    pkt = ssh_eap_create_request(eap, (SshUInt16)(pkt_len - 5),
                                 protocol->impl->id);

  if (!pkt)
    {
      ssh_eap_fatal(eap, protocol, "Out of memory, cannot send"
                    "EAP-TLS message.");
      return FALSE;
    }

  /* Put the correct flags in to the message. */
  ssh_buffer_ptr(pkt)[5] = flags;
  if (ssh_buffer_append(pkt, &flags, sizeof(flags)) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(pkt);
      pkt = NULL;
      ssh_eap_fatal(eap, protocol, "Out of memory, cannot send "
                    "EAP-TLS message");

      return FALSE;
    }

  /* First fragment, set the length to the beginning of the
     message. */
  if (flags & SSH_EAP_TLS_FLAGS_LENGTH_BIT)
    {
      char c_len[4];

      SSH_PUT_32BIT(c_len, total_length);

      SSH_ASSERT(total_length != 0);

      SSH_DEBUG_HEXDUMP(SSH_D_MY, ("Including length %d", total_length),
                        c_len, 4);

      if (ssh_buffer_append(pkt, c_len, 4) != SSH_BUFFER_OK)
        {
          ssh_buffer_free(pkt);
          pkt = NULL;
          ssh_eap_fatal(eap, protocol, "Out of memory, cannot send "
                        "EAP-TLS message");

          return FALSE;
        }
    }

  /* Copy the tls_buf in and let the packet go. */
  if (tls_buf)
    {
      if (ssh_buffer_append(pkt, ssh_buffer_ptr(tls_buf),
                            length) != SSH_BUFFER_OK)
        {
          ssh_buffer_free(pkt);
          pkt = NULL;
          ssh_eap_fatal(eap, protocol, "Out of memory, cannot send "
                        "EAP-TLS message");
          return FALSE;
        }
    }

  SSH_DEBUG_HEXDUMP(10, ("Send message"), ssh_buffer_ptr(pkt),
                    ssh_buffer_len(pkt));

  if (ssh_eap_isauthenticator(eap))
    ssh_eap_protocol_send_request(protocol, eap, pkt);
  else
    ssh_eap_protocol_send_response(protocol, eap, pkt);

  return TRUE;
}

/* ********************************************************************* */

/* Routines for handling input EAP packets, decapsulating any TLS records
   and forwarding the records to the TLS module. */

/* ********************************************************************* */

/* We have a two stage state machine in the EAP-TLS.
   The Initial state and then just 'pass-by' state
   when the conversation is ongoing with the TLS
   library and the TLS server. Therefore we quite
   strictly check the start message, since it's the
   only message we almost can validate that it has
   reasonable contents. */
Boolean
ssh_eap_tls_recv_start(SshEapProtocol protocol,
                       SshEap eap,
                       SshBuffer buf)
{
  SshEapTlsState state = NULL;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP TLS received start message"));

  state = ssh_eap_protocol_get_state(protocol);
  SSH_ASSERT(state != NULL);

  if (ssh_buffer_len(buf) != SSH_EAP_TLS_PKT_BASE_LEN)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid packet length %d",
                             ssh_buffer_len(buf)));
      goto fail;
    }

  /* Check the flags that they are correct. */
  if (!(ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_S_BIT))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid flags (%X), failing negotiation",
                             ssh_buffer_ptr(buf)[5]));
      goto fail;
    }

  if (!ssh_eap_tls_check_reserved_flags(buf))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Some reserved flag is set (%X), failing negotiation",
                 ssh_buffer_ptr(buf)[5]));
      goto fail;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Requesting TLS open from application"));

  state->tls_cas = NULL;

  if (!ssh_eap_tls_open(state, NULL))
    goto fail;
  return TRUE;

 fail:
  /* We have a failure. Finish the whole conversation,
     since we are not that intrested in conversation
     if the server misbehaves or something has failed in
     our side. */
  ssh_eap_discard_packet(eap, protocol, buf,
                         "Start message processing failed");

  ssh_eap_protocol_auth_fail(protocol, eap,
                             SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
  return FALSE;
}


Boolean
ssh_eap_tls_recv_ack(SshEapProtocol protocol,
                     SshEap eap, SshBuffer buf)
{
  SshEapTlsState state   = NULL;
  SshUInt16 msg_len = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP client ack received"));

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  SSH_ASSERT(state != NULL);

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);

  /* Check the flags are correct. */
  if ((ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_S_BIT) ||
      !ssh_eap_tls_check_reserved_flags(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf, "Invalid message flags"
                             "at waiting ack");
      return FALSE;
    }

  if (ssh_buffer_len(buf) != SSH_EAP_TLS_PKT_BASE_LEN ||
      msg_len != SSH_EAP_TLS_PKT_BASE_LEN)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "Invalid message length"
                             "at waiting ack");
      return FALSE;
    }

  state->out_waiting_ack = FALSE;

  /* If we are waiting for more records and there is not enough
     buffer for maximum size message, wait for a while... */
  if (state->out_buffer == NULL ||
      (ssh_buffer_len(state->out_buffer) < SSH_EAP_TLS_FRAGMENT_SIZE &&
       state->more_records))
    return TRUE;

  /* Continue our output buffer sending to the GW (actually to AAA) */
  ssh_eap_tls_continue_tlsrecord_send(protocol, eap);
  return TRUE;
}

Boolean
ssh_eap_tls_recv_generic_msg(SshEapProtocol protocol,
                                    SshEap eap,
                                    SshBuffer buf)
{
  SshEapTlsState state = NULL;
  SshUInt16 msg_len = 0;
  SshUInt16 msg_offset = SSH_EAP_TLS_PKT_BASE_LEN;
  Boolean non_first_frag;
  int bytes_written = 0;
  Boolean was_receiving_frags = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS generic message received"));

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  SSH_ASSERT(state != NULL);

  was_receiving_frags = state->in_receiving_frags == 1 ? TRUE : FALSE;

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);
  if (msg_len <= SSH_EAP_TLS_PKT_BASE_LEN)
    {
      ssh_eap_discard_packet(eap, protocol, buf, "Received a message "
                             "with too short length");
      return FALSE;
    }

  /* Check SBIT and reserved bits in flags. */
  if ((ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_S_BIT) ||
      !ssh_eap_tls_check_reserved_flags(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf, "Received a message "
                             "with invalid flags");
      return FALSE;
    }

  non_first_frag = state->in_receiving_frags ? TRUE : FALSE;

  /* Check for fragmented message */
  if (ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_MF_BIT)
    {
      if (!state->in_receiving_frags &&
          !(ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_LENGTH_BIT))
        {
          ssh_eap_discard_packet(eap, protocol, buf, "Packet received with "
                                 "Invalid flags");
          return FALSE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Receiving fragmented packet."));
          state->in_receiving_frags = 1;
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Sending acknowledgement for fragment"));
      ssh_eap_tls_send_message(protocol, eap, NULL, 0, 0, 0);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Received not fragmented packet. Last"
                                   " packet frag: %s", was_receiving_frags ?
                                   "<yes>" : "<no>"));
      state->in_receiving_frags = 0;
    }

  if (ssh_buffer_ptr(buf)[5] & SSH_EAP_TLS_FLAGS_LENGTH_BIT)
    msg_offset += SSH_EAP_TLS_IE_LENGTH_LEN;

  /* Remove EAP-TLS message headers and forward the message
     to the TLS module */
  ssh_buffer_consume(buf, msg_offset);

  /* Check to see if we have received a TLS ALERT message from
     the TLS server. Only do this for the first EAP-TLS fragment
     of the TLS message, or message that are not fragments. */
  if (!non_first_frag)
    {
      if ((ssh_buffer_len(buf) > 2) &&
          (ssh_buffer_ptr(buf)[1] == 3) &&
          (ssh_buffer_ptr(buf)[0] == 21))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Received TLS alert"));
          state->alert_received = TRUE;
        }
    }

  /* Have we already buffered incoming data? */
  if (state->in_buffer || state->in_receiving_frags)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Buffering packet %p %u",
                                   state->in_buffer,
                                   state->in_receiving_frags));

      if (!state->in_buffer)
        state->in_buffer = ssh_buffer_allocate();

      if (!state->in_buffer)
        {
          ssh_eap_discard_packet(eap, protocol, buf,
                                 "Inbound packet buffering failed.");
          return FALSE;
        }

      if (ssh_buffer_append(state->in_buffer, ssh_buffer_ptr(buf),
                            ssh_buffer_len(buf)) != SSH_BUFFER_OK)
        {
          ssh_buffer_free(state->in_buffer);
          state->in_buffer = NULL;
          ssh_eap_discard_packet(eap, protocol, buf,
                                 "Inbound packet buffering failed.");
          return FALSE;
        }

      if (was_receiving_frags && !state->in_receiving_frags)
        goto send_out;

      return TRUE;
    }

 send_out:

  if (state->in_buffer && state->in_receiving_frags == 0)
    {
      bytes_written = ssh_stream_write(state->eap_filter_stream,
                                       ssh_buffer_ptr(state->in_buffer),
                                       ssh_buffer_len(state->in_buffer));

      SSH_DEBUG(SSH_D_MIDOK, ("Wrote %d bytes from in_buffer to TLS. "
                              "In_buffer length %u",
                              bytes_written,
                              ssh_buffer_len(state->in_buffer)));

      if (bytes_written != ssh_buffer_len(state->in_buffer))
        {
          ssh_buffer_consume(state->in_buffer, bytes_written);
        }
      else
        {
          ssh_buffer_free(state->in_buffer);
          state->in_buffer = NULL;
        }
    }
  else
    {
      bytes_written = ssh_stream_write(state->eap_filter_stream,
                                       ssh_buffer_ptr(buf),
                                       ssh_buffer_len(buf));

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Wrote %d bytes from buf to TLS."
                                   " Buffer length", bytes_written,
                                   ssh_buffer_len(buf)));

      if (bytes_written != ssh_buffer_len(buf))
        {
          /* We couldn't write the whole stuff to the stream,
             we'll have to do it in delayed manner. Continue
             writing when the filter stream tells us that
             we can continue writing...
             So now make a new buffer for storing the input
             messages. */

          SSH_ASSERT(state->in_buffer == NULL);

          /* Take the written bytes away. */
          if (bytes_written > 0)
            ssh_buffer_consume(buf, bytes_written);

          state->in_buffer = ssh_buffer_allocate();

          if (ssh_buffer_append(state->in_buffer, ssh_buffer_ptr(buf),
                                ssh_buffer_len(buf)) != SSH_BUFFER_OK)
            {
              ssh_buffer_free(state->in_buffer);
              state->in_buffer = NULL;
              ssh_eap_discard_packet(eap, protocol, buf, "Inbound packet"
                                     " buffering failed.");
              return FALSE;
            }
        }
    }

  return TRUE;

}

/* General routine to receive EAP-TLS client side packets. */
void
ssh_eap_tls_client_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapTlsState state = NULL;
  SshUInt16 msg_len = 0;
  Boolean ok = FALSE;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);

  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP TLS state uninitialized");
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP Client received message, conversation "
                               "state %d", state->conversation_state));

  /* Here we handle only EAP-TLS specific messages. some notifications
     and Identity requests etc... are handled in ssheap_common. */
  if (ssh_buffer_len(buf) < 6)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet too short to be eap TLS request");
      return;
    }

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);
  if (msg_len != ssh_buffer_len(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP TLS msg length invalid");
      return;
    }

  switch (state->conversation_state)
    {
      /* Initial state. Nothing happened yet. */
    case SSH_EAP_TLS_STATE_INITIAL:
      ok = ssh_eap_tls_recv_start(protocol, eap, buf);
      state->conversation_state = SSH_EAP_TLS_STATE_TLS_CLIENT_HELLO;
      break;

      /* Server has started the conversation in the earlier state
         and now we are only receiving and forwarding messages between
         TLS lib and AAA server. We do not understand at all the TLS
         protocol here and therefore at the moment we rely on:

         1. AAA server will indicate success / failure.
         2. TLS lib / PM will notify timeout or failure somehow.

         Only thing that is book keeped at this stage is the messaging
         state. So the protocol (EAP-TLS) is monitored to be in decent
         state. */
    case SSH_EAP_TLS_STATE_TLS_CLIENT_HELLO:
    case SSH_EAP_TLS_STATE_TLS_SERVER_HELLO:
    case SSH_EAP_TLS_STATE_FINISHED:

      state->conversation_state = SSH_EAP_TLS_STATE_TLS_SERVER_HELLO;

      if (state->out_waiting_ack)
        ok = ssh_eap_tls_recv_ack(protocol, eap, buf);
      else
        ok = ssh_eap_tls_recv_generic_msg(protocol, eap, buf);
      break;

    default:
      ssh_eap_fatal(eap, protocol, "EAP-TLS state machine invalid state");
      break;
    }

  /* Something failed. Policymanager cleans up the state by calling the
     EAP destroy. */
  if (!ok)
    {
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
    }
}

/* General routine to receive EAP-TLS client side packets. */
void
ssh_eap_tls_server_recv_msg(SshEapProtocol protocol,
                            SshEap eap,
                            SshBuffer buf)
{
  SshEapTlsState state = NULL;
  SshUInt16 msg_len = 0;
  Boolean ok = FALSE;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  state = ssh_eap_protocol_get_state(protocol);
  if (state == NULL)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP TLS state uninitialized");
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS Server received message"));

  /* Here we handle only EAP-TLS specific messages. some notifications
     and Identity requests etc... are handled in ssheap_common. */
  if (ssh_buffer_len(buf) < 6)
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "packet too short to be eap TLS request");
      return;
    }

  msg_len = SSH_GET_16BIT(ssh_buffer_ptr(buf) + 2);
  if (msg_len != ssh_buffer_len(buf))
    {
      ssh_eap_discard_packet(eap, protocol, buf,
                             "EAP TLS msg length invalid");
      return;
    }

  if (state->out_waiting_ack ||
      (state->conversation_state == SSH_EAP_TLS_STATE_FINISHED))
    ok = ssh_eap_tls_recv_ack(protocol, eap, buf);
  else
    ok = ssh_eap_tls_recv_generic_msg(protocol, eap, buf);

  if (ok && state->conversation_state == SSH_EAP_TLS_STATE_FINISHED)
      ssh_eap_protocol_auth_ok(protocol, eap,
                               SSH_EAP_SIGNAL_NONE, NULL);

  /* Something failed. Policymanager cleans up the state by calling the
     EAP destroy. */
  if (!ok)
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
}

static void
ssh_eap_tls_server_send_start(SshEapProtocol protocol,
                              SshEap eap)
{
  SshBuffer req;
  SshUInt8 flags = SSH_EAP_TLS_FLAGS_S_BIT;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending EAP-TLS start message"));

  if ((req = ssh_eap_create_request(eap, 1, SSH_EAP_TYPE_TLS)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS start message creation "
                             "failed"));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
      return;
    }

  if (ssh_buffer_append(req, &flags, 1) != SSH_BUFFER_OK)
    {
      ssh_buffer_free(req);
      req = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS start message creation "
                             "failed"));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
      return;
    }

  ssh_eap_protocol_send_request(protocol, eap, req);
}

static void
ssh_eap_tls_server_continue_initialisation(SshEapProtocol protocol,
                                           SshEap eap,
                                           unsigned char **cas)
{
  SshEapTlsState s;
  unsigned char **new_cas;
  int cnt;
  int i;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS server continuing initialisation."));

  s = ssh_eap_protocol_get_state(protocol);
  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS state not initialised. Can "
                             "not continue authentication."));
      return;
    }

  /* Count how many items we got. */
  for (cnt = 0; cas[cnt]; cnt++)
    ;

  /* Allocate 1 extra, TLS library expects the NULL
     in the end as end marker. */
  new_cas = ssh_calloc(cnt + 1, sizeof(unsigned char *));
  if (new_cas == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS memory allocation for CA's failed."));

      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
      return;
    }

  /* Copy the CA strings. Allocate the memory and copy... */
  for (i = 0; i < cnt; i++)
    {
      new_cas[i] = ssh_memdup(cas[i], strlen(cas[i]));
      if (new_cas[i] == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS memory allocation for "
                                 "CA failed."));
          ssh_eap_protocol_auth_fail(protocol, eap,
                                     SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                     NULL);

          goto error;
        }
    }

  s->tls_cas = new_cas;
  if (ssh_eap_tls_open(s, new_cas) != TRUE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS TLS library initialisation failed."));
      ssh_eap_protocol_auth_fail(protocol, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION, NULL);
      goto error;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Requesting a private key token"));
  ssh_eap_protocol_request_token(s->eap, s->protocol->impl->id,
                                 SSH_EAP_TOKEN_PRIVATE_KEY);

  return;

 error:

  /* Free the memory used for CA's */
  for (i = 0; new_cas && new_cas[i]; i++)
    ssh_free(new_cas[i]);

  if (new_cas)
    ssh_free(new_cas);
}

void
ssh_eap_tls_recv_token(SshEapProtocol protocol, SshEap eap,
                       SshBuffer buf)
{
  SshEapTokenType token_type;
  SshPrivateKey prvkey;
  SshEapToken token;
  SshEapTlsState state;
  unsigned char *id_data = NULL;
  size_t id_data_size = 0;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(buf != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS received token"));

  token_type = ssh_eap_get_token_type_from_buf(buf);
  token = (SshEapToken)ssh_buffer_ptr(buf);

  state = ssh_eap_protocol_get_state(protocol);
  if (state == NULL)
    {
      ssh_eap_discard_token(eap, protocol, buf,
                            "EAP-TLS instance uninitialized");
      return;
    }

  switch (token_type)
    {
    case SSH_EAP_TOKEN_PRIVATE_KEY:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Continuing EAP-TLS protocol state"));

      if (token->token.prvkey.private_key == NULL)
        {
          ssh_eap_fatal(state->eap, state->protocol,
                        "Failed to retrieve private key");
          return;
        }

      if (ssh_private_key_copy(token->token.prvkey.private_key, &prvkey)
          != SSH_CRYPTO_OK)
        {
          ssh_eap_fatal(state->eap, state->protocol,
                        "Out of memory, cannot copy private key");
          return;
        }


       if (token->token.prvkey.id_data != NULL)
         {
           id_data = ssh_memdup(token->token.prvkey.id_data,
                                token->token.prvkey.id_data_size);

           if (id_data == NULL)
             {
               /* This is actually not a critical failure, since we can
                  do without the identity */
               SSH_DEBUG(SSH_D_FAIL,
                         ("Out of memory while duplicating identity"));
               id_data_size = 0;
             }
           else
             {
               id_data_size = token->token.prvkey.id_data_size;
             }
         }

      state->prvkey = prvkey;
      state->id_data = id_data;
      state->id_data_size = id_data_size;

      ssh_tls_set_private_key(state->tls_wrapped_stream,
                              prvkey, id_data, id_data_size);

      if (ssh_eap_isauthenticator(eap) == TRUE)
        {
          ssh_eap_tls_server_send_start(protocol, eap);
        }

      break;

    case SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY:
      {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Certificate authority token received."));

        if (token->token.cas == NULL)
          {
            ssh_eap_fatal(state->eap, state->protocol,
                          "Failed to retrieve certificate authorities.");
            return;
          }

        ssh_eap_tls_server_continue_initialisation(protocol, eap,
                                                   token->token.cas);

        break;
      }

    default:
      ssh_eap_discard_token(eap, protocol, buf,
                            ("unexpected token type"));
      return;
    }
}


static void
ssh_eap_tls_server_begin(SshEapProtocol protocol,
                         SshEap eap)
{
  SshEapTlsState s;

  SSH_ASSERT(protocol != NULL);
  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP-TLS server begin requested."));

  s = ssh_eap_protocol_get_state(protocol);
  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EAP-TLS state not initialised. Can "
                             "not start authentication."));
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Requesting a certificate authority token"));
  ssh_eap_protocol_request_token(s->eap, s->protocol->impl->id,
                                 SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY);
}
#endif /* SSHDIST_EAP_TLS */

/* Following functions are always available, even though
   EAP-TLS support is not compiled in. */
void* ssh_eap_tls_create(SshEapProtocol protocol,
                         SshEap eap, SshUInt8 type)
{
#ifdef SSHDIST_EAP_TLS
  SshEapTlsState state;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP TLS create"));

  state = ssh_calloc(1, sizeof(*state));
  if (!state)
    return state;

  state->eap = eap;
  state->protocol = protocol;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("created eap tls auth state"));

  return state;
#else /* SSHDIST_EAP_TLS */
  return NULL;
#endif /* SSHDIST_EAP_TLS */
}

void
ssh_eap_tls_destroy(SshEapProtocol protocol,
                    SshUInt8 type, void *state)
{
#ifdef SSHDIST_EAP_TLS
  SshEapTlsState s;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP TLS destroy"));

  s = ssh_eap_protocol_get_state(protocol);

  if (s != NULL)
    {
      if (s->out_buffer)
          ssh_buffer_free(s->out_buffer);

      if (s->in_buffer)
        {
          ssh_buffer_free(s->in_buffer);
          s->in_buffer = NULL;
        }

      if (s->tls_wrapped_stream)
        ssh_stream_destroy(s->tls_wrapped_stream);

      if (s->eap_filter_stream)
        ssh_stream_destroy(s->eap_filter_stream);

      if (s->tls_cas)
        {
          int i = 0;

          for (i = 0; s->tls_cas[i] != NULL; i++)
            ssh_free(s->tls_cas[i]);

          ssh_free(s->tls_cas);
        }

      if (s->prvkey)
        ssh_private_key_free(s->prvkey);

      if (s->id_data)
        ssh_free(s->id_data);

      ssh_free(s);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls state destroyed"));
#endif /* SSHDIST_EAP_TLS */
}

void
ssh_eap_tls_recv_params(SshEapProtocol protocol,
                        SshEap eap,
                        SshBuffer buf)
{
#ifdef SSHDIST_EAP_TLS
  SshEapTlsState tls;
  SshEapTlsParams params;

  tls = ssh_eap_protocol_get_state(protocol);

  params = (SshEapTlsParams)ssh_buffer_ptr(buf);

  if (ssh_buffer_len(buf) != sizeof(*params))
    {
      SSH_DEBUG(SSH_D_FAIL,("received paramas struct of incorrect size"));
      return;
    }

  tls->cm = params->cm;
  tls->crl_check_pol = params->crl_check_pol;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Set TLS cm to %p, flags %x", tls->cm,
                               tls->crl_check_pol));
#endif /* SSHDIST_EAP_TLS */
}


SshEapOpStatus
ssh_eap_tls_signal(SshEapProtocolSignalEnum sig,
                   SshEap eap,
                   SshEapProtocol protocol,
                   SshBuffer buf)
{
#ifdef SSHDIST_EAP_TLS
  SshEapTlsState state;

  state = ssh_eap_protocol_get_state(protocol);

  if (state == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("EAP-TLS not initialized, discarding signal"));
      return SSH_EAP_OPSTATUS_SUCCESS;
    }

  /* If we are the passby authenticator, we shouldn't
     be getting any of these signals... */
  if (ssh_eap_isauthenticator(eap) == TRUE)
    {
      switch (sig)
        {
        case SSH_EAP_PROTOCOL_RESET:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls signal protocol reset"));
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls signal protocol begin"));
          ssh_eap_tls_server_begin(protocol, eap);
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_tls_server_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          ssh_eap_tls_recv_token(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls receive params"));
          ssh_eap_tls_recv_params(protocol, eap, buf);
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
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls signal protocol reset"));
          break;

        case SSH_EAP_PROTOCOL_RECV_PARAMS:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls receive params"));
          ssh_eap_tls_recv_params(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_BEGIN:
          SSH_ASSERT(buf == NULL);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("eap tls signal protocol begin"));
          break;

        case SSH_EAP_PROTOCOL_RECV_MSG:
          SSH_ASSERT(buf != NULL);
          ssh_eap_tls_client_recv_msg(protocol, eap, buf);
          break;

        case SSH_EAP_PROTOCOL_RECV_TOKEN:
          ssh_eap_tls_recv_token(protocol, eap, buf);
          break;

        default:
          SSH_NOTREACHED;
        }
    }

#endif /* SSHDIST_EAP_TLS */
  return SSH_EAP_OPSTATUS_SUCCESS;
}

SshEapOpStatus
ssh_eap_tls_key(SshEapProtocol protocol,
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

  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("64 byte EAP-TLS MSK"),
                    eap->msk, eap->msk_len);

  return SSH_EAP_OPSTATUS_SUCCESS;
}
