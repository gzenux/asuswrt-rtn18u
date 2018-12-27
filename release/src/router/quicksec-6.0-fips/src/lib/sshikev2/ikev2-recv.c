/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 packet receive.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "sshikev2-fallback.h"
#include "isakmp_internal.h"
#include "isakmp.h"
#endif /* SSHDIST_IKEV1 */


#define SSH_DEBUG_MODULE "SshIkev2NetReceive"


SshTime
ssh_ikev2_sa_last_input_packet_time(SshIkev2Sa sa)
{
#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      return sa->last_input_stamp;
    }

#endif /* SSHDIST_IKEV1 */

  return sa->last_input_packet_time;
}


SshUInt32 ikev2_udp_sa_half_hash(const void *p, void *context)
{
  SshIkev2Half half = (SshIkev2Half) p;
  SshUInt32 hash = 0;
  int i;

  hash = half->remote_port;
  hash ^= SSH_IP_HASH(half->remote_ip);

  for (i = 0; i < sizeof(half->ike_spi_i); i++)
    {
      hash += half->ike_spi_i[i];
      hash += hash << 10;
      hash ^= hash >> 6;
    }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

int ikev2_udp_sa_half_compare(const void *p1, const void *p2, void *context)
{
  SshIkev2Half h1 = (SshIkev2Half) p1;
  SshIkev2Half h2 = (SshIkev2Half) p2;
  int ret;

  ret = memcmp(h1->ike_spi_i, h2->ike_spi_i, sizeof(h1->ike_spi_i));
  if (ret == 0)
    ret = (h1->remote_port - h2->remote_port);
  if (ret == 0)
    ret = SSH_IP_CMP(h1->remote_ip, h2->remote_ip);
  return ret;
}

void ikev2_udp_sa_half_free(void *obj, void *context)
{
  ssh_free(obj);
}

void ikev2_packet_destroy(SshFSM fsm, void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2 ikev2 = ssh_fsm_get_gdata_fsm(fsm);
  SshIkev2Sa ike_sa;
  Boolean free_ike_sa = TRUE;

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART, ("Destructor"));
  packet->destroyed = 1;

#ifdef SSHDIST_IKEV1
  /* If this is a packet to an existing IKEv1 SA, then do not free
     the IKE SA, except if we are just about fall back to IKEv1 */
  if ((packet->ike_sa &&
        (packet->ike_sa == (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA ||
        packet->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
      && packet->error != SSH_IKEV2_ERROR_USE_IKEV1)
    free_ike_sa = FALSE;
#endif /* SSHDIST_IKEV1 */

  ike_sa = packet->ike_sa;

  if (packet->operation)
    {
      ssh_operation_abort(packet->operation);
      packet->operation = NULL;
    }

  if (!packet->in_window)
    {
      ikev2_packet_free(ikev2, packet);
    }

  if (free_ike_sa && ike_sa != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("F: IKE SA REFCNT: %d",
                                    (int) ike_sa->ref_cnt));
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }
}

/* return zeroed packet or NULL. Initialized the packet to start
   executing state machine at the given start state. If ikev2 is given as
   NULL this packet will not be allocated from pool */
SshIkev2Packet
ikev2_packet_allocate(SshIkev2 ikev2, SshFSMStepCB start)
{
  SshIkev2Packet packet;

  SSH_ASSERT(ikev2 != NULL);

  if (ssh_adt_num_objects(ikev2->packets_free) > 0)
    {
      packet = ssh_adt_detach_from(ikev2->packets_free, SSH_ADT_BEGINNING);
      SSH_DEBUG(SSH_D_HIGHOK, ("Allocated packet %p from freelist", packet));
    }
  else
    {
      if ((packet = ssh_calloc(1, sizeof(*packet))) == NULL)
        return NULL;
      SSH_DEBUG(SSH_D_HIGHOK, ("Allocated packet %p from heap", packet));
    }

  memset(packet->freelist_header, 0, sizeof(packet->freelist_header));

#ifdef DEBUG_LIGHT
  {
    SshIkev2PacketStruct empty;
    memset(&empty, 0, sizeof(empty));

    /* Check that no-one has modified the packet on the freelist */
    SSH_ASSERT(memcmp(packet, &empty, sizeof(empty)) == 0);
  }
#endif /* DEBUG_LIGHT */

  ssh_adt_insert(ikev2->packets_used, packet);

  if (start != NULL_FNPTR)
    {
      packet->thread_started = 1;
      ssh_fsm_thread_init(ikev2->fsm, packet->thread,
                          start, NULL_FNPTR, ikev2_packet_destroy,
                          packet);
      ssh_fsm_set_thread_name(packet->thread, "packet thread");
    }
  else
    packet->thread_started = 0;

  packet->sent = 0;
  packet->in_window = 0;
  packet->destroyed = 0;

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART, ("Allocating"));
  return packet;
}

void
ikev2_packet_free(SshIkev2 ikev2, SshIkev2Packet packet)
{
  SSH_IKEV2_DEBUG(SSH_D_MIDSTART, ("Freeing"));

  SSH_ASSERT(!packet->in_window);

  if (packet->ed)
    {
      if (packet->ed->response_packet == packet)
        packet->ed->response_packet = NULL;

      if (packet->ed->packet_to_process == packet)
        packet->ed->packet_to_process = NULL;
      ikev2_free_exchange_data(packet->ed->ike_sa, packet->ed);
    }
  ssh_cancel_timeout(packet->timeout);
  ssh_free(packet->encoded_packet);

  ssh_adt_detach_object(ikev2->packets_used, packet);

  memset(packet, 0, sizeof(*packet));
  if (ikev2->params.packet_cache_size == 0
      || (ssh_adt_num_objects(ikev2->packets_free) <
          ikev2->params.packet_cache_size))
    ssh_adt_insert(ikev2->packets_free, packet);
  else
    ssh_free(packet);
}

/* This function schedules a packet in window to be freed. It does
   nothing for packets that are not in window */
void
ikev2_packet_done(SshIkev2Packet packet)
{
  SshIkev2 ikev2 = packet->server->context;

  SSH_ASSERT(packet->in_window == 0);

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART,
                  ("Scheduling packet (m-id=%ld) to be freed",
                   (long) packet->message_id));

  if (packet->operation)
    {
      ssh_operation_abort(packet->operation);
      packet->operation = NULL;
    }

  SSH_ASSERT(packet->ed == NULL ||
             packet->ed->magic == SSH_IKEV2_ED_MAGIC);

  if (packet->thread_started && !packet->destroyed)
    {
      SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                      ("Not destroyed; "
                       "running to end state and terminating there."));
      ssh_fsm_set_next(packet->thread, ikev2_packet_st_done);

      /* This code path is entered both in normal exchange termination
         and in exchange abort scenarios where the packet thread might
         be waiting for policy call completion. Therefore
         SSH_FSM_CONTINUE_AFTER_EXCEPTION() is used. */
      SSH_FSM_CONTINUE_AFTER_EXCEPTION(packet->thread);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("Destroyed already. "
                                    "Thread completed. Freeing now."));
      ikev2_packet_free(ikev2, packet);
    }
}

/****************************************************************************
 * Internals
 */

/*
 * State machine for receiving packets
 */

SSH_FSM_STEP(ikev2_packet_st_input_start);
SSH_FSM_STEP(ikev2_packet_st_input_get_or_create_sa);
#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ikev2_packet_st_input_v1_get_sa);
SSH_FSM_STEP(ikev2_packet_st_input_v1_handle_ikev1_fallback);
SSH_FSM_STEP(ikev2_packet_st_input_v1_create_sa);
#endif /* SSHDIST_IKEV1 */
SSH_FSM_STEP(ikev2_packet_st_connect_decision);
SSH_FSM_STEP(ikev2_packet_st_allocated);
SSH_FSM_STEP(ikev2_packet_st_verify);
SSH_FSM_STEP(ikev2_packet_st_forward);
SSH_FSM_STEP(ikev2_packet_st_done);
#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ikev2_packet_v1_start);
#endif /* SSHDIST_IKEV1 */


static void
ikev2_packet_get_sa_cb(SshIkev2Error error,
                       SshIkev2Sa sa,
                       void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  packet->ike_sa = sa;
  packet->error = error;
}


SSH_FSM_STEP(ikev2_packet_st_input_start)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);

  /* When the packet reaches this step the IKE header has been parsed.
     The IKE major and minor versions have not yet been checked. */

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Processing received"));

  /* Drop all IKE packets if the listener is already gone. */
  if (packet->server->server_stopped_flags & SSH_IKEV2_SERVER_STOPPED_2)
    return SSH_FSM_FINISH;

  /* Drop packets while server is being stopped if they are IKEv1 or
     IKEv2 requests. We'll still pass responses. */
  if ((packet->server->server_stopped_flags & SSH_IKEV2_SERVER_STOPPED_1)
      && ((packet->major_version == 1)
          || ((packet->major_version == 2)
              && !(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))))
    return SSH_FSM_FINISH;

#ifdef SSHDIST_IKEV1
  /* Lookup IKE SA for IKEv1 packets. */
  if (packet->major_version == 1)
    {
      SSH_FSM_SET_NEXT(ikev2_packet_st_input_v1_get_sa);
      SSH_FSM_ASYNC_CALL({
        packet->operation = (*(packet->server->sad_interface->ike_sa_get))
          (packet->server->sad_handle, 1, packet->ike_spi_i, packet->ike_spi_r,
           ikev2_packet_get_sa_cb, packet);
      });
    }
#endif /* SSHDIST_IKEV1 */

  /* Lookup IKE SA assuming this is an IKEv2 packet. Note that IKE major
     and minor version numbers are not yet checked. */
  SSH_FSM_SET_NEXT(ikev2_packet_st_input_get_or_create_sa);

  /* Check half open IKE SAs. */
  if (packet->major_version == 2
      && packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
    {
      SshADTHandle handle;
      SshIkev2HalfStruct probe, *half;

      memcpy(probe.ike_spi_i, packet->ike_spi_i, sizeof(probe.ike_spi_i));
      probe.remote_port = packet->remote_port;
      *(probe.remote_ip) = *(packet->remote_ip);

      /* Check for the half SA entry for the initiator SPI. */
      handle = ssh_adt_get_handle_to_equal(ikev2->sa_half_by_spi, &probe);
      if (handle != SSH_ADT_INVALID)
        {
          /* We have half SA entry. */
          /* Check if this is retransmission of the first packet. */
          if (packet->message_id == 0 &&
              !(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
            {
              /* It is a retransmit. Now perform sanity check for cookie. */
              if (memcmp(packet->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) != 0)
                {
                  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                  ("Responder SPI is not zero"));
                  SSH_FSM_SET_NEXT(ikev2_packet_st_done);
                  return SSH_FSM_CONTINUE;
                }

              /* And finally assing the responder SPI assigned by the
                 first transmission. */
              half = ssh_adt_get(ikev2->sa_half_by_spi, handle);
              memcpy(packet->ike_spi_r, half->ike_spi_r,
                     sizeof(half->ike_spi_r));
              SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                              ("Retransmission for first packet; "
                               "replacing SPI %08lx %08lx",
                               SSH_GET_32BIT(packet->ike_spi_r),
                               SSH_GET_32BIT(packet->ike_spi_r + 4)));
            }
          else
            {
              /* This is not first packet, so we can remove half entry. */
              half = ssh_adt_get(ikev2->sa_half_by_spi, handle);
              ssh_adt_detach(ikev2->sa_half_by_spi, handle);
              ssh_free(half);
            }
        }
      else
        {
          /* No half SA found, search for the SA. */
        }
    }

  /* Lookup IKE SA for IKEv2 packet. */
  SSH_FSM_ASYNC_CALL({
    if (packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
      packet->operation = (*(packet->server->sad_interface->ike_sa_get))
        (packet->server->sad_handle, 2, NULL, packet->ike_spi_r,
         ikev2_packet_get_sa_cb, packet);
    else
      packet->operation = (*(packet->server->sad_interface->ike_sa_get))
        (packet->server->sad_handle, 2, packet->ike_spi_i, NULL,
         ikev2_packet_get_sa_cb, packet);
  });
}


static void
ikev2_packet_new_connection_cb(SshIkev2Error error, void *context)
{
  SshIkev2Packet packet = context;

  packet->error = error;
  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
}


SSH_FSM_STEP(ikev2_packet_st_input_get_or_create_sa)
{
  SshIkev2Packet packet = thread_context;

  if (packet->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Dropping packet because get return error %s (%d)",
                       ssh_ikev2_error_to_string(packet->error),
                       packet->error));
      SSH_FSM_SET_NEXT(ikev2_packet_st_done);
      return SSH_FSM_CONTINUE;
    }

  if (packet->ike_sa)
    {
#ifdef SSHDIST_IKEV1
      /* Assert that the found SA is not IKEv1. */
      SSH_ASSERT(packet->ike_sa != (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA);
      SSH_ASSERT((packet->ike_sa->flags
                  & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0);
#endif /* SSHDIST_IKEV1 */

      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Packet to existing v2 SA"));

      SSH_FSM_SET_NEXT(ikev2_packet_st_verify);

      /* Found old SA based on SPI. Verify that both initiator and responder
         IKE SPIs match. Allow zero responder IKE SPI for IKE_SA_INIT
         responses only if the responder IKE SPI has not been set for IKE SA.
         The responder IKE SPI is copied to IKE SA after the packet has been
         decoded successfully and checked for sanity. Note that allthough
         IKE SPI must never be zero except in IKE_SA_INIT requests, we still
         want to allow this for error replies to IKE_SA_INIT. */
      if (packet->message_id == 0
          && !(packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
          && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
          && (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
          && (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
          && (packet->ike_sa->initial_ed != NULL)
          && (packet->ike_sa->initial_ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
          && (memcmp(packet->ike_sa->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) == 0))
        {
#ifdef DEBUG_LIGHT
          /* Print debug message for packets with all-zeros responder SPI. */
          if (memcmp(packet->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) == 0)
            SSH_DEBUG(SSH_D_NETGARB,
                      ("Received packet with zero responder IKE SPI "
                       "I %08lx %08lx - R %08lx %08lx",
                       SSH_GET_32BIT(packet->ike_spi_i),
                       SSH_GET_32BIT(packet->ike_spi_i + 4),
                       SSH_GET_32BIT(packet->ike_spi_r),
                       SSH_GET_32BIT(packet->ike_spi_r + 4)));
#endif /* DEBUG_LIGHT */
        }
      else
        {
          if (memcmp(packet->ike_sa->ike_spi_r,
                     packet->ike_spi_r, sizeof(packet->ike_spi_r)) != 0 ||
              memcmp(packet->ike_sa->ike_spi_i,
                     packet->ike_spi_i, sizeof(packet->ike_spi_i)) != 0)
            {
              /* The IKE SPIs are not matching exactly to the old ones, drop
                 the packet. We have already used one of the SPIs to find the
                 SA, so other SPI must have been different than before. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Received packet with invalid IKE SPI "
                         "I %08lx %08lx - R %08lx %08lx vs "
                         "I %08lx %08lx - R %08lx %08lx",
                         SSH_GET_32BIT(packet->ike_spi_i),
                         SSH_GET_32BIT(packet->ike_spi_i + 4),
                         SSH_GET_32BIT(packet->ike_spi_r),
                         SSH_GET_32BIT(packet->ike_spi_r + 4),
                         SSH_GET_32BIT(packet->ike_sa->ike_spi_i),
                         SSH_GET_32BIT(packet->ike_sa->ike_spi_i + 4),
                         SSH_GET_32BIT(packet->ike_sa->ike_spi_r),
                         SSH_GET_32BIT(packet->ike_sa->ike_spi_r + 4)));
              SSH_FSM_SET_NEXT(ikev2_packet_st_done);
              return SSH_FSM_CONTINUE;
            }
        }

      return SSH_FSM_CONTINUE;
    }
  else
    {
      if (!(packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR))
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Dropping unknown responder packet."));
          SSH_FSM_SET_NEXT(ikev2_packet_st_done);
          return SSH_FSM_CONTINUE;
        }

      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                      ("No IKE SA for packet; "
                       "requesting permission to create one."));

      SSH_FSM_SET_NEXT(ikev2_packet_st_connect_decision);
      SSH_FSM_ASYNC_CALL({
        packet->operation = (*(packet->server->sad_interface->new_connect))
          (packet->server->sad_handle,
           packet->server,
           packet->major_version, packet->minor_version,
           packet->remote_ip, packet->remote_port,
           ikev2_packet_new_connection_cb,
           packet);
      });
    }

  SSH_NOTREACHED;
}


#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ikev2_packet_st_input_v1_get_sa)
{
  SshIkev2Packet packet = thread_context;

  /* Only IKEv1 packets come here. Minor version is checked in the
     isakmp library. */
  SSH_ASSERT(packet->major_version == 1);

  if (packet->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Dropping packet because get return error %s (%d)",
                       ssh_ikev2_error_to_string(packet->error),
                       packet->error));
      SSH_FSM_SET_NEXT(ikev2_packet_st_done);
      return SSH_FSM_CONTINUE;
    }

  if (packet->ike_sa)
    {
      /* Assert that the found SA is IKEv1. */
      SSH_ASSERT(packet->ike_sa == (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA);

      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Packet to existing v1 SA"));

      SSH_FSM_SET_NEXT(ikev2_packet_v1_start);
      return SSH_FSM_CONTINUE;
    }

  /* This is an informational exchange. Check for possible IKEv1 fallback.
     Lookup an IKEv2 SA using the initiator cookie from the IKEv1 packet. */
  if ((SshIkeExchangeType)packet->exchange_type == SSH_IKE_XCHG_TYPE_INFO)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Checking if unauthenticated IKEv1 notify is for "
                 "an IKEv2 SA"));
      SSH_FSM_SET_NEXT(ikev2_packet_st_input_v1_handle_ikev1_fallback);
      SSH_FSM_ASYNC_CALL({
        packet->operation = (*(packet->server->sad_interface->ike_sa_get))
          (packet->server->sad_handle, 2, packet->ike_spi_i, NULL,
           ikev2_packet_get_sa_cb, packet);
      });
    }

  /* Continue to create an IKEv1 SA. */
  SSH_FSM_SET_NEXT(ikev2_packet_st_input_v1_create_sa);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_packet_st_input_v1_handle_ikev1_fallback)
{
  SshIkev2Packet packet = thread_context;
  SshBuffer buffer = NULL;
  SshIkePacket isakmp_packet = NULL;
  SshIkePayload isakmp_payload;

  /* Only IKEv1 packets come here. Minor version is checked in the
     isakmp library. */
  SSH_ASSERT(packet->major_version == 1);

  if (packet->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Dropping packet because get return error %s (%d)",
                       ssh_ikev2_error_to_string(packet->error),
                       packet->error));
      SSH_FSM_SET_NEXT(ikev2_packet_st_done);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ikev2_packet_st_input_v1_create_sa);

  /* No IKEv2 SA found. */
  if (packet->ike_sa == NULL)
    return SSH_FSM_CONTINUE;

  /* Assert that the found IKE SA is a valid IKEv2 SA. */
  SSH_ASSERT(packet->ike_sa != (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA);

  /* Matching IKEv2 SA found. Check that we are the initiator and that
     the IKEv2 SA is half-open and in initial state. */
  if (memcmp(packet->ike_sa->ike_spi_r, "\x00\x00\x00\x00\x00\x00\x00\x00", 8)
      != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("IKEv2 SA %p is not half-open",
                                   packet->ike_sa));
      goto out;
    }
  if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("This end is not the initiator for IKEv2 SA %p",
                 packet->ike_sa));
      goto out;
    }
  if (packet->ike_sa->initial_ed == NULL
      || packet->ike_sa->initial_ed->state != SSH_IKEV2_STATE_IKE_INIT_SA)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("IKEv2 SA %p is not in initial exchange",
                                   packet->ike_sa));
      goto out;
    }

  /* Decode IKEv1 packet. */
  buffer = ssh_buffer_allocate();
  if (buffer == NULL
      || ssh_buffer_append(buffer,
                           packet->encoded_packet,
                           packet->encoded_packet_len) != SSH_BUFFER_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Failed to allocate buffer space for IKEv1 packet"));
      goto out;
    }

  /* Consume NAT-T header. */
  if (packet->use_natt && ssh_buffer_len(buffer) >= 4)
    ssh_buffer_consume(buffer, 4);

  if (ike_decode_packet(NULL, &isakmp_packet, NULL, NULL, buffer)
      || isakmp_packet == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Failed to decode IKEv1 packet"));
      goto out;
    }

  {
    unsigned char ipaddr[64];
    unsigned char ripaddr[64];
    ikev1_list_packet_payloads(isakmp_packet,
            isakmp_packet->payloads,
            ssh_ipaddr_print(packet->server->ip_address,
                             ipaddr,
                             sizeof(ipaddr)),
            packet->use_natt ?
                    packet->server->nat_t_local_port :
                    packet->server->normal_local_port,
            ssh_ipaddr_print(packet->remote_ip, ripaddr, sizeof(ripaddr)),
            packet->server->normal_remote_port,
            FALSE);
  }

  /* Look for INVALID_MAJOR_VERSION notify. */
  for (isakmp_payload = isakmp_packet->first_n_payload;
       isakmp_payload != NULL;
       isakmp_payload = isakmp_payload->next_same_payload)
    {
      if (isakmp_payload->type == SSH_IKE_PAYLOAD_TYPE_N
          && (isakmp_payload->pl.n.notify_message_type
              == SSH_IKE_NOTIFY_MESSAGE_INVALID_MAJOR_VERSION))
        {
          /* Ok, this seems to be an IKEv1 INVALID_MAJOR_VERSION notify
             for the IKEv2 SA. Do not react immediately on this
             unauthenticated notify, but adjust retransmission counter
             for the IKEv2 SA and set 'received_unprotected_error' to
             USE_IKEV1 so that the IKE negotiation will fail with
             USE_IKEV1 instead of TIMEOUT. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Received unauthenticated IKEv1 notify "
                     "INVALID_MAJOR_VERSION for IKEv2 SA %p",
                     packet->ike_sa));
          packet->ike_sa->received_unprotected_error =
            SSH_IKEV2_ERROR_USE_IKEV1;
          ikev2_window_set_retransmit_count
            (packet->ike_sa, packet->server->context->params.retry_limit + 1
             - SSH_IKEV2_PACKET_UNPROTECTED_ERROR_RETRANSMIT_COUNT);

          /* Done with the packet. */
          SSH_FSM_SET_NEXT(ikev2_packet_st_done);
          break;
        }
    }

 out:
  if (isakmp_packet)
    ike_free_packet(isakmp_packet, 0);
  if (buffer)
    ssh_buffer_free(buffer);
  SSH_IKEV2_IKE_SA_FREE(packet->ike_sa);
  packet->ike_sa = NULL;
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_packet_st_input_v1_create_sa)
{
  SshIkev2Packet packet = thread_context;

  /* Only IKEv1 packets come here. Minor version is checked in the
     isakmp library. */
  SSH_ASSERT(packet->major_version == 1);

  /* Assert that packet processing is not in an error state. */
  SSH_ASSERT(packet->error == SSH_IKEV2_ERROR_OK);

  /* No IKE SA found. */
  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                  ("No IKE SA for packet; "
                   "requesting permission to create one."));

  SSH_FSM_SET_NEXT(ikev2_packet_st_connect_decision);
  SSH_FSM_ASYNC_CALL({
    packet->operation = (*(packet->server->sad_interface->new_connect))
      (packet->server->sad_handle,
       packet->server,
       packet->major_version, packet->minor_version,
       packet->remote_ip, packet->remote_port,
       ikev2_packet_new_connection_cb,
       packet);
  });
}
#endif /* SSHDIST_IKEV1 */


static void
ikev2_packet_alloc_sa_cb(SshIkev2Error error,
                         SshIkev2Sa sa,
                         void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  if (sa)
    {
      sa->server = packet->server;

      ikev2_transmit_window_init(sa->transmit_window);
      ikev2_receive_window_init(sa->receive_window);

      SSH_IKEV2_IKE_SA_TAKE_REF(sa);
      if (packet->error == SSH_IKEV2_ERROR_COOKIE_REQUIRED)
        sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_REQUIRE_COOKIE;
      sa->server->statistics->total_attempts++;
      sa->server->statistics->total_attempts_responded++;
#ifdef SSHDIST_IKE_MOBIKE
      /* Initialize additional IP addresses list with the remote IP from
         packet. */
      sa->num_additional_ip_addresses = 1;
      sa->additional_ip_addresses[0] = *packet->remote_ip;
#endif /* SSHDIST_IKE_MOBIKE */
    }

  packet->ike_sa = sa;
  packet->error = error;
}


SSH_FSM_STEP(ikev2_packet_st_connect_decision)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Pad %s connection",
                                packet->error == SSH_IKEV2_ERROR_OK
                                ? "allows" :
                                (packet->error ==
                                 SSH_IKEV2_ERROR_COOKIE_REQUIRED ?
                                 "requires cookie for" :
                                 "denies")));

  if (packet->major_version >= 2
      && (packet->error == SSH_IKEV2_ERROR_OK
          || packet->error == SSH_IKEV2_ERROR_COOKIE_REQUIRED))
    {
      SSH_FSM_SET_NEXT(ikev2_packet_st_allocated);
      SSH_FSM_ASYNC_CALL({
        packet->operation = (*(packet->server->sad_interface->ike_sa_allocate))
          (packet->server->sad_handle, FALSE,
           ikev2_packet_alloc_sa_cb,
           packet);
      });
    }
  else
    {
#ifdef SSHDIST_IKEV1
      if (packet->major_version == 2
          && packet->error == SSH_IKEV2_ERROR_USE_IKEV1)
        {
          /* We got, as an responder, an IKEv2 packet but our policy
             forces IKEv1 for this peer. Send packet to IKEv1 library
             that will take care of generating invalid major version
             notification. This code is here mostly for testing purposes
             as the policy manager never returns USE_IKEV1 from
             new_connection policy call. */
          ssh_fsm_set_next(packet->thread, ikev2_packet_v1_start);
          return SSH_FSM_CONTINUE;
        }
      if (packet->major_version == 1
          && (packet->error == SSH_IKEV2_ERROR_USE_IKEV1
              || packet->error == SSH_IKEV2_ERROR_OK))
        {
          /* We got an IKEv1 packet, forward it to the state
             machine. */
          ssh_fsm_set_next(packet->thread, ikev2_packet_v1_start);
          return SSH_FSM_CONTINUE;
        }
      else
#endif /* SSHDIST_IKEV1 */
        {
          SshADTHandle handle;
          SshIkev2HalfStruct probe;

          /* NOTE: check for other errors than SSH_IKEV2_ERROR_DISCARD_PACKET.
           */

          /* Detach the initiator SPI from the half container, as the
             PM decided to reject this new connection. */
          memcpy(probe.ike_spi_i, packet->ike_spi_i, sizeof(probe.ike_spi_i));
          probe.remote_port = packet->remote_port;
          *(probe.remote_ip) = *(packet->remote_ip);
          if ((handle =
               ssh_adt_get_handle_to_equal(ikev2->sa_half_by_spi, &probe))
              != SSH_ADT_INVALID)
            ssh_adt_delete(ikev2->sa_half_by_spi, handle);

          SSH_FSM_SET_NEXT(ikev2_packet_st_done);
          return SSH_FSM_CONTINUE;
        }
    }
}


SSH_FSM_STEP(ikev2_packet_st_allocated)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);
  SshIkev2Half half;

  if (packet->error != SSH_IKEV2_ERROR_OK || !packet->ike_sa)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Failed to allocate sa"));
      SSH_FSM_SET_NEXT(ikev2_packet_st_done);
      return SSH_FSM_CONTINUE;
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("New packet to new SA"));

  /* Allocated SA based on received packet, e.g. we are
     responder and SPI was unknown */
  *packet->ike_sa->remote_ip = *packet->remote_ip;
  packet->ike_sa->remote_port = packet->remote_port;
  packet->ike_sa->server = packet->server;

  memcpy(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
         sizeof(packet->ike_spi_i));
  memcpy(packet->ike_spi_r, packet->ike_sa->ike_spi_r,
         sizeof(packet->ike_spi_r));

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Inserting SA to half SA container"));

  half = ssh_calloc(1, sizeof(*half));
  if (half == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Out of memory allocating half entry"));
      SSH_FSM_SET_NEXT(ikev2_packet_st_done);
      return SSH_FSM_CONTINUE;
    }
  memcpy(half->ike_spi_i, packet->ike_spi_i, sizeof(half->ike_spi_i));
  memcpy(half->ike_spi_r, packet->ike_spi_r, sizeof(half->ike_spi_r));
  half->remote_port = packet->remote_port;
  *(half->remote_ip) = *(packet->remote_ip);
  half->ttl = 2; /* Allow peer 2 seconds */

  /* No need to take reference to SA, as we only store the
     spis. The entry is cleared from the container, after we
     see next packet on it. If we never see next packet on
     it, the entries can be cleared at any time, if we do
     not have the IKE SA existing anymore. */

  /* Start the timer to expire half-entries. We need to cancel this
     timeout first, as completion/rejection of entries above may cause
     number of objects to go to zero and timer still being running. */
  if (ssh_adt_num_objects(ikev2->sa_half_by_spi) == 0)
    {
      ssh_cancel_timeout(ikev2->timeout);
      ssh_register_timeout(ikev2->timeout, 1, 0, ikev2_timer, ikev2);
    }

  ssh_adt_insert(ikev2->sa_half_by_spi, half);
  SSH_FSM_SET_NEXT(ikev2_packet_st_verify);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_packet_st_verify)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Verifying"));


  if ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)
    {
      SshIkev2Packet request_packet;

      request_packet =
          ikev2_transmit_window_find_request(
                  packet->ike_sa->transmit_window,
                  packet->message_id);

      if (request_packet == NULL)
        {
          return SSH_FSM_FINISH;
        }
      else
        {
          packet->ed = request_packet->ed;
          ikev2_reference_exchange_data(packet->ed);
          SSH_ASSERT(packet->ed->magic == SSH_IKEV2_ED_MAGIC);

          SSH_FSM_SET_NEXT(ikev2_packet_st_forward);
        }
    }
  else
    {
      Boolean new_request;

      if (packet->ike_sa->waiting_for_delete != NULL)
        {
          SSH_IKEV2_DEBUG(
                  SSH_D_LOWOK,
                  ("Dropping request packet to an SA waiting for deletion."));

          return SSH_FSM_FINISH;
        }

      new_request =
          ikev2_receive_window_check_request(
                  packet->ike_sa->receive_window,
                  packet);

      if (new_request)
        {
          SSH_FSM_SET_NEXT(ikev2_packet_st_forward);
        }
      else
        {
          return SSH_FSM_FINISH;
        }
   }

  if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED) != 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Dropping packet to deleted SA."));
      return SSH_FSM_FINISH;
    }

  /* Enforce that packets are received on the NAT-T port after port
     floating has been done. */
  if (packet->use_natt == 0 &&
      (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Received packet on normal port although port float "
                 "is done for IKE SA %p", packet->ike_sa));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_PACKET_INVALID_PORT,
                  "Received packet on normal port after port floating "
                  "completed");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_packet_st_forward)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Forwarding packet to state machine"));

  SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("R: IKE SA REFCNT: %d",
                                (int) packet->ike_sa->ref_cnt));

  SSH_ASSERT(packet->ed == NULL ||
             packet->ed->magic == SSH_IKEV2_ED_MAGIC);

  /* Pass packet to the IKE state machine, it will continue processing
     and finally terminates the thread. */
  ikev2_state(packet);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_packet_st_done)
{
  SshIkev2Packet packet = thread_context;

  if (packet->in_window)
    return SSH_FSM_SUSPENDED;
  else
    return SSH_FSM_FINISH;
}


#ifdef SSHDIST_IKEV1
/* One step state machine, forward packet unconditionally to the IKEv1 */
SSH_FSM_STEP(ikev2_packet_v1_start)
{
  SshIkev2Packet packet = thread_context;
  SshBuffer buffer;
  int len;

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    goto error;

  if (ssh_buffer_append(buffer,
                        packet->encoded_packet,
                        packet->encoded_packet_len) == SSH_BUFFER_OK)
    {
      unsigned char r_ip[64], r_port[6];

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Passing IKE v%d.%d packet to IKEv1 library",
                 packet->major_version, packet->minor_version));

      len = ssh_snprintf(r_ip, sizeof(r_ip), "%@",
                         ssh_ipaddr_render, packet->remote_ip);
      if (len < 0)
        goto error;

      len = ssh_snprintf(r_port, sizeof(r_port), "%d",
                         packet->remote_port);
      if (len < 0)
        goto error;

      ike_udp_callback_common((SshIkeServerContext)packet->server,
                              packet->use_natt, r_ip, r_port,
                              buffer);
    }
  else
    {
      ssh_buffer_free(buffer);
    }

  /* Delete IKE SA, if in error state */
  if (packet->error == SSH_IKEV2_ERROR_USE_IKEV1 && packet->ike_sa)
    ikev2_do_error_delete(packet, packet->ike_sa);

  return SSH_FSM_FINISH;

 error:
  if (buffer)
    ssh_buffer_free(buffer);
  SSH_FSM_SET_NEXT(ikev2_packet_st_done);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKEV1 */


/****************************************************************************
 * Transport API
 */

/* Receive data from peer: this is UDP listeners packet callback.

   1. -> allocate packet
   2. -> decode header
   3. -> fetch SA
         ok? -> continue
         fail? -> create new responder SA, goto '3. fetch SA'
   4. verify window, possibly retransmit response, if
      the input was retransmitted request, and terminate
   5. give <server, remote, sa, packet> to state machine


   at same later time, the state machine will call ikev2_udp_update()
   with a SshIkev2Packet to update the window (after the packet
   received has been authenticated. */

void
ikev2_udp_recv(SshUdpListener listener, void *context)
{
  unsigned char *packet;
  size_t packet_len, max_packet_len;
  SshIkev2Server server = context;
  SshIpAddrStruct remote_addr;
  SshUInt16 remote_port;
  SshIkev2Packet header;
  int max_packets = 10; /* NOTE: This should be changed into a macro. */

  if (server->normal_local_port != 0 && server->normal_remote_port != 0)
    SSH_ASSERT(server->normal_listener != NULL);

  if (server->nat_t_local_port != 0 && server->nat_t_remote_port != 0)
    SSH_ASSERT(server->nat_t_listener != NULL);

  packet = ssh_udp_get_datagram_buffer(&max_packet_len);

  while (max_packets-- > 0 &&
         ssh_udp_read_ip(listener, &remote_addr, &remote_port, packet,
                         max_packet_len, &packet_len) == SSH_UDP_OK)
    {
      /* Zero lenght packet means that the implementation of the UDP
         listener read method has consumed the packet. Continue receiving
         packets. */
      if (packet_len == 0)
        continue;

      if (server->context->ikev2_suspended)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Received packet from %@:%d to %@:%d while "
                             "ikev2 library was suspended, discarded",
                             ssh_ipaddr_render, &remote_addr,
                             remote_port,
                             ssh_ipaddr_render,
                             server->ip_address,
                             (listener == server->normal_listener) ?
                             server->normal_local_port :
                             server->nat_t_local_port),
                            packet, packet_len);
          server->statistics->total_discarded_packets++;
          continue;
        }

      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("Received packet from %@:%d to %@:%d",
                         ssh_ipaddr_render, &remote_addr,
                         remote_port,
                         ssh_ipaddr_render,
                         server->ip_address,
                         (listener == server->normal_listener) ?
                         server->normal_local_port :
                         server->nat_t_local_port),
                        packet, packet_len);

      server->statistics->total_packets_in++;
      server->statistics->total_octets_in += packet_len;

      if ((header =
           ikev2_packet_allocate(server->context,
                                 ikev2_packet_st_input_start)) != NULL)
        {
          header->use_natt = (listener == server->normal_listener) ? 0 : 1;
          header->server = server;

          if (ikev2_decode_header(header, packet, packet_len)
              == SSH_IKEV2_ERROR_OK)
            {

              header->received = 1;
              if ((header->encoded_packet = ssh_memdup(packet, packet_len))
                  == NULL)
                {
                  ssh_fsm_uninit_thread(header->thread);
                  return;
                }

              header->encoded_packet_len = packet_len;
              header->remote_port = remote_port;
              *header->remote_ip = remote_addr;

              /* Check if the packet IKE version is something we support.
                 Only check major version and ignore minor version for now. */
              if (header->major_version == 2)
                {
                  return;
                }
              else if (header->major_version == 1)
                {
#ifdef SSHDIST_IKEV1
                  /* We can fallback, do so */
                  if (server->context->fallback)
                    return;
#endif /* SSHDIST_IKEV1 */

                  SSH_DEBUG(SSH_D_NETGARB,
                            ("Received packet for IKE version %d.%d "
                             "but CAN NOT FALLBACK",
                             header->major_version, header->minor_version));
                  ssh_fsm_uninit_thread(header->thread);
                  return;
                }
              else
                {
                  /* This negotiation is going to be terminated soon due to
                     IKE-version being invalid. However we can not send the
                     SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION yet. */
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("Received packet for unsupported "
                             "IKE version %d.%d ",
                             header->major_version,
                             header->minor_version));
                  return;
                }
              SSH_NOTREACHED;
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("listener: %p; error: failed to decode IKEv2 header",
                         listener));
              ssh_fsm_uninit_thread(header->thread);
            }
        }
    }
}









































































