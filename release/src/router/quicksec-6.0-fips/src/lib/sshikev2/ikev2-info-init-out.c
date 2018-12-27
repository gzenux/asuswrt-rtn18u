/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for INFORMATIONAL initiator out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInfoInitOut"

/* Start INFORMATIONAL state. */
SSH_FSM_STEP(ikev2_state_info_initiator_out)
{
  SshIkev2Packet packet = thread_context;

  ikev2_debug_exchange_begin(packet);

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_add_delete);

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  return SSH_FSM_CONTINUE;
}


/* Add delete payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_delete)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_add_notify);
  ikev2_info_add_delete(packet);
  return SSH_FSM_CONTINUE;
}

/* Add notify payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_notify)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_add_conf);
  ikev2_info_add_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Add conf payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_conf)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_MOBIKE
  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    /** If MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_mobike_add_cookie2);
  else
#endif /* SSHDIST_IKE_MOBIKE */
    /** No MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  ikev2_info_add_conf(packet);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_MOBIKE
/** Add MOBIKE cookie2 notify */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_cookie2)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotify notify;
  Boolean add_cookie2_notify = FALSE;

  SSH_ASSERT(packet->ed->info_ed != NULL);
  SSH_ASSERT(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_mobike_add_nat_notifies);

  /* Add a Cookie2 notify if this is a probe exchange or contains a MOBIKE
     related notify */
  if ((packet->ed->info_ed->flags & SSH_IKEV2_INFO_CREATE_FLAGS_PROBE_MESSAGE)
      || (packet->ed->info_ed->flags
          & SSH_IKEV2_INFO_CREATE_FLAGS_REQUEST_ADDRESSES))
    add_cookie2_notify = TRUE;

  notify = packet->ed->notify;
  while (notify != NULL)
    {
      SshIkev2NotifyMessageType type = notify->notify_message_type;

      if (type == SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS ||
          type == SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS ||
          type == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES ||
          type == SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES)
        {
          add_cookie2_notify = TRUE;
          break;
        }

      notify = notify->next_notify;
    }

  if (add_cookie2_notify)
    ikev2_info_add_cookie2_notify(packet);

  return SSH_FSM_CONTINUE;
}

/** Add NAT-D or NO_NATS_ALLOWED notify */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_nat_notifies)
{
  SshIkev2Packet packet = thread_context;

  SSH_ASSERT(packet->ed->info_ed != NULL);
  SSH_ASSERT(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out_mobike_add_additional_addrs);

  /* Add also the NAT-T related notifies. If NAT-T is not disabled, then
     add the NAT discovery payload. Add the NO_NATS_ALLOWED payload if the
     IKE SA flags indicate this and NAT-T is disabled. Do not add the payloads
     if the have already been added during creation of this informational
     exchange. */
  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED)
      && !(packet->ike_sa->flags
           & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T)
      && !(packet->ed->info_ed->flags & SSH_IKEV2_INFO_NAT_D_ADDED))
    ikev2_add_nat_discovery_notify(packet);

  else if ((packet->ike_sa->flags
            & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_NO_NATS_ALLOWED)
           && !(packet->ed->info_ed->flags
                & SSH_IKEV2_INFO_NO_NATS_ALLOWED_ADDED))
    ikev2_add_no_nats_notify(packet);

  return SSH_FSM_CONTINUE;
}

/** Add additional addresses */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_additional_addrs)
{
  SshIkev2Packet packet = thread_context;

  SSH_ASSERT(packet->ed->info_ed != NULL);

  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  /* Add additional addresses notify. */
  if (packet->ed->info_ed->flags
      & SSH_IKEV2_INFO_CREATE_FLAGS_REQUEST_ADDRESSES)
    {
      /* This will call
         SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_additional_address_list) */
      SSH_FSM_ASYNC_CALL(ikev2_add_additional_addresses(packet));
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

#endif /* SSHDIST_IKE_MOBIKE */
