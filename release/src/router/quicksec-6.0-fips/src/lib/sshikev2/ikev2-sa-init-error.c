/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInitError"


/* Make sure we have given other timeouts time to run. */
void ikev2_state_send_and_destroy_cont(void *context)
{
  SshIkev2Packet packet = context;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Delayed destroying"));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
}

/* Destroy IKEv2 SA and then send a return message. This can
   only be used in the responder. */
SSH_FSM_STEP(ikev2_state_send_and_destroy)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_send_and_destroy_now);
  /* We need to do the destroy from the bottom of event loop, so
     insert zero timeout and suspend. Before inserting timeout we make
     sure that skeyseed calculation is not in progress. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Delaying destroying"));
  ssh_cancel_timeout(packet->ed->timeout);
  SSH_FSM_ASYNC_CALL(ssh_register_timeout(packet->ed->timeout,
                                          0, 0,
                                          ikev2_state_send_and_destroy_cont,
                                          packet));
}

/* Callback to be called when delete is done. */
void ikev2_state_deleted_cb(SshIkev2Error error_code,
                            void *context)
{
  SshIkev2Packet packet = context;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Data freed"));

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
}

/* This will now do the actual delete operation. */
SSH_FSM_STEP(ikev2_state_send_and_destroy_now)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_send);

  if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);
      SshADTHandle handle;
      SshIkev2HalfStruct probe;

      /* Detach the initiator SPI from the half container, as this sa is
         removed because of error. */
      memcpy(probe.ike_spi_i, packet->ike_spi_i, sizeof(probe.ike_spi_i));
      probe.remote_port = packet->remote_port;
      *(probe.remote_ip) = *(packet->remote_ip);
      if ((handle =
           ssh_adt_get_handle_to_equal(ikev2->sa_half_by_spi, &probe))
          != SSH_ADT_INVALID)
        ssh_adt_delete(ikev2->sa_half_by_spi, handle);
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Freeing exchange data"));
  /* We need to manually delete the exchange data for
     responses. */
  ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
  ike_sa->initial_ed = NULL;

  /* Clear the references in the packet. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;
  packet->ike_sa = NULL;

  if (ike_sa->waiting_for_delete == NULL)
    {
      /* Destroy ike SA. */
      SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_sa_delete)
                         (ike_sa->server->sad_handle, ike_sa,
                          ikev2_state_deleted_cb, packet);
                         );
    }
  else
    {
      /* The IKE SA has already been deleted, so we simply
         decrement the reference used by the operation
         handle. */
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
      return SSH_FSM_CONTINUE;
    }
}

