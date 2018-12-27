/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Rekey IKEv2 SA initiator functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2InitRekeyIkeSa"

/* Aborting the Rekey IKE SA operation. */
void ikev2_rekey_sa_abort(void *context)
{
  SshIkev2ExchangeData ed = context;
  SshIkev2Sa ike_sa = ed->ike_sa;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Rekey IKE SA exchange for SA %p aborted %@;%d",
             ike_sa, ssh_ipaddr_render, ike_sa->remote_ip,
             ike_sa->remote_port));

  /* Clear the callback so the free_exchange_data will not call it. */
  ed->callback = NULL_FNPTR;

  /* If the exchange was in response processing terminate that packet
     too.
  */
  if (ed->response_packet != NULL)
    {
      SshIkev2Packet response_packet = ed->response_packet;

      ed->response_packet = NULL;

      ikev2_packet_done(response_packet);
    }

  /* Mark that we do not have operation registered anymore, as the abort
     callback was called. */
  ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

  /* First we need to stop the retransmissions as otherwise
     we cannot delete the SA, as there is references to it. */
  ikev2_transmit_window_flush(ike_sa->transmit_window);

  /* Mark ike sa so that is has been aborted, thus drop all packets
     immediately. */
  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_ABORTED;

  /* Then we destroy the IKE SA */

  /* Free the references to IKE SA and ED. They were taken in ike_sa_rekey. */
  /* OK, Added to the ssh_ikev2_ike_sa_rekey */
  ikev2_free_exchange_data(ike_sa, ed);

  /* And then we destroy the IKE SA. Note, that we have one
     reference which we took when installing the operation, and
     this will consume that one. */
  if (ike_sa->waiting_for_delete == NULL)
    {
      /* OK, Added to the ssh_ikev2_ike_sa_rekey */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
        (ike_sa->server->sad_handle, ike_sa, NULL, NULL);
    }
  else
    {
      /* The IKE SA has already been deleted, so we simply
         decrement the reference used by the operation
         handle. */
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }
}

/* This is not real FSM state, but we add this here, so we get state machine
   pictures to include this state too.
SSH_FSM_STEP(ssh_ikev2_ike_sa_rekey) */

/* Rekey the current IKEv2 SA. The rekey_callback function
   is called when the rekey operation is finished. The
   algorithms etc. SA information is requested by the
   ike_fill_sa policy manager function when needed. This
   will take reference to the IKE SA if needed, so the
   caller can free its reference immediately after this
   returns. Note that, this will NOT automatically delete
   the old IKE SA after it has been successfully rekeyed,
   but the old IKE SA is deleted by the policy manager when
   IKE library calls the policymanager function
   SadIkeSaRekey during this process. */
SshOperationHandle
ssh_ikev2_ike_sa_rekey(SshIkev2Sa ike_sa,
                       SshUInt32 flags,
                       SshIkev2NotifyCB callback)
{
  SshIkev2ExchangeData ed;
  SshIkev2Packet packet;
  SshIkev2Error error;

  SSH_ASSERT(ike_sa->server->context->ikev2_suspended == FALSE);
  if (ike_sa->server->server_stopped_flags)
    {
      (*callback)(ike_sa->server->sad_handle,
                  ike_sa, NULL,
                  SSH_IKEV2_ERROR_GOING_DOWN);
      return NULL;
    }

  if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) ||
      ike_sa->waiting_for_delete != NULL)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, NULL,
                    SSH_IKEV2_ERROR_SA_UNUSABLE);
      return NULL;
    }

#ifdef SSHDIST_IKEV1
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      (*callback)(ike_sa->server->sad_handle,
                  ike_sa, NULL,
                  SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */


  if (ike_sa->rekey != NULL)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, NULL,
                    SSH_IKEV2_ERROR_SA_UNUSABLE);
      return NULL;
    }

  ed = ikev2_allocate_exchange_data(ike_sa);
  if (ed == NULL)
    {
      (*callback)(ike_sa->server->sad_handle,
                  ike_sa, NULL,
                  SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return NULL;
    }

  error = ikev2_allocate_exchange_data_ipsec(ed);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      (*callback)(ike_sa->server->sad_handle, ike_sa, ed, error);
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("State = REKEY_IKE"));
  ed->state = SSH_IKEV2_STATE_REKEY_IKE;
  ed->ipsec_ed->flags = flags | SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR |
    SSH_IKEV2_IPSEC_REKEY_IKE;
  /* After this me must make sure we clear the ed->callback in case
     we call the callback directly.  */
  ed->callback = callback;

  SSH_DEBUG(SSH_D_MIDSTART, ("Rekeying IKE SA %@;%d",
                             ssh_ipaddr_render, ike_sa->remote_ip,
                             ike_sa->remote_port));

  packet = ikev2_packet_allocate(ike_sa->server->context,
                                 ikev2_state_ike_rekey_initiator_out);

  if (packet == NULL)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ssh_ikev2_ipsec_exchange_destroy(ed);
      return NULL;
    }

  memcpy(packet->ike_spi_i, ike_sa->ike_spi_i, 8);
  memcpy(packet->ike_spi_r, ike_sa->ike_spi_r, 8);
  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NONE;
  packet->major_version = 2;
  packet->minor_version = 0;

  error = ikev2_transmit_window_insert(ike_sa->transmit_window, packet);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      packet->ed = NULL;
      ssh_fsm_uninit_thread(packet->thread);
      if (callback)
        (*callback)(ike_sa->server->sad_handle, ike_sa, ed, error);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }

  /* Allocate abort handle, and take references to IKE SA and ED. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
  ikev2_reference_exchange_data(ed);
  /* This will call
     ikev2_free_exchange_data(ike_sa, ed);
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
  ssh_operation_register_no_alloc(ed->ipsec_ed->operation_handle,
                                  ikev2_rekey_sa_abort, ed);
  ed->ipsec_ed->flags |= SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

  /* Take new reference to the IKE SA and store it to packet. Store the ED
     to packet using the reference from ED creation. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
  packet->ike_sa = ike_sa;
  packet->ed = ed;

  packet->exchange_type = SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA;
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;
  else
    packet->flags = 0;
  packet->encoded_packet_len = 0;
  packet->encoded_packet = NULL;
  *(packet->remote_ip) = *(ike_sa->remote_ip);
  packet->remote_port = ike_sa->remote_port;
  packet->server = ike_sa->server;
  if (ike_sa->flags &
      (SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T |
       SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
    packet->use_natt = 1;
  else
    packet->use_natt = 0;

  if (ike_sa->rekey == NULL)
    {
      ike_sa->rekey = ssh_calloc(1, sizeof(*ike_sa->rekey));
      if (ike_sa->rekey == NULL)
        ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Started rekey IKE SA %@;%d",
                          ssh_ipaddr_render, ike_sa->remote_ip,
                          ike_sa->remote_port));
  return ed->ipsec_ed->operation_handle;
}
