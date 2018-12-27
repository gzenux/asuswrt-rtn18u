/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Info SA initiator init functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#ifdef SSHDIST_IKEV1
#include "ikev2-fb.h"
#endif /* SSHDIST_IKEV1 */

#define SSH_DEBUG_MODULE "SshIkev2InitInfoSa"

/* Aborting the info send operation. */
void ikev2_info_sa_abort(void *context)
{
  SshIkev2ExchangeData ed = context;
  SshIkev2Sa ike_sa = ed->ike_sa;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Info ED %p IKE SA %p exchange aborted %@;%d",
             ed, ike_sa, ssh_ipaddr_render, ike_sa->remote_ip,
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
  ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;

  /* First we need to stop the retransmissions as otherwise
     we cannot delete the SA, as there is references to it. */
  ikev2_transmit_window_flush(ike_sa->transmit_window);

  /* Mark ike sa so that is has been aborted, thus drop all packets
     immediately. */
  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_ABORTED;

  /* Then we destroy the IKE SA */

  /* Free references to IKE SA and ED. They were taken in info_send. */
  ikev2_free_exchange_data(ike_sa, ed);

  if (ike_sa->waiting_for_delete == NULL)
    {
      /* And then we destroy the IKE SA. Note, that we have
         one reference which we took when installing the
         operation, and this will consume that one. */
      /* OK, Added to the ssh_ikev2_info_send  */
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

/* Create informational exchange, this just allocates memory
   structures to store the payloads, the actual operation
   happens in the info_send. The created info ed must be passed
   to either ssh_ikev2_info_send or ssh_ikev2_info_destroy. */
SshIkev2ExchangeData
ssh_ikev2_info_create(SshIkev2Sa ike_sa,
                      SshUInt32 flags)
{
  SshIkev2ExchangeData ed;
  SshIkev2Error error;

  SSH_ASSERT(ike_sa->server->context->ikev2_suspended == FALSE);
  if (ike_sa->server->server_stopped_flags ||
      (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED) ||
      !((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
#ifdef SSHDIST_IKEV1
        || (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
#endif /* SSHDIST_IKEV1 */
        ))
    {
      return NULL;
    }
  ed = ikev2_allocate_exchange_data(ike_sa);
  if (ed == NULL)
    {
      return NULL;
    }
#ifdef SSHDIST_IKEV1
  if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
      ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      error = ikev2_allocate_exchange_data_ike(ed);
      if (error != SSH_IKEV2_ERROR_OK)
        {
          ikev2_free_exchange_data(ike_sa, ed);
          return NULL;
        }
    }
#endif /* SSHDIST_IKEV1 */
  error = ikev2_allocate_exchange_data_info(ed);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }
  ed->info_ed->flags = flags | SSH_IKEV2_INFO_CREATE_FLAGS_INITIATOR;
  SSH_DEBUG(SSH_D_LOWSTART, ("State = INFORMATIONAL"));
  ed->state = SSH_IKEV2_STATE_INFORMATIONAL;
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);

  /* At this point we have references to IKE SA and to ED. Those
     references are stolen to packet in info_send or freed in info_destroy. */

  return ed;
}


/* Add IPsec SA SPI to be deleted. To delete IKE SAs use the
   ssh_ikev2_ike_sa_delete function. This can be called as
   many times as liked, and it will create necessary delete
   payloads having all SPIs. */
SshIkev2Error
ssh_ikev2_info_add_delete(SshIkev2ExchangeData ed,
                          SshIkev2ProtocolIdentifiers protocol_id,
                          int number_of_spis,
                          const SshUInt32 *spi_array,
                          SshUInt32 flags)
{
  SshIkev2PayloadDelete del;

  del = ssh_obstack_alloc(ed->obstack, sizeof(*del));
  if (del == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating delete"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  del->protocol = protocol_id;
  del->spi_size = 4;
  del->number_of_spis = number_of_spis;
  del->spi.spi_array =
    (void *) ssh_obstack_memdup(ed->obstack, spi_array,
                                number_of_spis * sizeof(*spi_array));
  if (del->spi.spi_array == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Out of memory allocating spi table"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  del->next_delete = ed->info_ed->del;
  ed->info_ed->del = del;
  return SSH_IKEV2_ERROR_OK;
}

/* Add notification payload to informational exchange. */
SshIkev2Error
ssh_ikev2_info_add_n(SshIkev2ExchangeData ed,
                     SshIkev2ProtocolIdentifiers protocol_id,
                     const unsigned char *spi,
                     size_t spi_size,
                     SshIkev2NotifyMessageType
                     notify_message_type,
                     const unsigned char *notification_data,
                     size_t notification_data_size)
{
  SshIkev2PayloadNotify notify;

  notify = ssh_obstack_alloc(ed->obstack, sizeof(*notify));
  if (notify == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating notify"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  notify->protocol = protocol_id;
  notify->notify_message_type = notify_message_type;
  notify->spi_size = spi_size;
  notify->spi_data = NULL;
  notify->notification_size = notification_data_size;
  notify->notification_data = NULL;
  notify->authenticated = 0;

  if (spi)
    {
      notify->spi_data = ssh_obstack_memdup(ed->obstack, spi, spi_size);
      if (notify->spi_data == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating spi"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
    }
  if (notification_data)
    {
      notify->notification_data = ssh_obstack_memdup(ed->obstack,
                                                     notification_data,
                                                     notification_data_size);
      if (notify->notification_data == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating data"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
    }
  notify->next_notify = ed->info_ed->notify;
  ed->info_ed->notify = notify;
  return SSH_IKEV2_ERROR_OK;
}

/* Add configuration payload to informational exchange. */
SshIkev2Error
ssh_ikev2_info_add_conf(SshIkev2ExchangeData ed,
                        SshIkev2PayloadConf conf_payload)
{
  if (ed->info_ed->conf != NULL)
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;

  ed->info_ed->conf = conf_payload;
  ssh_ikev2_conf_take_ref(ed->ike_sa->server->sad_handle,
                          ed->info_ed->conf);
  return SSH_IKEV2_ERROR_OK;
}


#ifdef SSHDIST_IKE_MOBIKE
void
ssh_ikev2_info_use_addresses(SshIkev2ExchangeData ed,
                             SshIkev2Server server,
                             Boolean use_natt,
                             SshIpAddr remote_ip,
                             SshUInt16 remote_port)
{
  SSH_ASSERT(ed != NULL);
  SSH_ASSERT(server != NULL);
  SSH_ASSERT(remote_ip != NULL);

  *ed->info_ed->forced_remote_ip = *remote_ip;
  ed->info_ed->forced_remote_port = remote_port;
  ed->info_ed->forced_server = server;
  if (use_natt)
    ed->info_ed->forced_use_natt = 1;
  else
    ed->info_ed->forced_use_natt = 0;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Using addresses %@:%d/%@:%d for informational exchange",
             ssh_ipaddr_render, ed->info_ed->forced_server->ip_address,
             (ed->info_ed->forced_use_natt ?
              ed->info_ed->forced_server->nat_t_local_port :
              ed->info_ed->forced_server->normal_local_port),
             ssh_ipaddr_render, ed->info_ed->forced_remote_ip,
             ed->info_ed->forced_remote_port));
}
#endif /* SSHDIST_IKE_MOBIKE */

/* This is not real FSM state, but we add this here, so we get state machine
   pictures to include this state too.
SSH_FSM_STEP(ssh_ikev2_info_send) */

/* Encode and send the informational exchange. The notification
   callback will be called when the other end replies (or with error
   code if it times out). This will also free the exchange data when
   the operation is done. */
SshOperationHandle
ssh_ikev2_info_send(SshIkev2ExchangeData ed,
                    SshIkev2NotifyCB callback)
{
  SshIkev2Packet packet;
  SshIkev2Error error;
  SshIkev2Sa ike_sa;
  SshIkev2Server server;
  SshIpAddr remote_ip;
  SshUInt16 remote_port;
  Boolean use_natt;

  ike_sa = ed->ike_sa;

  remote_ip = ike_sa->remote_ip;
  remote_port = ike_sa->remote_port;
  server = ike_sa->server;
  if (ike_sa->flags &
      (SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T |
       SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
    use_natt = TRUE;
  else
    use_natt = FALSE;

#ifdef SSHDIST_IKE_MOBIKE
  if (ed->info_ed->forced_server != NULL)
    {
      remote_ip = ed->info_ed->forced_remote_ip;
      remote_port = ed->info_ed->forced_remote_port;
      server = ed->info_ed->forced_server;
      if (ed->info_ed->forced_use_natt)
        use_natt = TRUE;
      else
        use_natt = FALSE;
    }
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_ASSERT(server->context->ikev2_suspended == FALSE);

  if (server->server_stopped_flags)
    {
      if (callback)
        (*callback)(server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_GOING_DOWN);
      ssh_ikev2_info_destroy(ed);
      return NULL;
    }

  if (ike_sa->waiting_for_delete != NULL ||
      !((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
#ifdef SSHDIST_IKEV1
        || (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
#endif /* SSHDIST_IKEV1 */
        ))
    {
      if (callback)
        (*callback)(server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_SA_UNUSABLE);
      ssh_ikev2_info_destroy(ed);
      return NULL;
    }

  /* After this we must make sure we clear the ed->callback in case
     we call the callback directly.  */
  ed->callback = callback;

#ifdef SSHDIST_IKEV1
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      return ikev2_fb_initiate_info(ed);
    }
#endif /* SSHDIST_IKEV1 */

  SSH_DEBUG(SSH_D_MIDSTART, ("Sending Informational packet %@;%d",
                             ssh_ipaddr_render, remote_ip,
                             remote_port));

  packet = ikev2_packet_allocate(server->context,
                                 ikev2_state_info_initiator_out);

  if (packet == NULL)
    {
      if (callback)
        (*callback)(server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ssh_ikev2_info_destroy(ed);
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
        (*callback)(server->sad_handle,
                    ike_sa, ed, error);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ssh_ikev2_info_destroy(ed);
      return NULL;
    }

  /* Allocate abort handle, and take references to IKE SA and ED. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
  ikev2_reference_exchange_data(ed);

  /** Called if delete operation is aborted */
  /* SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
  ssh_operation_register_no_alloc(ed->info_ed->operation_handle,
                                  ikev2_info_sa_abort,
                                  ed);
  ed->info_ed->flags |= SSH_IKEV2_INFO_OPERATION_REGISTERED;

  /* The references to IKE SA and ED (taken in info_create) are from this
     point on associated to the packet. */
  packet->ike_sa = ike_sa;
  packet->ed = ed;

  packet->exchange_type = SSH_IKEV2_EXCH_TYPE_INFORMATIONAL;
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;
  else
    packet->flags = 0;
  packet->encoded_packet_len = 0;
  packet->encoded_packet = NULL;

  *(packet->remote_ip) = *remote_ip;
  packet->remote_port = remote_port;
  packet->server = server;
  if (use_natt)
    packet->use_natt = 1;
  else
    packet->use_natt = 0;

  SSH_DEBUG(SSH_D_MIDOK, ("Sending Informational packet %@;%d",
                          ssh_ipaddr_render, packet->remote_ip,
                          packet->remote_port));
  return ed->info_ed->operation_handle;
}

/* Free the exchange data without sending the informational
   notification. */
void
ssh_ikev2_info_destroy(SshIkev2ExchangeData ed)
{
  /* Free references to IKE SA and ED. They were taken in info_create. */
  SSH_IKEV2_IKE_SA_FREE(ed->ike_sa);
  ikev2_free_exchange_data(ed->ike_sa, ed);
}
