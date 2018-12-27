/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 IKE SA initiator init functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#ifdef SSHDIST_IKEV1
#include "sshikev2-fallback.h"
#include "ikev2-fb.h"
#endif /* SSHDIST_IKEV1 */

#define SSH_DEBUG_MODULE "SshIkev2InitIkeSa"

typedef struct SshIkev2IkeSaAllocateTempContextRec {
  SshIkev2Server server;
  SshIpAddrStruct remote_ip[1];
  SshUInt32 flags;
  SshIkev2IkeSaAllocatedCB callback;
  void *context;
  SshOperationDestructorStruct dest[1];
} *SshIkev2IkeSaAllocateTempContext, SshIkev2IkeSaAllocateTempContextStruct;


/* Callback which is called after the alloc is done. */
void ikev2_ike_sa_alloc_cb(SshIkev2Error error_code,
                           SshIkev2Sa sa,
                           void *context)
{
  SshIkev2IkeSaAllocateTempContext temp = context;

  if (error_code == SSH_IKEV2_ERROR_OK && sa != NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Allocated IKE SA %p %@ (%@;%d/%d)",
                                 sa,
                                 ssh_ikev2_ike_spi_render, sa,
                                 ssh_ipaddr_render,
                                 temp->remote_ip,
                                 temp->server->normal_remote_port,
                                 temp->server->nat_t_remote_port));
      sa->server = temp->server;
      *(sa->remote_ip) = *(temp->remote_ip);
      if (temp->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T)
        {
          sa->remote_port = temp->server->nat_t_remote_port;
          sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;
        }
      else
        sa->remote_port = temp->server->normal_remote_port;
      sa->flags |= (0x0000ffff & temp->flags);
      sa->server->statistics->total_attempts++;
      sa->server->statistics->total_attempts_initiated++;
#ifdef SSHDIST_IKE_MOBIKE
      /* Initialize additional IP addresses list with the initial remote IP. */
      sa->num_additional_ip_addresses = 1;
      sa->additional_ip_addresses[0] = *(temp->remote_ip);
#endif /* SSHDIST_IKE_MOBIKE */

      /* Initialize transmit and receive windows. */
      ikev2_transmit_window_init(sa->transmit_window);
      ikev2_receive_window_init(sa->receive_window);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Alloc of IKE SA failed = %d (%@;%d/%d)",
                             error_code,
                             ssh_ipaddr_render,
                             temp->remote_ip,
                             temp->server->normal_remote_port,
                             temp->server->nat_t_remote_port));
    }
  (*temp->callback)(error_code, sa, temp->context);
}

/* Free the temporary context. */
void ikev2_ike_sa_alloc_free_temp(Boolean aborted,
                                  void *context)
{
  SshIkev2IkeSaAllocateTempContext temp = context;

  SSH_DEBUG(SSH_D_MIDSTART, ("Freeing temp context (%@;%d/%d)",
                             ssh_ipaddr_render,
                             temp->remote_ip,
                             temp->server->normal_remote_port,
                             temp->server->nat_t_remote_port));

  ssh_free(temp);
}


/* Create IKEv2 SA structure. This does NOT do any
   exchanges, it only allocates IKEv2 structure, and
   initially bound it to the given remote_ip.
   Server is used to send outgoing packets (input packets
   are accepted from any server). The algorithms etc (sa
   information) is requested by ike_fill_sa policy manager
   function when needed. */
SshOperationHandle
ssh_ikev2_ike_sa_allocate(SshIkev2Server server,
                          SshIpAddr remote_ip,
                          SshUInt32 flags,
                          SshIkev2IkeSaAllocatedCB callback,
                          void *context)
{
  SshIkev2IkeSaAllocateTempContext temp;
  SshOperationHandle handle;

  if (server == NULL || server->server_stopped_flags)
    {
      (*callback)(SSH_IKEV2_ERROR_GOING_DOWN, NULL, context);
      return NULL;
    }
  SSH_ASSERT(server->context->ikev2_suspended == FALSE);

#ifdef SSHDIST_IKE_MOBIKE
#ifdef SSHDIST_IKEV1
  if ((flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE) &&
      (flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
    {
      (*callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, NULL, context);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_DEBUG(SSH_D_MIDSTART, ("Allocating IKE SA %@;%d/%d",
                             ssh_ipaddr_render, remote_ip,
                             server->normal_remote_port,
                             server->nat_t_remote_port));

  temp = ssh_calloc(1, sizeof(*temp));
  if (temp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Out of memory when allocating temp context"));
      goto error_out_of_memory;
    }
  temp->server = server;
  *(temp->remote_ip) = *remote_ip;
  if (server->nat_t_remote_port == 0 || server->nat_t_local_port == 0)
    {
      /* Disable NAT-T. */
      flags &= ~SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T;
      flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T;
    }
  temp->flags = flags;
  temp->callback = callback;
  temp->context = context;

  /* Allocate SA from the policy manager. */
  handle =
    (*server->sad_interface->ike_sa_allocate)(server->sad_handle,
                                              TRUE,
                                              ikev2_ike_sa_alloc_cb,
                                              temp);
  if (handle == NULL)
    {
      /* SA allocation completed synchronously. */
      ikev2_ike_sa_alloc_free_temp(FALSE, temp);
      return NULL;
    }

  /* Attach a destructor for temp to the PM operation handle. */
  ssh_operation_attach_destructor_no_alloc(temp->dest,
                                           handle,
                                           ikev2_ike_sa_alloc_free_temp,
                                           temp);
  return handle;

 error_out_of_memory:
  (*callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL, context);
  return NULL;
}

/* Allocate obstack for exchange data. */
SshIkev2ExchangeData
ikev2_allocate_exchange_data(SshIkev2Sa ike_sa)
{
  SshIkev2ExchangeData ed;

  SSH_DEBUG(SSH_D_LOWSTART, ("Calling exchange_data_alloc"));
  ed = (*ike_sa->server->sad_interface->exchange_data_alloc)
    (ike_sa->server->sad_handle, ike_sa);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Error: Out of memory allocating obstack for SA %p",
                 ike_sa));
    }
  else
    {
#ifdef DEBUG_LIGHT
      ed->magic = SSH_IKEV2_ED_MAGIC;
#endif /* DEBUG_LIGHT */
      ed->ref_cnt = 1;
      ed->ike_sa = ike_sa;
      ed->response_packet = NULL;

      SSH_DEBUG(SSH_D_LOWOK, ("Successfully allocated exchange data for SA %p",
                              ike_sa));
    }
  return ed;
}

/* Allocate IKE SA exchange data. */
SshIkev2Error
ikev2_allocate_exchange_data_ike(SshIkev2ExchangeData ed)
{
  if (ed->ike_ed != NULL)
    return SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating IKE exchange data for SA %p ED %p",
                             ed->ike_sa, ed));

  ed->ike_ed = ssh_obstack_alloc(ed->obstack, sizeof(*ed->ike_ed));
  if (ed->ike_ed == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating IKE exchange "
                              "data for SA %p ED %p", ed->ike_sa, ed));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  memset(ed->ike_ed, 0, sizeof(*ed->ike_ed));

  SSH_DEBUG(SSH_D_LOWOK,
            ("Successfully allocated IKE exchange data for SA %p ED %p",
             ed->ike_sa, ed));

  return SSH_IKEV2_ERROR_OK;
}

/* Allocate IPsec SA exchange data. */
SshIkev2Error
ikev2_allocate_exchange_data_ipsec(SshIkev2ExchangeData ed)
{
  if (ed->ipsec_ed != NULL)
    return SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating IPsec exchange data for SA %p ED %p",
                             ed->ike_sa, ed));

  ed->ipsec_ed = ssh_obstack_alloc(ed->obstack, sizeof(*ed->ipsec_ed));
  if (ed->ipsec_ed == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating Ipsec exchange "
                              "data SA %p ED %p", ed->ike_sa, ed));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  memset(ed->ipsec_ed, 0, sizeof(*ed->ipsec_ed));

  SSH_DEBUG(SSH_D_LOWOK,
            ("Successfully allocated IPsec exchange data for SA %p ED %p",
             ed->ike_sa, ed));

  return SSH_IKEV2_ERROR_OK;
}

/* Allocate Info exchange data. */
SshIkev2Error
ikev2_allocate_exchange_data_info(SshIkev2ExchangeData ed)
{
  if (ed->info_ed != NULL)
    return SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating Info exchange data for SA %p ED %p",
                             ed->ike_sa, ed));

  ed->info_ed = ssh_obstack_alloc(ed->obstack, sizeof(*ed->info_ed));
  if (ed->info_ed == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating Info exchange "
                              "data SA %p ED %p", ed->ike_sa, ed));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
  memset(ed->info_ed, 0, sizeof(*ed->info_ed));

  SSH_DEBUG(SSH_D_LOWOK,
            ("Successfully allocated Info exchange data for SA %p ED %p",
             ed->ike_sa, ed));

  return SSH_IKEV2_ERROR_OK;
}

/* Free Info SA exchange data. */
void ikev2_free_exchange_data_info(SshIkev2Sa ike_sa,
                                   SshIkev2InfoSaExchangeData ed)
{
  if (ed == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing Info exchange data from SA %p",
                             ike_sa));
  if (ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED)
    {
      ssh_operation_unregister_no_free(ed->operation_handle);
      ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
      SSH_DEBUG(SSH_D_LOWSTART, ("Freeing reference"));
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }

  if (ed->conf)
    ssh_ikev2_conf_free(ike_sa->server->sad_handle, ed->conf);
  ed->conf = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Successfully freed Info exchange data from SA %p",
                          ike_sa));
}

/* Free IPsec SA exchange data. */
void ikev2_free_exchange_data_ipsec(SshIkev2Sa ike_sa,
                                    SshIkev2IPsecSaExchangeData ed)
{
  if (ed == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing IPsec exchange data from SA %p",
                             ike_sa));

  if (ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED)
    {
      ssh_operation_unregister_no_free(ed->operation_handle);
      ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;
      SSH_DEBUG(SSH_D_LOWSTART, ("Freeing reference"));
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }

  if (ed->sa_i)
    ssh_ikev2_sa_free(ike_sa->server->sad_handle, ed->sa_i);
  ed->sa_i = NULL;

  if (ed->sa)
    ssh_ikev2_sa_free(ike_sa->server->sad_handle, ed->sa);
  ed->sa = NULL;

  if (ed->dh_secret)
    ssh_pk_group_dh_secret_free(ed->dh_secret);
  ed->dh_secret = NULL;

  if (ed->ts_local)
    ssh_ikev2_ts_free(ike_sa->server->sad_handle, ed->ts_local);
  ed->ts_local = NULL;

  if (ed->ts_remote)
    ssh_ikev2_ts_free(ike_sa->server->sad_handle, ed->ts_remote);
  ed->ts_remote = NULL;

  if (ed->ts_i)
    ssh_ikev2_ts_free(ike_sa->server->sad_handle, ed->ts_i);
  ed->ts_i = NULL;

  if (ed->ts_r)
    ssh_ikev2_ts_free(ike_sa->server->sad_handle, ed->ts_r);
  ed->ts_r = NULL;

#ifdef SSHDIST_IKEV1
  if (ed->ikev1_keymat)
    ssh_free(ed->ikev1_keymat);
#endif /* SSHDIST_IKEV1 */

  if (ed->new_ike_sa)
    {
      if (ed->new_ike_sa->waiting_for_delete == NULL)
        {
          /* OK, Special case in ikev2_free_exchange_data */
          SSH_IKEV2_POLICY_NOTIFY(ed->new_ike_sa, ike_sa_delete)
            (ed->new_ike_sa->server->sad_handle, ed->new_ike_sa, NULL, NULL);
        }
      else
        {
          SSH_IKEV2_IKE_SA_FREE(ed->new_ike_sa);
        }
    }
  ed->new_ike_sa = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Successfully freed IPsec exchange data from SA %p",
                          ike_sa));
}

/* Free IKE SA exchange data. */
void ikev2_free_exchange_data_ike(SshIkev2Sa ike_sa,
                                  SshIkev2SaExchangeData ed)
{

  if (ed == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing IKE exchange data from SA %p", ike_sa));

  if (ed->sa_i)
    ssh_ikev2_sa_free(ike_sa->server->sad_handle, ed->sa_i);
  ed->sa_i = NULL;

  if (ed->dh_secret)
    ssh_pk_group_dh_secret_free(ed->dh_secret);
  ed->dh_secret = NULL;

#ifdef SSHDIST_IKE_CERT_AUTH
  if (ed->private_key)
    ssh_private_key_free(ed->private_key);
  ed->private_key = NULL;

  if (ed->public_key)
    ssh_public_key_free(ed->public_key);
  ed->public_key = NULL;
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (ed->data_to_signed)
    ssh_free(ed->data_to_signed);
  ed->data_to_signed = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Successfully freed IKE exchange data from SA %p",
                          ike_sa));
}


/* Exchange Data and IKE SA Reference Counting in IKEv2 Initiator Exchanges

   Initial and Child Exchanges:

     ssh_ikev2_ipsec_create_sa takes one reference to IKE SA and creates the
   ED. If ssh_ikev2_ipsec_exchange_destroy is called, both references are freed
   and the exchange is aborted before any packets are sent out.
     ssh_ikev2_ipsec_send reuses the references taken in ipsec_create_sa, and
   assigns them to the packet.
     If this is an initial exchange, then the function takes a reference to ED
   and sets it to ike_sa->initial_ed. The function also takes a reference to
   IKE SA and associates this with the operation handle.
     The IKE SA reference in the packet is freed in packet_destroy. The ED
   reference in ike_sa->initial_ed is freed in state
   ikev2_state_auth_initiator_in_finish (or in packet_destroy).
     The references associated to the operation handle are freed either when
   the operation is unregistered in ikev2_state_auth_initiator_in_finish, or in
   the operation abort callback ikev2_ike_sa_abort.
     If this is a chils exchange, then the function ssh_ikev2_ipsec_send takes
   references to IKE SA and ED, and associates them with the operation handle.
      The IKE SA reference in the packet is freed in packet_destroy. The ED
   reference in the packet is freed in ikev2_state_child_initiator_in_finish
   (or in packet_destroy).
     The references associated to the operation handle are freed either when
   the operation is unregistered in ikev2_state_child_initiator_in_finish, or
   in the operation abort callback ikev2_ipsec_sa_abort.

   IKE Rekeys:

     ssh_ikev2_ike_sa_rekey take on reference to IKE SA and creates the ED.
   These references are assigned to the packet. The function also takes
   references to IKE SA and ED, and associates them with the operation.
     ikev2_state_ike_rekey_initiator_out_alloc_sa creates the new IKE SA, and
   sets the packet->ed->ipsec_ed->new_ike_sa.
     The IKE SA reference in the packet is freed in packet_destroy. The ED ref
   in the packet is freed in ikev2_state_ike_rekey_initiator_in_finish (or in
   packet_destroy).
     The references associated to the operation handle are frees either when
   the operation is unregistered in ikev2_state_ike_rekey_initiator_in_finish,
   or in the operation abort callback ikev2_rekey_sa_abort.
     The reference to the new IKE SA in packet->ed->ipsec_ed->new_ike_sa is
   also freed in ikev2_state_ike_rekey_initiator_in_finish.

   Informational Exchanges:

     ssh_ikev2_info_create takes one reference to IKE SA and creates the ED. If
   ssh_ikev2_info_destroy is called, both references are freed there and the
   informational exchange is aborted before any packets are sent out.
     ssh_ikev2_info_send reuses the references taken in info_create, and
   assigns them to the packet. In addition the function takes one reference to
   IKE SA and to ED and associates them with the operation.
     The IKE SA reference in the packet is freed in packet_destroy. The ED
   reference in the packet is freed in ikev2_state_info_initiator_in_end (or in
   packet_destroy).
     The references associated to the operation handle are freed either when
   the operation is unregistered in ikev2_state_info_initiator_in_end, or in
   the operation abort callback ikev2_info_sa_abort.

   IKE SA Delete:

     ssh_ikev2_ike_sa_delete takes one reference to IKE SA. This reference is
   freed in the subsequent ike_sa_delete policy call. If a delete notification
   is sent, then the function takes one reference to IKE SA and creates the ED,
   and assigns them to packet. In addition the function takes one reference to
   IKE SA and to ED, and associates them with the operation.
     The IKE SA reference in the packet is freed in packet_destroy. The ED
   reference in the packet is freed ikev2_state_info_initiator_in_end (or in
   packet_destroy).
     The references associated to the operation handle are freed either when
   the operation is unregistered in ikev2_state_info_initiator_in_end, or in
   the operation abort callback ikev2_ike_sa_delete_abort.
*/

void ikev2_reference_exchange_data(SshIkev2ExchangeData ed)
{
  ed->ref_cnt += 1;
  SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to exchange data %p (to %d)",
                          ed, ed->ref_cnt));
}

void ssh_ikev2_exchange_data_take_ref(SshIkev2ExchangeData ed)
{
  ikev2_reference_exchange_data(ed);
}

void ssh_ikev2_exchange_data_free(SshIkev2ExchangeData ed)
{
  ikev2_free_exchange_data(ed->ike_sa, ed);
}

/* Free exchange data. */
void ikev2_free_exchange_data(SshIkev2Sa ike_sa, SshIkev2ExchangeData ed)
{
  if (ed == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing exchange data from SA %p, ED %p (%d)",
                             ike_sa, ed, ed->ref_cnt));

  if (--ed->ref_cnt != 0)
    return;

  SSH_ASSERT(ike_sa == ed->ike_sa);
  if (ed->operation != NULL)
    ssh_operation_abort(ed->operation);
  ed->operation = NULL;

  if (ed->callback)
    {
      (*(ed->callback))(ike_sa->server->sad_handle,
                        ike_sa, ed, SSH_IKEV2_ERROR_SA_UNUSABLE);
      ed->callback = NULL_FNPTR;
    }

  ssh_cancel_timeout(ed->timeout);

  /* Delete the packet. */
  if (ed->packet_to_process)
    {
      /* This means that we were called during the async
         diffie-hellman call, and this packet is waiting in
         queue. Delete it, and mark that the ike_sa has
         already been freed. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Killing the thread for packet %p SA %p",
                                 ed->packet_to_process,
                                 ike_sa));
      ssh_fsm_uninit_thread(ed->packet_to_process->thread);
      SSH_ASSERT(ed->packet_to_process->ike_sa == ike_sa);
      SSH_IKEV2_IKE_SA_FREE(ed->packet_to_process->ike_sa);
      ed->packet_to_process->ike_sa = NULL;
    }
  ed->packet_to_process = NULL;

  if (ed->info_ed)
    ikev2_free_exchange_data_info(ike_sa, ed->info_ed);
  ed->info_ed = NULL;

  if (ed->ipsec_ed)
    ikev2_free_exchange_data_ipsec(ike_sa, ed->ipsec_ed);
  ed->ipsec_ed = NULL;

  if (ed->ike_ed)
    ikev2_free_exchange_data_ike(ike_sa, ed->ike_ed);
  ed->ike_ed = NULL;

  if (ed->buffer)
    ssh_buffer_free(ed->buffer);
  ed->buffer = NULL;

  if (ed->sa)
    ssh_ikev2_sa_free(ike_sa->server->sad_handle, ed->sa);
  ed->sa = NULL;

  if (ed->conf)
    ssh_ikev2_conf_free(ike_sa->server->sad_handle, ed->conf);
  ed->conf = NULL;

  /* OK, Special case in ikev2_free_exchange_data */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, exchange_data_free)
    (ike_sa->server->sad_handle, ed);

  SSH_DEBUG(SSH_D_LOWOK, ("Successfully freed exchange data from SA %p",
                          ike_sa));
}

/* Take reference to the IKE SA. */
void
ssh_ikev2_ike_sa_take_ref(SshIkev2Sa ike_sa)
{
  /* OK, Special case in fsmdoc */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_take_ref)
    (ike_sa->server->sad_handle, ike_sa);
}

/* Free one reference to the IKE SA. */
void
ssh_ikev2_ike_sa_free(SshIkev2Sa ike_sa)
{
  /* OK, Special case in fsmdoc */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_free_ref)
    (ike_sa->server->sad_handle, ike_sa);
}


/******************************** IKE SA deletion ***************************/

typedef struct SshIkev2IkeSaDeleteTempContextRec {
  SshSADHandle sad_handle;
  SshIkev2NotifyCB callback;
  SshOperationDestructorStruct dest[1];
} *SshIkev2IkeSaDeleteTempContext;

void ikev2_ike_sa_delete_cb(SshIkev2Error error_code,
                            void *context)
{
  SshIkev2IkeSaDeleteTempContext temp = context;

  if (temp->callback)
    (*temp->callback)(temp->sad_handle, NULL, NULL, error_code);
}

/* Free the temporary context. */
void ikev2_ike_sa_delete_free_temp(Boolean aborted,
                                   void *context)
{
  SshIkev2IkeSaDeleteTempContext temp = context;
  ssh_free(temp);
}

/* Aborting the delete send operation. */
void ikev2_ike_sa_delete_abort(void *context)
{
  SshIkev2ExchangeData ed = context;
  SshIkev2Sa ike_sa = ed->ike_sa;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Info IKE SA delete ED %p IKE SA %p exchange aborted %@;%d",
             ed, ike_sa, ssh_ipaddr_render, ike_sa->remote_ip,
             ike_sa->remote_port));

  /* If the exchange was in response processing terminate that packet
     too.
  */
  if (ed->response_packet != NULL)
    {
      SshIkev2Packet response_packet = ed->response_packet;

      ed->response_packet = NULL;

      ikev2_packet_done(response_packet);
    }


  /* Clear the callback so the free_exchange_data will not call it. */
  ed->callback = NULL_FNPTR;

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
  ikev2_free_exchange_data(ike_sa, ed);

  if (ike_sa->waiting_for_delete == NULL)
    {
      /* And then we destroy the IKE SA. Note, that we have
         one reference which we took when installing the
         operation, and this will consume that one. */
      /* OK, Added to the ssh_ikev2_ike_sa_delete  */
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
SSH_FSM_STEP(ssh_ikev2_ike_sa_delete) */

/* Delete the IKEv2 SA. This will call the delete_callback
   after the sa is actually deleted. This will automatically
   take the references needed to finish the operation. */
SshOperationHandle
ssh_ikev2_ike_sa_delete(SshIkev2Sa ike_sa,
                        SshUInt32 flags,
                        SshIkev2NotifyCB callback)
{
  SshIkev2PayloadDelete del;
  SshIkev2ExchangeData ed;
  SshIkev2Error error;
  SshIkev2Packet packet;

#ifdef SSHDIST_IKEV1
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      SshUInt32 isakmp_flags = 0;
      if ((flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION) == 0)
        isakmp_flags |= SSH_IKE_REMOVE_FLAGS_SEND_DELETE;
      if (flags & SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW)
        isakmp_flags |= SSH_IKE_REMOVE_FLAGS_FORCE_DELETE_NOW;

      if (ike_sa->v1_sa)
        ssh_ike_remove_isakmp_sa(ike_sa->v1_sa, isakmp_flags);

      if (callback)
        {
          (*callback)(ike_sa->server->sad_handle,
                      ike_sa, NULL,
                      SSH_IKEV2_ERROR_OK);
        }

      return NULL;
    }
#endif /* SSHDIST_IKEV1 */

  if (flags & SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION)
    {
      SshIkev2IkeSaDeleteTempContext temp;
      SshOperationHandle handle;
      SshIkev2SadIkeSaDelete ike_sa_delete;

      if (ike_sa->waiting_for_delete != NULL)
        {
          if (callback)
            (*callback)(ike_sa->server->sad_handle,
                        ike_sa, NULL,
                        SSH_IKEV2_ERROR_SA_UNUSABLE);
          return NULL;
        }

      temp = ssh_calloc(1, sizeof(*temp));
      if (temp == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Error: Out of memory when allocating temp context"));
          if (callback)
            (*callback)(ike_sa->server->sad_handle,
                        ike_sa,
                        NULL,
                        SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return NULL;
        }

      temp->sad_handle = ike_sa->server->sad_handle;
      temp->callback = callback;

      /* Take a reference to IKE SA. It is freed in the ike_sa_delete
         policy call below. */
      SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
      ike_sa_delete = ike_sa->server->sad_interface->ike_sa_delete;
      /* This is actually
         SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
         call, but we cannot call POLICY_NOTIFY as we need to store
         the handle. */
      handle = (*ike_sa_delete)(ike_sa->server->sad_handle,
                                ike_sa,
                                ikev2_ike_sa_delete_cb,
                                temp);
      if (handle == NULL)
        {
          ssh_free(temp);
          return NULL;
        }

      ssh_operation_attach_destructor_no_alloc(temp->dest,
                                               handle,
                                               ikev2_ike_sa_delete_free_temp,
                                               temp);
      return handle;
    }

  if (ike_sa->server->server_stopped_flags)
    {
      if (callback)
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

  ed = ikev2_allocate_exchange_data(ike_sa);
  if (ed == NULL)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, NULL,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return NULL;
    }

  error = ikev2_allocate_exchange_data_info(ed);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }
  ed->info_ed->flags = SSH_IKEV2_INFO_CREATE_FLAGS_INITIATOR;
  SSH_DEBUG(SSH_D_LOWSTART, ("State = INFORMATIONAL_DELETING"));
  ed->state = SSH_IKEV2_STATE_INFORMATIONAL_DELETING;

  SSH_DEBUG(SSH_D_MIDSTART, ("Sending IKE SA delete %@;%d",
                             ssh_ipaddr_render, ike_sa->remote_ip,
                             ike_sa->remote_port));

  del = ssh_obstack_alloc(ed->obstack, sizeof(*del));
  if (del == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating delete"));
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }

  del->protocol = SSH_IKEV2_PROTOCOL_ID_IKE;
  del->spi_size = 0;
  del->number_of_spis = 0;
  del->spi.spi_table = NULL;
  del->next_delete = ed->info_ed->del;
  ed->info_ed->del = del;

  /** Send first informational packet */
  /* SSH_FSM_SET_NEXT(ikev2_state_info_initiator_out) */
  packet = ikev2_packet_allocate(ike_sa->server->context,
                                 ikev2_state_info_initiator_out);

  if (packet == NULL)
    {
      if (callback)
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, ed,
                    SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }

  /* After this we must make sure we clear the ed->callback in case
     we call the callback directly.  */
  ed->callback = callback;

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
        (*callback)(ike_sa->server->sad_handle,
                    ike_sa, ed,
                    error);
      /* Clear the callback so it will not be called twice. */
      ed->callback = NULL_FNPTR;
      ikev2_free_exchange_data(ike_sa, ed);
      return NULL;
    }

  /* Take references to IKE SA and ED given to the abort. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
  ikev2_reference_exchange_data(ed);
  /** Called if delete operation is aborted */
  /* SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
  ssh_operation_register_no_alloc(ed->info_ed->operation_handle,
                                  ikev2_ike_sa_delete_abort,
                                  ed);
  ed->info_ed->flags |= SSH_IKEV2_INFO_OPERATION_REGISTERED;

  /* Take new reference to the IKE SA and store it to packet.
     Store the ED reference (from ikev2_allocate_exchange_data_info)
     to packet. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
  packet->ike_sa = ike_sa;
  packet->ed = ed;

  packet->exchange_type = SSH_IKEV2_EXCH_TYPE_INFORMATIONAL;
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

  SSH_DEBUG(SSH_D_MIDOK, ("Sending IKE SA delete %@;%d",
                          ssh_ipaddr_render, ike_sa->remote_ip,
                          ike_sa->remote_port));

  /* We can do the actual IKE SA delete here, but as we
     still have  references out it will take place only
     after the request and reply has been processed and
     after the callback has been called. */
  SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);

  /** Normal delete */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
    (ike_sa->server->sad_handle, ike_sa, NULL, NULL);

  return ed->info_ed->operation_handle;
}

/* Function inside the IKE library which the policy manager
   should use to uninitialize the IKE SA after all
   references to it has been freed. This will free the IKE
   SA allocated data (like sk_d and windows) before the
   policy manager actually frees the data. */
void ssh_ikev2_ike_sa_uninit(SshIkev2Sa ike_sa)
{
#ifdef SSHDIST_IKEV1
  if (ike_sa->v1_sa)
    ikev2_fb_ike_sa_uninit(ike_sa);
#endif /* SSHDIST_IKEV1 */

  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
#ifdef SSHDIST_IKEV1
      && !(ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
#endif /* SSHDIST_IKEV1 */
      )
    ikev2_debug_ike_sa_close(ike_sa);

  if (ike_sa->initial_ed != NULL)
    {
      ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
      ike_sa->initial_ed = NULL;
    }
  if (ike_sa->rekey != NULL)
    {
      if (ike_sa->rekey->responded_new_sa != NULL)
        SSH_IKEV2_IKE_SA_FREE(ike_sa->rekey->responded_new_sa);
      if (ike_sa->rekey->initiated_new_sa != NULL)
        SSH_IKEV2_IKE_SA_FREE(ike_sa->rekey->initiated_new_sa);
      ssh_free(ike_sa->rekey->initiated_smaller_nonce);
      ssh_free(ike_sa->rekey->responded_smaller_nonce);
      ssh_free(ike_sa->rekey);
      ike_sa->rekey = NULL;
    }
  if (ike_sa->sk_d_len)
    ssh_free(ike_sa->sk_d);
  ike_sa->sk_d = NULL;

  ikev2_transmit_window_uninit(ike_sa->transmit_window);
  ikev2_receive_window_uninit(ike_sa->receive_window);
}


#ifdef SSHDIST_IKE_MOBIKE
/** Initiator API for Mobike IKE exchanges */

/** Sets the server, remote_ip, and remote_port to the SshIkev2Sa ike_sa.
    The remote_ip should be copied during this call. */
SshIkev2Error
ssh_ikev2_ike_sa_change_addresses(SshIkev2Sa sa,
                                  SshIkev2Server server,
                                  SshIpAddr remote_ip,
                                  SshUInt16 remote_port,
                                  SshUInt32 flags)
{
  SSH_VERIFY(sa != NULL);

  /* Note that server may be NULL, but in that case flags must contain
     SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_NEXT_ADDRESS_PAIR or
     SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REQUEST_ADDRESSES. */

  if (flags & (SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_NEXT_ADDRESS_PAIR
               | SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REQUEST_ADDRESSES))
    {
      sa->request_address_from_policy = 1;

      if (flags & SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_NEXT_ADDRESS_PAIR)
        sa->address_index++;

      SSH_DEBUG(SSH_D_MIDOK, ("Changing IKE SA to request address pair %d",
                              sa->address_index));

      return SSH_IKEV2_ERROR_OK;
    }

  SSH_ASSERT(server != NULL);
  SSH_ASSERT(server->context->ikev2_suspended == FALSE);
  SSH_ASSERT((SSH_IP_IS6(server->ip_address) && SSH_IP_IS6(remote_ip)) ||
             (SSH_IP_IS4(server->ip_address) && SSH_IP_IS4(remote_ip)));

  SSH_DEBUG(SSH_D_MIDOK, ("Changing IKE SA address from "
                          "local:%@ remote:%@:%d to "
                          "local:%@ remote:%@:%d, NAT-T flags %08lx",
                          ssh_ipaddr_render, sa->server->ip_address,
                          ssh_ipaddr_render, sa->remote_ip, sa->remote_port,
                          ssh_ipaddr_render, server->ip_address,
                          ssh_ipaddr_render, remote_ip, remote_port,
                          (unsigned long) flags));
  sa->server = server;
  sa->remote_ip[0] = *remote_ip;
  sa->remote_port = remote_port;
  sa->address_index = 0;
  sa->address_index_count = 0;
  /* Clear the request address flag as the application has now decided
     on new addresses for the IKE SA. */
  sa->request_address_from_policy = 0;

  if (flags & SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT)
    sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT;
  else
    sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT;

  if (flags & SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT)
    sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT;
  else
    sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT;

  /* Move packets in the window to the new server. */
  ikev2_window_change_server(sa, server);

  return SSH_IKEV2_ERROR_OK;
}
#endif /* SSHDIST_IKE_MOBIKE */
