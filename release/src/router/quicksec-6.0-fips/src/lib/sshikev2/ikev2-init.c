/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 initialization and initiator module.
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

#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshIkev2Init"

SshUInt32 ikev2_udp_sa_half_hash(const void *p, void *context);
int ikev2_udp_sa_half_compare(const void *p1, const void *p2, void *context);
void ikev2_udp_sa_half_free(void *obj, void *context);
void ssh_ikev2_server_shutdown(void *context);
extern const int ikev2_num_states;
extern SSH_RODATA SshFSMStateDebugStruct ikev2_state_array[];

/* Initialize IKEv2 library. Return NULL if the allocation
   of the structures fails. If the params is NULL (or memset
   to zero) then use the default parameters. This does not
   allocate the SAD or anything else. */
SshIkev2
ssh_ikev2_create(SshIkev2Params params)
{
  SshCryptoStatus status;
  SshIkev2 ikev2;
  int i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Allocating IKEv2 context"));
  ikev2 = ssh_calloc(1, sizeof(*ikev2));

  if (ikev2 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating ikev2"));
      return NULL;
    }

  ssh_fsm_init(ikev2->fsm, ikev2);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(ikev2->fsm, ikev2_state_array,
                               ikev2_num_states);
#endif /* DEBUG_LIGHT */

  if ((status = ssh_hash_allocate("md5", &ikev2->hash)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error %s allocating transport hash",
                             ssh_crypto_status_message(status)));
      goto failed;
    }

  if ((ikev2->server_list =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshIkev2ServerStruct,
                                                server_list_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server_list"));
      goto failed;
    }

  if ((ikev2->packets_free =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshIkev2PacketStruct,
                                                freelist_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating packets_free"));
      goto failed;
    }

  if ((ikev2->packets_used =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshIkev2PacketStruct,
                                                freelist_header),
                              SSH_ADT_ARGS_END)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating packets_used"));
      goto failed;
    }

  if ((ikev2->sa_half_by_spi =
       ssh_adt_create_generic(SSH_ADT_BAG,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshIkev2HalfStruct,
                                                bag_header),
                              SSH_ADT_HASH, ikev2_udp_sa_half_hash,
                              SSH_ADT_COMPARE, ikev2_udp_sa_half_compare,
                              SSH_ADT_DESTROY, ikev2_udp_sa_half_free,
                              SSH_ADT_ARGS_END)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating packets_used"));
      goto failed;
    }

  if ((ikev2->group_intmap = ssh_adt_create_intmap()) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating group_intmap"));
      goto failed;
    }

  if (params != NULL && params->packet_preallocate_size)
    {
      SshIkev2Packet packet;

      for (i = 0; i < params->packet_preallocate_size; i++)
        {
          if ((packet = ssh_calloc(1, sizeof(*packet))) == NULL)
            goto failed;

          SSH_DEBUG(SSH_D_MY, ("Allocated packet %p from heap", packet));
          ssh_adt_insert(ikev2->packets_free, packet);
        }
    }

  if (params == NULL || params->normal_udp_params == NULL)
    ikev2->params.normal_udp_params = NULL;
  else
    ikev2->params.normal_udp_params = params->normal_udp_params;

  if (params == NULL || params->nat_t_udp_params == NULL)
    {
      if (params == NULL || params->normal_udp_params == NULL)
        ikev2->params.nat_t_udp_params = NULL;
      else
        ikev2->params.nat_t_udp_params = params->normal_udp_params;
    }
  else
    {
      ikev2->params.nat_t_udp_params = params->nat_t_udp_params;
    }

  if (params == NULL || params->forced_nat_t_enabled == FALSE)
    ikev2->params.forced_nat_t_enabled = FALSE;
  else
    ikev2->params.forced_nat_t_enabled = TRUE;

  if (params == NULL || params->audit_context == NULL)
    ikev2->params.audit_context = NULL;
  else
    ikev2->params.audit_context = params->audit_context;

  if (params == NULL || params->retry_limit == 0)
    ikev2->params.retry_limit = 10;
  else
    ikev2->params.retry_limit = params->retry_limit;

  if (params == NULL || params->retry_timer_msec == 0)
    ikev2->params.retry_timer_msec = 500;
  else
    ikev2->params.retry_timer_msec = params->retry_timer_msec;

  if (params == NULL || params->retry_timer_max_msec == 0)
    ikev2->params.retry_timer_max_msec = 10000;
  else
    ikev2->params.retry_timer_max_msec = params->retry_timer_max_msec;

#ifdef SSHDIST_IKE_MOBIKE
  if (params == NULL || params->mobike_worry_counter == 0)
    ikev2->params.mobike_worry_counter = 2;
  else
    ikev2->params.mobike_worry_counter = params->mobike_worry_counter;
#endif /* SSHDIST_IKE_MOBIKE */

  if (params == NULL || params->packet_cache_size == 0)
    ikev2->params.packet_cache_size = 0;
  else
    ikev2->params.packet_cache_size = params->packet_cache_size;

#ifdef SSHDIST_EXTERNALKEY
  if (params == NULL || params->external_key == NULL)
    ikev2->params.external_key = NULL;
  else
    ikev2->params.external_key = params->external_key;

  if (params == NULL || params->accelerator_short_name == NULL)
    ikev2->params.accelerator_short_name = NULL;
  else
    ikev2->params.accelerator_short_name = params->accelerator_short_name;
#endif /* SSHDIST_EXTERNALKEY */

  if (params == NULL || params->cookie_secret_timer == 0)
    ikev2->params.cookie_secret_timer = 5;
  else
    ikev2->params.cookie_secret_timer = params->cookie_secret_timer;

  ikev2->cookie_version_number = 1;
  ikev2->cookie_secret_created = ssh_time();
  ikev2->cookie_secret_use_counter = 0;
  ikev2->cookie_secret_use_counter_prev = 0;
  for(i = 0; i < IKEV2_COOKIE_SECRET_LEN; i++)
    {
      ikev2->cookie_secret[i] = ssh_random_get_byte();
      ikev2->cookie_secret_prev[i] = ssh_random_get_byte();
    }
  if ((status = ikev2_groups_init(ikev2)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error %s when initializing groups",
                              ssh_crypto_status_message(status)));

    failed:
      ssh_ikev2_destroy(ikev2);
      return NULL;
    }

  if (params != NULL)
    ikev2->params.debug_config = params->debug_config;

#ifdef SSHDIST_IKEV1
  if (params != NULL && params->v1_fallback)
    {
      /* Set undefined IKEv1 params with IKEv2 param values */

      if (params->v1_params->base_retry_limit == 0)
        params->v1_params->base_retry_limit = ikev2->params.retry_limit;

      if (params->v1_params->base_retry_timer == 0 &&
          params->v1_params->base_retry_timer_usec == 0)
        {
          params->v1_params->base_retry_timer =
            (ikev2->params.retry_timer_msec / 1000);
          params->v1_params->base_retry_timer_usec =
            (ikev2->params.retry_timer_msec % 1000) * 1000;
        }

      if (params->v1_params->base_retry_timer_max == 0 &&
          params->v1_params->base_retry_timer_max_usec == 0)
        {
          params->v1_params->base_retry_timer_max =
            (ikev2->params.retry_timer_max_msec / 1000);
          params->v1_params->base_retry_timer_max_usec =
            (ikev2->params.retry_timer_max_msec % 1000) * 1000;
        }

      if (params->v1_params->base_expire_timer == 0 &&
          params->v1_params->base_expire_timer_usec == 0)
        {
          params->v1_params->base_expire_timer =
            (params->expire_timer_msec / 1000);
          params->v1_params->base_expire_timer_usec =
            (params->expire_timer_msec % 1000) * 1000;
        }

#ifdef SSHDIST_EXTERNALKEY
      if (params->v1_params->external_key == NULL)
        params->v1_params->external_key = ikev2->params.external_key;

      if (params->v1_params->accelerator_short_name == NULL)
        params->v1_params->accelerator_short_name =
          ikev2->params.accelerator_short_name;
#endif /* SSHDIST_EXTERNALKEY */

      if ((ikev2->fallback = ssh_ikev2_fallback_create(params->v1_params,
                                                       params->audit_context))
          == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Error when initializing IKEv1 fallback"));
          goto failed;
        }
    }

#endif /* SSHDIST_IKEV1 */
  /* Memset timeout to zero so it can be safely cancelled. Do not
     start the timer yet, as it is only run on demand. */
  memset(ikev2->timeout, 0, sizeof(*ikev2->timeout));

  SSH_DEBUG(SSH_D_MIDOK, ("Succesfully allocated IKEv2 context"));
  return ikev2;
}


/* Uninitialized IKEv2 library. This can only be called when
   all servers have been successfully stopped. This will
   free all the data structures associated with the IKEv2
   library. */
void
ssh_ikev2_destroy(SshIkev2 ikev2)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Destroying IKEv2 context"));

  ssh_cancel_timeout(ikev2->timeout);
  ikev2_groups_uninit(ikev2);

  if (ikev2->group_intmap)
    ssh_adt_destroy(ikev2->group_intmap);
  if (ikev2->sa_half_by_spi)
    ssh_adt_destroy(ikev2->sa_half_by_spi);

  if (ikev2->packets_used)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle handle;

      for (handle = ssh_adt_enumerate_start(ikev2->packets_used);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_next(ikev2->packets_used, handle))
        {
          SshIkev2Packet packet = ssh_adt_get(ikev2->packets_used, handle);
          SSH_DEBUG(SSH_D_ERROR,
                    ("Packet %p ED %p IKE SA %p used",
                     packet, packet->ed,
                     packet->ed != NULL ? packet->ed->ike_sa : 0));
        }
#endif /* DEBUG_LIGHT */
      SSH_ASSERT(ssh_adt_num_objects(ikev2->packets_used) == 0);
      ssh_adt_destroy(ikev2->packets_used);
    }

  if (ikev2->packets_free)
    {
      SshADTHandle handle;

      for (handle = ssh_adt_enumerate_start(ikev2->packets_free);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_start(ikev2->packets_free))
        {
          SshIkev2Packet packet = ssh_adt_get(ikev2->packets_free, handle);


          ssh_adt_detach(ikev2->packets_free, handle);
          SSH_DEBUG(SSH_D_MY, ("Freed packet %p", packet));

          ssh_free(packet);
        }
      ssh_adt_destroy(ikev2->packets_free);
    }

  if (ikev2->server_list)
    {
      SSH_ASSERT(ssh_adt_num_objects(ikev2->server_list) == 0);
      ssh_adt_destroy(ikev2->server_list);
    }
  if (ikev2->hash)
    ssh_hash_free(ikev2->hash);

  ssh_fsm_uninit(ikev2->fsm);

#ifdef SSHDIST_IKEV1
  if (ikev2->fallback)
    {
      ssh_ikev2_fallback_destroy(ikev2->fallback);
    }
#endif /* SSHDIST_IKEV1 */

  ssh_free(ikev2);
  SSH_DEBUG(SSH_D_MIDOK, ("Succesfully destroyed IKEv2 context"));
}

/* Make new UDP listener tied to the ip_address and port. */
static SshUdpListener
ssh_ikev2_server_make_listener(SshIkev2Server server,
                               SshUdpListenerParams udp_params,
                               SshIpAddr ip_address,
                               SshUInt16 *local_port,
                               int interface_index,
                               int routing_instance_id)
{
  SshUdpListener listener;

  listener =
    ssh_udp_make_listener_ip(ip_address,
                             *local_port,
                             NULL,
                             0,
                             interface_index,
                             routing_instance_id,
                             udp_params,
                             ikev2_udp_recv,
                             server);

  /* Get selected local port if random local port requested. */
  if (listener != NULL && *local_port == 0)
    {
      if (ssh_udp_get_ip_addresses(listener, NULL, local_port, NULL, NULL)
          == FALSE)
        {
          ssh_udp_destroy_listener(listener);
          listener = NULL;
        }
    }

  return listener;
}


/**********************************************************************/
/* Add new server tied to the ip_address and ports to the be
   listened in the IKEv2 library. */
SshIkev2Server
ssh_ikev2_server_start(SshIkev2 ikev2,
                       SshIpAddr ip_address,
                       SshUInt16 normal_local_port,
                       SshUInt16 nat_t_local_port,
                       SshUInt16 normal_remote_port,
                       SshUInt16 nat_t_remote_port,
                       int interface_index,
                       int routing_instance_id,
                       SshSADInterface sad_interface,
                       SshSADHandle sad_handle)
{
  SshIkev2Server server;

  SSH_DEBUG(SSH_D_MIDSTART, ("Starting server %@;%d/%d -> %d/%d "
                             "routing instance %d",
                             ssh_ipaddr_render, ip_address,
                             normal_local_port, nat_t_local_port,
                             normal_remote_port, nat_t_remote_port,
                             routing_instance_id));

  server = ssh_calloc(1, sizeof(*server));
  if (server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server"));
      return NULL;
    }

  server->routing_instance_id = routing_instance_id;
  server->interface_index = interface_index;

  if (ip_address)
    *server->ip_address = *ip_address;

  server->normal_local_port = normal_local_port;
  server->nat_t_local_port = nat_t_local_port;
  server->normal_remote_port = normal_remote_port;
  server->nat_t_remote_port = nat_t_remote_port;
  server->original_normal_local_port = normal_local_port;
  server->original_nat_t_local_port = nat_t_local_port;
  server->sad_interface = sad_interface;
  server->sad_handle = sad_handle;
  server->context = ikev2;
  server->forced_nat_t_enabled = ikev2->params.forced_nat_t_enabled;

  if (server->normal_remote_port != 0)
    {
      server->normal_listener =
        ssh_ikev2_server_make_listener(server,
                                       ikev2->params.normal_udp_params,
                                       server->ip_address,
                                       &server->normal_local_port,
                                       server->interface_index,
                                       server->routing_instance_id);
      if (server->normal_listener == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("UDP make listener %@;%d failed",
                                 ssh_ipaddr_render, server->ip_address,
                                 server->normal_local_port));
          ssh_free(server);
          return NULL;
        }
    }

  if (server->nat_t_remote_port != 0)
    {
      server->nat_t_listener =
        ssh_ikev2_server_make_listener(server,
                                       ikev2->params.nat_t_udp_params,
                                       server->ip_address,
                                       &server->nat_t_local_port,
                                       server->interface_index,
                                       server->routing_instance_id);
      if (server->nat_t_listener == NULL)
        {
          ssh_udp_destroy_listener(server->normal_listener);
          SSH_DEBUG(SSH_D_FAIL, ("UDP make NAT-T listener %@;%d failed",
                                 ssh_ipaddr_render, server->ip_address,
                                 server->nat_t_local_port));
          ssh_free(server);
          return NULL;
        }
    }

#ifdef SSHDIST_IKEV1
  if (ikev2->fallback)
    ssh_ikev2_fallback_attach(server, ikev2->fallback);
#endif /* SSHDIST_IKEV1 */

  ssh_adt_insert(ikev2->server_list, server);
  SSH_DEBUG(SSH_D_MIDOK, ("Started server %@;%d/%d",
                          ssh_ipaddr_render, ip_address,
                          server->normal_local_port,
                          server->nat_t_local_port));
  return server;
}

/* Close and attempt to reopen UDP listeners for `server'. */
Boolean
ssh_ikev2_server_restart(SshIkev2Server server,
                         int interface_index)
{
  SshIkev2 ikev2 = server->context;

  SSH_ASSERT(server != NULL);
  SSH_DEBUG(SSH_D_MIDSTART, ("Restarting server %@;%d/%d -> %d/%d "
                             "routing instance %d",
                             ssh_ipaddr_render, server->ip_address,
                             server->normal_local_port,
                             server->nat_t_local_port,
                             server->normal_remote_port,
                             server->nat_t_remote_port,
                             server->routing_instance_id));

  if (server->normal_listener)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Stopping normal UDP listener"));

      ssh_udp_destroy_listener(server->normal_listener);
      server->normal_listener = NULL;
    }

  if (server->nat_t_listener)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Stopping NAT-T UDP listener"));

      ssh_udp_destroy_listener(server->nat_t_listener);
      server->nat_t_listener = NULL;
    }

  server->interface_index = interface_index;

  if (server->normal_remote_port != 0)
    {
      server->normal_listener =
        ssh_ikev2_server_make_listener(server,
                                       ikev2->params.normal_udp_params,
                                       server->ip_address,
                                       &server->normal_local_port,
                                       server->interface_index,
                                       server->routing_instance_id);
      if (server->normal_listener == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("UDP make listener %@;%d failed",
                                 ssh_ipaddr_render, server->ip_address,
                                 server->normal_local_port));
          return FALSE;
        }
    }

  if (server->nat_t_local_port != 0 && server->nat_t_remote_port != 0)
    {
      server->nat_t_listener =
        ssh_ikev2_server_make_listener(server,
                                       ikev2->params.nat_t_udp_params,
                                       server->ip_address,
                                       &server->nat_t_local_port,
                                       server->interface_index,
                                       server->routing_instance_id);
      if (server->nat_t_listener == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("UDP make NAT-T listener %@;%d failed",
                                 ssh_ipaddr_render, server->ip_address,
                                 server->nat_t_local_port));
          return FALSE;
        }
    }

  return TRUE;
}

void ikev2_server_free_now(void *context)
{
  ssh_free(context);
}

/* Check that the server does not have anymore IKE SAs and schedules server
   to be freed. */
void ikev2_server_free_check_sas(SshIkev2Error error,
                                 SshIkev2Sa ike_sa,
                                 void *context)
{
  SshIkev2Server server = context;

  if (ike_sa != NULL)
    {
      if (ike_sa->server == server)
        server->server_stopped_counter++;
    }
  else
    {
      if (server->server_stopped_counter != 0)
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("Server %@;%d/%d still has %d IKE SAs",
                                     ssh_ipaddr_render, server->ip_address,
                                     server->normal_local_port,
                                     server->nat_t_local_port,
                                     server->server_stopped_counter));

          if (ssh_register_timeout(NULL, 0, 500000L, ssh_ikev2_server_shutdown,
                                   server) != NULL)
            return;
          SSH_DEBUG(SSH_D_ERROR,
                    ("Unable to reschedule server free, continuing."));
        }

      SSH_DEBUG(SSH_D_MIDSTART, ("Freeing server %@;%d/%d",
                                 ssh_ipaddr_render, server->ip_address,
                                 server->normal_local_port,
                                 server->nat_t_local_port));

      if (server->normal_listener != NULL)
        ssh_udp_destroy_listener(server->normal_listener);
      if (server->nat_t_listener != NULL)
        ssh_udp_destroy_listener(server->nat_t_listener);

      server->server_stopped_flags |= SSH_IKEV2_SERVER_STOPPED_2;

      ssh_adt_detach_object(server->context->server_list, server);
      server->server_stopped_cb(error, server->server_stopped_context);
      SSH_DEBUG(SSH_D_MIDOK, ("Freed server %@;%d/%d",
                              ssh_ipaddr_render, server->ip_address,
                              server->normal_local_port,
                              server->nat_t_local_port));

      /* Free the server later, do not care if this fails */
      ssh_register_timeout(NULL, 0, 100, ikev2_server_free_now, server);
    }
}

/* Really free the server. This is called after the
   notifications etc have been sent to the other end. */
void ssh_ikev2_server_free(SshIkev2Error error,
                           SshIkev2Server server)
{
  SshADTHandle handle;

  /* Wait until all packets referring this server have reached
     terminal state. */
  for (handle = ssh_adt_enumerate_start(server->context->packets_used);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(server->context->packets_used, handle))
    {
      SshIkev2Packet packet = ssh_adt_get(server->context->packets_used,
                                          handle);
      if (packet->server == server)
        {
          /* This is the case where the exchange of the packet has
             already finished. */
          if (packet->ed == NULL && packet->ike_sa != NULL)
            {
              SSH_IKEV2_DEBUG(SSH_D_HIGHOK, ("Packet exchange is done, "
                                             "moving server from %p to %p",
                                             server, packet->ike_sa->server));
              packet->server = packet->ike_sa->server;
            }
          else
            {
              /* We have exchange going on, but we have already
                 sent this packet out. */
              if (packet->ed != NULL && packet->ike_sa != NULL &&
                  packet->sent)
                {
                  SSH_IKEV2_DEBUG(SSH_D_HIGHOK,
                                  ("Packet is already sent, "
                                   "moving server from %p to %p",
                                   server, packet->ike_sa->server));
                  packet->server = packet->ike_sa->server;
#ifdef SSHDIST_IKE_MOBIKE
                  packet->ed->multiple_addresses_used = 1;
#endif /* SSHDIST_IKE_MOBIKE */
                }
              else
                {
                  /* We have packet without IKE SA (i.e. waiting for
                     delete), or we are currently processing the
                     packet inside the state machine. */
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Packet %p refers to server %p, "
                             "rescheduling server free",
                             packet, server));
                  if (ssh_register_timeout(NULL, 0, 100000,
                                           ssh_ikev2_server_shutdown,
                                           server) != NULL)
                    return;
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Unable to reschedule server free, continuing."));
                }
            }
        }
    }

  /* Check that server does not contain any more IKE SAs and free server. */
  server->server_stopped_counter = 0;
  (*server->sad_interface->ike_enumerate)
    (server->sad_handle, ikev2_server_free_check_sas, server);
}

void ssh_ikev2_server_shutdown(void *context)
{
  SshIkev2Server server = context;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Calling server free"));
  ssh_ikev2_server_free(SSH_IKEV2_ERROR_OK, server);
}

void
ssh_ikev2_server_delete_sa_done(SshIkev2Error error_code,
                                void *context)
{
  SshIkev2Server server = context;

  server->server_stopped_counter--;
  SSH_DEBUG(SSH_D_MIDSTART, ("Delete done, %d still left",
                             server->server_stopped_counter));
  if (server->server_stopped_counter == 0)
    {
      SshTimeout timeout;

      SSH_DEBUG(SSH_D_HIGHSTART, ("Installing timer to call server free"));
      timeout = ssh_register_timeout(NULL, 0, 100,
                                     ssh_ikev2_server_shutdown, server);
      if (timeout == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Out of memory while shutting down"));
          ssh_ikev2_server_free(SSH_IKEV2_ERROR_OUT_OF_MEMORY, server);
        }
    }
}

typedef struct SshIkev2SaDeleteWaitRec {
  SshIkev2SadDeleteCB delete_callback;
  void *delete_callback_context;
  SshIkev2Server server;
} *SshIkev2SaDeleteWait, SshIkev2SaDeleteWaitStruct;

void
ssh_ikev2_server_free_ref_do(void *context)
{
  SshIkev2Sa sa = context;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Freeing reference of IKE SA %p %@ (%@;%d)",
             sa, ssh_ikev2_ike_spi_render, sa,
             ssh_ipaddr_render,
             sa->remote_ip, sa->remote_port));
  SSH_IKEV2_IKE_SA_FREE(sa);
}


void ikev2_server_wait_done(SshIkev2Error error, void *context)
{
  SshIkev2SaDeleteWait del = context;

  if (del->delete_callback)
    (*del->delete_callback)(error, del->delete_callback_context);
  ssh_ikev2_server_delete_sa_done(error, del->server);
  ssh_free(del);
}

void
ssh_ikev2_server_delete_sa_do(void *context)
{
  SshIkev2Sa sa = context;
  SshIkev2Server server = sa->server;

  /* Check if the SA was deleted during the timeout. */
  if (sa->waiting_for_delete != NULL)
    {
      /* Yes, simply chain ourselves to the callback. */
      SshIkev2SaDeleteWait del;

      /* First we free the reference we took earlier. */
      SSH_IKEV2_IKE_SA_FREE(sa);
      del = ssh_calloc(1, sizeof(*del));
      if (del == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory while shutting down and deleting "
                     "IKE SA %@ (%@;%d)",
                     ssh_ikev2_ike_spi_render, sa,
                     ssh_ipaddr_render,
                     sa->remote_ip, sa->remote_port));
          return;
        }
      del->delete_callback = sa->waiting_for_delete->delete_callback;
      del->delete_callback_context =
        sa->waiting_for_delete->delete_callback_context;
      del->server = server;
      sa->waiting_for_delete->delete_callback = ikev2_server_wait_done;
      sa->waiting_for_delete->delete_callback_context = del;
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Doing actual delete of IKE SA %p %@ (%@;%d)",
                                 sa, ssh_ikev2_ike_spi_render, sa,
                                 ssh_ipaddr_render,
                                 sa->remote_ip, sa->remote_port));
      (*server->sad_interface->ike_sa_delete)
        (server->sad_handle, sa,
         ssh_ikev2_server_delete_sa_done, server);
    }
}

void
ssh_ikev2_server_delete_sa(SshIkev2Error error_code,
                           SshIkev2Sa sa,
                           void *context)
{
  SshIkev2Server server = context;
  SshTimeout timeout;

  if (sa == NULL)
    {
      server->server_stopped_counter--;
      SSH_DEBUG(SSH_D_MIDSTART,
                ("Stopping server %@;%d/%d, enumerate %d SAs done",
                 ssh_ipaddr_render, server->ip_address,
                 server->normal_local_port, server->nat_t_local_port,
                 server->server_stopped_counter));
      if (server->server_stopped_counter == 0)
        {
          SSH_DEBUG(SSH_D_HIGHSTART, ("Installing timer to call server free"));
          timeout = ssh_register_timeout(NULL, 0, 100,
                                         ssh_ikev2_server_shutdown, server);
          if (timeout == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Out of memory while shutting down"));
              ssh_ikev2_server_free(SSH_IKEV2_ERROR_OUT_OF_MEMORY, server);
            }
        }
      return;
    }

#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    return;
#endif /* SSHDIST_IKEV1 */

  if (sa->server != server)
    return;

  SSH_DEBUG(SSH_D_MIDSTART, ("Starting delete of IKE SA %p %@ (%@;%d)",
                             sa, ssh_ikev2_ike_spi_render, sa,
                             ssh_ipaddr_render,
                             sa->remote_ip, sa->remote_port));
  if (sa->waiting_for_delete != NULL)
    {
      SshIkev2SaDeleteWait del;

      if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED)
        {
          /* Ok, we are simply waiting for the
             retransmissions from the other side, we can
             simply cancel the timeout, and free reference. */
          timeout = ssh_register_timeout(NULL, 0, 0,
                                         ssh_ikev2_server_free_ref_do, sa);
          if (timeout == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Out of memory while shutting down and deleting "
                         "IKE SA %@ (%@;%d)",
                         ssh_ikev2_ike_spi_render, sa,
                         ssh_ipaddr_render,
                         sa->remote_ip, sa->remote_port));
            }
          else
            {
              ssh_cancel_timeouts(ikev2_free_ref_after_timeout, sa);
              sa->waiting_for_delete->delete_callback =
                ssh_ikev2_server_delete_sa_done;
              sa->waiting_for_delete->delete_callback_context = server;
            }
        }
      else
        {
          /* The SA is already scheduled to be deleted, attach
             ourselves to the list of people getting
             notifications. */
          del = ssh_calloc(1, sizeof(*del));
          if (del == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Out of memory while shutting down and deleting "
                         "IKE SA %@ (%@;%d)",
                         ssh_ikev2_ike_spi_render, sa,
                         ssh_ipaddr_render,
                         sa->remote_ip, sa->remote_port));
              return;
            }
          del->delete_callback = sa->waiting_for_delete->delete_callback;
          del->delete_callback_context =
            sa->waiting_for_delete->delete_callback_context;
          del->server = server;
          sa->waiting_for_delete->delete_callback = ikev2_server_wait_done;
          sa->waiting_for_delete->delete_callback_context = del;
        }
    }
  else
    {
      /* We need to take reference, and then put the zero time
         where we delete the actual SA. */
      SSH_IKEV2_IKE_SA_TAKE_REF(sa);

      timeout = ssh_register_timeout(NULL, 0, 0,
                                     ssh_ikev2_server_delete_sa_do, sa);
      if (timeout == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory while shutting down and deleting "
                     "IKE SA %@ (%@;%d)",
                     ssh_ikev2_ike_spi_render, sa,
                     ssh_ipaddr_render,
                     sa->remote_ip, sa->remote_port));
          return;
        }
    }
  server->server_stopped_counter++;
}

void ikev2_server_stop_now(void *context)
{
  SshIkev2Server server = context;

  (*server->sad_interface->ike_enumerate)
    (server->sad_handle, ssh_ikev2_server_delete_sa, server);
}

/* Stop the server. The callback will be called when the
   server has been successfully stopped. */
void
ssh_ikev2_server_stop(SshIkev2Server server,
                      SshUInt32 flags,
                      SshIkev2ServerStoppedCB server_stopped_cb,
                      void *server_stopped_context)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("Stopping server %@;%d/%d",
                             ssh_ipaddr_render, server->ip_address,
                             server->normal_local_port,
                             server->nat_t_local_port));

  server->server_stopped_cb = server_stopped_cb;
  server->server_stopped_context = server_stopped_context;
  server->server_stopped_flags = (flags | SSH_IKEV2_SERVER_STOPPED_1);
  server->server_stopped_counter = 1;

#ifdef SSHDIST_IKEV1
  ssh_ikev2_fallback_detach(server);
#endif /* SSHDIST_IKEV1 */

  if (!ssh_register_timeout(NULL, 0, 0, ikev2_server_stop_now, server))
    ikev2_server_stop_now(server);
}

void ikev2_timer(void *context)
{
  SshIkev2 ikev2 = context;
  SshADTHandle handle, next;
  SshIkev2Half half_sa;
  int i;

  for (handle = ssh_adt_enumerate_start(ikev2->sa_half_by_spi);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      next = ssh_adt_enumerate_next(ikev2->sa_half_by_spi, handle);

      half_sa = ssh_adt_get(ikev2->sa_half_by_spi, handle);

      if (--half_sa->ttl == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Timing out Half-open SA entry from %@:%d"
                     " SPI in %08lx %08lx, SPI out %08lx %08lx",
                     ssh_ipaddr_render, half_sa->remote_ip,
                     half_sa->remote_port,
                     SSH_GET_32BIT(half_sa->ike_spi_i),
                     SSH_GET_32BIT(half_sa->ike_spi_i + 4),
                     SSH_GET_32BIT(half_sa->ike_spi_r),
                     SSH_GET_32BIT(half_sa->ike_spi_r + 4)));

          ssh_adt_delete(ikev2->sa_half_by_spi, handle);
        }
    }

  /* Check if cookies have been used. */
  if (ikev2->cookie_secret_use_counter != 0 ||
      ikev2->cookie_secret_use_counter_prev != 0)
    {
      /* Yes, do expire. */
      if (ssh_time() - ikev2->cookie_secret_created >
          ikev2->params.cookie_secret_timer)
        {
          /* Secret expired. */
          SSH_DEBUG(SSH_D_LOWOK, ("Recreating cookie secret."));
          ikev2->cookie_version_number++;
          ikev2->cookie_secret_created = ssh_time();

          ikev2->cookie_secret_use_counter_prev =
            ikev2->cookie_secret_use_counter;
          ikev2->cookie_secret_use_counter = 0;
          for (i = 0; i < IKEV2_COOKIE_SECRET_LEN; i++)
            {
              ikev2->cookie_secret_prev[i] = ikev2->cookie_secret[i];
              ikev2->cookie_secret[i] = ssh_random_get_byte();
            }
        }
    }

  if (ssh_adt_num_objects(ikev2->sa_half_by_spi) != 0)
    ssh_register_timeout(ikev2->timeout, 1, 0, ikev2_timer, ikev2);
}

void ikev2_audit_event(SshIkev2 ikev2,
                       SshAuditEvent event, ...)
{
  va_list ap;

  if (ikev2->params.audit_context)
    {
      va_start(ap, event);
      ssh_audit_event_va(ikev2->params.audit_context, event, ap);
      va_end(ap);
    }
}

/* Send audit event to audit log */
void ikev2_audit(SshIkev2Sa ike_sa,
                 SshAuditEvent event,
                 const char *txt)
{
  char spi[16];
  unsigned char src_ip_buf[16], dst_ip_buf[16];
  size_t src_ip_len, dst_ip_len;

  if (ike_sa == NULL)
    return;

  ikev2_debug_error(ike_sa, txt);

  memcpy(spi, ike_sa->ike_spi_i, 8);
  memcpy(spi + 8, ike_sa->ike_spi_r, 8);

  SSH_IP_ENCODE(ike_sa->server->ip_address, src_ip_buf, src_ip_len);
  SSH_IP_ENCODE(ike_sa->remote_ip, dst_ip_buf, dst_ip_len);

  ikev2_audit_event(ike_sa->server->context,
                    event,
                    SSH_AUDIT_SPI, spi, 16,
                    SSH_AUDIT_SOURCE_ADDRESS, src_ip_buf, src_ip_len,
                    SSH_AUDIT_DESTINATION_ADDRESS, dst_ip_buf, dst_ip_len,
                    SSH_AUDIT_TXT, txt,
                    SSH_AUDIT_ARGUMENT_END);
}

/** Suspends IKEv2 library. This makes it so that it does not
    process incoming packets anymore, and it also suspends
    internal processing of the ike library. The main reason is
    try to limit number of policy calls library might make to the
    policy manager. It does not prevent them completely, as
    timeouts, asyncronous crypto operations or CMI operations,
    etc are suspended, meaning if those return then ike library
    might call policy manager still. As most of the calls will be
    suspended, that means those few calls that might be called
    can safely be failed with SSH_IKEV2_ERROR_SUSPENDED, which
    will cause those few IKE SAs to fail.

    This will call the callback when suspend is done (this is
    fast operation, but it wants to make sure there is no IKEv2
    operations in the call stack and calls the callback from the
    bottom of event loop. This call cannot be called if ikev2
    library is already in suspended state (i.e. it cannot be
    called twice without the library being resumed between. */

void ssh_ikev2_suspend(SshIkev2 context,
                       SshUInt32 flags,
                       SshIkev2SuspendedCB suspended_cb,
                       void *suspended_context)
{
  SshTimeout timeout;

  SSH_ASSERT(context->ikev2_suspended == FALSE);
  timeout = ssh_register_timeout(NULL, 0, 0,
                                 suspended_cb, suspended_context);
  if (timeout == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Out of memory while suspending IKEv2 library"));
      (*suspended_cb)(suspended_context);
    }
  context->ikev2_suspended = TRUE;
  ssh_fsm_suspend(context->fsm);

#ifdef SSHDIST_IKEV1
  /* Suspend fallback FSM. */
  if (context->fallback)
    ssh_fsm_suspend(context->fallback->fsm);
#endif /* SSHDIST_IKEV1 */
}

/** Resume IKEv2 library after suspend. This can only be called
    when library has first been suspended and suspended callback
    has been called. After this library is again in normal
    running state. This will also start processing all of the
    packets which were queued during the suspend. */

void ssh_ikev2_resume(SshIkev2 context)
{
  SSH_ASSERT(context->ikev2_suspended == TRUE);
  context->ikev2_suspended = FALSE;
  ssh_fsm_resume(context->fsm);

#ifdef SSHDIST_IKEV1
  /* Resume fallback FSM. */
  if (context->fallback)
    ssh_fsm_resume(context->fallback->fsm);
#endif /* SSHDIST_IKEV1 */
}


#ifdef DEBUG_LIGHT
SSH_RODATA
SshFSMStateDebugStruct ikev2_state_array[] =
{
  SSH_FSM_STATE("ikev2_packet_st_allocated",
                "ikev2 packet st allocated",
                ikev2_packet_st_allocated)
  SSH_FSM_STATE("ikev2_packet_st_connect_decision",
                "ikev2 packet st connect decision",
                ikev2_packet_st_connect_decision)
  SSH_FSM_STATE("ikev2_packet_st_done",
                "ikev2 packet st done",
                ikev2_packet_st_done)
  SSH_FSM_STATE("ikev2_packet_st_forward",
                "ikev2 packet st forward",
                ikev2_packet_st_forward)
  SSH_FSM_STATE("ikev2_packet_st_input_get_or_create_sa",
                "ikev2 packet st input get or create sa",
                ikev2_packet_st_input_get_or_create_sa)
  SSH_FSM_STATE("ikev2_packet_st_input_start",
                "ikev2 packet st input start",
                ikev2_packet_st_input_start)
#ifdef SSHDIST_IKEV1
  SSH_FSM_STATE("ikev2_packet_v1_start",
                "ikev2 packet v1 start",
                ikev2_packet_v1_start)
#endif /* SSHDIST_IKEV1 */
  SSH_FSM_STATE("ikev2_packet_st_send",
                "ikev2 packet st send",
                ikev2_packet_st_send)
  SSH_FSM_STATE("ikev2_packet_st_send_done",
                "ikev2 packet st send done",
                ikev2_packet_st_send_done)
  SSH_FSM_STATE("ikev2_packet_st_verify",
                "ikev2 packet st verify",
                ikev2_packet_st_verify)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in",
                "ikev2 state auth initiator in",
                ikev2_state_auth_initiator_in)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_check_auth",
                "ikev2 state auth initiator in check auth",
                ikev2_state_auth_initiator_in_check_auth)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_done",
                "ikev2 state auth initiator in done",
                ikev2_state_auth_initiator_in_done)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_eap",
                "ikev2 state auth initiator in eap",
                ikev2_state_auth_initiator_in_eap)
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_end",
                "ikev2 state auth initiator in end",
                ikev2_state_auth_initiator_in_end)
#endif /* SSHDIST_IKE_EAP_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_finish",
                "ikev2 state auth initiator in finish",
                ikev2_state_auth_initiator_in_finish)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_public_key",
                "ikev2 state auth initiator in public key",
                ikev2_state_auth_initiator_in_public_key)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_sa",
                "ikev2 state auth initiator in sa",
                ikev2_state_auth_initiator_in_sa)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_shared_key",
                "ikev2 state auth initiator in shared key",
                ikev2_state_auth_initiator_in_shared_key)
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_ts",
                "ikev2 state auth initiator in ts",
                ikev2_state_auth_initiator_in_ts)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_in_verify_signature",
                "ikev2 state auth initiator in verify signature",
                ikev2_state_auth_initiator_in_verify_signature)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_out",
                "ikev2 state auth initiator out",
                ikev2_state_auth_initiator_out)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_alloc_sa",
                "ikev2 state auth initiator out alloc sa",
                ikev2_state_auth_initiator_out_alloc_sa)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_auth_check",
                "ikev2 state auth initiator out auth check",
                ikev2_state_auth_initiator_out_auth_check)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_auth_done",
                "ikev2 state auth initiator out auth done",
                ikev2_state_auth_initiator_out_auth_done)
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_auth_eap",
                "ikev2 state auth initiator out auth eap",
                ikev2_state_auth_initiator_out_auth_eap)
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_auth_pk",
                "ikev2 state auth initiator out auth pk",
                ikev2_state_auth_initiator_out_auth_pk)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_auth_shared_key",
                "ikev2 state auth initiator out auth shared key",
                ikev2_state_auth_initiator_out_auth_shared_key)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_cert",
                "ikev2 state auth initiator out cert",
                ikev2_state_auth_initiator_out_cert)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_certreq",
                "ikev2 state auth initiator out certreq",
                ikev2_state_auth_initiator_out_certreq)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_cp",
                "ikev2 state auth initiator out cp",
                ikev2_state_auth_initiator_out_cp)
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_eap",
                "ikev2 state auth initiator out eap",
                ikev2_state_auth_initiator_out_eap)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_eap_check",
                "ikev2 state auth initiator out eap check",
                ikev2_state_auth_initiator_out_eap_check)
#endif /* SSHDIST_IKE_EAP_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_fill_sa",
                "ikev2 state auth initiator out fill sa",
                ikev2_state_auth_initiator_out_fill_sa)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_idi",
                "ikev2 state auth initiator out idi",
                ikev2_state_auth_initiator_out_idi)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_idr",
                "ikev2 state auth initiator out idr",
                ikev2_state_auth_initiator_out_idr)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_sa",
                "ikev2 state auth initiator out sa",
                ikev2_state_auth_initiator_out_sa)
  SSH_FSM_STATE("ikev2_state_auth_initiator_out_ts",
                "ikev2 state auth initiator out ts",
                ikev2_state_auth_initiator_out_ts)
  SSH_FSM_STATE("ikev2_state_auth_responder_in",
                "ikev2 state auth responder in",
                ikev2_state_auth_responder_in)
  SSH_FSM_STATE("ikev2_state_auth_responder_in_alloc_sa",
                "ikev2 state auth responder in alloc sa",
                ikev2_state_auth_responder_in_alloc_sa)
  SSH_FSM_STATE("ikev2_state_auth_responder_in_check_auth",
                "ikev2 state auth responder in check auth",
                ikev2_state_auth_responder_in_check_auth)
  SSH_FSM_STATE("ikev2_state_auth_responder_in_end",
                "ikev2 state auth responder in end",
                ikev2_state_auth_responder_in_end)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_in_public_key",
                "ikev2 state auth responder in public key",
                ikev2_state_auth_responder_in_public_key)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_responder_in_shared_key",
                "ikev2 state auth responder in shared key",
                ikev2_state_auth_responder_in_shared_key)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_in_verify_signature",
                "ikev2 state auth responder in verify signature",
                ikev2_state_auth_responder_in_verify_signature)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_responder_out",
                "ikev2 state auth responder out",
                ikev2_state_auth_responder_out)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_auth_check",
                "ikev2 state auth responder out auth check",
                ikev2_state_auth_responder_out_auth_check)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_auth_done",
                "ikev2 state auth responder out auth done",
                ikev2_state_auth_responder_out_auth_done)
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_out_auth_eap",
                "ikev2 state auth responder out auth eap",
                ikev2_state_auth_responder_out_auth_eap)
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_out_auth_pk",
                "ikev2 state auth responder out auth pk",
                ikev2_state_auth_responder_out_auth_pk)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_responder_out_auth_shared_key",
                "ikev2 state auth responder out auth shared key",
                ikev2_state_auth_responder_out_auth_shared_key)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_out_cert",
                "ikev2 state auth responder out cert",
                ikev2_state_auth_responder_out_cert)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_responder_out_cp",
                "ikev2 state auth responder out cp",
                ikev2_state_auth_responder_out_cp)
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_FSM_STATE("ikev2_state_auth_responder_out_eap",
                "ikev2 state auth responder out eap",
                ikev2_state_auth_responder_out_eap)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_eap_check",
                "ikev2 state auth responder out eap check",
                ikev2_state_auth_responder_out_eap_check)
#endif /* SSHDIST_IKE_EAP_AUTH */
  SSH_FSM_STATE("ikev2_state_auth_responder_out_encrypt",
                "ikev2 state auth responder out encrypt",
                ikev2_state_auth_responder_out_encrypt)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_error_notify",
                "ikev2 state auth responder out error notify",
                ikev2_state_auth_responder_out_error_notify)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_idr",
                "ikev2 state auth responder out idr",
                ikev2_state_auth_responder_out_idr)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_install",
                "ikev2 state auth responder out install",
                ikev2_state_auth_responder_out_install)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_install_done",
                "ikev2 state auth responder out install done",
                ikev2_state_auth_responder_out_install_done)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_notify",
                "ikev2 state auth responder out notify",
                ikev2_state_auth_responder_out_notify)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_select_sa",
                "ikev2 state auth responder out select sa",
                ikev2_state_auth_responder_out_select_sa)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_narrow_ts",
                "ikev2 state auth responder out narrow ts",
                ikev2_state_auth_responder_out_narrow_ts)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_sa",
                "ikev2 state auth responder out sa",
                ikev2_state_auth_responder_out_sa)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_ts",
                "ikev2 state auth responder out ts",
                ikev2_state_auth_responder_out_ts)
  SSH_FSM_STATE("ikev2_state_auth_responder_out_vid",
                "ikev2 state auth responder out vid",
                ikev2_state_auth_responder_out_vid)
  SSH_FSM_STATE("ikev2_state_child_initiator_in",
                "ikev2 state child initiator in",
                ikev2_state_child_initiator_in)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_agree",
                "ikev2 state child initiator in agree",
                ikev2_state_child_initiator_in_agree)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_done",
                "ikev2 state child initiator in done",
                ikev2_state_child_initiator_in_done)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_finish",
                "ikev2 state child initiator in finish",
                ikev2_state_child_initiator_in_finish)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_ke",
                "ikev2 state child initiator in ke",
                ikev2_state_child_initiator_in_ke)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_nonce",
                "ikev2 state child initiator in nonce",
                ikev2_state_child_initiator_in_nonce)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_sa",
                "ikev2 state child initiator in sa",
                ikev2_state_child_initiator_in_sa)
  SSH_FSM_STATE("ikev2_state_child_initiator_in_ts",
                "ikev2 state child initiator in ts",
                ikev2_state_child_initiator_in_ts)
  SSH_FSM_STATE("ikev2_state_child_initiator_out",
                "ikev2 state child initiator out",
                ikev2_state_child_initiator_out)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_alloc_sa",
                "ikev2 state child initiator out alloc sa",
                ikev2_state_child_initiator_out_alloc_sa)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_fill_sa",
                "ikev2 state child initiator out fill sa",
                ikev2_state_child_initiator_out_fill_sa)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_ke",
                "ikev2 state child initiator out ke",
                ikev2_state_child_initiator_out_ke)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_nonce",
                "ikev2 state child initiator out nonce",
                ikev2_state_child_initiator_out_nonce)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_rekey_n",
                "ikev2 state child initiator out rekey n",
                ikev2_state_child_initiator_out_rekey_n)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_sa",
                "ikev2 state child initiator out sa",
                ikev2_state_child_initiator_out_sa)
  SSH_FSM_STATE("ikev2_state_child_initiator_out_ts",
                "ikev2 state child initiator out ts",
                ikev2_state_child_initiator_out_ts)
  SSH_FSM_STATE("ikev2_state_child_responder_in",
                "ikev2 state child responder in",
                ikev2_state_child_responder_in)
  SSH_FSM_STATE("ikev2_state_child_responder_in_alloc_sa",
                "ikev2 state child responder in alloc sa",
                ikev2_state_child_responder_in_alloc_sa)
  SSH_FSM_STATE("ikev2_state_child_responder_in_check_rekey",
                "ikev2 state child responder in check rekey",
                ikev2_state_child_responder_in_check_rekey)
  SSH_FSM_STATE("ikev2_state_child_responder_in_end",
                "ikev2 state child responder in end",
                ikev2_state_child_responder_in_end)
  SSH_FSM_STATE("ikev2_state_child_responder_in_invalid_ke",
                "ikev2 state child responder in invalid ke",
                ikev2_state_child_responder_in_invalid_ke)
  SSH_FSM_STATE("ikev2_state_child_responder_in_ke",
                "ikev2 state child responder in ke",
                ikev2_state_child_responder_in_ke)
  SSH_FSM_STATE("ikev2_state_child_responder_in_nonce",
                "ikev2 state child responder in nonce",
                ikev2_state_child_responder_in_nonce)
  SSH_FSM_STATE("ikev2_state_child_responder_in_sa",
                "ikev2 state child responder in sa",
                ikev2_state_child_responder_in_sa)
  SSH_FSM_STATE("ikev2_state_child_responder_in_ts",
                "ikev2 state child responder in ts",
                ikev2_state_child_responder_in_ts)
  SSH_FSM_STATE("ikev2_state_child_responder_out",
                "ikev2 state child responder out",
                ikev2_state_child_responder_out)
  SSH_FSM_STATE("ikev2_state_child_responder_out_agree",
                "ikev2 state child responder out agree",
                ikev2_state_child_responder_out_agree)
  SSH_FSM_STATE("ikev2_state_child_responder_out_encrypt",
                "ikev2 state child responder out encrypt",
                ikev2_state_child_responder_out_encrypt)
  SSH_FSM_STATE("ikev2_state_child_responder_out_install",
                "ikev2 state child responder out install",
                ikev2_state_child_responder_out_install)
  SSH_FSM_STATE("ikev2_state_child_responder_out_install_done",
                "ikev2 state child responder out install done",
                ikev2_state_child_responder_out_install_done)
  SSH_FSM_STATE("ikev2_state_child_responder_out_ke",
                "ikev2 state child responder out ke",
                ikev2_state_child_responder_out_ke)
  SSH_FSM_STATE("ikev2_state_child_responder_out_nonce",
                "ikev2 state child responder out nonce",
                ikev2_state_child_responder_out_nonce)
  SSH_FSM_STATE("ikev2_state_child_responder_out_sa",
                "ikev2 state child responder out sa",
                ikev2_state_child_responder_out_sa)
  SSH_FSM_STATE("ikev2_state_child_responder_out_ts",
                "ikev2 state child responder out ts",
                ikev2_state_child_responder_out_ts)
  SSH_FSM_STATE("ikev2_state_decode",
                "ikev2 state decode",
                ikev2_state_decode)
  SSH_FSM_STATE("ikev2_state_dispatch",
                "ikev2 state dispatch",
                ikev2_state_dispatch)
  SSH_FSM_STATE("ikev2_state_encrypt",
                "ikev2 state encrypt",
                ikev2_state_encrypt)
  SSH_FSM_STATE("ikev2_state_error",
                "ikev2 state error",
                ikev2_state_error)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in",
                "ikev2 state ike rekey initiator in",
                ikev2_state_ike_rekey_initiator_in)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_agree",
                "ikev2 state ike rekey initiator in agree",
                ikev2_state_ike_rekey_initiator_in_agree)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_done",
                "ikev2 state ike rekey initiator in done",
                ikev2_state_ike_rekey_initiator_in_done)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_finish",
                "ikev2 state ike rekey initiator in finish",
                ikev2_state_ike_rekey_initiator_in_finish)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_move_from_old",
                "ikev2 state ike rekey initiator in move from old",
                ikev2_state_ike_rekey_initiator_in_move_from_old)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_ke",
                "ikev2 state ike rekey initiator in ke",
                ikev2_state_ike_rekey_initiator_in_ke)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_nonce",
                "ikev2 state ike rekey initiator in nonce",
                ikev2_state_ike_rekey_initiator_in_nonce)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_in_sa",
                "ikev2 state ike rekey initiator in sa",
                ikev2_state_ike_rekey_initiator_in_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out",
                "ikev2 state ike rekey initiator out",
                ikev2_state_ike_rekey_initiator_out)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out_alloc_sa",
                "ikev2 state ike rekey initiator out alloc sa",
                ikev2_state_ike_rekey_initiator_out_alloc_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out_fill_sa",
                "ikev2 state ike rekey initiator out fill sa",
                ikev2_state_ike_rekey_initiator_out_fill_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out_ke",
                "ikev2 state ike rekey initiator out ke",
                ikev2_state_ike_rekey_initiator_out_ke)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out_nonce",
                "ikev2 state ike rekey initiator out nonce",
                ikev2_state_ike_rekey_initiator_out_nonce)
  SSH_FSM_STATE("ikev2_state_ike_rekey_initiator_out_sa",
                "ikev2 state ike rekey initiator out sa",
                ikev2_state_ike_rekey_initiator_out_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in",
                "ikev2 state ike rekey responder in",
                ikev2_state_ike_rekey_responder_in)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_alloc_sa",
                "ikev2 state ike rekey responder in alloc sa",
                ikev2_state_ike_rekey_responder_in_alloc_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_end",
                "ikev2 state ike rekey responder in end",
                ikev2_state_ike_rekey_responder_in_end)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_invalid_ke",
                "ikev2 state ike rekey responder in invalid ke",
                ikev2_state_ike_rekey_responder_in_invalid_ke)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_ke",
                "ikev2 state ike rekey responder in ke",
                ikev2_state_ike_rekey_responder_in_ke)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_nonce",
                "ikev2 state ike rekey responder in nonce",
                ikev2_state_ike_rekey_responder_in_nonce)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_in_sa",
                "ikev2 state ike rekey responder in sa",
                ikev2_state_ike_rekey_responder_in_sa)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out",
                "ikev2 state ike rekey responder out",
                ikev2_state_ike_rekey_responder_out)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_agree",
                "ikev2 state ike rekey responder out agree",
                ikev2_state_ike_rekey_responder_out_agree)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_encrypt",
                "ikev2 state ike rekey responder out encrypt",
                ikev2_state_ike_rekey_responder_out_encrypt)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_move_from_old",
                "ikev2 state ike rekey responder out move from old",
                ikev2_state_ike_rekey_responder_out_move_from_old)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_install",
                "ikev2 state ike rekey responder out install",
                ikev2_state_ike_rekey_responder_out_install)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_ke",
                "ikev2 state ike rekey responder out ke",
                ikev2_state_ike_rekey_responder_out_ke)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_nonce",
                "ikev2 state ike rekey responder out nonce",
                ikev2_state_ike_rekey_responder_out_nonce)
  SSH_FSM_STATE("ikev2_state_ike_rekey_responder_out_sa",
                "ikev2 state ike rekey responder out sa",
                ikev2_state_ike_rekey_responder_out_sa)
  SSH_FSM_STATE("ikev2_state_info_initiator_in",
                "ikev2 state info initiator in",
                ikev2_state_info_initiator_in)
  SSH_FSM_STATE("ikev2_state_info_initiator_in_check_delete",
                "ikev2 state info initiator in check delete",
                ikev2_state_info_initiator_in_check_delete)
  SSH_FSM_STATE("ikev2_state_info_initiator_in_check_notify",
                "ikev2 state info initiator in check notify",
                ikev2_state_info_initiator_in_check_notify)
  SSH_FSM_STATE("ikev2_state_info_initiator_in_end",
                "ikev2 state info initiator in end",
                ikev2_state_info_initiator_in_end)
  SSH_FSM_STATE("ikev2_state_info_initiator_out",
                "ikev2 state info initiator out",
                ikev2_state_info_initiator_out)
  SSH_FSM_STATE("ikev2_state_info_initiator_out_add_conf",
                "ikev2 state info initiator out add conf",
                ikev2_state_info_initiator_out_add_conf)
  SSH_FSM_STATE("ikev2_state_info_initiator_out_add_delete",
                "ikev2 state info initiator out add delete",
                ikev2_state_info_initiator_out_add_delete)
  SSH_FSM_STATE("ikev2_state_info_initiator_out_add_notify",
                "ikev2 state info initiator out add notify",
                ikev2_state_info_initiator_out_add_notify)
  SSH_FSM_STATE("ikev2_state_info_responder_in",
                "ikev2 state info responder in",
                ikev2_state_info_responder_in)
  SSH_FSM_STATE("ikev2_state_info_responder_in_check_delete",
                "ikev2 state info responder in check delete",
                ikev2_state_info_responder_in_check_delete)
  SSH_FSM_STATE("ikev2_state_info_responder_in_check_notify",
                "ikev2 state info responder in check notify",
                ikev2_state_info_responder_in_check_notify)
  SSH_FSM_STATE("ikev2_state_info_responder_in_end",
                "ikev2 state info responder in end",
                ikev2_state_info_responder_in_end)
  SSH_FSM_STATE("ikev2_state_info_responder_out",
                "ikev2 state info responder out",
                ikev2_state_info_responder_out)
  SSH_FSM_STATE("ikev2_state_info_responder_out_add_conf",
                "ikev2 state info responder out add conf",
                ikev2_state_info_responder_out_add_conf)
  SSH_FSM_STATE("ikev2_state_info_responder_out_add_delete",
                "ikev2 state info responder out add delete",
                ikev2_state_info_responder_out_add_delete)
  SSH_FSM_STATE("ikev2_state_info_responder_out_add_notify",
                "ikev2 state info responder out add notify",
                ikev2_state_info_responder_out_add_notify)
  SSH_FSM_STATE("ikev2_state_info_responder_out_encrypt",
                "ikev2 state info responder out encrypt",
                ikev2_state_info_responder_out_encrypt)
  SSH_FSM_STATE("ikev2_state_init_initiator_in",
                "ikev2 state init initiator in",
                ikev2_state_init_initiator_in)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_end",
                "ikev2 state init initiator in end",
                ikev2_state_init_initiator_in_end)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_ke",
                "ikev2 state init initiator in ke",
                ikev2_state_init_initiator_in_ke)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_nat_t",
                "ikev2 state init initiator in nat t",
                ikev2_state_init_initiator_in_nat_t)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_nonce",
                "ikev2 state init initiator in nonce",
                ikev2_state_init_initiator_in_nonce)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_notify",
                "ikev2 state init initiator in notify",
                ikev2_state_init_initiator_in_notify)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_restart",
                "ikev2 state init initiator in restart",
                ikev2_state_init_initiator_in_restart)
  SSH_FSM_STATE("ikev2_state_init_initiator_in_sa",
                "ikev2 state init initiator in sa",
                ikev2_state_init_initiator_in_sa)
  SSH_FSM_STATE("ikev2_state_init_initiator_out",
                "ikev2 state init initiator out",
                ikev2_state_init_initiator_out)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_cookie",
                "ikev2 state init initiator out cookie",
                ikev2_state_init_initiator_out_cookie)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_dh_setup",
                "ikev2 state init initiator out dh setup",
                ikev2_state_init_initiator_out_dh_setup)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_done",
                "ikev2 state init initiator out done",
                ikev2_state_init_initiator_out_done)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_fill_sa",
                "ikev2 state init initiator out fill sa",
                ikev2_state_init_initiator_out_fill_sa)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_nonce",
                "ikev2 state init initiator out nonce",
                ikev2_state_init_initiator_out_nonce)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_notify",
                "ikev2 state init initiator out notify",
                ikev2_state_init_initiator_out_notify)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_sa",
                "ikev2 state init initiator out sa",
                ikev2_state_init_initiator_out_sa)
  SSH_FSM_STATE("ikev2_state_init_initiator_out_vid",
                "ikev2 state init initiator out vid",
                ikev2_state_init_initiator_out_vid)
  SSH_FSM_STATE("ikev2_state_init_responder_in",
                "ikev2 state init responder in",
                ikev2_state_init_responder_in)
  SSH_FSM_STATE("ikev2_state_init_responder_in_cookie",
                "ikev2 state init responder in cookie",
                ikev2_state_init_responder_in_cookie)
  SSH_FSM_STATE("ikev2_state_init_responder_in_end",
                "ikev2 state init responder in end",
                ikev2_state_init_responder_in_end)
  SSH_FSM_STATE("ikev2_state_init_responder_in_invalid_ke",
                "ikev2 state init responder in invalid ke",
                ikev2_state_init_responder_in_invalid_ke)
  SSH_FSM_STATE("ikev2_state_init_responder_in_ke",
                "ikev2 state init responder in ke",
                ikev2_state_init_responder_in_ke)
  SSH_FSM_STATE("ikev2_state_init_responder_in_nat_t",
                "ikev2 state init responder in nat t",
                ikev2_state_init_responder_in_nat_t)
  SSH_FSM_STATE("ikev2_state_init_responder_in_nonce",
                "ikev2 state init responder in nonce",
                ikev2_state_init_responder_in_nonce)
  SSH_FSM_STATE("ikev2_state_init_responder_in_request_cookie",
                "ikev2 state init responder in request cookie",
                ikev2_state_init_responder_in_request_cookie)
  SSH_FSM_STATE("ikev2_state_init_responder_in_sa",
                "ikev2 state init responder in sa",
                ikev2_state_init_responder_in_sa)
  SSH_FSM_STATE("ikev2_state_init_responder_out",
                "ikev2 state init responder out",
                ikev2_state_init_responder_out)
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_STATE("ikev2_state_init_responder_out_certreq",
                "ikev2 state init responder out certreq",
                ikev2_state_init_responder_out_certreq)
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("ikev2_state_init_responder_out_dh_agree_start",
                "ikev2 state init responder out dh agree start",
                ikev2_state_init_responder_out_dh_agree_start)
  SSH_FSM_STATE("ikev2_state_init_responder_out_dh_setup",
                "ikev2 state init responder out dh setup",
                ikev2_state_init_responder_out_dh_setup)
  SSH_FSM_STATE("ikev2_state_init_responder_out_nonce",
                "ikev2 state init responder out nonce",
                ikev2_state_init_responder_out_nonce)
  SSH_FSM_STATE("ikev2_state_init_responder_out_notify",
                "ikev2 state init responder out notify",
                ikev2_state_init_responder_out_notify)
  SSH_FSM_STATE("ikev2_state_init_responder_out_sa",
                "ikev2 state init responder out sa",
                ikev2_state_init_responder_out_sa)
  SSH_FSM_STATE("ikev2_state_init_responder_out_vid",
                "ikev2 state init responder out vid",
                ikev2_state_init_responder_out_vid)
  SSH_FSM_STATE("ikev2_state_ke_error_out",
                "ikev2 state ke error out",
                ikev2_state_ke_error_out)
  SSH_FSM_STATE("ikev2_state_notify",
                "ikev2 state notify",
                ikev2_state_notify)
  SSH_FSM_STATE("ikev2_state_notify_vid_encrypt_send",
                "ikev2 state notify vid encrypt send",
                ikev2_state_notify_vid_encrypt_send)
  SSH_FSM_STATE("ikev2_state_reply_ke_error_out",
                "ikev2 state reply ke error out",
                ikev2_state_reply_ke_error_out)
  SSH_FSM_STATE("ikev2_state_request_cookie_out",
                "ikev2 state request cookie out",
                ikev2_state_request_cookie_out)
  SSH_FSM_STATE("ikev2_state_responder_notify_vid",
                "ikev2 state responder notify vid",
                ikev2_state_responder_notify_vid)
  SSH_FSM_STATE("ikev2_state_responder_notify",
                "ikev2 state responder notify",
                ikev2_state_responder_notify)
  SSH_FSM_STATE("ikev2_state_responder_vid",
                "ikev2 state responder vid",
                ikev2_state_responder_vid)
  SSH_FSM_STATE("ikev2_state_responder_notify_vid_continue",
                "ikev2 state responder notify vid continue",
                ikev2_state_responder_notify_vid_continue)
  SSH_FSM_STATE("ikev2_state_send",
                "ikev2 state send",
                ikev2_state_send)
  SSH_FSM_STATE("ikev2_state_send_and_destroy",
                "ikev2 state send and destroy",
                ikev2_state_send_and_destroy)
  SSH_FSM_STATE("ikev2_state_send_and_destroy_now",
                "ikev2 state send and destroy now",
                ikev2_state_send_and_destroy_now)
  SSH_FSM_STATE("ikev2_state_send_error",
                "ikev2 state send error",
                ikev2_state_send_error)
  SSH_FSM_STATE("ikev2_state_vid",
                "ikev2 state vid",
                ikev2_state_vid)
#ifdef SSHDIST_IKE_REDIRECT
  SSH_FSM_STATE("ikev2_state_redirect_out",
                "ikev2_state_redirect_out",
                ikev2_state_redirect_out)
#endif /* SSHDIST_IKE_REDIRECT */
};

const int ikev2_num_states = SSH_FSM_NUM_STATES(ikev2_state_array);
#endif /* DEBUG_LIGHT */
