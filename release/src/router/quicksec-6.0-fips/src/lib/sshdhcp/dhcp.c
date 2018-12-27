/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RFC 2131, RFC 2132, RFC 3046
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshfsm.h"
#include "sshtcp.h"
#include "sshcrypt.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"
#include "dhcp_states.h"

#define SSH_DEBUG_MODULE "SshDHCP"

static void ssh_dhcp_abort_timeout(void *context);
Boolean dhcp_make_listener(SshDHCPMainCtx main_ctx, SshUInt8 version);

static void dhcp_free_params(SshDHCPParams params)
{
  int i = 0;

  if (params)
    {
      if (params->info != NULL)
        ssh_dhcp_free_info(params->info);

      ssh_free(params->local_ip);
      for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
          ssh_free(params->dhcp_servers[i].remote_ip);

      ssh_free(params->gateway);
      ssh_free(params->hw_addr);
      ssh_free(params->client_identifier);
      ssh_free(params->vendor_id);
      ssh_free(params->options);
      if (params->remote_ip != NULL)
        {
          ssh_free(params->remote_ip);
          params->remote_ip = NULL;
        }
    }
}

SshFSM ssh_dhcp_library_init(SshUInt8 version,
                             unsigned char *local_ip,
                             SshUInt16 local_private_port,
                             SshUInt16 local_listening_port)
{
  SshFSM fsm = NULL;
  SshDHCPMainCtx main_context = NULL;

  fsm = ssh_calloc(1, sizeof(SshFSMStruct));
  if (fsm == NULL)
    return NULL;

  main_context = ssh_calloc(1, sizeof(SshDHCPMainCtxStruct));
  if (main_context == NULL)
    {
      ssh_free(fsm);
      return NULL;
    }

  ssh_fsm_init(fsm, main_context);

  main_context->local_ip = ssh_malloc(SSH_IP_ADDR_STRING_SIZE);
  if (main_context->local_ip == NULL)
    goto failed;
  memcpy(main_context->local_ip, local_ip,
         SSH_IP_ADDR_STRING_SIZE);
  main_context->local_listening_port = local_listening_port;
  main_context->local_private_port = local_private_port;

  if (dhcp_make_listener(main_context, version) == FALSE)
    goto failed;

  return fsm;

 failed:
  if (main_context->local_ip != NULL)
    ssh_free(main_context->local_ip);
  ssh_free(fsm);
  ssh_free(main_context);

  return NULL;
}

void  ssh_dhcp_uninit_timeout_cb(void *context)
{
  SshFSM fsm = (SshFSM)context;

  ssh_dhcp_library_uninit(fsm);
}

void ssh_dhcp_library_uninit(void *context)
{
  SshFSM fsm = (SshFSM)context;
  SshDHCPMainCtx main_context = NULL;

  if (fsm != NULL)
    {
      /* Check fsm reference count. */
      main_context = (SshDHCPMainCtx)ssh_fsm_get_gdata_fsm(fsm);
      SSH_DEBUG(SSH_D_MY, ("DHCP main ctx reference count %d",
                           main_context->fsm_reference_count));

      if (main_context == NULL)
        {
          ssh_fsm_uninit(fsm);
          ssh_free(fsm);
        }
      else if (main_context->fsm_reference_count > 0)
        {
          SSH_DEBUG(SSH_D_MY, ("DHCP main ctx reference count %d",
                               main_context->fsm_reference_count));
          ssh_register_timeout(&main_context->uninit_timeout, 1, 0,
                               ssh_dhcp_library_uninit, fsm);
        }
      else
        {
          SSH_DEBUG(SSH_D_MY, ("Freeing DHCP fsm"));
          if (main_context->sender &&
              main_context->sender != main_context->listener)
            ssh_udp_destroy_listener(main_context->sender);

          if (main_context->listener)
            ssh_udp_destroy_listener(main_context->listener);

          if (main_context->local_ip != NULL)
              ssh_free(main_context->local_ip);

          ssh_free(main_context);
          ssh_fsm_uninit(fsm);
          ssh_free(fsm);
        }
    }
}

/* Allocates new DHCP context. The `params' must be provided to define
   parameters for the DHCP session. The `callback' will be called during
   the DHCP session when the status changes.  It is called in case of
   error as well. */

SshDHCP ssh_dhcp_allocate(SshFSM fsm, SshDHCPParams params,
                          SshDHCPCallback callback,
                          SshDHCPCallback destructor_cb,
                          void *context)
{
  SshDHCP dhcp;
  unsigned char xid[4];
  int i = 0;
  SshUInt32 hashvalue;
  SshDHCPMainCtx main_context = NULL;
  int count = 0;
  int dlen = 0; /* length of the internal DUID type */

  if (params == NULL)
    return NULL;

  dhcp = ssh_calloc(1, sizeof(*dhcp));
  if (dhcp == NULL)
    return NULL;

  main_context = (SshDHCPMainCtx)ssh_fsm_get_gdata_fsm(fsm);
  dhcp->fsm = fsm;
  dhcp->callback = callback;
  dhcp->destructor_cb = destructor_cb;
  dhcp->context = context;

  dhcp->params.flags = params->flags;

  dhcp->params.options = ssh_memdup(params->options,
                                    sizeof(SshDHCPOptionsStruct));
  if (dhcp->params.options == NULL)
    goto failed;

  dhcp->params.local_ip = ssh_malloc(SSH_IP_ADDR_STRING_SIZE);
  if (dhcp->params.local_ip == NULL)
    goto failed;
  memcpy(dhcp->params.local_ip, params->local_ip, SSH_IP_ADDR_STRING_SIZE);

  dhcp->params.gateway = ssh_malloc(SSH_IP_ADDR_STRING_SIZE);
  if (dhcp->params.gateway == NULL)
    goto failed;
  memcpy(dhcp->params.gateway, params->gateway, SSH_IP_ADDR_STRING_SIZE);
  dhcp->params.local_listening_port =  params->local_listening_port;
  dhcp->params.local_private_port =  params->local_private_port;

  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
    {
      if (params->dhcp_servers[i].remote_ip == NULL)
        break;

      dhcp->params.dhcp_servers[i].remote_ip =
        ssh_malloc(SSH_IP_ADDR_STRING_SIZE);
      if (dhcp->params.dhcp_servers[i].remote_ip == NULL)
        goto failed;

      memcpy(dhcp->params.dhcp_servers[i].remote_ip,
             params->dhcp_servers[i].remote_ip,  SSH_IP_ADDR_STRING_SIZE);

      dhcp->params.dhcp_servers[i].remote_port =
        params->dhcp_servers[i].remote_port;
    }

  if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
    {
      dhcp->params.enterprise_number = params->enterprise_number;

      if (params->client_identifier_type >= 0)
        dlen = 2;

      dhcp->params.client_identifier =
        ssh_calloc(params->client_identifier_len + dlen, 1);
      if (dhcp->params.client_identifier == NULL)
        goto failed;

      if (params->client_identifier_type >= 0)
        dhcp->params.client_identifier[1] = params->client_identifier_type;

      memcpy(dhcp->params.client_identifier + dlen, params->client_identifier,
             params->client_identifier_len);
      dhcp->params.client_identifier_len = params->client_identifier_len +
                                           dlen;
    }
  else
    {
      /* Just add client ID type in the beginning */
      dhcp->params.client_identifier =
        ssh_calloc(params->client_identifier_len + 1, 1);
      if (dhcp->params.client_identifier == NULL)
        goto failed;

      dhcp->params.client_identifier[0] = params->client_identifier_type;
      memcpy(dhcp->params.client_identifier + 1, params->client_identifier,
             params->client_identifier_len);
      dhcp->params.client_identifier_len = params->client_identifier_len + 1;
    }

  dhcp->params.vendor_id = ssh_calloc(params->vendor_id_len, 1);
  if (dhcp->params.vendor_id == NULL)
    goto failed;

  memcpy(dhcp->params.vendor_id, params->vendor_id, params->vendor_id_len);
  dhcp->params.vendor_id_len = params->vendor_id_len;

  dhcp->params.retransmit_count = params->retransmit_count;
  dhcp->params.retransmit_interval = params->retransmit_interval;
  dhcp->params.retransmit_interval_usec = params->retransmit_interval_usec;
  dhcp->params.max_timeout = params->max_timeout;
  dhcp->params.max_total_timeout = params->max_total_timeout;
  dhcp->params.requested_lease_time = params->requested_lease_time;
  dhcp->params.offer_timeout = params->offer_timeout;
  dhcp->params.offer_timeout_usec = params->offer_timeout_usec;

  /* Explicit set of options, no_compatibility param cannot have effect */
  if (params->options != NULL)
    dhcp->params.no_compatibility = TRUE;
  else
  dhcp->params.no_compatibility = params->no_compatibility;

  if (params->info != NULL)
    {
      dhcp->info = ssh_dhcp_dup_info(params->info);
      if (dhcp->info == NULL)
        goto failed;
    }

  /* set xid and store to hash table */
  while (1)
    {
      /* Give up in reasonable time. */
      if (++count > 10)
        goto failed;
      ssh_random_stir();

      /* DHCPv6 uses 24bit xid */
      if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
        xid[0] = 0;
      else
        xid[0] = ssh_random_get_byte();
      xid[1] = ssh_random_get_byte();
      xid[2] = ssh_random_get_byte();
      xid[3] = ssh_random_get_byte();
      dhcp->xid = SSH_GET_32BIT(xid);
      if (dhcp->xid == 0)
        continue;

      hashvalue = dhcp->xid % DHCP_THREAD_HASH_TABLE_SIZE;
      if (main_context->thread_hash_table[hashvalue] == NULL)
        {
          main_context->thread_hash_table[hashvalue] = dhcp;
          break;
        }
      else
        {
          SshDHCP dhcp_iter, last;

          /* Ok, let's have a look if the XID is already booked. */
          last = dhcp_iter = main_context->thread_hash_table[hashvalue];
          while (dhcp_iter != NULL && (dhcp_iter->xid != dhcp->xid))
            {
              last = dhcp_iter;
              dhcp_iter = dhcp_iter->xid_hash_next;
            }

          if (dhcp_iter != NULL)
            continue;

          /* This XID we may accept, hits the same hash slot, but XID
             itself is not used before. */
          last->xid_hash_next = dhcp;
          dhcp->xid_hash_next = NULL;
          break;
        }
    }

  return dhcp;

 failed:
  dhcp_free_params(&dhcp->params);
  if (dhcp->info)
    ssh_dhcp_free_info(dhcp->info);
  ssh_free(dhcp);
  return NULL;
}

/* Frees DHCP context. The application must call ssh_dhcp_abort before
   freeing the DHCP context. */

void ssh_dhcp_free(SshDHCP dhcp)
{
  ssh_dhcp_cancel_timeouts(dhcp);
  ssh_cancel_timeouts(ssh_dhcp_abort_timeout, dhcp);

  if (dhcp->info)
    ssh_dhcp_free_info(dhcp->info);

  dhcp_free_params(&dhcp->params);
  ssh_free(dhcp);
}

/* Makes UDP listener for DHCP session. Return TRUE on successfull
   creation. */
Boolean dhcp_make_listener(SshDHCPMainCtx main_ctx, SshUInt8 version)
{
  SshUdpListenerParamsStruct udp_params;
  unsigned char local_port[6];

  if (!main_ctx->local_ip)
    {
      main_ctx->local_ip = ssh_strdup((char *)SSH_IPADDR_ANY);
      if (main_ctx->local_ip == NULL)
        goto failed;
    }
  if (!main_ctx->local_listening_port)
    main_ctx->local_listening_port = SSH_DHCP_CLIENT_PORT;

  SSH_DEBUG(SSH_D_MIDSTART, ("Start UDP listener %s:%d",
                main_ctx->local_ip,
                main_ctx->local_listening_port));

  /* We will be broadcasting */
  memset(&udp_params, 0, sizeof(udp_params));
  udp_params.broadcasting = TRUE;
  ssh_snprintf(local_port, sizeof(local_port), "%d",
               main_ctx->local_listening_port);
  if (version == SSH_DHCP_PROTOCOL_VERSION_6)
    main_ctx->listener = ssh_udp_make_listener(main_ctx->local_ip, local_port,
                                               NULL, 0, -1, 0, &udp_params,
                                               ssh_dhcpv6_udp_callback,
                                               main_ctx);
  else
    main_ctx->listener = ssh_udp_make_listener(main_ctx->local_ip, local_port,
                                               NULL, 0, -1, 0, &udp_params,
                                               ssh_dhcp_udp_callback,
                                               main_ctx);
  if (main_ctx->listener == NULL)
    goto failed;

  /* Make another listener for sending. */
  if (main_ctx->local_private_port != 0 &&
      main_ctx->local_private_port != main_ctx->local_listening_port)
    {
      SSH_DEBUG(5, ("Start UDP sender %s:%d",
                    main_ctx->local_ip, main_ctx->local_private_port));
      memset(&udp_params, 0, sizeof(udp_params));
      udp_params.broadcasting = TRUE;
      ssh_snprintf(local_port, sizeof(local_port), "%d",
                   main_ctx->local_private_port);
      main_ctx->sender = ssh_udp_make_listener(main_ctx->local_ip, local_port,
                                               NULL, 0, -1, 0, &udp_params,
                                               NULL, main_ctx);
      if (!main_ctx->sender)
        goto failed;
    }
  else
    main_ctx->sender =  main_ctx->listener;

  return TRUE;

 failed:
  if (main_ctx->listener != NULL)
    ssh_udp_destroy_listener(main_ctx->listener);
  main_ctx->listener = NULL;

  SSH_DEBUG(SSH_D_FAIL, ("Unable to create UDP listener"));
  return FALSE;
}

static void
ssh_dhcp_thread_destructor(SshFSM fsm, void *context)
{
  SshDHCP dhcp = (SshDHCP) context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)ssh_fsm_get_gdata_fsm(fsm);
  SshUInt32 hashvalue;
  SshDHCP dhcp_iterator, prev;
#ifdef DEBUG_LIGHT
  unsigned char buf[512] = {'\0'};
  SshDHCPStats statistics = NULL;
#endif /* DEBUG_LIGHT */

  main_context->fsm_reference_count--;

  /* remove from hash table. */
  hashvalue = dhcp->xid % DHCP_THREAD_HASH_TABLE_SIZE;
  dhcp_iterator = main_context->thread_hash_table[hashvalue];

  if (dhcp_iterator != NULL)
    {
      /* Head of list. */
      /* We may have look only at the dhcp pointers as the XID is not really
             interesting here. */
      if (dhcp_iterator == dhcp)
        {
          main_context->thread_hash_table[hashvalue] =
          dhcp_iterator->xid_hash_next;
        }
      else
        {
          /* Is it somewhere in the middle or end? */
          prev = dhcp_iterator;
          dhcp_iterator = dhcp_iterator->xid_hash_next;

          while (dhcp_iterator != NULL)
            {
              /* Got a match? */
              if (dhcp_iterator == dhcp)
                    {
                      prev->xid_hash_next = dhcp_iterator->xid_hash_next;
                      break;
                    }

                  /* No match with this entry. */
                  prev = dhcp_iterator;
                  dhcp_iterator = dhcp_iterator->xid_hash_next;
            }
        }
    }

#ifdef DEBUG_LIGHT
  /* Log statistics. */
  statistics = ssh_dhcp_get_statistics(fsm);
  if (statistics != NULL)
    {
      ssh_dhcp_statistics_buffer_append(statistics, buf, sizeof(buf));
      SSH_DEBUG(SSH_D_DATADUMP, ("DHCP statistics:%s", buf));
    }
#endif /* DEBUG_LIGHT */

  if (dhcp->destructor_cb)
    (*dhcp->destructor_cb)(dhcp, NULL, 0, NULL);
}

static SshDHCPStatus dhcp_setup(SshDHCP dhcp, SshFSMStepCB state)
{
  SshDHCPMainCtx main_context =
    (SshDHCPMainCtx)ssh_fsm_get_gdata_fsm(dhcp->fsm);

  if (main_context == NULL || main_context->listener == NULL)
    goto failed;

  /* Set default values for session */
  if (!dhcp->params.dhcp_servers[0].remote_ip)
    {
      dhcp->params.dhcp_servers[0].remote_ip = ssh_strdup(SSH_DHCP_BROADCAST);
      if (dhcp->params.dhcp_servers[0].remote_ip == NULL)
        goto failed;
    }

  if (!dhcp->params.dhcp_servers[0].remote_port)
    dhcp->params.dhcp_servers[0].remote_port = SSH_DHCP_SERVER_PORT;


  if (!dhcp->params.retransmit_count)
    dhcp->params.retransmit_count = SSH_DHCP_RETRANSMIT_COUNT;

  if (!dhcp->params.retransmit_interval &&
      !dhcp->params.retransmit_interval_usec)
    {
      dhcp->params.retransmit_interval = SSH_DHCP_RETRANSMIT_INTERVAL;
      dhcp->params.retransmit_interval_usec =
        SSH_DHCP_RETRANSMIT_INTERVAL_USEC;
    }

  if (!dhcp->params.max_timeout)
    dhcp->params.max_timeout = SSH_DHCP_TIMEOUT_MAX;

  if (!dhcp->params.max_total_timeout)
    dhcp->params.max_total_timeout = SSH_DHCP_TIMEOUT_MAX + 1;

  if (!dhcp->params.offer_timeout && !dhcp->params.offer_timeout_usec)
    {
      dhcp->params.offer_timeout = SSH_DHCP_OFFER_TIMEOUT;
      dhcp->params.offer_timeout_usec = SSH_DHCP_OFFER_TIMEOUT_USEC;
    }

  /* Start the thread for DHCP message exchange */
  dhcp->thread = ssh_fsm_thread_create(dhcp->fsm, state, NULL_FNPTR,
                                       ssh_dhcp_thread_destructor, dhcp);
  if (dhcp->thread == NULL)
    goto failed;

  ssh_fsm_set_thread_name(dhcp->thread, "DHCP protocol machine");

  /* Increase fsm reference count. */
  main_context->fsm_reference_count++;

  return SSH_DHCP_STATUS_OK;

 failed:
  if (dhcp->params.dhcp_servers[0].remote_ip != NULL)
    {
      ssh_free(dhcp->params.dhcp_servers[0].remote_ip);
      dhcp->params.dhcp_servers[0].remote_ip = NULL;
    }
  dhcp->status = SSH_DHCP_STATUS_ERROR;
  return SSH_DHCP_STATUS_ERROR;
}

static void
ssh_dhcp_total_timeout(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;

  /* Timeout, drop everything */
  SSH_DEBUG(SSH_D_FAIL, ("Timeout, giving up"));
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                "DHCP operation timeout.");

  dhcp->status = SSH_DHCP_STATUS_TIMEOUT;

  ssh_fsm_set_next(dhcp->thread, ssh_dhcp_st_finish_pending);
  ssh_fsm_continue(dhcp->thread);
}

/* Internal routine to run any state of the DHCP session. */

static SshDHCPStatus
ssh_dhcp_run_internal(SshDHCP dhcp, SshFSMStepCB state)
{

  SSH_DEBUG(SSH_D_MIDSTART, ("Running DHCP"));

  if (!state)
    {
      if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
        state = ssh_dhcpv6_st_solicit;
      else
        state = ssh_dhcp_st_discover;
    }

  if (dhcp->thread == NULL)
    {
      SshDHCPStatus status;

      status = dhcp_setup(dhcp, state);
      if (status != SSH_DHCP_STATUS_OK)
        return status;
    }
  else
    {
      /* Use old thread. Calling this function always sets the next
         state and calls ssh_fsm_continue to execute the state. */
      ssh_fsm_set_next(dhcp->thread, state);
      ssh_fsm_continue(dhcp->thread);
    }

  if (dhcp->params.max_total_timeout)
    {
      ssh_register_timeout(&dhcp->total_timeout,
                           dhcp->params.max_total_timeout,
                           0, ssh_dhcp_total_timeout, dhcp);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting total timeout for DHCP, %u",
                                   dhcp->params.max_total_timeout));
    }

  return SSH_DHCP_STATUS_OK;
}

/* The main DHCP runner. This function is called to start the DHCP session.
   The user callback will be called during the session when the status
   of the session changes. */

SshDHCPStatus ssh_dhcp_run(SshDHCP dhcp)
{
  if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
    {
      if (dhcp->info != NULL && dhcp->info->my_ip != NULL)
        return ssh_dhcp_run_internal(dhcp, ssh_dhcpv6_st_renew);

      return ssh_dhcp_run_internal(dhcp, ssh_dhcpv6_st_solicit);
    }

  return ssh_dhcp_run_internal(dhcp, ssh_dhcp_st_discover);
}

/* Gracefully release the bound IP address. External process can call this
   to release the IP address. After that client must not use the IP address
   anymore. The `dhcp' is the current DHCP session in BOUND state. */

SshDHCPStatus ssh_dhcp_release(SshDHCP dhcp)
{
  if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
    return ssh_dhcp_run_internal(dhcp, ssh_dhcpv6_st_release);

  return ssh_dhcp_run_internal(dhcp, ssh_dhcp_st_release);
}

/* Decline to use the IP address server bound to us. External process can
   call this for example after detecting that the IP address server sent
   is already in use. This will cause re-start of the DHCP session from the
   begin to receive a new IP address. Servers may return addresses that
   are in use. It is the client's responsibility to check whether the given
   address is already in use in the network. The `dhcp' is the current
   DHCP session in BOUND state. */

SshDHCPStatus ssh_dhcp_decline(SshDHCP dhcp)
{
  if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_DHCPV6)
    return ssh_dhcp_run_internal(dhcp, ssh_dhcpv6_st_decline);

  return ssh_dhcp_run_internal(dhcp, ssh_dhcp_st_decline);
}

static void ssh_dhcp_abort_timeout(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;

  ssh_dhcp_cancel_timeouts(dhcp);

  if (dhcp->callback)
    (*dhcp->callback)(dhcp, dhcp->info, dhcp->status, dhcp->context);
}

/* Abort DHCP session. User callback will be called after abortion. The
   DHCP session must be aborted before it can be freed using the
   ssh_dhcp_free function. This function can be called in any state of
   the session. */

void ssh_dhcp_abort(SshDHCP dhcp)
{
  if (dhcp->status == SSH_DHCP_STATUS_ABORTED)
    return;

  dhcp->status = SSH_DHCP_STATUS_ABORTED;
  ssh_xregister_timeout(0, 0, ssh_dhcp_abort_timeout, dhcp);
}

SshDHCPStats ssh_dhcp_get_statistics(SshFSM fsm)
{
  SshDHCPMainCtx main_context = NULL;
  SshDHCPStats statistics = NULL;

  if (fsm == NULL)
    return NULL;

  main_context = ssh_fsm_get_gdata_fsm(fsm);
  if (main_context == NULL)
    return NULL;

  statistics = &main_context->stats;
  return statistics;
}
