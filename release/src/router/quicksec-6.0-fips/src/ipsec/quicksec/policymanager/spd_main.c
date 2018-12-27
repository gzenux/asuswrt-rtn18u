/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Top-level functions for policy manager objects.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshvrf.h"

#define SSH_DEBUG_MODULE "SshPm"

#ifdef DEBUG_LIGHT
extern const int ssh_pm_fsm_names_count;
SSH_RODATA
extern SshFSMStateDebugStruct ssh_pm_fsm_names[];
#endif /* DEBUG_LIGHT */



/************************ Public interface functions ************************/

/************************ PM library init / uninit **************************/

void ssh_pm_library_init()
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshNameServerConfigStruct config;

  memset(&config, 0, sizeof(config));
  config.forward_dns_queries = TRUE;

  if (ssh_name_server_init(&config) == FALSE)
    {
      /* We need to call this, as the FALSE in the init does not
         necessarily mean that the whole initialization has failed.
         It might mean that we falled back to system DNS rather using
         our own. */
      ssh_name_server_uninit();

      ssh_fatal("Name server initialisation failed.");
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
}

void ssh_pm_library_uninit()
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
  /* Uninitialize domain name services */
  ssh_name_server_uninit();
#endif /* SSHDIST_IPSEC_DNSPOLICY */
}

/************************ PM create / destroy *******************************/

static void
pm_startup_failure_engine_disconnected(SshPm pm, Boolean ok, void *context)
{
  (*pm->create_cb)(NULL, pm->create_cb_context);
  ssh_pm_free(pm);
}

static void
ssh_pm_create_status_cb(SshPm pm, Boolean status, void *context)
{
  SshCryptoStatus crypto_status;

  if (!status)
    goto error;

  /* We are now connected to the engine. */
  pm->connected = 1;

  /* Init ID counters. */
  pm->next_service_id = 1;
  pm->next_tunnel_id = 2;       /* See `engine_pm_api.h' why the init is 2. */
  pm->next_rule_id = 1;
  pm->next_ek_key_id = 1;
  pm->next_ca_id = 1;
  pm->next_audit_id = 1;

  /* Init some statistics. */
  pm->stats.rule_struct_size = sizeof(SshPmRuleStruct);
  pm->stats.service_struct_size = sizeof(SshPmServiceStruct);
  pm->stats.tunnel_struct_size = sizeof(SshPmTunnelStruct);

  /* Set the default setting for default IKE algorithms. */
  pm->default_ike_algorithms =
    (SSH_PM_IKE_DEFAULT_CRYPT | SSH_PM_IKE_DEFAULT_MAC);

#ifdef SSHDIST_EXTERNALKEY
  /* Create an externalkey module.  We set the notify callback so we
     know when keys are available.  The user must set the
     authentication callback to query PINs, etc. */
  pm->externalkey = ssh_ek_allocate();
  if (pm->externalkey == NULL)
    goto error;

  ssh_ek_register_notify(pm->externalkey, ssh_pm_ek_notify, pm);

  if (!ssh_pm_ek_init(pm))
    goto error;

  /* Configure accelerator if one is specified. */
  if (pm->params.ek_accelerator_type)
    {
      SshEkStatus ek_status;
      char *short_name;

      ek_status = ssh_ek_add_provider(pm->externalkey,
                                      pm->params.ek_accelerator_type,
                                      pm->params.ek_accelerator_init_info,
                                      pm->asyncop,
                                      SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR,
                                      &short_name);
      if (ek_status != SSH_EK_OK)
        {
          ssh_warning("Cannot add external key provider: %s",
                      ssh_ek_get_printable_status(ek_status));
          SSH_DEBUG(SSH_D_FAIL, ("Accelerator type '%s' init-info '%s'",
                                 pm->params.ek_accelerator_type,
                                 pm->params.ek_accelerator_init_info));
          pm->accel_short_name = NULL;
          goto error;
        }
      else
        {
          pm->accel_short_name = short_name;
        }
    }
#endif /* SSHDIST_EXTERNALKEY */

  /* Allocate a hash function for various hash operations in the
     policy manager. */
  crypto_status = ssh_hash_allocate("sha1", &pm->hash);
  if (crypto_status != SSH_CRYPTO_OK)
    goto error;

#ifdef SSHDIST_CRYPTO_RANDOM_POLL
  /* Initialize random poll module. */
  ssh_random_noise_polling_init();
#endif /* SSHDIST_CRYPTO_RANDOM_POLL */

  /* Create the main thread and its synchronization variables.  The
     main thread controls the policy manager startup, shutdown, and
     default rule generation. */
  ssh_fsm_condition_init(&pm->fsm, &pm->main_thread_cond);
  ssh_fsm_thread_init(&pm->fsm, &pm->main_thread,
                      ssh_pm_st_main_initialize,
                      NULL_FNPTR, NULL_FNPTR, pm);
  ssh_fsm_set_thread_name(&pm->main_thread, "main thread");

  /* Create resume condition. This is needed if some threads have
     been suspended / waiting for this resume condition. */
  ssh_fsm_condition_init(&pm->fsm, &pm->resume_cond);

  /* Audit initialization. */
  if (!ssh_pm_audit_init(pm))
    goto error_main_running;

  /* Allocate SAD handle. */
  pm->sad_handle = ssh_calloc(1, sizeof(*pm->sad_handle));
  if (pm->sad_handle == NULL)
    goto error_main_running;
  pm->sad_handle->pm = pm;

  /* Allocate traffic selector freelist. */
  if (!ssh_ikev2_ts_freelist_create(pm->sad_handle))
    goto error_main_running;

#ifdef SSHDIST_EXTERNALKEY
  /* Create the externalkey thread and its synchronization variables.
     The externalkey thread controls externalkey events, like fetching
     certificates and private keys from notified key paths. */
  pm->ek_thread_ok = 1;
  ssh_fsm_condition_init(&pm->fsm, &pm->ek_thread_cond);
  ssh_fsm_thread_init(&pm->fsm, &pm->ek_thread, ssh_pm_st_ek_start,
                      NULL_FNPTR, NULL_FNPTR, pm);
  ssh_fsm_set_thread_name(&pm->ek_thread, "ek thread");
#endif /* SSHDIST_EXTERNALKEY */

  /* Allocate SPI database. */
  if (!ssh_pm_spis_create(pm))
    goto error_main_running;

#ifdef WITH_IKE
  /* Initialize IKE server. */
  if (!ssh_pm_ike_init(pm))
    goto error_main_running;
#endif /* WITH_IKE */

#ifdef SSHDIST_L2TP
  /* Initialize L2TP server. */
  if (!ssh_pm_l2tp_init(pm))
    goto error_main_running;
#endif /* SSHDIST_L2TP */

  /* Initialize dynamic server handler. */
  if (!ssh_pm_servers_init(pm))
    goto error_main_running;

  /* Initialize tunnel database. */
  if (!ssh_pm_tunnels_init(pm))
    goto error_main_running;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Initialize cfgmode client store. */
  if (!ssh_pm_cfgmode_client_store_init(pm))
    goto error_main_running;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSH_PM_BLACKLIST_ENABLED
  /* Initialize blacklisting functionality. */
  if (!ssh_pm_blacklist_init(pm))
    goto error_main_running;
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /* All done.  The main thread will call the completion callback
     after the interface information is received from the engine. */
  return;

  /* Error handling. */
 error_main_running:

  if (SSH_FSM_THREAD_EXISTS(&pm->main_thread))
    {
      ssh_fsm_kill_thread(&pm->main_thread);
      ssh_fsm_condition_uninit(&pm->main_thread_cond);
      ssh_fsm_condition_uninit(&pm->resume_cond);
    }
#ifdef SSHDIST_EXTERNALKEY
  if (SSH_FSM_THREAD_EXISTS(&pm->ek_thread))
    {
      ssh_fsm_kill_thread(&pm->ek_thread);
      ssh_fsm_condition_uninit(&pm->ek_thread_cond);
    }
#endif /* SSHDIST_EXTERNALKEY */

 error:
  ssh_pm_disconnect_engine(pm, pm_startup_failure_engine_disconnected, NULL);
}


void
ssh_pm_create(void *machine_context, SshPmParams params,
              SshPmCreateCB callback, void *context)
{
  SshPm pm;
  SshUInt32 flags = SSH_IPSEC_ENGINE_FLAGS;
  SshPmParamsStruct zero_params = {0};

  /* Allocate a policy manager object. */
  pm = ssh_pm_alloc();
  if (pm == NULL)
    goto error;

  /* Store parameters and set the default values for all unset
     parameters. */
  if (params == NULL)
    params = &zero_params;

  memset(&pm->params, 0x0, sizeof(SshPmParamsStruct));

  if (params->socks)
    {
      pm->params.socks = ssh_strdup(params->socks);
      if (pm->params.socks == NULL)
        goto error;
    }

  if (params->http_proxy)
    {
      pm->params.http_proxy = ssh_strdup(params->http_proxy);
      if (pm->params.http_proxy == NULL)
        goto error;
    }

  if (params->hostname)
    {
      pm->params.hostname = ssh_strdup(params->hostname);
      if (pm->params.hostname == NULL)
        goto error;
    }

  pm->params.pass_unknown_ipsec_packets = params->pass_unknown_ipsec_packets;

  /* Save IKE parameters. */
  if (params->ike_params)
    {
      pm->ike_params = *params->ike_params;
      if (params->ike_params->normal_udp_params)
        pm->ike_udp_params = *params->ike_params->normal_udp_params;
    }

  /* IKE parameters. */
  if (params->ike_params)
    {
      /* Init our default IKE params if they are not set. */
      if (pm->ike_params.retry_limit == 0)
        pm->ike_params.retry_limit = SSH_PM_IKE_RETRY_LIMIT;
    }

  /* And link the IKE params to the PM params just for consistency. */
  pm->params.ike_params = &pm->ike_params;
  if (pm->params.ike_params->normal_udp_params)
    pm->params.ike_params->normal_udp_params = &pm->ike_udp_params;

  /* Mark IKE listeners */
  if (params->ike_addrs_count)
    {
      pm->params.ike_addrs = ssh_calloc(params->ike_addrs_count,
                                        sizeof(SshIpAddrStruct));
      if (pm->params.ike_addrs == NULL)
        goto error;

      memcpy(pm->params.ike_addrs, params->ike_addrs,
             params->ike_addrs_count * sizeof(SshIpAddrStruct));
    }

  pm->params.ike_addrs_count = params->ike_addrs_count;

  if (params->num_ike_ports > SSH_IPSEC_MAX_IKE_PORTS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Configuring too many IKE listener ports"));
      goto error;
    }

  if (params->num_ike_ports == 0)
    pm->params.num_ike_ports = 1;
  else
    pm->params.num_ike_ports = params->num_ike_ports;

  if (params->num_ike_ports == 0)
    {
      pm->params.local_ike_ports[0] = SSH_IPSEC_IKE_PORT;
      pm->params.local_ike_natt_ports[0] = SSH_IPSEC_IKE_NATT_PORT;
      pm->params.remote_ike_ports[0] = SSH_IPSEC_IKE_PORT;
      pm->params.remote_ike_natt_ports[0] = SSH_IPSEC_IKE_NATT_PORT;
    }
  else
    {
      memmove(pm->params.local_ike_ports,
              params->local_ike_ports,
              pm->params.num_ike_ports * sizeof(SshUInt16));
      memmove(pm->params.local_ike_natt_ports,
              params->local_ike_natt_ports,
              pm->params.num_ike_ports * sizeof(SshUInt16));
      memmove(pm->params.remote_ike_ports,
              params->remote_ike_ports,
              pm->params.num_ike_ports * sizeof(SshUInt16));
      memmove(pm->params.remote_ike_natt_ports,
              params->remote_ike_natt_ports,
              pm->params.num_ike_ports * sizeof(SshUInt16));
    }

#ifdef SSHDIST_IPSEC_NAT
  if (params->nat_port_range_low)
    pm->params.nat_port_range_low = params->nat_port_range_low;
  else
    pm->params.nat_port_range_low = 40000;

  if (params->nat_port_range_high)
    pm->params.nat_port_range_high = params->nat_port_range_high;
  else
    pm->params.nat_port_range_high = 65535;

  if (params->nat_privileged_port_range_low)
    pm->params.nat_privileged_port_range_low =
        params->nat_privileged_port_range_low;
  else
    pm->params.nat_privileged_port_range_low = 770;

  if (params->nat_privileged_port_range_high)
    pm->params.nat_privileged_port_range_high =
        params->nat_privileged_port_range_high;
  else
    pm->params.nat_privileged_port_range_high = 869;
#endif /* SSHDIST_IPSEC_NAT */


#ifdef SSHDIST_EXTERNALKEY
  if (params->ek_accelerator_type && params->ek_accelerator_init_info)
    {
      pm->params.ek_accelerator_type = ssh_strdup(params->ek_accelerator_type);
      if (pm->params.ek_accelerator_type == NULL)
        goto error;

      pm->params.ek_accelerator_init_info = ssh_strdup(
                                       params->ek_accelerator_init_info);
      if (pm->params.ek_accelerator_init_info == NULL)
        goto error;
    }
#endif /* SSHDIST_EXTERNALKEY */

  /* Initialize the PM context */
  pm->params.flags = params->flags;

#ifdef DEBUG_LIGHT
  pm->magic = SSH_PM_MAGIC_PM;
#endif /* DEBUG_LIGHT */

  ssh_fsm_init(&pm->fsm, pm);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(&pm->fsm,
                               ssh_pm_fsm_names,
                               ssh_pm_fsm_names_count);
#endif /* DEBUG_LIGHT */

  pm->params.dhcp_ras_enabled = params->dhcp_ras_enabled;
  pm->params.enable_key_restrictions = params->enable_key_restrictions;

  ssh_vrf_register_cb(ssh_pm_find_interface_vri_name,
                      ssh_pm_find_interface_vri_id,
                      ssh_pm_find_interface_vri_id_by_ifnum,
                      pm);

  pm->create_cb = callback;
  pm->create_cb_context = context;

  /* Connect to the packet processing engine.  The rest of the
     initialization is done if the connection callback.  The
     callback context is the user-supplied context. */
  ssh_pm_connect_engine(pm, machine_context, flags,
#ifdef SSHDIST_IPSEC_NAT
                        pm->params.nat_port_range_low,
                        pm->params.nat_port_range_high,
                        pm->params.nat_privileged_port_range_low,
                        pm->params.nat_privileged_port_range_high,
#else /* SSHDIST_IPSEC_NAT */
                        0, 0, 0, 0,
#endif /* SSHDIST_IPSEC_NAT */
                        pm->params.num_ike_ports,
                        pm->params.local_ike_ports,
                        pm->params.local_ike_natt_ports,
                        pm->params.remote_ike_ports,
                        pm->params.remote_ike_natt_ports,
                        ssh_pm_create_status_cb, NULL);
  return;

  /* Error handling. */
 error:
  ssh_pm_free(pm);
  (*callback)(NULL, context);
}

void
ssh_pm_destroy(SshPm pm, SshPmDestroyCB callback, void *context)
{
  SSH_PM_ASSERT_PM(pm);

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Notifying main thread about shutdown"));
      pm->destroyed = 1;
      pm->destroy_callback = callback;
      pm->destroy_callback_context = context;
      ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
    }
}

#ifdef SSHDIST_IKE_REDIRECT

/**************** Disabling / enabling global IKE redirect *******************/

void ssh_pm_clear_ike_redirect(SshPm pm)
{
  SSH_IP_UNDEFINE(&pm->ike_redirect_addr);
  pm->ike_redirect_enabled = 0;
}

Boolean ssh_pm_set_ike_redirect(SshPm pm, SshIpAddr redirect_addr,
                                SshUInt8 phase)
{
  if (pm == NULL)
    return FALSE;

  /* Check address validity if address is given. Client does not set redirect
     address*/
  if (redirect_addr != NULL)
    {
      if (!SSH_IP_DEFINED(redirect_addr))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid IKE Redirect address."));
          return FALSE;
        }
      memcpy(&pm->ike_redirect_addr, redirect_addr, sizeof(*redirect_addr));
    }
  else
    {
      SSH_IP_UNDEFINE(&pm->ike_redirect_addr);
    }

  if (phase == 0) /* Implicit phase supported */
    {
      pm->ike_redirect_enabled = SSH_PM_IKE_REDIRECT_IKE_INIT;
    }
  else if ((phase & SSH_PM_IKE_REDIRECT_MASK) == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("IKE Redirect phase not supported."));
      return FALSE;
    }
  else if ((phase & SSH_PM_IKE_REDIRECT_IKE_INIT) != 0 &&
           (phase & SSH_PM_IKE_REDIRECT_IKE_AUTH) != 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("IKE Redirect at phases IKE_INIT and IKE_AUTH "
                              "cannot be configured simultaneously."));
      return FALSE;
    }
  else
    pm->ike_redirect_enabled = phase;

  return TRUE;
}
#endif /* SSHDIST_IKE_REDIRECT */

/**************** Disabling / enabling PM policy lookups *********************/

SshPmStatus
ssh_pm_get_status(SshPm pm)
{
  if (pm->destroyed)
    return SSH_PM_STATUS_DESTROYED;

  if (pm->policy_suspend_count)
    return SSH_PM_STATUS_SUSPENDED;

  if (pm->policy_suspending)
    return SSH_PM_STATUS_SUSPENDING;

  return SSH_PM_STATUS_ACTIVE;
}

static void
pm_policy_suspend_cb(void *context)
{
  SshPm pm = context;
  SshPmCallbacks status_cb;

  SSH_PM_ASSERT_PM(pm);

  /* Call all pending policy suspend completion callbacks, increment
     policy_suspend_count by one for each completed suspend. */
  while (pm->policy_suspend_cb)
    {
      status_cb = pm->policy_suspend_cb;
      pm->policy_suspend_cb = pm->policy_suspend_cb->next;

      pm->policy_suspend_count++;
      SSH_DEBUG(SSH_D_LOWOK,
                ("Incrementing policy manager suspend count to %d",
                 pm->policy_suspend_count));

      if (status_cb->u.status_cb != NULL_FNPTR)
        (*status_cb->u.status_cb)(pm, TRUE, status_cb->context);

      ssh_free(status_cb);
    }

  pm->policy_suspending = 0;
  SSH_DEBUG(SSH_D_LOWOK, ("Policy manager suspended"));
}

/* Internal function */
void
ssh_pm_policy_suspend(SshPm pm, SshPmStatusCB callback, void *context)
{
  SshPmCallbacks status_cb;

  SSH_PM_ASSERT_PM(pm);

  /* Policy manager is already suspended, increment suspend count and
     call completion callback. */
  if (pm->policy_suspend_count > 0)
    {
      pm->policy_suspend_count++;
      SSH_DEBUG(SSH_D_LOWOK,
                ("Incrementing policy manager suspend count to %d",
                 pm->policy_suspend_count));
      if (callback != NULL_FNPTR)
        (*callback)(pm, TRUE, context);
    }

  /* Start suspending policy manager, store callback for later completion. */
  else
    {
      status_cb = ssh_calloc(1, sizeof(*status_cb));
      if (status_cb == NULL)
        {
          if (callback != NULL_FNPTR)
            (*callback)(pm, FALSE, context);
          return;
        }

      status_cb->u.status_cb = callback;
      status_cb->context = context;

      /* Policy manager suspend is underway, just store completion callback. */
      if (pm->policy_suspend_cb)
        {
          status_cb->next = pm->policy_suspend_cb;
          pm->policy_suspend_cb = status_cb;
        }

      /* Start by suspending the IKEv2 library. */
      else
        {
          status_cb->next = pm->policy_suspend_cb;
          pm->policy_suspend_cb = status_cb;

          pm->policy_suspending = 1;

#ifdef WITH_IKE
          SSH_DEBUG(SSH_D_LOWOK, ("Suspending IKEv2 library"));
          ssh_ikev2_suspend(pm->ike_context, 0, pm_policy_suspend_cb, pm);
#else /* WITH_IKE */
          pm_policy_suspend_cb(pm);
#endif /* WITH_IKE */
        }
    }
}

/* Internal function */
Boolean ssh_pm_policy_resume(SshPm pm)
{
  SshPmP1 p1;

  SSH_PM_ASSERT_PM(pm);

  if (pm->policy_suspend_count == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Policy manager is not suspended"));
      return FALSE;
    }

  SSH_ASSERT(pm->policy_suspending == 0);
  pm->policy_suspend_count--;
  SSH_DEBUG(SSH_D_LOWOK,
            ("Decremented policy manager suspend count to %d",
             pm->policy_suspend_count));

  if (pm->policy_suspend_count == 0)
    {
#ifdef WITH_IKE
      SSH_DEBUG(SSH_D_LOWOK, ("Resuming IKEv2 library"));
      ssh_ikev2_resume(pm->ike_context);
#endif /* WITH_IKE */

      SSH_DEBUG(SSH_D_LOWOK, ("Policy manager resumed"));

      /* Handle resume queue unless batch is still active (batch thread
         will go through the whole IKE SA hash table and process all IKE
         SAs). */
      if (!pm->batch_active)
        {
          while (pm->resume_queue != NULL)
            {
              p1 = pm->resume_queue;
              pm->resume_queue = p1->resume_queue_next;
              p1->resume_queue_next = NULL;
              SSH_ASSERT(p1->in_resume_queue);
              p1->in_resume_queue = 0;
              if (!SSH_PM_P1_DELETED(p1))
                ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
            }
        }

      /* Trigger auto-start. */
      if (pm->auto_start == 0)
        {
          pm->auto_start = 1;
          ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
        }

#ifdef SSHDIST_IPSEC_MOBIKE
      /* Re-evaluate MOBIKE SAs. */
      ssh_pm_mobike_reevaluate(pm, NULL_FNPTR, NULL);
#endif /* SSHDIST_IPSEC_MOBIKE */

      SSH_APE_MARK(1, ("Policy rules loaded"));





    }

  return TRUE;
}

/* Public API function */
void
ssh_pm_disable_policy_lookups(SshPm pm, SshPmStatusCB callback, void *context)
{
  SSH_PM_ASSERT_PM(pm);

  if (pm->policy_suspended)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Policy lookups are already suspended"));
      if (callback != NULL_FNPTR)
        (*callback)(pm, FALSE, context);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Suspending policy manager policy lookups"));
  pm->policy_suspended = 1;
  ssh_pm_policy_suspend(pm, callback, context);
}

/* Public API function */
void
ssh_pm_enable_policy_lookups(SshPm pm, SshPmStatusCB callback, void *context)
{
  Boolean status = FALSE;

  SSH_PM_ASSERT_PM(pm);

  if (pm->policy_suspended)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Resuming policy manager policy lookups"));
      if (ssh_pm_policy_resume(pm))
        status = TRUE;

      pm->policy_suspended = 0;
    }
  else
    SSH_DEBUG(SSH_D_FAIL, ("Policy lookups are not suspended"));

  if (callback != NULL_FNPTR)
    (*callback)(pm, status, context);
}

SshUInt32
ssh_pm_get_number_of_interfaces(SshPm pm)
{
  return pm->ifs.nifs;
}

Boolean
ssh_pm_get_interface_number(SshPm pm, const char *ifname,
                            SshUInt32 *ifnum_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface(pm, ifname, ifnum_return);
  return ifp != NULL;
}

Boolean
ssh_pm_get_interface_name(SshPm pm, SshUInt32 ifnum, char **ifname_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL)
    return FALSE;

  if (ifname_return)
    *ifname_return = ifp->name;

  return TRUE;
}

Boolean
ssh_pm_interface_enumerate_start(SshPm pm, SshUInt32 *ifnum_return)
{
  SshUInt32 first_ifnum;

  first_ifnum = ssh_ip_enumerate_start(&pm->ifs);
  if (first_ifnum == SSH_INVALID_IFNUM)
    return FALSE;

  if (ifnum_return)
    *ifnum_return = first_ifnum;

  return TRUE;
}

Boolean
ssh_pm_interface_enumerate_next(SshPm pm, SshUInt32 ifnum,
                                SshUInt32 *ifnum_return)
{
  SshUInt32 next_ifnum;

  next_ifnum = ssh_ip_enumerate_next(&pm->ifs, ifnum);
  if (next_ifnum == SSH_INVALID_IFNUM)
    return FALSE;

  if (ifnum_return)
    *ifnum_return = next_ifnum;

  return TRUE;
}

Boolean
ssh_pm_interface_get_number_of_addresses(SshPm pm, SshUInt32 ifnum,
                                         SshUInt32 *addr_count_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL)
    return FALSE;

  if (addr_count_return)
    *addr_count_return = ifp->num_addrs;

  return TRUE;
}


Boolean
ssh_pm_interface_get_address(SshPm pm, SshUInt32 ifnum, SshUInt32 addrnum,
                             SshIpAddr addr)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL || addrnum >= ifp->num_addrs)
    return FALSE;

  switch (ifp->addrs[addrnum].protocol)
    {
    case SSH_PROTOCOL_IP4:
    case SSH_PROTOCOL_IP6:
      if (addr)
        *addr = ifp->addrs[addrnum].addr.ip.ip;
      break;

    default:
      SSH_IP_UNDEFINE(addr);
      break;
    }

  return TRUE;
}


Boolean
ssh_pm_interface_get_netmask(SshPm pm, SshUInt32 ifnum, SshUInt32 addrnum,
                             SshIpAddr netmask)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL || addrnum >= ifp->num_addrs)
    return FALSE;

  switch (ifp->addrs[addrnum].protocol)
    {
    case SSH_PROTOCOL_IP4:
    case SSH_PROTOCOL_IP6:
      *netmask = ifp->addrs[addrnum].addr.ip.mask;
      break;

    default:
      SSH_IP_UNDEFINE(netmask);
      break;
    }

  return TRUE;
}


Boolean
ssh_pm_interface_get_broadcast(SshPm pm, SshUInt32 ifnum, SshUInt32 addrnum,
                               SshIpAddr broadcast)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL || addrnum >= ifp->num_addrs)
    return FALSE;

  switch (ifp->addrs[addrnum].protocol)
    {
    case SSH_PROTOCOL_IP4:
    case SSH_PROTOCOL_IP6:
      *broadcast = ifp->addrs[addrnum].addr.ip.broadcast;
      break;

    default:
      SSH_IP_UNDEFINE(broadcast);
      break;
    }

  return TRUE;
}

Boolean
ssh_pm_interface_get_routing_instance_id(SshPm pm, SshUInt32 ifnum,
                                         SshVriId *id_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL)
    return FALSE;

  if (id_return)
    *id_return = ifp->routing_instance_id;

  return TRUE;
}

Boolean
ssh_pm_get_interface_routing_instance_name(SshPm pm, SshUInt32 ifnum,
                                           const char **riname_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (ifp == NULL)
    return FALSE;

  if (riname_return)
    *riname_return = ifp->routing_instance_name;

  return TRUE;
}

void
ssh_pm_set_interface_callback(SshPm pm, SshPmInterfaceChangeCB callback,
                              void *context)
{
  pm->interface_callback = callback;
  pm->interface_callback_context = context;
}


Boolean
ssh_pm_ike_debug_insert(SshPm pm, SshPdbgConstConfigEntry entry)
{
  return ssh_pdbg_config_insert(&pm->debug_config, entry);
}

Boolean
ssh_pm_ike_debug_remove(SshPm pm, SshPdbgConstConfigEntry entry)
{
  return ssh_pdbg_config_remove(&pm->debug_config, entry);
}

SshPdbgConstConfigEntry
ssh_pm_ike_debug_get(SshPm pm, SshPdbgConstConfigEntry previous)
{
  return ssh_pdbg_config_get(&pm->debug_config, previous);
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_LDAP
Boolean
ssh_pm_set_ldap_servers(SshPm pm, const unsigned char *servers)
{
  return ssh_cm_edb_ldap_init(pm->default_auth_domain->cm, servers);
}
#endif /* SSHDIST_LDAP */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_EXTERNALKEY
SshExternalKey
ssh_pm_get_externalkey(SshPm pm)
{
  return pm->externalkey;
}

void
ssh_pm_set_externalkey_notify_callback(SshPm pm, SshEkNotifyCB callback,
                                       void *context)
{
  pm->ek_user_notify_cb = callback;
  pm->ek_user_notify_cb_context = context;
}

void
ssh_pm_clear_externalkey_providers(SshPm pm)
{
  SshExternalKey ek = pm->externalkey;
  SshUInt32 i;
  SshEkProvider ek_providers;
  SshUInt32 num_ek_providers;

  /* Get the list of currently configured providers. */
  if (!ssh_ek_get_providers(ek, &ek_providers, &num_ek_providers))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get externalkey providers"));
      return;
    }

  if (num_ek_providers == 0)
    {
      /* No providers configured. */
      return;
    }

  for (i = 0; i < num_ek_providers; i++)
    {
      ssh_ek_remove_provider(ek, ek_providers[i].short_name);
    }

  /* Free the providers array. */
  ssh_free(ek_providers);
}

#endif /* SSHDIST_EXTERNALKEY */

/****************** Policy manager configuration functions ******************/


#ifdef SSHDIST_IPSEC_NAT
Boolean
ssh_pm_set_interface_nat(SshPm pm,
                         SshPmNatFlags flags,
                         const char *ifname,
                         SshPmNatType nat_type)
{
  SshPmIfaceNat nat;

  if (!ifname)
    return FALSE;

  nat = pm->iface_nat_list;
  while (nat != NULL)
    {
      if (strcmp(nat->ifname, ifname) == 0)
        break;
      nat = nat->next;
    }

  if (nat == NULL)
    {
      nat = ssh_pm_iface_nat_alloc(pm);
      if (nat == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No more pending NAT operations left"));
          return FALSE;
        }
      if (sizeof(nat->ifname) <= strlen(ifname))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Interface names cannot be longer than %d charaters",
                        sizeof(nat->ifname) - 1);
          ssh_pm_iface_nat_free(pm, nat);
          return FALSE;
        }
      strncpy(nat->ifname, ifname, sizeof(nat->ifname));
      /* ensure NULL termination */
      nat->ifname[sizeof(nat->ifname) - 1] = 0;

      /* Link it to pm's list of pending operations. */
      nat->next = pm->iface_nat_list;
      pm->iface_nat_list = nat;
    }

  nat->type = nat_type;
  /* Other flags are currently ignored. */
  nat->flags = flags;

  /* Notify the main thread that the interface information has
     changed. */
  pm->iface_change = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  return TRUE;
}

Boolean
ssh_pm_clear_interface_nat(SshPm pm)
{
  while (pm->iface_nat_list)
    {
      SshPmIfaceNat nat = pm->iface_nat_list;

      pm->iface_nat_list = nat->next;
      ssh_pm_iface_nat_free(pm, nat);
    }

  /* Notify the main thread that the interface information has
     changed. */
  pm->iface_change = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  return TRUE;
}
#endif /* SSHDIST_IPSEC_NAT */


/*********************** Global default SA parameters ***********************/


Boolean
ssh_pm_set_default_ike_algorithms(SshPm pm, SshUInt32 algorithms)
{
  SshUInt32 ciphers = 0;
  SshUInt32 hashes = 0;

  /* Use default encryption algorithms if none specified. */
  if ((algorithms & SSH_PM_CRYPT_MASK) == 0)
    algorithms |= SSH_PM_IKE_DEFAULT_CRYPT;

  /* Use default hash algorithms if none specified. */
  if ((algorithms & SSH_PM_MAC_MASK) == 0)
    algorithms |= SSH_PM_IKE_DEFAULT_MAC;

  if (!ssh_pm_ike_num_algorithms(pm, algorithms, 0,
                                 &ciphers, &hashes, NULL) ||
      ciphers == 0 || hashes == 0)
    return FALSE;

  SSH_ASSERT((algorithms & SSH_PM_CRYPT_MASK) != 0);
  SSH_ASSERT((algorithms & SSH_PM_MAC_MASK) != 0);

  pm->default_ike_algorithms = algorithms;
  return TRUE;
}

/************************ IPsec SA event notification ***********************/

void
ssh_pm_set_ike_sa_callback(SshPm pm, SshPmIkeSACB callback, void *context)
{
  pm->ike_sa_callback = callback;
  pm->ike_sa_callback_context = context;
}

void
ssh_pm_set_ipsec_sa_callback(SshPm pm, SshPmIpsecSACB callback, void *context)
{
  pm->ipsec_sa_callback = callback;
  pm->ipsec_sa_callback_context = context;
}

#ifdef SSHDIST_IKEV1
/*************** Pre-shared key selection for aggressive mode ***************/

void
ssh_pm_set_ike_preshared_key_callback(SshPm pm,
                                      SshPmIkePreSharedKeyCB callback,
                                      void *context)
{
  pm->ike_preshared_keys_cb = callback;
  pm->ike_preshared_keys_cb_context = context;
}
#endif /* SSHDIST_IKEV1 */


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/********************* Default remote access responder **********************/

void
ssh_pm_set_remote_access(SshPm pm,
                         SshPmRemoteAccessAttrsAllocCB alloc_cb,
                         SshPmRemoteAccessAttrsFreeCB free_cb,
                         void *context)
{
  pm->remote_access_alloc_cb = alloc_cb;
  pm->remote_access_free_cb = free_cb;
  pm->remote_access_cb_context = context;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
/********************** Extended authentication server **********************/

void
ssh_pm_xauth_server(SshPm pm,
                    Boolean enable)
{
  pm->xauth.enabled = enable;
}

void
ssh_pm_xauth_method(SshPm pm,
                    SshIkeXauthType method,
                    SshPmXauthFlags flags)
{
  pm->xauth.type = method;
  pm->xauth.flags = flags;
}
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

/********************** Password authentication server **********************/

void
ssh_pm_passwd_auth_server(SshPm pm, SshPmPasswdAuthCB callback, void *context)
{
  pm->passwd_auth_callback = callback;
  pm->passwd_auth_callback_context = context;
}

/******************  IKE redirect decision functionality ******************/
#ifdef SSHDIST_IKE_REDIRECT

void
ssh_pm_set_ike_redirect_decision_callback(
                                SshPm pm,
                                SshPmIkeRedirectDecisionCB decision_cb,
                                void *context)
{
  pm->ike_redirect_decision_cb = decision_cb;
  pm->ike_redirect_decision_cb_context = context;
}

#endif /* SSHDIST_IKE_REDIRECT */

/**************** Legacy authentication client functionality ****************/

void
ssh_pm_set_legacy_auth_client_callbacks(
                                SshPm pm,
                                SshPmLegacyAuthClientQueryCB query_cb,
                                SshPmLegacyAuthClientResultCB result_cb,
                                void *context)
{
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_IKE_XAUTH
  ssh_ikev2_fallback_set_xauth_client(pm->ike_context,
                                      pm_xauth_client_request,
                                      pm_xauth_client_set,
                                      pm);
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  pm->la_client_query_cb = query_cb;
  pm->la_client_result_cb = result_cb;
  pm->la_client_context = context;
}

#ifdef SSHDIST_IPSEC_MOBIKE
/******************************** Mobike ************************************/











Boolean ssh_pm_set_mobike_default_rrc_policy(SshPm pm,
                                             SshUInt32 flags)
{
  /* Sanity check rrc policy. */
  if ((flags & (SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE
                | SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE))
      && (flags & SSH_PM_MOBIKE_POLICY_NO_RRC))
    return FALSE;

  /* Set default policy. */
  if (flags == 0)
    return FALSE;

  pm->mobike_rrc_policy = flags;
  return TRUE;
}

#endif /* SSHDIST_IPSEC_MOBIKE */


/*************************** Engine Configuration ***************************/

void
ssh_pm_set_flags(SshPm pm, SshUInt32 flags)
{
  pm->flags = flags;
}


/************ FSM state names for debugging purposes ******************/

#ifdef DEBUG_LIGHT
SSH_RODATA
SshFSMStateDebugStruct ssh_pm_fsm_names[] =
 {
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  SSH_FSM_STATE("pm_cm_access_create_rule",
                  "pm cm access create rule",
                  pm_cm_access_create_rule)
  SSH_FSM_STATE("pm_cm_access_create_rule_done",
                  "pm cm access create rule done",
                  pm_cm_access_create_rule_done)
  SSH_FSM_STATE("pm_cm_access_delete_rule",
                "pm cm access delete rule",
                pm_cm_access_delete_rule)
  SSH_FSM_STATE("pm_cm_access_done",
                "pm cm access done",
                pm_cm_access_done)
  SSH_FSM_STATE("pm_cm_access_resolve_name",
                "pm cm access resolve name",
                pm_cm_access_resolve_name)
  SSH_FSM_STATE("pm_cm_access_start",
                "pm cm access start",
                pm_cm_access_start)
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_STATE("pm_ike_id_psk_lookup_finish",
                "pm ike id psk lookup finish",
                pm_ike_id_psk_lookup_finish)
  SSH_FSM_STATE("pm_ike_id_psk_lookup_start",
                "pm ike id psk lookup start",
                pm_ike_id_psk_lookup_start)
  SSH_FSM_STATE("pm_ike_sa_delete",
                "pm ike sa delete",
                pm_ike_sa_delete)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  SSH_FSM_STATE("pm_ras_addrpool_alloc",
                "pm ras addrpool alloc",
                pm_ras_addrpool_alloc)
  SSH_FSM_STATE("pm_ras_addrpool_alloc_done",
                "pm ras addrpool alloc done",
                pm_ras_addrpool_alloc_done)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  SSH_FSM_STATE("pm_rekey_ike_sa_start",
                "pm rekey ike sa start",
                pm_rekey_ike_sa_start)
#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_STATE("pm_rekey_ike_sa_update_ike_mapping",
                "pm rekey ike sa update ike mapping",
                pm_rekey_ike_sa_update_ike_mapping)
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_STATE("pm_rekey_ike_sa_update_ipsec_sas",
                "pm rekey ike sa update ipsec sas",
                pm_rekey_ike_sa_update_ipsec_sas)
  SSH_FSM_STATE("pm_rekey_ike_sa_finish",
                "pm rekey ike sa finish",
                pm_rekey_ike_sa_finish)
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  SSH_FSM_STATE("pm_ras_attrs_alloc",
                "pm ras attrs alloc",
                pm_ras_attrs_alloc)
  SSH_FSM_STATE("pm_ras_attrs_alloc_result",
                "pm ras attrs alloc result",
                pm_ras_attrs_alloc_result)
  SSH_FSM_STATE("pm_ras_attrs_register_clients",
                "pm ras attrs register clients",
                pm_ras_attrs_register_clients)
  SSH_FSM_STATE("pm_ras_attrs_register_clients_result",
                "pm ras attrs register clients result",
                pm_ras_attrs_register_clients_result)
  SSH_FSM_STATE("pm_ras_attrs_done",
                "pm ras attrs done",
                pm_ras_attrs_done)
  SSH_FSM_STATE("pm_ras_cfgmode_client_add_arp",
                "pm ras cfgmode client add arp",
                pm_ras_cfgmode_client_add_arp)
  SSH_FSM_STATE("pm_ras_cfgmode_client_add_arp_result",
                "pm ras cfgmode client add arp result",
                pm_ras_cfgmode_client_add_arp_result)
  SSH_FSM_STATE("pm_ras_cfgmode_client_add_arp_done",
                "pm ras cfgmode client add arp done",
                pm_ras_cfgmode_client_add_arp_done)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SSH_FSM_STATE("pm_ipsec_select_policy_rule",
                "pm ipsec select policy rule",
                pm_ipsec_select_policy_rule)
  SSH_FSM_STATE("pm_ipsec_set_authorization_groups",
                "pm ipsec set authorization groups",
                pm_ipsec_set_authorization_groups)
  SSH_FSM_STATE("pm_ipsec_spi_allocate",
                "pm ipsec spi allocate",
                pm_ipsec_spi_allocate)
  SSH_FSM_STATE("pm_ipsec_spi_allocate_done",
                "pm ipsec spi allocate done",
                pm_ipsec_spi_allocate_done)
  SSH_FSM_STATE("pm_ipsec_spi_delete",
                "pm ipsec spi delete",
                pm_ipsec_spi_delete)
  SSH_FSM_STATE("pm_ipsec_spi_delete_done",
                "pm ipsec spi delete done",
                pm_ipsec_spi_delete_done)
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  SSH_FSM_STATE("pm_rekey_ike_sa_renew_ras_attrs",
                "pm rekey ike sa renew ras attrs",
                pm_rekey_ike_sa_renew_ras_attrs)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SSH_FSM_STATE("pm_st_dns_iterate_done",
                "pm st dns iterate done",
                pm_st_dns_iterate_done)
  SSH_FSM_STATE("pm_st_dns_iterate_next",
                "pm st dns iterate next",
                pm_st_dns_iterate_next)
  SSH_FSM_STATE("pm_st_dns_qryupd_done",
                "pm st dns qryupd done",
                pm_st_dns_qryupd_done)
  SSH_FSM_STATE("pm_st_dns_qryupd_qry_start",
                "pm st dns qryupd qry start",
                pm_st_dns_qryupd_qry_start)
  SSH_FSM_STATE("pm_st_dns_qryupd_upd_start",
                "pm st dns qryupd upd start",
                pm_st_dns_qryupd_upd_start)
  SSH_FSM_STATE("pm_st_dns_query_end",
                "pm st dns query end",
                pm_st_dns_query_end)
  SSH_FSM_STATE("pm_st_dns_query_start",
                "pm st dns query start",
                pm_st_dns_query_start)
  SSH_FSM_STATE("pm_st_dns_update_done",
                "pm st dns update done",
                pm_st_dns_update_done)
  SSH_FSM_STATE("pm_st_dns_update_next",
                "pm st dns update next",
                pm_st_dns_update_next)
  SSH_FSM_STATE("pm_st_dns_update_start",
                "pm st dns update start",
                pm_st_dns_update_start)
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  SSH_FSM_STATE("ssh_pm_st_config_start",
                "ssh pm st config start",
                ssh_pm_st_config_start)
#ifdef SSHDIST_EXTERNALKEY
  SSH_FSM_STATE("ssh_pm_st_ek_certs",
                "ssh pm st ek certs",
                ssh_pm_st_ek_certs)
  SSH_FSM_STATE("ssh_pm_st_ek_get_cert_result",
                "ssh pm st ek get cert result",
                ssh_pm_st_ek_get_cert_result)
  SSH_FSM_STATE("ssh_pm_st_ek_get_private_key_result",
                "ssh pm st ek get private key result",
                ssh_pm_st_ek_get_private_key_result)
  SSH_FSM_STATE("ssh_pm_st_ek_key_done",
                "ssh pm st ek key done",
                ssh_pm_st_ek_key_done)
  SSH_FSM_STATE("ssh_pm_st_ek_lookup_change",
                "ssh pm st ek lookup change",
                ssh_pm_st_ek_lookup_change)
  SSH_FSM_STATE("ssh_pm_st_ek_private_key",
                "ssh pm st ek private key",
                ssh_pm_st_ek_private_key)
  SSH_FSM_STATE("ssh_pm_st_ek_shutdown",
                "ssh pm st ek shutdown",
                ssh_pm_st_ek_shutdown)
  SSH_FSM_STATE("ssh_pm_st_ek_start",
                "ssh pm st ek start",
                ssh_pm_st_ek_start)
#endif /* SSHDIST_EXTERNALKEY */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
  SSH_FSM_STATE("ssh_pm_st_lns_session_add_arp_result",
                "ssh pm st lns session add arp result",
                ssh_pm_st_lns_session_add_arp_result)
  SSH_FSM_STATE("ssh_pm_st_lns_session_add_rule_result",
                "ssh pm st lns session add rule result",
                ssh_pm_st_lns_session_add_rule_result)
  SSH_FSM_STATE("ssh_pm_st_lns_session_alloc_attributes",
                "ssh pm st lns session alloc attributes",
                ssh_pm_st_lns_session_alloc_attributes)
  SSH_FSM_STATE("ssh_pm_st_lns_session_alloc_attributes_result",
                "ssh pm st lns session alloc attributes result",
                ssh_pm_st_lns_session_alloc_attributes_result)
  SSH_FSM_STATE("ssh_pm_st_lns_session_established",
                "ssh pm st lns session established",
                ssh_pm_st_lns_session_established)
  SSH_FSM_STATE("ssh_pm_st_lns_session_opened",
                "ssh pm st lns session opened",
                ssh_pm_st_lns_session_opened)
  SSH_FSM_STATE("ssh_pm_st_lns_session_terminate",
                "ssh pm st lns session terminate",
                ssh_pm_st_lns_session_terminate)
  SSH_FSM_STATE("ssh_pm_st_lns_session_terminate_delete_outbound_rule",
                "ssh pm st lns session terminate delete outbound rule",
                ssh_pm_st_lns_session_terminate_delete_outbound_rule)
  SSH_FSM_STATE("ssh_pm_st_lns_session_wait_ppp",
                "ssh pm st lns session wait ppp",
                ssh_pm_st_lns_session_wait_ppp)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request",
                "ssh pm st lns tunnel request",
                ssh_pm_st_lns_tunnel_request)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_aborted",
                "ssh pm st lns tunnel request aborted",
                ssh_pm_st_lns_tunnel_request_aborted)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_accept",
                "ssh pm st lns tunnel request accept",
                ssh_pm_st_lns_tunnel_request_accept)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_add_control_rule",
                "ssh pm st lns tunnel request add control rule",
                ssh_pm_st_lns_tunnel_request_add_control_rule)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_add_l2tp_control_rule_result",
                "ssh pm st lns tunnel request add l2tp control rule result",
                ssh_pm_st_lns_tunnel_request_add_l2tp_control_rule_result)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_get_rule_result",
                "ssh pm st lns tunnel request get rule result",
                ssh_pm_st_lns_tunnel_request_get_rule_result)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_out_of_resources",
                "ssh pm st lns tunnel request out of resources",
                ssh_pm_st_lns_tunnel_request_out_of_resources)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_reject",
                "ssh pm st lns tunnel request reject",
                ssh_pm_st_lns_tunnel_request_reject)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_route_result",
                "ssh pm st lns tunnel request route result",
                ssh_pm_st_lns_tunnel_request_route_result)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_terminate",
                "ssh pm st lns tunnel request terminate",
                ssh_pm_st_lns_tunnel_request_terminate)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_request_transform_result",
                "ssh pm st lns tunnel request transform result",
                ssh_pm_st_lns_tunnel_request_transform_result)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_terminate",
                "ssh pm st lns tunnel terminate",
                ssh_pm_st_lns_tunnel_terminate)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_terminate_delete_control",
                "ssh pm st lns tunnel terminate delete control",
                ssh_pm_st_lns_tunnel_terminate_delete_control)
  SSH_FSM_STATE("ssh_pm_st_lns_tunnel_terminate_delete_sa",
                "ssh pm st lns tunnel terminate delete sa",
                ssh_pm_st_lns_tunnel_terminate_delete_sa)
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  SSH_FSM_STATE("ssh_pm_st_main_cfgmode_rules",
                "ssh pm st main cfgmode rules",
                ssh_pm_st_main_cfgmode_rules)
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
  SSH_FSM_STATE("ssh_pm_st_main_auto_start",
                "ssh pm st main auto start",
                ssh_pm_st_main_auto_start)
  SSH_FSM_STATE("ssh_pm_st_main_batch",
                "ssh pm st main batch",
                ssh_pm_st_main_batch)
  SSH_FSM_STATE("ssh_pm_st_main_batch_abort",
                "ssh pm st main batch abort",
                ssh_pm_st_main_batch_abort)
  SSH_FSM_STATE("ssh_pm_st_main_batch_abort_delete",
                "ssh pm st main batch abort delete",
                ssh_pm_st_main_batch_abort_delete)
  SSH_FSM_STATE("ssh_pm_st_main_batch_abort_delete_rule",
                "ssh pm st main batch abort delete rule",
                ssh_pm_st_main_batch_abort_delete_rule)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition",
                "ssh pm st main batch addition",
                ssh_pm_st_main_batch_addition)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_result",
                "ssh pm st main batch addition result",
                ssh_pm_st_main_batch_addition_result)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_enforcement",
                "ssh pm st main batch addition enforcement",
                ssh_pm_st_main_batch_addition_enforcement)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_enforcement_result",
                "ssh pm st main batch addition enforcement result",
                ssh_pm_st_main_batch_addition_enforcement_result)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_create_ike_rule",
                "ssh pm st main batch addition create ike rule",
                ssh_pm_st_main_batch_addition_create_ike_rule)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_add_ike_trigger",
                "ssh pm st main batch addition add ike trigger",
                ssh_pm_st_main_batch_addition_add_ike_trigger)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_add_ike_trigger_result",
                "ssh pm st main batch addition add ike trigger result",
                ssh_pm_st_main_batch_addition_add_ike_trigger_result)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_create_ike_pass_rule",
                "ssh pm st main batch addition create ike pass rule",
                ssh_pm_st_main_batch_addition_create_ike_pass_rule)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_add_ike_pass_rule",
                "ssh pm st main batch addition add ike pass rule",
                ssh_pm_st_main_batch_addition_add_ike_pass_rule)
  SSH_FSM_STATE("ssh_pm_st_main_batch_addition_add_ike_pass_rule_result",
                "ssh pm st main batch addition add ike pass rule result",
                ssh_pm_st_main_batch_addition_add_ike_pass_rule_result)
  SSH_FSM_STATE("ssh_pm_st_main_batch_additions",
                "ssh pm st main batch additions",
                ssh_pm_st_main_batch_additions)
  SSH_FSM_STATE("ssh_pm_st_main_batch_sanity_check",
                "ssh pm st main batch sanity check",
                ssh_pm_st_main_batch_sanity_check)
  SSH_FSM_STATE("ssh_pm_st_main_batch_deletions",
                "ssh pm st main batch deletions",
                ssh_pm_st_main_batch_deletions)
  SSH_FSM_STATE("ssh_pm_st_main_batch_deletions_delete",
                "ssh pm st main batch deletions delete",
                ssh_pm_st_main_batch_deletions_delete)
  SSH_FSM_STATE("ssh_pm_st_main_batch_deletions_delete_rule",
                "ssh pm st main batch deletions delete rule",
                ssh_pm_st_main_batch_deletions_delete_rule)
  SSH_FSM_STATE("ssh_pm_st_main_batch_done_resume",
                "ssh pm st main batch done_resume",
                ssh_pm_st_main_batch_done_resume)
  SSH_FSM_STATE("ssh_pm_st_main_batch_done",
                "ssh pm st main batch done",
                ssh_pm_st_main_batch_done)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change",
                "ssh pm st main iface change",
                ssh_pm_st_main_iface_change)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_done",
                "ssh pm st main iface change done",
                ssh_pm_st_main_iface_change_done)
#ifdef SSHDIST_IPSEC_NAT
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_nat",
                "ssh pm st main iface change nat",
                ssh_pm_st_main_iface_change_nat)
#endif /* SSHDIST_IPSEC_NAT */
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_pending_iface",
                "ssh pm st main iface change pending iface",
                ssh_pm_st_main_iface_change_pending_iface)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule",
                "ssh pm st main iface change rule",
                ssh_pm_st_main_iface_change_rule)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_add",
                "ssh pm st main iface change rule add",
                ssh_pm_st_main_iface_change_rule_add)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_add_result",
                "ssh pm st main iface change rule add result",
                ssh_pm_st_main_iface_change_rule_add_result)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_delete",
                "ssh pm st main iface change rule delete",
                ssh_pm_st_main_iface_change_rule_delete)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_done",
                "ssh pm st main iface change rule done",
                ssh_pm_st_main_iface_change_rule_done)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_enforcement",
                "ssh pm st main iface change rule enforcement",
                ssh_pm_st_main_iface_change_rule_enforcement)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rule_enforcement_result",
                "ssh pm st main iface change rule enforcement result",
                ssh_pm_st_main_iface_change_rule_enforcement_result)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_rules",
                "ssh pm st main iface change rules",
                ssh_pm_st_main_iface_change_rules)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_servers",
                "ssh pm st main iface change servers",
                ssh_pm_st_main_iface_change_servers)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_update_tunnels",
                "ssh pm st main iface change update tunnels",
                ssh_pm_st_main_iface_change_update_tunnels)
  SSH_FSM_STATE("ssh_pm_st_main_iface_change_servers_check_done",
                "ssh pm st main iface change servers check done",
                ssh_pm_st_main_iface_change_servers_check_done)
  SSH_FSM_STATE("ssh_pm_st_main_initialize",
                "ssh pm st main initialize",
                ssh_pm_st_main_initialize)
  SSH_FSM_STATE("ssh_pm_st_main_run",
                "ssh pm st main run",
                ssh_pm_st_main_run)
  SSH_FSM_STATE("ssh_pm_st_main_send_random_salt",
                "ssh pm st main send random salt",
                ssh_pm_st_main_send_random_salt)
  SSH_FSM_STATE("ssh_pm_st_main_shutdown",
                "ssh pm st main shutdown",
                ssh_pm_st_main_shutdown)
  SSH_FSM_STATE("pm_shutdown_abort_ike_negotiations",
                "ssh pm st main shutdown abort ike negotiations",
                pm_shutdown_abort_ike_negotiations)
  SSH_FSM_STATE("pm_shutdown_wait_qm_termination",
                "ssh pm st main shutdown wait qm termination",
                pm_shutdown_wait_qm_termination)
  SSH_FSM_STATE("pm_shutdown_complete",
                "ssh pm st main shutdown complete",
                pm_shutdown_complete)
  SSH_FSM_STATE("pm_shutdown_delete_sas",
                "ssh pm st main shutdown delete sas",
                pm_shutdown_delete_sas)
  SSH_FSM_STATE("pm_shutdown_disconnect_engine",
                "ssh pm st main shutdown disconnect engine",
                pm_shutdown_disconnect_engine)
  SSH_FSM_STATE("pm_shutdown_ike_servers",
                "ssh pm st main shutdown ike servers",
                pm_shutdown_ike_servers)
  SSH_FSM_STATE("pm_shutdown_l2tp",
                "ssh pm st main shutdown l2tp",
                pm_shutdown_l2tp)
  SSH_FSM_STATE("pm_shutdown_l2tp_servers",
                "ssh pm st main shutdown l2tp servers",
                pm_shutdown_l2tp_servers)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_FSM_STATE("pm_shutdown_vip_tunnels",
                "ssh pm st main shutdown vip tunnels",
                pm_shutdown_vip_tunnels)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  SSH_FSM_STATE("pm_shutdown_stop_cm",
                "ssh pm st main shutdown stop cm",
                pm_shutdown_stop_cm)
  SSH_FSM_STATE("pm_shutdown_wait_ek_thread",
                "ssh pm st main shutdown wait ek thread",
                pm_shutdown_wait_ek_thread)
  SSH_FSM_STATE("pm_shutdown_wait_ike_shutdown",
                "ssh pm st main shutdown wait ike shutdown",
                pm_shutdown_wait_ike_shutdown)
  SSH_FSM_STATE("pm_shutdown_wait_sub_threads",
                "ssh pm st main shutdown wait sub threads",
                pm_shutdown_wait_sub_threads)
  SSH_FSM_STATE("ssh_pm_st_main_start",
                "ssh pm st main start",
                ssh_pm_st_main_start)
  SSH_FSM_STATE("ssh_pm_st_main_start_complete",
                "ssh pm st main start complete",
                ssh_pm_st_main_start_complete)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_FSM_STATE("ssh_pm_st_main_start_get_virtual_adapters",
                "ssh pm st main start get virtual adapters",
                ssh_pm_st_main_start_get_virtual_adapters)
  SSH_FSM_STATE("ssh_pm_st_main_start_get_virtual_adapters_result",
                "ssh pm st main start get virtual adapters result",
                ssh_pm_st_main_start_get_virtual_adapters_result)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  SSH_FSM_STATE("ssh_pm_st_main_start_default_rules",
                "ssh pm st main start default rules",
                ssh_pm_st_main_start_default_rules)
  SSH_FSM_STATE("ssh_pm_st_main_start_default_rules_add_result",
                "ssh pm st main start default rules add result",
                ssh_pm_st_main_start_default_rules_add_result)
  SSH_FSM_STATE("ssh_pm_st_main_start_wait_interfaces",
                "ssh pm st main start wait interfaces",
                ssh_pm_st_main_start_wait_interfaces)
  SSH_FSM_STATE("ssh_pm_st_p1_negotiation",
                "ssh pm st p1 negotiation",
                ssh_pm_st_p1_negotiation)
#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  SSH_FSM_STATE("ssh_pm_st_p1_negotiation_check_cfgmode",
                "ssh pm st p1 negotiation check cfgmode",
                ssh_pm_st_p1_negotiation_check_cfgmode)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */
#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_STATE("ssh_pm_st_p1_negotiation_tcp_encaps_check_natt",
                "ssh pm st p1 negotiation tcp encaps check natt",
                ssh_pm_st_p1_negotiation_tcp_encaps_check_natt)
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_STATE("ssh_pm_st_qm_i_add_rule_result",
                "ssh pm st qm i add rule result",
                ssh_pm_st_qm_i_add_rule_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_check_apply_rule",
                "ssh pm st qm i check apply rule",
                ssh_pm_st_qm_i_check_apply_rule)
  SSH_FSM_STATE("ssh_pm_st_qm_i_check_apply_rule_result",
                "ssh pm st qm i check apply rule result",
                ssh_pm_st_qm_i_check_apply_rule_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_auto_start",
                "ssh pm st qm i auto start",
                ssh_pm_st_qm_i_auto_start)
  SSH_FSM_STATE("ssh_pm_st_qm_i_failed",
                "ssh pm st qm i failed",
                ssh_pm_st_qm_i_failed)
  SSH_FSM_STATE("ssh_pm_st_qm_i_make_sa_rule",
                "ssh pm st qm i make sa rule",
                ssh_pm_st_qm_i_make_sa_rule)
  SSH_FSM_STATE("ssh_pm_st_qm_i_manual_sa_handler_result",
                "ssh pm st qm i manual sa handler result",
                ssh_pm_st_qm_i_manual_sa_handler_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_alloc_ike_sa",
                "ssh pm st qm i n alloc ike sa",
                ssh_pm_st_qm_i_n_alloc_ike_sa)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_check_initial_contact",
                "ssh pm st qm i n check initial contact",
                ssh_pm_st_qm_i_n_check_initial_contact)
#ifdef SSHDIST_IKEV1
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_do_info",
                "ssh pm st qm i n do info",
                ssh_pm_st_qm_i_n_do_info)
#endif /* SSHDIST_IKEV1 */
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_do_qm",
                "ssh pm st qm i n do qm",
                ssh_pm_st_qm_i_n_do_qm)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_failed",
                "ssh pm st qm i n failed",
                ssh_pm_st_qm_i_n_failed)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_find_ike_peer",
                "ssh pm st qm i n find ike peer",
                ssh_pm_st_qm_i_n_find_ike_peer)
#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_create_ike_mapping",
                "ssh pm st qm i n create ike mapping",
                ssh_pm_st_qm_i_n_create_ike_mapping)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_create_ike_mapping_result",
                "ssh pm st qm i n create ike mapping result",
                ssh_pm_st_qm_i_n_create_ike_mapping_result)
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_restart_qm",
                "ssh pm st qm i n restart qm",
                ssh_pm_st_qm_i_n_restart_qm)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_prepare_qm",
                "ssh pm st qm i n prepare qm",
                ssh_pm_st_qm_i_n_prepare_qm)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_qm_result",
                "ssh pm st qm i n qm result",
                ssh_pm_st_qm_i_n_qm_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_route_result",
                "ssh pm st qm i n route result",
                ssh_pm_st_qm_i_n_route_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_sa_handler_result",
                "ssh pm st qm i n sa handler result",
                ssh_pm_st_qm_i_n_sa_handler_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_select_p1",
                "ssh pm st qm i n select p1",
                ssh_pm_st_qm_i_n_select_p1)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_select_server",
                "ssh pm st qm i n select server",
                ssh_pm_st_qm_i_n_select_server)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_start",
                "ssh pm st qm i n start",
                ssh_pm_st_qm_i_n_start)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_success",
                "ssh pm st qm i n success",
                ssh_pm_st_qm_i_n_success)
  SSH_FSM_STATE("ssh_pm_st_qm_i_n_wait_p1",
                "ssh pm st qm i n wait p1",
                ssh_pm_st_qm_i_n_wait_p1)
  SSH_FSM_STATE("ssh_pm_st_qm_i_negotiation_done",
                "ssh pm st qm i negotiation done",
                ssh_pm_st_qm_i_negotiation_done)
  SSH_FSM_STATE("ssh_pm_st_qm_i_rekey",
                "ssh pm st qm i rekey",
                ssh_pm_st_qm_i_rekey)
  SSH_FSM_STATE("ssh_pm_st_qm_i_reprocess_trigger",
                "ssh pm st qm i reprocess trigger",
                ssh_pm_st_qm_i_reprocess_trigger)
  SSH_FSM_STATE("ssh_pm_st_qm_i_sa_lookup_result",
                "ssh pm st qm i sa lookup result",
                ssh_pm_st_qm_i_sa_lookup_result)
  SSH_FSM_STATE("ssh_pm_st_qm_i_start_negotiation",
                "ssh pm st qm i start negotiation",
                ssh_pm_st_qm_i_start_negotiation)
  SSH_FSM_STATE("ssh_pm_st_qm_i_success",
                "ssh pm st qm i success",
                ssh_pm_st_qm_i_success)
  SSH_FSM_STATE("ssh_pm_st_qm_i_trigger",
                "ssh pm st qm i trigger",
                ssh_pm_st_qm_i_trigger)
  SSH_FSM_STATE("ssh_pm_st_qm_terminate",
                "ssh pm st qm terminate",
                ssh_pm_st_qm_terminate)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_add_rule",
                "ssh pm st sa handler add rule",
                ssh_pm_st_sa_handler_add_rule)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_add_rule_result",
                "ssh pm st sa handler add rule result",
                ssh_pm_st_sa_handler_add_rule_result)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_create_ike_apply_rule",
                "ssh pm st sa handler create ike apply rule",
                ssh_pm_st_sa_handler_create_ike_apply_rule)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_add_ike_apply_rule",
                "ssh pm st sa handler add ike apply rule",
                ssh_pm_st_sa_handler_add_ike_apply_rule)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_add_ike_apply_rule_result",
                "ssh pm st sa handler add ike apply rule result",
                ssh_pm_st_sa_handler_add_ike_apply_rule_result)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_next_ike_apply_rule",
                "ssh pm st sa handler next ike apply rule",
                ssh_pm_st_sa_handler_next_ike_apply_rule)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_route",
                "ssh pm st sa handler route",
                ssh_pm_st_sa_handler_route)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_create_trd",
                "ssh pm st sa handler create trd",
                ssh_pm_st_sa_handler_create_trd)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_create_trd_result",
                "ssh pm st sa handler create trd result",
                ssh_pm_st_sa_handler_create_trd_result)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_failed",
                "ssh pm st sa handler failed",
                ssh_pm_st_sa_handler_failed)
#ifdef SSHDIST_IKEV1
  SSH_FSM_STATE("ssh_pm_st_sa_handler_check_v1_responder_rekey",
                "ssh pm st sa handler check v1 responder rekey",
                ssh_pm_st_sa_handler_check_v1_responder_rekey)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_check_v1_responder_rekey_result",
                "ssh pm st sa handler check v1 responder rekey result",
                ssh_pm_st_sa_handler_check_v1_responder_rekey_result)
#endif /* SSHDIST_IKEV1 */
  SSH_FSM_STATE("ssh_pm_st_sa_handler_rekey",
                "ssh pm st sa handler rekey",
                ssh_pm_st_sa_handler_rekey)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_rekey_result",
                "ssh pm st sa handler rekey result",
                ssh_pm_st_sa_handler_rekey_result)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_rekey_outbound",
                "ssh pm st sa handler rekey outbound",
                ssh_pm_st_sa_handler_rekey_outbound)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_start",
                "ssh pm st sa handler start",
                ssh_pm_st_sa_handler_start)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_register_outbound_spi",
                "ssh pm st sa handler register outbound spi",
                ssh_pm_st_sa_handler_register_outbound_spi)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_success",
                "ssh pm st sa handler success",
                ssh_pm_st_sa_handler_success)
  SSH_FSM_STATE("ssh_pm_st_sa_handler_terminate",
                "ssh pm st sa handler terminate",
                ssh_pm_st_sa_handler_terminate)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_FSM_STATE("ssh_pm_st_vip_start",
                "ssh pm st vip start",
                ssh_pm_st_vip_start)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_result",
                "ssh pm st vip get attrs result",
                ssh_pm_st_vip_get_attrs_result)
  SSH_FSM_STATE("ssh_pm_st_vip_select_addresses",
                "ssh pm st vip select addresses",
                ssh_pm_st_vip_select_addresses)
  SSH_FSM_STATE("ssh_pm_st_vip_get_sgw_route",
                "ssh pm st vip get sgw route",
                ssh_pm_st_vip_get_sgw_route)
  SSH_FSM_STATE("ssh_pm_st_vip_get_sgw_route_result",
                "ssh pm st vip get sgw route result",
                ssh_pm_st_vip_get_sgw_route_result)
  SSH_FSM_STATE("ssh_pm_st_vip_add_sgw_route",
                "ssh pm st vip add sgw route",
                ssh_pm_st_vip_add_sgw_route)
  SSH_FSM_STATE("ssh_pm_st_vip_add_sgw_route_result",
                "ssh pm st vip add sgw route result",
                ssh_pm_st_vip_add_sgw_route_result)
  SSH_FSM_STATE("ssh_pm_st_vip_configure_interface_up",
                "ssh pm st vip configure interface up",
                ssh_pm_st_vip_configure_interface_up)
  SSH_FSM_STATE("ssh_pm_st_vip_configure_interface_up_result",
                "ssh pm st vip configure interface up result",
                ssh_pm_st_vip_configure_interface_up_result)
  SSH_FSM_STATE("ssh_pm_st_vip_wait_interface_up",
                "ssh pm st vip wait interface up",
                ssh_pm_st_vip_wait_interface_up)
  SSH_FSM_STATE("ssh_pm_st_vip_create_routes",
                "ssh pm st vip create routes",
                ssh_pm_st_vip_create_routes)
  SSH_FSM_STATE("ssh_pm_st_vip_add_routes",
                "ssh pm st vip add routes",
                ssh_pm_st_vip_add_routes)
  SSH_FSM_STATE("ssh_pm_st_vip_add_routes_result",
                "ssh pm st vip add routes result",
                ssh_pm_st_vip_add_routes_result)
  SSH_FSM_STATE("ssh_pm_st_vip_add_name_servers",
                "ssh pm st vip add name servers",
                ssh_pm_st_vip_add_name_servers)
  SSH_FSM_STATE("ssh_pm_st_vip_add_name_servers_result",
                "ssh pm st vip add name servers result",
                ssh_pm_st_vip_add_name_servers_result)
  SSH_FSM_STATE("ssh_pm_st_vip_setup_tunnel",
                "ssh pm st vip setup tunnel",
                ssh_pm_st_vip_setup_tunnel)
  SSH_FSM_STATE("ssh_pm_st_vip_setup_tunnel_result",
                "ssh pm st vip setup tunnel result",
                ssh_pm_st_vip_setup_tunnel_result)
  SSH_FSM_STATE("ssh_pm_st_vip_register",
                "ssh pm st vip register",
                ssh_pm_st_vip_register)
  SSH_FSM_STATE("ssh_pm_st_vip_up",
                "ssh pm st vip up",
                ssh_pm_st_vip_up)
  SSH_FSM_STATE("ssh_pm_st_vip_setup_failed",
                "ssh pm st vip setup failed",
                ssh_pm_st_vip_setup_failed)
  SSH_FSM_STATE("ssh_pm_st_vip_established",
                "ssh pm st vip established",
                ssh_pm_st_vip_established)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown",
                "ssh pm st vip shutdown",
                ssh_pm_st_vip_shutdown)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_session_result",
                "ssh pm st vip shutdown session result",
                ssh_pm_st_vip_shutdown_session_result)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_name_servers",
                "ssh pm st vip shutdown name servers",
                ssh_pm_st_vip_shutdown_name_servers)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_name_servers_result",
                "ssh pm st vip shutdown name servers result",
                ssh_pm_st_vip_shutdown_name_servers_result)
  SSH_FSM_STATE("ssh_pm_st_vip_remove_routes",
                "ssh pm st vip remove routes",
                ssh_pm_st_vip_remove_routes)
  SSH_FSM_STATE("ssh_pm_st_vip_remove_routes_result",
                "ssh pm st vip remove routes result",
                ssh_pm_st_vip_remove_routes_result)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_configure_interface_down",
                "ssh pm st vip shutdown configure interface down",
                ssh_pm_st_vip_shutdown_configure_interface_down)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_configure_interface_down_result",
                "ssh pm st vip shutdown configure interface down result",
                ssh_pm_st_vip_shutdown_configure_interface_down_result)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_wait_interface_down",
                "ssh pm st vip shutdown wait interface down",
                ssh_pm_st_vip_shutdown_wait_interface_down)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_sgw_route",
                "ssh pm st vip shutdown sgw route",
                ssh_pm_st_vip_shutdown_sgw_route)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_sgw_route_result",
                "ssh pm st vip shutdown sgw route result",
                ssh_pm_st_vip_shutdown_sgw_route_result)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_wait_references",
                "ssh pm st vip shutdown wait references",
                ssh_pm_st_vip_shutdown_wait_references)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_complete",
                "ssh pm st vip shutdown complete",
                ssh_pm_st_vip_shutdown_complete)
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_cfgmode",
                "ssh pm st vip get attrs cfgmode",
                ssh_pm_st_vip_get_attrs_cfgmode)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_cfgmode_done",
                "ssh pm st vip get attrs cfgmode done",
                ssh_pm_st_vip_get_attrs_cfgmode_done)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_cfgmode_failed",
                "ssh pm st vip get attrs cfgmode failed",
                ssh_pm_st_vip_get_attrs_cfgmode_failed)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_cfgmode_wait_cfgmode",
                "ssh pm st vip get attrs cfgmode wait cfgmode",
                ssh_pm_st_vip_get_attrs_cfgmode_wait_cfgmode)
  SSH_FSM_STATE("ssh_pm_st_vip_qm_failed",
                "ssh pm st vip qm failed",
                ssh_pm_st_vip_qm_failed)
  SSH_FSM_STATE("ssh_pm_st_vip_qm_negotiation_done",
                "ssh pm st vip qm negotiation done",
                ssh_pm_st_vip_qm_negotiation_done)
  SSH_FSM_STATE("ssh_pm_st_vip_start_qm_negotiation",
                "ssh pm st vip start qm negotiation",
                ssh_pm_st_vip_start_qm_negotiation)
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#ifdef SSHDIST_L2TP
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp",
                "ssh pm st vip get attrs l2tp",
                ssh_pm_st_vip_get_attrs_l2tp)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_failed",
                "ssh pm st vip get attrs l2tp failed",
                ssh_pm_st_vip_get_attrs_l2tp_failed)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_failed_done",
                "ssh pm st vip get attrs l2tp failed done",
                ssh_pm_st_vip_get_attrs_l2tp_failed_done)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_next_peer",
                "ssh pm st vip get attrs l2tp next peer",
                ssh_pm_st_vip_get_attrs_l2tp_next_peer)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_query_authentication",
                "ssh pm st vip get attrs l2tp query authentication",
                ssh_pm_st_vip_get_attrs_l2tp_query_authentication)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_query_result",
                "ssh pm st vip get attrs l2tp query result",
                ssh_pm_st_vip_get_attrs_l2tp_query_result)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_route_result",
                "ssh pm st vip get attrs l2tp route result",
                ssh_pm_st_vip_get_attrs_l2tp_route_result)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_start",
                "ssh pm st vip get attrs l2tp start",
                ssh_pm_st_vip_get_attrs_l2tp_start)
  SSH_FSM_STATE("ssh_pm_st_vip_get_attrs_l2tp_wait_lac",
                "ssh pm st vip get attrs l2tp wait lac",
                ssh_pm_st_vip_get_attrs_l2tp_wait_lac)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_close_session",
                "ssh pm st vip l2tp lac close session",
                ssh_pm_st_vip_l2tp_lac_close_session)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_lookup_sa",
                "ssh pm st vip l2tp lac lookup sa",
                ssh_pm_st_vip_l2tp_lac_lookup_sa)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_lookup_sa_result",
                "ssh pm st vip l2tp lac lookup sa result",
                ssh_pm_st_vip_l2tp_lac_lookup_sa_result)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_start",
                "ssh pm st vip l2tp lac start",
                ssh_pm_st_vip_l2tp_lac_start)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_start_ppp",
                "ssh pm st vip l2tp lac start ppp",
                ssh_pm_st_vip_l2tp_lac_start_ppp)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_terminate",
                "ssh pm st vip l2tp lac terminate",
                ssh_pm_st_vip_l2tp_lac_terminate)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_wait_events",
                "ssh pm st vip l2tp lac wait events",
                ssh_pm_st_vip_l2tp_lac_wait_events)
  SSH_FSM_STATE("ssh_pm_st_vip_l2tp_lac_wait_open",
                "ssh pm st vip l2tp lac wait open",
                ssh_pm_st_vip_l2tp_lac_wait_open)
  SSH_FSM_STATE("ssh_pm_st_vip_setup_tunnel_l2tp",
                "ssh pm st vip setup tunnel l2tp",
                ssh_pm_st_vip_setup_tunnel_l2tp)
  SSH_FSM_STATE("ssh_pm_st_vip_setup_tunnel_l2tp_add_rule_result",
                "ssh pm st vip setup tunnel l2tp add rule result",
                ssh_pm_st_vip_setup_tunnel_l2tp_add_rule_result)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_session_l2tp",
                "ssh pm st vip shutdown session l2tp",
                ssh_pm_st_vip_shutdown_session_l2tp)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_session_l2tp_finish",
                "ssh pm st vip shutdown session l2tp finish",
                ssh_pm_st_vip_shutdown_session_l2tp_finish)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_cleanup_l2tp",
                "ssh pm st vip shutdown cleanup l2tp",
                ssh_pm_st_vip_shutdown_cleanup_l2tp)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_cleanup_l2tp_delete_sa_rule",
                "ssh pm st vip shutdown cleanup l2tp delete sa rule",
                ssh_pm_st_vip_shutdown_cleanup_l2tp_delete_sa_rule)
  SSH_FSM_STATE("ssh_pm_st_vip_shutdown_cleanup_l2tp_finish",
                "ssh pm st vip shutdown cleanup l2tp finish",
                ssh_pm_st_vip_shutdown_cleanup_l2tp_finish)
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#ifdef SSHDIST_IPSEC_MOBIKE
  SSH_FSM_STATE("ssh_pm_st_mobike_i_start",
                "ssh pm st mobike i start",
                ssh_pm_st_mobike_i_start)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_address_update",
                "ssh pm st mobike i address update",
                ssh_pm_st_mobike_i_address_update)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_address_update_result",
                "ssh pm st mobike i address update result",
                ssh_pm_st_mobike_i_address_update_result)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_update_ike_sa",
                "ssh pm st mobike i update ike sa",
                ssh_pm_st_mobike_i_update_ike_sa)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_update_ipsec_sa",
                "ssh pm st mobike i update ipsec sa",
                ssh_pm_st_mobike_i_update_ipsec_sa)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_update_ipsec_sa_result",
                "ssh pm st mobike i update ipsec sa result",
                ssh_pm_st_mobike_i_update_ipsec_sa_result)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_success",
                "ssh pm st mobike i success",
                ssh_pm_st_mobike_i_success)
  SSH_FSM_STATE("ssh_pm_st_mobike_i_failed",
                "ssh pm st mobike i failed",
                ssh_pm_st_mobike_i_failed)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_start",
                "ssh pm st mobike r start",
                ssh_pm_st_mobike_r_start)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_update_ike_sa",
                "ssh pm st mobike r update ike sa",
                ssh_pm_st_mobike_r_update_ike_sa)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_check_rrc",
                "ssh pm st mobike r check rrc",
                ssh_pm_st_mobike_r_check_rrc)
#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_STATE("ssh_pm_st_mobike_r_get_ike_mapping",
                "ssh pm st mobike r get ike mapping",
                ssh_pm_st_mobike_r_get_ike_mapping)
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_STATE("ssh_pm_st_mobike_r_pre_rrc",
                "ssh pm st mobike r pre rrc",
                ssh_pm_st_mobike_r_pre_rrc)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_pre_rrc_result",
                "ssh pm st mobike r pre rrc result",
                ssh_pm_st_mobike_r_pre_rrc_result)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_update_ipsec_sa",
                "ssh pm st mobike r update ipsec sa",
                ssh_pm_st_mobike_r_update_ipsec_sa)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_update_ipsec_sa_result",
                "ssh pm st mobike r update ipsec sa result",
                ssh_pm_st_mobike_r_update_ipsec_sa_result)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_post_rrc",
                "ssh pm st mobike r post rrc",
                ssh_pm_st_mobike_r_post_rrc)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_post_rrc_result",
                "ssh pm st mobike r post rrc result",
                ssh_pm_st_mobike_r_post_rrc_result)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_success",
                "ssh pm st mobike r success",
                ssh_pm_st_mobike_r_success)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_failed",
                "ssh pm st mobike r failed",
                ssh_pm_st_mobike_r_failed)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_route_remote",
                "ssh pm st mobike r route remote",
                ssh_pm_st_mobike_r_route_remote)
  SSH_FSM_STATE("ssh_pm_st_mobike_r_route_remote_result",
                "ssh pm st mobike r route remote result",
                ssh_pm_st_mobike_r_route_remote_result)
#endif /* SSHDIST_IPSEC_MOBIKE */
  SSH_FSM_STATE("ssh_pm_st_ike_spd_select_ike_sa_start",
                "ssh pm st ike spd select ike sa start",
                ssh_pm_st_ike_spd_select_ike_sa_start)
#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_STATE("ssh_pm_st_ike_spd_select_ike_sa_get_ike_mapping",
                "ssh pm st ike spd select ike sa get ike mapping",
                ssh_pm_st_ike_spd_select_ike_sa_get_ike_mapping)
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_STATE("ssh_pm_st_ike_spd_select_ike_sa",
                "ssh pm st ike spd select ike sa",
                ssh_pm_st_ike_spd_select_ike_sa)
  SSH_FSM_STATE("ssh_pm_st_ike_spd_select_ipsec_sa_fetch_trd",
                "ssh pm st ike spd select ipsec sa fetch trd",
                ssh_pm_st_ike_spd_select_ipsec_sa_fetch_trd)
  SSH_FSM_STATE("ssh_pm_st_ike_spd_select_ipsec_sa",
                "ssh pm st ike spd select ipsec sa",
                ssh_pm_st_ike_spd_select_ipsec_sa)
};

const int ssh_pm_fsm_names_count =
SSH_FSM_NUM_STATES(ssh_pm_fsm_names);
#endif /* DEBUG_LIGHT */
