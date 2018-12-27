/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Handling various servers.  IKE (and some other protocols like L2TP)
   require a server per IP address in the system.  This file handles
   initializing the servers and starting and stopping the servers
   dynamically when the interface information changes.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmServers"

/* The time in seconds for which to wait after an interface disappears
   before deleting the servers attached to that interface. This value
   is large enough so that IKE SA's on the server can be migrated to a
   new server (where possible) without destroying the IKE SA. The need for
   this arises when there is a single interface which goes down and does not
   come up again for a short time. */
#define SSH_PM_DELETE_SERVER_TIMEOUT 300

/************************** Forward declarations ***************************/
static void pm_ike_servers_stop_enumerate_next(void *context);
static void pm_servers_iface_change_remove_l2tp_servers(SshPm pm);
static void pm_servers_iface_change_remove_ike_servers(SshPm pm);
static void pm_servers_delete_timeout_cb(void *context);

/************************** Static help functions ***************************/

/* Free the server object `server'. */
static void
pm_server_free(SshPmServer server)
{
  SSH_ASSERT(server != NULL);

  /* Free the server object. */
  ssh_free(server->ike_servers);
  ssh_free(server);
}


/*************************** ADT bag for servers ****************************/

static SshUInt32
pm_server_hash(void *ptr, void *ctx)
{
  SshPmServer server = (SshPmServer) ptr;

  return SSH_IP_HASH(&server->address);
}


static int
pm_server_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmServer server1 = (SshPmServer) ptr1;
  SshPmServer server2 = (SshPmServer) ptr2;

#ifdef WITH_IPV6
#ifndef SSH_IPSEC_LINK_LOCAL_SERVERS
  /* This server should not be on a link-local IPv6 addresses. */
  SSH_ASSERT(SSH_IP6_IS_LINK_LOCAL(&server1->address) == FALSE);
#endif /* SSH_IPSEC_LINK_LOCAL_SERVERS */
#endif /* WITH_IPV6 */

  if (!SSH_IP_EQUAL(&server1->address, &server2->address))
    return -1;

  if (server1->routing_instance_id != server2->routing_instance_id)
    return -1;

  if (server1->ifnum == SSH_INVALID_IFNUM ||
      server2->ifnum == SSH_INVALID_IFNUM)
    return 0;

  if (server1->ifnum != server2->ifnum)
    return -1;

#if defined(WITH_IPV6)
  if (SSH_IP_IS6(&server1->address))
    {
      if (SSH_IP6_SCOPE_ID(&server1->address) !=
          SSH_IP6_SCOPE_ID(&server2->address))
        return -1;
    }
#endif /* WITH_IPV6 */

  return 0;
}

static void
pm_server_destroy(void *ptr, void *ctx)
{
  pm_server_free((SshPmServer) ptr);
}


/**************** Public functions to manipulate IKE servers ****************/

Boolean
ssh_pm_servers_init(SshPm pm)
{
  pm->servers
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmServerStruct,
                                               adt_header),

                             SSH_ADT_HASH,      pm_server_hash,
                             SSH_ADT_COMPARE,   pm_server_compare,
                             SSH_ADT_DESTROY,   pm_server_destroy,
                             SSH_ADT_CONTEXT,   pm,

                             SSH_ADT_ARGS_END);
  if (pm->servers == NULL)
    return FALSE;

  return TRUE;
}


void
ssh_pm_servers_uninit(SshPm pm)
{
  if (pm->servers)
    {
      ssh_adt_destroy(pm->servers);
      pm->servers = NULL;
    }
}

/************************ Stopping servers *****************************/

#ifdef WITH_IKE
static void
pm_ike_server_stop_enumerate_next_cb(SshIkev2Error error, void *context)
{
  SshPm pm = (SshPm) context;

  SSH_DEBUG(SSH_D_MIDOK, ("Server stopped with error status %d", error));

  /* Continue enumerating through all servers. */
  pm_ike_servers_stop_enumerate_next(pm);
}
#endif /* WITH_IKE */

static void pm_ike_servers_stop_enumerate_next(void *context)
{
  SshPm pm = (SshPm) context;
#ifdef WITH_IKE
  SshADTHandle h;
#endif /* WITH_IKE */

  SSH_DEBUG(SSH_D_LOWOK, ("IKE servers stop enumerate next entered"));

#ifdef WITH_IKE
  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->servers, h))
    {
      SshPmServer server = ssh_adt_get(pm->servers, h);
      SshIkev2Server ike_server;

      if (server->num_ike_servers <= 0)
        continue;

      server->num_ike_servers--;
      ike_server = server->ike_servers[server->num_ike_servers];
      server->ike_servers[server->num_ike_servers] = NULL;

      /* Stop this server. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Stopping IKE server on  addr %@, routing instance id %d "
                 "local ports %d:%d, remote ports %d:%d",
                 ssh_ipaddr_render, ike_server->ip_address,
                 ike_server->routing_instance_id,
                 (int)ike_server->normal_local_port,
                 (int)ike_server->nat_t_local_port,
                 (int)ike_server->normal_remote_port,
                 (int)ike_server->nat_t_remote_port));

      ssh_ikev2_server_stop(ike_server, 0,
                            pm_ike_server_stop_enumerate_next_cb,
                            pm);
      return;
    }
#endif /* WITH_IKE */

  SSH_DEBUG(SSH_D_LOWOK, ("All IKE servers stopped"));


  /* We have stopped all servers, call the done callback. */
  (*pm->servers_stop_done_cb)(pm->servers_stop_done_cb_context);
  return;
}


void
ssh_pm_servers_stop(SshPm pm, SshUInt32 flags,
                    SshPmServersStopDoneCB callback, void *context)
{
#ifdef SSHDIST_L2TP
  SshADTHandle h;
#endif /* SSHDIST_L2TP */

  SSH_ASSERT(pm->servers != NULL);

#ifdef SSHDIST_L2TP
  /* First consider shutdown of all L2TP servers which is synchronous. */
  if (flags & SSH_PM_SERVER_L2TP)
    {
      for (h = ssh_adt_enumerate_start(pm->servers);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(pm->servers, h))
        {
          SshPmServer server = ssh_adt_get(pm->servers, h);

          if (server->l2tp_server)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Stopping L2TP server at %@",
                                      ssh_ipaddr_render, &server->address));
              ssh_l2tp_server_stop(server->l2tp_server);
              server->l2tp_server = NULL;
            }
        }
    }
#endif /* SSHDIST_L2TP */

  /* If we are shutting down IKE servers, since this operation is
     asynchronous, save the callback and context data. */
  if (flags & SSH_PM_SERVER_IKE)
    {
      pm->servers_stop_done_cb = callback;
      pm->servers_stop_done_cb_context = context;
      pm->servers_stop_flags = flags;

      /* Begin shutdown of all IKE servers. */
      pm_ike_servers_stop_enumerate_next(pm);
    }
  else
    {
      /* We have stopped all servers, call the done callback. */
      (*callback)(context);
      return;
    }
}


void
ssh_pm_servers_interface_change(SshPm pm,
                                SshPmServersIfaceChangeDoneCB callback,
                                void *context)
{
  SshUInt32 ifnum;
  SshADTHandle h, hnext;
  SshPmServer server;
  Boolean success = TRUE;
  Boolean retval;
  long delete_timeout = 0;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  Boolean vip = FALSE;
#else  /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#ifdef SSHDIST_L2TP
  Boolean vip = FALSE;
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  SSH_DEBUG(SSH_D_MIDOK, ("Server interface change called"));

  /* Update servers to match our local IP addresses. */
  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      SshUInt32 i;
#ifdef WITH_IKE
      SshUInt32 j, k;
#endif /* WITH_IKE */
      SshInterceptorInterface *ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);

      if (ifp == NULL)
        continue;

      SSH_DEBUG(SSH_D_MIDOK, ("Considering servers on interface %d",
                              (int) ifnum));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* Do not start some servers on virtual interfaces. */
      if (ssh_pm_virtual_adapter_find_byifnum(pm, ifnum) != NULL)
        vip = TRUE;
      else
        vip = FALSE;

      SSH_DEBUG(SSH_D_MIDOK, ("Server %p interface=%d%s, num_addrs=%d",
                              ifp, (int) ifnum, (vip ? " [vip]" : ""),
                              (int) ifp->num_addrs));
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      SSH_DEBUG(SSH_D_MIDOK, ("Server %p interface=%d, num_addrs=%d",
                              ifp, (int) ifnum, (int) ifp->num_addrs));
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      for (i = 0; i < ifp->num_addrs; i++)
        {
          SshInterfaceAddress addr = &ifp->addrs[i];
          SshPmServerStruct server_struct;
          Boolean found;
          Boolean restart = FALSE;

          if (addr->protocol != SSH_PROTOCOL_IP4
              && addr->protocol != SSH_PROTOCOL_IP6)
            /* We are only interested in IP addresses. */
            continue;

#if defined (WITH_IPV6)
          /* No need to check IPv6 addresses. */
#else /* WITH_IPV6 */
          /* Do not start servers on IPv6 addresses. */
          if (addr->protocol == SSH_PROTOCOL_IP6)
            continue;
#endif /* WITH_IPV6 */

          found = FALSE;

#ifdef WITH_IKE
          for (j = 0; j < pm->params.ike_addrs_count; j++)
            {
              if (SSH_IP_DEFINED(&pm->params.ike_addrs[j]))
                {
                  if (SSH_IP_EQUAL(&pm->params.ike_addrs[j],
                                   &addr->addr.ip.ip) == FALSE)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("ignoring interface %@",
                                 ssh_ipaddr_render, &addr->addr.ip.ip));
                    }
                  else
                    {
                      found = TRUE;
                      break;
                    }
                }
            }

          if (!found && pm->params.ike_addrs_count > 0)
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Ignoring server address %@ on "
                                      "ifnum=%d as it not an IKE listening "
                                      "address", ssh_ipaddr_render,
                                      &addr->addr.ip.ip, (int) ifnum));
              continue;
            }
#endif /* WITH_IKE */

          /* Do we already have server object for this address? */
          server_struct.address = addr->addr.ip.ip;
          /* We do not utilize the interface number in the lookups. */
          server_struct.ifnum = SSH_INVALID_IFNUM;
          /* Routing instance id needs to match, not just IP */
          server_struct.routing_instance_id = ifp->routing_instance_id;

          h = ssh_adt_get_handle_to_equal(pm->servers, &server_struct);
          if (h != SSH_ADT_INVALID)
            {
              /* The server object already exists.  Let's mark it
                 valid. */
              server = ssh_adt_get(pm->servers, h);
              SSH_ASSERT(server != NULL);

              SSH_DEBUG(SSH_D_MIDOK, ("Server already exists on address %@. "
                                      "Marking server valid",
                                      ssh_ipaddr_render,
                                      &addr->addr.ip.ip));

              /* If server was previously marked to be deleted,
                 then attempt to restart servers. */
              if (server->delete_time)
                restart = TRUE;

              server->valid = 1;
            }
          else
            {
#ifdef VXWORKS
              if (addr->protocol == SSH_PROTOCOL_IP6 &&
                  SSH_IP6_BYTE13(&addr->addr.ip.ip) == 0 &&
                  SSH_IP6_BYTE14(&addr->addr.ip.ip) == 0 &&
                  SSH_IP6_BYTE15(&addr->addr.ip.ip) == 0 &&
                  SSH_IP6_BYTE16(&addr->addr.ip.ip) == 0)
                {
                  SSH_DEBUG(SSH_D_HIGHOK,
                            ("VxWorks; ignoring address %@ due to platform "
                             "reporting it incorrectly as local.",
                             ssh_ipaddr_render, &addr->addr.ip.ip));
                  continue;
                }

#endif /* VXWORKS */
#ifndef SSH_IPSEC_LINK_LOCAL_SERVERS
              if (SSH_IP6_IS_LINK_LOCAL(&addr->addr.ip.ip))
                {
                  SSH_DEBUG(SSH_D_HIGHOK,
                            ("Link local address %@ ignored when creating "
                             "IKE server",
                             ssh_ipaddr_render, &addr->addr.ip.ip));
                  continue;
                }
#endif /* SSH_IPSEC_LINK_LOCAL_SERVERS */

              SSH_DEBUG(SSH_D_LOWSTART,
                        ("Creating server object at address `%@'",
                         ssh_ipaddr_render, &addr->addr.ip.ip));

              server = ssh_calloc(1, sizeof(*server));
              if (server == NULL)
                {
                  SSH_DEBUG(SSH_D_ERROR, ("Could not allocate server object"));
                  continue;
                }

              server->pm = pm;
              server->valid = 1;
              server->address = addr->addr.ip.ip;
              server->ifnum = ifnum;
              server->routing_instance_id = ifp->routing_instance_id;
#ifdef WITH_IPV6
              if (SSH_IP_IS6(&server->address))
                server->iface_mtu = ifp->to_adapter.mtu_ipv6;
              else
#endif /* WITH_IPV6 */
                server->iface_mtu = ifp->to_adapter.mtu_ipv4;

              /* Add it to our server bag. */
              ssh_adt_insert(pm->servers, server);
            }

#ifdef WITH_IKE
          if (server->ike_servers == NULL)
            {
              SSH_DEBUG(SSH_D_LOWSTART, ("IKE `%@'",
                                         ssh_ipaddr_render, &server->address));

              if ((server->ike_servers =
                   ssh_calloc(pm->params.num_ike_ports,
                              sizeof(server->ike_servers[0])))
                  == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Could not start IKE server `%@': out of memory",
                             ssh_ipaddr_render, &server->address));
                  (*callback)(pm, FALSE, context);
                  return;
                }
            }

          for (k = 0; k < pm->params.num_ike_ports; k++)
            {
              if (server->ike_servers[k] == NULL)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Starting IKE server on addr %@, "
                             "routing instance id %d "
                             "local ports %d:%d remote ports %d:%d",
                             ssh_ipaddr_render, &server->address,
                             server->routing_instance_id,
                             (int)pm->params.local_ike_ports[k],
                             (int)pm->params.local_ike_natt_ports[k],
                             (int)pm->params.remote_ike_ports[k],
                             (int)pm->params.remote_ike_natt_ports[k]));

                  server->ike_servers[k] =
                    ssh_ikev2_server_start(pm->ike_context,
                                           &server->address,
                                           pm->params.local_ike_ports[k],
                                           pm->params.local_ike_natt_ports[k],
                                           pm->params.remote_ike_ports[k],
                                           pm->params.remote_ike_natt_ports[k],
                                           -1,
                                           server->routing_instance_id,
                                           pm->sad_interface,
                                           pm->sad_handle);

                  if (server->ike_servers[k] == NULL)
                    {
                      ssh_warning("Could not start IKE server `%@'",
                                  ssh_ipaddr_render, &server->address);
                      success = FALSE;
                    }
                  else
                    {
                      server->num_ike_servers++;
                    }
                }
              else if (restart)
                {
                  /* IKE server restart is needed because we need to make sure
                     that the UDP listeners are fully functional.

                     Whenever an IPv6 address reappears, the UDP listener is
                     not able receive any packets while the IPv6 address is
                     in tentative state.

                     Thus we close the UDP listeners and attempt to reopen
                     them. If the restart succeeds, then the UDP listener is
                     fully functional and we can continue with other tasks
                     (MobIKE address update). If restart fails, we retry later.
                  */

                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Restarting IKE server on addr %@, "
                             "routing instance id %d"
                             "local ports %d:%d remote ports %d:%d",
                             ssh_ipaddr_render, &server->address,
                             server->routing_instance_id,
                             (int)pm->params.local_ike_ports[k],
                             (int)pm->params.local_ike_natt_ports[k],
                             (int)pm->params.remote_ike_ports[k],
                             (int)pm->params.remote_ike_natt_ports[k]));

                  if (!ssh_ikev2_server_restart(server->ike_servers[k], -1))
                    {
                      ssh_warning("Could not restart IKE server `%@'",
                                  ssh_ipaddr_render, &server->address);

                      /* Mark server invalid and attempt restart later. */
                      server->valid = 0;
                      success = FALSE;
                    }









                  /* Update the server interface number in case it has
                     changed. */
                  if (ifnum != server->ifnum)
                    server->ifnum = ifnum;
                }
            }

          if (server->num_ike_servers !=  pm->params.num_ike_ports)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Could not start all IKE servers on `%@'",
                         ssh_ipaddr_render, &server->address));
              success = FALSE;
            }
#endif /* WITH_IKE */

#ifdef SSHDIST_L2TP
          /* Do not start l2tp servers on virtual interfaces. */
          if (vip == FALSE && server->l2tp_server == NULL)
            {
              SSH_DEBUG(SSH_D_LOWSTART, ("L2TP `%@'",
                                         ssh_ipaddr_render, &server->address));




              server->l2tp_server =
                ssh_l2tp_server_start_ip(pm->l2tp,
                                         &server->address,
                                         SSH_IPSEC_L2TP_PORT,
                                         -1,
                                         server->routing_instance_id);

              if (server->l2tp_server == NULL)
                {
                  ssh_warning("Could not start L2TP server `%@'",
                              ssh_ipaddr_render, &server->address);
                  success = FALSE;
                }

            }
#endif /* SSHDIST_L2TP */
        }
    }

  if (success == FALSE)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Servers were restarted after interface change "
                               "with status FAILURE"));
      (*callback)(pm, FALSE, context);
      return;
    }

  /* Save callback data */
  pm->server_iface_change_done_cb = callback;
  pm->server_iface_change_done_cb_context = context;

  /* Clear the valid flag on all servers that are still alive. */
  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      hnext = ssh_adt_enumerate_next(pm->servers, h);

      server = ssh_adt_get(pm->servers, h);
      SSH_ASSERT(server != NULL);

      if (server->valid)
        {
          server->valid = 0;
          if (server->delete_time)
            {
              server->delete_time = 0;
              SSH_DEBUG(SSH_D_HIGHOK, ("Cancelling delete on "
                                       "server %p at %@", server,
                                       ssh_ipaddr_render, &server->address));
            }
        }
      else if (!server->delete_time)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Scheduling server %p on %@ for deletion ",
                                   server, ssh_ipaddr_render,
                                   &server->address));
          server->delete_time = ssh_time() + SSH_PM_DELETE_SERVER_TIMEOUT;
          delete_timeout = SSH_PM_DELETE_SERVER_TIMEOUT;
        }
      else
        {
          SshTime remaining_time = server->delete_time - ssh_time();
          if (remaining_time <= 0)
            server->delete_pending = 1;
          else if (delete_timeout == 0 || remaining_time < delete_timeout)
            delete_timeout = (long)remaining_time;
        }
    }

  /* Register server delete timeout. */
  if (delete_timeout && !pm->delete_server_timeout_registered)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Registering the delete server timeout to %d",
                               delete_timeout));
      pm->delete_server_timeout_registered = TRUE;
      ssh_register_timeout(&pm->delete_server_timer,
                           delete_timeout, 0,
                           pm_servers_delete_timeout_cb, pm);
    }

  /* No servers to be deleted, cancel server delete timeout. */
  else if (delete_timeout == 0 && pm->delete_server_timeout_registered)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Cancelling the delete server timeout"));
      pm->delete_server_timeout_registered = FALSE;
      ssh_cancel_timeout(&pm->delete_server_timer);
    }

  /* Delete expired servers. */
  pm_servers_iface_change_remove_l2tp_servers(pm);
}



static void pm_servers_delete_timeout_cb(void *context)
{
  SshPm pm = (SshPm)context;

  pm->delete_server_timeout_registered = FALSE;

  SSH_DEBUG(SSH_D_MIDOK, ("Signalling interface change to expire servers"));
  pm->iface_change = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
}

static void pm_servers_iface_change_remove_l2tp_servers(SshPm pm)
{
#ifdef SSHDIST_L2TP
  SshADTHandle h, hnext;
  SshPmServer server;

  /* Destroy L2TP servers which are not active anymore. */
  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      hnext = ssh_adt_enumerate_next(pm->servers, h);

      server = ssh_adt_get(pm->servers, h);
      SSH_ASSERT(server != NULL);

      if (!server->delete_pending)
          continue;

      if (server->l2tp_server)
        {
          SSH_DEBUG(SSH_D_LOWSTART, ("Stopping L2TP server on `%@' ifnum %d",
                                     ssh_ipaddr_render, &server->address,
                                     server->ifnum));

          ssh_l2tp_server_stop(server->l2tp_server);
          server->l2tp_server = NULL;
        }
    }
#endif /* SSHDIST_L2TP */

  /* Remove IKE servers which are no longer active */
  pm_servers_iface_change_remove_ike_servers(pm);
}

#ifdef WITH_IKE
static void
pm_servers_iface_change_remove_ike_cb(SshIkev2Error error,
                                      void *context)
{
  SshPm pm = (SshPm) context;

  SSH_DEBUG(SSH_D_MIDOK, ("Server stopped with error status %d", error));

  /* Continue enumerating through all IKE servers. */
  pm_servers_iface_change_remove_ike_servers(pm);
  return;
}
#endif /* WITH_IKE */

static void pm_servers_iface_change_remove_ike_servers(SshPm pm)
{
  SshADTHandle h, hnext;
  SshPmServer server;

  /* Destroy IKE servers which are not active anymore. */
  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      hnext = ssh_adt_enumerate_next(pm->servers, h);

      server = ssh_adt_get(pm->servers, h);
      SSH_ASSERT(server != NULL);

      if (!server->delete_pending)
        continue;

#ifdef WITH_IKE
      if (server->num_ike_servers > 0)
        {
          SshIkev2Server ike_server;

          server->num_ike_servers--;
          ike_server = server->ike_servers[server->num_ike_servers];
          server->ike_servers[server->num_ike_servers] = NULL;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Stopping IKE server on  addr %@, "
                     "routing instance id %d"
                     "local ports %d:%d, remote ports %d:%d",
                     ssh_ipaddr_render, ike_server->ip_address,
                     ike_server->routing_instance_id,
                     (int)ike_server->normal_local_port,
                     (int)ike_server->nat_t_local_port,
                     (int)ike_server->normal_remote_port,
                     (int)ike_server->nat_t_remote_port));

          ssh_ikev2_server_stop(ike_server, 0,
                                pm_servers_iface_change_remove_ike_cb,
                                pm);

          /* Remove parentless IPsec SAs from engine. This deletes both
             parentless IKEv1 keyed IPsec SAs and manually keyed IPsec SAs
             that use ike_server->ip_address as the local address. */
          ssh_pm_delete_by_local_address(pm, ike_server->ip_address,
                                         ike_server->routing_instance_id);

          return;
        }
#endif /* WITH_IKE */


      ssh_free(server->ike_servers);
      server->ike_servers = NULL;
      server->num_ike_servers = 0;

      /* Remove our reference from the server object. */
      ssh_adt_delete(pm->servers, h);
    }

  /* At this point all inactive servers have been stopped. */
  SSH_DEBUG(SSH_D_HIGHOK, ("Expired servers stopped"));
  (pm->server_iface_change_done_cb)(pm, TRUE,
                                    pm->server_iface_change_done_cb_context);
  return;
}

SshPmServer
ssh_pm_servers_select(SshPm pm, SshIpAddr local_addr,
                      SshUInt32 flags,
                      SshIkev2Server ike_server,
                      SshUInt32 ifnum,
                      int routing_instance_id)
{
  SshPmServerStruct server_struct;
  SshPmServer server;
  SshADTHandle h = SSH_ADT_INVALID;

  SSH_ASSERT(local_addr != NULL);

#ifdef WITH_IPV6
#ifndef SSH_IPSEC_LINK_LOCAL_SERVERS
  if (SSH_IP6_IS_LINK_LOCAL(local_addr))
    return NULL;
#endif /* SSH_IPSEC_LINK_LOCAL_SERVERS */
#endif /* WITH_IPV6 */

  server_struct.address = *local_addr;
  if (flags & SSH_PM_SERVERS_MATCH_IFNUM)
    server_struct.ifnum = ifnum;
  else
    server_struct.ifnum = SSH_INVALID_IFNUM;

  server_struct.routing_instance_id = routing_instance_id;

  h = ssh_adt_get_handle_to_equal(pm->servers, &server_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No servers running on `%@'",
                             ssh_ipaddr_render, local_addr));
      return NULL;
    }

  server = ssh_adt_get(pm->servers, h);
  SSH_ASSERT(server != NULL);

  if (server->delete_time)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Server %p running on `%@' is pending deletion "
                             "and cannot be used", server,
                             ssh_ipaddr_render, local_addr));
      return NULL;
    }

  /* Check the IKE server match criteria. */
  if (flags & SSH_PM_SERVERS_MATCH_IKE_SERVER)
    {
      int i;

      for (i = 0; i < server->num_ike_servers; i++)
        {
          if (server->ike_servers[i] == ike_server)
            break;
        }
      if (i == server->num_ike_servers)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("IKE server does not match the select criteria"));
          return NULL;
        }
    }
  return server;
}

SshIkev2Server
ssh_pm_servers_select_ike(SshPm pm,
                          SshIpAddr local_addr,
                          SshUInt32 flags,
                          SshUInt32 ifnum,
                          SshUInt16 port,
                          int routing_instance_id)
{
  SshPmServer server;
  SshUInt32 i = 0;

  server = ssh_pm_servers_select(pm, local_addr, flags, NULL,
                                 ifnum, routing_instance_id);

  if (server != NULL)
    {
      /* Check the IKE port match criteria. */
      if (flags & SSH_PM_SERVERS_MATCH_PORT)
        {
          for (i = 0; i < server->num_ike_servers; i++)
            {
              if (!server->ike_servers[i])
                continue;

              if (server->ike_servers[i]->normal_local_port == port)
                break;

              if (server->ike_servers[i]->nat_t_local_port == port)
                break;
            }

          if (i == server->num_ike_servers)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("IKE port does not match the select criteria"));
              return NULL;
            }
        }

      return server->ike_servers[i];
    }

  return NULL;
}


#ifdef SSHDIST_L2TP
SshPmServer
ssh_pm_servers_select_by_l2tp_server(SshPm pm, SshL2tpServer l2tp_server)
{
  SshADTHandle h;
  SshPmServer server = NULL;

  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->servers, h))
    {
      server = ssh_adt_get(pm->servers, h);

      if (server->l2tp_server == l2tp_server)
        /* Found it. */
        break;
    }
  return server;
}
#endif /* SSHDIST_L2TP */

Boolean
ssh_pm_foreach_ike_server(SshPm pm, SshPmIkeServerCB callback, void *context)
{
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(pm->servers);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->servers, h))
    {
      SshPmServer server = ssh_adt_get(pm->servers, h);

      if (server->ike_servers)
        {
          int i;

          for (i = 0; i < server->num_ike_servers; i++)
            {
              if (!server->ike_servers[i])
                continue;

              if (!(*callback)(pm,
                               server->ike_servers[i],
                               context))
                return FALSE;
            }
        }
    }

  return TRUE;
}

Boolean ssh_pm_ike_foreach_ike_sa(SshPm pm, SshIkev2Server server,
                                  SshPmIkeServerSaCB callback,
                                  void *context)
{
  SshPmIkeSaStatsStruct stats;
  SshPmAuthDataStruct auth;
  SshPmP1 p1;
  SshUInt32 i;
  const char *routing_instance_name;

  for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
    {
      for (p1 = pm->ike_sa_hash[i]; p1; p1 = p1->hash_next)
        {
          if (p1->ike_sa->server == server)
            {
              auth.p1 = p1;
              auth.pm = pm;
              stats.auth = &auth;

              stats.encrypt_algorithm = p1->ike_sa->encrypt_algorithm;
              stats.mac_algorithm = p1->ike_sa->mac_algorithm;
              stats.prf_algorithm = p1->ike_sa->prf_algorithm;
              stats.created = p1->expire_time - p1->lifetime;
              stats.num_child_sas = ssh_pm_peer_num_child_sas_by_p1(pm, p1);
              stats.routing_instance_id = server->routing_instance_id;
              routing_instance_name = ssh_ip_get_interface_vri_name(&pm->ifs,
                                                server->routing_instance_id);
              ssh_strncpy(stats.routing_instance_name,
                          routing_instance_name, 64);

              if (!(*callback)(pm, &stats, context))
                return FALSE;
            }
        }
    }
  return TRUE;
}
