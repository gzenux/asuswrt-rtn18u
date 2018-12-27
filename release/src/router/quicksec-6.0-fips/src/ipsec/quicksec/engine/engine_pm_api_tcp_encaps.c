/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec over TCP encapsulation. PM to engine message handling.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_tcp_encaps.h"
#include "engine_pm_api_marshal.h"
#include "sshinetencode.h"

#ifdef SSH_IPSEC_TCPENCAP

#define SSH_DEBUG_MODULE "SshEngineTcpEncaps"

/**************************** Declarations ***********************************/

void ssh_engine_index_callback(SshPm pm, SshUInt32 ind, void *context);


/**************************** Message handling *******************************/

/*
 * Add entry to TCP encapsulation configuration table.
 * This function will grab the 'tcp_encaps_lock'.
 */
Boolean
ssh_engine_pme_tcp_encaps_add_configuration(SshEngine engine,
                                            SshIpAddr local_addr,
                                            SshUInt16 local_port,
                                            SshIpAddr peer_lo_addr,
                                            SshIpAddr peer_hi_addr,
                                            SshUInt16 peer_port,
                                            SshUInt16 local_ike_port,
                                            SshUInt16 remote_ike_port)
{
  SshEngineTcpEncapsConfig config = NULL;

  /* Sanity checks */
  if (local_addr == NULL || !SSH_IP_DEFINED(local_addr)
      || peer_lo_addr == NULL || !SSH_IP_DEFINED(peer_lo_addr)
      || peer_hi_addr == NULL || !SSH_IP_DEFINED(peer_hi_addr))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid addresses in TCP encapsulation configuration."));
      goto error;
    }

  if ((SSH_IP_IS4(local_addr) && !SSH_IP_IS4(peer_lo_addr))
      || (!SSH_IP_IS4(local_addr) && SSH_IP_IS4(peer_lo_addr))
      || (SSH_IP_IS4(peer_lo_addr) && !SSH_IP_IS4(peer_hi_addr))
      || (!SSH_IP_IS4(peer_lo_addr) && SSH_IP_IS4(peer_hi_addr)))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid address families in TCP encapsulation "
                 "configuration."));
      goto error;
    }

  config = ssh_malloc(sizeof(*config));
  if (config)
    {
      memset(config, 0, sizeof(*config));
      memcpy(&config->local_addr, local_addr, sizeof(config->local_addr));
      config->local_port = local_port;
      memcpy(&config->peer_lo_addr,
             peer_lo_addr,
             sizeof(config->peer_lo_addr));
      memcpy(&config->peer_hi_addr,
             peer_hi_addr,
             sizeof(config->peer_hi_addr));
      config->peer_port = peer_port;
      if (local_ike_port == 0)
        config->local_ike_port = 500;
      else
        config->local_ike_port = local_ike_port;
      if (remote_ike_port == 0)
        config->remote_ike_port = 500;
      else
        config->remote_ike_port = remote_ike_port;

      /* Grab 'tcp_encaps_lock' */
      ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

      config->next = engine->tcp_encaps_configuration_table;
      engine->tcp_encaps_configuration_table = config;

      /* Unlock 'tcp_encaps_lock' */
      ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

      SSH_DEBUG(SSH_D_LOWOK,
                ("TCP encapsulation configuration: "
                 "[%@:%d] [%@-%@:%d] IKE local port %d, remote port %d",
                 ssh_ipaddr_render, local_addr, (int) local_port,
                 ssh_ipaddr_render, peer_lo_addr,
                 ssh_ipaddr_render, peer_hi_addr, (int) peer_port,
                 (int) local_ike_port, (int) remote_ike_port));
    }

  return TRUE;

 error:
  if (config)
    ssh_free(config);
  return FALSE;
}

/*
 * Clear TCP encapsulation configuration table
 */
void
ssh_engine_pme_tcp_encaps_clear_configurations(SshEngine engine)
{
  SshEngineTcpEncapsConfig config, config_next;

  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  config = engine->tcp_encaps_configuration_table;
  while (config)
    {
      config_next = config->next;
      ssh_free(config);
      config = config_next;
    }
  engine->tcp_encaps_configuration_table = NULL;

  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("TCP encapsulation configurations cleared."));
}

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

/***************************** Unmarshalling *********************************/

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_ADD_CONFIG)
{
  unsigned char *local_addr_buf, *peer_lo_addr_buf, *peer_hi_addr_buf;
  size_t local_addr_len, peer_lo_addr_len, peer_hi_addr_len;
  SshIpAddrStruct local_addr, peer_lo_addr, peer_hi_addr;
  SshUInt16 local_port, peer_port, local_ike_port, remote_ike_port;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));

  if (ssh_decode_array(data, data_len,

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &local_addr_buf, &local_addr_len),
                       SSH_DECODE_UINT16(&local_port),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &peer_lo_addr_buf, &peer_lo_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &peer_hi_addr_buf, &peer_hi_addr_len),
                       SSH_DECODE_UINT16(&peer_port),

                       SSH_DECODE_UINT16(&local_ike_port),
                       SSH_DECODE_UINT16(&remote_ike_port),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Sanity checks */
  if (local_addr_buf == NULL ||
      peer_lo_addr_buf == NULL ||
      peer_hi_addr_buf == NULL)
    return FALSE;

  memset(&local_addr, 0, sizeof(local_addr));
  memset(&peer_lo_addr, 0, sizeof(peer_lo_addr));
  memset(&peer_hi_addr, 0, sizeof(peer_hi_addr));

  ssh_decode_ipaddr_array(local_addr_buf, local_addr_len, &local_addr);
  ssh_decode_ipaddr_array(peer_lo_addr_buf, peer_lo_addr_len, &peer_lo_addr);
  ssh_decode_ipaddr_array(peer_hi_addr_buf, peer_hi_addr_len, &peer_hi_addr);

  return ssh_engine_pme_tcp_encaps_add_configuration(engine,
                                                     &local_addr,
                                                     local_port,
                                                     &peer_lo_addr,
                                                     &peer_hi_addr,
                                                     peer_port,
                                                     local_ike_port,
                                                     remote_ike_port);
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));
  ssh_engine_pme_tcp_encaps_clear_configurations(engine);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING)
{
  SshUInt32 operation_index;
  unsigned char *local_addr_buf, *peer_addr_buf, *ike_initiator_cookie;
  size_t local_addr_len, peer_addr_len, ike_initiator_cookie_len;
  SshIpAddrStruct local_addr, peer_addr;
  SshUInt16 local_port, peer_port, local_ike_port, remote_ike_port;
  void *context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &local_addr_buf, &local_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &peer_addr_buf, &peer_addr_len),
                       SSH_DECODE_UINT16(&local_port),
                       SSH_DECODE_UINT16(&peer_port),
                       SSH_DECODE_UINT16(&local_ike_port),
                       SSH_DECODE_UINT16(&remote_ike_port),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &ike_initiator_cookie, &ike_initiator_cookie_len),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Sanity checks. */
  if (local_addr_buf == NULL || peer_addr_buf == NULL
      || ike_initiator_cookie_len != SSH_ENGINE_IKE_COOKIE_LENGTH)
    return FALSE;

  memset(&local_addr, 0, sizeof(local_addr));
  memset(&peer_addr, 0, sizeof(peer_addr));

  ssh_decode_ipaddr_array(local_addr_buf, local_addr_len, &local_addr);
  ssh_decode_ipaddr_array(peer_addr_buf, peer_addr_len, &peer_addr);

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_tcp_encaps_create_ike_mapping(engine,
                                               &local_addr, &peer_addr,
                                               local_port, peer_port,
                                               ike_initiator_cookie,
                                               local_ike_port,
                                               remote_ike_port,
                                               ssh_engine_index_callback,
                                               context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING)
{
  SshUInt32 operation_index;
  unsigned char *local_addr_buf, *peer_addr_buf, *ike_initiator_cookie;
  size_t local_addr_len, peer_addr_len, ike_initiator_cookie_len;
  SshIpAddrStruct local_addr, peer_addr;
  void *context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &local_addr_buf, &local_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &peer_addr_buf, &peer_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &ike_initiator_cookie, &ike_initiator_cookie_len),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Sanity checks. */
  if (local_addr_buf == NULL || peer_addr_buf == NULL
      || ike_initiator_cookie_len != SSH_ENGINE_IKE_COOKIE_LENGTH)
    return FALSE;

  if (local_addr_len)
    {
      memset(&local_addr, 0, sizeof(local_addr));
      ssh_decode_ipaddr_array(local_addr_buf, local_addr_len, &local_addr);
    }

  if (peer_addr_len)
    {
      memset(&peer_addr, 0, sizeof(peer_addr));
      ssh_decode_ipaddr_array(peer_addr_buf, peer_addr_len, &peer_addr);
    }

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_tcp_encaps_get_ike_mapping(engine,
                                          local_addr_len ? &local_addr : NULL,
                                          peer_addr_len ? &peer_addr : NULL,
                                          ike_initiator_cookie,
                                          ssh_engine_index_callback,
                                          context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING)
{
  SshUInt32 operation_index;
  Boolean async_op, keep_address_matches;
  unsigned char *local_addr_buf, *peer_addr_buf;
  unsigned char *ike_initiator_cookie, *new_ike_initiator_cookie;
  size_t local_addr_len, peer_addr_len;
  size_t ike_initiator_cookie_len, new_ike_initiator_cookie_len;
  SshIpAddrStruct local_addr, peer_addr;
  void *context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),

                       SSH_DECODE_BOOLEAN(&async_op),
                       SSH_DECODE_BOOLEAN(&keep_address_matches),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &local_addr_buf, &local_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &peer_addr_buf, &peer_addr_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &ike_initiator_cookie, &ike_initiator_cookie_len),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &new_ike_initiator_cookie,
                       &new_ike_initiator_cookie_len),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Sanity checks. */
  if (local_addr_buf == NULL || peer_addr_buf == NULL
      || ike_initiator_cookie_len != SSH_ENGINE_IKE_COOKIE_LENGTH)
    return FALSE;

  if (local_addr_len)
    {
      memset(&local_addr, 0, sizeof(local_addr));
      ssh_decode_ipaddr_array(local_addr_buf, local_addr_len, &local_addr);
    }

  if (peer_addr_len)
    {
      memset(&peer_addr, 0, sizeof(peer_addr));
      ssh_decode_ipaddr_array(peer_addr_buf, peer_addr_len, &peer_addr);
    }

  if (new_ike_initiator_cookie_len == 0)
    new_ike_initiator_cookie = NULL;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_tcp_encaps_update_ike_mapping(engine,
                             keep_address_matches,
                             local_addr_len ? &local_addr : NULL,
                             peer_addr_len ? &peer_addr : NULL,
                             ike_initiator_cookie, new_ike_initiator_cookie,
                             async_op ? ssh_engine_index_callback : NULL_FNPTR,
                             context);

  return TRUE;
}

#endif /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#endif /* SSH_IPSEC_TCPENCAP */
