/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Allocating and freeing objects, used by the policy manager.  The
   allocation happens either dynamically or by using pre-allocated
   tables.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"


/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmAlloc"

/** A freelist item.  Various structures are put into a freelist using
    this structure as their place-holder. */
struct SshPmFreelistItemRec
{
  struct SshPmFreelistItemRec *next;
};

typedef struct SshPmFreelistItemRec SshPmFreelistItemStruct;

void
pm_freelist_put(SshPmFreelistItem *list, SshPmFreelistItem item,
                size_t item_size)
{
  SSH_ASSERT(list != NULL);
  SSH_ASSERT(item != NULL);
  SSH_ASSERT(item_size >= sizeof(SshPmFreelistItemStruct));

#ifdef DEBUG_LIGHT
  memset(item, 'F', item_size);
#endif /* DEBUG_LIGHT */

  item->next = *list;

  *list = item;
}

#define SSH_PM_FREELIST_PUT(list, item) \
pm_freelist_put(&(list), (SshPmFreelistItem) (item), sizeof(*(item)))

void
pm_freelist_index_put(SshPmFreelistItem *list, SshPmFreelistItem item,
                      size_t item_size, SshUInt32 *index)
{
  SshUInt32 i;

  i = *index;
  pm_freelist_put(list, item, item_size);
  *index = i;
}

#define SSH_PM_FREELIST_INDEX_PUT(list, item) \
pm_freelist_index_put(&(list), (SshPmFreelistItem) (item), sizeof(*(item)), \
                      &(item)->index)

void
pm_freelist_get(SshPmFreelistItem *list, SshPmFreelistItem *item,
                size_t item_size)
{
  SSH_ASSERT(list != NULL);
  SSH_ASSERT(item != NULL);

  if (*list == NULL)
    {
      *item = NULL;
    }
  else
    {
      *item = *list;
      *list = (*list)->next;
      if (item_size > 0)
        memset(*item, 0, item_size);
    }
}

#define SSH_PM_FREELIST_GET(list, item) \
pm_freelist_get(&(list), (void *) &(item), sizeof(*(item)))

void
pm_freelist_index_get(SshPmFreelistItem *list, SshPmFreelistItem *item,
                      size_t item_size, size_t index_offset)
{
  SshUInt32 i;

  pm_freelist_get(list, item, 0);
  if (*item != NULL)
    {
      i = SSH_GET_32BIT(((char *) *item) + index_offset);
      memset(*item, 0, item_size);
      SSH_PUT_32BIT(((char *) *item) + index_offset, i);
    }
}

#define SSH_PM_FREELIST_INDEX_GET(list, item) \
pm_freelist_index_get(&(list), (void *) &(item), sizeof(*(item)),\
                      (((char *) &(item)->index) - ((char *) (item))))


/*************************** Pre-allocated tables ***************************/

#ifdef SSH_IPSEC_PREALLOCATE_TABLES

/* Allocate large tables as global variables if PREALLOCATE_TABLES has
   been specified. */

SshPmStruct ssh_pm_pm;
SshPmRuleStruct ssh_pm_rules[SSH_PM_MAX_RULES];
SshPmServiceStruct ssh_pm_services[SSH_PM_MAX_SERVICES];

SshPmTunnelStruct ssh_pm_tunnels[SSH_PM_MAX_TUNNELS];
SshPmQmStruct ssh_pm_qm[SSH_PM_MAX_QM_NEGOTIATIONS];
SshPmSpiInStruct ssh_pm_spis_in[SSH_PM_MAX_SPIS];
SshPmSpiOutStruct ssh_pm_spis_out[SSH_PM_MAX_SPIS];
SshPmSpiUnknownStruct ssh_pm_spis_unknown[SSH_PM_MAX_UNKNOWN_SPIS];

#ifdef SSHDIST_IPSEC_MOBIKE
SshPmMobikeStruct ssh_pm_mobike[SSH_PM_MAX_QM_NEGOTIATIONS];
#endif /* SSHDIST_IPSEC_MOBIKE */

SshPmP1NegotiationStruct ssh_pm_p1_nego[SSH_PM_MAX_IKE_SA_NEGOTIATIONS];
SshPmIkeRekeyStruct ssh_pm_p1_rekey[SSH_PM_MAX_IKE_SA_NEGOTIATIONS];
SshPmPeerStruct ssh_pm_peers[SSH_PM_MAX_PEER_HANDLES];

#ifdef SSHDIST_IPSEC_NAT
SshPmIfaceNatStruct ssh_pm_iface_nats[SSH_PM_MAX_INTERFACE_NATS];
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
SshPmLnsTunnelStruct ssh_pm_lns_tunnels[SSH_PM_MAX_L2TP_CLIENTS];
SshPmLnsTunnelNegotiationStruct ssh_pm_lns_tunnel_negotiations[
                                        SSH_PM_MAX_L2TP_TUNNEL_REQUESTS];
SshPmLnsSessionStruct ssh_pm_lns_sessions[SSH_PM_MAX_L2TP_CLIENTS];
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
SshPmVipStruct ssh_pm_vips[SSH_PM_VIRTUAL_IP_MAX_VIP_SESSIONS];
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifndef SSH_GLOBALS_EMULATION
/* IKE SA's are always 'preallocated' if global variables are not forbidden. */
SshPmP1Struct ssh_pm_p1[SSH_PM_MAX_IKE_SAS];
#endif /* SSH_GLOBALS_EMULATION */


/********************* Handling policy manager objects **********************/

SshPm
ssh_pm_alloc(void)
{
  SshPm pm;
  int i;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES

  /* Initialize the policy manager object. */
  pm = &ssh_pm_pm;
  memset(pm, 0, sizeof(*pm));

  /* Initialize high-level policy manager objects. */

  for (i = 0; i < SSH_PM_MAX_RULES; i++)
    SSH_PM_FREELIST_PUT(pm->rule_freelist, &ssh_pm_rules[i]);

  for (i = 0; i < SSH_PM_MAX_SERVICES; i++)
    SSH_PM_FREELIST_PUT(pm->service_freelist, &ssh_pm_services[i]);

  for (i = 0; i < SSH_PM_MAX_TUNNELS; i++)
    SSH_PM_FREELIST_PUT(pm->tunnel_freelist, &ssh_pm_tunnels[i]);

  for (i = 0; i < SSH_PM_MAX_QM_NEGOTIATIONS; i++)
    SSH_PM_FREELIST_PUT(pm->qm_freelist, &ssh_pm_qm[i]);

  for (i = 0; i < SSH_PM_MAX_SPIS; i++)
    SSH_PM_FREELIST_PUT(pm->spi_in_freelist, &ssh_pm_spis_in[i]);

  for (i = 0; i < SSH_PM_MAX_SPIS; i++)
    SSH_PM_FREELIST_PUT(pm->spi_out_freelist, &ssh_pm_spis_out[i]);

  for (i = 0; i < SSH_PM_MAX_UNKNOWN_SPIS; i++)
    SSH_PM_FREELIST_PUT(pm->spi_unknown_freelist, &ssh_pm_spis_unknown[i]);

  for (i = 0; i < SSH_PM_MAX_IKE_SA_NEGOTIATIONS; i++)
    SSH_PM_FREELIST_PUT(pm->p1_rekey_freelist, &ssh_pm_p1_rekey[i]);

  for (i = 0; i < SSH_PM_MAX_IKE_SA_NEGOTIATIONS; i++)
    SSH_PM_FREELIST_PUT(pm->p1_negotiation_freelist, &ssh_pm_p1_nego[i]);

  for (i = 0; i < SSH_PM_MAX_PEER_HANDLES; i++)
    SSH_PM_FREELIST_PUT(pm->peer_freelist, &ssh_pm_peers[i]);

#ifdef SSHDIST_IPSEC_MOBIKE
  for (i = 0; i < SSH_PM_MAX_QM_NEGOTIATIONS; i++)
    SSH_PM_FREELIST_PUT(pm->mobike_freelist, &ssh_pm_mobike[i]);
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_NAT
  for (i = 0; i < SSH_PM_MAX_INTERFACE_NATS; i++)
    SSH_PM_FREELIST_PUT(pm->iface_nat_freelist, &ssh_pm_iface_nats[i]);
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
  for (i = 0; i < SSH_PM_MAX_L2TP_CLIENTS; i++)
    {
      SSH_PM_FREELIST_PUT(pm->lns_tunnel_freelist, &ssh_pm_lns_tunnels[i]);
      SSH_PM_FREELIST_PUT(pm->lns_session_freelist, &ssh_pm_lns_sessions[i]);
    }
  for (i = 0; i < SSH_PM_MAX_L2TP_TUNNEL_REQUESTS; i++)
    SSH_PM_FREELIST_PUT(pm->lns_tunnel_negotiation_freelist,
                        &ssh_pm_lns_tunnel_negotiations[i]);
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  for (i = 0; i < SSH_PM_VIRTUAL_IP_MAX_VIP_SESSIONS; i++)
    SSH_PM_FREELIST_PUT(pm->vip_freelist, &ssh_pm_vips[i]);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#else /* not SSH_IPSEC_PREALLOCATE_TABLES */

  /* Allocate and initialize the policy manager object. */
  pm = ssh_calloc(1, sizeof(*pm));
  if (pm == NULL)
    goto error;

  /* Allocate high-level policy manager objects. */

  for (i = 0; i < SSH_PM_MAX_RULES; i++)
    {
      SshPmRule rule = ssh_malloc(sizeof(*rule));

      if (rule == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->rule_freelist, rule);
    }

  for (i = 0; i < SSH_PM_MAX_SERVICES; i++)
    {
      SshPmService service = ssh_malloc(sizeof(*service));

      if (service == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->service_freelist, service);
    }

  for (i = 0; i < SSH_PM_MAX_TUNNELS; i++)
    {
      SshPmTunnel tunnel = ssh_malloc(sizeof(*tunnel));

      if (tunnel == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->tunnel_freelist, tunnel);
    }

  for (i = 0; i < SSH_PM_MAX_SPIS; i++)
    {
      SshPmSpiIn item = ssh_malloc(sizeof(*item));

      if (item == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->spi_in_freelist, item);
    }
  for (i = 0; i < SSH_PM_MAX_SPIS; i++)
    {
      SshPmSpiOut item = ssh_malloc(sizeof(*item));

      if (item == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->spi_out_freelist, item);
    }

  for (i = 0; i < SSH_PM_MAX_UNKNOWN_SPIS; i++)
    {
      SshPmSpiUnknown item = ssh_malloc(sizeof(*item));

      if (item == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->spi_unknown_freelist, item);
    }

  for (i = 0; i < SSH_PM_MAX_QM_NEGOTIATIONS; i++)
    {
      SshPmQm qm = ssh_malloc(sizeof(*qm));

      if (qm == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->qm_freelist, qm);
    }

  for (i = 0; i < SSH_PM_MAX_IKE_SA_NEGOTIATIONS; i++)
    {
      SshPmIkeRekey rekey = ssh_malloc(sizeof(*rekey));

      if (rekey == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->p1_rekey_freelist, rekey);
    }

  for (i = 0; i < SSH_PM_MAX_IKE_SA_NEGOTIATIONS; i++)
    {
      SshPmP1Negotiation n = ssh_malloc(sizeof(*n));

      if (n == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->p1_negotiation_freelist, n);
    }


  for (i = 0; i < SSH_PM_MAX_PEER_HANDLES; i++)
    {
      SshPmPeer item = ssh_malloc(sizeof(*item));

      if (item == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->peer_freelist, item);
    }

#ifdef SSHDIST_IPSEC_MOBIKE
  for (i = 0; i < SSH_PM_MAX_QM_NEGOTIATIONS; i++)
    {
      SshPmMobike mobike = ssh_malloc(sizeof(*mobike));

      if (mobike == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->mobike_freelist, mobike);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_NAT
  for (i = 0; i < SSH_PM_MAX_INTERFACE_NATS; i++)
    {
      SshPmIfaceNat nat = ssh_malloc(sizeof(*nat));

      if (nat == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->iface_nat_freelist, nat);
    }
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
  for (i = 0; i < SSH_PM_MAX_L2TP_CLIENTS; i++)
    {
      SshPmLnsTunnel t;
      SshPmLnsSession s;

      t = ssh_malloc(sizeof(*t));
      if (t == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->lns_tunnel_freelist, t);

      s = ssh_malloc(sizeof(*s));
      if (s == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->lns_session_freelist, s);
    }
  for (i = 0; i < SSH_PM_MAX_L2TP_TUNNEL_REQUESTS; i++)
    {
      SshPmLnsTunnelNegotiation n;

      n = ssh_malloc(sizeof(*n));
      if (n == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->lns_tunnel_negotiation_freelist, n);
    }
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  for (i = 0; i < SSH_PM_VIRTUAL_IP_MAX_VIP_SESSIONS; i++)
    {
      SshPmVip vip;

      vip = ssh_malloc(sizeof(*vip));
      if (vip == NULL)
        goto error;

      SSH_PM_FREELIST_PUT(pm->vip_freelist, vip);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  /* IKE SA's are always tabled. Except: Globals emulation. */
#ifdef SSH_GLOBALS_EMULATION
 {
   pm->ssh_pm_p1 = ssh_malloc(sizeof(SshPmP1Struct) * SSH_PM_MAX_IKE_SAS);

   for (i = 0; i < SSH_PM_MAX_IKE_SAS; i++)
     {
       pm->ssh_pm_p1[i].index = i;
       SSH_PM_FREELIST_INDEX_PUT(pm->p1_freelist, &pm->ssh_pm_p1[i]);
     }
 }
#else /* SSH_GLOBALS_EMULATION */
  for (i = 0; i < SSH_PM_MAX_IKE_SAS; i++)
    {
      ssh_pm_p1[i].index = i;
      SSH_PM_FREELIST_INDEX_PUT(pm->p1_freelist, &ssh_pm_p1[i]);
    }
#endif /* SSH_GLOBALS_EMULATION */

#ifdef WITH_IKE
  /* Reserve some QM structures for rekeys. */
  for (i = 0; i < SSH_PM_MAX_QM_NEGOTIATIONS / 2; i++)
    {
      SshPmQm qm;

      SSH_PM_FREELIST_GET(pm->qm_freelist, qm);
      SSH_ASSERT(qm != NULL);

      SSH_PM_FREELIST_PUT(pm->qm_rekey_freelist, qm);
    }
#endif /* WITH_IKE */

  if (ssh_ip_init_interfaces(&pm->ifs) == FALSE)
    goto error;
#ifdef SSHDIST_IPSEC_DNSPOLICY
  pm->dnscache = ssh_pm_dns_cache_create();
  if (pm->dnscache == NULL)
    goto error;

  pm->dns_query_freelist =
    ssh_pm_dns_query_pool_allocate(SSH_PM_MAX_DNS_QUERIES);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /* Allocate SPD (various rule containers) */
  pm->rule_by_id =
    ssh_adt_create_generic(SSH_ADT_BAG, SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                             rule_by_index_hdr),
                           SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                           SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                           SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (pm->rule_by_id == NULL)
    goto error;

  pm->rule_by_autostart =
    ssh_adt_create_generic(SSH_ADT_AVLTREE,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                             rule_by_autostart_hdr),
                           SSH_ADT_COMPARE, ssh_pm_rule_prec_compare_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (pm->rule_by_autostart == NULL)
    goto error;

  pm->rule_by_precedence =
    ssh_adt_create_generic(SSH_ADT_AVLTREE,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                             rule_by_precedence_hdr),
                           SSH_ADT_COMPARE, ssh_pm_rule_prec_compare_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (pm->rule_by_precedence == NULL)
    goto error;

  pm->rule_ike_trigger =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                             rule_ike_trigger_hdr),
                           SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                           SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (pm->rule_ike_trigger == NULL)
    goto error;

  pm->iface_pending_additions =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                             rule_by_index_hdr),
                           SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                           SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                           SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (pm->iface_pending_additions == NULL)
    goto error;

  /* All done. */
  return pm;

  /* Error handling. */

 error:
  ssh_pm_free(pm);
  return NULL;

}

void ssh_pm_uninit(SshPm pm)
{
#ifdef SSHDIST_EXTERNALKEY
  /* Uninit externalkey first since it unlocks certificates from the
     certificate manager. */
  if (pm->externalkey)
    ssh_ek_free(pm->externalkey, NULL_FNPTR, NULL);

  ssh_pm_ek_uninit(pm);
#endif /* SSHDIST_EXTERNALKEY */

#ifdef SSHDIST_CRYPTO_RANDOM_POLL
  /* Uninitialize random poll module. */
  ssh_random_noise_polling_uninit();
#endif /* SSHDIST_CRYPTO_RANDOM_POLL */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
  ssh_pm_cfgmode_client_store_uninit(pm);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  ssh_pm_servers_uninit(pm);

#ifdef SSHDIST_L2TP
  ssh_pm_l2tp_uninit(pm, NULL_FNPTR, NULL);
#endif /* SSHDIST_L2TP */

  ssh_pm_audit_uninit(pm);

  ssh_fsm_uninit(&pm->fsm);

  /* Free interfaces. */
  ssh_ip_uninit_interfaces(&pm->ifs);

#ifdef WITH_IKE
  ssh_pm_ike_uninit(pm);
#endif /* WITH_IKE */

  ssh_pm_spis_destroy(pm);

  /* Free SPD. */
  ssh_adt_destroy(pm->rule_by_autostart);
  ssh_adt_destroy(pm->rule_by_precedence);
  ssh_adt_destroy(pm->rule_ike_trigger);
  ssh_adt_destroy(pm->rule_by_id); /* destructor for this frees the
                                      rule */

  ssh_adt_destroy(pm->config_additions);
  ssh_adt_destroy(pm->config_deletions);
  ssh_adt_destroy(pm->config_pending_additions);
  ssh_adt_destroy(pm->config_pending_deletions);
  ssh_adt_destroy(pm->iface_pending_additions);
  ssh_adt_destroy(pm->batch.additions);

  ssh_pm_tunnels_uninit(pm);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  while (pm->addrpool)
    {
      SshPmAddressPool ap = pm->addrpool;
      pm->addrpool = ap->next;
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        ssh_pm_dhcp_address_pool_destroy(ap);
      else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
      ssh_pm_address_pool_destroy(ap);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_DNSPOLICY
  ssh_pm_dns_query_pool_free(pm->dns_query_freelist);
  ssh_pm_dns_cache_destroy(pm->dnscache);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSH_PM_BLACKLIST_ENABLED
  ssh_pm_blacklist_uninit(pm);
#endif /* SSH_PM_BLACKLIST_ENABLED */
}

void
ssh_pm_free(SshPm pm)
{

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  SshPmQm qm;
#endif /* not  SSH_IPSEC_PREALLOCATE_TABLES */

  if (pm == NULL)
    return;

  ssh_pm_uninit(pm);

#ifdef SSHDIST_EXTERNALKEY
  if (pm->accel_short_name)
    ssh_free(pm->accel_short_name);
#endif /* SSHDIST_EXTERNALKEY */

  if (pm->hash)
    ssh_hash_free(pm->hash);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  ssh_free(pm->virtual_adapters);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Free dynamic fields from parameters. */
  ssh_free(pm->params.socks);
  ssh_free(pm->params.http_proxy);
  ssh_free(pm->params.hostname);

  ssh_free(pm->params.ike_addrs);

  /* Free SAD handle. */
  if (pm->sad_handle)
    {
      ssh_ikev2_ts_freelist_destroy(pm->sad_handle);
      ssh_free(pm->sad_handle);
      pm->sad_handle = NULL;
    }
#ifdef SSHDIST_EXTERNALKEY
  ssh_free(pm->params.ek_accelerator_type);
  ssh_free(pm->params.ek_accelerator_init_info);
#endif /* SSHDIST_EXTERNALKEY */

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* Nothing here.  The memory is taken from global variables so we
     are done. */
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */

  /* Free high-level policy manager objects. */

  while (pm->rule_freelist)
    {
      SshPmRule rule;

      SSH_PM_FREELIST_GET(pm->rule_freelist, rule);
      ssh_free(rule);
    }

  while (pm->service_freelist)
    {
      SshPmService service;

      SSH_PM_FREELIST_GET(pm->service_freelist, service);
      ssh_free(service);
    }

  while (pm->tunnel_freelist)
    {
      SshPmTunnel tunnel;

      SSH_PM_FREELIST_GET(pm->tunnel_freelist, tunnel);
      ssh_free(tunnel);
    }

  while (pm->qm_freelist)
    {
      SSH_PM_FREELIST_GET(pm->qm_freelist, qm);
      ssh_free(qm);
    }

  while (pm->p1_negotiation_freelist)
    {
      SshPmP1Negotiation n;

      SSH_PM_FREELIST_GET(pm->p1_negotiation_freelist, n);
      ssh_free(n);
    }

  while (pm->p1_rekey_freelist)
    {
      SshPmIkeRekey rekey;

      SSH_PM_FREELIST_GET(pm->p1_rekey_freelist, rekey);
      ssh_free(rekey);
    }
  while (pm->qm_rekey_freelist)
    {
      SSH_PM_FREELIST_GET(pm->qm_rekey_freelist, qm);
      ssh_free(qm);
    }

  while (pm->peer_freelist)
    {
      SshPmPeer item;

      SSH_PM_FREELIST_GET(pm->peer_freelist, item);
      ssh_free(item);
    }

#ifdef SSHDIST_IPSEC_MOBIKE
  while (pm->mobike_freelist)
    {
      SshPmMobike mobike;

      SSH_PM_FREELIST_GET(pm->mobike_freelist, mobike);
      ssh_free(mobike);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */


#ifdef SSHDIST_IPSEC_NAT
  while (pm->iface_nat_list)
    {
      SshPmIfaceNat nat = pm->iface_nat_list;

      pm->iface_nat_list = nat->next;
      ssh_pm_iface_nat_free(pm, nat);
    }
  while (pm->iface_nat_freelist)
    {
      SshPmIfaceNat nat;

      SSH_PM_FREELIST_GET(pm->iface_nat_freelist, nat);
      ssh_free(nat);
    }
#endif /* SSHDIST_IPSEC_NAT */

  while (pm->spi_in_freelist)
    {
      SshPmSpiIn item;

      SSH_PM_FREELIST_GET(pm->spi_in_freelist, item);
      ssh_free(item);
    }
  while (pm->spi_out_freelist)
    {
      SshPmSpiOut item;

      SSH_PM_FREELIST_GET(pm->spi_out_freelist, item);
      ssh_free(item);
    }

  while (pm->spi_unknown_freelist)
    {
      SshPmSpiUnknown item;

      SSH_PM_FREELIST_GET(pm->spi_unknown_freelist, item);
      ssh_free(item);
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
  while (pm->lns_tunnel_freelist)
    {
      SshPmLnsTunnel tunnel;

      SSH_PM_FREELIST_GET(pm->lns_tunnel_freelist, tunnel);
      ssh_free(tunnel);
    }
  while (pm->lns_tunnel_negotiation_freelist)
    {
      SshPmLnsTunnelNegotiation n;

      SSH_PM_FREELIST_GET(pm->lns_tunnel_negotiation_freelist, n);
      ssh_free(n);
    }
  while (pm->lns_session_freelist)
    {
      SshPmLnsSession session;

      SSH_PM_FREELIST_GET(pm->lns_session_freelist, session);
      ssh_free(session);
    }
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  while (pm->vip_freelist)
    {
      SshPmVip vip;

      SSH_PM_FREELIST_GET(pm->vip_freelist, vip);
      ssh_free(vip);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_GLOBALS_EMULATION
  ssh_free(pm->ssh_pm_p1);
#endif /* SSH_GLOBALS_EMULATION */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
#ifdef SSH_IPSEC_STATISTICS
  if (pm->radius_acct_stats != NULL)
    {
      ssh_free(pm->radius_acct_stats);
    }
#endif /* SSH_IPSEC_STATISTICS */
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  ssh_free(pm);

#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */
}


/****************** Handling policy configuration objects *******************/

SshPmRule
ssh_pm_rule_alloc(SshPm pm)
{
  SshPmRule rule;

  SSH_PM_FREELIST_GET(pm->rule_freelist, rule);

  return rule;
}

void
ssh_pm_rule_free(SshPm pm, SshPmRule rule)
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (!(rule->flags & SSH_PM_RULE_I_CLONE))
    {
      if (rule->side_from.dns_ifname_sel_ref)
        ssh_pm_dns_cache_remove(pm->dnscache,
                                rule->side_from.dns_ifname_sel_ref);

      if (rule->side_from.dns_addr_sel_ref)
        ssh_pm_dns_cache_remove(pm->dnscache,
                                rule->side_from.dns_addr_sel_ref);

      if (rule->side_to.dns_addr_sel_ref)
        ssh_pm_dns_cache_remove(pm->dnscache,
                                rule->side_to.dns_addr_sel_ref);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  if (rule->side_from.tunnel)
    {
      SSH_PM_TUNNEL_DETACH_RULE(rule->side_from.tunnel, rule, FALSE);
      SSH_PM_TUNNEL_DESTROY(pm, rule->side_from.tunnel);
    }
  if (rule->side_to.tunnel)
    {
      SSH_PM_TUNNEL_DETACH_RULE(rule->side_to.tunnel, rule, TRUE);
      SSH_PM_TUNNEL_DESTROY(pm, rule->side_to.tunnel);
    }

  ssh_free(rule->access_groups);

  if (rule->side_from.ts)
    ssh_ikev2_ts_free(pm->sad_handle, rule->side_from.ts);
  if (rule->side_to.ts)
    ssh_ikev2_ts_free(pm->sad_handle, rule->side_to.ts);

  ssh_free(rule->side_from.ifname);
  SSH_ASSERT(rule->side_to.ifname == NULL);

  ssh_pm_service_destroy(rule->service);

#ifdef SSHDIST_IPSEC_SA_EXPORT
  ssh_free(rule->application_identifier);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  ssh_fsm_condition_uninit(&rule->cond);
  SSH_PM_FREELIST_PUT(pm->rule_freelist, rule);
}

SshPmService
ssh_pm_service_alloc(SshPm pm)
{
  SshPmService service;

  SSH_PM_FREELIST_GET(pm->service_freelist, service);

  return service;
}

void
ssh_pm_service_free(SshPm pm, SshPmService service)
{
  SSH_PM_FREELIST_PUT(pm->service_freelist, service);
}

SshPmTunnel
ssh_pm_tunnel_alloc(SshPm pm)
{
  SshPmTunnel tunnel;

  SSH_PM_FREELIST_GET(pm->tunnel_freelist, tunnel);

  return tunnel;
}

void
ssh_pm_tunnel_free(SshPm pm, SshPmTunnel tunnel)
{
  int i;
  SshPmTunnelLocalIp local_ip, next_local_ip;
#ifdef SSHDIST_IPSEC_MOBIKE
  SshPmTunnelLocalInterface local_iface, next_local_iface;
#endif /* SSHDIST_IPSEC_MOBIKE */
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshPmTunnelLocalDnsAddress local_dns, next_local_dns;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSHDIST_IPSEC_DNSPOLICY
  for (i = 0; i < tunnel->num_dns_peers; i++)
    ssh_pm_dns_cache_remove(pm->dnscache,
                            tunnel->dns_peer_ip_ref_array[i].ref);
  ssh_free(tunnel->dns_peer_ip_ref_array);

  for (local_dns = tunnel->local_dns_address;
       local_dns != NULL;
       local_dns = next_local_dns)
    {
      ssh_pm_dns_cache_remove(pm->dnscache, local_dns->ref);
      next_local_dns = local_dns->next;
      ssh_free(local_dns->name);
      ssh_free(local_dns);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSHDIST_IPSEC_MOBIKE
  for (local_iface = tunnel->local_interface;
       local_iface != NULL;
       local_iface = next_local_iface)
    {
      next_local_iface = local_iface->next;
      ssh_free(local_iface->name);
      ssh_free(local_iface);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

  for (local_ip = tunnel->local_ip;
       local_ip != NULL;
       local_ip = next_local_ip)
    {
      next_local_ip = local_ip->next;
      ssh_free(local_ip);
    }

  ssh_free(tunnel->tunnel_name);
  ssh_free(tunnel->peers);

  if (tunnel->local_identity)
    ssh_pm_ikev2_payload_id_free(tunnel->local_identity);
  if (tunnel->remote_identity)
    ssh_pm_ikev2_payload_id_free(tunnel->remote_identity);
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (tunnel->second_local_identity)
    ssh_pm_ikev2_payload_id_free(tunnel->second_local_identity);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  if (tunnel->auth_domain_name)
    {
      ssh_free(tunnel->auth_domain_name);
      tunnel->auth_domain_name = NULL;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (tunnel->second_auth_domain_name)
    {
      ssh_free(tunnel->second_auth_domain_name);
      tunnel->second_auth_domain_name = NULL;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /* IKE keyed tunnels. */
  if (tunnel->ike_tn)
    {
      ssh_free(tunnel->u.ike.tunnel_ike_groups);
      ssh_free(tunnel->u.ike.tunnel_pfs_groups);

      for (i = 0; i < tunnel->u.ike.num_secrets; i++)
        ssh_free(tunnel->u.ike.secrets[i].secret);

      ssh_free(tunnel->u.ike.secrets);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
      if (tunnel->u.ike.local_cert_kid)
        {
          ssh_free(tunnel->u.ike.local_cert_kid);
          tunnel->u.ike.local_cert_kid_len = 0;
        }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
    }

  /* Manually keyed tunnels. */
  if (tunnel->manual_tn)
    {
      /* Clear an free the key material. */
      if (tunnel->u.manual.key)
        {
          memset(tunnel->u.manual.key, 0, tunnel->u.manual.key_len);
          ssh_free(tunnel->u.manual.key);
        }
    }

  /* Free optional algorithm properties. */
  while (tunnel->algorithm_properties)
    {
      SshPmAlgorithmProperties prop;

      prop = tunnel->algorithm_properties;
      tunnel->algorithm_properties = prop->next;

      ssh_free(prop);
    }

#ifdef SSHDIST_IPSEC_SA_EXPORT
  ssh_free(tunnel->application_identifier);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  tunnel->last_attempted_peer = 0;

  /* Put the tunnel object back to the freelist. */
  SSH_PM_FREELIST_PUT(pm->tunnel_freelist, tunnel);
}


/************* Handling runtime policymanager objects ************************/

SshPmP1
ssh_pm_p1_from_ike_handle(SshPm pm, SshUInt32 ike_sa_handle,
                          Boolean ignore_unusable)
{
  SshPmP1 p1;
  SshUInt32 generation;

  if (ike_sa_handle == SSH_IPSEC_INVALID_INDEX)
    return NULL;

  /* Clear the topmost bit indicating the IKE version and generation
     of this SA. */
  generation = (ike_sa_handle >> 24) & 0x7f;
  ike_sa_handle &= (0xffffffff >> 8);

#ifdef SSH_GLOBALS_EMULATION
  p1 = &pm->ssh_pm_p1[ike_sa_handle];
#else /* SSH_GLOBALS_EMULATION */
  p1 = &ssh_pm_p1[ike_sa_handle];
#endif /* SSH_GLOBALS_EMULATION */

  /* Match generation */
  if (((p1->index >> 24) & 0x7f) != generation)
    return NULL;

  if (p1->unusable && ignore_unusable)
    return NULL;
  return p1;
}

SshPmP1
ssh_pm_p1_alloc(SshPm pm)
{
  SshPmP1 p1 = NULL;

  /* Check if we have any Phase-1 SA structures left. */
  if (pm->p1_freelist == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "The maximum number of active Phase-1 SAs reached");
      return NULL;
    }

  /* We had at least one.  Let's initialize it. */
  SSH_PM_FREELIST_INDEX_GET(pm->p1_freelist, p1);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  ssh_fsm_condition_init(&pm->fsm, &p1->xauth_wait_condition);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef DEBUG_LIGHT
  p1->magic = SSH_PM_MAGIC_P1;
#endif /* DEBUG_LIGHT */
  p1->pm = pm;

  /* We have one more active Phase-1 SA. */
  pm->stats.num_p1_active++;
  return p1;
}


SshPmIkeRekey
ssh_pm_p1_rekey_alloc(SshPm pm)
{
  SshPmIkeRekey rekey;

  if (pm->p1_rekey_freelist == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "The maximum number of active IKE rekeys reached");
      return NULL;
    }

  /* We had at least one.  Let's initialize it. */
  SSH_PM_FREELIST_GET(pm->p1_rekey_freelist, rekey);
  return rekey;
}

void ssh_pm_p1_rekey_free(SshPm pm, SshPmIkeRekey rekey)
{
  /* Put the structure back to PM's Phase-1 rekey structure freelist. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Recycling Phase-1 rekey context %p", rekey));
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&rekey->thread));
  SSH_PM_FREELIST_PUT(pm->p1_rekey_freelist, rekey);
}

SshPmP1Negotiation
ssh_pm_p1_negotiation_alloc(SshPm pm)
{
  SshPmP1Negotiation n;

  /* Do we have any Phase-1 negotiation structures left? */
  if (pm->p1_negotiation_freelist == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "The maximum number of active Phase-1 negotiations "
                    "reached");
      return NULL;
    }

  /* Initialize this negotiation structure. */
  SSH_PM_FREELIST_GET(pm->p1_negotiation_freelist, n);

  /* Init the wait condition variable. */
  ssh_fsm_condition_init(&pm->fsm, &n->wait_condition);

  pm->num_active_p1_negotiations++;
  return n;
}

void
ssh_pm_p1_negotiation_free(SshPm pm, SshPmP1Negotiation n)
{
  SSH_ASSERT(n != NULL);

  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&n->thread));
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&n->sub_thread));

  pm->num_active_p1_negotiations--;

  if (n->rule)
    SSH_PM_RULE_UNLOCK(pm, n->rule);

  if (n->tunnel)
    {
      SSH_PM_TUNNEL_DESTROY(pm, n->tunnel);
      n->tunnel = NULL;
    }

  if (n->next)
    n->next->n->prev = n->prev;

  if (n->prev)
    n->prev->n->next = n->next;
  else
    {
      pm->active_p1_negotiations = n->next;
    }

  ssh_fsm_condition_uninit(&n->wait_condition);

#ifdef SSHDIST_IKE_EAP_AUTH
  ssh_pm_ike_eap_destroy(n->eap);
  n->eap = NULL;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  ssh_pm_ike_eap_destroy(n->second_eap);
  n->second_eap = NULL;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
  {
    int i;

    for (i = 0; i < n->crs.num_cas; i++)
      ssh_free(n->crs.cas[i]);
    ssh_free(n->crs.cas);

    ssh_free(n->crs.ca_lens);

    ssh_pm_cert_request_result_free(n->certificate_request_results,
                                    n->crs.num_cas);

    for (i = 0; i < n->num_cert_access_urls; i++)
      ssh_free(n->cert_access_urls[i]);
    ssh_free(n->cert_access_urls);
  }
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Put the structure back to PM's Phase-1 negotiation structure
     freelist. */
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Recycling Phase-1 SA negotiation context %p", n));
  SSH_PM_FREELIST_PUT(pm->p1_negotiation_freelist, n);
}

#ifdef SSHDIST_IPSEC_MOBIKE
SshPmMobike
ssh_pm_mobike_alloc(SshPm pm, SshPmP1 p1)
{
  SshPmMobike mobike;

  SSH_PM_ASSERT_P1(p1);

  if (pm->mobike_freelist == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "The maximum number of active IKE mobikes negotiations "
                    "reached");
      return NULL;
    }

  /* We had at least one.  Let's initialize it. */
  SSH_PM_FREELIST_GET(pm->mobike_freelist, mobike);

  mobike->pm = pm;

  /* Take reference to p1. */
  SSH_PM_IKE_SA_TAKE_REF(p1->ike_sa);
  mobike->p1 = p1;

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
    mobike->old_natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    mobike->old_natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

#ifdef SSH_IPSEC_TCPENCAP
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    mobike->old_use_tcp_encaps = 1;
#endif /* SSH_IPSEC_TCPENCAP */

  *mobike->old_local_ip = *p1->ike_sa->server->ip_address;
  *mobike->old_remote_ip = *p1->ike_sa->remote_ip;
  mobike->old_local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
  mobike->old_remote_port = p1->ike_sa->remote_port;
  return mobike;
}

void ssh_pm_mobike_free(SshPm pm, SshPmMobike mobike)
{
  /* Free p1 reference. */
  if (mobike->p1)
   SSH_PM_IKE_SA_FREE_REF(pm->sad_handle, mobike->p1->ike_sa);

  /* Free tunnel reference. */
  if (mobike->tunnel)
    SSH_PM_TUNNEL_DESTROY(pm, mobike->tunnel);

  SSH_DEBUG(SSH_D_LOWSTART, ("Recycling mobike context %p", mobike));
  SSH_PM_FREELIST_PUT(pm->mobike_freelist, mobike);
}
#endif /* SSHDIST_IPSEC_MOBIKE */

SshPmQm
ssh_pm_qm_alloc(SshPm pm, Boolean rekey)
{
  SshPmQm qm = NULL;
  int i;

  if (rekey && pm->qm_rekey_freelist)
    {
      /* We have structures left at our rekey freelist. */
      SSH_PM_FREELIST_GET(pm->qm_rekey_freelist, qm);
      pm->qm_rekey_freelist_allocated++;
    }
  if (qm == NULL)
    {
      if (pm->qm_freelist == NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "The maximum number of active Quick-Mode negotiations "
                        "reached. Quick-Mode not done.");
          return NULL;
        }
      /* Structures left at the normal QM freelist. */
      SSH_PM_FREELIST_GET(pm->qm_freelist, qm);
    }

  /* We have one more active Quick-Mode negotiation. */
  pm->stats.num_qm_active++;

  /* Init QM structure. */
  qm->type = SSH_PM_ED_DATA_QM;

  qm->error = SSH_IKEV2_ERROR_OK;
#ifdef DEBUG_LIGHT
  qm->magic = SSH_PM_MAGIC_QM;
#endif /* DEBUG_LIGHT */

  qm->trd_index = SSH_IPSEC_INVALID_INDEX;
  qm->flow_index = SSH_IPSEC_INVALID_INDEX;
  qm->peer_handle = SSH_IPSEC_INVALID_INDEX;

  /* Initialize the SPI value to a nonzero error value. */
  qm->spis[0] = SSH_IPSEC_SPI_IKE_ERROR_RESERVED;
  qm->sa_index = SSH_IPSEC_INVALID_INDEX;
  qm->packet_ifnum = SSH_INVALID_IFNUM;

  for (i = 0;
       i < sizeof(qm->sa_handler_data.sa_indices) / sizeof(SshUInt32);
       i++)
    qm->sa_handler_data.sa_indices[i] = SSH_IPSEC_INVALID_INDEX;

  /* Link to active qm negotiations */
  qm->next = pm->active_qm_negotiations;
  pm->active_qm_negotiations = qm;
  if (qm->next)
    qm->next->prev = qm;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated Quick-Mode %p", qm));
  return qm;
}

void
ssh_pm_qm_free(SshPm pm, SshPmQm qm)
{
  SSH_PM_ASSERT_PM(pm);
  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&qm->thread));
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&qm->sub_thread));

  /* Clear key material from temporary negotiation context. */
  memset(qm->sa_handler_data.trd.data.keymat, 0,
         sizeof(qm->sa_handler_data.trd.data.keymat));

  /* Safe thing to perform regardless if timeout is requested or
     fired. */
  ssh_cancel_timeout(qm->timeout);

  if (qm->rule)
    SSH_PM_RULE_UNLOCK(pm, qm->rule);

  if (qm->tunnel)
    {
      SSH_PM_TUNNEL_DESTROY(pm, qm->tunnel);
      qm->tunnel = NULL;
    }

  if (qm->p1_tunnel)
    {
      SSH_PM_TUNNEL_DESTROY(pm, qm->p1_tunnel);
      qm->p1_tunnel = NULL;
    }

  /* Break linkage from active qm list */
  SSH_ASSERT(qm->next
             || qm->prev
             || pm->active_qm_negotiations == qm);

  if (qm->next)
    qm->next->prev = qm->prev;
  if (qm->prev)
    qm->prev->next = qm->next;
  else
    pm->active_qm_negotiations = qm->next;

  /* Update statistics. */
  SSH_ASSERT(pm->stats.num_qm_active > 0);
  pm->stats.num_qm_active--;

  /* Notify main thread if the policy manager is shutting down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  /* Free the fields of this Quick-Mode structure. */
  ssh_free(qm->packet);

  if (qm->local_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->local_ts);

  if (qm->remote_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->remote_ts);

  if (qm->local_trigger_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->local_trigger_ts);

  if (qm->remote_trigger_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->remote_trigger_ts);

  if (qm->sa_handler_data.ike_remote_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->sa_handler_data.ike_remote_ts);

  if (qm->sa_handler_data.ike_local_ts)
    ssh_ikev2_ts_free(pm->sad_handle, qm->sa_handler_data.ike_local_ts);

  /* Free SPI's if the QM negotiation was not successful. */
  ssh_pm_free_spis(pm, qm->spis);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Release network connection. */
  if (qm->conn_handle)
    ssh_pm_connection_release(qm->conn_handle);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Release peer handle reference taken for protecting qm->peer_handle. */
  if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
    ssh_pm_peer_handle_destroy(pm, qm->peer_handle);

  /* Put the structure back to PM's Quick-Mode structure freelist. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Recycling Quick-Mode context %p", qm));

  if (pm->qm_rekey_freelist_allocated)
    {
      /* Rekey freelist is not full.  Let's do our best in filling
         it. */
      SSH_PM_FREELIST_PUT(pm->qm_rekey_freelist, qm);
      pm->qm_rekey_freelist_allocated--;
    }
  else
    {
      /* Rekey freelist is full. */
      SSH_PM_FREELIST_PUT(pm->qm_freelist, qm);
    }
}

SshPmSpiIn ssh_pm_spi_in_alloc(SshPm pm)
{
  SshPmSpiIn spi = NULL;

  if (pm->spi_in_freelist == NULL)
      return NULL;

  /* Structures left at the freelist. */
  SSH_PM_FREELIST_GET(pm->spi_in_freelist, spi);
  return spi;
}

void ssh_pm_spi_in_free(SshPm pm, SshPmSpiIn spi)
{
  SSH_PM_FREELIST_PUT(pm->spi_in_freelist, spi);
}

SshPmSpiOut ssh_pm_spi_out_alloc(SshPm pm)
{
  SshPmSpiOut spi = NULL;

  if (pm->spi_out_freelist == NULL)
      return NULL;

  /* Structures left at the freelist. */
  SSH_PM_FREELIST_GET(pm->spi_out_freelist, spi);
  return spi;
}

void ssh_pm_spi_out_free(SshPm pm, SshPmSpiOut spi)
{
  SSH_PM_FREELIST_PUT(pm->spi_out_freelist, spi);
}

SshPmSpiUnknown ssh_pm_spi_unknown_alloc(SshPm pm)
{
  SshPmSpiUnknown spi = NULL;

  if (pm->spi_unknown_freelist == NULL)
      return NULL;

  /* Structures left at the freelist. */
  SSH_PM_FREELIST_GET(pm->spi_unknown_freelist, spi);
  return spi;
}

void ssh_pm_spi_unknown_free(SshPm pm, SshPmSpiUnknown spi)
{
  SSH_PM_FREELIST_PUT(pm->spi_unknown_freelist, spi);
}

SshPmPeer ssh_pm_peer_alloc(SshPm pm)
{
  SshPmPeer peer = NULL;

  SSH_PM_FREELIST_GET(pm->peer_freelist, peer);

  return peer;
}

void ssh_pm_peer_free(SshPm pm, SshPmPeer peer)
{
  SSH_ASSERT(peer != NULL);

  /* Free IKE identities. */
  if (peer->local_id)
    ssh_pm_ikev2_payload_id_free(peer->local_id);
  peer->local_id = NULL;

  if (peer->remote_id)
    ssh_pm_ikev2_payload_id_free(peer->remote_id);
  peer->remote_id = NULL;

  /* Assert that peer has been removed from hash tables. */
  SSH_ASSERT(peer->next_peer_handle == NULL);
  SSH_ASSERT(peer->prev_peer_handle == NULL);
  SSH_ASSERT(peer->next_sa_handle == NULL);
  SSH_ASSERT(peer->prev_sa_handle == NULL);
  SSH_ASSERT(peer->next_local_addr == NULL);
  SSH_ASSERT(peer->prev_local_addr == NULL);
  SSH_ASSERT(peer->next_remote_addr == NULL);
  SSH_ASSERT(peer->prev_remote_addr == NULL);

  /* Return peer to freelist. */
  SSH_PM_FREELIST_PUT(pm->peer_freelist, peer);
}

#ifdef SSHDIST_IPSEC_NAT
/***************************** NAT *******************************************/

SshPmIfaceNat
ssh_pm_iface_nat_alloc(SshPm pm)
{
  SshPmIfaceNat nat;

  if (pm->iface_nat_freelist == NULL)
    return NULL;

  SSH_PM_FREELIST_GET(pm->iface_nat_freelist, nat);

  return nat;
}

void
ssh_pm_iface_nat_free(SshPm pm, SshPmIfaceNat nat)
{
  SSH_PM_FREELIST_PUT(pm->iface_nat_freelist, nat);
}

#endif /* SSHDIST_IPSEC_NAT */


/************************ Remote Access Attributes **************************/

SshPmRemoteAccessAttrs
ssh_pm_dup_remote_access_attrs(SshPmRemoteAccessAttrs attrs)
{
  SshPmRemoteAccessAttrs a;

  if (attrs == NULL)
    return NULL;

  a = ssh_calloc(1, sizeof(*a));
  if (a == NULL)
    return NULL;

  *a = *attrs;

  if (attrs->server_duid != NULL && attrs->server_duid_len != 0)
    {
      a->server_duid = ssh_memdup(attrs->server_duid, attrs->server_duid_len);
      if (a->server_duid == NULL)
        {
          ssh_free(a);
          return NULL;
        }
      a->server_duid_len = attrs->server_duid_len;
    }

  return a;
}

void
ssh_pm_free_remote_access_attrs(SshPmRemoteAccessAttrs attributes)
{
  if (attributes == NULL)
    return;

  if (attributes->server_duid != NULL)
    ssh_free(attributes->server_duid);

  ssh_free(attributes);
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
/******************************** L2tp LNS ***********************************/

SshPmLnsTunnel
ssh_pm_lns_tunnel_alloc(SshPm pm)
{
  SshPmLnsTunnel tunnel;

  SSH_PM_FREELIST_GET(pm->lns_tunnel_freelist, tunnel);

  return tunnel;
}

void
ssh_pm_lns_tunnel_free(SshPm pm, SshPmLnsTunnel tunnel)
{
  if (--tunnel->refcount > 0)
    /* This was not the last reference. */
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing LNS tunnel %p", tunnel));

  if (tunnel->n)
    ssh_pm_lns_tunnel_negotiation_free(pm, tunnel->n);

  SSH_PM_FREELIST_PUT(pm->lns_tunnel_freelist, tunnel);
}

SshPmLnsTunnelNegotiation
ssh_pm_lns_tunnel_negotiation_alloc(SshPm pm)
{
  SshPmLnsTunnelNegotiation n;

  SSH_PM_FREELIST_GET(pm->lns_tunnel_negotiation_freelist, n);

  return n;
}

void
ssh_pm_lns_tunnel_negotiation_free(SshPm pm, SshPmLnsTunnelNegotiation n)
{
  SSH_PM_FREELIST_PUT(pm->lns_tunnel_negotiation_freelist, n);
}

SshPmLnsSession
ssh_pm_lns_session_alloc(SshPm pm)
{
  SshPmLnsSession session;

  SSH_PM_FREELIST_GET(pm->lns_session_freelist, session);

  return session;
}

void
ssh_pm_lns_session_free(SshPm pm, SshPmLnsSession session)
{
  if (--session->refcount > 0)
    /* This was not the last references. */
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing LNS session %p", session));
  SSH_PM_FREELIST_PUT(pm->lns_session_freelist, session);
}
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
/************************ Virtual IP Client *********************************/

SshPmVip ssh_pm_vip_alloc(SshPm pm)
{
  SshPmVip vip = NULL;
  int i;

  if (pm->vip_freelist == NULL)
    return NULL;

  /* Get a vip object from freelist. */
  SSH_PM_FREELIST_GET(pm->vip_freelist, vip);
  SSH_ASSERT(vip != NULL);

  /* Initialize the vip condition variable used for signalling. */
  ssh_fsm_condition_init(&pm->fsm, &vip->cond);

  /* Mark VIP initially unusable. */
  vip->unusable = 1;

  /* Undefine IKE peer handle. */
  vip->peer_handle = SSH_IPSEC_INVALID_INDEX;

  /* Undefine adapter ifnum. */
  vip->adapter_ifnum = SSH_INVALID_IFNUM;

  /* Routes and selected addresses are preallocated. */
  for (i = 0; i < SSH_PM_VIRTUAL_IP_MAX_ROUTES; i++)
    vip->routes[i].trd_index = SSH_IPSEC_INVALID_INDEX;

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated vip object %p", vip));

  return vip;
}

void ssh_pm_vip_free(SshPm pm, SshPmVip vip)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Freeing vip object %p", vip));

  ssh_fsm_condition_uninit(&vip->cond);

  SSH_PM_FREELIST_PUT(pm->vip_freelist, vip);
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
