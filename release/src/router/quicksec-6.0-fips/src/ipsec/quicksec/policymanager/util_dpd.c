/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKE Dead Peer Detection.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmDpd"

/* Dead Peer Bag *************************************************************/

struct SshPmDpdDeadPeerEntryRec
{
  SshADTBagHeaderStruct adt_header;

  /* Peer IP address */
  SshIpAddrStruct addr;

  /* Time to remain on dead status. The entry is freed when TTL reaches
     zero. It is decremented from pm_dpd_dead_peer_timer, which runs
     once every ten seconds. */
  SshUInt16 ttl;

  /* True, if reason for being dead is timeout or failed DPD. When
     this is false, the entry was put here due to other error on
     Phase-1 (no proposal, invalid credentials or similar). Entries
     having this as false are cleared on reconfiguration. */
  Boolean down;
};
typedef struct SshPmDpdDeadPeerEntryRec *SshPmDpdDeadPeerEntry;
typedef struct SshPmDpdDeadPeerEntryRec  SshPmDpdDeadPeerEntryStruct;

static int
pm_dpd_dead_peer_compare(const void *p1, const void *p2,
                         void *context)
{
  SshPmDpdDeadPeerEntry e1 = (SshPmDpdDeadPeerEntry) p1;
  SshPmDpdDeadPeerEntry e2 = (SshPmDpdDeadPeerEntry) p2;

  return SSH_IP_CMP(&e1->addr, &e2->addr);
}

static SshUInt32
pm_dpd_dead_peer_hash(const void *p, void *context)
{
  SshPmDpdDeadPeerEntry e = (SshPmDpdDeadPeerEntry) p;

  return ssh_ipaddr_hash(&e->addr);
}

static void
pm_dpd_dead_peer_destroy(void *p, void *context)
{
  SshPmDpdDeadPeerEntry e = (SshPmDpdDeadPeerEntry) p;

  ssh_free(e);
}


static void pm_dpd_dead_peer_timer(void *context)
{
  SshPm pm = (SshPm) context;
  SshADTHandle h, next;
  SshPmDpdDeadPeerEntry e;
  int npeers = 0;

  for (h = ssh_adt_enumerate_start(pm->dpd_dead_bag);
       h != SSH_ADT_INVALID;
       h = next)
    {
      next = ssh_adt_enumerate_next(pm->dpd_dead_bag, h);

      e = ssh_adt_get(pm->dpd_dead_bag, h);
      if (--e->ttl == 0)
        {
          ssh_adt_delete(pm->dpd_dead_bag, h);
          npeers++;
        }
    }

  if (ssh_adt_num_objects(pm->dpd_dead_bag) > 0)
    {
      /* The bag has still entries left.  Keep the timer running. */
      ssh_register_timeout(&pm->dpd_timer,
                           10L, 0L,
                           pm_dpd_dead_peer_timer, pm);
    }

  SSH_DEBUG(SSH_D_MIDOK, ("DPD; Timer reclaimed %d peers, %d left",
                          npeers,
                          ssh_adt_num_objects(pm->dpd_dead_bag) - npeers));
}

void ssh_pm_dpd_peer_dead(SshPm pm, const SshIpAddr addr,
                          Boolean down)
{
  SshPmDpdDeadPeerEntry e;
  unsigned char addrstring[SSH_IP_ADDR_STRING_SIZE];

  if (pm->dpd_dead_bag)
    {
      if (!ssh_pm_dpd_peer_dead_p(pm, addr))
        {
          e = ssh_malloc(sizeof(*e));
          if (e != NULL)
            {
              e->addr = *addr;
              e->down = down;
              e->ttl = pm->dpd_dead_ttl;

              ssh_adt_insert(pm->dpd_dead_bag, e);

              if (ssh_adt_num_objects(pm->dpd_dead_bag) == 1)
                ssh_register_timeout(&pm->dpd_timer, 10L, 0L,
                                     pm_dpd_dead_peer_timer, pm);

              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("DPD; Peer %@: marked as dead",
                         ssh_ipaddr_render, addr));

              ssh_ipaddr_print(addr, addrstring, sizeof(addrstring));
              if (pm->dpd_status_callback)
                (*pm->dpd_status_callback)(pm, addrstring,
                                           pm->dpd_status_callback_context);
            }
        }
      else
        {
          SshPmDpdDeadPeerEntryStruct e_tmp;
          SshADTHandle h;

          e_tmp.addr = *addr;
          h = ssh_adt_get_handle_to_equal(pm->dpd_dead_bag, &e_tmp);
          if (h != SSH_ADT_INVALID)
            {
              e = ssh_adt_get(pm->dpd_dead_bag, h);
              e->ttl = pm->dpd_dead_ttl;
            }
        }
    }
}

void ssh_pm_dpd_peer_alive(SshPm pm, const SshIpAddr addr)
{
  SshADTHandle h;
  SshPmDpdDeadPeerEntryStruct e;

  if (pm->dpd_dead_bag)
    {
      e.addr = *addr;
      h = ssh_adt_get_handle_to_equal(pm->dpd_dead_bag, &e);
      if (h != SSH_ADT_INVALID)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("DPD; Peer %@: revived", ssh_ipaddr_render, addr));

          ssh_adt_delete(pm->dpd_dead_bag, h);
        }

      if (ssh_adt_num_objects(pm->dpd_dead_bag) == 0)
        ssh_cancel_timeout(&pm->dpd_timer);
    }
}

Boolean ssh_pm_dpd_peer_dead_p(SshPm pm, const SshIpAddr addr)
{
  SshPmDpdDeadPeerEntryStruct e;

  if (!pm->dpd_dead_bag)
    return FALSE;

  e.addr = *addr;
  if (ssh_adt_get_handle_to_equal(pm->dpd_dead_bag, &e) != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("DPD; Peer %@: cached as dead", ssh_ipaddr_render, addr));
      return TRUE;
    }
  return FALSE;
}


Boolean
ssh_pm_set_dpd(SshPm pm,
               SshUInt16 metric,
               SshUInt16 ttl,
               SshPmDpdStatusCB callback, void *context)
{
  if (pm->dpd_dead_bag)
    ssh_pm_dpd_uninit(pm);

  pm->dpd_worry_metric = metric;
  pm->dpd_status_callback = callback;
  pm->dpd_status_callback_context = context;
  pm->dpd_dead_ttl = ttl;

  return ssh_pm_dpd_init(pm);
}




Boolean ssh_pm_dpd_init(SshPm pm)
{
  if (pm->dpd_dead_bag)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("DPD; not initialized: already initialize"));
      return TRUE;
    }

  if ((pm->dpd_dead_bag =
       ssh_adt_create_generic(SSH_ADT_BAG,
                              SSH_ADT_HASH, pm_dpd_dead_peer_hash,
                              SSH_ADT_COMPARE, pm_dpd_dead_peer_compare,
                              SSH_ADT_DESTROY, pm_dpd_dead_peer_destroy,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshPmDpdDeadPeerEntryStruct,
                                                adt_header),
                              SSH_ADT_ARGS_END))
      == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("DPD; not initialized: no core"));
      return FALSE;
    }

  memset(&pm->dpd_timer, 0, sizeof(pm->dpd_timer));
  SSH_DEBUG(SSH_D_HIGHSTART, ("DPD; initialized"));
  return TRUE;
}

void ssh_pm_dpd_uninit(SshPm pm)
{
  if (pm->dpd_dead_bag)
    {
      ssh_adt_destroy(pm->dpd_dead_bag);
      pm->dpd_dead_bag = NULL;
    }
  ssh_cancel_timeout(&pm->dpd_timer);
  SSH_DEBUG(SSH_D_HIGHSTART, ("DPD; uninitialized"));
}

void ssh_pm_dpd_policy_change_notify(SshPm pm)
{
  SshADTHandle h, next;
  SshPmDpdDeadPeerEntry e;
  int npeers = 0;

  if (pm->dpd_dead_bag)
    {
      for (h = ssh_adt_enumerate_start(pm->dpd_dead_bag);
           h != SSH_ADT_INVALID;
           h = next)
        {
          next = ssh_adt_enumerate_next(pm->dpd_dead_bag, h);

          e = ssh_adt_get(pm->dpd_dead_bag, h);
          if (!e->down)
            {
              ssh_adt_delete(pm->dpd_dead_bag, h);
              npeers++;
            }
        }

      if (ssh_adt_num_objects(pm->dpd_dead_bag) == 0)
        ssh_cancel_timeout(&pm->dpd_timer);

      SSH_DEBUG(SSH_D_HIGHOK, ("DPD; policy changed: %d dead peers reclaimed",
                               npeers));
    }
}
