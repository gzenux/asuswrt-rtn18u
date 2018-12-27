/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Peer information database.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmPeer"

/************************* Definitions **************************************/

#define SSH_PM_PEER_HANDLE_HASH(peer_handle) \
((peer_handle) % SSH_PM_PEER_HANDLE_HASH_TABLE_SIZE)

#define SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle) \
((ike_sa_handle) % SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE)

#define SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip) \
(SSH_IP_HASH((local_ip)) % SSH_PM_PEER_ADDR_HASH_TABLE_SIZE)

#define SSH_PM_PEER_REMOTE_ADDR_HASH(remote_ip) \
(SSH_IP_HASH((remote_ip)) % SSH_PM_PEER_ADDR_HASH_TABLE_SIZE)

#define SSH_PM_PEER_DEBUG_CONNECTION_SHOWN 1
#define SSH_PM_PEER_DEBUG_IKE_SA_CHANGED 2

/************************* Peer hashtable handling **************************/

static void
pm_peer_handle_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

  hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);

  peer->next_peer_handle = pm->peer_handle_hash[hash];
  if (peer->next_peer_handle)
    peer->next_peer_handle->prev_peer_handle = peer;
  pm->peer_handle_hash[hash] = peer;
}

static void
pm_peer_handle_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

  if (peer->next_peer_handle)
    peer->next_peer_handle->prev_peer_handle = peer->prev_peer_handle;
  if (peer->prev_peer_handle)
    peer->prev_peer_handle->next_peer_handle = peer->next_peer_handle;
  else
    {
      hash = SSH_PM_PEER_HANDLE_HASH(peer->peer_handle);
      SSH_ASSERT(pm->peer_handle_hash[hash] == peer);
      pm->peer_handle_hash[hash] = peer->next_peer_handle;
    }

  peer->next_peer_handle = NULL;
  peer->prev_peer_handle = NULL;
}

static void
pm_peer_sa_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);

  peer->next_sa_handle = pm->peer_sa_hash[hash];
  if (peer->next_sa_handle)
    peer->next_sa_handle->prev_sa_handle = peer;
  pm->peer_sa_hash[hash] = peer;
}

static void
pm_peer_sa_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  if (peer->next_sa_handle)
    peer->next_sa_handle->prev_sa_handle = peer->prev_sa_handle;
  if (peer->prev_sa_handle)
    peer->prev_sa_handle->next_sa_handle = peer->next_sa_handle;
  else
    {
      hash = SSH_PM_PEER_IKE_SA_HASH(peer->ike_sa_handle);
      SSH_ASSERT(pm->peer_sa_hash[hash] == peer);
      pm->peer_sa_hash[hash] = peer->next_sa_handle;
    }

  peer->next_sa_handle = NULL;
  peer->prev_sa_handle = NULL;
}

static void
pm_peer_local_addr_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);

  peer->next_local_addr = pm->peer_local_addr_hash[hash];
  if (peer->next_local_addr)
    peer->next_local_addr->prev_local_addr = peer;
  pm->peer_local_addr_hash[hash] = peer;
}

static void
pm_peer_local_addr_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  if (peer->next_local_addr)
    peer->next_local_addr->prev_local_addr = peer->prev_local_addr;
  if (peer->prev_local_addr)
    peer->prev_local_addr->next_local_addr = peer->next_local_addr;
  else
    {
      hash = SSH_PM_PEER_LOCAL_ADDR_HASH(peer->local_ip);
      SSH_ASSERT(pm->peer_local_addr_hash[hash] == peer);
      pm->peer_local_addr_hash[hash] = peer->next_local_addr;
    }

  peer->next_local_addr = NULL;
  peer->prev_local_addr = NULL;
}

static void
pm_peer_remote_addr_hash_insert(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  hash = SSH_PM_PEER_REMOTE_ADDR_HASH(peer->remote_ip);

  peer->next_remote_addr = pm->peer_remote_addr_hash[hash];
  if (peer->next_remote_addr)
    peer->next_remote_addr->prev_remote_addr = peer;
  pm->peer_remote_addr_hash[hash] = peer;
}

static void
pm_peer_remote_addr_hash_remove(SshPm pm, SshPmPeer peer)
{
  SshUInt32 hash;

  SSH_ASSERT(peer != NULL);

  if (peer->next_remote_addr)
    peer->next_remote_addr->prev_remote_addr = peer->prev_remote_addr;
  if (peer->prev_remote_addr)
    peer->prev_remote_addr->next_remote_addr = peer->next_remote_addr;
  else
    {
      hash = SSH_PM_PEER_REMOTE_ADDR_HASH(peer->remote_ip);
      SSH_ASSERT(pm->peer_remote_addr_hash[hash] == peer);
      pm->peer_remote_addr_hash[hash] = peer->next_remote_addr;
    }

  peer->next_remote_addr = NULL;
  peer->prev_remote_addr = NULL;
}

/************************* Peer reference counting ***************************/

static void
pm_peer_take_ref(SshPmPeer peer)
{
  SSH_ASSERT(peer != NULL);
  peer->refcnt++;
  SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to peer 0x%lx, refcnt %d",
                          (unsigned long) peer->peer_handle, peer->refcnt));
}

/**************************** Peer lookup ***********************************/

SshPmPeer
ssh_pm_peer_by_handle(SshPm pm, SshUInt32 peer_handle)
{
  SshPmPeer peer;
  SshUInt32 hash;

  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    return NULL;

  hash = SSH_PM_PEER_HANDLE_HASH(peer_handle);
  for (peer = pm->peer_handle_hash[hash];
       peer != NULL;
       peer = peer->next_peer_handle)
    {
      if (peer->peer_handle == peer_handle)
        return peer;
    }

  return NULL;
}

/** Iterating through peers that use IKE SA `ike_sa_handle'. */

SshPmPeer
ssh_pm_peer_by_ike_sa_handle(SshPm pm, SshUInt32 ike_sa_handle)
{
  SshPmPeer peer;
  SshUInt32 hash;

  hash = SSH_PM_PEER_IKE_SA_HASH(ike_sa_handle);
  for (peer = pm->peer_sa_hash[hash];
       peer != NULL;
       peer = peer->next_sa_handle)
    {
      if (peer->ike_sa_handle == ike_sa_handle)
        return peer;
    }

  return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_ike_sa_handle(SshPm pm, SshPmPeer peer)
{
  SshPmPeer next_peer;

  if (peer == NULL)
    return NULL;

  for (next_peer = peer->next_sa_handle;
       next_peer != NULL;
       next_peer = next_peer->next_sa_handle)
    {
      if (next_peer->ike_sa_handle == peer->ike_sa_handle)
        return next_peer;
    }

  return NULL;
}

SshPmPeer
ssh_pm_peer_by_p1(SshPm pm, SshPmP1 p1)
{
  SSH_ASSERT(p1 != NULL);
  return ssh_pm_peer_by_ike_sa_handle(pm, SSH_PM_IKE_SA_INDEX(p1));
}

SshUInt32
ssh_pm_peer_handle_by_p1(SshPm pm, SshPmP1 p1)
{
  SshPmPeer peer;

  SSH_ASSERT(p1 != NULL);
  peer = ssh_pm_peer_by_p1(pm, p1);
  if (peer)
    return peer->peer_handle;

  return SSH_IPSEC_INVALID_INDEX;
}

SshPmP1
ssh_pm_p1_by_peer_handle(SshPm pm, SshUInt32 peer_handle)
{
  SshPmPeer peer;

  peer = ssh_pm_peer_by_handle(pm, peer_handle);
  if (peer == NULL)
    return NULL;

  return ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, FALSE);
}

SshUInt32
ssh_pm_peer_handle_lookup(SshPm pm,
                          SshIpAddr remote_ip, SshUInt16 remote_port,
                          SshIpAddr local_ip, SshUInt16 local_port,
                          SshIkev2PayloadID remote_id,
                          SshIkev2PayloadID local_id,
                          SshVriId routing_instance_id,
                          Boolean use_ikev1,
                          Boolean manual_key)
{
  SshPmPeer peer;
  SshUInt32 hash;

  /* Addresses are mandatory, ports and identities are optional. */
  SSH_ASSERT(remote_ip != NULL);
  SSH_ASSERT(local_ip != NULL);

  hash = SSH_PM_PEER_REMOTE_ADDR_HASH(remote_ip);
  for (peer = pm->peer_remote_addr_hash[hash];
       peer != NULL;
       peer = peer->next_remote_addr)
    {
      /* Match routing instance id. */
      if (routing_instance_id != peer->routing_instance_id)
        continue;

      /* Match remote address. */
      if (SSH_IP_EQUAL(peer->remote_ip, remote_ip) == FALSE
          || (remote_port != 0 && peer->remote_port != remote_port))
        continue;

      /* Match local address. */
      if (SSH_IP_EQUAL(peer->local_ip, local_ip) == FALSE
          || (local_port != 0 && peer->local_port != local_port))
        continue;

      /* Match identities. */
      if (remote_id != NULL
          && ssh_pm_ikev2_id_compare(remote_id, peer->remote_id) == FALSE)
        continue;

      if (local_id != NULL
          && ssh_pm_ikev2_id_compare(local_id, peer->local_id) == FALSE)
        continue;

      /* Match rest. */
      if (peer->manual_key != manual_key
          || peer->use_ikev1 != use_ikev1)
        continue;

      /* We have a match. */
      return peer->peer_handle;
    }

  return SSH_IPSEC_INVALID_INDEX;
}


SshUInt32
ssh_pm_peer_handle_by_address(SshPm pm,
                              SshIpAddr remote_ip, SshUInt16 remote_port,
                              SshIpAddr local_ip, SshUInt16 local_port,
                              Boolean use_ikev1,
                              Boolean manual_key,
                              SshVriId routing_instance_id)
{
  return ssh_pm_peer_handle_lookup(pm, remote_ip, remote_port,
                                   local_ip, local_port, NULL, NULL,
                                   routing_instance_id,
                                   use_ikev1, manual_key);
}

/** Iterating through peers that use `local_ip'. */

SshPmPeer
ssh_pm_peer_by_local_address(SshPm pm, SshIpAddr local_ip)
{
  SshPmPeer peer;

  for (peer = pm->peer_local_addr_hash[SSH_PM_PEER_LOCAL_ADDR_HASH(local_ip)];
       peer != NULL;
       peer = peer->next_local_addr)
    {
      if (SSH_IP_EQUAL(peer->local_ip, local_ip))
        return peer;
    }

  return NULL;
}

SshPmPeer
ssh_pm_peer_next_by_local_address(SshPm pm, SshPmPeer peer)
{
  SshPmPeer next_peer;

  if (peer == NULL)
    return NULL;

  for (next_peer = peer->next_local_addr;
       next_peer != NULL;
       next_peer = next_peer->next_local_addr)
    {
      if (SSH_IP_EQUAL(next_peer->local_ip, peer->local_ip))
        return next_peer;
    }

  return NULL;
}

SshUInt32
ssh_pm_peer_num_child_sas_by_p1(SshPm pm, SshPmP1 p1)
{
  SshUInt32 num_child_sas = 0;
  SshPmPeer peer = NULL;

  /* Count child SAs of all the peers having the given p1. */
  for (peer = ssh_pm_peer_by_p1(pm, p1);
       peer != NULL;
       peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer))
    {
      num_child_sas += peer->num_child_sas;
    }

  return num_child_sas;
}

/********************* Peer creation / destruction **************************/

SshUInt32
ssh_pm_peer_create_internal(SshPm pm,
                            SshIpAddr remote_ip, SshUInt16 remote_port,
                            SshIpAddr local_ip, SshUInt16 local_port,
                            SshIkev2PayloadID local_id,
                            SshIkev2PayloadID remote_id,
                            SshUInt32 ike_sa_handle,
                            SshVriId routing_instance_id,
                            SshUInt32 flags,
                            Boolean force_ikev1_natt_draft_02)
{
  SshUInt32 peer_handle, i;
  SshPmPeer peer;

  SSH_ASSERT(remote_ip != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(remote_ip));
  SSH_ASSERT((flags & SSH_PM_PEER_CREATE_FLAGS_MANUAL_KEY) != 0
             || remote_port != 0);

  for (i = 0; i < SSH_PM_MAX_PEER_HANDLES; i++)
    {
      /* Select the next free peer_handle. */
      peer_handle = pm->next_peer_handle++;
      if (pm->next_peer_handle > SSH_PM_MAX_PEER_HANDLES)
        pm->next_peer_handle = 0;

      if (ssh_pm_peer_by_handle(pm, peer_handle))
        continue;

      /* Free peer_handle found, allocate a SshPmPeer. */
      peer = ssh_pm_peer_alloc(pm);
      if (!peer)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not allocate peer object"));
          return SSH_IPSEC_INVALID_INDEX;
        }

      peer->peer_handle = peer_handle;

      /* Take one reference for the caller. */
      peer->refcnt = 1;

      *peer->remote_ip = *remote_ip;
      peer->remote_port = remote_port;
      *peer->local_ip = *local_ip;
      peer->local_port = local_port;

      peer->routing_instance_id = routing_instance_id;

      /* Take one reference for p1. */
      peer->ike_sa_handle = ike_sa_handle;
      if (peer->ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
        peer->refcnt++;
      peer->debug_object.flags |= SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;

      if (local_id)
        peer->local_id = ssh_pm_ikev2_payload_id_dup(local_id);
      if (remote_id)
        peer->remote_id = ssh_pm_ikev2_payload_id_dup(remote_id);

      if (flags & SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1)
        peer->use_ikev1 = 1;

      if (flags & SSH_PM_PEER_CREATE_FLAGS_MANUAL_KEY)
        peer->manual_key = 1;

      if (force_ikev1_natt_draft_02 == TRUE)
        peer->ikev1_force_natt_draft_02 = 1;

#ifdef SSH_PM_BLACKLIST_ENABLED
      if (flags & SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK)
        peer->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

      peer->num_child_sas = 0;

      SSH_DEBUG(SSH_D_MIDOK,
                ("Allocating peer 0x%lx remote %@;%d local %@;%d "
                 "remote ID %@ local ID %@ ike_sa_handle 0x%lx [%s] "
                 "routing instance %d",
                 (unsigned long) peer->peer_handle,
                 ssh_ipaddr_render, remote_ip, (int) remote_port,
                 ssh_ipaddr_render, local_ip, (int) local_port,
                 ssh_pm_ike_id_render, peer->remote_id,
                 ssh_pm_ike_id_render, peer->local_id,
                 (unsigned long) peer->ike_sa_handle,
                 (peer->manual_key ? "manual" : ""),
                 (peer->use_ikev1 ? "ikev1" : ""),
                 peer->routing_instance_id));

      /* Insert into peer_handle_hash. */
      pm_peer_handle_hash_insert(pm, peer);

      /* Insert into peer_sa_hash. */
      pm_peer_sa_hash_insert(pm, peer);

      /* Insert into peer_addr_hash. */
      pm_peer_local_addr_hash_insert(pm, peer);
      pm_peer_remote_addr_hash_insert(pm, peer);

      return peer->peer_handle;
    }

  /* No free peer_handles available. */
  SSH_DEBUG(SSH_D_FAIL, ("Out of peer handles"));
  return SSH_IPSEC_INVALID_INDEX;
}

SshUInt32
ssh_pm_peer_create(SshPm pm,
                   SshIpAddr remote_ip, SshUInt16 remote_port,
                   SshIpAddr local_ip, SshUInt16 local_port,
                   SshPmP1 p1, Boolean manual_key,
                   SshVriId routing_instance_id)
{
  SshUInt32 flags = 0;
  Boolean force_ikev1_natt_draft_02 = FALSE;

  if (p1 != NULL)
    {
#ifdef SSHDIST_IKEV1
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
          flags |= SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;

          if (((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0
               && (p1->compat_flags & SSH_PM_COMPAT_NAT_T_DRAFT_02) != 0)
              || (p1->compat_flags & SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02) != 0)
            force_ikev1_natt_draft_02 = TRUE;
        }
#endif /* SSHDIST_IKEV1 */

#ifdef SSH_PM_BLACKLIST_ENABLED
      if (p1->enable_blacklist_check)
        flags |= SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */

      return ssh_pm_peer_create_internal(pm, remote_ip, remote_port,
                                         local_ip, local_port,
                                         p1->local_id, p1->remote_id,
                                         SSH_PM_IKE_SA_INDEX(p1),
                                         routing_instance_id,
                                         flags, force_ikev1_natt_draft_02);
    }
  else
    {
      if (manual_key == TRUE)
        flags |= SSH_PM_PEER_CREATE_FLAGS_MANUAL_KEY;

      return ssh_pm_peer_create_internal(pm, remote_ip, remote_port,
                                         local_ip, local_port,
                                         NULL, NULL, SSH_IPSEC_INVALID_INDEX,
                                         routing_instance_id,
                                         flags, force_ikev1_natt_draft_02);
    }
}

static void
pm_peer_destroy(SshPm pm, SshPmPeer peer)
{
  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(peer->refcnt > 0);

  peer->refcnt--;
  if (peer->refcnt > 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Freeing reference to peer 0x%lx, %d references left.",
                 (unsigned long) peer->peer_handle,
                 (int) peer->refcnt));
      return;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Destroying peer 0x%lx remote %@;%d local %@;%d "
             "ike_sa_handle 0x%lx num_child_sas %d",
             (unsigned long) peer->peer_handle,
             ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
             ssh_ipaddr_render, peer->local_ip, (int) peer->local_port,
             (unsigned long) peer->ike_sa_handle,
             (int) peer->num_child_sas));

  /* Remove from peer_handle_hash. */
  pm_peer_handle_hash_remove(pm, peer);

  /* Remove from peer_sa_hash. */
  pm_peer_sa_hash_remove(pm, peer);

  /* Remove from peer_addr_hash. */
  pm_peer_local_addr_hash_remove(pm, peer);
  pm_peer_remote_addr_hash_remove(pm, peer);

  /* Put peer back to freelist. */
  ssh_pm_peer_free(pm, peer);
}

void
ssh_pm_peer_handle_take_ref(SshPm pm, SshUInt32 peer_handle)
{
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  pm_peer_take_ref(ssh_pm_peer_by_handle(pm, peer_handle));
}

void
ssh_pm_peer_handle_destroy(SshPm pm, SshUInt32 peer_handle)
{
  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  pm_peer_destroy(pm, ssh_pm_peer_by_handle(pm, peer_handle));
}

/************************** Peer updating ***********************************/

static Boolean pm_peer_update_address(SshPm pm,
                                      SshPmPeer peer,
                                      SshIpAddr new_remote_ip,
                                      SshUInt16 new_remote_port,
                                      SshIpAddr new_local_ip,
                                      SshUInt16 new_local_port)
{
  SSH_ASSERT(peer != NULL);
  SSH_ASSERT(new_remote_ip != NULL);
  SSH_ASSERT(new_remote_port != 0);

  if (!SSH_IP_EQUAL(peer->remote_ip, new_remote_ip)
      || peer->remote_port != new_remote_port
      || !SSH_IP_EQUAL(peer->local_ip, new_local_ip)
      || peer->local_port != new_local_port)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Updating peer 0x%lx address remote %@;%d local %@;%d "
                 "to remote %@;%d local %@;%d",
                 (unsigned long) peer->peer_handle,
                 ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
                 ssh_ipaddr_render, peer->local_ip, (int) peer->local_port,
                 ssh_ipaddr_render, new_remote_ip, (int) new_remote_port,
                 ssh_ipaddr_render, new_local_ip, (int) new_local_port));

      /* Remove from peer_addr_hash. */
      pm_peer_local_addr_hash_remove(pm, peer);
      pm_peer_remote_addr_hash_remove(pm, peer);

      /* Update addresses and ports. */
      *peer->remote_ip = *new_remote_ip;
      peer->remote_port = new_remote_port;
      *peer->local_ip = *new_local_ip;
      peer->local_port = new_local_port;

      /* Insert into peer_addr_hash. */
      pm_peer_local_addr_hash_insert(pm, peer);
      pm_peer_remote_addr_hash_insert(pm, peer);
    }

  return TRUE;
}

Boolean
ssh_pm_peer_p1_update_address(SshPm pm,
                              SshPmP1 p1,
                              SshIpAddr new_remote_ip,
                              SshUInt16 new_remote_port,
                              SshIpAddr new_local_ip,
                              SshUInt16 new_local_port)
{
  SshPmPeer peer;

  SSH_ASSERT(p1 != NULL);

  /* There might be multiple IKE peers pointing to same IKE SA.
     It is also ok not to have any peers for p1. This means just
     that there are no IPsec SAs with this peer. */
  peer = ssh_pm_peer_by_p1(pm, p1);
  while (peer != NULL)
    {
      if (pm_peer_update_address(pm, peer, new_remote_ip, new_remote_port,
                                 new_local_ip, new_local_port) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to update addresses of peer %p",
                                 peer));
          return FALSE;
        }

      peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);
    }

  return TRUE;
}

Boolean
ssh_pm_peer_update_p1(SshPm pm, SshPmPeer peer, SshPmP1 new_p1)
{
  SshUInt32 new_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 old_ike_sa_handle = SSH_IPSEC_INVALID_INDEX;

  if (peer == NULL)
    return FALSE;

  if (new_p1 != NULL)
    {
      /* Fill in local and remote identities if they are not set. This may
         happen when importing IPsec SAs without a valid IKEv1 SA. */
      if (peer->local_id == NULL)
        peer->local_id = ssh_pm_ikev2_payload_id_dup(new_p1->local_id);
      if (peer->remote_id == NULL)
        peer->remote_id = ssh_pm_ikev2_payload_id_dup(new_p1->remote_id);

#ifdef SSH_PM_BLACKLIST_ENABLED
      /* Set peer's enable blacklist check flag if blacklist check is
         enabled for the new p1. */
      if (new_p1->enable_blacklist_check)
        peer->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

      new_ike_sa_handle =  SSH_PM_IKE_SA_INDEX(new_p1);
    }

  old_ike_sa_handle = peer->ike_sa_handle;

  if (old_ike_sa_handle == new_ike_sa_handle)
    return TRUE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Updating peer 0x%lx ike_sa_handle from 0x%lx to 0x%lx",
             (unsigned long) peer->peer_handle,
             (unsigned long) peer->ike_sa_handle,
             (unsigned long) new_ike_sa_handle));

  /* Update ike_sa_handle and peer_sa_hash. */
  pm_peer_sa_hash_remove(pm, peer);
  peer->ike_sa_handle = new_ike_sa_handle;
  peer->debug_object.flags |= SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;
  pm_peer_sa_hash_insert(pm, peer);

  /* Take one reference for the new IKE SA. */
  if (new_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
    pm_peer_take_ref(peer);

  /* Release the old IKE SA's reference. */
  if (old_ike_sa_handle != SSH_IPSEC_INVALID_INDEX)
    pm_peer_destroy(pm, peer);

  if (new_p1)
    pm_peer_update_address(pm, peer,
                           new_p1->ike_sa->remote_ip,
                           new_p1->ike_sa->remote_port,
                           new_p1->ike_sa->server->ip_address,
                           SSH_PM_IKE_SA_LOCAL_PORT(new_p1->ike_sa));

  return TRUE;
}

/**************************** Module cleanup ********************************/

void
ssh_pm_peers_uninit(SshPm pm)
{
  SshUInt32 hash;
  SshPmPeer peer;

  for (hash = 0; hash < SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE; hash++)
    {
      do
        {
          peer = pm->peer_handle_hash[hash];
          if (peer)
            {
















              pm_peer_destroy(pm, peer);
            }
        }
      while (peer != NULL);
      SSH_ASSERT(pm->peer_handle_hash[hash] == NULL);
    }
}

/**************************** Selective debug *******************************/

static void
pm_peer_debug_identify(SshPm pm, SshPmPeer peer)
{
  SshPdbgObject o = &peer->debug_object;
  unsigned char *l, *r;
  SshPmP1 p1;

  /* Show connection parameters only once. */
  if ((o->flags & SSH_PM_PEER_DEBUG_CONNECTION_SHOWN) == 0)
    {
      o->flags |= SSH_PM_PEER_DEBUG_CONNECTION_SHOWN;
      ssh_pdbg_output_connection(
        peer->local_ip, peer->local_port,
        peer->remote_ip, peer->remote_port);
    }

  /* Show IKE SPIs if they have changed since last shown. */
  if ((o->flags & SSH_PM_PEER_DEBUG_IKE_SA_CHANGED) != 0)
    {
      o->flags &= ~SSH_PM_PEER_DEBUG_IKE_SA_CHANGED;

      p1 = ssh_pm_p1_from_ike_handle(pm, peer->ike_sa_handle, FALSE);

      if (p1)
        {
          if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0)
            {
              l = p1->ike_sa->ike_spi_i;
              r = p1->ike_sa->ike_spi_r;
            }
          else
            {
              l = p1->ike_sa->ike_spi_r;
              r = p1->ike_sa->ike_spi_i;
            }

          ssh_pdbg_output_information(
            "Local-IKE-SPI: %.*@ Remote-IKE-SPI: %.*@",
            8, ssh_hex_render, l, 8, ssh_hex_render, r);
        }
    }
}

static void
pm_peer_debug_general(SshPm pm, SshPmPeer peer, const char *text)
{
  ssh_pdbg_output_event("IPSEC-CONN", &peer->debug_object, "%s", text);

  pm_peer_debug_identify(pm, peer);
}

static void
pm_peer_debug_ipsec_sa(SshPm pm,
                       SshPmPeer peer,
                       SshEngineTransformData trd,
                       SshIkev2PayloadTS ts_local,
                       SshIkev2PayloadTS ts_remote,
                       const char *text)
{
  ssh_pdbg_output_event(
    "IPSEC-CONN", &peer->debug_object, "IPsec SA %s", text);

  pm_peer_debug_identify(pm, peer);

  if (ts_local && ts_remote)
    {
      ssh_pdbg_output_information(
        "Local-Protected:%@", ssh_ikev2_ts_render, ts_local);

      ssh_pdbg_output_information(
        "Remote-Protected:%@", ssh_ikev2_ts_render, ts_remote);
    }

  if ((trd->transform & SSH_PM_IPSEC_ESP) != 0)
    {
      ssh_pdbg_output_information(
        "Protocol:ESP Inbound-SPI:%08x Outbound-SPI:%08x",
        (unsigned)trd->spis[SSH_PME_SPI_ESP_IN],
        (unsigned)trd->spis[SSH_PME_SPI_ESP_OUT]);
    }
  else if ((trd->transform & SSH_PM_IPSEC_AH) != 0)
    {
      ssh_pdbg_output_information(
        "Protocol:AH Inbound-SPI:%08x Outbound-SPI:%08x",
        (unsigned)trd->spis[SSH_PME_SPI_AH_IN],
        (unsigned)trd->spis[SSH_PME_SPI_AH_OUT]);
    }

  if ((trd->transform & SSH_PM_IPSEC_IPCOMP) != 0)
    {
      ssh_pdbg_output_information(
        "Protocol:IPCOMP Inbound-CPI:%04x Outbound-CPI:%04x",
        (unsigned)trd->spis[SSH_PME_SPI_IPCOMP_IN],
        (unsigned)trd->spis[SSH_PME_SPI_IPCOMP_OUT]);
    }
}

static Boolean
pm_peer_debug_enabled(SshPm pm, SshPmPeer peer, SshUInt32 level)
{
  SshPdbgConfig c = &pm->debug_config;
  SshPdbgObject o = &peer->debug_object;

  SshIpAddr l, r;

  if (peer == NULL)
    return FALSE;

  if (o->generation != c->generation)
    {
      if (o->level == 0)
        {
          l = peer->local_ip;
          r = peer->remote_ip;
          ssh_pdbg_object_update(c, o, l, r);
          if (o->level > 0)
            {
              *peer->debug_local = *l;
              *peer->debug_remote = *r;
            }
        }
      else
        {
          l = peer->debug_local;
          r = peer->debug_remote;
          ssh_pdbg_object_update(c, o, l, r);
        }
    }

  return o->level >= level;
}

void
ssh_pm_peer_debug_ipsec_sa_open(SshPm pm,
                                SshPmPeer peer,
                                SshPmQm qm)
{
  SshEngineTransformData trd = &qm->sa_handler_data.trd.data;
  SshPdbgBufferStruct b;
  SshPmCipher cipher;
  SshPmMac mac;
  SshPmCompression compr;
  const char *s, *cipher_name, *mac_name, *compr_name;

  if (!pm_peer_debug_enabled(pm, peer, 2))
    return;

  s = qm->rekey ? "rekeyed" : "opened";

  pm_peer_debug_ipsec_sa(pm, peer, trd, qm->local_ts, qm->remote_ts, s);

  if (qm->rekey)
    {
      ssh_pdbg_output_information(
        "Rekeyed-Inbound-SPI:%08x Rekeyed-Outbound-SPI:%08x",
        (unsigned)qm->old_inbound_spi, (unsigned)qm->old_outbound_spi);
    }

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "Algorithms:");

  if ((trd->transform & SSH_PM_IPSEC_ESP) != 0)
    {
      cipher = ssh_pm_ipsec_cipher(pm, 0, trd->transform);
      cipher_name = cipher ? cipher->name : "null";

      mac = ssh_pm_ipsec_mac(pm, 0, trd->transform);
      mac_name = mac ? mac->name : "null";

      ssh_pdbg_bprintf(&b, "%s,%s", cipher_name, mac_name);
    }

  if ((trd->transform & SSH_PM_IPSEC_AH) != 0)
    {
      mac = ssh_pm_ipsec_mac(pm, 0, trd->transform);
      mac_name = mac ? mac->name : "null";

      ssh_pdbg_bprintf(&b, "%s", mac_name);
    }

  if ((trd->transform & SSH_PM_IPSEC_IPCOMP) != 0)
    {
      compr = ssh_pm_compression(pm, 0, trd->transform);
      compr_name = compr ? compr->name : "null";

      ssh_pdbg_bprintf(&b, ",%s", compr_name);
    }

  if (qm->dh_group)
    ssh_pdbg_bprintf(&b, " PFS-Group:%d", (int)qm->dh_group);

  ssh_pdbg_output_information(ssh_pdbg_bstring(&b));

  ssh_pdbg_bclear(&b);
  ssh_pdbg_bprintf(&b, "Flags:");

  if ((trd->transform & SSH_PM_IPSEC_TUNNEL) != 0)
    ssh_pdbg_bprintf(&b, "Tunnel");
  else
    ssh_pdbg_bprintf(&b, "Transport");

  if ((trd->transform & SSH_PM_IPSEC_NATT) != 0)
    ssh_pdbg_bprintf(&b, ",NAT-T");

  if ((trd->transform & SSH_PM_IPSEC_LONGSEQ) != 0)
    ssh_pdbg_bprintf(&b, ",Seq-64");

  if ((trd->transform & SSH_PM_IPSEC_L2TP) != 0)
    ssh_pdbg_bprintf(&b, ",L2TP");

  ssh_pdbg_output_information(ssh_pdbg_bstring(&b));
}

void
ssh_pm_peer_debug_ipsec_sa_close(SshPm pm,
                                 SshPmPeer peer, SshEngineTransformData trd)
{
  if (!pm_peer_debug_enabled(pm, peer, 2))
    return;

  pm_peer_debug_ipsec_sa(pm, peer, trd, NULL, NULL, "closed");
}

void
ssh_pm_peer_debug_error_local(SshPm pm, SshPmPeer peer, const char *text)
{
  if (!pm_peer_debug_enabled(pm, peer, 1))
    return;

  pm_peer_debug_general(pm, peer, "local error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}

void
ssh_pm_peer_debug_error_remote(SshPm pm, SshPmPeer peer, const char *text)
{
  if (!pm_peer_debug_enabled(pm, peer, 1))
    return;

  pm_peer_debug_general(pm, peer, "remote error");

  ssh_pdbg_output_information("Error:\"%s\"", text);
}
