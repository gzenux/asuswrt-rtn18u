/**
   @copyright
   Copyright (c) 2005 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
    SPI management for IPSec SA's.

    The SPI's for manually keyed and dynamically keyed (via. IKE) SA's are
    managed together. Inbound SPI's are always unique across different
    IP protocols (i.e. the value of an inbound ESP SPI is never equal to
    the value of an inbound AH SPI). Inbound SPI values are registered to
    the ADT container pm->inbound_spis. Outbound SPI's for IKE SA's are
    stored in the pm->spi_out_hash hash table. The remote IP address,
    remote IKE port and IP protocol is also stored in the mapping.
    This mapping is used for handling IPSec delete notifications.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmIkeSPI"


/************* ADT containers for inbound and unknown SPI's ******************/


/* Hash function for SPI values. */
#define SSH_PM_SPI_HASH(spi) \
  ((spi) + 3 * ((spi) >> 8) + 7 * ((spi) >> 16) + 11 * ((spi) >> 24))

static SshUInt32
pm_spi_in_hash(void *ptr, void *ctx)
{
  SshPmSpiIn item = (SshPmSpiIn) ptr;

  return SSH_PM_SPI_HASH(item->spi);
}

static int
pm_spi_in_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmSpiIn item1 = (SshPmSpiIn) ptr1;
  SshPmSpiIn item2 = (SshPmSpiIn) ptr2;

  return (int)(item1->spi - item2->spi);
}

static void
pm_spi_in_destroy(void *ptr, void *ctx)
{
  return;
}


/************************* Hashtables for outbound SPI's ********************/

#define SSH_PM_SPI_OUT_SPI_HASH(spi_value) \
  (SSH_PM_SPI_HASH(spi_value) % SSH_PM_SPI_OUT_HASH_TABLE_SIZE)

static void
pm_spi_out_spi_hash_insert(SshPm pm, SshPmSpiOut spi)
{
  SshUInt32 hash;

  SSH_ASSERT(spi->hash_spi_next == NULL);

  /* Compute the hash value. */
  hash = SSH_PM_SPI_OUT_SPI_HASH(spi->outbound_spi);

  /* Insert it into the hash table. */
  spi->hash_spi_next = pm->spi_out_spi_hash[hash];
  pm->spi_out_spi_hash[hash] = spi;
}

static void
pm_spi_out_spi_hash_remove(SshPm pm, SshPmSpiOut spi, SshPmSpiOut prev_spi)
{
  /* Remove the SPI from the hash table. */
  if (prev_spi)
    prev_spi->hash_spi_next = spi->hash_spi_next;
  else
    {
      SshUInt32 hash;

      /* Count the hash value. */
      hash = SSH_PM_SPI_OUT_SPI_HASH(spi->outbound_spi);

      if (pm->spi_out_spi_hash[hash] == spi)
        /* The SPI `spi' was in the hash table. */
        pm->spi_out_spi_hash[hash] = spi->hash_spi_next;
    }
  spi->hash_spi_next = NULL;
}


/*********************** Creating and destroying SPI mappings ****************/

/* Init ADT container of inbound and unknown SPI's.
   Return TRUE if successful. */
Boolean
ssh_pm_spis_create(SshPm pm)
{
  pm->inbound_spis =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmSpiInStruct,
                                             adt_header),
                           SSH_ADT_HASH,      pm_spi_in_hash,
                           SSH_ADT_COMPARE,   pm_spi_in_compare,
                           SSH_ADT_DESTROY,   pm_spi_in_destroy,
                           SSH_ADT_CONTEXT,   pm,
                           SSH_ADT_ARGS_END);
  if (pm->inbound_spis == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating SPI freelist"));
      return FALSE;
    }
  return TRUE;
}

void
ssh_pm_spis_destroy(SshPm pm)
{
  SshUInt32 hash;
  SshADTHandle h;
  SshPmSpiIn spi_in;
  SshPmSpiOut spi_out;

  if (pm->inbound_spis)
    {
      while ((h = ssh_adt_enumerate_start(pm->inbound_spis)) !=
             SSH_ADT_INVALID)
        {
          spi_in = ssh_adt_get(pm->inbound_spis, h);
          SSH_ASSERT(spi_in != NULL);
          ssh_adt_detach(pm->inbound_spis, h);
          ssh_pm_spi_in_free(pm, spi_in);
        }
      SSH_ASSERT(ssh_adt_num_objects(pm->inbound_spis) == 0);
      ssh_adt_destroy(pm->inbound_spis);
    }
  pm->inbound_spis = NULL;

  for (hash = 0; hash < SSH_PM_SPI_OUT_HASH_TABLE_SIZE; hash++)
    {
      while (pm->spi_out_spi_hash[hash] != NULL)
        {
          spi_out = pm->spi_out_spi_hash[hash];
          pm->spi_out_spi_hash[hash] = spi_out->hash_spi_next;
          ssh_pm_spi_out_free(pm, spi_out);
        }
    }
}


/**************  Inbound SPI allocation and freeing ***********************/

/* Allocate a new SPI, return zero on error. */
static SshUInt32
pm_allocate_inbound_spi(SshPm pm,
                        SshUInt32 min_spi,
                        SshUInt32 max_spi,
                        Boolean for_esp)

{
  unsigned char array[4];
  SshPmSpiIn spi_in;
  SshUInt32 attempts, i;

  spi_in = ssh_pm_spi_in_alloc(pm);
  if (spi_in == NULL)
    return 0;

  attempts = 0;
  while (attempts < 1000)
    {
      attempts++;

      for (i = 0; i < 4; i++)
        array[i] = ssh_random_get_byte();

      spi_in->spi = SSH_GET_32BIT(array);

      spi_in->spi %= (max_spi - min_spi + 1);
      spi_in->spi += min_spi;
      SSH_ASSERT(spi_in->spi >= min_spi && spi_in->spi <= max_spi);
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Never allocate the bit sequence `0010' for the SPI bits 27-24
         for inbound ESP SPI.  This is needed to distinguish between
         different NAT-T drafts.  If this is changed, you must also
         modify the inbound UDP 500 traffic handling at the
         engine_flow_id.c:ssh_engine_compute_flow_id() function. */
      if (for_esp && (spi_in->spi & 0x0f000000) == 0x02000000)
        continue;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Check if this SPI value is known, if so then try again. */
      if (ssh_adt_get_handle_to_equal(pm->inbound_spis, spi_in)
          != SSH_ADT_INVALID)
        continue;

      /* OK, this SPI is unique. Insert it to the ADT mapping. */
      ssh_adt_insert(pm->inbound_spis, spi_in);
      return spi_in->spi;
    }

  /* No SPI available */
  ssh_pm_spi_in_free(pm, spi_in);
  return 0;
}

static void pm_free_inbound_spi(SshPm pm, SshUInt32 spi)
{
  SshPmSpiInStruct probe, *spi_in;
  SshADTHandle h;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing inbound SPI 0x%08lx",
                               (unsigned long) spi));

  memset(&probe, 0, sizeof(probe));
  probe.spi = spi;

  h = ssh_adt_get_handle_to_equal(pm->inbound_spis, &probe);

  if (h != SSH_ADT_INVALID)
    {
      spi_in = ssh_adt_get(pm->inbound_spis, h);
      SSH_ASSERT(spi_in != NULL);
      SSH_ASSERT(spi_in->spi == spi);
      ssh_adt_detach(pm->inbound_spis, h);
      ssh_pm_spi_in_free(pm, spi_in);
    }
  else
    SSH_DEBUG(SSH_D_FAIL, ("The inbound SPI 0x%08lx is unknown",
                           (unsigned long) spi));
}


/************************ Outbound SPI lookup *******************************/

SshPmSpiOut
ssh_pm_lookup_outbound_spi_by_inbound_spi(SshPm pm,
                                          SshUInt32 outbound_spi,
                                          SshUInt32 inbound_spi)
{
  SshPmSpiOut spi_out;
  SshUInt32 hash;

  SSH_DEBUG(SSH_D_LOWOK,
            ("SPI lookup for outbound SPI 0x%08lx, inbound SPI 0x%08lx",
             (unsigned long) outbound_spi, (unsigned long) inbound_spi));

  hash = SSH_PM_SPI_OUT_SPI_HASH(outbound_spi);

  for (spi_out = pm->spi_out_spi_hash[hash];
       spi_out != NULL;
       spi_out = spi_out->hash_spi_next)
    {
      if (spi_out->outbound_spi == outbound_spi &&
          spi_out->inbound_spi == inbound_spi)
        break;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Returning spi_out object %p", spi_out));

  return spi_out;
}



/***********************************************************************/
/*                      External functions.                            */
/***********************************************************************/

SshPmSpiOut
ssh_pm_lookup_outbound_spi(SshPm pm, Boolean match_address,
                           SshUInt32 spi, SshUInt8 ipproto,
                           SshIpAddr remote_ip,
                           SshUInt16 remote_ike_port,
                           SshVriId routing_instance_id)
{
  SshPmSpiOut spi_out;
  SshUInt32 hash;
  SshPmPeer peer;

  SSH_DEBUG(SSH_D_LOWOK, ("Outbound SPI lookup for SPI %@-%08lx "
                          "remote %@:%d, match_address %d, "
                          "routing instance %d",
                          ssh_ipproto_render, (SshUInt32) ipproto,
                          (unsigned long) spi,
                          ssh_ipaddr_render, remote_ip, (int) remote_ike_port,
                          match_address, routing_instance_id));

  hash = SSH_PM_SPI_OUT_SPI_HASH(spi);

  for (spi_out = pm->spi_out_spi_hash[hash];
       spi_out != NULL;
       spi_out = spi_out->hash_spi_next)
    {
      peer = ssh_pm_peer_by_handle(pm, spi_out->peer_handle);
      if (match_address)
        {
          if (peer
              && (peer->routing_instance_id == routing_instance_id)
              && SSH_IP_EQUAL(peer->remote_ip, remote_ip)
              && (remote_ike_port == 0 || peer->remote_port == remote_ike_port)
              && spi_out->outbound_spi == spi
              && spi_out->ipproto == ipproto)
            break;
        }
      else
        {
          if (peer
              && peer->routing_instance_id == routing_instance_id
              && spi_out->outbound_spi == spi
              && spi_out->ipproto == ipproto)
            break;
        }
    }

  if (spi_out == NULL)
    SSH_DEBUG(SSH_D_UNCOMMON,
              ("No outbound SPI object found for SPI value %@-%08lx",
               ssh_ipproto_render, (SshUInt32) ipproto,
               (unsigned long) spi));

  return spi_out;
}

Boolean ssh_pm_allocate_spis(SshPm pm, SshUInt32 spibits, SshUInt32 spis[3])
{
  int i;

  SSH_ASSERT(spis != NULL);
  SSH_ASSERT(spibits != 0);

  /* Allocate new entries for the inbound spi's in pm->inbound_spis. */
  for (i = 0; i < 3; i++)
    spis[i] = 0;

  /* Allocate ESP if requested. */
  if (spibits & (1 << SSH_PME_SPI_ESP_IN))
    {
      spis[SSH_PME_SPI_ESP_IN] =
        pm_allocate_inbound_spi(pm,
                                SSH_ENGINE_INBOUND_SPI_MAX_MANUAL,
                                0xffffffff, TRUE);
      if (spis[SSH_PME_SPI_ESP_IN] == 0)
        return FALSE;
    }

  /* Allocate AH if requested. */
  if (spibits & (1 << SSH_PME_SPI_AH_IN))
    {
      spis[SSH_PME_SPI_AH_IN] =
        pm_allocate_inbound_spi(pm,
                                SSH_ENGINE_INBOUND_SPI_MAX_MANUAL,
                                0xffffffff, FALSE);
      if (spis[SSH_PME_SPI_AH_IN] == 0)
        return FALSE;
    }

  /* Allocate IPCOMP if requested. */
  if (spibits & (1 << SSH_PME_SPI_IPCOMP_IN))
    {
      spis[SSH_PME_SPI_IPCOMP_IN] =
        pm_allocate_inbound_spi(pm, 256, 61439, FALSE);
      if (spis[SSH_PME_SPI_IPCOMP_IN] == 0)
        return FALSE;
    }

  return TRUE;
}

Boolean ssh_pm_register_inbound_spis(SshPm pm, const SshUInt32 spis[3])
{
  SshPmSpiIn spi_in[3];
  int i;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registering inbound spis 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) spis[0], (unsigned long) spis[1],
             (unsigned long) spis[2]));

  spi_in[0] = spi_in[1] = spi_in[2] = NULL;

  for (i = 0; i < 3; i++)
    {
      if (spis[i] == 0)
        continue;

      spi_in[i] = ssh_pm_spi_in_alloc(pm);
      if (spi_in[i] == NULL)
        goto error;

      spi_in[i]->spi = spis[i];

      if (ssh_adt_get_handle_to_equal(pm->inbound_spis, spi_in[i])
          != SSH_ADT_INVALID)
        goto error;
    }

  for (i = 0; i < 3; i++)
    {
      if (spi_in[i] != NULL)
        ssh_adt_insert(pm->inbound_spis, spi_in[i]);
    }

  return TRUE;

 error:
  for (i = 0; i < 3; i++)
    {
      if (spi_in[i] != NULL)
        ssh_pm_spi_in_free(pm, spi_in[i]);
    }

  return FALSE;
}


void ssh_pm_free_spis(SshPm pm, const SshUInt32 spis[3])
{
  SshUInt32 i, spi;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Freeing inbound spis 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) spis[0],
             (unsigned long) spis[1],
             (unsigned long) spis[2]));

  /* Loop over the array, freeing and zeroing all valid SPIs. */
  for (i = 0; i < 3; i++)
    {
      spi = spis[i];
      if (spi != 0 && spi != SSH_IPSEC_SPI_IKE_ERROR_RESERVED)
        pm_free_inbound_spi(pm, spi);
    }
  return;
}


/************** Management of outbound SPI's **********************/

Boolean ssh_pm_register_outbound_spi(SshPm pm, SshPmQm qm)
{
  SshPmSpiOut spi_out;
  SshPmPeer peer;

  peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
  if (peer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No peer found for peer handle 0x%lx",
                             (unsigned long) qm->peer_handle));
      return FALSE;
    }

  spi_out = ssh_pm_spi_out_alloc(pm);
  if (spi_out == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate outbound spi object"));
      return FALSE;
    }

  spi_out->trd_index = qm->trd_index;
  spi_out->peer_handle = qm->peer_handle;

  if (qm->transform & SSH_PM_IPSEC_AH)
    {
      spi_out->ipproto = SSH_IPPROTO_AH;

      spi_out->inbound_spi =
        qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_AH_IN];
      spi_out->outbound_spi =
        qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_AH_OUT];
    }
  else if (qm->transform & SSH_PM_IPSEC_ESP)
    {
      spi_out->ipproto = SSH_IPPROTO_ESP;

      spi_out->inbound_spi =
        qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_ESP_IN];
      spi_out->outbound_spi =
        qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_ESP_OUT];
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid transform (not ESP and not AH)"));
      ssh_pm_spi_out_free(pm, spi_out);
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registering outbound spi object %p: outbound SPI %@-%08lx, "
             "inbound SPI %@-%08lx, trd index %x, peer 0x%lx",
             spi_out,
             ssh_ipproto_render, (SshUInt32) spi_out->ipproto,
             (unsigned long) spi_out->outbound_spi,
             ssh_ipproto_render, (SshUInt32) spi_out->ipproto,
             (unsigned long) spi_out->inbound_spi,
             (unsigned int) spi_out->trd_index,
             (unsigned long) spi_out->peer_handle));

  /* OK, Insert the outbound SPI to the hashtable. */
  spi_out->hash_spi_next = NULL;
  pm_spi_out_spi_hash_insert(pm, spi_out);

  /* Add the SPI to peer's linked list. */
  spi_out->peer_spi_next = peer->spi_out;
  peer->spi_out = spi_out;

  return TRUE;
}


Boolean
ssh_pm_spi_mark_rekeyed(SshPm pm,
                        SshUInt32 outbound_spi,
                        SshUInt32 inbound_spi)
{
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                      inbound_spi);
  if (spi_out == NULL)
    return FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Successfully marked SPI %08lx-%08lx as rekeyed",
             (unsigned long) inbound_spi,
             (unsigned long) outbound_spi));

  spi_out->rekeyed = 1;
  return TRUE;
}

Boolean
ssh_pm_spi_mark_neg_started(SshPm pm,
                            SshUInt32 outbound_spi,
                            SshUInt32 inbound_spi)
{
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                      inbound_spi);
  if (spi_out == NULL)
    return FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Successfully marked SPI %08lx-%08lx as negotiation ongoing",
             (unsigned long) inbound_spi,
             (unsigned long) outbound_spi));

  spi_out->neg_in_progress = 1;
  return TRUE;
}

Boolean
ssh_pm_spi_mark_neg_finished(SshPm pm,
                             SshUInt32 outbound_spi,
                             SshUInt32 inbound_spi)
{
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                      inbound_spi);
  if (spi_out == NULL)
    return FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Successfully marked SPI %08lx-%08lx as negotiation finished",
             (unsigned long) inbound_spi,
             (unsigned long) outbound_spi));

  spi_out->neg_in_progress = 0;
  return TRUE;
}

Boolean
ssh_pm_spi_neg_ongoing(SshPm pm,
                       SshUInt32 outbound_spi,
                       SshUInt32 inbound_spi)
{
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                      inbound_spi);
  if (spi_out == NULL || spi_out->neg_in_progress == 0)
    return FALSE;

  return TRUE;
}

void
ssh_pm_spi_mark_delete_received(SshPm pm,
                                SshUInt32 outbound_spi,
                                SshUInt8 ipproto,
                                const SshIpAddr remote_ip,
                                SshUInt16 remote_ike_port,
                                SshVriId routing_instance_id)
{
  SshPmSpiOut spi_out;
  SshPmSpiInStruct probe, *spi_in;
  SshADTHandle h;

  spi_out = ssh_pm_lookup_outbound_spi(pm, TRUE, outbound_spi, ipproto,
                                       remote_ip, remote_ike_port,
                                       routing_instance_id);
  if (spi_out != NULL)
    {
      memset(&probe, 0, sizeof(probe));
      probe.spi = spi_out->inbound_spi;

      h = ssh_adt_get_handle_to_equal(pm->inbound_spis, &probe);
      if (h != SSH_ADT_INVALID)
        {
          spi_in = ssh_adt_get(pm->inbound_spis, h);
          SSH_ASSERT(spi_in != NULL);
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Marking spi delete notification received for "
                     "outbound SPI %@-%08lx",
                     ssh_ipproto_render, (SshUInt32) ipproto,
                     (unsigned long) outbound_spi));
          spi_in->delete_received = 1;
        }
    }
}

Boolean
ssh_pm_spi_check_delete_received(SshPm pm, SshUInt32 inbound_spi)
{
  SshPmSpiInStruct probe, *spi_in;
  SshADTHandle h;

  memset(&probe, 0, sizeof(probe));
  probe.spi = inbound_spi;

  h = ssh_adt_get_handle_to_equal(pm->inbound_spis, &probe);
  if (h != SSH_ADT_INVALID)
    {
      spi_in = ssh_adt_get(pm->inbound_spis, h);
      SSH_ASSERT(spi_in != NULL);
      SSH_ASSERT(spi_in->spi == inbound_spi);
      return (spi_in->delete_received == 1);
    }

  /* If inbound SPI was not found then return TRUE to indicate that
     the SPI has already been deleted and no delete notifications need
     to be sent. */
  return TRUE;
}

Boolean
ssh_pm_spi_disable_sa_events(SshPm pm,
                             SshUInt32 outbound_spi,
                             SshUInt32 inbound_spi,
                             Boolean disable)
{
  SshPmSpiOut spi_out;

  spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                      inbound_spi);
  if (spi_out == NULL || spi_out->disable_sa_events)
    return FALSE;

  if (disable)
    spi_out->disable_sa_events = 1;

  return TRUE;
}

void ssh_pm_spi_in_remove_by_trd(SshPm pm, SshEngineTransformData trd,
                                 Boolean old)
{
  int i;

  if (old == TRUE)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Freeing old inbound SPI's %08lx %08lx %08lx",
               (unsigned long) trd->old_spis[0],
               (unsigned long) trd->old_spis[1],
               (unsigned long) trd->old_spis[2]));
  else
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Freeing inbound SPI's %08lx %08lx %08lx",
               (unsigned long) trd->spis[0],
               (unsigned long) trd->spis[1],
               (unsigned long) trd->spis[2]));

  for (i = 0; i < 3; i++)
    {
      if (old == TRUE)
        {
          if (trd->old_spis[i] == 0)
            continue;
          pm_free_inbound_spi(pm, trd->old_spis[i]);
        }
      else
        {
          if (trd->spis[i] == 0)
            continue;
          pm_free_inbound_spi(pm, trd->spis[i]);
        }
    }
}

void ssh_pm_spi_out_remove(SshPm pm,
                           SshUInt32 trd_index,
                           SshUInt32 outbound_spi)
{
  SshPmSpiOut spi_out, prev_spi_out;
  SshUInt32 hash;
  SshPmPeer peer;

  /* The check for zero SPI is here for conviniency reasons. */
  if (outbound_spi == 0)
    return;

  /* Lookup spi_out from the SPI hash table. */
  hash = SSH_PM_SPI_OUT_SPI_HASH(outbound_spi);

  for (prev_spi_out = NULL, spi_out = pm->spi_out_spi_hash[hash];
       spi_out != NULL;
       prev_spi_out = spi_out, spi_out = spi_out->hash_spi_next)
    {
      if (spi_out->outbound_spi == outbound_spi
          && spi_out->trd_index == trd_index)
        {
          /* Remove spi_out from SPI hash table. */
          pm_spi_out_spi_hash_remove(pm, spi_out, prev_spi_out);

          peer = ssh_pm_peer_by_handle(pm, spi_out->peer_handle);
          if (peer != NULL)
            {
              /* Remove spi_out from peer's list. This reuses prev_spi_out. */
              if (peer->spi_out == spi_out)
                {
                  peer->spi_out = spi_out->peer_spi_next;
                }
              else
                {
                  for (prev_spi_out = peer->spi_out;
                       prev_spi_out != NULL
                         && prev_spi_out->peer_spi_next != NULL;
                       prev_spi_out = prev_spi_out->peer_spi_next)
                    {
                      if (prev_spi_out->peer_spi_next == spi_out)
                        {
                          prev_spi_out->peer_spi_next = spi_out->peer_spi_next;
                          break;
                        }
                    }
                }
            }

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Outbound SPI removed for transform: %@-%08lx gw %@",
                     ssh_ipproto_render, (SshUInt32) spi_out->ipproto,
                     (unsigned long) outbound_spi,
                     ssh_ipaddr_render,
                     (peer != NULL ? peer->remote_ip : NULL)));

          ssh_pm_spi_out_free(pm, spi_out);
          return;
        }
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Outbound SPI 0x%08lx (transform index 0x%lx) not found",
             (unsigned long) outbound_spi,
             (unsigned long) trd_index));
}

SshUInt32
ssh_pm_peer_handle_by_spi_out(SshPm pm, SshUInt32 spi, SshUInt32 trd_index)
{
  SshPmSpiOut spi_out;
  SshUInt32 hash;

  hash = SSH_PM_SPI_OUT_SPI_HASH(spi);

  for (spi_out = pm->spi_out_spi_hash[hash];
       spi_out != NULL;
       spi_out = spi_out->hash_spi_next)
    {
      if (spi_out->trd_index == trd_index)
        return spi_out->peer_handle;
    }

  return SSH_IPSEC_INVALID_INDEX;
}

/** Lookup inbound SPI value for `trd_index' using `outbound_spi'. */
SshUInt32
ssh_pm_spi_in_by_trd(SshPm pm, SshUInt32 outbound_spi, SshUInt32 trd_index)
{
  SshPmSpiOut spi_out;
  SshUInt32 hash;

  hash = SSH_PM_SPI_OUT_SPI_HASH(outbound_spi);

  for (spi_out = pm->spi_out_spi_hash[hash];
       spi_out != NULL;
       spi_out = spi_out->hash_spi_next)
    {
      if (spi_out->trd_index == trd_index)
        return spi_out->inbound_spi;
    }

  return 0;
}
