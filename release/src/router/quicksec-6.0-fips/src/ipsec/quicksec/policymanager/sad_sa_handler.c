/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec SA handler.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmSaHandler"


/***************************** IPSec SA handler *****************************/

static Boolean
pm_ipsec_sa_keymat(SshPm pm, SshPmP1 p1, SshPmQm qm, SshIkev2ExchangeData ed)
{
  SshEngineTransformData trd = &qm->sa_handler_data.trd.data;
  SshIkev2PayloadTransform trans;
  Boolean initiator;
  char keysizebuf[8] = {0};
  size_t mac_key_size, mac_nonce_size;
  size_t cipher_key_size, cipher_nonce_size;
  size_t keymat_len;
  SshPmMac mac;
  SshPmCipher cipher;
  int keyoff;
  unsigned char keymat[SSH_IPSEC_MAX_KEYMAT_LEN * 2];
  Boolean ipv6_gw;

  /* Key material generation takes initiator information from the
     exchange, not from the IKE SA. For the IKEv1 keymaterial is
     components are taken symmetrically for initiator and responder,
     and we splice is as in responder. */

#ifdef SSHDIST_IKEV1
  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    initiator = 0;
  else
#endif /* SSHDIST_IKEV1 */
    initiator = qm->initiator;

  mac = NULL;
  mac_key_size = 0;
  cipher = NULL;
  cipher_key_size = 0;
  cipher_nonce_size = 0;

  switch (ed->ipsec_ed->ipsec_sa_protocol)
    {
    case SSH_IKEV2_PROTOCOL_ID_AH:
      trd->transform |= SSH_PM_IPSEC_AH;
      break;
    case SSH_IKEV2_PROTOCOL_ID_ESP:
      trd->transform |= SSH_PM_IPSEC_ESP;
      break;
    default:
      SSH_DEBUG(SSH_D_ERROR,
                ("Trying to install protocol that is not AH or ESP"));
      return FALSE;
    }

  /* ENCR */
  trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR];
  if (trans != NULL)
    {
      SSH_ASSERT(trd->transform & SSH_PM_IPSEC_ESP);
      trd->spis[SSH_PME_SPI_ESP_IN] = ed->ipsec_ed->spi_inbound;
      trd->spis[SSH_PME_SPI_ESP_OUT] = ed->ipsec_ed->spi_outbound;

      cipher = ssh_pm_ipsec_cipher_by_id(pm, trans->id);
      if (cipher == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unsupported cipher with transform id %d",
                                 trans->id));
          goto error;
        }

      if (trans->transform_attribute & 0x800e0000)
        {
          cipher_key_size = (trans->transform_attribute & 0xffff) / 8;
          ssh_snprintf(keysizebuf, sizeof(keysizebuf), "/%u",
                       (unsigned int) (cipher_key_size * 8));
        }
      else
        {
          cipher_key_size = cipher->default_key_size / 8;
        }

      /* The nonce for counter mode */
      cipher_nonce_size = cipher->nonce_size / 8;

      /* Store the cipher key, iv, nonce and ICV size to the
         transform data. */
      trd->transform |= cipher->mask_bits;
      trd->cipher_key_size = cipher_key_size;
      trd->cipher_iv_size = cipher->iv_size / 8;
      trd->cipher_nonce_size = cipher_nonce_size;
    }

  /* Integrity */
  trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG];
  if (trans != NULL && trans->id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
      SSH_ASSERT(trd->transform & (SSH_PM_IPSEC_ESP|SSH_PM_IPSEC_AH));

      if (trd->transform & SSH_PM_IPSEC_AH)
        {
          trd->spis[SSH_PME_SPI_AH_IN] = ed->ipsec_ed->spi_inbound;
          trd->spis[SSH_PME_SPI_AH_OUT] = ed->ipsec_ed->spi_outbound;

          mac = ssh_pm_ipsec_mac_by_id(pm, trans->id);
          if (mac == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Unsupported AH mac, transform id %d",
                                     trans->id));
              goto error;
            }
        }
      else
        {
          mac = ssh_pm_ipsec_mac_by_id(pm, trans->id);
          if (mac == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Unsupported Auth mac, transform id %d",
                                     trans->id));
              goto error;
            }
        }

      mac_key_size = mac->default_key_size / 8;
      mac_nonce_size = mac->nonce_size / 8;
      trd->transform |= mac->mask_bits[1];
      if (mac_nonce_size != 0)
        {
          /* If MAC is using nonce, we must be using combined cipher as MAC
             in AH. */
          SSH_ASSERT(cipher_key_size == 0);
          cipher_key_size = mac_key_size;
          trd->cipher_iv_size = 8; /* According to gmac-aes. */
          cipher_nonce_size = mac_nonce_size;
          mac_key_size = 0;
          trd->cipher_key_size = cipher_key_size;
          trd->cipher_nonce_size = cipher_nonce_size;
        }
      trd->mac_key_size = mac_key_size;
    }

  /* D-H */
  trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H];
  if (trans != NULL)
    {
      /* Just record the group PFS was made on. */
      qm->dh_group = trans->id;
    }

  /* ESN */
  trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN];
  if (trans != NULL)
    {
      if (trans->id == SSH_IKEV2_TRANSFORM_ESN_ESN)
        trd->transform |= SSH_PM_IPSEC_LONGSEQ;
    }

  ipv6_gw = SSH_IP_IS6(&trd->gw_addr);

#ifdef SSHDIST_IPSEC_MOBIKE
#ifdef WITH_IPV6
  /* For MOBIKE enabled IKE SAs calculate the packet enlargement assuming
     IPv6 outer header. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    ipv6_gw = TRUE;
#endif /* WITH_IPV6 */
#endif /* SSHDIST_IPSEC_MOBIKE */

  /* Compute packet enlargement for this transform. */
  trd->packet_enlargement =
    ssh_pm_compute_trd_packet_enlargement(pm, trd->transform, ipv6_gw,
                                          cipher, mac);

  keymat_len = mac_key_size +
               cipher_key_size + cipher_nonce_size;

  SSH_ASSERT((2 * keymat_len) <= sizeof(keymat));

  if (ssh_ikev2_fill_keymat(ed, keymat, 2 * keymat_len) != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot generate key material"));
      goto error;
    }

  /* in ESP */
  keyoff  = 0;
  memcpy(trd->keymat + keyoff, keymat + ((initiator) ? keymat_len : 0),
         cipher_key_size);

  if (cipher_nonce_size)
    memcpy(trd->keymat + keyoff + cipher_key_size, keymat + ((initiator)
                     ? keymat_len + cipher_key_size : 0 + cipher_key_size),
           cipher_nonce_size);

  /* in MAC */
  keyoff  += SSH_IPSEC_MAX_ESP_KEY_BITS / 8;
  memcpy(trd->keymat + keyoff,
         keymat + ((initiator)
                   ? keymat_len + cipher_key_size + cipher_nonce_size
                   : 0 + cipher_key_size + cipher_nonce_size),
         mac_key_size);

  /* Out ESP */
  keyoff = SSH_IPSEC_MAX_KEYMAT_LEN / 2;
  memcpy(trd->keymat + keyoff, keymat + ((initiator) ? 0 : keymat_len),
         cipher_key_size);

  if (cipher_nonce_size)
    memcpy(trd->keymat + keyoff + cipher_key_size,
           keymat + ((initiator)
                     ? 0 + cipher_key_size
                     : keymat_len + cipher_key_size),
           cipher_nonce_size);

  /* Out MAC */
  keyoff += SSH_IPSEC_MAX_ESP_KEY_BITS / 8;
  memcpy(trd->keymat + keyoff, keymat + ((initiator)
                   ? 0 + cipher_key_size + cipher_nonce_size
                   : keymat_len + cipher_key_size + cipher_nonce_size),
         mac_key_size);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("ESP cipher key for inbound SA [0x%08lx]",
                     (unsigned long) trd->spis[SSH_PME_SPI_ESP_IN]),
                    trd->keymat, cipher_key_size);

  if (cipher_nonce_size)
    SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                      ("ESP cipher nonce for inbound SA [0x%08lx]",
                       (unsigned long) trd->spis[SSH_PME_SPI_ESP_IN]),
                      trd->keymat + cipher_key_size,
                      cipher_nonce_size);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("ESP auth key for inbound SA [0x%08lx]",
                     (unsigned long) trd->spis[SSH_PME_SPI_ESP_IN]),
                    trd->keymat + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
                    mac_key_size);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("ESP cipher key for outbound SA [0x%08lx]",
                     (unsigned long) trd->spis[SSH_PME_SPI_ESP_OUT]),
                    trd->keymat + SSH_IPSEC_MAX_KEYMAT_LEN / 2,
                    cipher_key_size);

  if (cipher_nonce_size)
    SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                      ("ESP cipher nonce for outbound SA [0x%08lx]",
                       (unsigned long) trd->spis[SSH_PME_SPI_ESP_OUT]),
                      trd->keymat +
                      (SSH_IPSEC_MAX_KEYMAT_LEN / 2) + cipher_key_size,
                      cipher_nonce_size);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART,
                    ("ESP auth key for outbound SA [0x%08lx]",
                     (unsigned long) trd->spis[SSH_PME_SPI_ESP_OUT]),
                    trd->keymat +
                    ((SSH_IPSEC_MAX_KEYMAT_LEN / 2) +
                     (SSH_IPSEC_MAX_ESP_KEY_BITS / 8)),
                    mac_key_size);

  memset(keymat, 0, sizeof(keymat));

  /* Compute additional packet enlargement from outer tunnels. */
  if (qm->tunnel->outer_tunnel != NULL)
    {
      SshPmTunnel outer_tunnel;
      SshUInt8 nested_packet_enlargement;
      SshUInt8 max_nested_packet_enlargement;
      SshUInt32 num_ciphers, num_macs, cipher_index, mac_index;

      for (outer_tunnel = qm->tunnel->outer_tunnel;
           outer_tunnel != NULL;
           outer_tunnel = outer_tunnel->outer_tunnel)
        {
          max_nested_packet_enlargement = 0;

          (void) ssh_pm_ipsec_num_algorithms(pm, outer_tunnel->transform, 0,
                                             &num_ciphers, &num_macs,
                                             NULL, NULL);

          for (cipher_index = 0; cipher_index <= num_ciphers; cipher_index++)
            {
              if (cipher_index == 0)
                cipher = NULL;
              else
                cipher = ssh_pm_ipsec_cipher(pm, cipher_index - 1,
                                             outer_tunnel->transform);

              for (mac_index = 0; mac_index <= num_macs; mac_index++)
                {
                  if (mac_index == 0)
                    mac = NULL;
                  else
                    mac = ssh_pm_ipsec_mac(pm, mac_index - 1,
                                           outer_tunnel->transform);

                  nested_packet_enlargement =
                    ssh_pm_compute_trd_packet_enlargement(
                                                    pm,
                                                    outer_tunnel->transform,
                                                    TRUE, cipher, mac);
                  if (nested_packet_enlargement >
                      max_nested_packet_enlargement)
                    max_nested_packet_enlargement = nested_packet_enlargement;
                }
            }
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Maximum packet enlargement %d bytes "
                     "caused by outer tunnel %d",
                     max_nested_packet_enlargement,
                     outer_tunnel->tunnel_id));
          trd->packet_enlargement += max_nested_packet_enlargement;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Total packet enlargement %d bytes",
                                   trd->packet_enlargement));
    }

  return TRUE;

 error:
  return FALSE;
}

/* Abort thread for Sa handler failure thread. */
static void pm_sa_handler_failed_abort(void *context)
{
  SshPmQm qm = context;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Aborting SA handler failure thread for Quick-Mode %p", qm));

  /* mark aborted as engine operation can not be aborted */
  qm->callbacks.aborted = TRUE;
  qm->callbacks.u.ipsec_sa_install_cb = NULL_FNPTR;
  qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
  qm->ike_done = 1;
}

static void pm_sa_handler_abort(void *context)
{
  SshPmQm qm = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting SA handler for Quick-Mode %p", qm));

  /* mark aborted as engine operation can not be aborted */
  qm->callbacks.aborted = TRUE;
  qm->callbacks.u.ipsec_sa_install_cb = NULL_FNPTR;
  qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
  qm->ike_done = 1;
  ssh_fsm_set_next(&qm->sub_thread, ssh_pm_st_sa_handler_failed);
}

/* Common workhorse for SA installation (reinstallation for HA).  The
   'ed' may be null in case this is reinstall and the qm already
   contains the key material */
SshOperationHandle
ssh_pm_ipsec_sa_install_qm(SshPm pm,
                           SshPmP1 p1, SshPmQm qm,
                           SshIkev2SadIPsecSaInstallCB reply_callback,
                           void *reply_callback_context)
{
  SshPmSaHandlerData shd = &qm->sa_handler_data;
  SshEngineTransformControl trc = &shd->trd.control;
  SshEngineTransformData trd = &shd->trd.data;

  qm->callbacks.aborted = FALSE;
  qm->callbacks.u.ipsec_sa_install_cb = reply_callback;
  qm->callbacks.callback_context = reply_callback_context;

  ssh_operation_register_no_alloc(qm->callbacks.operation,
                                  pm_sa_handler_abort, qm);

  SSH_DEBUG(SSH_D_HIGHSTART, ("[qm %p] IPsec SA %s: Rule %d",
                              qm,
                              qm->rekey ? "rekey" : "install",
                              (int) (qm->rule ? qm->rule->rule_id : -1)));

#ifdef SSHDIST_IKEV1
  if (!p1 || p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    trc->control_flags |= SSH_ENGINE_TR_C_IKEV1_SA;
#endif /* SSHDIST_IKEV1 */

  trc->peer_handle = SSH_IPSEC_INVALID_INDEX;

  trc->tunnel_id = qm->tunnel->tunnel_id;

  if (qm->tunnel->outer_tunnel)
    {
      trc->outer_tunnel_id = qm->tunnel->outer_tunnel->tunnel_id;
      trd->restart_after_tre = 1;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("[qm %p] Traffic selectors %@ <-> %@",
                          qm,
                          ssh_ikev2_ts_render, qm->local_ts,
                          ssh_ikev2_ts_render, qm->remote_ts));

  /* Start an SA handler thread that takes care of installing the
     transform and outbound rule. */

  qm->sa_handler_data.added_index = 0;
  qm->sa_handler_data.delete_index = 0;

  /* Set qm->p1 if not already done so. It *should* always be set, but it
     appears not to be in certain cases. It needs to be set when we update
     p1->num_child_sas after transform creation in sad_sa_handler_st.c */
  if (!qm->p1)
    qm->p1 = p1;
  SSH_ASSERT(qm->p1 == p1);

  ssh_fsm_thread_init(&pm->fsm, &qm->sub_thread,
                      ssh_pm_st_sa_handler_start,
                      NULL_FNPTR,
                      pm_qm_sub_thread_destructor, qm);

  ssh_fsm_set_thread_name(&qm->sub_thread, "SA handler");

  /* All done. */
  return qm->callbacks.operation;
}

/* This is the IKE library side endpoint to SA Installation */
SshOperationHandle
ssh_pm_ipsec_sa_install(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2SadIPsecSaInstallCB reply_callback,
                        void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmQm qm = ed->application_context;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmSaHandlerData shd;
  SshEngineTransformData trd;
  SshEngineTransformControl trc;

  SSH_DEBUG(SSH_D_MIDSTART, ("[qm %p] SA installation", qm));

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("[qm %p] Failed to install IPsec SA since pm is not active.",
                 qm));
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, reply_callback_context);
      return NULL;
    }

  /* Check the case of responder IKEv1 negotiations where the IKE SA has
     been deleted (ed->application_context is cleared). */
  if (qm == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OK, reply_callback_context);
      return NULL;
    }

  SSH_PM_ASSERT_PM(pm);
  SSH_PM_ASSERT_QM(qm);
  SSH_PM_ASSERT_P1(p1);
  SSH_ASSERT(qm->tunnel != NULL);

  shd = &qm->sa_handler_data;
  trd = &shd->trd.data;
  trc = &shd->trd.control;

  /* DPD should never end up here. */
  SSH_ASSERT(qm->dpd == 0);

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_ERROR, ("[qm %p] PM is going down", qm));
      qm->error = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error;
    }

  /* We'll have to check that the tunnel used for P1 still exists.
     It may have disappeared during reconfiguration. */
  if (ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id) == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("[qm %p] tunnel has disappeared", qm));
      qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;

      /* Mark the P1 to be unusable and to be deleted really soon. */
      p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
      p1->unusable = 1;
      p1->expire_time = ssh_time();
      goto error;
    }

  /* Check for simultaneous IPsec SA rekey. */
  if (qm->initiator && qm->rekey && qm->simultaneous_rekey
#ifdef SSHDIST_IKEV1
      && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
      && ssh_pm_qm_simultaneous_rekey_decide_loser(pm, qm) == TRUE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("[qm %p] Simultaneous rekey lost, deleting IPsec SA", qm));
      qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
      goto error;
    }

  /* Parse the notify payloads received from the peer's previous packet. */
#ifdef SSHDIST_IKEV1
  /* IKEv1 fallback code may have added notify payloads that need to be
     handled here before IPsec SA installation. */
#endif /* SSHDIST_IKEV1 */
  ssh_pm_ike_parse_notify_payloads(ed, qm);

  /* Replace the qm->{local,remote}_ts with proper narrowed values */
  if (qm->local_ts)
    ssh_ikev2_ts_free(sad_handle, qm->local_ts);
  if (qm->remote_ts)
    ssh_ikev2_ts_free(sad_handle, qm->remote_ts);

  qm->local_ts = qm->ed->ipsec_ed->ts_local;
  qm->remote_ts = qm->ed->ipsec_ed->ts_remote;
  ssh_ikev2_ts_take_ref(sad_handle, qm->local_ts);
  ssh_ikev2_ts_take_ref(sad_handle, qm->remote_ts);

#ifdef SSHDIST_L2TP
  /* Enable L2TP iff. both local and remote have just one TS item, and
     either the local or remote TS item is UDP on port 1701. */
  if (qm->local_ts->number_of_items_used == 1 &&
      qm->remote_ts->number_of_items_used == 1 &&
      ((qm->local_ts->items->proto == SSH_IPPROTO_UDP &&
        qm->local_ts->items->start_port == SSH_IPSEC_L2TP_PORT &&
        qm->local_ts->items->end_port == SSH_IPSEC_L2TP_PORT) ||
       (qm->remote_ts->items->proto == SSH_IPPROTO_UDP &&
        qm->remote_ts->items->start_port == SSH_IPSEC_L2TP_PORT &&
        qm->remote_ts->items->end_port == SSH_IPSEC_L2TP_PORT)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("[qm %p] Enabling L2TP encapsulation", qm));
      qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_L2TP;
      qm->sa_handler_data.trd.data.l2tp_flags
        = (SSH_ENGINE_L2TP_PPP_ACFC | SSH_ENGINE_L2TP_PPP_PFC);

      /* Set the local and remote L2TP port numbers.  The rest of the
         L2TP parameters are updated to the SA when L2TP session is
         established and the parameters are known. */
      trd->l2tp_local_port = qm->local_ts->items->start_port;
      trd->l2tp_remote_port = qm->remote_ts->items->start_port;
    }
#endif /* SSHDIST_L2TP */

  if (qm->transport_sent && !qm->transport_recv)
    {
      /* Responder did not select transport mode */
      if (!qm->tunnel_accepted)
        {
          /* Policy does not allow fallback to tunnel mode */
          SSH_DEBUG(SSH_D_FAIL,
                    ("[qm %p] Transport mode required but was not accepted "
                     "by the peer, failing negotiation",
                     qm));
          qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          goto error;
        }

      /* Fallback to tunnel mode */
      SSH_DEBUG(SSH_D_MIDOK,
                ("[qm %p] Transport mode required but was not accepted "
                 "by the peer, falling back to tunnel mode",
                 qm));
      trd->transform |= SSH_PM_IPSEC_TUNNEL;
    }

  if (!(qm->transport_sent && qm->transport_recv))
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("[qm %p] Setting tunnel mode encapsulation",
                                 qm));
      trd->transform |= SSH_PM_IPSEC_TUNNEL;
    }

#ifdef SSHDIST_IPSEC_IPCOMP
  if (qm->ipcomp_chosen && (qm->transform & SSH_PM_IPSEC_IPCOMP))
    {
      SshPmCompression compress;

      if (qm->transform & SSH_PM_COMPRESS_DEFLATE &&
          qm->ipcomp_chosen == SSH_IKEV2_IPCOMP_DEFLATE)
        {
          compress = ssh_pm_compression(pm, 0, SSH_PM_COMPRESS_DEFLATE);
        }
      else if (qm->transform & SSH_PM_COMPRESS_LZS &&
               qm->ipcomp_chosen == SSH_IKEV2_IPCOMP_LZS)
        {
          compress = ssh_pm_compression(pm, 0, SSH_PM_COMPRESS_LZS);
        }
      else
        {
          qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          SSH_DEBUG(SSH_D_FAIL, ("[qm %p] IPComp negotiation failed", qm));
          goto error;
        }

      if (compress == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("[qm %p] Negotiated compression algorithm not available",
                     qm));
          goto error;
        }

      trd->spis[SSH_PME_SPI_IPCOMP_IN] = qm->ipcomp_spi_in;
      trd->spis[SSH_PME_SPI_IPCOMP_OUT] = qm->ipcomp_spi_out;
      trd->transform |= compress->mask_bits;
      trd->transform |= SSH_PM_IPSEC_IPCOMP;
    }
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSHDIST_IPSEC_MOBIKE
  /* Check if negotiation was initiated with MOBIKE but finished with MOBIKE
     disabled. In this case the negotiation may have used multiple addresses
     and here the IKE SA must be updated before installing the IPsec SA. */
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE)
      && ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
      && ed->multiple_addresses_used)
    {
      SshUInt32 natt_flags;

      SSH_DEBUG(SSH_D_LOWOK,
                ("[qm %p] IPsec SA negotiation was started with "
                 "MOBIKE enabled, finished with MOBIKE disabled and "
                 "used multiple addresses",
                 qm));

      /* Get the NAT-T status of the current exchange. */
      (void)ssh_pm_mobike_get_exchange_natt_flags(p1, ed, &natt_flags);

      if (!ssh_pm_mobike_update_p1_addresses(pm, p1, ed->server,
                                             ed->remote_ip, ed->remote_port,
                                             natt_flags))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("[qm %p] Failed to update IKE SA addresses", qm));
          goto error;
        }
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

  trd->local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
  trd->remote_port = p1->ike_sa->remote_port;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (p1->ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT
                           | SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
      SshIkev2PayloadID remote_id = NULL;

      /* Enable NAT-T for transform. */
      trd->transform |= SSH_PM_IPSEC_NATT;

      /* Get the identity of the IKE peer. */
      if (p1->remote_id != NULL)
        {
          remote_id = p1->remote_id;
        }
      else if (ed->ike_ed != NULL)
        {
          if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
            remote_id = ed->ike_ed->id_r;
          else
            remote_id = ed->ike_ed->id_i;
        }

      if (remote_id == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("[qm %p] No remote ID available", qm));
          qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          goto error;
        }

      /* Store a hash of the remote IKE ID. */
      ssh_pm_ike_id_hash(pm, trc->peer_id, remote_id);

      /* Set the original addresses for transport mode NAT-T.

         Note that for now the original addresses are not set for
         IKEv1 and the engine will perform full checksum recalculation
         for such transforms. */
      if ((trd->transform & SSH_PM_IPSEC_TUNNEL) == 0)
        {
          SshIpAddrStruct natt_oa_l, natt_oa_r;

          ssh_ikev2_ipsec_get_natt_oa(ed, &natt_oa_l, &natt_oa_r);
          if (SSH_IP_IS4(&natt_oa_l))
            {
              SSH_IP4_ENCODE(&natt_oa_l, trd->natt_oa_l);
              trd->natt_flags |= SSH_ENGINE_NATT_OA_L;
            }
          else if (SSH_IP_IS6(&natt_oa_l))
            {
              SSH_IP6_ENCODE(&natt_oa_l, trd->natt_oa_l);
              trd->natt_flags |= SSH_ENGINE_NATT_OA_L;
            }

          if (SSH_IP_IS4(&natt_oa_r))
            {
              SSH_IP4_ENCODE(&natt_oa_r, trd->natt_oa_r);
              trd->natt_flags |= SSH_ENGINE_NATT_OA_R;
            }
          else if (SSH_IP_IS6(&natt_oa_r))
            {
              SSH_IP6_ENCODE(&natt_oa_r, trd->natt_oa_r);
              trd->natt_flags |= SSH_ENGINE_NATT_OA_R;
            }
        }

      /* Enable NAT-T keepalives if this end is behind NAT. */
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        trc->control_flags |= SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED;

      /* Enable internal NAT if policy says so and the traffic selectors
         are IPv4. */
      if (qm->tunnel->transform & SSH_PM_IPSEC_INT_NAT)
        {
          if (qm->local_ts->items[0].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
            trd->transform |= SSH_PM_IPSEC_INT_NAT;
        }

      /* Mark whether the local or remote ends are behind NAT. */
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        trd->natt_flags |= SSH_ENGINE_NATT_LOCAL_BEHIND_NAT;
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
        trd->natt_flags |= SSH_ENGINE_NATT_REMOTE_BEHIND_NAT;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  trd->inbound_tunnel_id = qm->tunnel->tunnel_id;

  if (ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN])
    {
      if (ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ESN]->id
          == SSH_IKEV2_TRANSFORM_ESN_ESN)
        trd->transform |= SSH_PM_IPSEC_LONGSEQ;
    }

  if ((qm->tunnel->flags & SSH_PM_T_DISABLE_ANTI_REPLAY) == 0)
    trd->transform |= SSH_PM_IPSEC_ANTIREPLAY;

#ifdef SSHDIST_IPSEC_NAT
  /* Enable port nat for decapsulated traffic? */
  if ((qm->tunnel->flags & SSH_PM_T_PORT_NAT) != 0)
    trd->transform |= SSH_PM_IPSEC_PORT_NAT;
#endif /* SSHDIST_IPSEC_NAT */

  /* Set df-bit policy. */
  if (qm->rule->flags & SSH_PM_RULE_DF_SET)
    trd->df_bit_processing = SSH_ENGINE_DF_SET;
  else if (qm->rule->flags & SSH_PM_RULE_DF_CLEAR)
    trd->df_bit_processing = SSH_ENGINE_DF_CLEAR;
  else
    trd->df_bit_processing = SSH_ENGINE_DF_KEEP;

  /* Set the peer IP addresses and interface number. */
  trd->gw_addr =  *p1->ike_sa->remote_ip;
  trd->own_addr = *p1->ike_sa->server->ip_address;
  trd->own_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  /* Set local lifetimes. */
#ifdef SSHDIST_IKEV1
  /* Lifetimes are negotiated for IKEv1 SA's, the negotiated value is
     set to the IKE exchange data. For IKEv2 SA's we use the value
     from the local policy. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      qm->trd_life_seconds = ed->ipsec_ed->sa_life_seconds;
      qm->trd_life_kilobytes = ed->ipsec_ed->sa_life_kbytes;
    }
  else
#endif /* SSHDIST_IKEV1 */
    {
      qm->trd_life_seconds = qm->tunnel->u.ike.life_seconds;
      qm->trd_life_kilobytes = qm->tunnel->u.ike.life_kb;
    }
  if (qm->trd_life_seconds == 0 && qm->trd_life_kilobytes == 0)
    qm->trd_life_seconds = SSH_PM_DEFAULT_IPSEC_SA_LIFE_SECONDS;

  /* Set lifetime in seconds for SAs that have only kilobyte lifetime.
     This ensures that SA's are always deleted even if there is no
     traffic through such SA's. */
  else if (qm->trd_life_seconds == 0)
    qm->trd_life_seconds = SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC;

  /* Use a bit shorter and jittered (5% - 8 - 11 - 14%) lifetimes for
     the initiator.  This way the initiator will most probably
     initiate also the rekey for the SA. Actually some jitter
     (especially for shorter lifetimes comes from the engine-timeout
     processing for need to rekey. */
  if (qm->initiator)
    {
      SshUInt32 life;

      life = qm->trd_life_seconds;
      if (life)
        qm->trd_life_seconds =
          (life - ((life / 20) + ((ssh_random_get_byte() % 4) * (life / 30))));
      life = qm->trd_life_kilobytes;
      if (life)
        qm->trd_life_kilobytes =
          (life - ((life / 20) + ((ssh_random_get_byte() % 4) * (life / 30))));
    }
  else if ((p1->compat_flags & SSH_PM_COMPAT_DONT_INITIATE)
#ifdef SSHDIST_IKEV1
           ||  p1->ike_sa->xauth_done
#endif /* SSHDIST_IKEV1 */
           )
    {
      /* Increase the lifetimes by 20% if we know the remote peer is not
         able to act as a responder. This disregards somewhat the
         negotiated policy, however not doing this causes interopability
         problems as many vendors do not use slightly shorter lifetimes
         as an initiator even though they cannot act as a responder. Note
         that increasing the lifetimes in this manner is only effective for
         IKEv1 SA's. */
      SshUInt32 life;

      life = qm->trd_life_seconds;
      if (life)
        {
          qm->trd_life_seconds = life + (life / 5);

          if (qm->trd_life_seconds < life)
            qm->trd_life_seconds  = 0;
        }

      life = qm->trd_life_kilobytes;
      if (life)
        {
          qm->trd_life_kilobytes = life + (life / 5);

          if (qm->trd_life_kilobytes < life)
            qm->trd_life_kilobytes  = 0;
        }
    }

  if (!pm_ipsec_sa_keymat(pm, p1, qm, ed))
    {
      qm->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
      SSH_DEBUG(SSH_D_FAIL,
                ("[qm %p] IPSec key material generation failed", qm));
      goto error;
    }

  trc->control_flags |= SSH_ENGINE_TR_C_DPD_ENABLED;
#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      /* Disable DPD if remote does not support it */
      if (!(p1->compat_flags & SSH_PM_COMPAT_REMOTE_DPD))
        trc->control_flags &= ~SSH_ENGINE_TR_C_DPD_ENABLED;
    }
#endif /* SSHDIST_IKEV1 */

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
  /* Disable DPD for SCTP multihomed SA's as the SCTP protocol takes
     care of liveliness checking, and DPD will not work correctly in
     this case anyway */
  if (qm->rule->flags & SSH_PM_RULE_MULTIHOME)
    trc->control_flags &= ~SSH_ENGINE_TR_C_DPD_ENABLED;
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

  /* Initialize the ESP sequence numbers and the replay window. Doing it
     here enables us to set the initial ESP sequence number and initial
     replay window to a non-zero value for imported IPsec SAs.  */
  trd->out_packets_low = 0;
  trd->out_packets_high = 0;
  memset(trd->replay_mask, 0, sizeof(trd->replay_mask));
  trd->replay_offset_high = 0;
  trd->replay_offset_low = 0;

  return ssh_pm_ipsec_sa_install_qm(pm,
                                    p1, qm,
                                    reply_callback, reply_callback_context);

  /* Error handling. */
 error:

  SSH_DEBUG(SSH_D_FAIL, ("[qm %p] Starting SA handler failed subthread", qm));

  qm->callbacks.aborted = FALSE;
  qm->callbacks.u.ipsec_sa_install_cb = reply_callback;
  qm->callbacks.callback_context = reply_callback_context;

  ssh_operation_register_no_alloc(qm->callbacks.operation,
                                  pm_sa_handler_failed_abort, qm);

  qm->sa_handler_data.added_index = 0;
  qm->sa_handler_data.delete_index = 0;

  /* Start an SA handler thread that takes care of notifying our
     Quick-Mode thread. */
  ssh_fsm_thread_init(&pm->fsm, &qm->sub_thread,
                      ssh_pm_st_sa_handler_failed, NULL_FNPTR, NULL_FNPTR, qm);
  ssh_fsm_set_thread_name(&qm->sub_thread, "SA handler error");

  return qm->callbacks.operation;
}

static void
pm_ipsec_sa_format(SshPm pm, SshPmP1 p1, SshPmQm qm, SshIkev2ExchangeData ed)
{
  SshEngineTransformData trd = &qm->sa_handler_data.trd.data;
  SshIkev2PayloadTransform trans;
  char keysizebuf[8] = {0};
  size_t cipher_key_size = 0;
  char buf[128];
  SshPmCipher cipher = NULL;
  SshPmMac mac = NULL;
#ifdef SSHDIST_IPSEC_IPCOMP
  SshPmCompression compress = NULL;
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* ENCR */
  if ((trans =
       ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR])
      != NULL)
    {
      SSH_VERIFY((cipher = ssh_pm_ipsec_cipher_by_id(pm, trans->id)) != NULL);

      if (trans->transform_attribute & 0x800e0000)
        {
          cipher_key_size = (trans->transform_attribute & 0xffff) / 8;
          ssh_snprintf(keysizebuf, sizeof(keysizebuf), "/%u",
                       (unsigned int) (cipher_key_size * 8));
        }
    }

  /* Integrity */
  trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG];
  if (trans != NULL && trans->id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
      SSH_VERIFY((mac = ssh_pm_ipsec_mac_by_id(pm, trans->id)) != NULL);
    }

  buf[0] = '\0';

  if (qm->rekey)
    strcat(buf, ", rekey");

  if (qm->initiator)
    {
      if (qm->tunnel->flags & SSH_PM_T_PER_PORT_SA)
        strcat(buf, ", perport");
      else if (qm->tunnel->flags & SSH_PM_T_PER_HOST_SA)
        strcat(buf, ", perhost");
    }

  /* Encapsulation mode. */
  if (trd->transform & SSH_PM_IPSEC_NATT)
    {
      if (trd->transform & SSH_PM_IPSEC_TUNNEL)
        strcat(buf, ", NAT-T, tunnel");
      else
        strcat(buf, ", NAT-T transport");
    }
  else
    {
      if (trd->transform & SSH_PM_IPSEC_TUNNEL)
        strcat(buf, ", tunnel");
      else
        strcat(buf, ", transport");
    }

#ifdef SSHDIST_IPSEC_NAT
  if (trd->transform & SSH_PM_IPSEC_INT_NAT)
    strcat(buf, ", int-nat");
#endif /* SSHDIST_IPSEC_NAT */

  if (qm->auto_start)
    strcat(buf, ", auto");

  if (trd->transform & SSH_PM_IPSEC_LONGSEQ)
    strcat(buf, ", seq-64");

#ifdef SSHDIST_L2TP
  if (trd->transform & SSH_PM_IPSEC_L2TP)
    strcat(buf, ", L2TP");
#endif /* SSHDIST_L2TP */

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "IPsec SA [%s%s] negotiation completed:",
                qm->initiator ? "Initiator" : "Responder",
                buf);

  if (qm->dh_group)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  PFS using Diffie-Hellman group %u (%u bits)",
                    qm->dh_group,
                    ssh_pm_dh_group_size(pm, qm->dh_group));
    }

  if (!qm->rekey)
    ssh_pm_log_p1(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, p1, FALSE);

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Local Traffic Selector  %@",
                ssh_ikev2_ts_render, qm->ed->ipsec_ed->ts_local);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Remote Traffic Selector %@",
                ssh_ikev2_ts_render, qm->ed->ipsec_ed->ts_remote);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Routing Instance  %s (%d)",
                qm->tunnel->routing_instance_name,
                qm->tunnel->routing_instance_id);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Inbound SPI:      | Outbound SPI: | Algorithm:");


  if (trd->transform & SSH_PM_IPSEC_ESP)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  ESP    [%08lx] | [%08lx]    | %s%s - %s",
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_ESP_IN],
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_ESP_OUT],
                  cipher ? cipher->name : "none", keysizebuf,
                  mac ? mac->name : "none");
  if (trd->transform & SSH_PM_IPSEC_AH)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  AH     [%08lx] | [%08lx]    | %s",
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_AH_IN],
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_AH_OUT],
                  mac ? mac->name : "none");
#ifdef SSHDIST_IPSEC_IPCOMP
  compress =
    ssh_pm_compression(pm, 0,
                       (trd->transform & SSH_PM_COMPRESS_MASK));
  if (trd->transform & SSH_PM_IPSEC_IPCOMP)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  IPCOMP [%08lx] | [%08lx]    | %s",
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_IPCOMP_IN],
                  (unsigned long)
                  trd->spis[SSH_PME_SPI_IPCOMP_OUT],
                  compress ? compress->name : "none");
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Print lifetimes */
  if (qm->trd_life_kilobytes && qm->trd_life_seconds)
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                  "  Local Lifetime: %u kilobytes, %u seconds",
                  (unsigned int) qm->trd_life_kilobytes,
                  (unsigned int) qm->trd_life_seconds);
  else if (qm->trd_life_seconds)
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                  "  Local Lifetime: %u seconds",
                  (unsigned int) qm->trd_life_seconds);
  else if (qm->trd_life_kilobytes)
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                  "  Local Lifetime: %u kilobytes",
                  (unsigned int) qm->trd_life_kilobytes);
  else
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                  "  Local Lifetime: infinite");
}

void
ssh_pm_ipsec_sa_done(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2Error status)
{
  SshPm pm = sad_handle->pm;
  SshPmQm qm = ed->application_context;
  SshEngineTransformData trd;
  SshPmQmStruct qm_struct;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART, ("IPsec SA done for qm=%p, status is %d",
                             qm, status));

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (!qm || !qm->rule || !(qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    pm->stats.num_qm_done++;

  /* Update the auto-start status for responder negotiations. */
  if (qm && !qm->initiator)
    ssh_pm_qm_update_auto_start_status(pm, qm);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  SSH_ASSERT(p1 != NULL);
  if (p1->auth_cert)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing P1 auth cert reference"));
      ssh_cm_cert_remove_reference(p1->auth_cert);
      p1->auth_cert = NULL;
    }

  if (p1->auth_ca_cert)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing P1 auth ca cert reference"));
      ssh_cm_cert_remove_reference(p1->auth_ca_cert);
      p1->auth_ca_cert = NULL;
    }
#else /* SSHDIST_CERT */
#ifdef WITH_MSCAPI



  if (p1->auth_cert)
    {
      ssh_pm_mscapi_free_cert(p1->auth_cert);
      p1->auth_cert = NULL;
    }
  if (p1->auth_ca_cert)
    {
      ssh_pm_mscapi_free_cert(p1->auth_ca_cert);
      p1->auth_ca_cert = NULL;
    }
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */







  /* 'qm' may be NULL for IKEv1 negotiations if the responder side
     Quick-Mode negotiation failed before SPI allocation. In this case,
     fabricate a 'qm' for clearer logging messages. */
  if (qm == NULL)
    {



      if (status == SSH_IKEV2_ERROR_OK)
        status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

      memset(&qm_struct, 0, sizeof(qm_struct));
      qm_struct.p1 = p1;
      qm = &qm_struct;

      SSH_DEBUG(SSH_D_FAIL, ("IPSEC SA negotiation failed: %d", status));

      pm->stats.num_qm_failed++;

      qm->error = status;
      ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          qm, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)",
                    ssh_pm_qm_error_to_string(status), status);

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "IPsec SA negotiations: %u done, %u successful, %u failed",
                    (unsigned int) pm->stats.num_qm_done,
                    (unsigned int) (pm->stats.num_qm_done -
                                    pm->stats.num_qm_failed),
                    (unsigned int) pm->stats.num_qm_failed);
      return;
    }

  SSH_PM_ASSERT_QM(qm);
  trd = &qm->sa_handler_data.trd.data;
  qm->ike_done = 1;

#ifdef SSHDIST_IKEV1
  if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
      && qm->initiator
      && !qm->aborted
      && qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
      && status == SSH_IKEV2_ERROR_SA_UNUSABLE)
    {
      SshPmPeer peer;
      SshUInt32 old_peer_handle;

      /* Detach this QM from P1 */
      PM_IKE_ASYNC_CALL_COMPLETE(qm->p1->ike_sa, ed);

      qm->p1->unusable = 1;

      /* For new IPsec SA negotiations update qm->peer_handle with the
         peer handle of this p1 that is next going to be replaced with
         a new p1. For rekeys and dpd we do not want to update the
         peer_handle. */
      if (!qm->rekey && !qm->dpd)
        {
          old_peer_handle = qm->peer_handle;
          qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);

          /* If qm->peer_handle changed then take a reference to the
             new peer_handle and free the reference to the old peer handle. */
          if (qm->peer_handle != old_peer_handle)
            {
              if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
                ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
              if (old_peer_handle != SSH_IPSEC_INVALID_INDEX)
                ssh_pm_peer_handle_destroy(pm, old_peer_handle);
            }
        }

      /* Detach IKE SA from IKE peer. */
      do
        {
          /* There might be multiple IKE peers pointing to same IKE SA. */
          peer = ssh_pm_peer_by_p1(pm, qm->p1);
          if (peer)
            ssh_pm_peer_update_p1(pm, peer, NULL);
        }
      while (peer != NULL);

      /* Reset qm->p1_tunnel before stepping back to
         ssh_pm_st_qm_i_n_select_p1. */
      if (qm->p1_tunnel)
        {
          SSH_PM_TUNNEL_DESTROY(pm, qm->p1_tunnel);
          qm->p1_tunnel = NULL;
        }

      /* Rekey for IKE SA is required to complete this QM.
         Perform it now. */
      SSH_DEBUG(SSH_D_FAIL, ("Quick-Mode failed because of unusable "
                             "IKE SA, reselecting Phase-I, qm=%p, "
                             "p1=%p", qm, qm->p1));

      qm->error = SSH_IKEV2_ERROR_USE_IKEV1;

      ssh_fsm_set_next(&qm->thread, ssh_pm_st_qm_i_n_select_p1);
      ssh_fsm_continue(&qm->thread);

      /* Decrement the statistics counter */
      pm->stats.num_qm_done--;
      return;
    }
#endif /* SSHDIST_IKEV1 */

  /* Negotiation or SA handler failed. */
  if (status != SSH_IKEV2_ERROR_OK || qm->error != SSH_IKEV2_ERROR_OK)
    {
      /* Do not clear qm->error in case SA handler has failed. */
      if (status == SSH_IKEV2_ERROR_OK)
        status = qm->error;

      SSH_DEBUG(SSH_D_FAIL, ("IPSEC SA negotiation failed: %d", status));

      qm->sa_handler_done = 1;
      qm->error = status;

      pm->stats.num_qm_failed++;

      ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          qm, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)",
                    ssh_pm_qm_error_to_string(status), status);

      if (qm->failure_mask || qm->ike_failure_mask)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Reason:");
          if (qm->failure_mask)
            ssh_pm_log_rule_selection_failure(SSH_LOGFACILITY_AUTH,
                                              SSH_LOG_INFORMATIONAL,
                                              p1,
                                              qm->failure_mask);

          if (qm->ike_failure_mask)
            ssh_pm_log_ike_sa_selection_failure(SSH_LOGFACILITY_AUTH,
                                                SSH_LOG_INFORMATIONAL,
                                                p1,
                                                qm->ike_failure_mask);
        }
    }
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  else if (qm->rule && (qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
    {
      qm->sa_handler_done = 1;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
  else /* Successful negotiation. */
    {
      SSH_ASSERT(qm->sa_handler_done == 1);

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
      if (p1->cfgmode_client != NULL)
        {
          pm_ras_radius_acct_start(pm, p1->cfgmode_client);
        }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

      /* Indicate that the SA has created/rekeyed. */
      if (qm->rekey)
        ssh_pm_ipsec_sa_event_rekeyed(pm, qm);
      else
        ssh_pm_ipsec_sa_event_created(pm, qm);

      /* Zeroize all SPI's that should be taken into use by the SA.
         Otherwise the SPI's will be freed when the Quick-mode is freed. */
      if (trd->transform & SSH_PM_IPSEC_ESP)
        qm->spis[SSH_PME_SPI_ESP_IN] = 0;
      if (trd->transform & SSH_PM_IPSEC_AH)
        qm->spis[SSH_PME_SPI_AH_IN] = 0;
      if (trd->transform & SSH_PM_IPSEC_IPCOMP)
        qm->spis[SSH_PME_SPI_IPCOMP_IN] = 0;

      /* Format SA options and print preamble for SA's */
      pm_ipsec_sa_format(pm, p1, qm, ed);
    }

  /* Clear key material from temporary negotiation context. */
  memset(qm->sa_handler_data.trd.data.keymat, 0,
         sizeof(qm->sa_handler_data.trd.data.keymat));

  /* Handle delayed delete notifications. */
  ssh_pm_send_ipsec_delete_notification_requests(pm, p1);

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (!qm || !qm->rule || !(qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "IPsec SA negotiations: %u done, %u successful, %u failed",
                  (unsigned int) pm->stats.num_qm_done,
                  (unsigned int) (pm->stats.num_qm_done -
                                  pm->stats.num_qm_failed),
                  (unsigned int) pm->stats.num_qm_failed);
}
