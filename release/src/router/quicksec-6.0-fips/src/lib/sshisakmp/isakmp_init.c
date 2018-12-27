/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp module initialization and delete functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshIkeInit"

/*                                                              shade{0.9}
 * Clear SKEYID data.                                           shade{1.0}
 */
void ike_clear_skeyid(SshIkeSASKeyID skeyid)
{
  skeyid->initialized = FALSE;

  if (skeyid->dh)
    {
      memset(skeyid->dh, 0, skeyid->dh_size);
      ssh_free(skeyid->dh);
      skeyid->dh = NULL;
      skeyid->dh_size = 0;
    }

  if (skeyid->skeyid)
    {
      memset(skeyid->skeyid, 0, skeyid->skeyid_size);
      ssh_free(skeyid->skeyid);
      skeyid->skeyid = NULL;
      skeyid->skeyid_size = 0;
    }
  if (skeyid->skeyid_mac)
    {
      ssh_mac_free(skeyid->skeyid_mac);
      skeyid->skeyid_mac = NULL;
    }

  if (skeyid->skeyid_d)
    {
      memset(skeyid->skeyid_d, 0, skeyid->skeyid_d_size);
      ssh_free(skeyid->skeyid_d);
      skeyid->skeyid_d = NULL;
      skeyid->skeyid_d_size = 0;
    }

  if (skeyid->skeyid_a)
    {
      memset(skeyid->skeyid_a, 0, skeyid->skeyid_a_size);
      ssh_free(skeyid->skeyid_a);
      skeyid->skeyid_a = NULL;
      skeyid->skeyid_a_size = 0;
    }
  if (skeyid->skeyid_a_mac)
    {
      ssh_mac_free(skeyid->skeyid_a_mac);
      skeyid->skeyid_a_mac = NULL;
    }

  if (skeyid->skeyid_e)
    {
      memset(skeyid->skeyid_e, 0, skeyid->skeyid_e_size);
      ssh_free(skeyid->skeyid_e);
      skeyid->skeyid_e = NULL;
      skeyid->skeyid_e_size = 0;
    }
  if (skeyid->skeyid_e_mac)
    {
      ssh_mac_free(skeyid->skeyid_e_mac);
      skeyid->skeyid_e_mac = NULL;
    }
}

/*                                                              shade{0.9}
 * Allocate and initialize common exchange data.                shade{1.0}
 */
Boolean ike_alloc_ed(SshIkeExchangeData *ed_ptr,
                     SshUInt32 compat_flags,
                     int retry_limit,
                     int retry_timer,
                     int retry_timer_usec,
                     int retry_timer_max,
                     int retry_timer_max_usec,
                     int expire_timer,
                     int expire_timer_usec,
                     SshUInt32 message_id)
{
  SshIkeExchangeData ed;

  *ed_ptr = ed = ssh_calloc(1, sizeof(*ed));
  if (ed == NULL)
    return FALSE;

  ed->compat_flags = compat_flags;
  ed->retry_limit = retry_limit;
  ed->retry_timer = retry_timer;
  ed->retry_timer_usec = retry_timer_usec;
  ed->retry_timer_max = retry_timer_max;
  ed->retry_timer_max_usec = retry_timer_max_usec;
  ed->expire_timer = expire_timer;
  ed->expire_timer_usec = expire_timer_usec;
  ed->message_id = message_id;
  ed->offending_payload_offset = -1;
  ed->packet_number = 0;
  ed->current_state_function = -1;
  ed->auth_method_type = SSH_IKE_AUTH_METHOD_ANY;
  ssh_time_measure_init(ed->last_packet_time);
  ssh_time_measure_start(ed->last_packet_time);
  return TRUE;
}

/*                                                              shade{0.9}
 * Free common exchange data.                                   shade{1.0}
 */
void ike_free_ed(SshIkeExchangeData ed)
{
  int i;

  for (i = 0; i < ed->number_of_packets_in; i++)
    ike_free_packet(ed->packets_in[i], ed->compat_flags);
  for (i = 0; i < ed->number_of_packets_out; i++)
    ike_free_packet(ed->packets_out[i], ed->compat_flags);

  if (ed->encryption_cipher)
    ssh_cipher_free(ed->encryption_cipher);

  if (ed->decryption_cipher)
    ssh_cipher_free(ed->decryption_cipher);

  ssh_free(ed->cipher_iv);
  ssh_free(ed->offending_payload);
  ssh_free(ed->error_text);
  ssh_free(ed->last_sent_packet);
  ssh_free(ed->last_recv_packet);
  if (ed->isakmp_packet_out)
    ike_free_packet(ed->isakmp_packet_out, ed->compat_flags);
  ssh_free(ed);
}

/*                                                              shade{0.9}
 * Allocate and initialize isakmp exchange data.                shade{1.0}
 */
Boolean ike_alloc_ike_ed(SshIkeSAPacketData *ed_ptr)
{
  SshIkeSAPacketData ed;

  *ed_ptr = ed = ssh_calloc(1, sizeof(*ed));
  if (ed == NULL)
    return FALSE;

#ifdef SSHDIST_IKE_CERT_AUTH
  ed->number_of_cas = -1;
  ed->own_number_of_cas = -1;
#endif /* SSHDIST_IKE_CERT_AUTH */
  ed->selected_proposal = -1;
  ed->selected_transform = -1;
  ed->number_of_vids = -1;
  ed->nonce_data_len = -1;
  ed->sig_verify_state = SSH_IKE_SIGNATURE_VERIFY_STATE_NOT_DONE;
  return TRUE;
}

/*                                                              shade{0.9}
 * Free isakmp exchange data.                                   shade{1.0}
 */
void ike_free_ike_ed(SshIkeSAPacketData ed)
{
  int i;
#ifdef SSHDIST_IKE_CERT_AUTH
  int j;
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* sa_i, sa_r, ke_i, ke_r, nonce_i, nonce_r are pointers to packets
     received / send to network. They point to packets_in and packets_out
     tables in the common exchange data. No need to free them here. */
  if (ed->secret)
    ssh_pk_group_dh_secret_free(ed->secret);

#ifdef SSHDIST_IKE_CERT_AUTH
  if (ed->public_key)
    ssh_public_key_free(ed->public_key);
  ssh_free(ed->public_key_hash);

  if (ed->private_key)
    ssh_private_key_free(ed->private_key);
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (ed->pre_shared_key)
    {
      memset(ed->pre_shared_key, 0, ed->pre_shared_key_len);
      ssh_free(ed->pre_shared_key);
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  if (ed->number_of_certificates)
    {
      for (i = 0; i < ed->number_of_cas; i++)
        {
          if (ed->cert_encodings && ed->cert_encodings[i])
            ssh_free(ed->cert_encodings[i]);
          if (ed->certs && ed->certs[i])
            {
              for (j = 0; j < ed->number_of_certificates[i]; j++)
                {
                  ssh_free(ed->certs[i][j]);
                }
              ssh_free(ed->certs[i]);
            }
          if (ed->cert_lengths && ed->cert_lengths[i])
            ssh_free(ed->cert_lengths[i]);
        }
      ssh_free(ed->cert_encodings);
      ssh_free(ed->certs);
      ssh_free(ed->cert_lengths);
      ssh_free(ed->number_of_certificates);
    }

  if (ed->certificate_authorities)
    {
      for (i = 0; i < ed->number_of_cas; i++)
        {
          ssh_free(ed->certificate_authorities[i]);
        }
      ssh_free(ed->certificate_authorities);
    }
  ssh_free(ed->ca_encodings);
  ssh_free(ed->certificate_authority_lens);

  if (ed->own_certificate_authorities)
    {
      for (i = 0; i < ed->own_number_of_cas; i++)
        {
          ssh_free(ed->own_certificate_authorities[i]);
        }
      ssh_free(ed->own_certificate_authorities);
    }
  ssh_free(ed->own_ca_encodings);
  ssh_free(ed->own_certificate_authority_lens);
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (ed->local_sa_proposal)
    ssh_ike_free_sa_payload(ed->local_sa_proposal);

  if (ed->vendor_ids)
    {
      for (i = 0; i < ed->number_of_vids; i++)
        ssh_free(ed->vendor_ids[i]);
      ssh_free(ed->vendor_ids);
      ssh_free(ed->vendor_id_lens);
    }
  ssh_free(ed->async_return_data);
  if (ed->listener)
    ssh_udp_destroy_listener(ed->listener);

  ssh_free(ed);
}


/*                                                              shade{0.9}
 * Allocate and initialize quick mode exchange data.            shade{1.0}
 */
Boolean ike_alloc_qm_ed(SshIkeQmSAPacketData *ed_ptr)
{
  SshIkeQmSAPacketData ed;

  *ed_ptr = ed = ssh_calloc(1, sizeof(*ed));
  if (ed == NULL)
    return FALSE;

  ed->no_local_id = FALSE;
  ed->no_remote_id = FALSE;
  ed->nonce_data_len = -1;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free quick mode exchange data.                               shade{1.0}
 */
void ike_free_qm_ed(SshIkeQmSAPacketData ed)
{
  int i, j;
  /* Contents of sas_i, sas_r, and ke_i, ke_r, nonce_i, nonce_r are pointers to
     packets received / send to network. They point to packets_in and
     packets_out tables in the common exchange data. No need to free them
     here. */
  ssh_free(ed->sas_i);
  ssh_free(ed->sas_r);
  if (ed->secret)
    ssh_pk_group_dh_secret_free(ed->secret);

  if (ed->indexes)
    {
      ssh_free(ed->indexes->transform_indexes);
      ssh_free(ed->indexes->spi_sizes);
      if (ed->indexes->spis)
        {
          for (i = 0; i < ed->indexes->number_of_protocols; i++)
            {
              ssh_free(ed->indexes->spis[i]);
            }
          ssh_free(ed->indexes->spis);
        }
      ssh_free(ed->indexes);
    }

  if (ed->selected_sas)
    {
      for (i = 0; i < ed->number_of_sas; i++)
        {
          if (ed->selected_sas[i].protocols)
            {
              for (j = 0; j < ed->selected_sas[i].number_of_protocols; j++)
                {
                  ssh_free(ed->selected_sas[i].protocols[j].spi_in);
                  ssh_free(ed->selected_sas[i].protocols[j].spi_out);
                }
              ssh_free(ed->selected_sas[i].protocols);
            }
        }
      ssh_free(ed->selected_sas);
    }

  if (ed->local_sa_proposals)
    {
      for (i = 0; i < ed->number_of_sas; i++)
        {
          if (ed->local_sa_proposals[i])
            ssh_ike_free_sa_payload(ed->local_sa_proposals[i]);
        }
      ssh_free(ed->local_sa_proposals);
    }
  ssh_free(ed->async_return_data);
  ssh_free(ed);
}


/*                                                              shade{0.9}
 * Allocate and initialize ngm exchange data.                   shade{1.0}
 */
Boolean ike_alloc_ngm_ed(SshIkeNgmSAPacketData *ed_ptr)
{
  SshIkeNgmSAPacketData ed;

  *ed_ptr = ed = ssh_calloc(1, sizeof(*ed));
  if (ed == NULL)
    return FALSE;

  ed->selected_proposal = -1;
  ed->selected_transform = -1;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free ngm exchange data.                                      shade{1.0}
 */
void ike_free_ngm_ed(SshIkeNgmSAPacketData ed)
{
  /* sa_i, sa_r are pointers to packets received / send to network. They point
     to packets_in and packets_out tables in the common exchange data. No need
     to free them here. */
  ssh_ike_free_grp_attrs(&(ed->attributes));

  if (ed->local_sa_proposal)
    ssh_ike_free_sa_payload(ed->local_sa_proposal);

  ssh_free(ed);
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * Allocate and initialize cfg exchange data.                   shade{1.0}
 */
Boolean ike_alloc_cfg_ed(SshIkeCfgSAPacketData *ed_ptr)
{
  SshIkeCfgSAPacketData ed;

  *ed_ptr = ed = ssh_calloc(1, sizeof(*ed));
  if (ed == NULL)
    return FALSE;

  ed->number_of_local_attr_payloads = -1;
  ed->number_of_remote_attr_payloads = -1;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free cfg exchange data.                                      shade{1.0}
 */
void ike_free_cfg_ed(SshIkeCfgSAPacketData ed)
{
  int i;

  if (ed->local_attrs)
    {
      for (i = 0; i < ed->number_of_local_attr_payloads; i++)
        {
          if (ed->local_attrs[i])
            {
              ssh_free(ed->local_attrs[i]->attributes);
              ssh_free(ed->local_attrs[i]);
            }
        }
      ssh_free(ed->local_attrs);
    }
  ssh_free(ed->remote_attrs);
  ssh_free(ed);
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


/*                                                              shade{0.9}
 * Allocate and initialize phase I pm info.                     shade{1.0}
 */
Boolean ike_alloc_phase_i_pm_info(SshIkePMPhaseI *pm_info_ptr,
                                  SshIkeNegotiation negotiation,
                                  SshIkePMContext pm,
                                  SshIkeCookies cookies,
                                  const unsigned char *local_ip,
                                  const unsigned char *local_port,
                                  const unsigned char *remote_ip,
                                  const unsigned char *remote_port,
                                  int major_version,
                                  int minor_version,
                                  SshIkeExchangeType exchange_type,
                                  Boolean this_end_is_initiator)
{
  SshIkePMPhaseI pm_info;

  *pm_info_ptr = NULL;

  pm_info = ssh_calloc(1, sizeof(*pm_info));
  if (pm_info == NULL)
    return FALSE;

  pm_info->pm = pm;
  pm_info->cookies = cookies;
  pm_info->negotiation = negotiation;
  pm_info->local_id_txt = ssh_strdup("No Id");
  pm_info->remote_id_txt = ssh_strdup("No Id");
  pm_info->local_ip = ssh_strdup(local_ip);
  pm_info->local_port = ssh_strdup(local_port);
  pm_info->remote_ip = ssh_strdup(remote_ip);
  pm_info->remote_port = ssh_strdup(remote_port);
  if (pm_info->local_id_txt == NULL ||
      pm_info->remote_id_txt == NULL ||
      pm_info->local_ip == NULL ||
      pm_info->local_port == NULL ||
      pm_info->remote_ip == NULL ||
      pm_info->remote_port == NULL)
    {
      ssh_free(pm_info->local_id_txt);
      ssh_free(pm_info->remote_id_txt);
      ssh_free(pm_info->local_ip);
      ssh_free(pm_info->local_port);
      ssh_free(pm_info->remote_ip);
      ssh_free(pm_info->remote_port);
      ssh_free(pm_info);
      return FALSE;
    }
  pm_info->major_version = major_version;
  pm_info->minor_version = minor_version;
  pm_info->exchange_type = exchange_type;
  pm_info->this_end_is_initiator = this_end_is_initiator;
  pm_info->auth_method_type = SSH_IKE_AUTH_METHOD_ANY;

  *pm_info_ptr = pm_info;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free phase I pm info.                                        shade{1.0}
 */
void ike_free_phase_i_pm_info(SshIkePMPhaseI pm_info)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  int i;
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_policy_isakmp_sa_freed(pm_info);

  if (pm_info->local_id)
    ike_free_id_payload(pm_info->local_id, TRUE);
  ssh_free(pm_info->local_id_txt);

  if (pm_info->remote_id)
    ike_free_id_payload(pm_info->remote_id, TRUE);
  ssh_free(pm_info->remote_id_txt);

  ssh_free(pm_info->local_ip);
  ssh_free(pm_info->local_port);
  ssh_free(pm_info->remote_ip);
  ssh_free(pm_info->remote_port);

  ssh_free(pm_info->auth_data);
  ssh_free(pm_info->own_auth_data);

#ifdef SSHDIST_IKE_CERT_AUTH
  if (pm_info->public_key)
    ssh_public_key_free(pm_info->public_key);

  if (pm_info->certificates)
    {
      for (i = 0; i < pm_info->number_of_certificates; i++)
        {
          ssh_free(pm_info->certificates[i]);
        }
      ssh_free(pm_info->certificates);
    }
  ssh_free(pm_info->certificate_lens);
  ssh_free(pm_info->certificate_encodings);
#endif /* SSHDIST_IKE_CERT_AUTH */
  ssh_free(pm_info->policy_manager_data);
  ssh_free(pm_info);
}

/*                                                              shade{0.9}
 * Allocate and initialize quick mode pm info.                  shade{1.0}
 */
Boolean ike_alloc_qm_pm_info(SshIkePMPhaseQm *pm_info_ptr,
                             SshIkeNegotiation negotiation,
                             SshIkePMContext pm,
                             SshIkePMPhaseI phase_i_pm_info,
                             const unsigned char *local_ip,
                             const unsigned char *local_port,
                             const unsigned char *remote_ip,
                             const unsigned char *remote_port,
                             SshIkeExchangeType exchange_type,
                             Boolean this_end_is_initiator,
                             SshUInt32 message_id)
{
  SshIkePMPhaseQm pm_info;

  *pm_info_ptr = NULL;

  pm_info = ssh_calloc(1, sizeof(*pm_info));
  if (pm_info == NULL)
    return FALSE;

  pm_info->pm = pm;
  pm_info->phase_i = phase_i_pm_info;
  pm_info->negotiation = negotiation;
  pm_info->local_i_id_txt = ssh_strdup("No Id");
  pm_info->local_r_id_txt = ssh_strdup("No Id");
  pm_info->remote_i_id_txt = ssh_strdup("No Id");
  pm_info->remote_r_id_txt = ssh_strdup("No Id");
  pm_info->local_ip = ssh_strdup(local_ip);
  pm_info->local_port = ssh_strdup(local_port);
  pm_info->remote_ip = ssh_strdup(remote_ip);
  pm_info->remote_port = ssh_strdup(remote_port);
  if (pm_info->local_i_id_txt == NULL ||
      pm_info->local_r_id_txt == NULL ||
      pm_info->remote_i_id_txt == NULL ||
      pm_info->remote_r_id_txt == NULL ||
      pm_info->local_ip == NULL ||
      pm_info->local_port == NULL ||
      pm_info->remote_ip == NULL ||
      pm_info->remote_port == NULL)
    {
      ssh_free(pm_info->local_i_id_txt);
      ssh_free(pm_info->local_r_id_txt);
      ssh_free(pm_info->remote_i_id_txt);
      ssh_free(pm_info->remote_r_id_txt);
      ssh_free(pm_info->local_ip);
      ssh_free(pm_info->local_port);
      ssh_free(pm_info->remote_ip);
      ssh_free(pm_info->remote_port);
      ssh_free(pm_info);
      return FALSE;
    }
  pm_info->exchange_type = exchange_type;
  pm_info->this_end_is_initiator = this_end_is_initiator;
  pm_info->message_id = message_id;

  *pm_info_ptr = pm_info;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free quick mode pm info.                                     shade{1.0}
 */
void ike_free_qm_pm_info(SshIkePMPhaseQm pm_info)
{
  ssh_policy_qm_sa_freed(pm_info);

  if (pm_info->local_i_id)
    ike_free_id_payload(pm_info->local_i_id, TRUE);
  ssh_free(pm_info->local_i_id_txt);

  if (pm_info->local_r_id)
    ike_free_id_payload(pm_info->local_r_id, TRUE);
  ssh_free(pm_info->local_r_id_txt);

  if (pm_info->remote_i_id)
    ike_free_id_payload(pm_info->remote_i_id, TRUE);
  ssh_free(pm_info->remote_i_id_txt);

  if (pm_info->remote_r_id)
    ike_free_id_payload(pm_info->remote_r_id, TRUE);
  ssh_free(pm_info->remote_r_id_txt);

  ssh_free(pm_info->local_ip);
  ssh_free(pm_info->local_port);
  ssh_free(pm_info->remote_ip);
  ssh_free(pm_info->remote_port);
  ssh_free(pm_info->policy_manager_data);
  ssh_free(pm_info);
}


/*                                                              shade{0.9}
 * Allocate and initialize phase II pm info.                    shade{1.0}
 */
Boolean ike_alloc_phase_ii_pm_info(SshIkePMPhaseII *pm_info_ptr,
                                   SshIkeNegotiation negotiation,
                                   SshIkePMContext pm,
                                   SshIkePMPhaseI phase_i_pm_info,
                                   const unsigned char *local_ip,
                                   const unsigned char *local_port,
                                   const unsigned char *remote_ip,
                                   const unsigned char *remote_port,
                                   SshIkeExchangeType exchange_type,
                                   Boolean this_end_is_initiator,
                                   SshUInt32 message_id)
{
  SshIkePMPhaseII pm_info;

  *pm_info_ptr = NULL;

  pm_info = ssh_calloc(1, sizeof(*pm_info));
  if (pm_info == NULL)
    return FALSE;

  pm_info->pm = pm;
  pm_info->phase_i = phase_i_pm_info;
  pm_info->negotiation = negotiation;
  pm_info->local_ip = ssh_strdup(local_ip);
  pm_info->local_port = ssh_strdup(local_port);
  pm_info->remote_ip = ssh_strdup(remote_ip);
  pm_info->remote_port = ssh_strdup(remote_port);

  if (pm_info->local_ip == NULL ||
      pm_info->local_port == NULL ||
      pm_info->remote_ip == NULL ||
      pm_info->remote_port == NULL)
    {
      ssh_free(pm_info->local_ip);
      ssh_free(pm_info->local_port);
      ssh_free(pm_info->remote_ip);
      ssh_free(pm_info->remote_port);
      ssh_free(pm_info);
      return FALSE;
    }
  pm_info->exchange_type = exchange_type;
  pm_info->this_end_is_initiator = this_end_is_initiator;
  pm_info->message_id = message_id;

  *pm_info_ptr = pm_info;
  return TRUE;
}


/*                                                              shade{0.9}
 * Free phase II pm info.                                       shade{1.0}
 */
void ike_free_phase_ii_pm_info(SshIkePMPhaseII pm_info)
{
  ssh_policy_phase_ii_sa_freed(pm_info);

  ssh_free(pm_info->local_ip);
  ssh_free(pm_info->local_port);
  ssh_free(pm_info->remote_ip);
  ssh_free(pm_info->remote_port);
  ssh_free(pm_info->policy_manager_data);
  ssh_free(pm_info);
}


/*                                                              shade{0.9}
 * Free common negotiation info.                                shade{1.0}
 */
void ike_free_negotiation(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));

  if (negotiation->ed)
    ike_free_ed(negotiation->ed);
  negotiation->ed = NULL;
}

/*                                                              shade{0.9}
 * Free isakmp sa negotiation.                                  shade{1.0}
 */
void ike_free_negotiation_isakmp(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));

  ike_free_negotiation(negotiation);
  if (negotiation->ike_ed)
    ike_free_ike_ed(negotiation->ike_ed);
  negotiation->ike_ed = NULL;
}


/*                                                              shade{0.9}
 * Free qm sa negotiation.                                      shade{1.0}
 */
void ike_free_negotiation_qm(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));
  ike_free_negotiation(negotiation);

  if (negotiation->qm_ed)
    ike_free_qm_ed(negotiation->qm_ed);
  negotiation->qm_ed = NULL;

  if (negotiation->qm_pm_info)
    ike_free_qm_pm_info(negotiation->qm_pm_info);
  negotiation->qm_pm_info = NULL;
}


/*                                                              shade{0.9}
 * Free new group mode sa negotiation.                          shade{1.0}
 */
void ike_free_negotiation_ngm(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));
  ike_free_negotiation(negotiation);

  if (negotiation->ngm_ed)
    ike_free_ngm_ed(negotiation->ngm_ed);
  negotiation->ngm_ed = NULL;

  if (negotiation->ngm_pm_info)
    ike_free_phase_ii_pm_info(negotiation->ngm_pm_info);
  negotiation->ngm_pm_info = NULL;
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * Free cfg mode sa negotiation.                                shade{1.0}
 */
void ike_free_negotiation_cfg(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));
  ike_free_negotiation(negotiation);

  if (negotiation->cfg_ed)
    ike_free_cfg_ed(negotiation->cfg_ed);
  negotiation->cfg_ed = NULL;

  if (negotiation->cfg_pm_info)
    ike_free_phase_ii_pm_info(negotiation->cfg_pm_info);
  negotiation->cfg_pm_info = NULL;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


/*                                                              shade{0.9}
 * Free info mode sa negotiation.                               shade{1.0}
 */
void ike_free_negotiation_info(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start, nego = %d", negotiation->negotiation_index));
  ike_free_negotiation(negotiation);

  if (negotiation->info_pm_info)
    ike_free_phase_ii_pm_info(negotiation->info_pm_info);
  negotiation->info_pm_info = NULL;
}


/*                                                              shade{0.9}
 * Free sa structure.                                           shade{1.0}
 */
void ike_free_sa(SshIkeSA sa)
{
  int i;
  SSH_DEBUG(5, ("Start"));

  ssh_free(sa->negotiations);
  if (sa->private_groups != NULL)
    {
      for (i = 0; i < sa->private_groups_count; i++)
        {
          ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->private_groups[i]);
          ssh_pk_group_free(sa->private_groups[i]->group);
#ifdef SSHDIST_EXTERNALKEY
          if (sa->private_groups[i]->old_group)
            ssh_pk_group_free(sa->private_groups[i]->old_group);
          ssh_operation_abort(sa->private_groups[i]->accelerator_handle);
#endif /* SSHDIST_EXTERNALKEY */

          ssh_free(sa->private_groups[i]);
        }
      ssh_free(sa->private_groups);
    }

  if (sa->cipher_key)
    {
      memset(sa->cipher_key, 0, sa->cipher_key_len);
      ssh_free(sa->cipher_key);
    }

  ike_clear_skeyid(&(sa->skeyid));

  if (sa->cipher_iv)
    {
      memset(sa->cipher_iv, 0, sa->cipher_iv_len);
      ssh_free(sa->cipher_iv);
    }

  ssh_free(sa);
}

/*                                                              shade{0.9}
 * Initialize isakmp sa structure.                              shade{1.0}
 */
Boolean ike_init_isakmp_sa(SshIkeSA sa,
                           const unsigned char *local_ip,
                           const unsigned char *local_port,
                           const unsigned char *remote_ip,
                           const unsigned char *remote_port,
                           int major_version,
                           int minor_version,
                           SshIkeExchangeType exchange_type,
                           Boolean this_end_is_initiator,
                           Boolean use_extended_retry)
{
  SshIkeNegotiation negotiation;

  SSH_DEBUG(5, ("Start, remote = %s:%s, initiator = %d",
                remote_ip, remote_port, this_end_is_initiator));

  /* Server_context is set in the ike_sa_allocate function */
  sa->lock_flags &= ~(SSH_IKE_ISAKMP_LOCK_FLAG_UNINITIALIZED);
  /* Cookies are set in the ike_sa_allocate function */
  sa->phase_1_done = 0;
  sa->wired = 0;
  sa->use_natt = 0;

  sa->isakmp_negotiation = ssh_calloc(1, sizeof(struct SshIkeNegotiationRec));
  if (sa->isakmp_negotiation == NULL)
    return FALSE;
  sa->allocated_negotiations = 10;
  sa->negotiations = ssh_calloc(sa->allocated_negotiations,
                                sizeof(SshIkeNegotiation));
  if (sa->negotiations == NULL)
    {
      sa->allocated_negotiations = 0;
      ssh_free(sa->isakmp_negotiation);
      sa->isakmp_negotiation = NULL;
      return FALSE;
    }
  sa->created_time = ssh_time();
  sa->last_use_time = sa->created_time;
  sa->encryption_algorithm_name = ssh_custr("unknown");
  sa->hash_algorithm_name = sa->encryption_algorithm_name;
  sa->prf_algorithm_name = sa->encryption_algorithm_name;

  sa->private_payload_phase_1_check =
    sa->server_context->isakmp_context->private_payload_phase_1_check;
  sa->private_payload_phase_1_input =
    sa->server_context->isakmp_context->private_payload_phase_1_input;
  sa->private_payload_phase_1_output =
    sa->server_context->isakmp_context->private_payload_phase_1_output;

  sa->private_payload_phase_2_check =
    sa->server_context->isakmp_context->private_payload_phase_2_check;
  sa->private_payload_phase_2_input =
    sa->server_context->isakmp_context->private_payload_phase_2_input;
  sa->private_payload_phase_2_output =
    sa->server_context->isakmp_context->private_payload_phase_2_output;

  sa->private_payload_phase_qm_check =
    sa->server_context->isakmp_context->private_payload_phase_qm_check;
  sa->private_payload_phase_qm_input =
    sa->server_context->isakmp_context->private_payload_phase_qm_input;
  sa->private_payload_phase_qm_output =
    sa->server_context->isakmp_context->private_payload_phase_qm_output;

  sa->private_payload_context =
    sa->server_context->isakmp_context->private_payload_context;

  sa->skeyid.initialized = FALSE;

  if (use_extended_retry)
    {
      sa->retry_limit =
        sa->server_context->isakmp_context->extended_retry_limit;
      sa->retry_timer =
        sa->server_context->isakmp_context->extended_retry_timer;
      sa->retry_timer_usec =
        sa->server_context->isakmp_context->extended_retry_timer_usec;
      sa->retry_timer_max =
        sa->server_context->isakmp_context->extended_retry_timer_max;
      sa->retry_timer_max_usec =
        sa->server_context->isakmp_context->extended_retry_timer_max_usec;
      sa->expire_timer =
        sa->server_context->isakmp_context->extended_expire_timer;
      sa->expire_timer_usec =
        sa->server_context->isakmp_context->extended_expire_timer_usec;
    }
  else
    {
      sa->retry_limit =
        sa->server_context->isakmp_context->base_retry_limit;
      sa->retry_timer =
        sa->server_context->isakmp_context->base_retry_timer;
      sa->retry_timer_usec =
        sa->server_context->isakmp_context->base_retry_timer_usec;
      sa->retry_timer_max =
        sa->server_context->isakmp_context->base_retry_timer_max;
      sa->retry_timer_max_usec =
        sa->server_context->isakmp_context->base_retry_timer_max_usec;
      sa->expire_timer =
        sa->server_context->isakmp_context->base_expire_timer;
      sa->expire_timer_usec =
        sa->server_context->isakmp_context->base_expire_timer_usec;
    }

  negotiation = sa->isakmp_negotiation;
  negotiation->sa = sa;
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  negotiation->policy_functions =
    sa->server_context->isakmp_context->policy_functions;
#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */
  negotiation->negotiation_index = -1;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;
  negotiation->exchange_type = exchange_type;
  if (!ike_alloc_ed(&negotiation->ed,
                    sa->server_context->isakmp_context->default_compat_flags,
                    sa->retry_limit, sa->retry_timer, sa->retry_timer_usec,
                    sa->retry_timer_max, sa->retry_timer_max_usec,
                    sa->expire_timer, sa->expire_timer_usec, 0))
    {
      ssh_free(sa->isakmp_negotiation);
      sa->isakmp_negotiation = NULL;
      ssh_free(sa->negotiations);
      return FALSE;
    }

  negotiation->ed->current_state = SSH_IKE_ST_START_SA_NEGOTIATION_R;

  negotiation->ed->private_payload_phase_1_check =
    sa->private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    sa->private_payload_phase_1_input;
  negotiation->ed->private_payload_phase_1_output =
    sa->private_payload_phase_1_output;

  negotiation->ed->private_payload_phase_2_check =
    sa->private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    sa->private_payload_phase_2_input;
  negotiation->ed->private_payload_phase_2_output =
    sa->private_payload_phase_2_output;

  negotiation->ed->private_payload_phase_qm_check =
    sa->private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    sa->private_payload_phase_qm_input;
  negotiation->ed->private_payload_phase_qm_output =
    sa->private_payload_phase_qm_output;
  negotiation->ed->private_payload_context =
    sa->private_payload_context;

  if (!ike_alloc_ike_ed(&(negotiation->ike_ed)))
    {
      ike_free_ed(negotiation->ed);
      ssh_free(sa->isakmp_negotiation);
      sa->isakmp_negotiation = NULL;
      ssh_free(sa->negotiations);
      return FALSE;
    }

  if (!ike_alloc_phase_i_pm_info(&(negotiation->ike_pm_info),
                                 negotiation,
                                 sa->server_context->pm,
                                 &(sa->cookies),
                                 local_ip, local_port, remote_ip, remote_port,
                                 major_version, minor_version, exchange_type,
                                 this_end_is_initiator))
    {
      ike_free_ike_ed(negotiation->ike_ed);
      ike_free_ed(negotiation->ed);
      ssh_free(sa->isakmp_negotiation);
      sa->isakmp_negotiation = NULL;
      ssh_free(sa->negotiations);
      return FALSE;
    }

  sa->server_context->statistics->total_attempts++;
  if (this_end_is_initiator)
    sa->server_context->statistics->total_attempts_initiated++;
  else
    sa->server_context->statistics->total_attempts_responded++;

  ssh_xregister_timeout(negotiation->ed->expire_timer,
                       negotiation->ed->expire_timer_usec,
                       ike_remove_callback,
                       negotiation);
  return TRUE;
}


/*                                                              shade{0.9}
 * Allocate new negotiation.                                    shade{1.0}
 */
SshIkeNegotiation ike_alloc_negotiation(SshIkeSA sa)
{
  int i;

  SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx}",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4)));

  /* find free slot */
  for (i = 0; i < sa->allocated_negotiations; i++)
    {
      if (sa->negotiations[i] == NULL)
        break;
    }
  if (i == sa->allocated_negotiations)
    {
      /* Enlarge negotiation table */
      SSH_DEBUG(6, ("Enlarging negotiation table"));
      i = sa->allocated_negotiations;
      if (!ssh_recalloc(&sa->negotiations,
                        &sa->allocated_negotiations,
                        sa->allocated_negotiations + 10,
                        sizeof(SshIkeNegotiation)))
        {
          return NULL;
        }
    }
  sa->negotiations[i] = ssh_calloc(1, sizeof(struct SshIkeNegotiationRec));
  if (sa->negotiations[i] == NULL)
    return NULL;
  sa->negotiations[i]->negotiation_index = i;
  sa->negotiations[i]->sa = sa;
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  sa->negotiations[i]->policy_functions =
    sa->server_context->isakmp_context->policy_functions;
#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */
  if (i >= sa->number_of_negotiations)
    sa->number_of_negotiations = i + 1;
  SSH_DEBUG(7, ("Found slot %d, max %d", i, sa->number_of_negotiations));
  return sa->negotiations[i];
}

/*                                                              shade{0.9}
 * Initialize info negotiation structure.                       shade{1.0}
 */
Boolean ike_init_info_negotiation(SshIkeNegotiation negotiation,
                                  SshIkePMPhaseI phase_i_pm_info,
                                  const unsigned char *local_ip,
                                  const unsigned char *local_port,
                                  const unsigned char *remote_ip,
                                  const unsigned char *remote_port,
                                  int major_version,
                                  int minor_version,
                                  Boolean this_end_is_initiator,
                                  SshUInt32 message_id)
{
  SshIkeSA sa;

  sa = negotiation->sa;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;
  negotiation->exchange_type = SSH_IKE_XCHG_TYPE_INFO;
  if (!ike_alloc_ed(&negotiation->ed,
                    sa->server_context->isakmp_context->default_compat_flags,
                    sa->retry_limit, sa->retry_timer, sa->retry_timer_usec,
                    sa->retry_timer_max, sa->retry_timer_max_usec,
                    sa->expire_timer, sa->expire_timer_usec, message_id))
    {
      return FALSE;
    }

  negotiation->ed->current_state = SSH_IKE_ST_DONE;

  negotiation->ed->private_payload_phase_1_check =
    sa->private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    sa->private_payload_phase_1_input;
  negotiation->ed->private_payload_phase_1_output =
    sa->private_payload_phase_1_output;

  negotiation->ed->private_payload_phase_2_check =
    sa->private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    sa->private_payload_phase_2_input;
  negotiation->ed->private_payload_phase_2_output =
    sa->private_payload_phase_2_output;

  negotiation->ed->private_payload_phase_qm_check =
    sa->private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    sa->private_payload_phase_qm_input;
  negotiation->ed->private_payload_phase_qm_output =
    sa->private_payload_phase_qm_output;

  negotiation->ed->private_payload_context =
    sa->private_payload_context;

  if (!ike_alloc_phase_ii_pm_info(&(negotiation->info_pm_info),
                                  negotiation,
                                  sa->server_context->pm,
                                  phase_i_pm_info,
                                  local_ip, local_port, remote_ip, remote_port,
                                  SSH_IKE_XCHG_TYPE_INFO,
                                  this_end_is_initiator, 0))
    {
      return FALSE;
    }
  return TRUE;
}


/*                                                              shade{0.9}
 * Create random message id.                                    shade{1.0}
 */
SshUInt32 ike_random_message_id(SshIkeSA sa,
                                SshIkeServerContext server_context)
{
  SshUInt32 message_id;
  int i;

retry:
  do {
    message_id =
      ssh_random_get_byte() << 24 |
      ssh_random_get_byte() << 16 |
      ssh_random_get_byte() << 8 |
      ssh_random_get_byte();
  } while (message_id == 0);

  for (i = 0; i < sa->number_of_negotiations; i++)
    {
      if (sa->negotiations[i] != NULL &&
          sa->negotiations[i]->ed != NULL &&
          sa->negotiations[i]->ed->message_id == message_id)
        goto retry;
    }
  return message_id;
}


/*                                                              shade{0.9}
 * Initialize quick mode negotiation structure.                 shade{1.0}
 */
Boolean ike_init_qm_negotiation(SshIkeNegotiation negotiation,
                                SshIkePMPhaseI phase_i_pm_info,
                                const unsigned char *local_ip,
                                const unsigned char *local_port,
                                const unsigned char *remote_ip,
                                const unsigned char *remote_port,
                                SshIkeExchangeType exchange_type,
                                Boolean this_end_is_initiator,
                                SshUInt32 message_id,
                                Boolean use_extended_retry)
{
  SshIkeSA sa;
  SSH_DEBUG(5, ("Start, initiator = %d, message_id = %08lx",
                this_end_is_initiator, (unsigned long) message_id));

  sa = negotiation->sa;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;
  negotiation->exchange_type = exchange_type;
  if (use_extended_retry)
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        extended_retry_limit,
                        sa->server_context->isakmp_context->
                        extended_retry_timer,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        extended_expire_timer,
                        sa->server_context->isakmp_context->
                        extended_expire_timer_usec,
                        message_id))
        return FALSE;
    }
  else
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        base_retry_limit,
                        sa->server_context->isakmp_context->
                        base_retry_timer,
                        sa->server_context->isakmp_context->
                        base_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        base_expire_timer,
                        sa->server_context->isakmp_context->
                        base_expire_timer_usec,
                        message_id))
        return FALSE;
    }

  negotiation->ed->current_state = SSH_IKE_ST_START_QM_R;

  negotiation->ed->private_payload_phase_1_check =
    sa->private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    sa->private_payload_phase_1_input;
  negotiation->ed->private_payload_phase_1_output =
    sa->private_payload_phase_1_output;

  negotiation->ed->private_payload_phase_2_check =
    sa->private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    sa->private_payload_phase_2_input;
  negotiation->ed->private_payload_phase_2_output =
    sa->private_payload_phase_2_output;

  negotiation->ed->private_payload_phase_qm_check =
    sa->private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    sa->private_payload_phase_qm_input;
  negotiation->ed->private_payload_phase_qm_output =
    sa->private_payload_phase_qm_output;

  negotiation->ed->private_payload_context =
    sa->private_payload_context;

  if (!ike_alloc_qm_pm_info(&(negotiation->qm_pm_info),
                            negotiation,
                            sa->server_context->pm,
                            phase_i_pm_info,
                            local_ip, local_port, remote_ip, remote_port,
                            exchange_type, this_end_is_initiator, message_id))
    return FALSE;
  if (!ike_alloc_qm_ed(&(negotiation->qm_ed)))
    return FALSE;

  ssh_xregister_timeout(negotiation->ed->expire_timer,
                       negotiation->ed->expire_timer_usec,
                       ike_remove_callback,
                       negotiation);
  return TRUE;
}


/*                                                              shade{0.9}
 * Initialize ngm negotiation structure.                        shade{1.0}
 */
Boolean ike_init_ngm_negotiation(SshIkeNegotiation negotiation,
                                 SshIkePMPhaseI phase_i_pm_info,
                                 const unsigned char *local_ip,
                                 const unsigned char *local_port,
                                 const unsigned char *remote_ip,
                                 const unsigned char *remote_port,
                                 int major_version,
                                 int minor_version,
                                 SshIkeExchangeType exchange_type,
                                 Boolean this_end_is_initiator,
                                 SshUInt32 message_id,
                                 Boolean use_extended_retry)
{
  SshIkeSA sa;
  SSH_DEBUG(5, ("Start, initiator = %d, message_id = %08lx",
                this_end_is_initiator, (unsigned long) message_id));

  sa = negotiation->sa;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;
  negotiation->exchange_type = exchange_type;
  if (use_extended_retry)
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        extended_retry_limit,
                        sa->server_context->isakmp_context->
                        extended_retry_timer,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        extended_expire_timer,
                        sa->server_context->isakmp_context->
                        extended_expire_timer_usec,
                        message_id))
        return FALSE;
    }
  else
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        base_retry_limit,
                        sa->server_context->isakmp_context->
                        base_retry_timer,
                        sa->server_context->isakmp_context->
                        base_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        base_expire_timer,
                        sa->server_context->isakmp_context->
                        base_expire_timer_usec,
                        message_id))
        return FALSE;
    }

  negotiation->ed->current_state = SSH_IKE_ST_START_NGM_R;

  negotiation->ed->private_payload_phase_1_check =
    sa->private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    sa->private_payload_phase_1_input;
  negotiation->ed->private_payload_phase_1_output =
    sa->private_payload_phase_1_output;

  negotiation->ed->private_payload_phase_2_check =
    sa->private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    sa->private_payload_phase_2_input;
  negotiation->ed->private_payload_phase_2_output =
    sa->private_payload_phase_2_output;

  negotiation->ed->private_payload_phase_qm_check =
    sa->private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    sa->private_payload_phase_qm_input;
  negotiation->ed->private_payload_phase_qm_output =
    sa->private_payload_phase_qm_output;

  negotiation->ed->private_payload_context =
    sa->private_payload_context;

  if (!ike_alloc_phase_ii_pm_info(&(negotiation->ngm_pm_info),
                                  negotiation,
                                  sa->server_context->pm,
                                  phase_i_pm_info,
                                  local_ip, local_port, remote_ip, remote_port,
                                  exchange_type,
                                  this_end_is_initiator, message_id))
    return FALSE;
  if (!ike_alloc_ngm_ed(&(negotiation->ngm_ed)))
    return FALSE;

  ssh_xregister_timeout(negotiation->ed->expire_timer,
                       negotiation->ed->expire_timer_usec,
                       ike_remove_callback,
                       negotiation);
  return TRUE;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * Initialize cfg negotiation structure.                        shade{1.0}
 */
Boolean ike_init_cfg_negotiation(SshIkeNegotiation negotiation,
                                 SshIkePMPhaseI phase_i_pm_info,
                                 const unsigned char *local_ip,
                                 const unsigned char *local_port,
                                 const unsigned char *remote_ip,
                                 const unsigned char *remote_port,
                                 int major_version,
                                 int minor_version,
                                 SshIkeExchangeType exchange_type,
                                 Boolean this_end_is_initiator,
                                 SshUInt32 message_id,
                                 Boolean use_extended_retry)
{
  SshIkeSA sa;
  SSH_DEBUG(5, ("Start, initiator = %d, message_id = %08lx",
                this_end_is_initiator, (unsigned long) message_id));

  sa = negotiation->sa;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;
  negotiation->exchange_type = exchange_type;
  if (use_extended_retry)
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        extended_retry_limit,
                        sa->server_context->isakmp_context->
                        extended_retry_timer,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max,
                        sa->server_context->isakmp_context->
                        extended_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        extended_expire_timer,
                        sa->server_context->isakmp_context->
                        extended_expire_timer_usec,
                        message_id))
        return FALSE;
    }
  else
    {
      if (!ike_alloc_ed(&negotiation->ed,
                        sa->server_context->isakmp_context->
                        default_compat_flags,
                        sa->server_context->isakmp_context->
                        base_retry_limit,
                        sa->server_context->isakmp_context->
                        base_retry_timer,
                        sa->server_context->isakmp_context->
                        base_retry_timer_usec,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max,
                        sa->server_context->isakmp_context->
                        base_retry_timer_max_usec,
                        sa->server_context->isakmp_context->
                        base_expire_timer,
                        sa->server_context->isakmp_context->
                        base_expire_timer_usec,
                        message_id))
        return FALSE;
    }

  negotiation->ed->current_state = SSH_IKE_ST_START_CFG_R;

  negotiation->ed->private_payload_phase_1_check =
    sa->private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    sa->private_payload_phase_1_input;
  negotiation->ed->private_payload_phase_1_output =
    sa->private_payload_phase_1_output;

  negotiation->ed->private_payload_phase_2_check =
    sa->private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    sa->private_payload_phase_2_input;
  negotiation->ed->private_payload_phase_2_output =
    sa->private_payload_phase_2_output;

  negotiation->ed->private_payload_phase_qm_check =
    sa->private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    sa->private_payload_phase_qm_input;
  negotiation->ed->private_payload_phase_qm_output =
    sa->private_payload_phase_qm_output;

  negotiation->ed->private_payload_context =
    sa->private_payload_context;

  if (!ike_alloc_phase_ii_pm_info(&(negotiation->cfg_pm_info),
                                  negotiation,
                                  sa->server_context->pm,
                                  phase_i_pm_info,
                                  local_ip, local_port, remote_ip, remote_port,
                                  exchange_type,
                                  this_end_is_initiator, message_id))
    return FALSE;

  if (!ike_alloc_cfg_ed(&(negotiation->cfg_ed)))
    return FALSE;

  ssh_xregister_timeout(negotiation->ed->expire_timer,
                       negotiation->ed->expire_timer_usec,
                       ike_remove_callback,
                       negotiation);
  return TRUE;
}

/*                                                              shade{0.9}
 * Restart cfg negotiation                                      shade{1.0}
 */
Boolean ike_restart_cfg_negotiation(SshIkeNegotiation negotiation)
{
  SSH_DEBUG(5, ("Start"));

  if (negotiation->cfg_ed)
    ike_free_cfg_ed(negotiation->cfg_ed);

  if (!ike_alloc_cfg_ed(&(negotiation->cfg_ed)))
    return FALSE;

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, negotiation);
  ssh_xregister_timeout(negotiation->ed->expire_timer,
                       negotiation->ed->expire_timer_usec,
                       ike_remove_callback,
                       negotiation);
  return TRUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * Free id payload.                                             shade{1.0}
 */
void ike_free_id_payload(SshIkePayloadID id, Boolean free_toplevel_struct)
{
  SSH_DEBUG(5, ("Start, id type = %d", id->id_type));
  if (id->id_type == IPSEC_ID_FQDN)
    ssh_free(id->identification.fqdn);
  else if (id->id_type == IPSEC_ID_USER_FQDN)
    ssh_free(id->identification.user_fqdn);
  else if (id->id_type == IPSEC_ID_DER_ASN1_DN ||
           id->id_type == IPSEC_ID_DER_ASN1_GN)
    ssh_free(id->identification.asn1_data);
  else if (id->id_type == IPSEC_ID_KEY_ID)
    ssh_free(id->identification.key_id);
#ifdef SSHDIST_IKE_ID_LIST
  else if (id->id_type == IPSEC_ID_LIST)
    {
      int cnt;

      if (id->identification.id_list_items)
        {
          for (cnt = 0;
              cnt < id->identification.id_list_number_of_items;
              cnt++)
            ike_free_id_payload(&(id->identification.id_list_items[cnt]),
                                FALSE);
          ssh_free(id->identification.id_list_items);
        }
    }
#endif /* SSHDIST_IKE_ID_LIST */
  if (id->raw_id_packet)
    ssh_free(id->raw_id_packet);
  if (free_toplevel_struct)
    ssh_free(id);
}

/*                                                              shade{0.9}
 * Free sa payload.                                             shade{1.0}
 */
void ssh_ike_free_sa_payload(SshIkePayloadSA sa)
{
  int i, j, k;

  SSH_DEBUG(5, ("Start, # prop = %d", sa->number_of_proposals));
  ssh_free(sa->situation.secrecy_level_data);
  ssh_free(sa->situation.secrecy_category_bitmap_data);
  ssh_free(sa->situation.integrity_level_data);
  ssh_free(sa->situation.integrity_category_bitmap_data);

  if (sa->proposals)
    {
      for (i = 0; i < sa->number_of_proposals; i++)
        {
          if (sa->proposals[i].protocols)
            {
              for (j = 0; j < sa->proposals[i].number_of_protocols; j++)
                {
                  if (sa->proposals[i].protocols[j].transforms)
                    {
                      for (k = 0;
                          k < sa->proposals[i].protocols[j].
                            number_of_transforms;
                          k++)
                        ssh_free(sa->proposals[i].protocols[j].
                                  transforms[k].sa_attributes);
                      ssh_free(sa->proposals[i].protocols[j].transforms);
                    }

                  if (sa->proposals[i].protocols[j].spi)
                    {
                      ssh_free(sa->proposals[i].protocols[j].spi);
                    }
                }
              ssh_free(sa->proposals[i].protocols);
            }
        }
      ssh_free(sa->proposals);
    }

  ssh_free(sa);
}


/*                                                              shade{0.9}
 * Initialize info message                                      shade{1.0}
 */
Boolean ike_init_info_exchange(SshIkeServerContext server,
                               SshIkeSA sa,
                               SshIkePacket *isakmp_packet_out,
                               SshIkeNegotiation *info_negotiation_out,
                               SshIkePayload *pl_out)
{
  SshUInt32 message_id;
  int j;
  unsigned char n[64], p[6];
  SshUInt16 local_port;

  /* Create random message_id */
  message_id = ike_random_message_id(sa, server);
  *isakmp_packet_out = NULL;

  /* Allocate new negotiation */
  *info_negotiation_out = ike_alloc_negotiation(sa);
  if (*info_negotiation_out == NULL)
    return FALSE;
  SSH_DEBUG(8, ("New informational negotiation message_id = %08lx "
                "initialized using slot %d",
                (unsigned long) message_id,
                (*info_negotiation_out)->negotiation_index));

  local_port = server->normal_local_port;
#ifdef SSHDIST_IKEV2
  if (sa->use_natt)
    local_port = server->nat_t_local_port;
#endif /* SSHDIST_IKEV2 */

  if (!ike_init_info_negotiation(*info_negotiation_out,
                                 sa->isakmp_negotiation->ike_pm_info,
                                 ike_ip_string(server->ip_address,
                                               n, sizeof(n)),
                                 ike_port_string(local_port,
                                                 p, sizeof(p)),
                                 sa->isakmp_negotiation->
                                 ike_pm_info->remote_ip,
                                 sa->isakmp_negotiation->
                                 ike_pm_info->remote_port,
                                 sa->isakmp_negotiation->
                                 ike_pm_info->major_version,
                                 sa->isakmp_negotiation->
                                 ike_pm_info->minor_version,
                                 TRUE, message_id))
    {
      (*info_negotiation_out)->notification_state =
        SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
      goto error;
    }

  /* Mark it so that we never send any notifications for this */
  (*info_negotiation_out)->notification_state =
    SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;

  *isakmp_packet_out = ssh_calloc(1, sizeof(struct SshIkePacketRec));
  if (*isakmp_packet_out == NULL)
    goto error;
  memcpy((*isakmp_packet_out)->cookies.initiator_cookie,
         sa->cookies.initiator_cookie, SSH_IKE_COOKIE_LENGTH);
  memcpy((*isakmp_packet_out)->cookies.responder_cookie,
         sa->cookies.responder_cookie, SSH_IKE_COOKIE_LENGTH);
  (*isakmp_packet_out)->major_version = 1;
  (*isakmp_packet_out)->minor_version = 0;
  (*isakmp_packet_out)->exchange_type = SSH_IKE_XCHG_TYPE_INFO;
  if (sa->phase_1_done)
    {
      SshIkeNotifyMessageType ret;
      (*isakmp_packet_out)->flags = SSH_IKE_FLAGS_ENCRYPTION;
      /* Make sure skeyid is initialized */
      ret = ike_calc_skeyid(server->isakmp_context, sa,
                            sa->isakmp_negotiation);
      if (ret != 0)
        goto error;
      ret = ike_calc_skeyid(server->isakmp_context, sa, *info_negotiation_out);
      if (ret != 0)
        {
          SSH_DEBUG(3, ("ike_calc_skeyid failed in the "
                        "ike_init_info_exchange"));
        }
    }

  /* Fill in message-id */
  (*isakmp_packet_out)->message_id = message_id;

  SSH_DEBUG(7, ("Created random message id = %08lx",
                (unsigned long) ((*isakmp_packet_out)->message_id)));
  if (!sa->phase_1_done ||
      (*info_negotiation_out)->ed->encryption_cipher == NULL)
    {
      SSH_DEBUG(7, ("No phase 1 done, use only N or D payload"));
      (*isakmp_packet_out)->number_of_payload_packets = 1; /* N or D */
    }
  else
    {
      SSH_DEBUG(7, ("Phase 1 done, use HASH and N or D payload"));
      (*isakmp_packet_out)->number_of_payload_packets = 2; /* HASH, N or D */
    }

  (*isakmp_packet_out)->payloads =
    ssh_calloc((*isakmp_packet_out)->number_of_payload_packets,
               sizeof(SshIkePayload));
  if ((*isakmp_packet_out)->payloads == NULL)
    {
      (*isakmp_packet_out)->number_of_payload_packets = 0;
      goto error;
    }

  (*isakmp_packet_out)->number_of_payload_packets_allocated =
    (*isakmp_packet_out)->number_of_payload_packets;

  for (j = 0;
      j < (*isakmp_packet_out)->number_of_payload_packets_allocated;
      j++)
    {
      (*isakmp_packet_out)->payloads[j] =
        ssh_calloc(1, sizeof(struct SshIkePayloadRec));
      if ((*isakmp_packet_out)->payloads[j] == NULL)
        goto error;
    }
  (*isakmp_packet_out)->packet_data_items_alloc = 16;
  (*isakmp_packet_out)->encoded_packet = NULL;
  (*isakmp_packet_out)->packet_data_items =
    ssh_calloc((*isakmp_packet_out)->packet_data_items_alloc,
               sizeof(unsigned char *));
  if ((*isakmp_packet_out)->packet_data_items == NULL)
    {
      (*isakmp_packet_out)->packet_data_items_alloc = 0;
      goto error;
    }
  if (sa->phase_1_done &&
      (*info_negotiation_out)->ed->encryption_cipher != NULL)
    {
      /* Add hash payload */
      *pl_out = (*isakmp_packet_out)->payloads[0];
      (*pl_out)->type = SSH_IKE_PAYLOAD_TYPE_HASH;

      /* Get hash length */
      (*pl_out)->payload_length =
        ssh_mac_length(ssh_mac_name(sa->skeyid.skeyid_a_mac));

      /* Allocate and register it */
      (*pl_out)->pl.hash.hash_data =
        ike_register_new((*isakmp_packet_out), (*pl_out)->payload_length);
      if ((*pl_out)->pl.hash.hash_data == NULL)
        goto error;

      /* Add finalization function that will calc the hash after
         packet is encoded */
      (*pl_out)->func = ike_finalize_gen_hash;

      (*isakmp_packet_out)->first_hash_payload = *pl_out;

      /* Next payload */
      *pl_out = (*isakmp_packet_out)->payloads[1];
    }
  else
    {
      /* First payload */
      *pl_out = (*isakmp_packet_out)->payloads[0];
    }
  return TRUE;
 error:
  if (*isakmp_packet_out != NULL)
    ike_free_packet(*isakmp_packet_out, 0);
  if (*info_negotiation_out != NULL)
    ike_delete_negotiation(*info_negotiation_out);
  *isakmp_packet_out = NULL;
  *info_negotiation_out = NULL;
  return FALSE;
}


/*                                                              shade{0.9}
 * Delete negotiation, and if it is isakmp sa negotiation
 * then the whole sa. This is called when retry timer expires
 * or the expire timer for whole negotiation expires.           shade{1.0}
 */
void ike_delete_negotiation(SshIkeNegotiation negotiation)
{
  SshIkeSA sa = negotiation->sa;
  int i;

  if (!(negotiation->lock_flags &
        SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
    ssh_cancel_timeouts(SSH_ALL_CALLBACKS, negotiation);

  if (sa)
    SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.initiator_cookie),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.responder_cookie),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                  negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Deleting negotiation"));

  /* Check if this is ISAKMP SA negotiation to be removed. */
  if (negotiation->negotiation_index == -1)
    {
      if (sa == NULL)
        {
          /* The IkeSA is already freed, but we need to free the isakmp SA
             negotiation, this can only happen if we were waiting for the
             policy manager call for the isakmp sa when the isakmp sa was
             deleted, now we must be coming from the ike_reply_check_deleted
             function. */

          /* Send notification is it isn't already sent */
          ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_ABORTED);

          /* ISAKMP SA negotiation */
          ike_free_negotiation_isakmp(negotiation);
          ike_free_phase_i_pm_info(negotiation->ike_pm_info);

          ssh_free(negotiation);

          return;
        }
      if (sa->phase_1_done)
        {
          ike_debug_ike_sa_close(negotiation);
          sa->server_context->statistics->current_ike_sas--;
          if (negotiation->ike_pm_info->this_end_is_initiator)
            sa->server_context->statistics->current_ike_sas_initiated--;
          else
            sa->server_context->statistics->current_ike_sas_responded--;
        }

      ike_sa_delete(sa->server_context->isakmp_context, sa);
      /* Yes, remove whole ISAKMP SA */
      for (i = 0; i < sa->number_of_negotiations; i++)
        {
          if (sa->negotiations[i] != NULL)
            {
              /* Remove timeouts */
              if (!(sa->negotiations[i]->lock_flags &
                    SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
                ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->negotiations[i]);

              /* Check if it is waiting for restart */
              if (sa->negotiations[i]->lock_flags &
                  (SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY |
                   SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
                {
                  /* If so, mark it to be deleted as soon as the
                     ike_reply_check_deleted is called, and continue */
                  sa->negotiations[i]->ed->current_state = SSH_IKE_ST_DELETED;
                  sa->negotiations[i]->sa = NULL;
                  continue;
                }

              /* Send notification if is it isn't already sent */
              ike_call_callbacks(sa->negotiations[i],
                                 SSH_IKE_NOTIFY_MESSAGE_ABORTED);

              switch (sa->negotiations[i]->exchange_type)
                {
                case SSH_IKE_XCHG_TYPE_IP:
                case SSH_IKE_XCHG_TYPE_AGGR:
                  /* ISAKMP SA negotiation */
                  ike_free_negotiation_isakmp(sa->negotiations[i]);
                  ike_free_phase_i_pm_info(sa->negotiations[i]->ike_pm_info);
                  break;
                case SSH_IKE_XCHG_TYPE_QM:
                  /* Quick mode negotation (qm) */
                  ike_free_negotiation_qm(sa->negotiations[i]);
                  break;
                case SSH_IKE_XCHG_TYPE_NGM:
                  /* New group mode negotation */
                  ike_free_negotiation_ngm(sa->negotiations[i]);
                  break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
                case SSH_IKE_XCHG_TYPE_CFG:
                  /* Configuration mode negotation */
                  ike_free_negotiation_cfg(sa->negotiations[i]);
                  break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
                case SSH_IKE_XCHG_TYPE_INFO:
                  ike_free_negotiation_info(sa->negotiations[i]);
                  break;
                default:
                  /* Nothing to be freed */
                  break;
                }

              ssh_free(sa->negotiations[i]);
              sa->negotiations[i] = NULL;
            }
        }
      if (sa->isakmp_negotiation)
        {
          /* Remove timeouts */
          if (!(sa->isakmp_negotiation->lock_flags &
                SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
            ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->isakmp_negotiation);

          /* Check if it is waiting for restart */
          if (sa->isakmp_negotiation->lock_flags &
              (SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY |
               SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
            {
              /* If so, mark it to be deleted as soon as the
                 ike_reply_check_deleted is called */
              sa->isakmp_negotiation->ed->current_state = SSH_IKE_ST_DELETED;
              sa->isakmp_negotiation->sa = NULL;
            }
          else
            {
              /* Send notification is it isn't already sent */
              ike_call_callbacks(sa->isakmp_negotiation,
                                 SSH_IKE_NOTIFY_MESSAGE_ABORTED);
              /* ISAKMP SA negotiation */
              ike_free_negotiation_isakmp(sa->isakmp_negotiation);
              ike_free_phase_i_pm_info(sa->isakmp_negotiation->ike_pm_info);
              ssh_free(sa->isakmp_negotiation);
              sa->isakmp_negotiation = NULL;
            }
        }
      ike_free_sa(sa);
      return;
    }
  i = negotiation->negotiation_index;

  /* Check if it is waiting for restart */
  if (negotiation->lock_flags &
      (SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY |
       SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY))
    {
      /* If so, mark it to be deleted as soon as the ike_reply_check_deleted is
         called. */
      negotiation->ed->current_state = SSH_IKE_ST_DELETED;
      return;
    }
  if (sa && sa->negotiations[i] != negotiation)
      ssh_fatal("Negotiation not found from isakmp sa list");

  /* Send notification is it isn't already sent */
  ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_ABORTED);

  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_QM:
      /* Quick mode negotation (qm) */
      ike_free_negotiation_qm(negotiation);
      break;
    case SSH_IKE_XCHG_TYPE_NGM:
      /* New group mode negotation */
      ike_free_negotiation_ngm(negotiation);
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      /* Configuration mode negotation */
      ike_free_negotiation_cfg(negotiation);
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case SSH_IKE_XCHG_TYPE_INFO:
      ike_free_negotiation_info(negotiation);
      break;
    default:
      /* Nothing to be freed */
      break;
    }

  if ((sa != NULL) &&
      (negotiation == sa->isakmp_negotiation))
    {
      ssh_free(negotiation);
      sa->isakmp_negotiation = NULL;
    }
  else
    {
      ssh_free(negotiation);
    }

  if (sa != NULL)
    {
      sa->negotiations[i] = NULL;
      for (i = sa->number_of_negotiations; i > 0; i--)
        if (sa->negotiations[i - 1] != NULL)
          {
            sa->number_of_negotiations = i;
            break;
          }
    }
  return;
}


/*                                                              shade{0.9}
 * Isakmp remove callback. Called from timer to
 * remove whole negotiation.                                    shade{1.0}
 */
void ike_remove_callback(void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SshIkeSA sa = negotiation->sa;
  SshIkeNotifyMessageType ret;

  if (sa == NULL)
    SSH_DEBUG(5, ("Start, delete, nego = %d",
                  negotiation->negotiation_index));
  else
    SSH_DEBUG(5, ("Start, delete SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.initiator_cookie),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.responder_cookie),
                  (unsigned long)
                  SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                  negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Removing negotiation"));

  if (negotiation->notification_state == SSH_IKE_NOTIFICATION_STATE_SEND_NOW)
    {
      ret = negotiation->ed->code;
      SSH_IKE_DEBUG(3, negotiation,
                    ("Connection got error = %d, calling callback", ret));
    }
  else
    {
      ret = SSH_IKE_NOTIFY_MESSAGE_TIMEOUT;
      if (negotiation->notification_state ==
          SSH_IKE_NOTIFICATION_STATE_NOT_SENT)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Connection timed out or error, calling callback"));
        }
    }
  ike_call_callbacks(negotiation, ret);
  ike_delete_negotiation(negotiation);
  return;
}

/*                                                              shade{0.9}
 * Isakmp expire callback. Called from timer to
 * expire whole negotiation. Sends a delete message to
 * other end.                                                   shade{1.0}
 */
void ike_expire_callback(void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SshIkeSA sa = negotiation->sa;
  SshIkeNotifyMessageType ret;

  SSH_DEBUG(5, ("Start, expire SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Expiring negotiation"));

  if (negotiation->negotiation_index == -1 &&
      negotiation->exchange_type != SSH_IKE_XCHG_TYPE_INFO &&
      sa->phase_1_done)
    {
      /* Send isakmp delete notification */
      SshIkePacket isakmp_packet_out;
      SshIkePayload pl;
      SshBuffer buffer = NULL;
      SshIkeNegotiation delete_negotiation;

      if (!ike_init_info_exchange(sa->server_context, sa,
                                  &isakmp_packet_out,
                                  &delete_negotiation, &pl))
        goto no_notification;
      /* Add D payload */
      isakmp_packet_out->first_d_payload = pl;
      pl->type = SSH_IKE_PAYLOAD_TYPE_D;
      pl->pl.d.doi = SSH_IKE_DOI_IPSEC;
      pl->pl.d.protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
      pl->pl.d.spi_size = SSH_IKE_COOKIE_LENGTH * 2;
      pl->pl.d.number_of_spis = 1;
      pl->pl.d.spis = ssh_malloc(sizeof(unsigned char *));
      if (pl->pl.d.spis == NULL)
        goto free_notification;
      pl->pl.d.spis[0] = ssh_malloc(SSH_IKE_COOKIE_LENGTH * 2);
      if (pl->pl.d.spis[0] == NULL)
        goto free_notification;
      isakmp_packet_out->
        packet_data_items[isakmp_packet_out->packet_data_items_cnt++] =
        pl->pl.d.spis[0];
      memcpy(pl->pl.d.spis[0],
             sa->cookies.initiator_cookie, SSH_IKE_COOKIE_LENGTH);
      memcpy(pl->pl.d.spis[0] + SSH_IKE_COOKIE_LENGTH,
             sa->cookies.responder_cookie, SSH_IKE_COOKIE_LENGTH);

      buffer = ssh_buffer_allocate();
      if (buffer == NULL)
        goto free_notification;

      SSH_IKE_DEBUG(6, delete_negotiation, ("Sending delete notify back"));

      /* Encode response packet */
      ret = ike_encode_packet(sa->server_context->isakmp_context,
                              isakmp_packet_out,
                              sa, delete_negotiation, buffer);
      if (ret != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Encoding delete packet failed : %d", ret));
        }
      else
        {
          SSH_DEBUG(6, ("Sending notification to %s:%s",
                        sa->isakmp_negotiation->ike_pm_info->remote_ip,
                        sa->isakmp_negotiation->ike_pm_info->remote_port));
          /* This is one time notification send, we simply ignore the
             error value of the ike_send_packet. */
          ike_send_packet(delete_negotiation,
                          ssh_buffer_ptr(buffer),
                          ssh_buffer_len(buffer),
                          FALSE, TRUE);
        }
    free_notification:
      /* Free packet */
      ike_free_packet(isakmp_packet_out, delete_negotiation->ed->compat_flags);

      /* Free buffer */
      if (buffer)
        ssh_buffer_free(buffer);

      /* Delete info negotiation */
      ike_delete_negotiation(delete_negotiation);
    }
 no_notification:
  ike_remove_callback(context);
}
