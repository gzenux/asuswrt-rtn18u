/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp_internal.h"
#include "isakmp.h"

#include "ikev2-fb.h"

#define SSH_DEBUG_MODULE "SshIkev2Fallback"

static
SSH_RODATA
struct SshIkePolicyFunctionsRec ikev2_fb_v1_policy_functions =
  {
    ikev2_fb_new_connection,
    ikev2_fb_new_connection_phase_ii,
    ikev2_fb_new_connection_phase_qm,
    ikev2_fb_find_pre_shared_key,
#ifdef SSHDIST_IKE_CERT_AUTH
    ikev2_fb_find_public_key,
    ikev2_fb_find_private_key,
    ikev2_fb_new_certificate,
    ikev2_fb_request_certificates,
    ikev2_fb_get_certificate_authorities,
#endif /* SSHDIST_IKE_CERT_AUTH */
    ikev2_fb_isakmp_nonce_data_len,
    ikev2_fb_isakmp_id,
    ikev2_fb_isakmp_vendor_id,
    ikev2_fb_isakmp_request_vendor_ids,
    ikev2_fb_isakmp_select_sa,
    ikev2_fb_ngm_select_sa,
    ikev2_fb_qm_select_sa,
    ikev2_fb_qm_nonce_data_len,
    ikev2_fb_qm_local_id,
    ikev2_fb_qm_remote_id,
#ifdef SSHDIST_ISAKMP_CFG_MODE
    ikev2_fb_cfg_fill_attrs,
    ikev2_fb_cfg_notify_attrs,
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    ikev2_fb_delete,
    ikev2_fb_notification,
    ikev2_fb_phase_i_notification,
    ikev2_fb_phase_qm_notification,
    ikev2_fb_isakmp_sa_freed,
    ikev2_fb_qm_sa_freed,
    ikev2_fb_phase_ii_sa_freed,
    ikev2_fb_negotiation_done_isakmp,
    ikev2_fb_negotiation_done_qm,
    ikev2_fb_negotiation_done_phase_ii
#ifdef SSHDIST_IKE_CERT_AUTH
    , ikev2_fb_certificate_request
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    , ikev2_fb_phase_i_server_changed
    , ikev2_fb_phase_qm_server_changed
    , ikev2_fb_phase_ii_server_changed
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  };


/********************** Fallback create / destroy ***************************/

SshIkev2Fb
ssh_ikev2_fallback_create(SshIkeParams params,
                          SshAuditContext audit)
{
  SshIkev2Fb fb;

  if ((fb = ssh_calloc(1, sizeof(*fb))) == NULL)
    return NULL;

  if (fb->ikev1 == NULL)
    {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Set NAT-T private payload handlers */
      ikev2_fb_natt_set_private_payload_handlers(params);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      fb->ikev1 = ssh_ike_init(params, audit);
      if (fb->ikev1 == NULL)
        {
          ssh_free(fb);
          return NULL;
        }

      ssh_ike_register_policy_functions(fb->ikev1,
                                        &ikev2_fb_v1_policy_functions);
    }

  /* Copy retry limit values from Ikev1 context. This done to avoid
     including isakmp_internal.h elsewhere in the fallback code. */
  fb->base_retry_limit = fb->ikev1->base_retry_limit;
  fb->base_expire_timer_msec =
    (fb->ikev1->base_expire_timer * 1000
     + fb->ikev1->base_expire_timer_usec / 1000);
  fb->base_retry_timer_msec =
    (fb->ikev1->base_retry_timer * 1000
     + fb->ikev1->base_retry_timer_usec / 1000);
  fb->base_retry_timer_max_msec =
    (fb->ikev1->base_retry_timer_max * 1000
     + fb->ikev1->base_retry_timer_max_usec / 1000);

  /* PM upper context points to us. */
  fb->pm->upper_context = fb;

  ssh_fsm_init(fb->fsm, fb);
  SSH_DEBUG(SSH_D_HIGHOK, ("FB; v1 policy manager %p started", fb));

  return fb;
}


void ssh_ikev2_fallback_destroy(SshIkev2Fb fb)
{
  SshIkev2FbNegotiation neg;

  ssh_ike_uninit(fb->ikev1);

  ssh_fsm_uninit(fb->fsm);

  while (fb->negotiation_freelist != NULL)
    {
      neg = fb->negotiation_freelist;
      fb->negotiation_freelist = neg->next;
      ssh_free(neg);
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("FB; v1 policy manager %p destroyed", fb));

  ssh_free(fb);
}

void ssh_ikev2_fallback_attach(SshIkev2Server server, SshIkev2Fb fb)
{
  SSH_DEBUG(SSH_D_HIGHOK,
            ("FB; v1 policy manager %p attached to server %p",
             fb, server));

  ssh_ike_attach_server((SshIkeServerContext)server,
                        fb->ikev1,
                        fb->pm,
                        ikev2_fb_sa_handler, fb);
}

void ssh_ikev2_fallback_detach(SshIkev2Server server)
{
  ssh_ike_detach_server((SshIkeServerContext)server);
}

void
ssh_policy_ikev2_fallback_set_params(SshIkev2 context,
                                     SshIkev2FallbackParams params)
{
  if (params)
    context->fallback->params = *params;
  else
    memset(&context->fallback->params, 0, sizeof(context->fallback->params));
  return;
}


/******************** Fallback negotiation alloc / free **********************/

SshIkev2FbNegotiation
ikev2_fallback_negotiation_alloc(SshIkev2Fb fb)
{
  SshIkev2FbNegotiation neg;

  if (fb->negotiation_freelist != NULL)
    {
      neg = fb->negotiation_freelist;
      fb->negotiation_freelist = neg->next;
      memset(neg, 0, sizeof(*neg));
    }
  else
    {
      neg = ssh_calloc(1, sizeof(*neg));
    }

  if (neg)
    {
      neg->fb = fb;
      neg->ike_error = SSH_IKEV2_ERROR_OK;
      IKEV2_FB_NEG_TAKE_REF(neg);
    }
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated fallback negotiation %p", neg));
  return neg;
}

void
ikev2_fallback_negotiation_free(SshIkev2Fb fb, SshIkev2FbNegotiation neg)
{

  SSH_ASSERT(neg->ref_count > 0);
  neg->ref_count--;
  if (neg->ref_count > 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Fallback negotiation %p has still %d references",
                 neg, neg->ref_count));
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing fallback negotiation %p", neg));

  if (neg->aggr_mode_responder)
    fb->num_aggr_mode_responder_active--;

  if (neg->ed)
    ikev2_free_exchange_data(neg->ike_sa, neg->ed);

  if (neg->ike_sa)
    SSH_IKEV2_IKE_SA_FREE(neg->ike_sa);

#ifdef SSHDIST_IKE_CERT_AUTH
  if (neg->private_key)
    ssh_private_key_free(neg->private_key);

  if (neg->public_key)
    ssh_public_key_free(neg->public_key);

  if (neg->cert_encodings)
    {
      ssh_free(neg->cert_encodings);
      neg->cert_encodings = NULL;
    }

  if (neg->cert_lengths)
    {
      ssh_free(neg->cert_lengths);
      neg->cert_lengths = NULL;
    }

  if (neg->certs)
    {
      int i;
      for (i = 0; i < neg->number_of_certificates; i++)
        ssh_free(neg->certs[i]);
      ssh_free(neg->certs);
      neg->certs = NULL;
    }
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_XAUTH
  if (neg->attrs)
    {
      ikev2_fb_xauth_free_attributes(neg->attrs);
      neg->attrs = NULL;
    }

  if (neg->v1_attrs)
    {
      ikev2_fb_xauth_free_v1_attributes(neg->v1_attrs);
      neg->v1_attrs = NULL;
    }
#endif /* SSHDIST_IKE_XAUTH */

  if (neg->transform_index)
    {
      ssh_free(neg->transform_index);
      neg->transform_index = NULL;
    }

  if (neg->selected)
    {
      ikev2_fb_free_sa_indexes(neg->selected, 1);
      neg->selected = NULL;
    }

  if (neg->psk)
    {
      ssh_free(neg->psk);
      neg->psk = NULL;
    }

  if (neg->sav2)
    {
      ssh_ikev2_sa_free(neg->server->sad_handle, neg->sav2);
      neg->sav2 = NULL;
    }

  if (neg->ikev1_id)
    ssh_ike_id_free(neg->ikev1_id);

  /* Assert that negotiation timeouts are not registered */
  SSH_ASSERT(SSH_TIMEOUT_IS_REGISTERED(neg->dpd_timeout) == FALSE);
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_ASSERT(SSH_TIMEOUT_IS_REGISTERED(neg->cfgmode_timeout) == FALSE);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  SSH_CLEAR_MEMORY(neg, sizeof(*neg));

  neg->next = fb->negotiation_freelist;
  fb->negotiation_freelist = neg;
  return;
}


/***************** Utilities for handling policy_manager_data ***************/

void
ikev2_fb_phase_qm_set_pm_data(SshIkePMPhaseQm pm_info,
                              SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(pm_info != NULL);
  SSH_ASSERT(neg != NULL);

  IKEV2_FB_NEG_TAKE_REF(neg);
  pm_info->policy_manager_data = neg;

  SSH_DEBUG(SSH_D_LOWOK, ("Setting FB negotiation %p to qm_info %p",
                          neg, pm_info));
}

void
ikev2_fb_phase_qm_clear_pm_data(SshIkePMPhaseQm pm_info,
                                SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(pm_info != NULL);
  SSH_ASSERT(neg != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing FB negotiation %p from qm_info %p",
                          neg, pm_info));

  pm_info->policy_manager_data = NULL;
}

void
ikev2_fb_phase_ii_set_pm_data(SshIkePMPhaseII pm_info,
                              SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(pm_info != NULL);
  SSH_ASSERT(neg != NULL);

  IKEV2_FB_NEG_TAKE_REF(neg);
  pm_info->policy_manager_data = neg;

  SSH_DEBUG(SSH_D_LOWOK, ("Setting FB negotiation %p to p2_info %p",
                          neg, pm_info));
}

void
ikev2_fb_phase_ii_clear_pm_data(SshIkePMPhaseII pm_info,
                                SshIkev2FbNegotiation neg)
{
  SSH_ASSERT(pm_info != NULL);
  SSH_ASSERT(neg != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing FB negotiation %p from p2_info %p",
                          neg, pm_info));

  pm_info->policy_manager_data = NULL;
}

void
ikev2_fb_negotiation_clear_pm_data(SshIkev2FbNegotiation neg)
{
  if (neg->qm_info && neg->qm_info->policy_manager_data)
    {
      /* Clear the reference from isakmp library
         `pm_info->policy_manager_data'. The reference is cleared here
         because in the normal case the isakmp library calls
         ikev2_fb_qm_sa_freed() only after the IKE retransmit time
         has gone. */
      ikev2_fb_phase_qm_clear_pm_data(neg->qm_info, neg);
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }

  if (neg->p2_info && neg->p2_info->policy_manager_data)
    {
      /* Clear the reference from isakmp library
         `pm_info->policy_manager_data'. The reference is cleared here
         because in the normal case the isakmp library calls
         ikev2_fb_phase_ii_sa_freed() only after the IKE retransmit time
         has gone. */
      ikev2_fb_phase_ii_clear_pm_data(neg->p2_info, neg);
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }
}

SshIkePMPhaseQm
ikev2_fb_get_qm_info(SshIkeNegotiation ike_negotiation)
{
  SSH_ASSERT(ike_negotiation != NULL);
  return ike_negotiation->qm_pm_info;
}

#ifdef SSHDIST_IKE_XAUTH
SshIkePMPhaseII
ikev2_fb_get_cfg_pm_info(SshIkeNegotiation ike_negotiation)
{
  SSH_ASSERT(ike_negotiation != NULL);
  return ike_negotiation->cfg_pm_info;
}
#endif /* SSHDIST_IKE_XAUTH */

/*--------------------------------------------------------------------*/
/* IKE SPI                                                            */
/*--------------------------------------------------------------------*/
SshIkeNegotiation ssh_ikev2_fb_get_sa(SshIkev2 ikev2,
                                      const unsigned char *ike_spi_i,
                                      const unsigned char *ike_spi_r)
{
  SshIkeNegotiation n = NULL;
  unsigned const char half_cookie[SSH_IKE_COOKIE_LENGTH]
    = { 0,0,0,0,0,0,0,0 };

  if (ikev2->fallback)
    {
      SshIkeContext ikev1 = ikev2->fallback->ikev1;
      SshADTHandle h;
      SshIkeSA sa;

      if (ike_spi_r == NULL
          || memcmp(ike_spi_r, half_cookie, SSH_IKE_COOKIE_LENGTH) == 0)
        {
          /* Check only if we know the initiator cookie. */
          if ((h = ssh_adt_get_handle_to_equal(ikev1->isakmp_cookie_mapping,
                                               (unsigned char *)ike_spi_i))
              != SSH_ADT_INVALID)
            {
              if ((sa = ssh_adt_map_lookup(ikev1->isakmp_cookie_mapping, h))
                  != NULL)
                n = sa->isakmp_negotiation;
            }
        }
      else
        {
          if ((sa = ike_sa_find(ikev1, ike_spi_i, ike_spi_r)) != NULL)
            n = sa->isakmp_negotiation;
        }
    }

  return n;
}

/*---------------------------------------------------------------------*/
/* IKE SA uninit                                                       */
/*---------------------------------------------------------------------*/

void ikev2_fb_ike_sa_uninit(SshIkev2Sa ike_sa)
{
  SSH_ASSERT(ike_sa->v1_sa != NULL);

  if (ike_sa->v1_sa->ike_pm_info->policy_manager_data == ike_sa)
    ike_sa->v1_sa->ike_pm_info->policy_manager_data = NULL;
  ssh_ike_remove_isakmp_sa(ike_sa->v1_sa,
                               SSH_IKE_REMOVE_FLAGS_FORCE_DELETE_NOW);
  ike_sa->v1_sa = NULL;

  SSH_ASSERT(ike_sa->ref_cnt == 1);
  SSH_DEBUG(SSH_D_LOWOK, ("Freeing reference to IKE SA %p to %d",
                          ike_sa, ike_sa->ref_cnt - 1));
  ike_sa->ref_cnt--;
}

#endif /* SSHDIST_IKEV1 */
