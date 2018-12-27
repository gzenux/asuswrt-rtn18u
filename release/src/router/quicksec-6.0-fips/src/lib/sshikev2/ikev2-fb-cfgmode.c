/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CFGMode functionality for IKEv1 fallback.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackCfg"

#ifdef SSHDIST_ISAKMP_CFG_MODE

/*--------------------------------------------------------------------*/
/* Configuration Mode Initiator                                       */
/*--------------------------------------------------------------------*/

void ikev2_fb_conf_cb(SshIkev2Error error,
                      SshIkev2PayloadConf conf_payload,
                      void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)context;
  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  neg->v2_conf = conf_payload;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}

static void
ikev2_fb_i_cfg_negotiation_cb(SshIkeNegotiation negotiation,
                              SshIkePMPhaseII pm_info,
                              SshIkeNotifyMessageType error,
                              int number_of_attr_payloads,
                              SshIkePayloadAttr *attributes,
                              void *callback_context)
{
  SshIkev2FbNegotiation neg = NULL;

  /* Take fallback negotiation from `policy_manager_data' to safely
     deal with negotiation abort. */
  if (pm_info && pm_info->policy_manager_data)
    neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  SSH_DEBUG(SSH_D_LOWOK, ("Connect Cfg done callback, status %s (neg %p)",
                          ssh_ike_error_code_to_string(error), neg));

  /* If `neg' is NULL then the negotiation has been aborted and
     freed already and the Quick-Mode thread is gone. */
  if (neg == NULL)
    return;

  /* Check if the negotiation was aborted or the negotiation failed
     synchronously. If so ignore the error and continue the Quick-Mode
     thread. */
  if (neg->ike_sa->v1_cfg_negotiation == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CFG negotiation aborted error %s",
                              ssh_ike_error_code_to_string(error)));

      neg->ike_error = (int) SSH_IKE_ERROR_OK;
      neg->v1_error = SSH_IKE_NOTIFY_MESSAGE_CONNECTED;

      ssh_fsm_set_next(neg->thread, ikev2_fb_i_p1_check_cfg);

      /* If the negotiation failed synchronously then this call does not
         do anything as the thread is running already. */
      ssh_fsm_continue(neg->thread);

      return;
    }

  neg->ike_sa->v1_cfg_negotiation = NULL;

  if (error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(error);
      neg->v1_error = error;
      SSH_ASSERT(neg->ike_error != SSH_IKEV2_ERROR_OK);
    }
  else
    {
      neg->v2_conf = ikev2_fb_cfgv1_to_cfgv2(neg->ike_sa->server->sad_handle,
                                             attributes[0]);
      neg->ike_sa->last_input_stamp = ssh_time();
    }
  ssh_fsm_continue(neg->thread);
}

SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("CFG mode negotiation starting (neg %p)", neg));

  /* Check if we already got the CFG mode attributes from XAUTH. */
  if (neg->ike_sa->cfg_attrs_received)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("CFG attributes already received, all done"));
      SSH_FSM_SET_NEXT(ikev2_fb_i_cfg_negotiation_final);
      return SSH_FSM_CONTINUE;
    }
  neg->ike_sa->server_cfg_pending = 0;

  SSH_FSM_SET_NEXT(ikev2_fb_i_cfg_negotiation_connect);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_connect)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkeErrorCode ret = SSH_IKE_ERROR_OUT_OF_MEMORY;
  SshIkePayloadAttr *attrs;
  SshIkeNegotiation cfg_negotiation = NULL;

  SSH_FSM_SET_NEXT(ikev2_fb_i_cfg_negotiation_result);

  if ((attrs = ssh_calloc(1, sizeof(*attrs))) == NULL)
    goto immediate_error;

  if ((attrs[0] =
       ikev2_fb_cfgv2_to_cfgv1(neg->ike_sa->server->sad_handle,
                               neg->ed->conf)) == NULL)
    goto immediate_error;

  SSH_DEBUG(SSH_D_MIDOK, ("Client initiated CFG mode"));

  /* Take a reference to fallback negotiation, it will be put to
     `pm_info->policy_manager_data' by the isakmp library. This will
     be freed in ikev2_fb_phase_ii_sa_freed(). */
  IKEV2_FB_NEG_TAKE_REF(neg);

  /* `v1_cfg_negotiation' is used for detecting error conditions in
     ikev2_fb_i_cfg_negotiation_cb(). */
  SSH_ASSERT(neg->ike_sa->v1_cfg_negotiation == NULL);

  ret = ssh_ike_connect_cfg((SshIkeServerContext)neg->ike_sa->server,
                            &cfg_negotiation,
                            neg->ike_sa->v1_sa,
                            NULL, NULL,
                            1, attrs,
                            neg,
                            SSH_IKE_FLAGS_USE_DEFAULTS,
                            ikev2_fb_i_cfg_negotiation_cb,
                            NULL);

  /* Success */
  if (ret == SSH_IKE_ERROR_OK && cfg_negotiation != NULL)
    {
      /* Save `neg->p2_info' so that `neg->p2_info->policy_manager_data'
         can be cleared before pm_info is freed. `p2_info' is used only for
         cleaning up references to fallback negotiation. */
      neg->ike_sa->v1_cfg_negotiation = cfg_negotiation;
      SSH_ASSERT(neg->p2_info == NULL);
      neg->p2_info = ikev2_fb_get_cfg_pm_info(neg->ike_sa->v1_cfg_negotiation);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("CFG mode started, suspending FSM"));

      /* All is fine, we'll wait for CFG to complete */
      return SSH_FSM_SUSPENDED;
    }

  /* Error, isakmp library has called callbacks synchronously. */
  else if (ret == SSH_IKE_ERROR_OK && cfg_negotiation == NULL)
    {
      /* Isakmp library has freed `attrs', called the completion callback
         and freed `policy_manager_data'. */
      attrs = NULL;
    }

  /* Error */
  else
    {
      /* Free the `policy_manager_data' reference to fallback negotiation. */
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }

 immediate_error:
  SSH_DEBUG(SSH_D_FAIL, ("CFG mode failed, immediate failure"));
  neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

  /* Free attributes. */
  if (attrs)
    {
      if (attrs[0])
        {
          ssh_free(attrs[0]->attributes);
          ssh_free(attrs[0]);
        }
      ssh_free(attrs);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("CFG mode negotiation result, error %d (neg %p)",
                             neg->ike_error, neg));

  if (neg->v2_conf != NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("CFG mode attributes received, passing "
                                 "them to policy manager"));

      /* Indicate that we have received the CFG mode attributes */
      neg->ike_sa->cfg_attrs_received = 1;

      if (neg->server->sad_interface->conf_received)
        (*neg->server->sad_interface->conf_received)
          (neg->server->sad_handle,
           neg->ed,
           neg->v2_conf);

      ssh_ikev2_conf_free(neg->server->sad_handle, neg->v2_conf);
      neg->v2_conf = NULL;
    }

  SSH_FSM_SET_NEXT(ikev2_fb_i_cfg_negotiation_final);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_final)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  if (neg->ed->info_ed)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Move to info negotiation start (neg %p)",
                                 neg));
      SSH_FSM_SET_NEXT(ikev2_fb_i_info_negotiation_start);
      return SSH_FSM_CONTINUE;
    }
  else if (neg->ed->ipsec_ed)
    {
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
      if (neg->ed->ipsec_ed->ts_local == NULL ||
          neg->ed->ipsec_ed->ts_remote == NULL)
        {
          /* Null traffic selectors indicate that no IPsec SA is
             wanted. */
          SSH_DEBUG(SSH_D_MIDSTART, ("Completing without QM negotiation"));
          ikev2_fb_ipsec_complete(neg);
          return SSH_FSM_FINISH;
        }
      else
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("Move to QM negotiation start"));
          SSH_FSM_SET_NEXT(ikev2_fb_i_qm_negotiation_start);
          return SSH_FSM_CONTINUE;
        }
    }
  else
    {
      SSH_NOTREACHED;
      return SSH_FSM_FINISH;
    }
}


/*--------------------------------------------------------------------*/
/* Configuration Mode Policy Calls                                    */
/*--------------------------------------------------------------------*/

SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_conf_received)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)thread_context;
  int i;

  SSH_FSM_SET_NEXT(ikev2_fb_st_cfg_fill_attrs_result);


  neg->v2_conf = ikev2_fb_cfgv1_to_cfgv2(neg->server->sad_handle,
                                         neg->v1_conf);

  if (neg->v2_conf == NULL)
    {
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("CFGMode attributes received, send to policy"));

  /* Indicate that we have received the CFG mode attributes */
  neg->ike_sa->cfg_attrs_received = 1;

  /* Notify the policy of the received Conf SET payloads */
  if (neg->server->sad_interface->conf_received)
    (*neg->server->sad_interface->conf_received)
      (neg->server->sad_handle,
       neg->ed,
       neg->v2_conf);

  /* Construct a configuration payload ACK'ing the received SET payloads.
     Do this by setting the attribute length of each of the attributes to
     zero, also convert the type from SET to ACK. */
  SSH_ASSERT(neg->v2_conf->conf_type == SSH_IKEV2_CFG_SET);
  neg->v2_conf->conf_type = SSH_IKEV2_CFG_ACK;

  for (i = 0; i < neg->v2_conf->number_of_conf_attributes_used; i++)
    {
      SshIkev2ConfAttribute attribute;
      attribute = &(neg->v2_conf->conf_attributes[i]);
      attribute->length = 0;
    }

  neg->ike_sa->server_cfg_pending = 0;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_conf_request)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_cfg_fill_attrs_result);

  neg->ed->conf = ikev2_fb_cfgv1_to_cfgv2(neg->server->sad_handle,
                                          neg->v1_conf);
  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg,
                         conf_request)(neg->server->sad_handle,
                                       neg->ed,
                                       ikev2_fb_conf_cb,
                                       neg);
  });

}

SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)thread_context;
  SshIkePayloadAttr *attrs;

  if (neg->v2_conf && neg->callbacks.u.cfg_fill_attrs)
    {
      if ((attrs = ssh_calloc(1, sizeof(*attrs))) == NULL)
        {
          goto failed;
        }

      if ((attrs[0] =
           ikev2_fb_cfgv2_to_cfgv1(neg->server->sad_handle, neg->v2_conf))
          == NULL)
        {
          ssh_free(attrs);
          goto failed;
        }

      attrs[0]->identifier = neg->v1_conf_id;
      if (neg->callbacks.u.cfg_fill_attrs)
        (*neg->callbacks.u.cfg_fill_attrs)(1,
                                           attrs,
                                           neg->callbacks.callback_context);

      ssh_ikev2_conf_free(neg->server->sad_handle, neg->v2_conf);
    }
  else
    {
    failed:
      if (neg->callbacks.u.cfg_fill_attrs)
        (*neg->callbacks.u.cfg_fill_attrs)(0,
                                           NULL,
                                           neg->callbacks.callback_context);
    }

  neg->v2_conf = NULL;
  return SSH_FSM_FINISH;
}

void
ikev2_fb_cfg_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_cfg_fill_attrs(SshIkePMPhaseII pm_info,
                        int number_of_attrs,
                        SshIkePayloadAttr *return_attributes,
                        SshPolicyCfgFillAttrsCB callback_in,
                        void *callback_context_in)
{
  SshIkev2FbNegotiation neg;
  SshFSMStepCB start = NULL_FNPTR;
  int i;

  neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  if (neg == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Received Conf payload without active negotiation."));
      neg = ikev2_fb_alloc_cfgmode_negotiation(pm_info);
    }

  if (neg == NULL || neg->ike_error != SSH_IKEV2_ERROR_OK || neg->aborted)
    {
      (*callback_in)(0, NULL, callback_context_in);
      return;
    }

  /* Store the completion callback and its context. */
  neg->callbacks.u.cfg_fill_attrs = callback_in;
  neg->callbacks.callback_context = callback_context_in;
  neg->v1_conf = *return_attributes;
  neg->v1_conf_id = return_attributes[0]->identifier;

#define XAUTHP(attr) \
 ((attr)->attribute_type > 16519 && (attr)->attribute_type < 16530)

  for (i = 0; i < neg->v1_conf->number_of_attributes; i++)
    {
      if (XAUTHP(&(neg->v1_conf->attributes[i])))
        {
          start = ikev2_fb_st_r_xauth_start;
          break;
        }
    }

  if (start == NULL_FNPTR)
    {
      if (neg->v1_conf[0].type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("CFG SET received"));
          start = ikev2_fb_st_cfg_fill_attrs_conf_received;

          /* The server has initiated CFGmode to us. Indicate this in
             the IKE SA. */
          neg->ike_sa->server_cfg_pending = 1;
        }
      else if (neg->v1_conf[0].type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("CFG REQUEST received"));
          start = ikev2_fb_st_cfg_fill_attrs_conf_request;
        }
      else
        {
          (*callback_in)(0, NULL, callback_context_in);
          return;
        }
    }
  else
    {
      /* The server has initiated XAUTH to us. Mark this in the IKE SA. */
      neg->ike_sa->xauth_enabled = 1;
    }

  /* If we (the client) receive a CFG SET/ACK exchange while our CFG
     Request/Reply CFG exchange is ongoing, we abort the ongoing
     Request/Reply CFG exchange. */
  if (neg->ike_sa->v1_cfg_negotiation)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Server initiated SET/ACK neogotiation. "
                               "Aborting ongoing CFG REQ/REP negotiation"));

      ssh_ike_abort_negotiation(neg->ike_sa->v1_cfg_negotiation, 0L);
      neg->ike_sa->v1_cfg_negotiation = NULL;
    }

  /* Take a reference to fallback negotiation for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      start, NULL_FNPTR,
                      ikev2_fb_cfg_sub_thread_destructor, neg);
}

/*--------------------------------------------------------------------*/

void
ikev2_fb_cfg_notify_attrs(SshIkePMPhaseII pm_info,
                          int number_of_attrs,
                          SshIkePayloadAttr *return_attributes)
{
  return;
}

#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IKEV1 */
