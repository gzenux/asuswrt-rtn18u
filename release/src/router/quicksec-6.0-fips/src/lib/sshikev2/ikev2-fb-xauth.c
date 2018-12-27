/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv1 extended authentication for IKEv2 library.
*/

#include "sshincludes.h"

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"


#define SSH_DEBUG_MODULE "SshIkev2FallbackXauth"

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IKE_XAUTH

#include "isakmp.h"
#include "isakmp_util.h"

#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

SshIkev2Error
ssh_ikev2_info_add_xauth(SshIkev2ExchangeData ed)
{
  if (ed->info_ed)
    {
      ed->info_ed->flags |= SSH_IKEV2_INFO_CREATE_FLAGS_XAUTH;
      return SSH_IKEV2_ERROR_OK;
    }
  return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
}


void
ssh_ikev2_fallback_set_xauth_client(SshIkev2 ikev2,
                                    SshIkev2FbXauthRequest request,
                                    SshIkev2FbXauthSet set,
                                    void *callback_context)
{
  if (ikev2->fallback)
    {
      ikev2->fallback->xauth_client_request_callback = request;
      ikev2->fallback->xauth_client_set_callback = set;
      ikev2->fallback->xauth_client_callback_context = callback_context;
    }
}


#define FB_ATTR_BASIC(attr, lval)                       \
do                                                      \
  {                                                     \
    (lval) = 0;                                         \
    if ((attr)->attribute_length == 0)                  \
      {                                                 \
        /* REQUEST/ACK */                               \
      }                                                 \
    else if ((attr)->attribute_length == 2)             \
      {                                                 \
        (lval) = SSH_GET_16BIT((attr)->attribute);      \
      }                                                 \
  }                                                     \
while (0)

#define FB_ATTR_VARIABLE(attr, lval, llen)              \
do                                                      \
  {                                                     \
    if ((attr)->attribute_length)                       \
      {                                                 \
        (lval) = ssh_memdup((attr)->attribute, (attr)->attribute_length); \
        (llen) = (attr)->attribute_length;              \
      }                                                 \
    else                                                \
      {                                                 \
        (lval) = NULL;                                  \
        (llen) = 0;                                     \
      }                                                 \
  }                                                     \
while (0)

void ikev2_fb_xauth_free_attributes(SshIkev2FbXauthAttributes attributes)
{
  if (attributes)
    {
      ssh_free(attributes->user_name);
      ssh_free(attributes->user_password);
      ssh_free(attributes->passcode);
      ssh_free(attributes->message);
      ssh_free(attributes->challenge);
      ssh_free(attributes->domain);
      ssh_free(attributes->next_pin);
      ssh_free(attributes->answer);

      if (attributes->num_subnets)
        ssh_free(attributes->subnets);
      ssh_free(attributes);
    }
}

SshIkev2FbXauthAttributes
ikev2_fb_xauth_decode_attributes(SshIkePayloadAttr attrs)
{
  SshIkev2FbXauthAttributes attributes;
  int i;

  if ((attributes = ssh_calloc(1, sizeof(*attributes))) == NULL)
    {
      return NULL;
    }

  for (i = 0; i < attrs->number_of_attributes; i++)
    {
      SshIkeDataAttribute attr = &attrs->attributes[i];

      switch (attr->attribute_type)
        {
        case SSH_IKE_CFG_ATTR_XAUTH_TYPE:
          attributes->type_set = TRUE;
          FB_ATTR_BASIC(attr, attributes->type);
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_USER_NAME:
          FB_ATTR_VARIABLE(attr,
                           attributes->user_name, attributes->user_name_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_USER_NAME;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD:
          FB_ATTR_VARIABLE(attr,
                           attributes->user_password,
                           attributes->user_password_len);
          attributes->attributes_mask
            |= SSH_IKEV2_XAUTH_ATTRIBUTE_USER_PASSWORD;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_PASSCODE:
          FB_ATTR_VARIABLE(attr,
                           attributes->passcode, attributes->passcode_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_PASSCODE;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_MESSAGE:
          FB_ATTR_VARIABLE(attr,
                           attributes->message, attributes->message_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_MESSAGE;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_CHALLENGE:
          FB_ATTR_VARIABLE(attr,
                           attributes->challenge, attributes->challenge_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_CHALLENGE;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_DOMAIN:
          FB_ATTR_VARIABLE(attr,
                           attributes->domain, attributes->domain_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_DOMAIN;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_STATUS:
          FB_ATTR_BASIC(attr, attributes->status);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_STATUS;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_NEXT_PIN:
          FB_ATTR_VARIABLE(attr,
                           attributes->next_pin, attributes->next_pin_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_NEXT_PIN;
          break;
        case SSH_IKE_CFG_ATTR_XAUTH_ANSWER:
          FB_ATTR_VARIABLE(attr,
                           attributes->answer, attributes->answer_len);
          attributes->attributes_mask |= SSH_IKEV2_XAUTH_ATTRIBUTE_ANSWER;
          break;
        default:
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Unknown attribute type %d: ignoring",
                     attr->attribute_type));
          break;
        }
    }

  return attributes;
}


static void
ikev2_fb_xauth_encode_cfg_attributes(SshIkeSAAttributeList attr,
                                     SshIkev2FbXauthAttributes attributes)
{
  unsigned char buf[17];
  size_t len, len2;
  SshIpAddrStruct mask, mask2;
  SshUInt32 i;
  SshUInt16 addrtype;

  if (attributes == NULL)
    return;

  /* IPv{4,6} address and netmask. */
  if (SSH_IP_DEFINED(&attributes->address))
    {
      addrtype = (SshUInt16)(SSH_IP_IS4(&attributes->address)
                             ? SSH_IKE_CFG_ATTR_INTERNAL_IPV4_ADDRESS
                             : SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS);

      SSH_IP_ENCODE(&attributes->address, buf, len);
      ssh_ike_data_attribute_list_add(attr, addrtype, buf, len);

      addrtype = (SshUInt16)(SSH_IP_IS4(&attributes->address)
                             ? SSH_IKE_CFG_ATTR_INTERNAL_IPV4_NETMASK
                             : SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NETMASK);

      ssh_ipaddr_set_bits(&mask2, &attributes->address, 0, 1);
      ssh_ipaddr_set_bits(&mask, &mask2,
                          SSH_IP_MASK_LEN(&attributes->address), 0);

      SSH_IP_ENCODE(&mask, buf, len);
      ssh_ike_data_attribute_list_add(attr, addrtype, buf, len);
    }

  /* Additional sub-networks. */
  for (i = 0; i < attributes->num_subnets; i++)
    {
      addrtype = (SshUInt16)(SSH_IP_IS4(&attributes->subnets[i])
                             ? SSH_IKE_CFG_ATTR_INTERNAL_IPV4_SUBNET
                             : SSH_IKE_CFG_ATTR_INTERNAL_IPV6_SUBNET);

      SSH_IP_ENCODE(&attributes->subnets[i], buf, len);
      if (SSH_IP_IS4(&attributes->subnets[i]))
        {
          ssh_ipaddr_set_bits(&mask2, &attributes->subnets[i], 0, 1);
          ssh_ipaddr_set_bits(&mask, &mask2,
                              SSH_IP_MASK_LEN(&attributes->subnets[i]), 0);

          SSH_IP4_ENCODE(&mask, buf + len);
          len2 = SSH_IP_ADDR_LEN(&mask);
        }
      else
        {
          buf[len] = SSH_IP_MASK_LEN(&attributes->subnets[i]);
          len2 = 1;
        }

      ssh_ike_data_attribute_list_add(attr, addrtype, buf, len + len2);
    }

}

void
ikev2_fb_xauth_free_v1_attributes(SshIkePayloadAttr *attributes)
{
  if ((attributes != NULL))
    {
      if (*attributes != NULL)
        {
          ssh_free(attributes[0]->attributes);
          ssh_free(attributes[0]);
        }
      ssh_free(attributes);
    }
}

SshIkePayloadAttr *
ikev2_fb_xauth_encode_attributes(SshIkev2FbXauthAttributes attributes,
                                 SshIkeCfgMessageType type,
                                 Boolean success,
                                 Boolean xauth_enabled,
                                 const unsigned char *message,
                                 size_t message_len)
{
  SshIkePayloadAttr *attrs;
  SshIkeSAAttributeList attr;

  if ((attrs = ssh_calloc(1, sizeof(*attrs))) == NULL)
    goto error;

  if ((attrs[0] = ssh_calloc(1, sizeof((*attrs)[0]))) == NULL)
    goto error;

  attrs[0]->type = type;

  if ((attr = ssh_ike_data_attribute_list_allocate()) == NULL)
    goto error;

  /* Now encode the attributes */
  if (type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
    {
      if (xauth_enabled)
        {
          ssh_ike_data_attribute_list_add_basic(attr,
                                                SSH_IKE_CFG_ATTR_XAUTH_STATUS,
                                                (SshUInt16)(success? 1 : 0));
          if (message)
            ssh_ike_data_attribute_list_add(attr,
                                            SSH_IKE_CFG_ATTR_XAUTH_MESSAGE,
                                            (unsigned char *) message,
                                            message_len);
        }

      /* Send possible address and network information as part of set
         exchange. */
      ikev2_fb_xauth_encode_cfg_attributes(attr, attributes);
    }
  else if (type != SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK && attributes != NULL)
    {
      SSH_ASSERT(xauth_enabled == TRUE);

      if (attributes->type_set)
        ssh_ike_data_attribute_list_add_basic(attr,
                                              SSH_IKE_CFG_ATTR_XAUTH_TYPE,
                                              (SshUInt16)attributes->type);
      if (attributes->user_name)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_USER_NAME,
                                        attributes->user_name,
                                        attributes->user_name_len);
      if (attributes->user_password)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_USER_PASSWORD,
                                        attributes->user_password,
                                        attributes->user_password_len);
      if (attributes->passcode)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_PASSCODE,
                                        attributes->passcode,
                                        attributes->passcode_len);
      if (attributes->message)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_MESSAGE,
                                        attributes->message,
                                        attributes->message_len);
      if (attributes->challenge)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_CHALLENGE,
                                        attributes->challenge,
                                        attributes->challenge_len);
      if (attributes->domain)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_DOMAIN,
                                        attributes->domain,
                                        attributes->domain_len);

      if (attributes->next_pin)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_NEXT_PIN,
                                        attributes->next_pin,
                                        attributes->next_pin_len);
      if (attributes->answer)
        ssh_ike_data_attribute_list_add(attr,
                                        SSH_IKE_CFG_ATTR_XAUTH_ANSWER,
                                        attributes->answer,
                                        attributes->answer_len);
    }

  if (type != SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK)
    {
      attrs[0]->attributes
        = ssh_ike_data_attribute_list_get(attr,
                                          &attrs[0]->number_of_attributes);
      ssh_ike_data_attribute_list_free(attr);

      /* Check if some of the list_add functions failed from the result. */
      if (attrs[0]->attributes == NULL)
        goto error;
    }
  else
    {
      ssh_ike_data_attribute_list_free(attr);
    }

  return attrs;

 error:
  if (attrs)
    ikev2_fb_xauth_free_v1_attributes(attrs);
  return NULL;
}

/* This function formats the attributes into cfg-request and arranges
   it to be sent to the peer. This server side implementation looks
   like it could be aborted - but is always gets aborted as part of
   the xauth initiated exchange. */
static SshOperationHandle
ikev2_fb_xauth_request(SshIkev2Sa sa,
                       SshIkev2FbXauthAttributes attributes,
                       SshIkev2FbXauthStatus callback,
                       void *callback_context,
                       void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)context;

  ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_negotiate);

  neg->xauth_type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST;
  neg->xauth_status_cb = callback;
  neg->xauth_status_cb_context = callback_context;

  if (neg->v1_attrs)
    ikev2_fb_xauth_free_v1_attributes(neg->v1_attrs);

  neg->v1_attrs =
    ikev2_fb_xauth_encode_attributes(attributes,
                                     SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST,
                                     FALSE,
                                     sa->xauth_enabled,
                                     NULL, 0L);
  if (neg->v1_attrs == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Unable to encode xauth attributes"));
      ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_failed);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->thread);

  /* On purpose */
  return NULL;
}

/* This function formats the status (success), message, and attributes
   into a cfg-set and arranges it to be sent to the peer. This server
   side implementation looks like it could be aborted - but is always
   gets aborted as part of the xauth initiated exchange. */
static SshOperationHandle
ikev2_fb_xauth_set(SshIkev2Sa sa,
                   Boolean success,
                   const unsigned char *message, size_t message_len,
                   SshIkev2FbXauthAttributes attributes,
                   SshIkev2FbXauthStatus callback,
                   void *callback_context,
                   void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)context;

  ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_negotiate);

  neg->xauth_type = SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET;
  neg->xauth_status_cb = callback;
  neg->xauth_status_cb_context = callback_context;

  if (neg->v1_attrs)
    ikev2_fb_xauth_free_v1_attributes(neg->v1_attrs);

  neg->v1_attrs =
    ikev2_fb_xauth_encode_attributes(attributes,
                                     SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET,
                                     success, sa->xauth_enabled,
                                     message, message_len);
  if (neg->v1_attrs == NULL)
    ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_failed);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->thread);

  /* On purpose */
  return NULL;
}

static void
ikev2_fb_xauth_done(void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)context;

  neg->sub_operation = NULL;
  ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_result);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->thread);
}

SSH_FSM_STEP(ikev2_fb_st_i_xauth_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("XAUTH thread starting (neg %p)", neg));

  SSH_FSM_ASYNC_CALL({
    SSH_IKEV2_FB_V2_CALL(neg, xauth_request)(neg->server->sad_handle,
                                             neg->ed,
                                             ikev2_fb_xauth_request,
                                             ikev2_fb_xauth_set,
                                             ikev2_fb_xauth_done,
                                             neg);
  });
}

static void
ikev2_fb_xauth_negotiation_cb(SshIkeNegotiation negotiation,
                              SshIkePMPhaseII pm_info,
                              SshIkeNotifyMessageType error,
                              int number_of_attr_payloads,
                              SshIkePayloadAttr *attr_payloads,
                              void *context)
{
  SshIkev2FbNegotiation neg = NULL;

  /* Take fallback negotiation from `policy_manager_data' to safely
     deal with negotiation abort. */
  if (pm_info && pm_info->policy_manager_data)
    neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  /* If `neg' is NULL then the negotiation has been aborted and
     freed already and the thread is gone. */
  if (neg == NULL)
    return;

  /* If `neg->cfg_negotiation' is NULL then this is an error case
     and the callback was called synchronously from the running
     thread. */
  if (neg->cfg_negotiation != NULL)
    {
      neg->cfg_negotiation = NULL;
      ssh_fsm_continue(neg->thread);
    }

  neg->ike_error = ikev2_fb_v1_notify_message_type_to_v2_error_code(error);
  neg->v1_error = error;

  if (error == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      int i;

      ikev2_fb_xauth_free_attributes(neg->attrs);
      neg->attrs = NULL;

      for (i = 0; i < number_of_attr_payloads; i++)
        {
          SshIkePayloadAttr attrs = attr_payloads[i];

          if (neg->v1_conf_id != attrs->identifier)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Invalid transaction ID %d on XAuth; "
                                        "expected %d",
                                        (int) attrs->identifier,
                                        (int) neg->v1_conf_id));
              continue;
            }

          ikev2_fb_xauth_free_attributes(neg->attrs);
          neg->attrs = ikev2_fb_xauth_decode_attributes(attrs);
          if (neg->attrs == NULL)
            ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_failed);

          break;
        }

      if (neg->attrs == NULL)
        ssh_fsm_set_next(neg->thread, ikev2_fb_st_i_xauth_failed);
    }
}

SSH_FSM_STEP(ikev2_fb_st_i_xauth_negotiate)
{
  SshIkeErrorCode ret;
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation)thread_context;
  SshIkeNegotiation cfg_negotiation = NULL;
  SshIkePayloadAttr *v1_attrs;

  SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_negotiation_result);

  /* Take a reference to fallback negotiation, it will be put to
     `pm_info->policy_manager_data' by the isakmp library. This will be
     freed in ikev2_fb_phase_ii_sa_freed(). */
  IKEV2_FB_NEG_TAKE_REF(neg);

  /* Steal `v1_attrs' from fallback negotiation. If ssh_ike_connect_cfg()
     fails synchronously, the isakmp library frees `v1_attrs'. */
  v1_attrs = neg->v1_attrs;
  neg->v1_attrs = NULL;

  /* Clear `neg->cfg_negotiation'. This is used for detecting error
     conditions in ikev2_fb_xauth_negotiation_cb(). */
  neg->cfg_negotiation = NULL;

  ret = ssh_ike_connect_cfg((SshIkeServerContext)neg->ike_sa->server,
                            &cfg_negotiation,
                            neg->ike_sa->v1_sa,
                            NULL, NULL,
                            1,
                            v1_attrs,
                            neg,
                            SSH_IKE_FLAGS_USE_DEFAULTS,
                            ikev2_fb_xauth_negotiation_cb,
                            NULL);

  /* Success */
  if (ret == SSH_IKE_ERROR_OK && cfg_negotiation != NULL)
    {
      /* Clear reference to fallback negotiation from previous xauth round. */
      if (neg->p2_info && neg->p2_info->policy_manager_data)
        {
          SSH_ASSERT(neg ==
                     (SshIkev2FbNegotiation)neg->p2_info->policy_manager_data);
          ikev2_fb_phase_ii_clear_pm_data(neg->p2_info,
                                          (SshIkev2FbNegotiation)
                                          neg->p2_info->policy_manager_data);
          neg->p2_info = NULL;
          ikev2_fallback_negotiation_free(neg->fb, neg);
        }

      /* Save `neg->p2_info' so that `neg->p2_info->policy_manager_data'
         can be cleared before pm_info is freed. `p2_info' is only used for
         cleaning up fallback negotiation references. */
      neg->cfg_negotiation = cfg_negotiation;
      neg->p2_info = ikev2_fb_get_cfg_pm_info(neg->cfg_negotiation);

      /* Exchange started - wait for the callback. Isakmp library now owns
         `v1_attrs'. */

      return SSH_FSM_SUSPENDED;
    }

  /* Error, isakmp library has called callbacks synchronously. */
  else if (ret == SSH_IKE_ERROR_OK && cfg_negotiation == NULL)
    {
      /* Isakmp library has freed `v1_attrs', called the completion callback
         and freed `policy_manager_data'. */

      SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_failed);
    }

  /* Error, terminate now. */
  else
    {
      SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_failed);

      /* Free `v1_attrs' here. */
      ikev2_fb_xauth_free_v1_attributes(v1_attrs);

      /* Free the reference to fallback negotiation. */
      ikev2_fallback_negotiation_free(neg->fb, neg);
    }

  if (ret == SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND)
    {
      /* Mark IKEv2 error, and indicate this SA to the application.
         It should restart from the scratch. */
      neg->ike_error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      neg->ed->ike_sa->v1_sa = NULL;
    }
  else
    {
      /* Other failure. */
      neg->ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_i_xauth_negotiation_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("XAUTH result, error %d (neg %p)",
                          neg->ike_error, neg));

  if (neg->xauth_type ==  SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
    {
      if (neg->xauth_status_cb)
        SSH_FSM_ASYNC_CALL({
          (*neg->xauth_status_cb)(neg->ike_error,
                                  neg->attrs,
                                  neg->xauth_status_cb_context);
          neg->xauth_status_cb = NULL_FNPTR;
        });
    }
  else
    {
      if (neg->xauth_status_cb)
        SSH_FSM_ASYNC_CALL({
          (*neg->xauth_status_cb)(neg->ike_error,
                                  NULL,
                                  neg->xauth_status_cb_context);
          neg->xauth_status_cb = NULL_FNPTR;
        });

    }
  /* Keep compliners happy */
  SSH_NOTREACHED;
  SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_i_xauth_failed)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  /* Internal error state. Emulate XAuth failure. */
  neg->ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
  neg->v1_error = SSH_IKE_NOTIFY_MESSAGE_ABORTED;
  SSH_FSM_SET_NEXT(ikev2_fb_st_i_xauth_result);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_fb_st_i_xauth_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_DEBUG(SSH_D_LOWOK, ("XAUTH negotiation completed error %d (neg %p)",
                          neg->ike_error, neg));

  if (neg->xauth_status_cb)
    SSH_FSM_ASYNC_CALL({
      (*neg->xauth_status_cb)(neg->ike_error,
                              neg->attrs,
                              neg->xauth_status_cb_context);
      neg->xauth_status_cb = NULL_FNPTR;
    });

  if (neg->ed->callback != NULL_FNPTR)
    (*neg->ed->callback)(neg->server->sad_handle,
                         neg->ike_sa,
                         neg->ed,
                         neg->ike_error);


  if (neg->ed->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED)
    {
      ssh_operation_unregister_no_free(neg->ed->info_ed->operation_handle);
      neg->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
    }

  neg->ed->callback = NULL_FNPTR;
  return SSH_FSM_FINISH;
}

/*--------------------------------------------------------------------*/
/* This is the xauth client side - simple. Most of the functionality
   is within the policy manager.                                      */
/*--------------------------------------------------------------------*/
static void
ikev2_fb_xauth_do_response(SshIkev2Error status,
                           SshIkev2FbXauthAttributes attributes,
                           void *context)
{
  SshIkePayloadAttr *attrs;
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);

  if ((attrs =
       ikev2_fb_xauth_encode_attributes(attributes,
                                        SSH_IKE_CFG_MESSAGE_TYPE_CFG_REPLY,
                                        (status == SSH_IKEV2_ERROR_OK),
                                        neg->ike_sa->xauth_enabled,
                                        NULL, 0))
      != NULL)
    {
      attrs[0]->identifier = neg->v1_conf_id;
      (*neg->callbacks.u.cfg_fill_attrs)(1,
                                         attrs,
                                         neg->callbacks.callback_context);
    }
  else
    {
      if (neg->callbacks.u.cfg_fill_attrs)
        (*neg->callbacks.u.cfg_fill_attrs)(0,
                                           NULL,
                                           neg->callbacks.callback_context);
    }
  ikev2_fb_xauth_free_attributes(neg->attrs);
  neg->attrs = NULL;
}

static void
ikev2_fb_xauth_do_ack(SshIkev2Error status,
                      SshIkev2FbXauthAttributes attributes,
                      void *context)
{
  SshIkePayloadAttr *attrs;
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);

  if ((attrs =
       ikev2_fb_xauth_encode_attributes(attributes,
                                        SSH_IKE_CFG_MESSAGE_TYPE_CFG_ACK,
                                        (status == SSH_IKEV2_ERROR_OK),
                                        neg->ike_sa->xauth_enabled,
                                        NULL, 0))
      != NULL)
    {
      attrs[0]->identifier = neg->v1_conf_id;
      (*neg->callbacks.u.cfg_fill_attrs)(1,
                                         attrs,
                                         neg->callbacks.callback_context);
    }
  else
    {
      if (neg->callbacks.u.cfg_fill_attrs)
        (*neg->callbacks.u.cfg_fill_attrs)(0,
                                           NULL,
                                           neg->callbacks.callback_context);
    }
  ikev2_fb_xauth_free_attributes(neg->attrs);
  neg->attrs = NULL;
}

SSH_FSM_STEP(ikev2_fb_st_r_xauth_result)
{
  SSH_DEBUG(SSH_D_LOWOK, ("XAUTH negotiation completed (neg %p)",
                          thread_context));

  return SSH_FSM_FINISH;
}


SSH_FSM_STEP(ikev2_fb_st_r_xauth_start)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;
  SshIkev2Fb fb;

  SSH_DEBUG(SSH_D_LOWOK, ("XAUTH thread starting (neg %p)", neg));

  fb = neg->ike_sa->server->context->fallback;
  neg->ike_sa->xauth_started = 1;

  if (fb)
    {
      SSH_FSM_SET_NEXT(ikev2_fb_st_r_xauth_result);

      ikev2_fb_xauth_free_attributes(neg->attrs);
      if ((neg->attrs =
           ikev2_fb_xauth_decode_attributes(neg->v1_conf)) == NULL)
        {
          return SSH_FSM_FINISH;
        }

      if (neg->v1_conf->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_REQUEST)
        {
          if (fb->xauth_client_request_callback == NULL_FNPTR)
            {
            no_callback:
              /* The application has not provided these callbacks. Do
                 not indicate it anything about the server requesting
                 extra authentication as she is not waiting any such
                 information */
              ikev2_fb_xauth_free_attributes(neg->attrs);
              neg->attrs = NULL;
              (*neg->
               callbacks.u.cfg_fill_attrs)(0,
                                           NULL,
                                           neg->callbacks.callback_context);

              if (neg->ed->info_ed &&
                  (neg->ed->info_ed->flags
                   & SSH_IKEV2_INFO_OPERATION_REGISTERED))
                {
                  ssh_operation_unregister_no_free(
                          neg->ed->info_ed->operation_handle);
                  neg->ed->info_ed->flags &=
                    ~SSH_IKEV2_INFO_OPERATION_REGISTERED;
                }
              return SSH_FSM_FINISH;
            }

          SSH_FSM_ASYNC_CALL({
            (*fb->
             xauth_client_request_callback)(neg->ike_sa,
                                            neg->attrs,
                                            ikev2_fb_xauth_do_response,
                                            neg,
                                            fb->xauth_client_callback_context);
          });
        }
      else if (neg->v1_conf->type == SSH_IKE_CFG_MESSAGE_TYPE_CFG_SET)
        {
          if (fb->xauth_client_set_callback == NULL_FNPTR)
            goto no_callback;

          /* Extract message and status for convenience. */
          SSH_FSM_ASYNC_CALL({
            (*fb->
             xauth_client_set_callback)(neg->ike_sa,
                                        neg->attrs->status,
                                        neg->attrs->message,
                                        neg->attrs->message_len,
                                        neg->attrs,
                                        ikev2_fb_xauth_do_ack,
                                        neg,
                                        fb->xauth_client_callback_context);
          });
        }
    }
  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */
