/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmAuthorization"

#define SSH_PM_ASSERT_AUTHENTICATION_DATA(data)  \
  SSH_ASSERT((data) && (data)->p1 && (data)->p1->magic == SSH_PM_MAGIC_P1)

/* Completion callback for SshPmAuthorizationCB. */
void
ssh_pm_authorization_cb(SshUInt32 *group_ids,
                        SshUInt32 num_group_ids,
                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshPmP1 p1 = qm->p1;

  /* Check qm->error in case qm->p1 has been freed */
  if (p1 != NULL && qm->error == SSH_IKEV2_ERROR_OK)
    {
      ssh_free(p1->authorization_group_ids);
      p1->authorization_group_ids = NULL;
      p1->num_authorization_group_ids = 0;
      if (num_group_ids > 0)
        {
          p1->authorization_group_ids =
            ssh_memdup(group_ids, sizeof(group_ids[0]) * num_group_ids);

          /* If the memory allocation fails, the num of auth groups is 0,
             eventually this negotiation should fail if rule has these set. */
          if (p1->authorization_group_ids != NULL)
            p1->num_authorization_group_ids = num_group_ids;
        }
      p1->auth_group_ids_set = 1;

      /* The IKE SA is updated. */
      ssh_pm_ike_sa_event_updated(pm, p1);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/************** Internal authorization related help functions ***************/

void
ssh_pm_authorization_p1(SshPm pm, SshPmP1 p1,
                        SshPmAuthorizationResultCB callback,
                        void *context)
{
  /* Does the policy manager have an authorization callback? */
  if (pm->authorization_callback)
    {
      /* Yes.  Let's call it and let it to decide the authorization
         group ID. */
      memset(&p1->authentication_data, 0,
             sizeof(p1->authentication_data));
      p1->authentication_data.p1 = p1;

      (*pm->authorization_callback)(&p1->authentication_data,
                                    callback, context,
                                    pm->authorization_callback_context);
    }
  else
    {
      /* No authorization callback and therefore no group ID
         either. */
      (*callback)(NULL, 0, context);
    }
}

/************************ Public interface functions ************************/

void
ssh_pm_set_authorization_callback(SshPm pm,
                                  SshPmAuthorizationCB callback,
                                  void *context)
{
  pm->authorization_callback = callback;
  pm->authorization_callback_context = context;
}


/*************** Fetching attributes from authentication data ***************/

/** Get the IKE version used for this IKE SA. */
SshUInt32 ssh_pm_auth_get_ike_version(SshPmAuthData data)
{
  SSH_ASSERT(data != NULL);

  /* p1 is always present for IKEv1. */
  if (data->p1)
    {
#ifdef SSHDIST_IKEV1
      if (data->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        return 1;
#endif /* SSHDIST_IKEV1 */
    }
  return 2;
}

void
ssh_pm_auth_get_local_ip(SshPmAuthData data, SshIpAddr addr_return)
{
  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);
  SSH_ASSERT(addr_return != NULL);
  *addr_return = *data->p1->ike_sa->server->ip_address;
}

SshUInt16
ssh_pm_auth_get_local_port(SshPmAuthData data)
{
  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);

  return SSH_PM_IKE_SA_LOCAL_PORT(data->p1->ike_sa);
}

void
ssh_pm_auth_get_remote_ip(SshPmAuthData data, SshIpAddr addr_return)
{
  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);
  SSH_ASSERT(addr_return != NULL);
  *addr_return = *data->p1->ike_sa->remote_ip;
  return;
}

SshUInt16
ssh_pm_auth_get_remote_port(SshPmAuthData data)
{
  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);
  return data->p1->ike_sa->remote_port;
}

SshUInt32
ssh_pm_auth_get_local_ifnum(SshPmAuthData data)
{
  SshUInt32 ifnum = SSH_INVALID_IFNUM;
  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);

  ssh_pm_find_interface_by_address(data->pm,
                                 data->p1->ike_sa->server->ip_address,
                                 data->p1->ike_sa->server->routing_instance_id,
                                 &ifnum);

  return ifnum;
}

SshIkev2PayloadID
ssh_pm_auth_get_local_id(SshPmAuthData data, SshUInt32 order)
{
 SSH_PM_ASSERT_AUTHENTICATION_DATA(data);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
 if (order == 2)
   return data->p1->second_local_id;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
 if (order == 1)
   return data->p1->local_id;
 else
   {
     SSH_DEBUG(SSH_D_FAIL, ("Invalid local identity order %d", order));
     return NULL;
   }
}


SshIkev2PayloadID
ssh_pm_auth_get_remote_id(SshPmAuthData data, SshUInt32 order)
{
  SSH_ASSERT(data && (data->p1 || data->ed));

#ifdef SSH_IKEV2_MULTIPLE_AUTH
 if (order == 2)
   {
#ifdef SSHDIST_IKE_EAP_AUTH
     /* Use the identity used in EAP if applicable. */
     if (data->p1->second_eap_remote_id != NULL)
       return data->p1->second_eap_remote_id;
     else
#endif /* SSHDIST_IKE_EAP_AUTH */
       return data->p1->second_remote_id;
   }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

 if (order == 1)
   {
     if (data->p1 != NULL)
       {
#ifdef SSHDIST_IKE_EAP_AUTH
         /* Use the identity used in EAP if applicable. */
         if (data->p1->eap_remote_id != NULL)
           return data->p1->eap_remote_id;
         else
#endif /* SSHDIST_IKE_EAP_AUTH */
           return data->p1->remote_id;
       }
     else
       {
         if (data->ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
           return data->ed->ike_ed->id_r;
         else
           return data->ed->ike_ed->id_i;
       }
   }

 else
   {
     SSH_DEBUG(SSH_D_FAIL, ("Invalid remote identity order %d", order));
     return NULL;
   }
}

SshTime ssh_pm_auth_get_lifetime(SshPmAuthData data)
{
  SshTime lifetime = 0;
  SshPmTunnel tunnel;

  SSH_ASSERT(data && (data->p1 || data->ed));

  if (data->p1)
      lifetime = data->p1->lifetime;
  else
    {
      tunnel = ssh_pm_p1_get_tunnel(data->pm, (SshPmP1)data->ed->ike_sa);
      if (tunnel != NULL)
          lifetime = tunnel->u.ike.ike_sa_life_seconds;
    }
  return lifetime;
}

SshPmAuthMethod ssh_pm_auth_get_auth_method_local(SshPmAuthData data)
{
 SSH_PM_ASSERT_AUTHENTICATION_DATA(data);
 return data->p1->local_auth_method;
}

SshPmAuthMethod ssh_pm_auth_get_auth_method_remote(SshPmAuthData data)
{
 SSH_PM_ASSERT_AUTHENTICATION_DATA(data);
 return data->p1->remote_auth_method;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
const unsigned char *
ssh_pm_auth_get_certificate(SshPmAuthData data, size_t *cert_len_return)
{
  unsigned char *ber;

  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);

  if (data->p1->auth_cert == NULL)
    {
      *cert_len_return = 0;
      return NULL;
    }

  if (ssh_cm_cert_get_ber(data->p1->auth_cert, &ber, cert_len_return)
      != SSH_CM_STATUS_OK)
    {
      *cert_len_return = 0;
      return NULL;
    }

  return ber;
}


const unsigned char *
ssh_pm_auth_get_ca_certificate(SshPmAuthData data, size_t *cert_len_return)
{
  unsigned char *ber;

  SSH_PM_ASSERT_AUTHENTICATION_DATA(data);

  if (data->p1->auth_ca_cert == NULL)
    {
      *cert_len_return = 0;
      return NULL;
    }

  if (ssh_cm_cert_get_ber(data->p1->auth_ca_cert, &ber, cert_len_return)
      != SSH_CM_STATUS_OK)
    {
      *cert_len_return = 0;
      return NULL;
    }

  return ber;
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
SshPmXauthType
ssh_pm_auth_get_xauth_type(SshPmAuthData data)
{
  return data->xauth_type;
}

void *
ssh_pm_auth_get_xauth_attributes(SshPmAuthData data)
{
  return data->xauth_attributes;
}
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

SshPmAuthData
ssh_pm_auth_data_dup(SshPmAuthData data)
{
  SshPmAuthData ad;

  SSH_ASSERT(data->pm != NULL);

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
  if (data->xauth_attributes != NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Cannot duplicate auth data that has xauth_attributes set"));
      return NULL;
    }
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

  ad = ssh_calloc(1, sizeof(*ad));
  if (ad != NULL)
    {
      ad->pm = data->pm;

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
      ad->xauth_type = data->xauth_type;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

      if (data->p1 != NULL)
        {
          ad->p1 = data->p1;
          SSH_PM_IKE_SA_TAKE_REF(ad->p1->ike_sa);
        }
      if (data->ed != NULL)
        {
          ad->ed = data->ed;
          ssh_ikev2_exchange_data_take_ref(ad->ed);
        }
    }

  return ad;
}

void
ssh_pm_auth_data_free(SshPmAuthData data)
{
  if (data->p1 != NULL)
    SSH_PM_IKE_SA_FREE_REF(data->pm->sad_handle, data->p1->ike_sa);
  if (data->ed != NULL)
    ssh_ikev2_exchange_data_free(data->ed);
  ssh_free(data);
}

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
void
ssh_pm_authorization_xauth(SshPm pm, SshPmP1 p1,
                           SshPmXauthType xauth_type, void *xauth_attributes,
                           SshPmAuthorizationResultCB callback, void *context)
{
  SshPmAuthDataStruct ad[1];

  if (pm->authorization_callback)
    {
      /* Yes. */
      memset(ad, 0, sizeof(*ad));
      ad->pm = pm;
      ad->p1 = p1;
      ad->xauth_type = xauth_type;
      ad->xauth_attributes = xauth_attributes;

      (*pm->authorization_callback)(ad,
                                    callback, context,
                                    pm->authorization_callback_context);
    }
  else
    {
      /* No callback.  This completes our operation. */
      (*callback)(NULL, 0, context);
    }
}

#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
