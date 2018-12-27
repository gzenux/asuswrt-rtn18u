/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   pad_authorization_local.h
*/

#ifndef PMAPI_AUTHORIZATION_LOCAL_H
#define PMAPI_AUTHORIZATION_LOCAL_H

#include "quicksec_pm_low.h"

/*************************** Types and definitions ***************************/

/** An authorization object. */
typedef struct SshPmAuthorizationLocalRec *SshPmAuthorizationLocal;

/** An authorization group. */
typedef struct SshPmAuthorizationGroupRec *SshPmAuthorizationGroup;

/** Certificate constraint types. */
typedef enum
{
  /** Constrain the identity associated with the subject associated
     with a shared secret used on authentication. */
  SSH_PM_CONSTRAIN_PSK_SUBJECT,
  /** Constrain the identity.  This constrains the certificate's
     subject or subject alternative names depending on the identity
     type.*/
  SSH_PM_CONSTRAIN_SUBJECT,

  /** Constrain the certificate issuer.  This contrains the
     certificate's issuer or issuer alternative names depending on the
     identity type. */
  SSH_PM_CONSTRAIN_ISSUER,

  /** Constrain the CA certificate that was our point of trust for the
     remote peer's certificate. */
  SSH_PM_CONSTRAIN_CA


#ifdef SSHDIST_IPSEC_XAUTH_SERVER
  /** Extended authentication is required. */
  , SSH_PM_CONSTRAIN_XAUTH,

  /** Extended authentication with RADIUS.  This constrains the RADIUS
     server reply's attribute-value pairs (AVPs). */
  SSH_PM_CONSTRAIN_XAUTH_RADIUS
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#ifdef SSHDIST_IKE_EAP_AUTH
  /** Constrain the EAP authentication method */
  , SSH_PM_CONSTRAIN_EAP_AUTH_METHOD,

  /** Constrain the identity used for EAP authentication. */
  SSH_PM_CONSTRAIN_EAP_SUBJECT
#endif /* SSHDIST_IKE_EAP_AUTH */
} SshPmConstraintType;


/*************** Creating and destroying authorization objects ***************/

/** Create a local authorization object.  The function returns the
   object or NULL if errors were encountered. */
SshPmAuthorizationLocal ssh_pm_authorization_local_create(void);

/** Destroy the local authorization object `authorization'. */
void ssh_pm_authorization_local_destroy(SshPmAuthorizationLocal authorization);

/** Complete an update batch.  If the argument `purge_old' has the
   value TRUE, then all groups, added before the last purge operation
   will be freed.  If the argument `purge_old' has the value FALSE,
   then all groups, added after the last purge operation will be
   freed.  This function can be used for implementing
   pseudo-transactional updates for the groups. */
void ssh_pm_authorization_local_purge(SshPmAuthorizationLocal authorization,
                                      Boolean purge_old);


/*********************** Creating authorization groups ***********************/

/** Create a new authorization group with group ID `group_id'.  The
   function returns the group object or NULL if the group could not be
   created. */
SshPmAuthorizationGroup ssh_pm_authorization_group_create(SshUInt32 group_id);

/** Destroy the authorization group `group'. */
void ssh_pm_authorization_group_destroy(SshPmAuthorizationGroup group);

/** Add group `group' to the local authorization object
   `authorization'.  This adds one reference to the group `group'; you
   can destroy your copy of the group `group' after this call.  The
   group object will not be destroyed before the authorization object
   `authorization' is destroyed. */
void ssh_pm_authorization_add_group(SshPmAuthorizationLocal authorization,
                                    SshPmAuthorizationGroup group);

/** Set a new group ID `group_id' for the group `group'.  This can be
   used to override the group ID that was specified when the group
   `group' was created. */
void ssh_pm_authorization_group_set_id(SshPmAuthorizationGroup group,
                                       SshUInt32 group_id);

/** Get the group ID from the group `group'. */
SshUInt32 ssh_pm_authorization_group_get_id(SshPmAuthorizationGroup group);

/** Add certificate constraint for the group `group'.  The argument
   `identity_type' specifies the identity type that must be found from
   the certificate.  The argument `constraint_type' specifies the
   certificate and its field which are constrained.  The argument
   `constraint_pattern' specifies a glob-like pattern for which the
   certificate field must match.  The function returns TRUE if the
   constraint could be added and FALSE otherwise. */
Boolean ssh_authorization_group_add_cert_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        SshPmConstraintType constraint_type,
                                        const char *constraint_pattern);

/** Add shared key subject constraint to the group. The argument
   'identity_type' specifies the type of identity associated with the
   remote-secret (being one of ip|fqdn|email|dn. The argument
   `constraint_pattern' specifies a glob-like pattern for which the
   identity field must match.  The function returns TRUE if the
   constraint could be added and FALSE otherwise.*/
Boolean
ssh_authorization_group_add_psk_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        const char *constraint_pattern);

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
/** Add extended authentication constraint for the group `group'.  The
   argument `constraint_type' specifies the type of the XAUTH
   required.  The argument `constraint_field' specifies an optional
   (`constraint_type' dependent) field that is constrained from the
   XAUTH authentication.  The argument `constraint_pattern' specifies
   a pattern for which the `constraint_field' must match.  The
   function returns TRUE if the constraint could be added and FALSE
   otherwise.  */
Boolean ssh_authorization_group_add_xauth_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmConstraintType constraint_type,
                                        const char *constraint_field,
                                        const char *constraint_pattern);
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#ifdef SSHDIST_IKE_EAP_AUTH
/** Add EAP subject constraint to the group. The argument
   'identity_type' specifies the type of identity used in EAP authentication
   (being one of ip|fqdn|email|dn). The argument `constraint_pattern'
   specifies a glob-like pattern for which the identity field must match.
   The function returns TRUE if the constraint could be added and FALSE
   otherwise.*/
Boolean
ssh_authorization_group_add_eap_subject_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        const char *constraint_pattern);

/** Add EAP authentication method constraint for the group 'group'. The
    argument 'eap_type' specifies the required EAP authentication method */
Boolean ssh_authorization_group_add_eap_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmAuthMethod auth_method);
#endif /* SSHDIST_IKE_EAP_AUTH */
/********************* Authorization callback for PM API *********************/

/** An authorization callback for a policy manager using the
   SshPmAuthorizationLocal object given in the `context' argument.
   This callback can be set for a policy manager with the
   ssh_pm_set_authorization_callback function. */
void ssh_pm_authorization_local_callback(SshPmAuthData auth_data,
                                         SshPmAuthorizationResultCB result_cb,
                                         void *result_cb_context,
                                         void *context);

#endif /* PMAPI_AUTHORIZATION_LOCAL_H */
