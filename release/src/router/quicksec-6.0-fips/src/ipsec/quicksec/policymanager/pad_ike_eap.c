/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager PAD module for EAP.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "ssheap.h"
#ifdef SSHDIST_SIM
#include "sshsim.h"
#endif /* SSHDIST_SIM */


#define SSH_DEBUG_MODULE "SshPmIkeEapPAD"

#ifdef SSHDIST_IKE_EAP_AUTH

/********************* Forward Declarations ****************************/

static void
pm_eap_handle_token_request(SshPmEapState eap,
                            SshUInt8 sig_type, SshBuffer buf);
static void
pm_eap_output_cb(SshEapConnection conn, void *context, const SshBuffer buf);
static void
pm_eap_signal_cb(SshEap e,
                 SshUInt8 type, SshEapSignal signal, SshBuffer buf,
                 void *context);

/* Mapping from an EAP type to a SshPmAuthMethod authentication value */
SshPmAuthMethod pm_eap_type_to_auth_method(SshUInt8 eap_type)
{
  switch (eap_type)
    {
    case SSH_EAP_TYPE_MD5_CHALLENGE:
      return SSH_PM_AUTH_EAP_MD5_CHALLENGE;
    case SSH_EAP_TYPE_MSCHAP_V2:
      return SSH_PM_AUTH_EAP_MSCHAP_V2;
    case SSH_EAP_TYPE_SIM:
      return SSH_PM_AUTH_EAP_SIM;
    case SSH_EAP_TYPE_AKA:
      return SSH_PM_AUTH_EAP_AKA;








    case SSH_EAP_TYPE_TLS:
      return SSH_PM_AUTH_EAP_TLS;
    default:
      return SSH_PM_AUTH_NONE;
    }
}

Boolean pm_mutual_eap_method_allowed(SshUInt8 eap_type)
{
  /* RFC 5998, page 8 */
 switch (eap_type)
    {
    case SSH_EAP_TYPE_SIM:
    case SSH_EAP_TYPE_AKA:






    case SSH_EAP_TYPE_TLS:
      return TRUE;
    case SSH_EAP_TYPE_MD5_CHALLENGE:
    case SSH_EAP_TYPE_MSCHAP_V2:
    default:
      return FALSE;
    }
}

/**************** Initialization and Shutdown functions ***************/

void ssh_pm_ike_eap_destroy(SshPmEapState eap)
{
  if (eap)
    {
      if (eap->eap) ssh_eap_destroy(eap->eap);
      if (eap->connection) ssh_eap_connection_destroy(eap->connection);
      if (eap->packet) ssh_free(eap->packet);
      if (eap->user) ssh_free(eap->user);
      if (eap->salt) ssh_free(eap->salt);
      if (eap->secret) ssh_free(eap->secret);
      if (eap->passcode) ssh_free(eap->passcode);
      if (eap->answer) ssh_free(eap->answer);
      if (eap->nextpin) ssh_free(eap->nextpin);
      if (eap->auth_input_buf) ssh_free(eap->auth_input_buf);
      if (eap->auth_output_buf) ssh_free(eap->auth_output_buf);
#ifdef SSHDIST_SIM
      if (eap->sim) ssh_sim_close(eap->sim);
#endif /* SSHDIST_SIM */
#ifdef SSHDIST_EAP_TLS
      if (eap->key_id) ssh_free(eap->key_id);
#endif /* SSHDIST_EAP_TLS */
      ssh_free(eap);
    }
}

/* This is called when the first EAP packet is received. It sets up any
   state required for handling the EAP exchange. */
static SshPmEapState pm_eap_create(SshPm pm, SshPmP1 p1,
                                   SshIkev2ExchangeData ed,
                                   Boolean client,
                                   SshIkev2Error *error)
{
  int i;
  SshPmEapState eap;

  SSH_DEBUG(SSH_D_LOWOK, ("Setup EAP state"));

  if (!p1->n || !p1->n->tunnel || p1->auth_domain->num_eap_protocols == 0)
    {
      if (p1->n)
        p1->n->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;

      *error = SSH_IKEV2_ERROR_INVALID_SYNTAX;
      return NULL;
    }

  /* RFC 4306 forbids EAP with pre shared key responder authentication.
     Fail EAP setup here if we are responder, and local end was authenticated
     using psk. */
  if (!client && p1->local_auth_method == SSH_PM_AUTH_PSK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("EAP authentication cannot be used with pre shared key "
                 "based responder authentication."));

      if (p1->n)
        p1->n->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;

      *error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      return NULL;
    }

  /* Fail the negotiation if EAP_ONLY_AUTH is not used and auth
     method for responder is not set. */
  if (!p1->eap_only_auth &&
      !client &&
      p1->local_auth_method == SSH_PM_AUTH_NONE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Responder has not been authenticated and EAP-only is not "
                 "set, failing negotiation"));

      if (p1->n)
        p1->n->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;

      *error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      return NULL;
    }


  eap = ssh_calloc(1, sizeof(*eap));
  if (eap == NULL)
    goto failed_out_of_memory;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (ed->ike_ed->first_auth_done)
    eap->second_auth = 1;
  else
    eap->second_auth = 0;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /* Store back pointer to P1, so we can later access configuration */
  eap->pm = pm;
  eap->p1 = p1;
  eap->eap_try = 0;
  eap->client = client;
  eap->config = p1->auth_domain->eap_config;

#ifdef SSHDIST_RADIUS
  if (p1->auth_domain->radius_auth)
    {
      ssh_pm_auth_radius_get_clientinfo(p1->auth_domain->radius_auth,
                                        &eap->radius_config.
                                        radius_client,
                                        &eap->radius_config.
                                        radius_servers);

      eap->radius_config.default_avps = NULL;




      if (eap->radius_config.radius_client != NULL)
        eap->radius_enabled = 1;
    }
#endif /* SSHDIST_RADIUS */

  /* Create the connection object for passing EAP packets to the lower
     layer, which is the IKE library. */
  if ((eap->connection =
       ssh_eap_connection_create_cb(pm_eap_output_cb, eap)) == NULL)
    goto failed_out_of_memory;

  if (client)
    eap->eap =
      ssh_eap_create_client(eap, p1->auth_domain->eap_config,
                            eap->connection);
  else
    eap->eap =
      ssh_eap_create_server(eap, p1->auth_domain->eap_config,
                            eap->connection);

  if (eap->eap == NULL)
    goto failed_out_of_memory;

  for (i = 0; i < p1->auth_domain->num_eap_protocols; i++)
    {
      if (ssh_eap_accept_auth(eap->eap,
                              p1->auth_domain->eap_protocols[i].eap_type,
                              p1->auth_domain->eap_protocols[i].preference)
          != SSH_EAP_OPSTATUS_SUCCESS)
        {
          SSH_DEBUG(SSH_D_UNCOMMON,
                    ("Can't accept EAP authentication: Out of memory."));
          goto failed_out_of_memory;
        }

#ifdef SSHDIST_EAP_TLS
      if ((client || (!client
#ifdef SSHDIST_RADIUS
          && !eap->radius_enabled
#endif /* SSHDIST_RADIUS */
          )) &&
          p1->auth_domain->eap_protocols[i].eap_type == SSH_EAP_TYPE_TLS)
        {
          SshEapTlsParamsStruct tls_params;

          /* Pass the handle to the cert manager to EAP-TLS client. */
          memset(&tls_params, 0, sizeof(tls_params));
          tls_params.cm = p1->auth_domain->cm;

          if (ssh_eap_configure_protocol(eap->eap, SSH_EAP_TYPE_TLS,
                                         (void *)&tls_params,
                                         sizeof(tls_params))
              != SSH_EAP_OPSTATUS_SUCCESS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to configure EAP TLS params"));
              ssh_pm_ike_eap_destroy(eap);
              *error =  SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
              return NULL;
            }
        }
#endif /* SSHDIST_EAP_TLS */
    }

  /* Should we request the client's identity? */
  if (!client && (p1->n->tunnel->flags & SSH_PM_TR_EAP_REQUEST_ID))
    {
      eap->request_identity = TRUE;
      eap->identity_req_string = "Who are you?";
      eap->identity_req_string_len = strlen("Who are you?");
    }
  else if (!client)
    {
      SshIkev2PayloadID id;

      /* In this case we will not request the client's identity but instead
         use the identity the client specified in the IKE packet. */
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (ed->ike_ed->first_auth_done)
        id = ed->ike_ed->second_id_i;
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        id = ed->ike_ed->id_i;

      SSH_DEBUG(SSH_D_LOWOK, ("Using the IKE ID as EAP username %@",
                              ssh_pm_ike_id_render, id));

      eap->user = ssh_memdup(id->id_data, id->id_data_size);
      if (eap->user == NULL)
        goto failed_out_of_memory;
      eap->user_len = id->id_data_size;

#ifdef SSHDIST_RADIUS
      /* Set up the Radius state if required. Inputing the peer's identity
         will sent the identity to the Radius server, which will start the
         authentication. */
      if (eap->radius_enabled)
        {
          ssh_eap_radius_attach(eap->eap, &eap->radius_config);

          ssh_eap_radius_input_peer_identity(eap->eap,
                                             id->id_data,
                                             (unsigned long)id->id_data_size);
        }
      else
#endif /* SSHDIST_RADIUS */
        {
          /* Just begin the authentication round. */
          ssh_eap_authenticate(eap->eap, SSH_EAP_AUTH_CONTINUE);
        }
    }

#ifdef SSHDIST_SIM
  /* Init access to SIM card if EAP-SIM is enabled. */
  if (eap->sim == NULL)
    {
      for (i = 0; i < p1->auth_domain->num_eap_protocols; i++)
        {
          SshUInt8 eap_type = p1->auth_domain->eap_protocols[i].eap_type;

          if ((eap_type == SSH_EAP_TYPE_SIM) || (eap_type == SSH_EAP_TYPE_AKA))
            {
              eap->sim = ssh_sim_open();
              if (eap->sim == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot open SIM"));
                  ssh_pm_ike_eap_destroy(eap);
                  *error =  SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
                  return NULL;
                }
              break;
            }
        }
    }
#endif /* SSHDIST_SIM */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (eap->second_auth)
    eap->p1->n->second_eap = eap;
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    eap->p1->n->eap = eap;

  *error = SSH_IKEV2_ERROR_OK;
  return eap;

 failed_out_of_memory:
  if (eap)
    ssh_pm_ike_eap_destroy(eap);
  *error =  SSH_IKEV2_ERROR_OUT_OF_MEMORY;
  return NULL;
}

/* Abort operation for the IKE EAP request policy call. */
static void pm_eap_request_abort_cb(void *context)
{
  SshPmEapState eap = context;

  eap->callbacks.u.eap_request_cb = NULL_FNPTR;
  eap->callbacks.callback_context = NULL;
}


/* Fail the Phase-I negotiation by returning an error to the IKE library.
   This gets called if the EAP library informs of an fatal internal error.
   In such cases the EAP negotiation cannot continue
   and will not be terminated by an EAP_FAILURE message. An explicit error is
   returned to IKE which will terminate the IKE negotiation. */
static void pm_eap_fail_p1(SshPmEapState eap, SshIkev2Error error)
{
  SshIkev2PadEapRequestCB callback;
  void *context;

  SSH_DEBUG(SSH_D_FAIL, ("Eap has failed, IKE error %d", error));

  SSH_PM_ASSERT_P1N(eap->p1);
  SSH_ASSERT(error != SSH_IKEV2_ERROR_OK);

  if (eap->request_pending)
    {
      eap->request_pending = 0;

      callback = eap->callbacks.u.eap_request_cb;
      context = eap->callbacks.callback_context;

      (*callback)(error, NULL, 0, context);

      ssh_operation_unregister(eap->callbacks.operation);
    }
  else
    {
      eap->p1->n->eap_error = error;
      eap->p1->n->eap_received_failed = 1;
    }
}



/******************** EAP Signal handling ***********************/

static void pm_eap_fail_authentication(void *context)
{
  SshPmEapState eap = context;
  ssh_eap_authenticate(eap->eap,  SSH_EAP_AUTH_FAILURE);
}

static void pm_eap_begin_authentication(void *context)
{
  SshPmEapState eap = context;

#ifdef SSHDIST_RADIUS
  /* Attach to Radius if radius is enabled and we have not already done
     so in pm_eap_create() */
  if (eap->request_identity && eap->radius_enabled)
    ssh_eap_radius_attach(eap->eap, &eap->radius_config);
#endif /* SSHDIST_RADIUS */

  ssh_eap_authenticate(eap->eap, SSH_EAP_AUTH_CONTINUE);
}

static void
pm_eap_user_secret_la_cb(Boolean success,
                         const unsigned char *user, size_t user_len,
                         const unsigned char *secret, size_t secret_len,
                         const unsigned char *passcode, size_t passcode_len,
                         const unsigned char *nextpin, size_t nextpin_len,
                         const unsigned char *answer, size_t answer_len,
                         void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (eap->user_required && (user == NULL || user_len == 0))
    goto error;

  if (secret == NULL || secret_len == 0)
    goto error;

  /* Store the responses for the attributes we have requested */
  if ((user != NULL) && (eap->user = ssh_memdup(user, user_len)) == NULL)
    goto error;

  eap->user_len = user_len;

  eap->secret = ssh_memdup(secret, secret_len);
  if (eap->secret == NULL)
    goto error;

  eap->secret_len = secret_len;

  /* Answer to the originating query */
  if (eap->user_required)
    ssh_eap_init_token_username(&token, eap->user,
                                (unsigned long)eap->user_len);
  else
    ssh_eap_init_token_secret(&token, eap->secret,
                              (unsigned long)eap->secret_len);

  ssh_eap_token(eap->eap, eap->eap_type, &token);
  return;

 error:
  if (!eap->client)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failing EAP authentication, no user "
                             "password found"));
      ssh_register_timeout(&eap->timeout, 0, 0,
                           pm_eap_fail_authentication, eap);
    }
}

static void pm_eap_get_passwd_cb(const unsigned char *user_password,
                                 size_t user_password_len,
                                 void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;

  if (!user_password)
    goto error;

  /* Cache password. */
  eap->secret = ssh_memdup(user_password, user_password_len);
  if (eap->secret == NULL)
    goto error;

  SSH_DEBUG(SSH_D_LOWOK, ("Received password from callback"));
  eap->secret_len = user_password_len;

  /* Answer to the originating query */
  ssh_eap_init_token_secret(&token, eap->secret,
                            (unsigned long)eap->secret_len);
  ssh_eap_token(eap->eap, eap->eap_type, &token);
  return;

 error:
  /* No shared secret is available, we must fail the negotiation */
  if (!eap->client)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failing EAP authentication, no user "
                             "password found"));
      ssh_register_timeout(&eap->timeout, 0, 0,
                           pm_eap_fail_authentication, eap);
    }
}

#ifdef SSHDIST_EAP_SIM
static void
pm_eap_get_gsm_imsi_cb(SshSimGetImsiResult result,
                       const unsigned char *imsi, size_t imsi_len,
                       void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;
  unsigned char *new_user;
  size_t new_user_len;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (result != SSH_SIM_GET_IMSI_SUCCESSFUL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get IMSI from SIM"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }

  /* Calculate the length of the final username: a "1" digit followed
     by the IMSI and potentially a partial username from the policy (a
     "@" character followed by a realm). */
  new_user_len = 1 + imsi_len;
  if (eap->user)
    new_user_len += eap->user_len;

  /* Allocate buffer for the username plus null-termination. */
  new_user = ssh_malloc(new_user_len + 1);
  if (new_user == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate EAP-SIM username"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }

  /* Construct the final username and null-terminate. */
  new_user[0] = '1';
  memcpy(new_user + 1, imsi, imsi_len);
  new_user_len = 1 + imsi_len;
  if (eap->user)
    {
      memcpy(new_user + new_user_len, eap->user, eap->user_len);
      new_user_len += eap->user_len;
    }
  new_user[new_user_len] = '\0';

  /* Store the final username in the EAP state struct. */
  if (eap->user)
    ssh_free(eap->user);
  eap->user = new_user;
  eap->user_len = new_user_len;

  /* Send the username to the EAP library. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning username '%s' to  EAP",
                               eap->user));
  ssh_eap_init_token_username(&token, eap->user,
                              (unsigned long)eap->user_len);
  ssh_eap_token(eap->eap, eap->eap_type, &token);
}

static void
pm_eap_get_gsm_user_cb(Boolean success,
                       const unsigned char *user, size_t user_len,
                       const unsigned char *secret, size_t secret_len,
                       const unsigned char *passcode, size_t passcode_len,
                       const unsigned char *nextpin, size_t nextpin_len,
                       const unsigned char *answer, size_t answer_len,
                       void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;
  unsigned char *new_user;
  size_t new_user_len;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (!success || !user || user_len <= 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No EAP username in the policy, using IMSI only"));
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_get_imsi(eap->sim, pm_eap_get_gsm_imsi_cb, eap);
      return;
    }

  /* Copy username. */
  new_user = ssh_memdup(user, user_len);
  if (new_user == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate EAP-SIM username"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }
  new_user_len = user_len;

  /* Store username in the EAP state struct. */
  if (eap->user)
    ssh_free(eap->user);
  eap->user = new_user;
  eap->user_len = new_user_len;

  /* If we got a complete username, send that back to the EAP
     library. If we got a partial (realm-only) username, continue with
     IMSI retrieval. */
  if (eap->user[0] != '@')
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning username '%.*s' to EAP",
                                   eap->user_len, eap->user));
      ssh_eap_init_token_username(&token, eap->user,
                                  (unsigned long)eap->user_len);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Got partial EAP username '%.*s' from the policy",
                 eap->user_len, eap->user));
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_get_imsi(eap->sim, pm_eap_get_gsm_imsi_cb, eap);
    }
}

void
pm_eap_gsm_authenticate_cb(SshSimGsmAuthenticateResult result,
                           const unsigned char *sres, size_t sres_len,
                           const unsigned char *kc, size_t kc_len,
                           void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (result != SSH_SIM_GSM_AUTHENTICATE_SUCCESSFUL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("GSM authenticate failed"));
      ssh_eap_init_token_typed(&token, SSH_EAP_TOKEN_SIM_CHALLENGE, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }

  /* SIM op succeeded, i.e. we must have valid SRES and Kc. */
  SSH_ASSERT(sres_len == 4);
  SSH_ASSERT(kc_len == 8);

  /* Append SRES and Kc in the return buffer in the EAP state struct. */
  memcpy(eap->auth_output_buf + eap->auth_output_len, sres, sres_len);
  eap->auth_output_len += sres_len;
  memcpy(eap->auth_output_buf + eap->auth_output_len, kc, kc_len);
  eap->auth_output_len += kc_len;

  /* This RAND is now processed. */
  eap->auth_input_pos += 16;

  /* If we have more RANDs to process then continue with another GSM
     authentication operation. Otherwise, send the output data to the
     EAP library now. */
  if (eap->auth_input_pos < eap->auth_input_len)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("GSM authenticate succeeded, continuing"));
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_gsm_authenticate(eap->sim,
                                 eap->auth_input_buf + eap->auth_input_pos, 16,
                                 pm_eap_gsm_authenticate_cb, eap);
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("GSM authenticate succeeded, "
                         "returning %ld bytes to EAP:",
                         (long int)eap->auth_output_len),
                        eap->auth_output_buf, eap->auth_output_len);
      ssh_eap_init_token_typed(&token, SSH_EAP_TOKEN_SIM_CHALLENGE,
                               eap->auth_output_buf,
                               (unsigned long)eap->auth_output_len);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
    }
}
#endif /* SSHDIST_EAP_SIM */

#ifdef SSHDIST_EAP_AKA
static void
pm_eap_get_3g_imsi_cb(SshSimGetImsiResult result,
                      const unsigned char *imsi, size_t imsi_len,
                      void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;
  unsigned char *new_user;
  size_t new_user_len;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (result != SSH_SIM_GET_IMSI_SUCCESSFUL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get IMSI from USIM"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }

  /* Calculate the length of the final username: a "0" digit followed
     by the IMSI and potentially a partial username from the policy (a
     "@" character followed by a realm). */
  new_user_len = 1 + imsi_len;
  if (eap->user)
    new_user_len += eap->user_len;

  /* Allocate buffer for the username plus null-termination. */
  new_user = ssh_malloc(new_user_len + 1);
  if (new_user == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate EAP-AKA username"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }

  /* Construct the final username and null-terminate. */
  new_user[0] = '0';
  memcpy(new_user + 1, imsi, imsi_len);
  new_user_len = 1 + imsi_len;
  if (eap->user)
    {
      memcpy(new_user + new_user_len, eap->user, eap->user_len);
      new_user_len += eap->user_len;
    }
  new_user[new_user_len] = '\0';

  /* Store the final username in the EAP state struct. */
  if (eap->user)
    ssh_free(eap->user);
  eap->user = new_user;
  eap->user_len = new_user_len;

  /* Send the username to the EAP library. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning username '%s' to  EAP",
                               eap->user));
  ssh_eap_init_token_username(&token, eap->user,
                              (unsigned long)eap->user_len);
  ssh_eap_token(eap->eap, eap->eap_type, &token);
}

static void
pm_eap_get_3g_user_cb(Boolean success,
                      const unsigned char *user, size_t user_len,
                      const unsigned char *secret, size_t secret_len,
                      const unsigned char *passcode, size_t passcode_len,
                      const unsigned char *nextpin, size_t nextpin_len,
                      const unsigned char *answer, size_t answer_len,
                      void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;
  unsigned char *new_user;
  size_t new_user_len;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (!success || !user || user_len <= 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No EAP username in the policy, using IMSI only"));
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_get_imsi(eap->sim, pm_eap_get_3g_imsi_cb, eap);
      return;
    }

  /* Copy username. */
  new_user = ssh_memdup(user, user_len);
  if (new_user == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate EAP-AKA username"));
      ssh_eap_init_token_username(&token, NULL, 0);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
      return;
    }
  new_user_len = user_len;

  /* Store username in the EAP state struct. */
  if (eap->user)
    ssh_free(eap->user);
  eap->user = new_user;
  eap->user_len = new_user_len;

  /* If we got a complete username, send that back to the EAP
     library. If we got a partial (realm-only) username, continue with
     IMSI retrieval. */
  if (eap->user[0] != '@')
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning username '%.*s' to EAP",
                                   eap->user_len, eap->user));
      ssh_eap_init_token_username(&token, eap->user,
                                  (unsigned long)eap->user_len);
      ssh_eap_token(eap->eap, eap->eap_type, &token);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Got partial EAP username '%.*s' from the policy",
                 eap->user_len, eap->user));
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_get_imsi(eap->sim, pm_eap_get_3g_imsi_cb, eap);
    }
}

void
pm_eap_3g_authenticate_cb(SshSim3GAuthenticateResult result,
                          const unsigned char *res, size_t res_len,
                          const unsigned char *ck, size_t ck_len,
                          const unsigned char *ik, size_t ik_len,
                          const unsigned char *auts, size_t auts_len,
                          void *context)
{
  SshPmEapState eap = context;
  SshEapTokenStruct token;
  SshUInt32 res_byte_len;

  eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  if (result == SSH_SIM_3G_AUTHENTICATE_SUCCESSFUL)
    {
      /* USIM op succeeded, i.e. we must have valid return parameters. */
      SSH_ASSERT(res_len >= 32 && res_len <= 128);
      SSH_ASSERT(ck_len == 16);
      SSH_ASSERT(ik_len == 16);

      res_byte_len = (res_len / 8) + ((res_len % 8) ? 1 : 0);

      /* Store return data in the EAP state struct. */
      memcpy(eap->auth_output_buf + eap->auth_output_len, ik, ik_len);
      eap->auth_output_len += ik_len;
      memcpy(eap->auth_output_buf + eap->auth_output_len, ck, ck_len);
      eap->auth_output_len += ck_len;

      eap->auth_output_buf[eap->auth_output_len++] = (unsigned char)res_len;
      memcpy(eap->auth_output_buf + eap->auth_output_len, res, res_byte_len);
      eap->auth_output_len += res_byte_len;

      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("3G authenticate succeeded, "
                         "returning %ld bytes to EAP",
                         (long int)eap->auth_output_len),
                        eap->auth_output_buf, eap->auth_output_len);
      ssh_eap_init_token_typed(&token, SSH_EAP_TOKEN_AKA_CHALLENGE,
                               eap->auth_output_buf,
                               (unsigned long)eap->auth_output_len);
    }
  else if (result == SSH_SIM_3G_AUTHENTICATE_SYNCFAIL)
    {
      /* USIM op succeeded, i.e. we must have valid return parameters. */
      SSH_ASSERT(auts_len == 14);

      /* Store return data in the EAP state struct. */
      memcpy(eap->auth_output_buf + eap->auth_output_len, auts, auts_len);
      eap->auth_output_len += auts_len;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("3G authenticate synch failure, "
                                   "returning %ld bytes to EAP",
                                   (long int)eap->auth_output_len));
      ssh_eap_init_token_typed(&token, SSH_EAP_TOKEN_AKA_SYNCH_REQ,
                               eap->auth_output_buf,
                               (unsigned long)eap->auth_output_len);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("3G authenticate failed"));
      ssh_eap_init_token_typed(&token, SSH_EAP_TOKEN_AKA_AUTH_REJECT, NULL, 0);
    }

  ssh_eap_token(eap->eap, eap->eap_type, &token);
}

#if defined (SSHDIST_EAP_AKA) || defined(SSHDIST_EAP_AKA_DASH)
static Boolean
pm_eap_set_transform(SshPmP1 p1, Boolean client,
                     SshPmEapState eap,
                     Boolean verify_kdfinput,
                     SshIkev2Error *error)
{
  SshUInt32 i;

  for (i = 0; i < p1->auth_domain->num_eap_protocols; i++)
    {
      if (p1->auth_domain->eap_protocols[i].eap_type == SSH_EAP_TYPE_AKA




          )
        {
          SshEapAkaParamsStruct aka_params;
          SshUInt32 transform;
          SshUInt8 eap_type = SSH_EAP_TYPE_NONE;

          /* Get the transform configured for this eap method */
          transform = p1->auth_domain->eap_protocols[i].transform;

          /* Get the eap_type we are processing */
          if (p1->auth_domain->eap_protocols[i].eap_type ==
                     SSH_EAP_TYPE_AKA)
            eap_type = SSH_EAP_TYPE_AKA;






          /* Pass the transform to EAP-AKA client. */
          memset(&aka_params, 0, sizeof(aka_params));

          /* Map the transform according to EAP */
          if (transform & SSH_PM_MAC_HMAC_SHA1)
            aka_params.transform |= SSH_EAP_TRANSFORM_PRF_HMAC_SHA1;
          if (transform & SSH_PM_MAC_HMAC_SHA2)
            aka_params.transform |= SSH_EAP_TRANSFORM_PRF_HMAC_SHA256;







          if (ssh_eap_configure_protocol(eap->eap, eap_type,
                                         (void *)&aka_params,
                                         sizeof(aka_params))
              != SSH_EAP_OPSTATUS_SUCCESS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Unable to configure transform for \
                                      eap_type: %d", eap_type));
              *error =  SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
              return FALSE;
            }






          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("configured the transform for EAP method %s",
                     eap_type == SSH_EAP_TYPE_AKA ? "AKA" : "NONE"));

        }
     }
  *error = SSH_IKEV2_ERROR_OK;
  return TRUE;
}
#endif /* SSHDIST_EAP_AKA || SSHDIST_EAP_AKA_DASH */


































































































#endif /* SSHDIST_EAP_AKA */




static void
pm_eap_handle_token_request(SshPmEapState eap,
                            SshUInt8 eap_type,
                            SshBuffer buf)
{
  SshEapTokenStruct token;
  SshEapTokenType token_type;
#ifdef SSHDIST_EAP_TLS
  unsigned char **ca = NULL;
#endif /* SSHDIST_EAP_TLS */




#ifdef SSHDIST_EAP_SIM
  void *data;
  size_t data_len;
#else /* SSHDIST_EAP_SIM */
#if defined (SSHDIST_EAP_AKA) || defined (SSHDIST_EAP_AKA_DASH)
  void *data;
  size_t data_len;
#endif /* SSHDIST_EAP_AKA  || SSHDIST_EAP_AKA_DASH */
#endif /* SSHDIST_EAP_SIM */
  SshUInt32 la_eap_client_flags = 0;

  la_eap_client_flags |= SSH_PM_LA_EAP;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* If we are running second authentication round as a client, we will
     prefer client auth suitable for second auth */
  if (!eap->second_auth)
    la_eap_client_flags |= SSH_PM_LA_FIRST_ROUND;
  else
    la_eap_client_flags |= SSH_PM_LA_SECOND_ROUND;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  SSH_ASSERT(buf != NULL);

  token_type = ssh_eap_get_token_type_from_buf(buf);
  eap->eap_type = eap_type;

  switch (token_type)
    {
    case SSH_EAP_TOKEN_USERNAME:
      /* Check if already cached */
      if (eap->user && eap->user_len > 0)
        {
          ssh_eap_init_token_username(&token, eap->user,
                                      (unsigned long)eap->user_len);
          break;
        }

      token_type = SSH_EAP_TOKEN_NONE;

#ifdef SSHDIST_EAP_SIM
      if (eap_type == SSH_EAP_TYPE_SIM)
        {
          /* Try getting a full or partial (realm-only) username from
             the policy. */
          if (eap->pm->la_client_query_cb)
            {
              eap->eap_try += 1;
              eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
                (*eap->pm->la_client_query_cb)(eap->eap_try,
                                               eap->p1->ike_sa->remote_ip,
                                               NULL, 0,
                                               NULL, 0,
                                               (la_eap_client_flags |
                                                SSH_PM_LA_ATTR_USER_NAME),
                                               0,
                                               pm_eap_get_gsm_user_cb, eap,
                                               eap->pm->la_client_context);
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No policy usernames, using IMSI only"));
              eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
                ssh_sim_get_imsi(eap->sim, pm_eap_get_gsm_imsi_cb, eap);
            }
          break;
        }
#endif /* SSHDIST_EAP_SIM */

#ifdef SSHDIST_EAP_AKA
      if (eap_type == SSH_EAP_TYPE_AKA



         )
        {
          /* Try getting a full or partial (realm-only) username from
             the policy. */
          if (eap->pm->la_client_query_cb)
            {
              eap->eap_try += 1;
              eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
                (*eap->pm->la_client_query_cb)(eap->eap_try,
                                               eap->p1->ike_sa->remote_ip,
                                               NULL, 0,
                                               NULL, 0,
                                               (la_eap_client_flags |
                                                SSH_PM_LA_ATTR_USER_NAME),
                                               0,
                                               pm_eap_get_3g_user_cb, eap,
                                               eap->pm->la_client_context);
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No policy usernames, using IMSI only"));
              eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
                ssh_sim_get_imsi(eap->sim, pm_eap_get_3g_imsi_cb, eap);
            }
          break;
        }
#endif /* SSHDIST_EAP_AKA */

      /* From client-auth block if not already cached. */
      if (eap->pm->la_client_query_cb)
        {
          eap->user_required = 1;
          eap->eap_try += 1;

          eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
            (*eap->pm->la_client_query_cb)(eap->eap_try,
                                           eap->p1->ike_sa->remote_ip,
                                           NULL, 0,
                                           NULL, 0,
                                           (la_eap_client_flags |
                                            SSH_PM_LA_ATTR_USER_NAME |
                                            SSH_PM_LA_ATTR_USER_PASSWORD),
                                           0,
                                           pm_eap_user_secret_la_cb, eap,
                                           eap->pm->la_client_context);

        }

      break;

    case SSH_EAP_TOKEN_SHARED_SECRET:

      /* If we have a shared secret, then use it. */
      if (eap->secret && eap->secret_len > 0)
        {
          ssh_eap_init_token_secret(&token, eap->secret,
                                    (unsigned long)eap->secret_len);
          break;
        }

      /* Else see if we can get the secret from the client-auth query */
      if (eap->client && eap->pm->la_client_query_cb)
        {
          token_type = SSH_EAP_TOKEN_NONE;
          eap->user_required = 0;
          eap->eap_try += 1;
          eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
            (*eap->pm->la_client_query_cb)(eap->eap_try,
                                           eap->p1->ike_sa->remote_ip,
                                           NULL, 0,
                                           NULL, 0,
                                           (la_eap_client_flags |
                                            SSH_PM_LA_ATTR_USER_NAME |
                                            SSH_PM_LA_ATTR_USER_PASSWORD),
                                           0,
                                           pm_eap_user_secret_la_cb, eap,
                                           eap->pm->la_client_context);
          break;
        }

      /* Otherwise (for non-RADIUS servers) try to get the shared secret
         from the password authentication callback */
      if (!eap->client && eap->p1->auth_domain->passwd_auth)
        {
          token_type = SSH_EAP_TOKEN_NONE;
          (*eap->pm->passwd_auth_callback)(
                                       eap->user,
                                       eap->user_len,
                                       pm_eap_get_passwd_cb, eap,
                                       eap->p1->auth_domain->passwd_auth);
          break;
        }

      /* No shared secret is available, we must fail the negotiation */
       if (!eap->client)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failing EAP authentication, no user "
                                 "password found"));
          ssh_register_timeout(&eap->timeout, 0, 0,
                               pm_eap_fail_authentication, eap);
        }
      return;






























#ifdef SSHDIST_EAP_SIM
    case SSH_EAP_TOKEN_SIM_CHALLENGE:
      token_type = SSH_EAP_TOKEN_NONE;

      /* Get the authentication data to be passed to the SIM. */
      ssh_eap_get_token_data_from_buf(buf, &data, &data_len);

      /* We should have two or three 16-byte RANDs. Correspondingly,
         the output buffer will consist of two or three 12-byte chunks
         each of which contains a 4-byte SRES and an 8-byte Kc. */
      if (data_len != 32 && data_len != 48)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid EAP-SIM authentication input data"));
          break;
        }

      /* Allocate output buffer for maximum output (36 bytes). */
      if (eap->auth_output_buf)
        {
          ssh_free(eap->auth_output_buf);
          eap->auth_output_len = 0;
        }

      eap->auth_output_buf = ssh_malloc(36);
      if (eap->auth_output_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot alloc EAP-SIM authentication output buffer"));
          break;
        }
      eap->auth_output_len = 0;

      /* Copy input data into the EAP state struct. */
      if (eap->auth_input_buf)
        {
          ssh_free(eap->auth_input_buf);
          eap->auth_input_len = 0;
        }

      eap->auth_input_buf = ssh_memdup(data, data_len);
      if (eap->auth_input_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot copy EAP-SIM authentication input data"));
          ssh_free(eap->auth_output_buf);
          eap->auth_output_buf = NULL;
          break;
        }

      eap->auth_input_len = data_len;
      eap->auth_input_pos = 0;

      /* Start GSM authenticate on the first 16-byte RAND. */
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Beginning GSM authenticate of %ld bytes of input:",
                         (long int)eap->auth_input_len),
                        eap->auth_input_buf, eap->auth_input_len);
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_gsm_authenticate(eap->sim,
                                 eap->auth_input_buf, 16,
                                 pm_eap_gsm_authenticate_cb, eap);
      break;
#endif /* SSHDIST_EAP_SIM */

#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TOKEN_AKA_CHALLENGE:
      token_type = SSH_EAP_TOKEN_NONE;

      /* Get the authentication data to be passed to the SIM. */
      ssh_eap_get_token_data_from_buf(buf, &data, &data_len);

      /* There should be a 16-byte RAND and a 16-byte AUTN. */
      if (data_len != 32)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid EAP-AKA authentication input data"));
          break;
        }

      /* Allocate output buffer the maximum size of which is 49 bytes
         (16-byte IK, 16-byte CK, RES length byte and a 4-to-16 byte
         RES). */
      if (eap->auth_output_buf)
        {
          ssh_free(eap->auth_output_buf);
          eap->auth_output_len = 0;
        }

      eap->auth_output_buf = ssh_malloc(49);
      if (eap->auth_output_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot alloc EAP-AKA authentication output buffer"));
          break;
        }
      eap->auth_output_len = 0;

      /* Copy input data into the EAP state struct. */
      if (eap->auth_input_buf)
        {
          ssh_free(eap->auth_input_buf);
          eap->auth_input_len = 0;
        }

      eap->auth_input_buf = ssh_memdup(data, data_len);
      if (eap->auth_input_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot copy EAP-AKA authentication input data"));
          ssh_free(eap->auth_output_buf);
          eap->auth_output_buf = NULL;
          break;
        }
      eap->auth_input_len = data_len;
      eap->auth_input_pos = 0;

      /* Start 3G authenticate. */
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("Beginning 3G authenticate of %ld bytes of input:",
                         (long int)eap->auth_input_len),
                        eap->auth_input_buf, eap->auth_input_len);
      eap->p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
        ssh_sim_3g_authenticate(eap->sim,
                                eap->auth_input_buf, 16,
                                eap->auth_input_buf + 16, 16,
                                pm_eap_3g_authenticate_cb, eap);
      break;
#endif /* SSHDIST_EAP_AKA */

































#ifdef SSHDIST_EAP_TLS
    case SSH_EAP_TOKEN_PRIVATE_KEY:
      {
        SshPrivateKey prvkey = NULL;
        SshIkev2PayloadID id = NULL;
        SshPmEk ek = NULL;
        unsigned char *id_data = NULL;
        size_t id_data_size = 0;
        SshUInt32 i;

        id = ssh_pm_ike_get_identity(eap->pm, eap->p1,
                                     eap->p1->n->tunnel, FALSE);
        if (id == NULL)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Tunnel identity vanished"));
            goto error;
          }

        /* Get the private key. Lookup based on our identity. */
        ek = ssh_pm_ek_get_by_identity(eap->pm, id);
        ssh_pm_ikev2_payload_id_free(id);

        /* If no private key available */
        if (ek == NULL || ek->private_key == NULL)
          {
            SSH_DEBUG(SSH_D_FAIL, ("No private key available"));
            goto error;
          }

        prvkey = ek->private_key;

        if (!ek->rsa_key)
          {
            SSH_DEBUG(SSH_D_FAIL, ("non-RSA keys not supported for EAP-TLS"));

            prvkey = NULL;
            goto error;
          }

        /* Try to fetch the certificate DN from EK to be used as search
           key in certificate search. */
        for (i = 0; i < ek->num_ids; i++)
          {
            if (ek->ids[i]->id_type == SSH_IKEV2_ID_TYPE_ASN1_DN)
              {
                id_data = ssh_memdup(ek->ids[i]->id_data,
                                     ek->ids[i]->id_data_size);
                if (id_data)
                  {
                    id_data_size = ek->ids[i]->id_data_size;
                    eap->key_id = id_data;
                  }
                break;
              }
          }

        /* On error a NULL private key will be returned to EAP */
      error:
        if (ek != NULL) ssh_pm_ek_unref(eap->pm, ek);
        ssh_eap_init_token_private_key(&token, prvkey,
                                       id_data, id_data_size);
        break;
      }

    case SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY:
      {
        int i;

        SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP requested token certificate"
                                     " authority"));

        /* Do we even have CA's? */
        if (eap->p1->auth_domain->num_cas == 0)
          {
            SSH_DEBUG(SSH_D_FAIL, ("No CA's configured."));
            goto ca_error;
          }

        /* Allocate a table for pointing CA's. Make it 1 larger,
           since the last one is NULL (end mark). */
        ca = ssh_calloc(eap->p1->auth_domain->num_cas + 1,
                        sizeof(unsigned char *));
        if (ca == NULL)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed. Can't give"
                                   " CA information to EAP."));
            goto ca_error;
          }

        for (i = 0; i < eap->p1->auth_domain->num_cas; i++)
          {
            SshPmCa authority = eap->p1->auth_domain->cas[i];

            ca[i] = authority->cert_issuer_dn;
          }

        /* Make sure the last one is NULL. */
        ca[eap->p1->auth_domain->num_cas] = NULL;

      ca_error:
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Initialising CA token (%p).", ca));
        ssh_eap_init_token_certificate_authority(&token, ca);
        break;
      }

#endif /* SSHDIST_EAP_TLS */

    default:
      token_type = SSH_EAP_TOKEN_NONE;
      break;
    }

  if (token_type != SSH_EAP_TOKEN_NONE)
    {
      ssh_eap_token(eap->eap, eap_type, &token);
    }






#ifdef SSHDIST_EAP_TLS
  if (ca)
    ssh_free(ca);
#endif /* SSHDIST_EAP_TLS */

  return;
}

static void
pm_eap_signal_cb(SshEap e, SshUInt8 type, SshEapSignal signal,
                 SshBuffer buf, void *context)

{
  SshPmEapState eap = context;

  SSH_DEBUG(SSH_D_MIDOK, ("received signal %d type %d buf %s",
                          signal, type, (buf == NULL ? "<no>" : "<yes>")));

  switch (signal)
    {
    case SSH_EAP_SIGNAL_IDENTITY:
      if (!eap->client)
        {
          SSH_ASSERT(buf != NULL);

          /* We may have the user already filled by the policy, and
             the client still may respond with it. Clear the policy
             one here. */
          ssh_free(eap->user);
          eap->user = ssh_memdup(ssh_buffer_ptr(buf), ssh_buffer_len(buf));

          if (eap->user == NULL)
            return;

          eap->user_len = ssh_buffer_len(buf);

          ssh_register_timeout(&eap->timeout, 0, 0,
                               pm_eap_begin_authentication, eap);
        }
      else
        SSH_NOTREACHED;

      break;

    case SSH_EAP_SIGNAL_NEED_TOKEN:
      SSH_ASSERT(buf != NULL);

      pm_eap_handle_token_request(eap, type, buf);
      break;

    case SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME:
    case SSH_EAP_SIGNAL_AUTH_FAIL_REPLY:
    case SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION:
      SSH_DEBUG(SSH_D_FAIL, ("EAP Authentication failed, signal %d "
                             "IKE SA %p", signal, eap->p1->ike_sa));
      if (eap->pm->la_client_result_cb)
        (*eap->pm->la_client_result_cb)(eap->eap_try,
                                        FALSE,
                                        NULL, 0,
                                        eap->pm->la_client_context);
      if (eap->client)
        pm_eap_fail_p1(eap, SSH_IKEV2_ERROR_AUTHENTICATION_FAILED);

      break;

    case SSH_EAP_SIGNAL_AUTH_OK_USERNAME:
      SSH_DEBUG(SSH_D_HIGHOK, ("username authentication ok"));

      break;

    case SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK:
      SSH_DEBUG(SSH_D_HIGHOK, ("EAP authentication ok"));

      /* Record the EAP method */
      eap->eap_type = type;
      eap->auth_ok = 1;

      break;

    case SSH_EAP_SIGNAL_AUTH_PEER_MAYBE_OK:
      /* Record the EAP method */
      eap->eap_type = type;
      break;

    case SSH_EAP_SIGNAL_AUTH_PEER_OK:
      SSH_DEBUG(SSH_D_HIGHOK, ("peer authentication ok"));

      if (eap->pm->la_client_result_cb)
        (*eap->pm->la_client_result_cb)(eap->eap_try,
                                        TRUE,
                                        NULL, 0,
                                        eap->pm->la_client_context);
      eap->peer_ok = 1;
      break;

    case SSH_EAP_SIGNAL_PACKET_DISCARDED:
    case SSH_EAP_SIGNAL_TOKEN_DISCARDED:
      if (buf)
        SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("Discard received packet/token"),
                          ssh_buffer_ptr(buf), ssh_buffer_len(buf));
      break;

    case SSH_EAP_SIGNAL_FATAL_ERROR:
      pm_eap_fail_p1(eap, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      break;

    case SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT:

      SSH_DEBUG(SSH_D_FAIL, ("Authentication failure timeout received"));

      if (!eap->client)
        pm_eap_fail_authentication(eap);
      else
        pm_eap_fail_p1(eap, SSH_IKEV2_ERROR_TIMEOUT);
      break;

    default:
      break;
    }
}


/******************** EAP output function ***********************/

/* The function outputs EAP packets to the lower layer. */
static void
pm_eap_output_cb(SshEapConnection conn,
                 void *context,
                 const SshBuffer buf)
{
  SshPmEapState eap = context;
  unsigned char *packet;
  size_t packet_len;

  SSH_DEBUG(SSH_D_MY, ("Sending EAP packet"));

  packet_len = ssh_buffer_len(buf);
  packet = ssh_buffer_ptr(buf);

  /* Log this event if the EAP layer is sending a EAP failure (EAP code
     equal to 4) message. */
  if (packet_len && packet[0] == 4)
    {
      ssh_ikev2_debug_error_local(
        eap->p1->ike_sa, "EAP Authentication Failed");
      ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          eap->p1, "EAP authentication failure", FALSE);
    }

  if (eap->request_pending)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Send packet, length %d",
                                      packet_len), packet, packet_len);

      /* Output the packet immediately */
      (*eap->callbacks.u.eap_request_cb)(SSH_IKEV2_ERROR_OK,
                                         packet, packet_len,
                                         eap->callbacks.callback_context);

      ssh_operation_unregister(eap->callbacks.operation);

      eap->callbacks.u.eap_request_cb = NULL_FNPTR;
      eap->callbacks.callback_context = NULL;
      eap->request_pending = 0;
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Saving packet, length %d", packet_len),
                        packet, packet_len);

      eap->packet_ready = 1;

      /* Save the packet data. */
      eap->packet = ssh_memdup(packet, packet_len);
      if (eap->packet != NULL)
        eap->packet_len = packet_len;
    }
  return;
}


/**************** Policy Manager Functions ****************************/

/* EAP payload processing */
void
ssh_pm_ike_eap_received(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        const unsigned char *eap,
                        size_t eap_length)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmEapState eap_state = NULL;
  SshBufferStruct buf[1];
  SshIkev2Error error;
  Boolean client;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  Boolean second_auth;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* If PM is not active, reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    return;

  if (p1->n == NULL || !SSH_PM_P1_USABLE(p1))
    return;

  /* Sanity check the state */
  if (ed->state != SSH_IKEV2_STATE_IKE_AUTH_1ST &&
      ed->state != SSH_IKEV2_STATE_IKE_AUTH_EAP &&
      ed->state != SSH_IKEV2_STATE_IKE_AUTH_LAST)
    return;

  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to get authentication domain for EAP"));
      return;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (ed->ike_ed->first_auth_done)
    second_auth = TRUE;
  else
    second_auth = FALSE;

  if (second_auth)
    eap_state = p1->n->second_eap;
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    eap_state = p1->n->eap;

  client =
    (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ? TRUE : FALSE;

  /* Check if this is the first EAP packet. */
  if (eap_state == NULL)
    {
      /* Client creates EAP when receiving first EAP payload */
      SSH_ASSERT(client);

      eap_state = pm_eap_create(pm, p1, ed, client, &error);
      if (eap_state == NULL)
        {
          p1->n->eap_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          p1->n->eap_received_failed = 1;
          return;
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (second_auth)
        p1->n->second_eap = eap_state;
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        p1->n->eap = eap_state;

#if defined (SSHDIST_EAP_AKA) || defined(SSHDIST_EAP_AKA_DASH)
      if (pm_eap_set_transform(p1, client, eap_state, FALSE, &error) == FALSE)
        return;
#endif /* SSHDIST_EAP_AKA || SSHDIST_EAP_AKA_DASH */
    }
  /* For IKE responders inspect if this is an EAP identity response, if
     so then save the identity. This identity will be used for any
     authorization checks. */
  if (!client && eap_length > 5 &&
      (eap[0] == 2) && /* EAP response */
      (eap[4] == 1)) /* EAP type is Identity */
  {
    Boolean malformed_id;
    SshIkev2PayloadID id;
    SshUInt16 length = SSH_GET_16BIT(eap + 2);

    SSH_DEBUG(SSH_D_MIDOK, ("Trying to parse EAP identity payload"));

    /* The length encoded in the EAP payload must be less than the actual
       packet length. If not, then do not try to decode the identirty here,
       we'll just pass the packet to the EAP module and it will take care
       of processing the error. */
    if (length <= eap_length)
      {
        /* Try first to decode the identity as an RFC822 address */
        id = ssh_pm_decode_identity(SSH_PM_IDENTITY_RFC822,
                                    eap + 5,
                                    length - 5,
                                    &malformed_id);

        /* If the identity could not be decoded as an RFC822 address then try
           decoding it as a ID_KEY_ID identiy type (RFC 4718, section 3.4). */
        if (malformed_id)
          {
            /* Try first to decode the identity as an RFC822 address */
            id = ssh_pm_decode_identity(SSH_PM_IDENTITY_KEY_ID,
                                        eap + 5,
                                        length - 5,
                                        &malformed_id);
          }

        /* Failure to decode the EAP identity is not currently treated as an
           error. */
        if (!malformed_id && id != NULL)
          {
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("Decoded the identity '%@' from EAP Identity response "
                       "packet", ssh_pm_ike_id_render, id));

#ifdef SSH_IKEV2_MULTIPLE_AUTH
            if (second_auth)
              {
                /* Only set 'p1->second_eap_remote_id' if it differs from
                   the remote second IKE identity. */
                if (ssh_pm_ikev2_id_compare(ed->ike_ed->second_id_i, id))
                  ssh_pm_ikev2_payload_id_free(id);
                else
                  p1->second_eap_remote_id = id;
              }
            else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
            {
              /* Only set 'p1->eap_remote_id' if it differs from the IKE
                 identity. */
              if (ssh_pm_ikev2_id_compare(ed->ike_ed->id_i, id))
                ssh_pm_ikev2_payload_id_free(id);
              else
                p1->eap_remote_id = id;
            }
          }
      }

  }
  SSH_DEBUG_HEXDUMP(SSH_D_HIGHSTART,
                    ("Received EAP payload of length %d/(displays 64)",
                     eap_length),
                    eap, eap_length > 64 ? 64: eap_length);

  /* Pass the buffer to the EAP connection. */
  ssh_buffer_init(buf);
  if (ssh_buffer_append(buf, (unsigned char *)eap, eap_length)
      == SSH_BUFFER_OK)
    {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (second_auth)
        ssh_eap_connection_input_packet(p1->n->second_eap->connection, buf);
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        ssh_eap_connection_input_packet(p1->n->eap->connection, buf);
    }
  else
    {
      p1->n->eap_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      p1->n->eap_received_failed = 1;
      return;
    }

  ssh_buffer_uninit(buf);
  return;
}

SshOperationHandle
ssh_pm_ike_eap_request(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       SshIkev2PadEapRequestCB reply_callback,
                       void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshIkev2Error error;
  SshPmEapState eap;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  Boolean second_auth;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  Boolean client =
    (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ? TRUE : FALSE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* If PM is not active, reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("PM is not active, request rejected."));
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  if (!SSH_PM_P1_USABLE(p1))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("IKE SA %p unusable.", p1->ike_sa));
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  if (p1->n == NULL || (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Negotiation context has vanished. Server going down."));
      (*reply_callback)(SSH_IKEV2_ERROR_GOING_DOWN, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  /* If we failed to handle EAP payload earlier, this is the first place
     we can reject the negotiation. */
  if (p1->n->eap_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKEv2 SA %p ED %p failed, error: %d",
                             ed->ike_sa, ed, p1->n->eap_error));
      (*reply_callback)(p1->n->eap_error, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  /* Select a tunnel for the reponder if not already done */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      SshIkev2Error error;

      error = ssh_pm_select_ike_responder_tunnel(pm, p1, ed);
      if (error != SSH_IKEV2_ERROR_OK)
        {
          (*reply_callback)(error, NULL, 0, reply_callback_context);
          return NULL;
        }
    }

  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to get authentication domain for EAP"));
      (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                        NULL, 0, reply_callback_context);
      return NULL;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (ed->ike_ed->first_auth_done)
    second_auth = TRUE;
  else
    second_auth = FALSE;

  if (second_auth)
    eap = p1->n->second_eap;
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    eap = p1->n->eap;

  /* IKE initiator decides here if we use EAP only auth or if we should
     drop the negotiation due to missing responder authentication. */
  if (client &&
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      second_auth == FALSE &&
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
      p1->remote_auth_method == SSH_PM_AUTH_NONE)
    {
      if (p1->n->tunnel->flags & SSH_PM_T_EAP_ONLY_AUTH)
        p1->eap_only_auth = 1;
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Missing responder authentication, "
                                 "failing negotiation"));
          (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                            NULL, 0, reply_callback_context);
          return NULL;
        }
    }

  /* Check if this is the first EAP packet. */
  if (eap == NULL)
    {
      /* Responder creates EAP when creating first EAP packet */
      SSH_ASSERT(!client);

      /* Check if the responder is to use EAP only authentication */
      if ((p1->n->tunnel->flags & SSH_PM_T_EAP_ONLY_AUTH) &&
          p1->n->peer_supports_eap_only_auth)
        p1->eap_only_auth = 1;

      /* If the IKE initiator has used the "me Tarzan, you Jane" option,
         then check here that that responder has replied with an acceptable
         identity. */
      if (!ssh_pm_ike_check_requested_identity(pm, p1, ed->ike_ed->id_r))
        {
          p1->n->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;
          (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                            NULL, 0, reply_callback_context);
          return NULL;
        }

      eap = pm_eap_create(pm, p1, ed, client, &error);
      if (eap == NULL)
        {
          (*reply_callback)(error, NULL, 0, reply_callback_context);
          return NULL;
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (second_auth)
        p1->n->second_eap = eap;
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        p1->n->eap = eap;

      if (!eap->client && eap->request_identity)
        {
          ssh_eap_send_identification_request(eap->eap,
                                eap->identity_req_string,
                                (unsigned long)eap->identity_req_string_len);
        }
    }

  /* Check for previous errors. This needs to be called after the possible
     call to pm_eap_create above as that function may cause the
     eap_received_failed flag to be set without returning FALSE (via
     the SshEapSignalCB callback). */
  if (p1->n->eap_received_failed)
    {
      SSH_ASSERT(p1->n->eap_error != SSH_IKEV2_ERROR_OK);
      (*reply_callback)(p1->n->eap_error, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  /* If the EAP library is ready, then send the packet out immediately.
     Otherwise we wait until the EAP library indicates it is ready (by
     calling the connection output callback). */
  if (eap->packet_ready)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, ("Sending EAP packet"),
                        eap->packet, eap->packet_len);

      (*reply_callback)(SSH_IKEV2_ERROR_OK, eap->packet, eap->packet_len,
                        reply_callback_context);

      ssh_free(eap->packet);
      eap->packet = NULL;
      eap->packet_len = 0;
      eap->packet_ready = 0;
      return NULL;
    }


  /* Check if the EAP layer is done, if so signal this to the IKE
     layer.  The initiator is done if and only if the signal
     SSH_EAP_SIGNAL_AUTH_PEER_OK has been received
     i.e. eap_ctx->peer_ok = 1.  The responder is done if the signal
     SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK has been received
     i.e. eap_ctx->auth_ok = 1.  */

  if (eap->peer_ok || eap->auth_ok)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Signal that EAP is done"));

      SSH_ASSERT(eap->packet_ready == 0);

      (*reply_callback)(SSH_IKEV2_ERROR_OK, NULL, 0, reply_callback_context);

      eap->protocol_done = 1;
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("EAP packet not ready yet, saving this request"));
  eap->request_pending = 1;

  eap->callbacks.u.eap_request_cb = reply_callback;
  eap->callbacks.callback_context = reply_callback_context;

  ssh_operation_register_no_alloc(eap->callbacks.operation,
                                  pm_eap_request_abort_cb, eap);
  return eap->callbacks.operation;
}

typedef struct SshPmEapAuthorizationContextRec
{
  unsigned char *buf;
  size_t buf_len;
  SshPmP1 p1;
  SshPmQm qm;
  SshIkev2PadSharedKeyCB reply_callback;
  void *reply_callback_context;
} *SshPmEapAuthorizationContext, SshPmEapAuthorizationContextStruct;

static void
pm_ike_eap_authorization_cb(SshUInt32 *group_ids,
                            SshUInt32 num_group_ids,
                            void *context)
{
  SshPmEapAuthorizationContext ctx = context;

  if (!ctx->qm || ctx->qm->error != SSH_IKEV2_ERROR_OK ||
      ctx->p1 == NULL || ctx->qm->rule == NULL)
    goto fail;

  /* Copy authorization group ids to p1 */
  if (ctx->p1->authorization_group_ids)
    ssh_free(ctx->p1->authorization_group_ids);
  ctx->p1->authorization_group_ids = NULL;
  if (num_group_ids > 0)
    ctx->p1->authorization_group_ids = ssh_memdup(group_ids,
                                                  sizeof(group_ids[0])
                                                  * num_group_ids);
  ctx->p1->num_authorization_group_ids = num_group_ids;

  /* Check authorization */
  if (ssh_pm_check_rule_authorization(ctx->p1, ctx->qm->rule))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, ("Returning EAP KEY"),
                        ctx->buf, ctx->buf_len);
      (*ctx->reply_callback)(SSH_IKEV2_ERROR_OK,
                             ctx->buf, ctx->buf_len,
                             ctx->reply_callback_context);
      return;
    }
  if (ctx->p1->n)
    ctx->p1->n->failure_mask |= SSH_PM_E_ACCESS_GROUP_MISMATCH;

 fail:
  SSH_DEBUG(SSH_D_FAIL,
            ("Authorization failed; access groups did not match"));
  (*ctx->reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                         NULL, 0,
                         ctx->reply_callback_context);
}

SshOperationHandle
ssh_pm_ike_eap_key(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2PadSharedKeyCB reply_callback,
                   void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  unsigned char *buf = NULL;
  size_t buf_len = 0;
  SshUInt32 i = 0;
  Boolean method_matched = FALSE;
  SshPmEapState eap;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* If PM is not active, reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("PM is not active, request rejected."));
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  if (!SSH_PM_P1_USABLE(p1))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("IKE SA %p unusable.", p1->ike_sa));
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  if (p1->n == NULL || (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Negotiation context has vanished. Server going down."));
      (*reply_callback)(SSH_IKEV2_ERROR_GOING_DOWN, NULL, 0,
                        reply_callback_context);
      return NULL;
    }
  /* Record the EAP authentication method, use the magic value of 0x1000
     plus the EAP type, see ipsec_pm_low.h */
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (ed->ike_ed->first_auth_done)
    {
      eap = p1->n->second_eap;
      if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
          p1->second_local_auth_method =
            pm_eap_type_to_auth_method(eap->eap_type);
      else
          p1->second_remote_auth_method =
            pm_eap_type_to_auth_method(eap->eap_type);
    }
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    {
      eap = p1->n->eap;
      if (p1->eap_only_auth)
        {
          p1->local_auth_method = pm_eap_type_to_auth_method(eap->eap_type);
          p1->remote_auth_method = pm_eap_type_to_auth_method(eap->eap_type);
        }
      else if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        p1->local_auth_method = pm_eap_type_to_auth_method(eap->eap_type);
      else
        p1->remote_auth_method = pm_eap_type_to_auth_method(eap->eap_type);
    }

  if (p1->eap_only_auth &&
      !ssh_eap_method_supports_mutual_auth(eap->eap_type))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Eap type used is not allowed for mutual auth"));
      (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                        NULL,
                        0,
                        reply_callback_context);
      return NULL;
    }

  for (i = 0; i < p1->auth_domain->num_eap_protocols; i++)
    {
      if (p1->auth_domain->eap_protocols[i].eap_type == eap->eap_type)
        {
          method_matched = TRUE;
          break;
        }
    }

  if (method_matched == FALSE)
    {
      /* This method was not allowed by configuration. We must reject this
         now. */
      (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                        NULL,
                        0,
                        reply_callback_context);
      return NULL;
    }

  ssh_eap_master_session_key(eap->eap, &buf, &buf_len, NULL, NULL);

  if (buf == NULL)
    {
      if (p1->eap_only_auth)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Selected EAP method does not return a shared key, "
                     "failing negotiation"));
          (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                            NULL,
                            0,
                            reply_callback_context);
          return NULL;
        }

      else if (eap->client)
        SSH_DEBUG(SSH_D_HIGHSTART, ("This EAP method does not "
                                    "return a key"));

      else
        SSH_DEBUG(SSH_D_HIGHSTART, ("This EAP method does not return a key "
                                    "or this EAP method was not allowed"
                                    " in configuration."));
    }

  /* Redo access group authorization */
  if (sad_handle->pm->authorization_callback)
    {
      SshPmEapAuthorizationContextStruct ctx;

      SSH_DEBUG(SSH_D_LOWSTART, ("Rechecking authorization groups"));

      ctx.buf = buf;
      ctx.buf_len = buf_len;
      ctx.p1 = p1;
      ctx.qm = ed->application_context;
      if (ctx.qm)
        SSH_PM_ASSERT_QM(ctx.qm);
      ctx.reply_callback = reply_callback;
      ctx.reply_callback_context = reply_callback_context;

      (*sad_handle->pm->authorization_callback)
        (&p1->authentication_data,
         pm_ike_eap_authorization_cb,
         &ctx,
         sad_handle->pm->authorization_callback_context);
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, ("Returning EAP KEY"), buf, buf_len);

      (*reply_callback)(SSH_IKEV2_ERROR_OK,
                        buf,
                        buf_len,
                        reply_callback_context);
    }
  if (buf)
    ssh_free(buf);
  return NULL;
}

/***************   Initialization of Policy Manager EAP state **************/


Boolean ssh_pm_eap_init(SshPmAuthDomain ad)
{
  SshEapConfiguration config;

  config = ssh_eap_config_create();
  if (config == NULL)
    return FALSE;

  config->auth_timeout_sec = 120;
  config->re_auth_delay_sec = 0;
  config->retransmit_delay_sec = 0;
  config->num_retransmit = 0;
#ifdef SSHDIST_RADIUS
  config->radius_buffer_identity = TRUE;
#endif /* SSHDIST_RADIUS */
  config->signal_cb = pm_eap_signal_cb;

  ad->eap_config = config;
  return TRUE;
}

void ssh_pm_eap_uninit(SshPmAuthDomain ad)
{
  if (ad->eap_config)
    {
      ssh_eap_config_destroy(ad->eap_config);
      ad->eap_config = NULL;
    }
}
#endif /* SSHDIST_IKE_EAP_AUTH */
