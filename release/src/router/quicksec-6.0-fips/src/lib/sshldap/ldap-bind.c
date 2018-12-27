/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Perform LDAP bind operation.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapBind"

/* Do LDAP bind. This is also done automatically, but here you can change the
   bind_name and password later. */

SshOperationHandle
ssh_ldap_client_bind(SshLdapClient client,
                     const unsigned char *bind_name,
                     size_t bind_name_len,
                     const unsigned char *password,
                     size_t password_len,
                     SshLdapClientResultCB callback,
                     void *callback_context)
{
  return ssh_ldap_client_bind_sasl(client, NULL, /* simple authentication */
                                   bind_name, bind_name_len,
                                   password, password_len,
                                   callback, callback_context);
}

/* Do LDAP bind authenticating with SASL. */
SshOperationHandle
ssh_ldap_client_bind_sasl(SshLdapClient client,
                          const char *sasl_mechanism,
                          const unsigned char *bind_name,
                          size_t bind_name_len,
                          const unsigned char *credentials,
                          size_t credentials_len,
                          SshLdapClientResultCB callback,
                          void *callback_context)
{
  SshLdapClientOperation op;
  SshAsn1Context asn1context;
  SshAsn1Node authnode = NULL;
  SshAsn1Status status;
  SshAsn1Tree message;
  SshLdapResultInfoStruct info;
  SshLdapResult lresult;

  memset(&info, 0, sizeof(info));

  if (bind_name == NULL)
    {
      bind_name = (unsigned char *)"";
      bind_name_len = 0;
    }
  if (credentials == NULL)
    {
      credentials = (unsigned char *)"";
      credentials_len = 0;
    }

#ifdef DEBUG_LIGHT
  {
    SSH_DEBUG_HEXDUMP(6, ("Bind name %s, mechanism %s, credentials: ",
                          bind_name,
                          sasl_mechanism ? sasl_mechanism : "simple"),
                          credentials, credentials_len);
  }
#endif

  START(client,
        SSH_LDAP_OPERATION_BIND_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  if (!sasl_mechanism)
    {
      status = ssh_asn1_create_node(asn1context, &authnode,
                                    "(octet-string (c 0))", /* Simple */
                                    credentials, credentials_len);
    }
  else
    {
      if (credentials_len > 0) /* credentials are optional */
        status = ssh_asn1_create_node(asn1context, &authnode,
                                      "(sequence (c 3)"    /* SASL */
                                      " (octet-string ())" /* Mechanism */
                                      " (octet-string ())" /* Credentials */
                                      ")",
                                      sasl_mechanism, strlen(sasl_mechanism),
                                      credentials, credentials_len);
      else
        status = ssh_asn1_create_node(asn1context, &authnode,
                                      "(sequence (c 3)"      /* SASL */
                                      " (octet-string ())"   /* Mechanism */
                                      ")",
                                      sasl_mechanism, strlen(sasl_mechanism));
    }

  if (status == SSH_ASN1_STATUS_OK)
    status = ssh_asn1_create_tree(asn1context, &message,
                                  "(sequence ()"
                                  " (integer-short ())"  /* Message id */
                                  " (sequence (a 0)"     /* Bind */
                                  "  (integer-short ())" /* Version number */
                                  "  (octet-string ())"  /* Name */
                                  "  (any ())"           /* Authentication */
                                  "))",
                                  (SshWord) op->id,
                                  (SshWord) client->version,
                                  bind_name, bind_name_len,
                                  authnode);

  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Can't start bind operation; encode failed.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return 0;
    }

  /* Send bind request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      MAKEINFO(&info, "Can't send bind request.");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}


/* Do LDAP unbind. This is also done automatically before disconnect,
   and after this only disconnect operation is allowed. */
void ssh_ldap_client_unbind(SshLdapClient client)
{
  SshAsn1Context asn1context;
  SshAsn1Status status;
  SshAsn1Tree message;
  SshLdapResult lresult;

  SSH_DEBUG(SSH_D_HIGHSTART, ("unbind(%p)", client));

  if ((asn1context = ssh_asn1_init()) == NULL)
    return;

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (null (a 16)))", /* unbind */
                                (SshWord) client->current_id++);
  if (status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_asn1_create_tree failed, status = %s",
                 ssh_asn1_error_string(status)));
    }
  else
    {
      /* Send abandon request */
      lresult = ssh_ldap_send_operation(client, asn1context, message);
      if (lresult != SSH_LDAP_RESULT_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("ssh_ldap_send_operation failed, status = %s",
                     ssh_asn1_error_string(status)));
        }
    }

  ssh_asn1_free(asn1context);
}
#endif /* SSHDIST_LDAP */
