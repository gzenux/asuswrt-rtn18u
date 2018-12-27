/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAPv3 extension mechanisms.
*/

#include "sshincludes.h"
#include "sshadt_list.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapExt"

SshOperationHandle
ssh_ldap_client_extension(SshLdapClient client,
                          const char *oid,
                          unsigned char *ext_data, size_t ext_data_len,
                          SshLdapClientResultCB callback,
                          void *callback_context)
{
  SshLdapClientOperation op;
  SshAsn1Context asn1context;
  SshAsn1Status status;
  SshAsn1Tree message;
  SshLdapResultInfoStruct info;
  SshLdapResult lresult;

  memset(&info, 0, sizeof(info));

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("extension(%p) oid=%s", client, oid));

  START(client, SSH_LDAP_OPERATION_EXTENSION_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  /* Compose extentedRequest */
  status = ext_data_len
    ?
    ssh_asn1_create_tree(asn1context, &message,
                         "(sequence ()"
                         "  (integer-short ())" /* Message id */
                         "  (sequence (a 23)"   /* ExtendedRequest */
                         "    (octet-string (c 0))"
                         "    (octet-string (c 1))))",
                         (SshWord) op->id,
                         oid, strlen(oid),
                         ext_data, ext_data_len)
    :
    ssh_asn1_create_tree(asn1context, &message,
                         "(sequence ()"
                         "  (integer-short ())" /* Message id */
                         "  (sequence (a 23)"   /* ExtendedRequest */
                         "    (octet-string (c 0))))",
                         (SshWord) op->id,
                         oid, strlen(oid));

  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Can't encode ASN.1 for sending extension request.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return 0;
    }

  /* Send bind request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      MAKEINFO(&info, "Can't send request.");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return 0;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}

#define LDAP_TLS_OID "1.3.6.1.4.1.1466.20037"

typedef struct SshLdapClientTlsStartRec
{
  SshLdapClientWrapCB callback;
  void *callback_context;
} *SshLdapClientTlsStart;

static void
ldap_client_enable_tls_result(SshLdapClient client,
                              SshLdapResult result,
                              const SshLdapResultInfo info,
                              void *callback_context)
{
  SshStream wrapped;
  SshLdapClientTlsStart context = callback_context;

  wrapped = (*context->callback)(client,
                                 result, info, client->ldap_stream,
                                 context->callback_context);
  if (wrapped)
    {
      client->ldap_stream = wrapped;
      ssh_stream_set_callback(client->ldap_stream,
                              ssh_ldap_stream_callback,
                              client);
    }
  ssh_free(context);
}

SshOperationHandle
ssh_ldap_client_enable_tls(SshLdapClient client,
                           SshLdapClientWrapCB callback,
                           void *callback_context)
{
  SshLdapResultInfoStruct info;
  SshLdapClientTlsStart context;

  if ((context = ssh_calloc(1, sizeof(*context))) != NULL)
    {
      context->callback = callback;
      context->callback_context = callback_context;

      return ssh_ldap_client_extension(client,
                                       LDAP_TLS_OID, NULL, 0,
                                       ldap_client_enable_tls_result,
                                       context);
    }

  memset(&info, 0, sizeof(info));
  MAKEINFO(&info, "Can't allocate space for the request.");
  (*callback)(client, SSH_LDAP_RESULT_INTERNAL, &info, NULL, callback_context);
  return NULL;
}
#endif /* SSHDIST_LDAP */
