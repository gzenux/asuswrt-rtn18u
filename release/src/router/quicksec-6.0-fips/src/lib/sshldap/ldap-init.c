/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAP client create routines.
*/

#include "sshincludes.h"
#include "sshadt_list.h"
#include "sshadt_map.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapInit"

static void ldap_abort_operation(void *context)
{
  SshLdapClientOperation op = context;
  SshLdapClient client = op->client;
  SshADTHandle handle;

  op->operation = NULL;

  op->result_cb = NULL_FNPTR;
  op->connect_cb = NULL_FNPTR;
  op->search_cb = NULL_FNPTR;

  if (op->suboperation)
    {
      ssh_operation_abort(op->suboperation);
      op->suboperation = NULL;
    }

  /* Return the operation to freelist. */
  handle = ssh_adt_get_handle_to(client->operations, op);
  if (handle != SSH_ADT_INVALID)
    {
      ssh_adt_detach(client->operations, handle);
      memset(op, '\0', sizeof(*op));
      ssh_adt_insert(client->freelist, op);
    }

  client->numoperations -= 1;
}

/* Allocate a new operation to be performed by client. This function
   will return a non-NULL pointer in success, or NULL, if number of
   operations allocated so far exceeds configuration limit, or if
   there is no space available to perform the operation. As a side
   effect the new operation will be inserted into operations hash for
   the client. */
SshLdapClientOperation
ssh_ldap_new_operation(SshLdapClient client,
                       SshLdapOperation type,
                       SshLdapClientResultCB callback, void *callback_context)
{
  SshLdapClientOperation op = NULL;
  SshADTHandle h;

  h = ssh_adt_enumerate_start(client->freelist);
  if (h != SSH_ADT_INVALID)
    {
      op = ssh_adt_detach(client->freelist, h);
    }
  else
    {
      if (client->numoperations < client->maxoperations)
        op = ssh_malloc(sizeof(struct SshLdapClientOperationRec));

      if (op == NULL)
        return NULL;
    }

  memset(op, '\0', sizeof(*op));

  client->numoperations += 1;
  op->id = client->current_id++;

  op->operation = ssh_operation_register(ldap_abort_operation, op);
  if (op->operation == NULL)
    {
      ssh_free(op);
      return NULL;
    }

  op->type = type;
  op->result_cb = callback;
  op->result_cb_context = callback_context;
  op->client = client;

  /* This should always succeed, as allocation method for the operations
     is preallocated and we already have the space... */
  if (ssh_adt_insert(client->operations, op) == SSH_ADT_INVALID)
    SSH_NOTREACHED;

  return op;
}

/* Get operation by LDAP message ID. */
SshLdapClientOperation
ssh_ldap_get_operation(SshLdapClient client, SshLdapMessageID id)
{
  struct SshLdapClientOperationRec optemp, *op = NULL;
  SshADTHandle handle;

  optemp.id = id;

  handle = ssh_adt_get_handle_to_equal(client->operations, &optemp);
  if (handle != SSH_ADT_INVALID)
    op = ssh_adt_get(client->operations, handle);

  return op;
}

/* Release operation. Move it from the operations to freelist. */
void
ssh_ldap_free_operation(SshLdapClient client, SshLdapClientOperation op)
{
  SshADTHandle handle;

  handle = ssh_adt_get_handle_to(client->operations, op);
  if (handle != SSH_ADT_INVALID)
    {
      if (op->operation)
        {
          ssh_operation_unregister(op->operation);
          op->operation = NULL;
        }

      ssh_adt_detach(client->operations, handle);
      memset(op, '\0', sizeof(*op));
      ssh_adt_insert(client->freelist, op);
    }
  client->numoperations -= 1;
}

Boolean
ssh_ldap_client_abandon(SshLdapClient client, SshLdapClientOperation op)
{
  Boolean ok = FALSE;

  /* Send abandon message if we are connected */
  if (client->status == SSH_LDAP_CLIENT_STATUS_CONNECTED)
    {
      SshAsn1Context asn1context;
      SshAsn1Status status;
      SshAsn1Tree message;
      SshLdapResult lresult;

      asn1context = ssh_asn1_init();
      if (asn1context != NULL)
        {
          status = ssh_asn1_create_tree(asn1context, &message,
                                        "(sequence ()"
                                        " (integer-short ())"
                                        " (integer-short (a 16)))",
                                        op->id, client->current_id++);
          if (status == SSH_ASN1_STATUS_OK)
            {
              ok = TRUE;

              lresult = ssh_ldap_send_operation(client, asn1context, message);
              if (lresult != SSH_LDAP_RESULT_SUCCESS)
                ok = FALSE;
            }
          ssh_asn1_free(asn1context);
        }
    }
  return ok;
}

/* Abort all operations */
void ssh_ldap_abort_all_operations(SshLdapClient client)

{
  SshLdapClientOperation op;
  SshADTHandle handle;
  SshLdapResultInfoStruct info;

  memset(&info, 0, sizeof(info));
  MAKEINFO(&info, "Operation was aborted by the user.");

  handle = ssh_adt_enumerate_start(client->operations);

  while (handle != SSH_ADT_INVALID)
    {
      op = ssh_adt_get(client->operations, handle);
      ssh_ldap_client_abandon(client, op);

      if (op->connect_cb)
        {
          if (op->suboperation)
            {
              ssh_operation_abort(op->suboperation);
              op->suboperation = NULL;
            }
          (*op->connect_cb)(op->client, SSH_TCP_FAILURE,
                            op->connect_cb_context);
        }

      if (op->result_cb)
        (*op->result_cb)(op->client, SSH_LDAP_RESULT_ABORTED,
                         &info,
                         op->result_cb_context);
      handle = ssh_adt_enumerate_next(client->operations, handle);
    }

  do {
    handle = ssh_adt_enumerate_start(client->operations);
    if (handle != SSH_ADT_INVALID)
      {
        op = ssh_adt_get(client->operations, handle);
        ssh_ldap_free_operation(client, op);
      }
    else
      break;
  } while (TRUE);
}

/* Mapping between error codes and error strings. */
const SshKeywordStruct ssh_ldap_error_keywords[] = {
  { "OK",
    SSH_LDAP_RESULT_SUCCESS },

  { "LDAP-OPERATIONS-ERROR",
    SSH_LDAP_RESULT_OPERATIONS_ERROR },
  { "LDAP-PROTOCOL-ERROR",
    SSH_LDAP_RESULT_PROTOCOL_ERROR },
  { "OPERATION-TIME-LIMIT-EXCEEDED",
    SSH_LDAP_RESULT_TIME_LIMIT_EXCEEDED },
  { "OPERATION-SIZE-LIMIT-EXCEEDED",
    SSH_LDAP_RESULT_SIZE_LIMIT_EXCEEDED },
  { "OPERATION-COMPARE-FALSE",
    SSH_LDAP_RESULT_COMPARE_FALSE },
  { "OPERATION-COMPARE-TRUE",
    SSH_LDAP_RESULT_COMPARE_TRUE },
  { "LDAP-AUTH-METHOD-UNSUPPORTED",
    SSH_LDAP_RESULT_AUTH_METHOD_NOT_SUPPORTED },
  { "LDAP-AUTH-REQUIRE-STRONG",
    SSH_LDAP_RESULT_STRONG_AUTH_REQUIRED },

  /* Only at LDAPv3. */
  { "OPERATION-REFERRAL",
    SSH_LDAP_RESULT_REFERRAL },
  { "OPERATION-ADMIN-LIMIT-EXCEEDED",
    SSH_LDAP_RESULT_ADMINLIMITEXCEEDED },
  { "OPERATION-CRITICAL-EXTENSION-UNAVAILABLE",
    SSH_LDAP_RESULT_UNAVAILABLECRITICALEXTENSION },
  { "LDAP-INAPPROPRIATE-CONFIDENTIALITY",
    SSH_LDAP_RESULT_CONFIDENTIALITYREQUIRED },
  { "LDAP-SASL-IN-PROGRESS",
    SSH_LDAP_RESULT_SASLBINDINPROGRESS },

  { "OPERATION-NO-SUCH-ATTRIBUTE",
    SSH_LDAP_RESULT_NO_SUCH_ATTRIBUTE },
  { "OPERATION-UNDEFINED-ATTRIBUTE-TYPE",
    SSH_LDAP_RESULT_UNDEFINED_ATTRIBUTE_TYPE },
  { "OPERATION-INAPPROPRIATE-MATCHING",
    SSH_LDAP_RESULT_INAPPROPRIATE_MATCHING },
  { "OPERATION-CONSTRAINT-VIOLATION",
    SSH_LDAP_RESULT_CONSTRAINT_VIOLATION },
  { "OPERATION-AVA-ALREADY-EXISTS",
    SSH_LDAP_RESULT_ATTRIBUTE_OR_VALUE_EXISTS },
  { "OPERATION-INVALID-ATTRIBUTE-SYNTAX",
    SSH_LDAP_RESULT_INVALID_ATTRIBUTE_SYNTAX },

  { "OPERATION-OBJECT-NOT-FOUND",
    SSH_LDAP_RESULT_NO_SUCH_OBJECT },
  { "OPERATION-ALIAS-PROBLEM",
    SSH_LDAP_RESULT_ALIAS_PROBLEM },
  { "LDAP-INVALID-DN-SYNTAX",
    SSH_LDAP_RESULT_INVALID_DN_SYNTAX },
  { "OPERATION-RESULT-IS-LEAF",
    SSH_LDAP_RESULT_IS_LEAF },
  { "OPEARTION-ALIAS-DEREFERENCING-PROBLEM",
    SSH_LDAP_RESULT_ALIAS_DEREFERENCING_PROBLEM },

  { "LDAP-INAPPROPRIATE-AUTHENTICATION",
    SSH_LDAP_RESULT_INAPPROPRIATE_AUTHENTICATION },
  { "LDAP-INVALID-CREDENTIALS",
    SSH_LDAP_RESULT_INVALID_CREDENTIALS },
  { "OPERATION-INSUFFICIENT-ACCESS-RIGHTS",
    SSH_LDAP_RESULT_INSUFFICIENT_ACCESS_RIGHTS },
  { "LDAP-SERVER-BUSY",
    SSH_LDAP_RESULT_BUSY },
  { "LDAP-SERVER-UNAVAILABLE",
    SSH_LDAP_RESULT_UNAVAILABLE },
  { "LDAP-SERVER-UNWILLING-TO-PERFORM",
    SSH_LDAP_RESULT_UNWILLING_TO_PERFORM },
  { "LDAP-LOOP-DETECT",
    SSH_LDAP_RESULT_LOOP_DETECT },

  { "OPERATION-NAMING-VIOLATION",
    SSH_LDAP_RESULT_NAMING_VIOLATION },
  { "OPERATION-OBJECTCLASS-VIOLATION",
    SSH_LDAP_RESULT_OBJECT_CLASS_VIOLATION },
  { "OPERATION-NOT-ALLOWED-ON-NON-LEAF",
    SSH_LDAP_RESULT_NOT_ALLOWED_ON_NON_LEAF },
  { "OPERATION-NOT-ALLOWED-ON-RDN",
    SSH_LDAP_RESULT_NOT_ALLOWED_ON_RDN },
  { "OPERATION-ENTRY-ALREADY-EXISTS",
    SSH_LDAP_RESULT_ENTRY_ALREADY_EXISTS },
  { "OPERATION-OBJECTCLASS-MODS-PROHIBITED",
    SSH_LDAP_RESULT_OBJECT_CLASS_MODS_PROHIBITED },

  { "OPERATION-AFFECTS-MULTIPLE-DSAS",
    SSH_LDAP_RESULT_AFFECTSMULTIPLEDSAS },

  { "LDAP-OTHER-RESULT",
    SSH_LDAP_RESULT_OTHER },

  { "LDAP-ABORTED",
    SSH_LDAP_RESULT_ABORTED },
  { "LDAP-IN-PROGRESS",
    SSH_LDAP_RESULT_IN_PROGRESS },
  { "LDAP-INTERNAL-ERROR",
    SSH_LDAP_RESULT_INTERNAL },
  { "LDAP-SERVER-DISCONNECTED",
    SSH_LDAP_RESULT_DISCONNECTED },
  { NULL, 0 }
};


/* Convert error code to string. */
const char *ssh_ldap_error_code_to_string(SshLdapResult code)
{
  const char *str;

  str = ssh_find_keyword_name(ssh_ldap_error_keywords, code);
  if (str == NULL)
    str = "LDAP-INVALID-ERROR-CODE";

  return str;
}

static int
ldap_client_opid_compare(const void *ptr1, const void *ptr2, void *context)
{
  const struct SshLdapClientOperationRec *op1 = ptr1, *op2 = ptr2;

  if (op1->id == op2->id)
    return 0;
  return -1;
}

static int ldap_client_opid_hash(const void *ptr, void *context)
{
  const struct SshLdapClientOperationRec *op = ptr;
  return op->id;
}

static void ldap_client_opid_destroy(void *ptr, void *context)
{
  ssh_free(ptr);
}

SshLdapClient ssh_ldap_client_create(const SshLdapClientParams params)
{
  SshLdapClient client;


  client = ssh_calloc(1, sizeof(*client));
  if (client != NULL)
    {
      client->current_id = 1;
      client->version = params ? params->version : SSH_LDAP_VERSION_2;
      if (client->version == 0)
        client->version = SSH_LDAP_VERSION_2;

      if (params && params->maxoperations)
        client->maxoperations = params->maxoperations;
      else
        client->maxoperations = 5;
      if (params && params->connection_attempts)
        client->connection_attempts = params->connection_attempts;
      else
        client->connection_attempts = 1;

      if (params && params->response_sizelimit)
        client->size_limit = params->response_sizelimit;

      if (params && params->request_timelimit)
        client->time_limit = params->request_timelimit;

      if (params && params->response_bytelimit)
        client->input_byte_limit = params->response_bytelimit;

      if (params && params->socks)
        if ((client->socks = ssh_strdup(params->socks)) == NULL)
          {
            ssh_free(client);
            return NULL;
          }

      if (params && params->stream_wrap)
        {
          client->stream_wrap = params->stream_wrap;
          client->stream_wrap_context = params->stream_wrap_context;
        }

      if (params)
        client->tcp_connect_timeout = params->tcp_connect_timeout;

      SSH_DEBUG(SSH_D_HIGHSTART,
                ("create(%p) v=%d, socks=%s",
                 client, client->version, client->socks));

      client->operations =
        ssh_adt_create_generic(SSH_ADT_MAP,
                               SSH_ADT_HEADER,
                               SSH_ADT_OFFSET_OF(SshLdapClientOperationStruct,
                                                 header),
                               SSH_ADT_HASH, ldap_client_opid_hash,
                               SSH_ADT_COMPARE, ldap_client_opid_compare,
                               SSH_ADT_ARGS_END);
      client->freelist =
        ssh_adt_create_generic(SSH_ADT_LIST,
                               SSH_ADT_DESTROY, ldap_client_opid_destroy,
                               SSH_ADT_HEADER,
                               SSH_ADT_OFFSET_OF(SshLdapClientOperationStruct,
                                                 header),
                               SSH_ADT_ARGS_END);

      client->out_buffer = ssh_buffer_allocate();
      client->in_buffer = ssh_buffer_allocate();

      if (client->in_buffer == NULL
          || client->out_buffer == NULL
          || client->operations == NULL
          || client->freelist == NULL)
        {
          ssh_ldap_client_destroy(client);
          client = NULL;
        }
    }

  return client;
}

/* Destroy LDAP client context */
void ssh_ldap_client_destroy(SshLdapClient client)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("destroy(%p) v=%d", client, client->version));

  SSH_ASSERT(client != NULL);

  ssh_ldap_client_disconnect(client);

  if (client->socks)
    ssh_free(client->socks);
  if (client->out_buffer)
    ssh_buffer_free(client->out_buffer);
  if (client->in_buffer)
    ssh_buffer_free(client->in_buffer);

  if (client->freelist)
    ssh_adt_destroy(client->freelist);
  if (client->operations)
    ssh_adt_destroy(client->operations);
  ssh_free(client);
}
#endif /* SSHDIST_LDAP */
