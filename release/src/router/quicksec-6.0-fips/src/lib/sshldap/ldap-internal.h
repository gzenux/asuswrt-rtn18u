/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions and data types.
*/

#ifndef SSHLDAP_INTERNAL_H
#define SSHLDAP_INTERNAL_H

#include "sshasn1.h"
#include "sshadt.h"
#include "sshbuffer.h"
#include "sshtcp.h"
#include "sshoperation.h"
#include "sshstream.h"

#define MAKEINFO(info, value)                           \
do {                                                    \
  (info)->error_message = (unsigned char *)value;       \
  (info)->error_message_len = strlen((char *)value);    \
} while (0)

#define START(client, which, cb, cb_ctx, info, op, asn1) do {           \
  if ((op = ssh_ldap_new_operation((client), (which), (cb), (cb_ctx)))  \
      == NULL)                                                          \
    {                                                                   \
      MAKEINFO(&(info), "Can't start operation, client is busy.");      \
      (*(cb))((client), SSH_LDAP_RESULT_INTERNAL, &(info), (cb_ctx));   \
      return NULL;                                                      \
    }                                                                   \
                                                                        \
  if (((asn1) = ssh_asn1_init()) == NULL)                               \
    {                                                                   \
      MAKEINFO(&(info), "Can't start operation, not enough memory.");   \
      ssh_ldap_result((client), (op), SSH_LDAP_RESULT_INTERNAL, &(info)); \
      return NULL;                                                      \
    }                                                                   \
} while (0)

typedef unsigned long SshLdapMessageID;

typedef enum {
  SSH_LDAP_OPERATION_CONNECT                    = -1,
  SSH_LDAP_OPERATION_BIND_REQUEST               = 0,
  SSH_LDAP_OPERATION_BIND_RESPONSE              = 1,
  SSH_LDAP_OPERATION_UNBIND_REQUEST             = 2,
  SSH_LDAP_OPERATION_SEARCH_REQUEST             = 3,
  SSH_LDAP_OPERATION_SEARCH_RESPONSE            = 4,
  SSH_LDAP_OPERATION_SEARCH_RESULT              = 5,
  SSH_LDAP_OPERATION_MODIFY_REQUEST             = 6,
  SSH_LDAP_OPERATION_MODIFY_RESPONSE            = 7,
  SSH_LDAP_OPERATION_ADD_REQUEST                = 8,
  SSH_LDAP_OPERATION_ADD_RESPONSE               = 9,
  SSH_LDAP_OPERATION_DELETE_REQUEST             = 10,
  SSH_LDAP_OPERATION_DELETE_RESPONSE            = 11,
  SSH_LDAP_OPERATION_MODIFY_RDN_REQUEST         = 12,
  SSH_LDAP_OPERATION_MODIFY_RDN_RESPONSE        = 13,
  SSH_LDAP_OPERATION_COMPARE_REQUEST            = 14,
  SSH_LDAP_OPERATION_COMPARE_RESPONSE           = 15,
  SSH_LDAP_OPERATION_ABANDON                    = 16,
  SSH_LDAP_OPERATION_EXTENSION_REQUEST          = 23,
  SSH_LDAP_OPERATION_EXTENSION_RESPONSE         = 24
} SshLdapOperation;

/* Filter operations */
typedef enum {
  SSH_LDAP_FILTER_OPERATION_AND                         = 0,
  SSH_LDAP_FILTER_OPERATION_OR                          = 1,
  SSH_LDAP_FILTER_OPERATION_NOT                         = 2,
  SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH              = 3,
  SSH_LDAP_FILTER_OPERATION_SUBSTRINGS                  = 4,
  SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL            = 5,
  SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL               = 6,
  SSH_LDAP_FILTER_OPERATION_PRESENT                     = 7,
  SSH_LDAP_FILTER_OPERATION_APPROX_MATCH                = 8
} SshLdapFilterOperator;

struct SshLdapSearchFilterRec {
  SshLdapFilterOperator ldap_operator;
  union {
    /* AND and OR operations. */
    struct {
      int number_of_filters;    /* Number of filters */
      /* Filters to combine */
      struct SshLdapSearchFilterRec *table_of_filters;
    } set_of_filters;
#define filter_number_of_filters o.set_of_filters.number_of_filters
#define filter_table_of_filters o.set_of_filters.table_of_filters

    /* NOT operation */
    struct SshLdapSearchFilterRec *not_filter;
#define filter_not_filter o.not_filter

    /* EQUALITY_MATCH, GREATER_OR_EQUAL, LESS_OR_EQUAL, or APPROX_MATCH
       operations. */
    struct SshLdapAttributeValueAssertionRec attribute_value_assertion;
#define filter_attribute_value_assertion o.attribute_value_assertion

    /* PRESENT operation. */
    struct {
      char *attribute_type;
      size_t attribute_type_len;
    } attribute_type;
#define filter_attribute_type o.attribute_type

    /* Substring operation */
    struct {
      char *attribute_type;
      size_t attribute_type_len;
      char *initial;
      size_t initial_len;
      int number_of_any_parts;
      char **any_table;
      size_t *any_table_lens;
      char *final;
      size_t final_len;
    } substring;
#define filter_substring o.substring
  } o;
};

/* LDAP operation context */
typedef struct SshLdapClientOperationRec {
  SshADTHeaderStruct header;

  /* Store operation handle so we can abort this when disconnecting.
     This is the operation handle allocated at the LDAP library. */
  SshOperationHandle operation;

  /* Operation handle for possible sub-operation of this
     operation. This is currently only used when 'type' is connect,
     This is the TCP connect handle in the case. */
  SshOperationHandle suboperation;

  /* Message ID. Used when matching the result, or abandoning ongoing
     operations. */
  SshLdapMessageID id;

  /* Then identify operation type and callbacks. 'search_cb' is of
     course valid only if type identifies a search operation, and
     'connect_cb' for connect. */
  SshLdapOperation type;

  SshLdapClientResultCB result_cb;
  void *result_cb_context;
  SshLdapSearchResultCB search_cb;
  void *search_cb_context;
  SshLdapConnectCB connect_cb;
  void *connect_cb_context;

  SshLdapClient client;

} *SshLdapClientOperation, SshLdapClientOperationStruct;


typedef enum {
  SSH_LDAP_CLIENT_STATUS_DISCONNECTED,
  SSH_LDAP_CLIENT_STATUS_CONNECTING,
  SSH_LDAP_CLIENT_STATUS_CONNECTED
} SshLdapClientStatus;

/* LDAP client context */
struct SshLdapClientRec {
  SshLdapVersion version;

  /* Connect information from parameters. */
  int connection_attempts;
  unsigned char *socks;

  /* Where we are currently connected (or trying to connect). */
  unsigned char *current_server_name;
  unsigned char *current_server_port;
  SshLdapClientStatus status;

  /* TLS wrapping. */
  SshLdapClientWrapCB stream_wrap;
  void *stream_wrap_context;

  /* Input and output buffer & stream to fill & flush them. */
  SshStream ldap_stream;
  SshBuffer out_buffer;
  SshBuffer in_buffer;

  /* Operations cache. We keep a freelist of allocated LDAP
     operations.  In addition we store all the ongoing operations into
     bag indexed by pointer to the operation context. The number of
     elements in these bags (cached at 'numoperations' will be lesser
     than 'maxoperations'. */
  SshADTContainer freelist;
  SshADTContainer operations;
  size_t maxoperations;
  size_t numoperations;

  int size_limit, time_limit;
  int input_byte_limit;

  SshUInt32 tcp_connect_timeout;
  /* Monotonically increasing message id. */
  SshLdapMessageID current_id;
};

#define SSH_LDAP_DEFAULT_SERVER_NAME            "ldap"
#define SSH_LDAP_DEFAULT_SERVER_PORT            "389"
#define SSH_LDAP_READ_BUFFER_LEN                512


SshLdapClientOperation
ssh_ldap_new_operation(SshLdapClient client,
                       SshLdapOperation type,
                       SshLdapClientResultCB callback, void *callback_context);

SshLdapResult ssh_ldap_send_operation(SshLdapClient client,
                                      SshAsn1Context asn1context,
                                      SshAsn1Tree message);

SshLdapClientOperation
ssh_ldap_get_operation(SshLdapClient client, SshLdapMessageID id);

void
ssh_ldap_free_operation(SshLdapClient client, SshLdapClientOperation op);

void
ssh_ldap_result(SshLdapClient client,
                SshLdapClientOperation op,
                SshLdapResult result,
                SshLdapResultInfo info);

void ssh_ldap_abort_all_operations(SshLdapClient client);
void ssh_ldap_stream_callback(SshStreamNotification notification,
                              void *context);

void ssh_ldap_process_search_response(SshLdapClient client,
                                      SshAsn1Context asn1context,
                                      SshAsn1Node result,
                                      SshLdapClientOperation operation);

SshAsn1Node ssh_ldap_create_filter(SshAsn1Context asn1_ctx,
                                   SshLdapSearchFilter filter);

#endif /* SSHLDAP_INTERNAL_H */
