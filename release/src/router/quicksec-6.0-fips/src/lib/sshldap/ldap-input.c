/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Receive responses from LDAP server, dispatch according to the
   type.
*/

#include "sshincludes.h"
#include "sshber.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapInput"

/* Send result from the operation to the caller */
void
ssh_ldap_result(SshLdapClient client,
                SshLdapClientOperation op,
                SshLdapResult result,
                SshLdapResultInfo info)
{
  SshLdapClientResultCB result_cb;
  void *result_cb_context;

  /* The result callback may disconnect and abort this operation. */
  result_cb = op->result_cb;
  result_cb_context = op->result_cb_context;

  ssh_ldap_free_operation(client, op);

  if (result_cb)
    (*result_cb)(client, result, info, result_cb_context);
}

/* Parse LDAPResult structure, and call callback */
void ssh_ldap_process_result(SshLdapClient client,
                             SshAsn1Context asn1context,
                             SshAsn1Node result,
                             SshLdapClientOperation operation)
{
  SshWord ldap_result;
  SshAsn1Status status;
  SshLdapResultInfoStruct info;
  SshAsn1Node sasl, refer;
  Boolean refer_found, sasl_found, extname_found, extdata_found;
  int i;

  memset(&info, 0, sizeof(info));

  status = ssh_asn1_read_node(asn1context, result,
                              "(enum-short ())"        /* ResultCode */
                              "(octet-string ())"      /* Matched DN */
                              "(octet-string ())"      /* error message */
                              "(optional (any (3)))"   /* Referral */
                              "(optional (any (7)))"   /* SASL */
                              "(optional (object-identifier (10)))"
                              "(optional (octet-string (11)))", /* Extrep */
                              &ldap_result,
                              &info.matched_dn, &info.matched_dn_len,
                              &info.error_message, &info.error_message_len,
                              &refer_found, &refer,
                              &sasl_found, &sasl,
                              &extname_found, &info.extension_name,
                              &extdata_found,
                                &info.extension_data,
                                &info.extension_data_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Can't decode result from LDAP server.");
      ssh_ldap_result(client, operation, SSH_LDAP_RESULT_INTERNAL, &info);
      return;
    }

  if (refer_found)
    {
      unsigned char *data;
      size_t len;
      SshAsn1Node list;

      for (list = refer; list; list = ssh_asn1_node_next(list))
        info.number_of_referrals++;

      if ((info.referrals =
           ssh_calloc(info.number_of_referrals, sizeof(char *))) != NULL)
        {
          for (i = 0, list = refer; list; i++, list = ssh_asn1_node_next(list))
            {
              if (ssh_asn1_read_node(asn1context, list,
                                     "(octet-string ())", &data, &len)
                  == SSH_ASN1_STATUS_OK)
                {
                  info.referrals[i] = (char *)data;
                }
            }
        }
      else
        info.number_of_referrals = 0;
    }

  ssh_ldap_result(client, operation, ldap_result, &info);

  /* Clear info now. */
  ssh_free(info.matched_dn);
  ssh_free(info.error_message);
  ssh_free(info.extension_name);
  ssh_free(info.extension_data);
  for (i = 0; i < info.number_of_referrals; i++)
    ssh_free(info.referrals[i]);
  ssh_free(info.referrals);
}

/* Process network input. returns number of messages processed. */
static size_t ssh_ldap_process_input(SshLdapClient client)
{
  size_t len, nmessages = 0;
  SshAsn1Context asn1context;
  SshAsn1Tree message;
  SshAsn1Status status;
  SshWord message_id;
  SshAsn1Node operation;
  unsigned int which;
  SshLdapClientOperation op;

  while (ssh_buffer_len(client->in_buffer) > 0)
    {
      len = ssh_ber_get_size(ssh_buffer_ptr(client->in_buffer),
                             ssh_buffer_len(client->in_buffer));
      /* Check if we have enough data */
      if (len == (size_t)-1 ||
          len == 0 ||
          len > ssh_buffer_len(client->in_buffer))
        return nmessages;

      /* Yes we do have enough data, parse one message */
      status = SSH_ASN1_STATUS_OPERATION_FAILED;
      if ((asn1context = ssh_asn1_init()) != NULL)
        {
          ssh_asn1_set_limits(asn1context, len, 0);
          status = ssh_asn1_decode(asn1context,
                                   ssh_buffer_ptr(client->in_buffer), len,
                                   &message);
        }

      ssh_buffer_consume(client->in_buffer, len);
      nmessages += 1;

      if (status != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Asn1 decode failed = %s, message skipped",
                     ssh_asn1_error_string(status)));
          ssh_asn1_free(asn1context);
          continue;
        }

      status =
        ssh_asn1_read_tree(asn1context, message,
                           "(sequence ()"
                           " (integer-short ())" /* Message id */
                           " (choice " /* Operation choice */
                           "  (sequence (a 0) (any ()))" /* Bind req */
                           "  (sequence (a 1) (any ()))" /* Bind rep */
                           "  (sequence (a 2) (any ()))" /* Unbind req */
                           "  (sequence (a 3) (any ()))" /* Search req */
                           "  (sequence (a 4) (any ()))" /* Search rep */
                           "  (sequence (a 5) (any ()))" /* Search result */
                           "  (sequence (a 6) (any ()))" /* Modify req */
                           "  (sequence (a 7) (any ()))" /* Modify rep */
                           "  (sequence (a 8) (any ()))" /* Add req */
                           "  (sequence (a 9) (any ()))" /* Add rep */
                           "  (sequence (a 10) (any ()))" /* Delete req */
                           "  (sequence (a 11) (any ()))" /* Delete rep */
                           "  (sequence (a 12) (any ()))" /* Modify RDN req */
                           "  (sequence (a 13) (any ()))" /* Modify RDN rep */
                           "  (sequence (a 14) (any ()))" /* Compare req */
                           "  (sequence (a 15) (any ()))" /* Compare rep */
                           "  (sequence (a 16) (any ()))" /* Abandon */
#define _SSH_LDAP_OPERATION_EXTENSION_REQUEST 17 /* See the switch() below */
                           "  (sequence (a 23) (any ()))" /* Extension req */
#define _SSH_LDAP_OPERATION_EXTENSION_RESPONSE 18
                           "  (sequence (a 24) (any ()))" /* Extension rep */
                           "  ))",
                           &message_id,
                           &which,
                           &operation, &operation, /* Bind */
                           &operation, /* Unbind */
                           &operation, &operation, &operation, /* Search */
                           &operation, &operation, /* Modify */
                           &operation, &operation, /* Add */
                           &operation, &operation, /* Delete */
                           &operation, &operation, /* Modify RDN */
                           &operation, &operation, /* Compare */
                           &operation, /* Abandon */
                           &operation, &operation /* Extension */);

      if (status != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Asn1 read tree failed = %s, message skipped",
                     ssh_asn1_error_string(status)));
          ssh_asn1_free(asn1context);
          continue;
        }
      if ((op = ssh_ldap_get_operation(client, message_id)) == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Message with unknown message id = %ld, message skipped",
                     message_id));
          ssh_asn1_free(asn1context);
          continue;
        }
      switch (which)
        {
        case SSH_LDAP_OPERATION_BIND_REQUEST:
        case SSH_LDAP_OPERATION_UNBIND_REQUEST:
        case SSH_LDAP_OPERATION_SEARCH_REQUEST:
        case SSH_LDAP_OPERATION_MODIFY_REQUEST:
        case SSH_LDAP_OPERATION_ADD_REQUEST:
        case SSH_LDAP_OPERATION_DELETE_REQUEST:
        case SSH_LDAP_OPERATION_MODIFY_RDN_REQUEST:
        case SSH_LDAP_OPERATION_COMPARE_REQUEST:
        case SSH_LDAP_OPERATION_ABANDON:
        case _SSH_LDAP_OPERATION_EXTENSION_REQUEST:
          SSH_DEBUG(SSH_D_FAIL,
                    ("Got server operation %d, message ignored", which));
          break;
        case SSH_LDAP_OPERATION_SEARCH_RESULT:
        case SSH_LDAP_OPERATION_MODIFY_RESPONSE:
        case SSH_LDAP_OPERATION_ADD_RESPONSE:
        case SSH_LDAP_OPERATION_DELETE_RESPONSE:
        case SSH_LDAP_OPERATION_MODIFY_RDN_RESPONSE:
        case SSH_LDAP_OPERATION_COMPARE_RESPONSE:
        case _SSH_LDAP_OPERATION_EXTENSION_RESPONSE:
          ssh_ldap_process_result(client, asn1context, operation, op);
          break;
        case SSH_LDAP_OPERATION_BIND_RESPONSE:
          ssh_ldap_process_result(client, asn1context, operation, op);
          ssh_ldap_stream_callback(SSH_STREAM_CAN_OUTPUT, client);
          break;
        case SSH_LDAP_OPERATION_SEARCH_RESPONSE:
          ssh_ldap_process_search_response(client,
                                           asn1context, operation, op);
        }
      ssh_asn1_free(asn1context);
    }
  return nmessages;
}

/* Ldap client stream notification callback */
void ssh_ldap_stream_callback(SshStreamNotification notification,
                              void *context)
{
  SshLdapClient client = (SshLdapClient) context;
  unsigned char *p;
  int l;

  if (client->ldap_stream == NULL)
    return;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      SSH_DEBUG(SSH_D_LOWOK, ("Input available"));
      while (1)
        {
          if ((ssh_buffer_append_space(client->in_buffer, &p,
                                       SSH_LDAP_READ_BUFFER_LEN))
              != SSH_BUFFER_OK)
            {
              ssh_ldap_client_disconnect(client);
              return;
            }

          if (client->ldap_stream)
            l = ssh_stream_read(client->ldap_stream,
                                p,
                                SSH_LDAP_READ_BUFFER_LEN);
          else
            l = 0;

          if (l < 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Read blocked"));
              ssh_buffer_consume_end(client->in_buffer,
                                     SSH_LDAP_READ_BUFFER_LEN);
              return;
            }

          if (l == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Eof received"));
              ssh_buffer_consume_end(client->in_buffer,
                                     SSH_LDAP_READ_BUFFER_LEN);
              if (ssh_buffer_len(client->in_buffer) != 0)
                (void) ssh_ldap_process_input(client);
              ssh_ldap_client_disconnect(client);
              return;
            }
          ssh_buffer_consume_end(client->in_buffer,
                                 SSH_LDAP_READ_BUFFER_LEN - l);

          /* We check the input size limit only after trying to
             decode, e.g. we may run SSH_LDAP_READ_BUFFER_LEN long
             from the limit. The responses from server may come in
             arbitrary order (if multiple requests sent), but one at a
             time. */
          (void) ssh_ldap_process_input(client);

          if (client->input_byte_limit > 0 &&
              ssh_buffer_len(client->in_buffer) > client->input_byte_limit)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Input limit %d bytes exceeded: read %zd bytes. "
                         "Discarding input and closing connection.",
                         client->input_byte_limit,
                         ssh_buffer_len(client->in_buffer)));
              ssh_ldap_client_disconnect(client);
              return;
            }

          SSH_DEBUG(SSH_D_MIDOK,
                    ("Read %d bytes, total size of input buffer %zd", l,
                     ssh_buffer_len(client->in_buffer)));

          ssh_ldap_process_input(client);
        }
      break;

    case SSH_STREAM_CAN_OUTPUT:
      if (ssh_buffer_len(client->out_buffer) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Can output, but nothing to send"));
          return;
        }

      while (ssh_buffer_len(client->out_buffer) != 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Can output, sending %zd bytes",
                     ssh_buffer_len(client->out_buffer)));
          l = ssh_stream_write(client->ldap_stream,
                               ssh_buffer_ptr(client->out_buffer),
                               ssh_buffer_len(client->out_buffer));
          if (l == 0)
            {
              ssh_ldap_client_disconnect(client);
              return;
            }
          if (l < 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Write blocked"));
              return;
            }
          ssh_buffer_consume(client->out_buffer, l);

        }
      SSH_DEBUG(SSH_D_MIDOK, ("All written"));
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_ldap_client_disconnect(client);
      break;
    }
}
#endif /* SSHDIST_LDAP */
