/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAP operations not needed on certificate path validation process,
   additions, modifications, deletions.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapModify"

/* Do LDAP modify. This automatically takes connection and bind if not done
   already (or if the connection has been broken). */
SshOperationHandle
ssh_ldap_client_modify(SshLdapClient client,
                       const unsigned char *object_name,
                       size_t object_name_len,
                       int number_of_operations,
                       SshLdapModifyOperation *operations,
                       SshLdapAttribute attributes,
                       SshLdapClientResultCB callback,
                       void *callback_context)
{
  SshLdapClientOperation op;
  SshAsn1Context asn1context;
  SshAsn1Status status;
  SshAsn1Tree message;
  SshAsn1Node attributes_asn1;
  int i, j;
  SshLdapResultInfoStruct info;
  SshLdapResult lresult;

  memset(&info, 0, sizeof(info));

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("modify(%p) base=%s", client, object_name));

  START(client,
        SSH_LDAP_OPERATION_MODIFY_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  attributes_asn1 = NULL;
  for (i = 0; i < number_of_operations; i++)
    {
      SshAsn1Node values_asn1, node;

      values_asn1 = NULL;
      for (j = 0; j < attributes[i].number_of_values; j++)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                                        "(octet-string ())", /* Value */
                                        attributes[i].values[j],
                                        attributes[i].value_lens[j]);
          if (status != SSH_ASN1_STATUS_OK)
            {
              MAKEINFO(&info, "Asn.1 create failed for operation.");
              ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
              ssh_asn1_free(asn1context);
              return NULL;
            }
          values_asn1 = ssh_asn1_add_list(values_asn1, node);
        }
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence ()"
                                    " (enum-short ())" /* Operation */
                                    " (sequence ()" /* modification */
                                    "  (octet-string ())" /* type */
                                    "  (set ()" /* Set of attribute values */
                                    "   (any ()))))", /* Attribute values */
                                    operations[i],
                                    attributes[i].attribute_type,
                                    attributes[i].attribute_type_len,
                                    values_asn1);

      if (status != SSH_ASN1_STATUS_OK)
        {
          MAKEINFO(&info, "Asn.1 create failed for operation.");
          ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
          ssh_asn1_free(asn1context);
          return NULL;
        }
      attributes_asn1 = ssh_asn1_add_list(attributes_asn1, node);
    }

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (sequence (a 6)" /* Modify */
                                "  (octet-string ())" /* Base Object */
                                "  (sequence ()"
                                "   (any ()))))", /* Modification */
                                (SshWord) op->id,
                                object_name, object_name_len,
                                attributes_asn1);
  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Send modify request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_ldap_send_operation failed, status = %s",
                 ssh_asn1_error_string(status)));
      MAKEINFO(&info, "Asn.1 encode for send failed.");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}


/* Do LDAP add. This automatically takes connection and bind if not done
   already (or if the connection has been broken). */
SshOperationHandle
ssh_ldap_client_add(SshLdapClient client,
                    const SshLdapObject object,
                    SshLdapClientResultCB callback,
                    void *callback_context)
{
  SshLdapClientOperation op;
  SshAsn1Context asn1context;
  SshAsn1Status status;
  SshAsn1Tree message;
  SshAsn1Node attributes_asn1;
  int i, j;
  SshLdapResultInfoStruct info;
  SshLdapResult lresult;

  memset(&info, 0, sizeof(info));

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("add(%p) object=%s", client, object->object_name));

  START(client,
        SSH_LDAP_OPERATION_ADD_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  attributes_asn1 = NULL;
  for (i = 0; i < object->number_of_attributes; i++)
    {
      SshAsn1Node values_asn1, node;

      values_asn1 = NULL;
      for (j = 0; j < object->attributes[i].number_of_values; j++)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                                        "(octet-string ())", /* Value */
                                        object->attributes[i].values[j],
                                        object->attributes[i].value_lens[j]);
          if (status != SSH_ASN1_STATUS_OK)
            {
              MAKEINFO(&info, "Asn.1 create failed for operation.");
              ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
              ssh_asn1_free(asn1context);
              return NULL;
            }
          values_asn1 = ssh_asn1_add_list(values_asn1, node);
        }
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence ()"
                                    " (octet-string ())" /* type */
                                    " (set ()" /* Set of attribute values */
                                    "  (any ())))", /* Attribute values */
                                    object->attributes[i].attribute_type,
                                    object->attributes[i].attribute_type_len,
                                    values_asn1);

      if (status != SSH_ASN1_STATUS_OK)
        {
          MAKEINFO(&info, "Asn.1 create failed for operation.");
          ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
          ssh_asn1_free(asn1context);
          return NULL;
        }
      attributes_asn1 = ssh_asn1_add_list(attributes_asn1, node);
    }

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (sequence (a 8)" /* Add */
                                "  (octet-string ())" /* Base Object */
                                "  (sequence ()"
                                "   (any ()))))", /* Attributes */
                                (SshWord) op->id,
                                object->object_name, object->object_name_len,
                                attributes_asn1);
  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Send add request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_ldap_send_operation failed, status = %s",
                 ssh_asn1_error_string(status)));
      MAKEINFO(&info, "Asn.1 create failed for operation");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}


/* Do LDAP delete. This automatically takes connection and bind if not done
   already (or if the connection has been broken). */
SshOperationHandle
ssh_ldap_client_delete(SshLdapClient client,
                       const unsigned char *object_name,
                       size_t object_name_len,
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
            ("delete(%p) object=%s", client, object_name));

  /* Start the delete operation */
  START(client,
        SSH_LDAP_OPERATION_DELETE_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (octet-string (a 10)))", /* base object */
                                (SshWord) op->id,
                                object_name, object_name_len);
  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Send delete request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_ldap_send_operation failed, status = %s",
                 ssh_asn1_error_string(status)));
      MAKEINFO(&info, "Asn.1 create failed for operation");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}


/* Do LDAP modify RDN. This automatically takes connection and bind if
   not done already (or if the connection has been broken). */
SshOperationHandle
ssh_ldap_client_modify_rdn(SshLdapClient client,
                           const unsigned char *object_name,
                           size_t object_name_len,
                           const unsigned char *new_rdn,
                           size_t new_rdn_len,
                           Boolean delete_old_rdn,
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
            ("modify/rdn(%p) object=%s new=%s",
             client, object_name, new_rdn));

  /* Start the modify rdn operation */
  START(client,
        SSH_LDAP_OPERATION_MODIFY_RDN_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (sequence (a 12)" /* Modify RDN */
                                "  (octet-string ())" /* Base Object */
                                "  (octet-string ())" /* New RDN */
                                "  (boolean ())))",
                                (SshWord) op->id,
                                object_name, object_name_len,
                                new_rdn, new_rdn_len,
                                delete_old_rdn);
  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Send modify rdn request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}


SshOperationHandle
ssh_ldap_client_compare(SshLdapClient client,
                        const unsigned char *object_name,
                        size_t object_name_len,
                        SshLdapAttributeValueAssertion ava,
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
            ("compare(%p) object=%s", client, object_name));

  START(client,
        SSH_LDAP_OPERATION_COMPARE_REQUEST,
        callback, callback_context, info,
        op, asn1context);

  status = ssh_asn1_create_tree(asn1context, &message,
                                "(sequence ()"
                                " (integer-short ())" /* Message id */
                                " (sequence (a 14)" /* Compare */
                                "  (octet-string ())" /* Base Object */
                                "  (sequence ()"/* Attribute value assertion */
                                "   (octet-string ())" /* attribute type */
                                "   (octet-string ()))))",/* attribute value */
                                (SshWord) op->id,
                                object_name, object_name_len,
                                ava->attribute_type, ava->attribute_type_len,
                                ava->attribute_value,
                                ava->attribute_value_len);
  if (status != SSH_ASN1_STATUS_OK)
    {
      MAKEINFO(&info, "Asn.1 create failed for operation.");
      ssh_ldap_result(client, op, SSH_LDAP_RESULT_INTERNAL, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }

  /* Send compare request */
  lresult = ssh_ldap_send_operation(client, asn1context, message);
  if (lresult != SSH_LDAP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_ldap_send_operation failed, status = %s",
                 ssh_asn1_error_string(status)));
      MAKEINFO(&info, "Asn.1 create failed for operation");
      ssh_ldap_result(client, op, lresult, &info);
      ssh_asn1_free(asn1context);
      return NULL;
    }
  ssh_asn1_free(asn1context);
  return op->operation;
}
#endif /* SSHDIST_LDAP */
