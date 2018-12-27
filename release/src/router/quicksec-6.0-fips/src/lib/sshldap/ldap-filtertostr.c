/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Convert LDAP search filter structure to string.
   Note; these routines are not out-of-memory safe.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapFilterToString"

/* Append to buffer quoting all '(', ')', '*', and '\\' characters. */
static Boolean
ldap_append_buffer_quoted(SshBuffer buffer, char *string, size_t len)
{
  for (; len > 0; len--)
    {
      if (*string == '(' || *string == ')' ||
          *string == '*' || *string == '\\')
        if (ssh_buffer_append(buffer, (const unsigned char *) "\\", 1)
            != SSH_BUFFER_OK)
          return FALSE;

      if (ssh_buffer_append(buffer, (unsigned char *) string++, 1)
          != SSH_BUFFER_OK)
        return FALSE;
    }
  return TRUE;
}

/* Convert SshLdapSearchFilter to buffer. TRUE if successfull, and FALSE in
   case of error.*/
Boolean ssh_ldap_filter_to_buffer(SshLdapSearchFilter filter,
                                  SshBuffer buffer)
{
  int i;

  switch (filter->ldap_operator)
    {
    case SSH_LDAP_FILTER_OPERATION_AND:
    case SSH_LDAP_FILTER_OPERATION_OR:
      if (filter->ldap_operator == SSH_LDAP_FILTER_OPERATION_AND)
        ssh_buffer_append(buffer, (const unsigned char *) "(&", 2);
      else
        ssh_buffer_append(buffer, (const unsigned char *) "(|", 2);

      for (i = 0; i < filter->filter_number_of_filters; i++)
        ssh_ldap_filter_to_buffer(&filter->filter_table_of_filters[i],
                                  buffer);

      ssh_buffer_append(buffer, (const unsigned char *) ")", 1);
      break;
    case SSH_LDAP_FILTER_OPERATION_NOT:
      ssh_buffer_append(buffer, (const unsigned char *) "(!", 2);
      ssh_ldap_filter_to_buffer(filter->filter_not_filter, buffer);
      ssh_buffer_append(buffer, (const unsigned char *) ")", 1);
      break;
    case SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH:
    case SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL:
    case SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL:
    case SSH_LDAP_FILTER_OPERATION_APPROX_MATCH:
      ssh_buffer_append(buffer, (const unsigned char *) "(", 1);
      ssh_buffer_append(buffer, (unsigned char *)
                        filter->filter_attribute_value_assertion.
                        attribute_type,
                        filter->filter_attribute_value_assertion.
                        attribute_type_len);
      if (filter->ldap_operator
          == SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH)
        ssh_buffer_append(buffer, (const unsigned char *) "=", 1);
      else if (filter->ldap_operator
               == SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL)
        ssh_buffer_append(buffer, (const unsigned char *) ">=", 2);
      else if (filter->ldap_operator
               == SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL)
        ssh_buffer_append(buffer, (const unsigned char *) "<=", 2);
      else if (filter->ldap_operator
               == SSH_LDAP_FILTER_OPERATION_APPROX_MATCH)
        ssh_buffer_append(buffer, (const unsigned char *) "~=", 2);

      ldap_append_buffer_quoted(buffer,
                                (char *)filter->
                                filter_attribute_value_assertion.
                                attribute_value,
                                filter->filter_attribute_value_assertion.
                                attribute_value_len);

      ssh_buffer_append(buffer, (const unsigned char *) ")", 1);
      break;
    case SSH_LDAP_FILTER_OPERATION_SUBSTRINGS:
      ssh_buffer_append(buffer, (const unsigned char *) "(", 1);
      ssh_buffer_append(buffer, (unsigned char *)
                        filter->filter_substring.attribute_type,
                        filter->filter_substring.attribute_type_len);
      ssh_buffer_append(buffer, (const unsigned char *) "=", 1);
      if (filter->filter_substring.initial)
        {
          ldap_append_buffer_quoted(buffer,
                                    filter->filter_substring.initial,
                                    filter->filter_substring.initial_len);
        }
      ssh_buffer_append(buffer, (const unsigned char *) "*", 1);
      if (filter->filter_substring.any_table)
        {
          for (i = 0; i < filter->filter_substring.number_of_any_parts; i++)
            {
              ldap_append_buffer_quoted(buffer,
                                        filter->filter_substring.
                                        any_table[i],
                                        filter->filter_substring.
                                        any_table_lens[i]);
              ssh_buffer_append(buffer, (const unsigned char *) "*", 1);
            }
        }
      if (filter->filter_substring.final)
        {
          ldap_append_buffer_quoted(buffer,
                                    filter->filter_substring.final,
                                    filter->filter_substring.final_len);
        }
      ssh_buffer_append(buffer, (const unsigned char *) ")", 1);
      break;
    case SSH_LDAP_FILTER_OPERATION_PRESENT:
      ssh_buffer_append(buffer, (const unsigned char *) "(", 1);
      ssh_buffer_append(buffer, (unsigned char *)
                        filter->filter_attribute_type.attribute_type,
                        filter->filter_attribute_type.attribute_type_len);
      ssh_buffer_append(buffer, (const unsigned char *) "=*)", 3);
      break;
    }
  return TRUE;
}

/* Convert SshLdapSearchFilter to string. TRUE if successfull, and FALSE in
   case of error.*/
Boolean ssh_ldap_filter_to_string(SshLdapSearchFilter filter,
                                  unsigned char **string,
                                  size_t *string_len)
{
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);

  if (filter)
    {
      if (!ssh_ldap_filter_to_buffer(filter, &buffer))
        {
          ssh_buffer_uninit(&buffer);
          return FALSE;
        }
    }

  if (string_len != NULL)
    *string_len = ssh_buffer_len(&buffer);

  *string = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);

  if (*string == NULL)
    {
      if (string_len)
        *string_len = 0;
      return FALSE;
    }
  return TRUE;
}
#endif /* SSHDIST_LDAP */
