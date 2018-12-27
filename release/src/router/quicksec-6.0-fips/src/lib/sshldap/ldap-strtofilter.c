/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAP search filter management, convert string to filter.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapFilterFromString"

/* Internal convert LDAP Search filter string to preallocated
   SshLdapSearchFilter structure. Returns TRUE if successful, and
   FALSE in case of error. */

static Boolean
ldap_string_to_filter_internal(unsigned char **string,
                               size_t *string_len,
                               SshLdapSearchFilter filter)
{
  int max_cnt;
  Boolean start_paren_not_found = FALSE;

  if (*string_len == 0) return FALSE;

  /* Check if the string starts with parenthesis. If so, good, if
     not, mark MS and Baltimore CA compatibility */
  if (**string != '(')
    start_paren_not_found = TRUE;
  else
    {
      (*string_len)--;
      (*string)++;
    }

  if (**string == '&' || **string == '|')
    {
      /* And, or OR */
      if (**string == '&')
        filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_AND;
      else
        filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_OR;

      (*string)++;
      if (*string_len == 0) return FALSE;
      (*string_len)--;

      max_cnt = 3;
      filter->filter_number_of_filters = 0;
      if ((filter->filter_table_of_filters =
           ssh_calloc(max_cnt, sizeof(*filter))) == NULL)
        return FALSE;

      while (**string == '(')
        {
          if (filter->filter_number_of_filters == max_cnt)
            {
              void *tmp;

              if ((tmp =
                   ssh_realloc(filter->filter_table_of_filters,
                               max_cnt * sizeof(*filter),
                               (3 + max_cnt) * sizeof(*filter))) == NULL)
                return FALSE;

              max_cnt += 3;
              filter->filter_table_of_filters = tmp;
              memset(&(filter->filter_table_of_filters[max_cnt - 3]),
                     0,
                     3 * sizeof(*filter));
            }
          if (!ldap_string_to_filter_internal(string, string_len,
                      &filter->
                      filter_table_of_filters[filter->
                                              filter_number_of_filters]))
            return FALSE;

          filter->filter_number_of_filters++;
        }
    }
  else if (**string == '!')
    {
      /* NOT */
      filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_NOT;
      if ((filter->filter_not_filter = ssh_calloc(1, sizeof(*filter))) == NULL)
        {
          return FALSE;
        }
      (*string)++;
      if (*string_len == 0) return FALSE;
      (*string_len)--;

      if (!ldap_string_to_filter_internal(string, string_len,
                                          filter->filter_not_filter))
        return FALSE;
    }
  else
    {
      unsigned char *value;
      unsigned char *attr, *p;
      size_t len, attr_len, value_len;

      /* Find attribute */
      attr = *string;
      for (p = *string, len = *string_len, attr_len = 0;
           len > 0;
           len--, p++, attr_len++)
        {
          if (*p == '=' || *p == '<' || *p == '>' || *p == '~')
            break;
        }
      if (len == 0)
        return FALSE;

      if (p[0] == '=' && len > 2 && p[1] == '*' && p[2] == ')')
        {
          /* Present */
          filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_PRESENT;
          if ((filter->filter_attribute_type.attribute_type =
               ssh_memdup(attr, attr_len)) == NULL)
            return FALSE;
          filter->filter_attribute_type.attribute_type_len = attr_len;
          *string = p + 2;
          *string_len = len - 2;
        }
      else
        {
          Boolean star_found;

          if (p[0] == '>' && len > 1 && p[1] == '=')
            filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL;
          else if (p[0] == '<' && len > 1 && p[1] == '=')
            filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL;
          else if (p[0] == '~' && len > 1 && p[1] == '=')
            filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_APPROX_MATCH;
          else if (p[0] == '=')
            filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH;
          else
            return FALSE;

          if (filter->ldap_operator
              == SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH)
            {
              p++;
              len--;
            }
          else
            {
              p += 2;
              len -= 2;
            }

          value = p;
          value_len = 0;

          star_found = FALSE;
          for (; len > 0 && *p != ')'; len--, p++, value_len++)
            {
              while (*p == '\\')
                {
                  if (len < 2)
                    return FALSE;
                  p += 2;
                  len -= 2;
                  value_len++;
                }
              if (*p == ')')
                break;
              if (*p == '*')
                {
                  star_found = TRUE;
                }
            }

          if (filter->ldap_operator
              == SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH
              && star_found)
            {
              filter->ldap_operator = SSH_LDAP_FILTER_OPERATION_SUBSTRINGS;

              if ((filter->filter_substring.attribute_type =
                   ssh_memdup(attr, attr_len)) == NULL)
                return FALSE;
              filter->filter_substring.attribute_type_len = attr_len;
              *string = p;
              *string_len = len;

              if (*value != '*')
                {
                  /* We have initial segment */
                  if ((filter->filter_substring.initial =
                       ssh_malloc(value_len + 1)) == NULL)
                    return FALSE;
                  filter->filter_substring.initial_len = 0;
                  for (p = (unsigned char *)filter->filter_substring.initial;
                       *value != '*' && value_len > 0;
                       value_len--, value++, p++,
                         filter->filter_substring.initial_len++)
                    {
                      if (*value == '\\')
                        *p = *++value;
                      else
                        *p = *value;
                    }
                  *p = '\0';
                }

              if (value_len > 0)
                {
                  /* Any parts, all starting with star */
                  max_cnt = 3;
                  filter->filter_substring.number_of_any_parts = 0;
                  if ((filter->filter_substring.any_table =
                       ssh_calloc(max_cnt, sizeof(char *))) == NULL)
                    return FALSE;
                  if ((filter->filter_substring.any_table_lens =
                       ssh_calloc(max_cnt, sizeof(size_t))) == NULL)
                    return FALSE;

                  while (value_len > 0)
                    {
                      /* Skip the initial star */
                      value++;
                      value_len--;

                      if (value_len == 0)
                        break;

                      if (max_cnt ==
                          filter->filter_substring.number_of_any_parts)
                        {
                          void *tmp1, *tmp2;

                          max_cnt += 3;
                          tmp1 =
                            ssh_realloc(filter->filter_substring.any_table,
                                        (max_cnt - 3) * sizeof(char *),
                                        (max_cnt - 0) * sizeof(char *));

                          tmp2 =
                            ssh_realloc(filter->filter_substring.
                                        any_table_lens,
                                        (max_cnt - 3) * sizeof(size_t),
                                        (max_cnt - 0) * sizeof(size_t));

                          if (tmp1 == NULL || tmp2 == NULL)
                            {
                              if (tmp1)
                                ssh_free(tmp1);
                              if (tmp2)
                                ssh_free(tmp2);
                              return FALSE;
                            }

                          filter->filter_substring.any_table = tmp1;
                          filter->filter_substring.any_table_lens = tmp2;

                        }
                      if ((filter->filter_substring.
                           any_table[filter->filter_substring.
                                     number_of_any_parts] =
                           ssh_malloc(value_len + 1)) == NULL)
                        return FALSE;
                      filter->filter_substring.
                        any_table_lens[filter->filter_substring.
                                      number_of_any_parts] = 0;
                      for (p = (unsigned char *)filter->filter_substring.
                             any_table[filter->filter_substring.
                                       number_of_any_parts];
                          *value != '*' && value_len > 0;
                          value_len--, value++, p++,
                            filter->filter_substring.
                            any_table_lens[filter->filter_substring.
                                          number_of_any_parts]++)
                        {
                          if (*value == '\\')
                            *p = *++value;
                          else
                            *p = *value;
                        }
                      *p = '\0';
                      filter->filter_substring.number_of_any_parts++;

                      if (value_len == 0)
                        {
                          /* It was final part, move it there */
                          filter->filter_substring.number_of_any_parts--;
                          filter->filter_substring.final =
                            filter->filter_substring.
                            any_table[filter->filter_substring.
                                     number_of_any_parts];
                          filter->filter_substring.
                            any_table[filter->filter_substring.
                                     number_of_any_parts] = NULL;

                          filter->filter_substring.final_len =
                            filter->filter_substring.
                            any_table_lens[filter->filter_substring.
                                          number_of_any_parts];
                        }
                    }
                }
            }
          else
            {
              if ((filter->filter_attribute_value_assertion.attribute_type =
                   ssh_memdup(attr, attr_len)) == NULL)
                return FALSE;
              filter->filter_attribute_value_assertion.attribute_type_len =
                attr_len;
              if ((filter->filter_attribute_value_assertion.attribute_value =
                   ssh_malloc(value_len + 1)) == NULL)
                return FALSE;
              filter->filter_attribute_value_assertion.attribute_value_len =
                value_len;
              *string = p;
              *string_len = len;
              for (p = filter->
                     filter_attribute_value_assertion.
                     attribute_value;
                   value_len > 0;
                   value_len--, value++, p++)
                {
                  if (*value == '\\')
                    *p = *++value;
                  else
                    *p = *value;
                }
              *p = '\0';
            }
        }
    }
  if (**string != ')' && !start_paren_not_found)
    return FALSE;

  if (!start_paren_not_found)
    {
      (*string)++;
      if (*string_len == 0) return FALSE;
      (*string_len)--;
    }
  return TRUE;
}


/* Convert LDAP Search filter string to SshLdapSearchFilter
   structure. Returns TRUE if successfull, and FALSE in case of
   error. */
Boolean ssh_ldap_string_to_filter(const unsigned char *string,
                                  size_t string_len,
                                  SshLdapSearchFilter *filter)
{
  unsigned char *p, *tmp;
  size_t tmplen = string_len;

  if (string_len == 0)
    {
      *filter = NULL;
      return TRUE;
    }

  if ((tmp = ssh_memdup(string, string_len)) != NULL)
    {
      if ((*filter = ssh_calloc(1, sizeof(struct SshLdapSearchFilterRec)))
          != NULL)
        {
          p = tmp;
          if (ldap_string_to_filter_internal(&tmp, &tmplen, *filter))
            {
              ssh_free(p);
              return TRUE;
            }
          ssh_free(p);
          ssh_ldap_free_filter(*filter);
          *filter = NULL;
        }
      else
        ssh_free(tmp);
    }
  return FALSE;
}

/* Interal, free SshLdapSearchFilter structure, but do not free filter
   structure itself. */
static void ldap_free_filter_internal(SshLdapSearchFilter filter)
{
  int i;

  switch (filter->ldap_operator)
    {
    case SSH_LDAP_FILTER_OPERATION_AND:
    case SSH_LDAP_FILTER_OPERATION_OR:
      if (filter->filter_table_of_filters)
        {
          for (i = 0; i < filter->filter_number_of_filters; i++)
            ldap_free_filter_internal(&filter->filter_table_of_filters[i]);
          ssh_free(filter->filter_table_of_filters);
        }
      break;
    case SSH_LDAP_FILTER_OPERATION_NOT:
      if (filter->filter_not_filter)
        {
          ldap_free_filter_internal(filter->filter_not_filter);
          ssh_free(filter->filter_not_filter);
        }
      break;
    case SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH:
    case SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL:
    case SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL:
    case SSH_LDAP_FILTER_OPERATION_APPROX_MATCH:
      if (filter->filter_attribute_value_assertion.attribute_type)
        ssh_free(filter->filter_attribute_value_assertion.attribute_type);
      if (filter->filter_attribute_value_assertion.attribute_value)
        ssh_free(filter->filter_attribute_value_assertion.attribute_value);
      break;
    case SSH_LDAP_FILTER_OPERATION_SUBSTRINGS:
      if (filter->filter_substring.attribute_type)
        ssh_free(filter->filter_substring.attribute_type);
      if (filter->filter_substring.initial)
        ssh_free(filter->filter_substring.initial);
      if (filter->filter_substring.any_table)
        {
          for (i = 0; i < filter->filter_substring.number_of_any_parts; i++)
            {
              if (filter->filter_substring.any_table[i])
                ssh_free(filter->filter_substring.any_table[i]);
            }
          ssh_free(filter->filter_substring.any_table);
        }
      if (filter->filter_substring.any_table_lens)
        ssh_free(filter->filter_substring.any_table_lens);
      if (filter->filter_substring.final)
        ssh_free(filter->filter_substring.final);
      break;
    case SSH_LDAP_FILTER_OPERATION_PRESENT:
      if (filter->filter_attribute_type.attribute_type)
        ssh_free(filter->filter_attribute_type.attribute_type);
      break;
    }
}

/* Free SshLdapSearchFilter structure. */
void ssh_ldap_free_filter(SshLdapSearchFilter filter)
{
  if (filter)
    {
      ldap_free_filter_internal(filter);
      ssh_free(filter);
    }
}

/* Create asn1 node from the filter code */
SshAsn1Node ssh_ldap_create_filter(SshAsn1Context asn1context,
                                   SshLdapSearchFilter filter)
{
  SshAsn1Node node, list;
  SshAsn1Status status = SSH_ASN1_STATUS_OPERATION_FAILED;
  int i;

  if (!filter)
    return NULL;

  node = NULL;
  switch (filter->ldap_operator)
    {
    case SSH_LDAP_FILTER_OPERATION_AND:
    case SSH_LDAP_FILTER_OPERATION_OR:
      list = NULL;
      for (i = 0; i < filter->filter_number_of_filters; i++)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                "(any ())",
                ssh_ldap_create_filter(asn1context,
                                       &filter->filter_table_of_filters[i]));
          if (status != SSH_ASN1_STATUS_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ssh_asn1_create_node failed, status = %s",
                         ssh_asn1_error_string(status)));
              return NULL;
            }
          list = ssh_asn1_add_list(list, node);
        }

      list = ssh_asn1_sort_list(asn1context, list);
      if (filter->ldap_operator == SSH_LDAP_FILTER_OPERATION_AND)
        status = ssh_asn1_create_node(asn1context, &node,
                                      "(set (0)"
                                      " (any ()))", /* Set of filters */
                                      list);
      else
        status = ssh_asn1_create_node(asn1context, &node,
                                      "(set (1)"
                                      " (any ()))", /* Set of filters */
                                      list);
      break;
    case SSH_LDAP_FILTER_OPERATION_NOT:
      list = ssh_asn1_sort_list(asn1context,
                                ssh_ldap_create_filter(asn1context,
                                                       filter->
                                                       filter_not_filter));
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(set (2)" /* Not filter */
                                    " (any ()))",
                                    list);
      break;
    case SSH_LDAP_FILTER_OPERATION_EQUALITY_MATCH:
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence (3)"
                                    " (octet-string ())" /* Type */
                                    " (octet-string ()))", /* Value */
                                    filter->filter_attribute_value_assertion.
                                    attribute_type,
                                    filter->filter_attribute_value_assertion.
                                    attribute_type_len,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value_len);
      break;
    case SSH_LDAP_FILTER_OPERATION_SUBSTRINGS:
      list = NULL;
      if (filter->filter_substring.initial != NULL)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                                        "(octet-string (0))",
                                        filter->filter_substring.initial,
                                        filter->filter_substring.initial_len);
          if (status != SSH_ASN1_STATUS_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ssh_asn1_create_node failed, status = %s",
                         ssh_asn1_error_string(status)));
              return NULL;
            }
          list = ssh_asn1_add_list(list, node);
        }
      for (i = 0; i < filter->filter_substring.number_of_any_parts; i++)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                                        "(octet-string (1))",
                                        filter->filter_substring.any_table[i],
                                        filter->filter_substring.
                                        any_table_lens[i]);

          if (status != SSH_ASN1_STATUS_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ssh_asn1_create_node failed, status = %s",
                         ssh_asn1_error_string(status)));
              return NULL;
            }
          list = ssh_asn1_add_list(list, node);
        }
      if (filter->filter_substring.final != NULL)
        {
          status = ssh_asn1_create_node(asn1context, &node,
                                        "(octet-string (2))",
                                        filter->filter_substring.final,
                                        filter->filter_substring.final_len);
          if (status != SSH_ASN1_STATUS_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ssh_asn1_create_node failed, status = %s",
                         ssh_asn1_error_string(status)));
              return NULL;
            }
          list = ssh_asn1_add_list(list, node);
        }
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence (4)"
                                    " (octet-string ())" /* Type */
                                    " (sequence ()" /* Sequence of substrings*/
                                    "  (any ())))",
                                    filter->filter_substring.attribute_type,
                                    filter->filter_substring.
                                    attribute_type_len,
                                    list);
      break;
    case SSH_LDAP_FILTER_OPERATION_GREATER_OR_EQUAL:
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence (5)"
                                    " (octet-string ())" /* Type */
                                    " (octet-string ()))", /* Value */
                                    filter->filter_attribute_value_assertion.
                                    attribute_type,
                                    filter->filter_attribute_value_assertion.
                                    attribute_type_len,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value_len);
      break;
    case SSH_LDAP_FILTER_OPERATION_LESS_OR_EQUAL:
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence (6)"
                                    " (octet-string ())" /* Type */
                                    " (octet-string ()))", /* Value */
                                    filter->filter_attribute_value_assertion.
                                    attribute_type,
                                    filter->filter_attribute_value_assertion.
                                    attribute_type_len,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value_len);
      break;
    case SSH_LDAP_FILTER_OPERATION_PRESENT:
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(octet-string (7))", /* Type */
                                    filter->filter_attribute_type.
                                    attribute_type,
                                    filter->filter_attribute_type.
                                    attribute_type_len);
      break;
    case SSH_LDAP_FILTER_OPERATION_APPROX_MATCH:
      status = ssh_asn1_create_node(asn1context, &node,
                                    "(sequence (8)"
                                    " (octet-string ())" /* Type */
                                    " (octet-string ()))", /* Value */
                                    filter->filter_attribute_value_assertion.
                                    attribute_type,
                                    filter->filter_attribute_value_assertion.
                                    attribute_type_len,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value,
                                    filter->filter_attribute_value_assertion.
                                    attribute_value_len);
      break;
    }
  if (status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_asn1_create_node failed, status = %s",
                 ssh_asn1_error_string(status)));
      return NULL;
    }
  return node;
}
#endif /* SSHDIST_LDAP */
