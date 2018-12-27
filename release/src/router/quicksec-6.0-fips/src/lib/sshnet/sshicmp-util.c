/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Convinience functions for converting human readable
   ICMP type and code to numeric traffic selector ports:

   ipv4(icmp:type(echo),10.0.1.1) -> ipv4(icmp:2048,10.0.1.1)
*/

#include "sshincludes.h"
#include "sshsnprintf.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshIcmpUtil"

/* Mapping between ICMP type name and number */
const SshKeywordStruct ssh_icmp_type_keywords[] =
{
  { "echo-reply",            SSH_ICMP_TYPE_ECHOREPLY },
  { "dst-unreachable",       SSH_ICMP_TYPE_UNREACH   },
  { "sourcequench",          SSH_ICMP_TYPE_SOURCEQUENCH },
  { "redirect",              SSH_ICMP_TYPE_REDIRECT },
  { "echo",                  SSH_ICMP_TYPE_ECHO },
  { "router-advert",         SSH_ICMP_TYPE_ROUTERADVERT },
  { "router-solicit",        SSH_ICMP_TYPE_ROUTERSOLICIT },
  { "time-exceeded",         SSH_ICMP_TYPE_TIMXCEED },
  { "parameter-problem",     SSH_ICMP_TYPE_PARAMPROB },
  { "timestamp",             SSH_ICMP_TYPE_TSTAMP },
  { "timestamp-reply",       SSH_ICMP_TYPE_TSTAMPREPLY },
  { "info-request",          SSH_ICMP_TYPE_IREQ },
  { "info-reply",            SSH_ICMP_TYPE_IREQREPLY },
  { "address-mask-request",  SSH_ICMP_TYPE_MASKREQ },
  { "address-mask-reply",    SSH_ICMP_TYPE_MASKREPLY },
  { NULL, 0}
};

/* Mapping between ICMP unreachable code name and number */
const SshKeywordStruct ssh_icmp_unreachable_code_keywords[] =
{
  { "net-unreachable",       SSH_ICMP_CODE_UNREACH_NET },
  { "host-unreachable",      SSH_ICMP_CODE_UNREACH_HOST },
  { "protocol-unreachable",  SSH_ICMP_CODE_UNREACH_PROTOCOL },
  { "port-unreachable",      SSH_ICMP_CODE_UNREACH_PORT },
  { "need-fragmentation",    SSH_ICMP_CODE_UNREACH_NEEDFRAG },
  { "source-route-failed",   SSH_ICMP_CODE_UNREACH_SRCFAIL },
  { "net-unknown",           SSH_ICMP_CODE_UNREACH_NET_UNKNOWN },
  { "host-unknown",          SSH_ICMP_CODE_UNREACH_HOST_UNKNOWN },
  { "source-host-isolated",  SSH_ICMP_CODE_UNREACH_ISOLATED },
  { "net-admin-prohibited",  SSH_ICMP_CODE_UNREACH_NET_PROHIB },
  { "host-admin-prohibited", SSH_ICMP_CODE_UNREACH_HOST_PROHIB },
  { "tos-net-unreachable",   SSH_ICMP_CODE_UNREACH_TOSNET },
  { "tos-host-unreachable",  SSH_ICMP_CODE_UNREACH_TOSHOST },
  { "admin-prohibited",      SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT },
  { NULL, 0}
};

/* Mapping between ICMP redirect code name and number */
const SshKeywordStruct ssh_icmp_redirect_code_keywords[] =
{
  { "net-redirect",          SSH_ICMP_CODE_REDIRECT_NET },
  { "host-redirect",         SSH_ICMP_CODE_REDIRECT_HOST },
  { "tos-net-redirect",      SSH_ICMP_CODE_REDIRECT_TOSNET },
  { "tos-host-redirect",     SSH_ICMP_CODE_REDIRECT_TOSHOST },
  { NULL, 0}
};

/* Mapping between ICMP time exceeded code name and number */
const SshKeywordStruct ssh_icmp_timeexceeded_code_keywords[] =
{
  { "in-transit",            SSH_ICMP_CODE_TIMXCEED_INTRANS },
  { "in-reassembly",         SSH_ICMP_CODE_TIMXCEED_REASS },
  { NULL, 0}
};

/* Mapping between ICMPv6 type name and number */
const SshKeywordStruct ssh_icmp6_type_keywords[] =
{
  { "dst-unreachable",       SSH_ICMP6_TYPE_UNREACH },
  { "too-big",               SSH_ICMP6_TYPE_TOOBIG },
  { "time-exceeded",         SSH_ICMP6_TYPE_TIMXCEED },
  { "parameter-problem",     SSH_ICMP6_TYPE_PARAMPROB },
  { "echo",                  SSH_ICMP6_TYPE_ECHOREQUEST },
  { "echo-reply",            SSH_ICMP6_TYPE_ECHOREPLY },
  { "router-solicit",        SSH_ICMP6_TYPE_ROUTER_SOLICITATION },
  { "router-advert",         SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT },
  { "neighbor-solicit",      SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION },
  { "neighbor-advert",       SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT },
  { "redirect",              SSH_ICMP6_TYPE_REDIRECT },
  { NULL, 0}
};

/* Mapping between ICMPv6 unreachable code name and number */
const SshKeywordStruct ssh_icmp6_unreachable_code_keywords[] =
{
  { "no-route",              SSH_ICMP6_CODE_UNREACH_NOROUTE },
  { "admin-prohibit",        SSH_ICMP6_CODE_UNREACH_PROHIBITED },
  { "address-unreachable",   SSH_ICMP6_CODE_UNREACH_ADDRESS },
  { "port-unreachable",      SSH_ICMP6_CODE_UNREACH_PORT },
  { NULL, 0}
};

/* Mapping between ICMPv6 time exceeded code name and number */
const SshKeywordStruct ssh_icmp6_timeexceeded_code_keywords[] =
{
  { "in-transit",            SSH_ICMP6_CODE_TIMXCEED_HOP},
  { "in-reassembly",         SSH_ICMP6_CODE_TIMXCEED_REASS},
  { NULL, 0}
};

/* Mapping between ICMPv6 parameter problem code name and number */
const SshKeywordStruct ssh_icmp6_paramproblem_code_keywords[] =
{
  { "invalid-header",        SSH_ICMP6_CODE_PARAMPROB_HEADER},
  { "unknown-nh",            SSH_ICMP6_CODE_PARAMPROB_NH},
  { "unknown-option",        SSH_ICMP6_CODE_PARAMPROB_OPTION },
  { NULL, 0}
};

#define ICMP_TSUTIL_SKIP_WHITESPACE(s) \
                                 while (*(s) && isspace(((int)(*s)))) (s)++

/** Performs one round of conversion. Returns ssh_mallocated result
    string which must be freed by the calling code, or NULL if no conversion
    was made to input string. */
static char *
ssh_icmputil_string_item_to_tsstring(const char *string)
{
  const char *str = string;
  unsigned char *result_string = NULL;
  size_t result_length;
  SshInetIPProtocolID proto = SSH_IPPROTO_ANY;
  const char *cendp, *cstartp;
  char *endp;
  int c;
  long type, min_code, max_code;

 restart:

  /* Skip any leading whitespace */
  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str == '\0')
    return NULL;

  /* Skip network protocol identifier */
  while (*str != '(' && *str != '\0')
    str++;
  if (*str == '\0')
    return NULL;
  str++;

  /* Check if IP protocol is either ICMP or IPV6ICMP */
  proto = ssh_find_partial_keyword_number_case_insensitive(
                                                   ssh_ip_protocol_id_keywords,
                                                   str, &cendp);
  str = cendp;
  if (proto != SSH_IPPROTO_ICMP && proto != SSH_IPPROTO_IPV6ICMP)
    {
      /* Skip this item. */
      while (*str != ')' && *str != '\0')
        str++;
      if (*str == '\0')
        return NULL;
      str++;
      if (*str == ',')
        str++;
      goto restart;
    }

  /* Find start of ports */
  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str != ':')
    return NULL;

  /* Look for 'type' */
  str += 1;
  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str == '\0')
    return NULL;

  if (strncasecmp(str, "type(", 5) != 0)
    {
      /* Skip this item. */
      while (*str != ')' && *str != '\0')
        str++;
      if (*str == '\0')
        return NULL;
      str++;
      if (*str == ',')
        str++;
      goto restart;
    }

  /* Remember the start point */
  cstartp = str;
  str += 5;

  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str == '\0')
    return NULL;

  /* Ok, now we can start converting */

  /* Parse type string */
  if (proto == SSH_IPPROTO_ICMP)
    type = ssh_find_partial_keyword_number_case_insensitive(
                                                        ssh_icmp_type_keywords,
                                                        str, &cendp);
  else
    type = ssh_find_partial_keyword_number_case_insensitive(
                                                       ssh_icmp6_type_keywords,
                                                       str, &cendp);

  /* Attempt to parse as a numeric string */
  if (type == -1)
    {
      type = strtol(str, &endp, 0);
      if (str == endp)
        type = -1;
      cendp = endp;
    }

  /* No known type found */
  if (type == -1)
    return NULL;
  str = cendp;

  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str == '\0')
    return NULL;

  /* Parse code */
  min_code = 0;
  max_code = 0xff;
  if (*str == ',')
    {
      int round = 0;

      min_code = -1;
      max_code = -1;
      str++;
      for (round = 0; round < 2; round++)
        {
          ICMP_TSUTIL_SKIP_WHITESPACE(str);
          if (*str == '\0')
            return NULL;

          /* Parse the code string */
          if (proto == SSH_IPPROTO_ICMP)
            {
              switch (type)
                {
                case SSH_ICMP_TYPE_UNREACH:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                            ssh_icmp_unreachable_code_keywords,
                                            str, &cendp);
                  break;

                case SSH_ICMP_TYPE_REDIRECT:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                               ssh_icmp_redirect_code_keywords,
                                               str, &cendp);
                  break;

                case SSH_ICMP_TYPE_TIMXCEED:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                           ssh_icmp_timeexceeded_code_keywords,
                                           str, &cendp);
                  break;

                default:
                  c = -1;
                  break;
                }
            }
          else
            {
              switch (type)
                {
                case SSH_ICMP6_TYPE_UNREACH:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                           ssh_icmp6_unreachable_code_keywords,
                                           str, &cendp);
                  break;

                case SSH_ICMP6_TYPE_TIMXCEED:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                          ssh_icmp6_timeexceeded_code_keywords,
                                          str, &cendp);
                  break;

                case SSH_ICMP6_TYPE_PARAMPROB:
                  c = ssh_find_partial_keyword_number_case_insensitive(
                                          ssh_icmp6_paramproblem_code_keywords,
                                          str, &cendp);
                  break;

                default:
                  c = -1;
                  break;
                }
            }

          /* Parse the code as a numeric string */
          if (c == -1)
            {
              c = strtol(str, &endp, 0);
              if (str == endp)
                c = -1;
              cendp = endp;
            }

          if (c == -1)
            return NULL;
          str = cendp;

          if (round == 0)
            {
              min_code = c;

              /* Check if this is a code range */
              ICMP_TSUTIL_SKIP_WHITESPACE(str);
              if (*str != '-')
                break;
              str++;
            }
          else
            {
              max_code = c;
              /* Require that the range is sane */
              if (max_code < min_code)
                return NULL;
            }
        } /* for ... */
    }

  /* Fix the code ranges for types that have a code, and
     clear the code range for types that do not have a code */
  if (proto == SSH_IPPROTO_ICMP)
    {
      switch (type)
        {
        case SSH_ICMP_TYPE_UNREACH:
          min_code = (min_code <= SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT ?
                      min_code : SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT);
          max_code = (max_code <= SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT ?
                      max_code : SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT);
          break;

        case SSH_ICMP_TYPE_REDIRECT:
          min_code = (min_code <= SSH_ICMP_CODE_REDIRECT_TOSHOST ?
                      min_code : SSH_ICMP_CODE_REDIRECT_TOSHOST);
          max_code = (max_code <= SSH_ICMP_CODE_REDIRECT_TOSHOST ?
                      max_code : SSH_ICMP_CODE_REDIRECT_TOSHOST);
          break;

        case SSH_ICMP_TYPE_TIMXCEED:
          min_code = (min_code <= SSH_ICMP_CODE_TIMXCEED_REASS ?
                      min_code : SSH_ICMP_CODE_TIMXCEED_REASS);
          max_code = (max_code <= SSH_ICMP_CODE_TIMXCEED_REASS ?
                      max_code : SSH_ICMP_CODE_TIMXCEED_REASS);
          break;

        case SSH_ICMP_TYPE_PARAMPROB:
          min_code = (min_code <= 1 ?
                      min_code : 1);
          max_code = (max_code <= 1 ?
                      max_code : 1);
          break;

        default:
          min_code = 0;
          max_code = -1;
          break;
        }
    }
  else /* SSH_IPPROTO_ICMPV6 */
    {
      switch (type)
        {
        case SSH_ICMP6_TYPE_UNREACH:
          min_code = (min_code <= SSH_ICMP6_CODE_UNREACH_PORT ?
                      min_code : SSH_ICMP6_CODE_UNREACH_PORT);
          max_code = (max_code <= SSH_ICMP6_CODE_UNREACH_PORT ?
                      max_code : SSH_ICMP6_CODE_UNREACH_PORT);
          break;

        case SSH_ICMP6_TYPE_TIMXCEED:
          min_code = (min_code <= SSH_ICMP6_CODE_TIMXCEED_REASS ?
                      min_code : SSH_ICMP6_CODE_TIMXCEED_REASS);
          max_code = (max_code <= SSH_ICMP6_CODE_TIMXCEED_REASS ?
                      max_code : SSH_ICMP6_CODE_TIMXCEED_REASS);
          break;

        case SSH_ICMP6_TYPE_PARAMPROB:
          min_code = (min_code <= SSH_ICMP6_CODE_PARAMPROB_OPTION ?
                      min_code : SSH_ICMP6_CODE_PARAMPROB_OPTION);
          max_code = (max_code <= SSH_ICMP6_CODE_PARAMPROB_OPTION ?
                      max_code : SSH_ICMP6_CODE_PARAMPROB_OPTION);
          break;

        default:
          min_code = 0;
          max_code = -1;
          break;
        }
    }

  /* Look for ')' */
  ICMP_TSUTIL_SKIP_WHITESPACE(str);
  if (*str != ')')
    return NULL;

  str++;
  cendp = str;

  /* Now all strings are parsed and the format is known to be valid */
  result_length = strlen(string) + 7 - (cendp - cstartp);
  if (max_code != -1)
    result_length += 7;

  result_string = ssh_malloc(result_length);
  if (result_string == NULL)
    return NULL;

  if (max_code != -1)
    c = ssh_snprintf(result_string, result_length,
                     "%.*s0x%04x-0x%04x%s",
                     (cstartp - string), string,
                     (int) ((type << 8) | (min_code & 0xff)),
                     (int) ((type << 8) | (max_code & 0xff)),
                     cendp);
  else
    c = ssh_snprintf(result_string, result_length,
                     "%.*s0x%04x%s",
                     (cstartp - string), string,
                     (int) ((type << 8) | (min_code & 0xff)),
                     cendp);

  if (c != result_length - 1)
    {
      ssh_free(result_string);
      result_string = NULL;
    }

  return (char *) result_string;
}

/** Converts input `string' from human-readable type and code format
    to numeric traffic selector port selector format. This function
    returns a ssh_mallocated result string which the calling code must
    free, or NULL no conversion was made to input string. */
char *
ssh_icmputil_string_to_tsstring(const char *string)
{
  char *str, *result;

  str = NULL;
  while (TRUE)
    {
      if (str == NULL)
        result = ssh_icmputil_string_item_to_tsstring(string);
      else
        result = ssh_icmputil_string_item_to_tsstring(str);

      if (result == NULL)
        break;

      ssh_free(str);
      str = result;
    }

  return str;
}
