/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Traffic selector utility functions.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshadt.h"
#include "sshadt_list.h"
#include "sshikev2-initiator.h"
#include "sshikev2-payloads.h"
#include "sshikev2-util.h"
#include "sshdsprintf.h"

#define SSH_DEBUG_MODULE "SshIkev2TsUtil"

/* Duplicate traffic selector. This will take new entry from
   the free list and copy data from the current traffic
   selector in to it. This will return NULL if no free
   traffic selectors available. */
SshIkev2PayloadTS
ssh_ikev2_ts_dup(SshSADHandle sad_handle,
                 SshIkev2PayloadTS ts)
{
  SshIkev2PayloadTS ts_copy;

  ts_copy = ssh_ikev2_ts_allocate(sad_handle);
  if (ts_copy == NULL)
    return NULL;

  /* Copy items. */
  if (ts->number_of_items_used > ts_copy->number_of_items_allocated)
    {
      ts_copy->items = ssh_realloc(ts_copy->items,
                                   ts_copy->number_of_items_allocated *
                                   sizeof(*(ts_copy->items)),
                                   ts->number_of_items_used *
                                   sizeof(*(ts_copy->items)));
      if (ts_copy->items == NULL)
        {
          ts_copy->number_of_items_allocated = 0;
          ssh_ikev2_ts_free(sad_handle, ts_copy);
          return NULL;
        }
      ts_copy->number_of_items_allocated = ts->number_of_items_used;
    }
  memcpy(ts_copy->items, ts->items,
         ts->number_of_items_used * sizeof(*(ts->items)));
  ts_copy->number_of_items_used = ts->number_of_items_used;
  return ts_copy;
}

/* Take extra reference to the traffic selector. */
void
ssh_ikev2_ts_take_ref(SshSADHandle sad_handle,
                      SshIkev2PayloadTS ts)
{
  ts->ref_cnt++;
}

/* Add item to the traffic selector list. This will add new
   entry to the end of the list. */
SshIkev2Error
ssh_ikev2_ts_item_add(SshIkev2PayloadTS ts,
                      SshInetIPProtocolID proto,
                      SshIpAddr start_address,
                      SshIpAddr end_address,
                      SshUInt16 start_port,
                      SshUInt16 end_port)
{
  if (ts->number_of_items_used >= ts->number_of_items_allocated)
    {
      /* NOTE: Check memory limits here */
      if (!ssh_recalloc(&(ts->items), &(ts->number_of_items_allocated),
                        ts->number_of_items_allocated +
                        SSH_IKEV2_TS_ITEMS_ADD,
                        sizeof(*(ts->items))))
        {
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
    }
  if (SSH_IP_IS4(start_address) &&
      SSH_IP_IS4(end_address))
    ts->items[ts->number_of_items_used].ts_type = SSH_IKEV2_TS_IPV4_ADDR_RANGE;
  else if (SSH_IP_IS6(start_address) &&
           SSH_IP_IS6(end_address))
    ts->items[ts->number_of_items_used].ts_type = SSH_IKEV2_TS_IPV6_ADDR_RANGE;
  else
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
  ts->items[ts->number_of_items_used].proto = proto;
  ts->items[ts->number_of_items_used].start_address[0] = *start_address;
  ts->items[ts->number_of_items_used].end_address[0] = *end_address;
  ts->items[ts->number_of_items_used].start_port = start_port;
  ts->items[ts->number_of_items_used].end_port = end_port;

  ts->number_of_items_used++;
  return SSH_IKEV2_ERROR_OK;
}

/* Remove item from the traffic selector list. This can be
   used to narrow down the traffic selector. */
SshIkev2Error
ssh_ikev2_ts_item_delete(SshIkev2PayloadTS ts,
                         int item_index_to_delete)
{
  if (ts->number_of_items_used < item_index_to_delete)
    {
      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }
  memmove(&(ts->items[item_index_to_delete]),
          &(ts->items[item_index_to_delete + 1]),
          (ts->number_of_items_used - item_index_to_delete - 1) *
          sizeof(*(ts->items)));
  ts->number_of_items_used--;
  return SSH_IKEV2_ERROR_OK;
}

/* Renderer function to render protocol and port numbers
   from traffic selector item for %@ format string for
   ssh_e*printf. Note, this will print the ',' at the end if
   it printed something. */
int ssh_ikev2_ts_render_proto_and_port_range(unsigned char *buf, int buf_size,
                                             int precision, void *datum)
{
  SshIkev2PayloadTSItem ts_item = datum;
  size_t len;

  len = 0;
  if (ts_item->start_port == 65535 && ts_item->end_port == 0)
    {
      /* Opaque. Print proto if we have it. */
      if (ts_item->proto != 0)
        len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%@:",
                            ssh_ipproto_render, (SshUInt32) ts_item->proto);

      if (len >= buf_size)
        return buf_size + 1;

      /* Print opaque. */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "opaque,");

      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }
  if (ts_item->proto == 0)
    {
      /* Otherwise if we do not have proto and this is not
         opaque, then we cannot have port numbers, as they
         would be meaningless without proto. */
      return 0;
    }

  /* Ok, this is the normal case. */
  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%@",
                      ssh_ipproto_render, (SshUInt32) ts_item->proto);

  if (len >= buf_size)
    return buf_size + 1;

  if (ts_item->start_port == 0 && ts_item->end_port == 65535)
    {
      /* Any port, so print nothing. */
    }
  else if (ts_item->start_port == ts_item->end_port)
    {
      /* Single port. */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ":%d",
                          (int) ts_item->start_port);
    }
  else
    {
      /* Port range. */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ":%d-%d",
                          (int) ts_item->start_port,
                          (int) ts_item->end_port);
    }

  if (len >= buf_size)
    return buf_size + 1;

  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ",");
  return len;
}

/* Renderer function to render traffic selector item for %@
   format string for ssh_e*printf. */
int ssh_ikev2_ts_render_item(unsigned char *buf, int buf_size,
                             int precision, void *datum)
{
  SshIkev2PayloadTSItem ts_item = datum;
  size_t len;

  if (ts_item == NULL)
    return ssh_snprintf(ssh_sstr(buf), buf_size + 1, "none()");

  if (SSH_IP_IS4(ts_item->start_address) &&
      SSH_IP_IS4(ts_item->end_address))
    {
      len = ssh_snprintf(ssh_sstr(buf), buf_size + 1, "ipv4(");
    }
  else if (SSH_IP_IS6(ts_item->start_address) &&
           SSH_IP_IS6(ts_item->end_address))
    {
      len = ssh_snprintf(ssh_sstr(buf), buf_size + 1, "ipv6(");
    }
  else
    {
      len = ssh_snprintf(ssh_sstr(buf), buf_size + 1, "error(");
    }

  if (len >= buf_size)
    return buf_size + 1;

  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%@%@",
                      ssh_ikev2_ts_render_proto_and_port_range, datum,
                      ssh_ipaddr_render, ts_item->start_address);

  if (len >= buf_size)
    return buf_size + 1;

  if (SSH_IP_CMP(ts_item->start_address, ts_item->end_address) != 0)
    {
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "-%@",
                          ssh_ipaddr_render, ts_item->end_address);
      if (len >= buf_size)
        return buf_size + 1;
    }

  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ")");

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

/* Renderer function to render traffic selectors for %@
   format string for ssh_e*printf. */
int ssh_ikev2_ts_render(unsigned char *buf, int buf_size,
                        int precision, void *datum)
{
  SshIkev2PayloadTS ts = datum;
  int i;
  size_t len;

  if (ts == NULL)
    return ssh_snprintf(ssh_sstr(buf), buf_size + 1, "none()");

  len = 0;
  for(i = 0; i < ts->number_of_items_used; i++)
    {
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          "%s%@",
                          (i == 0) ? "" : ",",
                          ssh_ikev2_ts_render_item,
                          &(ts->items[i]));
      if (len >= buf_size)
        return buf_size + 1;
    }
  return len;
}

/* This function takes a traffic selector and formats it as
   a string. This will return the allocated string inside
   the `str' argument. The `str' needs to be freed after it
   is no longer needed. Returns the number of characters
   written.*/
int ssh_ikev2_ts_to_string(char **str, SshIkev2PayloadTS ts)
{
  return ssh_dsprintf((unsigned char **) str, "%@", ssh_ikev2_ts_render, ts);
}

#define IKE_SKIP_WHITESPACE(s) while (*(s) && isspace(((int)(*s)))) (s)++
#define IKE_SKIP_IP_ADDR(s) while (*(s) && (isxdigit(((int)(*s))) || \
                                            *s == '.' || \
                                            *s == ':')) (s)++

/* Function to take one item from string and add that to the
   traffic selector. This will return the rest of the string
   not yet used. */
const char *ssh_ikev2_string_to_ts_item(const char *str, SshIkev2PayloadTS ts)
{
  SshInetIPProtocolID proto;
  SshIpAddrStruct start_address[1];
  SshIpAddrStruct end_address[1];
  long int start_port;
  long int  end_port;
  const char *cendp;
  char *endp;
  const char *p;
  char buf[64];
  char address_type = 0;

  memset(start_address, 0, sizeof start_address);
  SSH_IP_UNDEFINE(start_address);
  SSH_IP_UNDEFINE(end_address);
  start_port = 0;
  end_port = 65535;

  IKE_SKIP_WHITESPACE(str);
  if (*str == '\0')
    return str;

  if (strncasecmp(str, "ipv4", 4) == 0)
    {
      address_type = 4;
      str += 4;
    }
  else if (strncasecmp(str, "ipv6", 4) == 0)
    {
      address_type = 6;
      str += 4;
    }
  else
    {
      address_type = 0; /* No address prefix included. */
    }

  /* Skip the '(' after prefix. */
  IKE_SKIP_WHITESPACE(str);
  if (address_type != 0 && *str++ != '(')
    {
      return NULL;
    }
  IKE_SKIP_WHITESPACE(str);

  /* First check the opaque. */
  if (strncasecmp(str, "opaque", 6) == 0)
    {
      start_port = 65535;
      end_port = 0;
      proto = 0;
      str += 6;
      IKE_SKIP_WHITESPACE(str);
      if (*str++ != ',')
        {
          return NULL;
        }
    }
  else
    {
      /* Try to see if there is a protocol number in the
         beginning. */
      proto = ssh_find_partial_keyword_number_case_insensitive(
                               ssh_ip_protocol_id_keywords,
                               str, &cendp);
      if (proto == SSH_IPPROTO_ANY)
        proto = 0;

      if ((int) proto != -1 &&
          (*cendp == ',' || *cendp == ':' || *cendp == ')'
           || isspace(*cendp)))
        {
          /* We did find protocol, it is already set to
             proto. Skip the protocol name, and after this
             str should poind to ':' or ',' after the protocol
             name. */
          str = cendp;
        }
      else
        {
          /* No protocol string there, check for the (unknown %d). */
          if (*str == '(')
            {
              str++;
              IKE_SKIP_WHITESPACE(str);
              if (strncasecmp(str, "unknown", 7) != 0)
                {
                  return NULL;
                }
              str += 7;
              proto = strtol(str, &endp, 0);
              if (endp == str)
                {
                  return NULL;
                }
              str = endp;
              IKE_SKIP_WHITESPACE(str);
              if (*str++ != ')')
                {
                  return NULL;
                }
            }
          else
            {
              /* Ok, no protocol there, set the values to
                 default, and go to see if there is
                 ip-address range. */
              proto = 0;
              start_port = 0;
              end_port = 65535;
              if (*str == ',')
                str++;
              goto ip_check;
            }
        }
      IKE_SKIP_WHITESPACE(str);
      /* Try to see if there is port numbers. */
      if (*str == ':')
        {
          /* Yes. */
          str++;
          /* First check for any and opaque. */
          if (strncasecmp(str, "any", 3) == 0)
            {
              start_port = 0;
              end_port = 65535;
              str += 3;
            }
          else if (strncasecmp(str, "opaque", 6) == 0)
            {
              start_port = 65535;
              end_port = 0;
              str += 6;
            }
          else
            {
              start_port = strtol(str, &endp, 0);
              if (endp == str || start_port > 65535)
                {
                  return NULL;
                }
              end_port = start_port;
              str = endp;
              IKE_SKIP_WHITESPACE(str);
              if (*str == '-')
                {
                  /* Do we have end port? */
                  str++;
                  end_port = strtol(str, &endp, 0);
                  if (endp == str || end_port > 65535)
                    {
                      return NULL;
                    }
                  str = endp;
                }
              if (end_port < start_port)
                return NULL;
            }
        }

      IKE_SKIP_WHITESPACE(str);
      if (*str++ != ',')
        {
          return NULL;
        }
    }

 ip_check:
  /* Ok, start parsing the ip-addresses. */
  IKE_SKIP_WHITESPACE(str);

  /* First we need to find the end of the address. */
  p = str;
  IKE_SKIP_IP_ADDR(str);
  if (str - p + 1 > sizeof(buf))
    {
      /* This cannot be valid IP address since is should fit
         to 64 bytes. */
      return NULL;
    }
  memcpy(ssh_ustr(buf), p, str - p);
  buf[str - p] = '\0';

  if (!ssh_ipaddr_parse(start_address, ssh_ustr(buf)))
    {
      return NULL;
    }

  /* Copy the address, so if we only have one address we
     have range of 1 address. */
  *end_address = *start_address;

  IKE_SKIP_WHITESPACE(str);
  if (*str == '/')
    {
      int mask_size, i, len;

      /* Subnet format. */
      str++;
      mask_size = strtol(str, &endp, 0);
      if (endp == str)
        {
          return NULL;
        }
      str = endp;

      if ((SSH_IP_IS6(start_address) && mask_size > 128) ||
          (SSH_IP_IS4(start_address) && mask_size > 32) ||
          mask_size < 0)
        {
          return NULL;
        }
      /* We don't have to do anything when mask size is 32 for IPv4 and 128
         for IPv6 because start and end addresses are the same. By doing this
         we also avoid out-of-bounds write to SshIpAddrRec structure if mask
         length is 128 in IPv6 case. */
      if ((SSH_IP_IS6(start_address) && mask_size < 128) ||
          (SSH_IP_IS4(start_address) && mask_size < 32))
        {
          i = mask_size / 8;

          SSH_IP_BYTEN(start_address, i) &=
              ~((1 << (8 - (mask_size % 8))) - 1);
          SSH_IP_BYTEN(end_address, i) |= ((1 << (8 - (mask_size % 8))) - 1);

          if (SSH_IP_IS4(start_address))
            len = 4;
          else
            len = 16;

          for(i++; i < len; i++)
            {
              SSH_IP_BYTEN(start_address, i) = 0x00;
              SSH_IP_BYTEN(end_address, i) = 0xff;
            }
        }
    }
  else if (*str == '-')
    {
      /* Range. */
      str++;
      IKE_SKIP_WHITESPACE(str);

      /* We need to find the end of second address. */
      p = str;
      IKE_SKIP_IP_ADDR(str);
      if (str - p + 1 > sizeof(buf))
        {
          /* This cannot be valid IP address since is should fit
             to 64 bytes. */
          return NULL;
        }
      memcpy(ssh_ustr(buf), p, str - p);
      buf[str - p] = '\0';

      if (!ssh_ipaddr_parse(end_address, ssh_ustr(buf)))
        {
          return NULL;
        }
    }

  if (SSH_IP_CMP(end_address, start_address) < 0)
    return NULL;

  /* Ok, the address must be parsed now. */
  IKE_SKIP_WHITESPACE(str);
  if (address_type != 0 && *str++ != ')')
    {
      return NULL;
    }

  if (ssh_ikev2_ts_item_add(ts, proto, start_address, end_address,
                            (SshUInt16) start_port,
                            (SshUInt16) end_port) != SSH_IKEV2_ERROR_OK)
    {
      return NULL;
    }
  IKE_SKIP_WHITESPACE(str);
  return str;
}

/* Function to convert string back to traffic selector. This
   function is given traffic selector and items from the
   string are added to that traffic selector. Will return
   number of items added, or -1 if there was an error. */
int ssh_ikev2_string_to_ts(const char *str, SshIkev2PayloadTS ts)
{
  int i;

  i = 0;
  do {
    str = ssh_ikev2_string_to_ts_item(str, ts);
    if (str == NULL)
      return -1;
    i++;
    if (*str == 0)
      return i;
    if (*str++ != ',')
      return -1;
  } while (1);
}

/* Return TRUE if the `sub_item' is subrange of `item'. */
Boolean ssh_ikev2_ts_match_range(SshIkev2PayloadTSItem item,
                                 SshIkev2PayloadTSItem sub_item)
{
  /* Verify type first. */
  if (item->ts_type != sub_item->ts_type)
    return FALSE;
  /* Verify that protocol is same, or the item protocol is
     ANY. */
  if (item->proto != sub_item->proto &&
      item->proto != 0)
    return FALSE;
  /* Compare addresses. */
  if (SSH_IP_CMP(item->start_address, sub_item->start_address) > 0)
    return FALSE;
  if (SSH_IP_CMP(item->end_address, sub_item->end_address) < 0)
    return FALSE;
  /* First check if start_port and end_port are identical.
     This will make sure that ANY and OPAQUE match properly.
     Note, that OPAQUE is only subset of OPAQUE. */
  if (item->start_port == sub_item->start_port &&
      item->end_port == sub_item->end_port)
    return TRUE;
  /* Check if the item or sub_item is opaque, if so it will
     not match to any other than exact match. */
  if (item->start_port > item->end_port ||
      sub_item->start_port > sub_item->end_port)
    return FALSE;
  if (item->start_port > sub_item->start_port)
    return FALSE;
  if (item->end_port < sub_item->end_port)
    return FALSE;
  return TRUE;
}

/* Return TRUE if the `item1' and `item2' has overlapping
   area, i.e. their intersection is not empty. */
Boolean ssh_ikev2_ts_match_overlap(SshIkev2PayloadTSItem item1,
                                   SshIkev2PayloadTSItem item2)
{
  SshIpAddr start_address;
  SshIpAddr end_address;

  /* Verify type first. */
  if (item1->ts_type != item2->ts_type)
    return FALSE;
  /* Verify that protocol is same, or the item protocol is
     ANY. */
  if (item1->proto != item2->proto &&
      item1->proto != 0 && item2->proto != 0)
    return FALSE;

  /* Calculate intersection of ports. */
  /* Check if they are same, this will take care of any
     port, and opaque case. */
  if (item1->start_port != item2->start_port ||
      item1->end_port != item2->end_port)
    {
      SshUInt16 start_port;
      SshUInt16 end_port;

      start_port = SSH_MAX(item1->start_port, item2->start_port);
      end_port = SSH_MIN(item1->end_port, item2->end_port);
      if (start_port > end_port)
        return FALSE;
    }

  /* Calculate intersection of ip-addresses. */
  start_address = SSH_IP_MAX(item1->start_address, item2->start_address);
  end_address = SSH_IP_MIN(item1->end_address, item2->end_address);

  if (SSH_IP_CMP(start_address, end_address) > 0)
    return FALSE;
  return TRUE;
}

/* Modify the item1 to include also item2, if they can be
   merged together. Return TRUE if item1 now includes item2
   also, and otherwise return FALSE and do not modify item1
   or item2. */
Boolean ssh_ikev2_ts_merge(SshIkev2PayloadTSItem item1,
                           SshIkev2PayloadTSItem item2)
{
  SshIpAddr start_address;
  SshIpAddr end_address;
  SshUInt16 start_port;
  SshUInt16 end_port;

  /* Verify type first. */
  if (item1->ts_type != item2->ts_type)
    return FALSE;
  /* Verify that protocol is same, or the item protocol is
     ANY. */
  if (item1->proto != item2->proto)
    return FALSE;

  /* Calculate intersection of ports. */
  /* Check if they are same, this will take care of any
     port, and opaque case. */
  if (item1->start_port != item2->start_port ||
      item1->end_port != item2->end_port)
    {
      start_port = SSH_MAX(item1->start_port, item2->start_port);
      end_port = SSH_MIN(item1->end_port, item2->end_port);
      if (start_port > end_port)
        return FALSE;
      /* There is overlap in ports, so calculate the max
         port range. */
      start_port = SSH_MIN(item1->start_port, item2->start_port);
      end_port = SSH_MAX(item1->end_port, item2->end_port);
    }
  else
    {
      /* Port numbers are same, so use them. This will take
         care of opaque also as opaque can only be merged
         with another opaque rule. */
      start_port = item1->start_port;
      end_port = item1->end_port;
    }

  /* Calculate intersection of ip-addresses. */
  start_address = SSH_IP_MAX(item1->start_address, item2->start_address);
  end_address = SSH_IP_MIN(item1->end_address, item2->end_address);

  if (SSH_IP_CMP(start_address, end_address) > 0)
    return FALSE;

  /* There is overlap in the address, so calculate the max
     address range. */
  item1->start_port = start_port;
  item1->end_port = end_port;
  if (SSH_IP_CMP(item2->start_address, item1->start_address) < 0)
    *item1->start_address = *item2->start_address;
  if (SSH_IP_CMP(item1->end_address, item2->end_address) < 0)
    *item1->end_address = *item2->end_address;
  return TRUE;
}

/* Return TRUE if the `item' is valid subrange of the `ts'. */
Boolean ssh_ikev2_ts_match_ts(SshIkev2PayloadTS ts,
                              SshIkev2PayloadTSItem item)
{
  int i;

  for(i = 0; i < ts->number_of_items_used; i++)
    {
      if (ssh_ikev2_ts_match_range(&(ts->items[i]), item))
        return TRUE;
    }
  return FALSE;
}

/* Return TRUE if the `sub_ts' is valid subrange of the `ts'. */
Boolean ssh_ikev2_ts_match(SshIkev2PayloadTS ts,
                           SshIkev2PayloadTS sub_ts)
{
  int i;

  for(i = 0; i < sub_ts->number_of_items_used; i++)
    {
      if (!ssh_ikev2_ts_match_ts(ts, &(sub_ts->items[i])))
        return FALSE;
    }
  return TRUE;
}

/* Return TRUE if ts_1 and ts_2 are equal. */
Boolean ssh_ikev2_ts_equal(SshIkev2PayloadTS ts_1,
                           SshIkev2PayloadTS ts_2)
{

  return ssh_ikev2_ts_match(ts_1, ts_2) && ssh_ikev2_ts_match(ts_2, ts_1);
}

/* Add given item to the traffic selector. */
SshIkev2Error
ssh_ikev2_ts_item_add_item(SshIkev2PayloadTS ts,
                           SshIkev2PayloadTSItem item)
{
  return
    ssh_ikev2_ts_item_add(ts, item->proto,
                          item->start_address, item->end_address,
                          item->start_port, item->end_port);
}

/* Add intersection of two given items to the traffic selector. */
SshIkev2Error
ssh_ikev2_ts_item_add_intersection(SshIkev2PayloadTS ts,
                                   SshIkev2PayloadTSItem item1,
                                   SshIkev2PayloadTSItem item2)
{
  SshInetIPProtocolID proto;
  SshIpAddr start_address;
  SshIpAddr end_address;
  SshUInt16 start_port;
  SshUInt16 end_port;

  if (item1->ts_type != item2->ts_type)
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;

  /* Calculate intersection of protocol. */
  if (item1->proto == item2->proto)
    proto = item1->proto;
  else if (item1->proto == 0)
    proto = item2->proto;
  else if (item2->proto == 0)
    proto = item1->proto;
  else
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;

  /* Calculate intersection of ports. */
  /* Check if they are same, this will take care of any
     port, and opaque case. */
  if (item1->start_port == item2->start_port &&
      item1->end_port == item2->end_port)
    {
      start_port = item1->start_port;
      end_port = item1->end_port;
    }
  else
    {
      start_port = SSH_MAX(item1->start_port, item2->start_port);
      end_port = SSH_MIN(item1->end_port, item2->end_port);
      if (start_port > end_port)
        return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  /* Calculate intersection of ip-addresses. */
  start_address = SSH_IP_MAX(item1->start_address, item2->start_address);
  end_address = SSH_IP_MIN(item1->end_address, item2->end_address);

  if (SSH_IP_CMP(start_address, end_address) > 0)
    return SSH_IKEV2_ERROR_INVALID_ARGUMENT;

  return ssh_ikev2_ts_item_add(ts, proto, start_address, end_address,
                               start_port, end_port);
}

/* Remove duplicate items from the traffic selector ts. Returns FALSE on
   error and TRUE otherwise. */
Boolean ssh_ikev2_ts_remove_duplicate_items(SshSADHandle sad_handle,
                                            SshIkev2PayloadTS ts)
{
  int i, j;

 restart:
  for(i = 0; i < ts->number_of_items_used; i++)
    {
      for(j = i + 1; j < ts->number_of_items_used; j++)
        {
          /* If the later item is completely covered by the
             earlier item, then remove the later item. */
          if (ssh_ikev2_ts_match_range(&(ts->items[i]), &(ts->items[j])))
            {
              if (ssh_ikev2_ts_item_delete(ts, j) != SSH_IKEV2_ERROR_OK)
                return FALSE;
              goto restart;
            }

          /* If the earlier item is completely covered by the
             later item, then remove the earlier item. */
          if (ssh_ikev2_ts_match_range(&(ts->items[j]), &(ts->items[i])))
            {
              if (ssh_ikev2_ts_item_delete(ts, i) != SSH_IKEV2_ERROR_OK)
                return FALSE;
              goto restart;
            }
        }
    }
  return TRUE;
}

/* Allocate new traffic selector, and calculate intersection
   from of proposed_ts and policy_ts to it. This means that we
   first copy all items from proposed_ts to it, and then remove
   all items which are not in policy_ts, and narrow other
   subsets to be proper subsets of policy_ts. This can also
   split items in the new_ts if required to return maximal
   selectors. The first traffic selector item of the new_ts
   will always be the one that contains the first item from
   the proposed_ts, i.e. the information from the packet.
   Return FALSE if no intersection can be found (i.e.
   proposed_ts and policy_ts do not have any common elements),
   otherwise it will return TRUE. If implementation only
   supports one traffic selector, then it can take the first
   item from the new_ts, and send
   SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE.
 */
Boolean ssh_ikev2_ts_narrow(SshSADHandle sad_handle,
                            Boolean require_match_to_first_ts,
                            SshIkev2PayloadTS *new_ts,
                            SshIkev2PayloadTS proposed_ts,
                            SshIkev2PayloadTS policy_ts)
{
  SshIkev2PayloadTS ts;
  int policy, proposed;
  Boolean match_all_ts = FALSE;

  /* First find the superset item from policy that contains
     the first item from proposal. */
  for (policy = 0; policy < policy_ts->number_of_items_used; policy++)
    {
      if (ssh_ikev2_ts_match_range(&(policy_ts->items[policy]),
                                   &(proposed_ts->items[0])))
        {
          break;
        }
    }
  if (policy == policy_ts->number_of_items_used)
    {
      /* If that was not found, then it might be that the
         first item in the list is not exact set, but item
         from policy, and we have narrower policy in our
         end. See if we can find policy entry which has some
         overlap with the first item. */
      for (policy = 0; policy < policy_ts->number_of_items_used; policy++)
        {
          if (ssh_ikev2_ts_match_overlap(&(policy_ts->items[policy]),
                                         &(proposed_ts->items[0])))
            {
              break;
            }
        }
      /* If we didn't find any items from the policy which
         have overlap for the first item from the proposal
         list this means we cannot fulfill the policy. */
      if (policy == policy_ts->number_of_items_used)
        {
          if (require_match_to_first_ts)
            return FALSE;
          else
            match_all_ts = TRUE;
        }
    }


  /* Duplicate the ts from the other end. */
  ts = ssh_ikev2_ts_allocate(sad_handle);
  if (ts == NULL)
    return FALSE;

  if (!match_all_ts)
    {
      /* Next find the superset from proposals for the first
         item from proposal. */
      for (proposed = 1;
           proposed < proposed_ts->number_of_items_used;
           proposed++)
        {
          if (ssh_ikev2_ts_match_range(&(proposed_ts->items[proposed]),
                                       &(proposed_ts->items[0])))
            {
              break;
            }
        }
      if (proposed != proposed_ts->number_of_items_used)
        {
          /* Found superset, put that as first with intersection
             of the corresponding policy ts. */
          if (ssh_ikev2_ts_item_add_intersection(
                       ts,
                       &(proposed_ts->items[proposed]),
                       &(policy_ts->items[policy])) !=
              SSH_IKEV2_ERROR_OK)
            goto error;
        }
    }

  /* Now copy all items which are not already covered by items in the ts to
     there. */
  for (proposed = 0; proposed < proposed_ts->number_of_items_used; proposed++)
    {
      for(policy = 0; policy < policy_ts->number_of_items_used; policy++)
        {
          /* Find the matching item from policy, ignore the
             errors because it cannot calculate
             intersections. Also ignore memory errors, as we
             still have the first item in the list which
             makes this proper anyway. */
          ssh_ikev2_ts_item_add_intersection(ts,
                                             &(proposed_ts->items[proposed]),
                                             &(policy_ts->items[policy]));
        }
    }

  if (!ssh_ikev2_ts_remove_duplicate_items(sad_handle, ts))
    goto error;

  if (ts->number_of_items_used == 0)
    {
      /* There is no intersection */
      goto error;
    }

  if (new_ts)
    *new_ts = ts;
  else
    ssh_ikev2_ts_free(sad_handle, ts);
  return TRUE;
 error:
  ssh_ikev2_ts_free(sad_handle, ts);
  return FALSE;
}

/* Add a traffic selector `add_ts' to the `union_ts', i.e.
   calculate the union of `union_ts' and `add_ts' so that
   the `union_ts' is modified to include `add_ts'. The union
   is calculated so that it should have quite small number
   of items, i.e. the new item is merged with some existing
   ones. Note, that this does not try to merge other items
   inside the `union_ts' together, i.e. if there is item1,
   and item2 there and there is hole between them, and
   add_ts fills that hole, then add_ts is added to the
   item1, but item2 is not merged to item1. */
SshIkev2Error ssh_ikev2_ts_union(SshSADHandle sad_handle,
                                 SshIkev2PayloadTS union_ts,
                                 SshIkev2PayloadTS add_ts)
{
  SshIkev2Error error;
  int i, j;

  for(i = 0; i < add_ts->number_of_items_used; i++)
    {
      for(j = 0; j < union_ts->number_of_items_used; j++)
        {
          /* Try to combine it to existing item. */
          if (ssh_ikev2_ts_merge(&(union_ts->items[j]),
                                 &(add_ts->items[i])))
            {
              /* Succeded. */
              break;
            }
        }
      if (j == union_ts->number_of_items_used)
        {
          /* We couldn't add it to existing items, add it to
             end. */
          error = ssh_ikev2_ts_item_add_item(union_ts, &(add_ts->items[i]));
          if (error != SSH_IKEV2_ERROR_OK)
            return error;
        }
    }
  /* Remove the duplicate items from the final item. */
  for(i = 0; i < union_ts->number_of_items_used; i++)
    {
      for(j = i + 1; j < union_ts->number_of_items_used; j++)
        {
          /* If the later item can be combined to the first
             one, combine them. */
          if (ssh_ikev2_ts_merge(&(union_ts->items[i]), &(union_ts->items[j])))
            {
              error = ssh_ikev2_ts_item_delete(union_ts, j);
              if (error != SSH_IKEV2_ERROR_OK)
                return error;
              /* Now we need to check this again, so
                 decrement j, and continue. */
              j--;
              continue;
            }
          /* If the first item can be combined with the later one, combine
             them. */
          if (ssh_ikev2_ts_merge(&(union_ts->items[j]), &(union_ts->items[i])))
            {
              error = ssh_ikev2_ts_item_delete(union_ts, i);
              if (error != SSH_IKEV2_ERROR_OK)
                return error;
              /* Now we need to check this again, so
                 decrement i, and goto out from inner loop. */
              i--;
              break;
            }
        }
    }
  return SSH_IKEV2_ERROR_OK;
}

/* Exclude `higher_ts' from the `lower_ts', i.e. make a hole
   of size of `higher_ts' to the `lower_ts'. After this call
   the intersection of `higher_ts' and `lower_ts' is empty.
   This will modify the `lower_ts'. */
SshIkev2Error ssh_ikev2_ts_exclude(SshSADHandle sad_handle,
                                   SshIkev2PayloadTS lower_ts,
                                   SshIkev2PayloadTS higher_ts)
{
  SshIkev2PayloadTSItem item1, item2;
  SshIpAddrStruct orig_start[1], orig_end[1], temp[1];
  SshInetIPProtocolID proto;
  SshIpAddr start_address;
  SshIpAddr end_address;
  SshUInt16 start_port;
  SshUInt16 end_port;
  SshIkev2Error error;
  SshIkev2Error status;
  Boolean item1_used;
  int i, j;

  status = SSH_IKEV2_ERROR_OK;
  for(i = 0; i < higher_ts->number_of_items_used; i++)
    {
      item2 = &(higher_ts->items[i]);
      for(j = 0; j < lower_ts->number_of_items_used; j++)
        {
          item1 = &(lower_ts->items[j]);
          /* Verify type first. */
          if (item1->ts_type != item2->ts_type)
            continue;
          /* Verify that protocol is same, or the item protocol is
             ANY. */
          if (item1->proto != item2->proto &&
              item1->proto != 0 && item2->proto != 0)
            continue;

          /* Calculate intersection of ports. */
          /* Check if they are same, this will take care of any
             port, and opaque case. */
          if (item1->start_port != item2->start_port ||
              item1->end_port != item2->end_port)
            {
              start_port = SSH_MAX(item1->start_port, item2->start_port);
              end_port = SSH_MIN(item1->end_port, item2->end_port);
              if (start_port > end_port)
                continue;
            }
          start_port = item1->start_port;
          end_port = item1->end_port;

          /* Calculate intersection of ip-addresses. */
          start_address =
            SSH_IP_MAX(item1->start_address, item2->start_address);
          end_address =
            SSH_IP_MIN(item1->end_address, item2->end_address);

          if (SSH_IP_CMP(start_address, end_address) > 0)
            continue;

          *orig_start = *item1->start_address;
          *orig_end = *item1->end_address;
          proto = item1->proto;

          item1_used = FALSE;
          /* Ok, we now have overlapping section, first
             check the ip_addresses before hole.  */
          if (SSH_IP_CMP(orig_start, item2->start_address) < 0)
            {
              /* There is items left to hole, use the item1
                 to store that. */
              *item1->end_address = *item2->start_address;
              ssh_ipaddr_decrement(item1->end_address);
              item1_used = TRUE;
            }
          *orig_start = *(item2->start_address);
          /* Check if we have ip_addresses after hole. */

          if (SSH_IP_CMP(item2->end_address, orig_end) < 0)
            {
              *temp = *item2->end_address;
              ssh_ipaddr_increment(temp);
              /* Yes, add item. */
              if (item1_used)
                {
                  error =
                    ssh_ikev2_ts_item_add(lower_ts, proto,
                                          temp, orig_end,
                                          start_port, end_port);
                  if (error != SSH_IKEV2_ERROR_OK)
                    return error;
                }
              else
                {
                  *item1->start_address = *temp;
                  item1_used = TRUE;
                }
            }
          *orig_end = *(item2->end_address);

          /* Check if we have ports in the ip range lower to
             the hole. */
          if (start_port < item2->start_port)
            {
              /* Yes. */
              if (item1_used)
                {
                  error =
                    ssh_ikev2_ts_item_add(lower_ts, proto,
                                          orig_start, orig_end,
                                          start_port,
                                          (SshUInt16) (item2->start_port - 1));
                  if (error != SSH_IKEV2_ERROR_OK)
                    return error;
                }
              else
                {
                  item1->end_port = item2->start_port - 1;
                  item1_used = TRUE;
                }
            }

          /* Check if we have ports in the ip range higher
             to the hole. */
          if (end_port > item2->end_port)
            {
              /* Yes. */
              if (item1_used)
                {
                  error =
                    ssh_ikev2_ts_item_add(lower_ts, proto,
                                          orig_start, orig_end,
                                          (SshUInt16) (item2->end_port + 1),
                                          end_port);
                  if (error != SSH_IKEV2_ERROR_OK)
                    return error;
                }
              else
                {
                  item1->start_port = item2->end_port + 1;
                  item1_used = TRUE;
                }
            }

          /* Ok, check if we actually used the item1, or do
             it need to be removed. */
          if (!item1_used)
            {
              /* We didn't use it, so the whole lower_ts was
                 inside the hole, and should be removed. */
              error = ssh_ikev2_ts_item_delete(lower_ts, j);
              if (error != SSH_IKEV2_ERROR_OK)
                return error;

              /* As we removed the item, we need to try
                 again with the j'th item, so decrement j
                 now. */
              j--;
            }
          else
            {
              /* NOTE: we would need to add a new range which
                 will cover the hole with the non
                 item2->proto, but as we do not have
                 protocol ranges, we cannot. */
              if (proto == 0 && item2->proto != 0)
                status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
            }
        }
    }
  return status;
}

/** Calculate hash value of 'id'. This returns a hash value that can be
    used in hash table insertion and lookup. The returned hash cannot be
    used alone for comparing two SshIkev2PayloadID objects as this does
    not guarantee uniqueness of the hash value. */
SshUInt32
ssh_ikev2_payload_id_hash(SshIkev2PayloadID id)
{
  int i;
  SshUInt32 h = 0;

  if (id)
    {
      h = id->id_type;
      for (i = 0; i < id->id_data_size; i++)
        {
          h += id->id_data[i];
          h += h << 10;
          h ^= h >> 6;
        }
      h += h << 3;
      h ^= h >> 11;
      h += h << 15;
    }

  return h;
}
