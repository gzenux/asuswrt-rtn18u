/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform independent code for sshnetconfig.h API.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetconfig.h"

/** Renders a SshNetconfigLink. */
int ssh_netconfig_link_render(unsigned char *buf, int buf_size, int precision,
                              void *datum)
{
  const SshNetconfigLink link = (SshNetconfigLink) datum;
  int len, consumed, fail_ret, i;

  fail_ret = buf_size + 1;
  len = 0;

  if (link == NULL)
    {
      consumed = ssh_snprintf(buf, buf_size + 1, "<null>");
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
    }
  else
    {
      consumed = ssh_snprintf(buf, buf_size + 1, "ifnum %ld", link->ifnum);
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
      if (precision >= 0 && len >= precision)
        goto out;
      buf += consumed;
      buf_size -= consumed;

      if (link->ifnum != link->iflink)
        {
          if (link->iflink == SSH_INVALID_IFNUM)
            consumed = ssh_snprintf(buf, buf_size + 1, " link <undefined>");
          else
            consumed = ssh_snprintf(buf, buf_size + 1,
                                    " link %ld", link->iflink);
          if (consumed < 0 || consumed >= buf_size)
            goto fail;
          len += consumed;
          if (precision >= 0 && len >= precision)
            goto out;
          buf += consumed;
          buf_size -= consumed;
        }

      if (link->addr_len > 0)
        {
          consumed = ssh_snprintf(buf, buf_size + 1, " addr ");
          if (consumed < 0 || consumed >= buf_size)
            goto fail;
          len += consumed;
          if (precision >= 0 && len >= precision)
            goto out;
          buf += consumed;
          buf_size -= consumed;
          for (i = 0; i < link->addr_len; i++)
            {
              consumed = ssh_snprintf(buf, buf_size + 1, "%02x%s",
                                      link->media_addr[i],
                                      i == link->addr_len - 1 ? "" : ":");
              if (consumed < 0 || consumed >= buf_size)
                goto fail;
              len += consumed;
              if (precision >= 0 && len >= precision)
                goto out;
              buf += consumed;
              buf_size -= consumed;
            }

          if (link->flags & SSH_NETCONFIG_LINK_BROADCAST)
            {
              consumed = ssh_snprintf(buf, buf_size + 1, " brd ");
              if (consumed < 0 || consumed >= buf_size)
                goto fail;
              len += consumed;
              if (precision >= 0 && len >= precision)
                goto out;
              buf += consumed;
              buf_size -= consumed;
              for (i = 0; i < link->addr_len; i++)
                {
                  consumed = ssh_snprintf(buf, buf_size + 1, "%02x%s",
                                          link->broadcast_addr[i],
                                          i == link->addr_len - 1 ? "" : ":");
                  if (consumed < 0 || consumed >= buf_size)
                    goto fail;
                  len += consumed;
                  if (precision >= 0 && len >= precision)
                    goto out;
                  buf += consumed;
                  buf_size -= consumed;
                }
            }
        }

      consumed = ssh_snprintf(buf, buf_size + 1, " mtu %d B <%s%s%s%s%s>",
                              link->mtu,
                              (link->flags & SSH_NETCONFIG_LINK_UP ?
                               "up " : ""),
                              (link->flags & SSH_NETCONFIG_LINK_LOOPBACK ?
                               "loopback " : ""),
                              (link->flags & SSH_NETCONFIG_LINK_BROADCAST ?
                               "broadcast " : ""),
                              (link->flags & SSH_NETCONFIG_LINK_POINTOPOINT ?
                               "pointopoint " : ""),
                              (link->flags & SSH_NETCONFIG_LINK_LOWER_DOWN ?
                               "lower-down" : ""));
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
      if (precision >= 0 && len >= precision)
        goto out;
      buf += consumed;
      buf_size -= consumed;

      if (link->speed > 0)
        {
          SshUInt32 speed = link->speed;
          SshUInt16 unit = 3;
          while (speed >= 1000 && unit <= 12)
            {
              unit += 3;
              speed /= 1000;
            }
          consumed = ssh_snprintf(buf, buf_size + 1,
                                  " speed %d%s <%s>",
                                  speed,
                                  (unit == 12 ? "Tbit/s" :
                                   (unit == 9 ? "Gbit/s" :
                                    (unit == 6 ? "Mbit/s" :
                                     (unit == 3 ? "kbit/s" : "bit/s")))),
                                  (link->properties
                                   & SSH_NETCONFIG_LINK_PROPERTY_HALF_DUPLEX ?
                                   "half-duplex" :
                                   (link->properties
                                    & SSH_NETCONFIG_LINK_PROPERTY_FULL_DUPLEX ?
                                    "full-duplex" : "unknown duplex")));
          if (consumed < 0 || consumed >= buf_size)
            goto fail;
          len += consumed;
        }
    }

 out:
  if (precision >= 0 && len > precision)
    len = precision;
  return len;

 fail:
  return fail_ret;
}



/** Renders a SshNetconfigRoute. */
int ssh_netconfig_route_render(unsigned char *buf, int buf_size, int precision,
                               void *datum)
{
  const SshNetconfigRoute route = (const SshNetconfigRoute) datum;
  int len, consumed, fail_ret;
  unsigned char addr_buf[SSH_IP_ADDR_STRING_SIZE];

  fail_ret = buf_size + 1;
  len = 0;

  if (route == NULL)
    {
      consumed = ssh_snprintf(buf, buf_size + 1, "<null>");
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
    }
  else
    {
      ssh_ipaddr_print(&route->prefix, addr_buf, sizeof(addr_buf));
      consumed = ssh_snprintf(buf, buf_size + 1, "%s/%d",
                              addr_buf, SSH_IP_MASK_LEN(&route->prefix));
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
      if (precision >= 0 && len >= precision)
        goto out;
      buf += consumed;
      buf_size -= consumed;

      if (SSH_IP_DEFINED(&route->gateway))
        {
          ssh_ipaddr_print(&route->gateway, addr_buf, sizeof(addr_buf));
          consumed = ssh_snprintf(buf, buf_size + 1, " via %s", addr_buf);
          if (consumed < 0 || consumed >= buf_size)
            goto fail;
          len += consumed;
          if (precision >= 0 && len >= precision)
            goto out;
          buf += consumed;
          buf_size -= consumed;
        }

      if (route->ifnum != SSH_INVALID_IFNUM)
        {
          consumed = ssh_snprintf(buf, buf_size + 1, " dev %ld", route->ifnum);
          if (consumed < 0 || consumed >= buf_size)
            goto fail;
          len += consumed;
          if (precision >= 0 && len >= precision)
            goto out;
          buf += consumed;
          buf_size -= consumed;
        }

      consumed = ssh_snprintf(buf, buf_size + 1, " metric %ld", route->metric);
      if (consumed < 0 || consumed >= buf_size)
        goto fail;
      len += consumed;
    }

 out:
  if (precision >= 0 && len > precision)
    len = precision;
  return len;

 fail:
  return fail_ret;
}
