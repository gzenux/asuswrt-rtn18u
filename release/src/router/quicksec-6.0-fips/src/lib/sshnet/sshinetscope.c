/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP Scope ID related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetScope"

#ifdef WITH_IPV6

#ifdef KERNEL
Boolean
ssh_ipaddr_resolve_scope_id(SshScopeId scope, const unsigned char *id)
{
  return TRUE;
}
#else /* not KERNEL */

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(sun) ||\
  defined(VXWORKS_IPV6)

#include <sys/socket.h>
#include <net/if.h>

/* Resolve the scope ID into `id' from the `ip' and `scope_id'. */
Boolean
ssh_ipaddr_resolve_scope_id(SshScopeId scope, const unsigned char *id)
{
  /* If scope has already been resolved into number, e.g. parse, print, parse
     sequence is performed. */
  if (isdigit(*id))
    {
      scope->scope_id_union.ui32 = strtoul(ssh_csstr(id), NULL, 10);
      return TRUE;
    }

  scope->scope_id_union.ui32 = if_nametoindex(ssh_csstr(id));
  if (scope->scope_id_union.ui32 == 0)
    return FALSE;

  return TRUE;
}

#else /* not __NetBSD__ and not __FreeBSD__ and not sun */
#ifdef __linux__

#include <linux/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifdef NETLINK_ROUTE
struct SshLinuxNetlinkLinkRequestRec
{
  struct nlmsghdr nh;    /* Netlink message header */
  struct ifinfomsg info; /* GETLINK payload */
  char buf[128];         /* Some pad for netlink alignment macros */
};
#endif /* NETLINK_ROUTE */

Boolean
ssh_ipaddr_resolve_scope_id(SshScopeId scope, const unsigned char *id)
{
#ifdef NETLINK_ROUTE
  int sd;
  struct SshLinuxNetlinkLinkRequestRec req;
  struct sockaddr_nl nladdr;
  unsigned char response_buf[4096];
  struct nlmsghdr *nh;
  struct iovec iov;
  struct msghdr msg;
  struct ifinfomsg *ifi_res;
  struct nlmsgerr *errmsg;
  struct rtattr *rta;
  int res, offset, offset2, addr_len, i;
  char *addr_buf;

  SSH_ASSERT(scope != NULL);
  SSH_ASSERT(id != NULL);

  for (i = 0; i < ssh_ustrlen(id); i++)
    {
      if (!isdigit(id[i]))
        goto hardway;
    }

  scope->scope_id_union.ui32 = strtoul((char *)id, NULL, 10);
  return TRUE;

 hardway:
  /* Open a netlink/route socket. This should not require root
     permissions or special capabilities. */
  sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sd < 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("failed to open PF_NETLINK/NETLINK_ROUTE socket"));
      goto fail;
    }

  /* Build a request for all interfaces */
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
  req.nh.nlmsg_type = RTM_GETLINK;
  req.nh.nlmsg_seq = 0;
  req.nh.nlmsg_pid = 0; /* Message is directed to kernel */

  req.info.ifi_family = AF_UNSPEC;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = 0; /* pid = 0 is kernel in nladdr sock */

  /* Send the request. This request should not require
     root permissions or any special capabilities. */
  if (sendto(sd, &req, req.nh.nlmsg_len, 0,
             (struct sockaddr*)&nladdr,
             (ssh_socklen_t) sizeof(nladdr)) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("sendto() of GETLINK request failed."));
      goto fail;
    }

  /* Parse replies from kernel */
  nh = NULL;
  do {
    /* Read a response from the kernel, for some very odd reason
       recvmsg() seemed to work better in this instance during
       testing.. */
    msg.msg_name = (struct sockaddr*)&nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iov.iov_base = response_buf;
    iov.iov_len = sizeof(response_buf);

    res = recvmsg(sd, &msg, 0);
    if (res <= 0)
      {
        SSH_DEBUG(SSH_D_FAIL, ("recvmsg() failed"));
        goto fail;
      }

    /* This response contains several netlink messages
       concatenated. */
    for (offset = 0; offset < res; offset += nh->nlmsg_len)
      {
        nh = (struct nlmsghdr *)((unsigned char*)response_buf + offset);

        if (nh->nlmsg_len == 0)
          {
            SSH_DEBUG(SSH_D_ERROR,
                      ("Received netlink message of length 0.."));
            goto fail;
          }

        if (nh->nlmsg_type == NLMSG_ERROR)
          {
            errmsg = NLMSG_DATA(nh);
            SSH_DEBUG(SSH_D_ERROR,
                      ("PF_NETLINK/NETLINK_ROUTE GETLINK request returned "
                       "error %d", errmsg->error));
            goto fail;
          }

        if (nh->nlmsg_type == RTM_GETLINK || nh->nlmsg_type == RTM_NEWLINK
            || nh->nlmsg_type == RTM_DELLINK)
          {
            ifi_res = (struct ifinfomsg *)NLMSG_DATA(nh);
            rta = NULL;
            for (offset2 = NLMSG_ALIGN(sizeof(struct ifinfomsg));
                 offset2 < nh->nlmsg_len;
                 offset2 += RTA_ALIGN(rta->rta_len))
              {
                rta = (struct rtattr *)(((unsigned char*)ifi_res) + offset2);

                if (RTA_ALIGN(rta->rta_len) == 0)
                  break;

                switch (rta->rta_type)
                  {
                  case IFLA_IFNAME:
                    addr_buf = ((char *)RTA_DATA(rta));
                    addr_len = RTA_PAYLOAD(rta);

                    if (strncmp((char *)id, addr_buf, addr_len) != 0)
                      break;

                    scope->scope_id_union.ui32 = ifi_res->ifi_index;
                    goto ok;

                    break;
                  default:
                    break;
                  }
              }
          }
        else
          {
            /* It does not matter if this is a message of type
               NLMSG_DONE or some other type, in either case
               if we have not jumped to "ok:", we have not found
               the correct interface. */
            goto fail;
          }
      }
  } while((nh != NULL) && (nh->nlmsg_flags & NLM_F_MULTI) != 0);

  SSH_DEBUG(SSH_D_FAIL,
            ("could not find interface for '%s'", id));
 fail:
  if (sd >= 0) close(sd);
#endif
  return FALSE;

#ifdef NETLINK_ROUTE
 ok:
  close(sd);
  return TRUE;
#endif /* NETLINK_ROUTE */
}
#else /* not __linux__ */

Boolean
ssh_ipaddr_resolve_scope_id(SshScopeId scope, const unsigned char *id)
{
  SSH_DEBUG(SSH_D_ERROR, ("Don't know how to resolve IPv6 link-local "
                          "address scope ID on this platform"));
  return FALSE;
}
#endif /* not __linux__ */
#endif /* not __NetBSD__ and not __FreeBSD__ and not sun */
#endif /* not KERNEL */
#endif /* WITH_IPV6 */
