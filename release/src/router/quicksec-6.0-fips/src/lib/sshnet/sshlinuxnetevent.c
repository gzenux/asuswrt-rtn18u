/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linux implementation of the sshnetevent.h API. This implementation
   uses the Linux netlink socket and the SSH eventloop.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetevent.h"
#include "ssheloop.h"

#ifdef SSHDIST_PLATFORM_LINUX
#ifdef __linux__

#include "sshlinuxnetconfig_i.h"
#include <linux/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifndef NETLINK_ROUTE
#error "sshlinuxnetevent.c requires NETLINK_ROUTE"
#endif /* !NETLINK_ROUTE */

#define SSH_DEBUG_MODULE "SshLinuxNetevent"


/************************** Event Listener Handle ****************************/

struct SshNetconfigEventHandleRec
{
  int s;
  struct sockaddr_nl addr;
  SshNetconfigEventCallback callback;
  void *callback_context;
};


/******************* IO callback for the netlink socket **********************/

void netconfig_event_callback(unsigned int events, void *context)
{
  SshNetconfigEventHandle handle = context;
  struct sockaddr_nl nladdr;
  unsigned char message_buf[4096];
  struct nlmsghdr *nh;
  struct iovec iov;
  struct msghdr msg;
  struct nlmsgerr *errmsg;
  int res, offset;
  int nl_error;
  SshNetconfigEvent netconfig_event = SSH_NETCONFIG_EVENT_LAST;
  SshUInt32 ifnum;

  if (events & SSH_IO_READ)
    {
      do {

        /* Read a netlink message from the kernel, for some very odd reason
           recvmsg() seemed to work better in this instance during
           testing.. */
        msg.msg_name = (struct sockaddr *) &nladdr;
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        iov.iov_base = message_buf;
        iov.iov_len = sizeof(message_buf);

        res = recvmsg(handle->s, &msg, 0);
        if (res <= 0)
          {
            SSH_DEBUG(SSH_D_FAIL, ("recvmsg() failed"));
            goto out;
          }

        /* This message may contain several netlink messages concatenated. */
        nh = NULL;
        for (offset = 0; offset < res; offset += nh->nlmsg_len)
          {
            nh = (struct nlmsghdr *)((unsigned char *) message_buf + offset);
            ifnum = SSH_INVALID_IFNUM;

            if (nh->nlmsg_len == 0)
              {
                SSH_DEBUG(SSH_D_ERROR,
                          ("Received netlink message of length 0.."));
                goto out;
              }

            if (nh->nlmsg_type == NLMSG_ERROR)
              {
                /* Acknowledgements are sent with errorcode 0. */
                errmsg = NLMSG_DATA(nh);
                nl_error = errmsg->error;
                if (nl_error)
                  {
                    SSH_DEBUG(SSH_D_ERROR,
                              ("PF_NETLINK/NETLINK_ROUTE request "
                               "returned error %d", errmsg->error));
                  }
                continue;
              }
            else if (nh->nlmsg_type == RTM_GETLINK
                     || nh->nlmsg_type == RTM_NEWLINK
                     || nh->nlmsg_type == RTM_DELLINK)
              {
                struct ifinfomsg *ifi = (struct ifinfomsg *) NLMSG_DATA(nh);
                ifnum = SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifi->ifi_index);
                netconfig_event = SSH_NETCONFIG_EVENT_LINK_CHANGED;
              }
            else if (nh->nlmsg_type == RTM_GETADDR
                     || nh->nlmsg_type == RTM_NEWADDR
                     || nh->nlmsg_type == RTM_DELADDR)
              {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nh);
                ifnum = SSH_LINUX_NETCONFIG_IF_INDEX_TO_IFNUM(ifa->ifa_index);
                netconfig_event = SSH_NETCONFIG_EVENT_ADDRESS_CHANGED;
              }
            else if (nh->nlmsg_type == RTM_GETROUTE
                     || nh->nlmsg_type == RTM_NEWROUTE
                     || nh->nlmsg_type == RTM_DELROUTE)
              {
                ifnum = SSH_INVALID_IFNUM;
                netconfig_event = SSH_NETCONFIG_EVENT_ROUTES_CHANGED;
              }

            if (netconfig_event == SSH_NETCONFIG_EVENT_LINK_CHANGED
                || netconfig_event == SSH_NETCONFIG_EVENT_ADDRESS_CHANGED
                || netconfig_event == SSH_NETCONFIG_EVENT_ROUTES_CHANGED)
              {
                /* Call event callback. */
                (*handle->callback)(netconfig_event, ifnum,
                                    handle->callback_context);
              }

            if (nh->nlmsg_type == NLMSG_DONE)
              goto out;
          }
      } while((nh != NULL) && (nh->nlmsg_flags & NLM_F_MULTI) != 0);
    }
 out:
  ssh_io_set_fd_request(handle->s, SSH_IO_READ);
  return;
}


/******************* Event callback registration / unregistration ***********/

SshNetconfigEventHandle
ssh_netconfig_register_event_callback(SshNetconfigEventCallback callback,
                                      void *context)
{
  SshNetconfigEventHandle handle;
  int s = -1;

  handle = ssh_calloc(1, sizeof(*handle));
  if (handle == NULL)
    goto fail;

  handle->callback = callback;
  handle->callback_context = context;

  s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (s < 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to open PF_NETLINK/NETLINK_ROUTE socket"));
      goto fail;
    }
  handle->s = (SshIOHandle) s;

  handle->addr.nl_family = AF_NETLINK;
  handle->addr.nl_groups =
    RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
#ifdef WITH_IPV6
  handle->addr.nl_groups |= RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
#endif /* WITH_IPV6 */

  if (bind(s, (struct sockaddr *) &handle->addr, sizeof(handle->addr)))
    goto fail;

  if (!ssh_io_register_fd(s, netconfig_event_callback, handle))
    goto fail;

  ssh_io_set_fd_request(handle->s, SSH_IO_READ);

  return handle;

 fail:
  if (s >= 0)
    close(s);
  if (handle)
    ssh_free(handle);

  return NULL;
}

SshNetconfigError
ssh_netconfig_unregister_event_callback(SshNetconfigEventHandle handle)
{
  if (handle == NULL)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ssh_io_unregister_fd(handle->s, FALSE);
  close(handle->s);
  ssh_free(handle);

  return SSH_NETCONFIG_ERROR_OK;
}

#endif /* __linux__ */
#endif /* SSHDIST_PLATFORM_LINUX */
