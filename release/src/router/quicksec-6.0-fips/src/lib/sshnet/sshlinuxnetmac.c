/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linux implementation of the sshnetmac.h API.
*/

#include "sshincludes.h"
#include "sshnetmac.h"
#include "sshnetconfig.h"
#include "ssheloop.h"

#ifdef SSHDIST_PLATFORM_LINUX
#ifdef __linux__

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define SSH_DEBUG_MODULE "SshLinuxNetmac"

struct SshNetmacHandleRec
{
  SshUInt32 ifnum;
  SshUInt16 proto;
  SshNetmacReceiveCallback receive_callback;
  void *receive_context;
  int socket;
  unsigned char buffer[ETH_FRAME_LEN];
};

static
void netmac_io_callback(unsigned int events, void *context)
{
  SshNetmacHandle h = context;
  ssize_t length;
  struct ether_header *hdr;

  if (events & SSH_IO_READ)
    {
      if ((length = recv(h->socket, h->buffer, sizeof h->buffer, 0)) < 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed: recvfrom: %s", strerror(errno)));
          goto end;
        }
      if (length < sizeof *hdr)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Short MAC frame received"));
          goto end;
        }
      hdr = (void *)h->buffer;
      if (hdr->ether_type != htons(h->proto))
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC frame with wrong length/type received"));
          goto end;
        }
      SSH_DEBUG(SSH_D_LOWOK, ("MAC frame received, "
                              "dst %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
                              "src %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
                              "length/type 0x%04.4X, "
                              "data length %u",
                              hdr->ether_dhost[0], hdr->ether_dhost[1],
                              hdr->ether_dhost[2], hdr->ether_dhost[3],
                              hdr->ether_dhost[4], hdr->ether_dhost[5],
                              hdr->ether_shost[0], hdr->ether_shost[1],
                              hdr->ether_shost[2], hdr->ether_shost[3],
                              hdr->ether_shost[4], hdr->ether_shost[5],
                              (unsigned)h->proto,
                              (unsigned)(length - sizeof *hdr)));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Data"),
                        h->buffer + sizeof *hdr, length - sizeof *hdr);
      if (h->receive_callback)
        (*h->receive_callback)(hdr->ether_dhost,
                               hdr->ether_shost,
                               h->buffer + sizeof *hdr,
                               length - sizeof *hdr,
                               h->receive_context);
    }
 end:
  ssh_io_set_fd_request(h->socket, SSH_IO_READ);
  return;
}

SshNetconfigError
ssh_netmac_send(SshNetmacHandle h,
                const unsigned char *dst,
                const unsigned char *src,
                const unsigned char *data_buf,
                size_t data_len)
{
  struct ether_header *hdr;

  if (sizeof *hdr + data_len > sizeof h->buffer)
    {
      SSH_DEBUG(SSH_D_FAIL, ("MAC frame too large to send"));
      return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
    }

  hdr = (void *)h->buffer;
  memcpy(hdr->ether_dhost, dst, sizeof hdr->ether_dhost);
  memcpy(hdr->ether_shost, src, sizeof hdr->ether_shost);
  hdr->ether_type = htons(h->proto);
  memcpy(h->buffer + sizeof *hdr, data_buf, data_len);

  SSH_DEBUG(SSH_D_LOWOK, ("Sending MAC frame, "
                          "dst %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
                          "src %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
                          "length/type 0x%04.4X, "
                          "data length %u",
                          hdr->ether_dhost[0], hdr->ether_dhost[1],
                          hdr->ether_dhost[2], hdr->ether_dhost[3],
                          hdr->ether_dhost[4], hdr->ether_dhost[5],
                          hdr->ether_shost[0], hdr->ether_shost[1],
                          hdr->ether_shost[2], hdr->ether_shost[3],
                          hdr->ether_shost[4], hdr->ether_shost[5],
                          (unsigned)h->proto,
                          (unsigned)data_len));
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Data"),
                        h->buffer + sizeof *hdr, data_len);

  if (send(h->socket, h->buffer, sizeof *hdr + data_len, 0) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: send: %s", strerror(errno)));
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }
  return SSH_NETCONFIG_ERROR_OK;
}

SshNetmacHandle
ssh_netmac_register(SshUInt32 ifnum,
                    SshUInt16 proto,
                    SshNetmacReceiveCallback receive_callback,
                    void *receive_context)
{
  SshNetmacHandle h = NULL;
  struct ifreq ifr;
  struct sockaddr_ll addr;

  /* create handle and associated data */
  h = ssh_calloc(1, sizeof *h);
  if (h == NULL)
    goto fail;
  h->socket = -1;
  h->ifnum = ifnum;
  h->proto = proto;
  h->receive_callback = receive_callback;
  h->receive_context = receive_context;

  /* open socket */
  h->socket = socket(PF_PACKET, SOCK_RAW, htons(proto));
  if (h->socket < 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed: socket(PF_PACKET): %s", strerror(errno)));
      goto fail;
    }

  /* get interface name */
  memset(&ifr, 0, sizeof(ifr));
  if (ssh_netconfig_resolve_ifnum(ifnum, ifr.ifr_name, sizeof(ifr.ifr_name))
      != SSH_NETCONFIG_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to get name for interface %u", (unsigned)ifnum));
      goto fail;
    }
  if (ioctl(h->socket, SIOCGIFINDEX, &ifr))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed: ioctl(SIOCGIFINDEX): %s", strerror(errno)));
      goto fail;
    }

  /* configure interface and protocol */
  memset(&addr, 0, sizeof addr);
  addr.sll_family = PF_PACKET;
  addr.sll_ifindex = ifr.ifr_ifindex;
  addr.sll_protocol = htons(proto);
  if (bind(h->socket, (struct sockaddr *)&addr, sizeof addr) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed: bind(): %s", strerror(errno)));
      goto fail;
    }

  /* register socket in the event loop */
  if (!ssh_io_register_fd(h->socket, netmac_io_callback, h))
    goto fail;
  ssh_io_set_fd_request(h->socket, SSH_IO_READ);

  SSH_DEBUG(SSH_D_HIGHOK, ("Created MAC handle %p", h));
  return h;

 fail:
  if (h)
    {
      if (h->socket >= 0)
        close(h->socket);
      ssh_free(h);
    }

  return NULL;
}

SshNetconfigError
ssh_netmac_unregister(SshNetmacHandle h)
{
  if (h == NULL)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ssh_io_unregister_fd(h->socket, FALSE);
  close(h->socket);

  SSH_DEBUG(SSH_D_HIGHOK, ("Destroyed MAC handle %p", h));

  ssh_free(h);
  return SSH_NETCONFIG_ERROR_OK;
}

#endif /* __linux__ */
#endif /* SSHDIST_PLATFORM_LINUX */
