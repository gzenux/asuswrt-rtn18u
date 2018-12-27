/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Virtual adapter functions for VxWorks.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#define END_MACROS

#include "sshincludes.h"
#include "virtual_adapter.h"
#include "icept_internal.h"
#include "icept_vxworks.h"

#include <endLib.h>
#include <muxLib.h>
#include <ifLib.h>
#if defined(WITH_IPV6) && defined(INET6)
#include <if6Lib.h>
#endif /* defined(WITH_IPV6) && defined(INET6) */
#include <etherLib.h>
#include <etherMultiLib.h>
#include <ipProto.h>
#include <taskLib.h>
#include <netLib.h>

#define SSH_DEBUG_MODULE "IceptVirtualAdapterVxworks"

/* Number of virtual interfaces to create */
#define VXWORKS_VA_NUM 2

/* Maximum number of IP addresses per interface */
#define VXWORKS_VA_MAX_IP4ADDRS 2
#if defined(WITH_IPV6) && defined(INET6)
#define VXWORKS_VA_MAX_IP6ADDRS 2
#endif /* defined(WITH_IPV6) && defined(INET6) */

typedef struct {
  /* Generic END part */
  END_OBJ end;
  /* Device name (device name prefix and unit number) */
  char name[END_NAME_MAX + 3];
  /* Cookie returned by muxDevLoad() */
  void *cookie;
  /* Ethernet address */
  unsigned char enet_addr[6];
  /* Interface number */
  SshInterceptorIfnum ifnum;
  /* Stuff from ssh_virtual_adapter_attach() */
  int attached;
  SshInterceptor interceptor;
  void *adapter_context;
  SshVirtualAdapterPacketCB packet_cb;
  SshVirtualAdapterDetachCB detach_cb;
  /* IPv4 addresses */
  char ip4addr_tab[VXWORKS_VA_MAX_IP4ADDRS][INET_ADDR_LEN];
  int ip4addr_num;
#if defined(WITH_IPV6) && defined(INET6)
  /* IPv6 addresses */
  char ip6addr_tab[VXWORKS_VA_MAX_IP6ADDRS][INET6_ADDR_LEN];
  int ip6addr_num;
#endif /* defined(WITH_IPV6) && defined(INET6) */
} VxWorksVa;

/* Device name prefix, must not be longer than END_NAME_MAX - 1 */
static char *vxworks_va_devname = "vip";

/* Device description */
static char *vxworks_va_desc = "Virtual IP Interface";

/* Ethernet address prefix */
static const unsigned char vxworks_va_oui[3] = {0x02, 0x00, 0x00};

/* MTU and speed */
static const int vxworks_va_mtu = 1400;
static const int vxworks_va_speed = 100000000;

/* Device data */
static VxWorksVa vxworks_va_tab[VXWORKS_VA_NUM];
static const int vxworks_va_num =
sizeof vxworks_va_tab / sizeof vxworks_va_tab[0];

/* Task id of tNetTask */
static int vxworks_va_nettask;

/* Counters for tracking the number of pending netJob messages */
static unsigned vxworks_va_sends_submitted; /* updated by any task */
static unsigned vxworks_va_sends_processed; /* updated by tNetTask */
/* Max difference of the counters above */
#define VXWORKS_VA_SENDS_MAX 2

static void vxworks_va_report(
  VxWorksVa *va,
  SshVirtualAdapterError error,
  SshVirtualAdapterStatusCB callback,
  void *context);
static VxWorksVa *vxworks_va_find_va(SshInterceptorIfnum ifnum);

static END_OBJ *vxworks_va_load(char *params, void *arg);

static STATUS vxworks_va_start(END_OBJ *end);
static STATUS vxworks_va_stop(END_OBJ *end);
static STATUS vxworks_va_unload(END_OBJ *end);
static int vxworks_va_ioctl(END_OBJ *end, int cmd, caddr_t data);
static STATUS vxworks_va_send(END_OBJ *end , M_BLK_ID m);
static STATUS vxworks_va_mcast_addr_add(END_OBJ *end, char *addr);
static STATUS vxworks_va_mcast_addr_del(END_OBJ *end, char *addr);
static STATUS vxworks_va_mcast_addr_get(END_OBJ *end, MULTI_TABLE *tab);

static void vxworks_va_send_sub(END_OBJ *end, M_BLK_ID m);

static NET_FUNCS vxworks_va_funcs = {
  vxworks_va_start,
  vxworks_va_stop,
  vxworks_va_unload,
  vxworks_va_ioctl,
  vxworks_va_send,
  vxworks_va_mcast_addr_add,
  vxworks_va_mcast_addr_del,
  vxworks_va_mcast_addr_get,
  NULL, /* polled send */
  NULL, /* polled receive */
  endEtherAddressForm,
  endEtherPacketDataGet,
  endEtherPacketAddrGet
};

/* Add virtual IP interfaces to the system. */
void ssh_vxworks_virtual_adapter_init(void)
{
  VxWorksVa *va;
  STATUS status;
  int i, started, ip_attached;
  void *cookie;
  unsigned short if_index;

  vxworks_va_nettask = taskIdSelf();

  for (i = 0; i < vxworks_va_num; i++)
    {
      va = &vxworks_va_tab[i];
      started = 0;
      ip_attached = 0;

      memset(va, 0, sizeof *va);

      ssh_snprintf(va->name, sizeof va->name, "%s%d", vxworks_va_devname, i);

      memset(va->enet_addr, 0, sizeof va->enet_addr);
      memcpy(va->enet_addr, vxworks_va_oui, sizeof vxworks_va_oui);
      va->enet_addr[sizeof va->enet_addr - 1] = (unsigned char)i;

      if (!(cookie = muxDevLoad(i, vxworks_va_load, "", FALSE, va)))
        {
          SSH_TRACE(SSH_D_ERROR, ("%s: muxDevLoad failed", va->name));
          goto fail;
        }

      if ((status = muxDevStart(cookie)) != OK)
        {
          SSH_TRACE(
            SSH_D_ERROR,
            ("%s: muxDevStart failed, status %d", va->name, (int)status));
          goto fail;
        }
      started = 1;

      if (ipAttach(i, vxworks_va_devname) != OK)
        {
          SSH_TRACE(SSH_D_ERROR, ("%s: ipAttach failed", va->name));
          goto fail;
        }
      ip_attached = 1;

#if defined(WITH_IPV6) && defined(INET6)
      if (ip6Attach(i, vxworks_va_devname) != OK)
        {
          SSH_TRACE(SSH_D_ERROR, ("%s: ip6Attach failed", va->name));
          goto fail;
        }
#endif /* defined(WITH_IPV6) && defined(INET6) */

      if (!(if_index = ifNameToIfIndex(va->name)))
        {
          SSH_TRACE(
            SSH_D_ERROR,
            ("%s: cannot get interface index after IP attach", va->name));
          goto fail;
        }

      va->ifnum = if_index - 1;
      va->cookie = cookie;

      continue;

    fail:
      if (ip_attached)
        ipDetach(i, vxworks_va_devname);

      if (started)
        muxDevStop(cookie);

      if (cookie)
        muxDevUnload(vxworks_va_devname, i);
    }
}

/* Remove virtual IP interfaces from the system. */
void ssh_vxworks_virtual_adapter_uninit(void)
{
  VxWorksVa *va;
  int i;
  STATUS status;

  for (i = 0; i < vxworks_va_num; i++)
    {
      va = &vxworks_va_tab[i];

      if (!va->cookie)
        continue;

#if defined(WITH_IPV6) && defined(INET6)
      if (ip6Detach(i, vxworks_va_devname) != OK)
        SSH_TRACE(SSH_D_ERROR, ("%s: ip6Detach failed", va->name));
#endif /* defined(WITH_IPV6) && defined(INET6) */

      if (ipDetach(i, vxworks_va_devname) != OK)
        SSH_TRACE(SSH_D_ERROR, ("%s: ipDetach failed", va->name));

      if ((status = muxDevStop(va->cookie)) != OK)
        SSH_TRACE(
          SSH_D_ERROR,
          ("%s: muxDevStop failed, status %d", va->name, (int)status));

      if ((status = muxDevUnload(vxworks_va_devname, i)) != OK)
        SSH_TRACE(
          SSH_D_ERROR,
          ("%s: muxDevUnload failed, status %d", va->name, (int)status));

      va->cookie = NULL;
    }
}

/* Send a packet to the IP stack like it was received by the virtual
   IP interface indexed by pp->ifnum_in. */
void ssh_virtual_adapter_send(SshInterceptor interceptor,
			      SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp;
  VxWorksVa *va;
  M_BLK_ID m;

  if (!(va = vxworks_va_find_va(pp->ifnum_out)))
    {
      SSH_TRACE(
        SSH_D_ERROR,
        ("trying to send to a nonexistent ifnum %d", (int)pp->ifnum_out));

      ssh_interceptor_packet_free(pp);
      return;
    }

  if (pp->protocol != SSH_PROTOCOL_ETHERNET)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: dropping non-ethernet packet", va->name));

      ssh_interceptor_packet_free(pp);
      return;
    }

  ipp = (void *)pp;
  m = ipp->head;
  ipp->head = NULL;
  ssh_interceptor_packet_free_header(ipp);

  SSH_DEBUG(
    SSH_D_LOWOK,
    ("feeding receive packet to %s, ifnum %d", va->name, (int)va->ifnum));

  END_RCV_RTN_CALL(&va->end, m);
}

/* Attach a virtual IP interface to the IPsec engine. */
void ssh_virtual_adapter_attach(
  SshInterceptor interceptor,
  SshInterceptorIfnum adapter_ifnum,
  SshVirtualAdapterPacketCB packet_cb,
  SshVirtualAdapterDetachCB detach_cb,
  void *adapter_context,
  SshVirtualAdapterStatusCB callback,
  void *context)
{
  VxWorksVa *va;
  SshVirtualAdapterDetachCB old_detach_cb;
  void *old_adapter_context;

  SSH_DEBUG(SSH_D_HIGHOK, ("attach ifnum %d", (int)adapter_ifnum));

  if (!(va = vxworks_va_find_va(adapter_ifnum)))
    {
      SSH_TRACE(
        SSH_D_ERROR,
        ("trying to attach a nonexistent ifnum %d", (int)adapter_ifnum));

      if (callback)
        callback(
          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
          adapter_ifnum,
          NULL,
          SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
          NULL,
          context);

      return;
    }

  if (va->detach_cb)
    {
      old_detach_cb = va->detach_cb;
      old_adapter_context = va->adapter_context;
      va->detach_cb = NULL;
      va->adapter_context = NULL;

      SSH_DEBUG(
        SSH_D_HIGHOK,
        ("calling detach_cb of %s, ifnum %d because of new attach",
         va->name, (int)va->ifnum));

      old_detach_cb(old_adapter_context);
    }

  va->adapter_context = adapter_context;
  va->packet_cb = packet_cb;
  va->detach_cb = detach_cb;
  va->interceptor = interceptor;
  va->attached = 1;

  SSH_DEBUG(
    SSH_D_HIGHOK, ("attached %s, ifnum %d", va->name, (int)va->ifnum));

  vxworks_va_report(va, SSH_VIRTUAL_ADAPTER_ERROR_OK, callback, context);
}

/* Detach a virtual IP interface from the IPsec engine. */
void ssh_virtual_adapter_detach(
  SshInterceptor interceptor,
  SshInterceptorIfnum adapter_ifnum,
  SshVirtualAdapterStatusCB callback,
  void *context)
{
  VxWorksVa *va;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;
  SshIpAddrStruct addr;

  SSH_DEBUG(SSH_D_HIGHOK, ("detach ifnum %d", (int)adapter_ifnum));

  if (!(va = vxworks_va_find_va(adapter_ifnum)))
    {
      SSH_TRACE(
        SSH_D_ERROR,
        ("trying to detach a nonexistent ifnum %d", (int)adapter_ifnum));

      if (callback)
        callback(
          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
          adapter_ifnum,
          NULL,
          SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
          NULL,
          context);

      return;
    }

  detach_cb = va->detach_cb;
  adapter_context = va->adapter_context;

  va->detach_cb = NULL;
  va->adapter_context = NULL;
  va->interceptor = NULL;
  va->attached = 0;

  if (detach_cb)
    {
      SSH_DEBUG(
        SSH_D_HIGHOK,
        ("calling detach_cb of %s, ifnum %d", va->name, (int)va->ifnum));

      detach_cb(adapter_context);
    }

  SSH_IP_UNDEFINE(&addr);

  ssh_virtual_adapter_configure(
    interceptor,
    adapter_ifnum,
    SSH_VIRTUAL_ADAPTER_STATE_DOWN,
    0,
    &addr,
    NULL,
    NULL,
    NULL);

  SSH_DEBUG(
    SSH_D_HIGHOK, ("detached %s, ifnum %d", va->name, (int)va->ifnum));

  vxworks_va_report(va, SSH_VIRTUAL_ADAPTER_ERROR_OK, callback, context);
}

/* Detach all virtual IP interfaces from the IPsec engine. */
void ssh_virtual_adapter_detach_all(SshInterceptor interceptor)
{
  VxWorksVa *va;
  int i;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;
  SshIpAddrStruct addr;

  SSH_DEBUG(SSH_D_HIGHOK, ("detach all virtual adapters"));

  for (i = 0; i < vxworks_va_num; i++)
    {
      va = &vxworks_va_tab[i];

      if (!va->attached)
        continue;

      if (va->detach_cb)
        {
          detach_cb = va->detach_cb;
          adapter_context = va->adapter_context;

          va->detach_cb = NULL;
          va->adapter_context = NULL;

          SSH_DEBUG(
            SSH_D_HIGHOK,
            ("calling detach_cb of %s, ifnum %d", va->name, (int)va->ifnum));

          detach_cb(adapter_context);
        }

      SSH_IP_UNDEFINE(&addr);

      ssh_virtual_adapter_configure(
        interceptor,
        va->ifnum,
        SSH_VIRTUAL_ADAPTER_STATE_DOWN,
        0,
        &addr,
        NULL,
        NULL,
        NULL);
    }
}

/* Configure a virtual IP interface. */
void ssh_virtual_adapter_configure(
  SshInterceptor interceptor,
  SshInterceptorIfnum adapter_ifnum,
  SshVirtualAdapterState adapter_state,
  SshUInt32 num_addresses,
  SshIpAddr addresses,
  SshVirtualAdapterParams params,
  SshVirtualAdapterStatusCB callback,
  void *context)
{
  VxWorksVa *va;
  char *addrstr;
  SshIpAddr ipaddr;
  int i, addrlen, mask, oldflags, newflags;
  int inet_up = 0;
#if defined(WITH_IPV6) && defined(INET6)
  int inet6_up = 0;
#endif /* defined(WITH_IPV6) && defined(INET6) */

  SSH_DEBUG(SSH_D_HIGHOK, ("configure ifnum %d", (int)adapter_ifnum));

  if (!(va = vxworks_va_find_va(adapter_ifnum)))
    {
      SSH_TRACE(
        SSH_D_ERROR,
        ("trying to get status of a nonexistent ifnum %d",
         (int)adapter_ifnum));

      if (callback)
        callback(
          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
          adapter_ifnum,
          NULL,
          SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
          NULL,
          context);
      return;
    }

  /* Check addresses to determine IFF_INET_UP and IFF_INET6_UP status */
  if (adapter_state != SSH_VIRTUAL_ADAPTER_STATE_DOWN && addresses)
    {
      for (i = 0; i < num_addresses; i++)
        {
          ipaddr = &addresses[i];
          if (SSH_IP_IS4(ipaddr))
            inet_up = 1;
#if defined(WITH_IPV6) && defined(INET6)
          else if (SSH_IP_IS6(ipaddr))
            inet6_up = 1;
#endif /* defined(WITH_IPV6) && defined(INET6) */
        }
    }

  /* Clear addresses if new addresses are being configured or
     interface is being turned off */
  if (addresses || adapter_state == SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      for (i = 0; i < va->ip4addr_num; i++)
        {
          addrstr = va->ip4addr_tab[i];

          SSH_DEBUG(
            SSH_D_MIDOK,
            ("deleting IPv4 address %s on %s, ifnum %d",
             addrstr, va->name, (int)va->ifnum));

          if (ifAddrDelete(va->name, addrstr) != OK)
            SSH_TRACE(
              SSH_D_ERROR,
              ("%s: deleting IPv4 address %s failed", va->name, addrstr));
        }
      va->ip4addr_num = 0;

      if (ifRouteDelete(vxworks_va_devname, va->end.devObject.unit) ==
          ERROR)
        SSH_TRACE(SSH_D_ERROR, ("%s: deleting IPv4 routes failed", va->name));

#if defined(WITH_IPV6) && defined(INET6)
      for (i = 0; i < va->ip6addr_num; i++)
        {
          addrstr = va->ip6addr_tab[i];

          SSH_DEBUG(
            SSH_D_MIDOK,
            ("deleting IPv6 address %s on %s, ifnum %d",
             addrstr, va->name, (int)va->ifnum));

          if (if6AddrDelete(va->name, addrstr) != OK)
            SSH_TRACE(
              SSH_D_ERROR,
              ("%s: deleting IPv6 address %s failed", va->name, addrstr));
        }
      va->ip6addr_num = 0;
#endif /* defined(WITH_IPV6) && defined(INET6) */
    }

  /* Set interface status. */
  if (ifFlagGet(va->name, &oldflags) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: cannot get interface flags"));
      return;
    }
  newflags = oldflags;
  if (inet_up
#if defined(WITH_IPV6) && defined(INET6)
      || inet6_up
#endif /* defined(WITH_IPV6) && defined(INET6) */
      )
    newflags |= IFF_UP;
  else
    newflags &= ~IFF_UP;
#if VXWORKS_NETVER >= 55122
  if (inet_up)
    newflags |= IFF_INET_UP;
  else
    newflags &= ~IFF_INET_UP;
#if defined(WITH_IPV6) && defined(INET6)
  if (inet6_up)
    newflags |= IFF_INET6_UP;
  else
    newflags &= ~IFF_INET6_UP;
#endif /* defined(WITH_IPV6) && defined(INET6) */
#endif /* VXWORKS_NETVER >= 55122 */
  if (newflags != oldflags && ifFlagSet(va->name, newflags) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: cannot set interface flags"));
      return;
    }

  /* Add addresses if the addresses parameter is non-NULL and
     interface is not being turned off */
  if (addresses && adapter_state != SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      for (i = 0; i < num_addresses; i++)
        {
          ipaddr = &addresses[i];

          if (SSH_IP_IS4(ipaddr))
            {
              if (va->ip4addr_num >=
                  sizeof va->ip4addr_tab / sizeof va->ip4addr_tab[0])
                {
                  SSH_TRACE(
                    SSH_D_ERROR,
                    ("%s: too many IPv4 addresses, ignoring some", va->name));
                  break;
                }

              addrstr = va->ip4addr_tab[va->ip4addr_num];
              addrlen = sizeof va->ip4addr_tab[va->ip4addr_num];

              ssh_ipaddr_print(ipaddr, addrstr, addrlen);

              SSH_DEBUG(
                SSH_D_MIDOK,
                ("adding IPv4 address %s on %s, ifnum %d",
                 addrstr, va->name, (int)va->ifnum));

              mask = ~((1 << (32 - SSH_IP_MASK_LEN(ipaddr))) - 1) & 0xffffffff;

              if (ifAddrAdd(va->name, addrstr, NULL, mask) != OK)
                {
                  SSH_TRACE(
                    SSH_D_ERROR,
                    ("%s: adding IPv4 address %s failed", va->name, addrstr));
                  continue;
                }
              va->ip4addr_num++;
            }
#if defined(WITH_IPV6) && defined(INET6)
          else if (SSH_IP_IS6(ipaddr))
            {
              if (va->ip6addr_num >=
                  sizeof va->ip6addr_tab / sizeof va->ip6addr_tab[0])
                {
                  SSH_TRACE(
                    SSH_D_ERROR,
                    ("%s: too many IPv6 addresses, ignoring some", va->name));
                  break;
                }

              addrstr = va->ip6addr_tab[va->ip6addr_num];
              addrlen = sizeof va->ip6addr_tab[va->ip6addr_num];

              ssh_ipaddr_print(ipaddr, addrstr, addrlen);

              SSH_DEBUG(
                SSH_D_MIDOK,
                ("adding IPv6 address %s on %s, ifnum %d",
                 addrstr, va->name, (int)va->ifnum));

              if (if6AddrAdd(va->name, addrstr, SSH_IP_MASK_LEN(ipaddr), 0)
                  != OK)
                {
                  SSH_TRACE(
                    SSH_D_ERROR,
                    ("%s: adding IPv6 address %s failed", va->name, addrstr));
                  continue;
                }
              va->ip6addr_num++;
            }
#endif /* defined(WITH_IPV6) && defined(INET6) */
        }
    }

  /* Change MTU */
  if (params && params->mtu > 0)
    MIB_VAR_UPDATE(va->end.pMib2Tbl, M2_varId_ifMtu, (ULONG)params->mtu);

  /* Toggle IFF_UP twice to cause an interface event with up-to-date
     addresses in effect. */
  if (ifFlagGet(va->name, &oldflags) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: cannot get interface flags"));
      vxworks_va_report(
        va, SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR, callback, context);
      return;
    }
  newflags = oldflags ^ IFF_UP;
  if (ifFlagSet(va->name, newflags) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: cannot set interface flags"));
      vxworks_va_report(
        va, SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR, callback, context);
      return;
    }
  newflags ^= IFF_UP;
  if (ifFlagSet(va->name, newflags) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: cannot set interface flags"));
      vxworks_va_report(
        va, SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR, callback, context);
      return;
    }

  SSH_DEBUG(
    SSH_D_HIGHOK, ("configured %s, ifnum %d", va->name, (int)va->ifnum));

  vxworks_va_report(va, SSH_VIRTUAL_ADAPTER_ERROR_OK, callback, context);
}

/* Get information about a virtual IP interface. */
void ssh_virtual_adapter_get_status(
  SshInterceptor interceptor,
  SshInterceptorIfnum adapter_ifnum,
  SshVirtualAdapterStatusCB callback,
  void *context)
{
  VxWorksVa *va;
  int i;

  if (adapter_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("get status of all virtual adapters"));

      for (i = 0; i < vxworks_va_num; i++)
        {
          va = &vxworks_va_tab[i];

          if (!va->cookie)
            continue;

          SSH_DEBUG(
            SSH_D_HIGHOK,
            ("returning status of %s, ifnum %d", va->name, (int)va->ifnum));

          vxworks_va_report(
            va, SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE, callback, context);
        }

      SSH_DEBUG(SSH_D_HIGHOK, ("returning last status"));

      callback(
        SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
        SSH_INTERCEPTOR_INVALID_IFNUM,
        NULL,
        SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
        NULL,
        context);
      return;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("get status of ifnum %d", (int)adapter_ifnum));

      if (!(va = vxworks_va_find_va(adapter_ifnum)))
        {
          SSH_TRACE(
            SSH_D_ERROR,
            ("trying to get status of a nonexistent ifnum %d",
             (int)adapter_ifnum));

	  callback(
            SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
            adapter_ifnum,
            NULL,
            SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
            NULL,
            context);
          return;
        }

      SSH_DEBUG(
        SSH_D_HIGHOK,
        ("returning status of %s, ifnum %d", va->name, (int)va->ifnum));

      vxworks_va_report(va, SSH_VIRTUAL_ADAPTER_ERROR_OK, callback, context);
    }
}

/* Call IPsec engine status callback. */
static void vxworks_va_report(
  VxWorksVa *va,
  SshVirtualAdapterError error,
  SshVirtualAdapterStatusCB callback,
  void *context)
{
  char name[END_NAME_MAX + 4];
  SshVirtualAdapterState state;

  ssh_snprintf(name, sizeof name, "%s", va->name);

  if ((END_FLAGS_GET(&va->end) & IFF_UP))
    state = SSH_VIRTUAL_ADAPTER_STATE_UP;
  else
    state = SSH_VIRTUAL_ADAPTER_STATE_DOWN;

  if (callback)
    callback(error, va->ifnum, name, state, va->adapter_context, context);
}

/* Find a VA by ifnum. */
static VxWorksVa *vxworks_va_find_va(SshInterceptorIfnum ifnum)
{
  VxWorksVa *va;
  int i;

  for (i = 0; i < vxworks_va_num; i++)
    {
      va = &vxworks_va_tab[i];
      if (!va->cookie)
        continue;
      if (va->ifnum == ifnum)
        break;
    }

  if (i >= vxworks_va_num)
    return NULL;

  return va;
}

/* VA device load function. */
static END_OBJ *vxworks_va_load(char *init_string, void *arg)
{
  VxWorksVa *va;
  char *token, *last;
  int unit, end_initialized;

  if (!init_string)
    return NULL;

  /* Empty init string indicates driver name query */
  if (!*init_string)
    {
      strcpy(init_string, vxworks_va_devname);
      return NULL;
    }

  /* Otherwise begin loading */
  end_initialized = 0;

  /* Get VA pointer given by us to muxDevLoad() */
  va = arg;
  unit = (int)(va - vxworks_va_tab);

  /* Verify unit number in the beginning of the init string */
  if (!(token = strtok_r(init_string, ":", &last)) || atoi(token) != unit)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: bad unit number in init string", va->name));
      return NULL;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("loading %s", va->name));

  if (END_OBJ_INIT(&va->end, &va->end.devObject, vxworks_va_devname, unit,
                   &vxworks_va_funcs, vxworks_va_desc) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: END_OBJ_INIT failed", va->name));
      goto fail;
    }
  end_initialized = 1;

#if VXWORKS_NETVER < 55122
#ifdef INCLUDE_RFC_2233

  /* Initialize MIB-II entries (for RFC 2233 ifXTable) */
  if (!(va->end.pMib2Tbl =
        m2IfAlloc(M2_ifType_ethernet_csmacd,
                  va->enet_addr, sizeof va->enet_addr,
                  vxworks_va_mtu, vxworks_va_speed,
                  vxworks_va_devname, unit)))
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: m2IfAlloc failed", va->name));
      goto fail;
    }

    /*
     * Set the RFC2233 flag bit in the END object flags field and
     * install the counter update routines.
     */
    m2IfPktCountRtnInstall(va->end.pMib2Tbl, m2If8023PacketCount);

    /*
     * Make a copy of the data in mib2Tbl struct as well. We do this
     * mainly for backward compatibility issues. There might be some
     * code that might be referencing the END pointer and might
     * possibly do lookups on the mib2Tbl, which will cause all sorts
     * of problems.
     */
    bcopy(&va->end.pMib2Tbl->m2Data.mibIfTbl,
          &va->end.mib2Tbl, sizeof va->end.mib2Tbl);

    /* Mark the device ready */
    END_OBJ_READY (&va->end,
                   IFF_NOTRAILERS | IFF_MULTICAST | IFF_BROADCAST |
                   END_MIB_2233);

#else /* INCLUDE_RFC_2233 */

    /* Old RFC 1213 mib2 interface */
    if (END_MIB_INIT (&va->end, M2_ifType_ethernet_csmacd,
                      va->enet_addr, sizeof va->enet_addr,
                      vxworks_va_mtu, vxworks_va_speed) == ERROR)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: END_MIB_INIT failed", va->name));
      goto fail;
    }

    /* Mark the device ready */
    END_OBJ_READY (&va->end, IFF_NOTRAILERS | IFF_MULTICAST | IFF_BROADCAST);

#endif /* INCLUDE_RFC_2233 */
#else /* VXWORKS_NETVER < 55122 */

  if (endM2Init(&va->end, M2_ifType_ethernet_csmacd,
                va->enet_addr, sizeof va->enet_addr,
                vxworks_va_mtu, vxworks_va_speed,
                IFF_NOTRAILERS | IFF_MULTICAST | IFF_BROADCAST) != OK)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: endM2Init failed", va->name));
      goto fail;
    }

#endif /* VXWORKS_NETVER < 55122 */

  return &va->end;

 fail:
  if (end_initialized)
    END_OBJECT_UNLOAD(&va->end);
  return NULL;
}

/* VA device start handler. */
static STATUS vxworks_va_start(END_OBJ *end)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_HIGHOK, ("starting %s", va->name));

  /* A normal ethernet driver would set IFF_UP here; we leave it off
     for ssh_virtual_adapter_configure() to set. */
  END_FLAGS_SET(&va->end, IFF_RUNNING);
  return OK;
}

/* VA device stop handler. */
static STATUS vxworks_va_stop(END_OBJ *end)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_HIGHOK, ("stopping %s", va->name));

  END_FLAGS_CLR(&va->end, IFF_UP | IFF_RUNNING);
  return OK;
}

/* VA device unload handler. */
static STATUS vxworks_va_unload(END_OBJ *end)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_HIGHOK, ("unloading %s", va->name));

#if VXWORKS_NETVER < 55122

  m2IfFree(va->end.pMib2Tbl);
  va->end.pMib2Tbl = NULL;

#else /* VXWORKS_NETVER < 55122 */

  endM2Free(&va->end);

#endif /* VXWORKS_NETVER < 55122 */

  END_OBJECT_UNLOAD(&va->end);

  /* Returning EALREADY prevents muxDevUnload from trying to free va */
  return EALREADY;
}

/* VA device unload handler. */
static int vxworks_va_ioctl(END_OBJ *end, int cmd, caddr_t data)
{
  VxWorksVa *va = (void *)end;

  /* This function can be called from outside tNetTask. No SSH_DEBUG()
     here. */

  switch (cmd)
  {
  case EIOCSADDR:
    return EINVAL;

  case EIOCGADDR:
    if (data == NULL)
      return EINVAL;
#ifdef ETHER_ADDR_LEN
    memcpy(data, va->enet_addr, ETHER_ADDR_LEN);
#else /* ETHER_ADDR_LEN */
    memcpy(data, va->enet_addr, 6);
#endif /* ETHER_ADDR_LEN */
    return 0;

  case EIOCSFLAGS:
    if ((long)data < 0)
      END_FLAGS_CLR(&va->end, ~(long)data);
    else
      END_FLAGS_SET (&va->end, (long)data);
    return 0;

    case EIOCGFLAGS:
      if (data == NULL)
        return EINVAL;
      *(long *)data = END_FLAGS_GET(end);
      return 0;

#if VXWORKS_NETVER < 55122

  case EIOCGMIB2:
    if (data == NULL)
      return EINVAL;
    bcopy(&va->end.mib2Tbl, data, sizeof va->end.mib2Tbl);
    return 0;

#ifdef INCLUDE_RFC_2233

  case EIOCGMIB2233:
    if (data == NULL || va->end.pMib2Tbl == NULL)
      return EINVAL;
    *((M2_ID **)data) = va->end.pMib2Tbl;
    return 0;

#endif /* INCLUDE_RFC_2233 */
#else /* VXWORKS_NETVER < 55122 */

    case EIOCGMIB2:
    case EIOCGMIB2233:
      if (data == NULL)
        return EINVAL;
      return endM2Ioctl(&va->end, cmd, data);

#endif /* VXWORKS_NETVER < 55122 */

    default:
      return EINVAL;
  }
}

/* VA device send handler. */
static STATUS vxworks_va_send(END_OBJ *end , M_BLK_ID m)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_LOWOK, ("send on %s", va->name));

  /* Submit the packet as netJob for two reasons: 1) to avoid
     executing engine code from other than tNetTask, and 2) to avoid
     recursive calls to in_arpinput(). Without terminating the call
     stack here, the latter would occur when sending the first IP
     packet to the VA. The packet would be buffered pending ARP in the
     OS stack and when the spoofed ARP response was given to the
     stack, in_arpinput() would call the intercepted output function
     which would cause another ARP request generated by the IPsec
     engine during flow creation and another spoofed ARP response and
     so the buffered packet would be sent again because it was not
     cleared in the stack before calling the output function. */

  /* Discard packet if too many messages pending */
  if (vxworks_va_sends_submitted - vxworks_va_sends_processed >=
      VXWORKS_VA_SENDS_MAX)
    {
      SSH_TRACE(
        SSH_D_ERROR, ("%s: too many netJobs, dropping packet", va->name));
      m_freem(m);
      return OK;
    }
  if (netJobAdd((FUNCPTR)vxworks_va_send_sub, (int)end, (int)m, 0, 0, 0) != OK)
    {
      SSH_TRACE(
        SSH_D_ERROR, ("%s: netJobAdd failed, dropping packet", va->name));
      m_freem(m);
      return OK;
    }
  vxworks_va_sends_submitted++;
  return OK;
}

/* VA device multicast address add handler. */
static STATUS vxworks_va_mcast_addr_add(END_OBJ *end, char *addr)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_MIDOK, ("mcast addr add on %s", va->name));

  etherMultiAdd(&va->end.multiList, addr);
  return OK;
}

/* VA device multicast address delete handler. */
static STATUS vxworks_va_mcast_addr_del(END_OBJ *end, char *addr)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_MIDOK, ("mcast addr del on %s", va->name));

  etherMultiDel(&va->end.multiList, addr);
  return OK;
}

/* VA device multicast address get handler. */
static STATUS vxworks_va_mcast_addr_get(END_OBJ *end, MULTI_TABLE *tab)
{
  VxWorksVa *va = (void *)end;

  SSH_DEBUG(SSH_D_MIDOK, ("mcast addr get on %s", va->name));

  return etherMultiGet(&va->end.multiList, tab);
}

/* VA device send handler subroutine called through netJobAdd(). */
static void vxworks_va_send_sub(END_OBJ *end, M_BLK_ID m)
{
  VxWorksVa *va = (void *)end;
  SshInterceptorInternalPacket ipp;

  vxworks_va_sends_processed++;

  if (!va->attached)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: not attached, dropping packet", va->name));
      m_freem(m);
      return;
    }

  if (!va->packet_cb)
    {
      SSH_TRACE(SSH_D_ERROR, ("%s: no packet_cb, dropping packet", va->name));
      m_freem(m);
      return;
    }

  if (!(ipp =
        ssh_interceptor_packet_alloc_header(
          va->interceptor,
          SSH_PACKET_FROMPROTOCOL,
          SSH_PROTOCOL_ETHERNET,
          va->ifnum,
          SSH_INTERCEPTOR_INVALID_IFNUM)))
    {
      SSH_TRACE(
        SSH_D_ERROR,
        ("%s: out of interceptor headers, dropping packet", va->name));
      m_freem(m);
      return;
    }

  ipp->head = m;

  va->packet_cb(
    va->interceptor, (void *)ipp, va->adapter_context);
}
