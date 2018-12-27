/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP route functions for VxWorks.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "icept_internal.h"
#include "icept_vxworks.h"

#include <sockLib.h>
#include <errnoLib.h>
#include <net/route.h>
#if defined(WITH_IPV6) && defined(INET6)
#include <net/if.h>
#include <netinet6/nd6.h>
#endif /* defined(WITH_IPV6) && defined(INET6) */

#define SSH_DEBUG_MODULE "IceptRouteVxworks"

static struct {
  struct rt_msghdr hdr;
  unsigned char space[2048];
} vxworks_rtmsg;

static struct sockaddr *vxworks_rtaddr[RTAX_MAX];

static int vxworks_rtseq;

enum vxworks_route_op {
  SSH_VXWORKS_ROUTE_ADD, SSH_VXWORKS_ROUTE_DELETE
};

int
vxworks_route_modify(
  enum vxworks_route_op op,
  SshInterceptorRouteKey key,
  SshIpAddr gateway,
  SshRoutePrecedence precedence);

static void
vxworks_route_sockaddr_encode(struct sockaddr *sa, SshIpAddr ipaddr);

static void
vxworks_route_sockaddr_decode(struct sockaddr *sa, SshIpAddr ipaddr);

static void
vxworks_route_sockaddr_pack_mask(struct sockaddr *sa);

static int
vxworks_route_sockaddr_multicast(struct sockaddr *sa);

static void
vxworks_route_putaddrs(struct rt_msghdr *rtm, struct sockaddr **rtaddr);

/*
static void
vxworks_route_getaddrs(struct rt_msghdr *rtm, struct sockaddr **rtaddr);
*/

#if defined(WITH_IPV6) && defined(INET6)
static int
vxworks_prefix_add(
  struct ifnet *ifp, struct sockaddr_in6 *addr, struct sockaddr_in6 *mask);

static int
vxworks_prefix_del(
  struct ifnet *ifp, struct sockaddr_in6 *addr, struct sockaddr_in6 *mask);
#endif /* defined(WITH_IPV6) && defined(INET6) */

void
ssh_interceptor_route(
  SshInterceptor interceptor,
  SshInterceptorRouteKey key,
  SshInterceptorRouteCompletion completion,
  void *context)
{
  struct rtentry *rt;
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(WITH_IPV6) && defined(INET6)
    struct sockaddr_in6 sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  } su_dst;
  SshIpAddrStruct next_hop;
  SshInterceptorIfnum ifnum;
  size_t mtu;

  if (!SSH_IP_IS4(&key->dst)
#if defined(WITH_IPV6) && defined(INET6)
      && !SSH_IP_IS6(&key->dst)
#endif /* defined(WITH_IPV6) && defined(INET6) */
      )
    {
      SSH_DEBUG(SSH_D_ERROR, ("invalid destination address"));
      goto fail;
    }

  vxworks_route_sockaddr_encode(&su_dst.sa, &key->dst);

#if VXWORKS_NETVER < 55100
  if (!(rt = rtalloc1(&su_dst.sa, 1)))
#else
  if (!(rt = rtalloc1(&su_dst.sa, 1, 0)))
#endif
    goto fail;

  if (vxworks_route_sockaddr_multicast(&su_dst.sa))
    next_hop = key->dst;
  else if ((rt->rt_flags & RTF_GATEWAY))
    vxworks_route_sockaddr_decode(rt->rt_gateway, &next_hop);
  else if ((rt->rt_ifp->if_flags & IFF_POINTOPOINT))
    vxworks_route_sockaddr_decode(rt->rt_ifa->ifa_dstaddr, &next_hop);
  else
    next_hop = key->dst;

  rtfree(rt);

  ifnum = rt->rt_ifp->if_index - 1;
  mtu = rt->rt_ifp->if_mtu;

  (*completion)(TRUE, &next_hop, ifnum, mtu, context);
  return;

 fail:
  (*completion) (FALSE, NULL, 0, 0, context);
}

void
ssh_interceptor_add_route(
  SshInterceptor interceptor,
  SshInterceptorRouteKey key,
  SshIpAddr gateway,
  SshInterceptorIfnum ifnum,
  SshRoutePrecedence precedence,
  SshUInt32 flags,
  SshInterceptorRouteSuccessCB success_cb,
  void *success_cb_context)
{
  if (vxworks_route_modify(SSH_VXWORKS_ROUTE_ADD, key, gateway, precedence))
    {
      (*success_cb)(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, success_cb_context);
      return;
    }

  (*success_cb)(SSH_INTERCEPTOR_ROUTE_ERROR_OK, success_cb_context);
}

void
ssh_interceptor_remove_route(
  SshInterceptor interceptor,
  SshInterceptorRouteKey key,
  SshIpAddr gateway,
  SshInterceptorIfnum ifnum,
  SshRoutePrecedence precedence,
  SshUInt32 flags,
  SshInterceptorRouteSuccessCB success_cb,
  void *success_cb_context)
{
  if (vxworks_route_modify(SSH_VXWORKS_ROUTE_DELETE, key, gateway, precedence))
    {
      (*success_cb)(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, success_cb_context);
      return;
    }

  (*success_cb)(SSH_INTERCEPTOR_ROUTE_ERROR_OK, success_cb_context);
}

int
vxworks_route_modify(
  enum vxworks_route_op op,
  SshInterceptorRouteKey key,
  SshIpAddr gateway,
  SshRoutePrecedence precedence)
{
  int s = -1, n;
  struct rt_msghdr *rtm = &vxworks_rtmsg.hdr;
  struct sockaddr **rtaddr = vxworks_rtaddr;
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(WITH_IPV6) && defined(INET6)
    struct sockaddr_in6 sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  } su_dst, su_netmask, su_gw;
  SshIpAddrStruct netmask, addr;
#if defined(WITH_IPV6) && defined(INET6)
  struct ifaddr *ifa;
#endif /* defined(WITH_IPV6) && defined(INET6) */

  /* Check that addresses are valid. */
  if (!SSH_IP_IS4(&key->dst)
#if defined(WITH_IPV6) && defined(INET6)
      && !SSH_IP_IS6(&key->dst)
#endif /* defined(WITH_IPV6) && defined(INET6) */
      )
    {
      SSH_DEBUG(SSH_D_ERROR, ("invalid destination address"));
      goto fail;
    }

  if (!gateway)
    {
      SSH_DEBUG(SSH_D_ERROR, ("no gateway address"));
      goto fail;
    }

  if (gateway->type != key->dst.type)
    {
      SSH_DEBUG(SSH_D_ERROR, ("address family mismatch"));
      goto fail;
    }

  /* Convert addresses to system format. */
  vxworks_route_sockaddr_encode(&su_dst.sa, &key->dst);
  ssh_ipaddr_set_bits(&addr, &key->dst, 0, 1);
  ssh_ipaddr_set_bits(&netmask, &addr, SSH_IP_MASK_LEN(&key->dst), 0);
  vxworks_route_sockaddr_encode(&su_netmask.sa, &netmask);
  vxworks_route_sockaddr_pack_mask(&su_netmask.sa);
  vxworks_route_sockaddr_encode(&su_gw.sa, gateway);

#if defined(WITH_IPV6) && defined(INET6)
  /* If IPv6 gateway is local interface then do prefix instead of route */
  if (su_gw.sa.sa_family == AF_INET6 && (ifa = ifa_ifwithaddr(&su_gw.sa)))
    {
      if (op == SSH_VXWORKS_ROUTE_ADD)
        {
          if (vxworks_prefix_add(ifa->ifa_ifp, &su_dst.sin6, &su_netmask.sin6))
            goto fail;
        }
      else if (op == SSH_VXWORKS_ROUTE_DELETE)
        {
          if (vxworks_prefix_del(ifa->ifa_ifp, &su_dst.sin6, &su_netmask.sin6))
            goto fail;
        }
      return 0;
    }
#endif /* defined(WITH_IPV6) && defined(INET6) */

  /* Open a routing socket. */
  if ((s = socket(AF_ROUTE, SOCK_RAW, 0)) < 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("socket: %s", strerror(errno)));
      goto fail;
    }

  /* Set to nonblocking mode. */
  n = 1;
  if (ioctl(s, FIONBIO, (int)&n) < 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("ioctl: %s", strerror(errno)));
      goto fail;
    }

  /* Init routing message. */
  memset(rtm, 0, sizeof *rtm);
  rtm->rtm_msglen = sizeof *rtm;
  rtm->rtm_version = RTM_VERSION;

  if (op == SSH_VXWORKS_ROUTE_ADD)
    rtm->rtm_type = RTM_ADD;
  else if (op == SSH_VXWORKS_ROUTE_DELETE)
    rtm->rtm_type = RTM_DELETE;

  rtm->rtm_flags = RTF_UP | RTF_GATEWAY;

  /* Add address pointers. */
  memset(rtaddr, 0, RTAX_MAX * sizeof rtaddr[0]);
  rtaddr[RTAX_DST] = &su_dst.sa;
  rtaddr[RTAX_NETMASK] = &su_netmask.sa;
  rtaddr[RTAX_GATEWAY] = &su_gw.sa;

  /* Copy addresses to message. */
  vxworks_route_putaddrs(rtm, rtaddr);

#ifdef ROUTER_STACK
  /* Set route weight. */
  switch (precedence)
    {
    case SSH_ROUTE_PREC_LOWEST:
      rtm->rtm_rmx.weight = 1000;
      rtm->rtm_inits |= RTV_WEIGHT;
      break;

    case SSH_ROUTE_PREC_BELOW_SYSTEM:
      rtm->rtm_rmx.weight = 150;
      rtm->rtm_inits |= RTV_WEIGHT;
      break;

    case SSH_ROUTE_PREC_SYSTEM:
    default:
      break;

    case SSH_ROUTE_PREC_ABOVE_SYSTEM:
      rtm->rtm_rmx.weight = 50;
      rtm->rtm_inits |= RTV_WEIGHT;
      break;

    case SSH_ROUTE_PREC_HIGHEST:
      rtm->rtm_rmx.weight = 1;
      rtm->rtm_inits |= RTV_WEIGHT;
      break;

    }
#endif /* ROUTER_STACK */

  /* Get new sequence number. */
  rtm->rtm_seq = ++vxworks_rtseq;

  /* Send message. */
  if ((n = write(s, (void *)rtm, rtm->rtm_msglen)) < 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("write: %s", strerror(errno)));
      goto fail;
    }
  else if (n < rtm->rtm_msglen)
    {
      SSH_DEBUG(SSH_D_ERROR, ("short write"));
      goto fail;
    }

  /* Receive response. */
  do
    n = read(s, (void *)&vxworks_rtmsg, sizeof vxworks_rtmsg);
  while (n >= sizeof *rtm && rtm->rtm_seq != vxworks_rtseq);

  /* Close socket. */
  close(s);
  s = -1;

  /* Check errors. */
  if (n < 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("read: %s", strerror(errno)));
      goto fail;
    }
  else if (n < rtm->rtm_msglen)
    {
      SSH_DEBUG(SSH_D_ERROR, ("short read"));
      goto fail;
    }

  if (rtm->rtm_errno)
    {
      SSH_DEBUG(SSH_D_ERROR,
        ("routing socket operation failed: %s", strerror(rtm->rtm_errno)));
      goto fail;
    }

  return 0;

 fail:
  if (s >= 0)
    close(s);
  return -1;
}

static void
vxworks_route_sockaddr_encode(struct sockaddr *sa, SshIpAddr ipaddr)
{
#if defined(WITH_IPV6) && defined(INET6)
  struct sockaddr_in6 *sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  struct sockaddr_in *sin;

#if defined(WITH_IPV6) && defined(INET6)
  if (SSH_IP_IS6(ipaddr))
    {
      sin6 = (void *)sa;
      memset(sin6, 0, sizeof *sin6);

      sin6->sin6_len = sizeof *sin6;
      sin6->sin6_family = AF_INET6;
      SSH_IP6_ENCODE(ipaddr, &sin6->sin6_addr);
    }
  else
#endif /* defined(WITH_IPV6) && defined(INET6) */
    {
      sin = (void *)sa;
      memset(sin, 0, sizeof *sin);

      sin->sin_len = sizeof *sin;
      sin->sin_family = AF_INET;
      SSH_IP4_ENCODE(ipaddr, &sin->sin_addr);
    }
}

static void
vxworks_route_sockaddr_decode(struct sockaddr *sa, SshIpAddr ipaddr)
{
#if defined(WITH_IPV6) && defined(INET6)
  struct sockaddr_in6 *sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  struct sockaddr_in *sin;

#if defined(WITH_IPV6) && defined(INET6)
  if (sa->sa_family == AF_INET6)
    {
      sin6 = (void *)sa;
      SSH_IP6_DECODE(ipaddr, &sin6->sin6_addr);
    }
  else
#endif /* defined(WITH_IPV6) && defined(INET6) */
    {
      sin = (void *)sa;
      SSH_IP4_DECODE(ipaddr, &sin->sin_addr);
    }
}

static void
vxworks_route_sockaddr_pack_mask(struct sockaddr *sa)
{
  struct sockaddr_in *sin;
  u_int32_t hostn;

  if (sa->sa_family != AF_INET)
    return;

  sin = (void*)sa;

  sin->sin_family = 0;

  hostn = ntohl(sin->sin_addr.s_addr);
  if (hostn == 0)
    sin->sin_len = 2;
  else if ((hostn & 0x00ffffff) == 0)
    sin->sin_len = 5;
  else if ((hostn & 0x0000ffff) == 0)
    sin->sin_len = 6;
  else if ((hostn & 0x000000ff) == 0)
    sin->sin_len = 7;
  else
    sin->sin_len = 8;
}

static int
vxworks_route_sockaddr_multicast(struct sockaddr *sa)
{
#if defined(WITH_IPV6) && defined(INET6)
  struct sockaddr_in6 *sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  struct sockaddr_in *sin;

#if defined(WITH_IPV6) && defined(INET6)
  if (sa->sa_family == AF_INET6)
    {
      sin6 = (void *)sa;
      return IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
    }
  else
#endif /* defined(WITH_IPV6) && defined(INET6) */
    {
      sin = (void *)sa;
      return IN_MULTICAST(sin->sin_addr.s_addr);
    }
}

static void
vxworks_route_putaddrs(struct rt_msghdr *rtm, struct sockaddr **rtaddr)
{
  unsigned char *pos = (void *)(rtm + 1);
  int i, len;

  rtm->rtm_addrs = 0;

  for (i = 0; i < RTAX_MAX; i++)
    {
      if (!rtaddr[i])
        continue;

      len = (rtaddr[i]->sa_len + 3) & ~3;

      memcpy(pos, rtaddr[i], len);
      pos += len;

      rtm->rtm_addrs |= 1 << i;
    }

  rtm->rtm_msglen = pos - (unsigned char *)rtm;
}

/*
static void
vxworks_route_getaddrs(struct rt_msghdr *rtm, struct sockaddr **rtaddr)
{
  unsigned char *pos = (void *)(rtm + 1);
  unsigned char *end = (unsigned char *)rtm + rtm->rtm_msglen;
  int minlen = offsetof(struct sockaddr, sa_data);
  int i, len;

  memset(rtaddr, 0, RTAX_MAX * sizeof rtaddr[0]);

  for (i = 0; i < RTAX_MAX; i++)
    {
      if (!(rtm->rtm_addrs & (1 << i)))
        continue;

      if (pos + minlen > end)
        break;

      rtaddr[i] = (void *)pos;

      len = (rtaddr[i]->sa_len + 3) & ~3;

      if (pos + len > end)
        {
          rtaddr[i] = (void *)pos;
          break;
        }

      pos += len;
    }
}
*/

#if defined(WITH_IPV6) && defined(INET6)
static int
vxworks_prefix_add(
  struct ifnet *ifp, struct sockaddr_in6 *addr, struct sockaddr_in6 *mask)
{
      struct nd_prefix pr0;
      int error;

      memset(&pr0, 0, sizeof pr0);
      pr0.ndpr_ifp = ifp;
      pr0.ndpr_plen = in6_mask2len(&mask->sin6_addr, NULL);
      pr0.ndpr_mask = mask->sin6_addr;
      pr0.ndpr_prefix = *addr;
#if VXWORKS_NETVER < 61000
      pr0.ndpr_flags.onlink = 1;
      pr0.ndpr_flags.autonomous = 1;
#else /* VXWORKS_NETVER */
      pr0.ndpr_flags = PRF_RA_ONLINK | PRF_RA_AUTONOMOUS;
#endif /* VXWORKS_NETVER */
      pr0.ndpr_vltime = ND6_INFINITE_LIFETIME;
      pr0.ndpr_pltime = ND6_INFINITE_LIFETIME;

      if (nd6_prefix_lookup(&pr0))
        {
          SSH_DEBUG(SSH_D_ERROR, ("prefix already exists"));
          return -1;
        }

      if ((error = nd6_prelist_add(&pr0, NULL, NULL)))
        {
          SSH_DEBUG(SSH_D_ERROR, ("nd6_prelist_add: %s", strerror(errno)));
          return -1;
        }

      return 0;
}

static int
vxworks_prefix_del(
  struct ifnet *ifp, struct sockaddr_in6 *addr, struct sockaddr_in6 *mask)
{
      struct nd_prefix pr0, *pr;

      memset(&pr0, 0, sizeof pr0);
      pr0.ndpr_ifp = ifp;
      pr0.ndpr_plen = in6_mask2len(&mask->sin6_addr, NULL);
      pr0.ndpr_mask = mask->sin6_addr;
      pr0.ndpr_prefix = *addr;

      if (!(pr = nd6_prefix_lookup(&pr0)))
        {
          SSH_DEBUG(SSH_D_ERROR, ("prefix not found"));
          return -1;
        }

      prelist_remove(pr);
      return 0;
}
#endif /* defined(WITH_IPV6) && defined(INET6) */
