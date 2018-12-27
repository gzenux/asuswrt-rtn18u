/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec over TCP encapsulation.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_tcp_encaps.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineTcpEncaps"

#ifdef SSH_IPSEC_TCPENCAP

/********************** Pending connection deletion entry ********************/

typedef struct SshEngineTcpEncapsDeleteRec
{
  struct SshEngineTcpEncapsDeleteRec *next;
  SshUInt32 conn_id;
} SshEngineTcpEncapsDeleteStruct;

/*********************** Static function prototypes **************************/

static SshInterceptorPacket
ssh_engine_tcp_encaps_build_handshake(SshEngine engine,
                                      SshUInt16 ip_id,
                                      SshIpAddr src_addr, SshUInt16 src_port,
                                      SshIpAddr dst_addr, SshUInt16 dst_port,
                                      SshUInt32 seq, SshUInt32 ack,
                                      SshUInt16 flags,
                                      unsigned char *data, size_t data_len);

static void
ssh_engine_tcp_encaps_send_packet(SshEngine engine,
                                  SshInterceptorPacket pp,
                                  SshInetIPProtocolID ipproto,
                                  SshIpAddr src, SshIpAddr dst);

static void
engine_tcp_encaps_timeout_cb(void *context);

static SshEngineTcpEncapsConn
ssh_engine_tcp_encaps_conn_by_id(SshEngine engine, SshUInt32 conn_id);

static SshUInt16
ssh_engine_tcp_encaps_get_free_tcp_port(SshEngine engine);

/*********************** Utility functions ***********************************/

/* Checks if address ip is in range (lo:hi), assumes that lo < hi. */
#define SSH_IP_IN_RANGE(ip, lo, hi)                                   \
  ( ((ip)->type == (lo)->type && (ip)->type == (hi)->type) ?          \
   ((SSH_IP_CMP((ip), (lo)) >= 0) && (SSH_IP_CMP((ip), (hi)) <= 0)) : \
   FALSE)

/*
 * Calculates a hash value to access the table of active TCP encapsulation
 * connections.
 */
static SshUInt32
engine_tcp_encaps_hash(SshIpAddr addr, SshUInt16 port)
{
  unsigned char tmpbuf[16];
  size_t tmplen;
  SshUInt32 h;

  memset(tmpbuf, 0, sizeof(tmpbuf));

  tmplen = sizeof(tmpbuf);
  SSH_IP_ENCODE(addr, tmpbuf, tmplen);

  tmpbuf[0] ^= tmpbuf[4] ^ tmpbuf[8] ^ tmpbuf[12] ^ ((port >> 8) & 0xff);
  tmpbuf[1] ^= tmpbuf[5] ^ tmpbuf[9] ^ tmpbuf[13] ^ (port & 0xff);
  tmpbuf[2] ^= tmpbuf[6] ^ tmpbuf[10] ^ tmpbuf[14] ^ ((port >> 8) & 0xff);
  tmpbuf[3] ^= tmpbuf[7] ^ tmpbuf[11] ^ tmpbuf[15] ^ (port & 0xff);

  h = *((SshUInt32*) tmpbuf);

  return (h % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE);
}

static void
engine_tcp_encaps_initial_timeout_list_insert(SshEngine engine,
                                              SshEngineTcpEncapsConn conn)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Inserting connection 0x%lx to initial timeout list",
             (unsigned long) conn->conn_id));

  SSH_ASSERT(conn->in_initial_timeout_list == 0);
  SSH_ASSERT(conn->in_negotiation_timeout_list == 0);
  conn->timeout_next = engine->tcp_encaps_initial_timeout_list;
  engine->tcp_encaps_initial_timeout_list = conn;
  conn->in_initial_timeout_list = 1;
}

static void
engine_tcp_encaps_initial_timeout_list_remove(SshEngine engine,
                                              SshEngineTcpEncapsConn conn)
{
  SshEngineTcpEncapsConn prev_conn;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Removing connection 0x%lx from initial timeout list",
             (unsigned long) conn->conn_id));

  SSH_ASSERT(conn->in_initial_timeout_list == 1);
  SSH_ASSERT(engine->tcp_encaps_initial_timeout_list != NULL);

  if (engine->tcp_encaps_initial_timeout_list == conn)
    {
      engine->tcp_encaps_initial_timeout_list = conn->timeout_next;
      conn->in_initial_timeout_list = 0;
    }
  else
    {
      for (prev_conn = engine->tcp_encaps_initial_timeout_list;
           prev_conn->timeout_next != NULL;
           prev_conn = prev_conn->timeout_next)
        {
          if (prev_conn->timeout_next == conn)
            {
              prev_conn->timeout_next = conn->timeout_next;
              conn->in_initial_timeout_list = 0;
              return;
            }
        }
      SSH_NOTREACHED;
    }
}

static void
engine_tcp_encaps_negotiation_timeout_list_insert(SshEngine engine,
                                                  SshEngineTcpEncapsConn conn)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Inserting connection 0x%lx to negotiation timeout list",
             (unsigned long) conn->conn_id));

  SSH_ASSERT(conn->in_initial_timeout_list == 0);
  SSH_ASSERT(conn->in_negotiation_timeout_list == 0);
  conn->timeout_next = engine->tcp_encaps_negotiation_timeout_list;
  engine->tcp_encaps_negotiation_timeout_list = conn;
  conn->in_negotiation_timeout_list = 1;
}

static void
engine_tcp_encaps_negotiation_timeout_list_remove(SshEngine engine,
                                                  SshEngineTcpEncapsConn conn)
{
  SshEngineTcpEncapsConn prev_conn;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Removing connection 0x%lx from negotiation timeout list",
             (unsigned long) conn->conn_id));

  SSH_ASSERT(conn->in_negotiation_timeout_list == 1);
  SSH_ASSERT(engine->tcp_encaps_negotiation_timeout_list != NULL);

  if (engine->tcp_encaps_negotiation_timeout_list == conn)
    {
      engine->tcp_encaps_negotiation_timeout_list = conn->timeout_next;
      conn->in_negotiation_timeout_list = 0;
    }
  else
    {
      for (prev_conn = engine->tcp_encaps_negotiation_timeout_list;
           prev_conn->timeout_next != NULL;
           prev_conn = prev_conn->timeout_next)
        {
          if (prev_conn->timeout_next == conn)
            {
              prev_conn->timeout_next = conn->timeout_next;
              conn->in_negotiation_timeout_list = 0;
              return;
            }
        }
      SSH_NOTREACHED;
    }
}


/***************** Adding, closing and removing connections ******************/

/*
 * Picks a free connection ID and adds connection to the encapsulating
 * TCP connection table. This function asserts that 'tcp_encaps_lock' is
 * taken.
 */
static SshUInt32
engine_tcp_encaps_add_conn(SshEngine engine,
                           SshEngineTcpEncapsConn conn,
                           SshUInt32 hash)
{
  SshEngineTcpEncapsConn conn_p, conn_prev;

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);
  SSH_ASSERT(hash < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Connection [%@:%d] [%@:%d] hash 0x%lx",
             ssh_ipaddr_render, &conn->local_addr, (int) conn->local_port,
             ssh_ipaddr_render, &conn->peer_addr, (int) conn->peer_port,
             (unsigned long) hash));

  /* Pick a free connection ID.

     Connections are in the hash chain in ascending connection ID
     order and the relation
     ( (conn_id % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE) == hash )
     holds for each connection ID.

     Start searching for free connection ID from the hash value. If ID
     is reserved, increment ID by SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE,
     and continue traversing the chain.

     When a free connection ID is found, insert the connection entry
     to the hash chain, so that the connection IDs are in ascending order. */

  conn_p = engine->tcp_encaps_connection_table[hash];
  conn_prev = NULL;
  conn->conn_id = hash;
  while (conn_p && conn->conn_id < SSH_ENGINE_TCP_ENCAPS_MAX_CONN_ID)
    {
      /* Free conn_id found. */
      if (conn->conn_id != conn_p->conn_id)
        break;

      /* Try next conn_id */
      conn->conn_id = conn_p->conn_id + SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE;
      conn_prev = conn_p;
      conn_p = conn_p->next;
    }
  if (conn->conn_id >= SSH_ENGINE_TCP_ENCAPS_MAX_CONN_ID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of connection IDs"));
      goto error;
    }

  /* Add connection to table */
  conn->next = conn_p;
  if (conn_prev)
    conn_prev->next = conn;
  else
    engine->tcp_encaps_connection_table[hash] = conn;

  SSH_ASSERT((conn->conn_id % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE) == hash);
  SSH_ASSERT((conn->next == NULL) || (conn->conn_id < conn->next->conn_id));

  SSH_DEBUG(SSH_D_LOWOK,
            ("Added entry to connection table with ID 0x%lx",
             (unsigned long) conn->conn_id));

  return conn->conn_id;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("failed"));
  return SSH_IPSEC_INVALID_INDEX;
}

/*
 * Clone an existing connection and add the clone to the encapsulating
 * TCP connection table. This function asserts that 'tcp_encaps_lock' is
 * taken.
 */
static SshEngineTcpEncapsConn
engine_tcp_encaps_clone_conn(SshEngine engine,
                             SshEngineTcpEncapsConn conn,
                             SshIpAddr local_addr,
                             SshIpAddr peer_addr)
{
  SshEngineTcpEncapsConn conn_p, conn_ret = NULL;
  SshUInt32 tries = 0;
  SshUInt32 hash;

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(local_addr != NULL);
  SSH_ASSERT(peer_addr != NULL);

  /* Allocate new connection entry. */
  conn_ret = ssh_calloc(1, sizeof(*conn_ret));
  if (conn_ret == NULL)
    return NULL;

  conn_ret->engine = engine;

  /* Initialize to closed state. */
  conn_ret->state = SSH_ENGINE_TCP_CLOSED;
  conn_ret->negotiation_completed = 0;

  /* Store cookie */
  memcpy(conn_ret->ike_initiator_cookie, conn->ike_initiator_cookie,
         SSH_ENGINE_IKE_COOKIE_LENGTH);
  conn_ret->ike_mapping_set = 1;

  /* Store addresses and ports. */
  memcpy(&conn_ret->local_addr, local_addr, sizeof(conn->local_addr));
  memcpy(&conn_ret->peer_addr, peer_addr, sizeof(conn->peer_addr));
  conn_ret->peer_port = conn->peer_port;
  conn_ret->local_ike_port = conn->local_ike_port;
  conn_ret->remote_ike_port = conn->remote_ike_port;

  /* Allocate local port. */
 allocate_local_port:
  tries++;
  if (tries > 5)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to allocate free TCP port for connection entry"));
      goto error;
    }

  if (conn->configured_local_port == 0)
    conn_ret->local_port = ssh_engine_tcp_encaps_get_free_tcp_port(engine);
  else
    conn_ret->local_port = conn->configured_local_port;

  /* Check for TCP port collision. */
  hash = engine_tcp_encaps_hash(&conn_ret->peer_addr, conn_ret->peer_port);
  conn_p = engine->tcp_encaps_connection_table[hash];
  while (conn_p)
    {
      if (SSH_IP_EQUAL(&conn_ret->peer_addr, &conn_p->peer_addr)
          && conn_ret->peer_port == conn_p->peer_port
          && SSH_IP_EQUAL(&conn_ret->local_addr, &conn_p->local_addr)
          && conn_ret->local_port == conn_p->local_port)
        break;
      conn_p = conn_p->next;
    }
  /* Collision, attempt again. */
  if (conn_p != NULL)
    goto allocate_local_port;

  /* Add connection entry to connection table. */
  hash = engine_tcp_encaps_hash(&conn_ret->peer_addr, conn_ret->peer_port);
  if (engine_tcp_encaps_add_conn(engine, conn_ret, hash)
      == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to add connection entry to connection table"));
      goto error;
    }

  /* Copy IKE cookies. */
  memcpy(conn_ret->ike_initiator_cookie, conn->ike_initiator_cookie,
         SSH_ENGINE_IKE_COOKIE_LENGTH);
  memcpy(conn_ret->old_ike_initiator_cookie, conn->old_ike_initiator_cookie,
         SSH_ENGINE_IKE_COOKIE_LENGTH);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Cloned connection [%@:%d] - [%@:%d] IKE SPI 0x%lx 0x%lx "
             "to [%@:%d] - [%@:%d] IKE SPI 0x%lx 0x%lx",
             ssh_ipaddr_render, &conn->local_addr, (int) conn->local_port,
             ssh_ipaddr_render, &conn->peer_addr, (int) conn->peer_port,
             (unsigned long) SSH_GET_32BIT(conn->ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(conn->ike_initiator_cookie + 4),
             ssh_ipaddr_render, &conn_ret->local_addr,
             (int) conn_ret->local_port,
             ssh_ipaddr_render, &conn_ret->peer_addr,
             (int) conn_ret->peer_port,
             (unsigned long) SSH_GET_32BIT(conn_ret->ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(conn_ret->ike_initiator_cookie + 4)
             ));

  return conn_ret;

 error:
  ssh_free(conn_ret);
  return NULL;
}

/*
 * Marks connection closed and frees any pending trigger packet.
 * This also removes the connection entry from the connection table
 * if there are no active SPI mappings to it. This function asserts
 * that 'tcp_encaps_lock' is taken.
 */
static void
ssh_engine_tcp_encaps_remove_conn(SshEngine engine,
                                  SshEngineTcpEncapsConn conn)
{
  SshUInt32 hash;
  SshEngineTcpEncapsConn conn_p;
  SshUInt32 slot;

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  /* Mark connection closed. */
  conn->state = SSH_ENGINE_TCP_CLOSED;

  /* Free pending trigger packet immediately. */
  if (conn->trigger_packet != NULL)
    ssh_interceptor_packet_free(conn->trigger_packet);
  conn->trigger_packet = NULL;

  /* Remove connection from timeout lists. */
  if (conn->in_initial_timeout_list)
    engine_tcp_encaps_initial_timeout_list_remove(engine, conn);

  if (conn->in_negotiation_timeout_list)
    engine_tcp_encaps_negotiation_timeout_list_remove(engine, conn);

  /* Check if there are any active SPI mappings. */
  for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
    {
      if (conn->esp_outbound_spi[slot] != 0
          || conn->ah_outbound_spi[slot] != 0)
        break;
    }
  /* There are still SPI active mappings. */
  if (slot != SSH_ENGINE_TCP_ENCAPS_MAX_SAS || conn->ike_mapping_set)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Marking connection entry 0x%lx closed",
                              (unsigned long) conn->conn_id));
      return;
    }

  /* Remove connection from table */
  hash = engine_tcp_encaps_hash(&conn->peer_addr, conn->peer_port);
  conn_p = engine->tcp_encaps_connection_table[hash];
  if (conn_p == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not find entry 0x%lx in connection table",
                 (unsigned long) conn->conn_id));
    }
  else if (conn_p == conn)
    {
      engine->tcp_encaps_connection_table[hash] = conn->next;
    }
  else
    {
      while (conn_p->next)
        {
          if (conn_p->next == conn)
            {
              conn_p->next = conn->next;
              break;
            }
          conn_p = conn_p->next;
        }
    }

  /* Free connection entry */
  SSH_DEBUG(SSH_D_MIDOK, ("Freeing connection entry 0x%lx",
                          (unsigned long) conn->conn_id));
  ssh_free(conn);
}

/*
 * Close the connection (send TCP RST) and remove connection entry if
 * there are no active SPI mappings. This function asserts that
 * 'tcp_encaps_lock' is taken.
 */
static void
ssh_engine_tcp_encaps_close_conn(SshEngine engine, SshEngineTcpEncapsConn conn,
                                 SshInterceptorPacket *handshake_packet,
                                 SshIpAddr handshake_src,
                                 SshIpAddr handshake_dst)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Closing TCP connection 0x%lx",
                             (unsigned long) conn->conn_id));

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  if (engine->ipm_open && conn->state != SSH_ENGINE_TCP_CLOSED)
    {
      SshUInt16 ip_id = ssh_engine_get_ip_id(engine);

      /* Send TCP RST to peer */
      *handshake_packet =
        ssh_engine_tcp_encaps_build_handshake(engine, ip_id,
                                           &conn->local_addr, conn->local_port,
                                           &conn->peer_addr, conn->peer_port,
                                           0, 0,
                                           SSH_TCPH_FLAG_RST,
                                           NULL, 0);
      *handshake_src = conn->local_addr;
      *handshake_dst = conn->peer_addr;
    }

  /* Remove entry from connection table */
  ssh_engine_tcp_encaps_remove_conn(engine, conn);
}

/*
 * Timeout function to close connection. Called from a timeout.
 * This function will grab the 'tcp_encaps_lock'. This function
 * will call ssh_engine_send_packet (with no locks taken).
 */
static void
ssh_engine_tcp_encaps_close_conn_timeout_cb(void *context)
{
  SshEngine engine = (SshEngine) context;
  SshEngineTcpEncapsConn conn;
  SshEngineTcpEncapsDelete del;
  SshInterceptorPacket handshake_packet = NULL;
  SshIpAddrStruct handshake_src, handshake_dst;
  SshUInt32 slot;

  SSH_INTERCEPTOR_STACK_MARK();

  do {
    /* Get a deletion context from pending deletions list.
       Grab 'tcp_encaps_lock' for manipulating the
       pending deletions list. */
    ssh_kernel_mutex_lock(engine->tcp_encaps_lock);
    del = engine->tcp_encaps_delete_list;
    if (del == NULL)
      {
        ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
        return;
      }
    engine->tcp_encaps_delete_list = del->next;

    /* Lookup connection. */
    conn = ssh_engine_tcp_encaps_conn_by_id(engine, del->conn_id);
    if (conn == NULL)
      {
        ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
        goto done;
      }

    /* Re-check that there are no IKE or SPI mappings. */
    for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
      {
        if (conn->esp_outbound_spi[slot] != 0
            || conn->ah_outbound_spi[slot] != 0)
          break;
      }
    /* There are SPI or IKE mappings, do not close connection. */
    if (slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS || conn->ike_mapping_set)
      {
        ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
        goto done;
      }

    SSH_DEBUG(SSH_D_LOWOK, ("Closing TCP connection 0x%lx",
                            (unsigned long) conn->conn_id));

    /* Send TCP RST and remove entry from connection table */
    ssh_engine_tcp_encaps_close_conn(engine, conn, &handshake_packet,
                                     &handshake_src, &handshake_dst);
    ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
    if (handshake_packet != NULL)
      {
        ssh_engine_tcp_encaps_send_packet(engine, handshake_packet,
                                          SSH_IPPROTO_TCP,
                                          &handshake_src, &handshake_dst);
        handshake_packet = NULL;
      }

  done:
    if (del)
      ssh_free(del);

  } while (del != NULL);
}

/*
 * Register a short timeout to close the connection identified by 'conn_id'.
 * This function asserts that 'tcp_encaps_lock' is taken.
 */
static SshUInt32
ssh_engine_tcp_encaps_close_conn_timeout(SshEngine engine,
                                         SshUInt32 conn_id)
{
  SshEngineTcpEncapsDelete del;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Registering timeout to close TCP connection 0x%lx.",
             (unsigned long) conn_id));

  if (conn_id == SSH_IPSEC_INVALID_INDEX)
    return SSH_IPSEC_INVALID_INDEX;

  /* `tcp_encaps_lock' protects the pending deletions list. */
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  /* Check if conn_id is already in the deletion list. */
  for (del = engine->tcp_encaps_delete_list; del; del = del->next)
    if (del->conn_id == conn_id)
      return SSH_IPSEC_INVALID_INDEX;

  /* Insert 'conn_id' to list of pending deletions. */
  del = (SshEngineTcpEncapsDelete) ssh_calloc(1, sizeof(*del));
  if (del == NULL)
    return SSH_IPSEC_INVALID_INDEX;

  del->conn_id = conn_id;
  del->next = engine->tcp_encaps_delete_list;
  engine->tcp_encaps_delete_list = del;

  /* Register timeout to handle pending deletions. */
  ssh_kernel_timeout_register(0, SSH_ENGINE_TCP_ENCAPS_CLOSE_TIMEOUT,
                              ssh_engine_tcp_encaps_close_conn_timeout_cb,
                              engine);

  return SSH_IPSEC_INVALID_INDEX;
}

/********************************** Utility functions ************************/

/*
 * Pick a free local TCP port from the range
 * SSH_ENGINE_TCP_ENCAPS_LOCAL_PORT_{MIN,MAX}.
 */





static SshUInt16
ssh_engine_tcp_encaps_get_free_tcp_port(SshEngine engine)
{
  SshUInt16 port =
    0xffff & ssh_rand_range(SSH_ENGINE_TCP_ENCAPS_LOCAL_PORT_MIN,
                            SSH_ENGINE_TCP_ENCAPS_LOCAL_PORT_MAX);
  return port;
}

/*
 * Parse IP protocol and port numbers, spi or ike initiator cookie
 * from an IPv4/IPv6 packet.
 *
 * Implementation note: 'pc' is only partially valid when this
 * function is called.
 */
static Boolean
ssh_engine_tcp_encaps_pullup_ports(SshEnginePacketContext pc,
                                   SshInterceptorPacket pp,
                                   SshUInt8 *ipproto,
                                   SshUInt16 *src_port,
                                   SshUInt16 *dst_port,
                                   SshUInt32 *spi,
                                   unsigned char *cookie)
{
  const unsigned char *ucp;
  unsigned char pullup_buf[40];
  size_t offset = 0;
  size_t packet_len = ssh_interceptor_packet_len(pp);
  Boolean get_cookie = FALSE;
#ifdef DEBUG_LIGHT
  SshUInt8 flags;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(ipproto != NULL);
  SSH_ASSERT(src_port != NULL);
  SSH_ASSERT(dst_port != NULL);
  SSH_ASSERT(spi != NULL);
  SSH_ASSERT(cookie != NULL);

  /* Packet does not have enough bytes for the IP header */
  if (pc->hdrlen > packet_len)
    goto error;

  if (pp->protocol == SSH_PROTOCOL_IP4)
    {
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH4_HDRLEN, pullup_buf);
      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      *ipproto = SSH_IPH4_PROTO(ucp);
      offset = pc->hdrlen;
    }
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      unsigned char nh = 0;

      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH6_HDRLEN, pullup_buf);
      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      nh = SSH_IPH6_NH(ucp);
      offset = SSH_IPH6_HDRLEN;
      while (SSH_IP6_EXT_IS_COMMON(nh) && offset < packet_len)
        {
          /* Not enough data for the common part of the extension header */
          if (packet_len - offset < SSH_IP6_EXT_COMMON_HDRLEN)
            goto error;

          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_IP6_EXT_COMMON_HDRLEN,
                                    pullup_buf);
          if (ucp == NULL)
            {
              pp = NULL;
              goto error;
            }

          nh = SSH_IP6_EXT_COMMON_NH(ucp);
          offset += SSH_IP6_EXT_COMMON_LENB(ucp);
        }
      *ipproto = nh;
    }
#endif /* WITH_IPV6 */
  else
    goto error;

  SSH_DEBUG(SSH_D_LOWOK, ("ipproto 0x%x", *ipproto));
  switch (*ipproto)
    {
    case SSH_IPPROTO_TCP:
      /* Packet does not have enough bytes for the TCP header */
      if ((offset + SSH_TCPH_HDRLEN) > packet_len)
        goto error;

      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_TCPH_HDRLEN, pullup_buf);
      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      *src_port = SSH_TCPH_SRCPORT(ucp);
      *dst_port = SSH_TCPH_DSTPORT(ucp);

#ifdef DEBUG_LIGHT
      flags = SSH_TCPH_FLAGS(ucp);
      SSH_DEBUG(SSH_D_LOWOK, ("TCP src_port %d dst_port %d %s%s%s%s%s%s",
                              (int) *src_port, (int) *dst_port,
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
#endif /* DEBUG_LIGHT */
      return TRUE;

    case SSH_IPPROTO_UDP:
      /* Packet does not have enough bytes for the UDP header */
      if ((offset + SSH_UDPH_HDRLEN) > packet_len)
        goto error;

      /* Set the 'cookie' pointer to point to UDP payload,
         if there is enough data */

      /* Pullup UDP header and start of IKE header if there is enough bytes. */
      if ((offset + SSH_UDPH_HDRLEN + 2 * SSH_ENGINE_IKE_COOKIE_LENGTH)
          <= packet_len)
        {
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset,
                                    SSH_UDPH_HDRLEN +
                                    SSH_ENGINE_IKE_COOKIE_LENGTH,
                                    pullup_buf);
          get_cookie = TRUE;
        }
      else
        {
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_UDPH_HDRLEN,
                                    pullup_buf);
        }

      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      /* Get UDP ports. */
      *src_port = SSH_UDPH_SRCPORT(ucp);
      *dst_port = SSH_UDPH_DSTPORT(ucp);

      /* Get IKE initiator cookie. */
      if (get_cookie)
        memcpy(cookie, ucp + SSH_UDPH_HDRLEN, SSH_ENGINE_IKE_COOKIE_LENGTH);

#ifdef DEBUG_LIGHT
      if (get_cookie)
        SSH_DEBUG(SSH_D_LOWOK,
                  ("UDP src_port %d dst_port %d IKE cookie 0x%lx 0x%lx",
                   (int) *src_port, (int) *dst_port,
                   (unsigned long) SSH_GET_32BIT(cookie),
                   (unsigned long) SSH_GET_32BIT(cookie + 4)));
      else
        SSH_DEBUG(SSH_D_LOWOK, ("UDP src_port %d dst_port %d",
                                (int) *src_port, (int) *dst_port));
#endif /* DEBUG_LIGHT */
      return TRUE;

    case SSH_IPPROTO_ESP:
      /* Packet does not have enough bytes for the start of ESP header */
      if ((offset + 4) > packet_len)
        goto error;

      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, 4, pullup_buf);
      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      *spi = SSH_GET_32BIT(ucp);
      SSH_DEBUG(SSH_D_LOWOK, ("ESP spi 0x%lx", (unsigned long) *spi));
      return TRUE;

    case SSH_IPPROTO_AH:
      /* Packet does not have enough bytes for the start of AH header */
      if ((offset + 8) > packet_len)
        goto error;

      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, 8, pullup_buf);
      if (ucp == NULL)
        {
          pp = NULL;
          goto error;
        }

      *spi = SSH_GET_32BIT(ucp + SSH_AHH_OFS_SPI);
      SSH_DEBUG(SSH_D_LOWOK, ("AH spi 0x%lx", (unsigned long) *spi));
      return TRUE;

    default:
      break;
    }

  return TRUE;

 error:
  if (pp)
    ssh_interceptor_packet_free(pp);

  return FALSE;
}

/*
 * Lookup connection table for a (local_addr, peer_addr, ESP spi)
 * match. Return connection entry.
 */
static SshEngineTcpEncapsConn
ssh_engine_tcp_encaps_conn_by_spi(SshEngine engine,
                                  SshIpAddr local_addr,
                                  SshIpAddr peer_addr,
                                  SshInetIPProtocolID ipproto,
                                  SshUInt32 spi)
{
  SshEngineTcpEncapsConn conn;
  SshUInt32 hash = 0;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Connection table lookup for [%@] - [%@] %s SPI 0x%lx",
             ssh_ipaddr_render, local_addr,
             ssh_ipaddr_render, peer_addr,
             (ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH"),
             (unsigned long) spi));

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  /* Lookup connection table */
  do {
    conn = engine->tcp_encaps_connection_table[hash];
    while (conn)
      {
        if (SSH_IP_EQUAL(local_addr, &conn->local_addr)
            && SSH_IP_EQUAL(peer_addr, &conn->peer_addr))
          {
            for (i = 0; i < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; i++)
              if (ipproto == SSH_IPPROTO_ESP &&
                  spi == conn->esp_outbound_spi[i])
                goto found;
              else if (ipproto == SSH_IPPROTO_AH &&
                       spi == conn->ah_outbound_spi[i])
                goto found;
          }

        conn = conn->next;
      }
    hash++;
  } while (hash < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE);

 found:
  if (hash >= SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("failed"));
      return NULL;
    }

  return conn;
}

/*
 * Lookup connection table for connection ID match.
 * Return connection entry.
 */
static SshEngineTcpEncapsConn
ssh_engine_tcp_encaps_conn_by_id(SshEngine engine,
                                 SshUInt32 conn_id)
{
  SshEngineTcpEncapsConn conn;
  SshUInt32 hash;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Connection table lookup for 0x%lx",
             (unsigned long) conn_id));

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  if (conn_id == SSH_IPSEC_INVALID_INDEX)
    return NULL;

  /* Lookup connection table */
  hash = conn_id % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE;
  conn = engine->tcp_encaps_connection_table[hash];
  while (conn)
    {
      if (conn->conn_id == conn_id)
        break;
      conn = conn->next;
    }

#ifdef DEBUG_LIGHT
  if (conn == NULL)
    SSH_DEBUG(SSH_D_LOWOK, ("failed"));
#endif /* DEBUG_LIGHT */

  return conn;
}

/*
 * Lookup connection table for (local_addr, peer_addr, ike_initiator_cookie)
 * match. If `require_active_mapping' is TRUE, then only connection entries
 * with active IKE mapping are considered. Otherwise also connection entries
 * which have no active IKE mapping are also checked. This is needed to handle
 * delayed IKEv1 SA delete notification packets that may be sent after the IKE
 * mapping is already cleared. This returns the matching connection entry.
 * The caller of this function must hold the 'tcp_encaps_lock'.
 */
static SshEngineTcpEncapsConn
ssh_engine_tcp_encaps_conn_by_cookie(SshEngine engine,
                                     SshIpAddr local_addr,
                                     SshIpAddr peer_addr,
                                     const unsigned char *ike_initiator_cookie,
                                     Boolean require_active_mapping)
{
  SshEngineTcpEncapsConn conn = NULL;
  SshUInt32 hash = 0;
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  if (!ike_initiator_cookie)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("failed"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Connection table lookup for [%@] - [%@] IKE SPI 0x%lx 0x%lx",
             ssh_ipaddr_render, local_addr,
             ssh_ipaddr_render, peer_addr,
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie + 4)));

  /* Lookup connection table */
  do {
    conn = engine->tcp_encaps_connection_table[hash];
    while (conn)
      {
        if ((local_addr == NULL
             || SSH_IP_EQUAL(local_addr, &conn->local_addr))
            && (peer_addr == NULL
                || SSH_IP_EQUAL(peer_addr, &conn->peer_addr))
            && (conn->ike_mapping_set || !require_active_mapping)
            && (memcmp(conn->ike_initiator_cookie,
                       ike_initiator_cookie,
                       SSH_ENGINE_IKE_COOKIE_LENGTH) == 0 ||
                memcmp(conn->old_ike_initiator_cookie,
                       ike_initiator_cookie,
                       SSH_ENGINE_IKE_COOKIE_LENGTH) == 0))
          break;
        conn = conn->next;
      }
    if (conn)
      break;
    hash++;
  } while (hash < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE);

  if (hash >= SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No matching connection entry found"));
      return NULL;
    }

  return conn;
}

/******************************** Visible functions **************************/

/*
 * Lookup connection by address and port information extracted from
 * a PMTU ICMP message. Consider only established connections, that
 * have the IKE negotiation phase completed. Return connection ID
 * or SSH_IPSEC_INVALID_INDEX if no matching connection was found.
 * This function is called with `flow_control_table_lock' taken.
 * This function will grab the 'tcp_encaps_lock'.
 */
SshUInt32
ssh_engine_tcp_encaps_conn_by_pmtu_info(SshEngine engine,
                                        SshIpAddr dst,
                                        SshIpAddr src,
                                        SshUInt16 dst_port,
                                        SshUInt16 src_port)
{
  SshEngineTcpEncapsConn conn;
  SshUInt32 hash;
  SshUInt32 conn_id = SSH_IPSEC_INVALID_INDEX;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Searching TCP connection entry by address-port tupple."));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Forward direction. */
  hash = engine_tcp_encaps_hash(dst, dst_port);
  conn = engine->tcp_encaps_connection_table[hash];
  while (conn)
    {
      if (SSH_IP_EQUAL(dst, &conn->peer_addr) &&
          dst_port == conn->peer_port &&
          SSH_IP_EQUAL(src, &conn->local_addr) &&
          src_port == conn->local_port)
        break;
      conn = conn->next;
    }

  /* Reverse direction. */
  if (conn == NULL)
    {
      hash = engine_tcp_encaps_hash(src, src_port);
      conn = engine->tcp_encaps_connection_table[hash];
      while (conn)
        {
          if (SSH_IP_EQUAL(src, &conn->peer_addr) &&
              src_port == conn->peer_port &&
              SSH_IP_EQUAL(dst, &conn->local_addr) &&
              dst_port == conn->local_port)
            break;
          conn = conn->next;
        }
    }

  if (conn != NULL &&
      conn->state == SSH_ENGINE_TCP_ESTABLISHED &&
      conn->negotiation_completed)
    conn_id = conn->conn_id;

  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  return conn_id;
}

void
ssh_engine_pme_tcp_encaps_create_ike_mapping(SshEngine engine,
                                           SshIpAddr local_addr,
                                           SshIpAddr peer_addr,
                                           SshUInt16 local_port,
                                           SshUInt16 peer_port,
                                           unsigned char *ike_initiator_cookie,
                                           SshUInt16 local_ike_port,
                                           SshUInt16 remote_ike_port,
                                           SshPmeIndexCB callback,
                                           void *callback_context)
{
  SshUInt32 conn_id = SSH_IPSEC_INVALID_INDEX;
  SshEngineTcpEncapsConn conn = NULL, conn_p;
  SshUInt32 hash;
  SshUInt32 tries = 0;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(local_addr != NULL);
  SSH_ASSERT(peer_addr != NULL);
  SSH_ASSERT(peer_port != 0);
  SSH_ASSERT(ike_initiator_cookie != NULL);
  SSH_ASSERT(callback != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Creating new IKE cookie mapping: "
             "%@:%d %@:%d cookie 0x%08lx 0x%08lx",
             ssh_ipaddr_render, local_addr, (int) local_ike_port,
             ssh_ipaddr_render, peer_addr, (int) local_ike_port,
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie + 4)));

  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Check that there is no colliding connection entry. */
  if (ssh_engine_tcp_encaps_conn_by_cookie(engine, local_addr, peer_addr,
                                           ike_initiator_cookie, TRUE) != NULL)
    goto unlock_out;

  /* Allocate new connection entry. */
  conn = ssh_calloc(1, sizeof(*conn));
  if (conn == NULL)
    goto unlock_out;

  conn->engine = engine;

  /* Initialize to closed state. */
  conn->state = SSH_ENGINE_TCP_CLOSED;
  conn->negotiation_completed = 0;

  /* Store cookie */
  memcpy(conn->ike_initiator_cookie, ike_initiator_cookie,
         SSH_ENGINE_IKE_COOKIE_LENGTH);
  conn->ike_mapping_set = 1;

  /* Store addresses and ports. */
  memcpy(&conn->local_addr, local_addr, sizeof(conn->local_addr));
  memcpy(&conn->peer_addr, peer_addr, sizeof(conn->peer_addr));
  conn->peer_port = peer_port;
  conn->local_ike_port = local_ike_port;
  conn->remote_ike_port = remote_ike_port;
  conn->configured_local_port = local_port;

  /* Allocate local port. */
 allocate_local_port:
  tries++;
  if (tries > 5)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to allocate free TCP port for connection entry"));
      goto unlock_out;
    }

  if (conn->configured_local_port == 0)
    conn->local_port = ssh_engine_tcp_encaps_get_free_tcp_port(engine);
  else
    conn->local_port = conn->configured_local_port;

  /* Check for TCP port collision. */
  hash = engine_tcp_encaps_hash(&conn->peer_addr, conn->peer_port);
  conn_p = engine->tcp_encaps_connection_table[hash];
  while (conn_p)
    {
      if (SSH_IP_EQUAL(&conn->peer_addr, &conn_p->peer_addr)
          && conn->peer_port == conn_p->peer_port
          && SSH_IP_EQUAL(&conn->local_addr, &conn_p->local_addr)
          && conn->local_port == conn_p->local_port)
        break;
      conn_p = conn_p->next;
    }
  /* Collision, attempt again. */
  if (conn_p != NULL)
    goto allocate_local_port;

  /* Add connection entry to connection table. */
  hash = engine_tcp_encaps_hash(&conn->peer_addr, conn->peer_port);
  conn_id = engine_tcp_encaps_add_conn(engine, conn, hash);

 unlock_out:
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  if (conn_id == SSH_IPSEC_INVALID_INDEX)
    ssh_free(conn);
  else
    SSH_DEBUG(SSH_D_MIDOK,
              ("IKE mapping created to connection 0x%lx", conn_id));

  (*callback)(engine->pm, conn_id, callback_context);
}

void
ssh_engine_pme_tcp_encaps_get_ike_mapping(SshEngine engine,
                                          SshIpAddr local_addr,
                                          SshIpAddr peer_addr,
                                          unsigned char *ike_initiator_cookie,
                                          SshPmeIndexCB callback,
                                          void *callback_context)
{
  SshEngineTcpEncapsConn conn = NULL;
  SshUInt32 conn_id_ret = SSH_IPSEC_INVALID_INDEX;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(ike_initiator_cookie != NULL);
  SSH_ASSERT(callback != NULL);

  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);
  conn = ssh_engine_tcp_encaps_conn_by_cookie(engine, local_addr, peer_addr,
                                              ike_initiator_cookie, TRUE);
  if (conn == NULL)
    goto unlock_out;

  conn_id_ret = conn->conn_id;

 unlock_out:
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Returning IKE cookie mapping: "
             "cookie 0x%08lx 0x%08lx -> conn id 0x%lx",
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie + 4),
             conn_id_ret));

  (*callback)(engine->pm, conn_id_ret, callback_context);
}

void
ssh_engine_pme_tcp_encaps_update_ike_mapping(SshEngine engine,
                                       Boolean keep_address_matches,
                                       SshIpAddr local_addr,
                                       SshIpAddr peer_addr,
                                       unsigned char *ike_initiator_cookie,
                                       unsigned char *new_ike_initiator_cookie,
                                       SshPmeIndexCB callback,
                                       void *callback_context)
{
  SshEngineTcpEncapsConn conn = NULL;
  SshUInt32 conn_id_ret = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 hash, slot;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(ike_initiator_cookie != NULL);

  /* New IKE SPI must be NULL or a valid IKE SPI. */
  SSH_ASSERT(new_ike_initiator_cookie == NULL
             || memcmp(ike_initiator_cookie, new_ike_initiator_cookie,
                       SSH_ENGINE_IKE_COOKIE_LENGTH) != 0);

  /* Addresses must be specified if keep_address_matches is TRUE. */
  SSH_ASSERT(keep_address_matches == FALSE ||
             (local_addr != NULL && peer_addr != NULL));

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Updating IKE cookie mapping for "
             "connection %@ %@ 0x%0xlx 0x%08lx "
             "new cookie 0x%08lx 0x%08lx",
             ssh_ipaddr_render, local_addr,
             ssh_ipaddr_render, peer_addr,
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie),
             (unsigned long) SSH_GET_32BIT(ike_initiator_cookie + 4),
             (new_ike_initiator_cookie != NULL ?
              (unsigned long) SSH_GET_32BIT(new_ike_initiator_cookie) : 0),
             (new_ike_initiator_cookie != NULL ?
              (unsigned long) SSH_GET_32BIT(new_ike_initiator_cookie + 4) : 0)
             ));

  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Iterate through connection entry hash table and update
     matching connection entries. */
  hash = 0;
  do {
    conn = engine->tcp_encaps_connection_table[hash];
    while (conn)
      {
        /* IKE SPI matches. */
        if (memcmp(conn->ike_initiator_cookie,
                   ike_initiator_cookie,
                   SSH_ENGINE_IKE_COOKIE_LENGTH) == 0)
          {
            /* Addresses do not match, skip connection entry. */
            if (keep_address_matches == FALSE
                && ((local_addr != NULL
                     && !SSH_IP_EQUAL(local_addr, &conn->local_addr))
                    || (peer_addr != NULL
                        && !SSH_IP_EQUAL(peer_addr, &conn->peer_addr))))
              goto next;

            /* Addresses match, skip connection entry. */
            if (keep_address_matches == TRUE
                && SSH_IP_EQUAL(local_addr, &conn->local_addr)
                && SSH_IP_EQUAL(peer_addr, &conn->peer_addr))
              goto next;
          }

        /* IKE SPI does not match. */
        else
          goto next;

        conn_id_ret = conn->conn_id;

        /* Move old cookie to a safe place. */
        memcpy(conn->old_ike_initiator_cookie, conn->ike_initiator_cookie,
               SSH_ENGINE_IKE_COOKIE_LENGTH);

        if (new_ike_initiator_cookie != NULL)
          {
            /* Save new cookie */
            SSH_DEBUG(SSH_D_MIDOK, ("IKE mapping updated to connection 0x%lx",
                                    (unsigned long) conn->conn_id));
            memcpy(conn->ike_initiator_cookie, new_ike_initiator_cookie,
                   SSH_ENGINE_IKE_COOKIE_LENGTH);
            conn->ike_mapping_set = 1;
          }
        /* NULL new_ike_initiator_cookie means the IKE mapping is removed. */
        else
          {
            SSH_DEBUG(SSH_D_MIDOK,
                      ("IKE mapping cleared from connection 0x%lx",
                       (unsigned long) conn->conn_id));
            conn_id_ret = SSH_IPSEC_INVALID_INDEX;

            /* Clear IKE cookie */
            memset(conn->ike_initiator_cookie, 0,
                   SSH_ENGINE_IKE_COOKIE_LENGTH);
            conn->ike_mapping_set = 0;
          }

        /* Check if there are any more SPI mappings. */
        for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
          {
            if (conn->esp_outbound_spi[slot] != 0
                || conn->ah_outbound_spi[slot] != 0)
              break;
          }
        /* No more SPI mappings using this encapsulating TCP connection,
           close  connection if no IKE mapping is using the connection. */
        if (slot == SSH_ENGINE_TCP_ENCAPS_MAX_SAS
            && conn->ike_mapping_set == 0)
          {
            /* Mark connection waiting to be closed. */
            if (conn->state != SSH_ENGINE_TCP_CLOSED
                && conn->state != SSH_ENGINE_TCP_CLOSE_WAIT)
              {
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Moving connection 0x%lx to state CLOSE_WAIT",
                           (unsigned long) conn->conn_id));
                conn->state = SSH_ENGINE_TCP_CLOSE_WAIT;
              }
            ssh_engine_tcp_encaps_close_conn_timeout(engine,
                                                     conn->conn_id);
            conn_id_ret = SSH_IPSEC_INVALID_INDEX;
          }

      next:
        conn = conn->next;
      }
    hash++;
  } while (hash < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE);

  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  if (callback)
    (*callback)(engine->pm, conn_id_ret, callback_context);
}

/*
 * Add SPIs to the connection entry.
 * This function will grab the 'tcp_encaps_lock'. This function is
 * called with 'flow_control_table_lock' taken.
 */
static Boolean
ssh_engine_tcp_encaps_add_spi_mapping(SshEngine engine,
                                      SshEngineTcpEncapsConn conn,
                                      SshUInt32 esp_outbound_spi,
                                      SshUInt32 ah_outbound_spi)
{
  SshUInt32 slot;

  SSH_ASSERT(conn != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  /* Mark negotiation phase completed */
  conn->negotiation_completed = 1;

  /* Cancel negotiation timeout */
  if (conn->in_negotiation_timeout_list == 1)
    engine_tcp_encaps_negotiation_timeout_list_remove(engine, conn);

  /* Add the SPIs to the SPI mapping table. */

  /* Find a free slot for the SPIs */
  for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
    {
      if (conn->esp_outbound_spi[slot] == 0
          && conn->ah_outbound_spi[slot] == 0)
        break;
    }
  if (slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS)
    {
      /* Save new SPIs */
      conn->esp_outbound_spi[slot] = esp_outbound_spi;
      conn->ah_outbound_spi[slot] = ah_outbound_spi;
      SSH_DEBUG(SSH_D_MIDOK, ("SPI mapping added to connection 0x%lx",
                              (unsigned long) conn->conn_id));
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Maximum number of IPsec SAs per encapsulating TCP "
                 "connection reached (%d) for connect 0x%lx",
                 slot, (unsigned long) conn->conn_id));
      return FALSE;
    }
}

/*
 * Bind SPIs to the connection entry. This should be called during
 * IPSec SA (re-)installation. Returns connection ID.
 * This function will grab the 'tcp_encaps_lock'. This function is
 * called with 'flow_control_table_lock' taken.
 */
SshUInt32
ssh_engine_tcp_encaps_create_spi_mapping(SshEngine engine,
                                         SshIpAddr local_addr,
                                         SshIpAddr peer_addr,
                                         unsigned char *ike_initiator_cookie,
                                         SshUInt32 esp_outbound_spi,
                                         SshUInt32 ah_outbound_spi)
{
  SshEngineTcpEncapsConn conn;
  SshUInt32 conn_id = SSH_IPSEC_INVALID_INDEX;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(local_addr != NULL);
  SSH_ASSERT(peer_addr != NULL);
  SSH_ASSERT(ike_initiator_cookie != NULL);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Creating SPI mapping for "
             "connection entry %@ %@ 0x%08lx 0x%08lx "
             "ESP 0x%lx AH 0x%lx",
             ssh_ipaddr_render, local_addr, ssh_ipaddr_render, peer_addr,
             SSH_GET_32BIT(ike_initiator_cookie),
             SSH_GET_32BIT(ike_initiator_cookie + 4),
             (unsigned long) esp_outbound_spi,
             (unsigned long) ah_outbound_spi));

  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Lookup connection */
  conn = ssh_engine_tcp_encaps_conn_by_cookie(engine, local_addr, peer_addr,
                                              ike_initiator_cookie, TRUE);

  /* No connection found for this conn_id. */
  if (conn == NULL)
    goto unlock_out;

  if (ssh_engine_tcp_encaps_add_spi_mapping(engine, conn,
                                            esp_outbound_spi, ah_outbound_spi))

    conn_id = conn->conn_id;

 unlock_out:
  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  return conn_id;
}

/* Removes SPI mappings from the connection entry. If removing the last SPI
 * mappings from connection entry, then the connection is closed and removed.
 * This function is called with 'flow_control_table_lock' and `tcp_encaps_lock'
 * taken. */
static void
ssh_engine_tcp_encaps_clear_spi_mapping(SshEngine engine,
                                        SshEngineTcpEncapsConn conn,
                                        SshUInt32 esp_outbound_spi,
                                        SshUInt32 ah_outbound_spi)
{
  SshUInt32 slot;

  SSH_ASSERT(conn != NULL);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Removing SPIs from connection entry 0x%lx "
                             "ESP 0x%lx AH 0x%lx",
                             (unsigned long) conn->conn_id,
                             (unsigned long) esp_outbound_spi,
                             (unsigned long) ah_outbound_spi));

  /* Clear SPIs from connection entry. */
  for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
    {
      if (conn->esp_outbound_spi[slot] == esp_outbound_spi
          && conn->ah_outbound_spi[slot] == ah_outbound_spi)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("SPI mapping cleared from connection 0x%lx",
                                  conn->conn_id));
          conn->esp_outbound_spi[slot] = 0;
          conn->ah_outbound_spi[slot] = 0;
          break;
        }
    }

  /* Check if there are any more SPI mappings. */
  for (slot = 0; slot < SSH_ENGINE_TCP_ENCAPS_MAX_SAS; slot++)
    {
      if (conn->esp_outbound_spi[slot] != 0
          || conn->ah_outbound_spi[slot] != 0)
        break;
    }

  /* No more SPI mappings using this encapsulating TCP connection, close
     connection if no IKE mapping is using the connection. Cannot call
     close_conn directly, since `flow_control_table_lock'is taken. */
  if (slot == SSH_ENGINE_TCP_ENCAPS_MAX_SAS && conn->ike_mapping_set == 0)
    {
      /* Mark connection waiting to be closed. */
      if (conn->state != SSH_ENGINE_TCP_CLOSED
          && conn->state != SSH_ENGINE_TCP_CLOSE_WAIT)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Moving connection 0x%lx to state CLOSE_WAIT",
                     (unsigned long) conn->conn_id));
          conn->state = SSH_ENGINE_TCP_CLOSE_WAIT;
        }
      ssh_engine_tcp_encaps_close_conn_timeout(engine, conn->conn_id);
    }
}

/* Removes SPI mappings from the connection entry. If removing the last SPI
 * mappings from connection entry, then the connection is closed and removed.
 * This function is called with 'flow_control_table_lock' taken. */
SshUInt32
ssh_engine_tcp_encaps_remove_spi_mapping(SshEngine engine,
                                         SshUInt32 conn_id,
                                         SshUInt32 esp_outbound_spi,
                                         SshUInt32 ah_outbound_spi)
{
  SshEngineTcpEncapsConn conn;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(conn_id != SSH_IPSEC_INVALID_INDEX);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Removing SPIs from connection entry 0x%lx "
                             "ESP 0x%lx AH 0x%lx",
                             (unsigned long) conn_id,
                             (unsigned long) esp_outbound_spi,
                             (unsigned long) ah_outbound_spi));

  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Lookup connection */
  conn = ssh_engine_tcp_encaps_conn_by_id(engine, conn_id);

  /* No connection found for this conn_id. */
  if (conn == NULL)
    {
      /* Unlock 'tcp_encaps_lock' */
      ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
      return conn_id;
    }

  /* Connection found, clear SPI mapping. */
  ssh_engine_tcp_encaps_clear_spi_mapping(engine, conn,
                                          esp_outbound_spi, ah_outbound_spi);

  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  return SSH_IPSEC_INVALID_INDEX;
}

/*********************** TCP encapsulation / decapsulation *******************/

/*
 * Encapsulates packet pp by inserting a TCP header after IP header and
 * by appending the IPSec over TCP trailer.
 *
 * This function assumes that 'pc' is partially valid and 'pp' is a non
 * fragment.
 *
 * On error: Frees 'pp' and returns FALSE
 */
static Boolean
ssh_engine_tcp_encaps_encapsulate(SshEnginePacketContext pc,
                                  SshInterceptorPacket pp,
                                  SshEngineTcpEncapsConn conn,
                                  SshUInt8 ipproto)
{
  unsigned char *cp, *ip_cp, *tcp_cp, *trailer_cp;
  unsigned char *ip_hdr = NULL;
  SshUInt16 checksum;
  int tcp_seg_len = 0;
  unsigned char flags = SSH_TCPH_FLAG_ACK;
  size_t pullup_length = 0;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(conn->engine->tcp_encaps_lock);
#if defined (WITH_IPV6)
  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4 ||
             pp->protocol == SSH_PROTOCOL_IP6);
#else
  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4);
#endif /* WITH_IPV6 */

  /* Handle only IKE, ESP and AH */
  SSH_ASSERT(ipproto == SSH_IPPROTO_UDP ||
             ipproto == SSH_IPPROTO_ESP ||
             ipproto == SSH_IPPROTO_AH);

  SSH_ASSERT(conn != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Encapsulating packet %p using connection entry 0x%lx",
             pp, (unsigned long) conn->conn_id));

  /* Store IP header */
  ip_hdr = ssh_malloc(pc->hdrlen);
  if (!ip_hdr)
    goto error;

  ssh_interceptor_packet_copyout(pp, 0, ip_hdr, pc->hdrlen);

  /* Insert TCP header just before L4 header */
  tcp_cp = ssh_interceptor_packet_insert(pp, pc->hdrlen, SSH_TCPH_HDRLEN);
  if (!tcp_cp)
    {
      pp = NULL;
      goto error;
    }

  /* Pullup */
  pullup_length = pc->hdrlen + SSH_TCPH_HDRLEN;

  if (ipproto == SSH_IPPROTO_UDP)
    pullup_length += SSH_UDPH_HDRLEN;

  /* Check that it is safe to pullup the requested amount. */
  if (pullup_length > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    goto error;

  cp = ssh_interceptor_packet_pullup(pp, pullup_length);
  if (!cp)
    {
      pp = NULL;
      goto error;
    }
  ip_cp = cp;
  tcp_cp = ip_cp + pc->hdrlen;

  /* Build pseudoheader */
  memset(ip_cp, 0, pc->hdrlen + SSH_TCPH_HDRLEN);
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      unsigned char *pseudo_cp = tcp_cp - SSH_IP6_PSEUDOH_HDRLEN;
      tcp_seg_len = SSH_IPH6_LEN(ip_hdr) + SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN;
      SSH_IP6_PSEUDOH_SET_SRC(&conn->local_addr, pseudo_cp);
      SSH_IP6_PSEUDOH_SET_DST(&conn->peer_addr, pseudo_cp);
      SSH_IP6_PSEUDOH_SET_LEN(pseudo_cp,
                              tcp_seg_len + SSH_TCPH_HDRLEN);
      SSH_IP6_PSEUDOH_SET_NH(pseudo_cp, SSH_IPPROTO_TCP);
    }
  else
#endif /* WITH_IPV6 */
    {
      unsigned char *pseudo_cp = tcp_cp - SSH_TCPH_PSEUDO_HDRLEN;
      tcp_seg_len = (SSH_IPH4_LEN(ip_hdr) -
                     (SSH_IPH4_HLEN(ip_hdr) * 4) +
                     SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);
      SSH_IP4_ENCODE(&conn->local_addr, pseudo_cp + SSH_TCPH_PSEUDO_OFS_SRC);
      SSH_IP4_ENCODE(&conn->peer_addr, pseudo_cp + SSH_TCPH_PSEUDO_OFS_DST);
      *(pseudo_cp + SSH_TCPH_PSEUDO_OFS_PTCL) = SSH_IPPROTO_TCP;
      SSH_PUT_16BIT(pseudo_cp + SSH_TCPH_PSEUDO_OFS_TCPLEN,
                    tcp_seg_len + SSH_TCPH_HDRLEN);
    }

  /* Build TCP header */
  SSH_TCPH_SET_SRCPORT(tcp_cp, conn->local_port);
  SSH_TCPH_SET_DSTPORT(tcp_cp, conn->peer_port);
  SSH_TCPH_SET_SEQ(tcp_cp, conn->seq);
  SSH_TCPH_SET_ACK(tcp_cp, conn->ack);
  SSH_TCPH_SET_DATAOFFSET(tcp_cp, SSH_TCPH_HDRLEN / 4);
  SSH_TCPH_SET_FLAGS(tcp_cp, flags);
  SSH_TCPH_SET_WINDOW(tcp_cp, 65535);

  /* Zero UDP checksum from IKE packets to interoperate with
     Cisco VPN client. It does not recalculate UDP checksum during
     decapsulation. If there is a NAT between the peers, then the
     UDP checksum at decapsulator is invalid because of changed IP
     addresses. */
  if (ipproto == SSH_IPPROTO_UDP)
    {
      unsigned char *udp_cp = tcp_cp + SSH_TCPH_HDRLEN;
      SSH_UDPH_SET_CHECKSUM(udp_cp, 0);
    }

  /* Add magic trailer */
  trailer_cp = ssh_interceptor_packet_insert(pp,
                                             pc->hdrlen +
                                             SSH_TCPH_HDRLEN +
                                             tcp_seg_len -
                                             SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN,
                                             SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN
                                             );
  if (!trailer_cp)
    {
      pp = NULL;
      goto error;
    }
  SSH_PUT_32BIT(trailer_cp, 0);
  SSH_PUT_32BIT(trailer_cp + 4, 0);

  /* Add trailer sequence to IKE packets */
  if (pc->ipproto == SSH_IPPROTO_UDP)
    SSH_PUT_16BIT(trailer_cp + 4, SSH_IPH4_ID(ip_hdr));

  /* Add magic cookie */
  memcpy(trailer_cp + 8,
         SSH_ENGINE_TCP_ENCAPS_COOKIE_VALUE,
         SSH_ENGINE_TCP_ENCAPS_COOKIE_LEN);
  /* Add next header field */
  trailer_cp[12] = 0x10;
  trailer_cp[13] = ipproto;
  /* Add the rest */
  trailer_cp[14] = 0x01;
  trailer_cp[15] = 0x00;

  /* Calculate TCP checksum */
  SSH_DEBUG(SSH_D_LOWOK,
            ("tcp_seg_len %d pc->hdrlen %d",
             tcp_seg_len, pc->hdrlen));
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    checksum = ssh_ip_cksum_packet(pp,
                                   pc->hdrlen - SSH_IP6_PSEUDOH_HDRLEN,
                                   SSH_IP6_PSEUDOH_HDRLEN +
                                   SSH_TCPH_HDRLEN +
                                   tcp_seg_len);
  else
#endif /* WITH_IPV6 */
    checksum = ssh_ip_cksum_packet(pp,
                                   pc->hdrlen - SSH_TCPH_PSEUDO_HDRLEN,
                                   SSH_TCPH_PSEUDO_HDRLEN +
                                   SSH_TCPH_HDRLEN +
                                   tcp_seg_len);

  /* Restore IP header, length and protocol and TCP checksum
     and recalculate IPv4 checksum */
  if (!ssh_interceptor_packet_copyin(pp, 0, ip_hdr, pc->hdrlen))
    {
      pp = NULL;
      goto error;
    }

  /* Re-pullup, pullup_length has already been sanity checked. */
  pullup_length = pc->hdrlen + SSH_TCPH_HDRLEN;
  cp = ssh_interceptor_packet_pullup(pp, pullup_length);
  if (!cp)
    {
      pp = NULL;
      goto error;
    }
  ip_cp = cp;
  tcp_cp = ip_cp + pc->hdrlen;
  SSH_TCPH_SET_CHECKSUM(tcp_cp, checksum);

#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      int offset_prevnh = 0;
      int offset = 0;
      unsigned char nh = 0;

      nh = SSH_IPH6_NH(ip_cp);
      offset = SSH_IPH6_HDRLEN;
      while (nh != ipproto && offset < (pullup_length - (ip_cp - cp)))
        {
          nh = SSH_IP6_EXT_COMMON_NH(ip_cp + offset);
          offset_prevnh = offset;
          offset += SSH_IP6_EXT_COMMON_LENB(ip_cp + offset);
        }
      if (nh != ipproto)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not set next header value"));
          goto error;
        }

      /* Set next header to SSH_IPPROTO_TCP */
      if (offset_prevnh == 0)
        SSH_IPH6_SET_NH(ip_cp, SSH_IPPROTO_TCP);
      else
        SSH_IP6_EXT_COMMON_SET_NH(ip_cp + offset_prevnh, SSH_IPPROTO_TCP);

      /* Increase payload length */
      SSH_IPH6_SET_LEN(ip_cp, SSH_TCPH_HDRLEN + tcp_seg_len);
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_IPH4_SET_PROTO(ip_cp, SSH_IPPROTO_TCP);
      SSH_IPH4_SET_LEN(ip_cp,
                       SSH_IPH4_HLEN(ip_cp) * 4 +
                       SSH_TCPH_HDRLEN +
                       tcp_seg_len);
      SSH_IPH4_SET_CHECKSUM(ip_cp, 0);
      checksum = ssh_ip_cksum(ip_cp, SSH_IPH4_HLEN(ip_cp) * 4);
      SSH_IPH4_SET_CHECKSUM(ip_cp, checksum);
    }

  /* Mark packet as being checksummed by the engine. */
  pp->flags &= ~SSH_PACKET_HWCKSUM;
  pp->flags &= ~SSH_PACKET_IP4HHWCKSUM;

  /* Packet is ready */

  /* Update sequence number */
  conn->seq += tcp_seg_len;

  /* Update pc */
  pc->packet_len = ssh_interceptor_packet_len(pp);
  pc->ipproto = SSH_IPPROTO_TCP;

  ssh_free(ip_hdr);
  ip_hdr = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Packet encapsulated"));

  return TRUE;

 error:
  if (ip_hdr)
    ssh_free(ip_hdr);
  if (pp)
    ssh_interceptor_packet_free(pp);
  SSH_DEBUG(SSH_D_FAIL, ("Packet encapsulation failed"));
  return FALSE;
}

/*
 * Removes a TCP encapsulation header and trailer, and sets the
 * next header / protocol, checksum, and total length fields in the IP header.
 *
 * This function assumes that 'pp' is a reassembled packet.
 *
 * ip_cp points to start of IP header
 * tcp_cp points to start of TCP header (length SSH_TCPH_HDRLEN assumed)
 *
 * On error: Frees 'pp' and returns FALSE
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_decapsulate(SshEnginePacketContext pc,
                                  SshInterceptorPacket pp,
                                  unsigned char *ip_cp,
                                  unsigned char *tcp_cp,
                                  SshEngineTcpEncapsConn conn)
{
  size_t tcp_len = 0;
  size_t tcp_seg_len = 0;
  size_t trailer_offset = 0, offset;
  unsigned char *ucp, *udp_cp, *ike_cp;
  SshUInt16 nh;
  SshUInt16 checksum;
  unsigned char trailer[16];
  SshUInt32 seq;
  SshUInt32 trailer_seq;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(conn != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, ("Decapsulating packet %p connection entry 0x%lx",
                             pp, (unsigned long) conn->conn_id));

  ssh_kernel_mutex_assert_is_locked(conn->engine->tcp_encaps_lock);
  SSH_ASSERT(tcp_cp != NULL);

#if defined (WITH_IPV6)
  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4 ||
             pp->protocol == SSH_PROTOCOL_IP6);

  /* Let short packets through */
  if (pp->protocol == SSH_PROTOCOL_IP6 &&
      ssh_interceptor_packet_len(pp) < (SSH_IPH6_HDRLEN +
                                        SSH_TCPH_HDRLEN +
                                        SSH_UDPH_HDRLEN +
                                        SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Short IPv6 packet, drop"));
      goto drop;
    }
#else /* WITH_IPV6 */

  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4);
#endif /* WITH_IPV6 */
  if (pp->protocol == SSH_PROTOCOL_IP4 &&
      ssh_interceptor_packet_len(pp) < (SSH_IPH4_HDRLEN +
                                        SSH_TCPH_HDRLEN +
                                        SSH_UDPH_HDRLEN +
                                        SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Short IPv4 packet, drop"));
      goto drop;
    }





  seq = SSH_TCPH_SEQ(tcp_cp);
  tcp_len = SSH_TCPH_DATAOFFSET(tcp_cp) * 4;
  if (pp->protocol == SSH_PROTOCOL_IP4)
    tcp_seg_len = SSH_IPH4_LEN(ip_cp) - (SSH_IPH4_HLEN(ip_cp) * 4) - tcp_len;
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    tcp_seg_len = SSH_IPH6_LEN(ip_cp) - tcp_len;
#endif /* WITH_IPV6 */

  /* Read next header from TCP trailer */
  trailer_offset = pc->hdrlen +
                   tcp_len +
                   tcp_seg_len -
                   SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN;

  ssh_interceptor_packet_copyout(pp, trailer_offset, trailer,
                                 SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);

  /* Save trailer data */
  trailer_seq = SSH_GET_16BIT(trailer + 4);
  memcpy(conn->cookie, trailer + 8, SSH_ENGINE_TCP_ENCAPS_COOKIE_LEN);
#ifdef DEBUG_LIGHT
  if (memcmp(conn->cookie,
             SSH_ENGINE_TCP_ENCAPS_COOKIE_VALUE,
             SSH_ENGINE_TCP_ENCAPS_COOKIE_LEN) != 0)
    SSH_DEBUG(SSH_D_LOWOK,
              ("Warning: Unexpected TCP trailer cookie 0x%lx",
               (unsigned long) *((SshUInt32 *) conn->cookie) ));
#endif /* DEBUG_LIGHT */
  nh = trailer[13];

  /* Check next header */



  switch(nh)
    {
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported IPSec over TCP payload protocol %d", nh));
      goto error;
    }

  /* Set protocol / next header and length fields
     in IP header and recalculate IPv4 header checksum */
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      SSH_IP6_EXT_COMMON_SET_NH(ip_cp + pc->ipsec_offset_prevnh, nh);
      SSH_IPH6_SET_LEN(ip_cp, tcp_seg_len - SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_IPH4_SET_LEN(ip_cp, ((SSH_IPH4_HLEN(ip_cp) * 4) +
                               tcp_seg_len -
                               SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN));
      SSH_IPH4_SET_PROTO(ip_cp, nh);
      SSH_IPH4_SET_CHECKSUM(ip_cp, 0);
      checksum = ssh_ip_cksum(ip_cp, SSH_IPH4_HLEN(ip_cp) * 4);
      SSH_IPH4_SET_CHECKSUM(ip_cp, checksum);
    }

  /* Remove TCP trailer */
  if (!ssh_interceptor_packet_delete(pp,
                                     trailer_offset,
                                     SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN))
    {
      pp = NULL;
      goto error;
    }

  /* Remove TCP header */
  if (!ssh_interceptor_packet_delete(pp, pc->hdrlen, tcp_len))
    {
      pp = NULL;
      goto error;
    }

  /* Save information */
  switch(nh)
    {
    case SSH_IPPROTO_UDP:
#ifdef DEBUG_LIGHT
      if (trailer_seq != 0 && trailer_seq <= conn->trailer_seq)
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Warning: Unexpected TCP trailer sequence 0x%x",
                   trailer_seq));
#endif /* DEBUG_LIGHT */
      conn->trailer_seq = trailer_seq;

      /* Pullup UDP header */
      offset = pc->hdrlen
        + SSH_UDPH_HDRLEN
        + 2 * SSH_ENGINE_IKE_COOKIE_LENGTH
        + 2;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Possible non-ESP marker. */
      offset += 4;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Pullup start of IKE header, if there are enough bytes. */
      if (offset > ssh_interceptor_packet_len(pp))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("UDP packet too short to contain IKE"));
          break;
        }

      /* Check that it is safe to pullup the start of IKE header. */
      if (offset > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
        goto error;

      ucp = ssh_interceptor_packet_pullup(pp, offset);
      if (!ucp)
        {
          pp = NULL;
          goto error;
        }
      udp_cp = ucp + pc->hdrlen;

      /* Check IKE ports */
      if (SSH_UDPH_SRCPORT(udp_cp) == conn->remote_ike_port &&
          SSH_UDPH_DSTPORT(udp_cp) == conn->local_ike_port)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("IKE"));
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Non-IKE UDP packet"));
          break;
        }

      /* Check IKE */
      ike_cp = udp_cp + SSH_UDPH_HDRLEN;

      /* Save IKE initiator cookie */
      if (ike_cp != NULL &&
          memcmp(conn->ike_initiator_cookie,
                 ike_cp,
                 SSH_ENGINE_IKE_COOKIE_LENGTH) != 0 &&
          memcmp(conn->old_ike_initiator_cookie,
                 ike_cp,
                 SSH_ENGINE_IKE_COOKIE_LENGTH) != 0)
        {
          /* Move old cookie to a safe place */
          memcpy(conn->old_ike_initiator_cookie,
                 conn->ike_initiator_cookie,
                 SSH_ENGINE_IKE_COOKIE_LENGTH);
          /* Save new cookie */
          memcpy(conn->ike_initiator_cookie,
                 ike_cp,
                 SSH_ENGINE_IKE_COOKIE_LENGTH);
          conn->ike_mapping_set = 1;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Saved IKE initiator cookie 0x%lx 0x%lx",
                     (unsigned long)
                     SSH_GET_32BIT(conn->ike_initiator_cookie),
                     (unsigned long)
                     SSH_GET_32BIT(conn->ike_initiator_cookie + 4)));
        }

      /* Reset UDP checksum */
#if defined (WITH_IPV6)
      /* UDP checksum on IPv6 is mandatory, that is non-zero.  */
      if (pp->protocol == SSH_PROTOCOL_IP6)
        {
          if (!ssh_ip_cksum_packet_compute(pp, 0, pc->hdrlen))
            {
              pp = NULL;
              goto error;
            }
        }
      else
#endif /* WITH_IPV6 */
        SSH_UDPH_SET_CHECKSUM(udp_cp, 0);

      /* Mark that packet checksum has not been verified by hardware. */
      pp->flags &= ~SSH_PACKET_HWCKSUM;

      break;

    case SSH_IPPROTO_ESP:
      break;

    default:
      break;
    }

  /* Packet is ready */

  /* Update acknowledgement number */
  if (seq != conn->ack)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Expected TCP sequence 0x%lx got 0x%lx",
                 (unsigned long) seq, (unsigned long) conn->ack));
      if (seq + tcp_seg_len > conn->ack)
        conn->ack = seq + tcp_seg_len;
    }
  else
    {
      conn->ack += tcp_seg_len;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Packet decapsulated"));
  return SSH_ENGINE_RET_RESTART;

 drop:
  return SSH_ENGINE_RET_DROP;

 error:
  if (pp)
    ssh_interceptor_packet_free(pp);
  SSH_DEBUG(SSH_D_FAIL, ("Packet decapsulation failed"));
  return SSH_ENGINE_RET_ERROR;
}

/*********************** TCP packet sending and receiving ********************/

/* Send a packet using ssh_engine_send_packet. This function must be called
   with no locks taken. */
static void
ssh_engine_tcp_encaps_send_packet(SshEngine engine,
                                  SshInterceptorPacket pp,
                                  SshInetIPProtocolID ipproto,
                                  SshIpAddr src, SshIpAddr dst)
{
  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(src != NULL && SSH_IP_DEFINED(src));
  SSH_ASSERT(dst != NULL && SSH_IP_DEFINED(dst));
  SSH_DEBUG(SSH_D_MIDOK, ("Sending %s packet %p: src %@ dst %@",
                          (ipproto == SSH_IPPROTO_TCP ? "TCP" :
                           (ipproto == SSH_IPPROTO_UDP ? "UDP" : "")), pp,
                          ssh_ipaddr_render, src,
                          ssh_ipaddr_render, dst));
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    ssh_engine_send_packet(engine, pp,
                           SSH_IPH6_HDRLEN, SSH_IPSEC_INVALID_INDEX,
                           (const SshIpAddr) src, (const SshIpAddr) dst,
                           ipproto, 0, 0, FALSE);
  else
#endif /* WITH_IPV6 */
    ssh_engine_send_packet(engine, pp,
                           SSH_IPH4_HDRLEN, SSH_IPSEC_INVALID_INDEX,
                           (const SshIpAddr) src, (const SshIpAddr) dst,
                           ipproto, 0, 0, FALSE);
}

/*
 * Builds a TCP packet.
 *
 * Parameter 'data' points to the payload data of length 'data_len'
 * that is to be sent as the TCP payload. 'data' may be NULL in which
 * case a packet with only IP and TCP headers (TCP handshake) is sent out.
 */
#warning "Routing instance needed."
static SshInterceptorPacket
ssh_engine_tcp_encaps_build_handshake(SshEngine engine,
                                      SshUInt16 ip_id,
                                      SshIpAddr src_addr, SshUInt16 src_port,
                                      SshIpAddr dst_addr, SshUInt16 dst_port,
                                      SshUInt32 seq, SshUInt32 ack,
                                      SshUInt16 flags,
                                      unsigned char *data, size_t data_len)
{
  SshInterceptorPacket pp = NULL;
  SshInterceptorProtocol proto;
  size_t total_len;
  size_t ip_hdr_len;
  size_t tcp_len;
  unsigned char *ip_cp, *tcp_cp, *data_cp;
  SshUInt16 checksum;
  SshUInt32 pp_flags = SSH_PACKET_FROMPROTOCOL;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Building handshake packet: %@:%d %@:%d %s%s%s%s%s%s",
             ssh_ipaddr_render, src_addr, (int) src_port,
             ssh_ipaddr_render, dst_addr, (int) dst_port,
             (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
             (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
             (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
             (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
             (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
             (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));

  /* Sanity check addresses. */
  if (!SSH_IP_IS6(dst_addr) && !SSH_IP_IS6(src_addr))
    {
      ip_hdr_len = SSH_IPH4_HDRLEN;
      proto = SSH_PROTOCOL_IP4;
    }
#if defined (WITH_IPV6)
  else if (SSH_IP_IS6(dst_addr) && SSH_IP_IS6(src_addr))
    {
      ip_hdr_len = SSH_IPH6_HDRLEN;
      proto = SSH_PROTOCOL_IP6;
    }
#endif /* WITH_IPV6 */
  else
    goto error;

  /* Allocate packet */
  total_len = ip_hdr_len + SSH_TCPH_HDRLEN + data_len;

  /* Leave the interface numbers unset,
     as the packet is going to get routed. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor, pp_flags, proto,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    total_len);
  if (!pp)
    goto error;

  SSH_ASSERT((total_len - data_len) <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);
  ip_cp = ssh_interceptor_packet_pullup(pp, total_len - data_len);
  if (!ip_cp)
    {
      pp = NULL;
      goto error;
    }

  memset(ip_cp, 0, total_len - data_len);

#if defined (WITH_IPV6)
  /* Build pseudoheader */
  if (proto == SSH_PROTOCOL_IP6)
    {
      SSH_IP6_PSEUDOH_SET_SRC(src_addr, ip_cp);
      SSH_IP6_PSEUDOH_SET_DST(dst_addr, ip_cp);
      SSH_IP6_PSEUDOH_SET_LEN(ip_cp, SSH_TCPH_HDRLEN);
      SSH_IP6_PSEUDOH_SET_NH(ip_cp, SSH_IPPROTO_TCP);
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_IP4_ENCODE(src_addr, ip_cp + 8);
      SSH_IP4_ENCODE(dst_addr, ip_cp + 12);
      ip_cp[17] = SSH_IPPROTO_TCP;
      SSH_PUT_16BIT(ip_cp + 18, SSH_TCPH_HDRLEN);
    }

  /* Build TCP header */
  tcp_cp = ip_cp + ip_hdr_len;
  SSH_TCPH_SET_SRCPORT(tcp_cp, src_port);
  SSH_TCPH_SET_DSTPORT(tcp_cp, dst_port);
  SSH_TCPH_SET_SEQ(tcp_cp, seq);
  SSH_TCPH_SET_ACK(tcp_cp, ack);
  SSH_TCPH_SET_DATAOFFSET(tcp_cp, SSH_TCPH_HDRLEN / 4);
  SSH_TCPH_SET_FLAGS(tcp_cp, flags);
  SSH_TCPH_SET_WINDOW(tcp_cp, 65535);

  /* Add data */
  data_cp = tcp_cp + SSH_TCPH_HDRLEN;
  if (data_len > 0)
    {
      if (!ssh_interceptor_packet_copyin(pp, data_cp - ip_cp, data, data_len))
        {
          pp = NULL;
          goto error;
        }
    }

  /* Calculate TCP checksum, build IP header, ans send packet */
  tcp_len = ssh_interceptor_packet_len(pp) - (tcp_cp - ip_cp);
#if defined (WITH_IPV6)
  if (proto == SSH_PROTOCOL_IP6)
    {
      checksum = ssh_ip_cksum_packet(pp,
                                     ip_hdr_len - SSH_IP6_PSEUDOH_HDRLEN,
                                     tcp_len + SSH_IP6_PSEUDOH_HDRLEN);
      SSH_TCPH_SET_CHECKSUM(tcp_cp, checksum);

      /* Build IPv6 header */
      SSH_IPH6_SET_VERSION(ip_cp, 6);
      SSH_IPH6_SET_CLASS(ip_cp, 0);
      SSH_IPH6_SET_FLOW(ip_cp, 0);
      SSH_IPH6_SET_LEN(ip_cp, total_len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_NH(ip_cp, SSH_IPPROTO_TCP);
      SSH_IPH6_SET_HL(ip_cp, 240);
      SSH_IPH6_SET_SRC(src_addr, ip_cp);
      SSH_IPH6_SET_DST(dst_addr, ip_cp);
    }
  else
#endif /* WITH_IPV6 */
    {
      checksum = ssh_ip_cksum_packet(pp,
                                     ip_hdr_len - SSH_TCPH_PSEUDO_HDRLEN,
                                     tcp_len + SSH_TCPH_PSEUDO_HDRLEN);
      SSH_TCPH_SET_CHECKSUM(tcp_cp, checksum);

      /* Build IP header */
      SSH_IPH4_SET_VERSION(ip_cp, 4);
      SSH_IPH4_SET_HLEN(ip_cp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ip_cp, total_len);
      SSH_IPH4_SET_ID(ip_cp, ip_id);
      SSH_IPH4_SET_TTL(ip_cp, 240);
      SSH_IPH4_SET_PROTO(ip_cp, SSH_IPPROTO_TCP);
      SSH_IPH4_SET_CHECKSUM(ip_cp, 0);
      SSH_IPH4_SET_SRC(src_addr, ip_cp);
      SSH_IPH4_SET_DST(dst_addr, ip_cp);
      checksum = ssh_ip_cksum(ip_cp, SSH_IPH4_HDRLEN);
      SSH_IPH4_SET_CHECKSUM(ip_cp, checksum);
    }

  return pp;

 error:
  if (pp)
    ssh_interceptor_packet_free(pp);
  return NULL;
}


/* Tcpencaps timeout resolution in microseconds. */
#define SSH_ENGINE_TCPENCAPS_TIMER_RESOLUTION 10000

/* Round time in microseconds down to tcpencaps timer resolution. */
#define SSH_ENGINE_TCPENCAPS_TIME_USEC_ROUND(usec)                      \
  (((long) (usec) / SSH_ENGINE_TCPENCAPS_TIMER_RESOLUTION)              \
   * SSH_ENGINE_TCPENCAPS_TIMER_RESOLUTION)

/* Compare two times within tcpencaps timer resolution. */
#define SSH_ENGINE_TCPENCAPS_TIME_CMP(a_sec, a_usec, b_sec, b_usec)     \
  ((a_sec) < (b_sec) ? -1 :                                             \
   ((a_sec) == (b_sec) ?                                                \
    ((SSH_ENGINE_TCPENCAPS_TIME_USEC_ROUND(a_usec) -                    \
      (SSH_ENGINE_TCPENCAPS_TIME_USEC_ROUND(b_usec)))) : 1))

/*
 * Process connections in the initial timeout list.
 *
 * If the TCP handshake is not completed, this function closes the TCP
 * connection and frees the trigger packet.
 *
 * If the TCP handshake is completed, this function does nothing.
 */
static void
engine_tcp_encaps_process_initial_timeout_list(SshEngine engine,
                                               SshTime now_sec,
                                               SshUInt32 now_usec,
                                               SshTime *next_to_sec,
                                               SshUInt32 *next_to_usec)
{
  SshEngineTcpEncapsConn conn, prev_conn, next_conn;

  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Process initial timeout list */
  prev_conn = NULL;
  next_conn = NULL;
  for (conn = engine->tcp_encaps_initial_timeout_list;
       conn != NULL;
       conn = next_conn)
    {
      SSH_ASSERT(conn->in_initial_timeout_list == 1);
      next_conn = conn->timeout_next;

      if (SSH_ENGINE_TCPENCAPS_TIME_CMP(conn->timeout_sec,
                                        conn->timeout_usec,
                                        now_sec, now_usec) <= 0)
        {
          /* Remove connection from initial timeout list */
          if (prev_conn != NULL)
            {
              prev_conn->timeout_next = conn->timeout_next;
            }
          else
            {
              SSH_ASSERT(engine->tcp_encaps_initial_timeout_list == conn);
              engine->tcp_encaps_initial_timeout_list = conn->timeout_next;
            }
          conn->in_initial_timeout_list = 0;

          /* Timeout connection */
          if (conn->state != SSH_ENGINE_TCP_ESTABLISHED)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("TCP handshake timeout"));
              ssh_engine_tcp_encaps_remove_conn(engine, conn);
            }
        }
      else
        {
          if ((*next_to_sec == 0 && *next_to_usec == 0)
              || SSH_ENGINE_TCPENCAPS_TIME_CMP(conn->timeout_sec,
                                               conn->timeout_usec,
                                               *next_to_sec,
                                               *next_to_usec) < 0)
            {
              *next_to_sec = conn->timeout_sec;
              *next_to_usec = conn->timeout_usec;
            }
          prev_conn = conn;
        }
    }

  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
}

/*
 * Process connections in the negotiation timeout list.
 *
 * If the IKE negotiation is not completed, this function closes the TCP
 * connection.
 *
 * If the IKE negotiation is completed, this function does nothing.
 */
static void
engine_tcp_encaps_process_negotiation_timeout_list(SshEngine engine,
                                                   SshTime now_sec,
                                                   SshUInt32 now_usec,
                                                   SshTime *next_to_sec,
                                                   SshUInt32 *next_to_usec)
{
  SshEngineTcpEncapsConn conn, prev_conn, next_conn;
  SshInterceptorPacket handshake_packet = NULL;
  SshIpAddrStruct handshake_src, handshake_dst;

 restart:
  /* Grab 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Process negotiation timeout list */
  prev_conn = NULL;
  next_conn = NULL;
  for (conn = engine->tcp_encaps_negotiation_timeout_list;
       conn != NULL;
       conn = next_conn)
    {
      SSH_ASSERT(conn->in_negotiation_timeout_list == 1);
      next_conn = conn->timeout_next;

      if (SSH_ENGINE_TCPENCAPS_TIME_CMP(conn->timeout_sec,
                                        conn->timeout_usec,
                                        now_sec, now_usec) <= 0)
        {
          /* Remove connection from negotiation timeout list */
          if (prev_conn != NULL)
            {
              prev_conn->timeout_next = conn->timeout_next;
            }
          else
            {
              SSH_ASSERT(engine->tcp_encaps_negotiation_timeout_list == conn);
              engine->tcp_encaps_negotiation_timeout_list = conn->timeout_next;
            }
          conn->in_negotiation_timeout_list = 0;

          /* Close connection if IKE negotiation has not completed. */
          if (conn->negotiation_completed == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("IKE negotiation timeout"));
              ssh_engine_tcp_encaps_close_conn(engine, conn, &handshake_packet,
                                               &handshake_src, &handshake_dst);

              /* Unlock 'tcp_enacps_lock' */
              ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

              /* Send (possible) RST packet. */
              if (handshake_packet != NULL)
                {
                  ssh_engine_tcp_encaps_send_packet(engine, handshake_packet,
                                                    SSH_IPPROTO_TCP,
                                                    &handshake_src,
                                                    &handshake_dst);
                  handshake_packet = NULL;
                }

              /* Restart list processing from the head. */
              goto restart;
            }
        }
      else
        {
          if ((*next_to_sec == 0 && *next_to_usec == 0)
              || SSH_ENGINE_TCPENCAPS_TIME_CMP(conn->timeout_sec,
                                               conn->timeout_usec,
                                               *next_to_sec,
                                               *next_to_usec) < 0)
            {
              *next_to_sec = conn->timeout_sec;
              *next_to_usec = conn->timeout_usec;
            }
          prev_conn = conn;
        }
    }

  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
}

/*
 * Callback for tcpencaps timer.
 *
 * This timeout callback will iterate through the connections in the initial
 * and the negotiation timeout lists and process each connection.
 */
static void
engine_tcp_encaps_timeout_cb(void *context)
{
  SshEngine engine = context;
  SshTime now_sec, next_to_sec, timeout_sec;
  SshUInt32 now_usec, next_to_usec, timeout_usec;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_interceptor_get_time(&now_sec, &now_usec);

  SSH_DEBUG(SSH_D_LOWOK, ("Tcpencaps timeout: now %lu.%06lu",
                          (unsigned long) now_sec,
                          (unsigned long) now_usec));

  next_to_sec = 0;
  next_to_usec = 0;

  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);
  engine->tcp_encaps_timeout_sec = 0;
  engine->tcp_encaps_timeout_usec = 0;
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  /* Process connections in initial timeout list */
  engine_tcp_encaps_process_initial_timeout_list(engine, now_sec, now_usec,
                                                 &next_to_sec, &next_to_usec);

  /* Process connections in negotiation timeout list */
  engine_tcp_encaps_process_negotiation_timeout_list(engine, now_sec, now_usec,
                                                     &next_to_sec,
                                                     &next_to_usec);

  /* Register next timeout */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  if (next_to_sec == 0 && next_to_usec == 0
      && engine->tcp_encaps_timeout_sec == 0
      && engine->tcp_encaps_timeout_usec == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Tcpencaps timeout stopped"));
      goto unlock_out;
    }

  /* Check if next connection event for the connections in the timeout lists
     is before any previously registered connection event. */
  timeout_sec = 0;
  timeout_usec = 0;
  if ((next_to_sec != 0 || next_to_usec != 0)
      && ((engine->tcp_encaps_timeout_sec == 0
           && engine->tcp_encaps_timeout_usec == 0)
          || SSH_ENGINE_TCPENCAPS_TIME_CMP(next_to_sec,
                                           next_to_usec,
                                           engine->tcp_encaps_timeout_sec,
                                           engine->tcp_encaps_timeout_usec)
          < 0))
    {
      if (SSH_ENGINE_TCPENCAPS_TIME_CMP(next_to_sec, next_to_usec,
                                        now_sec, now_usec) > 0)
        {
          SSH_ENGINE_TIME_SUB(timeout_sec, timeout_usec,
                              next_to_sec, next_to_usec,
                              now_sec, now_usec);
        }
    }
  else
    {
      if (SSH_ENGINE_TCPENCAPS_TIME_CMP(engine->tcp_encaps_timeout_sec,
                                        engine->tcp_encaps_timeout_usec,
                                        now_sec, now_usec) > 0)
        {
          SSH_ENGINE_TIME_SUB(timeout_sec, timeout_usec,
                              engine->tcp_encaps_timeout_sec,
                              engine->tcp_encaps_timeout_usec,
                              now_sec, now_usec);
        }
    }

  /* Adjust the timeout if it would trigger too soon. */
  if (timeout_sec == 0
      && timeout_usec < SSH_ENGINE_TCPENCAPS_TIMER_RESOLUTION)
    timeout_usec = SSH_ENGINE_TCPENCAPS_TIMER_RESOLUTION;

  /* Calculate absolute time of next tcpencaps timeout. */
  SSH_ENGINE_TIME_ADD(engine->tcp_encaps_timeout_sec,
                      engine->tcp_encaps_timeout_usec,
                      now_sec, now_usec,
                      timeout_sec, timeout_usec);

  /* Move the tcp encaps timeout. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Re-registering tcpencaps timeout to %lu.%06lus at %lu.%06lu",
             (unsigned long) timeout_sec,
             (unsigned long) timeout_usec,
             (unsigned long) engine->tcp_encaps_timeout_sec,
             (unsigned long) engine->tcp_encaps_timeout_usec));

  /* Moving of a timeout from the same timeout is guaranteed to succeed.*/
  SSH_VERIFY(ssh_kernel_timeout_move(timeout_sec, timeout_usec,
                                     engine_tcp_encaps_timeout_cb, engine)
             == TRUE);

 unlock_out:
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
}

static void
engine_tcp_encaps_timeout_schedule(SshEngine engine,
                                   SshEngineTcpEncapsConn conn,
                                   SshUInt32 timeout_sec)
{
  SshTime now_sec;
  SshUInt32 now_usec;

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  ssh_interceptor_get_time(&now_sec, &now_usec);

  conn->timeout_sec = now_sec + timeout_sec;
  conn->timeout_usec = now_usec;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Scheduling timeout for connection 0x%lx to %lu.%06lus "
             "at %lu.%06lu",
             (unsigned long) conn->conn_id,
             (unsigned long) timeout_sec,
             (unsigned long) 0,
             (unsigned long) conn->timeout_sec,
             (unsigned long) conn->timeout_usec));

  if ((engine->tcp_encaps_timeout_sec == 0
       && engine->tcp_encaps_timeout_usec == 0)
      || SSH_ENGINE_TCPENCAPS_TIME_CMP(conn->timeout_sec,
                                       conn->timeout_usec,
                                       engine->tcp_encaps_timeout_sec,
                                       engine->tcp_encaps_timeout_usec) < 0)
    {
      engine->tcp_encaps_timeout_sec = conn->timeout_sec;
      engine->tcp_encaps_timeout_usec = conn->timeout_usec;

      SSH_DEBUG(SSH_D_LOWOK,
                ("Moving tcpencaps timeout to %lu.%06lus at %lu.%06lu",
                 (unsigned long) timeout_sec,
                 (unsigned long) 0,
                 (unsigned long) engine->tcp_encaps_timeout_sec,
                 (unsigned long) engine->tcp_encaps_timeout_usec));

      if (ssh_kernel_timeout_move(timeout_sec, 0,
                                  engine_tcp_encaps_timeout_cb, engine)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Registering tcpencaps timeout to %lu.%06lus "
                     "at %lu.%06lu",
                     (unsigned long) timeout_sec,
                     (unsigned long) 0,
                     (unsigned long) engine->tcp_encaps_timeout_sec,
                     (unsigned long) engine->tcp_encaps_timeout_usec));

          ssh_kernel_timeout_register(timeout_sec, 0,
                                      engine_tcp_encaps_timeout_cb, engine);
        }
    }
}



/*
 * Handles a TCP SYN from peer.
 *
 * This function replies to peer with a TCP SYN-ACK and starts the
 * TCP handshake timer.
 *
 * If 'conn' is NULL, then this is new incoming connection attempt,
 * and this funtion will add a new entry to the connection table.
 *
 * If 'conn' is not NULL, then this is either a duplicate SYN or
 * a simultaneous SYN, and the old connection entry is re-used.
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_syn(SshEngine engine,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 unsigned char *tcp_cp,
                                 SshEngineTcpEncapsConn conn,
                                 SshEngineTcpEncapsConfig config,
                                 SshInterceptorPacket *reply_packet,
                                 SshIpAddr reply_src, SshIpAddr reply_dst)
{
  SshUInt16 ip_id = ssh_engine_get_ip_id(engine);
  SshUInt32 hash = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 seq = ssh_rand();
  SshUInt32 ack = SSH_TCPH_SEQ(tcp_cp) + 1;
  SshUInt32 conn_id;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(tcp_cp != NULL);
  SSH_ASSERT(reply_packet != NULL && *reply_packet == NULL);
  SSH_ASSERT(reply_src != NULL && reply_dst != NULL);

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing inbound SYN to connection 0x%lx",
                             (unsigned long) (conn ? conn->conn_id :
                                              SSH_IPSEC_INVALID_INDEX)));

  /* New handshake. */
  if (conn == NULL)
    {
      conn = ssh_calloc(1, sizeof(*conn));
      if (conn == NULL)
        goto error;

      /* Calculate hash and put connection to hashtable later */
      hash = engine_tcp_encaps_hash(&pc->src, pc->u.rule.src_port);

      /* Initialize */
      conn->engine = engine;
    }

  /* SYN to an existing connection with ongoing TCP handshake. */
  else
    {
      /* Free trigger packet and reuse connection entry. */
      if (conn->trigger_packet != NULL)
        ssh_interceptor_packet_free(conn->trigger_packet);
      conn->trigger_packet = NULL;
    }

  conn->state = SSH_ENGINE_TCP_SYN;
  conn->negotiation_completed = 0;

  /* Store addresses */
  memcpy(&conn->peer_addr, &pc->src, sizeof(conn->peer_addr));
  conn->peer_port = pc->u.rule.src_port;
  memcpy(&conn->local_addr, &pc->dst, sizeof(conn->local_addr));
  conn->local_port = pc->u.rule.dst_port;
  conn->configured_local_port = conn->local_port;
  if (config)
    {
      conn->local_ike_port = config->local_ike_port;
      conn->remote_ike_port = config->remote_ike_port;
    }

  /* Build SYN-ACK packet. */
  *reply_packet =
    ssh_engine_tcp_encaps_build_handshake(engine,
                                          ip_id,
                                          &pc->dst, pc->u.rule.dst_port,
                                          &pc->src, pc->u.rule.src_port,
                                          seq, ack,
                                          SSH_TCPH_FLAG_SYN |
                                          SSH_TCPH_FLAG_ACK,
                                          NULL, 0);
  if (*reply_packet == NULL)
    {
      /* Entry was put to connection table earlier, remove it */
      if (hash == SSH_IPSEC_INVALID_INDEX)
        {
          ssh_engine_tcp_encaps_remove_conn(engine, conn);
          conn = NULL;
        }
      goto error;
    }

  *reply_src = pc->dst;
  *reply_dst = pc->src;

  /* Update state and sequence numbers */
  conn->state = SSH_ENGINE_TCP_SYN_ACK;
  conn->seq = seq + 1;
  conn->ack = ack;

  /* If entry was put to connection table earlier, skip this step */
  if (hash != SSH_IPSEC_INVALID_INDEX)
    {
      /* Add created entry to connection table */
      conn_id = engine_tcp_encaps_add_conn(engine, conn, hash);
      if (conn_id == SSH_IPSEC_INVALID_INDEX)
        goto error;
      SSH_ASSERT((conn->conn_id % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE)
                 == hash);
    }

  /* Register timeout to remove a pending handshake */
  if (conn->in_initial_timeout_list == 0)
    engine_tcp_encaps_initial_timeout_list_insert(engine, conn);
  engine_tcp_encaps_timeout_schedule(engine, conn,
                                     SSH_ENGINE_TCP_ENCAPS_INITIAL_TIMEOUT);

  /* Drop the SYN packet. */
  return SSH_ENGINE_RET_DROP;

 error:
  if (conn)
    ssh_free(conn);
  return SSH_ENGINE_RET_DROP;
}

/*
 * Handle trigger packet.
 *
 * This function starts a new TCP handshake and starts the TCP handshake
 * timer.
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_trigger(SshEngine engine,
                                     SshEnginePacketContext pc,
                                     SshInterceptorPacket pp,
                                     SshEngineTcpEncapsConn conn,
                                     SshInterceptorPacket *reply_packet,
                                     SshIpAddr reply_src, SshIpAddr reply_dst)
{
  SshUInt16 ip_id = ssh_engine_get_ip_id(engine);
  SshUInt32 seq = ssh_rand();
  SshUInt32 ack = 0;

  /* Only IKE packets should trigger a handshake */
  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->ipproto == SSH_IPPROTO_UDP);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(reply_packet != NULL && *reply_packet == NULL);
  SSH_ASSERT(reply_src != NULL && reply_dst != NULL);

  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing trigger packet to connection 0x%lx",
                             (unsigned long) conn->conn_id));

  /* Start handshake */
  *reply_packet =
    ssh_engine_tcp_encaps_build_handshake(engine,
                                          ip_id,
                                          &conn->local_addr,
                                          conn->local_port,
                                          &conn->peer_addr,
                                          conn->peer_port,
                                          seq, ack,
                                          SSH_TCPH_FLAG_SYN,
                                          NULL, 0);
  if (*reply_packet == NULL)
    {



      goto error;
    }
  *reply_src = conn->local_addr;
  *reply_dst = conn->peer_addr;

  /* Set state and sequence numbers */
  conn->state = SSH_ENGINE_TCP_SYN;
  conn->seq = seq + 1;
  conn->ack = ack;

  /* Store trigger packet */
  conn->trigger_packet = pp;

  /* Register timeout to remove a pending handshake */
  if (conn->in_initial_timeout_list == 0)
    engine_tcp_encaps_initial_timeout_list_insert(engine, conn);
  engine_tcp_encaps_timeout_schedule(engine, conn,
                                     SSH_ENGINE_TCP_ENCAPS_INITIAL_TIMEOUT);

  return SSH_ENGINE_RET_ASYNC;

 error:
  if (*reply_packet)
    {
      ssh_interceptor_packet_free(*reply_packet);
      *reply_packet = NULL;
    }

  return SSH_ENGINE_RET_DROP;
}

/*
 * Handles a TCP SYN-ACK from peer.
 *
 * This function updates the TCP connection state, replies to
 * peer with the last ACK, cancels the TCP handshake timer, and
 * starts the IKE negotiation timer.
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_syn_ack(SshEngine engine,
                                     SshEnginePacketContext pc,
                                     SshInterceptorPacket pp,
                                     unsigned char *tcp_cp,
                                     SshEngineTcpEncapsConn conn,
                                     SshInterceptorPacket *reply_packet,
                                     SshIpAddr reply_src, SshIpAddr reply_dst)
{
  SshUInt16 ip_id = ssh_engine_get_ip_id(engine);
  SshUInt32 seq = conn->seq;
  SshUInt32 ack = SSH_TCPH_SEQ(tcp_cp) + 1;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(reply_packet != NULL && *reply_packet == NULL);
  SSH_ASSERT(reply_src != NULL && reply_dst != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing SYN-ACK to connection 0x%lx",
                             (unsigned long) conn->conn_id));

  if (conn->seq != SSH_TCPH_ACK(tcp_cp))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Expecting ACK 0x%lx got 0x%lx",
                 (unsigned long) conn->seq,
                 (unsigned long) SSH_TCPH_ACK(tcp_cp)));
      return SSH_ENGINE_RET_DROP;
    }

  conn->state = SSH_ENGINE_TCP_SYN_ACK_ACK;

  /* Build ACK packet. */
  *reply_packet =
    ssh_engine_tcp_encaps_build_handshake(engine,
                                          ip_id,
                                          &pc->dst, pc->u.rule.dst_port,
                                          &pc->src, pc->u.rule.src_port,
                                          conn->seq, ack,
                                          SSH_TCPH_FLAG_ACK,
                                          NULL, 0);
  if (*reply_packet == NULL)
    {
      ssh_engine_tcp_encaps_remove_conn(engine, conn);
      return SSH_ENGINE_RET_DROP;
    }

  *reply_src = pc->dst;
  *reply_dst = pc->src;

  /* Update state and sequence numbers */
  conn->state = SSH_ENGINE_TCP_ESTABLISHED;
  conn->seq = seq;
  conn->ack = ack;

  /* Cancel initial timeout */
  if (conn->in_initial_timeout_list == 1)
    engine_tcp_encaps_initial_timeout_list_remove(engine, conn);

  /* Register IKE negotiation timeout */
  engine_tcp_encaps_negotiation_timeout_list_insert(engine, conn);
  engine_tcp_encaps_timeout_schedule(engine, conn,
                                    SSH_ENGINE_TCP_ENCAPS_NEGOTIATION_TIMEOUT);
  /* Drop the SYN-ACK. */
  return SSH_ENGINE_RET_DROP;
}

/*
 * Handles the last ack of TCP handshake from peer.
 *
 * This function updates the TCP connection state, cancels the TCP
 * handshake timer, and starts the IKE negotiation timer.
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_ack(SshEngine engine,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 unsigned char *tcp_cp,
                                 SshEngineTcpEncapsConn conn)
{
  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(tcp_cp != NULL);
  SSH_ASSERT(conn != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing ACK to connection 0x%lx",
                             (unsigned long) conn->conn_id));

  if (conn->seq != SSH_TCPH_ACK(tcp_cp))
    return SSH_ENGINE_RET_DROP;

  /* Update state and sequence numbers */
  conn->state = SSH_ENGINE_TCP_ESTABLISHED;
  conn->ack = SSH_TCPH_SEQ(tcp_cp);

  /* Cancel initial timeout */
  if (conn->in_initial_timeout_list == 1)
    engine_tcp_encaps_initial_timeout_list_remove(engine, conn);

  /* Register IKE negotiation timeout */
  engine_tcp_encaps_negotiation_timeout_list_insert(engine, conn);
  engine_tcp_encaps_timeout_schedule(engine, conn,
                                    SSH_ENGINE_TCP_ENCAPS_NEGOTIATION_TIMEOUT);

  /* Drop the ACK. */
  return SSH_ENGINE_RET_DROP;
}

/*
 * Handles a TCP rst from peer.
 *
 * If 'conn' is not NULL, this function removes the entry from
 * the connection table.
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_rst(SshEngine engine,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 unsigned char *tcp_cp,
                                 SshEngineTcpEncapsConn conn)
{
  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(tcp_cp != NULL);
  SSH_ASSERT(conn != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing RST to connection 0x%lx",
                             (unsigned long) (conn ? conn->conn_id :
                                              SSH_IPSEC_INVALID_INDEX)));

  if (conn != NULL)
    ssh_engine_tcp_encaps_remove_conn(engine, conn);

  /* Drop the RST. */
  return SSH_ENGINE_RET_DROP;
}

/*
 * Handles a TCP fin from peer.
 *
 * If 'conn' is not NULL, this funtion replies to peer with a TCP RST
 * and removes entry from the connection table
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_handle_fin(SshEngine engine,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 unsigned char *tcp_cp,
                                 SshEngineTcpEncapsConn conn,
                                 SshInterceptorPacket *reply_packet,
                                 SshIpAddr reply_src, SshIpAddr reply_dst)
{
  SshUInt16 ip_id = ssh_engine_get_ip_id(engine);
  SshUInt32 seq = 0;
  SshUInt8 flags = 0;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(tcp_cp != NULL);
  SSH_ASSERT(conn != NULL);
  SSH_ASSERT(reply_packet != NULL && *reply_packet == NULL);
  SSH_ASSERT(reply_src != NULL && reply_dst != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing FIN to connection 0x%lx",
                             (unsigned long) (conn ? conn->conn_id :
                                              SSH_IPSEC_INVALID_INDEX)));

  if (conn)
    {
      flags = SSH_TCPH_FLAGS(tcp_cp);

      if (flags & SSH_TCPH_FLAG_ACK)
        seq = SSH_TCPH_ACK(tcp_cp);

      *reply_packet =
        ssh_engine_tcp_encaps_build_handshake(engine,
                                              ip_id,
                                              &pc->dst, pc->u.rule.dst_port,
                                              &pc->src, pc->u.rule.src_port,
                                              seq, 0,
                                              SSH_TCPH_FLAG_RST,
                                              NULL, 0);
      *reply_src = pc->dst;
      *reply_dst = pc->src;
      ssh_engine_tcp_encaps_remove_conn(engine, conn);
    }

  /* Drop the FIN. */
  return SSH_ENGINE_RET_DROP;
}

/*********************** Packet Processing ***********************************/

/*
 * Process inbound no flow packets.
 *
 * This function performs connection entry lookup, and depending on the
 * TCP connection state passes the packet 'pp' to handshake handling or
 * to decapsulation, or lets the packet continue unmodified. This function
 * grabs `tcp_encaps_lock' when accessing encapsulating TCP connection
 * entries or configuration entries. This function will call
 * ssh_engine_send_packet (with no locks taken).
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_process_noflow_in(SshEngine engine,
                                        SshEnginePacketContext pc,
                                        SshInterceptorPacket pp)
{
  SshEngineTcpEncapsConn conn = NULL;
  SshEngineTcpEncapsConfig config = NULL;
  unsigned char *ucp = NULL;
  unsigned char *ip_cp = NULL;
  unsigned char *tcp_cp = NULL;
  SshUInt16 flags;
  SshUInt32 hash;
  size_t tcp_seg_len = -1, offset;
  SshUInt32 seq = 0;
  SshUInt32 ack = 0;
  SshInterceptorPacket trigger_packet = NULL;
  SshInterceptorPacket reply_packet = NULL;
  SshIpAddrStruct reply_src, reply_dst;
  SshEngineActionRet ret = SSH_ENGINE_RET_DROP;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing inbound noflow packet %p", pp));

  /* Let all non TCP packets through */
  if (pc->ipproto != SSH_IPPROTO_TCP)
    {




      SSH_DEBUG(SSH_D_LOWOK, ("Non TCP"));
      ret = SSH_ENGINE_RET_OK;
      goto out;
    }

  /* Reassemble fragmented TCP packets */
  if (pp->flags & SSH_ENGINE_P_ISFRAG)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Fragmented TCP packet"));
      ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
      goto out;
    }

  /* Drop short TCP packet */
  if (pc->packet_len < (pc->hdrlen + SSH_TCPH_HDRLEN))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Short TCP packet"));
      ret = SSH_ENGINE_RET_DROP;
      goto out;
    }

  /* Check that it is safe to pullup the TCP header. */
  offset = pc->hdrlen + SSH_TCPH_HDRLEN;
  if (offset > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Oversized IP header: length %d",
                                (int) pc->hdrlen));
      ret = SSH_ENGINE_RET_DROP;
      goto out;
    }

  /* Pullup TCP header */
  ucp = ssh_interceptor_packet_pullup(pp, offset);
  if (!ucp)
    goto error_pp_freed;
  ip_cp = ucp;
  tcp_cp = ip_cp + pc->hdrlen;

  /* Store TCP flags, sequence and acknowledgement numbers for later use */
  flags = SSH_TCPH_FLAGS(tcp_cp);
  seq = SSH_TCPH_SEQ(tcp_cp);
  if (flags & SSH_TCPH_FLAG_ACK)
    ack = SSH_TCPH_ACK(tcp_cp);

  /* Calculate TCP payload length */
  if (pp->protocol == SSH_PROTOCOL_IP4)
    tcp_seg_len = (SSH_IPH4_LEN(ip_cp) -
                   (SSH_IPH4_HLEN(ip_cp) * 4) -
                   (SSH_TCPH_DATAOFFSET(tcp_cp) * 4));
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    tcp_seg_len = (SSH_IPH6_LEN(ip_cp) -
                   (SSH_TCPH_DATAOFFSET(tcp_cp) * 4));
#endif /* WITH_IPV6 */

  /* Lookup connection table */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Connection table lookup for [%@:%d] -> [%@:%d]",
             ssh_ipaddr_render, &pc->src, (int) pc->u.rule.src_port,
             ssh_ipaddr_render, &pc->dst, (int) pc->u.rule.dst_port));

  /* Grab `tcp_encaps_lock' to protect connection entries. */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  hash = engine_tcp_encaps_hash(&pc->src, pc->u.rule.src_port);
  conn = engine->tcp_encaps_connection_table[hash];
  while (conn)
    {
      if (SSH_IP_EQUAL(&pc->src, &conn->peer_addr) &&
          pc->u.rule.src_port == conn->peer_port &&
          SSH_IP_EQUAL(&pc->dst, &conn->local_addr) &&
          pc->u.rule.dst_port == conn->local_port)
        break;
      conn = conn->next;
    }

  /* No active connection found */
  if (conn == NULL)
    {
      /* Lookup configuration table */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Config table lookup for [%@] -> [%@]",
                 ssh_ipaddr_render, &pc->src,
                 ssh_ipaddr_render, &pc->dst));
      config = engine->tcp_encaps_configuration_table;
      while (config)
        {
          if ((SSH_IP_EQUAL(&pc->dst, &config->local_addr)
               || (SSH_IP_IS_NULLADDR(&config->local_addr)
                   && ssh_engine_ip_is_local(engine, &pc->dst)))
              && pc->u.rule.dst_port == config->local_port
              && SSH_IP_IN_RANGE(&pc->src,
                                 &config->peer_lo_addr,
                                 &config->peer_hi_addr)
              && (pc->u.rule.src_port == config->peer_port
                  || config->peer_port == 0))
            break;
          config = config->next;
        }

      /* No match, pass packet */
      if (config == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("No matching configuration found"));
          ret = SSH_ENGINE_RET_OK;
          goto unlock_out;
        }

      /* Incoming connection establishment to a configured listen port
         from a configured peer address range */
      if (flags == SSH_TCPH_FLAG_SYN)
        {
          ret = ssh_engine_tcp_encaps_handle_syn(engine, pc, pp, tcp_cp, NULL,
                                                 config, &reply_packet,
                                                 &reply_src, &reply_dst);
          goto unlock_out;
        }

      /* A non SYN non RST packet is destined to our listen port and address
         but there is no established connection -> Reject with TCP RST */
      else if ((flags & SSH_TCPH_FLAG_RST) == 0)
        {
          SshUInt16 ip_id = ssh_engine_get_ip_id(engine);

          /* STD7:
             If the incoming segment has an ACK field, the reset takes its
             sequence number from the ACK field of the segment, otherwise the
             reset has sequence number zero and the ACK field is set to the sum
             of the sequence number and segment length of the incoming segment.
             The connection remains in the CLOSED state. */
          seq += tcp_seg_len;
          if (flags & SSH_TCPH_FLAG_SYN)
            seq++;

          SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s "
                                  "to an unknown connection, "
                                  "send RST and drop",
                                  (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                                  (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                                  (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                                  (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                                  (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                                  (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
          reply_packet =
            ssh_engine_tcp_encaps_build_handshake(engine,
                                                 ip_id,
                                                 &pc->dst, pc->u.rule.dst_port,
                                                 &pc->src, pc->u.rule.src_port,
                                                 ack, seq,
                                                 SSH_TCPH_FLAG_RST |
                                                 SSH_TCPH_FLAG_ACK,
                                                 NULL, 0);
          reply_src = pc->dst;
          reply_dst = pc->src;
          ret = SSH_ENGINE_RET_DROP;
          goto unlock_out;
        }

      /* Drop TCP RST packets */
      SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s"
                              "to an unknown connection, drop",
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
      ret = SSH_ENGINE_RET_DROP;
      goto unlock_out;
    }

  SSH_ASSERT(conn != NULL);

  /* Active connection closed by peer */
  if (flags & SSH_TCPH_FLAG_RST)
    {
      /* Close connection */
      ret = ssh_engine_tcp_encaps_handle_rst(engine, pc, pp, tcp_cp, conn);
      goto unlock_out;
    }

  /* Active connection closed by peer */
  if (flags & SSH_TCPH_FLAG_FIN)
    {
      /* Close connection and send TCP RST */
      ret = ssh_engine_tcp_encaps_handle_fin(engine, pc, pp, tcp_cp, conn,
                                             &reply_packet, &reply_src,
                                             &reply_dst);
      goto unlock_out;
    }

  /* Valid packet from an active connection */
  switch (conn->state)
    {
      /* State ESTABLISHED */
    case SSH_ENGINE_TCP_ESTABLISHED:
      /* Valid packet (no SYN, RST or FIN flags set) */
      if (!(flags & SSH_TCPH_FLAG_SYN))
        {
          /* TCP keepalive */
          if (tcp_seg_len == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("keepalive, drop"));
              ret = SSH_ENGINE_RET_DROP;
              goto unlock_out;
            }

          /* Decapsulate packet */
          ret = ssh_engine_tcp_encaps_decapsulate(pc, pp, ip_cp, tcp_cp, conn);
          goto unlock_out;
        }
      /* Drop everything else (SYN packets) */
      SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s"
                              "to an ESTABLISHED connection, drop",
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
      ret = SSH_ENGINE_RET_DROP;
      goto unlock_out;

      /* State SYN_SENT */
    case SSH_ENGINE_TCP_SYN:
      /* Second packet of handshake (SYN-ACK) */
      if ((flags & SSH_TCPH_FLAG_SYN) && (flags & SSH_TCPH_FLAG_ACK))
        {
          /* Send TCP ACK */
          ret = ssh_engine_tcp_encaps_handle_syn_ack(engine, pc, pp, tcp_cp,
                                                     conn, &reply_packet,
                                                     &reply_src, &reply_dst);
          if (ret != SSH_ENGINE_RET_DROP)
            {
              ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
              goto error;
            }

          /* Restart trigger packet. */
          trigger_packet = conn->trigger_packet;
          conn->trigger_packet = NULL;

          goto unlock_out;
        }
      /* Simultaneous open (SYN) */
      if ((flags & SSH_TCPH_FLAG_SYN) && !(flags & SSH_TCPH_FLAG_ACK))
        {
          ret = ssh_engine_tcp_encaps_handle_syn(engine, pc, pp, tcp_cp,
                                                 conn, NULL, &reply_packet,
                                                 &reply_src, &reply_dst);
          goto unlock_out;
        }
      /* Drop everything else */
      SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s"
                              "to a SYN_SENT connection, drop",
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
      ret = SSH_ENGINE_RET_DROP;
      goto unlock_out;

      /* State SYN_RCVD */
    case SSH_ENGINE_TCP_SYN_ACK:
      /* Last packet of handshake (ACK) */
      if (!(flags & SSH_TCPH_FLAG_SYN) && (flags & SSH_TCPH_FLAG_ACK))
        {
          ret = ssh_engine_tcp_encaps_handle_ack(engine, pc, pp, tcp_cp, conn);
          goto unlock_out;
        }
      /* Drop everything else */
      SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s"
                              "to a SYN_RCVD connection, drop",
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : "")));
      ret = SSH_ENGINE_RET_DROP;
      goto unlock_out;

    default:
      /* Default drop */
      SSH_DEBUG(SSH_D_LOWOK, ("Inbound %s%s%s%s%s%s"
                              "to a connection state %d, drop",
                              (flags & SSH_TCPH_FLAG_FIN ? "FIN " : ""),
                              (flags & SSH_TCPH_FLAG_SYN ? "SYN " : ""),
                              (flags & SSH_TCPH_FLAG_RST ? "RST " : ""),
                              (flags & SSH_TCPH_FLAG_PSH ? "PSH " : ""),
                              (flags & SSH_TCPH_FLAG_ACK ? "ACK " : ""),
                              (flags & SSH_TCPH_FLAG_URG ? "URG " : ""),
                              conn->state));
      ret = SSH_ENGINE_RET_DROP;
      goto unlock_out;
      break;
    }

 unlock_out:
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

 out:
  /* Send reply handshake packet. */
  if (reply_packet != NULL)
    ssh_engine_tcp_encaps_send_packet(engine, reply_packet, SSH_IPPROTO_TCP,
                                      &reply_src, &reply_dst);

  /* Restart trigger packet. */
  if (trigger_packet != NULL)
    fastpath_packet_handler(engine, trigger_packet, 0,
                            SSH_IPSEC_INVALID_INDEX, TRUE);

#ifdef DEBUG_LIGHT
  switch (ret)
    {
    case SSH_ENGINE_RET_OK:
      SSH_DEBUG(SSH_D_MIDOK, ("Passing packet %p", pp));
      break;
    case SSH_ENGINE_RET_DROP:
      SSH_DEBUG(SSH_D_MIDOK, ("Dropping packet %p", pp));
      break;
    case SSH_ENGINE_RET_RESTART:
      SSH_DEBUG(SSH_D_MIDOK, ("Restarting packet %p", pp));
      break;
    case SSH_ENGINE_RET_RESTART_FLOW_LOOKUP:
      SSH_DEBUG(SSH_D_MIDOK, ("Reassembling packet %p", pp));
      break;
    case SSH_ENGINE_RET_ERROR:
      SSH_DEBUG(SSH_D_FAIL, ("Error, packet %p was freed", pp));
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
#endif /* DEBUG_LIGHT */
  return ret;

  /* Error Handling. */
 error:
  SSH_DEBUG(SSH_D_FAIL, ("Error, packet %p was not freed", pp));
  return SSH_ENGINE_RET_DROP;

 error_pp_freed:
  SSH_DEBUG(SSH_D_FAIL, ("Error, packet %p was freed", pp));
  return SSH_ENGINE_RET_ERROR;
}

/*
 * Process outbound noflow packets.
 *
 * This function performs TCP connection lookup for the packet 'pp'
 * and triggers a new TCP connection establishment if necessary. This
 * function grabs `tcp_encaps_lock' when accessing encapsulating TCP
 * connection entries or configuration entries. This function will call
 * ssh_engine_send_packet (with no locks taken).
 */
static SshEngineActionRet
ssh_engine_tcp_encaps_process_noflow_out(SshEngine engine,
                                         SshEnginePacketContext pc,
                                         SshInterceptorPacket pp)
{
  SshEngineTcpEncapsConn conn = NULL;
  SshEngineActionRet ret = SSH_ENGINE_RET_DROP;
  SshInterceptorPacket handshake_packet = NULL;
  SshIpAddrStruct handshake_src, handshake_dst;
  SshUInt32 i;
  Boolean ike = FALSE;
  size_t offset;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_LOWSTART, ("Processing outbound noflow packet %p", pp));

  /* Check if packet is IKE. Grab flow_control_table_lock when
     accessing `engine->ike_ports'. */
  if (pc->ipproto == SSH_IPPROTO_UDP)
    {
      /* Calculate minimum packet length. */
      offset = pc->hdrlen + SSH_UDPH_HDRLEN + 2 * SSH_ENGINE_IKE_COOKIE_LENGTH;
      if (pc->packet_len >= offset)
        {
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          for (i = 0; i < engine->num_ike_ports; i++)
            {
              if ((pc->u.rule.src_port == engine->local_ike_ports[i] &&
                   pc->u.rule.dst_port == engine->remote_ike_ports[i])
                  || (pc->u.rule.src_port == engine->local_ike_natt_ports[i] &&
                      pc->u.rule.dst_port == engine->remote_ike_natt_ports[i]))
                {
                  ike = TRUE;
                  break;
                }
            }
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
        }
    }

  /* Grab `tcp_encaps_lock'. */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  /* Drop host stack originating TCP packets that would mess things up */
  if (pc->ipproto == SSH_IPPROTO_TCP)
    {
      SshUInt32 hash = 0;
      hash = engine_tcp_encaps_hash(&pc->dst, pc->u.rule.dst_port);
      conn = engine->tcp_encaps_connection_table[hash];
      while (conn)
        {
          if (SSH_IP_EQUAL(&pc->src, &conn->local_addr) &&
              pc->u.rule.src_port == conn->local_port &&
              SSH_IP_EQUAL(&pc->dst, &conn->peer_addr) &&
              pc->u.rule.dst_port == conn->peer_port)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Interfering TCP packet from host stack"));
              ret = SSH_ENGINE_RET_DROP;
              goto unlock_out;
            }
          conn = conn->next;
        }
    }

  /* Handle IKE packets. */
  if (ike)
    {
      /* Get IKE cookies from packet */
      unsigned char *ucp, *ike_initiator_cookie;

      /* Reassemble fragmented IKE packets */
      if (pp->flags & SSH_ENGINE_P_ISFRAG)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Fragmented IKE packet %p", pp));
          ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
          goto unlock_out;
        }

      /* Pullup start of IKE header */
      offset = pc->hdrlen
        + SSH_UDPH_HDRLEN
        + 2 * SSH_ENGINE_IKE_COOKIE_LENGTH;

      if (offset > pc->packet_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Too short IKE packet"));
          goto error;
        }

      /* Check that it is safe to pullup the requested amount. */
      if (offset > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
        goto error;

      ucp = ssh_interceptor_packet_pullup(pp, offset);
      if (!ucp)
        {
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          pp = NULL;
          goto error_pp_freed;
        }
      ike_initiator_cookie = ucp + pc->hdrlen + SSH_UDPH_HDRLEN;

      /* Lookup connection table for a cookie match */
      conn = ssh_engine_tcp_encaps_conn_by_cookie(engine,
                                                  &pc->src, &pc->dst,
                                                  ike_initiator_cookie, TRUE);

      /* No active connection found, relookup with wildcard addresses. */
      if (conn == NULL)
        {
          conn = ssh_engine_tcp_encaps_conn_by_cookie(engine,
                                                      NULL, NULL,
                                                      ike_initiator_cookie,
                                                      TRUE);
          /* No active connection found, let packet continue. */
          if (conn == NULL)
            {
              ret = SSH_ENGINE_RET_OK;
              goto unlock_out;
            }

          /* IKE has switched to new address pair, clone connection. */
          if (!SSH_IP_EQUAL(&conn->local_addr, &pc->src)
              || !SSH_IP_EQUAL(&conn->peer_addr, &pc->dst))
            {
              conn = engine_tcp_encaps_clone_conn(engine, conn,
                                                  &pc->src, &pc->dst);
              if (conn == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Could not clone encapsulating "
                             "TCP connection entry"));
                  ret = SSH_ENGINE_RET_DROP;
                  goto unlock_out;
                }
            }
        }
      SSH_ASSERT(conn != NULL);

      /* Active connection found */
      switch (conn->state)
        {
          /* Closed connection, establish new TCP connection. */
        case SSH_ENGINE_TCP_CLOSED:
          SSH_DEBUG(SSH_D_LOWOK, ("Closed connection"));
          /* Start new handshake */
          ret = ssh_engine_tcp_encaps_handle_trigger(engine, pc, pp, conn,
                                                     &handshake_packet,
                                                     &handshake_src,
                                                     &handshake_dst);
          goto unlock_out;

          /* Ongoing handshake, drop packet */
        case SSH_ENGINE_TCP_SYN:
        case SSH_ENGINE_TCP_SYN_ACK:
          SSH_DEBUG(SSH_D_LOWOK, ("Ongoing handshake"));
          ret = SSH_ENGINE_RET_DROP;
          goto unlock_out;

          /* Let packet continue */
        default:
          ret = SSH_ENGINE_RET_OK;
          goto unlock_out;
        }
    }

  /* Not IKE. */
  else
    {
      /* Pass everything else */
      SSH_DEBUG(SSH_D_LOWOK, ("IP proto 0x%x", pc->ipproto));
      ret = SSH_ENGINE_RET_OK;
      goto unlock_out;
    }

 unlock_out:
  /* Unlock `tcp_encaps_lock'. */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  /* Send reply handshake packet. */
  if (handshake_packet != NULL)
    ssh_engine_tcp_encaps_send_packet(engine, handshake_packet,
                                      SSH_IPPROTO_TCP,
                                      &handshake_src, &handshake_dst);

#ifdef DEBUG_LIGHT
  switch (ret)
    {
    case SSH_ENGINE_RET_OK:
      SSH_DEBUG(SSH_D_LOWOK, ("Passing packet %p", pp));
      break;
    case SSH_ENGINE_RET_DROP:
      SSH_DEBUG(SSH_D_MIDOK, ("Dropping packet %p", pp));
      break;
    case SSH_ENGINE_RET_RESTART_FLOW_LOOKUP:
      SSH_DEBUG(SSH_D_MIDOK, ("Reassembling packet %p", pp));
      break;
    case SSH_ENGINE_RET_ERROR:
      SSH_DEBUG(SSH_D_FAIL, ("Error, packet %p was freed", pp));
      break;
    case SSH_ENGINE_RET_ASYNC:
      SSH_DEBUG(SSH_D_MIDOK, ("Stealing trigger packet %p", pp));
      break;
    default:
      SSH_NOTREACHED;
      break;
    }
#endif /* DEBUG_LIGHT */
  return ret;

  /* Error handling. */
 error:
  SSH_DEBUG(SSH_D_FAIL, ("error occured, freeing packet"));
  ssh_interceptor_packet_free(pp);
  return SSH_ENGINE_RET_ERROR;

 error_pp_freed:
  SSH_DEBUG(SSH_D_FAIL, ("error occured, packet was freed"));
  return SSH_ENGINE_RET_ERROR;
}

/*
 * Checks if the packet should be processed by the IPSec over TCP code
 * and calls TCP decapsulation or handshake handlers.
 *
 * Real work is done in ssh_engine_tcp_encaps_process_noflow_in and
 * ssh_engine_tcp_encaps_process_noflow_out.
 */
SshEngineActionRet
ssh_engine_tcp_encaps_process_noflow(SshEngine engine,
                                     SshEnginePacketContext pc,
                                     SshInterceptorPacket pp)
{
  SshEngineActionRet ret = SSH_ENGINE_RET_DROP;

  /* Inbound */
  if (pp->flags & SSH_PACKET_FROMADAPTER)
    ret = ssh_engine_tcp_encaps_process_noflow_in(engine, pc, pp);

  /* Outbound */
  else if (pp->flags & SSH_PACKET_FROMPROTOCOL)
    ret = ssh_engine_tcp_encaps_process_noflow_out(engine, pc, pp);

  /* else Weirdo */

  return ret;
}


/*
 * Process an outbound packet that has hit a closed encapsulating TCP
 * connection.
 *
 * This function attempts to find another encapsulating TCP connection
 * that has matching IKE SPI values and is in usable state. If a valid
 * encapsulating TCP connection is found the packet 'pp' is passed to TCP
 * encapsulation and the transform is updated to use the found encapsulating
 * TCP connection.
 *
 * Function assumes that 'pc' is partially valid.
 *
 * This function must be called with `tcp_encaps_lock' taken. if the function
 * succeeds it returns TRUE and it has sent the packet out and released the
 * lock.
 *
 * On error this returns FALSE and the caller must drop the packet.
 * The `tcp_encaps_lock' has not been released.
 */
Boolean
ssh_engine_tcp_encaps_process_closed(SshEngine engine,
                                     SshEnginePacketContext pc,
                                     SshInterceptorPacket pp,
                                     SshUInt8 ipproto,
                                     SshEngineTcpEncapsConn closed_conn)
{
  SshEngineTcpEncapsConn conn;
  SshUInt32 conn_id, closed_conn_id;
  SshUInt32 trd_index;
  SshEngineTransformData d_trd;

  /* Assert that the TCP encaps lock is always taken. */
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pp != NULL);
  SSH_ASSERT(closed_conn != NULL);

  /* Process only ESP and AH. */
  if (ipproto != SSH_IPPROTO_ESP && ipproto != SSH_IPPROTO_AH)
    return FALSE;

  /* Mark the IKE mapping of the old connection invalid. */
  closed_conn->ike_mapping_set = 0;

  /* Lookup a matching TCP connection. */
  conn =
    ssh_engine_tcp_encaps_conn_by_cookie(engine, &pc->src, &pc->dst,
                                         closed_conn->ike_initiator_cookie,
                                         TRUE);
  if (conn == NULL || conn->state == SSH_ENGINE_TCP_CLOSED)
    {
      /* Resurrect IKE mapping. */
      closed_conn->ike_mapping_set = 1;
      return FALSE;
    }

  closed_conn_id = closed_conn->conn_id;
  conn_id = conn->conn_id;
  trd_index = pc->transform_index;

  /* Encapsulate and send packet out. After this `pc' and `pp' are unsafe
     to access. */
  SSH_DEBUG(SSH_D_MIDOK, ("TCP encapsulating packet %p", pp));
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);
  if (!ssh_engine_tcp_encaps_encapsulate(pc, pp, conn, ipproto))
    return FALSE;

  /* Need to unlock to maintain correct locking order. */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

  /* Update transform object to use the found encapsulating TCP connection. */
  SSH_ASSERT(conn_id != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(closed_conn_id != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  d_trd = FP_GET_TRD(engine->fastpath, trd_index);
  SSH_ASSERT(d_trd != NULL);

  /* Transform has disappeared or changed, skip transform update. */
  if (d_trd->transform == 0 || d_trd->tcp_encaps_conn_id != closed_conn_id)
    {
      FP_RELEASE_TRD(engine->fastpath, trd_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return TRUE;
    }

  /* Take `tcp_encaps_lock' back and relookup conn. */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);
  conn = ssh_engine_tcp_encaps_conn_by_id(engine, conn_id);
  if (conn == NULL)
    {
      /* Connection has been removed. */
      FP_RELEASE_TRD(engine->fastpath, trd_index);
      goto unlock_out;
    }

  /* Remove SPI mapping from old encapsulating TCP connection. */
  closed_conn = ssh_engine_tcp_encaps_conn_by_id(engine, closed_conn_id);
  if (closed_conn != NULL)
    ssh_engine_tcp_encaps_clear_spi_mapping(engine, closed_conn,
                                            d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                            d_trd->spis[SSH_PME_SPI_AH_OUT]);

  /* Add SPI mapping to new encapsulating TCP connection. */
  if (ssh_engine_tcp_encaps_add_spi_mapping(engine, conn,
                                            d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                            d_trd->spis[SSH_PME_SPI_AH_OUT])
      == FALSE)
    {
      /* SPI mapping add failed. Clear tcp_encaps_conn_id from transform. */
      conn_id = SSH_IPSEC_INVALID_INDEX;
    }

  /* Update new encapsulating TCP connection id to transform. */
  SSH_DEBUG(SSH_D_MIDOK, ("Updating connection entry 0x%lx to transform 0x%lx",
                          (unsigned long) conn_id, (unsigned long) trd_index));

  d_trd->tcp_encaps_conn_id = conn_id;
  FP_COMMIT_TRD(engine->fastpath, trd_index, d_trd);

 unlock_out:
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return TRUE;
}


/*
 * Checks if the packet should be processed by the TCP encapsulation code.
 *
 * For noflow packets, this function performs connection entry lookup
 * based on IKE initiator cookie or ESP / AH spi. For in-flow packets
 * connection is fetched from connection table by connection id.
 *
 * If a valid encapsulating TCP connection is found the packet 'pp' is
 * passed to TCP encapsulation.
 *
 * Function assumes that 'pc' is partially valid.
 */
SshEngineActionRet
ssh_engine_tcp_encaps_process_outbound(SshEngine engine,
                                       SshEnginePacketContext pc,
                                       SshInterceptorPacket pp)
{
  SshUInt32 hash = 0;
  SshEngineTcpEncapsConn conn = NULL;
  SshUInt16 src_port = 0;
  SshUInt16 dst_port = 0;
  SshUInt8 ipproto = 0;
  SshUInt32 outbound_spi = 0;
  unsigned char ike_initiator_cookie[SSH_ENGINE_IKE_COOKIE_LENGTH];
  SshEngineTransformRun tr;
  Boolean is_ike = FALSE;
  Boolean is_handshake = FALSE;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Handle only outbound packets */
  SSH_ASSERT(pp->flags & SSH_PACKET_FROMPROTOCOL);

  /* Get TCP connection ID. */
  tr = &pc->u.flow.tr;

  /* This packet belongs to flow that is either pass-through
     or does not require TCP encapsulation. */
  if (pc->flow_index != SSH_IPSEC_INVALID_INDEX &&
      (pc->transform == 0 ||
       tr->tcp_encaps_conn_id == SSH_IPSEC_INVALID_INDEX))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No encapsulation required"));
      goto pass;
    }

  /* This noflow packet might require TCP encapsulation. */
  if (pc->flow_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* Parse protocol, ports and some payload data */
      memset(ike_initiator_cookie, 0, sizeof(ike_initiator_cookie));
      if (!ssh_engine_tcp_encaps_pullup_ports(pc, pp,
                                              &ipproto,
                                              &src_port,
                                              &dst_port,
                                              &outbound_spi,
                                              ike_initiator_cookie))
        goto error;

      /* Grab 'tcp_encaps_lock' */
      ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

      /* Handle ESP and AH packets */
      if (ipproto == SSH_IPPROTO_ESP || ipproto == SSH_IPPROTO_AH)
        {
          /* Lookup connection table for a src, dst, SPI match */
          conn = ssh_engine_tcp_encaps_conn_by_spi(engine,
                                                   &pc->src,
                                                   &pc->dst,
                                                   ipproto,
                                                   outbound_spi);
        }

      /* Handle TCP handshake */
      else if (ipproto == SSH_IPPROTO_TCP)
        {
          /* Lookup connection table for active TCP connection */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Connection table lookup for [%@:%d] -> [%@:%d]",
                     ssh_ipaddr_render, &pc->src, (int) src_port,
                     ssh_ipaddr_render, &pc->dst, (int) dst_port));
          hash = engine_tcp_encaps_hash(&pc->dst, dst_port);
          conn = engine->tcp_encaps_connection_table[hash];
          while (conn)
            {
              if (SSH_IP_EQUAL(&pc->src, &conn->local_addr) &&
                  src_port == conn->local_port &&
                  SSH_IP_EQUAL(&pc->dst, &conn->peer_addr) &&
                  dst_port == conn->peer_port)
                break;
              conn = conn->next;
            }

          if (conn != NULL &&
              ssh_interceptor_packet_len(pc->pp)
              == (pc->hdrlen + SSH_TCPH_HDRLEN))
            is_handshake = TRUE;
        }

      /* Handle (possible) IKE packets */
      else if (ipproto == SSH_IPPROTO_UDP)
        {
          if (SSH_GET_32BIT(ike_initiator_cookie) != 0 ||
              SSH_GET_32BIT(ike_initiator_cookie + 4) != 0)
            {
              /* Lookup connection table for a src, dst, cookie match */
              conn =
                ssh_engine_tcp_encaps_conn_by_cookie(engine,
                                                     &pc->src,
                                                     &pc->dst,
                                                     ike_initiator_cookie,
                                                     FALSE);
            }
          /* Sanity check IKE ports. */
          if (conn != NULL
              && (src_port != conn->local_ike_port ||
                  dst_port != conn->remote_ike_port))
            conn = NULL;

          is_ike = TRUE;
        }

      /* No active connection found, let packet continue unmodified. */
      if (conn == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("No encapsulation required"));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto pass;
        }

    } /* if (pc->flow_index == SSH_IPSEC_INVALID_INDEX) */

  /* This in-flow packet requires TCP encapsulation for sure. */
  else
    {
      SSH_ASSERT(pc->flow_index != SSH_IPSEC_INVALID_INDEX);
      SSH_ASSERT(tr->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX);

      /* Lookup connection table */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Connection table lookup for connection ID 0x%lx",
                 (unsigned long) tr->tcp_encaps_conn_id));

      /* Grab 'tcp_encaps_lock' */
      ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

      hash = tr->tcp_encaps_conn_id % SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE;
      conn = engine->tcp_encaps_connection_table[hash];
      while (conn)
        {
          if (conn->conn_id == tr->tcp_encaps_conn_id)
            break;
          conn = conn->next;
        }

      /* Drop a packet that should be encapsulated, but there is no
         encapsulating TCP connection. */
      if (conn == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("No encapsulating TCP connection found for flow 0x%lx",
                     (unsigned long) pc->flow_index));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto drop;
        }

      SSH_ASSERT(conn != NULL);

      if (pc->transform & SSH_PM_IPSEC_ESP)
        ipproto = SSH_IPPROTO_ESP;
      else if (pc->transform & SSH_PM_IPSEC_AH)
        ipproto = SSH_IPPROTO_AH;
    }

  /* At this stage, the packet requires encapsulation and there is
     an active TCP connection. */
  SSH_ASSERT(conn != NULL);
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);

  /* Sanity check */
  if (!SSH_IP_EQUAL(&pc->src, &conn->local_addr) ||
      !SSH_IP_EQUAL(&pc->dst, &conn->peer_addr))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Connection lookup error for flow 0x%lx",
                             (unsigned long) pc->flow_index));
      ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
      goto drop;
    }

  /* Check connection state */
  switch (conn->state)
    {
    case SSH_ENGINE_TCP_ESTABLISHED:
      /* Encapsulate IKE, ESP and AH */
      if (is_ike
          || ipproto == SSH_IPPROTO_ESP
          || ipproto == SSH_IPPROTO_AH)
        goto encapsulate;
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("No encapsulation required for proto %d", ipproto));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto pass;
        }
      break;

    case SSH_ENGINE_TCP_CLOSE_WAIT:
      /* Encapsulate only IKE. */
      if (is_ike)
        goto encapsulate;
      else if (is_handshake == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("No encapsulation required for TCP handshake packet"));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto pass;
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Dropping packet ipproto 0x%lx [%@:%d] [%@:%d]\n"
                     "because of TCP connection state CLOSE_WAIT",
                     ipproto,
                     ssh_ipaddr_render, &pc->src, (int) src_port,
                     ssh_ipaddr_render, &pc->dst, (int) dst_port));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto drop;
        }
      break;

    case SSH_ENGINE_TCP_CLOSED:
      if (is_handshake == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("No encapsulation required for TCP handshake packet"));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto pass;
        }

      /* Attempt to migrate to a another connection. */
      else if (ssh_engine_tcp_encaps_process_closed(engine, pc, pp, ipproto,
                                                    conn) == FALSE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Dropping packet ipproto 0x%lx [%@:%d] [%@:%d]\n"
                     "because of TCP connection state CLOSED",
                     ipproto,
                     ssh_ipaddr_render, &pc->src, (int) src_port,
                     ssh_ipaddr_render, &pc->dst, (int) dst_port));
          ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto drop;
        }
      else
        {
          /* Packet was successfully sent out using another TCP connection.
             Lock has been released already. */
          goto out;
        }
      break;

    case SSH_ENGINE_TCP_INITIAL:
    case SSH_ENGINE_TCP_SYN:
    case SSH_ENGINE_TCP_SYN_ACK:
    case SSH_ENGINE_TCP_SYN_ACK_ACK:
      /* Let only handshake packets continue */
      if (is_handshake == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("No encapsulation required for TCP handshake packet"));
          ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
          goto pass;
        }
      /* Fall through to drop */

    default:
      SSH_DEBUG(SSH_D_LOWOK,
                ("Dropping packet ipproto 0x%x [%@:%d] [%@:%d]\n"
                 "because of invalid TCP connection state 0x%x",
                 ipproto,
                 ssh_ipaddr_render, &pc->src, (int) src_port,
                 ssh_ipaddr_render, &pc->dst, (int) dst_port,
                 conn->state));
      ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
      goto drop;
    }
  SSH_NOTREACHED;

 drop:
  SSH_DEBUG(SSH_D_MIDOK, ("Dropping packet %p", pp));
  return SSH_ENGINE_RET_DROP;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Error, packet %p was freed", pp));
  return SSH_ENGINE_RET_ERROR;

 pass:
  SSH_DEBUG(SSH_D_LOWOK, ("Passing packet %p", pp));
  return SSH_ENGINE_RET_OK;

 encapsulate:
  SSH_DEBUG(SSH_D_MIDOK, ("TCP encapsulating packet %p", pp));
  ssh_kernel_mutex_assert_is_locked(engine->tcp_encaps_lock);
  if (!ssh_engine_tcp_encaps_encapsulate(pc, pp, conn, ipproto))
    {
      ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
      goto error;
    }
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);

 out:
  return SSH_ENGINE_RET_OK;
}

/****************************** Init / Destroy *******************************/

/*
 * Remove all entries from connection and configuration tables and
 * cancel all TCP handshake, IKE negotiation, and connection close
 * timers.
 */
void
ssh_engine_tcp_encaps_destroy(SshEngine engine)
{
  SshUInt32 hash = 0;
  SshEngineTcpEncapsConn conn, conn_next;
  SshEngineTcpEncapsConfig config, config_next;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start"));

  /* Cancel all timeouts */
  ssh_kernel_timeout_cancel(engine_tcp_encaps_timeout_cb, engine);
  ssh_kernel_timeout_cancel(ssh_engine_tcp_encaps_close_conn_timeout_cb,
                            SSH_KERNEL_ALL_CONTEXTS);

  /* Handle pending deletions. */
  ssh_engine_tcp_encaps_close_conn_timeout_cb(engine);

  /* Grab lock 'tcp_encaps_lock' */
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);

  engine->tcp_encaps_timeout_sec = 0;
  engine->tcp_encaps_timeout_usec = 0;

  /* Cleanup connection table */
  while (hash < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE)
    {
      conn = engine->tcp_encaps_connection_table[hash];
      while (conn)
        {
          conn_next = conn->next;
          /* Free pending trigger packet */
          if (conn->trigger_packet)
            ssh_interceptor_packet_free(conn->trigger_packet);
          ssh_free(conn);
          conn = conn_next;
        }
      engine->tcp_encaps_connection_table[hash] = NULL;
      hash++;
    }

  /* Cleanup configuration table */
  config = engine->tcp_encaps_configuration_table;
  while (config)
    {
      config_next = config->next;
      ssh_free(config);
      config = config_next;
    }
  engine->tcp_encaps_configuration_table = NULL;

  /* Unlock 'tcp_encaps_lock' */
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
}

#endif /* SSH_IPSEC_TCPENCAP */
