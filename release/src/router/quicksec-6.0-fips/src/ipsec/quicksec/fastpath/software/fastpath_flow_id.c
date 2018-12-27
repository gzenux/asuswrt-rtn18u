/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code for flow id computations in the software fastpath.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathFlowId"


/* A 32-bit hash and 96-bit non-cryptographic signature function.

   The design criteria for this hash/signature function are as follows:

     - The first hash value, `hash[0]', is used to index the hash
       table.  Hence, to avoid collisions, the bits in `hash[0]'
       should be as randomly distributed as possible even given a
       small change in any part of the input.

       The value of `hash[0]' is computed with the same algorithm as
       `hash_32' given the `salt' equal to `salt[0]' of this function.

       I [cessu] have experimentally verified that all parts in
       `hash[0]' pass the khi^2 -test even for difficult inputs.

     - The three next hash values, `hash[1]' to `hash[3]', are
       collectively used as a signature of the data, but not for
       indexing hash tables.  Hence it is NOT important that a small
       change in the input changes many bits in the hash value as long
       as a change in input results a change somewhere in the output
       with the highest probability.  This alleviation to the
       requirements of `hash[1..3]' is used to compute them more
       efficiently.

       (I [cessu] have tested approximately 10^16 pairs of relatively
       adjacent keys and found no collisions of these three last
       words.  Multiply that with the probability of a collision in
       `hash[0]'.)

     - Computing the hash values must be as efficient as possible.
       For example, contrary to string hashing functions, we assume
       the input is aligned to 32-bit word boundaries.

     - The hash function must have a salt of some kind so that
      changing the salt yields different cases of collisions, or the
       salt can be used as intermediate values when hashing
       non-consecutive blocks of memory.

       Note that the signature function is not required to be
       cryptographically strong, since the salt and computed
       signatures are private information never shown to the attacker.

   When entering `fastpath_flow_id_hash' the four words `salt[0..3]'
   must be initialized to the 128-bit salt for the hash function, and
   on return the hash/signature values are stored in `hash[0..3]' as
   described above.  The function is MT-safe, and it does not allocate
   or free any memory.
*/

SSH_FASTTEXT
void fastpath_flow_id_hash(const SshUInt32 *data,     /* IN */
                           SshUInt32 count,           /* IN */
                           const SshUInt32 salt[4],   /* IN */
                           SshUInt32 hash[4])         /* OUT */
{
  SshUInt32 h1 = salt[0], h2 = salt[1], h3 = salt[2], h4 = salt[3];
  const SshUInt32 *p = &data[count];
  SshUInt32 w;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Flow ID union:"),
                    (unsigned char *) data, count * sizeof(SshUInt32));

  SSH_INTERCEPTOR_STACK_MARK();

  while (p > &data[3])
    {
      w = *--p;
      h2 ^= w;
      h1 += w;
      h1 += h1 << 10;
      h1 ^= h1 >> 6;

      w = *--p;
      h3 ^= w;
      h1 += w;
      h1 += h1 << 10;
      h1 ^= h1 >> 6;

      w = *--p;
      h4 ^= w;
      h1 += w;
      h1 += h1 << 10;
      h1 ^= h1 >> 6;

      /* Mixing step for the 96 bits in h2-h4.  The code comes from a
         hash table lookup function by Robert J. Jenkins, and has been
         presented on numerous web pages and in a Dr. Dobbs Journal
         sometimes in late 90's.

         h1 is computed according to the one-at-a-time hash function,
         presented in the same article. */
      h2 -= h3;  h2 -= h4;  h2 ^= h4 >> 13;
      h3 -= h4;  h3 -= h2;  h3 ^= h2 << 8;
      h4 -= h2;  h4 -= h3;  h4 ^= h3 >> 13;
      h2 -= h3;  h2 -= h4;  h2 ^= h4 >> 12;
      h3 -= h4;  h3 -= h2;  h3 ^= h2 << 16;
      h4 -= h2;  h4 -= h3;  h4 ^= h3 >> 5;
      h2 -= h3;  h2 -= h4;  h2 ^= h4 >> 3;
      h3 -= h4;  h3 -= h2;  h3 ^= h2 << 10;
      h4 -= h2;  h4 -= h3;  h4 ^= h3 >> 15;
    }
  w = *--p;
  h1 += w;
  h1 += h1 << 10;
  h1 ^= h1 >> 6;
  h2 ^= w;
  if (SSH_PREDICT_TRUE(p > data))
    {
      w = *--p;
      h1 += w;
      h1 += h1 << 10;
      h1 ^= h1 >> 6;
      h3 ^= w;
      if (SSH_PREDICT_FALSE(p > data))
        {
          w = *--p;
          h1 += w;
          h1 += h1 << 10;
          h1 ^= h1 >> 6;
          h4 ^= w;
        }
    }
  SSH_ASSERT(p == data);

  /* This last shuffling step is crucial for fragmagic.
     In the worst case the difference between two adjacent
     frag IDs is in the first and second octets of the input.
     Without this shuffling step, the difference does
     not progate to the fourth octet of h1, which points
     the frag entry hashtable slot. */
  h1 += h1 << 3;
  h1 ^= h1 >> 11;
  h1 += h1 << 15;

  hash[0] = h1;
  hash[1] = h2;
  hash[2] = h3;
  hash[3] = h4;
}

/* Structure containing the parameters to the flow id computation */
typedef struct SshEngineFlowIdRec
{
  SshUInt32 tunnel_id;

  unsigned char ipproto;
  unsigned char reserved_1;

  unsigned char flags;
#define SSH_ENGINE_FLOW_ID_F_FROMADAPTER       0x01
#define SSH_ENGINE_FLOW_ID_F_IP6               0x02






  SshUInt32 spi;
  unsigned char icmp_identifier[2];
  SshUInt16 src_port;
  SshUInt16 dst_port;

  unsigned char dst[SSH_IP_ADDR_SIZE];
  unsigned char src[SSH_IP_ADDR_SIZE];

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
} SshEngineFlowIdStruct, *SshEngineFlowId;


/* Data type (union) which is used in the computation of the flow id.
   To compute a flow id, this union must first be zeroed (with memset,
   so that any unused bytes also get zeroed), then the `id' structure
   should be filled with appropriate data, and finally the `raw' array
   should be passed to fastpath_flow_id_hash with
   (sizeof(SshEngineFlowIdStruct) + sizeof(SshUInt32) - 1) / sizeof(SshUInt32)
   as the length argument (where u is a variable of the type
   SshEngineFlowIdStruct) and engine->salt as the salt. */

#define SSH_ENGINE_FLOW_ID_NUMBER_OF_WORDS                                \
  ((sizeof(SshEngineFlowIdStruct) + sizeof(SshUInt32) - 1) / sizeof(SshUInt32))

typedef union
{
  SshEngineFlowIdStruct id;
  /* This is here to ensure proper word-alignment of the
     `SshEngineFlowIdUnion' and convenient cast to `SshUInt32 *'. */
  SshUInt32 raw[SSH_ENGINE_FLOW_ID_NUMBER_OF_WORDS];
} SshEngineFlowIdUnion;


/* Compute flow_id for ICMP error packets from the violating IP packet
   in the ICMP error payload. */
static SSH_FASTTEXT Boolean
fastpath_compute_icmp_error_flow_id(SshFastpath fastpath,
                                    SshEnginePacketContext pc,
                                    SshUInt32 tunnel_id,
                                    unsigned char *flow_id)
{
  SshInterceptorPacket inner_pp;
  SshEnginePacketContext inner_pc;

  /* Extract violating packet from ICMP payload. */
  inner_pp = ssh_engine_icmp_get_inner_packet(fastpath->engine, pc->pp);
  if (inner_pp == NULL)
    {
      /* The original ICMP packet has beed freed if inner packet could
         not be extracted. */
      pc->pp = NULL;
      return FALSE;
    }

  /* Allocate, initialize and pullup packet context for the
     violating packet. */
  inner_pc = ssh_engine_alloc_pc(fastpath->engine);
  if (inner_pc == NULL)
    {
      ssh_interceptor_packet_free(inner_pp);
      goto alloc_fail;
    }

  if (ssh_engine_init_and_pullup_pc(inner_pc, fastpath->engine, inner_pp,
                                    tunnel_id, SSH_IPSEC_INVALID_INDEX)
      == FALSE)
    goto error;

  /* Compute flow id for the violating packet. */
  SSH_ASSERT(inner_pc->pp == inner_pp);
  if (fastpath_compute_flow_id(fastpath, inner_pc, inner_pc->pp, tunnel_id,
                               flow_id) == FALSE)
    goto error;

  /* Free violating packet and packet context. */
  if (inner_pc->pp != NULL)
    ssh_interceptor_packet_free(inner_pc->pp);
  ssh_engine_free_pc(fastpath->engine, inner_pc);

  return TRUE;

 error:
  if (inner_pc->pp != NULL)
    ssh_interceptor_packet_free(inner_pc->pp);
  ssh_engine_free_pc(fastpath->engine, inner_pc);
  /* Fallthrough */

 alloc_fail:
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;

  return FALSE;
}


/* Computes a flow id from the packet.  The computed flow id is 16 bytes
   (128 bits), hashed from various fields of the packet.

   This returns TRUE if flow id computation was successful.  This returns
   FALSE if an error occurred, in which case pp has been already freed when
   this returns.

   This function asserts that pc->pp is equal to pp. */

SSH_FASTTEXT
Boolean fastpath_compute_flow_id(SshFastpath fastpath,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 SshUInt32 tunnel_id,
                                 unsigned char *flow_id)
{
  SshEngineFlowIdUnion u;
  int dummy;

  SSH_ASSERT(pc->pp == pp);
  SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP4
             || pc->pp->protocol == SSH_PROTOCOL_IP6);

  /* Clear the flow id union entirely. */
  memset(&u, 0, sizeof(u));

  /* Initialize fields common to all packets. */
  u.id.tunnel_id = tunnel_id;
  u.id.ipproto = pc->ipproto;
  if (pc->pp->flags & SSH_PACKET_FROMADAPTER)
    u.id.flags |= SSH_ENGINE_FLOW_ID_F_FROMADAPTER;
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    u.id.flags |= SSH_ENGINE_FLOW_ID_F_IP6;
#endif /* WITH_IPV6 */

  switch (pc->ipproto)
    {
    case SSH_IPPROTO_UDP:
      /* UDP encapsulated ESP packets */
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          /* The addresses are left as zeroed memory,
           *don't* jump to `store_ip_addresses'. */
          u.id.spi = pc->protocol_xid;
          u.id.ipproto = SSH_IPPROTO_ESP;
          break;
        }

      if (SSH_PREDICT_FALSE(pc->u.rule.dst_port == 67) ||
          SSH_PREDICT_FALSE(pc->u.rule.dst_port == 68))
        {
          /* Do not store IP addresses for DHCP, they tend to be
             meaningless. */
          u.id.spi = pc->protocol_xid;
          break;
        }

      /*FALLTHROUGH*/
    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_SCTP:
      /* Store ports. */
      u.id.src_port = pc->u.rule.src_port;
      u.id.dst_port = pc->u.rule.dst_port;
      goto store_ip_addresses;

    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_ESP:
      /* IPsec packets directed to us only use the SPI and protocol
         for flow id. IPsec packets not directed to us use IP addresses
         but not the SPI for flow id. */
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          u.id.spi = pc->u.rule.spi;
#ifdef SSH_IPSEC_MULTICAST
          /* RFC 4303: Include multicast destication IP in SA selection */
          if (SSH_IP_IS_MULTICAST(&pc->dst))
            {
              SSH_DEBUG(SSH_D_LOWOK,("Including multicast destination "
                                     "IP address in flow id calculations"));
              SSH_IP_ENCODE(&pc->dst, u.id.dst, dummy);
            }
#endif /* SSH_IPSEC_MULTICAST */
        }
      else
        goto store_ip_addresses;
      break;

    case SSH_IPPROTO_ICMP:
      /* Process the ICMP according to its type. */
      switch (pc->icmp_type)
        {
        case SSH_ICMP_TYPE_UNREACH:
        case SSH_ICMP_TYPE_SOURCEQUENCH:
        case SSH_ICMP_TYPE_TIMXCEED:
        case SSH_ICMP_TYPE_PARAMPROB:
          /* Compute flow id for ICMP errors from the violating packet.
             This call results into a recursive call to this function. */
          return fastpath_compute_icmp_error_flow_id(fastpath, pc, tunnel_id,
                                                     flow_id);

        case SSH_ICMP_TYPE_ECHO:
        case SSH_ICMP_TYPE_ECHOREPLY:
          /* Take identification and IP addresses. */
          SSH_PUT_16BIT(u.id.icmp_identifier, pc->u.rule.src_port);
          /*FALLTHROUGH*/

        default:
          goto store_ip_addresses;
        }
      break;

#if defined (WITH_IPV6)
    case SSH_IPPROTO_IPV6ICMP:
      {
        switch (pc->icmp_type)
          {
          case SSH_ICMP6_TYPE_UNREACH:
          case SSH_ICMP6_TYPE_TOOBIG:
          case SSH_ICMP6_TYPE_TIMXCEED:
          case SSH_ICMP6_TYPE_PARAMPROB:
            /* Compute flow id for ICMP errors from the violating packet.
               This call results into a recursive call to this function. */
            return fastpath_compute_icmp_error_flow_id(fastpath, pc, tunnel_id,
                                                       flow_id);

          case SSH_ICMP6_TYPE_ROUTER_SOLICITATION:
          case SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT:
          case SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION:
          case SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT:
            /* Magical value to differentiate us from other ICMP flows.
               This is required to allow solicitation/advertisement
               packets to reach rule lookup even in cases where ICMP
               flows exist between the hosts. */
            u.id.dst_port = 0xc0de;
            goto store_ip_addresses;

          case SSH_ICMP6_TYPE_ECHOREQUEST:
          case SSH_ICMP6_TYPE_ECHOREPLY:
            /* Take identification and IP addresses. */
            SSH_PUT_16BIT(u.id.icmp_identifier, pc->u.rule.src_port);
            /*FALLTHROUGH*/

          default:
            goto store_ip_addresses;
          }
        break;
      }
#endif /* WITH_IPV6 */

    default:
    store_ip_addresses:
      SSH_IP_ENCODE(&pc->dst, u.id.dst, dummy);
      SSH_IP_ENCODE(&pc->src, u.id.src, dummy);
      break;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Incoming IPsec flows have extension selectors set to 0. */
  if ((pc->flags & SSH_ENGINE_PC_IS_IPSEC) == 0)
    {
      int i;
      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          u.id.extension[i] = pc->pp->extension[i];
        }
    }
#endif /* SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0 */

  /* Hash the flow id structure into 128 bits. */
  fastpath_flow_id_hash(u.raw, SSH_ENGINE_FLOW_ID_NUMBER_OF_WORDS,
                        fastpath->engine->flow_id_salt, (SshUInt32 *) flow_id);

  return TRUE;
}
