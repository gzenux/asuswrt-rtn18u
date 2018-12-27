/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   TCP/IP state tracking for the flow engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTcp"

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Some commonly used TCP options */
#define SSH_TCPOPT_EOL  0 /* End of list */
#define SSH_TCPOPT_NOP  1 /* No operation */
#define SSH_TCPOPT_MSS  2 /* Maximum segment size */
#define SSH_TCPOPT_WS   3 /* Window scale factor */
#define SSH_TCPOPT_TS   8 /* Timestamp */

/* Data strucure for storing TCP option information */
typedef struct
{
  union
  {
    /* Maximum segment size */
    SshUInt16 mss;

    /* Windows scale factor */
    SshUInt8 ws;

    /* Timestamp */
    struct
    {
      /* timestamp */
      SshUInt32 ts;
      /* timestamp echo reply*/
      SshUInt32 ts_reply;
    } ts;
  } u;
} SshTcpOptionStruct, *SshTcpOption;


#define SSH_TCP_WINDOW_SIZE(tcp_flags,window_size,shift_count)  \
  (((tcp_flags & SSH_TCPH_FLAG_SYN) == 0) ?                     \
    (window_size << shift_count) : window_size)

#define SSH_TCP_WINDOW_MAX(tcp_flags,shift_count) \
  (SSH_TCP_WINDOW_SIZE(tcp_flags,0xFFFF,shift_count) | 0x0000FFFF)

#define SSH_TCP_SEQ_OK(prev_seq, prev_data, seq) \
   (((SshUInt32)(prev_seq) <= (SshUInt32)(seq) \
     && (SshUInt32)(seq) <= (SshUInt32)(prev_seq) + (SshUInt32)(prev_data)) \
   || (((SshUInt32)(prev_seq)+(SshUInt32)(prev_data)) < (SshUInt32)(prev_seq) \
     && ((SshUInt32)(seq) <= ((SshUInt32)(prev_seq) + (SshUInt32)(prev_data)) \
         || (SshUInt32)(prev_seq) <= (SshUInt32)(seq))))

#define SSH_TCP_SEQ_DIFF(seq_a, seq_b) \
  (SshUInt32)(((SshUInt32)(seq_a) < (SshUInt32)(seq_b) ? (SshUInt32)(seq_b) - \
    (SshUInt32)(seq_a) : ((SshUInt32)0xffffffff-(SshUInt32)(seq_a)) + \
    (SshUInt32)(seq_b) + (SshUInt32)1))

#define SSH_TCP_GOTO(flow, tcpdata, new_state) \
do {\
   SSH_DEBUG(SSH_D_HIGHOK, ("transitioning %@:%u -> %@:%u to state %u", \
                            ssh_ipaddr_render, &(flow)->src_ip, \
                            (flow)->src_port, \
                            ssh_ipaddr_render, &(flow)->dst_ip, \
                            (flow)->dst_port, \
                            (new_state))); \
   (tcpdata)->state = (new_state); \
} while(0)

#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
/* This function checks handles sequence number caching and checking
   for packets with destructive control flags (RST, FIN). Note that
   as it is now, it should not be used for discarding pure data packets.
   E.g. it does not handle partly overlapping windows gracefully for
   such cases. */
static Boolean
ssh_engine_tcp_seq_magic(SshUInt16 flags,
                         SshUInt32 seq,
                         SshUInt32 ack_seq,
                         SshUInt16 tcp_len,
                         SshUInt32 *seq_ptr,
                         SshUInt32 *data_ptr,
                         SshUInt32 *ack_seq_ptr,
                         SshUInt32 *ack_data_ptr,
                         SshUInt32 max_window_size)
{
  /* Do sequence number monitoring only for control packets */
  if ((flags & (SSH_TCPH_FLAG_RST|SSH_TCPH_FLAG_FIN)) != 0)
    {
      if (!SSH_TCP_SEQ_OK(*seq_ptr, *data_ptr, seq))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("bad sequence number in TCP packet, window "
                     "[%u,%u] seq %u",
                     *seq_ptr, *data_ptr, seq));
          return FALSE;
        }
      if (flags & SSH_TCPH_FLAG_ACK)
        {
          /* Update sequence pointer in other direction */
          if (!SSH_TCP_SEQ_OK(*ack_seq_ptr, *ack_data_ptr, ack_seq))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("bad ack sequence number in TCP packet window "
                         "[%u,%u] ack %u",
                         *ack_seq_ptr, *ack_data_ptr, ack_seq));
              return FALSE;
            }

          if (SSH_TCP_SEQ_DIFF(*ack_seq_ptr, ack_seq) <= *ack_data_ptr)
            *ack_data_ptr -= SSH_TCP_SEQ_DIFF(*ack_seq_ptr, ack_seq);
          else
            *ack_data_ptr = 0;
          *ack_seq_ptr = ack_seq;
        }
    }
  else
    {
      /* Update sequence window in reverse direction */
      if (flags & SSH_TCPH_FLAG_ACK)
        {
          if (SSH_TCP_SEQ_OK(*ack_seq_ptr, *ack_data_ptr, ack_seq))
            {
              if (SSH_TCP_SEQ_DIFF(*ack_seq_ptr, ack_seq) <= *ack_data_ptr)
                *ack_data_ptr -= SSH_TCP_SEQ_DIFF(*ack_seq_ptr, ack_seq);
              else
                *ack_data_ptr = 0;
              *ack_seq_ptr = ack_seq;
            }
          else
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("bad ack sequence number in TCP packet window "
                         "[%u,%u] ack %u",
                         *ack_seq_ptr, *ack_data_ptr, ack_seq));
            }
        }
    }

  /* Increase sequence window in forward direction. Note that
     we assume a maximum window size to be in use. This is required
     as otherwise an ACK for a set of out-of-order packets might
     be ignored. */
  if (SSH_TCP_SEQ_OK(*seq_ptr, max_window_size, seq))
    {
      if (((SshUInt32)tcp_len + SSH_TCP_SEQ_DIFF(*seq_ptr, seq))
          >= max_window_size)
        {
          *data_ptr = max_window_size;
        }
      else if ((SshUInt32)*data_ptr
               < (SshUInt32)tcp_len + SSH_TCP_SEQ_DIFF(*seq_ptr, seq))
        {
          *data_ptr = tcp_len + SSH_TCP_SEQ_DIFF(*seq_ptr, seq);
        }
    }
  else
    {
       SSH_DEBUG(SSH_D_NETGARB,
                ("discarding sequence information seq=%u len=%u "
                 "(window [%u,%u])!",
                 seq, tcp_len, *seq_ptr, *data_ptr));
    }

  SSH_DEBUG(SSH_D_MY,("window (%u, %u) packet (%u,%u) ack %u",
                      *seq_ptr, *data_ptr, seq, tcp_len, ack_seq));
  return TRUE;
}
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */


/*  */
static Boolean
ssh_engine_tcp_option_parse(SshUInt8 option_type,
                            const unsigned char *buffer,
                            size_t buf_len,
                            SshTcpOption option_return)
{
  SshUInt8 opt_len = 0;

  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(buf_len > 0);
  SSH_ASSERT(option_return != NULL);

  while (buf_len)
    {
      SshUInt8 kind = SSH_GET_8BIT(buffer);

      switch (kind)
        {
        case SSH_TCPOPT_EOL:
          goto not_found;

        case SSH_TCPOPT_NOP:
          opt_len = 1;
          break;

        case SSH_TCPOPT_MSS:
          if (buf_len < 4)
            goto invalid_len;

          opt_len = SSH_GET_8BIT(buffer+1);
          if (opt_len != 4)
            goto invalid_len;

          if (option_type == kind)
            {
              option_return->u.mss = SSH_GET_16BIT(buffer+2);
              SSH_DEBUG(SSH_D_MY5, ("MSS = %u", option_return->u.mss));
              return TRUE;
            }
          break;

        case SSH_TCPOPT_WS:
          if (buf_len < 3)
            goto invalid_len;

          opt_len = SSH_GET_8BIT(buffer+1);
          if (opt_len != 3)
            goto invalid_len;

          if (option_type == kind)
            {
              option_return->u.ws = SSH_GET_8BIT(buffer+2);
              SSH_DEBUG(SSH_D_MY5,
                        ("Window scale factor = %u", option_return->u.ws));
              return TRUE;
            }
          break;

        case SSH_TCPOPT_TS:
          if (buf_len <= 10)
            goto invalid_len;

          opt_len = SSH_GET_8BIT(buffer+1);
          if (opt_len != 10)
            goto invalid_len;

          if (option_type == kind)
            {
              option_return->u.ts.ts = SSH_GET_32BIT(buffer+2);
              option_return->u.ts.ts_reply = SSH_GET_32BIT(buffer+6);
              SSH_DEBUG(SSH_D_MY5,
                        ("Timestamp=%lu, Timestamp_reply=%ul",
                         option_return->u.ts.ts,
                         option_return->u.ts.ts_reply));
              return TRUE;
            }
          break;

        default:
          if (buf_len < 2)  /* At least 'kind' and 'len' fields */
            goto invalid_len;
          opt_len = SSH_GET_8BIT(buffer+1);
          if (opt_len >= buf_len)
            goto invalid_len;
          break;
        }

      SSH_ASSERT(buf_len >= opt_len);

      buffer += opt_len;
      buf_len -= opt_len;
    }

 not_found:

  SSH_DEBUG(SSH_D_MY, ("TCP option (%u) not found", option_type));
  return FALSE;

 invalid_len:

  SSH_DEBUG(SSH_D_NETGARB, ("Invalid TCP option length!"));
  return FALSE;
}


/* Processes a TCP/IP packet for a flow. */
SshEngineProtocolMonitorRet
ssh_engine_tcp_packet(SshEngineFlowData flow, SshEnginePacketContext pc)
{
  SshEngineTcpData tcpdata = NULL;
  SshUInt32 tcp_data_offset;
  unsigned char tcph[SSH_TCP_HEADER_LEN];
  SshUInt32 seq = 0, ack_seq, tcp_len = 0, pp_flags;
  SshUInt16 flags = 0;
  Boolean forward = FALSE;
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
  SshUInt32 *seq_ptr = NULL, *ack_seq_ptr;
  SshUInt32 *data_ptr, *ack_data_ptr;
  SshUInt8 *wnd_scale_ptr = NULL;
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  SshUInt32 new_seq, old_seq, new_ack;
  SshUInt16 sum;
#endif /* SSH_IPEC_TCP_SEQUENCE_RANDOMIZER */

  SSH_DEBUG(SSH_D_LOWOK, ("tcp/ip state processing"));
  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;

  /* Store flags in case pc->pp gets invalidated. */
  pp_flags = pc->pp->flags;

  /* Check IP protocol.  The flow mechanism also associates ICMP
     Destination Unreachable packets to this flow. */
  if (pc->ipproto != SSH_IPPROTO_TCP)
    return SSH_ENGINE_MRET_PASS;

  /* Let all but first fragments through */
  if ((pc->pp->flags & SSH_ENGINE_P_ISFRAG)
      && (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
    {
      tcp_data_offset = 0;
      goto pass;
    }

  /* Sanity check packet length. */
  if (pc->packet_len < pc->hdrlen + SSH_TCP_HEADER_LEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("DROP; packet too short to contain TCP header, len=%d",
                 pc->packet_len));
      return SSH_ENGINE_MRET_DROP;
    }

  /* Get TCP header. */
  ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen, tcph, SSH_TCP_HEADER_LEN);
  flags = SSH_TCPH_FLAGS(tcph);
  flags &= 0x3f;

  if (flow == NULL)
    {
      if (flags == SSH_TCPH_FLAG_SYN)
        return SSH_ENGINE_MRET_PASS;
      else
        return SSH_ENGINE_MRET_DROP;
    }

  seq = SSH_TCPH_SEQ(tcph);
  ack_seq = SSH_TCPH_ACK(tcph);

  /* Compute an estimate for the packet length */
  if (pc->pp->flags & SSH_ENGINE_P_ISFRAG)
    {
      SSH_ASSERT(pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG);
      tcp_data_offset = (SSH_TCPH_DATAOFFSET(tcph) << 2);
      tcp_len = 0xFFFF - pc->hdrlen - tcp_data_offset;
    }
  else
    {
      tcp_data_offset = (SSH_TCPH_DATAOFFSET(tcph) << 2);
      tcp_len = pc->packet_len - pc->hdrlen - tcp_data_offset;
    }

  /* If the data is beyond this packet boundary, (even if it is
     a fragment, we drop it) */
  if (tcp_data_offset + pc->hdrlen > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("dropping packet because TCP header not in first fragment!"));
      return SSH_ENGINE_MRET_DROP;
    }

  if (flags & SSH_TCPH_FLAG_SYN)
    tcp_len++;
  else if (flags & SSH_TCPH_FLAG_FIN)
    tcp_len++;

  /* Dispatch based on the state of the session. */
  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;

  tcpdata = &flow->u.tcp;

#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  /* Cancel previous ACK/seq values from checksum */
  sum = SSH_TCPH_CHECKSUM(tcph);

  /* Compute new ack/seq values */
  new_ack = 0;
  if (forward)
    {
      new_seq = (SshUInt32)(seq + tcpdata->delta_i_to_r);
      if (ack_seq != 0 || (flags & SSH_TCPH_FLAG_ACK) != 0)
        new_ack = (SshUInt32)(ack_seq - tcpdata->delta_r_to_i);

      SSH_DEBUG(SSH_D_MY,
                ("TCP sequence deltas [%u:%u]",
                 tcpdata->delta_i_to_r,
                 tcpdata->delta_r_to_i));
    }
  else
    {
      new_seq = (SshUInt32)(seq + tcpdata->delta_r_to_i);
      if (ack_seq != 0 || (flags & SSH_TCPH_FLAG_ACK) != 0)
        new_ack = (SshUInt32)(ack_seq - tcpdata->delta_i_to_r);

      SSH_DEBUG(SSH_D_MY,
                ("TCP sequence deltas [%u:%u]",
                 tcpdata->delta_r_to_i,
                 tcpdata->delta_i_to_r));
    }

  /* Cache old sequence value for IP cksum update */
  old_seq = seq;
  seq = new_seq;
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */

#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
  if (forward)
    {
      wnd_scale_ptr = &tcpdata->win_scale_r_to_i;
      seq_ptr = &tcpdata->seq_i_to_r;
      data_ptr = &tcpdata->data_i_to_r;
      ack_seq_ptr = &tcpdata->seq_r_to_i;
      ack_data_ptr = &tcpdata->data_r_to_i;
    }
  else
    {
      wnd_scale_ptr = &tcpdata->win_scale_i_to_r;
      seq_ptr = &tcpdata->seq_r_to_i;
      data_ptr = &tcpdata->data_r_to_i;
      ack_seq_ptr = &tcpdata->seq_i_to_r;
      ack_data_ptr = &tcpdata->data_i_to_r;
    }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */




  SSH_DEBUG(SSH_D_LOWOK,
            ("tcp: flow_flags=0x%04x forward=%d, state=%d, flags=0x%x, "
             "seq=%u, len=%u, ack=%u",
             (int)flow->data_flags, (int)forward, (int)tcpdata->state,
             (int)flags,
             seq, tcp_len, ack_seq));

  switch (tcpdata->state)
    {
    case SSH_ENGINE_TCP_INITIAL:
      if (!forward)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid TCP state"));
          goto reject;
        }
      /* SYN must open the session. */
      if (flags == SSH_TCPH_FLAG_SYN)
        {
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
          /* Support for large TCP windows */
          tcpdata->win_scale_i_to_r = 0;  /* default max. size: 64k */
          /* Does the packet contain TCP options? */
          if (tcp_data_offset > SSH_TCP_HEADER_LEN)
            {
              SshTcpOptionStruct opt;
              const unsigned char *opt_buff;
              size_t opt_len;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
              SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
              opt_buff = ssh_interceptor_packet_pullup_read(pc->pp,
                                                            pc->hdrlen +
                                                            tcp_data_offset);
              if (opt_buff == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("ssh_interceptor_packet_pullup_read failed"));
                  return SSH_ENGINE_MRET_ERROR;
                }

              opt_buff += pc->hdrlen + SSH_TCP_HEADER_LEN;
              opt_len = tcp_data_offset - SSH_TCP_HEADER_LEN;

              /* Read the shift count from window scale factor TCP option.
                 Use default value if the option does not exist in this SYN
                 packet. */
              if (ssh_engine_tcp_option_parse(SSH_TCPOPT_WS,
                                              opt_buff, opt_len, &opt))
                tcpdata->win_scale_i_to_r = opt.u.ws;
            }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */

          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_SYN);
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
          tcpdata->seq_i_to_r = seq;
          tcpdata->data_i_to_r = 1;
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
          break;
        }

      /* NULL-SCAN */
      if (flags == 0)
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TCP_NULL;
          goto drop;
        }

      /* FIN-SCAN */
      if (flags == SSH_TCPH_FLAG_FIN)
        {






          pc->audit.corruption = SSH_PACKET_CORRUPTION_TCP_FIN;
          goto drop;
        }
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid packet in INITIAL state"));
      goto reject;

    case SSH_ENGINE_TCP_SYN:
      /* SYN is followed by SYN-ACK in the reverse direction */
      if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }
      if (forward)
        { /* Resend of SYN */
          if (flags == SSH_TCPH_FLAG_SYN)
            {
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
              if (tcpdata->seq_i_to_r != seq)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("bad sequence number for resent SYN"));
                  pc->audit.corruption
                    = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
                  goto drop;
                }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
              break;
            }
        }
      else
        { /* Must be SYN-ACK or RST */
          if (flags == (SSH_TCPH_FLAG_SYN | SSH_TCPH_FLAG_ACK))
            {
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
              if (tcpdata->seq_i_to_r + tcpdata->data_i_to_r != ack_seq)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("bad ack sequence number for SYN-ACK"));
                  pc->audit.corruption
                    = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
                  goto drop;
                }
              /* Support for large TCP windows */
              tcpdata->win_scale_r_to_i = 0;  /* default max. size: 64k */
              /* Does the packet contain TCP options? */
              if (tcp_data_offset > SSH_TCP_HEADER_LEN)
                {
                  SshTcpOptionStruct opt;
                  const unsigned char *opt_buff;
                  size_t opt_len;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                  SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

                  opt_buff = ssh_interceptor_packet_pullup_read(pc->pp,
                                                            pc->hdrlen +
                                                            tcp_data_offset);
                  if (opt_buff == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                              ("ssh_interceptor_packet_pullup_read failed"));
                      return SSH_ENGINE_MRET_ERROR;
                    }

                  opt_buff += pc->hdrlen + SSH_TCP_HEADER_LEN;
                  opt_len = tcp_data_offset - SSH_TCP_HEADER_LEN;

                  /* Read the shift count from window scale factor TCP
                     option. Use default value if the option does not exist
                     in this SYN packet. */
                  if (ssh_engine_tcp_option_parse(SSH_TCPOPT_WS,
                                                  opt_buff, opt_len, &opt))
                    tcpdata->win_scale_r_to_i = opt.u.ws;
                }
              tcpdata->seq_i_to_r = ack_seq;
              tcpdata->data_i_to_r = 0;
              tcpdata->seq_r_to_i = seq;
              tcpdata->data_r_to_i = 1;
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
              SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_SYN_ACK);
              break;
            }
        }
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid packet in SYN state"));
      goto reject;

    case SSH_ENGINE_TCP_SYN_ACK:
      /* SYN-ACK is followed by ACK in the forward direction */
      if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata,  SSH_ENGINE_TCP_CLOSED);
          break;
        }
      if (forward)
        {
          /* Drop syn packet. If a correct SYN-ACK has been received, then
             this is obviously unnecessary. */
          if (flags == SSH_TCPH_FLAG_SYN)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Dropping extra SYN packet"));
              goto drop;
            }
          /* ACK of SYN-ACK, possibly with data as well. */
          if ((flags & SSH_TCPH_FLAG_ACK) &&
              !(flags & SSH_TCPH_FLAG_SYN))
            {
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
              if ((SshUInt32)(tcpdata->seq_i_to_r + tcpdata->data_i_to_r)
                  != seq)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("bad sequence number in TCP packet"));
                  pc->audit.corruption
                    = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
                  goto drop;
                }
              tcpdata->seq_i_to_r = (SshUInt32)seq;
              tcpdata->data_i_to_r = tcp_len;
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
              SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_SYN_ACK_ACK);
              break;
            }
        }
      else
        { /* Must be resend of SYN_ACK */
          if (flags == (SSH_TCPH_FLAG_SYN | SSH_TCPH_FLAG_ACK))
            {
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
              if (tcpdata->seq_r_to_i != seq)
                {
                  SSH_DEBUG(SSH_D_NETGARB,
                            ("bad sequence number in TCP packet"));
                  pc->audit.corruption
                    = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
                  goto drop;
                }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
              break;
            }
        }
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid packet in SYN_ACK state"));
      goto reject;

    case SSH_ENGINE_TCP_SYN_ACK_ACK:
      /* forward ACK means established, or resend of SYN-ACK */

#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
      if (ssh_engine_tcp_seq_magic(flags, seq, ack_seq, (SshUInt16)tcp_len,
                                   seq_ptr, data_ptr, ack_seq_ptr,
                                   ack_data_ptr,
                                   SSH_TCP_WINDOW_MAX(flags, 0)) == FALSE)
        {
          /* If this is out-of-order packet, just let it go. We don't
             wan't to cause unnecessary events to the policymanager. */
          if (*seq_ptr > seq)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("bad sequence number in TCP packet, window "
                         "[%u,%u] ack %u",
                         *seq_ptr, *data_ptr, seq));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
              goto drop;
            }
        }

      if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */

      if (forward)
        {
          /* A SYN in the forward direction might be a resend of
             an old SYN. Drop it. */
          if (flags & SSH_TCPH_FLAG_SYN)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Resend of old SYN"));
              goto drop;
            }

          /* After forward ACK received, allow any established */
          if (flags & SSH_TCPH_FLAG_FIN)
            {
              SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_FIN_FWD);
              break;
            }
        }
      else
        {
          /* After forward ACK received, allow established or resend SYN-ACK */
          if (flags == (SSH_TCPH_FLAG_SYN | SSH_TCPH_FLAG_ACK))
            {
              break;
            }

          if (flags & SSH_TCPH_FLAG_SYN)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid SYN packet in SYN_ACK_ACK state"));
              goto reject;
            }

          if (flags & SSH_TCPH_FLAG_FIN)
            {
              SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_FIN_REV);
              break;
            }
          /* Server sent some data, it must have seen our forward ACK. */
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_ESTABLISHED);

        }
      break; /* In this state we accept by default. */

    case SSH_ENGINE_TCP_ESTABLISHED:
#ifndef SSH_IPSEC_TCP_SEQUENCE_MONITOR
    case SSH_ENGINE_TCP_FIN_FWD:
    case SSH_ENGINE_TCP_FIN_REV:
#endif /* SSH_IPEC_TCP_SEQUENCE_MONITOR */
      /* Established and reverse ack seen. */

#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
      if (ssh_engine_tcp_seq_magic(flags, seq, ack_seq, (SshUInt16)tcp_len,
                         seq_ptr, data_ptr,
                         ack_seq_ptr, ack_data_ptr,
                         SSH_TCP_WINDOW_MAX(flags, *wnd_scale_ptr)) == FALSE)
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE;
          goto drop;
        }
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */

      if (flags & SSH_TCPH_FLAG_SYN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Unacceptable SYN packet!"));
          if (forward)
            goto drop;
          else
            goto reject;
        }

      if (flags & SSH_TCPH_FLAG_FIN)
        {
          if (tcpdata->state == SSH_ENGINE_TCP_ESTABLISHED)
            SSH_TCP_GOTO(flow, tcpdata,
                         (forward
                          ? SSH_ENGINE_TCP_FIN_FWD
                          : SSH_ENGINE_TCP_FIN_REV));
#ifndef SSH_IPSEC_TCP_SEQUENCE_MONITOR
          else if ((tcpdata->state == SSH_ENGINE_TCP_FIN_FWD && forward == 0)
                   || (tcpdata->state == SSH_ENGINE_TCP_FIN_REV && forward))
            SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_FIN_FIN);
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
        }
      /* RST's are heeded only if sequence numbers are monitored */
      else if ((flags & SSH_TCPH_FLAG_RST)
#ifndef SSH_IPSEC_TCP_SEQUENCE_MONITOR
               /* Handle so-called "half-duplex close" correctly */
               && (tcpdata->state == SSH_ENGINE_TCP_FIN_FWD
                   || tcpdata->state == SSH_ENGINE_TCP_FIN_REV)
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
               )
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }

      break;

#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
    case SSH_ENGINE_TCP_FIN_FWD:
      /* FIN seen in forward direction. */
      if (!forward && (flags & SSH_TCPH_FLAG_FIN))
        SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_FIN_FIN);
      else if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }
      if (flags & SSH_TCPH_FLAG_SYN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid SYN packet in FIN_FWD state"));
          goto reject;
        }
      break;

    case SSH_ENGINE_TCP_FIN_REV:
      /* FIN seen in reverse direction. */
      if (forward && (flags & SSH_TCPH_FLAG_FIN))
        SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_FIN_FIN);
      else if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }
      if (flags & SSH_TCPH_FLAG_SYN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid SYN packet in FIN_REV state"));
          goto reject;
        }
      break;
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */

    case SSH_ENGINE_TCP_FIN_FIN:
    case SSH_ENGINE_TCP_CLOSE_WAIT:
      /* FIN seen in both directions. Could get ACK or resend. */
      if (flags & SSH_TCPH_FLAG_RST)
        {
          SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSED);
          break;
        }
      if (flags & SSH_TCPH_FLAG_SYN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Invalid SYN packet in TCP state %u", tcpdata->state));
          goto reject;
        }
      if (flags == SSH_TCPH_FLAG_ACK)
        SSH_TCP_GOTO(flow, tcpdata, SSH_ENGINE_TCP_CLOSE_WAIT);
      break;

    case SSH_ENGINE_TCP_CLOSED:
      /* Only RST packets are allowed through */
      if (flags == SSH_TCPH_FLAG_RST
          || flags == (SSH_TCPH_FLAG_RST|SSH_TCPH_FLAG_ACK))
        break;







      /* No traffic allowed in any direction. */
      SSH_DEBUG(SSH_D_NETGARB, ("No traffic allowed in CLOSED state"));
      goto reject;

    default:
      ssh_fatal("ssh_engine_tcp_packet: invalid state %d", tcpdata->state);
    }

  /* Insert modified sequence numbers into packet if it
     is going to be passed. */

#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  /* Update header */
  SSH_TCPH_SET_SEQ(tcph, new_seq);
  SSH_TCPH_SET_ACK(tcph, new_ack);

  /* Offset is only used for checking alignment */
  sum = ssh_ip_cksum_update_long(sum, 0, old_seq, new_seq);
  sum = ssh_ip_cksum_update_long(sum, 0, ack_seq, new_ack);
  SSH_TCPH_SET_CHECKSUM(tcph, sum);

  /* Copy TCP header back to the packet. */
  if (!ssh_interceptor_packet_copyin(pc->pp, pc->hdrlen, tcph,
                                     SSH_TCP_HEADER_LEN))
    return SSH_ENGINE_MRET_ERROR; /* pc->pp is already freed. */
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */

 pass:
  return SSH_ENGINE_MRET_PASS;

 drop:
  return SSH_ENGINE_MRET_DROP;

 reject:
  return SSH_ENGINE_MRET_REJECT;
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

int
ssh_engine_tcp_lru_level(SshEngineFlowData d_flow)
{
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  SshEngineTcpData tcpdata;

  SSH_ASSERT(d_flow->ipproto == SSH_IPPROTO_TCP);
  tcpdata = &d_flow->u.tcp;

  switch (tcpdata->state)
    {
    case SSH_ENGINE_TCP_INITIAL:
    case SSH_ENGINE_TCP_SYN:
    case SSH_ENGINE_TCP_SYN_ACK:
      return 0;
    case SSH_ENGINE_TCP_SYN_ACK_ACK:
    case SSH_ENGINE_TCP_ESTABLISHED:
      return 2;
    case SSH_ENGINE_TCP_FIN_FWD:
    case SSH_ENGINE_TCP_FIN_REV:
    case SSH_ENGINE_TCP_FIN_FIN:
      return 1;
    case SSH_ENGINE_TCP_CLOSE_WAIT:
    case SSH_ENGINE_TCP_CLOSED:
      return 0;
    default:
      return 0;
    }
  /*NOTREACHED*/
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifndef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  return 2;
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
}
