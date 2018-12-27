/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppProtocol"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"

/*
  No actual "separate" data structure is used to represent the information
  present in Protocol Data Units. Instead an "opaque" byte-level
  representation of the actual packet is used, from which the relevant
  information is extracted using appropriate functions. Similarily actual
  packets are marshalled directly from the SshPppState and
  SshLCPLocal instances.

  Note: The "Protocol" field is considered to be part of both the HDLC
  and PPP frames. This is the same convention as used in RFC 1661 and
  RFC 1662.
*/


static void
ssh_ppp_protocol_flushpkt(SshPppState state,SshPppProtocol local)
{
  SshPppMuxProtocol mux = ssh_ppp_thread_get_mux(local->ppp_thread);

  ssh_ppp_flush_send_pkt(state, mux);
}

static SshPppPktBuffer
ssh_ppp_protocol_get_output_buf(SshPppState gdata,
                                SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshPppMuxProtocol mux = ssh_ppp_thread_get_mux(local->ppp_thread);

  if (ssh_ppp_flush_output_pkt_isavail(mux) == FALSE)
    return NULL;

  pkt = ssh_ppp_flush_get_output_pkt(mux);

  if (pkt == NULL)
    {
      ssh_ppp_fatal(gdata);
      return NULL;
    }

  SSH_ASSERT(ssh_ppp_pkt_buffer_isempty(pkt));

  ssh_ppp_pkt_buffer_offset(pkt,16);

  return pkt;
}

/* Handle identifiers in configuration req/ack/nak/rej messages */

SshUInt8
ssh_ppp_identifier_get(SshPppIdentifier id, SshUInt8 code)
{
  id->code = code;
  return id->id;
}

Boolean
ssh_ppp_identifier_ismatch(SshPppIdentifier id,
                           SshUInt8 code,
                           SshUInt8 val)
{
  if (id->code != code)
    {
      return FALSE;
    }

  if (id->id != val)
    {
      return FALSE;
    }

  return TRUE;
}

void
ssh_ppp_identifier_inc(SshPppIdentifier id)
{
  id->code = 0;
  id->id++;
}

void
ssh_ppp_identifier_mark(SshPppIdentifier id,
                        SshUInt8 code,
                        SshUInt8 val)
{
  id->code = code;
  id->id = val;
}

void
ssh_ppp_identifier_init(SshPppState gdata, SshPppIdentifier id)
{
  id->code = 0;

  if (gdata->no_magic_lcp == 1)
    {
      id->id = 0;
    }
  else
    {
      id->id = ssh_random_get_byte();
    }
}

/* Default values for several counters. See RFC 1661. */

static SshPppCounter
ssh_ppp_protocol_default_counter_max(void* ctx, int i)
{
  switch (i)
    {
    case SSH_PPP_COUNTER_CONFIGURE_REQ_RESEND:
      return 10;
    case SSH_PPP_COUNTER_TERMINATE_REQ_RESEND:
      return 2;
    case SSH_PPP_COUNTER_NAKS:
      return 10;
    case SSH_PPP_COUNTER_OPTION_NAKS:
      return 7;
    case SSH_PPP_COUNTER_NEUTRAL_ACKS:
      return 2;
    default:
      SSH_NOTREACHED;
    }
  return 0;
}

SshPppCounter
ssh_ppp_protocol_get_counter_max(SshPppProtocol tdata, int i)
{
  if (tdata->iface == NULL
      || tdata->iface->get_counter_max == NULL_FNPTR)
    {
      return ssh_ppp_protocol_default_counter_max(NULL,i);
    }
  return tdata->iface->get_counter_max(tdata->ctx,i);
}


/* Wrappers for handing the Configure NAK send counter */

static void
ssh_ppp_protocol_counter_nak_init(SshPppProtocol tdata)
{
  tdata->counter_naks_current = 0;
}

static void
ssh_ppp_protocol_counter_nak_inc(SshPppProtocol tdata)

{
  tdata->counter_naks_current++;
}

static int
ssh_ppp_protocol_counter_nak_isbad(SshPppProtocol tdata)
{
  if (tdata->counter_naks_current
      >= ssh_ppp_protocol_get_counter_max(tdata,SSH_PPP_COUNTER_NAKS))
    {
      return 1;
    }
  return 0;
}


/* Some convenience wrappers for callbacks */

static SshPppConfigOption
ssh_ppp_protocol_option_input_get(SshPppState state,
                                  SshPppProtocol tdata, SshUInt8 t)
{
  if (tdata->iface != NULL
      && tdata->iface->get_config_option_input_cb != NULL_FNPTR)
    {
      return tdata->iface->get_config_option_input_cb(state, tdata->ctx,t);
    }
  return NULL;
}

static SshPppConfigOption
ssh_ppp_protocol_option_output_get(SshPppState state,
                                   SshPppProtocol tdata, SshUInt8 t)
{
  if (tdata->iface != NULL
      && tdata->iface->get_config_option_output_cb != NULL_FNPTR)
    {
      return tdata->iface->get_config_option_output_cb(state, tdata->ctx,t);
    }
  return NULL;
}

static SshPppConfigOption
ssh_ppp_protocol_option_input_iter(SshPppState state,
                                   SshPppProtocol tdata, unsigned long i)
{
  if (tdata->iface != NULL
      && tdata->iface->iter_config_option_input_cb != NULL_FNPTR)
    {
      return tdata->iface->iter_config_option_input_cb(state, tdata->ctx,i);
    }
  return NULL;
}

static SshPppConfigOption
ssh_ppp_protocol_option_output_iter(SshPppState state,
                                    SshPppProtocol tdata, unsigned long i)
{
  if (tdata->iface != NULL
      && tdata->iface->iter_config_option_output_cb != NULL_FNPTR)
    {
      return tdata->iface->iter_config_option_output_cb(state, tdata->ctx,i);
  }
  return NULL;
}

static int
ssh_ppp_protocol_input_isquery(SshPppState state, SshPppProtocol tdata)
{
  SshPppConfigOption opt;
  unsigned long i;
  int ok;

  ok = 1;
  i = 0;

  while ((opt=ssh_ppp_protocol_option_input_iter(state,tdata,i)) != NULL)
    {
      ok &= ssh_ppp_config_option_isquery(opt);
      i++;
  }

  return ok;
}

static int
ssh_ppp_protocol_input_isfail(SshPppState state, SshPppProtocol tdata)
{
  unsigned long i;
  SshPppConfigOption opt;
  SshPppConfigPreference pref;
  SshPppConfigStatus config_status;

  i = 0;

  while ((opt=ssh_ppp_protocol_option_input_iter(state, tdata,i)) != NULL)
    {
      config_status = ssh_ppp_config_option_get_status(opt);
      pref = ssh_ppp_config_preference_get(opt);

      if (pref == SSH_PPP_CONFIG_PREF_MANDATORY &&
          (config_status == SSH_PPP_CONFIG_STATUS_NAK
           || config_status == SSH_PPP_CONFIG_STATUS_REJECTED))
        {
          return 1;
        }
      i++;
    }
  return 0;
}

/* Check the status of all requested options */

static SshPppConfigResponse
ssh_ppp_protocol_option_isok(SshPppState state, SshPppProtocol local,
                             SshPppConfigOption opt, SshPppPktBuffer pkt)
{
  if (ssh_ppp_config_option_get_counter(opt)
      > ssh_ppp_protocol_get_counter_max(local,
                                         SSH_PPP_COUNTER_OPTION_NAKS))
    {

      if (ssh_ppp_config_preference_get(opt)
          == SSH_PPP_CONFIG_PREF_MANDATORY)

        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("option %d nak counter value (%d) overflow for "
                     "a mandatory buffer, fatal",
                     ssh_ppp_config_option_get_type(opt),
                     ssh_ppp_config_option_get_counter(opt)));

          return SSH_LCP_FATAL;
        }

      SSH_DEBUG(SSH_D_NETGARB,("option %d nak counter value (%d) overflow",
                               ssh_ppp_config_option_get_type(opt),
                               ssh_ppp_config_option_get_counter(opt)));

      return SSH_LCP_REJ;
    }

  return ssh_ppp_config_option_isok(opt,pkt);
}

static void
ssh_ppp_protocol_reset_own_options(SshPppState state, SshPppProtocol local)
{
  unsigned long i;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;

  i = 0;
  while ((opt = ssh_ppp_protocol_option_input_iter(state,local,i)) != NULL)
    {

      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status == SSH_PPP_CONFIG_STATUS_QUERY
          || config_status == SSH_PPP_CONFIG_STATUS_ACK)
        {

          ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_UNINIT);
        }
      i++;
    }
}

static void
ssh_ppp_protocol_reset_peer_options(SshPppState state, SshPppProtocol local)
{
  unsigned long i;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;

  i = 0;
  while ((opt = ssh_ppp_protocol_option_output_iter(state,local,i)) != NULL)
    {

      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status == SSH_PPP_CONFIG_STATUS_QUERY
          || config_status == SSH_PPP_CONFIG_STATUS_ACK
          || config_status == SSH_PPP_CONFIG_STATUS_NAK )
        {
          ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_UNINIT);
        }
      i++;
    }
}

static void
ssh_ppp_protocol_update_nak_counters(SshPppState state,
                                     SshPppProtocol local,
                                     SshPppPktBuffer pkt)
{
  SshPppPktBufferStruct buf;
  SshIterationStatus iter;
  SshUInt8 type;
  SshPppConfigOption opt;
  SshPppConfigResponse res;
  unsigned long i;

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_output_get(state,local,type);

      if (opt != NULL)
        {
          res = ssh_ppp_protocol_option_isok(state,local,opt,pkt);

          if (res == SSH_LCP_NAK)
            {
              ssh_ppp_config_option_inc_counter(opt);
            }
        }
      ssh_ppp_protocol_option_skip(pkt);
    }

  i = 0;
  while ((opt=ssh_ppp_protocol_option_output_iter(state, local,i)) != NULL)
    {

      /* If mandatory options are not queried with accepted parameters
         force a NAK reply */

      if (ssh_ppp_config_option_get_status(opt) != SSH_PPP_CONFIG_STATUS_QUERY
          && ssh_ppp_config_preference_get(opt)
             == SSH_PPP_CONFIG_PREF_MANDATORY)
        {
          ssh_ppp_config_option_inc_counter(opt);
        }
      i++;
    }
}

static SshPppConfigResponse
ssh_ppp_protocol_input_options(SshPppState state,
                               SshPppProtocol local,
                               SshPppPktBuffer pkt)
{
  SshIterationStatus iter;
  SshPppPktBufferStruct buf;
  SshUInt8 type;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;
  SshPppConfigPreference config_pref;
  SshPppConfigResponse res,res2;
  unsigned long i;

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  res = SSH_LCP_ACK;

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {

      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_output_get(state,local,type);

      if (opt == NULL)
        {
          return SSH_LCP_REJ;
        }
      else
        {
          res2 = ssh_ppp_protocol_option_isok(state,local,opt,pkt);

          if (res2 == SSH_LCP_FATAL)
            {
              return SSH_LCP_FATAL;
            }

          if (res2 == SSH_LCP_REJ)
            {
              return SSH_LCP_REJ;
            }

          if (res2 == SSH_LCP_NAK)
            {
              res = res2;
            }

          ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_QUERY);
        }

      ssh_ppp_protocol_option_skip(pkt);
    }

  i = 0;
  while ((opt = ssh_ppp_protocol_option_output_iter(state, local, i)) != NULL)
    {
      /* An option which was ACK'd previously was not queried this time */
      config_status = ssh_ppp_config_option_get_status(opt);
      config_pref = ssh_ppp_config_preference_get(opt);

      /* If mandatory options are not queried with accepted parameters
         force a NAK reply */

      if (config_status != SSH_PPP_CONFIG_STATUS_QUERY
          && config_pref == SSH_PPP_CONFIG_PREF_MANDATORY)
        {
          res = SSH_LCP_NAK;
        }
      i++;
    }

  /* No reply warranted */
  if (iter == SSH_PPP_ERROR)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Configuration option list contained a corrupt option "
                 "field",local->iface->debug_name));
      return SSH_LCP_NONE;
    }

  return res;
}


/* Wrappers for callback functions */

void
ssh_ppp_protocol_default_input_config(SshPppState gdata, SshPppProtocol tdata)
{
  /* No, the below is not a typo. Contrary to the majority of cases,
     the magic number value option requested by a peer is
     the magic number it wishes to send, not the one it
     wishes to receive */

  tdata->magic_output = 0;

  if (tdata->iface != NULL
      && tdata->iface->default_input_config_cb != NULL_FNPTR)
    {
      tdata->iface->default_input_config_cb(gdata,tdata->ctx);
    }
}

void
ssh_ppp_protocol_default_output_config(SshPppState gdata, SshPppProtocol tdata)
{
  tdata->magic_input = 0;

  if (tdata->iface != NULL
      && tdata->iface->default_output_config_cb != NULL_FNPTR)
    {
      tdata->iface->default_output_config_cb(gdata,tdata->ctx);
    }
}

void
ssh_ppp_protocol_set_output_mru(SshPppProtocol tdata, unsigned long val)
{
  SshPppMuxProtocol mux = ssh_ppp_thread_get_mux(tdata->ppp_thread);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("%s: setting output packet buffer size to %ld bytes",
             tdata->iface->debug_name, val));

  /* The magic "+16" is used to allow for prepending of the PPP headers,
     note ssh_ppp_protocol_get_output_buf(). */

  ssh_ppp_flush_set_output_mru(mux,val+16);
}

unsigned long
ssh_ppp_protocol_get_output_mru(SshPppProtocol tdata)
{
  SshPppMuxProtocol mux = ssh_ppp_thread_get_mux(tdata->ppp_thread);

  SSH_ASSERT(tdata != NULL);

  return ssh_ppp_flush_get_output_mru(mux) - 16;
}

unsigned long
ssh_ppp_protocol_get_input_mru(SshPppProtocol tdata)
{
  SshPppMuxProtocol mux = ssh_ppp_thread_get_mux(tdata->ppp_thread);

  SSH_ASSERT(tdata != NULL);

  return ssh_ppp_flush_get_input_mru(mux);
}

void
ssh_ppp_protocol_apply_input_config(SshPppState gdata, SshPppProtocol tdata)
{
  if (tdata->iface != NULL
      && tdata->iface->apply_input_config_cb != NULL_FNPTR)
    {
      tdata->iface->apply_input_config_cb(gdata,tdata->ctx);
    }
}

void
ssh_ppp_protocol_apply_output_config(SshPppState gdata, SshPppProtocol tdata)
{
  if (tdata->iface != NULL
      && tdata->iface->apply_output_config_cb != NULL_FNPTR)
    {
      tdata->iface->apply_output_config_cb(gdata,tdata->ctx);
    }
}

/* Instantiate a protocol machine */

void
ssh_ppp_protocol_destroy(SshPppProtocol rec)
{
  SshPppTimer timer;
  SshPppMuxProtocolStruct* mux;

  SSH_DEBUG(SSH_D_MY,("destroying protocol instance %p",rec));

  ssh_fsm_kill_thread(ssh_ppp_thread_get_thread(rec->ppp_thread));

  mux = ssh_ppp_thread_get_mux(rec->ppp_thread);
  timer = ssh_ppp_thread_get_timer(rec->ppp_thread);

  ssh_ppp_timer_destroy(timer);
  ssh_ppp_flush_del_protocol(mux);

  if (rec->iface->destructor_cb != NULL_FNPTR)
    rec->iface->destructor_cb(rec->ctx);

  ssh_ppp_thread_destroy(rec->ppp_thread);

  ssh_free(rec);
}

SshPppEvents
ssh_ppp_protocol_get_eventq(SshPppProtocol rec)
{
  SshPppEvents evs;

  evs = ssh_ppp_thread_get_events(rec->ppp_thread);
  return evs;
}

SshPppProtocol
ssh_ppp_protocol_create(SshPppState gdata,
                        SshPppEvents eventq,
                        SshPppFlush io_mux,
                        void* ctx,
                        SshPppProtocolInterface iface)
{
  SshPppProtocol local;
  SshFSMThread thread;
  SshPppTimer timer;
  SshPppMuxProtocolStruct *mux;

  local = NULL;
  thread = NULL;
  mux = NULL;
  timer = NULL;

  SSH_DEBUG(SSH_D_MY,
            ("initializing protocol %s ctx %p cbs %p",
             iface->debug_name,ctx,iface));

  local = ssh_malloc(sizeof(*local));

  if (local == NULL)
    goto fail;

  thread = ssh_fsm_thread_create(gdata->fsm, ssh_lcp_initial,
                                 NULL_FNPTR, NULL_FNPTR, local);

  if (thread == NULL)
    goto fail;

  local->protocol_status = SSH_PPP_LCP_INITIAL;

  local->counter_current = 0;
  local->counter_max = 0;

  /* Note the deviation from the recommended RFC1661 Max-Failure default.
     This is because we count both NAK's and REJ's and not only NAK's.
  */

  ssh_ppp_protocol_counter_nak_init(local);

  ssh_ppp_identifier_init(gdata,&local->identifier_input);
  ssh_ppp_identifier_init(gdata,&local->identifier_output);

  /* RFC 1661 6.4: Magic number is 0 untill succesfully negotiated */
  local->magic_input = 0;
  local->magic_output = 0;
  local->boot_delay_usecs = 0;

  local->option_config_invalid = FALSE;

  /* Set up scheduler */
  local->ppp_thread = ssh_ppp_thread_create(gdata,
                                            thread,
                                            eventq,
                                            iface->debug_name);

  if (local->ppp_thread == NULL)
    goto fail;

  /* Set up other asynch event sources */

  timer = ssh_ppp_timer_create(local->ppp_thread);

  if (timer == NULL)
    goto fail;

  mux = ssh_ppp_flush_add_protocol(io_mux,
                                   iface->pid,
                                   local->ppp_thread,
                                   1500,
                                   NULL_FNPTR);

  ssh_ppp_thread_attach_timer(local->ppp_thread, timer);
  ssh_ppp_thread_attach_mux(local->ppp_thread,mux);

  /* Instance stuff */
  local->iface = iface;
  local->ctx = ctx;

  /* Set up a simple initial buffer */
  ssh_ppp_protocol_set_output_mru(local,1500);

  return local;

 fail:

  if (thread != NULL)
    ssh_fsm_kill_thread(thread);

  if (local != NULL)
    {
      if (local->ppp_thread != NULL)
        ssh_ppp_thread_destroy(local->ppp_thread);

      ssh_free(local);
    }

  return NULL;
}

void
ssh_ppp_protocol_boot(SshPppState gdata, SshPppProtocol tdata)
{
  ssh_ppp_thread_boot(tdata->ppp_thread);
}


/*
  A simple "validate packet" function. Use this to test
  the sanity of the actual byte level "opaque" representation before
  using any other functions to play with it.

  This function MUST NOT call any other ssh_ppp_lcp_*() functions,
  as it may be used in SSH_ASSERT() statements in them.
*/

SshIterationStatus
ssh_ppp_protocol_frame_isvalid(SshPppPktBuffer pkt)
{
  SshUInt16 len;
  unsigned long contentlen;

 /* Check that header is present in packet */

  contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  if (contentlen == 0)
    {
      return SSH_PPP_EMPTY;
    }

  if (contentlen < 5 || ((!ssh_ppp_hldc_ispfc(pkt)) && contentlen < 6))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Frame not sufficiently large to contain LCP header"));
      return SSH_PPP_ERROR;
    }

  /* Check that packet length is correct in the header */

  len = ssh_ppp_protocol_frame_get_len(pkt);

  /* Note that the HDLC/PPP  protocol identifier field is not
     counted within the length field */

  if (len > (contentlen-2))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("LCP header contains invalid length (%d vs actual %ld)",
                 (int) len,contentlen-2));
      return SSH_PPP_ERROR;
    }

  return SSH_PPP_OK;
}

/* Build a frame */

void
ssh_ppp_protocol_frame(SshPppPktBuffer pkt,
                       SshUInt8 type,
                       SshUInt8 id)
{
  unsigned long len;

  /* PPP LCP Header */

  len = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  ssh_ppp_pkt_buffer_prepend_uint16(pkt, (SshUInt16)(len + 4));
  ssh_ppp_pkt_buffer_prepend_uint8(pkt,id);
  ssh_ppp_pkt_buffer_prepend_uint8(pkt,type);
}


/*
  ssh_ppp_lcp_frame_strip_pad() "removes" data present
  in the HDLC frame but after the amount of data given
  in the LCP "Length" field. As per RFC1661 Section 5.
*/

void
ssh_ppp_protocol_frame_strip_pad(SshPppPktBuffer pkt)
{
  SshUInt16 len;

  len = ssh_ppp_protocol_frame_get_len(pkt);

  /* Remember to keep the Protocol field in the packet */

  len++;
  if (!ssh_ppp_hldc_ispfc(pkt))
    {
      len++;
    }

  ssh_ppp_pkt_buffer_truncate_abs(pkt,len);
}

/* Return fields from the LCP header */

SshUInt8
ssh_ppp_protocol_frame_get_code(SshPppPktBuffer pkt)
{
  SshUInt8 code;
  unsigned long offset;

  offset = (ssh_ppp_hldc_ispfc(pkt) ? 1 : 2);
  code = ssh_ppp_pkt_buffer_get_uint8(pkt,offset);

  return code;
}

SshUInt8
ssh_ppp_protocol_frame_get_id(SshPppPktBuffer pkt)
{
  SshUInt8 id;
  unsigned long offset;

  offset = (ssh_ppp_hldc_ispfc(pkt) ? 2: 3);
  id = ssh_ppp_pkt_buffer_get_uint8(pkt,offset);

  return id;
}

SshUInt16
ssh_ppp_protocol_frame_get_len(SshPppPktBuffer pkt)
{
  SshUInt16 len;
  unsigned long offset;

  offset = (ssh_ppp_hldc_ispfc(pkt) ? 3 : 4);

  len = ssh_ppp_pkt_buffer_get_uint16(pkt,offset);
  return len;
}

void
ssh_ppp_protocol_skip_hldc(SshPppPktBuffer pkt)
{
  unsigned long offset;

  /* If PFC has been used, the protocol value could be
     only one byte. Use the "HDLC" padding to detect
     if this is the case, and ignore any PFC values */

  offset = (ssh_ppp_hldc_ispfc(pkt) ? 1 : 2);

  ssh_ppp_pkt_buffer_skip(pkt,offset);
}

void
ssh_ppp_protocol_skip_hdr(SshPppPktBuffer pkt)
{
  ssh_ppp_protocol_skip_hldc(pkt);
  ssh_ppp_pkt_buffer_skip(pkt,4);
}

/* Return option fields */

SshIterationStatus
ssh_ppp_protocol_option_isvalid(SshPppPktBuffer pkt)
{
  unsigned long contentlen;
  SshUInt8 len;

  contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  if (contentlen == 0)
    {
      return SSH_PPP_EMPTY;
    }

  if (contentlen < 2)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Packet too small to contain LCP Configure option header"));
      return SSH_PPP_ERROR;
    }

  len = ssh_ppp_pkt_buffer_get_uint8(pkt,1);

  if (len > contentlen)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("LCP option length (%d) exceeds rest of frame (%ld)",
                 (int) len,contentlen));
      return SSH_PPP_ERROR;
  }

  if (len < 2)
    {
      SSH_DEBUG(SSH_D_NETGARB,("LCP option length (%d) < 2",len));
      return SSH_PPP_ERROR;
    }

  return SSH_PPP_OK;
}

static SshIterationStatus
ssh_ppp_protocol_option_set_isvalid(SshPppProtocol local, SshPppPktBuffer pkt)
{
  SshPppPktBufferStruct buf;
  SshIterationStatus iter;

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      ssh_ppp_protocol_option_skip(pkt);
    }

  if (iter == SSH_PPP_ERROR)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("protocol %s: option set is invalid",
                 local->iface->debug_name));
      return SSH_PPP_ERROR;
    }

  return SSH_PPP_OK;
}

SshUInt8
ssh_ppp_protocol_option_get_type(SshPppPktBuffer pkt)
{
  SshUInt8 type = ssh_ppp_pkt_buffer_get_uint8(pkt,0);

  return type;
}

SshUInt8
ssh_ppp_protocol_option_get_length(SshPppPktBuffer pkt)
{
  SshUInt8 len = ssh_ppp_pkt_buffer_get_uint8(pkt,1);
  return len;
}

void
ssh_ppp_protocol_option_skip(SshPppPktBuffer pkt)
{
  unsigned long len;

  SSH_ASSERT(ssh_ppp_protocol_option_isvalid(pkt) != SSH_PPP_ERROR);

  len = ssh_ppp_protocol_option_get_length(pkt);

  ssh_ppp_pkt_buffer_skip(pkt,len);
}


/*
   Config logic:

   0. Upon reception of a config request, reset
      all config variables to their defaults.

   1. If all options and values are acceptable.
      Reply with a config ACK.

   2. If all options are acceptable, but some values are not
      acceptable. Reply with a config NAK.

   3. If an option is not recognized or an option which is
      recognized, but only has one legal value (boolean option),
      Reply with a config reject.

   For each config variable a sane logic which converges
   to a configure-ack reply using (hopefully "a lot") less than 10
   configure request messages must exist RFC 1661 4.6).
*/

/* Build a configure request and send it */

void
ssh_ppp_protocol_output_configure_req(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  unsigned long len;
  unsigned long i;
  SshPppConfigOption opt;
  SshPppConfigPreference pref;
  SshPppConfigStatus status;
  SshPppConfigValueStatus val_status;
  SshUInt8 id;

  /* Reset all variables to defaults.
     Send a connection request */

  ssh_ppp_protocol_reset_own_options(state,local);
  ssh_ppp_protocol_default_input_config(state,local);

  if (local->option_config_invalid == TRUE)
    {
      SSH_DEBUG(SSH_D_MIDOK,("option configuration invalid. aborting send"));
      return;
    }

  pkt = ssh_ppp_protocol_get_output_buf(state, local);

  len = 0;
  i = 0;

  while ((opt = ssh_ppp_protocol_option_input_iter(state,local,i)) != NULL)
    {
      pref = ssh_ppp_config_preference_get(opt);
      status = ssh_ppp_config_option_get_status(opt);
      val_status = ssh_ppp_config_option_get_value_status(opt);

      SSH_ASSERT(status == SSH_PPP_CONFIG_STATUS_UNINIT
                 || status == SSH_PPP_CONFIG_STATUS_REJECTED
                 || status == SSH_PPP_CONFIG_STATUS_NAK);

      if ((pref == SSH_PPP_CONFIG_PREF_MANDATORY
           || pref == SSH_PPP_CONFIG_PREF_PREFER)
          && status == SSH_PPP_CONFIG_STATUS_UNINIT
          && val_status == SSH_PPP_CONFIG_VAL_SET) {

        len += ssh_ppp_config_option_marshal(opt,pkt);
        ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_QUERY);

      }
      i++;
    }

  SSH_ASSERT(len == pkt->nbytes);

  id = ssh_ppp_identifier_get(&local->identifier_output,
                              SSH_LCP_CONFIGURE_REQUEST);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending config request id = %d",
                          local->iface->debug_name,id));

   ssh_ppp_protocol_frame(pkt, SSH_LCP_CONFIGURE_REQUEST, id);
   ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_configure_ack(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  SshUInt8 type,length;
  SshPppConfigOption opt;
  SshIterationStatus iter;
  unsigned long len;
  SshUInt8 id;

  if (local->option_config_invalid == TRUE)
    {
      SSH_DEBUG(SSH_D_MIDOK,("option configuration invalid. aborting send"));
      return;
    }

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);
  id = ssh_ppp_protocol_frame_get_id(input);

  ssh_ppp_protocol_skip_hdr(input);

  len = 0;

  while ((iter = ssh_ppp_protocol_option_isvalid(input)) == SSH_PPP_OK)
    {
      /* Grab relevant fields from packet */
      type = ssh_ppp_protocol_option_get_type(input);
      length = ssh_ppp_protocol_option_get_length(input);
      opt = ssh_ppp_protocol_option_output_get(state,local,type);

      SSH_ASSERT(opt != NULL);

      ssh_ppp_config_option_unmarshal(opt,input);
      ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_ACK);

      /* Copy field from original packet to keep representation intact */
      ssh_ppp_pkt_buffer_copy(pkt,input,len,0,length);
      len += length;
      ssh_ppp_protocol_option_skip(input);
    }
  SSH_ASSERT(iter != SSH_PPP_ERROR);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending config ack id = %d",
                          local->iface->debug_name,id));

  ssh_ppp_protocol_frame(pkt, SSH_LCP_CONFIGURE_ACK,id);

  ssh_ppp_protocol_flushpkt(state,local);

  /* Force configuration into effect */
  ssh_ppp_protocol_default_output_config(state,local);
  ssh_ppp_protocol_apply_output_config(state,local);
}

void
ssh_ppp_protocol_output_configure_nak(SshPppState state,
                                      SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  SshUInt8 id,type,length;
  SshPppConfigResponse res,res2;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;
  SshPppConfigPreference config_pref;
  unsigned long len;
  SshIterationStatus iter;
  int i;

  if (local->option_config_invalid == TRUE)
    {
      SSH_DEBUG(SSH_D_MIDOK,("option configuration invalid. aborting send"));
      return;
    }

  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);
  id = ssh_ppp_protocol_frame_get_id(input);

  ssh_ppp_protocol_skip_hdr(input);

  res = ssh_ppp_protocol_input_options(state,local,input);

  SSH_ASSERT(res == SSH_LCP_REJ || res == SSH_LCP_NAK);

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  len = 0;

  while ((iter = ssh_ppp_protocol_option_isvalid(input)) == SSH_PPP_OK)
    {

      type = ssh_ppp_protocol_option_get_type(input);
      length = ssh_ppp_protocol_option_get_length(input);
      opt = ssh_ppp_protocol_option_output_get(state,local,type);

      SSH_ASSERT(length > 0);

      if (opt == NULL)
        {
          res2 = SSH_LCP_REJ;
        }
      else
        {
          res2 = ssh_ppp_protocol_option_isok(state,local,opt,input);
        }

      if (res == SSH_LCP_REJ)
        {
          if (res2 == SSH_LCP_REJ)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("%s: rejecting option %d",
                         local->iface->debug_name,type));

              ssh_ppp_pkt_buffer_copy(pkt,input,len,0,length);
              len += length;
              if (opt != NULL)
                {
                  ssh_ppp_config_option_set_status(opt,
                                             SSH_PPP_CONFIG_STATUS_REJECTED);
                }
            }
        }
      else
        {
          if (res2 == SSH_LCP_NAK) {
            SSH_DEBUG(SSH_D_MIDOK,
                      ("%s: negotiating against option %d",
                       local->iface->debug_name,type));

            /* Note that marshal_all must be called before any unmarshaling
               of the option, as due to the circular buffer nature,
               the result from ssh_ppp_config_option_isnakable()
               and hence ssh_ppp_protocol_option_isok() may
               be invalidated. */

            ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_NAK);
            len += ssh_ppp_config_option_marshal_all(opt,pkt);
          }
        }
      ssh_ppp_protocol_option_skip(input);
    }

  i = 0;
  if (res == SSH_LCP_NAK)
    {
      while ((opt=ssh_ppp_protocol_option_output_iter(state,local,i)) != NULL)
        {
          config_status = ssh_ppp_config_option_get_status(opt);
          config_pref = ssh_ppp_config_preference_get(opt);

          if (config_status != SSH_PPP_CONFIG_STATUS_QUERY
              && config_status != SSH_PPP_CONFIG_STATUS_NAK
              && config_pref == SSH_PPP_CONFIG_PREF_MANDATORY)
            {

              SSH_DEBUG(SSH_D_NETGARB,
                        ("%s: Peer did not query option %d which is required",
                         local->iface->debug_name, opt->impl->type));

              ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_NAK);
              len += ssh_ppp_config_option_marshal_all(opt,pkt);
            }
          i++;
        }
    }

  SSH_ASSERT(len > 0);
  SSH_ASSERT(iter != SSH_PPP_ERROR);

  if (res == SSH_LCP_NAK)
    {
      input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
      input = ssh_ppp_pkt_buffer_save(&buf,input);
      ssh_ppp_protocol_skip_hdr(input);
      ssh_ppp_protocol_update_nak_counters(state,local,input);
    }

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending config %s id = %d",
                          local->iface->debug_name,
                          (res == SSH_LCP_REJ?"reject":"nak"), id));

  ssh_ppp_protocol_frame(pkt,
                         (SshUInt8)(res == SSH_LCP_REJ ?
                                    SSH_LCP_CONFIGURE_REJECT :
                                    SSH_LCP_CONFIGURE_NAK),
                         id);

  ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_terminate_req(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_protocol_get_output_buf(state, local);

  id = ssh_ppp_identifier_get(&local->identifier_output,
                              SSH_LCP_TERMINATE_REQUEST);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending terminate req id = %d",
                          local->iface->debug_name, id));

  ssh_ppp_protocol_frame(pkt,
                         SSH_LCP_TERMINATE_REQUEST,
                         id);

  ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_terminate_ack(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  SshUInt8 id;

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);

  id = ssh_ppp_protocol_frame_get_id(input);

  ssh_ppp_protocol_skip_hdr(input);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending terminate ack id = %d",
                          local->iface->debug_name,id));

  ssh_ppp_protocol_frame(pkt,SSH_LCP_TERMINATE_ACK,id);
  ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_echo_reply(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  SshUInt8 id;

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);

  id = ssh_ppp_protocol_frame_get_id(input);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending echo reply id = %d",
                          local->iface->debug_name,id));

  ssh_ppp_protocol_skip_hdr(input);

  ssh_ppp_pkt_buffer_append_uint32(pkt,local->magic_output);

  ssh_ppp_protocol_frame(pkt,SSH_LCP_ECHO_REPLY,id);

  ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_code_reject(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  unsigned long output_len;
  SshUInt8 id;
  SshUInt8 *ptr;
  unsigned long len;

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);

  /* Skip Protocol field */

  ssh_ppp_pkt_buffer_skip(input,2);

  output_len = ssh_ppp_pkt_buffer_get_trailer(pkt) - 4;

  len = ssh_ppp_pkt_buffer_get_contentlen(input);

  if (len > output_len)
    {
      ssh_ppp_pkt_buffer_truncate_abs(input,output_len);
      len = ssh_ppp_pkt_buffer_get_contentlen(input);
    }

  ptr = ssh_ppp_pkt_buffer_get_ptr(input,0,len);

  ssh_ppp_pkt_buffer_append_buf(pkt, ptr, len);

  id = ssh_ppp_identifier_get(&local->identifier_protocol_reject,
                              SSH_LCP_CODE_REJECT);


  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending code reject id = %d",
                          local->iface->debug_name,id));

  ssh_ppp_protocol_frame(pkt, SSH_LCP_CODE_REJECT, id);

  /* Increase the output immediately after this to ensure
     that each code reject packet is transmitted with a different
     id. See RFC 1661 Section 5.6 */
  ssh_ppp_identifier_inc(&local->identifier_protocol_reject);

  ssh_ppp_protocol_flushpkt(state,local);
}

void
ssh_ppp_protocol_output_protocol_reject(SshPppState state,
                                        SshPppProtocol local)
{
  SshPppPktBuffer pkt, input;
  SshPppPktBufferStruct buf;
  SshUInt8 id;
  unsigned long output_len;
  SshUInt8 *ptr;
  unsigned long len;

  pkt = ssh_ppp_protocol_get_output_buf(state, local);
  input = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  input = ssh_ppp_pkt_buffer_save(&buf,input);

  /* RFC 1661 5.7: Shows 16 bits reserved for the Rejected Protocol,
     hence it is sent out uncompressed. */

  output_len = ssh_ppp_pkt_buffer_get_trailer(pkt) - 4;

  len = ssh_ppp_pkt_buffer_get_contentlen(input);

  if (len > output_len)
    {
      ssh_ppp_pkt_buffer_truncate_abs(input,output_len);
      len = ssh_ppp_pkt_buffer_get_contentlen(input);
    }

  ptr = ssh_ppp_pkt_buffer_get_ptr(input,0,len);

  ssh_ppp_pkt_buffer_append_buf(pkt, ptr, len);

  id = ssh_ppp_identifier_get(&local->identifier_protocol_reject,
                              SSH_LCP_PROTOCOL_REJECT);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: sending protocol reject id = %d",
                          local->iface->debug_name,id));


  ssh_ppp_protocol_frame(pkt, SSH_LCP_PROTOCOL_REJECT, id);

  /* Increase the output immediately after this to ensure
     that each code reject packet is transmitted with a different
     id. See RFC 1661 Section 5.6 */

  ssh_ppp_identifier_inc(&local->identifier_protocol_reject);

  ssh_ppp_protocol_flushpkt(state,local);
}


/*
   Handle a configure req request.

   If ALL fields are ok, then take the options into use (this is
   done via ssh_ppp_lcp_output_configure_ack()).
*/

SshPppEvent
ssh_ppp_protocol_input_configure_req(SshPppState state,
                                     SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct buf;
  SshPppConfigResponse res;
  SshUInt8 id;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received config req id = %d",
                          local->iface->debug_name,id));

  ssh_ppp_protocol_skip_hdr(pkt);

  ssh_ppp_protocol_reset_peer_options(state,local);
  res = ssh_ppp_protocol_input_options(state,local,pkt);

  switch (res)
    {
      /* A slight variation of theme from RFC1661. The Max-Failure counter
         has been split into several counters. The nak counter counts
         the amount of configure naks and configure rej's sent without
         sending a configure ack. If the limit is reached, it is assumed
         that a functioning configuration will not be negotiated and
         the link is terminated.

         Secondly a second counter is associated with each
         configuration option.  The counter records the amount of
         times the option has been nak'd without being ack'd, and
         after the specified limit is reached the option is always
         rejected.
      */

    case SSH_LCP_NAK:
    case SSH_LCP_REJ:
      ssh_ppp_identifier_mark(&local->identifier_input,
                              SSH_LCP_CONFIGURE_REQUEST,
                              id);

      if (ssh_ppp_protocol_counter_nak_isbad(local))
        {
          return SSH_PPP_EVENT_CLOSE;
        }
      ssh_ppp_protocol_counter_nak_inc(local);

      ssh_ppp_protocol_default_output_config(state,local);
      return SSH_PPP_EVENT_RCRMINUS;

    case SSH_LCP_ACK:
      ssh_ppp_identifier_mark(&local->identifier_input,
                              SSH_LCP_CONFIGURE_REQUEST,
                              id);

      ssh_ppp_protocol_counter_nak_init(local);
      ssh_ppp_protocol_default_output_config(state,local);
      return SSH_PPP_EVENT_RCRPLUS;

    case SSH_LCP_FATAL:
      return SSH_PPP_EVENT_CLOSE;

    case SSH_LCP_NONE:
      break;
    }

  /* If the message is bogus, do not reset configuration state */

  return SSH_PPP_EVENT_NONE;
}

/* Handle a configure ack request */

SshPppEvent
ssh_ppp_protocol_input_configure_ack(SshPppState state,
                                     SshPppProtocol local)
{
  SshPppPktBuffer pkt = NULL;
  SshPppPktBufferStruct buf;
  SshPppConfigOption opt;
  SshUInt8 type;
  SshUInt8 id;
  SshPppConfigStatus config_status;
  SshIterationStatus iter;
  SshPppEvent res;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received a config ack id = %d",
                          local->iface->debug_name,id));

  /* Check that identifier is valid */
  if (!ssh_ppp_identifier_ismatch(&local->identifier_output,
                                  SSH_LCP_CONFIGURE_REQUEST,
                                  id))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Identifier mismatch",local->iface->debug_name));
      return SSH_PPP_EVENT_NONE;
    }

  ssh_ppp_protocol_skip_hdr(pkt);

  if (ssh_ppp_protocol_option_set_isvalid(local,pkt) == SSH_PPP_ERROR)
    {
      return SSH_PPP_EVENT_NONE;
    }

  /* Check that configure ack message syntax is ok */

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      if (opt == NULL)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("%s: Peer ack'd unrecognized option %d",
                     local->iface->debug_name,type));
          return SSH_PPP_EVENT_NONE;
        }

      if (ssh_ppp_protocol_option_isok(state,local,opt,pkt) != SSH_LCP_ACK)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("%s: Peer ack'd option %d with unsupported value",
                     local->iface->debug_name,type));
          return SSH_PPP_EVENT_RXJMINUS;
        }

      /* Note that we do not here detect messages which feature
         the same value ACK'd twice with a legitimate value! */

      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status != SSH_PPP_CONFIG_STATUS_QUERY)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("%s: Peer ack'd option %d which was not queried "
                     "(option status %d)",
                     local->iface->debug_name,type,config_status));
          return SSH_PPP_EVENT_NONE;
        }

      /* Option seems to be SSH_PPP_OK */
      ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_ACK);
      ssh_ppp_protocol_option_skip(pkt);
    }

  /* Did the reply contain all proposed options from the request ? */
  if (ssh_ppp_protocol_input_isquery(state,local))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Config Ack did not contain all queried options",
                 local->iface->debug_name));
      return SSH_PPP_EVENT_NONE;
    }

  /* Message syntax is ok, now check if option semantics are ok */

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  ssh_ppp_protocol_skip_hdr(pkt);
  res = SSH_PPP_EVENT_RCA;

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      if (opt == NULL)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Failed to parse options."));
          res = SSH_PPP_EVENT_RCN;
          break;
        }

      /* RFC1661 5.2: "The acknowledged Configuration Options
         MUST NOT be reordered or modified in any way."

         If the option value is not acceptable with relation to the value
         we proposed we consider this option as rejected and handle message
         as a configure reject containing this option, as obviously
         the handshaking of the option in question is not possible.

         Note the unmarshal if the option is accepted, this is incase
         some other negotiation protocol breaks the spec, then *option_cmp()
         may be abused for some added functionality... ;-)
      */

      if (!ssh_ppp_config_option_cmp(opt, pkt))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("%s: Peer ack'd option %d value mismatches with query",
                     local->iface->debug_name, opt->impl->type));
          ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_REJECTED);
          res = SSH_PPP_EVENT_RCN;
        }
      else
        {
          ssh_ppp_config_option_unmarshal(opt,pkt);
        }

      ssh_ppp_protocol_option_skip(pkt);
    }

  ssh_ppp_identifier_inc(&local->identifier_output);
  return res;
}

/* Handle a configure nak request */

SshPppEvent
ssh_ppp_protocol_input_configure_nak(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct buf;
  SshPppConfigOption opt;
  SshPppConfigOption opt_nak;
  SshUInt8 type;
  SshUInt8 id;
  SshIterationStatus iter;
  SshPppConfigStatus config_status;
  SshPppConfigValueStatus config_value_status;
  SshPppConfigResponse res;
  SshPppConfigPreference pref;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  id = ssh_ppp_protocol_frame_get_id(pkt);
  ssh_ppp_protocol_skip_hdr(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received a config nak id = %d",
                          local->iface->debug_name,id));

  /* Check that identifier is valid */
  if (!ssh_ppp_identifier_ismatch(&local->identifier_output,
                                  SSH_LCP_CONFIGURE_REQUEST,
                                  id))
    {

      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Identifier mismatch",local->iface->debug_name));
      return SSH_PPP_EVENT_NONE;
    }

  if (ssh_ppp_protocol_option_set_isvalid(local,pkt) == SSH_PPP_ERROR)
    {
      return SSH_PPP_EVENT_NONE;
    }

  /* The handling of configure NAK's is divided into three stages.

     The initial pass handles preferences (as allowed by the configuration),
     and maps out the options which need handling.

     The second pass reads in the acceptable option values from the packet.

     The final pass triggers the negotiation of options which were nak'd
     but did not provide an acceptable value in the packet, but are configured
     with a default value.
  */

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      /* If peer nak's an option it has previously rejected,
         or NAK's an option we do not recognize, then we ignore
         the option. */

      if (opt != NULL)
        {
          config_status = ssh_ppp_config_option_get_status(opt);

          if (config_status != SSH_PPP_CONFIG_STATUS_REJECTED)
            {
              if (config_status == SSH_PPP_CONFIG_STATUS_QUERY)
                {
                  ssh_ppp_config_option_set_status(opt,
                                                   SSH_PPP_CONFIG_STATUS_NAK);
                }
              else
                {
                  ssh_ppp_config_option_set_status(opt,
                                           SSH_PPP_CONFIG_STATUS_NAK_PROMPT);
                }
            }

          /* Make sure we attempt to configure this the next session,
             if possible. Note that in the case that an option was
             not queried and the NAK did not provide an acceptable response,
             the next configure request will attempt to negotiate that
             initialized configured value (the final pass)

             Note that this in accordance with RFC1661, and it basically
             allows one attempt to override the optionvalue proposed
             by a peer by a pre-configured one, in case the one
             provided by the peer is unacceptable.
          */

          pref = ssh_ppp_config_preference_get(opt);

          if (pref != SSH_PPP_CONFIG_PREF_MANDATORY &&
              pref != SSH_PPP_CONFIG_PREF_REJECT)
            {
              ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
            }
        }

      ssh_ppp_protocol_option_skip(pkt);
    }

  /* Second pass */

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  ssh_ppp_protocol_skip_hdr(pkt);

  opt_nak = NULL;

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      if (opt != NULL)
        {

          config_status = ssh_ppp_config_option_get_status(opt);

          /*  First extract the first candidate of the set of options provided
              which is acceptable. Then cache this option in "opt_nak" and
              after this see if any following options of the same type
              are preferable using ssh_ppp_config_option_ispref()
              and if so, then choose that value instead. */

          res = ssh_ppp_protocol_option_isok(state,local,opt,pkt);

          if (res == SSH_LCP_ACK)
            {

              if (opt_nak == opt)
                {

                  if (ssh_ppp_config_option_ispref(opt, pkt) == TRUE)
                    {
                      ssh_ppp_config_option_unmarshal(opt,pkt);
                    }
                }
              else if (config_status == SSH_PPP_CONFIG_STATUS_NAK
                       || config_status == SSH_PPP_CONFIG_STATUS_NAK_PROMPT)
                {

                  /* Reset status of previous value, if it was NAK_PROMPT */
                  ssh_ppp_config_option_set_status(opt,
                                                   SSH_PPP_CONFIG_STATUS_NAK);

                  /* Note that the ssh_ppp_config_option_push() resets the
                     negotiation and value status for the "new item" which
                     is unmarshalled. */
                  ssh_ppp_config_option_push(opt);
                  ssh_ppp_config_option_unmarshal(opt,pkt);

                  opt_nak = opt;
                }
            }
        }
      ssh_ppp_protocol_option_skip(pkt);
    }

  /* Final pass */

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  ssh_ppp_protocol_skip_hdr(pkt);

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      if (opt != NULL)
        {
          config_status = ssh_ppp_config_option_get_status(opt);
          config_value_status = ssh_ppp_config_option_get_value_status(opt);

          if (config_status == SSH_PPP_CONFIG_STATUS_NAK_PROMPT)
            {
              if (config_value_status == SSH_PPP_CONFIG_VAL_SET)
                {
                  ssh_ppp_config_option_set_status(opt,
                                             SSH_PPP_CONFIG_STATUS_UNINIT);
                }
              else
                {
                  ssh_ppp_config_option_set_status(opt,
                                                   SSH_PPP_CONFIG_STATUS_NAK);
                }
            }
        }

      ssh_ppp_protocol_option_skip(pkt);
    }

  /* Houston, we have a problem! A parameter is marked as mandatory
     and we cannot agree on a value */

  if (ssh_ppp_protocol_input_isfail(state,local))
    {
      return SSH_PPP_EVENT_CLOSE;
    }

  ssh_ppp_identifier_inc(&local->identifier_output);
  return SSH_PPP_EVENT_RCN;
}

/* Handle a configure reject request */

SshPppEvent
ssh_ppp_protocol_input_configure_rej(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct buf;
  SshPppConfigOption opt;
  SshUInt8 type;
  SshUInt8 id;
  SshPppConfigStatus config_status;
  SshIterationStatus iter;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received a config reject id = %d",
                          local->iface->debug_name,id));

  /* Check that identifier is valid */
  if (!ssh_ppp_identifier_ismatch(&local->identifier_output,
                                  SSH_LCP_CONFIGURE_REQUEST,
                                  id))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Identifier mismatch",local->iface->debug_name));

      return SSH_PPP_EVENT_NONE;
    }

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);
  ssh_ppp_protocol_skip_hdr(pkt);

  if (ssh_ppp_protocol_option_set_isvalid(local,pkt) == SSH_PPP_ERROR)
    {
      return SSH_PPP_EVENT_NONE;
    }

  while ((iter = ssh_ppp_protocol_option_isvalid(pkt)) == SSH_PPP_OK)
    {
      type = ssh_ppp_protocol_option_get_type(pkt);
      opt = ssh_ppp_protocol_option_input_get(state,local,type);

      /* RFC 1661 5.4: "Additionally, the Configuration Options in a
         Configure-Reject MUST be a proper subset of those in the last
         transmitted Configure-Request.  Invalid packets are silently
         discarded."

         Hence if the option was not queried. We discard the packet.
      */

      if (opt == NULL)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("%s: Peer rejected unrecognized option %d",
                     local->iface->debug_name,type));
          return SSH_PPP_EVENT_NONE;
        }

      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status != SSH_PPP_CONFIG_STATUS_QUERY)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("%s: Peer rejected option %d which was not queried",
                     local->iface->debug_name,type));
          return SSH_PPP_EVENT_NONE;
        }

      SSH_DEBUG(SSH_D_MIDOK,
                ("%s: Peer rejected option %d",
                 local->iface->debug_name,type));

      ssh_ppp_config_option_set_status(opt,SSH_PPP_CONFIG_STATUS_REJECTED);
      ssh_ppp_protocol_option_skip(pkt);
    }

  if (iter == SSH_PPP_ERROR)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Config Reject contained a corrupt option field",
                 local->iface->debug_name));
      return SSH_PPP_EVENT_NONE;
    }

  if (ssh_ppp_protocol_input_isfail(state,local))
    {
      return SSH_PPP_EVENT_CLOSE;
    }

  ssh_ppp_identifier_inc(&local->identifier_output);

  return SSH_PPP_EVENT_RCN;
}

SshPppEvent
ssh_ppp_protocol_input_terminate_req(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received a terminate req id = %d",
                          local->iface->debug_name,
                          ssh_ppp_protocol_frame_get_id(pkt)));

  return SSH_PPP_EVENT_RTR;
}

SshPppEvent
ssh_ppp_protocol_input_terminate_ack(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received a terminate ack id = %d",
                          local->iface->debug_name,id));

  if (!ssh_ppp_identifier_ismatch(&local->identifier_output,
                                  SSH_LCP_TERMINATE_REQUEST,
                                  id))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("%s: Identifier mismatch",local->iface->debug_name));
      return SSH_PPP_EVENT_NONE;
    }

  return SSH_PPP_EVENT_RTA;
}

SshPppEvent
ssh_ppp_protocol_input_code_reject(SshPppState state, SshPppProtocol local)
{
  SshUInt16 len;
  SshUInt8 code;
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  len = ssh_ppp_protocol_frame_get_len(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("protocol %s: received a code reject id = %d",
             local->iface->debug_name, ssh_ppp_protocol_frame_get_id(pkt)));

  if (len < 7)
    {
      return SSH_PPP_EVENT_NONE;
    }

  code = ssh_ppp_pkt_buffer_get_uint8(pkt,6);

  SSH_DEBUG(SSH_D_MIDOK,
            ("protocol %s: peer rejecting code 0x%02x",
             local->iface->debug_name,code));

  /* Peer does not understand the basic options we are using */

  if (code <= 11 && code >= 1)
    {
      return SSH_PPP_EVENT_RXJMINUS;
    }

  return SSH_PPP_EVENT_RXJPLUS;
}

SshPppEvent
ssh_ppp_protocol_input_echo_request(SshPppState state, SshPppProtocol local)

{
  SshUInt16 len;
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  len = ssh_ppp_protocol_frame_get_len(pkt);

  SSH_DEBUG(SSH_D_HIGHOK,("%s: received an echo request id = %d",
                          local->iface->debug_name,
                          ssh_ppp_protocol_frame_get_id(pkt)));

  if (len < 8)
    {
      return SSH_PPP_EVENT_NONE;
    }

  return SSH_PPP_EVENT_RXR;
}


SshPppEvent
ssh_ppp_protocol_input_protocol_reject(SshPppState state,
                                       SshPppProtocol local)
{
  SshUInt16 len;
  SshUInt16 pid;
  SshPppPktBuffer pkt;
  SshPppEventsOutput out;

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  len = ssh_ppp_protocol_frame_get_len(pkt);
  out = ssh_ppp_thread_get_outputq(local->ppp_thread);

  if (len < 6)
    {
      return SSH_PPP_EVENT_NONE;
    }

  pid = ssh_ppp_pkt_buffer_get_uint16(pkt,6);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: received protocol reject id = %d protocol = 0x%04x",
             local->iface->debug_name,
             ssh_ppp_protocol_frame_get_id(pkt),
             pid));

  if (local->iface != NULL
      && local->iface->protocol_reject_cb != NULL_FNPTR)
    {
      local->iface->protocol_reject_cb(state,local->ctx,pid);
    }

  ssh_ppp_events_signal(out, SSH_PPP_EVENT_PROTOCOL_REJECT);

  if (pid == SSH_PPP_PID_LCP)
    {
      return SSH_PPP_EVENT_RXJMINUS;
    }

  return SSH_PPP_EVENT_RXJPLUS;
}

/* Handle the LCP message in local->input_pkt */

SshPppEvent
ssh_ppp_protocol_input(SshPppState state, SshPppProtocol local)
{
  SshPppPktBuffer pkt;
  SshUInt8 code;
  SshUInt16 pid;

  /* Route a request to the appropriate handler */

  pkt = ssh_ppp_thread_get_input_pkt(local->ppp_thread);
  pid = ssh_ppp_hldc_get_protocol(pkt);

  if (pid != local->iface->pid)
    {
      return SSH_PPP_EVENT_BAD_PROTOCOL;
    }

  /* The event has been computed using this configuration */

  code = ssh_ppp_protocol_frame_get_code(pkt);

  switch (code)
    {
    case SSH_LCP_CONFIGURE_REQUEST:
      return ssh_ppp_protocol_input_configure_req(state,local);
    case SSH_LCP_CONFIGURE_ACK:
      return ssh_ppp_protocol_input_configure_ack(state,local);
    case SSH_LCP_CONFIGURE_NAK:
      return ssh_ppp_protocol_input_configure_nak(state,local);
    case SSH_LCP_CONFIGURE_REJECT:
      return ssh_ppp_protocol_input_configure_rej(state,local);
    case SSH_LCP_TERMINATE_REQUEST:
      return ssh_ppp_protocol_input_terminate_req(state,local);
    case SSH_LCP_TERMINATE_ACK:
      return ssh_ppp_protocol_input_terminate_ack(state,local);
    case SSH_LCP_CODE_REJECT:
      return ssh_ppp_protocol_input_code_reject(state,local);
    case SSH_LCP_PROTOCOL_REJECT:
      return ssh_ppp_protocol_input_protocol_reject(state,local);
    case SSH_LCP_ECHO_REQUEST:
      return ssh_ppp_protocol_input_echo_request(state,local);
    case SSH_LCP_ECHO_REPLY:
      return SSH_PPP_EVENT_NONE;
    case SSH_LCP_DISCARD_REQUEST:
      return SSH_PPP_EVENT_NONE;
    }

  /* Send code reject. Protocol version mismatch ?  */

  SSH_DEBUG(SSH_D_NETGARB,("%s: recived a frame with unknown code %d",
                           local->iface->debug_name,code));

  return SSH_PPP_EVENT_RUC;
}

/* Events emitted by the LCP machine */

void
ssh_ppp_protocol_tlhalt(SshPppState state,SshPppProtocol local)
{
  SshPppEventsOutput outq;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer halted",local->iface->debug_name));

  outq = ssh_ppp_thread_get_outputq(local->ppp_thread);

  local->protocol_status = SSH_PPP_LCP_HALT;

  ssh_ppp_identifier_inc(&local->identifier_output);
  ssh_ppp_identifier_inc(&local->identifier_protocol_reject);

  if (outq != NULL)
    {
      SSH_ASSERT(!ssh_ppp_events_isfull(outq));

      ssh_ppp_events_signal(outq,SSH_PPP_EVENT_ISHALT);
    }
}


void
ssh_ppp_protocol_tlf(SshPppState state,SshPppProtocol local)
{
  SshPppEventsOutput outq;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer failed",local->iface->debug_name));

  outq = ssh_ppp_thread_get_outputq(local->ppp_thread);

  local->protocol_status = SSH_PPP_LCP_FAILED;

  ssh_ppp_identifier_inc(&local->identifier_output);
  ssh_ppp_identifier_inc(&local->identifier_protocol_reject);

  if (local->iface != NULL
      && local->iface->this_layer_failed_cb != NULL_FNPTR)
    {
      local->iface->this_layer_failed_cb(state,local->ctx);
    }

  if (outq != NULL)
    {
      SSH_ASSERT(!ssh_ppp_events_isfull(outq));

      ssh_ppp_events_signal(outq,SSH_PPP_EVENT_CLOSE);
    }
}

void
ssh_ppp_protocol_tld(SshPppState state,SshPppProtocol local)
{
  SshPppEventsOutput outq;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer down",local->iface->debug_name));

  outq = ssh_ppp_thread_get_outputq(local->ppp_thread);

  local->protocol_status = SSH_PPP_LCP_DOWN;

  if (local->iface != NULL
      && local->iface->this_layer_down_cb != NULL_FNPTR)
    {
      local->iface->this_layer_down_cb(state,local->ctx);
    }

  if (outq != NULL)
    {
      SSH_ASSERT(!ssh_ppp_events_isfull(outq));

      ssh_ppp_events_signal(outq,SSH_PPP_EVENT_DOWN);
    }
}

void
ssh_ppp_protocol_delay(SshPppState state, SshPppProtocol local)
{

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer up delay",local->iface->debug_name));

  if (local->iface != NULL
      && local->iface->this_layer_delay_cb != NULL_FNPTR)
    {
      local->iface->this_layer_delay_cb(state,local->ctx);
    }
}


void
ssh_ppp_protocol_tlu(SshPppState state, SshPppProtocol local)
{
  SshPppEventsOutput outq;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer up",local->iface->debug_name));

  outq = ssh_ppp_thread_get_outputq(local->ppp_thread);

  local->protocol_status = SSH_PPP_LCP_UP;

  if (local->iface != NULL
      && local->iface->this_layer_up_cb != NULL_FNPTR)
    {
      local->iface->this_layer_up_cb(state,local->ctx);
    }

  if (outq != NULL)
    {
      SSH_ASSERT(!ssh_ppp_events_isfull(outq));

      ssh_ppp_events_signal(outq,SSH_PPP_EVENT_UP);
    }
}

void
ssh_ppp_protocol_tls(SshPppState state, SshPppProtocol local)
{
  SshPppEventsOutput outq;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("%s: this layer started",local->iface->debug_name));

  outq = ssh_ppp_thread_get_outputq(local->ppp_thread);

  local->protocol_status = SSH_PPP_LCP_STARTED;

  ssh_ppp_identifier_inc(&local->identifier_output);
  ssh_ppp_identifier_inc(&local->identifier_protocol_reject);

  if (local->iface != NULL
      && local->iface->this_layer_started_cb != NULL_FNPTR)
    {
      local->iface->this_layer_started_cb(state,local->ctx);
    }

  if (outq != NULL)
    {
      SSH_ASSERT(!ssh_ppp_events_isfull(outq));

      ssh_ppp_events_signal(outq,SSH_PPP_EVENT_OPEN);
    }
}

SshPppProtocolStatus
ssh_ppp_protocol_get_status(SshPppProtocol protocol)
{
  return protocol->protocol_status;
}

void
ssh_ppp_protocol_set_bootdelay(SshPppProtocol local, unsigned long i)
{
  local->boot_delay_usecs = i;
}

SshPppThread
ssh_ppp_protocol_get_thread(SshPppProtocol local)
{
  return local->ppp_thread;
}

void
ssh_ppp_protocol_options_invalid_set(SshPppProtocol local, Boolean b)
{
  local->option_config_invalid = b;
}

void
ssh_ppp_protocol_options_reset(SshPppState gdata, SshPppProtocol local)
{
  unsigned long i;
  SshPppConfigOption opt;

  i = 0;

  while ((opt=ssh_ppp_protocol_option_output_iter(gdata,local,i)) != NULL)
    {
      ssh_ppp_config_option_reset(opt);
      i++;
    }

  i = 0;

  while ((opt=ssh_ppp_protocol_option_input_iter(gdata,local,i)) != NULL)
    {
      ssh_ppp_config_option_reset(opt);
      i++;
    }
}
