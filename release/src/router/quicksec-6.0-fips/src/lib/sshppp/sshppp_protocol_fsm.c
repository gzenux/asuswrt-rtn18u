/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppLcpFsm"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshtimeouts.h"
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

/* Misc. convenience functions for a sufficiently clean layout
   of the individual states */

static void
ssh_ppp_protocol_fsm_reset_timeout_resend(SshPppState gdata,
                                          SshPppProtocol tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
  ssh_ppp_timer_set_timeout(timer, 2, 0);
}

static void
ssh_ppp_protocol_fsm_cancel_timeout(SshPppState gdata, SshPppProtocol tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
}

/* Emulate the "zero resend counter" action in RFC 1661 */

static void
ssh_ppp_protocol_fsm_zero_resend_counter(SshPppState gdata,
                                         SshPppProtocol tdata)
{
  tdata->counter_current = 0;
  tdata->counter_max = 0;
}

static void
ssh_ppp_protocol_fsm_reset_timeout_bootdelay(SshPppState gdata,
                                             SshPppProtocol tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  if (tdata->boot_delay_usecs != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Protocol %s: Setting bootdelay of %ld us",
                 tdata->iface->debug_name,tdata->boot_delay_usecs));
      ssh_ppp_timer_cancel_timeout(timer);
      ssh_ppp_timer_set_timeout(timer, 0, tdata->boot_delay_usecs);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,("bootdelay not set"));
    }
}

static void
ssh_ppp_protocol_fsm_init_counter_config_req(SshPppState gdata,
                                             SshPppProtocol tdata)
{
  tdata->counter_current = 0;
  tdata->counter_max = ssh_ppp_protocol_get_counter_max(tdata,
                           SSH_PPP_COUNTER_CONFIGURE_REQ_RESEND);
}

static void
ssh_ppp_protocol_fsm_init_counter_terminate_req(SshPppState gdata,
                                                SshPppProtocol tdata)
{
  tdata->counter_current = 0;
  tdata->counter_max = ssh_ppp_protocol_get_counter_max(tdata,
                                        SSH_PPP_COUNTER_TERMINATE_REQ_RESEND);
}

static void
ssh_ppp_protocol_fsm_counter_inc(SshPppState gdata, SshPppProtocol tdata)
{
  tdata->counter_current++;
}

static void
ssh_ppp_protocol_fsm_handle_events(SshPppState gdata, SshPppProtocol tdata)
{
  SshPppPktBuffer pkt;
  SshPppEvent ev;

  /* Handle timeouts */

  ev = ssh_ppp_thread_get_event(gdata, tdata->ppp_thread);

  /* We can't cancel timeouts, because they used in
     terminate req -> terminate ack conversations
     and in other critical places.

     Configure Req packets instead cancel the send, in
     case a TIMEOUT event was under processing at the
     time the renegotiation was requested. This
     is not a problem, as timeout events
     do not tend to cause any positive (link up)
     style signals back to controlling thread.

     NOTE: THIS REQUIRES that if bootdelay is
     set, ALL signals to the user are sent
     already from the delay up function!
  */

  if (tdata->option_config_invalid == TRUE
      && (ev == SSH_PPP_EVENT_RCRPLUS
          || ev == SSH_PPP_EVENT_RCRMINUS
          || ev == SSH_PPP_EVENT_RCA
          || ev == SSH_PPP_EVENT_RCN))
    {
      ssh_ppp_thread_cancel_current_event(tdata->ppp_thread);
    }

  if (ev == SSH_PPP_EVENT_TIMEOUT)
    {
      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);

      ev = (tdata->counter_current > tdata->counter_max ?
            SSH_PPP_EVENT_TOMINUS : SSH_PPP_EVENT_TOPLUS);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
      return;
    }

  /* If an event has occurred or is cached do nothing */

  if (ev != SSH_PPP_EVENT_NONE)
    {
      return;
    }

  /* If we have input, parse it into an event */

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  if (pkt == NULL)
    {
      return;
    }

  if (ssh_ppp_protocol_frame_isvalid(pkt) == SSH_PPP_OK)
    {
      ssh_ppp_protocol_frame_strip_pad(pkt);
      ev = ssh_ppp_protocol_input(gdata,tdata);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
    }
  return;
}

SSH_FSM_STEP(ssh_lcp_initial)
{
  SSH_PPP_PROTOCOL_ENTRY();

  ssh_ppp_protocol_fsm_cancel_timeout(gdata,tdata);

  /* Iterate over events untill we get something we are
     interested in or a callback has been activated to
     wake us up. */

  if (tdata->protocol_status == SSH_PPP_LCP_DOWN ||
      tdata->protocol_status == SSH_PPP_LCP_FAILED)
    {
      ssh_ppp_protocol_tlhalt(gdata,tdata);
      SSH_PPP_THREAD_JUMP_STATE(gdata,tdata->ppp_thread, ssh_lcp_closed);
    }

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_UP:
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
      ssh_ppp_thread_set_next(tdata->ppp_thread,
                       ssh_lcp_closed);
      break;
    case SSH_PPP_EVENT_OPEN:
      ssh_ppp_thread_set_next(tdata->ppp_thread,
                              ssh_lcp_starting);
      ssh_ppp_protocol_tls(gdata,tdata);
      break;
    case SSH_PPP_EVENT_DOWN_UP:
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
      break;
    }
  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_starting)
{
  SSH_PPP_PROTOCOL_ENTRY();

  ssh_ppp_protocol_fsm_cancel_timeout(gdata,tdata);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_UP:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread,
                       ssh_lcp_req_sent);
      break;
    case SSH_PPP_EVENT_CLOSE:
      ssh_ppp_protocol_tlf(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread,
                       ssh_lcp_initial);
      break;
  case SSH_PPP_EVENT_OPEN:
    /* Goto state LCPStarting */
    break;
  case SSH_PPP_EVENT_DOWN_UP:
    ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
    break;
  default:
    ;
  }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_closed)
{
  SSH_PPP_PROTOCOL_ENTRY();

  ssh_ppp_protocol_fsm_cancel_timeout(gdata,tdata);

  if (tdata->protocol_status == SSH_PPP_LCP_DOWN ||
      tdata->protocol_status == SSH_PPP_LCP_FAILED)
    {
      ssh_ppp_protocol_tlhalt(gdata,tdata);
    }
  else
    {
      switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
        {
        case SSH_PPP_EVENT_DOWN:
          ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_lcp_initial);
          break;
        case SSH_PPP_EVENT_OPEN:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
          ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
          ssh_ppp_protocol_output_configure_req(gdata,tdata);


          ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_lcp_req_sent);
          break;
        case SSH_PPP_EVENT_CLOSE:
          /* Goto state LCPClosed */
          break;
        case SSH_PPP_EVENT_RXJMINUS:
          ssh_ppp_protocol_tlf(gdata,tdata);
          break;
        case SSH_PPP_EVENT_DOWN_UP:
          ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
          break;
        default:
          ;
        }
    }
  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_stopped)
{
  SSH_PPP_PROTOCOL_ENTRY();

  ssh_ppp_protocol_fsm_cancel_timeout(gdata,tdata);

  if (tdata->protocol_status == SSH_PPP_LCP_DOWN ||
      tdata->protocol_status == SSH_PPP_LCP_FAILED)
    {
      ssh_ppp_protocol_tlhalt(gdata,tdata);
    }
  else
    {
      switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
        {
        case SSH_PPP_EVENT_DOWN:
          ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
          ssh_ppp_protocol_tls(gdata,tdata);
          ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
          break;
        case SSH_PPP_EVENT_OPEN:
          /* Goto state LCPStopped */
          break;
        case SSH_PPP_EVENT_RCRPLUS:
        case SSH_PPP_EVENT_RCRNEUTRAL:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
          ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
          ssh_ppp_protocol_output_configure_req(gdata,tdata);

          ssh_ppp_thread_set_event(tdata->ppp_thread,SSH_PPP_EVENT_CUSTOM);
          /* fallthrough */

        case SSH_PPP_EVENT_CUSTOM:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_output_configure_ack(gdata,tdata);
          ssh_fsm_set_next(thread, ssh_lcp_ack_sent);
          break;

        case SSH_PPP_EVENT_RCRMINUS:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
          ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
          ssh_ppp_protocol_output_configure_req(gdata,tdata);

          ssh_ppp_thread_set_event(tdata->ppp_thread, SSH_PPP_EVENT_CUSTOM+1);
          /* fallthrough */

        case SSH_PPP_EVENT_CUSTOM+1:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_output_configure_nak(gdata,tdata);
          ssh_fsm_set_next(thread, ssh_lcp_req_sent);
          break;

        case SSH_PPP_EVENT_RCA:
        case SSH_PPP_EVENT_RCN:
        case SSH_PPP_EVENT_RTR:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_output_terminate_ack(gdata,tdata);
          break;
        case SSH_PPP_EVENT_RTA:
        case SSH_PPP_EVENT_RXJPLUS:
        case SSH_PPP_EVENT_RXR:
          /* Goto state LCPStopped */
          break;
        case SSH_PPP_EVENT_RUC:
          SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

          ssh_ppp_protocol_output_code_reject(gdata,tdata);
          break;
        case SSH_PPP_EVENT_RXJMINUS:
          ssh_ppp_protocol_tlf(gdata,tdata);
          break;
        case SSH_PPP_EVENT_DOWN_UP:
          ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
          break;
        }
    }
  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_closing)
{
  SSH_PPP_PROTOCOL_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_initial);
      break;
    case SSH_PPP_EVENT_OPEN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopping);
      break;
    case SSH_PPP_EVENT_CLOSE:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closed);
      break;
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);
      break;
    case SSH_PPP_EVENT_TOMINUS:
    case SSH_PPP_EVENT_RTA:
    case SSH_PPP_EVENT_RXJMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closed);
      break;
    case SSH_PPP_EVENT_RCRPLUS:
    case SSH_PPP_EVENT_RCRNEUTRAL:
    case SSH_PPP_EVENT_RCRMINUS:
    case SSH_PPP_EVENT_RCA:
    case SSH_PPP_EVENT_RCN:
    case SSH_PPP_EVENT_RXR:
    case SSH_PPP_EVENT_RXJPLUS:
      /* Goto state LCPClosing */
      break;
    case SSH_PPP_EVENT_RTR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RUC:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_code_reject(gdata,tdata);
      break;

    case SSH_PPP_EVENT_DOWN_UP:
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
      break;
    }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_stopping)
{
  SSH_PPP_PROTOCOL_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
      break;
    case SSH_PPP_EVENT_OPEN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopping);
      break;
    case SSH_PPP_EVENT_CLOSE:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closing);
      break;
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);
      break;
    case SSH_PPP_EVENT_TOMINUS:
    case SSH_PPP_EVENT_RTA:
    case SSH_PPP_EVENT_RXJMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;
    case SSH_PPP_EVENT_RCRPLUS:
    case SSH_PPP_EVENT_RCRNEUTRAL:
    case SSH_PPP_EVENT_RCRMINUS:
    case SSH_PPP_EVENT_RCA:
    case SSH_PPP_EVENT_RCN:
    case SSH_PPP_EVENT_RXJPLUS:
    case SSH_PPP_EVENT_RXR:
      /* Goto state LCPStopping */
      break;
    case SSH_PPP_EVENT_RTR:
      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);
      break;
    case SSH_PPP_EVENT_RUC:
      ssh_ppp_protocol_output_code_reject(gdata,tdata);
      break;
    case SSH_PPP_EVENT_DOWN_UP:
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);
      break;

    }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_req_sent)
{
  SSH_PPP_PROTOCOL_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
      break;
    case SSH_PPP_EVENT_OPEN:
    case SSH_PPP_EVENT_RTA:
    case SSH_PPP_EVENT_RXJPLUS:
    case SSH_PPP_EVENT_RXR:
      /* Go to state ReqSent */
      break;
    case SSH_PPP_EVENT_CLOSE:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_init_counter_terminate_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closing);
      break;
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);
      break;

    case SSH_PPP_EVENT_TOMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_RCRPLUS:
    case SSH_PPP_EVENT_RCRNEUTRAL:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_configure_ack(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_ack_sent);
      break;

    case SSH_PPP_EVENT_RCRMINUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_configure_nak(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RCA:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_default_input_config(gdata,tdata);
      ssh_ppp_protocol_apply_input_config(gdata,tdata);
      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_ack_rcvd);
      break;

    case SSH_PPP_EVENT_RCN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RTR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);

      break;
    case SSH_PPP_EVENT_RUC:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_code_reject(gdata,tdata);
      break;
    case SSH_PPP_EVENT_RXJMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_DOWN_UP:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_identifier_inc(&tdata->identifier_output);
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);

      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);


      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_ack_rcvd)
{
  SSH_PPP_PROTOCOL_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
    case SSH_PPP_EVENT_OPEN:
    case SSH_PPP_EVENT_RXR:
      /* Gotostate LCPAckRcvd */
      break;
    case SSH_PPP_EVENT_CLOSE:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_init_counter_terminate_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);

      ssh_ppp_identifier_inc(&tdata->identifier_output);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closing);
      break;

    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_TOMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_RCRPLUS:
    case SSH_PPP_EVENT_RCRNEUTRAL:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_configure_ack(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_bootdelay(gdata,tdata);
      ssh_ppp_protocol_delay(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_opening);
      break;

    case SSH_PPP_EVENT_RCRMINUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_configure_nak(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RCA:
    case SSH_PPP_EVENT_RCN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_RTR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_RTA:
    case SSH_PPP_EVENT_RXJPLUS:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_RUC:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_code_reject(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RXJMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_DOWN_UP:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_identifier_inc(&tdata->identifier_output);
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);

      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_ack_sent)
{
  SSH_PPP_PROTOCOL_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
    case SSH_PPP_EVENT_OPEN:
    case SSH_PPP_EVENT_RTA:
    case SSH_PPP_EVENT_RXJPLUS:
    case SSH_PPP_EVENT_RXR:
      /* Goto state LCPAckSent */
      break;
    case SSH_PPP_EVENT_CLOSE:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_init_counter_terminate_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closing);
      break;
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_counter_inc(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      break;
    case SSH_PPP_EVENT_TOMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_RCRPLUS:
    case SSH_PPP_EVENT_RCRNEUTRAL:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_configure_ack(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RCRMINUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_configure_nak(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_RCA:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_default_input_config(gdata,tdata);
      ssh_ppp_protocol_apply_input_config(gdata,tdata);
      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);

      ssh_ppp_protocol_fsm_reset_timeout_bootdelay(gdata,tdata);
      ssh_ppp_protocol_delay(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_opening);
      break;

    case SSH_PPP_EVENT_RCN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      break;
    case SSH_PPP_EVENT_RTR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;

    case SSH_PPP_EVENT_RUC:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_code_reject(gdata,tdata);
      break;
    case SSH_PPP_EVENT_RXJMINUS:
      ssh_ppp_protocol_tlf(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopped);
      break;

    case SSH_PPP_EVENT_DOWN_UP:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_identifier_inc(&tdata->identifier_output);
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);

      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    }

  SSH_PPP_PROTOCOL_EXIT();
}

SSH_FSM_STEP(ssh_lcp_opened)
{
  SSH_PPP_PROTOCOL_ENTRY();

  ssh_ppp_protocol_fsm_cancel_timeout(gdata,tdata);

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_DOWN:
      ssh_ppp_protocol_tld(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_starting);
      break;

    case SSH_PPP_EVENT_OPEN:
      break;

    case SSH_PPP_EVENT_CLOSE:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_tld(gdata,tdata);
      ssh_ppp_protocol_fsm_init_counter_terminate_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_closing);
      break;

    case SSH_PPP_EVENT_RCRNEUTRAL:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_configure_ack(gdata,tdata);
      break;

    case SSH_PPP_EVENT_RCRPLUS:
      /* Note that the Configure Req should be sent before the
         Configure Ack, especially in the Opened state */

      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_tld(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_event(tdata->ppp_thread,SSH_PPP_EVENT_CUSTOM);
      /* fallthrough */

    case SSH_PPP_EVENT_CUSTOM:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_configure_ack(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_ack_sent);
      break;
    case SSH_PPP_EVENT_RCRMINUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_tld(gdata,tdata);

      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_event(tdata->ppp_thread,SSH_PPP_EVENT_CUSTOM+1);
      /* fallthrough */
    case SSH_PPP_EVENT_CUSTOM+1:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_output_configure_nak(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    case SSH_PPP_EVENT_RCA:
    case SSH_PPP_EVENT_RCN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      ssh_ppp_protocol_tld(gdata,tdata);

      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    case SSH_PPP_EVENT_RTR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_tld(gdata,tdata);

      ssh_ppp_protocol_fsm_zero_resend_counter(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_terminate_ack(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopping);
      break;
    case SSH_PPP_EVENT_RTA:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_tld(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    case SSH_PPP_EVENT_RUC:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_code_reject(gdata,tdata);

      break;
    case SSH_PPP_EVENT_RXJPLUS:
      break;
    case SSH_PPP_EVENT_RXJMINUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_tld(gdata,tdata);

      ssh_ppp_protocol_fsm_init_counter_terminate_req(gdata,tdata);
      ssh_ppp_protocol_output_terminate_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_stopping);
      break;
    case SSH_PPP_EVENT_RXR:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_protocol_output_echo_reply(gdata,tdata);
      break;

      /* Do not send protocol rejects before the link is configured. */

    case SSH_PPP_EVENT_BAD_PROTOCOL:
      ssh_ppp_protocol_output_protocol_reject(gdata,tdata);
      break;

    case SSH_PPP_EVENT_DOWN_UP:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_identifier_inc(&tdata->identifier_output);
      ssh_ppp_protocol_options_invalid_set(tdata, FALSE);

      ssh_ppp_protocol_tld(gdata,tdata);
      ssh_ppp_protocol_fsm_init_counter_config_req(gdata,tdata);
      ssh_ppp_protocol_fsm_reset_timeout_resend(gdata,tdata);
      ssh_ppp_protocol_output_configure_req(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_req_sent);
      break;
    }

  SSH_PPP_PROTOCOL_EXIT();
}

/*
   Some PPP implementations keep the LCP protocol in userland
   and the HDLC multiplexing in kernel. This (combined with
   some other implementation details) tends to cause a delay
   before the HDLC configuration is set in the kernel after
   receiving a ConfigureAck.

   The purpose of the LCPOpening state is to wait a short
   delay to allow for this to happen before proceeding
   with other protocols.

   The state handles internal events like we already were in
   the LCPOpened state, but ignore I/O untill timeout has expired.
*/

SSH_FSM_STEP(ssh_lcp_opening)
{
  SSH_PPP_PROTOCOL_ENTRY();

  if (tdata->boot_delay_usecs == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,("bootdelay is disabled"));
      ssh_ppp_protocol_tlu(gdata,tdata);
      SSH_PPP_THREAD_JUMP_STATE(gdata,tdata->ppp_thread,ssh_lcp_opened);
    }

  switch (ssh_ppp_thread_get_event(gdata,tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_TOPLUS:
    case SSH_PPP_EVENT_TOMINUS:
      ssh_ppp_protocol_tlu(gdata,tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_lcp_opened);
      break;
    case SSH_PPP_EVENT_NONE:
      break;

    default:
      ssh_ppp_protocol_tlu(gdata,tdata);
      SSH_PPP_THREAD_JUMP_STATE(gdata,tdata->ppp_thread,ssh_lcp_opened);
      /* If some other event has happened, handle it in
         the true Opened state as we now assume that the
         boot delay is no longer necessary */
    }

  SSH_PPP_PROTOCOL_EXIT();
}
