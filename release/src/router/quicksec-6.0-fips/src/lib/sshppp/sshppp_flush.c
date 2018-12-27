/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppFlush"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"





#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_io_stream.h"

#include "sshppp_fcs.h"

/* Forward declarations of static functions */

static SshIterationStatus
ssh_ppp_flush_get_input(SshPppFlush rec);

static int
ssh_ppp_flush_hldc_destuff(SshPppFlush rec,SshPppPktBuffer pkt);

static SshIterationStatus
ssh_ppp_flush_find_l2tp_frame(SshPppFlush rec,
                              SshPppPktBuffer output);

static SshIterationStatus
ssh_ppp_flush_find_hldc_frame(SshPppFlush rec,
                              SshPppPktBuffer output);

static void
ssh_ppp_flush_hldc_deframe(SshPppFlush rec, SshPppPktBuffer pkt);

static SshIterationStatus
ssh_ppp_flush_get_new_frame(SshPppState gdata, SshPppFlush rec);

static SshIterationStatus
ssh_ppp_flush_get_frame(SshPppState gdata, SshPppFlush rec);

static void
ssh_ppp_flush_inputq_init(SshPppMuxInputBufferQueueStruct* q);

static void
ssh_ppp_flush_inputq_uninit(SshPppMuxInputBufferQueueStruct* q);

static void
ssh_ppp_flush_inputq_put(SshPppMuxInputBufferQueueStruct*q,
                         SshUInt8* buffer,
                         unsigned long offset,
                         unsigned long len);

static void
ssh_ppp_flush_inputq_get(SshPppMuxInputBufferQueueStruct*q,
                         SshPppPktBuffer pkt);

static void
ssh_ppp_flush_disable_output(SshPppFlush rec);

static void
ssh_ppp_flush_disable_input(SshPppFlush rec);

static SshPppMuxProtocol
ssh_ppp_flush_get_client(SshPppFlush rec, SshPppPktBuffer pkt);

static SshIterationStatus
ssh_ppp_flush_get_input(SshPppFlush rec);

static void
ssh_ppp_flush_free_pdu(SshPppFlush rec,
                       SshPppPktBuffer pkt);

static void
ssh_ppp_flush_wakeup_waits(SshPppFlush rec);

static unsigned long
ssh_ppp_flush_pad_mru(SshPppFlush rec, unsigned long mru);

static int
ssh_ppp_flush_output(SshPppState gdata, SshPppFlush rec);

/* HLDC framing and associated functions */

void
ssh_ppp_flush_hldc_stuff(SshPppFlush rec,
                         SshPppPktBuffer buf)
{
  unsigned long i;
  SshUInt8 c;

  for (i = 0; i < ssh_ppp_pkt_buffer_get_contentlen(buf); i++)
    {
      c = ssh_ppp_pkt_buffer_get_uint8(buf,i);

      if (ssh_ppp_flush_accm_isflag(&rec->output_opts,c))
        {
          ssh_ppp_pkt_buffer_insert_uint8(buf,i,SSH_PPP_HLDC_FLAG_STUFF);
          i++;
          c ^= 0x20;
          ssh_ppp_pkt_buffer_set_uint8(buf,i,c);
        }
    }
}

static int
ssh_ppp_flush_hldc_destuff(SshPppFlush rec,SshPppPktBuffer pkt)
{
  unsigned long i;
  int nstuffed;
  int isstuffed;
  SshUInt8 c;

  isstuffed = 0;
  nstuffed = 0;

  for (i = 0; i < ssh_ppp_pkt_buffer_get_contentlen(pkt); i++)
    {
      c = ssh_ppp_pkt_buffer_get_uint8(pkt,i);

      if (isstuffed)
        {
          ssh_ppp_pkt_buffer_set_uint8(pkt,i,(SshUInt8)(c^0x20));
          ssh_ppp_pkt_buffer_consume(pkt,i-1,1);
          i--;
          isstuffed = 0;
          nstuffed++;
        }
      else if (c == SSH_PPP_HLDC_FLAG_STUFF)
        {
          isstuffed = 1;
        }
    }

  return nstuffed;
}

static SshIterationStatus
ssh_ppp_flush_find_l2tp_frame(SshPppFlush rec,
                              SshPppPktBuffer output)
{
  SshPppPktBuffer input;
  SshUInt32 len;
  SshUInt8 buf[4];

  SSH_ASSERT(ssh_ppp_pkt_buffer_isempty(output));

  input = &rec->pkt;

  if (ssh_ppp_pkt_buffer_isempty(input))
    {
      (void) ssh_ppp_pkt_buffer_save(output,input);
      return SSH_PPP_EMPTY;
    }

  if (rec->input_mode == SSH_PPP_FLUSH_MODE_CB)
    {

      if (ssh_ppp_pkt_buffer_get_contentlen(input) < 3)
        {
          return SSH_PPP_ERROR;
        }

      (void) ssh_ppp_pkt_buffer_save(output,input);
      return SSH_PPP_OK;
    }

  if (ssh_ppp_pkt_buffer_get_contentlen(input) < 4)
    {
      return SSH_PPP_ERROR;
    }

  buf[0] = ssh_ppp_pkt_buffer_get_uint8(input,0);
  buf[1] = ssh_ppp_pkt_buffer_get_uint8(input,1);
  buf[2] = ssh_ppp_pkt_buffer_get_uint8(input,2);
  buf[3] = ssh_ppp_pkt_buffer_get_uint8(input,3);

  len = SSH_GET_32BIT(buf);
  ssh_ppp_pkt_buffer_skip(input,4);

  if (ssh_ppp_pkt_buffer_get_contentlen(input) < len)
    {
      ssh_ppp_pkt_buffer_consume_header(input);
      return SSH_PPP_EMPTY;
    }

  if (len < 1)
    { /* Empty frames are discarded */
      return SSH_PPP_ERROR;
    }

  (void) ssh_ppp_pkt_buffer_save(output,input);
  ssh_ppp_pkt_buffer_skip(input,len);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("L2TP frame received: length %ld: ",
                     (unsigned long) len),
                    ssh_ppp_pkt_buffer_get_ptr(output, 0, len), len);

  return SSH_PPP_OK;
}

static SshIterationStatus
ssh_ppp_flush_find_hldc_frame(SshPppFlush rec,
                              SshPppPktBuffer output)
{
  int i;
  unsigned long frame_end;
  unsigned long frame_length;
  SshUInt16 fcs;
  SshUInt8* frame;
  SshPppPktBufferStruct tmp;
  SshPppPktBuffer pkt, input;
  SshUInt8 c;

  /* Assert that any previously read packet has been
     duly handled and removed */

  SSH_ASSERT(ssh_ppp_pkt_buffer_isempty(output));

  input = &rec->pkt;

  SSH_ASSERT(input->nbytes + input->offset <= input->maxbytes);
  SSH_ASSERT(input->buffer != NULL);

  /* Consume all nonsense before a valid HLDC delimeter flag.
     Ignore frames of zero length. */

  do
    {
      frame_end = 0;

      while (ssh_ppp_pkt_buffer_get_contentlen(input) > 0)
        {
          c = ssh_ppp_pkt_buffer_get_uint8(input,0);
          if (c == SSH_PPP_HLDC_FLAG_DELIM)
            {
              break;
            }
          else
            {
              ssh_ppp_pkt_buffer_skip(input,1);
            }
        }

      /* Find the flag ending this frame */

      for (i = 1; i < ssh_ppp_pkt_buffer_get_contentlen(input); i++)
        {
          c = ssh_ppp_pkt_buffer_get_uint8(input,i);
          if (c == SSH_PPP_HLDC_FLAG_DELIM)
            {
              frame_end = i;
              break;
            }
        }

      /* If no frame was found, make room at the end of the buffer */
      if (frame_end == 0)
        {
          if (ssh_ppp_pkt_buffer_get_header(input) > 0)
            {
              SSH_DEBUG(SSH_D_MY,("adjusting buffer for additional input"));
              ssh_ppp_pkt_buffer_consume_header(input);
            }
          return SSH_PPP_EMPTY;
        }
      if (frame_end == 1)
        {
          ssh_ppp_pkt_buffer_skip(input,1);
        }
    }
  while (frame_end == 1);

  /* Get a temporary view of the buffer containing the
     potential frame. Save it to the output buffer
     only if it is correct. */
  pkt = ssh_ppp_pkt_buffer_save(&tmp,input);
  ssh_ppp_pkt_buffer_truncate_abs(pkt,frame_end);
  ssh_ppp_pkt_buffer_skip(pkt,1);

  /* Skip over the initial FLAG byte. If the FCS checks out
     then skip over the whole frame. We may be out of synch
     with the sender, and hence may be treating the "ending"
     flag byte as the "beginning" flag byte.  */

  ssh_ppp_pkt_buffer_skip(input,1);

  /* Get the destuffed contents of the HLDC frame */
  ssh_ppp_flush_hldc_destuff(rec, pkt);

  /* Check that frame large enough to contain address field,
     control field and FCS */
  frame_length = ssh_ppp_pkt_buffer_get_contentlen(pkt);
  frame = ssh_ppp_pkt_buffer_get_ptr(pkt,0,frame_length);

  /* Atleast 3 bytes must always be contained in a legitimate frame,
     even if pfc and acfc options are enabled. */

  if (frame_length < 3)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("HLDC: Frame size (%ld) too small",frame_length));
      return SSH_PPP_ERROR;
    }

  if (ssh_ppp_flush_get_acfc(&rec->input_opts) == FALSE)
    {
      /* Check HLDC address field and Control field if their "compression"
         is not enabled */
      if (ssh_ppp_pkt_buffer_get_uint8(pkt,0) != 0xFF)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("HLDC: Frame address not 0xff"));
          return SSH_PPP_ERROR;
        }

      if (ssh_ppp_pkt_buffer_get_uint8(pkt,1) != 0x03)
        {
          SSH_DEBUG(SSH_D_NETGARB,("HLDC: frame control field not 0x03"));
          return SSH_PPP_ERROR;
        }
    }

  /* Input FCS verification from RFC 1662 Appendix C */
  fcs = ssh_ppp_fcs_calculate_16bit_fcs(SSH_PPP_FCS_16BIT_INITIAL_FCS,
                                        frame, frame_length);

  if (fcs != SSH_PPP_FCS_16BIT_SSH_PPP_OK_FCS)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("HLDC: Frame FCS verification failed (0x%04x)",fcs));

      return SSH_PPP_ERROR;
    }

  /* Remove FCS from packet */
  ssh_ppp_pkt_buffer_truncate_rel(pkt,2);

  (void) ssh_ppp_pkt_buffer_save(output,pkt);

  /* Dump packet */
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("Valid HLDC frame received, length %ld", frame_length),
                    frame, frame_length);

  /* Frame checks out ok. Skip rest of input, but do
     NOT skip ending flag */
  ssh_ppp_pkt_buffer_skip(input,frame_end-1);

  return SSH_PPP_OK;
}

static void
ssh_ppp_flush_hldc_deframe(SshPppFlush rec, SshPppPktBuffer pkt)
{
  SSH_ASSERT(ssh_ppp_pkt_buffer_get_contentlen(pkt) >= 2);

  /* Do not skip the "Protocol identifier".
     We consider it to be part of BOTH the HLDC frame and PPP frame.
     This is the same convention as in RFC 1661 and RFC 1662 */

  if (ssh_ppp_flush_get_acfc(&rec->input_opts) == FALSE
      || (ssh_ppp_pkt_buffer_get_uint8(pkt,0) == 0xFF &&
          ssh_ppp_pkt_buffer_get_uint8(pkt,1) == 0x03))
    {
      ssh_ppp_pkt_buffer_skip(pkt,2);
    }
}

/* Return OK if a frame was found or EMPTY if no input
   was encountered */

static SshIterationStatus
ssh_ppp_flush_get_new_frame(SshPppState gdata, SshPppFlush rec)
{
  SshIterationStatus ok;
  SshIterationStatus io_iter;

  /* Try to parse out a new HLDC frame. ssh_ppp_flush_get_input()
     returns only SSH_PPP_OK or SSH_PPP_EMPTY. Errors are hidden
     and the input stream is silently closed upon input error. */

  do
    {
      if (rec->input_mode == SSH_PPP_FLUSH_MODE_STREAM)
        {

          if (ssh_ppp_pkt_buffer_set_size(&rec->pkt,
                                          rec->input_maxbufsize)
              == FALSE)
            {
              ssh_ppp_fatal(gdata);
              io_iter = SSH_PPP_ERROR;
              ok = SSH_PPP_EMPTY;
            }
          else
            {
              io_iter = ssh_ppp_flush_get_input(rec);

              if (rec->mode == SSH_PPP_MODE_HLDC)
                {
                  ok = ssh_ppp_flush_find_hldc_frame(rec,&rec->current_pkt);
                }
              else
                {
                  SSH_ASSERT(rec->mode == SSH_PPP_MODE_L2TP);
                  ok = ssh_ppp_flush_find_l2tp_frame(rec,&rec->current_pkt);
                }
            }
        }
      else
        {
          SSH_ASSERT ( rec->input_mode == SSH_PPP_FLUSH_MODE_CB);

          /* Assert that the buffer is unallocated */
          SSH_ASSERT(rec->pkt.buffer == NULL);

          /* Place buffer in rec->pkt for temporary processing */
          ssh_ppp_flush_inputq_get(&rec->input_q, &rec->pkt);

          if (!ssh_ppp_pkt_buffer_isempty(&rec->pkt))
            {

              io_iter = SSH_PPP_OK;

              if (rec->mode == SSH_PPP_MODE_HLDC)
                {
                  ok = ssh_ppp_flush_find_hldc_frame(rec,&rec->current_pkt);
                }
              else
                {
                  SSH_ASSERT(rec->mode == SSH_PPP_MODE_L2TP);
                  ok = ssh_ppp_flush_find_l2tp_frame(rec,&rec->current_pkt);
                }
            }
          else
            {
              io_iter = SSH_PPP_EMPTY;
              ok = SSH_PPP_EMPTY;
            }

          /* Remove the buffer from rec->pkt */
          ssh_ppp_pkt_buffer_uninit(&rec->pkt);
        }

      /* Loop untill input channel is empty or there is a legit frame
         to process */
    }
  while (io_iter == SSH_PPP_OK && ok != SSH_PPP_OK);

  return ok;
}

/*
  Return SSH_PPP_OK if a packet has been placed in current_pkt
  or SSH_PPP_EMPTY if not
*/

static SshIterationStatus
ssh_ppp_flush_get_frame(SshPppState gdata, SshPppFlush rec)
{
  SshUInt16 pid;

  SSH_ASSERT(rec != NULL);

  /* If a packet has not been handled and destroyed, return it */

  if (!ssh_ppp_pkt_buffer_isempty(&rec->current_pkt))
    return SSH_PPP_OK;

  while (ssh_ppp_flush_get_new_frame(gdata, rec) == SSH_PPP_OK)
    {
      ssh_ppp_flush_hldc_deframe(rec,&rec->current_pkt);

      /* RFC1661 states that protocol id MUST be odd */

      pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);

      if ((pid&1) == 1)
        {
          return SSH_PPP_OK;
        }
      else
        {
          /* Immediately discard the packet */

          SSH_DEBUG(SSH_D_NETGARB,
                    ("Discarding packet with even protocol id 0x%04x",
                     pid));

          ssh_ppp_flush_free_pdu(rec,&rec->current_pkt);
        }
    }

  return SSH_PPP_EMPTY;
}

/* Handle flags in SshPppMuxProtocolStruct and SshPppFlush */

static void
ssh_ppp_mux_set_flag(SshPppMuxProtocol mux,
                     int flag,
                     Boolean val)
{
  mux->flags &= ~(1<<flag);
  mux->flags |= (val==TRUE?1:0) << flag;
}

static Boolean
ssh_ppp_mux_get_flag(SshPppMuxProtocol mux, int flag)
{
  return (((mux->flags >> flag) & 1) ? TRUE : FALSE);
}

void
ssh_ppp_flush_set_flag(SshPppFlush fd,
                       int flag,
                       Boolean val)
{
  fd->flags &= ~(1<<flag);
  fd->flags |= (val==TRUE?1:0) << flag;
}

Boolean
ssh_ppp_flush_get_flag(SshPppFlush fd, int flag)
{
  return (((fd->flags >> flag) & 1) ? TRUE : FALSE);
}


/* Input queue handling */

static void
ssh_ppp_flush_inputq_init(SshPppMuxInputBufferQueueStruct *q)
{
  q->idx = 0;
  q->nbuf = 0;
}

static void
ssh_ppp_flush_inputq_uninit(SshPppMuxInputBufferQueueStruct *q)
{
  int i,idx;

  for (i = 0; i < q->nbuf; i++)
    {
      idx = (q->idx + i) % SSH_PPP_INPUT_QUEUE_SIZE;
      ssh_free(q->buffer[idx]);
    }

  q->idx = 0;
  q->nbuf = 0;
}

static void
ssh_ppp_flush_inputq_put(SshPppMuxInputBufferQueueStruct *q,
                         SshUInt8 *buffer,
                         unsigned long offset,
                         unsigned long len)
{
  int nidx;

  if (q->nbuf == SSH_PPP_INPUT_QUEUE_SIZE)
    {
      nidx = q->idx;
      ssh_free(q->buffer[nidx]); /* Free the previous buffer */
    }
  else
    {
      nidx = (q->idx + q->nbuf) % SSH_PPP_INPUT_QUEUE_SIZE;
    }

  q->buffer[nidx] = buffer;
  q->offset[nidx] = offset;
  q->length[nidx] = len;

  if (q->nbuf != SSH_PPP_INPUT_QUEUE_SIZE)
    {
      q->nbuf++;
    }
}

static void
ssh_ppp_flush_inputq_get(SshPppMuxInputBufferQueueStruct*q,
                         SshPppPktBuffer pkt)
{
  ssh_ppp_pkt_buffer_uninit(pkt);

  if (q->nbuf > 0)
    {
      pkt->buffer = q->buffer[q->idx];
      pkt->offset = q->offset[q->idx];
      pkt->nbytes = q->length[q->idx];
      pkt->maxbytes = pkt->offset + pkt->nbytes;

      q->idx = (q->idx + 1) % SSH_PPP_INPUT_QUEUE_SIZE;
      q->nbuf--;
    }
}

/* Static functions */

static void
ssh_ppp_flush_disable_output(SshPppFlush rec)
{
  if (rec->output_stream != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("removing output stream from use"));

      if (rec->input_stream != rec->output_stream)
        {
          ssh_stream_set_callback(rec->output_stream,NULL_FNPTR,NULL);
        }
      rec->output_stream = NULL;
    }

  if (rec->output_frame_cb != NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL,("removing output callback from use"));
      rec->output_frame_cb = NULL_FNPTR;
    }
}

static void
ssh_ppp_flush_disable_input(SshPppFlush rec)
{
  if (rec->input_stream != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("disabling input channel"));

      if (rec->output_stream != rec->input_stream)
        {
          ssh_stream_set_callback(rec->input_stream,NULL_FNPTR,NULL);
        }
      rec->input_stream = NULL;
    }
}

static SshPppMuxProtocol
ssh_ppp_flush_get_client_by_pid(SshPppFlush rec, SshUInt16 pid)
{
  int i;
  SshPppMuxProtocol pro;

  for (i = 0; i < rec->nprotocols; i++)
    {
      pro = &rec->protocols[i];
      if (pro->thread != NULL)
        {
          if (pro->id == pid)
            {
              return pro;
            }
        }
    }
  return NULL;
}

static SshPppMuxProtocol
ssh_ppp_flush_get_client(SshPppFlush rec, SshPppPktBuffer pkt)
{
  int i;
  SshUInt16 pkt_pid;
  SshPppMuxProtocol pro;

  pkt_pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);

  for (i = 0; i < rec->nprotocols; i++)
    {
      pro = &rec->protocols[i];
      if (pro->thread != NULL)
        {
          if (pkt_pid == pro->id)
            {
              if (pro->accept_cb == NULL_FNPTR
                  || pro->accept_cb(pkt) == SSH_PPP_OK)
                {
                  return pro;
                }
            }
        }
    }
  return NULL;
}

static SshIterationStatus
ssh_ppp_flush_get_input(SshPppFlush rec)
{
  int ret;
  unsigned long bufsize;
  SshUInt8 *ptr;

  if (rec->input_stream != NULL)
    {
      if (!ssh_ppp_pkt_buffer_isfull(&rec->pkt))
        {

          bufsize = rec->pkt.maxbytes - rec->pkt.nbytes - rec->pkt.offset;
          SSH_DEBUG(SSH_D_MY,
                    ("reading from stream into buffer (buffer %ld bytes)",
                     bufsize));

          ptr = &rec->pkt.buffer[rec->pkt.nbytes+rec->pkt.offset];
          ret = ssh_stream_read(rec->input_stream,ptr,bufsize);

          if (ret == -1)
            {
              ssh_ppp_flush_set_flag(rec,
                                     SSH_PPP_FLUSH_F_INPUT_CB_ACTIVE,TRUE);
              return SSH_PPP_EMPTY;
            }

          if (ret == 0)
            {
              ssh_ppp_flush_disable_input(rec);
              return SSH_PPP_EMPTY;
            }
          rec->pkt.nbytes += ret;
        }
      return SSH_PPP_OK;
    }
  else
    {
      return SSH_PPP_EMPTY;
    }
}

/* Unallocate buffer */

static void
ssh_ppp_flush_free_pdu(SshPppFlush rec,
                       SshPppPktBuffer pkt)
{
  if (pkt != NULL)
    {

      SSH_ASSERT(pkt == &rec->current_pkt);

      if (rec->input_mode == SSH_PPP_FLUSH_MODE_STREAM)
        {
          ssh_ppp_pkt_buffer_uninit(pkt);
        }
      else if (rec->input_mode == SSH_PPP_FLUSH_MODE_CB)
        {
          ssh_ppp_pkt_buffer_free(pkt);
        }
      else
        {
          SSH_ASSERT(0);
        }
    }
}

void
ssh_ppp_flush_return_pdu(SshPppMuxProtocol pro,
                         SshPppPktBuffer pkt)
{
  ssh_ppp_flush_free_pdu(pro->rec,pkt);
}

/* Handle ACCM */

SshPppHldcOptionsStruct*
ssh_ppp_flush_get_input_opts(SshPppFlush f)
{
  SSH_PRECOND(f != NULL);

  return &f->input_opts;
}

SshPppHldcOptionsStruct*
ssh_ppp_flush_get_output_opts(SshPppFlush f)
{
  SSH_PRECOND(f != NULL);

  return &f->output_opts;
}

void
ssh_ppp_flush_accm_set(SshPppHldcOptionsStruct* rec, SshUInt32 val)
{
  rec->accm = val;
}

SshUInt32
ssh_ppp_flush_accm_get(SshPppHldcOptionsStruct* rec)
{
  return rec->accm;
}

int
ssh_ppp_flush_accm_isflag(SshPppHldcOptionsStruct* rec, SshUInt8 val)
{
  if ((val < 32) && (((1L << val) & rec->accm) != 0))
    {
      return 1;
    }

  if (val == SSH_PPP_HLDC_FLAG_DELIM)
    {
      return 1;
    }

  if (val == SSH_PPP_HLDC_FLAG_STUFF)
    {
      return 1;
    }

  if (val == 0xFF)
    {
      return 1;
    }
  return 0;
}

void
ssh_ppp_flush_accm_default(SshPppHldcOptionsStruct* rec)
{
  ssh_ppp_flush_accm_set(rec,0xFFFFFFFF);
}

void
ssh_ppp_flush_set_pfc(SshPppHldcOptionsStruct* rec, Boolean b)
{
  SshUInt32 val;

  val = (b == TRUE ? 1 : 0);

  rec->flags &= ~(1 << SSH_PPP_HLDC_F_PFC);
  rec->flags |= (val << SSH_PPP_HLDC_F_PFC);
}

void
ssh_ppp_flush_set_acfc(SshPppHldcOptionsStruct* rec, Boolean b)
{
  SshUInt32 val;

  val = (b == TRUE ? 1 : 0);

  rec->flags &= ~(1 << SSH_PPP_HLDC_F_ACFC);
  rec->flags |= (val << SSH_PPP_HLDC_F_ACFC);
}

Boolean
ssh_ppp_flush_get_pfc(SshPppHldcOptionsStruct* rec)
{
  return (rec->flags >> SSH_PPP_HLDC_F_PFC) & 1;
}

Boolean
ssh_ppp_flush_get_acfc(SshPppHldcOptionsStruct* rec)
{
  return (rec->flags >> SSH_PPP_HLDC_F_ACFC) & 1;
}

unsigned long
ssh_ppp_flush_get_input_mru(SshPppMuxProtocol pro)
{
  return pro->input_mru;
}

void
ssh_ppp_flush_wait(SshPppMuxProtocol mux)
{
  ssh_ppp_mux_set_flag(mux,SSH_PPP_MUX_F_WAIT,TRUE);
}

void
ssh_ppp_flush_unwait(SshPppMuxProtocol  mux)
{
  ssh_ppp_mux_set_flag(mux,SSH_PPP_MUX_F_WAIT,FALSE);
}

static void
ssh_ppp_flush_wakeup_waits(SshPppFlush rec)
{
  int i,j;
  SshPppMuxProtocol pro;

  for (i = 0;  i < rec->nprotocols; i++)
    {
      j = (i + rec->sched_low_id) % rec->nprotocols;
      pro = &rec->protocols[j];

      if (pro->thread != NULL)
        {
          if (ssh_ppp_mux_get_flag(pro,SSH_PPP_MUX_F_WAIT) == TRUE)
            {
              ssh_ppp_thread_wakeup(pro->thread);
              return;
            }
        }
    }
}

Boolean
ssh_ppp_flush_output_pkt_isavail(SshPppMuxProtocol pro)
{
  SshPppFlush rec;
  int i,j;

  rec = pro->rec;

  if (ssh_ppp_flush_get_flag(rec,SSH_PPP_FLUSH_F_BUF_BUSY) == TRUE)
    {
      return FALSE;
    }

  /* Attempt to guarantee a little fair-play */

  for (i = 0; i < rec->nprotocols; i++)
    {
      j = ( i + rec->sched_low_id) % rec->nprotocols;
      if (rec->protocols[j].thread != NULL)
        {
          if (ssh_ppp_mux_get_flag(&rec->protocols[j],
                                    SSH_PPP_MUX_F_WAIT) == TRUE
               && &rec->protocols[j] != pro)
            {
              return FALSE;
            }
        }
    }

  return TRUE;
}

SshPppPktBuffer
ssh_ppp_flush_get_output_pkt(SshPppMuxProtocol pro)
{
  SshPppFlush rec;
  SshPppPktBuffer pkt;

  SSH_ASSERT(pro->output_mru != 0);

  rec = pro->rec;
  pkt = &rec->output_pkt;

  if (ssh_ppp_flush_output_pkt_isavail(pro) == FALSE)
    return NULL;

  if (ssh_ppp_pkt_buffer_get_size(pkt) < rec->output_maxbufsize)
    {
      if (ssh_ppp_pkt_buffer_set_size(pkt,rec->output_maxbufsize)
          == FALSE)
        {
          return NULL;
        }
    }

  /* Ready buffer for use */

  ssh_ppp_pkt_buffer_clear(pkt);
  ssh_ppp_pkt_buffer_offset(pkt,8);

  return pkt;
}

unsigned long
ssh_ppp_flush_get_output_mru(SshPppMuxProtocol pro)
{
  return pro->output_mru;
}

static unsigned long
ssh_ppp_flush_pad_mru(SshPppFlush rec, unsigned long mru)
{
  switch (rec->mode)
    {
    default:
      SSH_ASSERT(0);
      mru = 0;
      break;

    case SSH_PPP_MODE_HLDC:
      /* Allow for acf, protocol id, flags and fcs */
      mru += 8;
      /* Allow for byte-stuffing */
      mru *= 2;
      break;

    case SSH_PPP_MODE_L2TP:
      /* Allow for acf, protocol id and L2TP length field */
      if (rec->output_mode == SSH_PPP_FLUSH_MODE_STREAM)
        {
          mru += 4;
        }
      else
        {
          mru += 8;
        }
      break;
    }
  return mru;
}

void
ssh_ppp_flush_set_output_mru(SshPppMuxProtocol pro,
                             unsigned long mru)
{
  SshPppFlush rec;
  int i;

  SSH_ASSERT(pro != NULL);

  if (mru < 128)
    {
      mru = 128;
    }

  pro->output_mru = mru;
  rec = pro->rec;

  SSH_DEBUG(SSH_D_MY,("Setting output mru of protocol 0x%x to %ld",
                      pro->id, mru));

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].thread != NULL)
        {
          if (mru < rec->protocols[i].output_mru)
            {
              mru = rec->protocols[i].output_mru;
            }
        }
    }

  SSH_DEBUG(SSH_D_MY,("Setting output mru of shared output buffer to %ld",
                      mru));

  rec->output_maxbufsize = ssh_ppp_flush_pad_mru(rec, mru);
}

void
ssh_ppp_flush_set_input_mru(SshPppMuxProtocol pro, unsigned long mru)
{
  SshPppFlush rec;
  int i;

  SSH_ASSERT(pro != NULL);
  rec = pro->rec;

  if (mru < 128)
    mru = 128;

  pro->input_mru = mru;

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].thread != NULL)
        {
          if (mru < rec->protocols[i].input_mru)
            {
              mru = rec->protocols[i].input_mru;
            }
        }
    }

  if (mru < 1500)
    {
      mru = 1500;
    }

  rec->input_maxbufsize = ssh_ppp_flush_pad_mru(rec, mru);
}

void
ssh_ppp_flush_disable(SshPppFlush rec)
{
  ssh_ppp_flush_disable_input(rec);
  ssh_ppp_flush_disable_output(rec);
}

void
ssh_ppp_flush_destroy(SshPppFlush rec)
{
  SSH_DEBUG(SSH_D_MY,("destroying up SshPPPFlushRec structure %p",rec));

  ssh_ppp_flush_disable(rec);

  if (rec->protocols)
    ssh_free(rec->protocols);

  ssh_ppp_pkt_buffer_free(&rec->pkt);
  ssh_ppp_pkt_buffer_free(&rec->output_pkt);

  ssh_ppp_flush_inputq_uninit(&rec->input_q);

  ssh_free(rec);
}

SshPppFlush
ssh_ppp_flush_create(int size,
                     SshStream input_stream,
                     SshStream output_stream,
                     SshPPPFrameOutputCB output_frame_cb,
                     int mode)
{
  SshPppFlush rec;

  rec = ssh_malloc(sizeof(*rec));

  if (rec == NULL)
    return NULL;

  rec->nprotocols = 0;
  rec->maxprotocols = size;

  rec->protocols = ssh_malloc(size * sizeof(SshPppMuxProtocolStruct));

  if (rec->protocols == NULL)
    {
      ssh_free(rec);
      return NULL;
    }

  rec->default_recipient = NULL;
  rec->mode = mode;
  rec->sched_low_id = 0;
  rec->flags = 0;
  rec->output_maxbufsize = 1530;
  rec->input_maxbufsize = 1530;

  rec->input_stream = input_stream;
  rec->output_stream = output_stream;
  rec->output_frame_cb = output_frame_cb;

  rec->input_mode = (input_stream != NULL?
                     SSH_PPP_FLUSH_MODE_STREAM:SSH_PPP_FLUSH_MODE_CB);

  rec->output_mode = (output_stream != NULL?
                      SSH_PPP_FLUSH_MODE_STREAM:SSH_PPP_FLUSH_MODE_CB);

  ssh_ppp_flush_inputq_init(&rec->input_q);

  /* Set up external callback->"condition variable" forwarding thread */

  if (input_stream != NULL)
    {
      ssh_stream_set_callback(input_stream, ssh_ppp_stream_cb, rec);
      ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_INPUT_CB_ACTIVE,TRUE);
    }

  if (output_stream != NULL)
    {
      ssh_stream_set_callback(output_stream, ssh_ppp_stream_cb, rec);
      ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_OUTPUT_CB_ACTIVE,TRUE);
    }

  /* Initialize variables for HLDC */

  ssh_ppp_flush_set_acfc(&rec->input_opts,FALSE);
  ssh_ppp_flush_set_pfc(&rec->input_opts,FALSE);
  ssh_ppp_flush_accm_default(&rec->input_opts);

  ssh_ppp_flush_set_acfc(&rec->output_opts,FALSE);
  ssh_ppp_flush_set_pfc(&rec->output_opts,FALSE);
  ssh_ppp_flush_accm_default(&rec->output_opts);

  /* Input Packet Buffers */

  ssh_ppp_pkt_buffer_uninit(&rec->pkt);
  ssh_ppp_pkt_buffer_uninit(&rec->current_pkt);
  ssh_ppp_pkt_buffer_uninit(&rec->output_pkt);

  return rec;
}

void
ssh_ppp_flush_del_protocol(SshPppMuxProtocol pro)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("removing protocol %p protocol id 0x%x",pro,pro->id));

  pro->thread = NULL;
  pro->rec = NULL;
  pro->id = 0;
}

SshPppMuxProtocol
ssh_ppp_flush_add_protocol(SshPppFlush rec,
                           SshUInt16 protocol,
                           SshPppThread thread,
                           int input_mru,
                           SshPppMuxAcceptanceCB cb)
{
  int i;
  Boolean flag;

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].thread == NULL)
        {
          break;
        }
    }

  SSH_ASSERT(i < rec->maxprotocols);

  rec->protocols[i].id = protocol;
  rec->protocols[i].thread = thread;
  rec->protocols[i].input_mru = 0;
  rec->protocols[i].output_mru = 0;
  rec->protocols[i].accept_cb = cb;
  rec->protocols[i].rec = rec;
  rec->protocols[i].flags = 0;

  flag = ssh_ppp_flush_get_flag(rec,SSH_PPP_FLUSH_F_FILTER_DEFAULT);

  ssh_ppp_mux_set_flag(&rec->protocols[i], SSH_PPP_MUX_F_FILTER, flag);
  ssh_ppp_mux_set_flag(&rec->protocols[i], SSH_PPP_MUX_F_WAIT, FALSE);

  ssh_ppp_flush_set_input_mru(&rec->protocols[i],input_mru);
  ssh_ppp_flush_set_output_mru(&rec->protocols[i],1500);

  if (i == rec->nprotocols)
    rec->nprotocols++;

  SSH_DEBUG(SSH_D_LOWOK,("adding protocol %p protocol id 0x%x",
                         &rec->protocols[i], rec->protocols[i].id));

  return &rec->protocols[i];
}

void
ssh_ppp_flush_input_frame(SshPppState gdata,
                          SshPppFlush rec,
                          SshUInt8 *buf,
                          unsigned long offset,
                          unsigned long len)
{
  SSH_ASSERT(rec->input_mode == SSH_PPP_FLUSH_MODE_CB);
  ssh_ppp_flush_inputq_put(&rec->input_q,buf,offset,len);

  SSH_DEBUG(SSH_D_MIDOK,
            ("received frame, offset %ld, len %ld",offset,len));

  /* Signal any protocol thread via stream callback */
  ssh_ppp_stream_cb(SSH_STREAM_INPUT_AVAILABLE, rec);
}

static int
ssh_ppp_flush_output(SshPppState gdata, SshPppFlush rec)
{
  SshPppPktBuffer pkt;
  int ret;
  SshUInt8 *ptr;
  unsigned long len;

  pkt = &rec->output_pkt;

  if (rec->output_mode == SSH_PPP_FLUSH_MODE_STREAM
      && rec->output_stream != NULL)
    {

      len = ssh_ppp_pkt_buffer_get_contentlen(pkt);
      ptr = ssh_ppp_pkt_buffer_get_ptr(pkt,0,len);

      if (gdata->fatal_error == 0)
        ret = ssh_stream_write(rec->output_stream, ptr, len);
      else
        ret = len;

      if (ret > 0)
        ssh_ppp_pkt_buffer_skip(pkt,ret);
    }
  else
    {
      ret = ssh_ppp_pkt_buffer_get_contentlen(pkt);

      if (rec->output_mode == SSH_PPP_FLUSH_MODE_CB
          && rec->output_frame_cb != NULL_FNPTR
          && gdata->fatal_error == 0)
        {

          /* Ugly: give the buffer away to the callback */

          SSH_PPP_CB(gdata,rec->output_frame_cb(gdata,
                                                gdata->ctx,
                                                pkt->buffer,
                                                pkt->offset,
                                                pkt->nbytes));

          ssh_ppp_pkt_buffer_uninit(pkt);
        }
      else
        {
          ssh_ppp_pkt_buffer_free(pkt);
        }
    }
  return ret;
}

void
ssh_ppp_flush_run(SshPppState gdata, SshPppMuxProtocol mux)
{
  int ret;
  SshPppPktBuffer pkt;
  SshPppFlush rec;
  unsigned long len;

  rec = mux->rec;
  pkt = &rec->output_pkt;

  if (ssh_ppp_flush_get_flag(rec,SSH_PPP_FLUSH_F_BUF_BUSY) == TRUE
      && !ssh_ppp_pkt_buffer_isempty(pkt))
    {
      len = ssh_ppp_pkt_buffer_get_contentlen(pkt);

      SSH_DEBUG_HEXDUMP(SSH_D_MY,("Flushing: len = %ld:", len),
                        ssh_ppp_pkt_buffer_get_ptr(pkt,0,len), len);

      ret = ssh_ppp_flush_output(gdata, rec);

      if (ret == -1)
        {
          ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_OUTPUT_CB_ACTIVE,TRUE);
          SSH_DEBUG(SSH_D_LOWOK,("write blocked, callback active"));
          return;
        }

      if (ret == 0)
        {
          SSH_DEBUG(SSH_D_FAIL,("error writing, disabling output"));
          ssh_ppp_flush_disable_output(rec);
          return;
        }

      if (ssh_ppp_pkt_buffer_isempty(pkt))
        {
          ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_BUF_BUSY,FALSE);
          ssh_ppp_flush_wakeup_waits(rec);
        }
    }
}

void
ssh_ppp_flush_send_pkt(SshPppState gdata, SshPppMuxProtocol pro)
{
  SshUInt16 fcs;
  SshUInt16 protocol;
  SshPppFlush rec;
  SshUInt8 buf[4];
  SshPppPktBuffer pkt;
  unsigned long len;

  rec = pro->rec;
  pkt = &rec->output_pkt;

  SSH_ASSERT(pro != NULL);
  SSH_ASSERT(rec != NULL);

  /* Discard packet if protocol is being filtered */

  if (ssh_ppp_mux_get_flag(pro,SSH_PPP_MUX_F_FILTER))
    return;

  if (ssh_ppp_pkt_buffer_isempty(pkt))
    return;

  /* HLDC frame */

  protocol = pro->id;
  ssh_ppp_pkt_buffer_prepend_uint16(pkt,protocol);

  if (protocol == SSH_PPP_PID_LCP
      || ssh_ppp_flush_get_acfc(&pro->rec->output_opts) == FALSE)
    {
      ssh_ppp_pkt_buffer_prepend_uint8(pkt,0x03);
      ssh_ppp_pkt_buffer_prepend_uint8(pkt,0xFF);
    }

  if (rec->mode == SSH_PPP_MODE_HLDC)
    {

      /* Output FCS calculation from RFC 1662 Appendix C */

      fcs = ssh_ppp_fcs_calculate_16bit_fcs(SSH_PPP_FCS_16BIT_INITIAL_FCS,
                                            &pkt->buffer[pkt->offset],
                                            pkt->nbytes);

      fcs ^= 0xffff;

      ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)(fcs&0xff));
      ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)((fcs >> 8)&0xff));


      len = ssh_ppp_pkt_buffer_get_contentlen(pkt);

      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("sending frame: len = %ld: ", len),
                        ssh_ppp_pkt_buffer_get_ptr(pkt,0,len), len);

      /* HLDC byte-stuff frame */

      if (protocol == SSH_PPP_PID_LCP)
        {
          SshPppHldcOptionsStruct *opts = ssh_ppp_flush_get_output_opts(rec);
          SshUInt32 backup = ssh_ppp_flush_accm_get(opts);

          ssh_ppp_flush_accm_set(opts,0xFFFFFFFF);
          ssh_ppp_flush_hldc_stuff(pro->rec, pkt);

          ssh_ppp_flush_accm_set(opts,backup);
        }
      else
        {
        ssh_ppp_flush_hldc_stuff(pro->rec, pkt);
        }

      /* Append and prepend flag bytes */

      ssh_ppp_pkt_buffer_append_uint8(pkt,SSH_PPP_HLDC_FLAG_DELIM);
      ssh_ppp_pkt_buffer_prepend_uint8(pkt,SSH_PPP_HLDC_FLAG_DELIM);
    }
  else
    {

      SSH_ASSERT(rec->mode == SSH_PPP_MODE_L2TP);

      /* For output, do not prepend the length field */

      if (rec->output_mode != SSH_PPP_FLUSH_MODE_CB)
        {

          SSH_PUT_32BIT(buf,ssh_ppp_pkt_buffer_get_contentlen(pkt));
          ssh_ppp_pkt_buffer_prepend_uint8(pkt,buf[3]);
          ssh_ppp_pkt_buffer_prepend_uint8(pkt,buf[2]);
          ssh_ppp_pkt_buffer_prepend_uint8(pkt,buf[1]);
          ssh_ppp_pkt_buffer_prepend_uint8(pkt,buf[0]);
        }
    }

  ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_BUF_BUSY,TRUE);
  rec->sched_low_id = (rec->sched_low_id + 1) % rec->nprotocols;
  ssh_ppp_flush_run(gdata,pro);
}

SshIterationStatus
ssh_ppp_flush_get_pdu(SshPppState gdata,
                      SshPppMuxProtocol pro, SshPppPktBuffer *retpkt)
{
  SshPppFlush rec;
  SshUInt16 pkt_pid;
  SshPppMuxProtocol recipient;
  SshIterationStatus status;
  Boolean flag;

  rec = pro->rec;
  *retpkt = NULL;

  /* The loop below traverses the following sequence.

     1. Attempt to find an unhandled HLDC frame using ssh_ppp_flush_get_frame
        which returns only SSH_PPP_OK or SSH_PPP_EMPTY. Erroneous input is not
        signaled via SSH_PPP_ERROR, as erroneous input is immediately
        discarded.

     2. If the recipient of the frame is the calling protocol, pass
        the buffer to it and RETURN.

     3. If the recipient of the frame is another protocol, signal that
        protocol for wakeup, and RETURN.

     4. If the packet should be filtered, or no protocol for it
        exists. Destroy it.

     5. Loop untill all input has been handled.
  */


  /* A fatal error has occured, do not process any
     more input. */

  if (gdata->fatal_error == 1)
    return SSH_PPP_EMPTY;

  do
    {
      /* Get an unhandled HLDC frame into rec->current_pkt */

      status = ssh_ppp_flush_get_frame(gdata, rec);

      if (status == SSH_PPP_OK)
        {

          /* Get recipient protocol of frame */

          recipient = ssh_ppp_flush_get_client(rec,&rec->current_pkt);

          if (recipient == NULL && rec->default_recipient != NULL)
            {
              pkt_pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);

              /* Use default recipient only in the case there does not
                 exist another protocol from the same id. DO NOT use
                 default recipient when the "guard" acceptor callback
                 fails (This would result in incorrect protocol
                 reject messages). */

              if (ssh_ppp_flush_get_client_by_pid(rec, pkt_pid) == NULL)
                {
                  recipient = rec->default_recipient;
                }
            }

          if (recipient != NULL)
            {
              flag = ssh_ppp_mux_get_flag(recipient, SSH_PPP_MUX_F_FILTER);
              if (flag == FALSE)
                {
                  if (recipient == pro)
                    {

                      *retpkt = &rec->current_pkt;
                      return SSH_PPP_OK;
                    }
                  else
                    {
                      /* Mark another protocol thread for wake-up, and do not
                         destroy the frame waiting in the buffer. */

                      ssh_ppp_thread_wakeup(recipient->thread);
                      pkt_pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);
                      SSH_DEBUG(SSH_D_MY,
                                ("HLDC: Routing 0x%x to protocol %p "
                                 "from thread %p",
                                 pkt_pid,recipient,pro));
                      return SSH_PPP_EMPTY;
                    }
                }
              else
                {
                  /* The value of pkt_pid is used for debug message when
                     debug is enabled. */
                  /* coverity[returned_value] */
                  pkt_pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("HLDC: filtering protocol 0x%x",pkt_pid));

                  ssh_ppp_flush_return_pdu(pro,&rec->current_pkt);
                }
            }
          else
            {
              /* The value of pkt_pid is used for debug message when
                 debug is enabled. */
              /* coverity[returned_value] */
              pkt_pid = ssh_ppp_hldc_get_protocol(&rec->current_pkt);
              SSH_DEBUG(SSH_D_LOWOK,("HLDC: No protocol accepting message "
                                     "with pid %x",pkt_pid));

              ssh_ppp_flush_return_pdu(pro,&rec->current_pkt);
            }
        }
    }
  while (status != SSH_PPP_EMPTY);

  return status;
}

Boolean
ssh_ppp_hldc_ispfc(SshPppPktBuffer pkt)
{
  SshUInt8 b0;

  if (ssh_ppp_pkt_buffer_get_contentlen(pkt) < 1)
    return FALSE;

  b0 = ssh_ppp_pkt_buffer_get_uint8(pkt,0);

  return ((b0 & 1) == 1 ? TRUE : FALSE);
}


SshUInt16
ssh_ppp_hldc_get_protocol(SshPppPktBuffer frame)
{
  SshUInt16 val;

  /* This should only be called with valid HLDC frames
     discovered using the functions above */

  SSH_ASSERT(ssh_ppp_pkt_buffer_get_contentlen(frame) >= 1);

  val = ssh_ppp_pkt_buffer_get_uint8(frame, 0);

  if (!ssh_ppp_hldc_ispfc(frame))
    {
      SSH_ASSERT(ssh_ppp_pkt_buffer_get_contentlen(frame) >= 2);
      val = (val << 8) | ssh_ppp_pkt_buffer_get_uint8(frame, 1);
    }

  return val;
}

/* Handle filter */

void
ssh_ppp_flush_filter_all(SshPppFlush rec)
{
  unsigned long i;

  ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_FILTER_DEFAULT,TRUE);

  for (i = 0; i < rec->nprotocols; i++)
    ssh_ppp_mux_set_flag(&rec->protocols[i],SSH_PPP_MUX_F_FILTER,TRUE);
}

void
ssh_ppp_flush_unfilter_all(SshPppFlush rec)
{
  unsigned long i;

  ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_FILTER_DEFAULT,FALSE);

  for (i = 0; i < rec->nprotocols; i++)
    ssh_ppp_mux_set_flag(&rec->protocols[i],SSH_PPP_MUX_F_FILTER,FALSE);
}

void
ssh_ppp_flush_filter(SshPppFlush rec, SshUInt16 pid)
{
  unsigned long i;

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].id == pid)
        ssh_ppp_mux_set_flag(&rec->protocols[i],SSH_PPP_MUX_F_FILTER,TRUE);
    }
}

void
ssh_ppp_flush_unfilter(SshPppFlush rec, SshUInt16 pid)
{
  unsigned long i;

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].id == pid)
        {
          ssh_ppp_mux_set_flag(&rec->protocols[i],SSH_PPP_MUX_F_FILTER,FALSE);
        }
    }
}

SshPppFilterPidStatus
ssh_ppp_flush_get_pid_status(SshPppFlush rec, SshUInt16 pid)
{
  unsigned long i;
  int x;

  x = 0;

  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].id == pid && rec->protocols[i].thread != NULL)
        {
          x = 1;
          if (ssh_ppp_mux_get_flag(&rec->protocols[i],
                                   SSH_PPP_MUX_F_FILTER))
            {
              return SSH_PPP_FLUSH_FILTER;
            }
        }
    }

  if (x == 1)
    {
      return SSH_PPP_FLUSH_PASS;
    }

  return SSH_PPP_FLUSH_DROP;
}

void
ssh_ppp_flush_set_default_recipient(SshPppFlush rec, SshPppMuxProtocol mux)
{
  SSH_ASSERT(rec != NULL);

  rec->default_recipient = mux;
}

void
ssh_ppp_mux_filter_all(SshPppMuxProtocol pro)
{
  ssh_ppp_flush_filter_all(pro->rec);
}

void
ssh_ppp_mux_unfilter_all(SshPppMuxProtocol pro)
{
  ssh_ppp_flush_unfilter_all(pro->rec);
}

void
ssh_ppp_mux_filter(SshPppMuxProtocol pro, SshUInt16 pid)
{
  ssh_ppp_flush_filter(pro->rec,pid);
}

void
ssh_ppp_mux_unfilter(SshPppMuxProtocol pro, SshUInt16 pid)
{
  ssh_ppp_flush_unfilter(pro->rec,pid);
}

