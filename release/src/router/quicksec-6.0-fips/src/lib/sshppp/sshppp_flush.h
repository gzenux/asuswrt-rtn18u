/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_FLUSH_H

#define SSH_PPP_FLUSH_H 1

#define SSH_PPP_HLDC_FLAG_DELIM 0x7e
#define SSH_PPP_HLDC_FLAG_STUFF 0x7d

#define SSH_PPP_FLUSH_MODE_STREAM 1
#define SSH_PPP_FLUSH_MODE_CB 2

#define SSH_PPP_INPUT_QUEUE_SIZE 4

typedef SshUInt32 SshLCPACCM;

typedef SshIterationStatus (*SshPppMuxAcceptanceCB)(SshPppPktBuffer pkt);

#define SSH_PPP_HLDC_F_PFC 0
#define SSH_PPP_HLDC_F_ACFC 1

typedef struct SshPppHldcOptionsRec
{
  SshLCPACCM accm;
  SshUInt8 flags;
} SshPppHldcOptionsStruct;

typedef enum {
  SSH_PPP_FLUSH_FILTER,
  SSH_PPP_FLUSH_PASS,
  SSH_PPP_FLUSH_DROP
} SshPppFilterPidStatus;

#define SSH_PPP_MUX_F_FILTER 0
#define SSH_PPP_MUX_F_WAIT 1

typedef struct SshPppMuxProtocolRec
{

  SshUInt16 id;
  struct SshPppThreadRec *thread;

  SshPppMuxAcceptanceCB accept_cb;

  unsigned long input_mru;
  unsigned long output_mru;

  struct SshPppFlushRec *rec;

  SshUInt8 flags;

} *SshPppMuxProtocol, SshPppMuxProtocolStruct;

typedef struct SshPppMuxInputbufferQueueRec
{
  SshUInt8 idx;
  SshUInt8 nbuf;

  SshUInt8 *buffer[SSH_PPP_INPUT_QUEUE_SIZE];
  unsigned long offset[SSH_PPP_INPUT_QUEUE_SIZE];
  unsigned long length[SSH_PPP_INPUT_QUEUE_SIZE];
} SshPppMuxInputBufferQueueStruct;

#define SSH_PPP_FLUSH_F_BUF_BUSY 0
#define SSH_PPP_FLUSH_F_FILTER_DEFAULT 1
#define SSH_PPP_FLUSH_F_INPUT_CB_ACTIVE 2
#define SSH_PPP_FLUSH_F_OUTPUT_CB_ACTIVE 3

typedef struct SshPppFlushRec
{
  /* Input buffer and window to input buffer */
  SshPppPktBufferStruct pkt;
  SshPppPktBufferStruct current_pkt;

  /* Shared output buffer */
  SshPppPktBufferStruct output_pkt;

  /* I/O configuration */
  SshStream input_stream;
  SshStream output_stream;

  SshPPPFrameOutputCB output_frame_cb;

  /* Cyclic buffer for holding input buffers passed to this instance */
  SshPppMuxInputBufferQueueStruct input_q;

  /* Maximum buffer sizes, these limit the mru */
  unsigned long output_maxbufsize;
  unsigned long input_maxbufsize;

  /* Protocols we are attached to */

  SshPppMuxProtocol protocols;
  SshPppMuxProtocol default_recipient;

  SshPppHldcOptionsStruct input_opts;
  SshPppHldcOptionsStruct output_opts;

  /* Modes for I/O and framing */
  SshUInt8 input_mode;
  SshUInt8 output_mode;
  SshUInt8 mode;

  /* Index of the next thread which has priority access to buffer */
  SshUInt8 sched_low_id;

  /* Amount of protocols created */
  SshUInt8 nprotocols;

  /* Maximum amount of protocols */
  SshUInt8 maxprotocols;

  /* Flags */
  SshUInt8 flags;
} *SshPppFlush, SshPppFlushStruct;

void ssh_ppp_flush_input_frame(struct SshPppStateRec*,
                               SshPppFlush rec,
                               SshUInt8 *buffer,
                               unsigned long offset,
                               unsigned long len);

void ssh_ppp_flush_disable(SshPppFlush rec);
void ssh_ppp_flush_destroy(SshPppFlush rec);

SshPppFlush
ssh_ppp_flush_create(int maxprotocols,
                     SshStream input_stream,
                     SshStream output_stream,
                     SshPPPFrameOutputCB output_cb,
                     int mode);

Boolean
ssh_ppp_flush_output_pkt_isavail(SshPppMuxProtocol pro);

SshPppPktBuffer
ssh_ppp_flush_get_output_pkt(SshPppMuxProtocol pro);

void
ssh_ppp_flush_send_pkt(struct SshPppStateRec *gdata,
                       SshPppMuxProtocol pro);

void
ssh_ppp_flush_set_output_mru(SshPppMuxProtocol pro,
                             unsigned long mru);

unsigned long
ssh_ppp_flush_get_output_mru(SshPppMuxProtocol pro);

void
ssh_ppp_flush_set_input_mru(SshPppMuxProtocol pro,
                            unsigned long mru);

unsigned long
ssh_ppp_flush_get_input_mru(SshPppMuxProtocol pro);

void
ssh_ppp_flush_run(struct SshPppStateRec *gdata,
                  SshPppMuxProtocol pro);

void
ssh_ppp_flush_wait(SshPppMuxProtocol pro);

void
ssh_ppp_flush_unwait(SshPppMuxProtocol mux);

SshPppHldcOptionsStruct*
ssh_ppp_flush_get_input_opts(SshPppFlush flush);

SshPppHldcOptionsStruct*
ssh_ppp_flush_get_output_opts(SshPppFlush flush);

void
ssh_ppp_flush_accm_set(SshPppHldcOptionsStruct *hldc_opt,
                       SshUInt32 accm);

SshUInt32
ssh_ppp_flush_accm_get(SshPppHldcOptionsStruct *hldc_opt);

int
ssh_ppp_flush_accm_isflag(SshPppHldcOptionsStruct *hldc_opt,
                          SshUInt8 charval);

void
ssh_ppp_flush_accm_default(SshPppHldcOptionsStruct *hldc_opt);

Boolean
ssh_ppp_flush_get_pfc(SshPppHldcOptionsStruct *hldc_opt);

Boolean
ssh_ppp_flush_get_acfc(SshPppHldcOptionsStruct *hldc_opt);

void
ssh_ppp_flush_set_pfc(SshPppHldcOptionsStruct *hldc_opt,
                      Boolean pfc);

void
ssh_ppp_flush_set_acfc(SshPppHldcOptionsStruct *hldc_opt,
                       Boolean val);

SshPppMuxProtocol
ssh_ppp_flush_add_protocol(SshPppFlush rec,
                           SshUInt16 protocol,
                           struct SshPppThreadRec* thread,
                           int mru,
                           SshPppMuxAcceptanceCB cb);

void
ssh_ppp_flush_del_protocol(SshPppMuxProtocol pro);

SshIterationStatus
ssh_ppp_flush_get_pdu(struct SshPppStateRec *gdata,
                      SshPppMuxProtocol pro,
                      SshPppPktBuffer *pkt);

void
ssh_ppp_flush_return_pdu(SshPppMuxProtocol pro,
                         SshPppPktBuffer pkt);

SshUInt16
ssh_ppp_hldc_get_protocol(SshPppPktBuffer frame);

Boolean
ssh_ppp_hldc_ispfc(SshPppPktBuffer pkt);

void
ssh_ppp_flush_hldc_stuff(SshPppFlush rec, SshPppPktBuffer buf);

void ssh_ppp_flush_input_done(SshPppFlush rec);

void
ssh_ppp_flush_set_flag(SshPppFlush fd,
                       int flag,
                       Boolean val);

Boolean
ssh_ppp_flush_get_flag(SshPppFlush fd, int flag);

/* Handle authentication via this mechanism */

SshPppFilterPidStatus
ssh_ppp_flush_get_pid_status(SshPppFlush rec, SshUInt16 pid);

void
ssh_ppp_flush_filter_all(SshPppFlush rec);

void
ssh_ppp_flush_unfilter_all(SshPppFlush rec);

void
ssh_ppp_flush_unfilter(SshPppFlush rec, SshUInt16 pid);

void
ssh_ppp_flush_filter(SshPppFlush rec, SshUInt16 pid);

void
ssh_ppp_flush_set_default_recipient(SshPppFlush flush,
                                    SshPppMuxProtocol protocol);

void
ssh_ppp_mux_filter_all(SshPppMuxProtocol rec);

void
ssh_ppp_mux_unfilter_all(SshPppMuxProtocol rec);

void
ssh_ppp_mux_unfilter(SshPppMuxProtocol rec, SshUInt16 pid);

void
ssh_ppp_mux_filter(SshPppMuxProtocol rec, SshUInt16 pid);

#endif /* SSH_PPP_FLUSH_H */
