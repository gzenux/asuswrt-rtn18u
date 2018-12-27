/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements simple generic "packetizer" module, which receives data from a
   continuous stream (such as a character device) and formats this into chunks
   as indicated by the embedded size fields.
*/

#ifndef SSH_INTERCEPTOR_PKTIZER_H
#define SSH_INTERCEPTOR_PKTIZER_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


typedef struct SshPacketizerRec *SshPacketizer;

typedef void (__fastcall *SshPacketizerCallback)(int len,
                                                 unsigned char *buf,
                                                 SshPacketizer pktizer);

/*
  struct SshPacketizerRec - per-instance context needed by "packetizer"
*/
typedef struct SshPacketizerRec
{
  /* 'buf' points to intermediate buffer of 'buf_len' bytes */
  unsigned char *buf;

  /* There is valid, buffered data from 'buf' to 'buf + len' */
  unsigned int len;

  /* Total length of the current chunk in bytes */
  unsigned int pkt_len;

  /* Indicates how many bytes of the pkt_len field are valid (0-4) */
  unsigned int pkt_len_bytes_valid;

  /*
    Callback and associated context which is called for each completely
    received chunk
  */
  SshPacketizerCallback callback;
  void *callback_context;

};

typedef struct SshPacketizerRec SshPacketizerStruct;


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

void ssh_interceptor_pktizer_init(SshPacketizer pktizer,
                                  SshPacketizerCallback callback,
                                  void *callback_context);


void ssh_interceptor_pktizer_uninit(SshPacketizer pktizer);


Boolean ssh_interceptor_pktizer_receive(unsigned int len,
                                        unsigned char *buf,
                                        SshPacketizer pktizer);

#ifdef __cplusplus
}
#endif

#endif /* SSH_INTERCEPTOR_PKTIZER_H */
