/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshtlskextrans.h
*/

#ifndef SSHTLSKEXTRANS_H_INCLUDED
#define SSHTLSKEXTRANS_H_INCLUDED

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"

/* Module name. */
#define SSH_DEBUG_MODULE "SshTlsKexTrans"

extern const SshCharPtr ssh_tls_minlength_str,
  ssh_tls_checktype_str, ssh_tls_malformed_str;

/* The length of temporary buffers that are used for formatting some
   hairy debug output. */
#define TEMP_BUF_SIZE 100

/* A macro that can be used to check that there are at least `q' bytes
   of data remaining. This compares the value of `q' against the
   variable `data_len', which is a part of the standard interface to
   all the transition functions. If not enough data is present, FAIL()
   is called which causes the transition to abort and an alert message
   to be sent. */
#define MIN_LENGTH(q) do { if (data_len < q) \
FAIL(SSH_TLS_ALERT_DECODE_ERROR, \
     (ssh_tls_minlength_str, \
      q, data_len)); } while(0)

/* A generic macro that fails fatally a transition. `v' is given as an
   argument to SSH_DEBUG and `type' is the type of an alert message to
   be sent. The protocol is also shut down. Returns from the
   transition immediately with the return value SSH_TLS_TRANS_FAILED. */
#define FAIL(type, v) do { \
  SSH_DEBUG(4, v); \
  ssh_tls_alert_and_kill(s, type); \
  return SSH_TLS_TRANS_FAILED; } while(0)

/* A macro to check the type of the received packet. If the type is
   different from `t', FAIL() is called with appropriate arguments. */
#define CHECKTYPE(t) \
do { if (type != t) \
       FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE, \
            (ssh_tls_checktype_str, type, t)); \
     } while(0)

/* A macro to further reduce the troubles of the programmer. */
#define FAILMF FAIL(SSH_TLS_ALERT_DECODE_ERROR, (ssh_tls_malformed_str))

#endif /* SSHTLSKEXTRANS_H_INCLUDED */
