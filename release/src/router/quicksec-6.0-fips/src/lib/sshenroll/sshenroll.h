/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Key enrollment; end entity functions. This functionality
   assume out-of-band root CA key public key distribution and
   verification.
*/

#include "x509.h"
#include "sshstream.h"

#ifndef SSHENROLL_H
#define SSHENROLL_H

typedef enum {
  SSH_PKI_OK,
  SSH_PKI_FAILED,
  SSH_PKI_DELAYED,
  SSH_PKI_ABORTED
} SshPkiStatus;

typedef enum {
  SSH_PKI_SCEP   = 0,
  SSH_PKI_CMP    = 1
} SshPkiType;

typedef struct SshPkiSessionRec *SshPkiSession;

/* This callback function will be called when events occur in the
   enrollment.

   OK      -> certificate available from session. One should get
              rid of the session (if it was earlier saved on this
              callback, or if the operation was resumed).

   DELAYED -> received polling information from the CA. One should
              store this string in case resume is to be done.
              Unless aborted, the callback will be called again
              after the specified polling interval, or CA estimated
              completion time is reached, and poll is tried again.

   FAILED  -> this function will not be called again. If session
              is non NULL it can be resumed later (the request
              was done correctly, maybe could not connect?). */

typedef void (*SshPkiSessionDone)(SshPkiStatus status,
                                  SshPkiSession session,
                                  void *context);

/* Initialize PKI client session of specified `type' with the CA
   accessible at address `ca_access_uri'. The local network is
   described with `http_proxy_uri' and *socks_server_uri'. Both may be
   NULL if the CA is directly accessible.

   The resulting pointer can be given as argument to function
   ssh_pki_enroll to actually start sending data to the PKI
   session. */
SshPkiSession
ssh_pki_session_create(SshPkiType type,
                       const unsigned char *ca_access_uri,
                       const unsigned char *http_proxy_uri,
                       const unsigned char *socks_server_uri,
                       SshUInt32 retry_timer_secs,
                       SshUInt32 expire_timer_secs);

void
ssh_pki_session_set_extra(SshPkiSession session,
                          const unsigned char *data, size_t len);
void
ssh_pki_session_get_extra(SshPkiSession session,
                          unsigned char **data, size_t *len);

void ssh_pki_session_free(SshPkiSession session);

/* This call startes an enrollment session. The `session' argument
   describes the enrollment protocol and the protocol specific
   data access information.

   The message type sent has to match the `type' argument of the
   ssh_pki_session_create function used originally to create the
   session. (E.g. one must not send SCEP formatted messages to CMP CA
   address.

   The `callback' indicating completion of the key enrollment will not
   be called while still executing this function.

   The function returns an operation handle that can be used to cancel
   the operation. If cancelled, the callback will not be called in the
   future. It is legal to cancel operation after the callback has been
   called with pending status. */

SshOperationHandle
ssh_pki_enroll(SshPkiSession session,
               const unsigned char *message, size_t message_len,
               SshPkiSessionDone callback, void *context);

/* Convert enrollment session to string that can be stored into
   permanent storage for later resume. The format is platform
   independent, therefore it may be possible to continue session on
   different platform it was initially started. */
char *ssh_pki_session_linearize(SshPkiSession session);
SshPkiSession ssh_pki_session_delinearize(const char *linear_session);

/* Send confirmation message required by some enrollment protocols. If
   the protocol does not require this, the function does nothing (but
   calls the callback with success). */
SshOperationHandle
ssh_pki_confirm(SshPkiSession session,
                const unsigned char *message, size_t message_len,
                SshPkiSessionDone callback, void *context);


/* This function returns the type of the PKI session. */
SshPkiType ssh_pki_enrollment_get_type(SshPkiSession session);

/* This function retieves the last payload received into the
   session. */
Boolean
ssh_pki_enrollment_get_response(SshPkiSession session,
                                const unsigned char **message,
                                size_t *message_len);

/* Sets a session to use a preopened stream instead of creating TCP
   stream for itself. */
void ssh_pki_session_set_stream(SshPkiSession session, SshStream stream);

#endif /* SSHENROLL_H */
