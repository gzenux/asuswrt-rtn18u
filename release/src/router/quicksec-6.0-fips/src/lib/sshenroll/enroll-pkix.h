/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RFC2510 based direct TCP enrollment protocol as described at
   draft-ietf-pkix-cmp-tcp-00.txt and
   draft-ietf-pkix-cmp-http-00.txt.
*/

typedef enum
{
  SSH_PKI_MSG_PKIREQ    = 0,
  SSH_PKI_MSG_POLLREP   = 1,
  SSH_PKI_MSG_POLLREQ   = 2,
  SSH_PKI_MSG_FINREP    = 3,
  SSH_PKI_MSG_PKIREP    = 5,
  SSH_PKI_MSG_ERRORREP  = 6
} SshPkiTcpProtoMessage;

typedef enum
{
  SSH_PKI_VERSION_0     =  0,
  SSH_PKI_VERSION_1     = 10
} SshPkiTcpProtoVersion;

/* Function prototypes for client side. */
SshPkiStatus ssh_pki_pkix_session_start(SshPkiSession session);
SshPkiStatus ssh_pki_pkix_session_resume(SshPkiSession session);
SshPkiStatus ssh_pki_pkix_session_confirm(SshPkiSession session);
Boolean ssh_pki_pkix_session_linearize(SshPkiSession session);
Boolean ssh_pki_pkix_session_delinarize(SshPkiSession session);
void ssh_pki_pkix_session_finish(SshPkiSession session);
