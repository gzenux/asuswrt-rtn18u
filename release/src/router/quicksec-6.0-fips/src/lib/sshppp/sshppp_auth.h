/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/


#ifndef SSH_PPP_AUTH_H

#define SSH_PPP_AUTH_H 1

typedef enum {
  SSH_PPP_AUTH_AUTHENTICATOR = 1,
  SSH_PPP_AUTH_PEER = 2
} SshPppAuthMode;

/* This function is called to create an authentication protocol
   instance. It should return an opaque pointer to the
   authentication protocol state. */

typedef void* (*SshPppAuthProtocolCreateCB)(struct SshPppStateRec *gdata,
                                            SshPppAuthMode mode,
                                            SshPppEvents eventq_internal,
                                            SshPppFlush flush);

/* This function is called to "boot" the protocol. The protocol
   should not perform any i/o or any other asynch tasks before
   this function is called. */

typedef void (*SshPppAuthProtocolBootCB)(void*);

/* This function is called to destroy the opaque state associated
   with the authentication protocol created with a
   SshPppAuthProtocolCreateCB callback. */

typedef void (*SshPppAuthProtocolDestroyCB)(void*);

/* This function is called to return a secret requested by
   the protocol using ssh_ppp_get_secret().

   The recipient of the callback must not free or modify the
   secret_buf. If is_secret_valid is FALSE, then the contents
   of secret_buf should be ignored and any resources associated
   with the pending callback freed. The PPP library will
   take care of restarting the secret lookup later on. */

typedef void (*SshPppAuthReturnSecretCB)(struct SshPppStateRec *gdata,
                                         void *auth_state,
                                         SshUInt8 *secret_buf,
                                         SshUInt32 secret_length,
                                         Boolean is_secret_valid);

#ifdef SSHDIST_EAP
typedef void (*SshPppAuthReturnTokenCB)(struct SshPppStateRec *gdata,
                                        void *auth_state,
                                        SshUInt8 eap_type,
                                        SshEapToken tok,
                                        Boolean is_token_valid);

#endif /* SSHDIST_EAP */

/* This function should restart the "request secret" process.
   This callback can be called in a situation where LCP
   negotiation has reset the authentication protocol
   while the callback was pending, and the results are now invalid. */

typedef void (*SshPppAuthGetSecretCB)(struct SshPppStateRec *gdata,
                                      void *auth_state);

#ifdef SSHDIST_EAP
typedef void (*SshPppAuthGetTokenCB)(struct SshPppStateRec *gdata,
                                     void *auth_state);

#endif /* SSHDIST_EAP */

/* This callback notifies the authentication protocol of the
   name of the system it is acting on behalf of. The recipient
   function must not modify the buffer given to it. */

typedef Boolean (*SshPppAuthSetNameCB)(void *auth_state,
                                       SshUInt8 *name_buf,
                                       unsigned long name_len);

/* This callback should return the status of the authentication
   as a SshPppEvent. The values SSH_PPP_EVENT_NONE (pending
   or otherwise unknown), SSH_PPP_EVENT_AUTH_FAIL and
   SSH_PPP_EVENT_AUTH_OK are at least understood by the receiver. */

typedef SshPppEvent (*SshPppAuthGetStatusCB)(void *auth_state);

/* This callback must return the
   SshPppEvents passed as input to SshPppAuthProtocolCreateCB.
   The purpose is merely to avoid storing the pointer twice. */

typedef SshPppEvents (*SshPppAuthGetEventsCB)(void *auth_state);

/* This callback must return the SshPppAuthMode mode passed
   as input SshPppAuthProtocolCreateCB. */

typedef SshPppAuthMode (*SshPppAuthGetModeCB)(void *auth_state);

#ifdef SSHDIST_RADIUS

/* Enter the authentication instance from a RADIUS callback. */
typedef void (*SshPppAuthRadiusEntryCB)(struct SshPppStateRec *gdata,
                                        void *auth_state,
                                        SshRadiusClientRequestStatus status,
                                        SshRadiusClientRequest request,
                                        SshRadiusOperationCode reply_code);
#endif /* SSHDIST_RADIUS */

typedef struct SshPppAuthProtocolImplRec
{
  /* Callbacks for implementing the interface */
  SshPppAuthProtocolCreateCB create;
  SshPppAuthProtocolBootCB boot;
  SshPppAuthProtocolDestroyCB destroy;
  SshPppAuthReturnSecretCB return_secret;
  SshPppAuthGetSecretCB get_secret;
#ifdef SSHDIST_EAP
  SshPppAuthReturnTokenCB return_token;
  SshPppAuthGetTokenCB get_token;
#endif /* SSHDIST_EAP */
  SshPppAuthSetNameCB set_name;
  SshPppAuthGetStatusCB get_status;
  SshPppAuthGetEventsCB get_events;
  SshPppAuthGetModeCB get_mode;

#ifdef SSHDIST_RADIUS
  SshPppAuthRadiusEntryCB radius_cb;
#endif /* SSHDIST_RADIUS */

  /* The Authentication type this interface represents */
  SshPppAuthType type;
} *SshPppAuthProtocolImpl, SshPppAuthProtocolImplStruct;

#define SSH_PPP_AUTH_SECRET_CB_NONE 0
#define SSH_PPP_AUTH_SECRET_CB_DISCARD 1
#define SSH_PPP_AUTH_SECRET_CB_PENDING 2
#define SSH_PPP_AUTH_SECRET_CB_REDO 3

typedef struct SshPppAuthProtocolRec {
  SshPppEventsOutput events_output;

  void *ctx;
  SshPppAuthProtocolImpl impl;

  SshUInt8 get_secret_cb_state;
} *SshPppAuthProtocol, SshPppAuthProtocolStruct;

/* Functions for hiding the interface implementations */

SshPppEvent
ssh_ppp_auth_get_status(SshPppAuthProtocol authp);

SshPppAuthMode
ssh_ppp_auth_get_mode(SshPppAuthProtocol authp);

void
ssh_ppp_auth_uninit(struct SshPppStateRec *gdata,
                    SshPppAuthProtocol authpro);

void
ssh_ppp_auth_boot(SshPppAuthProtocol authp);

Boolean
ssh_ppp_auth_set_name(SshPppAuthProtocol authp,
                      SshUInt8 *sys_name,
                      unsigned long sys_name_len);

void
ssh_ppp_auth_return_secret(struct SshPppStateRec *gdata,
                           SshPppAuthProtocol authp,
                           SshUInt8* buf,
                           unsigned long len);

#ifdef SSHDIST_EAP
void
ssh_ppp_auth_return_token(struct SshPppStateRec *gdata,
                          SshPppAuthProtocol auth,
                          SshUInt8 eap_type,
                          SshEapToken token);

#endif /* SSHDIST_EAP */

void
ssh_ppp_auth_init_none(SshPppAuthProtocol authp);

#ifdef SSHDIST_RADIUS


void
ssh_ppp_auth_radius_cb(struct SshPppStateRec *gdata,
                       SshPppAuthProtocol authp,
                       SshRadiusClientRequestStatus status,
                       SshRadiusClientRequest request,
                       SshRadiusOperationCode reply_code);
#endif /* SSHDIST_RADIUS */

Boolean
ssh_ppp_auth_init_chap(struct SshPppStateRec *gdata,
                       SshPppAuthProtocol authp,
                       SshPppAuthMode mode,
                       SshPppEvents events,
                       SshPppFlush mux);

Boolean
ssh_ppp_auth_init_mschapv2(struct SshPppStateRec *gdata,
                           SshPppAuthProtocol authp,
                           SshPppAuthMode mode,
                           SshPppEvents events,
                           SshPppFlush mux);


Boolean
ssh_ppp_auth_init_mschapv1(struct SshPppStateRec *gdata,
                           SshPppAuthProtocol authp,
                           SshPppAuthMode mode,
                           SshPppEvents events,
                           SshPppFlush mux);


#ifdef SSHDIST_EAP
Boolean
ssh_ppp_auth_init_eap(struct SshPppStateRec *gdata,
                      SshPppAuthProtocol authp,
                      SshPppAuthMode mode,
                      SshPppEvents events,
                      SshPppFlush mux);
#endif /* SSHDIST_EAP */

Boolean
ssh_ppp_auth_init_pap(struct SshPppStateRec *gdata,
                      SshPppAuthProtocol authp,
                      SshPppAuthMode mode,
                      SshPppEvents events,
                      SshPppFlush mux);


#endif /* SSH_PPP_AUTH_H */
