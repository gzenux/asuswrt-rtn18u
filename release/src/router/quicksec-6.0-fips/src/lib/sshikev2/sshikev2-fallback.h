/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Integrated IKEv1 fallback functionality.

   * Design goals *

   * Use as much as possible from the existing IKEv1 library.
   * Change as little as possible the existing IKEv2 library and the
     policy management application.
   * IKEv1 can be turned off at compile time, in which case it does
     not increase the system footprint or runtime memory consumption.
     Alternatively it can be turned off at run time, in which case it
     increases the footprint and runtime memory consumption with
     a constant value.

   To meet these goals the IKEv1 fallback is implemented as glue code
   between the IKEv2 API (initiator, SAD, PAD, SPD) and the IKEv1
   library API (initiator, policy).

   For the initiator, IKEv1 exchange starts with an
   application-allocated IKEv2 SA that has a set flag indicating IKEv1
   use profile. When the IKEv2 call ssh_ikev2_ipsec_send() receives
   such SA, it dispatches execution to the fallback module. The
   fallback then calls the approriate IKEv2 SAD, SPD and PAD functions
   to collect information necessary to call the IKEv1 library functions
   ssh_ike_connect() and ssh_ike_connect_ipsec(). If IKE SA SPI values
   of a received packet indicate IKEv1 SA, the packet is again
   dispatched to the IKEv1 library from the ikev2-recv.c file.

   On the responder side, the incoming packet header is first decoded
   at the ikev2-recv.c and an IKEv2 policy call gets called to accept
   or reject the incoming connection. This call will decide whether
   IKEv1 is allowed or required with the given peer, and based on this
   and the version number of the received packet, approriate action
   (ikev2, ikev1, reject) is performed. If connect decision is use-ikev1,
   then the packet is passed to the IKEv1 library, and from there to the
   fallback functionality (yielding to proxy SA allocation).

   The fallback module converts between IKEv2 and IKEv1 API data
   structures (TS, ID, SA payloads).

   When IKEv1 and the IPsec SA made using it are ready, the
   appropriate IKEv2 policy calls get called to install the SA.
*/

#ifndef SSHIKEV2_FALLBACK_H
#define SSHIKEV2_FALLBACK_H

#include "sshincludes.h"
#ifdef SSHDIST_IKE_CERT_AUTH
#include "cmi.h"
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Magic value for a handle to a valid IKEv1 SA. */
#define SSH_IKEV2_FB_IKEV1_SA 0xdeadbeee


/*--------------------------------------------------------------------*/
/* Fallback startup and shutdown for use of IKEv2 module              */
/*--------------------------------------------------------------------*/

/** Sets up the fallback policy manager context and
    associates IKEv1 context to that, and assigns the functions
    implemented by this policy manager to the IKEv1 library.

    This function is called from the IKEv2 library when the library
    context is initialized to set up the IKEv1 fallback (in case v2
    parameters require fallback). */
SshIkev2Fb
ssh_ikev2_fallback_create(SshIkeParams params, SshAuditContext audit);

#ifdef SSHDIST_IKE_XAUTH
/* XAuth */

/** XAUTH attributes */
#define SSH_IKEV2_XAUTH_ATTRIBUTE_USER_NAME     0x0001
#define SSH_IKEV2_XAUTH_ATTRIBUTE_USER_PASSWORD 0x0002
#define SSH_IKEV2_XAUTH_ATTRIBUTE_PASSCODE      0x0004
#define SSH_IKEV2_XAUTH_ATTRIBUTE_MESSAGE       0x0008
#define SSH_IKEV2_XAUTH_ATTRIBUTE_CHALLENGE     0x0010
#define SSH_IKEV2_XAUTH_ATTRIBUTE_DOMAIN        0x0020
#define SSH_IKEV2_XAUTH_ATTRIBUTE_STATUS        0x0040
#define SSH_IKEV2_XAUTH_ATTRIBUTE_NEXT_PIN      0x0080
#define SSH_IKEV2_XAUTH_ATTRIBUTE_ANSWER        0x0100

/** Xauth attributes.  This structure is used by the application to
    receive and send Xauth attributes using the IKEv2 library IKEv1
    fallback extented authentication mechanism. */
struct SshIkev2FbXauthAttributesRec
{
  /** Type of legacy method. */
  SshUInt32 type;
  Boolean type_set;

  /** Mask of the attributes requested. This is a mask of the
      SSH_IKEV2_XAUTH_ATTRIBUTE_ defines. */
  SshUInt32 attributes_mask;

  /** User name. */
  unsigned char *user_name;
  size_t user_name_len;

  /** User password. */
  unsigned char *user_password;
  size_t user_password_len;

  /** Passcode. */
  unsigned char *passcode;
  size_t passcode_len;

  /** Extra message. */
  unsigned char *message;
  size_t message_len;

  /** Challenge. */
  unsigned char *challenge;
  size_t challenge_len;

  /** Domain to authenticate into. */
  unsigned char *domain;
  size_t domain_len;

  /** Status value to send. */
  SshUInt32 status;
  Boolean status_set;

  /** PIN number. */
  unsigned char *next_pin;
  size_t next_pin_len;

  /** Answer corresponding to PIN. */
  unsigned char *answer;
  size_t answer_len;

  /* Then some attributes for remote access combined with the XAUTH.  */
  SshIpAddrStruct address;
  SshIpAddr subnets;
  SshUInt32 num_subnets;
};

void
ssh_ikev2_fallback_set_xauth_client(SshIkev2 ikev2,
                                    SshIkev2FbXauthRequest request,
                                    SshIkev2FbXauthSet set,
                                    void *callback_context);
#endif /* SSHDIST_IKE_XAUTH */

/** Shut down the v1 fallback policy manager. */
void ssh_ikev2_fallback_destroy(SshIkev2Fb fb);

/** Attach the given IKEv1 fallback policy manager to the IKEv2 server. */
void ssh_ikev2_fallback_attach(SshIkev2Server server, SshIkev2Fb fb);

/** Detach the IKEv1 policy manager from the IKEv2 server.
    After this, the IKEv2 server can still serve v2 calls,
    but will not handle v1 calls any more. */
void ssh_ikev2_fallback_detach(SshIkev2Server server);

/** This function maps the SPI value(s) into IKEv1 SA pointer.

    @return
    NULL is returned if ike_spi_i and (ike_spi_r if given) do not
    specify a known SA. */
SshIkeNegotiation ssh_ikev2_fb_get_sa(SshIkev2 ikev2,
                                      const unsigned char *ike_spi_i,
                                      const unsigned char *ike_spi_r);

/*--------------------------------------------------------------------*/
/*  Interface between the IKE fallback module and the IKEv2 PM        */
/*--------------------------------------------------------------------*/

/** Ikev2 parameters given to the ssh_ikev2_init function and
    copied to the SshIkev2 context structure. */
typedef struct SshIkev2FallbackParamsRec {

  /** The maximum number of simultaneous responder
      aggressive mode negotiations. */
  SshUInt32 max_num_aggr_mode_active;
} SshIkev2FallbackParamsStruct, *SshIkev2FallbackParams;

/** Set the parameters for the fallback module. This function passes
    some information from the policy manager (currently the
    certificate validator) into the IKEv2 fallback module. */
void
ssh_policy_ikev2_fallback_set_params(SshIkev2 context,
                                     SshIkev2FallbackParams params);

/* eof */

#endif /* SSHIKEV2_FALLBACK_H */
