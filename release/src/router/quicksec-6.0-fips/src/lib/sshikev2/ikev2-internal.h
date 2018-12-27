/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header to the IKEv2 library.
*/

#ifndef SSH_IKEV2_INTERNAL_H
#define SSH_IKEV2_INTERNAL_H

#include "sshfsm.h"
#include "sshadt_bag.h"

/** Cookie MAC. */
#define IKEV2_COOKIE_MAC_ALGORITHM "hmac-sha1"

#ifdef SSHDIST_EXTERNALKEY
/** Contexts for the ssh_ek_generate_accelerated_group
    operation. */
struct SshIkev2EkGroupContextRec {
  /** Old extra group needing to be freed at destroy time. If
      acceleration succeeded, this is the old software group
      that might still be in use, otherwise this is NULL. */
  SshPkGroup old_pk_grp;
  SshUInt32 group_number;       /** Number of the group */
  SshOperationHandle operation; /** Acceleration operation handle */
  SshIkev2 ikev2;               /** Back pointer */
  struct SshIkev2EkGroupContextRec *next;
};

typedef struct SshIkev2EkGroupContextRec SshIkev2EkGroupContextStruct;
#endif /* SSHDIST_EXTERNALKEY */

typedef struct SshIkev2HalfRec {
  SshADTBagHeaderStruct bag_header;

  /** SPI for this connection. */
  unsigned char ike_spi_i[8];

  /** SPI for this connection. */
  unsigned char ike_spi_r[8];

  /** Remote end IP address. */
  SshIpAddrStruct remote_ip[1];

  /** Remote end port used. */
  SshUInt16 remote_port;

  /** TTL; number of timer ticks this HALF entry will live. Decremented
     at ikev2->timeout */
  SshUInt16 ttl;

} *SshIkev2Half, SshIkev2HalfStruct;

/** Call Policy Manager and wait for reply. */
#define SSH_IKEV2_POLICY_CALL(packet, ike_sa, func) \
  SSH_DEBUG(SSH_D_LOWSTART, ("Calling " #func)); \
  (packet)->operation = (*((ike_sa)->server->sad_interface->func))

/** Call Policy Manager and notify it about something, for example of
   no reply callback. */
#define SSH_IKEV2_POLICY_NOTIFY(ike_sa, func) \
  SSH_DEBUG(SSH_D_LOWSTART, ("Calling " #func)); \
  (*((ike_sa)->server->sad_interface->func))


#ifdef SSHDIST_IKE_EAP_AUTH
/** A macro to check if EAP is enabled for the exchange 'ed'. */
#define SSH_IKEV2_EAP_ENABLED(ed) \
  ((ed->eap_state == SSH_IKEV2_NO_EAP) ? FALSE : TRUE)
#endif /* SSHDIST_IKE_EAP_AUTH */

/** Allocate an empty packet, and initialize the state machine.
   Set the first state to be the `first_state'. Return NULL
   in case of an error. */
SshIkev2Packet
ikev2_packet_allocate(SshIkev2 ike_context,
                      SshFSMStepCB first_state);

/** FSM destructor for packets */
void
ikev2_packet_destroy(SshFSM fsm, void *context);

void
ikev2_packet_free(SshIkev2 ikev2, SshIkev2Packet packet);

/** Arranges packet to run immediately to the end state. */
void
ikev2_packet_done(
        SshIkev2Packet packet);

/** This function decodes the header part of the input 'encoded_packet'
    to packet descriptor 'header' and stores a copy of 'encoded_packet'
    to 'header->encoded_packet'. */
SshIkev2Error
ikev2_decode_header(SshIkev2Packet header,
                    const unsigned char *encoded_packet,
                    size_t encoded_packet_len);

/** This function encodes the header and the packet data
    (from `buffer') to the encoded_packet field inside
    'packet'. */
SshIkev2Error
ikev2_encode_header(SshIkev2Packet packet, SshBuffer buffer);


void
ikev2_transmit_window_init(SshIkev2TransmitWindow transmit_window);

void
ikev2_transmit_window_reset(
        SshIkev2TransmitWindow transmit_window);

Boolean
ikev2_transmit_window_full(
        SshIkev2TransmitWindow transmit_window);

SshIkev2Error
ikev2_transmit_window_insert(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet);

SshIkev2Packet
ikev2_transmit_window_find_request(
        SshIkev2TransmitWindow transmit_window,
        SshUInt32 message_id);

Boolean
ikev2_transmit_window_acknowledge(
        SshIkev2TransmitWindow transmit_window,
        SshUInt32 message_id);

void
ikev2_transmit_window_flush(
        SshIkev2TransmitWindow transmit_window);

void
ikev2_transmit_window_uninit(SshIkev2TransmitWindow transmit_window);

SshIkev2Error
ikev2_transmit_window_set_size(
        SshIkev2TransmitWindow transmit_window,
        unsigned int newsize);

SshIkev2Error
ikev2_transmit_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len);


SshIkev2Error
ikev2_transmit_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len);

void
ikev2_receive_window_init(SshIkev2ReceiveWindow receive_window);

Boolean
ikev2_receive_window_check_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet);

Boolean
ikev2_receive_window_register_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet);

void
ikev2_receive_window_insert_response(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet response_packet);


SshIkev2Error
ikev2_receive_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len);

SshIkev2Error
ikev2_receive_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len);

SshIkev2Error
ikev2_receive_window_set_size(
        SshIkev2ReceiveWindow receive_window,
        unsigned int newsize);

void
ikev2_receive_window_uninit(SshIkev2ReceiveWindow receive_window);


/** This define specifies the maximum number of times a packet is retransmitted
    after an unprotected error notify is received for the IKE SA. */
#define SSH_IKEV2_PACKET_UNPROTECTED_ERROR_RETRANSMIT_COUNT 2

/** Set the retransmit counter for any pending requests in IKE SA window.
    This sets the retransmit counter of all request packets in both
    windows of the IKE SA. */
void
ikev2_window_set_retransmit_count(SshIkev2Sa ike_sa,
                                  SshUInt16 retransmit_counter);

#ifdef SSHDIST_IKE_MOBIKE
/** Moves packets in the IKE SAs window to new server. */
void
ikev2_window_change_server(SshIkev2Sa ike_sa,
                           SshIkev2Server server);
#endif /* SSHDIST_IKE_MOBIKE */

/** UDP send function. This will send the given packet, using
    the specified server to given remote address. The
    function will handle retransmissions for the requests
    packets internally. For response packets it will arrange
    retransmit reply capabilities. The IKEv2 state machine
    can therefore send packets at fire-and-forget mentality.
    The IKEv2 state machine MUST not touch the thread in the
    packet after this function is called, as this will start
    using the thread. The IKEv2 state machine will simply
    return SSH_FSM_CONTINUE to the thread after this function
    returns. The packet contains the server, remote_ip and
    port where the packet is sent. */
void
ikev2_udp_send(SshIkev2Sa sa,
               SshIkev2Packet packet);

/** UDP send function for replying to retransmitted packets.
    The packet to be sent is in 'packet'. The packet is sent
    using the server 'server' to remote address 'remote_ip' and
    remote port 'remote_port'. The response packet must be sent
    out using the address and port information of the received packet.
    The address and port information will differ to that stored in 'packet',
    if the initiator restransmits a request using a different addrss pair.
    The 'server', 'remote_ip' and 'remote_port' paramters should be
    taken from the restranmitted request packet. */
void ikev2_udp_retransmit_response_packet(SshIkev2Packet packet,
                                          SshIkev2Server server,
                                          SshIpAddr remote_ip,
                                          SshUInt16 remote_port);

/** UDP library application callback functions called when
    UDP listeners have received data. These functions read
    out the data, check for retransmissions, possibly create
    an SA for the first packets and serve the packet to the
    IKEv2 state machine. */
void
ikev2_udp_recv(SshUdpListener listener, void *context);


/** Global timer to clean up temporary containers. The context is
    expected to be SshIkev2. */
void ikev2_timer(void *context);

/** Start the IKE state machine. This will assume that the thread
    in the SshIkev2Packet structure is initialized and
    working, and that it can be used to run the state machine. In
    the end this function will call the ikev2_udp_send function and give the
    FSM thread to it. The packet receive state machine will
    simply return SSH_FSM_CONTINUE to the thread after this
    function returns.*/
void ikev2_state(SshIkev2Packet packet);

/** Indicate a tranmission error for the request 'packet'. */
void ikev2_xmit_error(SshIkev2Packet packet, SshIkev2Error error);

/** Allocates a reply packet, and copies all the necessary fields
    to it. Returns NULL in case of error, and in that case
    also sets the next state to be error. */
SshIkev2Packet
ikev2_reply_packet_allocate(SshIkev2Packet packet,
                            SshFSMStepCB first_state);

/** Decode the whole packet, i.e. call the various decode
    payload functions to decode payloads. This can return
    SSH_FSM_CONTINUE if we need to continue immediately, or
    SSH_FSM_SUSPENDED, if we are waiting for the async call.
    This can also set the state to the error state, and
    continue processing there. */
SshFSMStepStatus ikev2_decode_packet(SshIkev2Packet packet);

/** Set thread to error state (if error !=
    SSH_IKEV2_ERROR_OK), and store the error code to the packet.
    Then return SSH_FSM_CONTINUE. After this the packet
    processing will continue from the error state and it will
    check whether we need to send the error message or not. If
    the error code is SSH_IKEV2_ERROR_OK, then this will
    simply continue from the next normal step. */
SshFSMStepStatus ikev2_error(SshIkev2Packet, SshIkev2Error error);

/** Just like ikev2_error() but the error was received from the IKE
    peer instead of being detected locally. */
SshFSMStepStatus ikev2_error_remote(SshIkev2Packet, SshIkev2Error error);

/** If this is fatal error then set the thread to error
    state, otherwise store the error code to the ipsec_ed so
    that we will be sending the error notify afterwords. */
SshFSMStepStatus ikev2_ipsec_error(SshIkev2Packet packet,
                                   SshIkev2Error error);

/** Restart the packet state machine. */
void ikev2_restart_packet(SshIkev2Packet packet);

/** Allocate obstack for exchange data. */
SshIkev2ExchangeData ikev2_allocate_exchange_data(SshIkev2Sa ike_sa);

/** Allocate IKE SA exchange data. */
SshIkev2Error ikev2_allocate_exchange_data_ike(SshIkev2ExchangeData ed);

/** Allocate IPsec SA exchange data. */
SshIkev2Error ikev2_allocate_exchange_data_ipsec(SshIkev2ExchangeData ed);

/** Allocate Info exchange data. */
SshIkev2Error ikev2_allocate_exchange_data_info(SshIkev2ExchangeData ed);

/** Free Info SA exchange data. */
void ikev2_free_exchange_data_info(SshIkev2Sa ike_sa,
                                   SshIkev2InfoSaExchangeData ed);

/** Free exchange data. */
void ikev2_free_exchange_data(SshIkev2Sa ike_sa, SshIkev2ExchangeData ed);
void ikev2_reference_exchange_data(SshIkev2ExchangeData ed);

/** Free IKE SA exchange data. */
void ikev2_free_exchange_data_ike(SshIkev2Sa ike_sa,
                                  SshIkev2SaExchangeData ed);

/** Free IPsec SA exchange data. */
void ikev2_free_exchange_data_ipsec(SshIkev2Sa ike_sa,
                                    SshIkev2IPsecSaExchangeData ed);


/** Take reference to the IKE SA. */
#define SSH_IKEV2_IKE_SA_TAKE_REF(_ike_sa)                              \
  do                                                                    \
    {                                                                   \
      SshIkev2Sa __sa = (_ike_sa);                                      \
      SSH_DEBUG(SSH_D_LOWOK,                                            \
              ("Taking reference to IKE SA %p to ref count %d",         \
               __sa, __sa->ref_cnt + 1));                               \
      ssh_ikev2_ike_sa_take_ref(__sa);                                  \
    }                                                                   \
  while (0)

/** Internal macro for releasing references to SshIkev2Sa. */
#define SSH_IKEV2_IKE_SA_FREE(_ike_sa)                                  \
  do                                                                    \
    {                                                                   \
      SshIkev2Sa __sa = (_ike_sa);                                      \
      SSH_DEBUG(SSH_D_LOWOK,                                            \
                ("Freeing reference to IKE SA %p to ref count %d",      \
                 __sa, __sa->ref_cnt - 1));                             \
      ssh_ikev2_ike_sa_free(__sa);                                      \
    }                                                                   \
  while (0)

/** Take reference to the IKE SA. */
void
ssh_ikev2_ike_sa_take_ref(SshIkev2Sa ike_sa);

/** Free one reference to the IKE SA. */
void
ssh_ikev2_ike_sa_free(SshIkev2Sa ike_sa);

/** Initialize default groups. */
SshCryptoStatus ikev2_groups_init(SshIkev2 ikev2);

/** Uninitialize default groups. */
void ikev2_groups_uninit(SshIkev2 ikev2);

/** The length of the KE payload of the group in bits */
extern const size_t
ssh_ikev2_predefined_group_lengths[SSH_IKEV2_TRANSFORM_D_H_MAX];

/** Group names for default groups */
extern const char *
ssh_ikev2_predefined_group_names[SSH_IKEV2_TRANSFORM_D_H_MAX];

/** Group types for default groups */
extern const char *
ssh_ikev2_predefined_group_types[SSH_IKEV2_TRANSFORM_D_H_MAX];

/** Strengths of group in bits */
extern const unsigned int
ssh_ikev2_predefined_group_strengths[SSH_IKEV2_TRANSFORM_D_H_MAX];

/** Decode function prototypes. */
SshIkev2Error ikev2_decode_sa(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len);
SshIkev2Error ikev2_decode_ke(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len);
SshIkev2Error ikev2_decode_idi(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len);
SshIkev2Error ikev2_decode_idr(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len);
SshIkev2Error ikev2_decode_cert(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len);
SshIkev2Error ikev2_decode_certreq(SshIkev2Packet packet,
                                   const unsigned char *payload,
                                   size_t payload_len);
SshIkev2Error ikev2_decode_auth(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len);
SshIkev2Error ikev2_decode_nonce(SshIkev2Packet packet,
                                 const unsigned char *payload,
                                 size_t payload_len);
SshIkev2Error ikev2_decode_notify(SshIkev2Packet packet,
                                  Boolean authenticated,
                                  const unsigned char *payload,
                                  size_t payload_len);
SshIkev2Error ikev2_decode_delete(SshIkev2Packet packet,
                                  const unsigned char *payload,
                                  size_t payload_len);
SshIkev2Error ikev2_decode_vendor_id(SshIkev2Packet packet,
                                     const unsigned char *payload,
                                     size_t payload_len);
SshIkev2Error ikev2_decode_tsi(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len);
SshIkev2Error ikev2_decode_tsr(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len);
SshIkev2Error ikev2_decode_conf(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len);
SshIkev2Error ikev2_decode_eap(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len);

/** Update the next payload. */
void ikev2_update_next_payload(SshIkev2Packet packet,
                               SshIkev2PayloadType next_payload);

/** Each of these functions will get the payload structure
    and the buffer where the payload is stored. These
    functions only add the payload contents - the generic
    payload header is not added by these functions. These
    functions return the size used from the buffer, just
    like the ssh_encode_buffer functions, or zero if an error
    occurred. If the `next_payload_offset' is not NULL, then
    the offset of the next_payload in the `buffer' is stored
    there, so the next payload type can later be updated
    using the ikev2_update_next_payload function. */

size_t ikev2_encode_sa(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadSA sa,
                       int *next_payload_offset);
size_t ikev2_encode_ke(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadKE ke,
                       int *next_payload_offset);
size_t ikev2_encode_idi(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadID id,
                       int *next_payload_offset);
size_t ikev2_encode_idr(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadID id,
                       int *next_payload_offset);
#ifdef SSHDIST_IKE_CERT_AUTH
size_t ikev2_encode_cert(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadCert cert,
                         int *next_payload_offset);
size_t ikev2_encode_certreq(SshIkev2Packet packet,
                            SshBuffer buffer,
                            SshIkev2PayloadCertReq cp,
                            int *next_payload_offset);
#endif /* SSHDIST_IKE_CERT_AUTH */
size_t ikev2_encode_auth(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadAuth auth,
                         int *next_payload_offset);
size_t ikev2_encode_nonce(SshIkev2Packet packet,
                          SshBuffer buffer,
                          SshIkev2PayloadNonce nonce,
                          int *next_payload_offset);
size_t ikev2_encode_notify(SshIkev2Packet packet,
                           SshBuffer buffer,
                           SshIkev2PayloadNotify notify,
                           int *next_payload_offset);
size_t ikev2_encode_delete(SshIkev2Packet packet,
                           SshBuffer buffer,
                           SshIkev2PayloadDelete d,
                           int *next_payload_offset);
size_t ikev2_encode_vendor_id(SshIkev2Packet packet,
                              SshBuffer buffer,
                              SshIkev2PayloadVendorID vid,
                              int *next_payload_offset);
size_t ikev2_encode_ts(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadTS ts,
                       int *next_payload_offset,
                       Boolean tsi);
size_t ikev2_encode_conf(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadConf conf,
                         int *next_payload_offset);
#ifdef SSHDIST_IKE_EAP_AUTH
size_t ikev2_encode_eap(SshIkev2Packet packet,
                        SshBuffer buffer,
                        SshIkev2PayloadEap eap,
                        int *next_payload_offset);
#endif /* SSHDIST_IKE_EAP_AUTH */

/** Encrypt the packet and calculate its MAC. This will
    also encode the packet to the packet->encoded_packet. */
SshIkev2Error ikev2_encrypt_packet(SshIkev2Packet packet,
                                   SshBuffer buffer);

SshCryptoStatus ssh_prf_plus(const unsigned char *prf,
                             const unsigned char *key,
                             size_t key_len,
                             const unsigned char *data,
                             size_t data_len,
                             unsigned char *output,
                             size_t output_len);

/** Wait for timeout and then free the reference. */
void ikev2_free_ref_after_timeout(void *context);


/* Send audit event to audit log */
void ikev2_audit_event(SshIkev2 ikev2,
                       SshAuditEvent event, ...);

/* Send audit event to audit log */
void ikev2_audit(SshIkev2Sa ike_sa,
                 SshAuditEvent event,
                 const char *txt);

/* Report local failure of an IKE exchange. */
void ikev2_debug_exchange_fail_local(SshIkev2Packet packet,
                                     SshIkev2Error error);

/* Report remote failure of an IKE exchange. */
void ikev2_debug_exchange_fail_remote(SshIkev2Packet packet,
                                      SshIkev2Error error);

/* Report a general error associated with an IKE SA. */
void ikev2_debug_error(SshIkev2Sa ike_sa, const char *text);

/* Report start of an IKE exchange. */
void ikev2_debug_exchange_begin(SshIkev2Packet packet);

/* Report successful completion of an IKE exchange. */
void ikev2_debug_exchange_end(SshIkev2Packet packet);

/* Report establishment of an IKE SA. */
void ikev2_debug_ike_sa_open(SshIkev2Sa ike_sa);

/* Report IKE SA rekey. */
void ikev2_debug_ike_sa_rekey(SshIkev2Sa new_sa, SshIkev2Sa old_sa);

/* Report termination of an IKE SA. */
void ikev2_debug_ike_sa_close(SshIkev2Sa ike_sa);

/* Report reception of a packet. */
void ikev2_debug_packet_in(SshIkev2Packet packet);

/* Report transmission of a packet. */
void ikev2_debug_packet_out(SshIkev2Packet packet);

/* Report retransmission of a packet. */
void ikev2_debug_packet_out_retransmit(SshIkev2Sa ike_sa,
                                       SshIkev2Packet packet);

/* Report encoding of a packet with printf-like arguments. If this is
   the first payload, report start of packet encoding before the
   payload. */
void ikev2_debug_encode_payload(SshIkev2Packet packet, const char *fmt, ...);

/* Report start of packet decoding. */
void ikev2_debug_decode_start(SshIkev2Packet packet);

/* Report decoding of packet payload with printf-like arguments. */
void ikev2_debug_decode_payload(SshIkev2Packet packet, const char *fmt, ...);

/* Report decoding of packet payload in hex, prefixed with printf-like
   string. */
void ikev2_debug_decode_payload_hex(SshIkev2Packet packet,
                                    const unsigned char *payload,
                                    size_t payload_len,
                                    const char *fmt, ...);

/* *********************************************************************/
/** ikev2-state.c. */

/* Do IKE SA delete on error. */
void
ikev2_do_error_delete(SshIkev2Packet packet, SshIkev2Sa ike_sa);

/* Indicate responder exchange completion to policy implementation. Called
   at the end of responder exchanges. */
void ikev2_responder_exchange_done(SshIkev2Packet packet);

/* *********************************************************************/
/** ikev2-state-common.c. */

/** Create a nonce payload and add it. Moves to the error state in case of
    errors. */
void
ikev2_create_nonce_and_add(SshIkev2Packet packet,
                           SshIkev2PayloadNonce *return_nonce);

/** Verifies that the nonce payload is OK and stores it in the given
    location. Sets the thread to the error state on error.  */
void ikev2_check_nonce(SshIkev2Packet packet,
                       SshIkev2PayloadNonce *nonce);


/** Do async operation to request Notify payloads and add
    them to the outgoing packet. Moves to the error state in
    case of error, otherwise simply continues the thread, and
    assumes the next state is already set. */
void ikev2_add_notify(SshIkev2Packet packet);

/** Do async operation to request Vendor ID payloads and add
    them to the outgoing packet. Moves to the error state in
    case of error, otherwise simply continues the thread, and
    assumes the next state is already set. */
void ikev2_add_vid(SshIkev2Packet packet);

/** Do async operation to request ID and add it to the
    outgoing packet. Moves to the error state in case of
    error, otherwise simply continues the thread, and assumes the
    next state is already set. */
void ikev2_add_id(SshIkev2Packet packet, Boolean local);

/** Add the auth payload to the packet. */
void ikev2_add_auth(SshIkev2Packet packet,
                    SshIkev2AuthMethod auth_method,
                    const unsigned char *auth_data,
                    size_t auth_size);

/** Do async operation to request conf payload and add it to
    the outgoing packet. Moves to the error state in case of
    error, otherwise simply continues the thread, and assumes the
    next state is already set. */
void ikev2_add_conf(SshIkev2Packet packet);


/** Fill in the algorithm names in the IKEv2 SA structure,
    based on the ike_sa->ed->ike_sa_transforms. */
SshIkev2Error ikev2_fill_in_algorithms(SshIkev2Sa ike_sa,
                                       SshIkev2PayloadTransform *transforms);

/** Verify that the SA payload matches the payload we sent out.
    Return TRUE if successful, otherwise return FALSE and
    move the thread to the error state. */
Boolean ikev2_verify_sa(SshIkev2Packet packet,
                        SshIkev2PayloadSA sa_payload,
                        SshIkev2PayloadSA original_sa_payload,
                        SshIkev2PayloadTransform *transforms,
                        Boolean ike);

/** The SA select reply processing. Fill in the transforms
    table and proposal number. Return TRUE if successful,
    otherwise return FALSE and move the thread to the error
    state. */
Boolean ikev2_select_sa_reply(SshIkev2Packet packet,
                              SshIkev2Error error_code,
                              SshIkev2PayloadTransform *selected_transforms,
                              SshIkev2PayloadTransform *transforms);

/** Find a group from policy. The input group is the preferred
    group from previous notifications, if available. */
SshUInt16 ikev2_find_policy_group(SshIkev2Packet packet,
                                  SshIkev2PayloadSA sa_payload,
                                  SshUInt16 group);

/** Find a group from notifications. Returns -1 if no
    notification was found. */
int ikev2_find_notify_group(SshIkev2Packet packet);

/** Find a group. First check for the notifications, and if no
    INVALID_KE_PAYLOAD notification is found, then take the
    first group from sa_payload. */
SshUInt16 ikev2_find_group(SshIkev2Packet packet,
                           SshIkev2PayloadSA sa_payload);

/** Add KE payload. Do the Diffie-Hellman setup for the
    selected group and add a KE payload. */
void ikev2_add_ke(SshIkev2Packet packet, SshUInt16 group);

/** Calculate the Diffie-Hellman agree for the child SA. */
void ikev2_child_agree(SshIkev2Packet packet);

/** Parse notifies from the packet. */
void ikev2_process_notify(SshIkev2Packet packet);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
void ikev2_get_secondary_id(SshIkev2Packet packet);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */



/* *********************************************************************/
/** ikev2-shared-key-auth.c. */
/** Complete the preshared key callback for the local (preshared or EAP)
    key. This computes the local AUTH payload. */
void ikev2_reply_cb_shared_key_auth_compute(const unsigned char *key_out,
                                            size_t key_out_len,
                                            SshIkev2Packet packet);

/** Do the async operation and get the shared key from the
    other end and add AUTH payload to packet. Moves to the
    error state in case of error, otherwise simply continues
    the thread and assumes that the next state is already set.
    Sets eap_enabled to true, if we cannot find a key for the
    other end. */
void ikev2_add_auth_shared_key(SshIkev2Packet packet);

/** Complete the preshared key callback for the remote (preshared or EAP)
    key. This verifies the remote AUTH payload. */
void ikev2_reply_cb_shared_key_auth_verify(const unsigned char *key_out,
                                           size_t key_out_len,
                                           SshIkev2Packet packet);

/** Check that the auth payload is valid. */
void ikev2_check_auth_shared_key(SshIkev2Packet packet);

#ifdef SSHDIST_IKE_CERT_AUTH
/* *********************************************************************/
/** ikev2-pk-auth.c */
/** Do async operation to request CAs and add them to the
    outgoing packet as certificate request payloads. Moves to
    the error state in case of error, otherwise simply
    continues the thread and assumes that the next state is already
    set. */
void ikev2_add_certreq(SshIkev2Packet packet);

/** Do async operation to request certificates. Moves to the
    error state in case of error, otherwise simply continues
    the thread and assumes the next state is already set. */
void ikev2_add_certs(SshIkev2Packet packet);

/** Do async operation and sign the data and add AUTH payload
    to the packet. Moves to the error state in case of error,
    otherwise simply continues the thread and assumes the next
    state is already set. */
void ikev2_add_auth_public_key(SshIkev2Packet packet);

/** Check that the auth payload is valid. */
void ikev2_check_auth_public_key(SshIkev2Packet packet);

/** Verify the signature. */
void ikev2_check_auth_public_key_verify(SshIkev2Packet packet);
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_MOBIKE
/* Do async operation to request additional addresses
   and add them to the outgoing packet as additional address
   notifications. Moves to the error state in case of error, otherwise
   simply continues thread, and assumes the next state is already
   set. */
void ikev2_add_additional_addresses(SshIkev2Packet packet);

/** Generate and add a NO_NATS notify payload to the packet. */
void ikev2_add_no_nats_notify(SshIkev2Packet packet);

/** Generate and add a cookie2 notify payload to the packet. */
void ikev2_info_add_cookie2_notify(SshIkev2Packet packet);

/** Check for a NO_NATS notify payload and if present verify that it
    agrees with the addresses and ports in the packet. Returns
    SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED if a NO_NATS payload is present
    and its contents do not agree with the packet's addresses and ports. */
SshIkev2Error
ikev2_check_no_nats_notify(SshIkev2Packet packet);

/** Encodes MOBIKE specific fields of `sa'. This is called when the IKE SA
    is exported. */
SshIkev2Error
ikev2_mobike_encode(SshIkev2Sa sa, unsigned char **buf_ret, size_t *len_ret);

/** Decodes MOBIKE specific fields to `sa'. This is called when the IKE SA
    is imported. */
SshIkev2Error
ikev2_mobike_decode(SshIkev2Sa sa, unsigned char *buf, size_t len);

#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* *********************************************************************/
/** ikev2-multiple-auth.c */

/** Add MULTIPLE_AUTH_SUPPORTED notify payload for the IKEv2-packet. */
void
ikev2_add_multiple_auth_notify(SshIkev2Packet packet);

void
ikev2_add_another_auth_follows(SshIkev2Packet packet);

Boolean ikev2_check_multiple_auth(SshIkev2Packet packet);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


#ifdef SSHDIST_IKE_EAP_AUTH
/* *********************************************************************/
/** ikev2-eap-auth.c */
/** Do the async operation and get the EAP shared key from
    the other end and add AUTH payload to packet. Moves to
    the error state in case of an error, otherwise simply
    continues the thread and assumes that the next state is already
    set. Sets the eap_enabled to true if we cannot find key
    for the other end. */
void ikev2_add_auth_eap(SshIkev2Packet packet);

/** Do async operation to request EAP payload and add it to
    the outgoing packet. Moves to the error state in case of
    an error, otherwise simply continues the thread and assumes the
    next state is already set. */
void ikev2_add_eap(SshIkev2Packet packet);

/** Check that the auth payload is valid. */
void ikev2_check_auth_eap(SshIkev2Packet packet);
#endif /* SSHDIST_IKE_EAP_AUTH */

/* *********************************************************************/
/*  ikev2-nat-t.c */

/** Check for the NAT_DETECTION_*_IP notifies. If both NAT detection source
    and destination notifies are present, this sets *nat_t_enabled to TRUE,
    otherwise *nat_t_enabled is set to TRUE.

    If the SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP payload is present and
    does not match the remote IP and port of the packet, this sets *nat_source
    to TRUE, otherwise is set to FALSE.

    If SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP payload is present and
    does not match the local IP and port of the packet, this sets
    *nat_destination to TRUE, otherwise is set to FALSE.

    @return
    Returns FALSE in case of error and TRUE otherwise. */
Boolean ikev2_compute_nat_detection(SshIkev2Packet packet,
                                    Boolean use_responder_cookie,
                                    Boolean *nat_t_enabled,
                                    Boolean *nat_source,
                                    Boolean *nat_destination);

/** Calculate the hash used in the NAT_DETECTION_*_IP
    notifications. */
SshIkev2Error ikev2_calc_nat_detection(SshIpAddr ip,
                                       SshUInt16 port,
                                       const unsigned char *spi_i,
                                       const unsigned char *spi_r,
                                       unsigned char *digest,
                                       size_t *out_len);

/** Add NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP
    notifications to the exchange. */
void ikev2_add_nat_discovery_notify(SshIkev2Packet packet);

/** Check for the NAT_DETECTION_*_IP notifies and set the
    flags on the ike_sa based on those. */
void ikev2_check_nat_detection(SshIkev2Packet packet,
                               Boolean use_responder_cookie);

/** Check transport mode NAT-T traffic selectors. This that both traffic
    selectors contain only items with one IP address. On success this
    returns TRUE and the caller may safely call
    ikev2_transport_mode_natt_ts_substitute() to perform actual transport
    mode NAT-T traffic selector IP address substitution. */
Boolean
ikev2_transport_mode_natt_ts_check(SshIkev2ExchangeData ed);


/** Perform transport mode NAT-T traffic selector IP address substitution
    as specified in RFC5996 2.23.1. This also stores the NAT-T original
    IP addresses for the ends that are detected to be behind NAT. */
void
ikev2_transport_mode_natt_ts_substitute(SshIkev2ExchangeData ed,
                                        SshIkev2PayloadTS ts_local,
                                        SshIkev2PayloadTS ts_remote);

/* *********************************************************************/
/*  ikev2-crypto.c. */
/** Calculate IKE SA keying material. */
SshCryptoStatus ikev2_calculate_keys(SshIkev2Sa ike_sa,
                                     unsigned char *digest,
                                     size_t mac_len,
                                     SshIkev2PayloadNonce ni,
                                     SshIkev2PayloadNonce nr);

/** Start calculating ikev2_skeyseed. When the operation is
    finished, either restart the packet if we have it, or simply
    stop and wait for the packet. */
void ikev2_skeyseed(void *context);

/** Calculate IKE SA rekey keymat. */
SshCryptoStatus ikev2_calculate_rekey_skeyseed(SshIkev2ExchangeData ed);

/** Generate a stateless cookie based on the secret, nonce,
    spi_i and ip-address. */
SshIkev2Error ikev2_generate_cookie(SshIkev2Packet packet, SshIkev2Sa ike_sa,
                                    unsigned char *notify_data,
                                    size_t notify_len);

/** Generate the AUTH data to be signed or MACed. It consist
    of either remote or local packet, either initiator or
    responder Nonce and either initiator or responder ID
    payload. Return NULL if failure, otherwise return
    mallocated string to be used. */
unsigned char *
ikev2_auth_data(SshIkev2Packet packet,
                Boolean local_packet,
                Boolean initiator_nonce,
                Boolean initiator_id,
                size_t *return_len);

/* *********************************************************************/
/*  ikev2-common-info.c. */
/** Add delete payloads to informational exchange. */
void ikev2_info_add_delete(SshIkev2Packet packet);

/** Add notify payloads to informational exchange. */
void ikev2_info_add_notify(SshIkev2Packet packet);

/** Add conf payloads to informational exchange. */
void ikev2_info_add_conf(SshIkev2Packet packet);

/* *********************************************************************/
#ifdef SSHDIST_IKE_REDIRECT
/* Redirect */
/** Check whether this connection should be redirected. */
void ikev2_check_redirect(SshIkev2Packet packet);

/** Handle a valid redirect message */
void ikev2_redirected(SshIkev2Packet packet);

/** Create a redirect payload */
SshIkev2Error
ikev2_make_redirect_payload(SshIkev2Packet packet, SshBuffer buffer,
                            SshIkev2PayloadNonce nonce);

#endif /* SSHDIST_IKE_REDIRECT */

/* *********************************************************************/
/*  State machine functions for the IKE SA state machine. */

/** Decode packet. */
SSH_FSM_STEP(ikev2_state_decode);

/** Dispatch where to go next. */
SSH_FSM_STEP(ikev2_state_dispatch);

/** Error processing state. */
SSH_FSM_STEP(ikev2_state_error);

/** Send error notify. */
SSH_FSM_STEP(ikev2_state_send_error);

/** Send unprotected error notify. */
SSH_FSM_STEP(ikev2_state_send_unprotected_error);

/** Send message and destroy IKEv2 SA. */
SSH_FSM_STEP(ikev2_state_send_and_destroy);

/** This will now do the actual delete operation. */
SSH_FSM_STEP(ikev2_state_send_and_destroy_now);

/** Add notifies and vendor IDs. */
SSH_FSM_STEP(ikev2_state_responder_notify_vid);

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_responder_notify);

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_responder_vid);

/* Continue negotiation thread. */
SSH_FSM_STEP(ikev2_state_responder_notify_vid_continue);

/** Add notifies, vendor IDs, do encryption and send. */
SSH_FSM_STEP(ikev2_state_notify_vid_encrypt_send);

/** Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_notify);

/** Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_vid);

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_encrypt);

/** Send message. Note that the send function will steal the
   thread and packet, so we do not need to do anything for
   the thread or the packet. */
SSH_FSM_STEP(ikev2_state_send);

/* *********************************************************************/
/** Responder side IKE SA INIT packet in. */
SSH_FSM_STEP(ikev2_state_init_responder_in);

#ifdef SSHDIST_IKE_REDIRECT
/** Redirect client if redirecting is supported. */
SSH_FSM_STEP(ikev2_state_init_responder_in_redirect_start);
SSH_FSM_STEP(ikev2_state_init_responder_in_redirect);
#endif /* SSHDIST_IKE_REDIRECT */

/** Responder side IKE SA INIT packet, check if we have
    cookie, and if it is needed. */
SSH_FSM_STEP(ikev2_state_init_responder_in_cookie);

/** Do the SA payload processing, i.e. call to the Policy
    Manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_init_responder_in_sa);

/** Check the KE payload. It must match the selected proposal
    from the SA. */
SSH_FSM_STEP(ikev2_state_init_responder_in_ke);

/** Check the nonce. */
SSH_FSM_STEP(ikev2_state_init_responder_in_nonce);

/** Check the NAT-T notifies. */
SSH_FSM_STEP(ikev2_state_init_responder_in_nat_t);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* Check the multiple auth notify */
SSH_FSM_STEP(ikev2_state_init_initiator_in_multiple_auth);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_init_responder_in_end);

/** Request cookie from the other end. */
SSH_FSM_STEP(ikev2_state_init_responder_in_request_cookie);

/** Send INVALID_KE_PAYLOAD error with proper group. */
SSH_FSM_STEP(ikev2_state_init_responder_in_invalid_ke);

/* *********************************************************************/
/** Responder side IKE SA INIT packet out. */
SSH_FSM_STEP(ikev2_state_init_responder_out);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_init_responder_out_sa);

/** Do the Diffie-Hellman setup. */
SSH_FSM_STEP(ikev2_state_init_responder_out_dh_setup);

/** Add nonce payload. */
SSH_FSM_STEP(ikev2_state_init_responder_out_nonce);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Request CAs and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_certreq);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_notify);

/** Done with adding Notify payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_notify_done);

#ifdef SSHDIST_IKE_REDIRECT
/** Send redirect notify  */
SSH_FSM_STEP(ikev2_state_auth_responder_out_redirect);
#endif /* SSHDIST_IKE_REDIRECT */

/** Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_responder_out_vid);

/** Start the Diffie-Hellman agree from the bottom of event
   loop, so it will not slow down the process here, but so
   that it should be ready when the packet comes back here. */
SSH_FSM_STEP(ikev2_state_init_responder_out_dh_agree_start);

/** Send cookie request out. */
SSH_FSM_STEP(ikev2_state_request_cookie_out);

#ifdef SSHDIST_IKE_REDIRECT
/** Send redirect notify out. */
SSH_FSM_STEP(ikev2_state_redirect_out);
#endif /* SSHDIST_IKE_REDIRECT */


/* *********************************************************************/
/** Send INVALID_KE_PAYLOAD error out. */
SSH_FSM_STEP(ikev2_state_ke_error_out);

/** Send invalid KE error out. */
SSH_FSM_STEP(ikev2_state_reply_ke_error_out);

/* *********************************************************************/
/** Initiator side IKE SA INIT packet in. */
SSH_FSM_STEP(ikev2_state_init_initiator_in);

/** Check for COOKIE or INVALID_KE_PAYLOAD payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_notify);

/** Notify found, restart from the beginning. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_restart);

#ifdef SSHDIST_IKE_REDIRECT
/** We have been redirected, finish current negotiation */
SSH_FSM_STEP(ikev2_state_init_initiator_in_redirected);
#endif /* SSHDIST_IKE_REDIRECT */

/** Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ike_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_sa);

/** Check the KE payload. It must match the selected proposal
   from the SA, and also the group we selected when sending
   our KE payload out. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_ke);

/** Check the nonce. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_nonce);

/** Check the NAT-T notifies. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_nat_t);

/** Input processing done, start output processing of the next packet. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_end);

/* *********************************************************************/
/** Initiator side IKE SA INIT packet out. */
SSH_FSM_STEP(ikev2_state_init_initiator_out);

/** Check if we have a cookie from the other end, and if so, add it
   to the packet. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_cookie);

/** Fill in the SA payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_fill_sa);

/** Add the SA payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_sa);

/** Do the Diffie-Hellman setup. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_dh_setup);

/** Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_nonce);

/** Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_notify);

/** Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_vid);

/** Encode packet and sent it. */
SSH_FSM_STEP(ikev2_state_init_initiator_out_done);

/* *********************************************************************/
/** Initiator side IKE AUTH packet out. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out);

/** Add IDi payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_idi);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Add optional CERT payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_cert);

/** Add optional CERTREQ payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_certreq);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Add optional IDr payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_idr);

/** Check auth type. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_check);

#ifdef SSHDIST_IKE_EAP_AUTH
/** Add AUTH payload based on EAP keys. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_eap);
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
/** Add AUTH payload based on signature. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_pk);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Fetch shared key. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_shared_key);

/** Auth payload is done. Now see whether we were doing EAP - if yes,
   we have the packet ready, otherwise continue normal
   processing. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_done);

/** Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_alloc_sa);

/** Add optional CP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_cp);

/** Fill the SA payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_fill_sa);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_sa);

/** Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_ts);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap_another_auth);

SSH_FSM_STEP(ikev2_state_auth_initiator_out_multiple_auth);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_MOBIKE
/** Do port floating or add NO_NATS_ALLOWED notify payload for MOBIKE
    enabled SA's . */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_mobike_add_nat_notifies);

/** Add MOBIKE_SUPPORTED and additional addresses notify payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_mobike_add_additional_addrs);
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_IKE_EAP_AUTH
/** Send out EAP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap);

/** Check if EAP is done. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap_check);
#endif /* SSHDIST_IKE_EAP_AUTH */


#ifdef SSH_IKEV2_MULTIPLE_AUTH
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_check_auth);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_shared_key);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_eap);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_in_end);

SSH_FSM_STEP(ikev2_state_second_auth_initiator_out);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_eap);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_eap_check);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_auth_eap);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_id);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_check);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_cert);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_auth_check);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_auth_pk);
SSH_FSM_STEP(ikev2_state_second_auth_initiator_out_auth);

/** Responder secondary authentication states: */
SSH_FSM_STEP(ikev2_state_second_auth_responder_in);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_check_auth);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_shared_key);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_public_key);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_verify_signature);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_alloc_sa);
SSH_FSM_STEP(ikev2_state_second_auth_responder_in_end);

SSH_FSM_STEP(ikev2_state_second_auth_responder_out);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_auth_eap);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_auth_done);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_cp);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_select_sa);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_narrow_ts);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_sa);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_ts);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_eap);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_eap_check);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_error_notify);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_notify);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_notify_done);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_mobike);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_vid);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_install);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_install_done);
SSH_FSM_STEP(ikev2_state_second_auth_responder_out_encrypt);

#endif /* SSH_IKEV2_MULTIPLE_AUTH */


/* *********************************************************************/
/** Initiator side IKE AUTH packet in. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in);

/** Initiator side IKE SA INIT packet, check if we have AUTH
   payload, and its type. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_check_auth);

/** Verify shared key AUTH payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_shared_key);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Get public key. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_public_key);

/** Verify signature. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_verify_signature);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Check for EAP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_eap);

/** Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_sa);

/** Check the traffic selectors. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_ts);

#ifdef SSHDIST_IKE_REDIRECT
/** Redirect processing */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_redirect);
#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IKE_EAP_AUTH
/** Input processing is done, start output processing. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_end);
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/** First AUTH processing done, start second */
SSH_FSM_STEP(ikev2_state_auth_initiator_first_auth_in_end);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

/** SA exchange done. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_done);

/** Finish the exchange. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_finish);

/* *********************************************************************/
/** Responder side IKE AUTH packet in. */
SSH_FSM_STEP(ikev2_state_auth_responder_in);

/** Responder side IKE SA INIT packet, check if we have AUTH
   payload, and its type. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_check_auth);

/** Verify the shared key AUTH payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_shared_key);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Get public key. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_public_key);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Verify the signature. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_verify_signature);

/** Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_alloc_sa);

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_auth_responder_in_end);

/* *********************************************************************/
/** Responder side IKE AUTH packet out. */
SSH_FSM_STEP(ikev2_state_auth_responder_out);

/** Add IDr payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_idr);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Add optional CERT payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_cert);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Check auth type. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_check);

#ifdef SSHDIST_IKE_EAP_AUTH
/** Add AUTH payload based on EAP keys. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_eap);
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
/** Add AUTH payload based on signature. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_pk);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Fetch shared key. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_shared_key);

/** Check if we had auth payload from the other end. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_done);

/** Add optional CP payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_cp);

/* Do the SA payload processing, i.e. call to the policy
   manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_select_sa);

/* Narrow the traffic selector. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_narrow_ts);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_sa);

/** Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_ts);

#ifdef SSHDIST_IKE_MOBIKE
/* Add optional additional address notifies for MOBIKE enabled SA's . */
SSH_FSM_STEP(ikev2_state_auth_responder_out_mobike);
#endif /* SSHDIST_IKE_MOBIKE */

/** Send error notify about the IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_error_notify);

/** Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_notify);

/** Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_vid);

#ifdef SSHDIST_IKE_EAP_AUTH
/** Request EAP payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_eap);

/** Check if EAP is done. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_eap_check);
#endif /* SSHDIST_IKE_EAP_AUTH */

/** Install IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_install);

/** Call done callbacks. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_install_done);

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_encrypt);

/* *********************************************************************/
/** Initiator side CREATE_CHILD packet out. */
SSH_FSM_STEP(ikev2_state_child_initiator_out);

/** Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_alloc_sa);

/** Fill the SA payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_fill_sa);

/** Add optional rekey notify payload */
SSH_FSM_STEP(ikev2_state_child_initiator_out_rekey_n);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_sa);

/** Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_nonce);

/** Add KE payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_ke);

/** Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_ts);

/* *********************************************************************/
/** Responder side CREATE_CHILD packet in. */
SSH_FSM_STEP(ikev2_state_child_responder_in);

/** Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_child_responder_in_alloc_sa);

/** Responder side CREATE CHILD packet, check if we have
   REKEY notify payload. */
SSH_FSM_STEP(ikev2_state_child_responder_in_check_rekey);

/** Do the SA payload processing, i.e. call to the Policy
   Manager SPD select IKE SA function. */
SSH_FSM_STEP(ikev2_state_child_responder_in_sa);

/** Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_nonce);

/** Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_ke);

/** Narrow the traffic selector. */
SSH_FSM_STEP(ikev2_state_child_responder_in_ts);

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_child_responder_in_end);

/** Send INVALID_KE_PAYLOAD error with proper group. */
SSH_FSM_STEP(ikev2_state_child_responder_in_invalid_ke);

/* *********************************************************************/
/** Responder side CREATE_CHILD packet out. */
SSH_FSM_STEP(ikev2_state_child_responder_out);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_sa);

/** Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_nonce);

/** Add KE payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_ke);

/** Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_child_responder_out_ts);

/** Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_child_responder_out_agree);

/** Install IPsec SA. */
SSH_FSM_STEP(ikev2_state_child_responder_out_install);

/** Call done callbacks. */
SSH_FSM_STEP(ikev2_state_child_responder_out_install_done);

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_child_responder_out_encrypt);

/* *********************************************************************/
/** Initiator side CREATE_CHILD packet in. */
SSH_FSM_STEP(ikev2_state_child_initiator_in);

/** Do the SA payload processing, i.e. verify that the
    returned SA matches our proposal. This will also fill in
    the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_sa);

/** Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_nonce);

/** Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_ke);

/** Check the traffic selectors. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_ts);

/** Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_agree);

/** SA exchange done. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_done);

/** Finish the exchange. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_finish);

/* *********************************************************************/
/** Start CREATE_CHILD state for IKE SA rekey. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out);

/** Allocate new IKE SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_alloc_sa);

/** Fill the SA payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_fill_sa);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_sa);

/** Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_nonce);

/** Add KE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_ke);

/* *********************************************************************/
/** Responder side CREATE CHILD packet in. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in);

/** Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_alloc_sa);

/** Do the SA payload processing, i.e. call to the Policy
   Manager SPD select IKE SA function. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_sa);

/** Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_nonce);

/** Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_ke);

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_end);

/** Send INVALID_KE_PAYLOAD error with the proper group. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_invalid_ke);

/* *********************************************************************/
/** Start CREATE_CHILD_SA IKE SA rekey state. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out);

/** Add SA payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_sa);

/** Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_nonce);

/** Add KE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_ke);

/** Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_agree);

/** Install IPsec SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_install);

/** Move from old IKE SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_move_from_old);

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_encrypt);

/* *********************************************************************/
/** Initiator side CREATE_CHILD_SA packet in. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in);

/** Do the SA payload processing, i.e. verify that the
    returned SA matches our proposal. This will also fill in
    the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_sa);

/** Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_nonce);

/** Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_ke);

/** Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_agree);

/** Rekey exchange done. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_done);

/** Rekey, move from old one. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_move_from_old);

/** Finish the exchange. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_finish);

/* *********************************************************************/
/** Initiator side INFORMATIONAL packet out. */
SSH_FSM_STEP(ikev2_state_info_initiator_out);

/** Add delete payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_delete);

/** Add notify payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_notify);

/** Add conf payload. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_add_conf);

#ifdef SSHDIST_IKE_MOBIKE
/** Add MOBIKE cookie2 notify */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_cookie2);

/** Add NAT-D or NO_NATS_ALLOWED notify */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_nat_notifies);

/** Add additional addresses */
SSH_FSM_STEP(ikev2_state_info_initiator_out_mobike_add_additional_addrs);
#endif /* SSHDIST_IKE_MOBIKE */

/** Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_vid);

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_info_initiator_out_encrypt);

/* *********************************************************************/
/** Responder side INFORMATIONAL packet in. */
SSH_FSM_STEP(ikev2_state_info_responder_in);

/** Check for notify payloads */
SSH_FSM_STEP(ikev2_state_info_responder_in_check_notify);

/** Check for delete payloads */
SSH_FSM_STEP(ikev2_state_info_responder_in_check_delete);

/** Check NAT discovery payloads if present */
SSH_FSM_STEP(ikev2_state_info_responder_in_check_nat);

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_info_responder_in_end);

/* *********************************************************************/
/** Responder side INFORMATIONAL packet out. */
SSH_FSM_STEP(ikev2_state_info_responder_out);

/** Add delete payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_delete);

/** Add notify payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_notify);

/** Add conf payload. */
SSH_FSM_STEP(ikev2_state_info_responder_out_add_conf);

#ifdef SSHDIST_IKE_MOBIKE
/** Add MOBIKE related notifies */
SSH_FSM_STEP(ikev2_state_info_responder_out_mobike);
#endif /* SSHDIST_IKE_MOBIKE */

/** Encrypt packet. */
SSH_FSM_STEP(ikev2_state_info_responder_out_encrypt);

/* *********************************************************************/
/** Initiator side INFORMATIONAL packet in. */
SSH_FSM_STEP(ikev2_state_info_initiator_in);

#ifdef SSHDIST_IKE_MOBIKE
/* Check COOKIE 2 */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_cookie2);

/** Check NAT discovery payloads */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_natt);
#endif /* SSHDIST_IKE_MOBIKE */

/** Check for notify payloads */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_notify);

/** Check for delete payloads */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_delete);

/** Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_info_initiator_in_end);

/* *********************************************************************/
/** Other step functions. */
SSH_FSM_STEP(ikev2_packet_st_input_start);
SSH_FSM_STEP(ikev2_packet_st_connect_decision);
SSH_FSM_STEP(ikev2_packet_st_allocated);
SSH_FSM_STEP(ikev2_packet_st_input_get_or_create_sa);
#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ikev2_packet_st_input_v1_get_or_create_sa);
#endif /* SSHDIST_IKEV1 */
SSH_FSM_STEP(ikev2_packet_st_forward);
SSH_FSM_STEP(ikev2_packet_st_verify);
SSH_FSM_STEP(ikev2_packet_st_done);

#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(ikev2_packet_v1_start);
#endif /* SSHDIST_IKEV1 */

SSH_FSM_STEP(ikev2_packet_st_send);
SSH_FSM_STEP(ikev2_packet_st_send_done);


/* *********************************************************************/
/** Debug macros. This assumes there is a packet structure in
   the local context. These are copied from the sshdebug.h file. */

/** Outputs a debug message. This macro is always compiled into the binary. */
#define SSH_IKEV2_TRACE(level, pckt, varcall)                         \
  do                                                                    \
  {                                                                     \
    if (SSH_TRACE_ENABLED(level))                                       \
      {                                                                 \
        char *__tmp;                                                    \
        __tmp = ssh_debug_format varcall;                               \
        ssh_debug_output((level), __FILE__, __LINE__, SSH_DEBUG_MODULE, \
                         SSH_DEBUG_FUNCTION,                            \
                         ssh_debug_format("[%p/%p] %s",                 \
                                          (pckt), (pckt)->ike_sa,       \
                                          __tmp));                      \
        ssh_free(__tmp);                                                \
      }                                                                 \
  }                                                                     \
  while (0)

#define SSH_IKEV2_TRACE_HEX(level, pckt, varcall, len, buf)             \
  do                                                                    \
  {                                                                     \
    if (SSH_TRACE_ENABLED(level))                                       \
      {                                                                 \
        char *__tmp;                                                    \
        __tmp = ssh_debug_format varcall;                               \
        ssh_debug_output((level), __FILE__, __LINE__, SSH_DEBUG_MODULE, \
                         SSH_DEBUG_FUNCTION,                            \
                         ssh_debug_format("[%p/%p] %s %.*@",            \
                                          (pckt), (pckt)->ike_sa, __tmp,\
                                          len, ssh_hex_render, buf));   \
        ssh_free(__tmp);                                                \
      }                                                                 \
  }                                                                     \
  while (0)

/** SSH_DEBUG is compiled in only if DEBUG_LIGHT is defined. */
#ifdef DEBUG_LIGHT
#define SSH_IKEV2_DEBUG(level, varcall) \
        SSH_IKEV2_TRACE((level), packet, varcall)
#define SSH_IKEV2_DEBUG_HEX(level, varcall, len, buf) \
        SSH_IKEV2_TRACE_HEX((level), packet, varcall, len, buf)
#else
#define SSH_IKEV2_DEBUG(level, varcall) do {} while (0)
#define SSH_IKEV2_DEBUG_HEX(level, varcall, len, buf) do {} while (0)
#endif

/** Prints out RFC-style description of IKEv2 packet via SSH_DEBUG */
void ikev2_list_packet_payloads(SshIkev2Packet packet,
                                unsigned char *buffer,
                                size_t buffer_len,
                                SshIkev2PayloadType first_payload,
                                Boolean is_sending);

#define SSH_IKEV2_DEBUG_ENCODE(packet, ...) \
  do { \
    ikev2_debug_encode_payload(packet, __VA_ARGS__); \
    SSH_IKEV2_DEBUG(SSH_D_PCKDMP, (__VA_ARGS__)); \
  } while (0);

#define SSH_IKEV2_DEBUG_DECODE(packet, ...) \
  do { \
    ikev2_debug_decode_payload(packet, __VA_ARGS__); \
    SSH_IKEV2_DEBUG(SSH_D_PCKDMP, (__VA_ARGS__)); \
  } while (0);

#define SSH_IKEV2_DEBUG_DECODE_HEX(packet, len, buf, ...) \
  do { \
    ikev2_debug_decode_payload_hex(packet, buf, len, __VA_ARGS__); \
    SSH_IKEV2_DEBUG_HEX(SSH_D_PCKDMP, (__VA_ARGS__), len, buf); \
  } while (0);

#endif /* SSH_IKEV2_INTERNAL_H */
