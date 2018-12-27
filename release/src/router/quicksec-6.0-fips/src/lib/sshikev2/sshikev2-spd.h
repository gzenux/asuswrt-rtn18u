/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface functions to Security Policy Database (SPD).
*/

#ifndef SSH_IKEV2_SPD_H
#define SSH_IKEV2_SPD_H

/*--------------------------------------------------------------------*/
/** Fill in the IKE/IPsec SA parameters for an outgoing SA.
    Policy Manager gives the references to PayloadSA to the
    IKE library. The IKE library will not modify or change
    the payload. The caller must make sure that the payload
    is not modified during the length of this
    exchange. After the the exchange is done, the IKEv2
    library will release the reference it has to the SA
    payload. */
typedef void
(*SshIkev2SpdFillSACB)(SshIkev2Error error_code,
                       SshIkev2PayloadSA sa,
                       void *context);

/** Fill in the SA parameters for an outgoing IKE SA. */
typedef SshOperationHandle
(*SshIkev2SpdFillIkeSa)(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2SpdFillSACB reply_callback,
                        void *reply_callback_context);

/** Fill in the SA parameters for an outgoing IPsec SA. Note
    that SSH_IKEV2_TRANSFORM_TYPE_D_H cannot be set when
    negotiating the IPsec SA during the initial exchange. It
    can be returned in case PFS is needed for separate
    CREATE_CHILD_SA exchanges. */
typedef SshOperationHandle
(*SshIkev2SpdFillIPsecSa)(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2SpdFillSACB reply_callback,
                          void *reply_callback_context);

/*--------------------------------------------------------------------*/
/** Select the IKE/IPsec SA parameters from the SA payload.
    The selected_transforms argument is an array of
    transforms pointer, one item per each type, and the
    pointers point to sa_in to the selected transform.

    Note that all transforms selected must be from the same proposal,
    i.e proposal_index must be the same in all transforms. The array
    can be freed immediately when this function returns, but the
    actual items where the data points must remain same (if they are
    from sa_in payload, then this is ensured by IKEv2 library).

    @param proposal_index
    The index to the protocol_id / number_of_transforms /
    proposals arrays in SA payload structure.

    @return
    If there is no proposal acceptable, then this returns error_code
    SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN. In that case proposal_index is
    ignored and selected_transforms can be NULL. */
typedef void
(*SshIkev2SpdSelectSACB)(SshIkev2Error error_code,
                         int proposal_index,
                         SshIkev2PayloadTransform
                         selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                         void *context);

/** Select the SA parameters for incoming IKE SA. */
typedef SshOperationHandle
(*SshIkev2SpdSelectIkeSa)(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2PayloadSA sa_in,
                          SshIkev2SpdSelectSACB reply_callback,
                          void *reply_callback_context);

/** Select the SA parameters for incoming IPsec SA. */
typedef SshOperationHandle
(*SshIkev2SpdSelectIPsecSa)(SshSADHandle sad_handle,
                            SshIkev2ExchangeData ed,
                            SshIkev2PayloadSA sa_in,
                            SshIkev2SpdSelectSACB reply_callback,
                            void *reply_callback_context);


/*--------------------------------------------------------------------*/
/** Narrow the traffic selectors to be acceptable for the
    policy. The return_ts_local and return_ts_remote must
    stay intact during the rest of this negotiation. This
    function takes one reference to them, and that reference
    is freed when the exchange finishes. The caller of this
    function can remove its own reference immediately after
    calling the callback.

    The return_ts_local and return_ts_remote values can be
    NULL, in which case we do not narrow down the selection
    (i.e keep the original traffic selectors). Remember that
    the first entry in the traffic selector list must be
    inside the narrowed traffic selector.

    In case of rekey, the new narrowed traffic selectors
    should also consult the traffic selectors for the old
    IPsec SA, and try to make sure that as much as possible
    of the traffic selectors of the old SA fits in the new
    narrowed traffic selectors.

    Use the ssh_ikev2_ts_allocate / ssh_ikev2_ts_item_delete
    / ssh_ikev2_ts_dup / ssh_ikev2_ts_free functions to work
    with traffic selectors. I.e ssh_ikev2_ts_allocate, to
    allocate new traffic selector structure, or
    ssh_ikev2_ts_dup to duplicate the data from incoming
    traffic selector, and ssh_ikev2_ts_item_delete to remove
    entry from the list, etc. */
typedef void
(*SshIkev2SpdNarrowCB)(SshIkev2Error error_code,
                       SshIkev2PayloadTS return_ts_local,
                       SshIkev2PayloadTS return_ts_remote,
                       void *context);

/** Narrow traffic selectors to be returned back. Use the
    ssh_ikev2_ts_allocate / ssh_ikev2_ts_dup /
    ssh_ikev2_ts_item_delete / ssh_ikev2_ts_free functions
    to work with traffic selectors.

    @param ts_in_local
    This end's traffic selector to be narrowed down. As this
    function is called in the responder, it will be TSr from
    the IKE packets.

    @param ts_in_remote
    The remote end's (initiator's) traffic selector. */
typedef SshOperationHandle
(*SshIkev2SpdNarrow)(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2PayloadTS ts_in_local,
                     SshIkev2PayloadTS ts_in_remote,
                     SshIkev2SpdNarrowCB reply_callback,
                     void *reply_callback_context);

/*--------------------------------------------------------------------*/
/** Request notification payload to be sent to the other
    end.  This can be called multiple time to add multiple
    notify payloads.

    If the notify_message_type value is 0, then no more notify
    payloads will be added and normal processing should be continued.
    If this is called with an error code, then no more calls should be
    done to this function, but the operation will move to the error
    state, and continue from there to finish the exchange with error.
    */
typedef void
(*SshIkev2SpdNotifyCB)(SshIkev2Error error_code,
                       SshIkev2ProtocolIdentifiers protocol_id,
                       unsigned char *spi,
                       size_t spi_size,
                       SshIkev2NotifyMessageType notify_message_type,
                       unsigned char *notification_data,
                       size_t notification_data_size,
                       void *context);

/** Request notification payload to be set to the other end.
    Note that the reply callback can be called multiple
    times, once per each notify to be added, and then once
    more with notify_message_type set to zero to indicate
    that no more notifications are added. */
typedef SshOperationHandle
(*SshIkev2SpdNotifyRequest)(SshSADHandle sad_handle,
                            SshIkev2ExchangeData ed,
                            SshIkev2SpdNotifyCB reply_callback,
                            void *reply_callback_context);

/*--------------------------------------------------------------------*/

typedef enum {
  /* The notify is authenticated, called when a packet is received. */
  SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL = 0,

  /* The notify is authenticated, called when an exchange is completed. */
  SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_FINAL = 1,

  /* The notify is unauthenticated, called when a packet is received. */
  SSH_IKEV2_NOTIFY_STATE_UNAUTHENTICATED_INITIAL = 2,

  /* The notify is unauthenticated, called when an exchange is completed. */
  SSH_IKEV2_NOTIFY_STATE_UNAUTHENTICATED_FINAL = 3

} SshIkev2NotifyState;




/** Received notification from the other end inside the IKE
    SA, either as inside the IKE SA initial exchange, or
    CREATE_CHILD_SA or separate INFORMATIONAL exchange. */
typedef void
(*SshIkev2SpdNotifyReceived)(SshSADHandle sad_handle,
                             SshIkev2NotifyState notify_state,
                             SshIkev2ExchangeData ed,
                             SshIkev2ProtocolIdentifiers protocol_id,
                             unsigned char *spi,
                             size_t spi_size,
                             SshIkev2NotifyMessageType notify_message_type,
                             unsigned char *notification_data,
                             size_t notification_data_size);


/** Responder exchange has completed. */
typedef void
(*SshIkev2SpdResponderExchangeDone)(SshSADHandle sad_handle,
                                    SshIkev2Error error,
                                    SshIkev2ExchangeData ed);
#endif /* SSH_IKEV2_SPD_H */
