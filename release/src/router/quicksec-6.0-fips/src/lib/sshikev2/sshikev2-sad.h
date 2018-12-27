/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface functions to Security Association Database (SAD).
*/

#ifndef SSH_IKEV2_SAD_H
#define SSH_IKEV2_SAD_H

/*--------------------------------------------------------------------*/
/** Return the allocated SshIkev2Sa. The reference is only
    valid during this call. If it is needed after that, this
    function should take its own reference. */
typedef void
(*SshIkev2SadIkeSaAllocateCB)(SshIkev2Error error_code, /** Error code. */
                              /** Security Association. */
                              SshIkev2Sa sa,
                              /** Context. */
                              void *context);

/** Allocate a new IKE SA. This will automatically allocate
    a new IKE SA SPI for the IKE SA, too. */
typedef SshOperationHandle
(*SshIkev2SadIkeSaAllocate)(SshSADHandle sad_handle, /** SAD handle. */
                            /** Initiator. */
                            Boolean initiator,
                            /** Reply callback. */
                            SshIkev2SadIkeSaAllocateCB reply_callback,
                            /** Reply context. */
                            void *reply_context);

/*--------------------------------------------------------------------*/
/** Return the allocated IPsec Security Parameter Index (SPI).

    In case of an error, set the error code to something else
    than SSH_IKEV2_ERROR_OK and set the SPI value to zero, unless
    you want the SshIkev2SadIPsecSaDone and SshIkev2SadIPsecSpiDelete
    functions to be called. I.e. if the error is such that
    SshIkev2SadIPsecSaDone should be called with this same
    error code, then return error and set SPI to non-zero.
    The library will then call SshIkev2SadIPsecSaDone and
    SshIkev2SadIPsecSpiDelete when deleting the exchange. */
typedef void
(*SshIkev2SadIPsecSpiAllocateCB)(SshIkev2Error error_code, /** Error code. */
                                /** Security Parameters Index. */
                                 SshUInt32 spi,
                                /** Context. */
                                 void *context);

/** Allocate a new IPsec SA SPI. */
typedef SshOperationHandle
(*SshIkev2SadIPsecSpiAllocate)(SshSADHandle sad_handle, /* SAD handle. */
                               SshIkev2ExchangeData ed, /* Exchange data. */
                               /** Reply callback. */
                               SshIkev2SadIPsecSpiAllocateCB reply_cb,
                               /** Reply context. */
                               void *reply_context);

/*--------------------------------------------------------------------*/
/** The SA requested to be deleted has been deleted. This is
    called after the actual delete, which might happen much
    later if there were references out there. */
typedef void
(*SshIkev2SadDeleteCB)(SshIkev2Error error_code,        /* Error code. */
                       void *context);                  /* Context. */

/** A function inside the IKE library which Policy Manager
    should use to uninitialize the IKE SA after all
    references to it have been freed. This will free the IKE
    SA allocated data (like sk_d and windows) before
    Policy Manager actually frees the data.

    This function can be called multiple times, for example for the
    first time when the IKE SA is started to be deleted in order to
    clear out the retransmission windows (we cannot process packets to
    the SA after we call this), and then again when the actual free
    happens. */

void ssh_ikev2_ike_sa_uninit(SshIkev2Sa ike_sa);

/** Request an IKE SA to be deleted from the Security
    Association Database (SAD).

    This function is called after a delete notification has been sent
    and an ack received or a delete notification has been received and
    an ack sent (and the timeout for retranmissions has passed), or
    after the DPD decides that the other end is dead. All IPsec SAs
    are deleted along the IKE SA.

    This will automatically decrement one reference from SshIkev2Sa,
    and the IKE SA given to this function cannot be used by the caller
    after this call (unless the caller has other references). */

typedef SshOperationHandle
(*SshIkev2SadIkeSaDelete)(SshSADHandle sad_handle, /** SAD handle. */
                          /** Security Association. */
                          SshIkev2Sa sa,
                          /** Reply callback. */
                          SshIkev2SadDeleteCB reply_callback,
                          /** Reply context. */
                          void *reply_context);

/** Request an IPsec SA SPI to be deleted from the SAD.

    This function is called to free up the SPI allocated with
    IPsecSpiAllocate in case the exchange ended with error, and no
    IPsecSaInstall will be called.

    This function is called only if the IPsecSpiAllocate returned a
    non-zero SPI. */

typedef void
(*SshIkev2SadIPsecSpiDelete)(SshSADHandle sad_handle, /** SAD handle. */
                             /** Security Parameter Index. */
                             SshUInt32 spi);

/*--------------------------------------------------------------------*/
/** Return the SPIs to the other direction to the SAs which
    were requested to be deleted.

    Note that the number of SPIs does not have to match the ones given
    to SpiDeleteReceived. The contents of spi_array are copied during
    this call. */

typedef void
(*SshIkev2SadDeleteReceivedCB)(SshIkev2Error error_code, /** Error code. */
                               /** Protocol. */
                               SshIkev2ProtocolIdentifiers protocol,
                               /** Number of Security Parameter Indices. */
                               int number_of_spis,
                               /** SPI array. */
                               SshUInt32 *spi_array,
                               /** Context. */
                               void *context);

/** Received a delete payload from the other end. This
    requests all given IPsec SAs to be deleted.

    If the reply_context value is not NULL, then it can be used to
    include a return list of SPIs to be sent to the other end. This
    will be called once per each delete payload.

    @return
    The return list should include the SPIs of the other direction
    matching the ones received here, but only if we haven't
    already sent delete for them. I.e. first mark that this SA has
    already been sent a delete notification, then send delete
    notifications, and then when receiving the delete notification
    deleting the SPI of the other direction on SAs which have the
    delete sent flag on, then delete the SA completely.

    If the reply_callback value is NULL, it means that this is
    already their response to our delete, thus there is no way we
    can send any more SPIs to the other direction. On the other
    hand in that case, if the other end is implemented correctly
    we shouldn't receive any other SPIs than the corresponding pairs
    of the ones we have already sent, thus there should not be any
    need to send any more SPIs. If the other end added SPIs that we
    didn't include, then Policy Manager should tear down the IKE SA,
    or send deletes for them as a separate informational exchange. */

typedef SshOperationHandle
(*SshIkev2SadIPsecSpiDeleteReceived)(SshSADHandle sad_handle,/**SAD handle.*/
                                     /** Exchange data. */
                                     SshIkev2ExchangeData ed,
                                     /** Protocol. */
                                     SshIkev2ProtocolIdentifiers protocol,
                                     /** Number of SPIs.*/
                                     int number_of_spis,
                                     /** SPI array. */
                                     SshUInt32 *spi_array,
                                     /** Reply callback. */
                                     SshIkev2SadDeleteReceivedCB
                                     reply_callback,
                                     /** Reply context. */
                                     void *reply_context);

/*--------------------------------------------------------------------*/
/** This function is called after the rekey of the SA has
    been registered to the database and taken into
    use. After this the old SA is still valid until deleted,
    but no other operation is done to the SA except
    delete. */

typedef void
(*SshIkev2SadRekeyedCB)(SshIkev2Error error_code, /* Error code. */
                        void *context);           /* Context. */

/** Inform that the IKE SA has been rekeyed. This means that
    all IPsec SAs are to be moved during this call from the
    old IKE SA to the new IKE SA.

    @param delete_old
    If delete_old is TRUE, then Policy Manager needs to delete the
    old_sa after some suitable timeout. If the delete_old is FALSE,
    then it is assumed that the other end of the negotiation will
    delete the old_sa.

    Only the IPsec SAs are moved during this call, the old_sa
    value is otherwise left untouched. */

typedef SshOperationHandle
(*SshIkev2SadIkeSaRekey)(SshSADHandle sad_handle, /** SAD handle. */
                         /** Delete old_sa after timeout period? */
                         Boolean delete_old,
                         /** Old Security Association.*/
                         SshIkev2Sa old_sa,
                         /** New Security Association.*/
                         SshIkev2Sa new_sa,
                         /** Reply callback.*/
                         SshIkev2SadRekeyedCB reply_callback,
                         /** Reply context.*/
                         void *reply_context);

/*--------------------------------------------------------------------*/
/*  Get and put functions. */

/** A return callback to return the IKE SA requested. If no
    SA is found, then SA is set to NULL, and the error_code
    value is SSH_IKEV2_ERROR_OK. */
typedef void
(*SshIkev2SadIkeSaGetCB)(SshIkev2Error error_code, /** Error code. */
                         /** Security Association. */
                         SshIkev2Sa sa,
                         /** Context. */
                         void *context);

/** Get IKE SA based on IKE SPI. This starts a new operation
    for the IKE SA, and after that the IKE SA can be
    modified, and it will automatically have one reference.

    To take more references, call
    SshIkev2SadIkeSaTakeRef. To free references, call
    SshIkev2SadIkeSaFreeRef. */
typedef SshOperationHandle
(*SshIkev2SadIkeSaGet)(SshSADHandle sad_handle, /** SAD handle. */
                       /** IKE Protocol Major Version */
                       const SshUInt32 ike_version,
                       /** IKE Security Association Initiator SPI. */
                       const unsigned char *ike_sa_spi_i,
                       /** IKE Security Association Responder SPI. */
                       const unsigned char *ike_sa_spi_r,
                       /** Reply callback. */
                       SshIkev2SadIkeSaGetCB reply_callback,
                       /** Reply context. */
                       void *reply_context);

/** Take reference to the IKE SA. */
typedef void
(*SshIkev2SadIkeSaTakeRef)(SshSADHandle sad_handle, /* SAD handle. */
                           SshIkev2Sa sa); /* Security Association. */

/** Free one reference to the IKE SA. If this was the last
    reference, then the IKE SA can be deleted in case a
    delete has been requested for the SA.

    The actual freeing of IKE SA needs to be done from the bottom of
    the event loop. */

typedef void
(*SshIkev2SadIkeSaFreeRef)(SshSADHandle sad_handle, /* SAD handle. */
                           SshIkev2Sa sa); /* Security Association. */

/** Allocate exchange context. The IKE library calls this
    when it needs an exchange context to be allocated. This
    should allocate one obstack and store the obstack
    pointer to the SshIkev2ExchangeData obstack field. The
    IKEv2 library will then initialize the rest of the
    exchange data.

    @return
    This returns NULL if alloc fails. */
typedef SshIkev2ExchangeData
(*SshIkev2SadExchangeDataAlloc)(SshSADHandle sad_handle, /* SAD handle. */
                                SshIkev2Sa sa); /* Security Association. */

/** Free the exchange context. The IKE library calls this
    when it needs to free the exchange context. It has
    already uninitialized the exchange data from its own
    parts before calling this function. */
typedef void
(*SshIkev2SadExchangeDataFree)(SshSADHandle sad_handle, /** SAD handle. */
                                /** Exchange data. */
                                SshIkev2ExchangeData exchange_data);

/*--------------------------------------------------------------------*/
/*  Enumerate IKE SAs interface. */

/** A function called during an enumerate operation for each
    IKE SA.

    After all SAs have been processed, this function will be called
    once more, with the sa value set to NULL. If an error occurs
    during the enumeration, then error_code is set, and no more calls
    to this function are going to happen.

    Note: The enumerate_callback callback MUST NOT modify or change
    the IKE SA in any way. This includes deleting the SA, i.e. if it
    wants to delete the SA, it needs to install a timeout and delete
    the SA from there.  It also gets a temporary reference to the
    object during all of this function, but if it needs to do
    something later, it must take its own reference. */

typedef void
(*SshIkev2SadIkeSaEnumerateCB)(SshIkev2Error error_code, /* Error code. */
                               SshIkev2Sa sa, /* Security Association. */
                               void *context); /* Context. */

/** Call the enumerate_callback callback to each IKE SA in
    the database. After all SAs have been done, call the
    enumerate_callback callback with the sa value set to
    NULL.

    If an error occurs during the enumeration, then call
    enumerate_callback with error_code.

    Note: The enumerate_callback callback MUST NOT modify or change
    the IKE SA in any way. */
typedef void
(*SshIkev2SadIkeSaEnumerate)(SshSADHandle sad_handle,
                             SshIkev2SadIkeSaEnumerateCB enumerate_callback,
                             void *context);


/*--------------------------------------------------------------------*/
/* Installing an IPsec SA. */

/** IPsec SA install was done. */
typedef void
(*SshIkev2SadIPsecSaInstallCB)(SshIkev2Error error_code, /* Error code. */
                               void *context); /* Context. */

/** Install an IPsec SA to the IPsec engine. Called once per
    IPsec SA. The SPI number can be found from the IPsec
    exchange data structure, as can the old SPI in case this
    was a rekey. The traffic selectors are also found from
    the exchange data.

    The IKEv2 library does not automatically destroy the
    IPsec or IKE SA if SA handler fails. The application
    must do that if neccessary. */
typedef SshOperationHandle
(*SshIkev2SadIPsecSaInstall)(SshSADHandle sad_handle, /** SAD handle. */
                             /** Exchange data. */
                             SshIkev2ExchangeData ed,
                             /** Reply callback. */
                             SshIkev2SadIPsecSaInstallCB reply_callback,
                             /** Reply context. */
                             void *reply_context);

/** Update endpoint for tunnels. This will update the IKE SA
    and all IPsec SAs negotiated with that IKE SA. The
    endpoint is used only for outgoing traffic, incoming
    traffic is accepted anywhere. */
typedef void
(*SshIkev2SadIPsecSaUpdate)(SshSADHandle sad_handle, /* SAD handle. */
                            SshIkev2ExchangeData ed, /* Exchange data. */
                            SshIpAddr ip_address,    /* IP address. */
                            SshUInt16 port);         /* Port. */

/*--------------------------------------------------------------------*/
/* SAs negotiated callbacks. */

/** This callback is called when the IKE SA negotiation has
    been done.

    This call is called one or two times for the IKE SA (it can be
    called first to tell success, but in case something goes wrong
    after that, it can call this function again with error code).

    @param error_code
    The error_code value tells whether the negotiation was successful
    or not. In case the negotiation failed, the IKE SA will be deleted
    shortly after this call.

    */

typedef void
(*SshIkev2SadIkeSaDone)(SshSADHandle sad_handle, /** SAD handle. */
                        /** Exchange data. */
                        SshIkev2ExchangeData ed,
                        /** Error code. */
                        SshIkev2Error error_code);

/** This callback is called when the IPsec SA negotiation
    has been done.

    This call will be called if the SPI for the IPsec SA was allocted
    (i.e. IPsecSpiAllocate returned a non-zero SPI). This can also be
    called twice, in case error happens after we had already reported
    success.

    @param error_code
    The error_code value tells whether the negotiation was successful
    or not. In case the negotiation failed, the exchange data will be
    deleted shortly after this call.

    */

typedef void
(*SshIkev2SadIPsecSaDone)(SshSADHandle sad_handle, /** SAD handle. */
                          /** Exchange data. */
                          SshIkev2ExchangeData ed,
                          /** Error code. */
                          SshIkev2Error error_code);

#endif /* SSH_IKEV2_SAD_H */
