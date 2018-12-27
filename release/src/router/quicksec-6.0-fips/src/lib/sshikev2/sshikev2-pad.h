/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface functions to Peer Authentication Database (PAD).
*/

#ifndef SSH_IKEV2_PAD_H
#define SSH_IKEV2_PAD_H

/*--------------------------------------------------------------------*/

/** Error code handling.

    If the error_code value is SSH_IKEV2_ERROR_OK, the exchange is
    continued.

    If the error_code value is SSH_IKEV2_ERROR_COOKIE_REQUIRED,
    then we require the cookie for the connection, and the
    connection either sends back a notification requesting the
    cookie, or verifies that the cookie in the payload is valid,
    and if so, continues the exchange.

    If the error_code value is SSH_IKEV2_ERROR_DISCARD_PACKET, the
    connection attempt is silently discarded.

    If the error code is SSH_IKEV2_ERROR_USE_IKEV1, then the
    packet is forwarded to the IKEv1 library if the packet
    from initiator was IKEv1, or a notification to request
    v1 is sent, if the packet from initiator was IKEv2. */
typedef void
(*SshIkev2PadNewConnectionCB)(SshIkev2Error error_code,
                              void *context);

/** A new IKE SA connection. This is used to authorize a new
    connection attempt. */
typedef SshOperationHandle
(*SshIkev2PadNewConnection)(SshSADHandle sad_handle,
                            SshIkev2Server server,
                            SshUInt8 major_version, SshUInt8 minor_version,
                            SshIpAddr remote_address,
                            SshUInt16 port,
                            SshIkev2PadNewConnectionCB reply_callback,
                            void *reply_callback_context);

#ifdef SSHDIST_IKE_REDIRECT
/*--------------------------------------------------------------------*/
/** Request IKE redirect decision and address. */
typedef void
(*SshIkev2PadIkeRedirectCB)(SshIkev2Error error_code,
                            SshIpAddr redirect_addr,
                            void *context);

typedef SshOperationHandle
(*SshIkev2PadIkeRedirect)(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2PadIkeRedirectCB reply_callback,
                          void *reply_callback_context);
#endif /* SSHDIST_IKE_REDIRECT */
/*--------------------------------------------------------------------*/
/** Return the identity to the IKEv2 library. The id_payload
    value is copied to the internal structures, thus it can
    be freed immediately after this call returns (or it can
    be freed from the stack). */
typedef void
(*SshIkev2PadIDCB)(SshIkev2Error error_code,
                   Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                   Boolean another_id_follows,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                   const SshIkev2PayloadID id_payload,
                   void *context);

/** Select the local or remote identity to be used in the
    exchange. Note that if we are the responder and the
    initiator used the "You Tarzan, Me Jane" option, then
    the id_r value in the exchange data already contains the
    Tarzan id sent by the other end.

    @param local
    If 'local' is true, then we are asking our own ID, otherwise we
    are asking for the remote ID. */
typedef SshOperationHandle
(*SshIkev2PadID)(SshSADHandle sad_handle,
                 SshIkev2ExchangeData ed,
                 Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                 SshUInt32 authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                 SshIkev2PadIDCB reply_callback,
                 void *reply_callback_context);

#ifdef SSHDIST_IKE_MOBIKE

/** This callback is used by the IKEv2 library to receive the local
    and remote addresses used for sending a packet.

    The remote port is taken from NAT-T status of the exchange.

    @param local_server
    The local_server parameter specifies the local bound ip address.

    @param remote_ip
    The remote_ip parameter is the preferred peer address.

    */
typedef void
(*SshIkev2PadGetAddressPairCB)(SshIkev2Error error_code,
                               SshIkev2Server local_server,
                               SshIpAddr remote_ip,
                               void *context);

/** This policy call is used by the IKEv2 library to receive the next
    possible address pair for transmitting a packet belonging to
    exchange 'ed'.

    The application will use its own configuration database to construct
    an address pair matching to requested address_index value. The remote
    addresses at which the peer may be reachable can be found from the IKE
    SA fields 'remote_ip' and 'additional_ip_addresses'. Typically
    for the first call, the most preferred address pair would be used, and
    for larger address_index values less preferred addresses would be
    returned.

    This function may also be called also during the initial exchange.

    @param address_index
    The address_index value is incremented for each subsequent
    call within the same exchange and is initialized to one the first
    time this is called for an exchange. Index zero denotes the
    address pair currently used by the IKE SA.

    @param reply_callback
    The given 'reply_callback' will be called by application according
    to SshOperation semantics.

    */

typedef SshOperationHandle
(*SshIkev2PadGetAddressPair)(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshUInt32 address_index,
                             SshIkev2PadGetAddressPairCB reply_callback,
                             void *reply_callback_context);

/** This callback returns the list of local addresses from the application
    to the IKE library. The IKE library sends this list to the peer in
    ADDITIONAL_*_ADDRESSES notifies.

    When the IKE library receives ADDITIONAL_*_ADDRESSES notifies from
    the peer, it stores them to the IKE SA. */
typedef void
(*SshIkev2PadGetAdditionalAddressListCB)(SshIkev2Error error_code,
                                         SshUInt32 num_local_ip_addresses,
                                         SshIpAddr local_ip_address_list,
                                         void *context);

/** This type of function is called by the IKEv2 library and implemented
    by application. The implementation will return the local additional
    addresses applicable for the IKE SA identified by exchange data
    'ed' using the callback function 'reply_callback'.

    This function may also be called also during the initial exchange.

    @param reply_callback
    The given 'reply_callback' will be called by the application according
    to SshOperation semantics.

    */
typedef SshOperationHandle
(*SshIkev2PadGetAdditionalAddressList)(SshSADHandle sad_handle,
                                       SshIkev2ExchangeData ed,
                                       SshIkev2PadGetAdditionalAddressListCB
                                       reply_callback,
                                       void *reply_callback_context);
#endif /* SSHDIST_IKE_MOBIKE */


#ifdef SSHDIST_IKE_CERT_AUTH
/*--------------------------------------------------------------------*/
/** A callback function to call from get certificate
    authorities when the list of certificate authorities is
    ready. If no certificate authorities are to be sent to
    the other end, then set the number_of_cas value to zero.

    If a non-zero number of CA's is returned, then the
    ca_encodings, ca_authority_data, and ca_authority_size
    tables are allocated and contain the encoding type, CA
    authority data and data length, respectively. The IKEv2
    library will copy the entries from the tables during
    this call, and the caller can free them immediately when
    this returns.

    Note: If the IKEv1 fallback module is enabled, the X.509 encoding
    differs for IKEv1 SA's. For IKEv1 SA's the ca_authority_data field
    should contain the Distinguished Name encoding of the Issuer Name
    of the X.509 CA. If there are multiple CA's then number_of_cas
    should match the mumber of CA's and should not be set to 1 as is
    done for IKEv2 SA's.

    @param ca_encodings
    Encoding type.

    @param ca_authority_data
    CA authority data. For the X.509, the ca_authority_data field
    should contain an SHA-1 hash of Subject public Key Info elements
    of the trust anchor certificate. If there are multiple CAs, their
    SHA-1 hashes are simply concatenated together (i.e.  do not set
    number_of_cas to match the number of CAs, but set it to 1, and
    concatenate hashes).

    @param ca_authority_size
    The length of the CA authority data.

*/

#ifdef SSHDIST_IKEV1
/** If the IKEv1 fallback module is enabled the X.509 encoding differs
    for IKEv1 SA's. For IKEv1 SA's the ca_authority_data field should
    contain the Distinguished Name encoding of the Issuer Name of the
    X.509 CA. If there are multiple CA's then number_of_cas should match
    the mumber of CA's and should not be set to 1 as is done for IKEv2
    SA's. */
#endif /* SSHDIST_IKEV1 */

typedef void
(*SshIkev2PadGetCAsCB)(SshIkev2Error error_code,
                       int number_of_cas,
                       SshIkev2CertEncoding *ca_encodings,
                       const unsigned char **ca_authority_data,
                       size_t *ca_authority_size,
                       void *context);

/** Get the certificate authority list to be sent to the
    other end. Call reply_callback when the data is
    available (it can also be called immediately). This list
    is used for sending certificate requests to the other
    end. */
typedef SshOperationHandle
(*SshIkev2PadGetCAs)(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2PadGetCAsCB reply_callback,
                     void *reply_callback_context);

/*--------------------------------------------------------------------*/
/** A callback function to call from request_certificates
    when the certificate chain is ready. The first
    certificate in the certs table MUST be the end user
    certificate. The other certificates are something that
    should be sent to the other end to enable the
    authentication of the end user certificate. The
    private_key_out value MUST match the end user
    certificate (i.e the first certificate). The
    private_key_out value MUST have a proper schema selected
    when given to this function. The schema must be PKCS #1
    padded hash, and it should use the same hash that was
    used in the certificates to make sure the other end can
    verify the signature.

    In case there are no certificates, the number_of_certificates
    value is zero, but the private_key value must still be valid (raw
    public key authentication).

    If this end wants to use pre-shared keys or EAP to authenticate
    itself, then it should set the `number_of_certificates' value to
    zero, and `private_key_out' to NULL. In that case the
    SshIkev2PadSharedKey function is called next to get the pre-shared
    key.

    This function will copy all the necessary data away, including the
    private key, so the caller can free everything when this returns.

    @param private_key_out
    The private_key_out value MUST have a proper schema selected when
    given to this function. The schema must be PKCS #1 padded hash,
    and it should use the same hash that was used in the certificates
    to make sure the other end can verify the signature.

    */
typedef void
(*SshIkev2PadGetCertificatesCB)(SshIkev2Error error_code,
                                SshPrivateKey private_key_out,
                                int number_of_certificates,
                                SshIkev2CertEncoding *cert_encs,
                                const unsigned char **certs,
                                size_t *cert_lengths,
                                void *context);

/** Get private key to be used locally and the certificates
    containig the corresponding public keys to be sent to
    the other end. The certificate authorities were already
    given to the SAD earlier by a
    SshIkev2PadCertificateRequest call.

    Call reply_callback when the data is available (it can also be
    called immediately). */
typedef SshOperationHandle
(*SshIkev2PadGetCertificates)(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              SshIkev2PadGetCertificatesCB reply_cb,
                              void *reply_callback_context);

/*--------------------------------------------------------------------*/
/** Received a new certificate request from the other
    end. This function will be called once per each CA. The
    PAD should remember these and use them during the
    GetCertificates call, i.e. when selecting the user's
    certificate. The data is only valid during this call.

    For the X.509, the certificate_authority field should contain
    an SHA-1 hash of Subject public Key Info elements of the
    trust anchor certificate. If there are multiple CAs,
    their SHA-1 hashes are simply concatenated together.
*/

#ifdef SSHDIST_IKEV1
/** If the IKEv1 fallback module is enabled the X.509 encoding differs
    for IKEv1 SA's. For IKEv1 SA's the certificate_authority field should
    contain the Distinguished Name encoding of the Issuer Name of the
    trust anchor certificate. */
#endif /* SSHDIST_IKEV1 */

typedef void
(*SshIkev2PadNewCertificateRequest)(SshSADHandle sad_handle,
                                    SshIkev2ExchangeData ed,
                                    SshIkev2CertEncoding ca_encoding,
                                    const unsigned char *certificate_authority,
                                    size_t certificate_authority_len);

/*--------------------------------------------------------------------*/
/** A callback function to call from PublicKey when the
    public key data is ready. The certificates received from
    the peer have already been reported to PAD using
    SshIkev2PadNewCertificate at the time this gets
    called.

    If no key is found, the public_key_out value is
    NULL. The IKE library will take the copy of public_key
    during this call. The key must have the proper schema
    already set before calling this function, i.e. PKCS #1
    padding over implicit hash (so that the hash
    algorithm is taken from the signature when the signature
    is verified, i.e. for example "rsa-pkcs1-implicit"). */
typedef void
(*SshIkev2PadPublicKeyCB)(SshIkev2Error error_code,
                          SshPublicKey public_key_out,
                          void *context);

/** Find public key for remote host. Call reply_callback
    when the data is available (it can also be called
    immediately). */
typedef SshOperationHandle
(*SshIkev2PadPublicKey)(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2PadPublicKeyCB reply_callback,
                        void *reply_callback_context);
#endif /* SSHDIST_IKE_CERT_AUTH */

/*--------------------------------------------------------------------*/
/** A callback function to call from shared_key when the
    pre-shared key data is ready. If no data is found, the
    key_out value is NULL. The key_out value will be copied
    by this function.

    If 'local' was FALSE, and the key_out value is NULL, then it means
    that authentication failed, as we didn't find a pre-shared key for
    the other end.

    If 'local' is TRUE and the key_out value is NULL,
    it means that we plan to use EAP to authenticate this end.

    */

typedef void
(*SshIkev2PadSharedKeyCB)(SshIkev2Error error_code,
                          const unsigned char *key_out,
                          size_t key_out_len,
                          void *context);

/** Find the pre-shared secret for the remote host. The
    primary selector is the remote id field. Call
    reply_callback when the data is available (it can also
    be called immediately).

    @param local
    If 'local' is true then we search for the local
    pre-shared key. If `local' is false then we search for
    the key for the remote host.

    */
typedef SshOperationHandle
(*SshIkev2PadSharedKey)(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        Boolean local,
                        SshIkev2PadSharedKeyCB reply_callback,
                        void *reply_callback_context);

#ifdef SSHDIST_IKE_EAP_AUTH
/** Retrieve an EAP shared key (MSK generated by the EAP
    exchange). Call reply_callback when the data is
    available (it can also be called immediately).

    In case the EAP method does not return key, then call the
    reply_callback with key_out set to NULL. */

typedef SshOperationHandle
(*SshIkev2PadEapKey)(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2PadSharedKeyCB reply_callback,
                     void *reply_callback_context);
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
/*--------------------------------------------------------------------*/
/** Received a new certificate from the other end. Give it
    to Policy Manager. The data is only valid during this
    call. */
typedef void
(*SshIkev2PadNewCertificate)(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2CertEncoding cert_encoding,
                             const unsigned char *cert_data,
                             size_t cert_data_len);
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
/*--------------------------------------------------------------------*/
/** Received EAP payload from the other end. The data is
    only valid during this call. */
typedef void
(*SshIkev2PadEapReceived)(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          const unsigned char *eap,
                          size_t eap_length);

/*--------------------------------------------------------------------*/
/** Request EAP payload to be sent to the other end. If the
    EAP value is NULL, then do not send EAP payload to the
    other end, but continue the normal packet
    processing, i.e. assume that the EAP is ready. The
    caller can free the data immediately when this call
    returns. */
typedef void
(*SshIkev2PadEapRequestCB)(SshIkev2Error error_code,
                           const unsigned char *eap,
                           size_t eap_len,
                           void *context);

/** Request EAP payload to be sent to the other end. */
typedef SshOperationHandle
(*SshIkev2PadEapRequest)(SshSADHandle sad_handle,
                         SshIkev2ExchangeData ed,
                         SshIkev2PadEapRequestCB reply_callback,
                         void *reply_callback_context);
#endif /* SSHDIST_IKE_EAP_AUTH */

/*--------------------------------------------------------------------*/
/** Received configuration payload from the other end. The
    configuration payload is taken from the free list, and
    is also stored to the exchange data. It will be freed
    when there are no more references to it. */
typedef void
(*SshIkev2PadConfReceived)(SshSADHandle sad_handle,
                           SshIkev2ExchangeData ed,
                           SshIkev2PayloadConf conf_payload_in);

/*--------------------------------------------------------------------*/
/** Request configuration payload to be sent to the other
    end.

    If the conf_payload value is NULL, do not send
    configuration payload to the other end. The IKEv2
    library will free the configuration payload when it is
    no longer needed. */
typedef void
(*SshIkev2PadConfCB)(SshIkev2Error error_code,
                     SshIkev2PayloadConf conf_payload,
                     void *context);

/** Request configuration payload to be sent to the other
    end. This is called if we received a request with
    configuration payload, or if the initiator is sending
    out the IKE_AUTH exchange. */
typedef SshOperationHandle
(*SshIkev2PadConfRequest)(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2PadConfCB reply_callback,
                          void *reply_callback_context);

/*--------------------------------------------------------------------*/
/** Received vendor id from the other end. The data is only
    valid during this call. */
typedef void
(*SshIkev2PadVendorId)(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       const unsigned char *vendor_id,
                       size_t vendor_id_len);

/*--------------------------------------------------------------------*/
/** Add the vendor id to the packet. This can be called
    multiple times to add multiple vendor id payloads.

    If the vendor_id_len value is zero, then no more vendor id
    payloads will be added, and normal processing of the packet will
    continue.

    If this is called with an error code, then no more calls
    should be done to this function, but the operation will move to
    the error state and continue from there. */
typedef void
(*SshIkev2PadAddVendorIDCB)(SshIkev2Error error_code,
                            const unsigned char *vendor_id,
                            size_t vendor_id_len,
                            void *context);

/** Request vendor id payloads to be sent to the other end.
    Note that the reply callback can be called multiple
    times, once for each vendor id to be added, and then one
    more time with the vendor_id_len value set to zero to
    indicate that no more vendor id payloads are added. */
typedef SshOperationHandle
(*SshIkev2PadVendorIDRequest)(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              SshIkev2PadAddVendorIDCB reply_callback,
                              void *reply_callback_context);

#ifdef SSHDIST_IKE_XAUTH

typedef struct SshIkev2FbXauthAttributesRec *SshIkev2FbXauthAttributes;
typedef struct SshIkev2FbXauthAttributesRec  SshIkev2FbXauthAttributesStruct;

/** This type has two uses.

    At the XAuth server this type is used by the application to return
    the XAuth request to the IKE. The callback is an application
    callback that gets called whenever the server completes the
    request-reply exchange. The user_callback_context given to the IKE
    library is ignored.

    At the XAuth client this type is used by the IKE to request XAuth
    reply from the client. The client completes this operation by
    calling the callback with given callback context. The
    user_callback_context is whatever was given when the xauth client
    was registered.

    @return
    Non-null operation handles for XauthRequest and XauthSet are
    returned only at the client. The server always return NULL.
*/

typedef void (*SshIkev2FbXauthStatus)(SshIkev2Error status,
                                      SshIkev2FbXauthAttributes attributes,
                                      void *context);

typedef SshOperationHandle
(*SshIkev2FbXauthRequest)(SshIkev2Sa sa,
                          SshIkev2FbXauthAttributes attributes,

                          SshIkev2FbXauthStatus callback,
                          void *callback_context,
                          void *context);

typedef SshOperationHandle
(*SshIkev2FbXauthSet)(SshIkev2Sa sa,
                      Boolean status,
                      const unsigned char *message, size_t message_len,
                      SshIkev2FbXauthAttributes attributes,

                      SshIkev2FbXauthStatus callback, void *callback_context,
                      void *context);

typedef void (*SshIkev2FbXauthDone)(void *context);


/** This function gets called as a response to a call to an XAUTH
    request function call at the server side to collect XAUTH server
    side exchange data.

    A typical call sequence is like the following:

    <CODE>
    IKE          PM

                 > xauthserver is called, PM records the callbacks and
                   establishes state
    <'request' called from the PM, staus callback is given with context
<request is sent
>response is received
                > callback given to request gets called, with attributes
   <'set' is called with proper status, again callback  is given
<set is sent
>ack is received
                > callback given to set gets called
   <'done' is called completing the exchange.

   'request' if it wishes to send xauth request exchange to the peer
   'set' if the it wishes to complete xauth with set-ack
   'done' if it considers the exchange having been done.
    </CODE>
*/
typedef SshOperationHandle
(*SshIkev2FbXauth)(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2FbXauthRequest request,
                   SshIkev2FbXauthSet set,
                   SshIkev2FbXauthDone done,
                   void *callback_context); /* neg */


#endif /* SSHDIST_IKE_XAUTH */

#endif /* SSH_IKEV2_PAD_H */
