/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
     External Key Interface (EKI)

     The External Key Interface (EKI) provides a layer to external
     cryptographic devices that can perform cryptographic operations and
     may contain certificates.

     Externalkey uses 'providers' that implement device specific calls to
     the device API. A provider could be for example a PKCS #11 module,
     Microsoft Cryptographic API (MS CAPI) or some other hardware or
     software token.

     The application that uses externalkey can use multiple providers at
     the same time. New providers can be added for the application using
     the ssh_ek_add_provider() function call.

     To extend the known provider types, the list of known providers in
     file sshexternalkey.c needs to be modified.


     * Provider Identification *

     Each provider in the system is identified with a name (a C-string),
     typically something that descibes the kind of the provider. A
     provider name could be for example "smartcard".

     The externalkey interface uses 'short names' to refer to installed
     providers instances. The short name format is
     '[provider_type]://[counter]/', for example 'smartcard://0/'. The
     counter in the provider name makes each provider's short name unique
     if multiple providers of the same type are added.


     * EKI Operation *

     The system works roughly as follows:

       * The application allocates an externalkey object using the function
         ssh_ek_allocate(). Two callback functions need to be registered for
         the externalkey object, an authentication callback and a notify
         callback.

           - The authentication callback is called by the externalkey system
             when a provider needs a authentication code (PIN) to complete an
             operation. The authentication callback is registered by calling
             ssh_ek_register_authentication_callback().

           - The notify callback is called when a provider needs to inform
             the application of new or missing keys. The notify callback is
             also called to inform the application about "interesting" events
             from providers, such as failures, etc. The notify callback is
             registered by calling ssh_ek_register_notify().


       * The application adds the required providers to the system.

       * Objects inside providers (private keys, public keys or
         certificates) are identified with keypaths (C-strings). Keypaths
         are of the form [provider_short_name][object_id], where object_id
         depends on the kind of provider used as the back-end. The notify
         callback tells the application what objects are in the provider.

       * When the application wishes to retrieve a handle to a key or to
         certificate, it can use ssh_ek_get_ family functions passing them
         the appropriate keypath.

     The following diagram illustrates the relationship between different
     externalkey objects:

   <CODE>

              +------------------------------------------------------+
              |                   SshExternalKey                     |
              +------------------------------------------------------+
                        |                |                       |
                        |                |                       |
                        |                |                       |
             +-----------------+   +--------------------+   +------------+
             | PKCS11 Provider |   | SmartCard Provider |   | Provider   |
             +-----------------+   +--------------------+   +------------+
              /         \\                      |
             /           \\                     |
          Token 1       Token 2              Token 1
          /    \\         /  \\              /    |   \\
         /      \\       /    \\            /     |    \\
      Cert1  PrvKey1  Cert2  PrvKey2   CA Cert Cert1  PrvKey1

   </CODE>
*/

#ifndef SSHEXTERNALKEY_H
#define SSHEXTERNALKEY_H

#include "sshcrypt.h"


/** Handle representing an "external key" subsystem. */
typedef struct SshExternalKeyRec *SshExternalKey;

/** This call allocates the externalkey subsystem instance.
    Returns NULL on failure. */
SshExternalKey ssh_ek_allocate(void);

/** A callback function of this type is called when the externalkey has
    been freed. */
typedef void (*SshEkFreeCB)(void *context);

/** Close the externalkey subsystem.

    No more callbacks will be delivered.  All keys obtained from
    externalkey must have been freed before this function is
    called. Any existing providers are automatically removed from the
    system by this call. If external keys are used after this call
    their behavior is undefined.

    The function will call the callback function 'callback' when the
    free operation is complete.
    */
void ssh_ek_free(SshExternalKey externalkey, SshEkFreeCB callback,
                 void *context);


/*--------------------------------------------------------------------*/
/*  Events that providers report to externalkey                       */
/*--------------------------------------------------------------------*/

/** Types for external key events.

    When a provider is first inserted to the system, the notification
    of the event SSH_EK_EVENT_PROVIDER_ENABLED is sent to the
    application. When a provider has been removed from the system, the
    notification of the event SSH_EK_EVENT_PROVIDER_DISABLED is given.

    When a token is inserted to the provider, the notification
    SSH_EK_EVENT_TOKEN_INSERTED is given to the application, then the
    SSH_EK_EVENT_KEY_AVAILABLE notification is sent for each key in
    the token. When the notification for all keys in the token have
    been sent to the application, then the SSH_EK_EVENT_TOKEN_SCANNED
    notification is sent.

    When a token is removed from the provider, the notifiation
    SSH_EK_EVENT_TOKEN_REMOVE_DETECTED is sent to the application,
    then the SSH_EK_EVENT_KEY_UNAVAILABLE notification is sent for
    each key in the token for which a SSH_EK_EVENT_KEY_AVAILABLE
    notification was sent previously. When all keys in the token have
    been notified as unavailable, the application is sent the
    SSH_EK_EVENT_TOKEN_REMOVED notification. */

typedef enum {
  /** A provider was enabled - the keypath contains the short name of
      the provider, label may be some message to display to the
      user; this is called when the initialization of the provider is
      successfully completed.*/
  SSH_EK_EVENT_PROVIDER_ENABLED = 1,

  /** A provider was disabled - the keypath contains the short name of
      the provider, label may be some message to display to the
      user; this is called when the provider is removed from the
      system. */
  SSH_EK_EVENT_PROVIDER_DISABLED,

  /** Provider failure event - this is sent if an unexpeced error has
      been occured such as a corrupted smart card; the keypath of the
      notification callback contains at least the short name of the
      provider; the label may be NULL, or it may contain an English
      printable string, which may be shown to the user.*/
  SSH_EK_EVENT_PROVIDER_FAILURE,

  /** This notification informs the application that a token was
      inserted; the label contains the name of the token or smart card. */
  SSH_EK_EVENT_TOKEN_INSERTED,

  /** The provider has scanned and notified all keys in the token, and
      new keys are notified only if some external event happens - this
      event is useful in utilities that use externalkey, after this
      event is delivered they can proceed with the keys which have
      been found. */
  SSH_EK_EVENT_TOKEN_SCANNED,

  /** This notification informs the application that a token has been
      removed - in addition to delivering this callback, the provider
      must call the notify callback with SSH_EK_EVENT_KEY_UNAVAILABLE
      for each key that it has announced available. */
  SSH_EK_EVENT_TOKEN_REMOVE_DETECTED,

  /** This notification informs the application about a token for
      which a SSH_EK_EVENT_TOKEN_REMOVE_DECTECTED event has previously
      been called - when this event occurs, the notify callback has
      been delivered with event SSH_EK_EVENT_KEY_UNAVAILABLE for all
      keys in the token that it had announced available. */
  SSH_EK_EVENT_TOKEN_REMOVED,

  /** This notification informs the application that a key is
      available at the specified keypath - flags indicate how it can be
      used. */
  SSH_EK_EVENT_KEY_AVAILABLE,

  /** Informs the application that a key that has been previously
      announced available by SSH_EK_EVENT_KEY_AVAILABLE has become
      temporarily unavailable (e.g. because the token on which the key
      resides has been removed) - if at a later time the notify
      callback is called with the event SSH_EK_EVENT_KEY_AVAILABLE and
      the same keypath, then the keys that have been previously
      fetched using the keypath should work again. */
  SSH_EK_EVENT_KEY_UNAVAILABLE,

  /** An internal event - applications should never see this event. */
  SSH_EK_EVENT_NONE
} SshEkEvent;

/** This function returns a printable, US English, event name. */
const char *ssh_ek_get_printable_event(SshEkEvent event);

/** Key usage flags for private and public keys within the external
    key providers.  */
typedef SshUInt32 SshEkUsageFlags;

/** The key is used for authentication. */
#define SSH_EK_USAGE_AUTHENTICATE               0x0001

/** The key is used to encrypt data. */
#define SSH_EK_USAGE_ENCRYPTION                 0x0002

/** The key is used to generate digital signatures. */
#define SSH_EK_USAGE_SIGNATURE                  0x0004

/** The key is an accelerator key. The provider announces that the
    usage of this key may be somewhat faster than normal keys. */
#define SSH_EK_USAGE_ACCELERATOR                0x0008

/** The token that contains this key needs an authentication code
    before the key can be read. */
#define SSH_EK_USAGE_AUTHENTICATION_REQUIRED    0x0010


/** A callback function of this type can be registered to be called
    whenever the status of a device (or some other hardware token)
    changes.

    The fact that this function is called for with a
    SSH_EK_TOKEN_REMOVED event does not invalidate any key objects
    that may have been retrieved using the keypath.  However, when any
    such key is used, operations using the key are likely to fail.

    It is also possible that the removal notification is delivered
    with a delay; thus operations may start failing before this
    callback is actually called.

    @param event
    Describes the type of event that occurred.

    @param keypath
    The keypath that can be supplied to one of the ssh_ek_get_*
    functions to obtain the corresponding public key, private key, or
    certificate.  The same keypath can be used for all of these
    functions.  The private key must be present; if there are multiple
    certificates for the same private key, they must be fetched using
    separate cert_index arguments when fetching the certificate. In
    the events SSH_EK_EVENT_TOKEN_INSERTED and
    SSH_EK_EVENT_TOKEN_REMOVED, the keypath argument has only the
    short name of the provider and the name of the token inserted.
    flags tell if the authentication code is needed to obtain objects.

    @param label
    For some events this is a string obtained from the
    provider(typically something that identifies the key and that can
    be displayed to the user).  This is empty if not available.

    @param flags
    Specifies how the key at keypath can be used.  This is a
    bitwise-or of the available flags.  If a key supports more than
    one function, it may be displayed as one or two keys depending on
    the particular device.

    @param context
    The context argument supplied when the callback was registered.

    */
typedef void (*SshEkNotifyCB)(SshEkEvent event,
                              const char *keypath,
                              const char *label,
                              SshEkUsageFlags flags,
                              void *context);

/** Registers a callback function to be called when the
    status of a device (or some other hardware/software token)
    changes.

    If there is already a device (or another token) inserted, the
    notify callback will be called once with
    SSH_EK_EVENT_KEY_AVAILABLE after this has been set.  The call may
    occur either during this function call or at some later time.  If
    there are multiple hardware tokens available, or a token supports
    more than one key, the notify callback will be called once for
    each available key.  The notify callback is also called for "soft
    tokens" (e.g., a key stored encrypted on local disk, which is
    accessed using the PKCS-11 interface).

    If the supplied callback is NULL, this cancels any previously set
    callback. */
void ssh_ek_register_notify(SshExternalKey externalkey,
                            SshEkNotifyCB notify_cb,
                            void *context);


/*--------------------------------------------------------------------*/
/*  Authentication to the externalkey providers                       */
/*--------------------------------------------------------------------*/

/** This type tells the authentication code callback information that
    may be of interest to the user (e.g., the error message should be
    different if the authentication code has been blocked due to too
    many failed attempts as opposed to being wrong on the first
    attempt). */
typedef enum {
  /** An authentication code (= password/passphrase) is needed for
      this key - the code is required for a private key calculation to
      be completed or to open the token. */
  SSH_EK_AUTHENTICATION_CODE_NEEDED = 1,

  /** An authentication code is needed to "login" to the token - when
      the code is entered, the provider can see what keys there are in
      the token. */
  SSH_EK_AUTHENTICATION_NEEDED_FOR_THE_TOKEN,

  /** An authentication code is needed for this key - this value is
      used instead of SSH_EK_AUTHENTICATION_CODE_NEEDED if we
      previously queried the code for this key, and the code was not
      accepted. */
  SSH_EK_AUTHENTICATION_CODE_WRONG,

  /** Authentication is needed, but the device (or other hardware
      token) has blocked the code (because of too many retries) - the
      application must call reply_cb with NULL data if this error is
      obtained. */
  SSH_EK_AUTHENTICATION_CODE_BLOCKED,

  /** The previous authentication code failed for some reason other
      than just being wrong in the normal way. */
  SSH_EK_AUTHENTICATION_CODE_FAILED,

  /** The previous authentication code has succeeded and no further
      authentication is needed - in this case the reply_cb need not be
      called. */
  SSH_EK_AUTHENTICATION_OK
} SshEkAuthenticationStatus;

/** The authentication code callback must call a reply function when
    the authentication code query completes.  The reply function is of
    this type.  If the user cancelled the authentication code query,
    the code_data argument should be NULL, in which case no attempt
    will be made to use the authentication code. */
typedef void (*SshEkAuthenticationReplyCB)(const unsigned char *code_data,
                                           size_t code_length,
                                           void *reply_context);

/** A callback function of this type is used to query the
    authentication code from the user.

    The callback function of this type should be registered with
    ssh_ek_register_authentication_callback. The callback is called
    whenever an authentication code is needed, typically this is when
    a provider is computing an private key operation using a key, or
    after the provider has been initialized.

    This function must call the reply_cb callback when the
    authentication code is known. If the code is not known, the
    reply_cb can be called with NULL code, which cancels the operation
    which needed the code.

    This function must return SshOperationHandle which can be used to
    abort the query. If the reply_cb is called during this call, NULL
    must be returned. The returned handle should be unregistered,
    after the call to the reply callback is done.

    The authentication query may be aborted using the non NULL handle
    returned from this callback (e.g. the sign operation can be
    cancelled using the handle returned from cryptolibrary). If the
    operation is aborted using the returned handle, then the reply
    callback must not be called.

    If user aborts the query (e.g. from a dialog), the reply callback
    should be called with NULL parameters.

    @param keypath
    Identifies the key or token, the code is needed for. If the path
    has a slash at the end of the path, the authentication code is
    needed for the token, and not for a key.

    @param label
    A "label" string obtained from the provider (typically something
    that identifies the authentication code and that can be displayed
    to the user).  This is empty if not available.

    @param try_number
    Indicates how many times the user has already tried to enter the
    authentication code.  The first time the code is queried, this is
    zero.

    @param authentication_status
    Gives additional information that may be useful for the user.
    This information is usually obtained from the previous try.

    @param reply_cb
    Must be called with the code data and the reply_context when the
    code has been entered, or a user cancelled the query.

    @param reply_context
    Context argument that must be supplied to the reply_cb callback.

    @param context
    Context argument that was supplied when the callback was
    registered.

    */
typedef SshOperationHandle (*SshEkAuthenticationCB)(const char *keypath,
                                                    const char *label,
                                                    SshUInt32 try_number,
                                                    SshEkAuthenticationStatus
                                                    authentication_status,
                                                    SshEkAuthenticationReplyCB
                                                    reply_cb,
                                                    void *reply_context,
                                                    void *context);

/** Set the function that is used to query authentication code
    (effectively a password or PIN, but it is not always numeric) from
    the user.

    If the function is NULL, it is cleared.  If no function is
    specified (is NULL), the effect is as if the authentication code
    callback called the reply function with NULL authentication code
    (in effect, any operation that requires a authentication code
    silently fails). */
void ssh_ek_register_authentication_callback(SshExternalKey externalkey,
                                             SshEkAuthenticationCB
                                             authentication_cb,
                                             void *context);

/*--------------------------------------------------------------------*/
/*  Status return values of externalkey provider operations           */
/*--------------------------------------------------------------------*/

/** Status codes for operations. The qualifier at the end of each type
    describes the scope this status applies to (global, token, provider,
    etc).  */

typedef enum {

  /** The operation was successful - global. */
  SSH_EK_OK = 0,

  /** Not enough memory to perform an operation - global. */
  SSH_EK_NO_MEMORY = 10,

  /** The requested operation is not supported by this provider - global. */
  SSH_EK_OPERATION_NOT_SUPPORTED,

  /** The operation failed; this is a generic catch-all error that should
     be used if none of the above is applicable - global. */
  SSH_EK_FAILED,

  /** The specified initialization information is invalid; this can only be
      returned by ssh_ek_add_provider - provider. */
  SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID = 30,

  /** Initialization of the specified provider failed - provider. */
  SSH_EK_PROVIDER_INITIALIZATION_FAILED,

  /** The specified provider type is not supported; this can only be
      returned by ssh_ek_add_provider - provider. */
  SSH_EK_PROVIDER_TYPE_NOT_SUPPORTED,

  /** The operation failed, because the keypath indicates a provider
      that is not (any longer) available; this could happen, for
      example, if the user removes the provider after the keypath was
      obtained - provider. */
  SSH_EK_PROVIDER_NOT_AVAILABLE,

  /** The operation failed, because there is no token inserted (as
      indicated by keypath) - token. */
  SSH_EK_TOKEN_NOT_INSERTED = 50,

  /** The operation failed, because the inserted token is not
      recognized - token. */
  SSH_EK_TOKEN_UNRECOGNIZED,

  /** An unspecific error occurred when communicating with the token
      (e.g., some kind of read error) - token. */
  SSH_EK_TOKEN_ERROR,


  /** The file specified by keypath was not found; this can only
      happen if the keypath refers to a file - key. */
  SSH_EK_KEY_FILE_NOT_FOUND = 70,

  /** The object specified by keypath was not found (when it is
      something other than a file); this could happen e.g. if a bogus
      keypath referring to a token was constructed - key. */
  SSH_EK_KEY_NOT_FOUND,

  /** Permission to access the object specified by keypath was denied;
      this could occur for example if the current process does not
      have read access for the file - key. */
  SSH_EK_KEY_ACCESS_DENIED,

  /** The object specified by keypath is not in valid format; this
      happens, for example, if the user specifies a PEM encododed file
      and it is actually hexl-encoded - key. */
  SSH_EK_KEY_BAD_FORMAT,


  /** This status return can only be returned by
      ssh_ek_get_certificate; this indicates that there is no
      certificate at the specified index (or any higher index) -
      misc. */
  SSH_EK_NO_MORE_CERTIFICATES = 100,

  /** The message sent to provider is unknown - misc. */
  SSH_EK_UNKNOWN_MESSAGE

} SshEkStatus;

/** Return printable string for a status code. */
const char *ssh_ek_get_printable_status(SshEkStatus status);

/** Callback type which is used with ssh_ek_get_public_key. The
    application must free the returned public key 'public_key_return'
    by calling ssh_public_key_free. */
typedef void (*SshEkGetPublicKeyCB)(SshEkStatus status,
                                    SshPublicKey public_key_return,
                                    void *context);

/** Callback type which is used with ssh_ek_get_private_key. The
    application must free the returned private key
    'private_key_return' by calling ssh_private_key_free. */
typedef void (*SshEkGetPrivateKeyCB)(SshEkStatus status,
                                     SshPrivateKey private_key_return,
                                     void *context);

/** Callback type which is used with ssh_ek_get_certificate. The
    certificate returned in cert_return should be copied in this call
    if it is needed later. */
typedef void (*SshEkGetCertificateCB)(SshEkStatus status,
                                      const unsigned char *cert_return,
                                      size_t cert_return_length,
                                      void *context);

/** Callback type which is used with ssh_ek_get_group and
    ssh_ek_generate_accelerated_group. The returned group needs to be
    freed with ssh_pk_group_free. */
typedef void (*SshEkGetGroupCB)(SshEkStatus status,
                                SshPkGroup group,
                                void *context);


/** Callback type which is used with ssh_ek_get_random_bytes. The
    returned random bytes should be copied in this call if needed
    later. */
typedef void (*SshEkGetRandomBytesCB)(SshEkStatus status,
                                      const unsigned char *random_bytes_return,
                                      size_t random_bytes_return_length,
                                      void *context);


/** Get a public key handle from the location indicated by keypath.
    The caller must supply the callback which is called when the
    public key is available. If this function is called several times
    with the same keypath, a different copy of the key handle is
    returned. */
SshOperationHandle ssh_ek_get_public_key(SshExternalKey externalkey,
                                         const char *keypath,
                                         SshEkGetPublicKeyCB get_public_key_cb,
                                         void *context);

/** Get a private key handle from the location indicated by keypath.
    Caller must supply the callback which is called when the private
    key is available.

    Note: If this function is called several times with
    the same keypath, a different copy of the key handle is
    returned. */
SshOperationHandle ssh_ek_get_private_key(SshExternalKey externalkey,
                                          const char *keypath,
                                          SshEkGetPrivateKeyCB
                                          get_private_key_cb,
                                          void *context);

/** Get the certificate from the location indicated by keypath and use
    the certificate specified by cert_index.

    @param externalkey
    The external key.

    @param keypath
    The location of the certificate.

    @param cert_index
    An integer starting from zero used for identifying different
    certificates.

    @param get_certificate_cb
    The callback to call when the certificate is available.

    @param context
    The context.

    @return
    If there are no certificates with the supplied keypath and
    index, SSH_EK_NO_MORE_CERTIFICATES is returned in the
    callback.

    */
SshOperationHandle ssh_ek_get_certificate(SshExternalKey externalkey,
                                          const char *keypath,
                                          SshUInt32 cert_index,
                                          SshEkGetCertificateCB
                                          get_certificate_cb,
                                          void *context);

/** Get the trusted certificates from the provider. The caller must
    provide the provider's short name and a certificate
    index.

    @param externalkey
    The external key.

    @param provider_short_name
    The short name of the provider.

    @param cert_index
    An integer starting from zero which identifies different
    certificates.

    @param get_certificate_cb
    The callback to call when the certificate is available.

    @param context
    The context.

    @return
    If there are no trusted certificates with the index,
    SSH_EK_NO_MORE_CERTIFICATES is returned in the callback.

    */
SshOperationHandle ssh_ek_get_trusted_cert(SshExternalKey externalkey,
                                           const char *provider_short_name,
                                           SshUInt32 cert_index,
                                           SshEkGetCertificateCB
                                           get_certificate_cb,
                                           void *context);

/** Get a group (such as a Diffie-Hellman group) from a provider. The
    caller must provide the path of the group in group_path. The group
    is returned in a callback. The group_path contains the provider
    and the name of the group which is provider specific, but if the
    provider can generate standard ike groups, they should be named
    "ike-1", "ike-2" and so on. */
SshOperationHandle ssh_ek_get_group(SshExternalKey externalkey,
                                    const char *group_path,
                                    SshEkGetGroupCB callback,
                                    void *context);

/** Build an accelerated key. The provider will convert the specified
    key to an accelerated key (if it can), and call the callback with
    an accelerated version of the key, if everything worked out
    well. */
SshOperationHandle
ssh_ek_generate_accelerated_private_key(SshExternalKey externalkey,
                                        const char *provider_short_name,
                                        SshPrivateKey source,
                                        SshEkGetPrivateKeyCB
                                        get_private_key_cb,
                                        void *context);


/** Build an accelerated key. The provider will convert the specified
    key to an accelerated key (if it can), and call the callback with
    an accelerated version of the key, if everything worked out
    well. */
SshOperationHandle
ssh_ek_generate_accelerated_public_key(SshExternalKey externalkey,
                                       const char *provider_short_name,
                                       SshPublicKey source,
                                       SshEkGetPublicKeyCB
                                       get_public_key_cb,
                                       void *context);

/** Build an accelerated group. The provider will convert the
    specified group to an accelerated group (if it can) and return the
    group in the callback. */
SshOperationHandle
ssh_ek_generate_accelerated_group(SshExternalKey externalkey,
                                  const char *provider_short_name,
                                  SshPkGroup source,
                                  SshEkGetGroupCB callback,
                                  void *context);

/** Attempts to get 'bytes_requested' random bytes from the location
    indicated by 'keypath'. The caller must supply the callback which
    is called when the provider has obtained the random bytes. */
SshOperationHandle ssh_ek_get_random_bytes(SshExternalKey externalkey,
                                           const char *provider_short_name,
                                           size_t bytes_requested,
                                           SshEkGetRandomBytesCB
                                           get_random_bytes_cb,
                                           void *context);


/** This callback function is called by provider when it has handled
    the message sent to it by the ssh_ek_send_message function.

    @param status

    @param answer
    The function may give some provider-specific information to the
    application using the 'answer' argument.

    @param answer_len
    The size of the data passed in 'answer'.

    @param context
    The context.

    */
typedef void (*SshEkSendMessageCB)(SshEkStatus status,
                                   void *answer,
                                   size_t answer_len,
                                   void *context);


/** Sends a provider-specific message to a provider. When provider has
    received/handled the message, the message_cb is called.  The
    message is provider-specific.

    @param externalkey

    @param short_name

    @param message

    @param message_arg

    @param message_arg_len
    The size of the data passed in 'message_arg'.

    @param message_cb
    The callback to be called when the provider has received/handled
    the message.

    @param context

     */
SshOperationHandle
ssh_ek_send_message(SshExternalKey externalkey,
                    const char *short_name,
                    const char *message,
                    void *message_arg,
                    size_t message_arg_len,
                    SshEkSendMessageCB message_cb,
                    void *context);

/*--------------------------------------------------------------------*/
/*  Provider configuration interface.                                 */
/*--------------------------------------------------------------------*/

/** These flags give additional information about the provider. These
    flags may be supplied when adding the provider. */
typedef SshUInt32 SshEkProviderFlags;

/** "No flags" flag. */
#define SSH_EK_PROVIDER_FLAG_NONE 0x00

/** If this flag has been set, hardware acceleration is available -
    use ssh_ek_generate_accelerated_private_key or
    ssh_ek_generate_accelerated_public_key to get the accelerated
    keys. */
#define SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR   0x0001

/** If this flag is set, the provider supports acceleration of
    groups - use ssh_ek_generate_accelerated_group to get the
    accelerated group. */
#define SSH_EK_PROVIDER_FLAG_GROUP_ACCELERATOR 0x0002

/** The provider is trusted, meaning that the application may trust
    the trusted certificates returned by this provider. */
#define SSH_EK_PROVIDER_FLAG_TRUSTED_PROVIDER  0x0004

/** The provider is the default provider of the application. */
#define SSH_EK_PROVIDER_FLAG_DEFAULT           0x0008


/** Data structure describing a provider. */
typedef struct SshEkProviderRec{
  /** Type of the provider - this is a string that identifies the name
      of provider backed (software, safenet, pkcs11, mscapi, smartcard
      etc.) */
  const char *type;

  /** Further refines how this provider can be used. */
  SshEkProviderFlags provider_flags;

  /** Name for the provider (supplied by the implementation of this
      interface, usually by querying the underlying provider) - a
      typical name could be "Zappa Inc. Device PKCS-11 Interface";
      the name should be user-printable, so that it can be displayed
      in a configuration dialog. */
  const char *printable_name;

  /** A short name of the provider, that will be used as an provider
      specific tag in the beginning of the keypath - the name consists
      of alphanumeric characters, colons and slashes; the
      implementation uses it as part of the keypath supplied to
      applications; the name consist of the provider type specific
      part and an instance part, so for example with PKCS #11 it could
      be pkcs11://0/, or pkcs11://1/. */
  const char *short_name;

  /** Initialization information for the provider - the interpretation
      of info depends on the type of the provider; for some provider
      types, it may be the path name (file name) of the DLL that
      implements the interface (with or without directory components;
      if without, it will be searched using the normal DLL search
      mechanism of the platform). */
  const char *info;

  /** If TRUE, the provider has been enabled. */
  Boolean enabled;
} *SshEkProvider;


/** Checks if a particular keypath belongs to the given provider
    identified with a short name. */
Boolean ssh_ek_key_path_belongs_to_provider(const char *key_path,
                                            const char *provider_short_name);

/** Lists the available providers (these may be dynamically linked
    libraries that implement a standard hardware token interface, such
    as PKCS #11 or hardware accelerators that supply only the
    ssh_ek_generate_accelerated_* functions).  The array is allocated
    using ssh_malloc, and must be freed by the caller using ssh_free.

    The ssh_ek_get_providers function gets the list of providers from
    internal memory structures, thus it is possible to use this
    function even if the ssh_ek_add_provider is still pending (i.e.
    the SSH_EK_EVENT_PROVIDER_ENABLED notification has not yet been
    received).

    If ssh_ek_remove_provider is called for a provider after this
    function returns, the SshEkProvider structure is still valid, but
    the data items (type, printable_name, short_name, info) of the
    provider that was removed are invalid.

    Return FALSE on error in which case providers_return,
    and num_providers_return are set to NULL and 0. On success
    this function returns TRUE. */
Boolean ssh_ek_get_providers(SshExternalKey externalkey,
                             SshEkProvider *providers_return,
                             SshUInt32 *num_providers_return);

/** Adds and initializes a new built-in provider.  This function is
    typically be called in the beginning of the program to add the
    provider for externalkey to use.  The provider can be removed by
    calling ssh_ek_remove_provider. Any remaining providers are
    removed when the externalkey object is freed.

    @param type
    Type.

    @param initialization_info
    Provider-specific argument. It may be a path to dynamic link
    library, initialization information or something else. Consult the
    provider headers to find appropriate provider initialization
    information.

    @param initialization_ptr
    A provider-specific argument. It allows the passing of context
    information to the provider initialization function.

    @param flags
    Flags.

    @param provider_short_name
    The short name of the provider.

    @return
    When this call returns, the provider is available and will be
    appear in the list obtained with ssh_ek_get providers (provided
    the adding was successful). When the provider is fully initialized
    (initialization for some providers may be asynchronous), the
    application will be notified by a call to the SshEkNotifyCB with
    the event SSH_EK_EVENT_PROVIDER_ENABLED if initialization was
    successful, and with the event SSH_EK_EVENT_PROVIDER_FAILURE if
    the provider could not be initialized.

    The short name of the provider is returned in provider_short_name
    and it should be freed with ssh_free.

    */
SshEkStatus ssh_ek_add_provider(SshExternalKey externalkey,
                                const char *type,
                                const char *initialization_info,
                                void *initialization_ptr,
                                SshEkProviderFlags flags,
                                char **provider_short_name);


/** Remove the provider from the system. This should be called only
    when the application has no further need for this provider. When
    the provider is actually removed from the system, the application
    will be notified by a call to the SshEkNotifyCB with the event
    SSH_EK_EVENT_PROVIDER_DISABLED.  No more notifications are
    delivered from this provider after this call to the SshEkNotiyCB
    has been received.

    If 'provider_short_name' does not correspond to a valid provider,
    this function does nothing.  */
void
ssh_ek_remove_provider(SshExternalKey externalkey,
                       const char *provider_short_name);

/** Handle representing an external provider type. The application may
    add custom provider types using this function. */
typedef struct SshEkProviderOpsRec *SshEkProviderOps;

/** Add an new provider to the system. The system has a set of
    built-in providers, which could be added with
    ssh_ek_add_provider. The custom providers can be added with this
    function by providing a pointer to the provider context. */
SshEkStatus ssh_ek_add_provider_external(SshExternalKey externalkey,
                                         SshEkProviderOps provider,
                                         const char *initialization_info,
                                         void *initialization_ptr,
                                         SshEkProviderFlags flags,
                                         char **provider_short_name);

#endif /* SSHEXTERNALKEY_H */
