/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Function interfaces for external key providers and data structures
   that the external key providers need to know. Some useful
   functions that all providers are likely to need are included.
*/

#ifndef EXTKEYPROV_H
#define EXTKEYPROV_H

#include "sshexternalkey.h"
#include "sshoperation.h"

/*--------------------------------------------------------------------*/
/* Data types for providers.                                          */
/*--------------------------------------------------------------------*/

/** Initializes the provider and allocates a context for it.  If
    multiple providers of the same type are specified with different
    initialization info, this will be called for each of them.

    The provider instance must keep track of any keys that it has
    announced using the notify callback, and deliver
    SSH_EK_EVENT_KEY_UNAVAILABLE notifications for any such keys if
    for example the smartcard on which they are stored is removed.

    When the provider calls the notify callback, the 'keypath'
    argument should only contain the part of the path that is
    interpreted by the provider. The generic code will prefix the path
    with the provider tag, and will remove the prefix whenever a path
    is passed to the provider.

    When this provider has been initialized (initialization may be an
    asynchronous operation), the notify callback should be called with
    event SSH_EK_EVENT_PROVIDER_ENABLED.

    @return
    This returns a provider context, which is a private data type for
    the provider type specified glue.  The provider_context_return is
    passed to all of the other functions.

    The following error messages are defined:

    - SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID: fails because the
    initialization information given was invalid (DLL search path
    invalid, etc).

    - SSH_EK_PROVIDER_INITIALIZATION_FAILED: initialization failed for
    some other reason than the initialization information.

    The provider should not return any other error status codes.

    */
typedef SshEkStatus (*SshEkProviderInit)(const char *initialization_info,
                                         void *initialization_ptr,
                                         SshEkNotifyCB notify_cb,
                                         SshEkAuthenticationCB
                                         authentication_cb,
                                         void *context,
                                         void **provider_context_return);

/** Uninitializes the provider.

    When this provider has been uninitialized (uninitialization may be
    an asynchronous operation), the notify callback should be called
    with event SSH_EK_EVENT_PROVIDER_DISABLED.

    @param provider_context
    The value returned by the init function.  If there are public or
    private keys out that use this provider instance, unitializing the
    provider instance will be delayed until the last of them has been
    freed using the ssh_public_key_free or ssh_private_key_free
    functions.  This means that the provider must do reference
    counting.

    */
typedef void (*SshEkProviderUninit)(void *provider_context);

/** Retrieves a public key based on the keypath.

    Having a public key for a provider should not lock anything.  In
    particular, having a key for a smartcard does not prevent other
    applications from using the smartcard.  The provider must lock and
    queue requests when actual operations are performed using it.

    @param keypath
    The keypath is in the same format as passed from the provider to
    the notify callback.  The key object must remain valid until it
    has been freed using ssh_public_key_free, even if for example the
    smartcard is removed from the reader or the provider is
    uninitialized.

    */
typedef SshOperationHandle (*SshEkProviderGetPublicKey)
     (void *provider_context,
      const char *keypath,
      SshEkGetPublicKeyCB get_public_key_cb, void *context);

/** Retrieves a private key based on the keypath.

    Having a public key for a provider should not lock anything.  In
    particular, having a key for a smartcard does not prevent other
    applications from using the smartcard.  The provider must lock and
    queue requests when actual operations are performed using it.

    @param keypath
    The keypath is in the same format as passed from the provider to
    the notify callback.  The key object must remain valid until it
    has been freed using ssh_private_key_free, even if e.g. the
    smartcard is removed from the reader or the provider is
    uninitialized.

    */
typedef SshOperationHandle (*SshEkProviderGetPrivateKey)
     (void *provider_context,
      const char *keypath,
      SshEkGetPrivateKeyCB get_private_key_cb, void *context);

/** Retrieves a certificate based on the keypath.

    @param keypath
    The keypath is in the same format as passed from the provider to
    the notify callback. The provider may free the provided
    certificate when the get_certicate_cb returns.

    */
typedef SshOperationHandle (*SshEkProviderGetCertificate)
     (void *provider_context,
      const char *keypath, SshUInt32 cert_index,
      SshEkGetCertificateCB get_certificate_cb, void *context);

/** Retrieves a trusted certificate from the provider.

    @return
    If there are no trusted certificates with the index,
    SSH_EK_NO_MORE_CERTIFICATES is returned in callback. The provider
    may free the provided certificate when the get_certicate_cb
    returns.

    */
typedef SshOperationHandle (*SshEkProviderGetTrustedCert)
     (void *provider_context, SshUInt32 cert_index,
      SshEkGetCertificateCB get_certificate_cb, void *context);


/** Retrieve a group (such as a Diffie-Hellman group) from a
    provider. Caller must provide the name of the group in name.

    @param group_path
    Contains the provider and the name of the group which is provider
    specific, but if the provider can generate standard ike groups,
    they should be named "ike-1", "ike-2" and so on.

    @return
    The group is returned in a callback.

    */
typedef SshOperationHandle (*SshEkProviderGetGroup)(void *provider_context,
                                                    const char *group_path,
                                                    SshEkGetGroupCB callback,
                                                    void *context);

/** Returns the printable name of the provider. A typical name could
    be "Zappa Inc. Smartcard Interface".  The name should be
    user-printable, so that it can be displayed in a configuration dialog. */
typedef const char *(*SshEkProviderGetPrintableName)(void *provider_context);

/** Generates an accelerated version of the key. The provider inspects
    the source key and builds an accelerated version of it and
    returns the accelerated key if successful. This callback can be
    NULL. Providers who support key acceleration should be initialized
    with the SSH_EK_PROVIDER_FLAG_ACCELERATOR flag. */
typedef SshOperationHandle (*SshEkProviderGenAccPrvKey)
     (void *provider_context,
      SshPrivateKey source,
      SshEkGetPrivateKeyCB get_private_key_cb, void *context);

/** Generates an accelerated version of the key. The provider inspects
    the source key and builds an accelerated version of it and
    returns the accelerated key if successful. This callback can be
    NULL. Providers who support key acceleration should be initialized
    with the SSH_EK_PROVIDER_FLAG_ACCELERATOR flag. */
typedef SshOperationHandle (*SshEkProviderGenAccPublicKey)
     (void *provider_context,
      SshPublicKey source,
      SshEkGetPublicKeyCB get_public_key_cb, void *context);

/** Generate an accelerated group. The provider inspects the source
    group and builds and accelerated version of the group and returns
    it in the callback. */
typedef SshOperationHandle (*SshEkProviderGenAccGroup)
     (void *provider_context,
      SshPkGroup source,
      SshEkGetGroupCB callback,
      void *context);

/** Get random bytes. The provider will attempt to generate the
    requested number of random bytes and return them in the
    callback. The provider may return fewer than the requested number
    of random bytes in the callback.*/
typedef SshOperationHandle (*SshEkProviderGetRandomBytes)
     (void *provider_context,
      size_t bytes_requested,
      SshEkGetRandomBytesCB callback,
      void *context);

/** Sends a provider specific message. When provider has
    received/handled the message, it will call the message_cb. It can
    give some additional information to application by using the
    message_context argument in the callback function. */
typedef SshOperationHandle (*SshEkProviderSendMessage)
     (void *provider_context,
      const char *message,
      void *message_arg,
      size_t message_arg_len,
      SshEkSendMessageCB message_cb, void *context);

/*--------------------------------------------------------------------*/
/** Data structure describing the provider.  There should be one of
    these structures for each provider type.                          */
/*--------------------------------------------------------------------*/
struct SshEkProviderOpsRec
{
  /** Provider type. */
  char *type;

  /** Function to initialize the provider. */
  SshEkProviderInit init;

  /** Function to uninitialize the provider - this may not destroy the
      provider immediately if there are keys that reference it;
      this function will be called if the provider is removed using
      ssh_ek_remove_provider. */
  SshEkProviderUninit uninit;

  /** Retrieves a public key from the provider. */
  SshEkProviderGetPublicKey get_public_key;

  /** Retrieves a private key from the provider. */
  SshEkProviderGetPrivateKey get_private_key;

  /** Retrieves a certificate from the provider. */
  SshEkProviderGetCertificate get_certificate;

  /** Retrieves a trusted certificate from the provider. */
  SshEkProviderGetTrustedCert get_trusted_cert;

  /** Retrieve a group from a provider */
  SshEkProviderGetGroup get_group;

  /** Returns a printable name of of the provider. */
  SshEkProviderGetPrintableName get_printable_name;

  /** Gets the accelerated private key. */
  SshEkProviderGenAccPrvKey gen_acc_private_key;

  /** Gets the accelerated public key. */
  SshEkProviderGenAccPublicKey gen_acc_public_key;

  /** Gets the accelerated group. */
  SshEkProviderGenAccGroup gen_acc_group;

  /** Gets random bytes from the provider. */
  SshEkProviderGetRandomBytes get_random_bytes;

  /** Sends a provider-specific message. */
  SshEkProviderSendMessage send_message;

};

/*--------------------------------------------------------------------*/
/* Helper functions for providers.                                    */
/*--------------------------------------------------------------------*/

/** Extracts the public key from a binary certificate. */
SshPublicKey
ssh_ek_extract_public_key_from_certificate(const unsigned char *data,
                                           size_t data_len);

#define SSH_EK_PROVIDER_DEFAULT_HASH "sha1"

/** Hashes the buffer using SSH_EK_PROVIDER_DEFAULT_HASH (sha) and
    forms a printable string (base64) string from the result of the
    hash.

    This is useful for providers that need to format printable
    keypaths from long arbitary buffers.  */
void ssh_ek_provider_hash_buffer_to_string(const unsigned char *buf,
                                           size_t buf_len,
                                           char **str_result_return);

/** Makes a base64 string from a buffer.

    This is useful for providers that need to form printable keypaths
    from arbitary buffers. */
void ssh_ek_provider_buffer_to_string(const unsigned char *buf,
                                      size_t buf_len,
                                      char **str_result_return);

/** Get the size of public key in bits, e.g 1024 commonly for RSA.

    @return
    The value -1 indicates an error.

    */
SshInt32 ssh_ek_get_pub_key_size(SshPublicKey key);

/** The type representing the auth call handle, which can be used to
    free, or do the retry calls */
typedef struct SshEkAuthCallRec *SshEkAuthCall;

/** The type of the callback what the ek_perform_auth_call calls when
    it has acquired the authentication code from the user using the
    callback. If the code is not correct, the call to the user can be
    retried with ssh_ek_auth_call_retry. The aborted value is set to true
    when the operation handle, returned from ssh_ek_perform_auth_call
    was aborted.

    The call can be retried by providing the function
    ssh_ek_auth_call_retry, the call and a status argument. */
typedef SshOperationHandle (*SshEkAuthCallTryCB)(Boolean aborted,
                                                 SshEkAuthCall call,
                                                 const unsigned char *code,
                                                 size_t code_len,
                                                 void *context);

/** Perform an authentication call query from the user.

    Arguments are the following:
    - status: the status that is given to  the user authentication call
    - auth_cb: the callback which is used to perform the query
    - auth_ctx: the context that is provided to the auth_cb
    - try_callback: The callback which is called when the code has
      been acquired or the call has been cancelled.
    - context: context provided to the try_callback.

    It is quaranteed that the call will be asynchronous.

    @return
    If NULL is returned, a memory allocation error occurred.

    */
SshOperationHandle ssh_ek_perform_auth_call(const char *keypath,
                                            const char *label,
                                            SshEkAuthenticationStatus status,
                                            SshEkAuthenticationCB auth_cb,
                                            void *auth_ctx,
                                            SshEkAuthCallTryCB try_callback,
                                            void *context);

/** The call can be retried with this. Other arguments are reused, and
    the same operation handle aborts the whole query. */
void ssh_ek_auth_call_retry(SshEkAuthCall call,
                            SshEkAuthenticationStatus status);

/** Free the authentication call. */
void ssh_ek_auth_call_free(SshEkAuthCall call);

#endif /* EXTKEYPROV_H */
