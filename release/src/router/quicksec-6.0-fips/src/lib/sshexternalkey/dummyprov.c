/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Example provider file, which can be used as a starting point for new
   providers. Just replace dummy with something more sensible.
*/

#define SSH_DEBUG_MODULE "SshEKDummy"

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "extkeyprov.h"
#include "sshproxykey.h"
#include "sshmiscstring.h"

/* The structure holding the dummy provider parameters.  */
typedef struct SshDummyProvRec
{
  /* Notification callback for the keys. The provider needs to call
   this to announce the new keys */
  SshEkNotifyCB notify_callback;

  /* Authentication callack. The provider can call this to get
     authentication data from the user, e.g. PIN code */
  SshEkAuthenticationCB auth_callback;

  /* The context that is passed to the upper layer in notify_callback
     and in auth_callback */
  void *callback_context;

  /* Number of keys out */
  SshUInt32 keys_out;

  /* Set to true when the provider is destroyed. */
  Boolean destroyed;

  /* Set to true, when the provider has been enabled. */
  Boolean enabled;

  /* Set to true if tracing is enabled. Tracing_enabled means that the
     provider is actively looking for key changes. It makes sense, to
     set this to false, if looking for key changes is too cpu/memory
     consuming.  */
  Boolean enable_tracing;

  /* Add here other provider specific fields. */
} *SshDummyProv, SshDummyProvStruct;

#define SSH_DUMMY_PARAMETER "dummy"
/* Parse the initialization information provided for the provider at
   the initialization stage. */
static Boolean
dummy_prov_parse_init_info(SshDummyProv dummy,
                           const char *info)
{
  char *comp_data;

  /* Get the first occurance of the DUMMY parameter */
  comp_data = ssh_get_component_data_from_string(info,
                                                  SSH_DUMMY_PARAMETER, 0);

  ssh_free(comp_data);
  return TRUE;
}


/* Disables the provider. The user does not need notification callbacks from
   this provider. */
static void
dummy_prov_disable(void *provider_context)
{
  SshDummyProv dummy = provider_context;

  dummy->enabled = FALSE;

  if (dummy->notify_callback)
    (*dummy->notify_callback)(SSH_EK_EVENT_PROVIDER_DISABLED,
                              NULL, "Dummy Provider Disabled", 0,
                              dummy->callback_context);
}


/* Enables this provider. */
static void
dummy_prov_enable(void *provider_context)
{
  SshDummyProv dummy = provider_context;

  dummy->enabled = TRUE;
  dummy->enable_tracing = TRUE;

  if (dummy->notify_callback)
    (*dummy->notify_callback)(SSH_EK_EVENT_PROVIDER_ENABLED,
                              NULL, "Dummy Provider Enabled", 0,
                              dummy->callback_context);
  return;
}


/* Uninitializes the provider.  The provider_context is the value returned
   by the init function.  If there are public or private keys out that
   use this provider instance, unitializing the provider instance will
   be delayed until the last of them has been freed using ssh_public_key_free
   or ssh_private_key_free.  This means that the provider must do reference
   counting. */
static void
dummy_prov_uninit(void *provider_context)
{
  SshDummyProv dummy = provider_context;

  dummy->destroyed = TRUE;
  if (dummy->keys_out > 0)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Provider uninitialized, but keys still out. "
                                 "Deferring uninitialization"));
      return;
    }

  dummy_prov_disable(dummy);

  ssh_free(dummy);
}


/* Initializes the provider and allocates a context for it.  If multiple
   providers of the same type are specified with different initialization
   info, this will be called for each of them. This returns a provider
   context, which is a private data type for the provider type specified glue.
   The provider_context_return is passed to all of the other functions.

   Following error messages are defined:

   SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID fails because the initialization
   information given was invalid. (DLL search path invalid etc..)

   SSH_EK_PROVIDER_INITIALIZATION_FAILED initialization failed for some other
   reason than the initializaion information.

   The provider should not return any other error status codes.

   The provider instance must keep track of any keys that it has announced
   using the notify callback, and deliver SSH_EK_EVENT_KEY_UNAVAILABLE
   notifications for any such keys if e.g. the smartcard on which they are
   stored is removed.

   When the provider calls the notify callback, the keypath argument should
   only contain the part of the path that is interpreted by the provider.
   The generic code will prefix the path with the provider tag, and will
   remove the prefix whenever a path is passed to the provider.

   This should not call the notify callback before this provider is enabled. */
static SshEkStatus
dummy_prov_init(const char *initialization_info,
                void *init_ptr,
                SshEkNotifyCB notify_cb,
                SshEkAuthenticationCB
                authentication_cb,
                void *context,
                void **provider_context_return)
{
  SshDummyProv dummy;

  dummy = ssh_calloc(1, sizeof(*dummy));

  if (dummy == NULL)
    return SSH_EK_PROVIDER_INITIALIZATION_FAILED;

  dummy->notify_callback = notify_cb;
  dummy->auth_callback = authentication_cb;
  dummy->callback_context = context;

  if (dummy_prov_parse_init_info(dummy, initialization_info) == FALSE)
    {
      ssh_free(dummy);
      return SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID;
    }

  *provider_context_return = dummy;

  ssh_register_timeout(NULL, 0, 0, dummy_prov_enable, dummy);

  return SSH_EK_OK;
}







/* The context for dummy provider keys */
typedef struct SshDummyKeyRec
{
  /* Back pointer to the provider */
  SshDummyProv dummy;

  /* Keypath. This may or may not be needed in here */
  char *keypath;

  /* Add here other key specific fields. */
} *SshDummyKey, SshDummyKeyStruct;

/* The destroy function for dummy provider keys */
static void
ssh_dummy_key_free(SshDummyKey key)
{
  if (key)
    {
      key->dummy->keys_out--;
      if (key->dummy->destroyed)
        dummy_prov_uninit(key->dummy);

      ssh_free(key->keypath);
      ssh_free(key);
    }
}

static void
ssh_dummy_key_free_cb(void *context)
{
  SshDummyKey key = context;
  ssh_dummy_key_free(key);
}

/* The callback that is called when calls to ssh_private key sign are
   made with the proxy key */
static SshOperationHandle
ssh_dummy_key_sign_cb(SshProxyRGFId rgf_id,
                      const unsigned char *data,
                      size_t data_len,
                      SshProxyReplyCB reply_cb,
                      void *reply_context,
                      void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyKey key = context;
#endif

  /* For the sake of example, lets just fail */
  (*reply_cb)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);

  /* We return NULL because we were synchronous. If we had been
     asynchronous, we had retrurned an SshOperationHandle object, by
     which the asunc operation could have been cancelled. */
  return NULL;
}

/* The callback that is called when calls to ssh_private_key_decrypt
   are made with the procy key */
static SshOperationHandle
ssh_dummy_key_decrypt_cb(SshProxyRGFId rgf_id,
                         const unsigned char *data,
                         size_t data_len,
                         SshProxyReplyCB reply_cb,
                         void *reply_context,
                         void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyKey key = context;
#endif

  /* For the sake of example, lets just fail */
  (*reply_cb)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);

  /* We return NULL because we were synchronous. If we had been
     asynchronous, we had retrurned an SshOperationHandle object, by
     which the asunc operation could have been cancelled. */
  return NULL;
}


SshOperationHandle ssh_dummy_key_op_cb(SshProxyOperationId operation_id,
                                       SshProxyRGFId rgf_id,
                                       SshProxyKeyHandle handle,
                                       const unsigned char *input_data,
                                       size_t input_data_len,
                                       SshProxyReplyCB reply_cb,
                                       void *reply_context,
                                       void *context)
{
  switch (operation_id)
    {
    case SSH_RSA_PRV_DECRYPT:
      return ssh_dummy_key_decrypt_cb(rgf_id, input_data, input_data_len,
                                   reply_cb, reply_context, context);

    case SSH_RSA_PRV_SIGN:
      return ssh_dummy_key_sign_cb(rgf_id, input_data, input_data_len,
                                   reply_cb, reply_context, context);

    default:
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }
}

/* Creates a proxy key. */
static SshPrivateKey
dummy_prov_create_proxy_key(SshDummyProv dummy,
                            const char *keypath)
{
  SshDummyKey key = NULL;
  SshPrivateKey proxy_key;

  /* We allocate a key context */
  key = ssh_calloc(1, sizeof(*key));
  if (key == NULL)
    goto failed;

  /* In reality, we would put something sensible inside the key. Now
     we just put the keypath into the context */
  key->keypath = ssh_strdup(keypath);
  if (key->keypath == NULL)
    goto failed;

  key->dummy = dummy;
  /* Lets create a 1024 bit RSA proxy key. The first FALSE means that
     we let the proxy key to do all padding for us, so that we need
     only concentrate on doing the plain RSA on the callback (and no
     hashing or PKCS#1 padding). */
  proxy_key = ssh_private_key_create_proxy(SSH_PROXY_RSA, 1024,
                                           ssh_dummy_key_op_cb,
                                           ssh_dummy_key_free_cb,
                                           key);
  if (proxy_key == NULL)
    goto failed;


  /* We return NULL, because we did everything synchronously. */
  return proxy_key;

 failed:
  ssh_dummy_key_free(key);
  return NULL;
}

/* Retrieves a public key based on the keypath.  The keypath is in the
   same format as passed from the provider to the notify callback.
   The key object must remain valid until it has been freed using
   ssh_public_key_free, even if e.g. the smartcard is removed from the
   reader or the provider is uninitialized.

   Having a public key for a provider should not lock anything.  In
   particular, having a key for a smartcard does not prevent other
   applications from using the smartcard.  The provider must lock and
   queue requests when actual operations are performed using it.  */
static SshOperationHandle
dummy_prov_get_public_key(void *provider_context,
                          const char *keypath,
                          SshEkGetPublicKeyCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
  return NULL;
}


/* Retrieves a private key based on the keypath.  The keypath is in the
   same format as passed from the provider to the notify callback.
   The key object must remain valid until it has been freed using
   ssh_private_key_free, even if e.g. the smartcard is removed from the
   reader or the provider is uninitialized.

   Having a public key for a provider should not lock anything.  In
   particular, having a key for a smartcard does not prevent other
   applications from using the smartcard.  The provider must lock and
   queue requests when actual operations are performed using it. */
static SshOperationHandle
dummy_prov_get_private_key(void *provider_context,
                           const char *keypath,
                           SshEkGetPrivateKeyCB callback, void *context)
{
  SshDummyProv dummy = provider_context;
  SshPrivateKey proxy_key;
  SshEkStatus status = SSH_EK_OK;

  proxy_key = dummy_prov_create_proxy_key(dummy, keypath);
  if (proxy_key != NULL)
    {
      /* Proxy key created succesfully */
      dummy->keys_out++;
    }
  else
    {
      /* Failed to crete the proxy key */
      status = SSH_EK_FAILED;
    }

  /* Call the callback with success status */
  (*callback)(status, proxy_key, context);
  return NULL;
}


/* Retrieves a certificate based on the keypath.  The keypath is in
   the same format as passed from the provider to the notify callback.
   The provider may free the provided certificate when the
   get_certicate_cb returns. */
static SshOperationHandle
dummy_prov_get_certificate(void *provider_context,
                           const char *keypath, SshUInt32 cert_index,
                           SshEkGetCertificateCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
  return NULL;
}


/* Retrieves a trusted certificate from the provider. If there are no
   trusted certificates with the index, SSH_EK_NO_MORE_CERTIFICATES is
   returned in callback. The provider may free the provided
   certificate when the get_certicate_cb returns. */
static SshOperationHandle
dummy_prov_get_trusted_certs(void *provider_context, SshUInt32 cert_index,
                             SshEkGetCertificateCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
  return NULL;
}



/* Rertrieve a group (such as a diffie-hallman group) from a
   provider. Caller must provide the name of the group in name. The
   group is returned in a callback. The group_path contains the
   provider and the name of the group which is provider specific, but
   if the provider can generate standard ike groups, they should be
   named "ike-1", "ike-2" and so on. */
static SshOperationHandle
dummy_prov_get_group(void *provider_context,
                     const char *group_path,
                     SshEkGetGroupCB callback,
                     void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
  return NULL;
}


/* Returns the printable name of the privoder. A typical name could
   be "Zappa Inc. Smartcard Interface".  The name should be
   user-printable, so that it can be displayed in a configuration dialog. */
static const char *
dummy_prov_get_printable_name(void *provider_context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  return "Dummy provider";
}



/* Generates an accelerated version of the key. The provider inspects
   the source key and builds an accelerated version of it and returnes
   the accelerated key if succesfull. This callback can be
   NULL. Providers who support key acceleration should be initialized
   flag SSH_EK_PROVIDER_FLAG_ACCELERATOR. */
static SshOperationHandle
dummy_prov_gen_acc_prvkey(void *provider_context,
                          SshPrivateKey source,
                          SshEkGetPrivateKeyCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
  return NULL;
}

/* Generates an accelerated version of the key. The provider inspects
   the source key and builds an accelerated version of it and returnes
   the accelerated key if succesfull. This callback can be
   NULL. Providers who support key acceleration should be initialized
   with the flag SSH_EK_PROVIDER_FLAG_ACCELERATOR. */
static SshOperationHandle
dummy_prov_gen_acc_pubkey(void *provider_context,
                          SshPublicKey source,
                          SshEkGetPublicKeyCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
  return NULL;
}

/* Generate an accelerated group. The provider inspects the source group
   and builds and accelerated version of the group and returns it in
   the callback. */
static SshOperationHandle
dummy_prov_gen_acc_group(void *provider_context,
                         SshPkGroup source,
                         SshEkGetGroupCB callback,
                         void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
  return NULL;
}


/* Get random bytes. The provider will attempt to generate the requested
   number of random bytes and return them in the callback. The provider
   may return fewer than the requested number of random byrtes in the
   callback.*/
static SshOperationHandle
dummy_prov_get_random_bytes(void *provider_context,
                            size_t bytes_requested,
                            SshEkGetRandomBytesCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
  return NULL;
}

/* Sends a provider specific message. When provider has received/handled
   the message, it will call the message_cb. It can give some
   additional information to application by using the message_context
   argument in the callback functio. */
static SshOperationHandle
dummy_prov_send_message(void *provider_context,
                        const char *message,
                        void *message_arg, size_t message_arg_len,
                        SshEkSendMessageCB callback, void *context)
{
#if 0
  /* Here as an example, but conditioned out, because causes
     an "unused variable" compiler warning. */
  SshDummyProv dummy = provider_context;
#endif
  (*callback)(SSH_EK_UNKNOWN_MESSAGE, NULL, 0, context);
  return NULL;
}

/* This is the GLOBAL provider function pointer array we pass to the
   sshexternalkey.c.  It is identified with the externalkey provider
   prefix, which is in our case "dummy". The other fields are
   function pointers to the provider methods. More documentation for
   functions can be found in extkeyprov.h. */
const
struct SshEkProviderOpsRec ssh_ek_dummy_ops =
  {
    "dummy",
    dummy_prov_init,
    dummy_prov_uninit,
    dummy_prov_get_public_key,
    dummy_prov_get_private_key,
    dummy_prov_get_certificate,
    dummy_prov_get_trusted_certs,
    dummy_prov_get_group,
    dummy_prov_get_printable_name,
    dummy_prov_gen_acc_prvkey,
    dummy_prov_gen_acc_pubkey,
    dummy_prov_gen_acc_group,
    dummy_prov_get_random_bytes,
    dummy_prov_send_message
  };
