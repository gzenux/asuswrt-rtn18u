/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshexternalkey_internal.h"

#define SSH_DEBUG_MODULE "SshEKSystem"


/* The data structure that describes the provider. This is not meant
   to be altered directly. */
typedef struct SshEkProviderInternalRec
{
  /* Internal next pointer. */
  struct SshEkProviderInternalRec *next;

  /* The type of provider. */
  char *type;

  /* The flags of provider. */
  SshEkProviderFlags flags;

  /* The provider function pointers. */
  SshEkProviderOps provider_ops;

  /* A printable name for the provider. */
  const char *printable_name;

  /* The provider short name. Provider short name uniquely identifies
     the provider. */
  char *short_name;

  /* The initialization information that was used to install this
     provider. */
  char *info;

  /* The provider context obtained from underyling provider implementation,
     we pass to the provider when asking actions from it. */
  void *provider_context;

  /* The Provider has been enabled. */
  Boolean enabled;

  /* The Provider has been marked as destroyed. */
  Boolean destroyed;
  /* Provider uninitialization has been called. */
  Boolean destroy_pending;

  /* The tracking (automatic notify when keys are available) is on */
  Boolean tracking_enabled;

  /* This provider has been registered as a noise source to crypto library. */
  Boolean noise_src;

  /* Operation handle for ongoing get_random_bytes for noise generation. */
  SshOperationHandle noise_src_operation;

  /* This provider is handling an ongoing noise src request. Can not trust on
     noise_src_operation to detect this in case of a synchronous
     get_random_bytes() implementation. */
  Boolean noise_src_operation_ongoing;

  /* The externalkey this provider belongs to. */
  SshExternalKey externalkey;
} *SshEkProviderInternal;

/* This is an externalkey context that is used with all externalkey
   actions. It is not meant to be used straightly. */
struct SshExternalKeyRec
{
  /* Pin callback that is called when a pin to the keyis needed. */
  SshEkAuthenticationCB authentication_cb;

  /* Authentication callback context */
  void *authentication_context;

  /* The notify callback of the external key. */
  SshEkNotifyCB notify_cb;

  /* The notify callback context. */
  void *notify_context;

  /* The linked list of providers */
  SshEkProviderInternal providers;

  /* Map of key names reported to ssh_ek_internal_notify_cb, used to resolve
     wildcard searches. */
  SshADTContainer available_keys;

  SshInt32 refcount;

  /* If TRUE we are waiting to destroy the externalkey. */
  Boolean destroyed;

  /* Callback and context that are called when externalkey is freed. */
  SshEkFreeCB free_callback;
  void *free_context;
};


/******************* Crypto library noise source implementation **************/

/* Maximum number of random bytes to request per noise request. */
#define SSH_EK_NOISE_SOURCE_MAX_BYTES         16

/* Estimated number of entropy bits in a random byte. */
#define SSH_EK_NOISE_SOURCE_ENTROPY_PER_BYTE  8

/* Completion callback for get_random_bytes. */
static void
noise_request_get_random_bytes_cb(SshEkStatus status,
                                  const unsigned char *noise_bytes,
                                  size_t noise_bytes_length,
                                  void *context)
{
  SshEkProviderInternal provider = context;

  SSH_ASSERT(provider != NULL);
  SSH_ASSERT(provider->noise_src);

  /* Add random bytes as noise to crypto library. */
  if (status == SSH_EK_OK)
    ssh_random_add_noise(noise_bytes, noise_bytes_length,
                         noise_bytes_length
                         * SSH_EK_NOISE_SOURCE_ENTROPY_PER_BYTE);

  /* Complete noise request. */
  provider->noise_src_operation_ongoing = FALSE;
  provider->noise_src_operation = NULL;
}

/* Noise request callback. */
static void ssh_ek_noise_request_cb(void *context)
{
  SshEkProviderInternal provider = context;

  SSH_ASSERT(provider != NULL);
  SSH_ASSERT(provider->noise_src);
  SSH_ASSERT(provider->provider_ops->get_random_bytes != NULL_FNPTR);

  /* Ignore noise request if already fetching noise for crypto library
     or if provider destroy is pending. */
  if (provider->noise_src_operation_ongoing
      || provider->destroyed || provider->destroy_pending)
    return;

  /* TODO: Rate limit according to device capability. */

  SSH_DEBUG(SSH_D_LOWOK,
            ("Fetching random data for crypto library from provider '%s'",
             provider->short_name ));

  /* Request random bytes from hardware. */
  provider->noise_src_operation_ongoing = TRUE;
  provider->noise_src_operation = (*provider->provider_ops->get_random_bytes)
    (provider->provider_context, SSH_EK_NOISE_SOURCE_MAX_BYTES,
     noise_request_get_random_bytes_cb, provider);
}

/* Unregister noise source from crypto library. This also cancels any ongoing
   noise request operation. */
static void ssh_ek_unregister_noise_src(SshEkProviderInternal provider)
{
  SSH_ASSERT(provider != NULL);
  SSH_ASSERT(provider->noise_src);

  /* Unregister noise source from crypto library. */
  if (ssh_crypto_library_unregister_noise_request(ssh_ek_noise_request_cb,
                                                  provider))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Unregistered crypto library noise source '%s'",
                              provider->short_name));
      provider->noise_src = FALSE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to unregister crypto library noise source '%s'",
                 provider->short_name));
    }

  /* Cancel ongoing noise request operation. */
  if (provider->noise_src_operation != NULL)
    {
      ssh_operation_abort(provider->noise_src_operation);
      provider->noise_src_operation = NULL;
    }
}


/************************* Externalkey internals *****************************/

/* Returns TRUE if all providers are destroyed */
static Boolean ssh_ek_all_providers_destroyed(SshExternalKey externalkey)
{
  SshEkProviderInternal provider;
  Boolean destroyed = FALSE;

  provider = externalkey->providers;

  while (provider)
    {
      if (!provider->destroyed)
        break;

      provider = provider->next;
    }
  if (provider == NULL)
    destroyed = TRUE;

  return destroyed;
}

static void ssh_ek_destroy(void *ctx)
{
  SshExternalKey externalkey = ctx;
  SshEkProviderInternal provider, p;

  SshEkFreeCB callback = externalkey->free_callback;
  void *callback_context = externalkey->free_context;

  SSH_ASSERT(externalkey->destroyed);

  p = provider = externalkey->providers;

  /* Free all the providers. */
  while (provider)
    {
      provider = provider->next;

      /* Free the internal provider structure. */
      ssh_free(p->info);
      ssh_free(p->type);
      ssh_free(p->short_name);
      ssh_free(p);

      p = provider;
    }

  ssh_adt_destroy(externalkey->available_keys);

  ssh_free(externalkey);

  /* Call the free callback to inform the application that we are done */
  if (callback)
    (*callback)(callback_context);
}

void ssh_ek_free_internal(SshExternalKey externalkey)
{
  SshEkProviderInternal provider;

  provider = externalkey->providers;

  if (provider == NULL)
    {
      SshEkFreeCB callback = externalkey->free_callback;
      void *callback_context = externalkey->free_context;

      ssh_adt_destroy(externalkey->available_keys);
      ssh_free(externalkey);

      /* Call the free callback to inform the application that we are done */
      if (callback)
        (*callback)(callback_context);
      return;
    }

  externalkey->destroyed = TRUE;

  /* Uninit all the providers. */
  while (provider)
    {
      /* Unregister noise source from crypto library. */
      if (provider->noise_src)
        ssh_ek_unregister_noise_src(provider);

      if (!provider->destroy_pending && provider->provider_ops->uninit)
        {
          provider->destroy_pending = TRUE;
          (*provider->provider_ops->uninit)(provider->provider_context);
        }

      provider = provider->next;
    }
}

static void ssh_ek_inc_refcount(SshExternalKey ek)
{
  ek->refcount++;
}

static void ssh_ek_dec_refcount(SshExternalKey ek)
{
  ek->refcount--;

  if (ek->refcount == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Free EK"));
      ssh_ek_free_internal(ek);
    }
}

/* Returns a provider type for a given provider name. Provider name
   can be either a short name or a keypath.  */
char *ssh_ek_get_provider_type(const char *provider_name)
{
  unsigned char *scheme;

  if (ssh_url_parse(ssh_custr(provider_name), &scheme,
                    NULL, NULL, NULL, NULL, NULL))
    return ssh_sstr(scheme);
  else
    return NULL;
}

static const char *const ek_events[] =
{ "",
  "provider enabled",
  "provider disabled",
  "provider failure",
  "token inserted",
  "token scanned",
  "token remove detected",
  "token removed",
  "key available",
  "key unavailable",
  "event none"
};

const char *ssh_ek_get_printable_event(SshEkEvent event)
{
  if ((int)event < sizeof(ek_events) / sizeof(const char *))
    return ek_events[(int)event];
  else
    return "Unknown event";
}

const char *ssh_ek_get_printable_status(SshEkStatus status)
{
  switch (status)
    {
    case SSH_EK_OK: return "The EK operation was successful";
    case SSH_EK_TOKEN_NOT_INSERTED: return "Token not inserted";
    case SSH_EK_TOKEN_UNRECOGNIZED: return "Unrecognized token";
    case SSH_EK_TOKEN_ERROR: return "Token error";
    case SSH_EK_PROVIDER_NOT_AVAILABLE: return "Provider not available";
    case SSH_EK_KEY_FILE_NOT_FOUND: return "File not found";
    case SSH_EK_KEY_NOT_FOUND: return "Object not found";
    case SSH_EK_KEY_ACCESS_DENIED: return "Access denied";
    case SSH_EK_KEY_BAD_FORMAT: return "Bad format";
    case SSH_EK_NO_MORE_CERTIFICATES: return "No more certificates";
    case SSH_EK_PROVIDER_TYPE_NOT_SUPPORTED:
      return "Provider type not supported";
    case SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID:
      return "Initialization information is invalid";
    case SSH_EK_PROVIDER_INITIALIZATION_FAILED:
      return "Initialization failed";
    case SSH_EK_UNKNOWN_MESSAGE: return "Unknown message";
    case SSH_EK_FAILED:
      return "EK operation failed";
    default:
      {
        SSH_DEBUG(0, ("Unkown status %d", status));
        return "Unknown Status";
      }
    }
}

/* Finds the appropriate structure for the type of provider. It is
   kind of slow to enumerate all the provider types and use strcmp
   for all of them, but assumably there wont be so many providers. If
   there will be more than 15 different provider types, one could
   considering maintaining a hash table mapping between provider
   names. */
static SshEkProviderOps
ssh_ek_find_provider_ops(const char *type)
{
  int i = 0;

  if (!type)
    return NULL;

  while (ssh_ek_supported_providers[i] != NULL &&
         strcmp(ssh_ek_supported_providers[i]->type, type))
    i++;

  return ssh_ek_supported_providers[i];
}


/* Buils the user keypath, a keypath that can be displayed to the
   user, that contains the provider short name as the prefix. Caller
   must free the returned keypath with ssh_free. Returns NULL if no
   memory is available.*/
static char *ssh_ek_get_user_keypath(const char *keypath,
                                     SshEkProviderInternal provider)
{
  char *user_keypath;

  if (!provider)
    return NULL;

  if (keypath)
  {
    user_keypath = (char *) ssh_calloc(1, strlen(provider->short_name) +
                                        strlen(keypath) + 1);
    if (!user_keypath)
      {
        SSH_DEBUG(SSH_D_FAIL, ("No memory available"));
        return NULL;
      }

    strcat(user_keypath, provider->short_name);
    strcat(user_keypath, keypath);
  }
  else
  {
    user_keypath = ssh_strdup(provider->short_name);
  }

  return user_keypath;
}


/* This is the internal authentication callback that is called by the
   providers. We redirect the call to the callback the application
   supplied if such is available. */
static SshOperationHandle
ssh_ek_internal_authentication_cb(const char *keypath,
                                  const char *label,
                                  SshUInt32 try_number,
                                  SshEkAuthenticationStatus auth_status,
                                  SshEkAuthenticationReplyCB reply_cb,
                                  void *reply_context,
                                  void *context)
{
  SshEkProviderInternal provider = context;
  char *user_keypath;
  SshOperationHandle handle;
  SshExternalKey ek;

  if (!provider)
    {
      /* The authetication callback will be cancelled. */
      (*reply_cb)(NULL, 0, reply_context);
      return NULL;
    }

  ek = provider->externalkey;

  if (ek == NULL || ek->authentication_cb == NULL_FNPTR)
    {
      /* No notify callback installed yet. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Internal authentication callback called, "
                 "but no application authentication callback defined. "));

      /* The authetication callback will be cancelled. */
      (*reply_cb)(NULL, 0, reply_context);
      return NULL;
    }

  /* Make a user keypath. */
  user_keypath = ssh_ek_get_user_keypath(keypath, provider);

  /* If no memory available, the authetication callback will be cancelled */
  if (!user_keypath)
    {
      (*reply_cb)(NULL, 0, reply_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Calling authentication callback for the key %s", user_keypath));

  handle =
    (*ek->authentication_cb)(user_keypath, label, try_number, auth_status,
                             reply_cb, reply_context,
                             ek->authentication_context);

  ssh_free(user_keypath);
  return handle;
}

/* Forward declaration. */
static void ssh_ek_provider_destroy(void *context);

/* This callback is called by providers, to anounce about available keys.
   This function will call the application callbacks with the keypath, that
   contains the provider prefix. */
static void
ssh_ek_internal_notify_cb(SshEkEvent event,
                          const char *keypath,
                          const char *label,
                          SshEkUsageFlags flags,
                          void *context)
{
  char *user_keypath;
  SshEkProviderInternal provider;
  SshExternalKey externalkey;
  Boolean exec_callback = TRUE;

  provider = context;

  if (provider == NULL || provider->externalkey == NULL)
    return;

  externalkey = provider->externalkey;

  if (externalkey->notify_cb == NULL_FNPTR)
    {
      /* No notify callback installed yet. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Internal notify callback called, "
                 "but no application callback defined."));
      exec_callback = FALSE;
    }

  /* Check if we need to deliver this callback at all. */
  if (!provider->enabled && (event != SSH_EK_EVENT_PROVIDER_DISABLED &&
                             event != SSH_EK_EVENT_PROVIDER_ENABLED))
    exec_callback = FALSE;

  user_keypath = ssh_ek_get_user_keypath(keypath, provider);

  /* If no memory available, just return. */
  if (keypath && !user_keypath)
   return;

  /* If this is a key-available event, remember the keypath so that
     keys can be later asked using pattern matching. Likewise, if this
     is a key-unavailable event, forget the key path. */
  SSH_DEBUG(SSH_D_MIDOK, ("Event %d, provider %s", event, user_keypath));

  switch (event)
    {
    case SSH_EK_EVENT_PROVIDER_ENABLED:
      provider->enabled = TRUE;
      SSH_DEBUG(SSH_D_MIDSTART,
                ("Enabled the provider %s, %s", keypath, label));
     break;
    case SSH_EK_EVENT_PROVIDER_DISABLED:
      /* Check if we are waiting to destroy the externalkey */
      provider->enabled = FALSE;
      if (externalkey->destroyed)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Mark the provider as destroyed"));
          provider->destroyed = TRUE;

          /* We wait until all providers are uninitialized before
             the final freeing */
          if (!ssh_ek_all_providers_destroyed(externalkey))
            break;

          SSH_DEBUG(SSH_D_MIDOK, ("Destroy externalkey now"));
          ssh_register_timeout(NULL, 0, 0, ssh_ek_destroy, externalkey);
          ssh_free(user_keypath);
          return;
        }
      else
        /* If not destroying externalkey, we are just removing a single
         provider, can finish it here. */
        {
          ssh_register_timeout(NULL, 0, 0, ssh_ek_provider_destroy, provider);
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Removed the provider %s, %s", keypath, label));
        }
      break;
    case SSH_EK_EVENT_KEY_AVAILABLE:
      if (user_keypath &&
          !ssh_adt_strmap_exists(externalkey->available_keys, user_keypath))
        ssh_adt_strmap_add(externalkey->available_keys, user_keypath, NULL);
      break;
    case SSH_EK_EVENT_KEY_UNAVAILABLE:
      if (user_keypath)
        ssh_adt_strmap_remove(externalkey->available_keys, user_keypath);
      break;
    default:
      break;
    }

  if (externalkey->destroyed)
    exec_callback = FALSE;

  /* Call the user callback */
  if (exec_callback)
    (*externalkey->notify_cb)(event, user_keypath, label,
                              flags, externalkey->notify_context);
  ssh_free(user_keypath);
}

static void
ssh_ek_add_new_provider_item(SshExternalKey externalkey,
                             SshEkProviderInternal provider)
{
  SshEkProviderInternal iter;

  SSH_DEBUG(SSH_D_LOWSTART, ("Adding new provider item"));

  if (provider == NULL || externalkey == NULL)
    return;

  provider->externalkey  = externalkey;
  if (externalkey->providers == NULL)
    {
      /* First provider case. */
      externalkey->providers = provider;
      return;
    }

  /* Find the last provider in the list and add the empty entry and
     return a pointer to it. */
  iter = externalkey->providers;
  while (iter->next != NULL)
    iter = iter->next;

  iter->next = provider;
}


static void
ssh_ek_remove_provider_item(SshExternalKey externalkey,
                            SshEkProviderInternal provider)
{
  SshEkProviderInternal iter, prev;

  SSH_DEBUG(SSH_D_LOWSTART, ("Removing a provider item"));

  if (provider == NULL || externalkey == NULL)
    return;

  /* Search the linked list for 'provider' */
  iter = externalkey->providers;
  prev = NULL;
  while (iter && iter->short_name &&
         strcmp(provider->short_name, iter->short_name) != 0)
    {
      prev = iter;
      iter = iter->next;
    }

  if (iter == NULL)
    return;

  /* Remove 'provider' from the linked list */
  if (prev == NULL)
    externalkey->providers = iter->next;
  else
    prev->next = iter->next;
}


/* Finds the internal provider record used by this short name. */
static SshEkProviderInternal
ssh_ek_find_provider_using_short_name(SshExternalKey externalkey,
                                      const char *short_name)
{
  SshEkProviderInternal  provider;

  if (externalkey == NULL || short_name == NULL)
    return NULL;

  provider = externalkey->providers;

  while (provider &&
         provider->short_name &&

         strcmp(short_name, provider->short_name) != 0)
    {
      provider = provider->next;
    }

  return (provider && provider->short_name) ? provider : NULL;
}

/* Adds the provider to the internal array of providers and returns a
   pointer to it. */
static SshEkStatus
ssh_ek_add_provider_internal(SshExternalKey externalkey,
                             const char *provider_short_name,
                             SshEkProviderOps provider_ops,
                             const char *info,
                             void *initialization_ptr,
                             SshEkProviderFlags flags,
                             SshEkProviderInternal *provider_internal_return)
{

  SshEkProviderInternal provider;
  SshEkStatus status;

  if (externalkey == NULL || provider_short_name == NULL)
    return SSH_EK_NO_MEMORY;

  provider = ssh_calloc(1, sizeof(*provider));

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No memory available"));
      return SSH_EK_NO_MEMORY;
    }

  /* Build the provider. */
  provider->externalkey = externalkey;
  provider->flags = flags;

  if (info)
    provider->info = ssh_strdup(info);

  provider->next = NULL;

  provider->short_name = ssh_strdup(provider_short_name);

  provider->provider_ops = provider_ops;
  provider->type = ssh_strdup(provider_ops->type);

  /* If no memory ... */
  if ((info && provider->info == NULL) || provider->short_name == NULL ||
      provider->type == NULL)
    {
      ssh_free(provider->info);
      ssh_free(provider->short_name);
      ssh_free(provider->type);
      ssh_free(provider);
      provider = NULL;

      return SSH_EK_NO_MEMORY;
    }

  /* Add new provider item to the list. */
  ssh_ek_add_new_provider_item(externalkey, provider);

  *provider_internal_return = provider;

  /* Initialize the provider. We obtain the provider context which we
     will use later when we ask actions from the provider. */
  if ((status = provider_ops->init(info,
                                   initialization_ptr,
                                   ssh_ek_internal_notify_cb,
                                   ssh_ek_internal_authentication_cb,
                                   provider,
                                   &provider->provider_context)) != SSH_EK_OK)
    {
      ssh_ek_remove_provider_item(externalkey, provider);
      ssh_free(provider->info);
      ssh_free(provider->short_name);
      ssh_free(provider->type);
      ssh_free(provider);
      provider = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("Provider initialization failed"));
      return status;
    }

  provider->printable_name =
    (*provider_ops->get_printable_name)(provider->provider_context);

  /* If provider implements get_random_bytes, add it as a noise source to
     crypto library. */
  if (provider_ops->get_random_bytes != NULL_FNPTR)
    {
      provider->noise_src = TRUE;
      if (ssh_crypto_library_register_noise_request(ssh_ek_noise_request_cb,
                                                    provider))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Registered provider '%s' as noise source to "
                     "crypto library",
                     provider->printable_name));
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to register provider '%s' as noise source to "
                     "crypto library",
                     provider->printable_name));
          ssh_ek_remove_provider_item(externalkey, provider);
          ssh_free(provider->info);
          ssh_free(provider->short_name);
          ssh_free(provider->type);
          ssh_free(provider);
          provider = NULL;
          SSH_DEBUG(SSH_D_FAIL, ("Provider initialization failed"));
          return SSH_EK_PROVIDER_INITIALIZATION_FAILED;
        }
    }

  return SSH_EK_OK;
}


/* Allocates the externalkey. Returns NULL if no memory. */
SshExternalKey ssh_ek_allocate()
{
  SshExternalKey externalkey;
  externalkey = ssh_calloc(sizeof(*externalkey), 1);

  if (externalkey)
    {
      externalkey->available_keys =
        ssh_adt_xcreate_strmap(NULL_FNPTR, ssh_adt_callback_destroy_free);
      ssh_ek_inc_refcount(externalkey);
    }

  return externalkey;
}


/* Frees the externalkey. */
void ssh_ek_free(SshExternalKey externalkey, SshEkFreeCB callback,
                 void *context)
{
  if (!externalkey)
    {
      if (callback)
        (*callback)(context);
      return;
    }

  externalkey->free_callback = callback;
  externalkey->free_context = context;

  ssh_ek_dec_refcount(externalkey);
}

void ssh_ek_register_authentication_callback(SshExternalKey externalkey,
                                             SshEkAuthenticationCB
                                             authentication_cb,
                                             void *context)
{
  if (externalkey)
    {
      externalkey->authentication_cb = authentication_cb;
      externalkey->authentication_context = context;
    }
}

/* After registering the notify callback, the user will be deliverd
   key available messages... */
void ssh_ek_register_notify(SshExternalKey externalkey,
                            SshEkNotifyCB notify_cb, void *context)
{
  if (externalkey)
    {
      externalkey->notify_cb = notify_cb;
      externalkey->notify_context = context;
    }
}

/* Returns an array of providers to the application. */
Boolean ssh_ek_get_providers(SshExternalKey externalkey,
                             SshEkProvider *providers_return,
                             SshUInt32 *num_providers_return)
{
  SshEkProviderInternal provider;
  int i, num_providers;

  if (!externalkey)
    return FALSE;

  /* Count the providers. */
  provider = externalkey->providers;
  num_providers = 0;
  while (provider)
    {
      if (provider->destroyed == FALSE && provider->destroy_pending == FALSE)
        num_providers++;
      provider = provider->next;
    }

  if (num_providers == 0)
    {
      *providers_return = NULL;
      *num_providers_return = 0;
      return TRUE;
    }

  /* Construct a user friendly array of providers. */
  *providers_return = (SshEkProvider)ssh_calloc(num_providers,
                                                sizeof(**providers_return));

  if (*providers_return == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No memory available"));
      *num_providers_return = 1;
      return FALSE;
    }

  i = 0;
  provider = externalkey->providers;

  while (i < num_providers)
    {
      const char *name;

      if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
        continue;

      name = (*provider->provider_ops->get_printable_name)
        (provider->provider_context);

      /* Copy data from internal provider linked list. */
      (*providers_return)[i].type = provider->type;
      (*providers_return)[i].enabled = provider->enabled;
      (*providers_return)[i].info =  provider->info;
      (*providers_return)[i].printable_name = name;
      (*providers_return)[i].short_name = provider->short_name;
      (*providers_return)[i].provider_flags = provider->flags;
      provider = provider->next;
      i++;
    }
  *num_providers_return = num_providers;
  return TRUE;
}

/* Finds a next available name for the provider of type "type". */
static char *ssh_ek_find_next_provider_name(SshExternalKey externalkey,
                                            SshEkProviderOps provider)
{
  const char *type = provider->type;
  unsigned char *name_test = NULL;
  int i = 0;
  Boolean found = FALSE;

  while (!found)
    {
      ssh_dsprintf(&name_test, "%s://%d/", type, i++);

      if (ssh_ek_find_provider_using_short_name(externalkey,
                                                ssh_sstr(name_test)))
        ssh_free(name_test);
      else
        found = TRUE;
    }
  return ssh_sstr(name_test);
}

/* Add an new provider to the system. The system has a set of built-in
   providers, which could be added with ssh_ek_add_provider. The
   custom providers can be added with this function by providing a
   pointer to the provider context. */
SshEkStatus ssh_ek_add_provider_external(SshExternalKey externalkey,
                                         SshEkProviderOps ops,
                                         const char *initialization_info,
                                         void *initialization_ptr,
                                         SshEkProviderFlags flags,
                                         char **short_name_ret)
{
  char *short_name;
  SshEkStatus status;
  SshEkProviderInternal provider;

  /* Find the next available provider name. */
  short_name = ssh_ek_find_next_provider_name(externalkey, ops);

  /* Use the internal provider adding function. */
  if ((status = ssh_ek_add_provider_internal(externalkey,
                                             short_name, ops,
                                             initialization_info,
                                             initialization_ptr,
                                             flags,
                                             &provider))
      != SSH_EK_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_ek_add_provider failed."));
      ssh_free(short_name);
      return status;
    }
  if (short_name_ret)
    *short_name_ret = short_name;
  else
    {
      ssh_free(short_name);
    }

  return SSH_EK_OK;
}


/* Adds a new provider.  This function would typically be called in
   the beginning of the program to add the provider for externalkey to
   use.  After the addition the provider should be enabled using
   ssh_ek_enable_provider. The providers can not be removed, they can
   only be disabled by calling ssh_ek_disable_provider. The added
   providers are freed, when the externalkey object is freed.

   <initialization_info> is provider specific. It may be a path to
   dynamic link library, initialization information or something
   else. Consult the provider headers to find appropriate provider
   initialization information.

   When this call returns, the providers is available and will be
   appear in the list obtained with ssh_ek_get providers (given the
   adding was successful).

   The short name of the provider is returned in short_name_ret and it
   should be freed with ssh_free. */
SshEkStatus ssh_ek_add_provider(SshExternalKey externalkey,
                                const char *type,
                                const char *initialization_info,
                                void *initialization_ptr,
                                SshEkProviderFlags flags,
                                char **short_name_ret)
 {
  SshEkProviderOps ops;

  /* Check if we have a provider with type 'type' */
  if ((ops = ssh_ek_find_provider_ops(type)) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unexistent provider type %s", type ? type : "<NULL>"));
      return SSH_EK_PROVIDER_TYPE_NOT_SUPPORTED;
    }

  return ssh_ek_add_provider_external(externalkey, ops, initialization_info,
                                      initialization_ptr, flags,
                                      short_name_ret);
}


static void ssh_ek_provider_destroy(void *context)
{
  SshEkProviderInternal provider = context;
  SshExternalKey ek = provider->externalkey;

  /* Remove the provider from the linked list */
  ssh_ek_remove_provider_item(provider->externalkey, provider);

  /* Free the internal provider structure. */
  ssh_free(provider->info);
  ssh_free(provider->type);
  ssh_free(provider->short_name);
  ssh_free(provider);

  /* If this is the last provider and ek is marked as destroyed,
     finalize the destroying of EK. */
  if (ek->providers == NULL && ek->destroyed)
      ssh_ek_destroy(ek);
}

void ssh_ek_remove_provider(SshExternalKey externalkey,
                            const char *provider_short_name)
{
  SshEkProviderInternal provider;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Removing provider %s", provider_short_name));

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   provider_short_name);

  if (!provider)
    return;

  /* Unregister noise source from crypto library. */
  if (provider->noise_src)
    ssh_ek_unregister_noise_src(provider);

  /* Uninitialize the provider. */
  if (!provider->destroy_pending && provider->provider_ops->uninit)
    {
      provider->destroy_pending = TRUE;
      (*provider->provider_ops->uninit)(provider->provider_context);
    }
}


/* Returns the prefix of the keypath */
static char *ssh_ek_get_short_name_from_keypath(const char *keypath)
{
  char *short_name = NULL;
  int i, f;

  if (!keypath)
    return NULL;

  /* Find the third occurance of '/' */
  for (f = i = 0; f < 3 && i < strlen(keypath); i++)
    {
      if (keypath[i] == '/')
        f++;
    }

  if (f == 3)
    {
      short_name = (char *)ssh_malloc(i + 1);

      if (!short_name)
        return NULL;

      memcpy(short_name, keypath, i);
      short_name[i] = 0;
      return short_name;
    }
  return NULL;
}

/* Strips the prefix from the keypath */
static char *ssh_ek_strip_prefix_from_keypath(const char *keypath)
{
  char *path = NULL;

  int i, f;
  /* Find the third occurance of '/' */
  for (f = i = 0; f < 3 && i < strlen(keypath); i++)
    {
      if (keypath[i] == '/')
        f++;
    }

  if (f == 3)
    {
      path = (char *)ssh_calloc(1, strlen(keypath) - i + 1);

      if (!path)
        return NULL;

      strcat(path, &keypath[i]);
    }
  return path;
}

static SshEkProviderInternal
ssh_ek_find_provider_using_keypath(SshExternalKey externalkey,
                                   const char *keypath)
{

  char *short_name;
  SshEkProviderInternal provider;

  short_name = ssh_ek_get_short_name_from_keypath(keypath);
  if (short_name == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error parsing the keypath %s", keypath));
      return NULL;
    }

  provider = ssh_ek_find_provider_using_short_name(externalkey, short_name);
  if (provider == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Can not find a provider with short name %s", short_name));
      ssh_free(short_name);
      return NULL;
    }

  ssh_free(short_name);
  return provider;
}

/* Attempts to match a keypath against the stored paths.
   Returns the matching path if successful, NULL otherwise.
   Notice that if there are multiple matches, this function
   returns arbitrarily the first of them. */
static char *
ssh_ek_match_regexp_keypath(SshExternalKey externalkey,
                            const char *key_pattern)
{
  SshADTHandle handle;

  if (externalkey == NULL || key_pattern == NULL)
    return NULL;

  /* Is it a pattern after all? */
  if (strchr(key_pattern, '*') == NULL)
    return NULL;

  /* Remove all the key file names */
  for (handle = ssh_adt_enumerate_start(externalkey->available_keys);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(externalkey->available_keys, handle))
    {
      char *key = ssh_adt_get(externalkey->available_keys, handle);
      if (ssh_match_pattern(key, key_pattern))
        return key;
    }

  return NULL;
}
/* Strips the prefix from the key path, and asks the provider for the
   key. */
SshOperationHandle
ssh_ek_get_public_key(SshExternalKey externalkey,
                      const char *keypath,
                      SshEkGetPublicKeyCB get_public_key_cb,
                      void *context)
{
  SshEkProviderInternal provider;
  char *bare_keypath;
  char *match;
  SshOperationHandle handle;

  /* Is this a regular-expression key path? If it is, search the map
     of available keys and replace KEYPATH with a match. */
  match  = ssh_ek_match_regexp_keypath(externalkey, keypath);
  if (match != NULL)
    keypath = match;

  provider = ssh_ek_find_provider_using_keypath(externalkey, keypath);
  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Provider not for keypath %s", keypath));
      get_public_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider for keypath %s is destroyed",
                                   keypath));
      get_public_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  bare_keypath = ssh_ek_strip_prefix_from_keypath(keypath);
  if (!bare_keypath)
    {
      get_public_key_cb(SSH_EK_FAILED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Provider %s, asking a public key %s.",
                          provider->printable_name,
                          keypath));
  if (provider->provider_ops->get_public_key == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The provider %s does not implement \"get "
                             "public key\" .",
                             keypath));
      (*get_public_key_cb)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      ssh_free(bare_keypath);
      return NULL;
    }
  handle =
    (*provider->provider_ops->get_public_key)(provider->provider_context,
                                              bare_keypath,
                                              get_public_key_cb, context);
  ssh_free(bare_keypath);
  return handle;
}

/* Strips the prefix from the key path, and asks the provider for the
   key. */
SshOperationHandle
ssh_ek_get_private_key(SshExternalKey externalkey,
                       const char *keypath,
                       SshEkGetPrivateKeyCB get_private_key_cb,
                       void *context)
{
  SshEkProviderInternal provider;
  char *bare_keypath;
  char *match;
  SshOperationHandle handle;

  /* Is this a regular-expression key path? If it is, search the map
     of available keys and replace KEYPATH with a match. */
  match  = ssh_ek_match_regexp_keypath(externalkey, keypath);
  if (match != NULL)
    keypath = match;

  provider = ssh_ek_find_provider_using_keypath(externalkey, keypath);
  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available for keypath %s", keypath));
      get_private_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider for keypath %s is destroyed",
                                   keypath));
      get_private_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  bare_keypath = ssh_ek_strip_prefix_from_keypath(keypath);
  if (!bare_keypath)
    {
      get_private_key_cb(SSH_EK_FAILED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Provider %s, asking a private key %s.",
                 provider->printable_name,
                 keypath));
  if (provider->provider_ops->get_private_key == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The provider %s does not implement \"get "
                             "private key\" .",
                             keypath));
      (*get_private_key_cb)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      ssh_free(bare_keypath);
      return NULL;
    }

  handle =
    (*provider->provider_ops->get_private_key)(provider->provider_context,
                                               bare_keypath,
                                               get_private_key_cb, context);
  ssh_free(bare_keypath);
  return handle;

}
/* Finds the provider identified by the prefix of the keypath,
   calls the providers get certificate routine. */
SshOperationHandle
ssh_ek_get_certificate(SshExternalKey externalkey,
                       const char *keypath,
                       SshUInt32 cert_index,
                       SshEkGetCertificateCB get_certificate_cb,
                       void *context)
{
  SshEkProviderInternal provider;
  char *bare_keypath;
  char *match;
  SshOperationHandle handle;

  /* Is this a regular-expression key path? If it is, search the map
     of available keys and replace KEYPATH with a match. */
  match  = ssh_ek_match_regexp_keypath(externalkey, keypath);
  if (match != NULL)
    keypath = match;

  provider = ssh_ek_find_provider_using_keypath(externalkey, keypath);
  if (!provider)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Provider not available for keypath %s", keypath));
      get_certificate_cb(SSH_EK_PROVIDER_NOT_AVAILABLE,
                         NULL, 0, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider for keypath %s is destroyed",
                                   keypath));
      get_certificate_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, 0, context);
      return NULL;
    }

  bare_keypath = ssh_ek_strip_prefix_from_keypath(keypath);
  if (!bare_keypath)
    {
      get_certificate_cb(SSH_EK_FAILED, NULL, 0, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Provider %s, asking a certificate %s.",
                          provider->printable_name, keypath));

  if (provider->provider_ops->get_certificate == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The provider %s does not implement \"get "
                             "certificate\" .",
                             keypath));
      (*get_certificate_cb)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
      ssh_free(bare_keypath);
      return NULL;
    }

  handle =
    (*provider->provider_ops->get_certificate)(provider->provider_context,
                                               bare_keypath,
                                               cert_index,
                                               get_certificate_cb, context);
  ssh_free(bare_keypath);
  return handle;
}

/* Get the trusted certificates from the provider. Caller must provide
   the providers short name and a certiuficate index. If there are no
   trusted certificates with the index, SSH_EK_NO_MORE_CERTIFICATES
   is returned in callback. */
SshOperationHandle ssh_ek_get_trusted_cert(SshExternalKey externalkey,
                                           const char *provider_short_name,
                                           SshUInt32 cert_index,
                                           SshEkGetCertificateCB
                                           get_certificate_cb,
                                           void *context)
{
  SshEkProviderInternal provider;
  SshOperationHandle handle;
  char *short_name = NULL;


  provider = ssh_ek_find_provider_using_keypath(externalkey,
                                                provider_short_name);
  if (!provider)
    {
      short_name = ssh_ek_get_short_name_from_keypath(provider_short_name);
      provider = ssh_ek_find_provider_using_keypath(externalkey, short_name);
      ssh_free(short_name);
    }

  if (!provider)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Provider %s not available", provider_short_name));
      (*get_certificate_cb)(SSH_EK_PROVIDER_NOT_AVAILABLE,
                            NULL, 0, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed",
                                   provider_short_name));
      (*get_certificate_cb)(SSH_EK_PROVIDER_NOT_AVAILABLE,
                            NULL, 0, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Provider %s, asking a trusted certificate %d.",
                          provider->printable_name,
                          (int) cert_index));

  if (provider->provider_ops->get_trusted_cert == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The provider %s does not implement \"get "
                             "trusted certificate \" .",
                             provider_short_name));
      (*get_certificate_cb)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
      return NULL;
    }
  handle =
    (*provider->provider_ops->get_trusted_cert)(provider->provider_context,
                                                cert_index,
                                                get_certificate_cb, context);
  return handle;
}


/* Get a group (such as a diffie-hallman group) from a
   provider. Caller must provide the name of the group in name. The
   group is returned in a callback. The group_path contains the
   provider and the name of the group which is provider specific, but
   if the provider can generate standard ike groups, they should be
   named "ike-1", "ike-2" and so on. */
SshOperationHandle ssh_ek_get_group(SshExternalKey externalkey,
                                    const char *group_path,
                                    SshEkGetGroupCB callback,
                                    void *context)
{
  SshEkProviderInternal provider;
  char *bare_group_path;
  SshOperationHandle handle;

  provider = ssh_ek_find_provider_using_keypath(externalkey, group_path);
  if (!provider)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Provider not available for keypath %s", group_path));
      (*callback)(SSH_EK_PROVIDER_NOT_AVAILABLE,
                  NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider for keypath %s is destroyed",
                                   group_path));
      (*callback)(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  bare_group_path = ssh_ek_strip_prefix_from_keypath(group_path);
  if (!bare_group_path)
    {
      (*callback)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Provider %s, asking a group %s.",
                          provider->printable_name, group_path));

  if (provider->provider_ops->get_group == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("The provider %s does not implement get group.", group_path));
      ssh_free(bare_group_path);
      (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      return NULL;
    }
  handle =
    (*provider->provider_ops->get_group)(provider->provider_context,
                                         bare_group_path,
                                         callback, context);
  ssh_free(bare_group_path);
  return handle;
}

/* Builds an accelerated key. The provider will convert the specified
   key to an accelerated key and call the notify callback with keypath
   containing the "key_path_id". */
SshOperationHandle
ssh_ek_generate_accelerated_private_key(SshExternalKey externalkey,
                                        const char *provider_short_name,
                                        SshPrivateKey source,
                                        SshEkGetPrivateKeyCB
                                        get_private_key_cb,
                                        void *context)
{
  SshEkProviderInternal provider;
  SshOperationHandle handle;

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   provider_short_name);

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available for short_name %s",
                 provider_short_name));
      get_private_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE,
                         NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed",
                                   provider_short_name));
      get_private_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE,
                         NULL, context);
      return NULL;
    }

  if (provider->provider_ops->gen_acc_private_key == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider %s has not accelerator private key function.",
                 provider_short_name));
      get_private_key_cb(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Provider %s, asking for an accelerated private key",
             provider->printable_name));

  handle = (*provider->provider_ops->gen_acc_private_key)
    (provider->provider_context,
     source, get_private_key_cb, context);

  return handle;

}

SshOperationHandle
ssh_ek_generate_accelerated_public_key(SshExternalKey externalkey,
                                       const char *provider_short_name,
                                       SshPublicKey source,
                                       SshEkGetPublicKeyCB
                                       get_public_key_cb,
                                       void *context)
{
  SshEkProviderInternal provider;
  SshOperationHandle handle;

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   provider_short_name);

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available with short_name %s",
                 provider_short_name));
      get_public_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed",
                                   provider_short_name));
      get_public_key_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->provider_ops->gen_acc_public_key == NULL_FNPTR)
    {
      get_public_key_cb(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Provider %s, asking for an accelerated public key.",
             provider->printable_name));

  handle = (*provider->provider_ops->gen_acc_public_key)
    (provider->provider_context,
     source, get_public_key_cb, context);

  return handle;
}

/* Builds an accelerated group. The provider will convert the
   specified group to an accelerated group (if it can) and return the
   group in the callback. */
SshOperationHandle
ssh_ek_generate_accelerated_group(SshExternalKey externalkey,
                                  const char *provider_short_name,
                                  SshPkGroup source,
                                  SshEkGetGroupCB callback,
                                  void *context)
{
  SshEkProviderInternal provider;
  SshOperationHandle handle;

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   provider_short_name);

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available with short_name %s",
                 provider_short_name));
      (*callback)(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed",
                                   provider_short_name));
      (*callback)(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, context);
      return NULL;
    }

  if (provider->provider_ops->gen_acc_group == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The provider %s does not have the "
                             "get_accelerated_group method",
                             provider_short_name));
      (*callback)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Provider %s, asking for an accelerated group.",
             provider->printable_name));

  handle = (*provider->provider_ops->gen_acc_group)
    (provider->provider_context,
     source, callback, context);

  return handle;
}


/* Attempts to get 'bytes_requested' random bytes from the location
   indicated by 'keypath'. The caller must supply the callback which
   is called when the provider has obtained the random bytes. */
SshOperationHandle ssh_ek_get_random_bytes(SshExternalKey externalkey,
                                           const char *provider_short_name,
                                           size_t bytes_requested,
                                           SshEkGetRandomBytesCB
                                           get_random_bytes_cb,
                                           void *context)
{
  SshEkProviderInternal provider;
  SshOperationHandle handle;

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   provider_short_name);

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available for short_name %s",
                 provider_short_name));
      get_random_bytes_cb(SSH_EK_PROVIDER_NOT_AVAILABLE,
                         NULL, 0, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed",
                                   provider_short_name));
      get_random_bytes_cb(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, 0, context);
      return NULL;
    }

  if (provider->provider_ops->get_random_bytes == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider %s has no get random bytes function.",
                 provider_short_name));
      get_random_bytes_cb(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Provider %s, asking for %d random bytes.",
             provider->printable_name, bytes_requested));

  handle = (*provider->provider_ops->get_random_bytes)
    (provider->provider_context, bytes_requested,
     get_random_bytes_cb, context);

  return handle;

}



SshOperationHandle
ssh_ek_send_message(SshExternalKey externalkey,
                    const char *short_name,
                    const char *message,
                    void *message_arg, size_t message_arg_len,
                    SshEkSendMessageCB message_cb,
                    void *context)
{
  SshEkProviderInternal provider;

  provider = ssh_ek_find_provider_using_short_name(externalkey,
                                                   short_name);

  if (!provider)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Provider not available with short_name %s", short_name));
      if (message_cb)
        (*message_cb)(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, 0, context);
      return NULL;
    }

  if (provider->destroyed == TRUE || provider->destroy_pending == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider %s is destroyed", short_name));
      if (message_cb)
        (*message_cb)(SSH_EK_PROVIDER_NOT_AVAILABLE, NULL, 0, context);
      return NULL;
    }

  if (provider->provider_ops->send_message == NULL_FNPTR)
    {
      if (message_cb)
        (*message_cb)(SSH_EK_OPERATION_NOT_SUPPORTED, NULL, 0, context);
      return NULL;
    }

 return (*provider->provider_ops->send_message)(
                          provider->provider_context,
                          message,
                          message_arg,
                          message_arg_len,
                          message_cb,
                          context);
}


/* Checks if a particular keypath belongs to the given provider
   identified with a short name. */
Boolean ssh_ek_key_path_belongs_to_provider(const char *key_path,
                                            const char *provider_short_name)
{
  if (key_path == NULL || provider_short_name == NULL)
    return FALSE;

  return (strncmp(provider_short_name,
                  key_path,
                  strlen(provider_short_name)) == 0);
}

/* eof */
