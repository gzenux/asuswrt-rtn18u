/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"

#ifdef SSHDIST_EXTKEY_MSCAPI_PROV

#include "msprovider.h"
#include "sshmiscstring.h"
#include "x509.h"
#include "sshmutex.h"
#include "sshcondition.h"
#include "sshthread.h"
#include "sshcrypt.h"
#include "ssheloop.h"
#include "sshproxykey.h"
#include "sshtimeouts.h"
#include "sshadt_list.h"
#include "sshdsprintf.h"
#include "sshbase16.h"
#include <windows.h>
#include <wincrypt.h>
#include <string.h>

#define CERT_ID_LENGTH 20

/* CRYPT_NOHASHOID is defined by the newer wincrypt.h header, but
   older versions do not have this definition */
#ifndef CRYPT_NOHASHOID
#define CRYPT_NOHASHOID 1
#endif

#ifndef CERT_STORE_CTRL_NOTIFY_CHANGE
/* Platform SDK possibly not installed. Declare function by ourself. */
WINCRYPT32API BOOL WINAPI
CertControlStore(HCERTSTORE hCertStore,
                 DWORD dwFlags,
                 DWORD dwCtrlType,
                 void const *pvCtrlPara);

/* Define needed constants. */
#define CERT_STORE_CTRL_RESYNC              1
#define CERT_STORE_CTRL_NOTIFY_CHANGE       2
#endif /* CERT_STORE_CTRL_NOTIFY_CHANGE */

typedef WINCRYPT32API BOOL
(WINAPI *PCertControlStore)(HCERTSTORE hCertStore,
                            DWORD dwFlags,
                            DWORD dwCtrlType,
                            void const *pvCtrlPara);

#define SSH_DEBUG_MODULE "SshEKMSCAPI"

/* The standard digest lengths for MD5 and SHA-1 */
#define SSH_MSCAPI_PROV_MD5_DIGEST_LENGTH 16
#define SSH_MSCAPI_PROV_SHA1_DIGEST_LENGTH 20

#define SSH_MSCAPI_DEFAULT_POLL_DELAY_MS 1500

typedef void (*OperationCB)(void *provider_context, void *context);

typedef struct ProviderCtxRec *ProviderCtx;

typedef struct OperationRec {
  ProviderCtx provider;
  OperationCB callback;
  void *context;
} *Operation;

/* MSVC magic pragma that includes the crypt32.lib. There is really no other
   way to do this */
#pragma comment(lib, "crypt32.lib")

#define ENABLED(PROV) (PROV->operations != NULL)

/* Represents a certificate found in the Microsoft Certificate
   store. Only certificates which has private keys are
   reported by this provider. */
typedef struct CertRec {
  Boolean informed;     /* TRUE if the private key of this certificate is
                           already informed to the application. */
  Boolean present;      /* TRUE if certificate is still found in the
                           certificate store. */
  unsigned char id[CERT_ID_LENGTH]; /* Sha1 ID (hash of the certificate). */
  char *friendly_name;  /* User friendly name for the certificate. */
  char *container;      /* The container name. This is also the path of the
                          private keys */
  char *provider;       /* Provider name (!CSP) */
  DWORD provider_type;  /* Type of the key provider */
  DWORD key_spec;       /* AT_KEYEXCHANGE or AT_SIGNATURE. */
  unsigned int key_size; /* Key size in bits. */
  SshProxyKeyTypeId key_type; /* Key type (extracted from public key) */
  unsigned char *data;  /* BER encoded certificate data. */
  size_t data_len;      /* BER data length. */
} *Cert;

/* Internal context for the private keys returned
   to the application. */
typedef struct MSProvPrivateKeyRec {
  ProviderCtx ctx;    /* Provider of the private key */
  char *path;         /* Private key path. The path we use is actally
                         a CSP key container name, which explicitely
                         defines the private key to use within
                         the service provider. */
} *MSProvPrivateKey;


/* Provider context. */
struct ProviderCtxRec {
  SshADTContainer operations;   /* Queue of operations to be executed in
                                   our separate working thread. */
  SshADTContainer certificates; /* List of certificates
                                   (see Cert type above) */
  HANDLE event;                 /* Event triggered when changes in the
                                   store. */
  HCERTSTORE store;             /* Certificate store. */
  HCRYPTPROV rand_provider;     /* A CSP context for generating random
                                   numbers.  Note that this is used
                                   only for random number generation
                                   and uses the default CSP.*/
  SshMutex mutex;               /* Mutex to protect data from simultaenous
                                   access from separate threads. */
  SshCondition cond;            /* Condition to signal when new operation
                                   is added to queue. */
  PCertControlStore ctrl_store; /* Is pointer to CertControlStore function.
                                   if this is NULL, then it is not
                                   supported and we must poll the
                                   certificate store. */
  Boolean tracing;
  SshThread thread;             /* Working thread handle. */
  Boolean uninit_started;       /* TRUE, if uninitialize function for this
                                   provider has been called. This prevents
                                   installing new keys but allows marking old
                                   keys unavailable. */
  Boolean uninitialized;        /* TRUE, if provider has been uninitialized and
                                   old keys have been marked unavailable. */
  SshUInt32 reference_count;    /* Number of references to provider context.*/
  SshUInt32 poll_delay;         /* Delay in milliseconds between each
                                   certificate store poll. */
  char *provider_name;          /* Provider to use*/
  char *servicename;            /* service name */
  SshEkNotifyCB notify_cb;      /* Callback to notify application about
                                   key availibility. */
  void *notify_context;         /* Context for notify_cb. */
};
Boolean service_flag =FALSE;

static void *
ssh_ms_prov_thread(void *context);

static Boolean
ms_prov_add_operation(ProviderCtx ctx,
              OperationCB callback,
              void *context);

/* Destroys one operation. */
static void
ms_prov_destroy_operation(void *obj, void *provider_context)
{
  ProviderCtx ctx = provider_context;
  ssh_free(obj);
}

/* Increases the reference count for the provider context. */
static void
prov_inc_reference(ProviderCtx ctx)
{
  ctx->reference_count++;
}

/* Actually destroys the provider context. This is called from
   the event loop, when the reference count of the context
   hits zero. */
static void
prov_destroy(void *provider_context)
{
  ProviderCtx ctx = provider_context;

  ctx->uninitialized = TRUE;
  if (ctx->cond) ssh_condition_signal(ctx->cond);
  if (ctx->thread) ssh_thread_join(ctx->thread);
  if (ctx->cond) ssh_condition_destroy(ctx->cond);
  if (ctx->mutex) ssh_mutex_destroy(ctx->mutex);
  if (ctx->operations) ssh_adt_destroy(ctx->operations);
  if (ctx->certificates) ssh_adt_destroy(ctx->certificates);
  if (ctx->event)
    {
      if (ctx->tracing)
        ssh_event_loop_unregister_handle(ctx->event);
      CloseHandle(ctx->event);
    }

  if (ctx->store)
    {
#ifdef DEBUG_LIGHT
      Boolean result;
      result = CertCloseStore(ctx->store,CERT_CLOSE_STORE_CHECK_FLAG);
      if (!result)
        {
          SSH_DEBUG(SSH_D_FAIL,("CertCloseStore failed with error %x",
                                 GetLastError()));
        }
#else
      CertCloseStore(ctx->store, 0);
#endif
    }
  if (ctx->rand_provider)
    CryptReleaseContext(ctx->rand_provider,0);
  ssh_free(ctx->provider_name);
  ssh_free(ctx->servicename);
  ssh_free(ctx);
}

/* Decrements the reference count of the provider context. When
   the reference count hits zero provider context is uninitialized
   through a zero timeout. */
static void
prov_dec_reference(ProviderCtx ctx)
{
  if (--ctx->reference_count == 0)
    {
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, ctx);
      ssh_register_threaded_timeout(NULL, 0, 0, prov_destroy, ctx);
    }
}

/* Call 'callback' through zero timeout. The reference count
   for the provider is incremented by one. The callback
   function must decrement the reference count by one to
   keep the reference counter in balance. */
static void
ssh_ms_prov_referenced_call(ProviderCtx ctx,
                            SshTimeoutCallback callback,
                            void *context)
{
  ssh_mutex_lock(ctx->mutex);
  prov_inc_reference(ctx);
  ssh_mutex_unlock(ctx->mutex);
  ssh_register_threaded_timeout(NULL, 0, 0, callback, context);
}

/* Callback called by ms_prov_enumerate_certs for every
   certificate in the provider context. */
typedef void (*MSProvCertEnumCB)(Cert c, void *context);

/* Enumerates all the certificats in the provider context. Calls
   callback for every certificate. */
static void
ms_prov_enumerate_certs(SshADTContainer list,
                        MSProvCertEnumCB callback,
                        void *context)
{
  SshADTHandle h;
  Cert c;

  if (list == NULL)
    return;

  h = ssh_adt_enumerate_start(list);
  while (h != SSH_ADT_INVALID)
    {
      c = ssh_adt_get(list, h);
      (*callback)(c, context);
      h = ssh_adt_enumerate_next(list, h);
    }
}


/* This structure contains information about
   the key availability. */
typedef struct KeyInfoRec {
  char *label;           /* Label of the key. */
  char *container;       /* CSP container name where the key is located. */
  SshEkUsageFlags usage; /* The key usage flags. */
  Boolean available;     /* TRUE if key has become available, FALSE if
                            key has become unavailable. */
} *KeyInfo;

/* Structure containing information about all keys
   to be informed to the application. */
typedef struct NotifyCtxRec {
  SshOperationHandle op; /* Operation handle for the operation. */
  SshTimeoutCallback callback; /* Called after application was notified. */
  void *context;         /* Context to callback. */
  ProviderCtx prov;      /* Provider context. */
  SshADTContainer keys;  /* List of keys to inform. */
} *NotifyCtx;

static void
ms_prov_destroy_key_info(void *obj, void *context)
{
  KeyInfo info = obj;

  ssh_free(info->label);
  ssh_free(info->container);
  ssh_free(info);
}

/* Creates and initializes a notify context. */
static NotifyCtx
ms_prov_create_notify_context(ProviderCtx prov)
{
  NotifyCtx notify;

  notify = ssh_calloc(1, sizeof(*notify));

  if (!notify)
    return NULL;

  notify->prov = prov;
  notify->keys = ssh_adt_create_generic(SSH_ADT_LIST,
                                        SSH_ADT_DESTROY,
                                        ms_prov_destroy_key_info,
                                        SSH_ADT_CONTEXT,
                                        notify,
                                        SSH_ADT_ARGS_END);
  return notify;
}

static void
ms_prov_add_info_to_notify(NotifyCtx notify,
                           Boolean available,
                           const char *label,
                           const char *container,
                           SshEkUsageFlags usage)
{
  KeyInfo info;

  info = ssh_calloc(1, sizeof(*info));

  if (!info)
    return;

  info->label = ssh_strdup(label);
  info->container = ssh_strdup(container);

  if (info->label == NULL || info->container == NULL)
    {
      ssh_free(info->label);
      ssh_free(info->container);
      ssh_free(info);
      return;
    }

  info->available = available;
  info->usage = usage;
  ssh_adt_insert_to(notify->keys, SSH_ADT_END, info);
}

/* Tries to find a certificate by a container name from the notify context. */
static Boolean
ms_prov_find_cert_from_notify(NotifyCtx notify,
                              const char *container)
{
  SshADTHandle h;
  KeyInfo info;

  h = ssh_adt_enumerate_start(notify->keys);
  while (h != SSH_ADT_INVALID)
    {
      info = ssh_adt_get(notify->keys, h);
      if (strcmp(info->container, container) == 0)
        return TRUE;
      h = ssh_adt_enumerate_next(notify->keys, h);
    }
  return FALSE;
}

/* Calls the notify callback for every key in the notify context. */
static void
ms_prov_notify_keys(NotifyCtx notify)
{
  SshADTHandle h;
  KeyInfo info;
  Boolean allow_new_keys;

  if (notify->prov->uninit_started)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Started to uninitialize msprovider, "
                 "not notifying of new keys"));
      allow_new_keys = FALSE;
    }
  else
    allow_new_keys = TRUE;

  h = ssh_adt_enumerate_start(notify->keys);
  while (h != SSH_ADT_INVALID)
    {
      info = ssh_adt_get(notify->keys, h);

      if (allow_new_keys)
        {
          (*notify->prov->notify_cb)(
                ((info->available)?(SSH_EK_EVENT_KEY_AVAILABLE):
                 (SSH_EK_EVENT_KEY_UNAVAILABLE)),
                info->container,
                info->label,
                info->usage,
                notify->prov->notify_context);
        }
      else if (!info->available)
        {
          /* If we are shutting down we are still able to notify
             that the keys have become unavailable */
          (*notify->prov->notify_cb)(
                SSH_EK_EVENT_KEY_UNAVAILABLE,
                info->container,
                info->label,
                info->usage,
                notify->prov->notify_context);
        }


      h = ssh_adt_enumerate_next(notify->keys, h);
    }
}


static void
ms_prov_free_notify_ctx(NotifyCtx notify)
{
  ssh_operation_unregister(notify->op);

  ssh_mutex_lock(notify->prov->mutex);
  prov_dec_reference(notify->prov);
  ssh_mutex_unlock(notify->prov->mutex);

  ssh_adt_destroy(notify->keys);
  ssh_free(notify);
}


/* This function is called through zero timeout to
   inform application about new keys. */
static void
ms_prov_notify_application_cb(void *context)
{
  NotifyCtx notify = context;

  if (!notify->prov->uninitialized && ENABLED(notify->prov))
    {
      ms_prov_notify_keys(notify);
    }

  if (notify->callback)
    (*notify->callback)(notify->context);

  ms_prov_free_notify_ctx(notify);
}

static void
ms_prov_abort_notify_application(void *context)
{
  NotifyCtx notify = context;

  ssh_cancel_timeouts(ms_prov_notify_application_cb, context);
  notify->op = NULL;
  ms_prov_free_notify_ctx(notify);
}

static void
ms_prov_notify_application(NotifyCtx ctx,
                           SshTimeoutCallback callback,
                           void *context)
{
  ctx->callback = callback;
  ctx->context = context;
  ctx->op = ssh_operation_register(ms_prov_abort_notify_application, ctx);

  /* Callback function frees the notify context */
  ssh_ms_prov_referenced_call(ctx->prov,
                              ms_prov_notify_application_cb,
                              ctx);
}


/* Converts wide char string to normal 8bit string. */
char *WCharToChar(WCHAR *w)
{
  char *ptr, *ret;

  ptr = ret = ssh_malloc(wcslen(w)+1);
  if (!ret) return NULL;

  while (*w)
    *ptr++ = (char)*w++;

  *ptr = 0;

  return ret;
}

/* Searches a certificate by container name and index. If
   the certificate is not found, returns NULL. */
static Cert
ms_prov_find_certificate_by_container(SshADTContainer list,
                                      const char *container,
                                      SshUInt32 cert_index)
{
  SshADTHandle h;
  Cert c;
  SshUInt32 index = 0;

  if (list == NULL)
    return NULL;

  h = ssh_adt_enumerate_start(list);
  while (h != SSH_ADT_INVALID)
    {
      c = ssh_adt_get(list, h);
      if (strcmp(c->container, container) == 0 && index++ == cert_index)
        return c;
      h = ssh_adt_enumerate_next(list, h);
    }
  return NULL;
}

/* Searches a certificate by id. If the certificate is not found,
   returns NULL. */
static Cert
ms_prov_find_certificate_by_id(SshADTContainer list,
                               unsigned char *id)
{
  SshADTHandle h;
  Cert c;

  if (list == NULL)
    return NULL;

  h = ssh_adt_enumerate_start(list);
  while (h != SSH_ADT_INVALID)
    {
      c = ssh_adt_get(list, h);
      if (memcmp(c->id, id, CERT_ID_LENGTH) == 0)
        return c;
      h = ssh_adt_enumerate_next(list, h);
    }
  return NULL;
}

/* Returns the BER encoded data of a certificate. If the certificate
   is not found by container and index this function will return NULL. */
unsigned char *
ms_prov_get_certificate_data(SshADTContainer list,
              const char *container,
              SshUInt32 cert_index,
              size_t *data_len)
{
  Cert cert;

  cert = ms_prov_find_certificate_by_container(list, container, cert_index);
  if (cert == NULL)
    return NULL;
  *data_len = cert->data_len;
  return cert->data;
}

/* Finds a certificate for private key with keypath. */
static SshOperationHandle
ssh_ms_prov_get_certificate(void *provider_context,
                            const char *keypath,
                            SshUInt32 cert_index,
                            SshEkGetCertificateCB get_certificate_cb,
                            void *context)
{
  ProviderCtx ctx = provider_context;
  unsigned char *data;
  size_t data_len;

  data = ms_prov_get_certificate_data(ctx->certificates, keypath,
                                      cert_index, &data_len);
  if (data)
    (*get_certificate_cb)(SSH_EK_OK, data, data_len, context);
  else
    (*get_certificate_cb)(SSH_EK_NO_MORE_CERTIFICATES, NULL, 0, context);
  return NULL;
}

/* Context for asynchronous get trusted certificate operation. */
typedef struct GetTrustedCertRec {
  ProviderCtx prov;               /* Provider. */
  SshEkStatus status;             /* Status which is returned to
                                     application. */
  Boolean aborted;                /* TRUE if operation was aborted while
                                     the thread was executing this op. */
  SshOperationHandle op;          /* Operation handle returned to the
                                     application. */
  SshUInt32 index;                /* index of the CA cert. */
  unsigned char *data;            /* BER encoded data to be returned to
                                     the application. */
  size_t data_len;                /* BER data length. */
  SshEkGetCertificateCB callback; /* Completion callback. */
  void *context;                  /* Context for the callback. */
} *GetTrustedCert;

static void
ssh_ms_prov_abort_get_trusted_cert(void *context)
{
  GetTrustedCert ctx = context;

  ctx->aborted = TRUE;
}

static void
ssh_ms_prov_get_trusted_cert_done(void *context)
{
  GetTrustedCert ctx = context;

  if (!ctx->aborted)
    {
      (*ctx->callback)(ctx->status, ctx->data, ctx->data_len, ctx->context);
      ssh_operation_unregister(ctx->op);
    }
  ssh_mutex_lock(ctx->prov->mutex);
  prov_dec_reference(ctx->prov);
  ssh_mutex_unlock(ctx->prov->mutex);

  ssh_free(ctx->data);
  ssh_free(ctx);
}

static void
ssh_ms_prov_get_trusted_cert_op(void *provider, void *context)
{
  ProviderCtx prov = provider;
  GetTrustedCert ctx = context;
  HCERTSTORE store = 0;
  PCCERT_CONTEXT prev = NULL, cert;
  SshUInt32 index = 0;

  store = CertOpenSystemStore(0, "ROOT");
  if (!store)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("CertOpenSystemStore failed with error %X", GetLastError()));
      ctx->status = SSH_EK_NO_MORE_CERTIFICATES;
      goto exit_cert_op;
    }

  while (cert = CertEnumCertificatesInStore(store, prev))
    {
      if (index++ == ctx->index)
        {
          ctx->data_len = cert->cbCertEncoded;
          ctx->data = ssh_memdup(cert->pbCertEncoded, ctx->data_len);

          if (ctx->data)
            ctx->status = SSH_EK_OK;
          else
            ctx->status = SSH_EK_NO_MEMORY;

          goto exit_cert_op;
        }
      prev = cert;
    }
  /* Get trusted certificates from the list of publishers as well */
  CertCloseStore(store, 0);
  store = CertOpenSystemStore(0,"CA");
  if (!store)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("CertOpenSystemStore failed with error %X", GetLastError()));
      ctx->status = SSH_EK_NO_MORE_CERTIFICATES;
      goto exit_cert_op;
    }
  prev = NULL;
  while (cert = CertEnumCertificatesInStore(store, prev))
    {
      if (index++ == ctx->index) /* Continue the last loop */
        {
          ctx->data_len = cert->cbCertEncoded;
          ctx->data = ssh_memdup(cert->pbCertEncoded, ctx->data_len);

          if (ctx->data)
            ctx->status = SSH_EK_OK;
          else
            ctx->status = SSH_EK_NO_MEMORY;

          goto exit_cert_op;
        }
      prev = cert;
    }
   ctx->status = SSH_EK_NO_MORE_CERTIFICATES;

exit_cert_op:
  if (store) CertCloseStore(store, 0);
  ssh_ms_prov_referenced_call(prov, ssh_ms_prov_get_trusted_cert_done, ctx);
}

/* Gets CA certificate from CA store. */
static SshOperationHandle
ssh_ms_prov_get_trusted_cert(void *provider_context,
                             SshUInt32 cert_index,
                             SshEkGetCertificateCB callback,
                             void *context)
{
  ProviderCtx prov = provider_context;
  GetTrustedCert ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));

  if (!ctx)
    {
      (*callback)(SSH_EK_NO_MEMORY, NULL, 0, context);
      return NULL;
    }

  ctx->callback = callback;
  ctx->context = context;
  ctx->prov = prov;
  ctx->index = cert_index;
  ctx->op = ssh_operation_register(ssh_ms_prov_abort_get_trusted_cert, ctx);
  ms_prov_add_operation(prov, ssh_ms_prov_get_trusted_cert_op, ctx);
  return ctx->op;
}


static SshOperationHandle
ssh_ms_prov_get_public_key(void *provider_context,
                           const char *keypath,
                           SshEkGetPublicKeyCB get_public_key_cb,
                           void *context)
{
  ProviderCtx ctx = provider_context;
  SshX509Certificate c;
  unsigned char *data;
  size_t data_len;
  SshPublicKey pubkey;

  data = ms_prov_get_certificate_data(ctx->certificates,
                                      keypath,
                                      0,
                                      &data_len);
  if (!data)
    {
      (*get_public_key_cb)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }

  c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (!c)
    {
      (*get_public_key_cb)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }

  if (ssh_x509_cert_decode(data,
                           data_len,
                           c) != SSH_X509_OK)
    {
      ssh_x509_cert_free(c);
      (*get_public_key_cb)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }
  if (!ssh_x509_cert_get_public_key(c, &pubkey))
    {
      ssh_x509_cert_free(c);
      (*get_public_key_cb)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }
  ssh_x509_cert_free(c);
  (*get_public_key_cb)(SSH_EK_OK, pubkey, context);
  return NULL;
}



static const char *
ssh_ms_prov_get_printable_name(void *provider_context)
{
  static char *provider_name = "Microsoft CryptoAPI";
  return provider_name;
}

static SshOperationHandle
ssh_ms_prov_get_random_bytes(void *provider_context,
                             size_t bytes_requested,
                             SshEkGetRandomBytesCB callback,
                             void *context)
{
  unsigned char * buffer = NULL;
  Boolean result;
  ProviderCtx ctx = provider_context;


  if (ctx->rand_provider == 0)
    {
      (*callback)(SSH_EK_FAILED, NULL, 0, context);
      return NULL;
    }

  buffer = ssh_calloc(1, bytes_requested);
  if (NULL == buffer)
    {
      (*callback)(SSH_EK_NO_MEMORY, NULL, 0, context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK,("Generating %d random bytes", bytes_requested));

  result = CryptGenRandom(ctx->rand_provider,
                          (DWORD)bytes_requested,
                          buffer);
  if (result)
    (*callback)(SSH_EK_OK, buffer, bytes_requested, context);
  else
    (*callback)(SSH_EK_FAILED, NULL, 0, context);

  if (buffer)
    ssh_free(buffer);
  return NULL;
}


/* Returns TRUE if provider name is accepted by the filter. */
static Boolean
ms_prov_match_provider_name(const char *provider,
                            const char *include)
{
  if (strcmp(provider, include) == 0)
    return TRUE;
  return FALSE;
}

static HCRYPTPROV
ms_prov_acquire_crypt_context(Cert cert)
{
  HCRYPTPROV prov;
  char *tmp;
#ifdef UNICODE
  WCHAR pwszContainerName[512];
  WCHAR provider[512];
#else
  char *pwszContainerName;
  char *provider;
#endif /* UNICODE */

  /* Strip the certificate ID before acquiring the crypto context */
  tmp = ssh_strdup(cert->container);
  if (tmp == NULL)
    return 0;

  tmp = strtok(tmp, "/");

#ifdef UNICODE
  ssh_ascii_to_unicode(pwszContainerName, sizeof(pwszContainerName), tmp);
  ssh_ascii_to_unicode(provider, sizeof(provider), cert->provider);
#else
  pwszContainerName = tmp;
  provider  = cert->provider;
#endif /* UNICODE */


  SSH_DEBUG(SSH_D_LOWOK,
            ("Acquiring crypto context for %s from provider %s",
             pwszContainerName, provider));

  if (!CryptAcquireContext(&prov,
                           pwszContainerName,
                           provider,
                           cert->provider_type,
                           service_flag ? CRYPT_MACHINE_KEYSET : 0))
    {
      ssh_free(tmp);
      return 0;
    }

  ssh_free(tmp);
  return prov;
}

/* Adds a certificate to the provider context if the certificate
   is not already added. */
static Boolean
ms_prov_add_certificate(ProviderCtx ctx,
                        PCCERT_CONTEXT cert,
                        SshADTContainer list)
{
  DWORD id_len = CERT_ID_LENGTH, info_len, fn_len;
  unsigned char id[CERT_ID_LENGTH], *prov;
  unsigned short *friendly_name = NULL;
  char *cert_id_base16, *container, *container_id;
  DWORD key_spec, provider_type;
  CRYPT_KEY_PROV_INFO *info;
  SshX509Certificate x509_cert;
  SshPublicKey pubkey;
  char *key_type_name;
  SshProxyKeyTypeId key_type;
  unsigned int key_size;
  Cert c;

  if (ctx->certificates == NULL)
    return FALSE;

  x509_cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(cert->pbCertEncoded,
                           cert->cbCertEncoded,
                           x509_cert) != SSH_X509_OK)
    {
      ssh_x509_cert_free(x509_cert);
      return FALSE;
    }
  if (!ssh_x509_cert_get_public_key(x509_cert, &pubkey))
    {
      ssh_x509_cert_free(x509_cert);
      return FALSE;
    }
  if (ssh_public_key_get_info(pubkey,
                              SSH_PKF_KEY_TYPE, &key_type_name,
                              SSH_PKF_SIZE, &key_size,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_public_key_free(pubkey);
      ssh_x509_cert_free(x509_cert);
      return FALSE;
    }
  ssh_public_key_free(pubkey);
  ssh_x509_cert_free(x509_cert);

  if (strncmp(key_type_name, "if-modn", 6) == 0)
    key_type = SSH_PROXY_RSA;
  else if (strncmp(key_type_name, "dl-modp", 7) == 0)
    key_type = SSH_PROXY_DSA;
  else
    {
      return FALSE;
    }

  if (!CertGetCertificateContextProperty(cert,
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         NULL,
                                         &info_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
       ("CertGetCertificateContextProperty failed with error %X",
        GetLastError()));
      return FALSE;
    }

  info = ssh_malloc(info_len);
  if (!info || !CertGetCertificateContextProperty(cert,
                                                  CERT_KEY_PROV_INFO_PROP_ID,
                                                  info,
                                                  &info_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("CertGetCertificateContextProperty failed with error %X",
        GetLastError()));
      return FALSE;
    }

  if (info->dwProvType != PROV_RSA_FULL &&
      info->dwProvType != PROV_DSS && info->dwProvType != PROV_DSS_DH)
    {
      ssh_free(info);
      return FALSE;
    }

  if (info->pwszProvName == NULL)
    {
      ssh_free(info);
      return FALSE;
    }

  prov = WCharToChar(info->pwszProvName);

  /* Check that certificate is from correct provider. */
  if (!ms_prov_match_provider_name(prov,
                                   ctx->provider_name))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Provider name %s does not match, expected %s",
                 prov, ctx->provider_name));
      ssh_free(info);
      ssh_free(prov);
      return FALSE;
    }
  key_spec = info->dwKeySpec;
  provider_type = info->dwProvType;
  container = WCharToChar(info->pwszContainerName);
  ssh_free(info);

  if (!CertGetCertificateContextProperty(cert,
                                         CERT_SHA1_HASH_PROP_ID,
                                         id,
                                         &id_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("CertGetCertificateContextProperty failed with error %X",
        GetLastError()));
      ssh_free(prov);
      ssh_free(container);
      return FALSE;
    }

  c = ms_prov_find_certificate_by_id(ctx->certificates, id);
  if (c != NULL)
    {
      if (c->present == FALSE)
        {
          c->present = TRUE;
          c->informed = FALSE;
        }
      ssh_free(prov);
      ssh_free(container);
      return TRUE;
    }

  if (CertGetCertificateContextProperty(cert,
                                        CERT_FRIENDLY_NAME_PROP_ID,
                                        NULL,
                                        &fn_len))
    {
      friendly_name = ssh_malloc(fn_len);
      if (!friendly_name ||
          !CertGetCertificateContextProperty(cert,
                                             CERT_FRIENDLY_NAME_PROP_ID,
                                             friendly_name,
                                             &fn_len))
        {
          ssh_free(friendly_name);
          friendly_name = NULL;
        }
    }

  c = ssh_calloc(1, sizeof(*c));

  if (!c)
    {
      ssh_free(friendly_name);
      return FALSE;
    }

  cert_id_base16 = ssh_buf_to_base16(id, CERT_ID_LENGTH);

  if (!cert_id_base16)
    {
      ssh_free(c);
      ssh_free(friendly_name);
      return FALSE;
    }

  /* Combine container name and certificate ID */
  container_id = ssh_string_concat_3(container, "/", cert_id_base16);

  if (!container_id)
    {
      ssh_free(cert_id_base16);
      ssh_free(c);
      ssh_free(friendly_name);
      return FALSE;
    }

  c->provider_type = provider_type;
  c->provider = prov;

  c->key_type = key_type;
  c->key_size = key_size;
  c->present = TRUE;
  c->informed = FALSE;
  memcpy(c->id, id, CERT_ID_LENGTH);
  c->data = ssh_memdup(cert->pbCertEncoded, cert->cbCertEncoded);
  c->data_len = cert->cbCertEncoded;
  c->key_spec = key_spec;

  c->container = container_id;

  ssh_free(container);
  ssh_free(cert_id_base16);


  if (friendly_name)
    {
      c->friendly_name = WCharToChar(friendly_name);
      ssh_free(friendly_name);
    }
  else
    {
      if (c->key_spec == AT_SIGNATURE)
        {
          ssh_dsprintf(&c->friendly_name,
                       "Signature key (%s)",
                       prov);
        }
      else
        {
          ssh_dsprintf(&c->friendly_name,
                       "Key exchange key (%s)",
                       prov);
        }
    }
  ssh_adt_insert_to(list, SSH_ADT_END, c);
  return TRUE;
}

static void
notify_new_keys_enum_cb(Cert c, void *context)
{
  NotifyCtx notify = context;

  if (!c->informed)
    {
      c->informed = TRUE;

      /* Check if there is already an informed certificate in the
         notify context. With this check we assure that
         private key having more than one certificate is only
         reported once to the application. */
      if (!ms_prov_find_cert_from_notify(notify, c->container))
        {
          ms_prov_add_info_to_notify(notify,
                                     c->present,
                                     c->friendly_name,
                                     c->container,
                                     SSH_EK_USAGE_SIGNATURE);
        }
    }
}

/* Goes through all the certificates in the provider context and
   informs the application of all the new ones. */
static void
notify_certificate_changes(ProviderCtx ctx)
{
  NotifyCtx notify;

  notify = ms_prov_create_notify_context(ctx);
  ms_prov_enumerate_certs(ctx->certificates,
                          notify_new_keys_enum_cb,
                          notify);
  ms_prov_notify_application(notify, NULL, NULL);
}

static Boolean
find_cert_in_store_list(SshADTContainer store_list,
                        Cert c)
{
  PCCERT_CONTEXT cert;
  SshADTHandle h;
  unsigned char id[CERT_ID_LENGTH];
  DWORD id_len;

  for (h = ssh_adt_enumerate_start(store_list);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(store_list, h))
    {
      cert = ssh_adt_get(store_list, h);

      id_len = CERT_ID_LENGTH;
      if (!CertGetCertificateContextProperty(cert,
                                             CERT_SHA1_HASH_PROP_ID,
                                             id,
                                             &id_len))
        {
          return FALSE;
        }
      if (memcmp(c->id, id, CERT_ID_LENGTH) == 0)
        {
          return TRUE;
        }
    }
  return FALSE;

}

static void
check_absent_certs(ProviderCtx ctx,
                   SshADTContainer store_list,
                   SshADTContainer check_list)

{
  SshADTHandle h;
  Cert c;

  if (check_list == NULL)
    return;

  h = ssh_adt_enumerate_start(check_list);
  while (h != SSH_ADT_INVALID)
    {
      c = ssh_adt_get(check_list, h);
      if (c->present && !find_cert_in_store_list(store_list, c))
        {
          c->informed = FALSE;
          c->present = FALSE;
        }
      h = ssh_adt_enumerate_next(check_list, h);
    }
}

/* Destroys a provider certificate context. */
static void
ms_prov_destroy_certificate(void *obj, void *context)
{
  Cert c = obj;

  ssh_free(c->data);
  ssh_free(c->friendly_name);
  ssh_free(c->provider);
  ssh_free(c->container);
  ssh_free(c);
}

static void
ms_prov_destroy_store_cert(void *obj, void *context)
{
  PCCERT_CONTEXT cert = obj;
  CertFreeCertificateContext(cert);
}

static SshADTContainer
ms_prov_read_store(HCERTSTORE store)
{
  PCCERT_CONTEXT prev = NULL, cert, copy;
  SshADTContainer list;

  list = ssh_adt_create_generic(SSH_ADT_LIST,
                                SSH_ADT_DESTROY,
                                ms_prov_destroy_store_cert,
                                SSH_ADT_ARGS_END);

  while ((cert = CertEnumCertificatesInStore(store, prev)) != NULL)
    {
      copy = CertDuplicateCertificateContext(cert);
      ssh_adt_insert_to(list, SSH_ADT_END, (void *)copy);
      prev = cert;
    }
  return list;
}

/* Polling function to search new certificates from the Microsoft
   certificate store. If any new certificates is found, the applcation
   is informed about them through the notify callback. */
static void
poll_certificates(ProviderCtx ctx, HCERTSTORE store)
{
  SshADTContainer store_list;
  SshADTHandle h;

  store_list = ms_prov_read_store(store);
  check_absent_certs(ctx, store_list, ctx->certificates);
  for (h = ssh_adt_enumerate_start(store_list);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(store_list, h))
    {
      ms_prov_add_certificate(ctx,
                              ssh_adt_get(store_list, h),
                              ctx->certificates);
    }
  ssh_adt_destroy(store_list);
}

static void
trigger_poll(void *context);

/* This function is called from the worker thread. */
static void
poll_func(void *provider_context)
{
  ProviderCtx ctx = provider_context;
  HCERTSTORE store;

  if (ctx->ctrl_store)
    {
      (*ctx->ctrl_store)(ctx->store,
                         0,
                         CERT_STORE_CTRL_RESYNC,
                         &ctx->event);
      store = ctx->store;
    }
  else
    {
      if (ctx->servicename)
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER |
                              CERT_SYSTEM_STORE_CURRENT_SERVICE,
                              L"QUICKSECPM\\MY");
      else
        store = CertOpenSystemStore(0, "MY");

      if (!store)
        return;
    }

  ssh_mutex_lock(ctx->mutex);
  if (ctx->certificates != NULL)
    {
      poll_certificates(ctx, store);
    }
  ssh_mutex_unlock(ctx->mutex);
  notify_certificate_changes(ctx);

  if (ctx->ctrl_store == NULL)
    {
      CertCloseStore(store, 0);
      if (ctx->tracing)
        ssh_register_threaded_timeout(NULL, 0,
                                      ctx->poll_delay*1000,
                                      trigger_poll, ctx);
    }
}

static void
poll_operation(void *provider_context, void *context)
{
  poll_func(provider_context);
}

static void
trigger_poll(void *context)
{
  ProviderCtx ctx = context;
  ms_prov_add_operation(ctx, poll_operation, NULL);
}

static void
poll_func(void *provider_context);

static void
ssh_ms_prov_enable(void *provider_context)
{
  ProviderCtx ctx = provider_context;

  if (ENABLED(ctx))
    {
      (*ctx->notify_cb)(SSH_EK_EVENT_PROVIDER_ENABLED, NULL, NULL, 0,
                        ctx->notify_context);
      return;
    }
  ssh_mutex_lock(ctx->mutex);
  ctx->operations = ssh_adt_create_generic(SSH_ADT_LIST,
                                           SSH_ADT_DESTROY,
                                           ms_prov_destroy_operation,
                                           SSH_ADT_CONTEXT,
                                           ctx,
                                           SSH_ADT_ARGS_END);
  ssh_mutex_unlock(ctx->mutex);
  if (!ctx->operations)
    {
      (*ctx->notify_cb)(SSH_EK_EVENT_PROVIDER_FAILURE, NULL, NULL, 0,
                        ctx->notify_context);
      return;
    }

  ctx->certificates = ssh_adt_create_generic(SSH_ADT_LIST,
                                             SSH_ADT_DESTROY,
                                             ms_prov_destroy_certificate,
                                             SSH_ADT_CONTEXT,
                                             ctx,
                                             SSH_ADT_ARGS_END);
  if (!ctx->certificates)
    {
      ssh_adt_destroy(ctx->operations);
      ctx->operations = NULL;
      (*ctx->notify_cb)(SSH_EK_EVENT_PROVIDER_FAILURE, NULL, NULL, 0,
                        ctx->notify_context);
      return;
    }
    if (ctx->ctrl_store)
      {
        if (!(*ctx->ctrl_store)(ctx->store,
                                0,
                                CERT_STORE_CTRL_NOTIFY_CHANGE,
                                &ctx->event))
          {
            ssh_adt_destroy(ctx->operations);
            ctx->operations = NULL;
            (*ctx->notify_cb)(SSH_EK_EVENT_PROVIDER_FAILURE, NULL, NULL, 0,
                              ctx->notify_context);
            return;
          }
        ssh_event_loop_register_handle(ctx->event, FALSE, poll_func, ctx);
      }
    ctx->tracing = TRUE;
    ssh_register_timeout(NULL, 0, 0, trigger_poll, ctx);

  (*ctx->notify_cb)(SSH_EK_EVENT_PROVIDER_ENABLED, NULL, NULL, 0,
                    ctx->notify_context);
  return;
}



/* Initializes the provider and starts the working thread. */
static SshEkStatus
ssh_ms_prov_init(const char *initialization_info,
                 const void *initialization_ptr,
                 SshEkNotifyCB notify_cb,
                 SshEkAuthenticationCB authentication_cb,
                 void *context,
                 void ** provider_context_return)
{
  ProviderCtx ctx;
  char *provider_include;
  char *service_name;
  SshUInt32 buf_len;
  Boolean status;

  HANDLE c32;
  HCERTSTORE cert_store;

  provider_include =
    ssh_get_component_data_from_string(initialization_info, "csp", 0);

  /* If no provider has been provided then use default provider
   for PROV_RSA_FULL for the system */
  if (provider_include == NULL || provider_include[0] == '\0')
    {
      TCHAR *default_provider;
      size_t buf_size;

      if (!CryptGetDefaultProvider(
                              PROV_RSA_FULL,
                              NULL,
                              CRYPT_MACHINE_DEFAULT,
                              NULL,
                              &buf_len))
        return SSH_EK_FAILED;

      buf_size = buf_len + sizeof(TCHAR);
      default_provider = ssh_calloc(1, buf_size);
      if (default_provider == NULL)
        return SSH_EK_FAILED;

      if (!CryptGetDefaultProvider(
                              PROV_RSA_FULL,
                              NULL,
                              CRYPT_MACHINE_DEFAULT,
                              default_provider,
                              &buf_len))
        {
          ssh_free(default_provider);
          return SSH_EK_FAILED;
        }

#ifdef UNICODE
      buf_size = (buf_len / sizeof(WCHAR)) + 1;
      provider_include = ssh_calloc(1, buf_size);
      if (provider_include == NULL)
        {
          ssh_free(default_provider);
          return SSH_EK_FAILED;
        }

      ssh_unicode_to_ascii(provider_include, buf_size, default_provider);
#else
      provider_include = default_provider;
#endif /* UNICODE */
    }
  service_name =
    ssh_get_component_data_from_string(initialization_info, "service-name", 0);
  if (service_name)
        service_flag = TRUE;
  SSH_DEBUG(SSH_D_MIDOK, ("service name %s", service_name));

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      ssh_free(provider_include);
      ssh_free(service_name);
      return SSH_EK_FAILED;
    }
  ctx->servicename = service_name;
  ctx->provider_name = provider_include;
  ctx->reference_count = 1;
  ctx->poll_delay = SSH_MSCAPI_DEFAULT_POLL_DELAY_MS;
  ctx->notify_cb = notify_cb;
  ctx->notify_context = context;
  ctx->cond = ssh_condition_create("MSCAPI Provider condition", 0);
  if (!ctx->cond)
    {
      prov_destroy(ctx);
      return SSH_EK_FAILED;
    }
#if 1
  c32 = GetModuleHandle("crypt32.dll");

  if (c32)
    {
      ctx->ctrl_store =
        (PCertControlStore)GetProcAddress(c32, "CertControlStore");
    }

  if (ctx->ctrl_store)
    {
      cert_store = CertOpenSystemStore(0, "MY");
      if (!cert_store)
        {
          prov_destroy(ctx);
          return SSH_EK_FAILED;
        }
      ctx->store = cert_store;

      ctx->event = CreateEvent(NULL,
                               FALSE,
                               FALSE,
                               NULL);
      if (!ctx->event)
        {
          prov_destroy(ctx);
          return SSH_EK_FAILED;
        }
    }
#endif /* 1 */
  ctx->mutex = ssh_mutex_create("MSCAPI Provider mutex", 0);
  if (!ctx->mutex)
    {
      prov_destroy(ctx);
      return SSH_EK_FAILED;
    }
  ctx->thread = ssh_thread_create(ssh_ms_prov_thread, ctx);
  if (!ctx->thread)
    {
      prov_destroy(ctx);
      return SSH_EK_FAILED;
    }

  *provider_context_return = ctx;

  /*Grab default provider for generating random bytes. It is not
   a failure if this context cannot be attained.
  */
  status = CryptAcquireContext(&ctx->rand_provider,
                          NULL,
                          NULL,
                          PROV_RSA_FULL,
                          0);
  if (!status)
    SSH_DEBUG(SSH_D_MIDOK, ("Unable to acquire provider."
                            " Random number generation is not supported"));
  ssh_ms_prov_enable(ctx);
  SSH_DEBUG(SSH_D_MIDOK,("Successfully initialized MS CAPI external key"));
  return SSH_EK_OK;
}




static void
ms_prov_disable_cb(void *context)
{
  ProviderCtx prov = context;

  ssh_mutex_lock(prov->mutex);
  prov->uninitialized = TRUE;
  ssh_adt_destroy(prov->certificates);
  prov->certificates = NULL;
  ssh_adt_destroy(prov->operations);
  prov->operations = NULL;
  ssh_mutex_unlock(prov->mutex);
  if (prov->tracing)
    {
      prov->tracing = FALSE;
      ssh_event_loop_unregister_handle(prov->event);
    }

  (*prov->notify_cb)(SSH_EK_EVENT_PROVIDER_DISABLED, NULL, NULL, 0,
                     prov->notify_context);
}

static void
notify_new_keys_unavail_cb(Cert c, void *context)
{
  NotifyCtx notify = context;

  if (!ms_prov_find_cert_from_notify(notify, c->container))
    {
      ms_prov_add_info_to_notify(notify,
                                 FALSE,
                                 c->friendly_name,
                                 c->container,
                                 SSH_EK_USAGE_SIGNATURE);
    }
}

static void ssh_ms_prov_disable(void *provider_context)

{
  ProviderCtx prov = provider_context;
  NotifyCtx notify;

  if (!ENABLED(prov))
    {
      (*prov->notify_cb)(SSH_EK_EVENT_PROVIDER_DISABLED, NULL, NULL, 0,
                        prov->notify_context);
      return;
    }

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, prov);
  notify = ms_prov_create_notify_context(prov);
  ms_prov_enumerate_certs(prov->certificates, notify_new_keys_unavail_cb,
                          notify);

  ms_prov_notify_application(notify, ms_prov_disable_cb, prov);
}



/* Marks provider context uninitialized and decrements the
   reference count by one. When the worker thread notices
   that this uninitialize has been called it will exit. */
static void
ssh_ms_prov_uninit(void *provider_context)
{
  ProviderCtx ctx = provider_context;

  ssh_ms_prov_disable(ctx);

  ssh_mutex_lock(ctx->mutex);
  ctx->uninit_started = TRUE;
  prov_dec_reference(ctx);
  ssh_mutex_unlock(ctx->mutex);
  ms_prov_add_operation(ctx, NULL, NULL);
}



/* Adds operation to the thread operation queue. These operations
   are executed in the FIFO order. */
static Boolean
ms_prov_add_operation(ProviderCtx ctx,
              OperationCB callback,
              void *context)
{
  Operation op;

  if (!ENABLED(ctx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Provider not enabled"));
      return FALSE;
    }
  op = ssh_calloc(1, sizeof(*ctx));
  if (!op)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Couldn't allocate memory."));
      return FALSE;
    }
  op->provider = ctx;
  op->callback = callback;
  op->context = context;

  /* Increment the reference count of the provider context. This
     assures that provider context is not freed while executing
     an operation. */
  ssh_mutex_lock(ctx->mutex);
  prov_inc_reference(ctx);
  ssh_adt_insert_to(ctx->operations, SSH_ADT_END, op);
  ssh_mutex_unlock(ctx->mutex);

  /* Signal the working thread about a new operation. */
  ssh_condition_signal(ctx->cond);
  return TRUE;
}

/* Returns the first operation in the queue (and removes it from
   the queue). */
static Operation
ms_prov_get_operation(ProviderCtx ctx)
{
  if (ENABLED(ctx) && (ssh_adt_num_objects(ctx->operations) > 0))
    return ssh_adt_detach_from(ctx->operations,
                               SSH_ADT_BEGINNING);
  else
    return NULL;
}

/* The provider working thread executing the operations in the queue. */
static void *
ssh_ms_prov_thread(void *provider_context)
{
  ProviderCtx ctx = provider_context;
  Operation op;

  ssh_mutex_lock(ctx->mutex);

  /* Increment the reference cound so that provider context is
     not destroyed while this thread is executing. */
  prov_inc_reference(ctx);
  while (!ctx->uninitialized && !ctx->uninit_started)
    {
      /* Wait for new operations. */
      while ((op = ms_prov_get_operation(ctx)) == NULL)
        ssh_condition_wait(ctx->cond, ctx->mutex);

      /* Call operation callback only if the provider is
         not uninitialized and there actually is an
         operation callback. */
      if (!ctx->uninitialized && op->callback != NULL)
        {
          ssh_mutex_unlock(ctx->mutex);
          (*op->callback)(ctx, op->context);
          ssh_mutex_lock(ctx->mutex);
        }
      /* Free the operation context. */
      ms_prov_destroy_operation(op, ctx);

      /* Decrement the reference count of the provider context. We must do
         this because it is incremented in the ms_prov_add_operation
         function. */
      prov_dec_reference(ctx);
    }
  prov_dec_reference(ctx);
  ssh_mutex_unlock(ctx->mutex);
  return NULL;
}

/* Swap the byte order of an array. */
static void
ms_prov_swap_byte_order(unsigned char *s, size_t len)
{
  unsigned char t;
  size_t i;

  for (i = 0; i < len / 2; i ++)
    {
      t = s[i];
      s[i] = s[len-i-1];
      s[len-i-1] = t;
    }
}

static void
ms_prov_private_key_free(void *pr_key)
{
  MSProvPrivateKey key = pr_key;

  /* Decrement the reference count of the provider context. */
  ssh_mutex_lock(key->ctx->mutex);
  prov_dec_reference(key->ctx);
  ssh_mutex_unlock(key->ctx->mutex);

  /* Free the key context. */
  ssh_free(key->path);
  ssh_free(key);
}

typedef struct MSProvKeyOperationCtxRec {
  ProviderCtx ctx;
  Boolean sign;
  SshProxyOperationId operation_id;
  SshOperationHandle op;
  SshCryptoStatus status;
  Cert cert;
  Boolean aborted;
  SshProxyRGFId rgf_id;
  unsigned char *input_data;
  size_t input_data_len;
  unsigned char *output_data;
  size_t output_data_len;
  SshProxyReplyCB reply_cb;
  void *reply_context;
} *MSProvKeyOperationCtx;

static void
ms_prov_key_operation_free(void *context)
{
  MSProvKeyOperationCtx ctx = context;

  ssh_free(ctx->input_data);
  ssh_free(ctx->output_data);
  ssh_free(ctx);
}

static void
ms_prov_key_operation_abort(void *context)
{
  MSProvKeyOperationCtx ctx = context;
  ctx->aborted = TRUE;
}

static void
ms_prov_key_operation_done(void *context)
{
  MSProvKeyOperationCtx ctx = context;
  if (!ctx->aborted)
    {
      (*ctx->reply_cb)(ctx->status,
                       ctx->output_data,
                       ctx->output_data_len,
                       ctx->reply_context);
      ssh_operation_unregister(ctx->op);
    }
  ssh_mutex_lock(ctx->ctx->mutex);
  prov_dec_reference(ctx->ctx);
  ssh_mutex_unlock(ctx->ctx->mutex);
  ms_prov_key_operation_free(ctx);
}

static Boolean
ms_prov_get_sign_alg_id(SshProxyRGFId rgf_id,
                        size_t input_data_len,
                        ALG_ID *alg_id,
                        DWORD *sign_flags,
                        Boolean *no_hash)
{
  *sign_flags = 0;
  *no_hash = TRUE;

  switch (rgf_id)
    {
    case SSH_DSA_NONE_NONE:
    case SSH_RSA_PKCS1_NONE:
    case SSH_RSA_NONE_NONE:
      if (rgf_id != SSH_DSA_NONE_NONE)
        *sign_flags = CRYPT_NOHASHOID;
      if (input_data_len == SSH_MSCAPI_PROV_MD5_DIGEST_LENGTH)
        *alg_id = CALG_MD5;
      else if (input_data_len == SSH_MSCAPI_PROV_SHA1_DIGEST_LENGTH)
        *alg_id = CALG_SHA1;
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Sign digest called with an unknown length"));
          return FALSE;
        }
      break;
    case SSH_RSA_PKCS1_SHA1:
      *alg_id = CALG_SHA1;
      *no_hash = FALSE;
      break;
    case SSH_RSA_PKCS1_MD5:
      *alg_id = CALG_MD5;
      *no_hash = FALSE;
      break;
    case SSH_RSA_PKCS1_SHA1_NO_HASH:
      *alg_id = CALG_SHA1;
      break;
    case SSH_RSA_PKCS1_MD5_NO_HASH:
      *alg_id = CALG_MD5;
      break;
    case SSH_RSA_PKCS1_MD2_NO_HASH:
      *alg_id = CALG_MD2;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unknown RGF id."));
      return FALSE;
    }

  return TRUE;
}

#ifndef SCARD_E_CANCELLED
#define SCARD_E_CANCELLED                _HRESULT_TYPEDEF_(0x80100002L)
#endif /* SCARD_E_CANCELLED */

#ifndef SCARD_W_CANCELLED_BY_USER
#define SCARD_W_CANCELLED_BY_USER        _HRESULT_TYPEDEF_(0x8010006EL)
#endif /* SCARD_W_CANCELLED_BY_USER */

SshCryptoStatus
ms_prov_map_crypt_error(DWORD status)
{
  switch (status)
    {
    case SCARD_E_CANCELLED:
    case SCARD_W_CANCELLED_BY_USER:
    case ERROR_CANCELLED:
      return SSH_CRYPTO_OPERATION_CANCELLED;

    case NTE_BAD_ALGID:
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

    case ERROR_NOT_ENOUGH_MEMORY:
    case NTE_NO_MEMORY:
      return SSH_CRYPTO_NO_MEMORY;

    default:
      return SSH_CRYPTO_OPERATION_FAILED;
    }
}

static void
ms_prov_key_operation_sign(MSProvKeyOperationCtx key_context)
{
  HCRYPTHASH hash_obj = 0;
  HCRYPTPROV prov = 0;
  ALG_ID alg_id;
  DWORD sign_flags;
  Boolean no_hash;
  DWORD last_error;
  DWORD output_data_len;

  prov = ms_prov_acquire_crypt_context(key_context->cert);
  if (prov == 0)
    {
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptAcquireContext failed with error %X",
                              last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto sign_operation_done;

    }


  if (!ms_prov_get_sign_alg_id(key_context->rgf_id,
                               key_context->input_data_len,
                               &alg_id,
                               &sign_flags,
                               &no_hash))
    {
      key_context->status = SSH_CRYPTO_OPERATION_FAILED;
      goto sign_operation_done;
    }

  if (!CryptCreateHash(prov,
                       alg_id,
                       0, 0,
                       &hash_obj))
    {
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptCreateHash failed with error %X",
                             last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto sign_operation_done;
    }

  if (no_hash)
    {
      if (!CryptSetHashParam(hash_obj, HP_HASHVAL, key_context->input_data, 0))
        {
          last_error = GetLastError();
          SSH_DEBUG(SSH_D_FAIL, ("CryptSetHashParam failed with error %X",
                                 last_error));
          key_context->status = ms_prov_map_crypt_error(last_error);
          goto sign_operation_done;
        }
    }
  else
    {
      if (!CryptHashData(hash_obj, key_context->input_data,
                         (DWORD)key_context->input_data_len, 0))
        {
          last_error = GetLastError();
          SSH_DEBUG(SSH_D_FAIL, ("CryptHashData failed with error %X",
                                 last_error));
          key_context->status = ms_prov_map_crypt_error(last_error);
          goto sign_operation_done;
        }
    }
  output_data_len = (DWORD)key_context->output_data_len;
  if (!CryptSignHash(hash_obj,
                     key_context->cert->key_spec,
                     NULL,
                     sign_flags,
                     NULL,
                     &output_data_len))
    {
          key_context->output_data_len = output_data_len;
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptSignHash failed with error %X",
                              last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto sign_operation_done;
    }

  key_context->output_data_len = output_data_len;
  key_context->output_data = ssh_malloc(key_context->output_data_len);
  if (!key_context->output_data)
    {
      key_context->status = SSH_CRYPTO_OPERATION_FAILED;
      goto sign_operation_done;
    }
  if (!CryptSignHash(hash_obj,
                     key_context->cert->key_spec,
                     NULL,
                     sign_flags,
                     key_context->output_data,
                     &output_data_len))
    {
          key_context->output_data_len = output_data_len;
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptSignHash failed with error %X",
                             last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto sign_operation_done;
    }
  key_context->output_data_len = output_data_len;
  ms_prov_swap_byte_order(key_context->output_data,
                          key_context->output_data_len);

sign_operation_done:
  if (hash_obj)
    CryptDestroyHash(hash_obj);

  if (prov)
    CryptReleaseContext(prov, 0);

  ssh_ms_prov_referenced_call(key_context->ctx,
                              ms_prov_key_operation_done,
                              key_context);
}

static void
ms_prov_key_operation_decrypt(MSProvKeyOperationCtx key_context)
{
  HCRYPTPROV prov;
  HCRYPTKEY private_key;
  DWORD last_error;
  DWORD output_data_len;

  ms_prov_swap_byte_order(key_context->input_data,
                          key_context->input_data_len);

  prov = ms_prov_acquire_crypt_context(key_context->cert);
  if (prov == 0)
    {
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptAcquireContext failed with error %X",
                              last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto decrypt_operation_done;
    }

  if (!CryptGetUserKey(prov,
                       key_context->cert->key_spec,
                       &private_key))
    {
      last_error = GetLastError();
      SSH_DEBUG(SSH_D_FAIL, ("CryptGetUserKey failed with error %X",
                             last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto decrypt_operation_done;
    }
  output_data_len = (DWORD)key_context->input_data_len;
  if (!CryptDecrypt(private_key,
                    0, TRUE, 0,
                    key_context->input_data,
                    &output_data_len))
    {
          key_context->output_data_len = output_data_len;
      last_error = GetLastError();

      SSH_DEBUG(SSH_D_FAIL, ("CryptDecrypt failed with error %X",
                             last_error));
      key_context->status = ms_prov_map_crypt_error(last_error);
      goto decrypt_operation_done;
    }
  key_context->output_data_len = output_data_len;
  key_context->output_data = ssh_memdup(key_context->input_data,
                                        key_context->output_data_len);

decrypt_operation_done:
  CryptReleaseContext(prov, 0);
  ssh_ms_prov_referenced_call(key_context->ctx,
                              ms_prov_key_operation_done,
                              key_context);

}

static void
ms_prov_key_operation_start(void *provider_context, void *context)
{
  MSProvKeyOperationCtx ctx = context;

  if (ctx->sign)
    ms_prov_key_operation_sign(ctx);
  else
    ms_prov_key_operation_decrypt(ctx);
}

static Boolean
ms_prov_check_key_type(Cert c,
                       SshProxyOperationId operation_id,
                       Boolean *sign)
{
  if (operation_id == SSH_DSA_PRV_SIGN)
    {
      if (c->key_type != SSH_PROXY_DSA)
        return FALSE;
      *sign = TRUE;
    }
  else if (operation_id == SSH_RSA_PRV_DECRYPT)
    {
      if (c->key_type != SSH_PROXY_RSA)
        return FALSE;
      *sign = FALSE;
    }
  else if (operation_id == SSH_RSA_PRV_SIGN)
    {
      if (c->key_type != SSH_PROXY_RSA)
        return FALSE;
      *sign = TRUE;
    }
  else
    {
      return FALSE;
    }
  return TRUE;

}

static SshOperationHandle
ms_prov_key_operation(SshProxyOperationId operation_id,
                      SshProxyRGFId rgf_id,
                      SshProxyKeyHandle handle,
                      const unsigned char *input_data,
                      size_t input_data_len,
                      SshProxyReplyCB reply_cb,
                      void *reply_context,
                      void *context)
{
  MSProvPrivateKey key;
  MSProvKeyOperationCtx ctx;
  Cert c;
  Boolean sign;

  key = (MSProvPrivateKey) context;

  c = ms_prov_find_certificate_by_container(key->ctx->certificates,
                                            key->path,
                                            0);
  if (c == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }
  if (!ms_prov_check_key_type(c, operation_id, &sign))
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (!ctx)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ctx->input_data_len = input_data_len;
  ctx->input_data = ssh_memdup(input_data, ctx->input_data_len);
  ctx->operation_id = operation_id;
  ctx->sign = sign;
  ctx->ctx = key->ctx;
  ctx->cert = c;
  ctx->rgf_id = rgf_id;
  ctx->reply_cb = reply_cb;
  ctx->reply_context = reply_context;
  ctx->op = ssh_operation_register(ms_prov_key_operation_abort, ctx);
  ms_prov_add_operation(key->ctx, ms_prov_key_operation_start, ctx);
  return ctx->op;
}

static SshOperationHandle
ssh_ms_prov_get_private_key(void *provider_context,
                            const char *keypath,
                            SshEkGetPrivateKeyCB callback,
                            void *context)
{
  ProviderCtx ctx = provider_context;
  MSProvPrivateKey key_ctx;
  SshPrivateKey prkey;
  Cert c;

  if (keypath == NULL)
    {
      (*callback)(SSH_EK_FAILED, NULL, context);
      return NULL;
    }
  c = ms_prov_find_certificate_by_container(ctx->certificates, keypath, 0);
  if (c == NULL)
    {
      (*callback)(SSH_EK_KEY_NOT_FOUND, NULL, context);
      return NULL;
    }

  key_ctx = ssh_calloc(1, sizeof(*key_ctx));
  if (!key_ctx)
    {
      (*callback)(SSH_EK_NO_MEMORY, NULL, context);
      return NULL;
    }

  key_ctx->path = ssh_strdup(keypath);

  if (!key_ctx->path)
    {
      (*callback)(SSH_EK_NO_MEMORY, NULL, context);
      ssh_free(key_ctx);
      return NULL;
    }

  key_ctx->ctx = ctx;
  prkey = ssh_private_key_create_proxy(c->key_type,
                                       c->key_size,
                                       ms_prov_key_operation,
                                       ms_prov_private_key_free,
                                       key_ctx);
  if (prkey != NULL)
    {
      ssh_mutex_lock(ctx->mutex);
      prov_inc_reference(ctx);
      ssh_mutex_unlock(ctx->mutex);
      (*callback)(SSH_EK_OK, prkey, context);
    }
  else
    {
      (*callback)(SSH_EK_NO_MEMORY, NULL, context);
    }
  return NULL;
}

struct SshEkProviderOpsRec ssh_ek_ms_ops =
  {
    "mscapi",
    ssh_ms_prov_init,
    ssh_ms_prov_uninit,
    ssh_ms_prov_get_public_key,
    ssh_ms_prov_get_private_key,
    ssh_ms_prov_get_certificate,
    ssh_ms_prov_get_trusted_cert,
    NULL_FNPTR, /* No groups */
    ssh_ms_prov_get_printable_name,
    NULL_FNPTR, /* No accelerator for public keys. */
    NULL_FNPTR, /* No accelerator for private keys. */
    NULL_FNPTR, /* No accelerator for groups. */
    ssh_ms_prov_get_random_bytes,
    NULL_FNPTR /* No messages. */
  };

void
ssh_ms_prov_enum_providers(char ***providers_ret,
                           SshUInt32 *num_providers_ret)
{

  DWORD index = 0;
  TCHAR name[512];
  DWORD len;

/* If Windows is not 98/2000/XP, we do manual registry enumeration */
#if (_WIN32_WINDOWS < 0x0410) && !defined(_WIN32_WCE)

#define PROVIDERS_KEY "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"

  HKEY key;
  FILETIME ftime;

  *providers_ret = NULL;
  *num_providers_ret = 0;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                   PROVIDERS_KEY,
                   0,
                   KEY_ENUMERATE_SUB_KEYS,
                   &key) != ERROR_SUCCESS)
    return;

  while (1)
    {
      len = sizeof(name);

      if (RegEnumKeyEx(key,
                       index,
                       name,
                       &len,
                       0,
                       NULL,
                       NULL,
                       &ftime) != ERROR_SUCCESS)
        {
          break;
        }
      *providers_ret = ssh_realloc(*providers_ret,
                                   (*num_providers_ret)*sizeof(char *),
                                   (*num_providers_ret + 1)*sizeof(char *));

      if (*providers_ret == NULL)
        {
          *num_providers_ret = 0;
          return;
        }

      (*providers_ret)[*num_providers_ret] = ssh_strdup(name);
      (*num_providers_ret)++;

      index++;
    }
  RegCloseKey(key);

#else /* (_WIN32_WINDOWS < 0x0410) */

  DWORD prov_type;

  *providers_ret = NULL;
  *num_providers_ret = 0;

  while (1)
    {
#ifdef UNICODE
      char prov_name[sizeof(name) / sizeof(TCHAR)];
#else
      char *prov_name = name;
#endif /* UNICODE */

      len = sizeof(name);

      if (CryptEnumProviders(index,
                             NULL, /* RFU */
                             0,    /* RFU */
                             &prov_type,
                             name,
                             &len) != TRUE)
        {
          break;
        }

#ifdef UNICODE
      ssh_unicode_to_ascii(prov_name, sizeof(prov_name), name);
#endif /* UNICODE */

      *providers_ret = ssh_realloc(*providers_ret,
                                   (*num_providers_ret)*sizeof(char *),
                                    (*num_providers_ret + 1)*sizeof(char *));

      if (*providers_ret == NULL)
        {
          *num_providers_ret = 0;
          return;
        }

      (*providers_ret)[*num_providers_ret] = ssh_strdup(prov_name);
      (*num_providers_ret)++;

      index++;
    }
#endif /* (_WIN32_WINDOWS < 0x0410) */
}

#endif /* SSHDIST_EXTKEY_MSCAPI_PROV */
