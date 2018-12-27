/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is a software "accelerator" provider. It does the all the
   operation using software keys but it acts like a hardware
   cryptographic provider.

   The code serves several purposes. It is an example of how to
   create actual external key providers. In addition to this it
   allows testing code that uses asyncronous external key providers
   in enveronments where the provider hardware is not available.

   This provider also supports querying for passphrase for
   several known public key types for example PKCS8 and PKCS#12.

   Test string for test externalkey:

   -t software -i "directory(c:\temp\temp\) async_time_ms(100)
                    key_files(test-user-1.prv test-user-1.bin)"

   Note; this is not compatible with FIPS certificed crypto library
   that does not provide synchronous crypto functions.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshoperation.h"
#include "softprovideri.h"

#include "sshfileio.h"
#include "sshdirectory.h"

#include "sshadt.h"
#include "sshadt_list.h"
#include "sshadt_conv.h"
#include "sshadt_strmap.h"

#include "sshdsprintf.h"
#include "sshmiscstring.h"
#include "sshbase64.h"

#include "x509.h"
#include "sshpkcs8.h"
#include "sshpkcs12-conv.h"
#include "sshprvkey.h"
#include "sshpubkey.h"

#include "extkeyprov.h"
#include "sshproxykey.h"

#define SSH_DEBUG_MODULE "SshEKSoft"

/* The default polling interval */
#define SSH_SOFT_PROV_DEFAULT_POLLING_INTERVAL_MS 10000

/* Convert bits to a byte */
#define SSH_BITS_TO_BYTE(x) (((x) + 7) >> 3)

/* This is the provider object */
typedef struct SshSoftProvRec
{
  /* Call to notify the application there are keys available. */
  SshEkNotifyCB notify_cb;

  /* Get PIN code from the application for a key. */
  SshEkAuthenticationCB authentication_cb;

  /* Callback context for the callbacks above. */
  void *notify_context;

  /* Reference count for the keys this provider instance has out. */
  SshUInt32 num_keys;

  /* Mark the provider destroyed (actual descruction is done when the
     last key provided has been destroyed). */
  Boolean destroyed;

  /* This flag is set when public key operations completion is
     decided randomly. */
  Boolean random_completion;

  /* When this flag is set private keys are converted to proxy format. */
  Boolean use_proxy;

  /* This is the asynchronous completion timeout, in milliseconds.
     Zero means completion is synchronous. */
  unsigned int async_time_ms;

  /* This is the interval by which the added directories are polled. */
  unsigned int polling_interval_ms;

  /*  Keys added from directories or from initialization info */
  SshADTContainer keys_out;

  /* List of directories that are polled perioidically. */
  SshADTContainer poll_directories;

  /* strmap of all files found in directories, indexed by their full name */
  SshADTContainer all_dir_files;

  /* list of all proxy keys. When we invalidate all the pin information
     we iterate all these and delete the key */
  SshADTContainer proxy_keys;

  /* Operation handle for an ongoing private-key get operation. This
     is aborted during softprovider uninit. */
  SshOperationHandle key_operation;

  /* Enabled */
  Boolean enabled;

  /* Tracing is enabled; */
  Boolean enable_tracing;

  /* This is incremented on each poll and the polling_generation is
     stored on all found files. After the poll we check that if some
     of the known files were not touched, we investigate should they
     be reported. */
  SshUInt32 polling_generation;
} *SshSoftProv, SshSoftProvStruct;

/* Key context for software keys. */
typedef struct SshSoftKeyRec
{
  char *keypath;
  char *directory;
  char *label;
  SshEkEvent key_state;
  SshEkEvent notify_state;
  SshPublicKey public_key;
  SshPrivateKey private_key;
  SshUInt32 key_size;

  /* Used as a first try for the passphrase. Otherwise the auth
     callback may need to be called first for get public key, then for
     get certificate, and then for get private key, where the private
     key will be made as a "raw" key where only public key is stored
     (get public key will ask for passphrase again) and when
     operations are done with the key, the passphrase is asked
     again... You see, caching is useful */
  unsigned char *passphrase;
  size_t passphrase_len;

  struct {
    unsigned char *data;
    size_t len;
  } raw;

  struct {
    unsigned char *data;
    size_t len;
  } cert;

  SshPkGroup pk_group;

  char *path;
  int trynum;

  SshADTContainer key_files;
  SshSoftProv soft;             /* Back pointer to provider. */

} *SshSoftKey, SshSoftKeyStruct;

#define SshSoftFileType SshUInt32

/* Different types of keys */
#define SSH_SOFT_FT_UNKNOWN_FILE 0x01
#define SSH_SOFT_FT_PUB_KEY      0x02
#define SSH_SOFT_FT_PRV_KEY      0x04
#define SSH_SOFT_FT_CRT_FILE     0x08
#define SSH_SOFT_FT_INVALIDATED  0x10

/*  PKCS#12 may be (and usually is prv and cert) type */
#define SSH_SOFT_FT_PKCS12  \
(SSH_SOFT_FT_PUB_KEY | SSH_SOFT_FT_PRV_KEY | SSH_SOFT_FT_CRT_FILE)

/* Contains information about key file, so that we do not have to
   deduce the key type everyt time.  */
typedef struct SshSoftFileInfoRec
{
  SshSoftFileType file_type;

  /* For each polling time we update our generation. If we find out,
     that some of the files are missing (the generation did not get
     updated) during the directory traveersals, we check if the
     private key file is still available. */
  SshUInt32 generation;
  char *label;
} *SshSoftFileInfo;


/* The ADT callback for clearing key info */
void ssh_soft_file_info_clear_cb(void *obj, void *context)
{
  SshSoftFileInfo info = obj;
  ssh_free(info->label);
  ssh_free(info);
}

/* Find the file info for a known key */
SshSoftFileInfo ssh_soft_get_file_info(SshSoftProv soft,
                                       const char *file_name)
{
  return ssh_adt_strmap_get(soft->all_dir_files, file_name);
}


/* Insert a file into the provider. if the file is known to the provider,
   just update the type of it, even it in most cases it the same. */
void ssh_soft_cache_known_file(SshSoftProv soft,
                               const char *full_file_name,
                               SshSoftFileType type,
                               const char *label)
{
  SshSoftFileInfo info;

  info = ssh_soft_get_file_info(soft, full_file_name);

  if (info == NULL)
    {
      /* A new key */
      info = ssh_calloc(1, sizeof(*info));
      if (info && ssh_adt_strmap_add(soft->all_dir_files,
                                     full_file_name, info) == NULL)
        {
          ssh_free(info);
          info = NULL;
        }
    }
  if (info)
    {
      info->file_type = type;
      info->generation = soft->polling_generation;
      ssh_free(info->label);
      info->label = NULL;
      if (label)
        info->label = ssh_strdup(label);
    }
}

/* Clear the software provider key. ADT destroy callback */
void ssh_soft_clear_key(void *obj, void *context)
{
  SshSoftKey key = obj;
  SshADTHandle handle, next;
  SshSoftProv soft = key->soft;

  /* Enumerate all the proxy keys and delete the listed keys from
     proxy key list */
  for (handle = ssh_adt_enumerate_start(soft->proxy_keys);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      SshSoftKey tmp_key;

      next = ssh_adt_enumerate_next(soft->proxy_keys, handle);
      tmp_key = ssh_adt_get(soft->proxy_keys, handle);
      if (key == tmp_key)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Deleting proxy key from ADT list"));
          ssh_adt_delete(soft->proxy_keys, handle);
        }
    }

  ssh_free(key->label);
  ssh_free(key->keypath);
  ssh_free(key->directory);
  ssh_free(key->raw.data);
  ssh_free(key->cert.data);

  if (key->pk_group)
    ssh_pk_group_free(key->pk_group);
  ssh_free(key->path);
  if (key->key_files)
    ssh_adt_destroy(key->key_files);
  if (key->public_key)
    ssh_public_key_free(key->public_key);
  if (key->private_key)
    ssh_private_key_free(key->private_key);
  if (key->passphrase)
    ssh_free(key->passphrase);
  ssh_free(key);
}



/* Returns components from string. Returns true if the component
   exists, and the component data in buf_return. The strings to this
   function are typically of form
   component1=data?component2=data2... The return data is null terminated
   string. */
static Boolean
soft_get_path_component(const char *input_str,
                        const char *component_name,
                        unsigned char **buf_return,
                        size_t *buf_return_len)
{
  char *comp_start, *comp_end;
  const char *str_end;

  *buf_return = NULL;

  str_end = input_str + strlen(input_str);

  comp_start = (char *)(strstr(input_str, component_name));

  if (comp_start == NULL)
    {
      /* The component was not found from the input string. */
      return FALSE;
    }

  comp_start += strlen(component_name);
  if (comp_start >= str_end - 2 || comp_start[0] != '=')
    {
      SSH_DEBUG(SSH_D_ERROR, ("Possibly the URL is not in the right format. "
                              "Input string %s, component %s",
                              input_str, component_name));
      return FALSE;
    }

  comp_start += 1;
  comp_end = strchr(comp_start, '?');

  if (comp_end == NULL)
    comp_end = (char *)str_end;

  /* The return data becomes zero padded automatically. */
  if ((*buf_return = ssh_memdup(comp_start, comp_end - comp_start)) != NULL)
    *buf_return_len = comp_end - comp_start;
  else
    {
      *buf_return_len = 0;
      return FALSE;
    }
  return TRUE;
}

/* Returns components from string. Returns true if the component
   exists, and the component data in buf_return. The strings to this
   function are typically of form
   component1=base64block?component2=base64bloc... The return data
   contains the data where the base64 armoring has been removed. The
   data is automatically zero padded, but the zero is not included in
   the return_len. */
static Boolean
soft_get_path_component_base64(const char *input_str,
                               const char *component_name,
                               unsigned char **buf_return,
                               size_t *buf_return_len)
{
  Boolean ret;

  ret = soft_get_path_component(input_str, component_name,
                                buf_return, buf_return_len);

  if (ret)
    {
      unsigned char *p;

      p = *buf_return;
      *buf_return = ssh_base64_to_buf(p, buf_return_len);
      ssh_free(p);

      if ((*buf_return) == NULL)
        return FALSE;
    }
  return ret;
}


/* Too bad, that these are different in the different systems. */
#ifdef WIN32
#define DIR_SEPARATOR '\\'
#define DIR_SEPARATOR_STR "\\"
#else
#define DIR_SEPARATOR '/'
#define DIR_SEPARATOR_STR "/"
#endif /* WIN32 */

/* Makes the full path names out of directory and file names.
   Caller must free the resulting string. */
static char *
ssh_soft_make_full_file_name(const char *dir, const char *file_name)
{
  unsigned char *tmp_file_name;
  size_t l;
  Boolean has_separator = FALSE;

  if (file_name == NULL)
    return NULL;

  if (dir == NULL || (l = strlen(dir)) == 0)
    return ssh_strdup(file_name);

  if (dir[l - 1] == DIR_SEPARATOR)
    has_separator = TRUE;

  if (ssh_dsprintf(&tmp_file_name, "%s%s%s",
                   dir,
                   (has_separator ? "" : DIR_SEPARATOR_STR),
                   file_name) == -1)
    return NULL;

  return ssh_sstr(tmp_file_name);
}

/* Callback type */
typedef enum {
  SOFT_PROV_TIMEOUT,
  SOFT_PROV_ASYNC_PRIVATE,
  SOFT_PROV_ASYNC_PUBLIC,
  SOFT_PROV_ASYNC_CERT,
  SOFT_PROV_KEYOP_RESULT,
  SOFT_PROV_VERFY_RESULT
} SshSoftAsyncType;


/* Schedule an asynchronous keyop callback */
static SshOperationHandle
soft_prov_async_keyop_cb(SshSoftProv soft,
                         SshCryptoStatus status,
                         unsigned char *buf, size_t buf_len,
                         SshPrivateKeyDecryptCB callback, void *context);

/* Schedule an asynchronous verify callback. */
SshOperationHandle
soft_prov_async_verify_cb(SshSoftProv soft,
                          SshCryptoStatus status,
                          SshProxyReplyCB callback, void *context);

/* Schedule an asyncronous private key callback */
static SshOperationHandle
soft_prov_async_private_cb(SshSoftProv soft,
                          SshEkStatus status, SshPrivateKey key,
                          SshEkGetPrivateKeyCB cb, void *context);

/* Schedule an asyncronous public key callback */
static SshOperationHandle
soft_prov_async_public_cb(SshSoftProv soft,
                          SshEkStatus status, SshPublicKey key,
                          SshEkGetPublicKeyCB cb, void *context);

/* Schedule an asyncronous cert callback */
static SshOperationHandle
soft_prov_async_cert_cb(SshSoftProv soft,
                        SshEkStatus status, unsigned char *data,
                        size_t data_len,
                        SshEkGetCertificateCB cb, void *context);


/* The type of the passphrase callback, which is called when the
   passphrase query is over. */
typedef void (*SshSoftAskPassCB)(SshEkStatus status,
                                 SshPrivateKey key,
                                 unsigned char *cert,
                                 size_t cert_len,
                                 void *context);


/* Find a suitable name for the directory key */
char *ssh_soft_find_key_label(SshSoftProv soft, const char *file_name)
{
  char *label, *cipher, *hash;
  unsigned char *buf;
  size_t buf_len;
  SshSKBType prv_type;
  SshCryptoStatus status;
  SshSoftFileInfo info;

  info = ssh_soft_get_file_info(soft, file_name);
  if (info != NULL && info->label)
    return ssh_strdup(info->label);

  if (ssh_read_file_with_limit(file_name, SSH_READ_FILE_LIMIT_CRYPTO_OBJ,
                               &buf, &buf_len) == FALSE)
    {
      return ssh_strdup("Unreadable file");
    }

  status = ssh_skb_get_info(buf, buf_len,
                            &cipher, &hash,
                            NULL, NULL, &prv_type, &label);

  ssh_free(buf);
  ssh_free(cipher);
  ssh_free(hash);
  if (status == SSH_CRYPTO_OK && label != NULL)
    {
      return label;
    }
  else
    {
      /* We could not get the label out from the key, return the file
         name.  */
      return ssh_strdup(file_name);
    }
}


/* The structure holding auxilliary information during the
   authentication callback call */
typedef struct SshSoftAskPassRec
{
  SshSoftProv soft;
  SshUInt32 trynum;
  SshOperationHandle handle;

  /* The handle of the authentication call returned by the
     authentication callback */
  SshOperationHandle sub_op;
  unsigned char *key_data;
  size_t key_data_len;
  char *keypath;
  SshSoftAskPassCB callback;
  void *context;
  SshEkAuthenticationStatus astatus;
  SshUInt32 cert_index;
} *SshSoftAskPass;


void ssh_soft_store_passphrase(SshSoftProv soft,
                               const char *keypath,
                               const unsigned char *code,
                               size_t len)
{
  SshSoftKey key_ctx;

  if (keypath &&
      (key_ctx = ssh_adt_strmap_get(soft->keys_out, keypath)))
    {
      if (key_ctx->passphrase && key_ctx->passphrase != code)
        ssh_free(key_ctx->passphrase);

      if (code != key_ctx->passphrase)
        if ((key_ctx->passphrase = ssh_memdup(code, len)) != NULL)
          key_ctx->passphrase_len = len;
    }
}

/* Forward declaration of a function */
static void
ssh_soft_ask_pass(void *context);

/* Free the context used during the authentication call */
static void
ssh_soft_ask_pass_free(void *context)
{
  SshSoftAskPass c = context;
  ssh_free(c->key_data);
  ssh_cancel_timeouts(ssh_soft_ask_pass, context);
  ssh_operation_unregister(c->handle);
  ssh_free(c->keypath);
  ssh_free(c);
}

/* get SshStr for PKCS12 operations */
static SshStr
get_sshstr(const unsigned char *str, size_t len)
{
  SshStr passwd;
  passwd = ssh_str_make(SSH_CHARSET_ISO_8859_1,
                        ssh_memdup(str, len), len);
  return passwd;
}


/* The callback called by the user of the external key when the
   acquiring of the pin data is completed. We will try to decode
   the key in here */
static void ssh_soft_auth_reply(const unsigned char *code,
                                size_t len,
                                void *context)
{
  SshSoftAskPass c = context;
  SshCryptoStatus status;
  SshSKBType kind;
  unsigned char *cert_buf = NULL;
  size_t cert_buf_len = 0;
  SshPrivateKey key = NULL;
  SshEkStatus estatus;
  char *cipher, *hash;

  c->sub_op = NULL;

#define DECODING_PROTECTED_KEY 1

/* Try to decide */
  while (DECODING_PROTECTED_KEY)
    {
      if (code == NULL)
        {
          /* No code provided,  the call will fail */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication call aborted"));
          estatus = SSH_EK_KEY_ACCESS_DENIED;
          break;
        }

      /* Re get information about the object type we are dealing with */
      if (ssh_skb_get_info(c->key_data, c->key_data_len,
                           &cipher, &hash,
                           NULL, NULL,
                           &kind, NULL) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Can not deduce the kind of the key"));
          estatus = SSH_EK_KEY_BAD_FORMAT;
          break;
        }

      /* Decode the private key object */
      status = ssh_skb_decode(kind, c->key_data, c->key_data_len,
                              cipher, hash,
                              code, len, &key);
      ssh_free(cipher);
      ssh_free(hash);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to decode the key data: %s",
                     ssh_crypto_status_message(status)));

          if (status == SSH_CRYPTO_INVALID_PASSPHRASE)
            {
              /* The passphrase must have been wrong. New call to auth
                 callback. */
              c->astatus = SSH_EK_AUTHENTICATION_CODE_WRONG;
              ssh_soft_ask_pass(context);
              return;
            }

          /* Some other error. */
          estatus = SSH_EK_KEY_BAD_FORMAT;
          break;
        }

      /* The password was applied successfully. We store the
         passphrase to the key context, so that it can be used as a
         first try for next attempts. */
      ssh_soft_store_passphrase(c->soft, c->keypath, code, len);

      /* Check for PKSC#12 cert */
      if (kind == SSH_SKB_PKCS12_BROWSER_KEY)
        {
          SshStr pass;

          pass = get_sshstr(code, len);
          if (pass == NULL)
            {
              estatus = SSH_EK_NO_MEMORY;
              break;
            }

          cert_buf = NULL;
          /* Extract the nth certificate */
#if 1
          if (ssh_pkcs12_conv_decode_cert(c->key_data, c->key_data_len,
                                          pass, c->cert_index, NULL,
                                          &cert_buf, &cert_buf_len)
              != SSH_PKCS12_OK)
            {
              ssh_free(cert_buf);
              cert_buf = NULL;
            }
#endif
         ssh_str_free(pass);
        }

      estatus = SSH_EK_OK;
      break;
    }

  (*c->callback)(estatus,
                 key, cert_buf, cert_buf_len,
                 c->context);

  ssh_operation_unregister(c->handle);
  c->handle = NULL;
  ssh_soft_ask_pass_free(context);
}

/* Internal operation that starts the whole query. It makes things simplier
   if we know that the ssh_soft_ask_password is always asynchronous, not
   depending on the response from the externalkey user */
static void
ssh_soft_ask_pass(void *context)
{
  SshSoftAskPass c = context;
  SshOperationHandle h;
  SshSoftKey key_ctx;
  char *label;

  key_ctx = ssh_adt_strmap_get(c->soft->keys_out, c->keypath);
  /* If there is a cached passphrase for this key, try using it first */
  if (key_ctx)
    {
      if (key_ctx->passphrase)
        {
          ssh_soft_auth_reply(key_ctx->passphrase,
                              key_ctx->passphrase_len,
                              context);

          return;
        }
    }


  if (key_ctx)
    label = key_ctx->label;
  else
    label = "Software Key";

  h = (*c->soft->authentication_cb)(c->keypath, label, c->trynum++,
                                    c->astatus,
                                    ssh_soft_auth_reply,
                                    context,
                                    c->soft->notify_context);
  if (h)
    c->sub_op = h;
}

/* The abort callback for the ask pass operation */
static void ssh_soft_ask_pass_abort(void *context)
{
  SshSoftAskPass c = context;

  ssh_operation_abort(c->sub_op);
  ssh_cancel_timeouts(ssh_soft_ask_pass, context);
  ssh_soft_ask_pass_free(context);
}


/* This starts authentication code query from the externalkey
   authentication callback using the authentication_cb that was
   provided to the initalization function of the EK provider.

   The key material, and the possible cert_index is goven as an
   argument. The decoded key and cert is given in callback.
   The authentication operation may be cancelled by calling
   ssh_operation_abort for the returned handle.

   This function eats the input buffer, so the caller must not
   access it after this call has completed. */
static SshOperationHandle
ssh_soft_ask_password(SshSoftProv soft,
                      unsigned char *buf,
                      size_t buf_len,
                      const char *keypath,
                      SshUInt32 cert_index,
                      SshSoftAskPassCB passwd_cb,
                      void *context)
{
  SshSoftAskPass pass = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Key required a password"));

  pass = ssh_calloc(1, sizeof(*pass));
  if (pass == NULL)
    goto failed;

  pass->soft = soft;
  pass->key_data = buf;
  pass->key_data_len = buf_len;
  pass->keypath = ssh_strdup(keypath);
  if (pass->keypath == NULL)
      goto failed;

  pass->cert_index = cert_index;
  pass->callback = passwd_cb;
  pass->context = context;
  pass->astatus = SSH_EK_AUTHENTICATION_CODE_NEEDED;
  pass->handle = ssh_operation_register(ssh_soft_ask_pass_abort,
                                        pass);
  if (pass->handle == NULL)
    goto failed;

  ssh_register_timeout(NULL, 0, 0, ssh_soft_ask_pass, pass);
  return pass->handle;

 failed:
  if (pass)
    {
      if (pass->keypath)
        ssh_free(pass->keypath);
      ssh_free(pass);
    }
  ssh_free(buf);
  (*passwd_cb)(SSH_EK_FAILED, NULL, NULL, 0, context);
  return NULL;
}

/* Forward declaration. Called when crypto library is doing
   an operation with the private key.  */
static SshOperationHandle
ssh_soft_key_op_cb(SshProxyOperationId operation_id,
                   SshProxyRGFId rgf_id,
                   SshProxyKeyHandle handle,
                   const unsigned char *data,
                   size_t data_len,
                   SshProxyReplyCB reply_cb,
                   void *reply_context,
                   void* context);

/* The structure used while asking the passphrase during the key
   operation */
typedef struct SshSoftKeyOpAskPassRec
{
  SshOperationHandle op;
  SshOperationHandle sub_op;
  SshProxyOperationId operation_id;
  SshProxyRGFId rgf_id;
  SshProxyKeyHandle handle;
  const unsigned char *data;
  size_t data_len;

  /* Key data is freed by the passphrase query */
  unsigned char *key_data;
  size_t key_data_len;
  SshProxyReplyCB reply_cb;
  void *reply_context;
  void *context;
  SshSoftKey key_ctx;
} *SshSoftKeyOpAskPass;

/* frees the passphrase query during the key op */
void ssh_soft_ask_pass_in_keyop_free(void *context)
{
  SshSoftKeyOpAskPass ctx = context;
  ssh_operation_unregister(ctx->op);
  /* Key data is freed by the passphrase query, and the other buffer
     data is constant */
  ssh_free(ctx);
}

/* The abort callback for the operation we return from the proxy key
   callback */
void ssh_keyop_ask_pass_abort(void *context)
{
  SshSoftKeyOpAskPass ctx = context;
  ssh_operation_abort(ctx->sub_op);
  ctx->sub_op = NULL;
  ctx->op = NULL;
  ssh_soft_ask_pass_in_keyop_free(ctx);
}

/* Called when we have retried the key operation when we have decrypted
   the key */
static void ssh_ask_key_op_retry_cb(SshCryptoStatus status,
                                    const unsigned char *operated_data,
                                    size_t data_len,
                                    void *context)
{
  SshSoftKeyOpAskPass ctx = context;

  ctx->sub_op = NULL;
  /* Inform the proxy key about the completed operation */
  (*ctx->reply_cb)(status, operated_data, data_len, ctx->reply_context);

  /* Free our auxillary context */
  ssh_soft_ask_pass_in_keyop_free(ctx);
}

/* Called when the ask passphrase (during the keyop) is done, and we
   might have a key if everything went fine.  */
static void
ssh_soft_ask_pass_in_keyop_done(SshEkStatus status,
                                SshPrivateKey key,
                                unsigned char *cert,
                                size_t cert_data,
                                void *context)
{
  SshSoftKeyOpAskPass ctx = context;
  SshCryptoStatus cstatus;

  ctx->sub_op = NULL;

  /* Cert data is not needed here, even if such was found in the key data. */
  ssh_free(cert);

  if (status == SSH_EK_OK)
    {
      /* Acquiring of the private key was successfull */
      SshOperationHandle handle;

      if (ctx->key_ctx->private_key != NULL)
        {
          /* Somebody had completed the key decrypt before us. Just
             free our key then */
          ssh_private_key_free(key);
        }
      else
        {
          /* Store the key to the key context so that the decrypt is
             not needed anymore */
          ctx->key_ctx->private_key = key;
        }

      /* Now try again the key operation. */
      handle = ssh_soft_key_op_cb(ctx->operation_id,
                                  ctx->rgf_id,
                                  ctx->handle,
                                  ctx->data,
                                  ctx->data_len,
                                  ssh_ask_key_op_retry_cb,
                                  ctx,
                                  ctx->context);
      if (handle)
        ctx->sub_op = handle;
    }
  else
    {
      switch (status)
        {
        case SSH_EK_KEY_ACCESS_DENIED:
          cstatus = SSH_CRYPTO_OPERATION_CANCELLED;
          break;
        case SSH_EK_KEY_BAD_FORMAT:
          cstatus = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
          break;
        default:
          cstatus = SSH_CRYPTO_PROVIDER_ERROR;
        }

      /*  We could not decipher the key. Fail */
      (*ctx->reply_cb)(cstatus,
                       NULL, 0, ctx->reply_context);
      ssh_soft_ask_pass_in_keyop_free(ctx);
    }
}

/* The callback that is called when a key is freed using
   ssh_private_key_free. */
void ssh_soft_free_cb(void *context)
{
  SshSoftKey key_ctx = context;

  key_ctx->soft->num_keys--;
  ssh_soft_clear_key(context, NULL);
}

#define SSH_DSA_SIGNATURE_LEN 40
#define SSH_ECDSA_SIGNATURE_LEN 132

/* Called when crypto library is doing an operation with the proxy
   private key.  */
static SshOperationHandle
ssh_soft_key_op_cb(SshProxyOperationId operation_id,
                   SshProxyRGFId rgf_id,
                   SshProxyKeyHandle proxy_handle,
                   const unsigned char *data,
                   size_t data_len,
                   SshProxyReplyCB reply_cb,
                   void *reply_context,
                   void* context)
{
  SshSoftKey key_ctx;
  unsigned char *result_buf = NULL;
  size_t plain_len_return_len;
  SshCryptoStatus status = SSH_CRYPTO_NO_MEMORY;

  key_ctx = (SshSoftKey)context;

  /* If we do not have the key yet, (it needed a passphrase) ask the
     passphrase now */
  if (key_ctx->private_key == NULL && key_ctx->raw.data != NULL)
    {
      SshOperationHandle op, handle;
      SshSoftKeyOpAskPass ctx;

      ctx = ssh_calloc(1, sizeof(*ctx));
      if (ctx == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation error"));
          goto failed;
        }

      op = ssh_operation_register(ssh_keyop_ask_pass_abort, ctx);
      ctx->op = op;

      if (ctx->op == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation error"));
          ssh_free(ctx);
          goto failed;
        }
      ctx->key_data = ssh_memdup(key_ctx->raw.data, key_ctx->raw.len);
      if (ctx->key_data == NULL)
        {
          ssh_operation_unregister(ctx->op);
          ssh_free(ctx);
          goto failed;
        }
      ctx->key_data_len = key_ctx->raw.len;
      ctx->operation_id = operation_id;
      ctx->rgf_id = rgf_id;
      ctx->handle = proxy_handle;
      ctx->data = data;
      ctx->data_len = data_len;
      ctx->reply_cb = reply_cb;
      ctx->reply_context = reply_context;
      ctx->context = context;
      ctx->key_ctx = key_ctx;

      handle = ssh_soft_ask_password(key_ctx->soft,
                                     ctx->key_data,
                                     ctx->key_data_len,
                                     key_ctx->keypath,
                                     0,
                                     ssh_soft_ask_pass_in_keyop_done,
                                     ctx);
      if (handle)
        ctx->sub_op = handle;
      return op;
    }

  status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
  if (key_ctx->private_key == NULL)
    goto failed;

#ifdef DEBUG_LIGHT
  if (key_ctx->keypath)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Key op with %s", key_ctx->keypath));
    }
#endif

  if (operation_id == SSH_RSA_PRV_SIGN)
    {
      /* RSA SIGN  */
      unsigned char *output_data;
      size_t output_data_len;
      size_t max_len, max_bit_len;

      max_bit_len = key_ctx->key_size;
      max_len = SSH_BITS_TO_BYTE(key_ctx->key_size);

      status = ssh_proxy_key_rgf_sign(operation_id, rgf_id,
                                      max_bit_len,
                                      data, data_len,
                                      &output_data, &output_data_len);
      if (status != SSH_CRYPTO_OK)
        goto failed;

      result_buf = ssh_malloc(max_len);
      if (result_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Mem allocation error"));
          ssh_free(output_data);
          (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }

      ssh_private_key_select_scheme(key_ctx->private_key, SSH_PKF_ENCRYPT,
                                    "rsa-none-none", SSH_PKF_END);

      status = ssh_private_key_decrypt(key_ctx->private_key,
                                       output_data, output_data_len,
                                       result_buf, max_len,
                                       &plain_len_return_len);
      ssh_free(output_data);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(result_buf);
          SSH_DEBUG(SSH_D_FAIL, ("Could not sign the data"));
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }
    }
  else if (operation_id == SSH_RSA_PRV_DECRYPT)
    {
      unsigned char *output_data;
      size_t max_len, max_bit_len;

      max_bit_len = key_ctx->key_size;
      max_len = SSH_BITS_TO_BYTE(key_ctx->key_size);

      result_buf = ssh_malloc(max_len);
      if (result_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Mem allocation error"));
          (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }

      ssh_private_key_select_scheme(key_ctx->private_key, SSH_PKF_ENCRYPT,
                                    "rsa-none-none", SSH_PKF_END);

      status = ssh_private_key_decrypt(key_ctx->private_key,
                                       data, data_len,
                                       result_buf, max_len,
                                       &plain_len_return_len);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(result_buf);
          SSH_DEBUG(SSH_D_FAIL, ("Could not decrypt the data"));
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }

      status = ssh_proxy_key_rgf_decrypt(operation_id, rgf_id,
                                         max_bit_len,
                                         result_buf, plain_len_return_len,
                                         &output_data, &plain_len_return_len);
      ssh_free(result_buf);
      result_buf = output_data;

      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(result_buf);
          SSH_DEBUG(SSH_D_FAIL, ("Could not decrypt the data"));
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }
    }
  else if (operation_id == SSH_DSA_PRV_SIGN)
    {
      /* DSA key */
      result_buf = ssh_malloc(SSH_DSA_SIGNATURE_LEN);
      if (result_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Mem allocation error"));
          (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }

      /* Use rgf_id to determine whether this is a sign or sign_digest */

      if (rgf_id == SSH_DSA_NIST_SHA1)
        {
          status = ssh_private_key_select_scheme(key_ctx->private_key,
                                                 SSH_PKF_SIGN,
                                                 "dsa-nist-sha1",
                                                 SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Failed to select scheme for DSA key."));
              ssh_free(result_buf);
              (*reply_cb)(status, NULL, 0, reply_context);
              return NULL;
            }

          status = ssh_private_key_sign(key_ctx->private_key,
                                        data, data_len,
                                        result_buf,
                                        SSH_DSA_SIGNATURE_LEN,
                                        &plain_len_return_len);
        }
      else if (rgf_id == SSH_DSA_NONE_NONE)
        {
          /* The private key must have a scheme set even if the hash
             function was not used in the signing operation */
          status = ssh_private_key_select_scheme(key_ctx->private_key,
                                                 SSH_PKF_SIGN,
                                                 "dsa-nist-sha1",
                                                 SSH_PKF_END);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Failed to select scheme for DSA key."));
              ssh_free(result_buf);
              (*reply_cb)(status, NULL, 0, reply_context);
              return NULL;
            }

          status = ssh_private_key_sign_digest(key_ctx->private_key,
                                               data, data_len,
                                               result_buf,
                                               SSH_DSA_SIGNATURE_LEN,
                                               &plain_len_return_len);
        }
      else
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          SSH_DEBUG(SSH_D_FAIL, ("Unknown scheme %d", rgf_id));
        }

      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(result_buf);
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not sign digest: %s",
                     ssh_crypto_status_message(status)));
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }
    }
  else if (operation_id == SSH_ECDSA_PRV_SIGN)
    {
      const char *scheme = NULL;

      result_buf = ssh_malloc(SSH_ECDSA_SIGNATURE_LEN);

      if (result_buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
          (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }

      switch (rgf_id)
        {
        case SSH_ECDSA_NIST_SHA256:
          scheme = "dsa-none-sha256";
          break;
        case SSH_ECDSA_NIST_SHA384:
          scheme = "dsa-none-sha384";
          break;
        case SSH_ECDSA_NIST_SHA512:
          scheme = "dsa-none-sha512";
          break;
        case SSH_ECDSA_NONE_NONE:
          /* We need to set a scheme to the key even if the hash was
             not used*/
          scheme = "dsa-none-sha512";
          break;
        default:
          SSH_NOTREACHED;
        }

      status = ssh_private_key_select_scheme(key_ctx->private_key,
                                             SSH_PKF_SIGN, scheme,
                                             SSH_PKF_END);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to select scheme '%s' for ECDSA key."));
          ssh_free(result_buf);
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }

      if (rgf_id == SSH_ECDSA_NONE_NONE)
        {
          status = ssh_private_key_sign_digest(key_ctx->private_key,
                                               data, data_len,
                                               result_buf,
                                               SSH_ECDSA_SIGNATURE_LEN,
                                               &plain_len_return_len);
        }
      else
        {
          status = ssh_private_key_sign(key_ctx->private_key,
                                        data, data_len,
                                        result_buf,
                                        SSH_ECDSA_SIGNATURE_LEN,
                                        &plain_len_return_len);
        }


      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to sign data"));
          ssh_free(result_buf);
          (*reply_cb)(status, NULL, 0, reply_context);
          return NULL;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid proxy operation id: '%d'",
                             (int) operation_id));
      (*reply_cb)(status, NULL, 0, reply_context);
      return NULL;
    }

  return soft_prov_async_keyop_cb(key_ctx->soft,
                                  SSH_CRYPTO_OK,
                                  result_buf, plain_len_return_len,
                                  reply_cb, reply_context);
 failed:
  ssh_free(result_buf);
  return soft_prov_async_keyop_cb(key_ctx->soft,
                                  status,
                                  NULL, 0,
                                  reply_cb, reply_context);
}

/* Converts a software key to "accelerated key". The real
   implementation would use ssh_private_key_get_info as declared in
   sshcryp.h, we just create a context which has the original key
   inside. */
static SshPrivateKey
soft_convert_prv_key(SshSoftProv soft,
                     SshPrivateKey source)
{
  SshSoftKey key_ctx = NULL;
  SshPrivateKey key = source;
  char *source_key_name = NULL;
  unsigned int size;
  SshUInt32 key_size = 0;
  SshProxyKeyTypeId key_type_id;
  SshMPIntegerStruct p;

  source_key_name = ssh_private_key_name(source);
  if (source_key_name == NULL)
    goto failed;

  if (strstr(source_key_name, "if-modn") != NULL)
    key_type_id = SSH_PROXY_RSA;
  else if (strstr(source_key_name, "dl-modp") != NULL)
    key_type_id = SSH_PROXY_DSA;
  else if (strstr(source_key_name, "ec-modp") != NULL)
    key_type_id = SSH_PROXY_ECDSA;
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid key name '%s'", source_key_name));
      goto failed;
    }

  if (key_type_id == SSH_PROXY_ECDSA)
    {
      ssh_mprz_init(&p);

      if (ssh_private_key_get_info(source,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to get ECDSA prime"));
          goto failed;
        }

      key_size = ssh_mprz_byte_size(&p);
      ssh_mprz_clear(&p);
    }
  else
    {
      if (ssh_private_key_get_info(source,
                                   SSH_PKF_SIZE, &size,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to get public key size"));
          goto failed;
        }
      key_size = (SshUInt32)size;
    }

  /* Wrap the actual software implementation inside external key. */
  key_ctx = ssh_calloc(1, sizeof(*key_ctx));
  if (key_ctx == NULL)
    goto failed;

  key_ctx->private_key = source;
  key_ctx->soft = soft;
  key_ctx->key_size = key_size;

  key = ssh_private_key_create_proxy(key_type_id,
                                     key_size,
                                     ssh_soft_key_op_cb,
                                     ssh_soft_free_cb,
                                     key_ctx);

  if (key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create proxy key"));
      goto failed;
    }

  soft->num_keys++;
  ssh_free(source_key_name);
  return key;

 failed:
  if (source_key_name)
    ssh_free(source_key_name);
  if (key_ctx)
    ssh_soft_clear_key(key_ctx, NULL);
  return source;
}


/* Converts a software key to "accelerated key". The real
   implementation would use ssh_private_key_get_info as declared in
   sshcryp.h, we just create a context which has the original key
   inside or in this raw key case, we use the context which has
   the encrypted key material inside, and when we use the key
   we decrypt the key once we had received the passphrase from
   the user. */
static SshPrivateKey
soft_convert_raw_prv_key(SshSoftProv soft,
                         char *keypath,
                         SshPublicKey public_key,
                         unsigned char *private_buf,
                         size_t private_buf_len)
{
  SshSoftKey key_ctx = NULL;
  SshPrivateKey key = NULL;
  char *source_key_name = NULL;
  unsigned int size;
  SshUInt32 key_size = 0;
  SshProxyKeyTypeId key_type_id;
  SshMPIntegerStruct p;

  source_key_name = ssh_public_key_name(public_key);

  if (source_key_name == NULL)
    goto failed;

  if ((strstr(source_key_name, "if-modn") != NULL))
    key_type_id = SSH_PROXY_RSA;
  else if (strstr(source_key_name, "dl-modp") != NULL)
    key_type_id = SSH_PROXY_DSA;
  else if (strstr(source_key_name, "ec-modp") != NULL)
    key_type_id = SSH_PROXY_ECDSA;
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unknown keytype '%s'", source_key_name));
      goto failed;
    }

  if (key_type_id == SSH_PROXY_ECDSA)
    {
      ssh_mprz_init(&p);

      if (ssh_public_key_get_info(public_key,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to get ECDSA prime"));
          goto failed;
        }

      key_size = ssh_mprz_byte_size(&p);
      ssh_mprz_clear(&p);
    }
  else
    {
      if (ssh_public_key_get_info(public_key,
                                  SSH_PKF_SIZE, &size,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to get public key size"));
          goto failed;
        }
      key_size = (SshUInt32)size;
    }


  /* Wrap the actual software implementation inside external key. */
  key_ctx = ssh_calloc(1, sizeof(*key_ctx));
  if (key_ctx == NULL)
    goto failed;

  key_ctx->keypath = ssh_strdup(keypath);
  if (key_ctx->keypath == NULL)
    goto failed;
  key_ctx->public_key = public_key;
  key_ctx->soft = soft;
  key_ctx->key_size = key_size;
  key_ctx->raw.data = ssh_memdup(private_buf, private_buf_len);
  if (key_ctx->raw.data == NULL)
    goto failed;

  key_ctx->raw.len = private_buf_len;

  key = ssh_private_key_create_proxy(key_type_id,
                                     key_size,
                                     ssh_soft_key_op_cb,
                                     ssh_soft_free_cb,
                                     key_ctx);

  if (key == NULL)
    goto failed;

  ssh_adt_insert(soft->proxy_keys, key_ctx);
  soft->num_keys++;
  ssh_free(source_key_name);
  return key;

 failed:
  if (key_ctx)
    ssh_soft_clear_key(key_ctx, NULL);
  if (source_key_name)
    ssh_free(source_key_name);
  return key;
}


/* Guesses a file type based on suffix. */
SshSoftFileType ssh_soft_prov_get_file_type(const char *file_name)
{
  /* Check for private key */
  if (strstr(file_name, ".prv") || strstr(file_name, ".priv"))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("%s -> prvkey", file_name));
      return SSH_SOFT_FT_PRV_KEY;
    }

  if (strstr(file_name, ".crt") || strstr(file_name, ".bin") ||
      strstr(file_name, ".ca"))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("%s -> certificate", file_name));
      return SSH_SOFT_FT_CRT_FILE;
    }

  if (strstr(file_name, ".pub"))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("%s -> pubkey", file_name));
      return SSH_SOFT_FT_PUB_KEY;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Type of file '%s' is unknown", file_name));

  return SSH_SOFT_FT_UNKNOWN_FILE;
}

/* Makes a keypath component for a private key file */
char *ssh_soft_prov_get_filepath(const char *file,
                                 SshSoftFileType type)
{
  unsigned char *r = NULL;

  if (type == SSH_SOFT_FT_PRV_KEY)
    ssh_dsprintf(&r, "prvkeyfile=%s? ", file);
  else if (type == SSH_SOFT_FT_PUB_KEY)
    ssh_dsprintf(&r, "pubkeyfile=%s? ", file);
  else if (type == SSH_SOFT_FT_CRT_FILE)
    ssh_dsprintf(&r, "certfile=%s? ", file);

  return ssh_sstr(r);
}


/* Notifies about an initialization added key */
void ssh_soft_prov_notify_key(SshSoftProv soft,
                              SshSoftKey key,
                              SshEkEvent event)
{
  if (key->key_state != key->notify_state)
    {
      if (soft->notify_cb && soft->enable_tracing && soft->enabled)
        (*soft->notify_cb)(event,
                           key->keypath, key->label,
                           SSH_EK_USAGE_AUTHENTICATE |
                           SSH_EK_USAGE_ENCRYPTION |
                           SSH_EK_USAGE_SIGNATURE,
                           soft->notify_context);

      key->notify_state = key->key_state;
    }
}



/* Adds a init key to the store */
void ssh_soft_prov_add_init_key(SshSoftProv soft,
                                const char *keypath,
                                const char *label)
{
  SshSoftKey key;

  key = ssh_calloc(1, sizeof(*key));
  if (key == NULL)
    return;

  key->key_state = SSH_EK_EVENT_KEY_AVAILABLE;
  key->notify_state = SSH_EK_EVENT_KEY_UNAVAILABLE;
  key->keypath = ssh_strdup(keypath);
  key->label = ssh_strdup(label);
  key->soft = soft;

  if (key->keypath == NULL || key->label == NULL)
    {
      ssh_soft_clear_key(key, NULL);
      return;
    }
  if (!ssh_adt_strmap_exists(soft->keys_out, keypath))
    ssh_adt_strmap_add(soft->keys_out, keypath, key);
  else
    ssh_soft_clear_key(key, NULL);
}

/* parses a key spec */
void ssh_soft_prov_parse_key_spec(SshSoftProv soft,
                                  char *key_spec)
{
  char *item;
  char *keypath = NULL, *old_keypath = NULL;
  char *key_spec_end;
  char *label = NULL; /* If label is null, the private keys is not
                         found */

  key_spec_end = key_spec + strlen(key_spec);
  item = key_spec;

  /* Find the comma separated items from the key spec */
  SSH_DEBUG(SSH_D_LOWOK, ("Adding init key %s", key_spec));
  while (item && *item)
    {
      char *e;
      SshSoftFileType file_type;
      unsigned char *buf;
      size_t len;

      /* Find the end of the key spec, (either ',', ')', or '\0') */
      e = strchr(item, ',');
      if (e == NULL)
        e = strchr(item, ')');
      if (e == NULL)
        e = item + strlen(item);
      *e = 0;

      /* Skip all leading whitespace. */
      while (*item && (*item == ' ' || *item == '\t' || *item == '\n'))
        item++;

      if (!*item)
        break;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Checking keypath item %s", item));

      /* Is cert data, prvkey, or path to such */
      if (soft_get_path_component(item, "certdata", &buf, &len))
        {
          old_keypath = keypath;
          keypath = ssh_string_concat_2(keypath, item);
          ssh_free(buf);
          ssh_free(old_keypath);
          SSH_DEBUG(SSH_D_MIDOK, ("keypath=\"%s\"", keypath));

        }
      else if (soft_get_path_component(item, "prvkeydata", &buf, &len))
        {
          ssh_free(label);
          label = ssh_strdup("inlined private key");

          old_keypath = keypath;
          keypath = ssh_string_concat_2(keypath, item);
          ssh_free(buf);
          ssh_free(old_keypath);
          SSH_DEBUG(SSH_D_MIDOK, ("keypath=\"%s\"", keypath));
        }
      else
        {
          file_type = ssh_soft_prov_get_file_type(item);

          if (file_type == SSH_SOFT_FT_PRV_KEY)
            {
              if (label == NULL)
                label = ssh_soft_find_key_label(soft, item);
            }

          if (file_type != SSH_SOFT_FT_UNKNOWN_FILE)
            {
              char *keypath_item;
              old_keypath = keypath;

              keypath_item = ssh_soft_prov_get_filepath(item, file_type);
              SSH_DEBUG(SSH_D_LOWOK, ("keypath item %s", keypath_item));
              keypath = ssh_string_concat_2(keypath, keypath_item);
              SSH_DEBUG(SSH_D_LOWOK, ("New keypath = %s", keypath));
              ssh_free(old_keypath);
              ssh_free(keypath_item);
            }
        }

      if (e < key_spec_end)
        item = e + 1;
      else
        item = NULL;
    }

  if (keypath && label)
    {
      ssh_soft_prov_add_init_key(soft, keypath, label);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Key spec '%s' item did not result into a keypath",
                 key_spec));
    }
  ssh_free(keypath);
  ssh_free(label);
}

/* Inserts directories to be polled to the software provider */
static void
ssh_soft_add_polling_dir(SshSoftProv soft, const char *directory)
{
  char *dir_copy;

  dir_copy = ssh_strdup(directory);
  if (dir_copy == NULL)
    return;
  ssh_adt_insert(soft->poll_directories, dir_copy);
}

/* Parse the initialization string passed to soft_prov_init. */
static SshEkStatus
soft_prov_parse_init_string(SshSoftProv soft, const char *init_str)
{
  char *key_spec, *s;
  SshUInt32 occurance = 0;

  /* Scan for directory specifiers in the initialization info */
  s = ssh_get_component_data_from_string(init_str, "directory", occurance++);
  while (s)
    {
      ssh_soft_add_polling_dir(soft, s);
      ssh_free(s);
      s = ssh_get_component_data_from_string(init_str,
                                             "directory", occurance++);
    }

  /* Scan for key specs */
  occurance = 0;
  key_spec = ssh_get_component_data_from_string(init_str, "key_files",
                                                occurance++);
  while (key_spec)
    {
      /* Notify the key */
      ssh_soft_prov_parse_key_spec(soft, key_spec);

      ssh_free(key_spec);
      key_spec = ssh_get_component_data_from_string (init_str,
                                                     "key_files",
                                                     occurance++);
    }

  /* key_data(prvkeydata=... , certdata= ...) */
  occurance = 0;
  while ((key_spec =
          ssh_get_component_data_from_string(init_str,
                                             "key_data",
                                             occurance++))
         != NULL)
    {
      ssh_soft_prov_parse_key_spec(soft, key_spec);
      ssh_free(key_spec);
    }

  if ((s = ssh_get_component_data_from_string(init_str, "async_time_ms", 0))
      != NULL)
    {
      soft->async_time_ms = atoi(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("Async timeout %dms.", soft->async_time_ms));
      ssh_free(s);
    }

  /* random completion can be used only with a timeout */
  if ((s = ssh_get_component_data_from_string(init_str,
                                              "random_async_completion", 0))
      != NULL)
    {
      if (soft->async_time_ms > 0)
        {
          soft->random_completion = TRUE;
          SSH_DEBUG(SSH_D_HIGHOK, ("Complete operations in random."));
        }
      ssh_free(s);
    }

  if ((s = ssh_get_component_data_from_string(init_str,
                                              "use_proxy", 0)) != NULL)
    {
      soft->use_proxy = TRUE;
      SSH_DEBUG(SSH_D_HIGHOK, ("Will convert private keys to proxy format."));
      ssh_free(s);
    }

  if ((s = ssh_get_component_data_from_string(init_str,
                                              "polling_interval_ms", 0))
      != NULL)
    {
      soft->polling_interval_ms = atoi(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("Pollint interval %dms.",
                               soft->polling_interval_ms));
      ssh_free(s);
    }
  else
    soft->polling_interval_ms = SSH_SOFT_PROV_DEFAULT_POLLING_INTERVAL_MS;

  return SSH_EK_OK;
}

void ssh_soft_prov_notify_keys(SshSoftProv soft)
{
  SshADTHandle handle;

  if (soft->keys_out == NULL)
    return;

  for (handle = ssh_adt_enumerate_start(soft->keys_out);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->keys_out, handle))
    {
      char *keypath;
      SshSoftKey key;

      keypath = ssh_adt_get(soft->keys_out, handle);
      key = ssh_adt_strmap_get(soft->keys_out, keypath);

      /* Notify the key if the state is other than notified */
      ssh_soft_prov_notify_key(soft, key, key->key_state);
    }
}


/* Get the base name of the file name. Scan backwords the string,
   until the first "." is found and return the first part. The calller
   must free the returned string */
static char *ssh_soft_base_name(const char *file_name)
{
  char *d;

  d = strrchr(file_name, '.');
  if (d == NULL)
    {
      /* No dot, the file IS a base name */
      return ssh_strdup(file_name);
    }
  else
    {
      char *base_name;

      if ((base_name = ssh_calloc(1, d - file_name + 1)) == NULL)
        return NULL;

      memcpy(base_name, file_name, d - file_name);
      return base_name;
    }
}

/* Try to determine if the source buffer is base64-encoded. If not,
   copy the source pointer and length into the destination pointer and
   length. If the source buffer is base64-encoded, decode it into a
   new buffer, free the source buffer and return the new buffer in the
   destination pointer and length. If succesful, return TRUE. If not
   succesful (e.g. out of memory) free the source buffer and return
   FALSE. */

static Boolean
ssh_soft_decode_if_base64(unsigned char *src, size_t src_len,
                          unsigned char **dst, size_t *dst_len)
{
  size_t pos, b64_start, b64_end, clean_len, bin_len;
  unsigned char c, *clean, *bin;

  /* A very heuristic test to determine if the input is base 64: check
     if it contains only printable characters, CR, NL or TAB. */
  for (pos = 0; pos < src_len; pos++)
    {
      c = src[pos];

      if ((c < 0x20 && c != '\r' && c != '\n' && c != '\t') || c >= 0x7f)
        {
          *dst = src;
          *dst_len = src_len;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Buffer is not base64-encoded, found char: %c "
                     "from position %u",
                     c, (unsigned int) pos));
          return TRUE;
        }
    }

  if (!ssh_base64_remove_headers(src, src_len, &b64_start, &b64_end))
    {
      *dst = src;
      *dst_len = src_len;
      SSH_DEBUG(SSH_D_LOWOK,
                ("Buffer is not base64-encoded"));
      return TRUE;
    }

  clean = ssh_base64_remove_whitespace(src + b64_start, b64_end - b64_start);
  if (clean == NULL)
    {
      ssh_free(src);
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to remove base64 whitespaces"));
      return FALSE;
    }

  clean_len = ssh_ustrlen(clean);
  if (ssh_is_base64_buf(clean, clean_len) != clean_len)
    {
      ssh_free(clean);
      *dst = src;
      *dst_len = src_len;
      SSH_DEBUG(SSH_D_LOWOK,
                ("Buffer is not base64-encoded"));
      return TRUE;
    }

  ssh_free(src);

  bin = ssh_base64_to_buf(clean, &bin_len);
  ssh_free(clean);

  if (bin == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to decode base64-encoding"));
      return FALSE;
    }

  *dst = bin;
  *dst_len = bin_len;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Buffer is base64-encoded"));
  return TRUE;
}

/* Tries to deduce the file type first by checking the cache, and then
   by reading the file and trying to decode */
SshSoftFileType ssh_soft_file_type(SshSoftProv soft,
                                   const char *full_file_name)
{
  SshSKBType prv_type;
  SshPKBType pub_type;
  unsigned char *buf = NULL;
  size_t buf_len;
  SshSoftFileInfo info;
  char *cipher, *hash;

  /* First check cache */
  info = ssh_soft_get_file_info(soft, full_file_name);
  if (info && info->file_type != SSH_SOFT_FT_INVALIDATED)
    {
      /* Found in cache */
      return info->file_type;
    }

  /* Read file */
  if (ssh_read_file_with_limit(full_file_name,
                               SSH_READ_FILE_LIMIT_CRYPTO_OBJ,
                               &buf, &buf_len) == FALSE)
    return SSH_SOFT_FT_UNKNOWN_FILE;

  if (buf == NULL || buf_len == 0)
    {
      if (buf != NULL)
        ssh_free(buf);

      return SSH_SOFT_FT_UNKNOWN_FILE;
    }

  /* Remove possible PEM-encoding */
  if (ssh_soft_decode_if_base64(buf, buf_len, &buf, &buf_len) == FALSE)
    return SSH_SOFT_FT_UNKNOWN_FILE;

  /* test if private key */
  if (ssh_skb_get_info(buf, buf_len,
                       &cipher, &hash,
                       NULL, NULL, &prv_type, NULL)
      == SSH_CRYPTO_OK)
    {
      ssh_free(cipher);
      ssh_free(hash);

      ssh_free(buf);
      if (prv_type == SSH_SKB_PKCS12_BROWSER_KEY)
        return SSH_SOFT_FT_PKCS12;
      else
        return SSH_SOFT_FT_PRV_KEY;
    }

  /* test if public key or certificate */
  if (ssh_pkb_get_info(buf, buf_len, NULL, NULL, &pub_type, NULL, NULL) ==
      SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      if (pub_type == SSH_PKB_FROM_X509)
        return (SSH_SOFT_FT_CRT_FILE | SSH_SOFT_FT_PUB_KEY);
      else
        return SSH_SOFT_FT_PUB_KEY;
    }

  ssh_free(buf);
  return SSH_SOFT_FT_UNKNOWN_FILE;
}

/* returns the 'n':th occurance of a file that matches the type */
char *ssh_soft_find_file_of_type(SshSoftProv soft,
                                 const char *directory,
                                 SshADTContainer key_files,
                                 SshSoftFileType file_types,
                                 SshUInt32 n)
{
  SshUInt32 occurance = 0;
  SshADTHandle handle;

  if (key_files == NULL)
    return NULL;

  /*Iterate the adt container */
  for (handle = ssh_adt_enumerate_start(key_files);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(key_files, handle))
    {
      char *file_name, *f;
      SshSoftFileType type;

      file_name =  ssh_adt_get(key_files, handle);
      f = ssh_soft_make_full_file_name(directory, file_name);

      type = ssh_soft_file_type(soft, f);

      if (type & file_types)
        {
          if (occurance == n)
            {
              return f;
            }
          occurance++;
        }
      ssh_free(f);
    }
  return NULL;
}


Boolean ssh_soft_get_data_for_type(SshSoftProv soft,
                                   SshSoftKey key_ctx,
                                   SshSoftFileType file_type,
                                   SshUInt32 occurance,
                                   unsigned char **data_ret,
                                   size_t *data_len_ret)
{
  char *file_name;
  file_name = ssh_soft_find_file_of_type(soft,
                                         key_ctx->directory,
                                         key_ctx->key_files,
                                         file_type,
                                         occurance);
  if (key_ctx->key_files == NULL)
    return FALSE;

  if (file_name != NULL)
    {
      /* Find the file. Now just read the data */
      if (ssh_read_file_with_limit(file_name,
                                   SSH_READ_FILE_LIMIT_CRYPTO_OBJ,
                                   data_ret, data_len_ret))
        {
          /* Read the file.  */
          ssh_free(file_name);
          return TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not read file %s", file_name));
          ssh_free(file_name);
          return FALSE;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not find the right type of data"));
      return FALSE;
    }
}


/* macro for creating sortable adt lists for C strings */
#define CREATE_KEY_FILES                                \
  ssh_adt_create_generic(SSH_ADT_LIST,                  \
                         SSH_ADT_COMPARE,               \
                         ssh_adt_callback_compare_str,  \
                         SSH_ADT_DESTROY,               \
                         ssh_adt_callback_destroy_free, \
                         SSH_ADT_ARGS_END)

/* Checks all files, and throws away unknown files. Returns the list
   of known files and a possible label for the key in *comment_return. */
SshADTContainer ssh_soft_check_known_files(SshSoftProv soft,
                                           const char *directory,
                                           SshADTContainer key_files,
                                           char **label_return)
{
  SshADTContainer checked_files;
  SshADTHandle handle;
  Boolean prv_found = FALSE;
  char *key_label = NULL;

  checked_files = CREATE_KEY_FILES;
  if (checked_files == NULL)
    return NULL;

  for (handle = ssh_adt_enumerate_start(key_files);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(key_files, handle))
    {
      char *full_file_name;
      char *file_name;
      SshSoftFileType type;

      file_name = ssh_adt_get(key_files, handle);

      full_file_name = ssh_soft_make_full_file_name(directory, file_name);
      if (full_file_name == NULL)
        break;

      type = ssh_soft_file_type(soft, full_file_name);

      if (type & SSH_SOFT_FT_PRV_KEY)
        {
          prv_found = TRUE;
          ssh_free(key_label);
          key_label = ssh_soft_find_key_label(soft, full_file_name);

          /* If the key label suggested the same as file name  then
              ignore the directory */
          if (key_label && strcmp(full_file_name, key_label) == 0)
            {
               ssh_free(key_label);
               key_label = ssh_strdup(file_name);
            }
        }

      /* Cache this information */
      ssh_soft_cache_known_file(soft, full_file_name, type, key_label);

      ssh_free(full_file_name);
      if (type != SSH_SOFT_FT_UNKNOWN_FILE)
        {
          file_name = ssh_strdup(file_name);
          if (file_name)
            ssh_adt_insert(checked_files, file_name);
        }
    }
  if (ssh_adt_num_objects(checked_files) == 0 || prv_found == FALSE)
    {
      ssh_adt_destroy(checked_files);
      checked_files = NULL;
    }

  if (label_return)
    *label_return = key_label;
  else
    ssh_free(key_label);

  return checked_files;
}


/* Gets the list of files, with the same base name. Make a keypath out
   of those */
static void
ssh_soft_make_file_key(SshSoftProv soft,
                       const char *directory,
                       SshADTContainer key_files,
                       const char *basename)
{
  SshADTContainer known_files;
  char *key_label = NULL;

  /* Check which of the files are of known types */
  known_files = ssh_soft_check_known_files(soft, directory, key_files,
                                           &key_label);
  ssh_adt_destroy(key_files);

  if (known_files)
    {
      SshSoftKey key = NULL, old_key = NULL;
      unsigned char *keypath = NULL;
      char *file_name = NULL;
      char *dir = NULL;

      file_name = ssh_soft_make_full_file_name(directory, basename);

      if (file_name == NULL)
          goto failed;

      dir = ssh_strdup(directory);
      if (dir == NULL)
        goto failed;

      ssh_dsprintf(&keypath, "directory_key(%s)", file_name);
      if (keypath == NULL)
        goto failed;

      ssh_free(file_name);
      file_name = NULL;

      key = ssh_calloc(1, sizeof(*key));
      if (key == NULL)
        goto failed;

      key->keypath = ssh_sstr(keypath);
      key->directory = dir;
      key->key_files = known_files;
      key->key_state = SSH_EK_EVENT_KEY_AVAILABLE;
      key->notify_state = SSH_EK_EVENT_KEY_UNAVAILABLE;
      key->soft = soft;
      key->label = key_label;

      old_key = ssh_adt_strmap_get(soft->keys_out, keypath);

      if (old_key != NULL)
        {
          /* We just do not want to delete the old key. It might have
             a lot of usefull information inside (e.g. the cached
             password) */

          /* Mark the old key as available, whatever the state was before */
          old_key->key_state = SSH_EK_EVENT_KEY_AVAILABLE;

          /* Replace the file referencies from the old key,
             the new list is more accurant */
          ssh_adt_destroy(old_key->key_files);
          old_key->key_files = key->key_files;
          key->key_files = NULL;

          /* Delete the new key context */
          ssh_soft_clear_key(key, NULL);
        }
      else
        {
          ssh_adt_strmap_add(soft->keys_out, keypath, key);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Added key with keypath '%s'",
                                       basename));
        }
      return;

    failed:
      ssh_adt_destroy(known_files);
      ssh_free(keypath);
      ssh_free(file_name);
      ssh_free(dir);
      ssh_free(key);
      ssh_free(key_label);

      return;
    }

  if (key_label)
    {
      ssh_free(key_label);
    }
}

/* Iterates through the sorted list of directory files, and finds out
   the group of files, which has the same base name */
static void
ssh_soft_find_key_files(SshSoftProv soft,
                        const char *directory,
                        SshADTContainer sorted_file_list)
{
  char *basename, *t = NULL;
  SshADTContainer key_files;
  SshADTHandle handle;
  void *object;

  /* Initialize the basename to a dummy, so that it is different from the
     first */
  if ((basename = ssh_strdup("")) == NULL)
    return;

  /* In key_files we only have the file names which have the same base
     name. They supposingly belong to the same key */
  if ((key_files = CREATE_KEY_FILES) == NULL)
    {
      ssh_free(basename);
      return;
    }
  /* iterate all the files in the directory, and find, which of them
     have the same base name */
  for (handle = ssh_adt_enumerate_start(sorted_file_list);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(sorted_file_list, handle))
    {
      char *file_name;
      file_name = ssh_adt_get(sorted_file_list, handle);

      t = ssh_soft_base_name(file_name);
      if (t == NULL)
        continue;

      if (strlen(t) == 0)
        {
          ssh_free(t);
          t = NULL;
          continue;
        }

      if (strcmp(t, basename) != 0)
        {
          /* A new group of files started. Check the old names, and
             start a new group */
          ssh_soft_make_file_key(soft, directory, key_files, basename);

          /* Key files got stolen by check files */
          if ((key_files = CREATE_KEY_FILES) == NULL)
            break;

          ssh_free(basename);

          if ((basename = ssh_strdup(t)) == NULL)
            break;
        }

      /* The file belongs to the same group. Add it to our list */
      if ((object = ssh_strdup(file_name)) != NULL)
        ssh_adt_insert(key_files, object);

      ssh_free(t);
      t = NULL;
    }

  /* The group of files ended. Check the names.  */
  if (key_files != NULL)
    ssh_soft_make_file_key(soft, directory, key_files, basename);

  ssh_free(basename);
  ssh_free(t);
}


static Boolean
ssh_soft_is_dir(const char *dir, const char *file_name)
{
  char *tmp_file_name;
  SshDirectoryHandle dh;

  tmp_file_name = ssh_soft_make_full_file_name(dir, file_name);

  if (tmp_file_name == NULL)
    return FALSE;

  dh = ssh_directory_open(tmp_file_name);
  ssh_free(tmp_file_name);

  if (dh != NULL)
    {
      ssh_directory_close(dh);
      return TRUE;
    }
  return FALSE;
}

static void
ssh_soft_poll_dir(SshSoftProv soft,
                  const char *dir)
{
  SshDirectoryHandle dh;
  SshADTContainer dir_files;

  dh = ssh_directory_open(dir);
  if (dh == NULL)
    {
      /* Could not open dir. All keys missing from here will be
         notified missing. */
      return;
    }

  /* Create a container for file names in the dir */
  if ((dir_files =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_COMPARE,
                              ssh_adt_callback_compare_str,
                              SSH_ADT_DESTROY,
                              ssh_adt_callback_destroy_free,
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_directory_close(dh);
      return;
    }

  /* Iterate all files in dir.  */
  while (ssh_directory_read(dh))
    {
      char *file_name;

      if ((file_name = ssh_strdup(ssh_directory_file_name(dh))) == NULL)
        continue;

      if (strcmp(file_name, ".") == 0 ||
          strcmp(file_name, "..") == 0)
        {
          /* Do not mess with "." or "..". */
          ssh_free(file_name);
        }
      else
        {
          /* Insert the file name into the list, if not a directory. */
          if (ssh_soft_is_dir(dir, file_name) == FALSE)
            ssh_adt_insert(dir_files, file_name);
          else
            ssh_free(file_name);
        }
    }

  /* Close the dir */
  ssh_directory_close(dh);

  /* Sort the list to help finding similar files */
  ssh_adt_list_sort(dir_files);

  /* Find and add the files */
  ssh_soft_find_key_files(soft, dir, dir_files);

  /* Destroy the list of files, since it not used anymore */
  ssh_adt_destroy(dir_files);
}

static SshSoftKey
ssh_soft_find_key_ctx(SshSoftProv soft,
                      const char *file_name)
{
  unsigned char *keypath;
  char *base_name;
  SshSoftKey key;

  base_name = ssh_soft_base_name(file_name);
  if (base_name == NULL)
    return NULL;

  ssh_dsprintf(&keypath, "directory_key(%s)", base_name);
  ssh_free(base_name);
  if (keypath == NULL)
    return NULL;

  key = ssh_adt_strmap_get(soft->keys_out,
                           keypath);
  ssh_free(keypath);
  return key;
}

static void
ssh_soft_check_if_key_missing(SshSoftProv soft,
                              const char *file_name)
{
  SshSoftFileType type;

  /* Check the file type */
  type = ssh_soft_file_type(soft, file_name);

  if (type & SSH_SOFT_FT_PRV_KEY)
    {
      SshSoftKey key_ctx;

      key_ctx = ssh_soft_find_key_ctx(soft, file_name);
      if (key_ctx)
        {
          key_ctx->key_state = SSH_EK_EVENT_KEY_UNAVAILABLE;
        }
    }
}

static void
ssh_soft_check_missing_files(SshSoftProv soft)
{
  SshADTHandle handle;

  for (handle = ssh_adt_enumerate_start(soft->all_dir_files);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->all_dir_files, handle))
    {
      char *file_name;
      SshSoftFileInfo info;

      /* Find the file name */
      file_name = ssh_adt_get(soft->all_dir_files, handle);

      /* get the file info */
      info = ssh_adt_strmap_get(soft->all_dir_files, file_name);

      /* did we touch the file in this poll */
      if (info->generation != soft->polling_generation)
        {
          /* We did not find this file at this poll time. Check
             if we need to report the key missisng */
          ssh_soft_check_if_key_missing(soft, file_name);
          ssh_soft_cache_known_file(soft, file_name,
                                    SSH_SOFT_FT_INVALIDATED, NULL);
        }
    }
}

static void
ssh_soft_poll_dirs(SshSoftProv soft)
{
  SshADTHandle handle;


  /* Increment our poll generation and check below if we
     found all our known files */
  soft->polling_generation++;

  /* Iterates through all dirs added in init */
  for (handle = ssh_adt_enumerate_start(soft->poll_directories);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->poll_directories, handle))
    {
      char *dir = ssh_adt_get(soft->poll_directories, handle);

      ssh_soft_poll_dir(soft, dir);
    }

  ssh_soft_check_missing_files(soft);
}

/* Polls the software keys */
void ssh_soft_prov_poll(void *context)
{
  SshSoftProv soft = context;

  if (soft->enabled)
    {
      ssh_soft_poll_dirs(soft);

      /* Notify changes */
      ssh_soft_prov_notify_keys(soft);
      if (soft->notify_cb && soft->enable_tracing && soft->enabled)
        (*soft->notify_cb)(SSH_EK_EVENT_TOKEN_SCANNED,
                           NULL, NULL, 0, soft->notify_context);
    }

  /* Reschedule */
  ssh_register_timeout(NULL, 0, soft->polling_interval_ms * 1000,
                       ssh_soft_prov_poll, context);
}


static void
soft_prov_invalidate_keys(SshSoftProv soft);

static void
soft_prov_abort_key_op(SshSoftProv soft,
                       SshOperationHandle handle);

static void
soft_prov_uninit_internal(void *provider)
{
  SshSoftProv soft = provider;

  if (soft)
    {
      soft->destroyed = TRUE;

      if (soft->num_keys > 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Provider still has %d keys out, delaying destroy",
                     (int) soft->num_keys));
          return;
        }

      if (soft->key_operation)
        {
          soft_prov_abort_key_op(soft,
                                 soft->key_operation);
        }

      soft_prov_invalidate_keys(soft);
      ssh_soft_prov_notify_keys(soft);
      soft->enabled = FALSE;

      if (soft->notify_cb)
        (*soft->notify_cb)(SSH_EK_EVENT_PROVIDER_DISABLED, NULL,
                           "Softprovider disabled",
                           0, soft->notify_context);

      if (soft->poll_directories)
        ssh_adt_destroy(soft->poll_directories);
      if (soft->keys_out)
        ssh_adt_destroy(soft->keys_out);
      if (soft->all_dir_files)
        ssh_adt_destroy(soft->all_dir_files);
      if (soft->proxy_keys)
        ssh_adt_destroy(soft->proxy_keys);
      ssh_free(soft);
    }
}


/* Uninitializes the provider. */
static void
soft_prov_uninit(void *provider)
{
  /* Do the actual uninitialization in timeout, because we might
     have been called from a callback of our own.*/
  ssh_cancel_timeouts(ssh_soft_prov_poll, provider);
  ssh_register_timeout(NULL, 0, 0, soft_prov_uninit_internal, provider);
}




/* Initializes software provider.  All providers init routines must
   return an context which is passed to other provider functions.
   See softprovider.h for the initialization info format. */
static SshEkStatus
soft_prov_init(const char *init_info,
               void *init_ptr,
               SshEkNotifyCB notify_cb,
               SshEkAuthenticationCB authentication_cb,
               void *context,
               void **provider_return)
{
  SshSoftProv soft;

  /* Build the context. */
  soft = ssh_calloc(1, sizeof(*soft));
  if (soft == NULL)
    return SSH_EK_NO_MEMORY;

  soft->poll_directories =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_DESTROY,
                           ssh_adt_callback_destroy_free,
                           SSH_ADT_ARGS_END);

  soft->proxy_keys = ssh_adt_create_generic(SSH_ADT_LIST,
                                            SSH_ADT_ARGS_END);

  soft->all_dir_files = ssh_adt_xcreate_strmap(NULL_FNPTR,
                                               ssh_soft_file_info_clear_cb);


  soft->keys_out = ssh_adt_xcreate_strmap(NULL_FNPTR, ssh_soft_clear_key);


  /* Check for memory errors */
  if (soft->poll_directories == NULL ||
      soft->all_dir_files == NULL    ||
      soft->keys_out == NULL         ||
      soft->proxy_keys == NULL)
    {
      soft_prov_uninit_internal(soft);
      return SSH_EK_NO_MEMORY;
    }

  if (init_info)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("softkey; init-string %s", init_info));
      if (soft_prov_parse_init_string(soft, init_info) != SSH_EK_OK)
        {
          soft_prov_uninit_internal(soft);
          return SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID;
        }
    }

  *provider_return = soft;

  /* Register our public key type */
  soft->enabled = TRUE;
  soft->enable_tracing = TRUE;

  soft->notify_cb = notify_cb;
  soft->authentication_cb = authentication_cb;
  soft->notify_context = context;

  /* Should we wait a bit before telling the caller we're enabled? */
  if (notify_cb)
    (*notify_cb)(SSH_EK_EVENT_PROVIDER_ENABLED, NULL, "Softprovider enabled",
                 0, context);

  /* Poll the directories now, polling function always sets a timeout to
     call itself after softprovider's polling interval.
  */
  ssh_soft_prov_poll(soft);

  SSH_DEBUG(SSH_D_HIGHOK, ("softkey; init OK"));

  return SSH_EK_OK;
}

/* Forward declaration */
static SshOperationHandle
soft_prov_get_private_key_internal(void *provider,
                                   Boolean dont_proxy,
                                   const char *keypath,
                                   SshEkGetPrivateKeyCB key_cb, void *context);

typedef struct SshSoftCertPKCS12Rec
{
  SshSoftProv soft;
  SshUInt32 cert_index;
  SshEkGetCertificateCB certificate_cb;
  void *context;
} *SshSoftCertPKCS12;

static void ssh_soft_ask_pass_in_get_cert_free(Boolean aborted, void *context)
{
  SshSoftCertPKCS12 ctx = context;
  ssh_free(ctx);
}

/* Called when passphrase query for PKCS#12 is done */
static void
ssh_soft_ask_pass_in_getcert_done(SshEkStatus status,
                                  SshPrivateKey key,
                                  unsigned char *cert,
                                  size_t cert_len,
                                  void *context)
{
   SshSoftCertPKCS12 ctx = context;

   if (cert && status == SSH_EK_OK)
     {
       (*ctx->certificate_cb)(status, cert, cert_len, ctx->context);
       ssh_free(cert);
     }
   else
     (*ctx->certificate_cb)(SSH_EK_NO_MORE_CERTIFICATES, NULL,
                            0, ctx->context);
}


/* Retrieves a certificate based on the keypath.  */
static SshOperationHandle
soft_prov_get_certificate(void *provider,
                          const char *keypath, SshUInt32 cert_index,
                          SshEkGetCertificateCB certificate_cb, void *context)
{
  unsigned char *path = NULL;
  unsigned char *buf = NULL;
  size_t path_len, buf_len = 0;
  SshEkStatus status = SSH_EK_NO_MORE_CERTIFICATES;
  SshOperationHandle op_handle;
  char *keypath_copy = NULL;
  int i = 0;
  SshSoftKey key_ctx;
  SshSoftProv soft = provider;

  /* Test if we can find the key from the keys_out */
  if ((key_ctx = ssh_adt_strmap_get(soft->keys_out, keypath)))
    {
      /* Try getting the data for the cert */
      if (ssh_soft_get_data_for_type(soft, key_ctx,
                                     SSH_SOFT_FT_CRT_FILE,
                                     cert_index, &buf, &buf_len))
        {
          SshSoftFileType type;
          char *file_name;

          /* Check if we are in PKSC#12, we might need to ask for
             password */
          file_name = ssh_soft_find_file_of_type(soft,
                                                 key_ctx->directory,
                                                 key_ctx->key_files,
                                                 SSH_SOFT_FT_CRT_FILE,
                                                 cert_index);

          type = ssh_soft_file_type(soft, file_name);
          ssh_free(file_name);
          if (type == SSH_SOFT_FT_PKCS12)
            {
              /* The type is PKCS#12. We must ask for the password
                 now. */
              SshSoftCertPKCS12 ctx;
              SshOperationHandle handle;

              ctx = ssh_calloc(1, sizeof(*ctx));
              if (ctx == NULL)
                {
                  status = SSH_EK_NO_MEMORY;
                  ssh_free(buf);
                  buf = NULL;
                  goto done;
                }
              ctx->soft = soft;
              ctx->cert_index = cert_index;
              ctx->certificate_cb = certificate_cb;
              ctx->context = context;
              handle = ssh_soft_ask_password(soft, buf, buf_len, keypath,
                                             cert_index,
                                             ssh_soft_ask_pass_in_getcert_done,
                                             ctx);
              ssh_operation_attach_destructor
                (handle, ssh_soft_ask_pass_in_get_cert_free, ctx);
              return handle;
            }
          else
            {
              /* We are done, we have the certificate */
              status = SSH_EK_OK;
              goto done;
            }
        }
    }

  /* To be able to iterate to the "cert_index" cert,
     we take a copy of the keypath, and obfuscate the indexes
     that we found before the right cert */
  if ((keypath_copy = ssh_strdup(keypath)) == NULL)
    {
      status = SSH_EK_NO_MEMORY;
      goto done;
    }

  while (i < cert_index)
    {
      char *comp;

      if ((comp = (char *)(strstr(keypath_copy, "certdata"))))
        {
          *comp = '*';
          i++;
          continue;
        }
      if ((comp = (char *)(strstr(keypath_copy, "certfile"))))
        {
          *comp = '*';
          i++;
          continue;
        }
      break;
    }

#define READING_CERT_DATA 1
  while (READING_CERT_DATA)
    {
      if (soft_get_path_component_base64(keypath_copy, "certdata",
                                         &buf, &buf_len))
        {
          status = SSH_EK_OK;
          /* The data is in URL. */
          break;
        }
      if (soft_get_path_component(keypath_copy, "certfile", &path, &path_len))
        {
          /* The key data is read from a file. */
          if (ssh_read_gen_file((char *)path, &buf, &buf_len) == FALSE)
            {
              status = SSH_EK_KEY_FILE_NOT_FOUND;
              SSH_DEBUG(SSH_D_FAIL, ("Could not read the cert from %s",
                                      (char *)path));
              ssh_free(path);
              break;
            }
          ssh_free(path);
          status = SSH_EK_OK;
        }
      else
        {
          SSH_ASSERT(path == NULL);
          status = SSH_EK_NO_MORE_CERTIFICATES;
        }
      break;
    }
 done:
  ssh_free(keypath_copy);
  op_handle = soft_prov_async_cert_cb(provider,
                                      status, buf, buf_len, certificate_cb,
                                      context);
  return op_handle;
}

/* Context used during the get_public key operation. If we
   are unable to get the key from a file, we will first try
   to get it from a certificate and then derive the public key from
   a private key */
typedef struct SshSoftGetPubKeyRec
{
  SshOperationHandle op;
  SshOperationHandle sub_op;
  SshSoftProv soft;
  Boolean allow_derive;
  SshEkGetPublicKeyCB callback;
  void *context;
  char *keypath;
} *SshSoftGetPubKey;

static void ssh_soft_get_pub_free(SshSoftGetPubKey ctx)
{
  ssh_free(ctx->keypath);
  ssh_free(ctx);
}

static void
soft_prov_pub_derive(SshEkStatus status, SshPrivateKey priv, void *context)
{
  SshSoftGetPubKey ctx = context;
  SshPublicKey pub = NULL;

  ctx->sub_op = NULL;
  if (status == SSH_EK_OK)
    {
      if (ssh_private_key_derive_public_key(priv, &pub) != SSH_CRYPTO_OK)
        {
          status = SSH_EK_FAILED;
        }
      ssh_private_key_free(priv);
    }
  (*ctx->callback)(status, pub, ctx->context);
  ssh_operation_unregister(ctx->op);
  ssh_soft_get_pub_free(ctx);
}

void ssh_soft_get_pub_from_cert_cb(SshEkStatus status,
                                   const unsigned char *cert,
                                   size_t cert_len,
                                   void *context)
{
  SshSoftGetPubKey ctx = context;
  SshOperationHandle handle;
  ctx->sub_op = NULL;

  if (status == SSH_EK_OK)
    {
      /* Got the certificate. Now extract the public key and be happy */
      SshPublicKey key;

      key = ssh_ek_extract_public_key_from_certificate(cert, cert_len);
      if (key != NULL)
        {
          (*ctx->callback)(SSH_EK_OK, key, ctx->context);
          ssh_operation_unregister(ctx->op);
          ctx->op = NULL;
          ssh_soft_get_pub_free(ctx);
          return;
        }
    }

  /* Check if we are allowed try deriving the publickey from the
     private key. If allow derive is FALSE, it means that we are
     already being called from the get private key, where we tried to
     get the public key (because we wanted to make a raw key ) and if
     we tried to derive again here, it would lead to infinite
     recursion. */
  if (ctx->allow_derive == FALSE)
    {
      /* We are not allowed to derive, just fail */
      (*ctx->callback)(SSH_EK_FAILED, NULL, ctx->context);
      ssh_operation_unregister(ctx->op);
      ssh_soft_get_pub_free(ctx);
      return;
    }

  /* Try deriving the pubkey from the private key. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Trying to derive the public key"));
  handle =  soft_prov_get_private_key_internal(ctx->soft,
                                               TRUE, ctx->keypath,
                                               soft_prov_pub_derive, ctx);
  if (handle)
    ctx->sub_op = handle;
}

/* This starts the actual getting of the certificate for public key
   extraction purpose. Because we returned handle, we had to start this
   operation asynchronously, so we use callbacks. */
void ssh_soft_get_pub_from_cert_int(void *context)
{
  SshSoftGetPubKey ctx = context;
  SshOperationHandle handle;
  /* Now query the certificate using the normal method. We just want
     to get some certificate, so the cert with index 0 does us very
     well.  */
  handle = soft_prov_get_certificate(ctx->soft, ctx->keypath, 0,
                                     ssh_soft_get_pub_from_cert_cb,
                                     ctx);
  if (handle)
    ctx->sub_op = handle;
}

/* Abort callback for the get public key operation that is trying to
   first get the certificate and if it fails, get the private key
   and derive the public key from there */
static void
ssh_soft_get_pub_abort(void *context)
{
  SshSoftGetPubKey ctx = context;

  ssh_cancel_timeouts(ssh_soft_get_pub_from_cert_int, ctx);
  ssh_operation_abort(ctx->sub_op);
  ssh_soft_get_pub_free(ctx);
}


/* These are used to increase the readibility of code. They are mainly
   used inside while, to make the dummy while look nicer. (avoid
   goto's by while). */
#define READING_KEY_DATA 1
#define MAKING_KEY 1

static SshOperationHandle
soft_prov_get_public_key_internal(void *provider,
                                  Boolean allow_derive,
                                  const char *keypath,
                                  SshEkGetPublicKeyCB key_cb, void *context)
{
  SshSoftGetPubKey ctx = NULL;
  unsigned char *buf = NULL;
  size_t buf_len;
  SshSoftProv soft = provider;
  SshSoftKey key_ctx;
  SshPublicKey key;
  SshOperationHandle handle;

  /* Test if we can find the key from the keys_out */
  if ((key_ctx = ssh_adt_strmap_get(soft->keys_out, keypath)))
    {
      /* Yes. Check if we have data in the key */
      if (key_ctx->public_key)
        {
          /* We already have the key. Just return a copy of the key */
          if (ssh_public_key_copy(key_ctx->public_key, &key) == SSH_CRYPTO_OK)
            goto had_key;
          else
            goto extract_from_cert;
        }
      /* Try gettimg the data for the key */
      if (ssh_soft_get_data_for_type(soft, key_ctx,
                                     SSH_SOFT_FT_PUB_KEY,
                                     0, &buf, &buf_len))
        {
          goto got_data;
        }

    }

  while (READING_KEY_DATA)
    {
      unsigned char *path;
      size_t path_len;
      /* First check if the keypath provided contains public key
         material. If not, then get the private key based on the keypath
         and derive software public key from that. */

      if (soft_get_path_component_base64(keypath, "pubkeydata",
                                         &buf, &buf_len))
        {
          /* pub key data was found */
          break;
        }

      if (soft_get_path_component(keypath, "pubkeyfile", &path, &path_len))
        {
          /* From file */
          if (ssh_read_gen_file((char *)path, &buf, &buf_len) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Can't read public key from %s",
                                     (char *)path));
              ssh_free(path);
              (*key_cb)(SSH_EK_KEY_FILE_NOT_FOUND, NULL, context);
              return NULL;
            }
          ssh_free(path);
        }
      else
        {
          SSH_ASSERT(path == NULL);
        }
      break;
    }
  while (MAKING_KEY)
    {
      SshPKBType kind;
      SshOperationHandle op_handle;

    got_data:
      if (buf == NULL)
        break;

      if (ssh_pkb_get_info(buf, buf_len, NULL, NULL, &kind, NULL, NULL) !=
          SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to find the public key data type"));
          goto failed;
        }

      if (ssh_pkb_decode(kind, buf, buf_len, NULL, 0,
                         &key) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to decode the public key data"));
          ssh_free(buf);
          goto extract_from_cert;
        }
    had_key:

      op_handle = soft_prov_async_public_cb(soft, SSH_EK_OK, key,
                                            key_cb, context);
      ssh_free(buf);
      return op_handle;
    }

 extract_from_cert:
  /* Unable to find public key, try getting it from the certificate */
  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto failed;

  handle = ssh_operation_register(ssh_soft_get_pub_abort, ctx);
  if (handle == NULL)
    goto failed;

  ctx->op = handle;
  ctx->callback = key_cb;
  ctx->context = context;
  ctx->soft = soft;
  ctx->allow_derive = allow_derive;

  /* Copy keypath */
  ctx->keypath = ssh_strdup(keypath);
  if (ctx->keypath == NULL)
    goto failed;

  /* Now regster the timeout. Because we return a handle
     we must really be asynchronous */
  ssh_register_timeout(NULL, 0, 0, ssh_soft_get_pub_from_cert_int, ctx);

  return handle;


 failed:
  if (ctx)
    {
      ssh_operation_unregister(ctx->op);
      ssh_soft_get_pub_free(ctx);
    }
  SSH_DEBUG(SSH_D_FAIL, ("Failed getting the public key"));
  return soft_prov_async_public_cb(soft, SSH_EK_FAILED, NULL,
                                   key_cb, context);
}


/* Retrieves a public key based on the keypath. */
static SshOperationHandle
soft_prov_get_public_key(void *provider,
                        const char *keypath,
                        SshEkGetPublicKeyCB key_cb, void *context)
{
  return soft_prov_get_public_key_internal(provider, TRUE, keypath,
                                           key_cb, context);
}


typedef struct SshSoftMakingPrvKeyRec
{
  SshOperationHandle op;
  SshOperationHandle sub_op;
  SshSoftProv soft;
  char *keypath;
  unsigned char *buf;
  size_t buf_len;
  SshEkGetPrivateKeyCB key_cb;
  void *context;
} *SshSoftMakingPrvKey;


static void
ssh_soft_get_prv_key_free(void *context)
{
  SshSoftMakingPrvKey ctx = context;
  ssh_free(ctx->keypath);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}

/* Called when the password query using the authentication callback is
   done.  We come here only if there were no public key or certificate
   available and the key required a password. */
void ssh_soft_prv_key_get_cb(SshEkStatus status,
                             SshPrivateKey key,
                             unsigned char *cert,
                             size_t cert_len,
                             void *context)
{
  SshSoftMakingPrvKey ctx = context;

  ctx->sub_op = NULL;

  ssh_free(cert);
  if (status == SSH_EK_OK && key)
    {
        /* Successfully done */
      (*ctx->key_cb)(SSH_EK_OK, key, ctx->context);
      ssh_operation_abort(ctx->op);
      return;
    }

  (*ctx->key_cb)(status, NULL, ctx->context);
  ssh_operation_abort(ctx->op);
}

/* Called when we acquiring of the public key pair of the private key
   has been completed. We need to be able to get at least the public
   key to make a raw private key, which is decoded only when the
   public key is decoded */
void ssh_soft_get_pubkey_cb(SshEkStatus status,
                            SshPublicKey key,
                            void *context)
{
  SshSoftMakingPrvKey ctx = context;
  SshPrivateKey prv_key;

  ctx->sub_op = NULL;

  if (status != SSH_EK_OK)
    {
      unsigned char *buf;

      /* Ask password eats the buffer. */
      buf = ssh_memdup(ctx->buf, ctx->buf_len);
      if (buf == NULL)
        goto failed;
      /* We were unable to get the public key. We must then ask the
         passphrase now. */
      ctx->sub_op = ssh_soft_ask_password(ctx->soft,
                                          buf, ctx->buf_len,
                                          ctx->keypath, 0,
                                          ssh_soft_prv_key_get_cb,
                                          ctx);

      return;
    }

  prv_key = soft_convert_raw_prv_key(ctx->soft, ctx->keypath, key,
                                     ctx->buf, ctx->buf_len);
  if (prv_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to convert raw private key"));
      goto failed;
    }

  /* Successfully done */
  (*ctx->key_cb)(SSH_EK_OK, prv_key, ctx->context);
  ssh_operation_abort(ctx->op);
  return;

 failed:
  (*ctx->key_cb)(SSH_EK_FAILED, NULL, ctx->context);
  ssh_operation_abort(ctx->op);
  return;
}

/* The type requires a password. Call the authentication
   callback, becore continuing. */
void ssh_soft_get_raw_key_int(void *context)
{
  SshSoftMakingPrvKey ctx = context;

  SshOperationHandle handle;
  /* First try getting the public key. */
  handle = soft_prov_get_public_key_internal(ctx->soft, FALSE, ctx->keypath,
                                             ssh_soft_get_pubkey_cb, ctx);
  if (handle)
    ctx->sub_op = handle;
}


void ssh_soft_get_raw_key_abort(void *context)
{
  SshSoftMakingPrvKey ctx = context;

  ssh_cancel_timeouts(ssh_soft_get_raw_key_int, context);
  ssh_operation_abort(ctx->sub_op);

  /* Operation is not valid after this */
  ctx->soft->key_operation = NULL;

  ssh_soft_get_prv_key_free(ctx);
}

static void
soft_prov_abort_key_op(SshSoftProv soft,
                       SshOperationHandle handle)
{
  SshSoftMakingPrvKey ctx = (SshSoftMakingPrvKey)
    ssh_operation_get_context(handle);

  (*ctx->key_cb)(SSH_EK_FAILED, NULL, ctx->context);
  ssh_operation_abort(handle);
}

static SshOperationHandle
soft_prov_get_private_key_internal(void *provider,
                                   Boolean dont_proxy,
                                   const char *keypath,
                                   SshEkGetPrivateKeyCB key_cb,
                                   void *context)
{
  unsigned char *path = NULL;
  unsigned char *buf = NULL;
  size_t buf_len, path_len;
  SshEkStatus status = SSH_EK_FAILED;
  SshCryptoStatus crypto_status = SSH_CRYPTO_OK;
  SshPrivateKey key = NULL;
  SshSoftProv soft = provider;
  SshSoftKey key_ctx;
  SshOperationHandle op_handle = NULL;

  /* Test if we can find the key from the keys_out */
  if ((key_ctx = ssh_adt_strmap_get(soft->keys_out, keypath)))
    {
      /* Yes. Check if we have data in the key */
      if (key_ctx->private_key)
        {
          /* We already have the key. Just return a copy of the key */
          if (ssh_private_key_copy(key_ctx->private_key, &key)
              == SSH_CRYPTO_OK)
            goto had_key;
          else
            goto failed;
        }
      /* Try gettimg the data for the key */
      if (ssh_soft_get_data_for_type(soft, key_ctx,
                                     SSH_SOFT_FT_PRV_KEY,
                                     0, &buf, &buf_len))
        {
          goto got_data;
        }

    }


  /* Parse keypath. It may contain either a file, or the actual key as
     ascii armored string. Also certificates may be present at the
     keypath. Also the keypath may contain some constraints related to
     the key (or its passphrase/pin). */
  while (READING_KEY_DATA)
    {
      /* The private key data must be either in keypath or in a file
         indicated by keypath. */
      if (soft_get_path_component_base64(keypath, "prvkeydata",
                                         &buf, &buf_len))
        {
          /* Private key data is in the URL. */
          break;
        }

      if (soft_get_path_component(keypath, "prvkeyfile", &path, &path_len))
        {
          /* The key data is read from a file. */
          if (ssh_read_gen_file((char *)path, &buf, &buf_len) == FALSE)
            {
              status = SSH_EK_KEY_FILE_NOT_FOUND;
              SSH_DEBUG(SSH_D_FAIL, ("Could not read the key from %s",
                                      (char *)path));
              ssh_free(path);
              break;
            }
          ssh_free(path);
        }
      break;
    }

  while (MAKING_KEY)
    {
      SshSKBType kind;
      Boolean needs_passphrase;
      char *cipher, *hash;

    got_data:
      if (buf == NULL || buf_len == 0)
        break;

      /* Remove possible PEM-encoding */
      if (ssh_soft_decode_if_base64(buf, buf_len, &buf, &buf_len) == FALSE)
        {
          buf = NULL;
          buf_len = 0;
          goto failed;
        }

      crypto_status = ssh_skb_get_info(buf, buf_len,
                                       &cipher, &hash,
                                       NULL, NULL, &kind, NULL);

      if (crypto_status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Key type could not be deduced: %s",
                     ssh_crypto_status_message(crypto_status)));
          status = SSH_EK_KEY_BAD_FORMAT;
          break;
        }

      ssh_skb_get_type_info(kind, &needs_passphrase, NULL);

      SSH_DEBUG(SSH_D_LOWOK,
                ("Identified key type as '%s'%s",
                 ssh_skb_type_to_name(kind),
                 needs_passphrase ? ", needs passphrase." : "."));

      if (needs_passphrase || cipher != NULL)
        {
          SshSoftMakingPrvKey raw_key;
          /* If we can deduce the key type here, we can decode the key
             only when it is used, and ask the passphrase when the key
             is used to better simulate smart cards. */

          raw_key = ssh_calloc(1, sizeof(*raw_key));
          if (raw_key == NULL)
            {
              status = SSH_EK_NO_MEMORY;
              SSH_DEBUG(SSH_D_FAIL, ("Allocation error"));
              break;
            }
          raw_key->keypath = ssh_strdup(keypath);
          raw_key->soft = soft;
          raw_key->key_cb = key_cb;
          raw_key->context = context;
          raw_key->buf = buf;
          raw_key->buf_len = buf_len;

          raw_key->op = ssh_operation_register(ssh_soft_get_raw_key_abort,
                                               raw_key);
          if (raw_key->op == NULL || raw_key->keypath == NULL)
            {
              status = SSH_EK_NO_MEMORY;
              ssh_operation_unregister(raw_key->op);
              SSH_DEBUG(SSH_D_FAIL, ("Memory allocation error"));
              ssh_soft_get_prv_key_free(raw_key);
              break;
            }
          ssh_register_timeout(NULL, 0, 0, ssh_soft_get_raw_key_int, raw_key);

          soft->key_operation = raw_key->op;

          return raw_key->op;

        }

      if (ssh_skb_decode(kind,
                         buf, buf_len,
                         cipher, hash, NULL, 0, &key)
          != SSH_CRYPTO_OK)
        {
          ssh_free(cipher); ssh_free(hash);
          status = SSH_EK_KEY_BAD_FORMAT;
          SSH_DEBUG(SSH_D_FAIL, ("Failed to decode the key data"));
          break;
        }
      ssh_free(cipher); ssh_free(hash);

    had_key:
      status = SSH_EK_OK;
      if (dont_proxy == FALSE)
        {
          /* We have the key that does not need PIN. Convert it
             into a "proxy" */
          key = soft_convert_prv_key(provider, key);
        }
      break;
    }

 failed:
  op_handle = soft_prov_async_private_cb(soft, status, key,
                                         key_cb, context);
  ssh_free(buf);
  return op_handle;

}


/* Retrieves a private key based on the keypath. */
static SshOperationHandle
soft_prov_get_private_key(void *provider,
                         const char *keypath,
                         SshEkGetPrivateKeyCB key_cb, void *context)
{
  SshSoftProv soft = provider;
  Boolean dont_proxy;

  dont_proxy = !(soft->use_proxy);

  return soft_prov_get_private_key_internal(provider, dont_proxy,
                                            keypath, key_cb, context);
}


/* Returns the printable name of the ssh smart card library.
   Soft Cryptographic Accelerator Provider. */
static const char *soft_prov_get_printable_name(void *provider)
{
  return "Soft Cryptographic Accelerator Provider.";
}

/* Set all keys state to a specified "event".  */
static void
soft_prov_set_all_keys_state(SshSoftProv soft,
                             SshEkEvent event)
{
  SshADTHandle handle;

  if (soft->keys_out == NULL)
    return;

  /* Invalidate keys */
  for (handle = ssh_adt_enumerate_start(soft->keys_out);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->keys_out, handle))
    {
      char *keypath;
      SshSoftKey key;

      keypath = ssh_adt_get(soft->keys_out, handle);
      key = ssh_adt_strmap_get(soft->keys_out, keypath);
      if (key)
        key->key_state = event;
    }
}

/* Invalidates the key state of the keys in the soft provider, so that
   they will be re notified, when the provider is enabled again.  */
static void
soft_prov_invalidate_keys(SshSoftProv soft)
{
  soft_prov_set_all_keys_state(soft, SSH_EK_EVENT_KEY_UNAVAILABLE);
}




/* Converts the provider soft key into "soft accelerated key". This
   demonstrates how custom key types can be generated. */
static SshOperationHandle
soft_prov_gen_acc_prvkey(void *provider,
                         SshPrivateKey source,
                         SshEkGetPrivateKeyCB key_cb, void *context)
{
  SshPrivateKey key = NULL;
  SshPrivateKey kcopy;
  SshSoftProv soft;
  SshEkStatus status = SSH_EK_FAILED;
  SshOperationHandle op_handle;

  soft = provider;

  if (ssh_private_key_copy(source, &kcopy) != SSH_CRYPTO_OK)
    goto failed;

  key = soft_convert_prv_key(provider, kcopy);

  if (key)
    status = SSH_EK_OK;

failed:
  op_handle = soft_prov_async_private_cb(soft, status, key,
                                         key_cb, context);

  return op_handle;
}

static void
ssh_soft_reset_pins(SshSoftProv soft)
{
  SshADTHandle handle;
  SshSoftKey key;

  /* Enumerate all the proxy keys and delete the decrypted provate
     keys */
  for (handle = ssh_adt_enumerate_start(soft->proxy_keys);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->proxy_keys, handle))
    {
      key = ssh_adt_get(soft->proxy_keys, handle);
      if (key->private_key)
        {
          ssh_private_key_free(key->private_key);
          key->private_key = NULL;
        }
    }
  /* Delete all cached passphrases of directory keys */

  for (handle = ssh_adt_enumerate_start(soft->keys_out);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(soft->keys_out, handle))
    {
      char *keypath;
      keypath = ssh_adt_get(soft->keys_out, handle);

      key = ssh_adt_strmap_get(soft->keys_out, keypath);
      if (key && key->passphrase)
        {
          memset(key->passphrase, 0, key->passphrase_len);
          ssh_free(key->passphrase);
          key->passphrase = NULL;
        }

    }



}

/* Converts the key and the certificate into a keypath format used by
   the softprovider */
SshEkStatus ssh_soft_convert_cert_and_key_to_keypath(SshPrivateKey priv,
                                                     const unsigned char *cert,
                                                     size_t cert_len,
                                                     char **keypath_ret)
{
  unsigned char *key_buf = NULL;
  size_t key_buf_len;
  char *base64_key = NULL;
  char *base64_cert = NULL;
  unsigned char *cert_comp = NULL;
  unsigned char *keypath;
  SshEkStatus status = SSH_EK_FAILED;

  if (ssh_x509_encode_private_key(priv, &key_buf, &key_buf_len) != SSH_X509_OK)
    {
      /* Can not export the private key */
      SSH_DEBUG(SSH_D_FAIL, ("Can not export the private key"));
      return SSH_EK_FAILED;
    }

  base64_key = (char *)ssh_buf_to_base64(key_buf, key_buf_len);
  if (base64_key == NULL)
    goto failed;

  if (cert) {
    base64_cert = (char *)ssh_buf_to_base64(cert, cert_len);
    if (base64_cert == NULL)
      goto failed;
    ssh_dsprintf(&cert_comp, "certdata=%s",
                 base64_cert);
    if (cert_comp == NULL)
      goto failed;
  }
  else
    {
      cert_comp = ssh_strdup("");
      if (cert_comp == NULL)
        goto failed;
    }

  /* Now create the keypath */
  ssh_dsprintf(&keypath, "prvkeydata=%s?%s",
               base64_key, cert_comp);

  if (keypath == NULL)
    goto failed;

  *keypath_ret = ssh_sstr(keypath);
  status = SSH_EK_OK;

 failed:

  if (status != SSH_EK_OK)
    SSH_DEBUG(SSH_D_FAIL, ("Key and cert to keypath failed."));
  ssh_free(key_buf);
  ssh_free(base64_key);
  ssh_free(base64_cert);
  ssh_free(cert_comp);
  return status;;
}

void ssh_soft_add_key_and_cert(SshSoftProv soft,
                               SshSoftAddKeyCert ctx)
{
  char *keypath;

  /* Convert the key to a keypath */
  ctx->status = ssh_soft_convert_cert_and_key_to_keypath(ctx->priv,
                                                         ctx->cert,
                                                         ctx->cert_len,
                                                         &keypath);
  if (ctx->status == SSH_EK_OK)
    {
      /* Notify the key */
      (*soft->notify_cb)(SSH_EK_EVENT_KEY_AVAILABLE,
                         keypath, ctx->key_label,
                         SSH_EK_USAGE_AUTHENTICATE |
                         SSH_EK_USAGE_ENCRYPTION |
                         SSH_EK_USAGE_SIGNATURE,
                         soft->notify_context);
      ssh_free(keypath);
    }
}


static SshOperationHandle
ssh_soft_message_cb(void *provider_context,
                    const char *message,
                    void *message_arg, size_t message_arg_len,
                    SshEkSendMessageCB message_cb, void *context)
{
  SshEkStatus status = SSH_EK_UNKNOWN_MESSAGE;
  void *response = NULL;

  if (message == NULL)
      goto done;

  if (strcmp(message, "reset_pins") == 0)
    {
      ssh_soft_reset_pins(provider_context);
      status = SSH_EK_OK;
      goto done;
    }

  if (strcmp(message, SSH_SOFTPROVIDER_ADD_KEY_AND_CERT_MESSAGE) == 0)
    {
      SshSoftAddKeyCert ctx = message_arg;
      ssh_soft_add_key_and_cert(provider_context,
                                ctx);
      return NULL;
    }


 done:
  if (message_cb)
    (*message_cb)(status, response, 0, context);
  return NULL;
}

/*********************** Support for simulated async operations *********/

typedef struct SshSoftAsyncContextRec
{
  SshSoftAsyncType type;
  union
  {
    SshTimeoutCallback completion_cb;
    SshEkGetPrivateKeyCB private_cb;
    SshEkGetPublicKeyCB public_cb;
    SshEkGetCertificateCB cert_cb;
    SshProxyReplyCB keyop_cb;
    SshProxyReplyCB vrfy_cb;
    void *anycb;
  } u;
  /* Context for the above callback */
  void *context;

  /* Operation status (either Crypto or Ek) and result value. */
  int status;
  unsigned char *data;
  size_t len;

  /* Key for private/public key callbacks */
  union
  {
    SshPrivateKey private_key;
    SshPublicKey public_key;
  } key;

  /* Operation handle for aborting an asynchronous operation */
  SshOperationHandle op_handle;
} *SshSoftAsyncContext;

/* Execute the callback stored in the context */
static void soft_prov_async_execute(SshSoftAsyncContext ac)
{
  switch (ac->type)
    {
    case SOFT_PROV_KEYOP_RESULT:
      (*ac->u.keyop_cb)(ac->status, ac->data, ac->len, ac->context);
      if (ac->data) ssh_free(ac->data);
      break;
    case SOFT_PROV_VERFY_RESULT:
      (*ac->u.vrfy_cb)(ac->status, NULL, 0, ac->context);
      break;
    case SOFT_PROV_TIMEOUT:
      (*ac->u.completion_cb)(ac->context);
      break;
    case SOFT_PROV_ASYNC_PRIVATE:
      (*ac->u.private_cb)(ac->status, ac->key.private_key, ac->context);
      break;
    case SOFT_PROV_ASYNC_PUBLIC:
      (*ac->u.public_cb)(ac->status, ac->key.public_key, ac->context);
      break;
    case SOFT_PROV_ASYNC_CERT:
      (*ac->u.cert_cb)(ac->status, ac->data, ac->len, ac->context);
      ssh_free(ac->data);
      break;
    }
  if (ac->op_handle)
    ssh_operation_unregister(ac->op_handle);
}

/* This is called when an asynchronous operation completes */
static void soft_prov_async_callback(void *context)
{
  SshSoftAsyncContext ac = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Async timeout callback called."));

  /* Call the real completion routine */
  soft_prov_async_execute(ac);
  ssh_free(ac);
}

/* This is called when the user wants to abort an asynchronous operation */
static void soft_prov_async_abort(void *context)
{
  SshSoftAsyncContext ac = context;

  ssh_cancel_timeouts(soft_prov_async_callback, context);

  /* We need to clean up the context */
  switch (ac->type)
    {
    case SOFT_PROV_ASYNC_PRIVATE:
      if (ac->key.private_key)
        ssh_private_key_free(ac->key.private_key);
      break;
    case SOFT_PROV_ASYNC_PUBLIC:
      if (ac->key.public_key)
        ssh_public_key_free(ac->key.public_key);
      break;
    case SOFT_PROV_ASYNC_CERT:
      if (ac->data)
        ssh_free(ac->data);
      break;
    case SOFT_PROV_KEYOP_RESULT:
      if (ac->data) ssh_free(ac->data);
    default:
      break;
    }
  ssh_free(ac);
}

/* Schedule a callback function to be called after the designated
   timeout, to make it appear as if the software provider were
   asynchronous. AC points to a temporary callback context. */
static SshOperationHandle
soft_prov_async_schedule(SshSoftProv soft, SshSoftAsyncContext ac)
{
  unsigned int timeout = soft->async_time_ms;

  if (timeout > 0 && soft->random_completion)
    {
      /* Random timeout: 50% cases execute synchronously, 50%
         asynchronously, with varying timeouts. */
      unsigned int rnd_byte = ssh_random_get_byte();

      if (rnd_byte & 1)
        timeout = 0;
      else
        {
          rnd_byte /= 2;
          timeout = timeout * rnd_byte / 128;
        }
    }
  if (timeout == 0)
    {
      /* Synchronous execution -- just calls the callback function. */
      soft_prov_async_execute(ac);
      return NULL;
    }
  else
    {
      unsigned int seconds = timeout / 1000;
      unsigned int micros  = (timeout % 1000) * 1000;
      SshSoftAsyncContext acp;

      /* Allocate a "permanent" copy of the context on the heap. If
         this fails, act synchronously. */
      if ((acp = ssh_memdup(ac, sizeof(*acp))) == NULL ||
          (acp->op_handle =
           ssh_operation_register(soft_prov_async_abort, acp)) == NULL)
        {
          ssh_free(acp);
          soft_prov_async_execute(ac);
          return NULL;
        }

      ssh_register_timeout(NULL, seconds, micros,
                           soft_prov_async_callback, acp);
      return acp->op_handle;
    }
}

static SshOperationHandle
soft_prov_async_keyop_cb(SshSoftProv soft,
                         SshCryptoStatus status,
                         unsigned char *buf, size_t buf_len,
                         SshPrivateKeyDecryptCB callback,
                         void *context)
{
  struct SshSoftAsyncContextRec ac;
  memset(&ac, 0, sizeof(ac));

  ac.u.keyop_cb = callback;
  ac.context = context;
  ac.type = SOFT_PROV_KEYOP_RESULT;
  ac.data = buf;
  ac.len = buf_len;
  ac.status = status;
  return soft_prov_async_schedule(soft, &ac);
}

SshOperationHandle
soft_prov_async_verify_cb(SshSoftProv soft,
                          SshCryptoStatus status,
                          SshProxyReplyCB callback,
                          void *context)
{
  struct SshSoftAsyncContextRec ac;

  memset(&ac, 0, sizeof(ac));
  ac.u.vrfy_cb = callback;
  ac.context = context;
  ac.type = SOFT_PROV_VERFY_RESULT;
  ac.status = status;
  return soft_prov_async_schedule(soft, &ac);
}

/* Schedule an asynchronous private key acquire callback */
static SshOperationHandle
soft_prov_async_private_cb(SshSoftProv soft,
                           SshEkStatus status, SshPrivateKey key,
                           SshEkGetPrivateKeyCB cb, void *context)
{
  struct SshSoftAsyncContextRec ac;

  memset(&ac, 0, sizeof(ac));
  ac.u.private_cb = cb;
  ac.context = context;
  ac.type = SOFT_PROV_ASYNC_PRIVATE;
  ac.key.private_key = key;
  ac.status = status;
  return soft_prov_async_schedule(soft, &ac);
}

/* Schedule an asynchronous public key acquire callback */
static SshOperationHandle
soft_prov_async_public_cb(SshSoftProv soft,
                           SshEkStatus status, SshPublicKey key,
                           SshEkGetPublicKeyCB cb, void *context)
{
  struct SshSoftAsyncContextRec ac;

  memset(&ac, 0, sizeof(ac));
  ac.u.public_cb = cb;
  ac.context = context;
  ac.type = SOFT_PROV_ASYNC_PUBLIC;
  ac.key.public_key = key;
  ac.status = status;
  return soft_prov_async_schedule(soft, &ac);
}

/* Schedule an asyncronous cert callback */
static SshOperationHandle
soft_prov_async_cert_cb(SshSoftProv soft,
                        SshEkStatus status, unsigned char *data,
                        size_t data_len,
                        SshEkGetCertificateCB cb, void *context)
{
  struct SshSoftAsyncContextRec ac;

  memset(&ac, 0, sizeof(ac));
  ac.u.cert_cb = cb;
  ac.context = context;
  ac.data = data;
  ac.len = data_len;
  ac.type = SOFT_PROV_ASYNC_CERT;
  ac.status = status;
  return soft_prov_async_schedule(soft, &ac);
}




/* This is the GLOBAL provider function pointer array we pass to the
   sshexternalkey.c.  It is identified with the externalkey provider
   prefix, which is in our case "software". The other fields are
   function pointers to the provider methods. More documentation for
   functions can be found in extkeyprov.h. */

const
struct SshEkProviderOpsRec ssh_ek_soft_ops =
  {
    "software",
    soft_prov_init,
    soft_prov_uninit,
    soft_prov_get_public_key,
    soft_prov_get_private_key,
    soft_prov_get_certificate,
    NULL_FNPTR, /* No trusted certs*/
    NULL_FNPTR, /* No groups (yet) */
    soft_prov_get_printable_name,
    soft_prov_gen_acc_prvkey,
    NULL_FNPTR,
    NULL_FNPTR, /* No accelerator for groups. */
    NULL_FNPTR, /* No random bytes available */
    ssh_soft_message_cb /* No messages */
  };

/* eof */
