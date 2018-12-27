/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initialize CA engine's external key providers.
*/








#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshcrypt.h"
#include "sshexternalkey.h"
#include "sshtimeouts.h"
#include "sshfsm.h"
#include "sshprvkey.h"
#include "sshpubkey.h"
#include "sshpkcs12-conv.h"
#include "sshfileio.h"
#include "sshurl.h"
#include "x509.h"
#include "oid.h"
#include "sshinet.h"
#include "au-ek.h"

#define SSH_DEBUG_MODULE "SshCAEK"

/* The total number externalkey providers */
static unsigned int num_providers = 0;
/* The number of enabled externalkey providers */
static unsigned int num_completed = 0;

typedef struct {
  SshAuProvider providers;

  SshEkAuthenticationCB auth;
  SshEkNotifyCB notify;
  void *context;

  SshAuEKStartCB done;
  void *done_context;

  SshExternalKey ek;
} *WhileAdd;


static void
au_ek_providers_added(void *context)
{
  WhileAdd c = context;

  (*c->done)(c->ek, c->done_context);
  ssh_xfree(c);
}

static void notify_internal(SshEkEvent event,
                            const char *keypath,
                            const char *label,
                            SshEkUsageFlags flags,
                            void *context)
{
  WhileAdd c = context;

  /* Incremented the number of enabled providers */
  num_completed++;

  /* Are all providers enabled? */
   if (num_providers == num_completed)
     {
       SSH_DEBUG(SSH_D_HIGHOK,
                 ("All %d correctly configured providers ready.",
                  num_providers));
       ssh_xregister_timeout(0L, 0L, au_ek_providers_added, c);
     }

   /* Call the user notify callback */
  c->notify(event, keypath, label, flags, c->context);
}


static void
au_ek_allocation_done(SshExternalKey ek, void *context)
{
  WhileAdd c = context;

  if (ek)
    {
      c->ek = ek;

      ssh_ek_register_notify(ek, notify_internal, c);
      ssh_ek_register_authentication_callback(ek, c->auth, c->context);

      if (num_providers)
        {
          int i;
          char *name;
          SshEkStatus status;

          for (i = 0; i < num_providers; i++)
            {
              if ((status =
                   ssh_ek_add_provider(ek,
                                       c->providers[i].type,
                                       c->providers[i].info,
                                       NULL, 0L, &name)) != SSH_EK_OK)



                (*c->done)(NULL, c->done_context);
              return;
            }
        }
      else
        {
          (*c->done)(ek, c->done_context);
          ssh_xfree(c);
        }
    }
  else
    {
      (*c->done)(NULL, c->done_context);
      ssh_xfree(c);
    }
}

/* Providers array is stolen by the library. It has to to be an
   contiguous ssh_xmalloc()'d memory block with numproviders
   element. */
void
ssh_au_ek_init(SshAuProvider providers,
               int numproviders,
               SshEkAuthenticationCB auth,
               SshEkNotifyCB notify,
               void *ek_context,
               SshAuEKStartCB done, void *done_context)
{
  WhileAdd c;
  SshExternalKey ek;

  c = ssh_xmalloc(sizeof(*c));

  c->providers = providers;
  num_providers = numproviders;
  num_completed = 0;

  c->notify = notify;
  c->auth = auth;
  c->context = ek_context;

  c->done = done;
  c->done_context = done_context;

  ek = ssh_ek_allocate();
  au_ek_allocation_done(ek, c);
}


typedef struct SshAuEKContextRec
{
  SshExternalKey ek;
  SshEkStatus ekstatus;

  /* Private and public keys collected with certificates. */
  char *prvpath; SshPrivateKey prvkey;
  char *pubpath; SshPublicKey pubkey;
  unsigned char *cert; size_t cert_len;

  /* Operation context for cancelling this and subops. */
  SshOperationHandle op;
  SshFSMThread thread;

  Boolean tried_cert, tried_pub;

  SshAuEKKeyCB user_callback;
  void *user_callback_context;
} *SshAuEKContext, SshAuEKContextStruct;

SSH_FSM_STEP(ek_get_private_key);
SSH_FSM_STEP(ek_get_public_key);
SSH_FSM_STEP(ek_return_keypair);

static void
ek_prv_done(SshEkStatus status, SshPrivateKey prvkey, void *context)
{
  SshAuEKContext c = context;

  if (status == SSH_EK_OK)
    c->prvkey = prvkey;
  else
    {
      c->ekstatus = status;
      ssh_fsm_set_next(c->thread, ek_return_keypair);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(ek_get_private_key)
{
  SshCryptoStatus status;
  SshPrivateKey prvkey;
  const char *kt;
  char outfile[256];
  SshAuEKContext c = ssh_fsm_get_tdata(thread);
  unsigned char *data;
  size_t len;
  unsigned char *scheme = NULL, *type = NULL, *size = NULL, *kind = NULL,
    *pass = NULL, *path = NULL;
  Boolean was_plain_filename = FALSE;

  /* "generate://<kind>:<passphrase>@<type>:<size>/<path>"  */
  /* example: "generate://pkcs8:mypassphrase@rsa:1024/mykeyfile" */

  /* "file://<passphrase>/<path>" */
  /* example: "file://mypassphrase/mykeyfile" */

  /* "file:/<path>" */
  /* example: "file:/some/dir/mykeyfile" */

  /* <filename> */
  /* example: "/some/dir/mykey.prv" */

  /* any other external key path that belongs to ek's providers. */




#define MAPFREE(s, t, l, k, x, p)               \
  do {                                          \
    ssh_xfree(s); ssh_xfree(t); ssh_xfree(l);   \
    ssh_xfree(k); ssh_xfree(x), ssh_xfree(p);   \
  } while (0)

  if (ssh_read_gen_file(c->prvpath, &data, &len))
    was_plain_filename = TRUE;

  if ((was_plain_filename == TRUE) ||
      ssh_url_parse((unsigned char *)c->prvpath,
                    &scheme, &type, &size, &kind, &pass, &path) ||
      path == NULL)
    {
      unsigned int keybits = 0;
      char *cipher, *hash;

      if (was_plain_filename ||
          !scheme || !ssh_usstrcasecmp(scheme, "file"))
        {
          SshSKBType inform;

          if (scheme && !ssh_usstrcasecmp(scheme, "file"))
            {
              pass = type;
              type = NULL;
            }

          if ((was_plain_filename == FALSE && (!scheme || !path)) ||
              (was_plain_filename == FALSE &&
               ssh_read_gen_file(path[0] == '/' ?
                                 ssh_csstr(path + 1) : ssh_csstr(path),
                                 &data, &len) == FALSE))
            {
              c->ekstatus = SSH_EK_KEY_FILE_NOT_FOUND;
              SSH_FSM_SET_NEXT(ek_return_keypair);
              MAPFREE(scheme, type, size, kind, pass, path);
              return SSH_FSM_CONTINUE;
            }

          if (ssh_skb_get_info(data, len,
                               &cipher, &hash, NULL, NULL, &inform, NULL)
              == SSH_CRYPTO_OK)
            {
              SshCryptoStatus cs;

              cs = ssh_skb_decode(inform, data, len, cipher, hash, pass,
                                  pass ? ssh_ustrlen(pass) : 0,
                                  &prvkey);
              ssh_free(cipher);
              ssh_free(hash);
              ssh_free(data);

              if (cs != SSH_CRYPTO_OK)
                {
                  c->ekstatus = SSH_EK_KEY_ACCESS_DENIED; /* Wrong pass */
                  SSH_FSM_SET_NEXT(ek_return_keypair);
                  MAPFREE(scheme, type, size, kind, pass, path);
                  return SSH_FSM_CONTINUE;
                }
              else
                {
                  c->prvkey = prvkey;
                  SSH_FSM_SET_NEXT(ek_get_public_key);
                  if (ssh_private_key_get_info(prvkey,
                                               SSH_PKF_KEY_TYPE, &kt,
                                               SSH_PKF_END)
                      == SSH_CRYPTO_OK)
                    {
                      if (!strcasecmp(kt, "if-modn"))
                        kt = "rsa-pkcs1-sha1";
                      else if (!strcasecmp(kt, "dl-modp"))
                        kt = "dsa-nist-sha1";

                      ssh_private_key_select_scheme(prvkey,
                                                    SSH_PKF_SIGN, kt,
                                                    SSH_PKF_END);
                      MAPFREE(scheme, type, size, kind, pass, path);
                      return SSH_FSM_CONTINUE;
                    }
                  else
                    {
                      c->ekstatus = SSH_EK_KEY_BAD_FORMAT;
                      SSH_FSM_SET_NEXT(ek_return_keypair);
                    }
                }
            }
          else
            {
              c->ekstatus = SSH_EK_KEY_BAD_FORMAT;
              SSH_FSM_SET_NEXT(ek_return_keypair);
              ssh_xfree(data);
              MAPFREE(scheme, type, size, kind, pass, path);
              return SSH_FSM_CONTINUE;
            }
          ssh_xfree(data);
        }

      if (!ssh_usstrcasecmp(scheme, "generate"))
        {
          SshSKBType outform;

          if (!type)
            type = ssh_xstrdup("rsa");
          if (!kind)
            kind = ssh_xstrdup("pkcs8");

          if (!ssh_usstrcasecmp(type, "rsa"))
            kt = "if-modn{encrypt{rsa-pkcs1-none},sign{rsa-pkcs1-sha1}}";
          else if (!ssh_usstrcasecmp(type, "dsa"))
            kt = "dl-modp{sign{dsa-nist-sha1}}";
          else
            {
              c->ekstatus = SSH_EK_KEY_BAD_FORMAT;
              SSH_FSM_SET_NEXT(ek_return_keypair);
              MAPFREE(scheme, type, size, kind, pass, path);
              return SSH_FSM_CONTINUE;
            }

          if (size) keybits = ssh_uatoi(size);
          if (!keybits) keybits = 1024;
          if (keybits < 170) keybits = 384;

          if (!ssh_usstrcmp(kind, "secsh1"))
            outform = SSH_SKB_SECSH_1;
          else if (!ssh_usstrcmp(kind, "ssh1"))
            outform = SSH_SKB_SECSH_1;

          else if (!ssh_usstrcmp(kind, "ssh"))
            outform = SSH_SKB_SECSH_2;
          else if (!ssh_usstrcmp(kind, "ssh2"))
            outform = SSH_SKB_SECSH_2;
          else if (!ssh_usstrcmp(kind, "secsh"))
            outform = SSH_SKB_SECSH_2;
          else if (!ssh_usstrcmp(kind, "secsh2"))
            outform = SSH_SKB_SECSH_2;

          else if (!ssh_usstrcmp(kind, "cryptolib1"))
            outform = SSH_SKB_SSH_1;
          else if (!ssh_usstrcmp(kind, "cryptolib2"))
            outform = SSH_SKB_SSH_2;

          else if (!ssh_usstrcmp(kind, "pkcs1"))
            outform = SSH_SKB_PKCS1;
          else if (!ssh_usstrcmp(kind, "pkcs8s"))
            outform = SSH_SKB_PKCS8_SHROUDED;
          else if (!ssh_usstrcmp(kind, "pkcs8"))
            outform = SSH_SKB_PKCS8;

          else if (!ssh_usstrcmp(kind, "x509"))
            outform = SSH_SKB_SSH_X509;
          else
            {
              c->ekstatus = SSH_EK_KEY_BAD_FORMAT;
              SSH_FSM_SET_NEXT(ek_return_keypair);
              MAPFREE(scheme, type, size, kind, pass, path);
              return SSH_FSM_CONTINUE;
            }

          if ((status = ssh_private_key_generate(&prvkey, kt,
                                                 SSH_PKF_SIZE, keybits,
                                                 SSH_PKF_END))
              != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Can't generate %s private key of %d bits: %s",
                         kt, keybits,
                         ssh_crypto_status_message(status)));

              c->ekstatus = SSH_EK_TOKEN_ERROR;
              SSH_FSM_SET_NEXT(ek_return_keypair);
              MAPFREE(scheme, type, size, kind, pass, path);
              return SSH_FSM_CONTINUE;
            }

          c->prvkey = prvkey;

          if (path)
            {
              ssh_snprintf(outfile, sizeof(outfile), "%s.prv", path);
              if (ssh_skb_encode(outform, prvkey, NULL, NULL,
                                 ssh_custr("3des-cbc"), pass,
                                 pass ? ssh_ustrlen(pass) : 0,
                                 &data, &len) == SSH_CRYPTO_OK)
                {
                  if (!ssh_write_file(outfile, data, len))
                    {
                      ssh_xfree(data);
                      c->ekstatus = SSH_EK_KEY_FILE_NOT_FOUND;
                      SSH_FSM_SET_NEXT(ek_return_keypair);
                      MAPFREE(scheme, type, size, kind, pass, path);
                      return SSH_FSM_CONTINUE;
                    }
                  ssh_xfree(data);
                }
              else
                {
                  c->ekstatus = SSH_EK_KEY_BAD_FORMAT;
                  SSH_FSM_SET_NEXT(ek_return_keypair);
                  MAPFREE(scheme, type, size, kind, pass, path);
                  return SSH_FSM_CONTINUE;
                }
            }

          SSH_FSM_SET_NEXT(ek_get_public_key);
          MAPFREE(scheme, type, size, kind, pass, path);
          return SSH_FSM_CONTINUE;
        }
      MAPFREE(scheme, type, size, kind, pass, path);
    }
  else
    {
      SshUInt32 i, nproviders;
      SshEkProvider providers;

      (void)ssh_ek_get_providers(c->ek, &providers, &nproviders);

      for (i = 0; i < nproviders; i++)
        {
          if (ssh_ek_key_path_belongs_to_provider(c->prvpath,
                                                  providers[i].short_name))
            {
              SSH_FSM_SET_NEXT(ek_get_public_key);
              SSH_FSM_ASYNC_CALL({
                ssh_ek_get_private_key(c->ek, c->prvpath,
                                       ek_prv_done, c);
              });
            }
        }
    }
  SSH_FSM_SET_NEXT(ek_return_keypair);
  return SSH_FSM_CONTINUE;
}

static void
ek_crt_done(SshEkStatus status,
            const unsigned char *cert, size_t cert_len,
            void *context)
{
  SshAuEKContext c = context;
  SshX509Certificate crt = NULL;

  if (status == SSH_EK_OK
      && (crt = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) != NULL
      && ssh_x509_cert_decode(cert, cert_len, crt) == SSH_X509_OK)
    {
      if (c->pubkey == NULL)
        ssh_x509_cert_get_public_key(crt, &c->pubkey);
      c->cert = ssh_xmemdup(cert, cert_len);
      c->cert_len = cert_len;
      ssh_x509_cert_free(crt);
    }
  else
    {
      if (!c->tried_cert || !c->tried_pub)
        {
          /* Retry via ek_get_public_key. */
          if (crt) ssh_x509_cert_free(crt);
          ssh_fsm_set_next(c->thread, ek_get_public_key);
        }
      else
        {
          c->ekstatus = status;
          ssh_fsm_set_next(c->thread, ek_return_keypair);
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static void
ek_pub_done(SshEkStatus status, SshPublicKey pub, void *context)
{
  SshAuEKContext c = context;

  if (status == SSH_EK_OK && pub)
    c->pubkey = pub;
  else
    {
      c->ekstatus = status;
      ssh_fsm_set_next(c->thread, ek_return_keypair);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(ek_get_public_key)
{
  void *ekparams;
  SshAuEKContext c = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(ek_return_keypair);

  if (ssh_private_key_get_info(c->prvkey,
                               SSH_PKF_PROXY, &ekparams,
                               SSH_PKF_END)
      == SSH_CRYPTO_UNSUPPORTED_IDENTIFIER)
    {
      /* Might have received this from a certificate */
      if (c->pubkey == NULL)
        {
          SshCryptoStatus status;
          status = ssh_private_key_derive_public_key(c->prvkey, &c->pubkey);
          SSH_ASSERT(status == SSH_CRYPTO_OK);
        }
      if (c->pubpath)
        {
#if 0
          char *scheme, *path;
#endif
          unsigned char *data;
          size_t len;

          c->tried_pub = c->tried_cert = TRUE;

#if 0
          if (ssh_url_parse(c->pubpath,
                            &scheme, NULL, NULL, NULL, NULL, &path)
              && path)
            {
              if (ssh_read_gen_file(path[0] == '/' ? path + 1 : path,
                                    &data, &len))
                {
                  ssh_xfree(scheme);
                  ssh_xfree(path);
                  SSH_FSM_ASYNC_CALL({
                    ek_crt_done(SSH_EK_OK, data, len, c);
                    ssh_xfree(data);
                  });
                }
              ssh_xfree(scheme);
              ssh_xfree(path);
            }
          else
#endif
            {
              if (au_read_certificate(c->pubpath, &data, &len, NULL))
                {
                  SSH_FSM_ASYNC_CALL({
                    ek_crt_done(SSH_EK_OK, data, len, c);
                    ssh_xfree(data);
                  });
                }
            }
          SSH_FSM_ASYNC_CALL({
            ek_crt_done(SSH_EK_KEY_NOT_FOUND, NULL, 0, c);
          });
        }
    }
  else
    {
      if (c->tried_cert && c->tried_pub)
        {
          SSH_FSM_SET_NEXT(ek_return_keypair);
          c->ekstatus = SSH_EK_KEY_NOT_FOUND;
          return SSH_FSM_CONTINUE;
        }
      else if (c->tried_cert)
        {
          c->tried_cert = TRUE;
          SSH_FSM_ASYNC_CALL({
            ssh_ek_get_certificate(c->ek, c->pubpath, 0,
                                   ek_crt_done, c);
          });
        }
      else
        {
          c->tried_pub = TRUE;
          SSH_FSM_ASYNC_CALL({
            ssh_ek_get_public_key(c->ek, c->pubpath, ek_pub_done,
                                  c);
          });
        }
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ek_return_keypair)
{
  SshAuEKContext c = ssh_fsm_get_tdata(thread);

  (*c->user_callback)(c->ekstatus,
                      c->prvkey,
                      c->pubkey, c->cert, c->cert_len,
                      c->user_callback_context);
  ssh_xfree(c->prvpath);
  ssh_xfree(c->pubpath);
  ssh_xfree(c->cert);
  ssh_xfree(c);
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}

SshOperationHandle
au_ek_get_keypair(SshExternalKey ek,
                  const char *private_key_path,
                  const char *public_key_path,
                  SshAuEKKeyCB callback, void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  SshAuEKContext c;

  fsm = ssh_fsm_create(NULL);
  c = ssh_xcalloc(1, sizeof(*c));
  thread = ssh_fsm_thread_create(fsm,
                                 ek_get_private_key,
                                 NULL_FNPTR, NULL_FNPTR,
                                 c);

  c->ek = ek;
  c->ekstatus = SSH_EK_OK;

  if (private_key_path) c->prvpath = ssh_xstrdup(private_key_path);
  if (public_key_path) c->pubpath = ssh_xstrdup(public_key_path);
  c->user_callback = callback;
  c->user_callback_context = callback_context;
  c->thread = thread;

  return NULL;



}

static Boolean
check_cert(const unsigned char *der, size_t der_len,
           SshX509Certificate* cert_ret)
{
  SshX509Certificate c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(der, der_len, c) == SSH_X509_OK)
    {
      if (cert_ret)
        *cert_ret = c;
      else
        ssh_x509_cert_free(c);
      return TRUE;
    }

  ssh_x509_cert_free(c);
  return FALSE;
}

Boolean
au_read_certificate(const char *path,
                    unsigned char **der, size_t *der_len,
                    SshX509Certificate *opencert)
{
  SshX509Certificate c;
  unsigned char *data;
  size_t len;
  unsigned char *scheme = NULL, *type = NULL, *size = NULL, *kind = NULL,
    *pass = NULL, *filepath = NULL;
  unsigned char *pass_str = NULL;
  SshStr passwd = NULL;
  Boolean ret;

  /* Try PEM first. */
  ret = ssh_read_file_base64(path, der, der_len);
  if (ret)
    {
      if (check_cert(*der, *der_len, opencert))
        return TRUE;
      ssh_free(*der);
    }

  if (!ssh_read_gen_file(path, der, der_len))
    {
      if (!ssh_url_parse((unsigned char *)path, &scheme, &type, &size, &kind,
                         &pass, &filepath))
          return FALSE;

      if (!ssh_read_gen_file(filepath[0] == '/' ?
                             ssh_csstr(filepath + 1) : ssh_csstr(filepath),
                             der, der_len))
        {
          ssh_xfree(scheme);
          ssh_xfree(type);
          ssh_xfree(size);
          ssh_xfree(kind);
          ssh_xfree(pass);
          ssh_xfree(filepath);
          return FALSE;
      }

      if (ssh_usstrcmp(scheme, "file") == 0)
        pass_str = ssh_xstrdup(type);
      else
        pass_str = ssh_xstrdup(pass);

      ssh_xfree(scheme);
      ssh_xfree(type);
      ssh_xfree(size);
      ssh_xfree(kind);
      ssh_xfree(pass);
      ssh_xfree(filepath);
    }

  c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(*der, *der_len, c) == SSH_X509_OK)
    {
      if (opencert)
        *opencert = c;
      else
        ssh_x509_cert_free(c);
      return TRUE;
    }
  ssh_x509_cert_free(c);
  c = ssh_x509_cert_allocate(SSH_X509_PKIX_CRMF);

  if (ssh_x509_cert_decode(*der, *der_len, c) == SSH_X509_OK)
    {
      if (opencert)
        *opencert = c;
      else
        ssh_x509_cert_free(c);
      return TRUE;
    }
  ssh_x509_cert_free(c);
  c = ssh_x509_cert_allocate(SSH_X509_PKCS_10);

  if (ssh_x509_cert_decode(*der, *der_len, c) == SSH_X509_OK)
    {
      if (opencert)
        *opencert = c;
      else
        ssh_x509_cert_free(c);
      return TRUE;
    }
  ssh_x509_cert_free(c);

  data = NULL;
  if (pass_str)
    {
      passwd = ssh_str_make(SSH_CHARSET_ISO_8859_1,
                            ssh_xstrdup(pass_str),
                            ssh_ustrlen(pass_str));
      ssh_xfree(pass_str);
    }
  ssh_pkcs12_conv_decode_cert(*der, *der_len, passwd, 0, NULL, &data, &len);
  if (data)
    {
      c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(data, len, c) == SSH_X509_OK)
        {
          ssh_xfree(*der);
          *der = data;
          *der_len = len;
          if (opencert)
            *opencert = c;
          else
            ssh_x509_cert_free(c);
          return TRUE;
        }
      ssh_x509_cert_free(c);
    }

  {
    SshPKBType pkbtype;
    char *pubkey_comment = NULL, *pubkey_subject = NULL;
    const char  *pubkey_type_name = NULL;
    Boolean pubkey_needs_secret = FALSE;
    SshPublicKey pubkey;

    if (SSH_CRYPTO_OK == ssh_pkb_get_info(*der, *der_len,
                                          NULL, NULL,
                                          &pkbtype,
                                          &pubkey_subject,
                                          &pubkey_comment)) {
      if (ssh_pkb_get_type_info(pkbtype,
                                &pubkey_needs_secret,
                                &pubkey_type_name) == TRUE) {

        if (SSH_CRYPTO_OK ==
            ssh_pkb_decode(pkbtype,
                           *der, *der_len,
                           pubkey_needs_secret ? pass : NULL,
                           pubkey_needs_secret ? ssh_ustrlen(pass) : 0,
                           &pubkey)) {
          Boolean rv;
          c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
          rv = ssh_x509_cert_set_public_key(c, pubkey);
          /* Get the subject name from the public key as well.
             Ssh2 pubkeys have them. */
          if (rv && pubkey_subject && *pubkey_subject) {
            char *tmp = ssh_xmalloc(strlen(pubkey_subject) + 4);
            ssh_snprintf(tmp, strlen(pubkey_subject) + 4,
                         "CN=%s", pubkey_subject);
            rv = ssh_x509_cert_set_subject_name(c, (unsigned char *)tmp);
            ssh_xfree(tmp);
          }
          ssh_public_key_free(pubkey);
          if (opencert)
            *opencert = c;
          else
            ssh_x509_cert_free(c);
          return rv;
        } else {
          /* decode failed */
          return FALSE;
        }
      } else {
        /* get_type_info failed  */
        return FALSE;
      }
    } else {
      /* pkb_get_info failed  */
      return FALSE;
    }
  }

  ssh_free(*der);
  return FALSE;
}

void
au_cert_set_subject(SshX509Certificate t,
                    SshCharset subject_charset,
                    const char *subjectstr)
{
  char *thisalt, *kind;
  unsigned char *value;
  char *subject = ssh_xstrdup(subjectstr);
  SshX509Name altnames = NULL;
  SshStr subject_str = NULL;
  Boolean subject_ok;

  subject = (char *)(strtok(subject, ";"));
  if (subject)
    {
      if ((subject_str =
           ssh_str_make(subject_charset,
                        ssh_xstrdup(subject), strlen(subject)))
          == NULL)
        {
        subject_charset_conversion_failed:
          ssh_warning("Cannot convert %s to current charset (%s)",
                      subject,
                      subject_charset == SSH_CHARSET_UTF8 ? "utf8":
                      subject_charset == SSH_CHARSET_ISO_8859_1 ?
                      "latin1" : "unknown");
          return;
        }
      subject_ok = ssh_x509_cert_set_subject_name_str(t, subject_str);
      ssh_str_free(subject_str);
      if (!subject_ok)
        {
          thisalt = subject;
          goto try_alternative_only;
        }
    }

  while ((thisalt = (char *)(strtok(NULL, ";"))) != NULL)
    {
    try_alternative_only:
      kind = ssh_xstrdup(thisalt);
      if ((value = ssh_ustr(strchr(kind, '='))) != NULL)
        {
          *value = 0; value++;
          if (strcasecmp(kind, "ip") == 0)
            {
              unsigned char ipval[16];
              size_t iplen = sizeof(ipval);

              if (ssh_inet_strtobin(value, ipval, &iplen))
                ssh_x509_name_push_ip(&altnames, ipval, iplen);
            }
          if (strcasecmp(kind, "dns") == 0)
            ssh_x509_name_push_dns(&altnames, (char *) value);
          if (strcasecmp(kind, "email") == 0)
            ssh_x509_name_push_email(&altnames, (char *) value);
          if (strcasecmp(kind, "uri") == 0)
            ssh_x509_name_push_uri(&altnames, (char *) value);
          if (strcasecmp(kind, "rid") == 0)
            ssh_x509_name_push_rid(&altnames, (char *) value);
          if (strcasecmp(kind, "dn") == 0)
            {
              if ((subject_str =
                   ssh_str_make(subject_charset,
                                ssh_xstrdup(value), ssh_ustrlen(value)))
                  == NULL)
                goto subject_charset_conversion_failed;
              ssh_x509_name_push_directory_name_str(&altnames, subject_str);
              ssh_str_free(subject_str);
            }
        }
      ssh_xfree(kind);
    }
  if (altnames)
    ssh_x509_cert_set_subject_alternative_names(t, altnames, FALSE);

  ssh_xfree(subject);
}

typedef struct
{
  unsigned int flag;
  char *name;
} CertFlagEntry;

static CertFlagEntry key_usage_flag_table[] =
{
  { SSH_X509_UF_DIGITAL_SIGNATURE, "digitalsignature" },
  { SSH_X509_UF_NON_REPUDIATION,   "nonrepudiation" },
  { SSH_X509_UF_KEY_ENCIPHERMENT,  "keyencipherment" },
  { SSH_X509_UF_DATA_ENCIPHERMENT, "dataencipherment" },
  { SSH_X509_UF_KEY_AGREEMENT,     "keyagreement" },
  { SSH_X509_UF_KEY_CERT_SIGN,     "keycertsign" },
  { SSH_X509_UF_CRL_SIGN,          "crlsign" },
  { SSH_X509_UF_ENCIPHER_ONLY,     "encipheronly" },
  { SSH_X509_UF_DECIPHER_ONLY,     "decipheronly" },
  { 0,                             NULL }
};

void
au_cert_set_key_usage(SshX509Certificate t, const char *usestr)
{
  char *copy = ssh_xstrdup(usestr), *tmp, *c;
  SshUInt32 flags = 0, i;

  tmp = copy;
  do {
    if ((c = strchr(tmp, ';')) != NULL)
      {
        *c = 0;
        c++;
      }
    else
      c = NULL;
    for (i = 0; key_usage_flag_table[i].name; i++)
      {
        if (!strcasecmp(tmp, "help"))
          {
            au_help_extensions();
            exit(0);
          }
        if (!strcasecmp(tmp, key_usage_flag_table[i].name))
          {
            flags |= key_usage_flag_table[i].flag;
          }
      }
    tmp = c;
  } while (tmp != NULL && *tmp != '\0');
  ssh_xfree(copy);

  if (flags)
    ssh_x509_cert_set_key_usage(t, flags, FALSE);
}

void au_help_extensions(void)
{
  int i;
  ssh_warning("Key usage extension names:");
  for (i = 0; key_usage_flag_table[i].name; i++)
    ssh_warning("\t%s", key_usage_flag_table[i].name);
}

void au_help_subject(void)
{
  ssh_warning("Subject name format:");
  ssh_warning("DN-name[;othernames]*");
  ssh_warning("  where DN-name is reverse LDAP name presentation.");
  ssh_warning("  and othernames are tuples type=value, valid types being:");
  ssh_warning("    IP, DNS, EMAIL, URI, RID, and DN");
  ssh_warning("    IP=1.2.3.4;IP=fe80::1;DNS=ssh.com;Email=info@ssh.com");
}

void au_help_keytypes(void)
{
  ssh_warning("Key types:");
  ssh_warning("  ssh2(alias ssh, secsh, secsh2): SSH Secure Shell key format");
  ssh_warning("  ssh1(alias secsh1): SSH Secure Shell key format version 1");
  ssh_warning("  cryptolib1; SSH cryptographic library export key format, v1");
  ssh_warning("  cryptolib2; SSH cryptographic library export key format, v2");
  ssh_warning("  pkcs1; Asn.1 encoded RSA PKCS#1 key parameters");
  ssh_warning("  pkcs8; RSA PKCS#8 private key export; plaintext");
  ssh_warning("  pkcs8s; RSA PKCS#8 private key export; encrypted");
  ssh_warning("  x509; PKIX certificate profile Asn.1 encoded keys");
}

static const SshOidStruct *au_cert_numeric_oid(const char *usestr)
{
  static SshOidStruct oid;

  oid.oid = usestr;
  return &oid;
}

void
au_cert_set_ext_key_usage(SshX509Certificate t, const char *usestr)
{
  char *copy = ssh_xstrdup(usestr), *tmp, *c;
  SshX509OidList list, head = NULL;
  const SshOidStruct *oid;

  tmp = copy;
  do {
    if ((c = strchr(tmp, ';')) != NULL)
      {
        *c = 0;
        c++;
      }
    else
      c = NULL;

    if ((oid = ssh_oid_find_by_std_name(tmp)) != NULL ||
        (oid = au_cert_numeric_oid(tmp)) != NULL)
      {
        if (head)
          {
            list = ssh_xcalloc(1, sizeof(*list));
            list->next = head->next;
            head->next = list;
          }
        else
          head = list = ssh_xcalloc(1, sizeof(*list));

        list->oid = ssh_xstrdup(oid->oid);
      }
    tmp = c;
  } while (tmp != NULL && *tmp != '\0');
  ssh_xfree(copy);

  if (head)
    ssh_x509_cert_set_ext_key_usage(t, head, FALSE);
}
#endif /* SSHDIST_CERT */
