/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Application which produces DER encoded X.509 v3 certificates and v2
   certification revocation lists given a file in suitable format.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "x509.h"
#include "oid.h"
#include "dn.h"
#include "sshpsystem.h"
#include "sshexternalkey.h"
#include "parse-x509-forms.h"
#include "sshadt.h"
#include "sshadt_strmap.h"
#include "sshfileio.h"
#include "sshtimeouts.h"
#include "iprintf.h"
#include "sshglobals.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshCertmake"

#ifdef WINDOWS
#define MONITOR_VIEW
#else
#define MONITOR_VIEW
#endif /* WINDOWS */

static int terminal_width;

void monitor(SshCryptoProgressID id,
             unsigned int time_value,
             void *progress_context)
{
#ifdef MONITOR_VIEW
  int i;

  if (time_value > terminal_width-40)
    time_value = 1;

  printf("Working |");
  for (i = 0; i < time_value; i++)
    printf("#");
  for (; i < terminal_width-40; i++)
    printf(".");
  printf("|");
  printf("\r");
  fflush(stdout);
#endif /* MONITOR_VIEW */
}

void create_monitor(void)
{
  ssh_crypto_library_register_progress_func(monitor, NULL);
}

void free_monitor(void)
{
#ifdef MONITOR_VIEW
  int i;
  for (i = 0; i < terminal_width - 10; i++)
    printf(" ");
  printf("\r");
  fflush(stdout);
#endif /* MONITOR_VIEW */
  ssh_crypto_library_register_progress_func(NULL_FNPTR, NULL);
}

/************************* EK provider support *****************************/

typedef struct EkProviderRec {
  struct EkProviderRec *next;
  char *type;
  char *init_str;
  char *short_name;
  Boolean key_notified;
  SshEkProviderFlags flags;
  unsigned int timeout_sec;
} *EkProvider;

typedef enum {
  /* We're waiting for enable operations to complete */
  EK_TIMEOUT_ENABLE,

  /* We're waiting for GetPrivateKey operations to complete */
  EK_TIMEOUT_GET_KEY
} EkTimeoutPhase;

typedef struct EkTimeoutRec {
  /* What are we waiting for? */
  EkTimeoutPhase phase;

  /* Current "time", in seconds */
  unsigned int counter;

  /* How many seconds we are willing to wait */
  unsigned int timeout;
} *EkTimeout;

/* This controls the "Finished successfully" message at the end. */
Boolean successful = TRUE;

EkTimeout cur_timeout;

/* The main externalkey object */
SshExternalKey ext_key;

/* List of providers we want */
EkProvider ek_providers;

/* The total number externalkey providers */
unsigned int num_providers;
/* The number of enabled externalkey providers */
unsigned int num_completed;

/* This is set to true when all the externalkey providers are enabled. */
Boolean all_ek_providers_enabled = FALSE;

/* List of private keys to use */
SshX509FormPrivateKey private_keys;

/* Mapping of key names to FormPrivateKey structures */
SshADTContainer private_key_map;

/* This a global list of forms (the contents of all input files) */
SshX509FormListStruct form_list;

/* Forward references */
void acquire_keys(void*);
void process_forms(void*);
void ek_timeout_cb(void *context);

/* Verify that all referenced EK providers are declared. Exits via
   fatal if they aren't. */
void verify_providers(SshX509FormList list)
{
  /* Stores the names of all declared providers */
  SshADTContainer provider_map = ssh_adt_create_strmap();
  SshX509FormNode node;
  SshX509FormContainer c;
  EkProvider ek;
  EkProvider *ek_last = &ek_providers;
  SshX509FormPrivateKey pk;
  SshX509FormPrivateKey *pk_last = &private_keys;
  char *tmp_name, *t;
  SshUInt32 max_timeout_sec = 0;

  ek_providers = NULL;

  /* Make a pass over the data to record provider declarations */
  for (node = list->head; node; node = node->next)
    {
      c = node->container;
      if (node->type == SSH_X509_FORM_LIST_TYPE_PROVIDER)
        {
          ssh_adt_strmap_add(provider_map, c->current.provider->type,
            c->current.provider->type);

          ek = ssh_xcalloc(1, sizeof(*ek));
          *ek_last = ek;
          ek_last = &ek->next;

          ek->type     = c->current.provider->type;
          ek->init_str = c->current.provider->init_str;
          ek->flags    = c->current.provider->flags;
          ek->timeout_sec = c->current.provider->timeout_sec;
          if (ek->timeout_sec > max_timeout_sec)
            max_timeout_sec = ek->timeout_sec;

          SSH_DEBUG(10, ("Adding provider %s[%s,%d]\n", ek->type,
                         ek->init_str ? ek->init_str : "",
                         (int) ek->flags));
        }
    }

  /* The software provider is always defined */
  if (!ssh_adt_strmap_get(provider_map, "software"))
    {
      ek = ssh_xcalloc(1, sizeof(*ek));
      *ek_last = ek;
      ek->type = "software";
      ek->init_str = "";
      SSH_DEBUG(10, ("Adding default provider\n"));
      ssh_adt_strmap_add(provider_map, ek->type, ek->type);
    }

  /* Then look at the key declarations. Arrange them in a list
     and make sure all providers have been declared. */
  for (node = list->head; node; node = node->next)
    {
      c = node->container;
      pk = NULL;
      if (node->type == SSH_X509_FORM_LIST_TYPE_KEY)
        pk = c->current.pkey;
      else if (node->type == SSH_X509_FORM_LIST_TYPE_GEN_KEY)
        pk = &c->current.gen_pkey->key;
      if (pk == NULL)
        continue;  /* Not a key entry */

      /* Add to list of private keys */
      *pk_last = pk;
      pk->next = NULL;
      pk_last = &pk->next;

      if (pk->pub_key != NULL)
        continue; /* Is a public key entry. */

      /* Verify the key path */
      if (!pk->key_path)
        ssh_fatal("Key %s doesn't have a key path", pk->name);

      SSH_DEBUG(10, ("Looking at key %s: %s\n", pk->name, pk->key_path));

      /* Find the provider, or fail. */
      tmp_name = ssh_xstrdup(pk->key_path);
      t = strchr(tmp_name, ':');
      if (t == NULL)
        ssh_fatal("Key path %s is not valid", pk->key_path);

      *t = '\0'; /* Leave only the provider name */
      if (!ssh_adt_strmap_get(provider_map, tmp_name))
        ssh_fatal("Provider %s for key %s has not been declared.",
                  tmp_name, pk->name);

      ssh_xfree(tmp_name);
    }

  ssh_adt_destroy(provider_map);
}

void start_acquire_keys(void)
{
  /* Cancel the enable timeout. Don't free the context, it will be
     reused. */
  ssh_cancel_timeouts(ek_timeout_cb, SSH_ALL_CONTEXTS);

  /* Continue the process in one half a second so that if this
     provider is about to notify even more keys. */
  ssh_xregister_timeout(0, 500000, acquire_keys, NULL);
}

/************************** EK Callbacks **********************************/

void ek_timeout_cb(void *context)
{
  EkTimeout tm = context;

  if (++tm->counter == tm->timeout)
    {
      ssh_xfree(tm);

      if (num_completed < num_providers)
        {
          printf ("\nError: not all providers have responded \n");
          successful = FALSE;
          ssh_event_loop_abort();
          return;
        }

      start_acquire_keys();
    }
  else
    {
      printf(".");
      fflush(stdout);
      ssh_xregister_timeout(1, 0, ek_timeout_cb, tm);
    }
}

/* External key notification callback */
void ek_notify_cb(SshEkEvent event,
                  const char *keypath,
                  const char *label,
                  SshEkUsageFlags flags,
                  void *context)
{
  if (event == SSH_EK_EVENT_KEY_AVAILABLE)
    {
      EkProvider ekp;

      SSH_DEBUG(10, ("Key available: %s\n", keypath));
      /* Find the provider this key belons to */
      for (ekp = ek_providers; ekp; ekp = ekp->next)
        if (ssh_ek_key_path_belongs_to_provider(keypath, ekp->short_name))
          ekp->key_notified = TRUE;

      /* Now we make an assumtion. If all the providers are enabled
         and all of the providers have keys notified then we can start
         the process. */
      for (ekp = ek_providers; ekp; ekp = ekp->next)
        if (ekp->key_notified == FALSE)
          return;

      /* All providers have at least one key notified */
      if (all_ek_providers_enabled)
        {
          start_acquire_keys();
        }
    }

  if (event == SSH_EK_EVENT_PROVIDER_FAILURE)
    {
      /* Informoing about the provider failures is always a nice
         thing to do */
      printf("Provider %s failed with info '%s'.\n",
             keypath, (label ? label : ""));
    }

  if (event == SSH_EK_EVENT_PROVIDER_ENABLED)
    {
      Boolean all_providers_notified_keys = TRUE;
      EkProvider ekp;

      /* Increment the number of enabled providers */
      num_completed++;

    if (num_completed < num_providers)
      return;

    SSH_DEBUG(10, ("All providers enabled.\n"));

    printf(" - done. \n");
    all_ek_providers_enabled = TRUE;

    for (ekp = ek_providers; ekp; ekp = ekp->next)
      if (ekp->key_notified == FALSE)
        all_providers_notified_keys = FALSE;

    if (all_providers_notified_keys)
      start_acquire_keys();
    }
}

/* External key authentication callback */
SshOperationHandle ek_authentication_cb(const char *keypath,
                                        const char *label,
                                        SshUInt32 try_number,
                                        SshEkAuthenticationStatus status,
                                        SshEkAuthenticationReplyCB reply_cb,
                                        void *reply_context,
                                        void *context)
{
  char *pin = NULL;
  SshX509FormPrivateKey key;
#ifdef WIN32
  unsigned char pin_buffer[100];
#endif

  /* Search our list of provider records to see if
     we can provide authentication code, or if we need to
     ask the user. */
  for (key = private_keys; key; key = key->next)
    {
      if (strcmp(keypath, key->key_path) == 0 && key->auth_code != NULL)
        {
          pin = key->auth_code;
          break;
        }
    }

  if (!pin)
    {
      printf ("Please enter the PIN code for %s.\n", label);
#ifndef WIN32
      pin = (char *)(getpass("PIN:"));
#else
      printf("(Warning: your PIN will be visible)\nPIN: ");
      scanf("%s", pin_buffer);
      pin = pin_buffer;
#endif
    }
  (*reply_cb)((unsigned char *)pin, strlen(pin), reply_context);
  return NULL;
}

/* This is allocates the EK. */
static void cert_make_add_ek(void)
{
  EkProvider ekp;
  EkTimeout tm;
  unsigned int max_timeout = 1;

  num_providers = 0;
  num_completed = 0;

  for (ekp = ek_providers; ekp; ekp = ekp->next)
    num_providers++;

  ext_key = ssh_ek_allocate();

  /* Register authentication and notification callbacks */
  ssh_ek_register_notify(ext_key, ek_notify_cb, ext_key);
  ssh_ek_register_authentication_callback(ext_key, ek_authentication_cb,
                                          ext_key);

  /* Add the providers. This list is never empty, "software" is always
     present. */
  for (ekp = ek_providers; ekp; ekp = ekp->next)
    {
      char *short_name;
      if (ssh_ek_add_provider(ext_key, ekp->type, ekp->init_str, NULL,
                              ekp->flags, &short_name) != SSH_EK_OK)
        {
          ssh_fatal("Can not add crytographic provider '%s' "
                    "with initialization info '%s'.",
                    ekp->type, ekp->init_str);
        }
      if (ekp->timeout_sec > max_timeout)
        max_timeout = ekp->timeout_sec;
      ekp->short_name = short_name;
    }

  /* Allocate and establish a timeout to print cool dots while waiting keys. */
  tm = ssh_xmalloc(sizeof(*tm));
  tm->phase = EK_TIMEOUT_ENABLE;
  tm->counter = 0;
  tm->timeout = max_timeout;
  ssh_xregister_timeout(1, 0, ek_timeout_cb, tm);
  cur_timeout = tm;

  fflush(stdout);
}

/******************** Private key support routines ************************/

SshX509FormPrivateKey get_key_by_name(const char *name)
{
  if (!name)
    return NULL;

  return ssh_adt_strmap_get(private_key_map, name);
}

void check_key(const char* cname, Boolean subject_key,
               SshX509FormContainer container)
{
  const char *key_name;
  const char *key_type;

  if (subject_key)
    {
      key_name = container->subject_key;
      key_type = "subject";
    }
  else
    {
      key_name = container->issuer_prv_key;
      key_type = "issuer";
    }

  if (!get_key_by_name(key_name))
    {
      if (key_name)
        ssh_fatal("%s %s %s private key %s not found.",
                  cname, container->output_file,
                  key_type, key_name);
      else
        ssh_fatal("%s %s needs %s private key.",
                  cname, container->output_file, key_type);
    }
}

/* Build a map of private key names and verify that all forms
   refer to key names that actually exist. */
void verify_keys(SshX509FormList forms)
{
  SshX509FormPrivateKey key;
  SshX509FormContainer container;
  SshX509FormNode node;

  /* Put all key names into the map */
  private_key_map = ssh_adt_create_strmap();
  for (key = private_keys; key; key = key->next)
    ssh_adt_strmap_add(private_key_map, key->name, key);

  for (node = forms->head; node; node = node->next)
    {
      container = node->container;
      switch (node->type)
        {
        case SSH_X509_FORM_LIST_TYPE_CERT:
          /* Check subject key */
          if (container->self_signed || !container->input_request_file)
            check_key("Certificate", TRUE, container);

          /* Check issuer key presence */
          if (!container->self_signed)
            check_key("Certificate", FALSE, container);
          break;

        case SSH_X509_FORM_LIST_TYPE_REQUEST:
          check_key("Certificate request", TRUE, container);
          break;

        case SSH_X509_FORM_LIST_TYPE_CRL:
          check_key("CRL", FALSE, container);
          break;

        default:
          break;
        }
    }
}

void start_process_forms_p(void)
{
  SshX509FormPrivateKey key;

  for (key = private_keys; key; key = key->next)
    {
      if (key->prv_key == NULL || key->pub_key == NULL)
        return;
    }

  SSH_DEBUG(10, ("All keys acquired, standing by...\n"));
  printf(" - done.\n");

  /* Cancel the key acquire timeout. */
  ssh_cancel_timeouts(ek_timeout_cb, SSH_ALL_CONTEXTS);

  /* Continue the process */
  form_list.current = NULL;
  ssh_xregister_timeout(0, 0, process_forms, &form_list);
}

/* EK private key callback */
void ek_private_key_cb(SshEkStatus status,
                       SshPrivateKey private_key,
                       void *context)
{
  SshX509FormPrivateKey key = context;

  if (status != SSH_EK_OK)
    ssh_fatal("Can not acquire private key at %s (%d)",
              key->key_path, status);

  /* Store this key away and check if it was the last one. */
  key->prv_key = private_key;

  start_process_forms_p();
}

/* EK private key callback */
void ek_public_key_cb(SshEkStatus status,
                      SshPublicKey public_key,
                      void *context)
{
  SshX509FormPrivateKey key = context;

  if (status != SSH_EK_OK)
    ssh_fatal("Can not acquire public key at %s (%d).",
              key->key_path, status);

  /* Store this key away and check if it was the last one. */
  key->pub_key = public_key;
  start_process_forms_p();
}


/* This function is called when all the providers have been enabled.
   Here we go through the private key list and call the EK providers
   to return SshPrivateKey objects. */
void acquire_keys(void* context)
{
  SshX509FormPrivateKey key;

  SSH_DEBUG(10, ("Starting to acquire private keys\n"));

  /* Check if we already have all the keys. If so, go straight to
     process_forms(), which actually generates the certificates. */
  for (key = private_keys; key; key = key->next)
    {
      if (key->prv_key == NULL && key->key_path != NULL)
        break;
    }
  form_list.current = NULL;
  if (key == NULL)
    process_forms(&form_list);
  else
    {
      /* Reuse the timeout context allocated in allocate_cb */
      cur_timeout->phase = EK_TIMEOUT_GET_KEY;
      cur_timeout->counter = 0;
      ssh_xregister_timeout(1, 0, ek_timeout_cb, cur_timeout);

      printf("Acquiring private keys for signing\n");
      fflush(stdout);

      for (key = private_keys; key; key = key->next)
        {
          /* Skip keys that already exist (generate_software_keys
             could have created them). */
          if (key->prv_key == NULL && key->key_path != NULL)
            {
              SSH_DEBUG(10, ("Private key %s, path %s\n",
                             key->name, key->key_path));

              ssh_ek_get_private_key(ext_key, key->key_path,
                                     ek_private_key_cb, key);
              ssh_ek_get_public_key(ext_key, key->key_path,
                                    ek_public_key_cb, key);
            }
        }
    }
}

/* This is for compatibility with earlier Certmake: generate
   software private keys (which obviously don't need acquiring
   from the software provider)  */
void generate_software_keys(SshX509FormList forms)
{
  SshX509FormNode node;
  SshX509FormContainer container;
  SshX509FormGenPrivateKey gen;
  int count = 0;
  unsigned char* buf;
  size_t buf_len;

  /* Count the number of key generation blocks */
  for (node = forms->head; node; node = node->next)
    {
      container = node->container;
      if (container->type == SSH_X509_FORM_LIST_TYPE_GEN_KEY)
        count++;
    }
  if (count == 0)
    return;

  iprintf("Creating software private keys.#I\n");
  create_monitor();

  for (node = forms->head; node; node = node->next)
    {
      SshCryptoStatus cs;

      container = node->container;
      if (container->type != SSH_X509_FORM_LIST_TYPE_GEN_KEY)
        continue;

      gen = container->current.gen_pkey;
      if (gen->pk_type == NULL)
        {
          ssh_warning("Check configuration; no key type for %s",
                      gen->key.name);
          continue;
        }
#ifdef MONITOR_VIEW
      printf("\r%*s", terminal_width-40 + 11, "\r");
#endif /* MONITOR_VIEW */
      printf("Creating private key %s\n", gen->key.name);
      fflush(stdout);

      SSH_DEBUG(10, ("Creating private key %s\n", gen->key.name));
      if (strstr(gen->pk_type, "ec-modp") == NULL)
        {
          cs =
           ssh_private_key_generate(&gen->key.prv_key,
                                    gen->pk_type,
                                    SSH_PKF_SIZE, gen->pk_key_bits,
                                    SSH_PKF_END);
        }
      else
        {
          SshX509FormECPPrvKeyAttr attr = (SshX509FormECPPrvKeyAttr)
                                                     gen->key.key_attrs;
          cs =
           ssh_private_key_generate(&gen->key.prv_key,
                                    gen->pk_type,
                                    SSH_PKF_PREDEFINED_GROUP,
                                        attr->curve_name,
                                    SSH_PKF_END);
        }
      if (cs != SSH_CRYPTO_OK)
        {
          ssh_fatal("Failed create \'%s\' key because: \'%s\'.",
                    gen->pk_type,
                    ssh_crypto_status_message(cs));
        }
      if ((cs =
           ssh_private_key_derive_public_key(gen->key.prv_key,
                                             &gen->key.pub_key))
          != SSH_CRYPTO_OK)
        {
          ssh_fatal("Failed create \'%s\' key because: \'%s\'.",
                    gen->pk_type,
                    ssh_crypto_status_message(cs));
        }
    }
  free_monitor();

  /* Yet another pass, to write the keys  to files. (I didn't put this
     into the second pass because of the progress monitor.) */
 for (node = forms->head; node; node = node->next)
   {
     container = node->container;
     if (container->type != SSH_X509_FORM_LIST_TYPE_GEN_KEY)
       continue;

     gen = container->current.gen_pkey;
     if (ssh_x509_encode_private_key(gen->key.prv_key,
                                     &buf, &buf_len) != SSH_X509_OK)
       ssh_fatal("Failed to encode private key %s.", gen->key.name);

     iprintf("Writing private key to file %s.\n", gen->output_file);
     if (!ssh_write_gen_file(gen->output_file,
                             SSH_PEM_SSH_PRV_KEY,
                             buf, buf_len))
       ssh_fatal("Can not save private key to file %s.", gen->output_file);
     ssh_xfree(buf);
   }

 iprintf("#i");
}

/* Free all private keys we have acquired */
void free_keys(void)
{
  SshX509FormPrivateKey key;
  SshPublicKey pub = NULL;

  for (key = private_keys; key; key = key->next)
    {
      if (key->prv_key != NULL)
        {
          ssh_private_key_free(key->prv_key);
          if (key->pub_key)
            pub = key->pub_key;
          key->prv_key = NULL;
        }
    }
  if (pub)
    ssh_public_key_free(pub);
  ssh_adt_destroy(private_key_map);
}

/*********************** Certificate utilities ****************************/

/* Find the subject private key and set appropriate
   certificate fields */
void get_subject_private_key(SshX509FormContainer container)
{
  char *key_type, *sign;
  const SshX509PkAlgorithmDefStruct *algorithm;
  const SshOidStruct *oids;
  const SshOidPkStruct *extra;
  SshX509FormPrivateKey key;
  SshX509Certificate cert = container->current.cert;

  key = get_key_by_name(container->subject_key);

  if (key->pub_key == NULL && key->prv_key != NULL)
    {
      SshCryptoStatus status;

      status =
        ssh_private_key_derive_public_key(key->prv_key,
                                          &cert->subject_pkey.public_key);

      SSH_ASSERT(status == SSH_CRYPTO_OK);

      if (ssh_private_key_get_info(key->prv_key,
                                   SSH_PKF_KEY_TYPE, &key_type,
                                   SSH_PKF_SIGN, &sign,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        ssh_fatal("Can not find private key information for %s.",
                  container->subject_key);

    }
  else
    {
      if (ssh_public_key_copy(key->pub_key, &cert->subject_pkey.public_key)
          != SSH_CRYPTO_OK)
        ssh_fatal("Could not copy the public key for use.");
      if (ssh_public_key_get_info(key->pub_key,
                                  SSH_PKF_KEY_TYPE, &key_type,
                                  SSH_PKF_SIGN, &sign,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        ssh_fatal("can not find public key information for %s.",
                  container->subject_key);
      ssh_public_key_free(key->pub_key);
      key->pub_key = NULL;
    }

  algorithm = ssh_x509_match_algorithm(key_type, sign, NULL);

  if (algorithm == NULL)
    ssh_fatal("Cryptographic algorithm not available '%s' - '%s'.",
              key_type, sign);

  oids = ssh_oid_find_by_std_name_of_type(algorithm->known_name,  SSH_OID_PK);
  if (oids == NULL)
    ssh_fatal("Cryptographic algorithm OID not known '%s'.",
              algorithm->known_name);

  extra = oids->extra;
  cert->subject_pkey.subject_key_usage_mask = extra->key_usage;
  cert->subject_pkey.ca_key_usage_mask = extra->ca_key_usage;
  cert->subject_pkey.pk_type = extra->alg_enum;
}

void read_cert_request_file(SshX509FormContainer container)
{
  SshX509Certificate c, req;
  SshPublicKey key;
  SshX509Name names;
  Boolean critical;
  unsigned char *buf;
  size_t buf_len;

  if (ssh_read_gen_file(container->input_request_file,
                        &buf, &buf_len) == FALSE)
    ssh_fatal("Can not read request from file '%s'.",
              container->input_request_file);

  req = ssh_x509_cert_allocate(SSH_X509_PKCS_10);
  if (ssh_x509_cert_decode(buf, buf_len, req) != SSH_X509_OK)
    {
      iprintf("Certificate request decode failed, trying to decode "
              "as certificate\n");
      if (ssh_x509_cert_decode(buf, buf_len, req) != SSH_X509_OK)
        {
          ssh_fatal("Can not decode request read from file '%s'.",
                    container->input_request_file);
        }
      iprintf("#ISucceeded.#i\n");
    }

  ssh_xfree(buf);

  /* Copy information from request to final certificate */
  c = container->current.cert;

  /* Copy public key */
  if (!ssh_x509_cert_get_public_key(req, &key))
    ssh_fatal("Can not acquire the public key from the certificate "
              "request read from file '%s'.", container->input_request_file);
  ssh_x509_cert_set_public_key(c, key);

  /* Verify request signature */
  if (!ssh_x509_cert_verify(req, key))
    iprintf("CAUTION: Signature in the request doesn't match.\n");
  else
    iprintf("Signature check success.\n");

  ssh_public_key_free(key);

  /* Copy rest of the information */
  if (container->copy_from_request & SSH_X509_FORM_COPY_FROM_REQ_SUBJECT_NAME)
    {
      SshStr str;
      if (ssh_x509_cert_get_subject_name_str(req, &str))
        {
          ssh_x509_cert_set_subject_name_str(c, str);
          ssh_str_free(str);
        }
    }

  if (ssh_x509_cert_get_subject_alternative_names(req, &names, &critical) &&
      names != NULL)
    {
      SshX509Name copy;
      char *p;
      size_t s;
      unsigned char *u;

      copy = NULL;
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_IP)
        {
          while (ssh_x509_name_pop_ip(names, &u, &s))
            {
              ssh_x509_name_push_ip(&copy, u, s);
              ssh_xfree(u);
            }
        }
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_EMAIL)
        {
          while (ssh_x509_name_pop_email(names, (char **) &p))
            {
              ssh_x509_name_push_email(&copy, p);
              ssh_xfree(p);
            }
        }
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DNS)
        {
          while (ssh_x509_name_pop_dns(names, &p))
            {
              ssh_x509_name_push_dns(&copy, p);
              ssh_xfree(p);
            }
        }
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_URI)
        {
          while (ssh_x509_name_pop_uri(names, &p))
            {
              ssh_x509_name_push_uri(&copy, p);
              ssh_xfree(p);
            }
        }
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_RID)
        {
          while (ssh_x509_name_pop_rid(names, &p))
            {
              ssh_x509_name_push_rid(&copy, p);
              ssh_xfree(p);
            }
        }
      if (container->copy_from_request &
          SSH_X509_FORM_COPY_FROM_REQ_EXT_S_ALT_N_DN)
        {
          while (ssh_x509_name_pop_directory_name(names, &p))
            {
              ssh_x509_name_push_directory_name(&copy, (unsigned char *)p);
              ssh_xfree(p);
            }
        }
      ssh_x509_cert_set_subject_alternative_names(c, copy, critical);
    }
  if (container->copy_from_request &
      SSH_X509_FORM_COPY_FROM_REQ_EXT_KEY_USAGE &&
      ssh_x509_cert_ext_available(req, SSH_X509_EXT_KEY_USAGE, NULL))
    {
      SshX509UsageFlags flags;

      if (ssh_x509_cert_get_key_usage(req, &flags, &critical) &&
          flags != 0)
        {
          ssh_x509_cert_set_key_usage(c, flags, critical);
        }
    }
  if (container->copy_from_request &
      SSH_X509_FORM_COPY_FROM_REQ_EXT_BASIC_CONSTRAINTS &&
      ssh_x509_cert_ext_available(req, SSH_X509_EXT_BASIC_CNST, NULL))
    {
      size_t path_length;
      Boolean ca;

      if (ssh_x509_cert_get_basic_constraints(req, &path_length,
                                              &ca, &critical))
        {
          ssh_x509_cert_set_basic_constraints(c, path_length,
                                              ca, critical);
        }
    }
  if (container->copy_from_request &
      SSH_X509_FORM_COPY_FROM_REQ_EXT_CRL_DIST_POINT &&
      ssh_x509_cert_ext_available(req, SSH_X509_EXT_CRL_DIST_POINTS, NULL))
    {
      SshX509ExtCRLDistPoints dist_points;

      if (ssh_x509_cert_get_crl_dist_points(req, &dist_points,
                                            &critical) &&
          dist_points != NULL)
        {
          /* Note steal the distribution point from the
             request, because we dont want to copy it here */
          req->extensions.crl_dp = NULL;
          ssh_x509_cert_set_crl_dist_points(c, dist_points,
                                            critical);
        }
    }
  ssh_x509_cert_free(req);
}

/**************************** Main routines ******************************/

typedef struct EncodeContextRec {
  /* String describing what was encoded: "certificate", "CRL", etc. */
  const char *what;

  /* PEM begin/end strings. */
  const char *pem_begin;
  const char *pem_end;

  /* Name of file where the encoded certificate is to be written. */
  char *file_name;
  SshX509FormList forms;

} EncodeContext;

/* Callback that gets called after certificate/CRL encoding */
void encode_callback(SshX509Status status,
                     const unsigned char *buf, size_t buf_len,
                     void *context)
{
  EncodeContext *c = context;

  if (status != SSH_X509_OK)
    ssh_fatal("Can not generate %s. Reason (%d).", c->what, status);

  if (!ssh_write_gen_file(c->file_name, c->pem_begin, c->pem_end,
                          buf, buf_len))
    ssh_fatal("Can not write %s into file %s.", c->what, c->file_name);

  /* Announce success. */
  iprintf("%c%s generated successfully (%s)\n",
          toupper(((unsigned char *) c->what)[0]), c->what + 1, c->file_name);

  ssh_xfree(c->file_name);
  ssh_xregister_timeout(0L, 0L, process_forms, c->forms);
  ssh_xfree(c);
}

/* Encode certificate with given private key and write the
   result into output_file. */
static SshOperationHandle
encode_and_write_cert(SshX509FormList forms,
                      SshX509Certificate cert,
                      SshX509FormPrivateKey key,
                      const char* output_file,
                      const char* what)
{
  const char* pk_alg;
  EncodeContext *ec;
  SshPrivateKey private_key;

  /* At this stage this is an internal error */
  if (key == NULL || key->prv_key == NULL)
    {
      iprintf("Error: private key for %s signing is not available\n", what);
      exit(1);
    }

  private_key = key->prv_key;

  /* Check that the signature algorithm has been given */
  pk_alg = cert->pop.signature.pk_algorithm;
  if (!pk_alg)
    ssh_fatal("SignatureAlgorithm was not given in the Signature block.");

  if (ssh_private_key_select_scheme(private_key,
                                    SSH_PKF_SIGN, pk_alg,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Signature algorithm '%s' not supported.", pk_alg);

  /* Build the context information that is needed to write the
     encoded certificate to a file */
  ec = ssh_xmalloc(sizeof(*ec));
  ec->what      = what;
  ec->file_name = ssh_xstrdup(output_file);
  if (!strcmp(what, "certificate"))
    {
      ec->pem_begin = SSH_PEM_X509_BEGIN;
      ec->pem_end   = SSH_PEM_X509_END;
    }
  if (!strcmp(what, "certificate request"))
    {
      ec->pem_begin = SSH_PEM_CERT_REQ_BEGIN;
      ec->pem_end   = SSH_PEM_CERT_REQ_END;
    }
  ec->forms     = forms;

  return ssh_x509_cert_encode_async(cert, private_key, encode_callback, ec);
}

/* Handle certificate form */
static SshOperationHandle
handle_cert(SshX509FormContainer container, SshX509FormList forms)
{
  SshX509FormPrivateKey private_key;
  SshX509Name name;
  SshX509Certificate cert = container->current.cert;

  /* Sanity checks for the information from the configuration file */

  /* Check that the output file has been given */
  if (container->output_file == NULL)
    ssh_fatal("Output file for the certificate not given in "
              "configuration file.");

  if (cert->subject_name == NULL)
    iprintf("\nwarning: No subject name given. Generated certificate "
            "may be unusable.\n\n");

  if (ssh_ber_time_cmp(&cert->not_before, &cert->not_after) == 0)
    ssh_fatal("Validity period length is zero.");

  if (!ssh_ber_time_available(&cert->not_before))
    ssh_fatal("Invalid validity start time.");

  if (!ssh_ber_time_available(&cert->not_after))
    ssh_fatal("Invalid validity end time.");

  name = cert->issuer_name;
  if (name == NULL)
    iprintf("\nwarning: No issuer name given. Generated certificate "
            "may be unusable.\n\n");

  while (name != NULL && name->type != SSH_X509_NAME_DISTINGUISHED_NAME)
    name = name->next;

  if (name == NULL)
    iprintf("\nwarning: No distinguished issuer name given. "
            "Generated certificate may be unusable.\n\n");

  if (cert->serial_number.v == NULL)
    iprintf("\nwarning: No serial number given or serial number is "
            "zero. Generated certificate may be unusable.\n\n");

  /* Sanity checks end. */

  /* Read and copy request fields */
  if (container->input_request_file)
    read_cert_request_file(container);
  else
    get_subject_private_key(container);

  if (container->self_signed && container->subject_key == NULL)
    ssh_fatal("Private key is not available when trying to generate "
              "a selfsigned certificate.");

  if (container->issuer_prv_key == NULL && !container->self_signed)
    ssh_fatal("Issuer private key is not available.");

  iprintf("Proceeding with the signing operation.\n");

  if (container->self_signed)
    private_key = get_key_by_name(container->subject_key);
  else
    private_key = get_key_by_name(container->issuer_prv_key);

  return encode_and_write_cert(forms,
                               cert, private_key, container->output_file,
                               "certificate");
}

/* Handle certificate request forms */
static SshOperationHandle
handle_cert_req(SshX509FormContainer container, SshX509FormList forms)
{
  SshX509Certificate cert = container->current.cert;

  get_subject_private_key(container);

  iprintf("  Proceeding with the signing operation.\n");
  return encode_and_write_cert(forms,
                               cert, get_key_by_name(container->subject_key),
                               container->output_file,
                               "certificate request");
}

/* Handle CRL form */
static SshOperationHandle
handle_crl(SshX509FormContainer container, SshX509FormList forms)
{
  SshPrivateKey private_key;
  SshX509Crl crl = container->current.crl;
  EncodeContext *ec;

  /* Find the private key. */
  if (container->issuer_prv_key == NULL)
    ssh_fatal("Issuer private key file not defined for CRL.");

  private_key = get_key_by_name(container->issuer_prv_key)->prv_key;
  if (ssh_private_key_select_scheme(private_key,
                                    SSH_PKF_SIGN,
                                    crl->pop.signature.pk_algorithm,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("Signature algorithm '%s' not supported.",
              crl->pop.signature.pk_algorithm);

  iprintf("Encoding the CRL.\n");

  /* Build the context information that is needed to write the
     encoded certificate to a file */
  ec = ssh_xmalloc(sizeof(*ec));
  ec->what      = "CRL";
  ec->file_name = ssh_xstrdup(container->output_file);
  ec->pem_begin = SSH_PEM_X509_CRL_BEGIN;
  ec->pem_end   = SSH_PEM_X509_CRL_END;
  ec->forms     = forms;

  return ssh_x509_crl_encode_async(crl, private_key, encode_callback, ec);
}

/* Parse a file into form list, exit if an error occurs. */
Boolean
handle_file(char *name, SshCharset encoding,
            SshX509FormList list)
{
  unsigned char *buf;
  size_t buf_len;
  SshX509FormListStruct forms;
  SshPSystemErrorStruct error;

  iprintf("Processing file '%s'.\n#I", name);

  if (!ssh_read_gen_file(name, &buf, &buf_len))
    ssh_fatal("Could not read file %s.", name);

  /* Init the form list. */
  ssh_x509_form_list_init(&forms, encoding);

  /* Handle the parsing */
  ssh_x509_form_parse(buf, buf_len, &forms, &error);
  ssh_xfree(buf);

  if (error.status != SSH_PSYSTEM_OK)
    {
      iprintf("Parsing error in #I\n"
              "file   = %s\n"
              "line   = %5u column = %u\n"
              "msg    = %s#i#i\n",
              name, error.line, error.pos,
              ssh_psystem_error_msg(error.status));

      ssh_x509_form_list_free(&forms);
      return FALSE;
    }
  else
    {
      iprintf("#i");

      /* Add the contents to the global list of forms */
      if (list->head == NULL)
        {
          list->head = forms.head;
          list->tail = forms.tail;
        }
      else
        {
          list->tail->next = forms.head;
          list->tail = forms.tail;
        }
      return TRUE;
    }
}

/* This is a timeout callback, called via acquire_keys() */
void process_forms(void *context)
{
  SshX509FormList forms = context;
  SshX509FormNode node;
  SshX509FormContainer container;
  SshOperationHandle op;

  for (node = forms->current ? forms->current->next : forms->head;
       node;
       node = node->next)
    {
      forms->current = node;
      container = node->container;
      switch (node->type)
        {
        case SSH_X509_FORM_LIST_TYPE_CERT:
          iprintf("Certificate: #I\n");
          op = handle_cert(container, forms);
          iprintf("#i");
          break;

        case SSH_X509_FORM_LIST_TYPE_CRL:
          iprintf("CRL: #I\n");
          op = handle_crl(container, forms);
          iprintf("#i");
          break;

        case SSH_X509_FORM_LIST_TYPE_REQUEST:
          iprintf("Certificate Request: #I\n");
          op = handle_cert_req(container, forms);
          iprintf("#i");
          break;

        default:
          op = NULL;
          break;
        }

      if (op)
        {
          return;
        }
    }

  /* The work is done. We still need to clean up the keys and to
     uninitialize the EK provider (in this order) before we can
     exit the event loop. */
  free_keys();

  {
    EkProvider ekp, next;
    for (ekp = ek_providers; ekp; ekp = next)
      {
        next = ekp->next;
        ssh_xfree(ekp->short_name);
        ssh_free(ekp);
      }
  }

  ssh_ek_free(ext_key, NULL_FNPTR, NULL);
  ext_key = NULL;

  ssh_cancel_timeouts(process_forms, SSH_ALL_CONTEXTS);
}

static void certmake_error_callback(const char *message,
                                    void *context)
{
  fprintf(stderr, "Error: %s\n", message);
  exit(1);
}

static void usage(void)
{
  iprintf("Usage: ssh-certmake [options] [commandfile]\n"
          "where options is combination of the following:\n"
          "\t -h        display this help and exit.\n"
          "\t -V        print version information, continue.\n"
          "\t -d string set debug level into <string>.\n"
          "\t -w number set terminal width into <number> characters.\n"
          "\t -r file   initialize random pool with contents of <file>.\n"
          "\t -e coding set input encoding into <coding>, one of:\n"
          "\t    latin1, latin2, latin3, latin4, latin15, bmp, or universal\n"
          "\t    default encoding is UTF-8.\n"
          "and command file is file path containing object descriptions.\n"
          "if not given, 'test.x509' is assumed. This may be '-' indicating\n"
          "standard input.\n");
}

int main(int ac, char **av)
{
  int opt;
  SshX509ConfigStruct c;
  SshCharset encoding = SSH_CHARSET_UTF8;
  Boolean rv;

  ssh_x509_library_set_default_config(&c);
  c.cs.treat_printable_as_latin1 = 1;
  c.cs.treat_t61_as_latin1 = 1;
  c.cs.enable_visible_string = 0;
  c.cs.enable_bmp_string = 0;
  c.cs.enable_printable_within_bitstring = 0;
  c.ec.allow_ee_basic_constraints = 1;

  ssh_debug_register_callbacks(certmake_error_callback,
                               NULL_FNPTR, NULL_FNPTR, NULL);

  terminal_width = 80;
  iprintf_set(terminal_width, 0, 0);

  form_list.head = NULL;
  form_list.tail = NULL;

  ssh_x509_library_initialize(&c);
  ssh_random_stir();

  while ((opt = ssh_getopt(ac, av, "VPhd:w:r:e:", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'P':
        case 'V':
          iprintf("SSH X.509 v3 certificate and v2 crl make utility\n"
                  "Copyright (c) 2002 - 2014, INSIDE Secure Oy."
                  "  All rights reserved.\n");
          break;
        case 'h':
        usage:
          usage();
          ssh_x509_library_uninitialize();
          ssh_util_uninit();
          exit(0);
        case 'd':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'w':
          terminal_width = atoi(ssh_optarg);
          iprintf_set(terminal_width, 0, 0);
          break;

        case 'r':
          {
            unsigned char *buffer;
            size_t buffer_len;

            if (FALSE == ssh_read_file(ssh_optarg, &buffer, &buffer_len))
              ssh_fatal("Cannot read file %s.", ssh_optarg);

            ssh_random_add_noise(buffer, buffer_len, 8 * buffer_len);
            memset(buffer, 0, buffer_len);
            ssh_xfree(buffer);
            ssh_random_stir();
            iprintf("Stirred in %lu bytes of entropy.\n",
                    (unsigned long) buffer_len);
          }
          break;

        case 'e':
          if (!strcmp(ssh_optarg, "latin1"))
            encoding =  SSH_CHARSET_ISO_8859_1;
          else if (!strcmp(ssh_optarg, "latin2"))
            encoding =  SSH_CHARSET_ISO_8859_2;
          else if (!strcmp(ssh_optarg, "latin3"))
            encoding =  SSH_CHARSET_ISO_8859_3;
          else if (!strcmp(ssh_optarg, "latin4"))
            encoding =  SSH_CHARSET_ISO_8859_4;
          else if (!strcmp(ssh_optarg, "latin15"))
            encoding = SSH_CHARSET_ISO_8859_15;
          else if (!strcmp(ssh_optarg, "bmp"))
            encoding = SSH_CHARSET_BMP;
          else if (!strcmp(ssh_optarg, "teletext"))
            encoding = SSH_CHARSET_T61;
          else if (!strcmp(ssh_optarg, "universal"))
            encoding = SSH_CHARSET_UNIVERSAL;
          else if (!strcmp(ssh_optarg, "utf8"))
            encoding = SSH_CHARSET_UTF8;
          else
            {
              ssh_warning("Unknown input encoding: '%s'", ssh_optarg);
              goto usage;
            }
          break;

        default:
          goto usage;
        }
    }

  ac -= ssh_optind;
  av += ssh_optind;

  if (ac > 1)
    goto usage;

  ssh_event_loop_initialize();

  if (ac == 0)
    rv = handle_file("test.x509", encoding, &form_list);
  else if (ac == 1)
    rv = handle_file(av[0], encoding, &form_list);
  else
    rv = 0; /* never happens */

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp_generator);
#endif /* SSHDIST_CRYPT_ECP */

  if (rv)
    {
      /* Verify EK providers and order the keys */
      verify_providers(&form_list);

      /* Verify that all keys are known (meaning that key references
         in certificates etc. resolve to key/key generate forms) */
      verify_keys(&form_list);

      /* Create (and write to disk) software keys */
      generate_software_keys(&form_list);

      /* Allocate the externalkey object to get things a-going */
      cert_make_add_ek();

      /* Run the event loop to handle async callbacks */
      ssh_event_loop_run();
    }

  ssh_event_loop_uninitialize();

  /* Free the form list (must be done after freeing the private keys) */
  ssh_x509_form_list_free(&form_list);

  if (successful)
    iprintf("Finished successfully.\n");

  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
