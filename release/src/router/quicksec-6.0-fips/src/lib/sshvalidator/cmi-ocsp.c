/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions that are used to combine OCSP with CMi.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_map.h"

#include "sshocspclient.h"

#ifdef SSHDIST_CERT
#ifdef SSHDIST_VALIDATOR_HTTP
#include "sshocsphttp.h"
#include "sshurl.h"
#endif /* SSHDIST_VALIDATOR_HTTP */

#include "cmi.h"
#include "cmi-internal.h"
#include "ocsp_internal.h" /* Nonce handling. */

#ifdef SSHDIST_VALIDATOR_OCSP

#define SSH_DEBUG_MODULE "SshCertEdbOcsp"

typedef void (*SshCMOcspSearchCB)(void *context, void *search_ctx);

/* Structure for key identifier data (unsigned char * + size_t pair) */
/* sha1 is always used. */
typedef struct SshCMOcspKeyIDRec
{
  unsigned char *kid;
  size_t kid_len;
} *SshCMOcspKeyID;

typedef struct SshCMOcspServerRec
{
  /* Optional certificate for the responder. */
  /*  SshCMCertificate responder_cert; */

  /* Unique identifier for the calling application. */
  unsigned int id;

  /* Recheck time for the responder. */
  SshUInt32 recheck_time;

  /* CA under which this OCSP responder is only used. Can be 0 to
     indicate that the responder is "generic". */
  unsigned int cache_id;

  /* A list of CA's for which the server acts as an OCSP responder. */
  SshGList ca_kid_list;

  /* The URL of the particular OCSP server. If NULL implies that the
     URL from the subject certificate is tried instead. */
  unsigned char *responder_url;

  /* Host and port Parsed out from responder URL */
  unsigned char *name;
  unsigned char *port;

  /* A translation algorithm for URLs, when responder_url is not
     present. */
  unsigned char *(*url_translate)(unsigned char *url);

  /* Preferred hash algorithm for the responder. */
  char *hash_algorithm;

  /* Requestor identification. */
  SshX509Name requestor_name;
  SshPrivateKey requestor_private_key;
  /* This identifies the requestor internally. */
  SshCMOcspKeyID public_key_info;

  /* Hash of all the data above. */
  unsigned char *unique_id;

  /* Flags that tell how to deal with responder. */
  SshCMOcspResponderFlags flags;

  /* If not NULL, the response from this server shall be verifiable
     using this public key. */
  SshPublicKey responder_public_key;

  SshADTContainer current_searches;
} *SshCMOcspServer;

typedef struct SshCMOcspLocalEntryRec
{
  SshADTMapHeaderStruct adt_header;

  /* Subject */
  SshOcspCertIDStruct id;

  /* The entry within the 'response' the subject appears in */
  int response_entry;

  SshOcspResponse response;

} *SshCMOcspLocalEntry, SshCMOcspLocalEntryStruct;


typedef struct SshCMOcspSearchRec
{
  /* At current search container, indexed by string presentation of
     the nonce. */
  SshADTMapHeaderStruct adt_header;

  unsigned int refcount;
  SshOcspResponse response;
  unsigned char *url;
  SshOperationHandle handle;
  SshCMSearchContext *context;
  SshCMOcspServer server;
  SshCMCertificate subject;
  SshCMCertificate issuer;
  char *hash_algorithm;
  SshCMOcspKeyID requestor_public_key_id;
  SshMPInteger nonce;
  SshTime send, recv; /* Times when request was send and received */
  SshInt64 clock_compensation;
  Boolean completed;
  SshCMOcspLocalEntry entry;
  SshCMContext cm;

} *SshCMOcspSearch, SshCMOcspSearchStruct;

typedef struct SshCMOcspSearchResultRec
{
  SshOcspResponse response;
  SshOcspBasicSingleResponse single_response;
  SshTime produced_at;
} *SshCMOcspSearchResult, SshCMOcspSearchResultStruct;


/*****************************************************************************
 * ADT functions
 */

SshUInt32
cm_ocsp_search_hash(const void *object, void *context)
{
  SshCMOcspSearch s = (SshCMOcspSearch)object;
  unsigned char buf[20] = { 0 };
  size_t len, i;
  SshUInt32 h = 0;

  if (s->nonce)
    {
      /* Actually we know the nonce is 16 bytes, but prepare for 20 */
      if ((len = ssh_mprz_get_buf(buf, sizeof(buf), s->nonce)) > 0)
        {
          for (i = 0; i < len; i++)
            h = ((h << 19) ^ (h >> 13)) + buf[i];
          return h;
        }
    }
  return 0;
}

int
cm_ocsp_search_compare(const void *object1, const void *object2,
                       void *context)
{
  SshCMOcspSearch s1 = (SshCMOcspSearch)object1;
  SshCMOcspSearch s2 = (SshCMOcspSearch)object2;

  if (s1->nonce == NULL || s2->nonce == NULL) return -1;
  return ssh_mprz_cmp(s1->nonce, s2->nonce);
}

SshUInt32
cm_ocsp_local_entry_hash(const void *object, void *context)
{
  SshCMOcspLocalEntry le = (SshCMOcspLocalEntry) object;
  unsigned char buf[20] = { 0 };
  size_t len, i;
  SshUInt32 h = 0;

  if ((len = ssh_mprz_get_buf(buf, sizeof(buf), &le->id.serial_number)) > 0)
    {
      for (i = 0; i < len; i++)
        h = ((h << 19) ^ (h >> 13)) + buf[i];
      return h;
    }
  return 0;
}

int
cm_ocsp_local_entry_compare(const void *object1, const void *object2,
                            void *context)
{
  SshCMOcspLocalEntry le1 = (SshCMOcspLocalEntry)object1;
  SshCMOcspLocalEntry le2 = (SshCMOcspLocalEntry)object2;

#if 0
  if (le1->id.issuer_name_hash)
    {
      if (le2->id.issuer_name_hash == NULL)
        return -1;
      if (memcmp(le1->id.issuer_name_hash,
                 le2->id.issuer_name_hash,
                 le1->id.hash_len))
        return 1;
    }
  if (le1->id.issuer_key_hash)
    {
      if (le2->id.issuer_key_hash == NULL)
        return -1;
      if (memcmp(le1->id.issuer_key_hash,
                 le2->id.issuer_key_hash,
                 le1->id.hash_len))
        return 1;
    }
#endif

  return ssh_mprz_cmp(&le1->id.serial_number, &le2->id.serial_number);
}

/* Hash the search information.

   This information is sufficient, but may cause confusion when there
   are possibility for different hash algorithms and requestor
   information for working for the OCSP server. Perhaps this is only a
   minor inconvenience, hopefully.  */
static Boolean
hash_search_info(SshCMCertificate    subject,
                 SshCMCertificate    issuer,
                 const unsigned char *responder_url,
                 const char         *hash_algorithm,
                 SshCMOcspKeyID      key_id,
                 unsigned char      *ret_digest,
                 size_t              ret_digest_len)
{
  SshHash hash;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t key_digest_length;
  unsigned char tag_str[4];
  unsigned int id_subject, id_issuer;

  if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,("Can't allocate search info hash %s",
                             SSH_CM_HASH_ALGORITHM));
      return FALSE;
    }

  id_subject = ssh_cm_cert_get_cache_id(subject);
  SSH_PUT_32BIT(tag_str, id_subject);
  ssh_hash_update(hash, tag_str, 4);

  id_issuer = ssh_cm_cert_get_cache_id(issuer);
  SSH_PUT_32BIT(tag_str, id_issuer);
  ssh_hash_update(hash, tag_str, 4);

  if (responder_url)
    ssh_hash_update(hash,
                    responder_url,
                    ssh_ustrlen(responder_url));

  if (key_id && key_id->kid && key_id->kid_len > 0)
    ssh_hash_update(hash, key_id->kid, key_id->kid_len);

  ssh_hash_final(hash, digest);

  /* Copy the digest length. */
  key_digest_length = ssh_hash_digest_length(ssh_hash_name(hash));

  ssh_hash_free(hash);

  if (key_digest_length < ret_digest_len)
    {
      memset(ret_digest, 0, ret_digest_len);
      memcpy(ret_digest, digest, key_digest_length);
    }
  else
    memcpy(ret_digest, digest, ret_digest_len);

  return TRUE;
}


#ifdef SSHDIST_VALIDATOR_HTTP
#define DIGEST_LEN 10

static Boolean
cm_ocsp_ban_check(SshCMContext cm,
                  SshCMCertificate issuer,
                  SshCMCertificate subject,
                  const unsigned char *url,
                  const char *hash_algorithm,
                  SshCMOcspKeyID key_id)
{
  unsigned char digest[DIGEST_LEN];
  SshBerTimeStruct current_time;

  if (hash_search_info(issuer, subject, url,
                       hash_algorithm, key_id, digest, sizeof(digest)))
    {
      ssh_ber_time_set_from_unix_time(&current_time,
                                      (*cm->config->time_func)
                                      (cm->config->time_context));
      return ssh_edb_nega_cache_check(cm->negacache,
                                      SSH_CM_DATA_TYPE_CERTIFICATE,
                                      digest, sizeof(digest),
                                      &current_time);
    }
  return FALSE;
}

static void
cm_ocsp_ban_add(SshCMContext cm,
                SshCMCertificate issuer,
                SshCMCertificate subject,
                const unsigned char *url,
                const char *hash_algorithm,
                SshCMOcspKeyID key_id)
{
  unsigned char digest[DIGEST_LEN];
  SshBerTimeStruct current_time;

#ifdef DEBUG_LIGHT
  char *buf;

  buf = ssh_mprz_get_str(&subject->cert->serial_number, 16);

  SSH_DEBUG(SSH_D_UNCOMMON,
            ("Add to nega cache: URL: %s, serial: %s, hash: %s.",
             url, buf, hash_algorithm));
  ssh_free(buf);

  if (key_id)
    {
      SSH_DEBUG_HEXDUMP(11, ("Requestor identifier: "),
                        key_id->kid, key_id->kid_len);
    }
  else
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("No requestor key identifier."));
    }
#endif /* DEBUG_LIGHT */

  if (hash_search_info(issuer, subject,
                       url, hash_algorithm,
                       key_id, digest, sizeof(digest)))
    {
      ssh_ber_time_set_from_unix_time(&current_time,
                                      (*cm->config->time_func)
                                      (cm->config->time_context));
      SSH_DEBUG_HEXDUMP(7, ("Nega cache digest:"), digest, sizeof(digest));
      ssh_edb_nega_cache_add(cm->negacache,
                             SSH_CM_DATA_TYPE_CERTIFICATE,
                             digest, sizeof(digest),
                             &current_time);
    }
}

#endif /* SSHDIST_VALIDATOR_HTTP */

/***********************************************************/

static SshCMMapState
ssh_cm_ocsp_operation_invoke(SshCMMap map,
                             void *msg,
                             void *context,
                             void *ob_context)
{
  SshCMOcspSearch search = context;

  /* Check if waiting. */
  if (search->context->waiting)
    {
      /* Note, we found something and could as well continue with
         searching. However, as there may be still pending searches
         this may not be such a good idea.

         Certainly multiple simultaneous searches for same key
         might not be that a good idea. */
      search->context->waiting--;
    }
  else
    ssh_fatal("ssh_cm_ocsp_operation_invoke: "
              "searcher wasn't waiting for this!");

  if (msg)
    {
      SshCMOcspSearchResult result = msg;
      SshOcspBasicSingleResponse bsr = result->single_response;
      SshOcspResponse response = result->response;
      SshBerTimeStruct next_update;
      SshTime update_time, next_check_time;

      update_time = result->produced_at;

      /* Set first version of the next update time. Smaller of the
         recheck_time and min_ocsp_validity_time is added to the
         update time. */
      if (search->server->recheck_time <
          search->context->cm->config->min_ocsp_validity_secs)
        {
          next_check_time = update_time + search->server->recheck_time;
        }
      else
        {
          next_check_time = update_time +
            search->context->cm->config->min_ocsp_validity_secs;
        }
      ssh_ber_time_set_from_unix_time(&next_update, next_check_time);

      /* Set next update time if available. If not, this update +
         minimum validity time is used. */
      if (bsr->next_update_available)
        {
          SshBerTimeStruct tmp;

          ssh_ber_time_set_from_unix_time(&tmp,
                                          bsr->next_update -
                                          search->clock_compensation);
          if (ssh_ber_time_cmp(&next_update, &tmp) > 0)
            ssh_ber_time_set(&next_update, &tmp);
        }

      search->subject->inspection.ocsp = response;

      /* The actual status of the certificate is handled here. */
      if (bsr->status.status == SSH_OCSP_CERT_STATUS_GOOD)
        {
          SSH_DEBUG(SSH_D_HIGHSTART, ("OCSP Result: Certificate is good."));


          /* Now we can modify the values in the subject certificate. */
          if (ssh_ber_time_cmp(&search->subject->ocsp_valid_not_after,
                               &next_update) < 0)
            {
              ssh_ber_time_set_from_unix_time(&search->subject->
                                              ocsp_valid_not_before,
                                              update_time);
              ssh_ber_time_set(&search->subject->ocsp_valid_not_after,
                               &next_update);
              search->subject->not_checked_against_crl = FALSE;
            }
          search->subject->status = SSH_CM_VS_OK;
          SSH_DEBUG(SSH_D_MIDOK,
                    ("OCSP validity: not before: '%@' not after '%@'",
                     ssh_ber_time_render,
                     &search->subject->ocsp_valid_not_before,
                     ssh_ber_time_render,
                     &search->subject->ocsp_valid_not_after));
        }
      else
        {
          if (bsr->status.status == SSH_OCSP_CERT_STATUS_REVOKED)
            {
              SshBerTimeStruct revocation_time;
              SshX509CRLReasonCode reason = SSH_X509_CRLF_UNSPECIFIED;
              const char *reason_name = "revoked";
              SshBerTimeStruct tmp;

              if (bsr->status.statusinfo.revoked.reason_available)
                {
                  reason = bsr->status.statusinfo.revoked.revocation_reason;
                  if (reason == SSH_X509_CRLF_CERTIFICATE_HOLD)
                    reason_name = "on hold";
                }

              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("OCSP Result: Certificate is %s.", reason_name));

              /* Set revocation starting time. Here we have bug
                 compensation. If revocation time on the response
                 indicates later time than response creation, mark it
                 revoked at the time of response. */
              ssh_ber_time_set_from_unix_time(&revocation_time,
                                              bsr->status.statusinfo.revoked.
                                              revocation_time);
              ssh_ber_time_set_from_unix_time(&tmp, update_time);

              if (ssh_ber_time_cmp(&revocation_time, &tmp) > 0)
                ssh_ber_time_set(&revocation_time, &tmp);

              if (reason == SSH_X509_CRLF_CERTIFICATE_HOLD)
                {
                  search->subject->status = SSH_CM_VS_HOLD;
                  ssh_ber_time_set(&search->subject->crl_recompute_after,
                                   &next_update);
                  ssh_ber_time_set(&search->subject->ocsp_valid_not_after,
                                   &next_update);
                }
              else
                {
                  search->subject->status = SSH_CM_VS_REVOKED;
                  ssh_ber_time_set(&search->subject->ocsp_valid_not_after,
                                   &revocation_time);
                }
              search->subject->not_checked_against_crl = FALSE;
            }
          else
            {
              /* We could not analyze the certificate at all. We leave
                 it to others to decide what to do. */
              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("OCSP Result: Certificate is unknown."));
              search->context->end_cert->ocsp_mode = SSH_CM_OCSP_NO_OCSP;
            }
        }
    }
  else
    {
      /* This situation indicates that the search did not succeed. What we
         must do now is to free the search and start again. */
    }

  search->completed = TRUE;

  /* Register a timeout, this will cause all the searches to continue
     at some later point in time. */
  if (!search->context->cm->control_timeout_active)
    {
      search->context->cm->control_timeout_active = TRUE;
      ssh_register_timeout(&search->context->cm->control_timeout,
                           search->context->cm->config->timeout_seconds,
                           search->context->cm->config->timeout_microseconds,
                           ssh_cm_timeout_control, search->context->cm);
    }

  /* Search will be freed after this returns. */
  return SSH_CM_MAP_STATE_FREE;
}

static SshCMOcspSearch
cm_ocsp_search_create(SshCMOcspServer server,
                      const unsigned char *url,
                      SshCMCertificate issuer,
                      SshCMCertificate subject,
                      SshCMSearchContext *search)
{
  SshCMOcspSearch osearch;
#ifdef SSHDIST_VALIDATOR_HTTP
  unsigned char buf[16], i;
#endif /* SSHDIST_VALIDATOR_HTTP */

  if ((osearch = ssh_calloc(1, sizeof(*osearch))) != NULL)
    {
#ifdef SSHDIST_VALIDATOR_HTTP
      if (!(server->flags & SSH_CM_OCSP_RESPONDER_OMIT_REQUEST_NONCE))
        {
          osearch->nonce = ssh_mprz_malloc();
          if (osearch->nonce == NULL)
            {
              ssh_free(osearch);
              return NULL;
            }
          for (i = 0; i < sizeof(buf); i++) buf[i] = ssh_random_get_byte();
          ssh_mprz_set_buf(osearch->nonce, buf, sizeof(buf));
        }
#endif /* SSHDIST_VALIDATOR_HTTP */
      osearch->response = NULL;
      osearch->context = search;

      osearch->issuer = issuer;
      ssh_cm_cert_take_reference(issuer);

      osearch->subject = subject;
      ssh_cm_cert_take_reference(subject);

      osearch->url = ssh_strdup(url);
      osearch->server = server;
      osearch->handle = NULL;
      osearch->hash_algorithm = server->hash_algorithm;
      osearch->requestor_public_key_id = server->public_key_info;
      osearch->send = ssh_time();
      osearch->completed = FALSE;
      osearch->cm = search->cm;
    }
  return osearch;
}

static void
cm_ocsp_search_destroy(SshCMOcspSearch search)
{
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing OCSP search."));

  if (search->nonce)
    {
      if ((handle =
           ssh_adt_get_handle_to_equal(search->server->current_searches,
                                       search)) != SSH_ADT_INVALID)
        {
          ssh_adt_detach(search->server->current_searches, handle);
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("OCSP Free; expected to find search from container "
                     "but did not!"));
          return;
        }
    }

  search->refcount--;
  if (search->refcount > 0)
    return;

#ifdef SSHDIST_VALIDATOR_HTTP
  if (search->response)
    {
      ssh_ocsp_response_free(search->response);
      search->response = NULL;
    }
#endif /* SSHDIST_VALIDATOR_HTTP */

  if (ssh_adt_num_objects(search->server->current_searches) == 0)
    {
      if (search->cm->config->access_callback)
        (*search->cm->config->access_callback)(FALSE,
                                               search->server->name,
                                               search->server->port,
                                               NULL_FNPTR, NULL,
                                               search->cm->config
                                               ->access_callback_context);
    }

  ssh_free(search->url);
  ssh_cm_cert_remove_reference(search->subject);
  ssh_cm_cert_remove_reference(search->issuer);
  ssh_mprz_free(search->nonce);
  ssh_free(search);
}

void ssh_cm_ocsp_operation_free(void *context,
                                void *search_context)
{
  SshCMOcspSearch search = search_context;

  if (search->handle)
    {
      ssh_operation_abort(search->handle);
      search->handle = NULL;
    }
  cm_ocsp_search_destroy(search);
}

void ssh_cm_ocsp_operation_free_op(SshCMMap map,
                                   void *context,
                                   void *ob_context)
{
  SshCMOcspSearch search = context;

  ssh_cm_ocsp_operation_free(context, search);
}

SshCMMapState ssh_cm_ocsp_operation_state(SshCMMap map,
                                          void    *context,
                                          void    *ob_context)
{
  SshCMOcspSearch search = context;

  if (search->completed)
    return SSH_CM_MAP_STATE_FREE;
  else
    return SSH_CM_MAP_STATE_KEEP;
}

void ssh_cm_ocsp_operation_free_ob(SshCMMap map,
                                   void *ob_context)
{
  SshCMSearchContext *ctx = ob_context;

  ctx->ocsp_op_locator = 0;
}

const SshCMMapOp ssh_cm_ocsp_operation_table =
{
  ssh_cm_ocsp_operation_state,
  ssh_cm_ocsp_operation_invoke,
  ssh_cm_ocsp_operation_free_ob,
  ssh_cm_ocsp_operation_free_op
};

void ssh_cm_ocsp_operation_add_ob(SshCMContext cm,
                                  SshCMSearchContext *context)
{
  SSH_DEBUG(SSH_D_UNCOMMON, ("ssh_cm_ocsp_operation_add_ob"));
  context->ocsp_op_locator = ssh_cm_map_add_ob(cm->op_map,
                                               &ssh_cm_ocsp_operation_table,
                                               context);
}

Boolean ssh_cm_ocsp_operation_remove_ob(SshCMContext cm,
                                        SshCMSearchContext *context)
{
  Boolean rv;
  SSH_DEBUG(SSH_D_UNCOMMON, ("ssh_cm_ocsp_operation_remove_ob."));
  if (context->ocsp_op_locator == 0)
    return TRUE;

  rv = ssh_cm_map_remove_ob(cm->op_map,
                            context->ocsp_op_locator);
  context->ocsp_op_locator = 0;
  return rv;
}

unsigned char *ssh_cm_ocsp_operation_name(SshCMCertificate issuer,
                                          SshCMCertificate subject,
                                          char unsigned *url,
                                          char *hash_algorithm,
                                          SshCMOcspKeyID key_id,
                                          size_t *name_length)
{
  unsigned char *buf;
  size_t buf_len = 10;

  if ((buf = ssh_calloc(1, buf_len)) != NULL)
    {
      if (hash_search_info(subject, issuer, url, hash_algorithm, key_id,
                           buf, buf_len))
        *name_length = buf_len;
      else
        {
          ssh_free(buf); buf = NULL;
          *name_length = 0;
        }
    }
  return buf;
}

Boolean ssh_cm_ocsp_operation_check(SshCMSearchContext *context,
                                    SshCMCertificate issuer,
                                    SshCMCertificate subject,
                                    unsigned char *url,
                                    char *hash_algorithm,
                                    SshCMOcspKeyID key_id)
{
  SshCMContext cm = context->cm;
  unsigned char *name;
  size_t         name_length;
  Boolean rv = FALSE;

  if ((name =
       ssh_cm_ocsp_operation_name(issuer, subject, url,
                                  hash_algorithm, key_id,
                                  &name_length))
      != NULL)
    {
      rv = ssh_cm_map_check(cm->op_map, name, name_length);
      ssh_free(name);
    }
  return rv;
}

Boolean ssh_cm_ocsp_operation_link(SshCMSearchContext *context,
                                   SshCMCertificate issuer,
                                   SshCMCertificate subject,
                                   char unsigned *url,
                                   char *hash_algorithm,
                                   SshCMOcspKeyID key_id,
                                   SshCMOcspSearch search)
{
  SshCMContext cm = context->cm;
  unsigned char *name;
  size_t name_length;

  if ((name =
       ssh_cm_ocsp_operation_name(issuer, subject, url,
                                  hash_algorithm, key_id,
                                  &name_length))
      != NULL)
    {
      if (!ssh_cm_map_link_op(cm->op_map,
                              name, name_length,
                              cm->config->op_delay_msecs,
                              context->ocsp_op_locator,
                              search))
        return FALSE;
      else
        {
          return TRUE;
        }
    }
  return FALSE;
}

void ssh_cm_ocsp_operation_msg(SshCMSearchContext *context,
                               SshCMOcspSearch    search,
                               void *result)
{
  SshCMContext cm = context->cm;
  unsigned char *name;
  size_t name_length;

  if ((name =
       ssh_cm_ocsp_operation_name(search->issuer, search->subject,
                                  search->url,
                                  search->hash_algorithm,
                                  search->requestor_public_key_id,
                                  &name_length))
      != NULL)
    {
      ssh_cm_map_invoke(cm->op_map, name, name_length, result);
      ssh_free(name);
    }
}

static void ssh_cm_ocsp_operation_failed(SshCMOcspSearch search)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("OCSP operation failed."));

#ifdef SSHDIST_VALIDATOR_HTTP
  /* The search failed. */
  cm_ocsp_ban_add(search->context->cm,
                  search->issuer, search->subject,
                  search->url, search->hash_algorithm,
                  search->requestor_public_key_id);
#endif /* SSHDIST_VALIDATOR_HTTP */

  /* Send the message. */
  ssh_cm_ocsp_operation_msg(search->context,
                            search,
                            NULL);
}

/***********************************************************/
const SshKeywordStruct ssh_cm_ocsp_response_status[] = {
  { "OK"                                   ,SSH_OCSP_SUCCESSFUL        },
  { "Illegal confirmation request"         ,SSH_OCSP_MALFORMED_REQUEST },
  { "Internal error on the responder side" ,SSH_OCSP_INTERNAL_ERROR    },
  { "Try again later"                      ,SSH_OCSP_TRY_LATER         },
  { "Request must be signed"               ,SSH_OCSP_SIG_REQUIRED      },
  { "Request was not authorized"           ,SSH_OCSP_UNAUTHORIZED      },
  { NULL },
};

/* Responder's signature verified. Examine the result and
   notify CMi somehow. */
static void
cm_ocsp_verification_complete(SshOcspStatus status,
                              void *search_context)
{
  SshCMOcspSearch search = search_context;
  unsigned char *issuer_key_hash = NULL;
  size_t kid_len = 0;
  SshCMOcspSearchResultStruct result;
  Boolean nonce_ok = FALSE;
  char *buf1, *buf2;
  SshOcspResponse response;
  SshOcspBasicSingleResponse responses = NULL, bsr = NULL;
  SshTime produced_at, this_update_seconds, next_update_seconds;
  size_t count = 0, i;
  SshBerTimeStruct this_update, next_update;
#ifdef SSHDIST_VALIDATOR_HTTP
  SshInt64 rrtt = search->recv - search->send;
#endif /* SSHDIST_VALIDATOR_HTTP */

  /* Make the handle as "used". */
  search->handle = NULL;
  search->context->waiting -= 1;

  if (status != SSH_OCSP_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Failed: Response validation failed."));
      ssh_cm_ocsp_operation_failed(search);
      return;
    }
  SSH_DEBUG(SSH_D_HIGHOK, ("Response validation OK."));
  response = search->response;

  produced_at = ssh_ocsp_response_get_production_time(response);

  /* Now check if this response is acceptable for us. This is done
     by 'nonce' and 'produced at' handling. If we have a nonce at
     the response and that matches what we sent we do not need to
     care about the claimed produced at time at the response. */
  if (search->nonce)
    {
      SshX509Attribute extensions;
      SshMPInteger nonce = NULL;

      if ((extensions =
           ssh_ocsp_response_get_extensions(response))
          != NULL)
        nonce = ssh_ocsp_extension_get_nonce(extensions);

      if (!nonce &&
          (search->server->flags & SSH_CM_OCSP_RESPONDER_REQUIRE_NONCE))
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: Response nonce required but not present."));
          ssh_free(responses);
          ssh_cm_ocsp_operation_failed(search);
          return;
        }

      if (nonce && ssh_mprz_cmp(nonce, search->nonce) != 0)
        {
          if (nonce)
            ssh_mprz_free(nonce);
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: Response nonce did not match sent."));
          ssh_free(responses);
          ssh_cm_ocsp_operation_failed(search);
          return;
        }

      if (nonce)
        {
          ssh_mprz_free(nonce);
          nonce_ok = TRUE;

#ifdef SSHDIST_VALIDATOR_HTTP
          /* As the response did contain our nonce, we can now safely
             compensate clock differencies on response times. */
          search->clock_compensation = produced_at - search->send;

          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Nonce OK: clock compensation %ld, rrtt %ld",
                     (unsigned long) search->clock_compensation,
                     (unsigned long) rrtt));
#endif /* SSHDIST_VALIDATOR_HTTP */

        }
      else
        {
          nonce_ok = FALSE;
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Nonce sent, but not present on the response"));
        }
    }

  /* Get single responses. */
  ssh_ocsp_response_get_responses(response, &responses, &count);

  /* We assume that there is at least one single response because we
     requested for one. If there is more, assume the first one is
     relevant. */
  if (count < 1)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Failed: Response didn't contain any results."));
      ssh_cm_ocsp_operation_failed(search);

      if (responses != NULL)
        ssh_free(responses);
      return;
    }

  for (i = 0; i < count; i++)
    {
      bsr = &responses[i];

      /* Check that the response corresponds to the request (serial
         numbers and issuer match) */
      if (ssh_mprz_cmp(&bsr->cert_id.serial_number,
                       &search->subject->cert->serial_number) != 0)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: "
                     "Response serial number did not match requested."));
          continue;
        }

      issuer_key_hash =
        ssh_x509_cert_compute_key_identifier(search->issuer->cert,
                                             bsr->cert_id.hash_algorithm,
                                             &kid_len);

      if (memcmp(issuer_key_hash, bsr->cert_id.issuer_key_hash, kid_len) != 0)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: "
                     "Response issuer key hash did not match requested."));
          ssh_free(issuer_key_hash);
          continue;
        }

      ssh_free(issuer_key_hash);
      break;
    }

  if (i == count)
    {
      ssh_free(responses);
      ssh_cm_ocsp_operation_failed(search);
      return;
    }

  /* Now BSR points to proper single response */

  /* If nonce was not present, check response times against current wall
     clock time (with compensations). */
  if (!nonce_ok)
    {
      /* Produced-at time should be within given delta from current
         wall clock. If it is on PAST beyond this delta, this may be a
         replay, and must be rejected. During future we'll allow
         longer delta. In any case compute clock compensation. */
      if (produced_at <
          (search->send -
           search->context->cm->config->min_ocsp_validity_secs))
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: "
                     "The response produced too far (%ld seconds) at past. "
                     "Rejected as a possible replay. "
                     "Check wall clock time at host computer and at "
                     "validation authority.",
                     (unsigned long) (search->send - produced_at)));
          goto response_times_bad;
        }

      if (produced_at >
          (search->send +
           3 * search->context->cm->config->min_ocsp_validity_secs))
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: "
                     "The response produced too far (%ld seconds) at future. "
                     "Rejected due to problems this may cause on validation. "
                     "Check wall clock time at host computer and at "
                     "validation authority.",
                     (unsigned long) (produced_at - search->send)));
          goto response_times_bad;
        }

#ifdef SSHDIST_VALIDATOR_HTTP
      search->clock_compensation = produced_at - search->send;
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Times OK: clock compensation %ld, rrtt %ld",
                 (unsigned long) search->clock_compensation,
                 (unsigned long) rrtt));
#endif /* SSHDIST_VALIDATOR_HTTP */
    }

  /* Got clock compensation and we know the response is produced
     recently enough. This update gets extra compensation of round
     trip time. */
#ifdef SSHDIST_VALIDATOR_HTTP
  produced_at -= search->clock_compensation;
  this_update_seconds = bsr->this_update - search->clock_compensation - rrtt;
#else /* SSHDIST_VALIDATOR_HTTP */
  this_update_seconds = bsr->this_update;
#endif /* SSHDIST_VALIDATOR_HTTP */

  buf1 = ssh_time_string(produced_at);
  SSH_DEBUG(SSH_D_MIDOK, ("Response produced at: %s", buf1));
  ssh_free(buf1);

  if (bsr->next_update_available)
    {
      next_update_seconds = bsr->next_update - search->clock_compensation;

      buf1 = ssh_time_string(this_update_seconds);
      buf2 = ssh_time_string(next_update_seconds);
      SSH_DEBUG(SSH_D_MIDOK, ("Response valid from %s to %s", buf1, buf2));
      ssh_free(buf2);
      ssh_free(buf1);
    }
  else
    {
      next_update_seconds = 0;

      buf1 = ssh_time_string(this_update_seconds);
      SSH_DEBUG(SSH_D_MIDOK, ("Response valid from %s to undefined", buf1));
      ssh_free(buf1);
    }

  /* 'This_update' and 'next_update' time checks only if there was no
     nonce in the reply. */
  if (!nonce_ok)
    {
      ssh_ber_time_set_from_unix_time(&this_update, this_update_seconds);
      if (ssh_ber_time_cmp(&this_update, &search->context->cur_time) > 0)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: The response does not contain requested "
                     "time %@, coverage starts from %@.",
                     ssh_ber_time_render, &search->context->cur_time,
                     ssh_ber_time_render, &this_update));
          goto response_times_bad;
        }

      /* Check if there's new information available. */
      if (next_update_seconds)
        {
          ssh_ber_time_set_from_unix_time(&next_update, next_update_seconds);
          if (ssh_ber_time_cmp(&next_update, &search->context->cur_time) < 0)
            {
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("OCSP Failed: "
                         "New information should be already available."));
            response_times_bad:
              ssh_free(responses);
              ssh_cm_ocsp_operation_failed(search);
              return;
            }
        }
    }

  /* Set the production time for the result. */
  result.produced_at = produced_at;
  result.single_response = bsr;
  result.response = response;

  /* At this point we know that the response what truly for the
     subject we hoped it to be and the responder information has
     checkout. We can not message to all that the response was
     good. */
  ssh_cm_ocsp_operation_msg(search->context, search, &result);

  /* This should be freed before the above call, but currently
     there is no way to copy single responses. */
  ssh_free(responses);
}


/* Check whether the responder is authorized to sign OCSP responses.
   Responder should be the CA who issued the certificate or delegated
   responder (has to be directly under the CA). */

static Boolean
ssh_cm_ocsp_is_responder_authorized(SshX509Certificate responder,
                                    SshX509Certificate issuer_certificate,
                                    SshX509Certificate issuer_of_resp)
{
  Boolean authorized = FALSE;
  Boolean critical = FALSE;
  SshX509OidList ext_key_usage = NULL;
  unsigned char *resp_kid = NULL;
  unsigned char *issuer_kid = NULL;
  unsigned char *issuer_of_resp_kid = NULL;
  size_t kid_len = 0;

  /* Check if responder = CA. Names are not necessarily unique. */
  /* Is there an easier way to do this. */
  issuer_kid = ssh_x509_cert_compute_key_identifier(issuer_certificate,
                                                    "sha1", &kid_len);

  resp_kid = ssh_x509_cert_compute_key_identifier(responder,
                                                  "sha1", &kid_len);

  if (memcmp(issuer_kid, resp_kid, kid_len) == 0)
    {
      authorized = TRUE;
    }

  if (!authorized)
    {
      /* OK. Responder and issuer are not the same entity. */
      ssh_x509_cert_get_ext_key_usage(responder,
                                      &ext_key_usage, &critical);

      /* Check whether the responder is authorized to respond. It has to
         have an id-kp-ocpsSigning oid in the extended key usage field. */
      for (; ext_key_usage; ext_key_usage = ext_key_usage->next)
        {
          if (strcmp(SSH_OCSP_OID_ID_KP_OCSPSIGNING, ext_key_usage->oid) == 0)
            {
              /* Now, we still have to check that the responder is
                 issued by the same CA who issued the certificate we
                 were originally requesting. */
              issuer_of_resp_kid =
                ssh_x509_cert_compute_key_identifier(issuer_of_resp,
                                                     "sha1", &kid_len);
              if (memcmp(issuer_kid, issuer_of_resp_kid, kid_len) == 0)
                {
                  authorized = TRUE;
                }
              break;
            }
        }
      if (ext_key_usage == NULL)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: ocsp-signing eku missing from responder "
                     "certificate."));
        }
    }

  ssh_free(issuer_kid);
  ssh_free(resp_kid);
  ssh_free(issuer_of_resp_kid);

  return authorized;
}

/* We have hopefully now found the responder certificate. Check if
   the responder is authorized to sign OCSP messages and verify
   the signature in the response. */
static void cm_ocsp_responder_search_done(void *search_context,
                                          SshCMSearchInfo info,
                                          SshCMCertList list)
{
  SshCMOcspSearch search = search_context;
  SshCMContext cm;

  cm = search->context->cm;
  search->context->waiting -= 1;

  if (info->status == SSH_CM_STATUS_OK)
    {
      SshCMCertificate cm_cert = NULL;
      SshCMCertificate cm_issuer = NULL;

      SSH_DEBUG(SSH_D_HIGHOK, ("Responder search OK."));

      /* I've understood that the responder is the last in the list
         and its issuer just before it. */
      cm_cert   = ssh_cm_cert_list_last(list);
      cm_issuer = ssh_cm_cert_list_prev(list);
      if (cm_cert)
        {
          SshOperationHandle tmp_handle = NULL;
          /* Check whether the responder is authorized to sign responses. */
          if (cm_issuer &&
              !ssh_cm_ocsp_is_responder_authorized(cm_cert->cert,
                                                   search->issuer->cert,
                                                   cm_issuer->cert))
            {
              SSH_DEBUG(SSH_D_HIGHSTART, ("Responder not authorized."));
              ssh_cm_ocsp_operation_failed(search);
              ssh_cm_cert_list_free(cm, list);
              return;
            }

          search->context->waiting += 1;
          tmp_handle =
            ssh_ocsp_response_verify_signature(search->response,
                                               cm_cert->cert->
                                               subject_pkey.public_key,
                                               cm_ocsp_verification_complete,
                                               search);

          /* If operation is synchronous, search will be already freed
             when verify signature returns. */
          if (tmp_handle)
            {
              search->handle = tmp_handle;
            }
          else
            {
              ;
            }
        }
      else
        ssh_cm_ocsp_operation_failed(search);
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Responder search done. Status: failed."));
      ssh_cm_ocsp_operation_failed(search);
    }

  ssh_cm_cert_list_free(cm, list);
}

/* We have received the OCSP response. Next, we want to check the
   signature. We need the public key of the responder for that.
   Because we don't have it, we'll search for it. */

static void
cm_ocsp_response_received(SshOcspStatus status,
                          SshHttpResult http_result, /* not used */
                          SshOcspResponse response,
                          void *search_context)
{
  SshCMOcspSearch search = search_context;
  SshOcspResponderIDType id_type = SSH_OCSP_RESPONDER_BY_NAME;
  SshX509Name responder_name = NULL;
  SshCertDBKey *key = NULL;
  SshCMSearchConstraints cm_search = NULL;
  SshCertDBKey *ca_key = NULL;
  SshCMSearchConstraints ca_search = NULL;
  Boolean issuer_is_responder = FALSE;
  SshBerTimeStruct notafter, notbefore;

  /* Certificates added to the response. */
  SshOcspEncodedCert certs = NULL;
  size_t ncerts = 0;
  int index = 0;
  SshCMCertificate resp_cert = NULL;
  SshOcspResponseStatus rstatus;

  /* We start by taking the response into our search context. */
  search->response = response;
  search->handle   = NULL;
  search->recv     = ssh_time();

  /* Did the search succeed? */

  /* What if the get status function returns SSH_OCSP_TRY_LATER?
     Possible solution: the "try later" message may be assumed to mean
     that currently we cannot validate the certificate using this OCSP
     responder. Hence, we just fail and hope that some other means
     exists for validation. It would be theoretically possible to
     somehow store a "hint" that if nothing else succeeds and enough
     time has passed when we exhaust other means then we try this
     again. However, this would lead to very big difficulties and
     perhaps even cycles. */
  if (status != SSH_OCSP_STATUS_OK || response == NULL)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Failed: unable to receive response."));
      ssh_cm_ocsp_operation_failed(search);
      return;
    }

  rstatus = ssh_ocsp_response_get_status(search->response);
  SSH_DEBUG(SSH_D_HIGHOK,
            ("OCSP Response status: %s.",
             ssh_find_keyword_name(ssh_cm_ocsp_response_status, rstatus)));
  if (rstatus != SSH_OCSP_SUCCESSFUL)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Failed: response status indicates failure."));
      ssh_cm_ocsp_operation_failed(search);
      return;
    }

  if (ssh_cm_cert_check_signature_algorithm(
                              search->cm->config,
                              search->response->response.signature_algorithm)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Failed: signature algorithm not allowed."));
      ssh_cm_error_set(search->context,
                       SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                       SSH_CM_ERROR_ALGORITHM_STRENGTH_TOO_WEAK,
                       NULL,
                       NULL);
      ssh_cm_ocsp_operation_failed(search);
      return;
    }

  if (search->server->responder_public_key)
    {
      SshOperationHandle handle;

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Responder public key was specified at the "
                 "local configuration for this OCSP server. "
                 "Trusting blindly to that key instead of "
                 "performing certificate validation!"));

      if (ssh_cm_cert_check_key_length(search->cm->config,
                                       search->server->responder_public_key)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: algorithm set not allowed."));
          ssh_cm_error_set(search->context,
                           SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                           SSH_CM_ERROR_ALGORITHM_STRENGTH_TOO_WEAK,
                           NULL,
                           NULL);
          ssh_cm_ocsp_operation_failed(search);
          return;
        }

      search->context->waiting += 1;
      handle =
        ssh_ocsp_response_verify_signature(search->response,
                                           search->
                                           server->responder_public_key,
                                           cm_ocsp_verification_complete,
                                           search);
      if (handle)
        search->handle = handle;

      return;
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("OCSP response received succesfully. Validating it."));

  /* Get the extra certificates from the response. Certificates can be
     included to make the signature verification process easier. */
  ssh_ocsp_response_get_certs(response, &certs, &ncerts);

  id_type = ssh_ocsp_response_get_responder_id_type(response);
  if (id_type == SSH_OCSP_RESPONDER_BY_NAME)
    {
      unsigned char *der = NULL, *iss_der = NULL, *resp_der = NULL;
      size_t der_len = 0, iss_der_len = 0, resp_der_len = 0, len = 0;
      SshX509Certificate cert = NULL;

      responder_name = ssh_ocsp_response_get_responder_name(response);

      ssh_x509_name_pop_directory_name_der(responder_name, &der, &der_len);

      /* Is responder == issuer */
      ssh_x509_name_pop_der_dn(search->issuer->cert->subject_name,
                               &iss_der, &iss_der_len);
      len = iss_der_len < der_len ? iss_der_len : der_len;

      if (memcmp(der, iss_der, len) == 0)
        issuer_is_responder = TRUE;

      /* Check if the responder cert is sent with the response. */
      for (index = 0; index < ncerts; index++)
        {
          if ((cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) == NULL)
            {
              /* out of memory, stop searching. */
              index = ncerts;
              break;
            }

          /* Decode certificate first. */
          if (ssh_x509_cert_decode(certs[index].ber, certs[index].ber_len,
                                   cert)
              == SSH_X509_OK)
            {
              if (ssh_cm_cert_check_allowed_algorithms(search->cm->config,
                                                        cert)
                   == FALSE)
                {
                  SSH_DEBUG(SSH_D_NETFAULT,
                            ("OCSP Failed: algorithm set not allowed."));
                  ssh_cm_error_set(
                          search->context,
                          SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                          SSH_CM_ERROR_CERT_ALGORITHM_STRENGTH_TOO_WEAK,
                          NULL,
                          NULL);
                  ssh_cm_ocsp_operation_failed(search);
                  ssh_x509_cert_free(cert);
                  ssh_free(der);
                  ssh_free(iss_der);
                  ssh_free(certs);
                  certs = NULL;
                  return;
                }

              /* Get name and compare it to the responder's name der. */
              ssh_x509_name_pop_der_dn(cert->subject_name,
                                       &resp_der, &resp_der_len);
              len = resp_der_len < der_len ? resp_der_len : der_len;

              /* If match, stop searching. */
              if (memcmp(der, resp_der, len) == 0)
                {
                  ssh_x509_cert_free(cert);
                  ssh_free(resp_der);
                  break;
                }
              ssh_free(resp_der);
            }
          ssh_x509_cert_free(cert);
        }

      /* Responder cert not found. Use the name as a search key. */
      if (index == ncerts)
        ssh_cm_key_set_dn(&key, der, der_len);

      ssh_free(der);
      ssh_free(iss_der);
    }
  else
    {
      size_t kid_len = 0, resp_kid_len = 0, p_len;
      unsigned char *issuer_kid = NULL, *resp_kid = NULL;
      const unsigned char *p;
      unsigned char *key_hash = NULL;
      SshX509Certificate cert = NULL;

      p = ssh_ocsp_response_get_responder_key(response, &p_len);
      if ((key_hash = ssh_memdup(p, p_len)) == NULL)
        {
          ssh_free(certs);
          return;
        }

      /* Is responder == issuer */
      issuer_kid =
        ssh_x509_cert_compute_key_identifier(search->issuer->cert,
                                             "sha1",
                                             &kid_len);
      if (issuer_kid != NULL)
        {
          if (memcmp(key_hash, issuer_kid, kid_len) == 0)
            issuer_is_responder = TRUE;
        }

      /* Check if the responder cert is sent with the response. */
      for (index = 0; index < ncerts; index++)
        {
          if ((cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) == NULL)
            {
              index = ncerts;
              break;
            }

          /* Decode certificate first. */
          if (ssh_x509_cert_decode(certs[index].ber,
                                   certs[index].ber_len, cert)
              == SSH_X509_OK)
            {
              if (ssh_cm_cert_check_allowed_algorithms(search->cm->config,
                                                        cert)
                   == FALSE)
                {
                  SSH_DEBUG(SSH_D_NETFAULT,
                            ("OCSP Failed: algorithm set not allowed."));
                  ssh_cm_error_set(
                          search->context,
                          SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                          SSH_CM_ERROR_CERT_ALGORITHM_STRENGTH_TOO_WEAK,
                          NULL,
                          NULL);
                  ssh_cm_ocsp_operation_failed(search);
                  ssh_x509_cert_free(cert);
                  ssh_free(issuer_kid);
                  ssh_free(key_hash);
                  ssh_free(certs);
                  certs = NULL;
                  return;
                }
              /* Get name and compare it to the responder's key id. */
              resp_kid = ssh_x509_cert_compute_key_identifier(cert,
                                                              "sha1",
                                                              &resp_kid_len);
              /* If match, stop searching. */
              if (memcmp(resp_kid, key_hash, resp_kid_len) == 0)
                {
                  ssh_x509_cert_free(cert);
                  ssh_free(resp_kid);
                  break;
                }
              ssh_free(resp_kid);
            }
          ssh_x509_cert_free(cert);
        }
      /* Responder cert not found. Use the name as a search key. */
      if (index == ncerts)
        /* Push the public key digest to the key list. */
        ssh_certdb_key_push(&key, SSH_CM_KEY_TYPE_X509_KEY_IDENTIFIER,
                            key_hash, 20, FALSE);
      else
        ssh_free(key_hash);

      ssh_free(issuer_kid);
    }

  /* Check if responder certificate found. */
  if (index < ncerts)
    {
      resp_cert = ssh_cm_cert_allocate(search->context->cm);
      if (resp_cert == NULL ||
          ssh_cm_cert_set_ber(resp_cert,
                              certs[index].ber, certs[index].ber_len)
          != SSH_CM_STATUS_OK)
        {
          if (resp_cert) ssh_cm_cert_free(resp_cert);

          SSH_DEBUG(SSH_D_NETFAULT,
                    ("OCSP Failed: Can't decode certificate found from the "
                     "response. This is not fatal but may cause problems "
                     "on response signature validation."));
        }
      else
        {
          SshCMStatus status = SSH_CM_STATUS_OK;

          SSH_DEBUG(SSH_D_HIGHOK,
                    ("OCSP Responder certificate found from the response."));
          status = ssh_cm_add(resp_cert);
          if (status != SSH_CM_STATUS_OK &&
              status != SSH_CM_STATUS_ALREADY_EXISTS)
            {
              ssh_cm_cert_free(resp_cert);
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("OCSP: Could not add responder certificate. "
                         "This may cause problems on response signature "
                         "validation."));
            }
          else
            {
              /* Everything OK. Let's use the cache id as a search key. */
              ssh_cm_key_set_cache_id(&key,
                                      ssh_cm_cert_get_cache_id(resp_cert));
              if (status == SSH_CM_STATUS_ALREADY_EXISTS)
                {
                  ssh_cm_cert_free(resp_cert);
                }
            }
        }
    }

  /* Free extra certs. */
  ssh_free(certs);
  certs = NULL;

  ssh_ber_time_set_from_unix_time(&notbefore, (ssh_time() - 10));
  ssh_ber_time_set_from_unix_time(&notafter,  (ssh_time() + 10));

  /* Allocate and set the search constraints. */
  if ((cm_search = ssh_cm_search_allocate()) == NULL)
    {
      ssh_cm_ocsp_operation_failed(search);
      return;
    }

  /* Change the search constraints so that the OCSP is not used. */
  ssh_cm_search_set_ocsp_vs_crl(cm_search, SSH_CM_OCSP_NO_END_ENTITY_OCSP);
  ssh_cm_search_set_keys(cm_search, key);
  ssh_cm_search_set_time(cm_search, &notbefore, &notafter);

  /* Here we really should check that responder certificate has
     ocsp-no-check extension to disable responder certificate
     revocation checking, but we've run into too many ocsp responders
     not having this extension and not providing revocation
     information, thus we assume all ocsp responders are
     short-lived. */
  ssh_cm_search_check_revocation(cm_search, FALSE);

  if (issuer_is_responder)
    {
      /* Let's find the issuer certificate. */
      search->context->waiting += 1;
      if (ssh_cm_find(search->context->cm,
                      cm_search,
                      cm_ocsp_responder_search_done,
                      search) == SSH_CM_STATUS_FAILURE)
        search->context->waiting -= 1;
    }
  else
    {
      ssh_cm_key_set_cache_id(&ca_key,
                              ssh_cm_cert_get_cache_id(search->issuer));







      if ((ca_search = ssh_cm_search_allocate()) == NULL)
        {
          ssh_cm_ocsp_operation_failed(search);
          return;
        }

      ssh_cm_search_check_revocation(ca_search, FALSE);
      ssh_cm_search_set_keys(ca_search, ca_key);

      /* Start searching. */
      search->context->waiting += 1;
      if (ssh_cm_find_path(search->context->cm,
                           ca_search,
                           cm_search,
                           cm_ocsp_responder_search_done,
                           search) == SSH_CM_STATUS_FAILURE)
        search->context->waiting -= 1;
    }
}

#ifdef SSHDIST_VALIDATOR_HTTP

typedef struct SshCMOcspConnectEstablishRec
{
  SshFSMThreadStruct thread[1];
  SshOperationHandle application_op;
  SshOperationHandle op;

  SshCMOcspServer server;
  SshHttpClientContext client;
  unsigned char *url;
  SshOcspRequest request;
  SshPrivateKey private_key;

  SshCMOcspSearch search;

  SshOcspHttpCB callback;
  void *callback_context;
} *SshCMOcspConnectEstablish, SshCMOcspConnectEstablishStruct;

static SSH_FSM_STEP(cm_ocsp_ce_request_port);
static SSH_FSM_STEP(cm_ocsp_ce_send_request);
static SSH_FSM_STEP(cm_ocsp_ce_failed);

static void
cm_ocsp_ce_request_port_done(Boolean success, void *context)
{
  SshCMOcspConnectEstablish ce = context;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Application responded to port-open: %s",
             success ? "OK" : "DENIED"));
  if (!success)
    ssh_fsm_set_next(ce->thread, cm_ocsp_ce_failed);

  ce->application_op = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ce->thread);
}

static SSH_FSM_STEP(cm_ocsp_ce_request_port)
{
  SshCMContext cm = fsm_context;
  SshCMOcspConnectEstablish ce = thread_context;
  unsigned char *authority, *name, *port;

  SSH_FSM_SET_NEXT(cm_ocsp_ce_send_request);

  if (cm->config->access_callback)
    {
      port = name = NULL;

      if (ssh_url_parse_get(ce->url,
                            NULL, &authority, NULL, NULL, NULL, TRUE)
          == SSH_URL_OK)
        {
          ssh_url_parse_authority(authority,
                                  NULL, NULL,
                                  &name,
                                  &port);
          ssh_free(authority);
        }

      if (name == NULL)
        {
          SSH_FSM_SET_NEXT(cm_ocsp_ce_failed);
          return SSH_FSM_CONTINUE;
        }

      if (port == NULL)
        port = ssh_strdup("80");

      SSH_FSM_ASYNC_CALL({
        SSH_DEBUG(SSH_D_HIGHSTART, ("Calling Application port callback"));
        ce->application_op =
          (*cm->config->access_callback)(TRUE,
                                         name,
                                         port,
                                         cm_ocsp_ce_request_port_done,
                                         ce,
                                         cm->config->access_callback_context);

        if (ce->server->name)
          ssh_free(name);
        else
          ce->server->name = name;

        if (ce->server->port)
          ssh_free(port);
        else
          ce->server->port = port;
      });
    }
  else
    return SSH_FSM_CONTINUE;
}

static SSH_FSM_STEP(cm_ocsp_ce_send_request)
{
  SshCMContext cm = fsm_context;
  SshCMOcspConnectEstablish ce = thread_context;

  /* Overwrite search handle with the actual OCSP handle now. */
  ce->search->handle =
    ssh_ocsp_http_send_request(ce->request,
                               cm->edb.ocsp.http_context,
                               ce->url,
                               ce->server->requestor_private_key,
                               cm_ocsp_response_received,
                               ce->search);
  return SSH_FSM_FINISH;
}

static SSH_FSM_STEP(cm_ocsp_ce_failed)
{
  SshCMOcspConnectEstablish ce = thread_context;

  ssh_ocsp_request_free(ce->request);
  ce->request = NULL;

  (*ce->callback)(SSH_OCSP_STATUS_HTTP_ERROR,
                  SSH_HTTP_RESULT_CONNECT_FAILED,
                  NULL,
                  ce->callback_context);
  return SSH_FSM_FINISH;
}

static void cm_ocsp_ce_destroy(SshFSM fsm, void *context)
{
  SshCMOcspConnectEstablish ce = context;

  if (ce->op)
  ssh_operation_unregister(ce->op);
  ssh_free(ce->url);
  ssh_free(ce);
}

static void cm_ocsp_ce_abort(void *context)
{
  SshCMOcspConnectEstablish ce = context;

  ce->op = NULL;
  if (ce->application_op)
    ssh_operation_abort(ce->application_op);
  ce->application_op = NULL;
  ssh_fsm_kill_thread(ce->thread);
}

/* Request access for sending 'request' to specified OCSP 'server'
   using HTTP 'client' to contact 'url'. Encode 'request' using the
   given 'private_key'. When the OCSP server responds (or access is
   refused) the 'callback' is called.  */
static SshOperationHandle
cm_ocsp_connect_establish(SshCMContext cm,
                          SshCMOcspSearch search,
                          SshCMOcspServer server,
                          SshHttpClientContext client,
                          unsigned char *url,
                          SshOcspRequest request,
                          const SshPrivateKey private_key,
                          SshOcspHttpCB callback, void *callback_context)
{
  SshCMOcspConnectEstablish ce;

  if ((ce = ssh_calloc(1, sizeof(*ce))) == NULL)
    {
    failed:
      ssh_ocsp_request_free(request);
      (*callback)(SSH_OCSP_STATUS_HTTP_ERROR,
                  SSH_HTTP_RESULT_CONNECT_FAILED,
                  NULL,
                  callback_context);
      return NULL;
    }

  if ((ce->op = ssh_operation_register(cm_ocsp_ce_abort, ce)) != NULL)
    {
      ce->url = ssh_ustrdup(url);
      ce->search = search;
      ce->server = server;
      ce->client = client;
      ce->request = request;
      ce->private_key = private_key;
      ce->callback = callback;
      ce->callback_context = callback_context;

      ssh_fsm_thread_init(cm->fsm,
                          ce->thread,
                          cm_ocsp_ce_request_port, NULL_FNPTR,
                          cm_ocsp_ce_destroy,
                          ce);
    }
  else
    {
      goto failed;
    }

  return ce->op;
}


/* Gets the responder location from the certificate's
   AuthorityInfoAccess extension. */
unsigned char *ssh_cm_ocsp_get_responder_url(SshCMCertificate certificate)
{
  Boolean critical = FALSE;
  SshX509ExtInfoAccess access = NULL;

  if (ssh_x509_cert_get_auth_info_access(certificate->cert, &access,
                                         &critical) == FALSE)
    return NULL;

  while (access && access->access_method)
    {
      if (strcmp(access->access_method, SSH_OCSP_OID_ID_AD_OCSP) == 0)
        {
          SshX509Name name_uri, name;
          name = access->access_location;
          name_uri = ssh_x509_name_find(name, SSH_X509_NAME_URI);
          if (name_uri)
            {
              char *url;
              ssh_x509_name_pop_uri(name_uri, &url);
              ssh_x509_name_reset(name_uri);
              return (unsigned char *)url;
            }
          break;
        }
      access = access->next;
    }
  return NULL;
}

/***********************************************************/

SshCMStatus cm_ocsp_http_search(SshCMSearchContext *context,
                                SshCMOcspServer     server,
                                SshCMCertificate    issuer,
                                SshCMCertificate    subject)
{
  unsigned char *url = NULL;
  SshCMOcspSearch search;
  SshOcspRequest request = NULL;
  SshOperationHandle handle = NULL;
  SshMPInteger serial_number;
  SshX509Attribute extensions = NULL;

  /* Does the server parameters allow us to do the operation? */
  if (server->cache_id &&
      server->cache_id != ssh_cm_cert_get_cache_id(issuer))
    return SSH_CM_STATUS_FAILURE;

  /* Now test whether we get the URL from the parameters or from the
     subject. */
  if (server->responder_url == NULL)
    {
      /* Attempt first to obtain the responder url. */
      url = ssh_cm_ocsp_get_responder_url(subject);
      if (url == NULL)
        return SSH_CM_STATUS_FAILURE;

      /* A simple URL translation. This could be elaborated bit. */
      if (server->url_translate != NULL_FNPTR)
        {
          unsigned char *new_url;

          new_url = (*server->url_translate)(url);
          ssh_free(url);
          url = new_url;
        }
    }
  else
    url = ssh_ustrdup(server->responder_url);

  /* At this point we know quite a lot already. Let us test the negative
     cache. */
  if (url &&
      cm_ocsp_ban_check(context->cm, issuer, subject,
                        url, server->hash_algorithm,
                        server->public_key_info))
    {
      /* Apparently we have failed with this OCSP server lately. Let
         us not bother it again this soon. */
#ifdef DEBUG_LIGHT
      char *buf;
      buf = ssh_mprz_get_str(&subject->cert->serial_number, 10);
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Failed: The request was found in the nega cache."));
      SSH_DEBUG(SSH_D_UNCOMMON, ("URL: %s, serial: %s, hash: %s", url, buf,
        server->hash_algorithm));
      ssh_free(buf);
      if (server->public_key_info)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Requestor identifier: "),
                            server->public_key_info->kid,
                            server->public_key_info->kid_len);
        }
      else
        {
          SSH_DEBUG(SSH_D_UNCOMMON, ("No requestor key identifier."));
        }
#endif /* DEBUG_LIGHT */
      ssh_free(url);
      return SSH_CM_STATUS_FAILURE;
    }

  /* We are now content with the situation and want to allocate a
     search context for the OCSP search attempt. */

  if ((search = cm_ocsp_search_create(server, url,
                                      issuer, subject, context)) == NULL)
    {
      ssh_free(url);
      return SSH_CM_STATUS_FAILURE;
    }

  /* The server must be not removed from the list while the search is
     running as it is not reference counted and thus the response
     manipulation will then crash the system. */

  /* Check if we had ongoing operation for the same object. */
  if (ssh_cm_ocsp_operation_check(context, issuer, subject, url,
                                  server->hash_algorithm,
                                  server->public_key_info))
    {
      if (context->end_cert->ocsp_mode == SSH_CM_OCSP_NO_END_ENTITY_OCSP)
        {
          cm_ocsp_search_destroy(search);
          ssh_free(url);
          return SSH_CM_STATUS_FAILURE;
        }

      if (!ssh_cm_ocsp_operation_link(context, issuer, subject, url,
                                      server->hash_algorithm,
                                      server->public_key_info,
                                      search))
        {
          ssh_cm_ocsp_operation_failed(search);
          ssh_free(url);
          return SSH_CM_STATUS_FAILURE;
        }
      ssh_free(url);

      /* We are waiting for an answer, even though we are just one a
         free ride and don't do the work ourselves. */
      context->waiting++;
      ssh_adt_insert(server->current_searches, search);
      search->refcount++;
      return SSH_CM_STATUS_SEARCHING;
    }

  /* No pending operation, we are going to start a new search. */
  if (!ssh_cm_ocsp_operation_link(context, issuer, subject, url,
                                  server->hash_algorithm,
                                  server->public_key_info,
                                  search))
    {
      ssh_cm_ocsp_operation_failed(search);
      ssh_free(url);
      return SSH_CM_STATUS_FAILURE;
    }

  /* Create request. */
  if ((serial_number = ssh_mprz_malloc()) == NULL ||
      !ssh_x509_cert_get_serial_number(subject->cert, serial_number))
    goto request_failed;

  extensions = NULL;
  if (!(server->flags & SSH_CM_OCSP_RESPONDER_OMIT_REQUEST_NONCE))
    {
      if ((extensions = ssh_malloc(sizeof(*extensions))) == NULL)
        {
        request_failed:
          ssh_cm_ocsp_operation_failed(search);
          ssh_mprz_free(serial_number);
          ssh_free(extensions);
          ssh_free(url);
          return SSH_CM_STATUS_FAILURE;
        }
      if (!ssh_ocsp_extension_create_nonce(extensions, search->nonce))
        {
          ssh_free(extensions);
          extensions = NULL;
        }
    }

  handle = NULL;
  if ((request = ssh_ocsp_request_allocate(SSH_OCSP_VERSION_V1,
                                           server->requestor_name,
                                           extensions)) != NULL)
    {
      ssh_ocsp_request_add_single(request,
                                  server->hash_algorithm,
                                  issuer->cert,
                                  serial_number,
                                  NULL);

      ssh_mprz_free(serial_number);

      handle = cm_ocsp_connect_establish(context->cm,
                                         search, server,
                                         context->cm->edb.ocsp.http_context,
                                         url,
                                         request,
                                         server->requestor_private_key,
                                         cm_ocsp_response_received, search);
      context->waiting++;
      ssh_adt_insert(server->current_searches, search);
      search->refcount++;
    }
  else
    {
      ssh_cm_ocsp_operation_failed(search);
    }
  ssh_free(url);

  if (handle == NULL)
    return SSH_CM_STATUS_FAILURE;

  search->handle = handle;
  return SSH_CM_STATUS_SEARCHING;
}
#else /* SSHDIST_VALIDATOR_HTTP */

/* Fill */
Boolean
ssh_cm_ocsp_add_response(SshCMContext cm,
                         const unsigned char *response_data,
                         size_t response_data_size)
{
  SshOcspResponse response = NULL;
  SshCMOcspLocalEntry centry = NULL;
  size_t ncerts, i, nbsrs;
  SshOcspBasicSingleResponse bsrs;
  SshOcspEncodedCert certs;

  if (ssh_ocsp_response_decode(response_data, response_data_size, &response)
      == SSH_OCSP_SUCCESSFUL)
    {
      if (ssh_ocsp_response_get_response_type(response)
          != SSH_OCSP_RESPONSE_TYPE_BASIC)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unknown OCSP response type"));
          goto failed;
        }

      /* Add extra certs from response into the cache. */
      ssh_ocsp_response_get_certs(response, &certs, &ncerts);
      for (i = 0; i < ncerts; i++)
        {
          SshCMCertificate cmcert;

          if ((cmcert = ssh_cm_cert_allocate(cm)) != NULL)
            {
              ssh_cm_cert_set_ber(cmcert, certs[i].ber, certs[i].ber_len);
              ssh_cm_add(cmcert);
            }
        }
      if (ncerts) ssh_free(certs);

      /* Keep track of responses added */
      ssh_glist_add_item(cm->edb.ocsp.all_responses, response, SSH_GLIST_TAIL);

      /* Store responses */
      ssh_ocsp_response_get_responses(response, &bsrs, &nbsrs);
      for (i = 0; i < nbsrs; i++)
        {
          if ((centry = ssh_calloc(1, sizeof(*centry))) != NULL)
            {
              centry->id = bsrs[i].cert_id;
              centry->response_entry = i;
              centry->response = response;
              ssh_adt_insert(cm->edb.ocsp.responses, centry);
            }
        }
      if (nbsrs) ssh_free(bsrs);
    }
  return TRUE;

 failed:
  ssh_free(centry);
  ssh_ocsp_response_free(response);
  return FALSE;
}

SshCMStatus cm_ocsp_local_search(SshCMSearchContext *search,
                                 SshCMOcspServer     server,
                                 SshCMCertificate    issuer,
                                 SshCMCertificate    subject)
{
  SshCMOcspLocalEntryStruct probe, *entry;
  SshCMOcspSearch osearch;
  SshADTHandle handle;

  if (search->cm->edb.ocsp.responses)
    {
      memset(&probe, 0, sizeof(probe));

      /* Set serial of subject and a) issuer name hash b) issuer
         subject public key hash */

      ssh_mprz_init_set(&probe.id.serial_number,
                        &subject->cert->serial_number);

      /* a) */
      if ((handle =
           ssh_adt_get_handle_to_equal(search->cm->edb.ocsp.responses, &probe))
          == SSH_ADT_INVALID)
        {
          /* b) */
          if ((handle =
               ssh_adt_get_handle_to_equal(search->cm->edb.ocsp.responses,
                                           &probe))
              == SSH_ADT_INVALID)
            {
              goto failed;
            }
        }

      entry = ssh_adt_get(search->cm->edb.ocsp.responses, handle);

      if ((osearch =
           cm_ocsp_search_create(server, NULL, issuer, subject, search))
          != NULL)
        {

          if (!ssh_cm_ocsp_operation_link(search, issuer, subject, NULL,
                                          server->hash_algorithm,
                                          server->public_key_info,
                                          osearch))
            {
              ssh_cm_ocsp_operation_failed(osearch);
              return SSH_CM_STATUS_FAILURE;
            }
          search->waiting++;

          osearch->entry = entry;
          cm_ocsp_response_received(SSH_OCSP_STATUS_OK,
                                    entry->response,
                                    osearch);
          return SSH_CM_STATUS_SEARCHING;
        }
    }

 failed:
  return SSH_CM_STATUS_FAILURE;
}

#endif /* SSHDIST_VALIDATOR_HTTP */

/* The entry point to the code in this file from certificate manager.
   This one tries all known means of finding a suitable OCSP service
   that can give revocation information about the subject
   certificate. */
SshCMStatus
ssh_cm_ocsp_check_status(SshCMSearchContext *context,
                         SshCMCertificate subject,
                         SshCMCertificate issuer)
{
  unsigned char *issuer_kid = NULL;
  size_t issuer_kid_len = 0;
  SshGListNode node;

#ifdef DEBUG_LIGHT
  char *buf;
  buf = ssh_mprz_get_str(&subject->cert->serial_number, 10);
  SSH_DEBUG(SSH_D_HIGHSTART, ("Cert serial number: %s", buf));
  ssh_free(buf);
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Checking a certificate status via OCSP."));


#ifdef SSHDIST_VALIDATOR_HTTP
  if (context->cm->edb.ocsp.http_context == NULL)
    {
      if (!ssh_cm_edb_ocsp_init(context->cm))
        {
          return SSH_CM_STATUS_FAILURE;
        }
    }
#endif /* SSHDIST_VALIDATOR_HTTP */

  /* Get the issuer key identifier so that we can check if the server may
     respond for this query (if the server has its ca key identifier
     information available. */

  issuer_kid =
    ssh_x509_cert_compute_key_identifier(issuer->cert, "sha1",
                                         &issuer_kid_len);

  if (context->cm->edb.ocsp.servers->head == NULL)
    ssh_cm_edb_ocsp_add_responder(context->cm,
                                  NULL, NULL, NULL,
                                  "sha1", NULL, 0,
                                  NULL, 0,
                                  context->cm->config->min_ocsp_validity_secs,
                                  context->cm->config->ocsp_responder_flags);

  for (node = context->cm->edb.ocsp.servers->head; node; node = node->next)
    {
      SshCMOcspServer server = node->data;
      SshGListNode node = NULL;
      Boolean allowed = TRUE;

      if (server == NULL)
        {
          /* Possibly a bug in the code. */
          continue;
        }

      /* Check if the issuer info match. */
      for (node = server->ca_kid_list->head; node; node = node->next)
        {
          SshCMOcspKeyID ca = node->data;
          size_t len =
            issuer_kid_len < ca->kid_len ? issuer_kid_len : ca->kid_len;

          allowed = FALSE;

          if (memcmp(issuer_kid, ca->kid, len) == 0)
            {
              allowed = TRUE;
              break;
            }
        }

      if (!allowed)
        {
          continue;
        }

      /* Start a search now, if possible. */
      switch (
#ifdef SSHDIST_VALIDATOR_HTTP
              cm_ocsp_http_search(context, server, issuer, subject)
#else /* SSHDIST_VALIDATOR_HTTP */
              cm_ocsp_local_search(context, server, issuer, subject)
#endif /* SSHDIST_VALIDATOR_HTTP */
              )
        {
        case SSH_CM_STATUS_FAILURE:
          continue;

        case SSH_CM_STATUS_SEARCHING:
          ssh_free(issuer_kid);
          return SSH_CM_STATUS_SEARCHING;

        default:
          ssh_free(issuer_kid);
          return SSH_CM_STATUS_FAILURE;
        }
    }

  ssh_free(issuer_kid);
  return SSH_CM_STATUS_FAILURE;
}


/***********************************************************/

Boolean ssh_cm_ocsp_init(SshCMOcsp *ocsp)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Initializing OCSP data structures."));
  if ((ocsp->servers = ssh_glist_allocate()) == NULL)
    return FALSE;
#ifdef SSHDIST_VALIDATOR_HTTP
  ocsp->http_context = NULL;
#else /* SSHDIST_VALIDATOR_HTTP */
  ocsp->responses = NULL;
#endif /* SSHDIST_VALIDATOR_HTTP */
  ocsp->next_id = 1;
  return TRUE;
}

/* Free the glist. */
static void free_ca_kid_list_item(SshGListNode node, void *context)
{
    SshCMOcspKeyID key = node->data;

    ssh_free(key->kid);
    ssh_free(key);
}

static void free_key_id(SshCMOcspKeyID key_id)
{
  if (key_id)
    {
      ssh_free(key_id->kid);
      key_id->kid = NULL;
      ssh_free(key_id);
    }
}

void ssh_cm_ocsp_free_responder(SshCMOcspServer server)
{
  SshADTHandle handle, next;

  ssh_free(server->responder_url);
  ssh_free(server->name); ssh_free(server->port);

  if (server->requestor_name)
    ssh_x509_name_free(server->requestor_name);

  if (server->requestor_private_key)
    ssh_private_key_free(server->requestor_private_key);

  ssh_free(server->hash_algorithm);
  free_key_id(server->public_key_info);
  ssh_free(server->unique_id);

  ssh_glist_free_with_iterator(server->ca_kid_list,
                               free_ca_kid_list_item,
                               NULL);

  if (server->responder_public_key)
    ssh_public_key_free(server->responder_public_key);

  for (handle = ssh_adt_enumerate_start(server->current_searches);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      SshCMOcspSearch search;
      next = ssh_adt_enumerate_next(server->current_searches, handle);
      search = ssh_adt_get(server->current_searches, handle);
      search->completed = TRUE;
      ssh_cm_ocsp_operation_msg(search->context, search, NULL);
    }

  ssh_adt_destroy(server->current_searches);
  ssh_free(server);
}

#ifndef SSHDIST_VALIDATOR_HTTP
static void cm_ocsp_glist_all_responses_free(SshGListNode node, void *context)
{
  SshOcspResponse response = node->data;
  ssh_ocsp_response_free(response);
}
#endif /* SSHDIST_VALIDATOR_HTTP */

void ssh_cm_ocsp_stop(SshCMOcsp *ocsp)
{
  SshGListNode gnode;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Stopping OCSP"));

  for (gnode = ocsp->servers->head; gnode; gnode = gnode->next)
    {
      SshCMOcspServer server = gnode->data;
      SshADTHandle handle, next;
      SshCMOcspSearch search;

      for (handle = ssh_adt_enumerate_start(server->current_searches);
           handle != SSH_ADT_INVALID;
           handle = next)
        {
          next = ssh_adt_enumerate_next(server->current_searches, handle);
          search = ssh_adt_get(server->current_searches, handle);
          search->context->waiting -= 1;
          search->completed = TRUE;
          ssh_cm_ocsp_operation_free(NULL, search);
        }
    }
#ifdef SSHDIST_VALIDATOR_HTTP
  if (ocsp->http_context)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Stopping HTTP client."));
      ssh_http_client_uninit(ocsp->http_context);
      ocsp->http_context = NULL;
    }
#endif /* SSHDIST_VALIDATOR_HTTP */
}

void ssh_cm_ocsp_free(SshCMOcsp *ocsp)
{
  SshGListNode node;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Freeing OCSP."));

  /* Stop it in case application does not perform ssh_cm_stop for us. */
  ssh_cm_ocsp_stop(ocsp);

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing OCSP responders."));
  for (node = ocsp->servers->head; node; node = node->next)
    {
      SshCMOcspServer server = node->data;

      ssh_cm_ocsp_free_responder(server);
    }
#ifndef SSHDIST_VALIDATOR_HTTP
  if (ocsp->responses)
    ssh_adt_destroy(ocsp->responses);
  if (ocsp->all_responses)
    ssh_glist_free_with_iterator(ocsp->all_responses,
                                 cm_ocsp_glist_all_responses_free, NULL);
#endif /* SSHDIST_VALIDATOR_HTTP */

  ssh_glist_free(ocsp->servers);
  ocsp->servers = NULL;
}


/* This interface contains the magic token 'edb'. This is because we
   want to inherit the local network information from EDB, and thus is
   it logical to use same naming convention.

   However, OCSP uses somewhat different approach and thus does not
   fall directly beneath the EDB stuff. */

Boolean ssh_cm_edb_ocsp_init(SshCMContext cm)
{
#ifdef SSHDIST_VALIDATOR_HTTP
  SshHttpClientParams params;
  SshCMLocalNetwork net;

  SSH_DEBUG(SSH_D_MIDOK, ("Initializing OCSP and creating a HTTP client."));

  /* If version 1.1 is used, only first request work when Valicert's
     responder is used. Using version 1.0 seems to fix the problem. */

  net = ssh_cm_edb_get_local_network(cm);

  memset(&params, 0, sizeof(params));
  if (net->socks) params.socks = net->socks;
  if (net->proxy) params.http_proxy_url = net->proxy;
  params.use_http_1_0 = TRUE;
  params.tcp_connect_timeout = cm->config->tcp_connect_timeout;

  cm->edb.ocsp.http_context = ssh_http_client_init(&params);

  /* Check whether we succeeded in our goal. */
  if (cm->edb.ocsp.http_context == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Could not create OCSP client."));
      return FALSE;
    }
#else /* SSHDIST_VALIDATOR_HTTP */

  cm->edb.ocsp.all_responses = ssh_glist_allocate();
  cm->edb.ocsp.responses =
    ssh_adt_create_generic(SSH_ADT_MAP,
                           SSH_ADT_HASH,    cm_ocsp_local_entry_hash,
                           SSH_ADT_COMPARE, cm_ocsp_local_entry_compare,
                           SSH_ADT_DESTROY, cm_ocsp_local_entry_destroy,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshCMOcspLocalEntryStruct,
                                             adt_header),
                           SSH_ADT_ARGS_END);
#endif /* SSHDIST_VALIDATOR_HTTP */
  return TRUE;
}

/* Calculate hash for the responder info. */
static Boolean hash_responder_info(SshX509Name     requestor_name,
                                   SshCMOcspKeyID  public_key,
                                   const unsigned char *responder_url,
                                   const char      *hash_algorithm,
                                   unsigned char   *ret_digest,
                                   size_t          ret_digest_len)
{
  SshHash hash = NULL;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t key_digest_length = 0;
  char *name = NULL;

  if (ssh_hash_allocate(hash_algorithm, &hash) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Warning: %s is not a valid hash algorithm.",
                 hash_algorithm));
      return FALSE;
    }
  /* Compute the hash. */
  ssh_hash_reset(hash);
  ssh_x509_name_pop_directory_name(requestor_name, &name);
  ssh_x509_name_reset(requestor_name);

  if (name)
    {
      ssh_hash_update(hash, (unsigned char *)name, strlen(name));
      ssh_free(name);
    }

  if (responder_url)
    ssh_hash_update(hash,
                   responder_url, ssh_ustrlen(responder_url));

  if (public_key)
    ssh_hash_update(hash, public_key->kid, public_key->kid_len);

  ssh_hash_final(hash, digest);

  /* Copy the digest length. */
  key_digest_length = ssh_hash_digest_length(ssh_hash_name(hash));

  /* Free the hash algorithm. */
  ssh_hash_free(hash);

  if (key_digest_length < ret_digest_len)
    {
      memset(ret_digest, 0, ret_digest_len);
      memcpy(ret_digest, digest, key_digest_length);
    }
  else
    memcpy(ret_digest, digest, ret_digest_len);

  return TRUE;
}

unsigned int
ssh_cm_edb_ocsp_add_responder(SshCMContext cm,
                              /* Who asks */
                              SshX509Name requestor_name,
                              SshPrivateKey requestor_private_key,
                              const unsigned char *responder_url,
                              /* Optionally, hich CA's this responder
                                 serves. */
                              const char *hash_algorithm,
                              const unsigned char *ca_key_identifier,
                              size_t ca_key_identifier_len,
                              /* Optionally, direct trust to this responder. */
                              const unsigned char *responder_certificate,
                              size_t responder_certificate_len,

                              SshUInt32 recheck_time,
                              SshCMOcspResponderFlags flags)
{
#define SSH_CMI_OCSP_ID_DIGEST_LEN 10
  SshPublicKey requestor_public_key = NULL;
  SshPublicKey responder_public_key = NULL;
  SshCMOcspKeyID public_key_id = NULL;
  SshCMOcspServer server;
  SshCMOcspKeyID ca;
  SshGListNode gnode;
  unsigned char *responder_id = NULL;
  size_t id_len = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Adding a new OCSP responder."));

  id_len = SSH_CMI_OCSP_ID_DIGEST_LEN;
  if ((responder_id = ssh_malloc(id_len)) == NULL)
    return 0;

  if (requestor_private_key)
    if (ssh_private_key_derive_public_key(requestor_private_key,
                                          &requestor_public_key)
        != SSH_CRYPTO_OK)
      requestor_public_key = NULL;

  if (requestor_public_key)
    {
      unsigned char *buf = NULL;
      size_t buf_len = 0;

      if (ssh_cm_key_kid_create(requestor_public_key, FALSE, &buf, &buf_len))
        {
          if ((public_key_id = ssh_malloc(sizeof(*public_key_id)))
              != NULL)
            {
              public_key_id->kid = buf;
              public_key_id->kid_len = buf_len;
            }
          else
            {
              ssh_free(buf);
            }
        }
      /* Public key is not needed any more.*/
      ssh_public_key_free(requestor_public_key);
    }

  if (!hash_responder_info(requestor_name, public_key_id,
                           responder_url, hash_algorithm,
                           responder_id, id_len))
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Couldn't add responder."));

      ssh_x509_name_free(requestor_name);
      if (requestor_private_key)
        ssh_private_key_free(requestor_private_key);
      free_key_id(public_key_id);
      ssh_free(responder_id);
      return 0;
    }

  /* Check whether the same responder has already been inserted.  If
     ca_key_identifier, however, is different, add it to the list (not
     a new responder but a new item in the responder's list of
     CA's) */

  for (gnode = cm->edb.ocsp.servers->head; gnode; gnode = gnode->next)
    {
      SshCMOcspServer tmp_server = gnode->data;

      if (memcmp(tmp_server->unique_id, responder_id, id_len) == 0)
        {
          SshGListNode node = NULL;
          SshCMOcspKeyID new_kid = NULL;

          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Responder with the same URL and requestor info "
                     "already exists."));

          ssh_free(responder_id);

          if (ca_key_identifier == NULL || ca_key_identifier_len == 0)
            {
              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("Cannot add responder, because CA info is empty and "
                         "otherwise identical responder already exists."));

              ssh_x509_name_free(requestor_name);
              if (requestor_private_key)
                ssh_private_key_free(requestor_private_key);
              free_key_id(public_key_id);
              return 0;
            }

          for (node = tmp_server->ca_kid_list->head; node; node = node->next)
            {
              SshCMOcspKeyID kid = node->data;
              size_t len;

              len = kid->kid_len < ca_key_identifier_len ?
                kid->kid_len : ca_key_identifier_len;
              if (memcmp(kid->kid, ca_key_identifier, len) == 0)
                {
                  SSH_DEBUG(SSH_D_HIGHSTART,
                            ("CA with same information already exists."));

                  ssh_x509_name_free(requestor_name);
                  if (requestor_private_key)
                    ssh_private_key_free(requestor_private_key);
                  free_key_id(public_key_id);
                  return 0;
                }
            }

          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Adding a new CA entry for the responder."));

          if ((new_kid = ssh_calloc(1, sizeof(*new_kid))) != NULL &&
              (new_kid->kid = ssh_memdup(ca_key_identifier,
                                         ca_key_identifier_len))
              != NULL)
            {
              new_kid->kid_len = ca_key_identifier_len;
              ssh_glist_add_item(tmp_server->ca_kid_list, new_kid,
                                 SSH_GLIST_TAIL);
            }
          else
            {
              if (new_kid != NULL)
                ssh_free(new_kid);
              new_kid = NULL;
            }
          ssh_x509_name_free(requestor_name);
          if (requestor_private_key)
            ssh_private_key_free(requestor_private_key);
          free_key_id(public_key_id);

          return 0;
        }
    }

  if ((server = ssh_calloc(1, sizeof(*server))) == NULL)
    {
      free_key_id(public_key_id);
      ssh_free(responder_id);
      return 0;
    }

  /* Make container for current searches. */
  if ((server->current_searches =
       ssh_adt_create_generic(SSH_ADT_MAP,
                              SSH_ADT_HASH,    cm_ocsp_search_hash,
                              SSH_ADT_COMPARE, cm_ocsp_search_compare,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshCMOcspSearchStruct,
                                                adt_header),
                              SSH_ADT_CONTEXT, server,
                              SSH_ADT_ARGS_END))
      == NULL)
    {

      free_key_id(public_key_id);
      ssh_free(responder_id);
      ssh_free(server);
      return 0;
    }

  /* Add the CA key identifier info. */
  if ((server->ca_kid_list = ssh_glist_allocate()) == NULL)
    {
      free_key_id(public_key_id);
      ssh_adt_destroy(server->current_searches);
      ssh_free(responder_id);
      ssh_free(server);
      return 0;
    }

  if (ca_key_identifier && ca_key_identifier_len > 0)
    {
      if ((ca = ssh_malloc(sizeof(*ca))) != NULL)
        {
          ca->kid = ssh_memdup(ca_key_identifier, ca_key_identifier_len);
          ca->kid_len = ca_key_identifier_len;
          ssh_glist_add_item(server->ca_kid_list, ca, SSH_GLIST_TAIL);
        }
    }

  if (responder_certificate)
    {
      SshX509Certificate tmp;

      if ((tmp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) != NULL)
        {
          if (ssh_x509_cert_decode(responder_certificate,
                                   responder_certificate_len,
                                   tmp) == SSH_X509_OK)
            (void) ssh_x509_cert_get_public_key(tmp, &responder_public_key);
          ssh_x509_cert_free(tmp);
        }
    }

  server->public_key_info = public_key_id;
  server->id = cm->edb.ocsp.next_id++;
  server->responder_url = (responder_url) ? ssh_ustrdup(responder_url) : NULL;
  server->hash_algorithm = ssh_strdup(hash_algorithm);
  server->requestor_name = requestor_name;
  server->requestor_private_key = requestor_private_key;
  server->unique_id = responder_id;
  server->recheck_time = recheck_time;
  server->flags = flags;
  server->responder_public_key = responder_public_key;

  if ((gnode = ssh_glist_allocate_n(cm->edb.ocsp.servers)) != NULL)
    {
      gnode->data = server;
      ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
      return server->id;
    }

  ssh_cm_ocsp_free_responder(server);
  return 0;
}

void ssh_cm_edb_ocsp_remove_responder(SshCMContext cm,
                                      unsigned int id)
{
  SshGListNode gnode;

  for (gnode = cm->edb.ocsp.servers->head; gnode; gnode = gnode->next)
    {
      SshCMOcspServer server = gnode->data;
      if (server->id == id)
        {
          /* We want to remove this responder. */
          ssh_cm_ocsp_free_responder(server);

          /* Remove from the list. */
          gnode->data = NULL;
          ssh_glist_free_n(gnode);
          return;
        }
    }
}

#endif /* SSHDIST_VALIDATOR_OCSP */
/* cmi-ocsp.c */
#endif /* SSHDIST_CERT */
