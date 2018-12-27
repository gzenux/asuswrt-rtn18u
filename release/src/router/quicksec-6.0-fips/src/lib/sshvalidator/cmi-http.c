/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Validator HTTP backend.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "cmi-edb.h"
#include "cmi-debug.h"
#include "sshurl.h"
#include "sshhttp.h"
#include "sshfsm.h"
#include "sshadt.h"
#include "sshadt_list.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertEdbHttp"

#ifdef SSHDIST_VALIDATOR_HTTP
/* Implementation of the HTTP external database client. */

typedef struct SshCMEdbHttpSearchRec
{
  SshCMSearchDatabase  *db;
  SshCMDBDistinguisher *dg;
  void                 *context;
  unsigned char        *url;
  /* cached from url */
  unsigned char        *host;
  unsigned char        *port;
  SshStream             stream;
  SshBufferStruct       buffer;
  SshOperationHandle    op_handle;
  unsigned long         tc;
  SshCMContext          cm;
  SshADTHeaderStruct    adt_header;
} *SshCMEdbHttpSearch, SshCMEdbHttpSearchStruct;

typedef struct SshCMEdbHttpRec
{
  SshHttpClientContext client;
  SshHttpClientParams *params;

  /* Basically searches should be stored here, but we don't do that
     yet. */
  SshADTContainer      searches;

} *SshCMEdbHttp, SshCMEdbHttpStruct;

void ssh_cm_edb_http_free_search(SshCMEdbHttpSearch search)
{
  if (search->stream)
    ssh_stream_destroy(search->stream);

  ssh_cm_edb_distinguisher_free(search->dg);
  ssh_free(search->url);
  ssh_free(search->host);
  ssh_free(search->port);
  ssh_buffer_uninit(&search->buffer);
  ssh_free(search);
}

void ssh_cm_edb_http_stream_cb(SshStreamNotification notification,
                               void *context)
{
  SshCMEdbHttpSearch search = context;
  int l;
  unsigned char buf[1024];

  while (1)
    {
      l = ssh_stream_read(search->stream, buf, sizeof(buf));
      if (l == 0)
        {
          /* Throw a reply. */
          ssh_cm_edb_reply(search->db, search->context, search->dg,
                           ssh_buffer_ptr(&search->buffer),
                           ssh_buffer_len(&search->buffer));

          if (search->cm->config->access_callback)
            (*search->cm->config->access_callback)(FALSE,
                                                   search->host,
                                                   search->port,
                                                   NULL_FNPTR, NULL,
                                                   search->cm->config
                                                   ->access_callback_context);

          ssh_cm_edb_operation_msg(search->context, search->dg,
                                   search->db->functions->db_identifier,
                                   SSH_CMDB_STATUS_OK);
          return;
        }
      if (l < 0)
        {
          /* Would block. */
          return;
        }

      /* Append the buffer. */
      if ((ssh_buffer_append(&search->buffer, buf, l)) != SSH_BUFFER_OK)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Failed to append data to receive buffer"));
          ssh_stream_destroy(search->stream);
          search->stream = NULL;
          ssh_cm_edb_reply(search->db, search->context, search->dg, NULL, 0);
          return;
        }
    }
}

void ssh_cm_edb_http_result(SshHttpClientContext http_ctx,
                            SshHttpResult        result,
                            SshTcpError          ip_error,
                            SshStream            stream,
                            void                *ctx)
{
  SshCMEdbHttpSearch search = ctx;

  /* In any case mark the http operation as used. */
  search->op_handle = NULL;

  SSH_DEBUG(SSH_D_UNCOMMON, ("BAN: banning the search."));
  ssh_cm_edb_ban_add_ctx(search->context, search->dg,
                         search->db->functions->db_identifier);

  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Error: %s", ssh_http_error_code_to_string(result)));

      if (search->cm->config->access_callback)
        (*search->cm->config->access_callback)(FALSE,
                                               search->host,
                                               search->port,
                                               NULL_FNPTR, NULL,
                                               search->cm->config
                                               ->access_callback_context);

      ssh_cm_edb_operation_msg(search->context,
                               search->dg,
                               search->db->functions->db_identifier,
                               SSH_CMDB_STATUS_FAILED);
    }
  else
    {
      /* Some debugging. */
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Content-type: %s",
                 ssh_http_get_header_field(http_ctx,
                                           (unsigned char *)"content-type")));
      search->stream = stream;
      ssh_stream_set_callback(stream, ssh_cm_edb_http_stream_cb,
                              search);
      ssh_cm_edb_http_stream_cb(SSH_STREAM_INPUT_AVAILABLE, search);
    }

}

void ssh_cm_edb_http_operation_free(void *context,
                                    void *search_context)
{
  SshCMEdbHttpSearch search = search_context;
  SshCMEdbHttp http = search->db->context;

  if (search->op_handle)
    {
      ssh_operation_abort(search->op_handle);
      search->stream = NULL;
    }
  ssh_adt_delete_object(http->searches, search);
  ssh_cm_edb_http_free_search(search);
}

static Boolean is_http(const unsigned char *str)
{
  Boolean rv;
  unsigned char *scheme = NULL;

  if (str == NULL ||
      ssh_url_parse(str, &scheme,
                    NULL, NULL, NULL, NULL, NULL) == FALSE)
    {
      ssh_free(scheme);
      return FALSE;
    }
  rv = (scheme == NULL ? FALSE :
        ssh_usstrcasecmp(scheme, "http") != 0 ? FALSE :
        TRUE);
  ssh_free(scheme);
  return rv;
}

typedef struct SshCMHttpConnectEstablishRec
{
  SshFSMThreadStruct thread[1];
  SshOperationHandle application_op;
  SshOperationHandle op;

  SshHttpClientContext client;
  unsigned char *url;
  SshCMEdbHttpSearch search;

  SshHttpClientResultCb callback;
  void *callback_context;
} *SshCMHttpConnectEstablish, SshCMHttpConnectEstablishStruct;

static SSH_FSM_STEP(cm_http_ce_request_port);
static SSH_FSM_STEP(cm_http_ce_send_request);
static SSH_FSM_STEP(cm_http_ce_failed);

static void
cm_http_ce_request_port_done(Boolean success, void *context)
{
  SshCMHttpConnectEstablish ce = context;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Application responded to port-open: %s",
             success ? "OK" : "DENIED"));
  if (!success)
    ssh_fsm_set_next(ce->thread, cm_http_ce_failed);

  ce->application_op = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ce->thread);
}

static SSH_FSM_STEP(cm_http_ce_request_port)
{
  SshCMContext cm = fsm_context;
  SshCMHttpConnectEstablish ce = thread_context;
  unsigned char *authority;

  ce->search->host = NULL;
  ce->search->port = NULL;

  if (ssh_url_parse_get(ce->url,
                        NULL, &authority, NULL, NULL, NULL, TRUE)
      == SSH_URL_OK)
    {
      ssh_url_parse_authority(authority,
                              NULL, NULL,
                              &ce->search->host,
                              &ce->search->port);
      ssh_free(authority);
    }

  if (ce->search->host == NULL)
    {
      SSH_FSM_SET_NEXT(cm_http_ce_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(cm_http_ce_send_request);

  if (ce->search->port == NULL)
    ce->search->port = ssh_strdup("80");

  if (cm->config->access_callback)
    SSH_FSM_ASYNC_CALL({
        SSH_DEBUG(SSH_D_HIGHSTART, ("Calling Application port callback"));
        ce->application_op =
          (*cm->config->access_callback)(TRUE,
                                         ce->search->host,
                                         ce->search->port,
                                         cm_http_ce_request_port_done,
                                         ce,
                                         cm->config->access_callback_context);
      });
  else
    return SSH_FSM_CONTINUE;
}

static SSH_FSM_STEP(cm_http_ce_send_request)
{
  SshCMHttpConnectEstablish ce = thread_context;

  /* Overwrite search handle with the actual HTTP handle now. */
  ce->search->op_handle =
    ssh_http_get(ce->client,
                 ce->url,
                 ce->callback, ce->callback_context,
                 SSH_HTTP_HDR_END);

  ssh_operation_unregister(ce->op);
  return SSH_FSM_FINISH;
}

static SSH_FSM_STEP(cm_http_ce_failed)
{
  SshCMHttpConnectEstablish ce = thread_context;

  ce->search->op_handle = NULL;

  (*ce->callback)(ce->client,
                  SSH_HTTP_RESULT_CONNECT_FAILED,
                  SSH_TCP_REFUSED,
                  NULL,
                  ce->callback_context);

  ssh_operation_unregister(ce->op);
  return SSH_FSM_FINISH;
}

static void cm_http_ce_destroy(SshFSM fsm, void *context)
{
  SshCMHttpConnectEstablish ce = context;

  ssh_free(ce->url);
  ssh_free(ce);
}

static void cm_http_ce_abort(void *context)
{
  SshCMHttpConnectEstablish ce = context;

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
cm_http_connect_establish(SshCMContext cm,
                          SshHttpClientContext client,
                          SshCMEdbHttpSearch search,
                          const unsigned char *url,
                          SshHttpClientResultCb callback,
                          void *callback_context)
{
  SshCMHttpConnectEstablish ce;

  ce = ssh_calloc(1, sizeof(*ce));
  if (ce == NULL)
    goto failed;

  ce->op = ssh_operation_register(cm_http_ce_abort, ce);
  if (ce->op == NULL)
    goto failed;

  ce->url = ssh_strdup(url);
  if (ce->url == NULL)
    goto failed;

  ce->client = client;
  ce->search = search;
  ce->callback = callback;
  ce->callback_context = callback_context;

  ssh_fsm_thread_init(cm->fsm,
                      ce->thread,
                      cm_http_ce_request_port, NULL_FNPTR,
                      cm_http_ce_destroy,
                      ce);
  return ce->op;

 failed:
  if (ce != NULL)
    {
      if (ce->url != NULL)
        ssh_free(ce->url);
      if (ce->op != NULL)
        ssh_operation_unregister(ce->op);
      ssh_free(ce);
    }
  return NULL;
}


SshCMSearchMode ssh_cm_edb_http_search(SshCMSearchDatabase  *db,
                                       SshCMContext          cm,
                                       void                 *context,
                                       SshCMDBDistinguisher *dg)
{
  SshCMEdbHttp http_ctx = db->context;
  SshCMEdbHttpSearch search;
  unsigned char *url;

  /* Check that the key suggested is really an URL. */
  if (dg->key_type != SSH_CM_KEY_TYPE_URI)
    return SSH_CM_SMODE_FAILED;

  /* Allocate the http client. */
  if (http_ctx->client == NULL)
    {
      http_ctx->client = ssh_http_client_init(http_ctx->params);
      if (http_ctx->client == NULL)
        return SSH_CM_SMODE_FAILED;
    }

  /* Generate suitable search string. */
  url = ssh_memdup(dg->key, dg->key_length);
  if (!is_http(url))
    {
      ssh_free(url);
      return SSH_CM_SMODE_FAILED;
    }

  /* Check for a ban. */
  if (ssh_cm_edb_ban_check(cm, dg, db->functions->db_identifier) == TRUE)
    {
      ssh_free(url);
      return SSH_CM_SMODE_FAILED;
    }

  /* Allocate search context. */
  search = ssh_calloc(1, sizeof(*search));
  if (search == NULL)
    {
      ssh_free(url);
      return SSH_CM_SMODE_FAILED;
    }

  search->db        = db;
  search->dg        = dg;
  ssh_cm_edb_distinguisher_lock(dg);
  search->context   = context;
  search->url       = url;
  search->stream    = NULL;
  search->op_handle = NULL;
  search->tc        = 0;
  search->cm        = cm;

  /* Allocate the buffer. */
  ssh_buffer_init(&search->buffer);

  ssh_adt_insert(http_ctx->searches, search);

  /* Determine whether there is a search already for the same
     data. */
  if (ssh_cm_edb_operation_check(context, dg,
                                 db->functions->db_identifier) == TRUE)
    {
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Http search already exists for '%s', waiting "
                 "for it to terminate.", url));

      /* Currently there is an on-going search. We will attach to it. */
      if (ssh_cm_edb_operation_link(context,
                                    dg, db, db->functions->db_identifier,
                                    ssh_cm_edb_http_operation_free,
                                    search) == FALSE)
        goto error;

      /* Simple initialization. */
      ssh_cm_edb_mark_search_init_start(db, context, dg);
      ssh_cm_edb_mark_search_init_end  (db, context, dg, FALSE);
      return SSH_CM_SMODE_SEARCH;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Http search of '%s'.", url));

  ssh_cm_edb_mark_search_init_start(search->db, search->context, search->dg);

  /* We don't know whether the URL is valid, or whether it is even
     a string, however, hopefully the http client code checks these. */

  search->op_handle = cm_http_connect_establish(cm,
                                                http_ctx->client,
                                                search,
                                                url,
                                                ssh_cm_edb_http_result,
                                                search);

  /* Check if http connect failed synchronously. */
  if (search->op_handle == NULL)
    {
      ssh_cm_edb_mark_search_init_end(db, context, dg, TRUE);
      goto error;
    }

  /* Register time control for the search function. */
  if (ssh_cm_edb_operation_link(context,
                                dg, db, db->functions->db_identifier,
                                ssh_cm_edb_http_operation_free,
                                search) == FALSE)
    {
      ssh_cm_edb_mark_search_init_end(db, context, dg, TRUE);
      goto error;
    }

  /* Search was started successfully. */
  ssh_cm_edb_mark_search_init_end(db, context, dg, FALSE);
  return SSH_CM_SMODE_SEARCH;

 error:
  if (search->op_handle != NULL)
    ssh_operation_abort(search->op_handle);
  ssh_adt_delete_object(http_ctx->searches, search);
  ssh_cm_edb_http_free_search(search);
  return SSH_CM_SMODE_FAILED;
}

void ssh_cm_edb_http_free(SshCMSearchDatabase *db)
{
  SshCMEdbHttp context = db->context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Freeing HTTP"));

  /* Simply free the client. */
  if (context->client)
    ssh_http_client_uninit(context->client);
  context->client = NULL;

  if (context->searches)
    ssh_adt_destroy(context->searches);
  context->searches = NULL;

  /* Free the params. */
  ssh_free(context->params->socks);
  ssh_free(context->params->http_proxy_url);
  ssh_free(context->params);
  ssh_free(context);
}

void ssh_cm_edb_http_stop(SshCMSearchDatabase *db)
{
  SshCMEdbHttp context = db->context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Stopping HTTP"));

  if (context->client)
    ssh_http_client_uninit(context->client);
  context->client = NULL;

  /* Signal the searches. This will abort the operations. */
  if (context->searches)
    {
      SshADTHandle h;
      while ((h =
              ssh_adt_enumerate_start(context->searches))
             != SSH_ADT_INVALID)
        {
          SshCMEdbHttpSearch search = ssh_adt_get(context->searches, h);

          ssh_operation_abort(search->op_handle);
          search->op_handle = NULL;

          ssh_cm_edb_operation_msg(search->context, search->dg,
                                   search->db->functions->db_identifier,
                                   SSH_CMDB_STATUS_FAILED);
        }
    }
}

const SshCMSearchFunctionsStruct ssh_cm_edb_http_functions =
{
  "ssh.http", SSH_CM_SCLASS_SERVER,
  ssh_cm_edb_http_search,
  ssh_cm_edb_http_stop,
  ssh_cm_edb_http_free
};

int
cm_http_search_compare(const void *object1,
                           const void *object2,
                           void *context)
{
  SshCMEdbHttpSearch c1 = (SshCMEdbHttpSearch) object1;
  SshCMEdbHttpSearch c2 = (SshCMEdbHttpSearch) object2;

  return c1 == c2 ? 0 : 1;
}

Boolean ssh_cm_edb_http_init(SshCMContext cm)
{
  SshCMEdbHttp context;
  SshCMLocalNetwork net;

  if (ssh_cm_edb_lookup_database(cm,
                                 ssh_cm_edb_http_functions.db_identifier))
    return TRUE;

  /* Allocate the context for the method. */
  if ((context = ssh_malloc(sizeof(*context))) == NULL)
    return FALSE;

  /* Create parameters. */
  if ((context->params = ssh_calloc(1, sizeof(*context->params))) == NULL)
    {
      ssh_free(context);
      return FALSE;
    }

  /* Take the local net. */
  net = ssh_cm_edb_get_local_network(cm);

  /* Make a copy. */
  if (net->socks)
    {
      if ((context->params->socks = ssh_strdup(net->socks)) == NULL)
        goto fail;
    }
  if (net->proxy)
    {
      if ((context->params->http_proxy_url = ssh_strdup(net->proxy)) == NULL)
        goto fail;
    }

  context->params->tcp_connect_timeout = cm->config->tcp_connect_timeout;

  /* Ignore user_name and password for now. We also let the http code
     to use defauls here, it may be later productive to add
     configurability for that too. Perhaps even take the http params
     directly (although that loses the help of local network
     information, which isn't that much of a loss). */

  context->client = NULL;

  context->searches =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_COMPARE, cm_http_search_compare,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshCMEdbHttpSearchStruct,
                                             adt_header),
                           SSH_ADT_ARGS_END);

  /* Basically we are now done. */
  if (!ssh_cm_edb_add_database(cm, &ssh_cm_edb_http_functions, context))
    {
    fail:
      if (context->searches)
        ssh_adt_destroy(context->searches);
      ssh_free(context->params->socks);
      ssh_free(context->params->http_proxy_url);
      ssh_free(context->params);
      ssh_free(context);
      return FALSE;
    }
  return TRUE;
}
#endif /* SSHDIST_VALIDATOR_HTTP */

/* cmi-http.c */
#endif /* SSHDIST_CERT */
