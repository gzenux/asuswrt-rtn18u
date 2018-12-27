/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate validator; LDAP external database for retrieving CRL's
   and Certificates.
*/

#include "sshincludes.h"

#include "cmi.h"
#include "cmi-edb.h"
#include "cmi-debug.h"
#include "cmi-internal.h"

#include "sshurl.h"
#include "sshdsprintf.h"
#include "sshglist.h"
#include "sshldap.h"
#include "sshtimeouts.h"

#include "sshadt.h"
#include "sshadt_map.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertEdbLdap"

#ifdef SSHDIST_VALIDATOR_LDAP

typedef enum {
  LDAP_NOT_CONNECTED,
  LDAP_CONNECTING,
  LDAP_CONNECTED
} SshCMEdbLdapConnectionState;

typedef struct
{
  /* Concrete header, concrete object model for ADT. */
  SshADTMapHeaderStruct adt_header;

  unsigned char *identifier;
  SshLdapClientParams  params;
  SshLdapClient context;
  SshCMEdbLdapConnectionState state;

  unsigned char *ldap_server_name;
  unsigned char *ldap_server_port;
  unsigned char *bind_name; size_t bind_name_len;
  unsigned char *password; size_t password_len;

  int idle;
} *SshCMEdbLdapConnection, SshCMEdbLdapConnectionStruct;

typedef struct
{
  SshCMSearchDatabase    *db;
  SshCMDBDistinguisher   *dg;
  SshCMEdbLdapConnection  connection;
  void                   *context;
  char                   *object_name;
  SshLdapSearchFilter     filter;
  unsigned int            counter;
  SshOperationHandle      msg_id;
  unsigned long           tc;
  Boolean                 use_old_connection;
} *SshCMEdbLdapSearch, SshCMEdbLdapSearchStruct;

typedef struct
{
  SshCMContext cm;
  SshADTContainer map;
  SshTimeoutStruct timeout;
} *SshCMEdbLdap, SshCMEdbLdapStruct;


static void cm_edb_ldap_timeout(void *context);

SshUInt32
cm_ldap_connection_hash(const void *object, void *context)
{
  SshCMEdbLdapConnection conn = (SshCMEdbLdapConnection) object;
  SshUInt32 hash = 0;
  const unsigned char *c = conn->identifier;

  while (*c)
    {
      hash += *c++;
      hash += hash << 10;
      hash ^= hash >> 6;
    }

  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

int
cm_ldap_connection_compare(const void *object1,
                           const void *object2,
                           void *context)
{
  SshCMEdbLdapConnection c1 = (SshCMEdbLdapConnection) object1;
  SshCMEdbLdapConnection c2 = (SshCMEdbLdapConnection) object2;

  return ssh_ustrcmp(c1->identifier, c2->identifier);
}


static void
cm_ldap_connection_destroy(SshCMEdbLdapConnection connection, void *context)
{
  if (connection->context)
    ssh_ldap_client_destroy(connection->context);

  ssh_free(connection->ldap_server_name);
  ssh_free(connection->ldap_server_port);
  ssh_free(connection->bind_name);
  ssh_free(connection->password);
  ssh_free(connection->params->socks);
  ssh_free(connection->params);
  ssh_free(connection->identifier);
  ssh_free(connection);
}

/* Note, this function stores everything. Hence, it may not be very
   memory friendly. Most of the information about LDAP could be freed
   immediately after initialization.

   This steals server, bind_name and password. */
static SshCMEdbLdapConnection
cm_ldap_connection_create(SshCMContext cm,
                          SshCMLocalNetwork net,
                          unsigned char *server,
                          unsigned char *bind_name, unsigned char *password)
{
  SshCMEdbLdapConnection connection = ssh_calloc(1, sizeof(*connection));
  unsigned char *host, *port;

  if (connection == NULL)
    return NULL;

  /* Allocate the params space. */
  connection->params = ssh_calloc(1, sizeof(*connection->params));
  if (connection->params == NULL)
    {
      ssh_free(connection);
      return NULL;
    }

  connection->state        = LDAP_NOT_CONNECTED;

  /* Parse the server name. */
  if (ssh_url_parse(server, NULL, &host, &port, NULL, NULL, NULL))
    {
      connection->ldap_server_name = host;
      connection->ldap_server_port = port;
    }
  else
    {
      ssh_free(connection->params);
      ssh_free(connection);
      return NULL;
    }

  if (bind_name)
    {
      connection->bind_name = bind_name;
      connection->bind_name_len = ssh_ustrlen(bind_name);
    }
  if (password)
    {
      connection->password = password;
      connection->password_len = ssh_ustrlen(password);
    }

  if (net->socks)
    {
      connection->params->socks = ssh_strdup(net->socks);
    }

  connection->params->version = SSH_LDAP_VERSION_3;
  connection->params->response_bytelimit =
    cm->config->max_ldap_response_length;
  connection->params->tcp_connect_timeout = cm->config->tcp_connect_timeout;

  /* Initialize the LDAP client. */
  connection->context = ssh_ldap_client_create(connection->params);
  if (connection->context == NULL)
    {
      cm_ldap_connection_destroy(connection, NULL);
      return NULL;
    }

  /* Store the server also. */
  connection->identifier = server;
  return connection;
}

static void
cm_edb_ldap_reply(SshLdapClient ldap_ctx,
                  SshLdapObject object,
                  void *ctx)
{
  SshCMEdbLdapSearch search = ctx;
  int i, j;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Ldap reply callback reached (%s, %u attributes).",
             search->connection->identifier,
             object->number_of_attributes));

  for (i = 0; i < object->number_of_attributes; i++)
    {
      for (j = 0; j < object->attributes[i].number_of_values; j++)
        {
          search->counter++;
          ssh_cm_edb_reply(search->db, search->context, search->dg,
                           (const unsigned char *)
                           object->attributes[i].values[j],
                           object->attributes[i].value_lens[j]);
        }
    }
  SSH_DEBUG(SSH_D_HIGHOK, ("Ldap reply ends."));
  ssh_ldap_free_object(object);
}

static void
cm_edb_ldap_result(SshLdapClient ldap_ctx,
                   SshLdapResult result,
                   const SshLdapResultInfo info,
                   void *ctx)
{
  SshCMEdbLdapSearch search = ctx;
  SshCMDBStatus status;

  if (result == SSH_LDAP_RESULT_SUCCESS
      && info != NULL && info->error_message == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB/LDAP: Search for %@ [OK].",
                 ssh_cm_edb_distinguisher_render, search->dg));

      /* If the result set was empty, consider is as failure (not
         found) */
      if (search->counter)
        status = SSH_CMDB_STATUS_OK;
      else
        status = SSH_CMDB_STATUS_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("EDB/LDAP: Search for %@ [FAILED]: %s. %s",
                 ssh_cm_edb_distinguisher_render, search->dg,
                 ssh_find_keyword_name(ssh_ldap_error_keywords, result),
                 info ? (char *) info->error_message : ""));

      /* If connection got closed, store this information so that we
         can restart later. */
      if (result == SSH_LDAP_RESULT_ABORTED ||
          result == SSH_LDAP_RESULT_DISCONNECTED)
        {
          /* This call is safe */
          ssh_ldap_client_disconnect(search->connection->context);
          status = SSH_CMDB_STATUS_DISCONNECTED;
          search->connection->state = LDAP_NOT_CONNECTED;
        }
      else
        status = SSH_CMDB_STATUS_FAILED;
    }

  /* If we got indication about closed connection, and were reusing an
     existing one, do not ban the exact search, else do */
  if (!(search->use_old_connection && result == SSH_LDAP_RESULT_DISCONNECTED))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("EDB/LDAP: banning the exact search for a while."));

      ssh_cm_edb_ban_add_ctx(search->context, search->dg,
                             ssh_csstr(search->connection->identifier));
    }

  /* Reset idle timer */
  search->connection->idle = 0;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Signalling waiters, search 0x%p LDAP operation 0x%p",
             search, search->msg_id));

  search->msg_id = NULL;
  ssh_cm_edb_operation_msg(search->context, search->dg,
                           ssh_csstr(search->connection->identifier),
                           status);
}

static void cm_ldap_search_free(SshCMEdbLdapSearch search)
{
  if (search != NULL)
    {
      if (search->filter != NULL)
        ssh_ldap_free_filter(search->filter);
      ssh_free(search->object_name);
      ssh_free(search);
    }
}

void ssh_cm_edb_ldap_operation_free(void *context,
                                    void *search_context)
{
  SshCMEdbLdapSearch search = search_context;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Freeing LDAP search 0x%p for %s", search, search->object_name));

  if (search->msg_id)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("-> Aborting LDAP operation 0x%p", search->msg_id));
      ssh_operation_abort(search->msg_id);
      search->msg_id = NULL;
    }

  cm_ldap_search_free(search);
}

typedef struct SshCMEdbLdapConnectionEstRec {
  SshCMEdbLdapConnection connection;
  SshCMEdbLdapSearch search;
  SshLdapSearchScope ldap_scope;
  int attribute_cnt;
  size_t *attribute_len_table;
  unsigned char **attribute_table;
  unsigned char *attribute_data;
  SshCMEdbLdap ldap;

  SshFSMThreadStruct thread[1];
  SshOperationHandle op;
  SshOperationHandle application_op;

  Boolean access_ok;
} *SshCMEdbLdapConnectionEst;


static Boolean
cm_edb_ldap_start_search(SshCMEdbLdapConnectionEst ce)
{
  SshCMEdbLdapConnection connection = ce->connection;
  SshCMEdbLdapSearch search = ce->search;
  SshOperationHandle op_handle;

  SSH_DEBUG(SSH_D_MIDOK, ("Starting LDAP search for %s", search->object_name));

  op_handle = ssh_ldap_client_search(connection->context, search->object_name,
                                     ce->ldap_scope,
                                     SSH_LDAP_DEREF_ALIASES_NEVER,
                                     0, 0, FALSE, search->filter,
                                     ce->attribute_cnt,
                                     ce->attribute_table,
                                     ce->attribute_len_table,
                                     cm_edb_ldap_reply,  search,
                                     cm_edb_ldap_result, search);
  if (op_handle == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Failed to start ldap search"));
      return FALSE;
    }

  search->msg_id = op_handle;
  return TRUE;
}

static void
cm_edb_ldap_connect_cb(SshLdapClient client,
                       SshLdapResult result,
                       const SshLdapResultInfo info,
                       void *callback_context)
{
  SshCMEdbLdapConnectionEst ce = callback_context;
  SshCMEdbLdapConnection connection = ce->connection;
  SshCMEdbLdapSearch search = ce->search;
  SshCMEdbLdap ldap = ce->ldap;

  search->msg_id = NULL;
  if (result == SSH_LDAP_RESULT_SUCCESS)
    {
      /* Info is only set when call comes from the LDAP
         library. Validator calls this without info being set (if
         deciding to reuse this client connection. */
      if (info)
        {
          connection->state = LDAP_CONNECTED;

          if (ldap->cm->config->ldap_connection_idle_timeout != 0)
            /* Start open connection tracker */
            ssh_register_timeout(&ldap->timeout,
                                 10L, 0L,
                                 cm_edb_ldap_timeout, ldap);
        }

      /* Mark connection as active */
      connection->idle = 0;

      /* Start the search */
      cm_edb_ldap_start_search(ce);
    }
  else
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("Can't connect to server '%s'; %s(%d) for search %s: %s.",
                 connection->identifier,
                 ssh_find_keyword_name(ssh_ldap_error_keywords, result),
                 result,
                 search->object_name,
                 info->error_message));

      cm_edb_ldap_result(connection->context, result, info, search);
      connection->state = LDAP_NOT_CONNECTED;
    }
}

static void
cm_ldap_connect_establish_free(Boolean aborted, void *context)
{
  SshCMEdbLdapConnectionEst ce = context;

  if (aborted)
    ce->connection->state = LDAP_NOT_CONNECTED;

  if (ce->op)
    ssh_operation_unregister(ce->op);

  ssh_free(ce->attribute_table);
  ssh_free(ce->attribute_len_table);
  ssh_free(ce->attribute_data);
  ssh_free(ce);
}

static SSH_FSM_STEP(cm_ldap_ce_request_port);
static SSH_FSM_STEP(cm_ldap_ce_connect_and_bind);
static SSH_FSM_STEP(cm_ldap_ce_failed);

static void
cm_ldap_ce_request_port_done(Boolean success, void *context)
{
  SshCMEdbLdapConnectionEst ce = context;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Application responded to port-open: %s",
             success ? "OK" : "DENIED"));
  if (!success)
    ssh_fsm_set_next(ce->thread, cm_ldap_ce_failed);

  ce->application_op = NULL;
  ce->access_ok = success;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ce->thread);
}

static SSH_FSM_STEP(cm_ldap_ce_request_port)
{
  SshCMContext cm = fsm_context;
  SshCMEdbLdapConnectionEst ce = thread_context;

  SSH_FSM_SET_NEXT(cm_ldap_ce_connect_and_bind);

  if (cm->config->access_callback)
    SSH_FSM_ASYNC_CALL({
      SSH_DEBUG(SSH_D_HIGHSTART, ("Calling Application port callback"));
      ce->application_op =
        (*cm->config->access_callback)(TRUE,
                                       ce->connection->ldap_server_name,
                                       ce->connection->ldap_server_port,
                                       cm_ldap_ce_request_port_done,
                                       ce,
                                       cm->config->access_callback_context);
    });
  else
    {
      ce->access_ok = TRUE;
      return SSH_FSM_CONTINUE;
    }
}

static SSH_FSM_STEP(cm_ldap_ce_connect_and_bind)
{
  SshCMEdbLdapConnectionEst ce = thread_context;
  SshCMEdbLdapConnection connection = ce->connection;

  /* Now start LDAP operations */
  SSH_DEBUG(SSH_D_HIGHSTART, ("LDAP connect after successful port open"));
  ce->search->msg_id =
    ssh_ldap_client_connect_and_bind(connection->context,
                                     connection->ldap_server_name,
                                     connection->ldap_server_port,
                                     NULL_FNPTR,
                                     connection->bind_name,
                                     connection->bind_name_len,
                                     connection->password,
                                     connection->password_len,
                                     cm_edb_ldap_connect_cb,
                                     ce);

  ssh_operation_attach_destructor(ce->search->msg_id,
                                  cm_ldap_connect_establish_free,
                                  ce);
  return SSH_FSM_FINISH;
}

static SSH_FSM_STEP(cm_ldap_ce_failed)
{
  SshCMEdbLdapConnectionEst ce = thread_context;

  SSH_DEBUG(SSH_D_FAIL,
            ("LDAP signals search failure after application port denial"));
  cm_edb_ldap_result(ce->connection->context,
                     SSH_LDAP_RESULT_UNAVAILABLE, NULL,
                     ce->search);
  return SSH_FSM_FINISH;
}

static void cm_ldap_ce_destroy(SshFSM fsm, void *context)
{
  SshCMEdbLdapConnectionEst ce = context;

  if (ce->access_ok)
    return;
  cm_ldap_connect_establish_free(TRUE, ce);
}

static void cm_ldap_ce_abort(void *context)
{
  SshCMEdbLdapConnectionEst ce = context;

  /* Clear operation handle, since it is freed after this callback returns. */
  ce->op = NULL;

  ssh_operation_abort(ce->application_op);
  ce->application_op = NULL;
  /* kill will call the destructor, freeing 'ce' */
  ssh_fsm_uninit_thread(ce->thread);
}

static SshOperationHandle
cm_ldap_connect_establish(SshCMContext cm,
                          SshCMEdbLdapConnectionEst ce)
{
  ce->op = ssh_operation_register(cm_ldap_ce_abort, ce);
  if (ce->op == NULL)
    return NULL;

  ce->access_ok = FALSE;
  ssh_fsm_thread_init(cm->fsm,
                      ce->thread,
                      cm_ldap_ce_request_port, NULL_FNPTR,
                      cm_ldap_ce_destroy,
                      ce);
  return ce->op;
}


#define SSH_CM_LDAP_SEARCH_FILTER "(objectclass=*)"

Boolean ssh_cm_edb_ldap_add(SshCMContext cm,
                            const unsigned char *default_servers);


/** This function is called by the external database (edb) layer to
    perform search of object described by queyr distinguisher from
    some ldap database. The object may be either a certificate of
    certificate revocation list (dg->key_type).

    The distinguisher may be either name of object, or a LDAP URL
    pointing to location of object. Names are used if a) we are
    looking for a certificate with this name from the application, or
    b) certificate to be verified either contains b.1) a DN or
    relative DN to CDP, or b.2) does not contain CDP. URL comes from
    URI-type CDP or Info-Access extension.

    If name is given, the name is looked from all the configured LDAP
    directories known by the system (ldap->map). If URL is given and
    contains host portion, only that host is consulted (unless
    banned).

    This function will cache the open TCP connections to LDAP
    servers. This behaviour can be changed from CM configuration
    parameter ldap_connection_idle_timeout. If a connection is open,
    it is used (and if write to that fails, it gets closed). If there
    is no connection, external firewall callback is called to allow
    connection, and when that is open, LDAP connect, bind and search
    are performed.


    Search operation concludes into call to cm_edb_ldap_result on this
    file, and that function propagates the resulting objects to the
    EDB. */

SshCMSearchMode ssh_cm_edb_ldap_search(SshCMSearchDatabase  *db,
                                       SshCMContext          cm,
                                       void                 *context,
                                       SshCMDBDistinguisher *dg)
{
  SshCMEdbLdap ldap = db->context;
  SshCMSearchMode status = SSH_CM_SMODE_FAILED;
  unsigned char *url = NULL;
  unsigned char *scheme = NULL, *host = NULL, *port = NULL;
  unsigned char *username = NULL, *password = NULL, *path = NULL;
  unsigned char *urlpath;
  const unsigned char *pname;
  unsigned char *name = NULL, *attributes = NULL, *scope = NULL;
  unsigned char *filter = NULL;
  unsigned char *ps, *p;
  Boolean one_host = FALSE;
  SshADTHandle handle;
  const unsigned char *null;

  /* Determine whether the search key is suitable for LDAP. */
  if (dg->key_type == SSH_CM_KEY_TYPE_DIRNAME ||
      dg->key_type == SSH_CM_KEY_TYPE_DISNAME)
    {
      SshDNStruct dn;
      char *base_dn;

      /* Make a LDAP name. */
      ssh_dn_init(&dn);
      if (ssh_dn_decode_der(dg->key, dg->key_length, &dn, NULL) == 0)
        {
          /* Free the allocated space. */
          ssh_dn_clear(&dn);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("EDB/LDAP: Base-DN decode failed."));
          return SSH_CM_SMODE_FAILED;
        }
      /* Reverse the DN to the LDAP style. */
      ssh_dn_reverse(&dn);
      if (ssh_dn_encode_ldap(&dn, &base_dn) == 0)
        {
          /* Free the allocated space. */
          ssh_dn_clear(&dn);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("EDB/LDAP: Base-DN encode failed."));
          return SSH_CM_SMODE_FAILED;
        }
      ssh_dn_clear(&dn);
      /* Now we have allocated a LDAP name. */

      if (ssh_dsprintf(&url, "ldap:/%s", base_dn) == -1)
        url = NULL;
      ssh_free(base_dn);
    }
  else if (dg->key_type == SSH_CM_KEY_TYPE_URI)
    {
      url = ssh_memdup(dg->key, dg->key_length);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("EDB/LDAP: Unknown key type %s.",
                 ssh_find_keyword_name(ssh_cm_edb_key_types, dg->key_type)));
      return SSH_CM_SMODE_FAILED;
    }

  if (url == NULL ||
      ssh_url_parse(url,
                    &scheme, &host, &port,
                    &username, &password, &urlpath) == FALSE)
    {
      ssh_free(url);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("EDB/LDAP: Invalid URL syntax."));
      return SSH_CM_SMODE_FAILED;
    }
  path = urlpath;

  /* URI is now parsed, we need to know whether this is a LDAP connection
     request. */
  if (ssh_usstrcasecmp(scheme, "ldap") != 0)
  {
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("EDB/LDAP: Invalid URL schema %s not LDAP.", scheme));
    goto exit_point;
  }

  /* If the URL specifies host, we'll make a LDAP connection to that
     host, if it does not already exists.  */
  if (host)
    {
      unsigned char *server;
      SshCMEdbLdapConnectionStruct probe;

      one_host = TRUE;
      if (port == NULL)
        port = ssh_strdup("389");

      ssh_dsprintf(&server, "%s://%s%s%s%s%s:%s",
                   scheme,
                   username ? username : ssh_custr(""),
                   password ? ":" : "", password ? password : ssh_custr(""),
                   username ? "@" : "",
                   host, port);

      if (server == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("EDB/ldap server encoding: no space."));
          goto exit_point;
        }

      if (ssh_cm_edb_ldap_add(cm, server) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("EDB/ldap server '%s': add failed.",
                                 server));
          ssh_free(server);
          goto exit_point;
        }
      probe.identifier = server;
      handle = ssh_adt_get_handle_to_equal(ldap->map, &probe);
      ssh_free(server);
    }
  else
    {
      handle = ssh_adt_enumerate_start(ldap->map);
    }

  /* Split path in to pieces, remember, urlpath is what was allocated,
     path is only pointer for its traversal.*/
  if (path == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EDB/LDAP: No base object."));
      goto exit_point;
    }

  /* Decode the object name, make it dynamic even if invalid url
     encoding. */
  pname = path;
  path = ssh_ustrchr(path, '?');
  if (path) *path++ = '\0';
  if ((name = ssh_url_data_decode(pname, ssh_ustrlen(pname), NULL)) == NULL)
    name = ssh_ustrdup(pname);

  /* grab attributes if any, make them dynamic */
  attributes = path;
  if (path) path = ssh_ustrchr(path, '?');
  if (path) *path++ = '\0';
  if (attributes == NULL || ssh_ustrlen(attributes) == 0)
    {
      if (dg->data_type == SSH_CM_DATA_TYPE_CRL)
        attributes =
          (unsigned char *)"certificaterevocationlist,authorityrevocationlist";
      else
        attributes =
        (unsigned char *)"usercertificate,cacertificate,crosscertificatepair";
    }

  /* grab scope if any, make it dynamic */
  scope = path;
  if (path) path = ssh_ustrchr(path, '?');
  if (path) *path++ = '\0';
  if (scope == NULL || ssh_ustrlen(scope) == 0)
    scope = (unsigned char *)"base";

  /* grab filter if any, make it dynamic */
  filter = path;
  if (path) path = ssh_ustrchr(path, '?');
  if (path) *path++ = '\0';
  if (filter == NULL || ssh_ustrlen(filter) == 0)
    filter = (unsigned char *)SSH_CM_LDAP_SEARCH_FILTER;

  null = ssh_custr("null");
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("LDAP base dn = <%s> attributes <%s>, scope = <%s>, "
             "filter = <%s>",
             name ? name : null,
             attributes ? attributes : null,
             scope ? scope : null,
             filter ? filter : null));

 restart_with_all_servers:

  for (;
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(ldap->map, handle))
    {
      SshCMEdbLdapConnection connection;
      SshCMEdbLdapSearch search;
      SshCMEdbLdapConnectionEst ce;
      SshLdapSearchScope ldap_scope;
      unsigned char **attribute_table;
      size_t *attribute_len_table;
      int attribute_alloc;
      int attribute_cnt;
      Boolean search_started;

      connection = ssh_adt_get(ldap->map, handle);

      /* The search starting. */
      if (ssh_cm_edb_ban_check(cm, NULL, ssh_csstr(connection->identifier)) ||
          ssh_cm_edb_ban_check(cm, dg, ssh_csstr(connection->identifier)))
        {
          if (one_host)
            {
              if ((handle = ssh_adt_enumerate_start(ldap->map))
                  != SSH_ADT_INVALID)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("EDB/LDAP: Search for '%s' [single host] "
                             "at %s was banned. Restarting from servers "
                             "given at configuration",
                             name, connection->identifier));
                  one_host = FALSE;
                  goto restart_with_all_servers;
                }
            }
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("EDB/LDAP: Search for '%s' at %s was banned.",
                     name, connection->identifier));
          continue;
        }

      /* Try searching, and for that we need to generate a small
         search context. */
      search = ssh_calloc(1, sizeof(*search));
      if (search == NULL)
        goto exit_point;

      search->context    = context;
      search->db         = db;
      search->dg         = dg;
      search->connection = connection;
      search->counter    = 0;
      search->tc         = 0;
      search->use_old_connection = FALSE;

      /* Take a copy for later use. */
      search->object_name = ssh_strdup(name);
      if (search->object_name == NULL)
        {
          cm_ldap_search_free(search);
          goto exit_point;
        }

      ce = ssh_calloc(1, sizeof(*ce));
      if (ce == NULL)
        {
          cm_ldap_search_free(search);
          goto exit_point;
        }

      /* Check for search in progress. */
      if (ssh_cm_edb_operation_check(context, dg,
                                     ssh_csstr(connection->identifier))
          == TRUE)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("EDB/LDAP: Search already exists for '%s', waiting for "
                     "it to terminate.",
                     search->object_name));

          /* Currently there is an on-going search. We will attach
             to it. */
          if (ssh_cm_edb_operation_link(context, dg, db,
                                        ssh_csstr(connection->identifier),
                                        ssh_cm_edb_ldap_operation_free,
                                        search))
            {
              /* Simple initialization. */
              ssh_cm_edb_mark_search_init_start(db, context, dg);
              ssh_cm_edb_mark_search_init_end(db, context, dg, FALSE);
              status = SSH_CM_SMODE_SEARCH;
            }
          else
            {
              cm_ldap_search_free(search);
            }

          ssh_free(ce);
          goto exit_point;
        }

      /* Set up our search with the LDAP client. */
      if (!ssh_ldap_string_to_filter(filter,
                                     ssh_ustrlen(filter),
                                     &search->filter))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("EDB/LDAP: Filter encode failed."));
          cm_ldap_search_free(search);
          ssh_free(ce);
          goto exit_point;
        }

      /* Initialize the attribute number. */
      p = ps = ssh_strdup(attributes);
      attribute_cnt = 0;
      attribute_alloc = 4;

      attribute_table = ssh_malloc(attribute_alloc * sizeof(char *));
      attribute_len_table = ssh_malloc(attribute_alloc * sizeof(size_t));
      if (attribute_table == NULL || attribute_len_table == NULL)
        {
        attribute_alloc_error:
          SSH_DEBUG(SSH_D_FAIL,
                    ("EDB/LDAP: No space for attributes when doing %s.",
                     connection->identifier));
          ssh_free(attribute_table);
          ssh_free(attribute_len_table);
          cm_ldap_search_free(search);
          ssh_free(ps);
          ssh_free(ce);
          goto exit_point;
        }

      while (1)
        {
          attribute_table[attribute_cnt] = p;
          p = ssh_ustrchr(p, ',');
          if (p == NULL)
            break;
          *p++ = '\0';
          attribute_len_table[attribute_cnt] =
            ssh_ustrlen(attribute_table[attribute_cnt]);
          attribute_cnt++;
          if (attribute_cnt == attribute_alloc)
            {
              void *tmp;
              size_t olditems = attribute_alloc;

              attribute_alloc += 4;
              tmp = ssh_realloc(attribute_table,
                                olditems * sizeof(char *),
                                attribute_alloc * sizeof(char *));
              if (tmp == NULL)
                goto attribute_alloc_error;
              attribute_table = tmp;

              tmp = ssh_realloc(attribute_len_table,
                                olditems * sizeof(size_t),
                                attribute_alloc * sizeof(size_t));
              if (tmp == NULL)
                goto attribute_alloc_error;
              attribute_len_table = tmp;

            }
        }
      attribute_len_table[attribute_cnt] =
        ssh_ustrlen(attribute_table[attribute_cnt]);
      attribute_cnt++;

      if (ssh_usstrcmp(scope, "one") == 0)
        ldap_scope = SSH_LDAP_SEARCH_SCOPE_SINGLE_LEVEL;
      else if (ssh_usstrcmp(scope, "sub") == 0)
        ldap_scope = SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE;
      else
        ldap_scope = SSH_LDAP_SEARCH_SCOPE_BASE_OBJECT;

      ssh_cm_edb_mark_search_init_start(search->db, search->context,
                                        search->dg);

      ce->connection = connection;
      ce->search = search;
      ce->attribute_cnt = attribute_cnt;
      ce->attribute_table = (unsigned char **)attribute_table;
      ce->attribute_len_table = attribute_len_table;
      ce->ldap_scope = ldap_scope;
      ce->attribute_data = ps;
      ce->ldap = ldap;

      if (connection->state == LDAP_CONNECTED)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("EDB/LDAP: search from server '%s' (old).",
                     connection->identifier));
          search->use_old_connection = TRUE;
          search_started = cm_edb_ldap_start_search(ce);
          cm_ldap_connect_establish_free(FALSE, ce);
          ce = NULL;
        }
      else if (connection->state == LDAP_NOT_CONNECTED)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("EDB/LDAP: search from server '%s' (new).",
                     connection->identifier));

          search->msg_id = cm_ldap_connect_establish(cm, ce);
          if (search->msg_id == NULL)
            {
              cm_ldap_connect_establish_free(FALSE, ce);
              ce = NULL;
              search_started = FALSE;
            }
          else
            {
              connection->state = LDAP_CONNECTING;
              search_started = TRUE;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("EDB/LDAP: connection to server '%s' is not ready.",
                     connection->identifier));
          cm_ldap_connect_establish_free(FALSE, ce);
          ce = NULL;
          search_started = FALSE;
        }

      if (search_started == FALSE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("EDB/LDAP: Failed to start ldap search"));
          ssh_cm_edb_mark_search_init_end(db, context, dg, TRUE);
          cm_ldap_search_free(search);
        }
      else
        {
          if (ssh_cm_edb_operation_link(context, dg, db,
                                        ssh_csstr(connection->identifier),
                                        ssh_cm_edb_ldap_operation_free,
                                        search) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to link ldap search operation"));
              ssh_operation_abort(search->msg_id);
              ssh_cm_edb_mark_search_init_end(db, context, dg, TRUE);
              cm_ldap_search_free(search);
              goto exit_point;
            }

          status = SSH_CM_SMODE_SEARCH;
          SSH_DEBUG(SSH_D_MIDOK, ("EDB/LDAP: Search initiated"));
        }

      /* Break out from the for loop in case this query was directed
         to single host. */
      if (one_host)
        break;
    }

 exit_point:

  /* Free stuff from url library */
  ssh_free(url);
  ssh_free(scheme);
  ssh_free(host);
  ssh_free(port);
  ssh_free(username);
  ssh_free(password);
  ssh_free(urlpath);

  /* Free the decoded name to search */
  ssh_free(name);

  return status;
}

void ssh_cm_edb_ldap_free(SshCMSearchDatabase *db)
{
  SshCMEdbLdap ldap = db->context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Freeing LDAP."));

  ssh_adt_destroy(ldap->map);
  ssh_free(ldap);
}

static void cm_edb_ldap_timeout(void *context)
{
  SshCMEdbLdap ldap = context;
  SshADTHandle handle;
  SshCMEdbLdapConnection connection;
  int active_connections = 0;

  if (ldap->cm->config->ldap_connection_idle_timeout == 0)
    return;

  for (handle = ssh_adt_enumerate_start(ldap->map);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(ldap->map, handle))
    {
      connection = ssh_adt_get(ldap->map, handle);

      if (connection->state == LDAP_CONNECTED &&
          connection->idle > ldap->cm->config->ldap_connection_idle_timeout)
        {
          if (ldap->cm->config->access_callback)
            (*ldap->cm->config->access_callback)(FALSE,
                                                 connection->ldap_server_name,
                                                 connection->ldap_server_port,
                                                 NULL_FNPTR, NULL,
                                                 ldap->cm->config
                                                 ->access_callback_context);
          ssh_ldap_client_disconnect(connection->context);
          connection->state = LDAP_NOT_CONNECTED;
          continue;
        }
      connection->idle += 10;
      active_connections += 1;
    }
  if (active_connections)
    ssh_register_timeout(&ldap->timeout,
                         10L, 0L,
                         cm_edb_ldap_timeout, ldap);
}

void ssh_cm_edb_ldap_stop(SshCMSearchDatabase *db)
{
  SshCMEdbLdap ldap = db->context;
  SshADTHandle handle;
  SshCMEdbLdapConnection connection;

  /* Cancel connection closing engine and disconnect clients */
  ssh_cancel_timeout(&ldap->timeout);

  for (handle = ssh_adt_enumerate_start(ldap->map);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(ldap->map, handle))
    {
      connection = ssh_adt_get(ldap->map, handle);

      if (ldap->cm->config->access_callback)
        (*ldap->cm->config->access_callback)(FALSE,
                                             connection->ldap_server_name,
                                             connection->ldap_server_port,
                                             NULL_FNPTR, NULL,
                                             ldap->cm->config
                                             ->access_callback_context);
      ssh_ldap_client_disconnect(connection->context);
      connection->state = LDAP_NOT_CONNECTED;
    }
}

const SshCMSearchFunctionsStruct ssh_cm_edb_ldap_functions =
{
  "ssh.ldap", SSH_CM_SCLASS_SERVER,
  ssh_cm_edb_ldap_search,
  ssh_cm_edb_ldap_stop,
  ssh_cm_edb_ldap_free
};


/* Scan for the next comma */
static size_t skip_comma_sep_token_pos(const unsigned char *str)
{
  size_t i;
  Boolean escape = FALSE;
  for (i = 0; str[i] != '\0'; )
    {
      if (escape)
        {
          i++;
          escape = FALSE;
        }
      else
        {
          switch (str[i])
            {
            case ',':
              goto end;
            case '\\':
              escape = TRUE;
              i++;
              break;
            default:
              i++;
              break;
            }
        }
    }
 end:
  return i;
}

/* Get the next token after comma */
static unsigned char *skip_comma_sep_token(const unsigned char *str)
{
  size_t pos;
  if (str == NULL)
    return NULL;
  pos = skip_comma_sep_token_pos(str);
  if (str[pos] != '\0')
    pos++;
  return &((unsigned char *)str)[pos];
}

Boolean get_comma_sep_token(const unsigned char *str,
                            unsigned char **ret_server,
                            unsigned char **ret_username,
                            unsigned char **ret_password)
{
  size_t pos;
  unsigned char *tmp = NULL;
  unsigned char *scheme = NULL, *username = NULL, *password = NULL;
  unsigned char *host = NULL, *port = NULL, *path = NULL;
  Boolean rv = TRUE;

  if (str == NULL)
    return FALSE;

  /* Initialize to dummy values. */
  *ret_server   = NULL;
  *ret_username = NULL;
  *ret_password = NULL;

  /* Seek to the end of the token */
  pos = skip_comma_sep_token_pos(str);
  if (pos == 0)
    return FALSE;

  /* ... memdup shall set the last char to '\0' */
  tmp = ssh_memdup(str, pos);
  if (tmp == NULL)
    return FALSE;

  /* Check for ldap schema in server address and append it if necessary. */
  if (ssh_usstrncmp(tmp, "ldap://", 7) != 0)
    {
      unsigned char *tmp2 = tmp;

      ssh_dsprintf(&tmp, "ldap://%s", tmp2);
      ssh_free(tmp2);
      if (tmp == NULL)
        return FALSE;
    }

  if (ssh_url_parse_relaxed(tmp,
                            &scheme, &host, &port,
                            &username, &password, &path) == FALSE)
    {
      if (host == NULL)
        rv = FALSE;

      *ret_server   = host;
      *ret_username = NULL;
      *ret_password = NULL;

      ssh_free(tmp);
      ssh_free(scheme);
      ssh_free(port);
      ssh_free(username);
      ssh_free(password);
      ssh_free(path);

      return rv;
    }

  /* Return those values that have some use. */
  if (port == NULL)
    port = ssh_strdup("389");

  if (host != NULL)
    {
      if ((ssh_dsprintf(ret_server, "%s://%s:%s",
                        scheme ? scheme : ssh_custr("ldap"),
                        host, port)) == -1)
        rv = FALSE;

      if (username)
        {
          *ret_username = ssh_strdup(username);
          if (*ret_username == NULL)
            rv = FALSE;
        }

      if (password)
        {
          *ret_password = ssh_strdup(password);
          if (*ret_password == NULL)
            rv = FALSE;
        }

      /* Check the rest, for consistency. */
      if (rv && (scheme != NULL && ssh_usstrcmp(scheme, "ldap") != 0))
        {
          rv = FALSE;
        }
    }

  ssh_free(scheme);
  ssh_free(host);
  ssh_free(port);
  ssh_free(username);
  ssh_free(password);
  ssh_free(path);
  ssh_free(tmp);

  return rv;
}

Boolean ssh_cm_edb_ldap_add(SshCMContext cm,
                            const unsigned char *default_servers)
{
  SshCMEdbLdap ldap;
  SshCMSearchDatabase *database;
  unsigned char *server = NULL;
  unsigned char *password = NULL, *bind_name = NULL;

  database =
    ssh_cm_edb_lookup_database(cm, ssh_cm_edb_ldap_functions.db_identifier);

  if (!database)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("EDB/LDAP: Adding new LDAP backend."));

      /* Allocate the ldap context for the method. */
      ldap = ssh_calloc(1, sizeof(*ldap));
      if (ldap == NULL)
        return FALSE;

      ldap->cm = cm;

      /* Initialize the mapping. */
      ldap->map =
        ssh_adt_create_generic(
               SSH_ADT_MAP,
               SSH_ADT_HASH,    cm_ldap_connection_hash,
               SSH_ADT_COMPARE, cm_ldap_connection_compare,
               SSH_ADT_DESTROY, cm_ldap_connection_destroy,
               SSH_ADT_HEADER,
               SSH_ADT_OFFSET_OF(SshCMEdbLdapConnectionStruct, adt_header),
               SSH_ADT_ARGS_END);
      if (ldap->map == NULL)
        {
          ssh_free(ldap);
          return FALSE;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("EDB/LDAP: Database already exists."));
      ldap = database->context;
    }

  /* Remark. This code might need changing to be more careful in the
     checking of the data in the hash table. At the moment only
     the `host' and `port' are used to identify a ldap server---and
     this may not be what one would like in somecases. */

  for (;
       get_comma_sep_token(default_servers,
                          &server, &bind_name, &password);
       default_servers = skip_comma_sep_token(default_servers))
    {
      SshCMEdbLdapConnectionStruct *connection, probe;
      SshADTHandle h;

      if (server == NULL)
        {
          ssh_free(server);
          ssh_free(bind_name);
          ssh_free(password);
          server = NULL;
          bind_name = NULL;
          password = NULL;
          continue;
        }

      probe.identifier = server;
      h = ssh_adt_get_handle_to_equal(ldap->map, &probe);
      if (h != SSH_ADT_INVALID)
        {
          ssh_free(server);
          ssh_free(bind_name);
          ssh_free(password);
          server = NULL;
          bind_name = NULL;
          password = NULL;
          continue;
        }

      SSH_DEBUG(SSH_D_MIDOK, ("EDB/LDAP: Making connection to '%s'.", server));

      connection =
        cm_ldap_connection_create(cm, ssh_cm_edb_get_local_network(cm),
                                  server, bind_name, password);
      if (connection)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Created ldap client for connecting to server: %s",
                     server));
          (void )ssh_adt_insert(ldap->map, connection);
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Connection to %s failed.", server));
          ssh_free(server);
          ssh_free(bind_name);
          ssh_free(password);
          server = NULL;
          bind_name = NULL;
          password = NULL;
          goto fail;
        }

      server = NULL;
      bind_name = NULL;
      password = NULL;
    }

  ssh_free(server);
  ssh_free(bind_name);
  ssh_free(password);

  /* Set up the servers etc. */
  if (!database)
    {
      if (!ssh_cm_edb_add_database(cm, &ssh_cm_edb_ldap_functions, ldap))
        goto fail;
    }

  return TRUE;

 fail:
  ssh_adt_destroy(ldap->map);
  ssh_free(ldap);
  return FALSE;
}


Boolean ssh_cm_edb_ldap_init(SshCMContext cm,
                             const unsigned char *default_servers)
{
  ssh_cm_edb_remove_database(cm, ssh_cm_edb_ldap_functions.db_identifier);
  return ssh_cm_edb_ldap_add(cm, default_servers);
}

#endif /* SSHDIST_VALIDATOR_LDAP */
#endif /* SSHDIST_CERT */
