/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Convenience function for performing LDAP search.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"
#include "sshfsm.h"
#include "sshurl.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapConvenience"

typedef struct SshLdapConvThreadDataRec
{
  /* Server */
  unsigned char *host;
  unsigned char *port;
  unsigned char *user;
  unsigned char *pass;

  SshLdapClientWrapCB wrapper;

  /* Query */
  unsigned char *basedn;
  struct {
    unsigned char **attributes;
    size_t *attribute_lens;
    size_t attribute_count;
  } attributes;
  SshLdapSearchScope scope;
  SshLdapDerefAliases deref;
  SshLdapSearchFilter filter;

  SshLdapClientResultCB done_callback;
  void *done_callback_context;
  SshLdapSearchResultCB item_callback;
  void *item_callback_context;

  /* Result */
  SshLdapResult status;
  unsigned char *matched, *error;
  size_t matched_len, error_len;

  /* Support information. */
  Boolean client_allocated;
  SshLdapClient client;
  SshFSMThread thread;

  SshOperationHandle op;
  SshOperationHandle subop;
} *SshLdapConvThreadData;

/* Idea here is to enter at start state, then connect, bind, start
   search, give out objects without this module kwing about that, then
   receive result, give it to the application, then move to done phase
   to clean-up. */

SSH_FSM_STEP(ldap_search_start);
SSH_FSM_STEP(ldap_search_connected);
SSH_FSM_STEP(ldap_search_tls_started);
SSH_FSM_STEP(ldap_search_bound);
SSH_FSM_STEP(ldap_search_resulted);
SSH_FSM_STEP(ldap_search_done);



#define FREEURL(s, h, n, u, x, p) do {           \
    ssh_free((s)); ssh_free((h)); ssh_free((n)); \
    ssh_free((u)); ssh_free((x)); ssh_free((p)); \
} while (0)

static void
ldap_attributes_free(size_t cnt,
                     unsigned char **attribute_table,
                     size_t *attribute_len_table)
{
  int i;

  for (i = 0; i < cnt; i++)
    ssh_free(attribute_table[i]);

  ssh_free(attribute_table);
  ssh_free(attribute_len_table);
}

/* This spoils the 'attrs' string, therefore the string has to be
   writable. The elements at returned array are all pointers to
   different offsets of the 'attrs'. */
static unsigned char **
ldap_string_to_attributes(const char *attrs,
                          size_t *ldap_attributes_count,
                          size_t **ldap_attribute_lens)
{
  unsigned char **attribute_table;
  char *p, *attrs_tmp;
  size_t *attribute_len_table, i = 0, cnt;

  if (!attrs || !*attrs)
    {
      *ldap_attributes_count = 0;
      *ldap_attribute_lens = NULL;
      return NULL;
    }
  /* Count number of attributes; that is number of commas in the
     attrs plus one. */
  for (p = (char *)attrs, cnt = 1; p && (p = strchr(p, ',')) != NULL; cnt++);

  attribute_table = ssh_malloc(cnt * sizeof(char *));
  attribute_len_table = ssh_malloc(cnt * sizeof(size_t));
  attrs_tmp = ssh_strdup(attrs);

  if (attrs_tmp == NULL ||
      attribute_table == NULL || attribute_len_table == NULL)
    {
      ssh_free(attrs_tmp);
      ssh_free(attribute_table);
      ssh_free(attribute_len_table);
      return NULL;
    }

  p = attrs_tmp;
  while (TRUE)
    {
      attribute_table[i] = (unsigned char *)p;

      p = strchr(p, ',');
      if (p == NULL)
        {
          attribute_len_table[i] = strlen((char *)attribute_table[i]);

          attribute_table[i] =
            ssh_memdup(attribute_table[i], attribute_len_table[i]);
          if (attribute_table[i] == NULL)
            {
              ldap_attributes_free(cnt, attribute_table, attribute_len_table);
              attribute_table = NULL;
              attribute_len_table = NULL;
              cnt = 0;
            }
          break;
        }

      attribute_len_table[i] = strlen((char *)attribute_table[i]);

      attribute_table[i] =
        ssh_memdup(attribute_table[i], attribute_len_table[i]);
      if (attribute_table[i] == NULL)
        {
          ldap_attributes_free(cnt, attribute_table, attribute_len_table);
          attribute_table = NULL;
          attribute_len_table = NULL;
          cnt = 0;
          break;
        }
      *p++ = '\0';
      i++;
    }

  ssh_free(attrs_tmp);
  *ldap_attribute_lens = attribute_len_table;
  *ldap_attributes_count = cnt;
  return attribute_table;
}

static void
ldap_search_free(SshLdapConvThreadData search)
{
  ssh_free(search->host); ssh_free(search->port);
  ssh_free(search->user); ssh_free(search->pass);

  ssh_free(search->basedn);
  ldap_attributes_free(search->attributes.attribute_count,
                       search->attributes.attributes,
                       search->attributes.attribute_lens);
  ssh_ldap_free_filter(search->filter);

  ssh_free(search->matched); ssh_free(search->error);

  if (search->op)
    ssh_operation_unregister(search->op);
  if (search->subop)
    ssh_operation_unregister(search->subop);
  if (search->client_allocated && search->client)
    ssh_ldap_client_destroy(search->client);

  ssh_free(search);
}


static void ldap_search_abort(void *context)
{
  SshLdapConvThreadData search = context;
  SshFSM fsm;

  if (search == NULL)
    return;

  if (search->thread == NULL)
    return;

  fsm = ssh_fsm_get_fsm(search->thread);
  search->op = NULL;

  /* Make sure the underlying mechanisms do not call callbacks
     first. */
  if (search->subop)
    {
      ssh_operation_abort(search->subop);
      search->subop = NULL;
    }

  if (search->thread)
    {
      ssh_fsm_kill_thread(search->thread);
      search->thread = NULL;
    }
  ldap_search_free(search);
  ssh_fsm_destroy(fsm);
}


/* Initialize new search from given URL */
static SshLdapConvThreadData
ldap_search_initialize_from_url(const unsigned char *url,
                                SshLdapResultInfo info)
{
  SshLdapConvThreadData search = NULL;
  unsigned char *scheme, *host, *port, *user, *pass, *path;
  unsigned char *filter, *scope, *attrs;
  unsigned char **attributes = NULL;
  size_t *attribute_lens = NULL, attribute_count = 0;
  SshLdapSearchFilter ldap_filter;

  /* Check validity for the URL. */
  if (!ssh_url_parse(url, &scheme, &host, &port, &user, &pass, &path)
      || ssh_usstrcasecmp(scheme, "ldap") != 0
      || path == NULL)
    {
      MAKEINFO(info, "Can't parse URL, scheme not LDAP, or no path.");
      FREEURL(scheme, host, port, user, pass, path);
      goto startup_failed;
    }

  /* Dig out attributes, scope and filter from the path. This will
     split the path string, thus leaving the path point into the
     search base-DN. */
  filter = NULL;
  attrs = ssh_ustrchr(path, '?');
  if (attrs != NULL)
    {
      *attrs++ = '\0';
      /* If scope, terminate attributes. */
      scope = ssh_ustrchr(attrs, '?');
      if (scope != NULL)
        {
          *scope++ = '\0';
          /* If filter, terminate scope. */
          if ((filter = ssh_ustrchr(scope, '?')) != NULL)
            *filter++ = '\0';
        }
      else
        {
          filter = ssh_ustr("(objectclass=*)");
          scope = "";
        }
    }
  else
    {
      scope  = ssh_ustr("one");
      filter = ssh_ustr("(objectclass=*)");
    }
  /* Attributes may be NULL. Filter must be of valid syntax, and scope
     is handled later. */
  attributes = ldap_string_to_attributes(ssh_sstr(attrs),
                                         &attribute_count,
                                         &attribute_lens);

  if (filter == NULL || !ssh_ldap_string_to_filter(filter, ssh_ustrlen(filter),
                                 &ldap_filter))
    {
      MAKEINFO(info, "Can't parse LDAP filter.");
      FREEURL(scheme, host, port, user, pass, path);
      goto startup_failed;
    }

  /* Then allocate a thread to perform query. We have all the relevant
     data available now (some of which may come from default values
     from above. */
  search = ssh_calloc(1, sizeof(*search));
  if (search != NULL)
    {
      search->basedn = path;

      search->attributes.attribute_count = attribute_count;
      search->attributes.attributes = attributes;
      search->attributes.attribute_lens = attribute_lens;

      if (!ssh_usstrcasecmp(scope, "one"))
        search->scope = SSH_LDAP_SEARCH_SCOPE_SINGLE_LEVEL;
      else if (!ssh_usstrcasecmp(scope, "sub"))
        search->scope = SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE;
      else
        search->scope = SSH_LDAP_SEARCH_SCOPE_BASE_OBJECT;

      search->filter = ldap_filter;

      if (user == NULL) user = ssh_strdup("");
      if (pass == NULL) pass = ssh_strdup("");

      search->host = host;
      search->port = port;
      search->user = user;
      search->pass = pass;

      search->client_allocated = FALSE;
      search->op = ssh_operation_register(ldap_search_abort, search);
      if (search->op == NULL)
        {
          MAKEINFO(info, "Can't allocate space for LDAP operation.");
          ssh_free(scheme);
          goto startup_failed;
        }
    }
  else
    {
      MAKEINFO(info, "Can't allocate space for LDAP search.");
      ssh_free(scheme);
      ssh_free(ldap_filter);
      ssh_free(host);
      ssh_free(port);
      ssh_free(path);
      goto startup_failed;
    }

  ssh_free(scheme);
  return search;

 startup_failed:
  if (search)
    ldap_search_free(search);

  if (!search && attributes)
    ldap_attributes_free(attribute_count, attributes, attribute_lens);

  return NULL;
}

static void ldap_connect_cb(SshLdapClient client,
                            SshTcpError status,
                            void *context)
{
  SshLdapConvThreadData search = context;

  search->subop = NULL;
  if (status == SSH_TCP_OK)
    {
      ssh_fsm_set_next(search->thread, ldap_search_connected);
    }
  else
    {
      search->status = SSH_LDAP_RESULT_DISCONNECTED;
      ssh_fsm_set_next(search->thread, ldap_search_resulted);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(search->thread);
}


SSH_FSM_STEP(ldap_search_start)
{
  SshLdapConvThreadData search = ssh_fsm_get_tdata(thread);
  SshOperationHandle op;

  SSH_FSM_ASYNC_CALL({
    op = ssh_ldap_client_connect(search->client,
                                 search->host,
                                 search->port,
                                 ldap_connect_cb, search);
    search->subop = op;
  });
}

static void
ldap_bind_cb(SshLdapClient client,
             SshLdapResult result,
             const SshLdapResultInfo info,
             void *context)
{
  SshLdapConvThreadData search = context;

  search->status = result;
  search->subop = NULL;
  switch (result)
    {
    case SSH_LDAP_RESULT_SUCCESS:
      ssh_fsm_set_next(search->thread, ldap_search_bound);
      break;
    case SSH_LDAP_RESULT_DISCONNECTED:
      ssh_fsm_set_next(search->thread, ldap_search_start);
      break;
    default:
      ssh_fsm_set_next(search->thread, ldap_search_resulted);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(search->thread);
}

static SshStream
ldap_tls_cb(SshLdapClient client,
            SshLdapResult result,
            const SshLdapResultInfo info,
            SshStream plain_ldap_stream,
            void *context)
{
  SshLdapConvThreadData search = context;
  SshStream stream = NULL;

  switch (result)
    {
    case SSH_LDAP_RESULT_SUCCESS:
      stream = (*search->wrapper)(client,
                                  result, info, plain_ldap_stream,
                                  search->done_callback_context);
      ssh_fsm_set_next(search->thread, ldap_search_connected);
      search->wrapper = NULL_FNPTR;

      break;
    case SSH_LDAP_RESULT_DISCONNECTED:
      ssh_fsm_set_next(search->thread, ldap_search_start);
      break;
    default:
      ssh_fsm_set_next(search->thread, ldap_search_resulted);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(search->thread);
  return stream;
}

SSH_FSM_STEP(ldap_search_connected)
{
  SshLdapConvThreadData search = ssh_fsm_get_tdata(thread);

  if (search->wrapper)
    {
      SSH_FSM_ASYNC_CALL({
        search->subop =
          ssh_ldap_client_enable_tls(search->client,
                                     ldap_tls_cb, search);
      });
    }

  if (search->user && search->pass)
    {
      SSH_FSM_ASYNC_CALL({
        search->subop =
          ssh_ldap_client_bind(search->client,
                               search->user,
                               ssh_ustrlen(search->user),
                               search->pass,
                               ssh_ustrlen(search->pass),
                               ldap_bind_cb, search);
      });
    }
  ssh_fsm_set_next(search->thread, ldap_search_bound);
  return SSH_FSM_CONTINUE;
}


static void
ldap_process_result(SshLdapClient client,
                    SshLdapResult result,
                    const SshLdapResultInfo info,
                    void *callback_context)
{
  SshLdapConvThreadData search = callback_context;

  search->status = result;
  search->subop = NULL;

  search->matched = ssh_memdup(info->matched_dn, info->matched_dn_len);
  if (search->matched != NULL)
    search->matched_len = info->matched_dn_len;

  search->error = ssh_memdup(info->error_message, info->error_message_len);
  if (search->error != NULL)
    search->error_len = info->error_message_len;

  ssh_fsm_set_next(search->thread, ldap_search_resulted);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(search->thread);
}

SSH_FSM_STEP(ldap_search_bound)
{
  SshLdapConvThreadData search = ssh_fsm_get_tdata(thread);

  if (search->item_callback)
    SSH_FSM_ASYNC_CALL({
      search->subop =
        ssh_ldap_client_search(search->client,
                               ssh_csstr(search->basedn),
                               search->scope,
                               search->deref,
                               -1, -1, FALSE,
                               search->filter,
                               search->attributes.attribute_count,
                               search->attributes.attributes,
                               search->attributes.attribute_lens,
                               search->item_callback,
                               search->item_callback_context,
                               ldap_process_result,
                               search);
    });
  else
    {
      ssh_fsm_set_next(search->thread, ldap_search_resulted);
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(ldap_search_resulted)
{
  SshLdapConvThreadData search = ssh_fsm_get_tdata(thread);
  SshLdapResultInfoStruct info;

  ssh_fsm_set_next(search->thread, ldap_search_done);
  memset(&info, 0, sizeof(info));

  info.matched_dn = search->matched;
  info.matched_dn_len = search->matched_len;
  info.error_message = search->matched;
  info.error_message_len = search->matched_len;

  (*search->done_callback)(search->client, search->status, &info,
                           search->done_callback_context);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ldap_search_done)
{
  SshLdapConvThreadData search = ssh_fsm_get_tdata(thread);

  ssh_fsm_destroy(ssh_fsm_get_fsm(search->thread));
  if (!search->item_callback)
    search->client = NULL;
  ldap_search_free(search);
  return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_ldap_client_search_url(SshLdapClient client,
                           const unsigned char *url,
                           SshLdapSearchResultCB search_callback,
                           void *search_callback_context,
                           SshLdapClientResultCB callback,
                           void *callback_context)
{
  SshLdapConvThreadData search;
  SshFSM fsm;
  SshLdapResultInfoStruct info;

  memset(&info, 0, sizeof(info));

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("search/url(%p) path=%s", client, url));

  search = ldap_search_initialize_from_url(url, &info);
  if (search != NULL)
    {
      search->item_callback = search_callback;
      search->item_callback_context = search_callback_context;
      search->done_callback = callback;
      search->done_callback_context = callback_context;
      search->client_allocated = FALSE;
      search->client = client;

      fsm = ssh_fsm_create(NULL);
      if (fsm == NULL)
        {
          MAKEINFO(&info, "Can't create FSM. No enough core.");
          goto startup_failed;
        }

      search->thread = ssh_fsm_thread_create(fsm, ldap_search_bound,
                                             NULL_FNPTR, NULL_FNPTR, search);
      if (search->thread != NULL)
        return search->op;

      MAKEINFO(&info, "Can't create FSM thread. No enough core.");
    }
  else
    {
      MAKEINFO(&info, "Can't initialize search from URL.");
    }

 startup_failed:
  if (search)
    ldap_search_free(search);

  (*callback)(NULL, SSH_LDAP_RESULT_INTERNAL, &info, callback_context);
  return NULL;

}

SshOperationHandle
ssh_ldap_search_url(SshLdapClientParams params,
                    const char unsigned *url,
                    SshLdapSearchResultCB search_callback,
                    void *search_callback_context,
                    SshLdapClientResultCB callback,
                    void *callback_context)
{
  SshLdapConvThreadData search;
  SshLdapClient client;
  SshFSM fsm;
  SshLdapResultInfoStruct info;

  memset(&info, 0, sizeof(info));

  SSH_DEBUG(SSH_D_HIGHSTART, ("search/url(params) path=%s", url));

  search = ldap_search_initialize_from_url(url, &info);
  if (search != NULL)
    {
      client = ssh_ldap_client_create(params);
      if (client == NULL)
        {
          MAKEINFO(&info, "Can't create LDAP client. No enough core.");
          goto startup_failed;
        }

      search->item_callback = search_callback;
      search->item_callback_context = search_callback_context;
      search->done_callback = callback;
      search->done_callback_context = callback_context;
      search->client = client;
      search->client_allocated = TRUE;

      fsm = ssh_fsm_create(NULL);
      if (fsm == NULL)
        {
          MAKEINFO(&info, "Can't create FSM. No enough core.");
          goto startup_failed;
        }

      search->thread = ssh_fsm_thread_create(fsm, ldap_search_start,
                                             NULL_FNPTR, NULL_FNPTR, search);
      if (search->thread != NULL)
        return search->op;

      MAKEINFO(&info, "Can't create FSM thread. No enough core.");
    }
  else
    {
      MAKEINFO(&info, "Can't initialize search from URL.");
    }

 startup_failed:
  if (search)
    ldap_search_free(search);
  (*callback)(NULL, SSH_LDAP_RESULT_INTERNAL, &info, callback_context);
  return NULL;
}


SshOperationHandle
ssh_ldap_client_connect_and_bind(SshLdapClient client,
                                 const char unsigned *server,
                                 const unsigned char *port,
                                 SshLdapClientWrapCB wrapper,
                                 const unsigned char *bind_name,
                                 size_t bind_name_len,
                                 const unsigned char *password,
                                 size_t password_len,
                                 SshLdapClientResultCB callback,
                                 void *callback_context)
{
  SshLdapConvThreadData search;
  SshFSM fsm;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("connect/bind(%p) server=%s:%s user=%s",
             client, server, port, (char *)bind_name));

  search = ssh_calloc(1, sizeof(*search));
  if (search != NULL)
    {
      search->host = ssh_ustrdup(server);
      search->port = ssh_ustrdup(port);
      search->user = ssh_memdup(bind_name, bind_name_len);
      search->pass = ssh_memdup(password, password_len);

      search->op = ssh_operation_register(ldap_search_abort, search);
      if (search->op == NULL)
        {
          ldap_search_free(search);
          return NULL;
        }

      search->done_callback = callback;
      search->done_callback_context = callback_context;
      search->client_allocated = FALSE;
      search->client = client;
      search->wrapper = wrapper;

      fsm = ssh_fsm_create(NULL);
      if (fsm == NULL)
        {
          ldap_search_free(search);
          return NULL;
        }

      search->thread = ssh_fsm_thread_create(fsm, ldap_search_start,
                                             NULL_FNPTR, NULL_FNPTR, search);
      if (search->thread != NULL)
        return search->op;
    }
  return NULL;
}

/* eof */
#endif /* SSHDIST_LDAP */
