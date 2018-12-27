/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshadt.h"
#include "sshadt_list.h"

#define SSH_DEBUG_MODULE "SshTlsSessionCache"

SshTlsSessionCache ssh_tls_create_session_cache(int max_connections,
                                                int alive_time)
{
  SshTlsSessionCache c;
  int i;

  if ((c = ssh_calloc(1, sizeof(*c))) != NULL)
    {
      if ((c->table = ssh_tls_mh_allocate()) == NULL)
        {
          ssh_free(c);
          return NULL;
        }
      if ((c->ids = ssh_tls_mh_allocate()) == NULL)
        {
          ssh_tls_mh_free(c->table);
          ssh_free(c);
          return NULL;
        }

      if ((c->list =
           ssh_adt_create_generic(SSH_ADT_LIST,
                                  SSH_ADT_HEADER,
                                  SSH_ADT_OFFSET_OF(struct
                                                    SshTlsCachedSessionRec,
                                                    adt_header),
                                  SSH_ADT_ARGS_END))
          == NULL)
        {
          ssh_tls_mh_free(c->table);
          ssh_tls_mh_free(c->ids);
          ssh_free(c);
          return NULL;
        }

      c->max_connections = max_connections;
      c->alive_time = alive_time;
      c->counter = 0;

      c->num_cached = 0;

      c->destroyed = FALSE;
      memcpy(c->identifier, "SSHTLS", 6);

      for (i = 6; i < CACHE_ID_LEN; i++)
        {
          c->identifier[i] = ssh_random_get_byte();
        }

      c->pending_timeouts = 0;
    }
  return c;
}

static void destroy_session_cache_actual(SshTlsSessionCache cache)
{
  SSH_DEBUG(5, ("Destroying session cache."));
  SSH_PRECOND(cache->destroyed == TRUE);
  SSH_PRECOND(cache->num_cached == 0);

  ssh_tls_mh_free(cache->table);
  ssh_tls_mh_free(cache->ids);
  ssh_adt_destroy(cache->list);
  ssh_free(cache);
}

static void delete_cached_session(SshTlsCachedSession s)
{
  SshTlsSessionCache cache;

  if (!s) return;

  cache = s->backptr;

  SSH_DEBUG_HEXDUMP(6, ("Deleting cached session %p from cache %p: "
                        "ID dumped:", s, cache),
                    s->session_id, s->id_len);


  SSH_ASSERT(cache->num_cached > 0);
  cache->num_cached--;

  /* Cancel timeouts */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, s);

  /* Free the actual structure. */
  if (s->group_name != NULL)
    {
      ssh_tls_mh_delete_all(cache->ids,
                            (unsigned char *)s->group_name,
                            strlen(s->group_name));
      ssh_free(s->group_name);
    }

  ssh_tls_free_cert_chain(s->peer_certs);
  memset(s->master_secret, 0, 48);

  SSH_DEBUG(4, ("Cached session deleted."));

  ssh_adt_detach_object(cache->list, s);
  ssh_tls_mh_delete_all(cache->table, s->session_id, s->id_len);
  ssh_free(s);

  if (cache->num_cached == 0 && cache->destroyed == TRUE)
    {
      SSH_DEBUG(5, ("No more cached sessions."));
      destroy_session_cache_actual(cache);
    }

}

static void add_to_containers(SshTlsSessionCache cache,
                              SshTlsCachedSession s)
{
  ssh_adt_insert_to(cache->list, SSH_ADT_END, s);
  ssh_tls_mh_add_nonuniq(cache->table, s->session_id, s->id_len, s);
}

/* Aging callback. */
static void aging_callback(void *context)
{
  SshTlsCachedSession s = context;

  SSH_DEBUG_HEXDUMP(4, ("Aging cached session: "
                        "cipher suite = `%s', ID dumped:",
                        ssh_tls_format_suite(s->cipher_suite)),
                    s->session_id, s->id_len);
  delete_cached_session(s);
}

static void schedule_aging_timeout(SshTlsSessionCache cache,
                                   SshTlsCachedSession s)
{
  ssh_xregister_timeout(cache->alive_time, 0L, aging_callback, s);
}

static void free_old_record(SshTlsSessionCache cache)
{
  SshADTHandle h;
  SshTlsCachedSession s;

  /* Take the first object, and remove it. */
  if ((h = ssh_adt_get_handle_to_location(cache->list,
                                          SSH_ADT_BEGINNING))
      != NULL)
    {
      s = ssh_adt_get(cache->list, h);
      delete_cached_session(s);
    }
}

/* Cache a session with a given session id. If `peer_name' is non-NULL
   it is locally strdup()ed. If there is an old session with the given
   name then its data is overwritten. */
void ssh_tls_cache_session(SshTlsSessionCache cache,
                           SshTlsProtocol *protocol_version,
                           const unsigned char *name, int name_len,
                           const unsigned char *master_secret, /* 48 bytes */
                           SshTlsCipherSuite cipher_suite,
                           SshTlsBerCert peer_cert_chain)
{
  void **entries;
  SshTlsCachedSession s;

  SSH_PRECOND(name != NULL);
  SSH_PRECOND(name_len > 0);
  SSH_PRECOND(name_len <= 32);
  SSH_PRECOND(cache != NULL);
  SSH_PRECOND(cache->table != NULL);

  if (cache->destroyed == TRUE) /* This should not happen */
    return;
  if (ssh_tls_mh_find(cache->table, name, name_len, &entries) > 0)
    {
      /* Exactly one item returned! */
      delete_cached_session(entries[0]);
    }

  SSH_ASSERT(cache->num_cached <= cache->max_connections);
  if (cache->num_cached == cache->max_connections)
    {
      /* Cannot cache the session because the cache is full.
         Free an old record. */
      free_old_record(cache);
      SSH_ASSERT(cache->num_cached < cache->max_connections);
    }

  if ((s = ssh_calloc(1, sizeof(*s))) != NULL)
    {
      memcpy(s->session_id, name, name_len);
      s->id_len = name_len;

      memcpy(s->master_secret, master_secret, 48);
      s->cipher_suite = cipher_suite;
      s->peer_certs = ssh_tls_duplicate_ber_cert_chain(peer_cert_chain);
      s->backptr = cache;
      s->group_name = NULL;
      s->protocol_version.major = protocol_version->major;
      s->protocol_version.minor = protocol_version->minor;

      cache->num_cached++;

      add_to_containers(cache, s);
      schedule_aging_timeout(cache, s);

      SSH_DEBUG_HEXDUMP(6, ("Session %p cached to cache %p: "
                            " ID dumped:", s, s->backptr),
                        s->session_id, s->id_len);
    }
}

SshTlsCachedSession ssh_tls_find_cached_session(SshTlsSessionCache cache,
                                                unsigned char *id,
                                                int id_len)
{
  void **entries;
  int result;

  SSH_PRECOND(cache != NULL && id != NULL && id_len > 0 && id_len <= 32);

  SSH_DEBUG_HEXDUMP(6, ("Trying to find session from cache %p: "
                        " ID dumped:",
                        cache),
                    id, id_len);

  result = ssh_tls_mh_find(cache->table, id, id_len, &entries);

  SSH_ASSERT(result == 0 || result == 1);

  if (result == 0)
    {
      SSH_DEBUG(4, ("Cache miss."));
      return NULL;
    }
  SSH_DEBUG(4, ("Cache hit."));
  return entries[0];
}

SshTlsCachedSession ssh_tls_find_cached_by_group(SshTlsSessionCache cache,
                                                 const char *group_name)
{
  void **entries;
  int result;

  SSH_PRECOND(cache != NULL && group_name != NULL);

  SSH_DEBUG(5, ("Trying to find session from cache %p: group %s",
                cache, group_name));

  result = ssh_tls_mh_find(cache->ids,
                           (unsigned char *)group_name, strlen(group_name),
                           &entries);

  SSH_ASSERT(result == 0 || result == 1);

  if (result == 0)
    {
      SSH_DEBUG(4, ("Cache miss."));
      return NULL;
    }

  SSH_DEBUG_HEXDUMP(6, ("Cache hit."
                        " ID dumped:"),
                    ((SshTlsCachedSession)entries[0])->session_id,
                    ((SshTlsCachedSession)entries[0])->id_len);
  return entries[0];
}

void ssh_tls_invalidate_cached_session(SshTlsSessionCache cache,
                                       unsigned char *id,
                                       int id_len)
{
  void **entries;
  if (ssh_tls_mh_find(cache->table, id, id_len, &entries) > 0)
    {
      /* Exactly one item returned! */
      delete_cached_session(entries[0]);
    }
}

void ssh_tls_create_session_id(SshTlsSessionCache cache,
                               unsigned char *buf, int *length_return)
{
  *length_return = 32;
  memcpy(buf, cache->identifier, 32 - sizeof(cache->counter));
  memcpy(&buf[32 - sizeof(cache->counter)], &(cache->counter),
         sizeof(cache->counter));
  cache->counter++;
}

void ssh_tls_associate_with_group(SshTlsSessionCache cache,
                                  unsigned char *name, int name_len,
                                  const char *group_name)
{
  void **entries;
  SshTlsCachedSession s;

  SSH_VERIFY(ssh_tls_mh_find(cache->table, name, name_len, &entries) == 1);
  s = entries[0];

  SSH_DEBUG_HEXDUMP(6, ("Session %p in cache %p associated with group %s"
                        " ID dumped:",
                        s, s->backptr, group_name),
                    s->session_id, s->id_len);

  if (s->group_name != NULL)
    {
      ssh_tls_mh_delete_all(cache->ids,
                            (unsigned char *)s->group_name,
                            strlen(s->group_name));
      ssh_free(s->group_name);
    }
  if ((s->group_name = ssh_strdup(group_name)) != NULL)
    ssh_tls_mh_add_nonuniq(cache->ids, (unsigned char *)s->group_name,
                           strlen(s->group_name), s);
}

void ssh_tls_destroy_session_cache(SshTlsSessionCache cache)
{
  if (!cache) return;
  SSH_DEBUG(5, ("Marking session cache as destroyed."));
  cache->destroyed = TRUE;
  if (cache->num_cached == 0)
    destroy_session_cache_actual(cache);
}

void ssh_tls_flush_session_cache(SshTlsSessionCache cache)
{
  SshADTHandle h;
  SshTlsCachedSession s;

  if (!cache)
    return;
  SSH_DEBUG(3, ("Flushing session cache.."));
  do
    {
      if ((h = ssh_adt_get_handle_to_location(cache->list,
                                              SSH_ADT_BEGINNING))
          != SSH_ADT_INVALID)
        {
          s = ssh_adt_get(cache->list, h);
          delete_cached_session(s);
        }
    } while (h != SSH_ADT_INVALID);
}
