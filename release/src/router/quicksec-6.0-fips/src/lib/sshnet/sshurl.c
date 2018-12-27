/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RFC2396; Uniform Resource Identifiers (URI): Generic Syntax
   URL and HTTP POST data encode and decode.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_list.h"
#include "sshurl.h"

/* Query container has the following properties:
   - it retains orders of entries on enumeration.
   - individual entries within query are accessible via their name. */

struct SshUrlQueryRec {
  SshADTContainer by_name;
  SshADTContainer by_position;
  size_t nentries;

  /* For old API compability, this stores the copy of query string
     when parsing. */
  char *query_string;
};

typedef struct SshUrlQueryRec SshUrlQueryStruct;

/* Query entry container has the following properties:
   - Other questions with the same key can be accessed from the entry. */
struct SshUrlEntryRec {
  SshADTMapHeaderStruct adt_by_name;
  SshADTListHeaderStruct adt_by_postition;

  unsigned char *key;
  size_t key_len;
  unsigned char *value;
  size_t value_len;

  struct SshUrlEntryRec *next_same_entry;
  struct SshUrlEntryRec *prev_same_entry;

  /* Handle for ordered enumeration. */
  SshADTHandle handle;
};

typedef struct SshUrlEntryRec SshUrlEntryStruct;

static SshUInt32
url_entry_key_hash(const void *object, void *context)
{
  SshUrlEntry e = (SshUrlEntry) object;
  SshUInt32 h = 0;
  size_t i;

  for (i = 0; i < e->key_len; i++)
    {
      h += e->key[i];
      h += h << 10;
      h ^= h >> 6;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;
  return h;
}

static int
url_entry_key_compare(const void *object1, const void *object2,
                      void *context)
{
  SshUrlEntry e1 = (SshUrlEntry) object1, e2 = (SshUrlEntry) object2;

  if (e1->key_len == e2->key_len)
    return memcmp(e1->key, e2->key, e1->key_len);
  else
    return (int)(e1->key_len - e2->key_len);
}

static void
url_entry_destroy(void *object, void *context)
{
  ssh_url_entry_destroy(object);
}

SshUrlQuery
ssh_url_query_allocate(void)
{
  SshUrlQuery query;

  query = ssh_malloc(sizeof(*query));
  if (query == NULL)
    return NULL;

  query->by_name =
    ssh_adt_create_generic(SSH_ADT_MAP,
                           SSH_ADT_HASH,    url_entry_key_hash,
                           SSH_ADT_COMPARE, url_entry_key_compare,
                           SSH_ADT_DESTROY, url_entry_destroy,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshUrlEntryStruct,
                                             adt_by_name),
                           SSH_ADT_ARGS_END);
  if (query->by_name != NULL)
    {
      query->by_position =
        ssh_adt_create_generic(SSH_ADT_LIST, SSH_ADT_ARGS_END);
      if (query->by_position != NULL)
        {
          query->query_string = NULL;
          query->nentries = 0;
          return query;
        }
      ssh_adt_destroy(query->by_name);
    }

  ssh_free(query);
  return NULL;
}

void
ssh_url_query_free(SshUrlQuery query)
{
  if (query)
    {
      ssh_adt_destroy(query->by_position);
      ssh_adt_destroy(query->by_name);
      ssh_free(query->query_string);
      ssh_free(query);
    }
}


/* Create entry from key and value. Both key and value may be NULL
   pointers. Input values are copied from application memory.

   Return values: Pointer to an URL query entry, or NULL, if memory
   allocation failed. */

SshUrlEntry
ssh_url_entry_create(const unsigned char *key, size_t key_len,
                     const unsigned char *value, size_t value_len)
{
  SshUrlEntry p;

  p = ssh_calloc(1, sizeof(*p));
  if (p != NULL)
    {
      if (key)
        {
          p->key = ssh_memdup(key, key_len);
          if (p->key == NULL)
            goto failed;

          p->key_len = key_len;
        }
      if (value)
        {
          p->value = ssh_memdup(value, value_len);
          if (p->value == NULL)
            {
            failed:
              ssh_free(p->key);
              ssh_free(p);
              return NULL;
            }

          p->value_len = value_len;
        }

      return p;
    }
  return NULL;
}

#define UNRESERVED "-_.~*'()"
#define RESERVED   ";/?:@&=+$,"


#define VALUE(_c) \
  (unsigned char )(((_c) >= 'A' && (_c) <= 'F') ? ((_c) - ('A' - 10)) : \
    ((_c) >= 'a' && (_c) <= 'f') ? ((_c) - ('a' - 10)) : \
    ((_c) - '0'))
#define HEXBYTE(_hex) (((VALUE(_hex[0]) << 4) + (VALUE(_hex[1]))))

/* Decode data into output. This checks for zero length data. */
static SshUrlError
url_data_decode(const unsigned char *data, size_t data_len,
                unsigned char **output, size_t *output_len)
{
  SshBufferStruct b;
  unsigned char value;
  int rv = 0;
  size_t left = data_len;
  SshUrlError ret = SSH_URL_OK;

  ssh_buffer_init(&b);

  while (left > 0 && rv == 0)
    {
      if (*data == '+')
        {
          rv += ssh_buffer_append(&b, (unsigned char *)" ", 1);
          data += 1;
          left -= 1;
          continue;
        }
      if (*data == '%')
        {
          if (left >= 3 &&
              isxdigit((int)*(data + 1)) &&
              isxdigit((int)*(data + 2)))
            {
              value = HEXBYTE((data + 1));
              rv += ssh_buffer_append(&b, &value, 1);
              data += 3;
              left -= 3;
              continue;
            }
          else
            {
              rv = 1;
              ret = SSH_URL_INVALID_ENCODING;
              continue;
            }
        }

      rv += ssh_buffer_append(&b, (unsigned char *)data, 1);
      data += 1;
      left -= 1;
    }

  rv  += ssh_buffer_append(&b, (unsigned char *)"\000", 1);

  if (output_len) *output_len = 0;
  *output = NULL;

  if (ret == SSH_URL_OK)
    {
      if (rv == 0)
        {
          *output = ssh_buffer_steal(&b, output_len);
          if (*output != NULL)
            {
              if (output_len)
                *output_len -= 1; /* Compensate terminal NUL */
            }
          else
            ret = SSH_URL_NO_MEMORY;
        }
      else
        {
          *output = NULL;
          ret = SSH_URL_NO_MEMORY;
        }
    }

  ssh_buffer_uninit(&b);
  return ret;
}

unsigned char *
ssh_url_data_decode(const unsigned char *data, size_t data_len,
                    size_t *output_len)
{
  unsigned char *output;

  if (url_data_decode(data, data_len, &output, output_len) == SSH_URL_OK)
    return output;
  else
    return NULL;
}

static SshUrlError
url_data_encode(const unsigned char *data, size_t data_len,
                unsigned char **output, size_t *output_len,
                const char *safe_characters)
{
  SshBufferStruct b;
  size_t i;
  int rv = 0;
  SshUrlError ret;

  ssh_buffer_init(&b);
  for (i = 0; i < data_len; i++)
    {
      if (isalnum((int)data[i]) || strchr(safe_characters, data[i]))
        {
          rv += ssh_buffer_append(&b, (unsigned char *)&data[i], 1);
          continue;
        }
      else
        {
          unsigned char temp[4];
          ssh_snprintf(temp, sizeof(temp), "%%%02x", data[i]);
          rv += ssh_buffer_append(&b, temp, 3);
        }
    }

  ret = SSH_URL_NO_MEMORY;
  if (rv == 0)
    {
      ssh_buffer_append(&b, (unsigned char *)"\000", 1);
      *output = ssh_buffer_steal(&b, output_len);
      if (*output != NULL)
        {
          if (output_len)
            *output_len -= 1;

          ret = SSH_URL_OK;
        }
    }

  ssh_buffer_uninit(&b);

  return ret;
}

unsigned char *
ssh_url_data_encode(const unsigned char *data, size_t data_len,
                    size_t *output_len)
{
  unsigned char *output;

  if (url_data_encode(data, data_len, &output, output_len, "-_.!~*'()")
      == SSH_URL_OK)
    return output;
  else
    return NULL;
}

/* Get key value from given URL query entry. Lenght of key is filled
   into 'len' argument, if it is not a NULL pointer.

   Return value: Pointer to key value within the given entry or NULL,
   if the entry does not contain key.  The pointer returned belongs to
   the 'entry' container and must not be freed by the application. */
const unsigned char *
ssh_url_entry_key(SshUrlEntry entry, size_t *len)
{
  if (len) *len = entry->key_len;
  return entry->key;
}

/* Get data value from given URL query entry. Lenght of value is filled
   into 'len' argument, if it is not a NULL pointer.

   Return value: Pointer to data value within the given entry or NULL,
   if the entry does not contain data.  The pointer returned belongs
   to the 'entry' container and must not be freed by the
   application. */
const unsigned char *
ssh_url_entry_value(SshUrlEntry entry, size_t *len)
{
  if (len)
    *len = entry->value_len;

  return entry->value;
}

/* Destroy an query entry that is not part of a query. Entrys
   belonging to a query are destroyed when the query is freed. */
void
ssh_url_entry_destroy(SshUrlEntry entry)
{
  ssh_free(entry->value);
  ssh_free(entry->key);
  ssh_free(entry);
}

static SshUrlError
ssh_url_query_new_entry(SshUrlQuery *query, const unsigned char *data,
                        size_t len)
{
  SshUrlEntry entry;
  SshUrlError rv;
  const unsigned char *key;
  unsigned char *value;
  unsigned char *dekey = NULL, *deval = NULL;
  size_t dekey_len = 0, deval_len = 0, key_len, value_len;

  if (len == 0)
    return SSH_URL_OK;

  if (*query == NULL)
    {
      *query = ssh_url_query_allocate();
      if (*query == NULL)
        return SSH_URL_NO_MEMORY;
    }

  key = data;
  value = ssh_ustrchr(data, '=');

  if (value == NULL || ((size_t)(value - data) > len))
    {
      /* Check the equal sign was on this entry. If not, the entry has
         no value, only key that extends till the end of entry. */
      key_len = len;
      value_len = 0;
    }
  else
    {
      key_len = value - key;
      value++;
      value_len = len - key_len - 1;
    }

  rv = url_data_decode(key, key_len, &dekey, &dekey_len);
  if (rv != SSH_URL_OK)
    return rv;

  if (value != NULL)
    {
      if (url_data_decode(value, value_len, &deval, &deval_len) != SSH_URL_OK)
        {
          ssh_free(dekey);
          return SSH_URL_INVALID_ENCODING;
        }
    }

  entry = ssh_url_entry_create(dekey, dekey_len, deval, deval_len);
  if (entry != NULL)
    ssh_url_query_entry_insert(*query, entry);

  ssh_free(dekey);
  ssh_free(deval);

  return SSH_URL_OK;
}

/* Parse GET data. Decode URL escaped character sequences.
  scheme://  [authority]/[path][#fragment]  (case 0)
  [scheme://][authority]/[path][#fragment]  (case 1)
  [scheme:]  [authority]/[path][#fragment]  (case 2)
             [authority][/][path][#fragment]  (case 3)

  If relaxed form is allowed, this will consider cases 1, 2, and 3
  as valid. If not, only form 0 is valid.

  -> file:relative-path
*/
SshUrlError
ssh_url_parse_get(const unsigned char *url,
                  unsigned char **scheme,
                  unsigned char **authority,
                  unsigned char **path,
                  SshUrlQuery *queries,
                  unsigned char **fragment,
                  Boolean relaxed)
{
  const unsigned char *p, *q;
  SshUrlError rv = SSH_URL_NO_MEMORY;


  if (scheme)
    *scheme = NULL;

  if (authority)
    *authority = NULL;

  if (path)
    *path = NULL;

  if (fragment)
    *fragment = NULL;

  if (queries)
    *queries = NULL;

  p = url;

  /* Skip whitespace */
  while (isspace((int)*p))
    p++;

  if (!*p)
    return SSH_URL_INVALID_ENCODING;

  q = p;

  /* scheme = alpha *( alpha | digit | "+" | "-" | "." ) */
  while (isalpha((int)*p) ||
         isdigit((int)*p) ||
         *p == '+' || *p == '-' || *p == '.')
    p++;

  /* Check for scheme */
  if (*p == ':')
    {
      if (scheme != NULL)
        {
          *scheme = ssh_memdup(q, p - q);
          if (*scheme == NULL)
            goto failed;
        }

      p++;
    }
  else
    {
      /* Missing or invalid scheme */
      if (!relaxed)
        return SSH_URL_INVALID_ENCODING;
      else
        {
          p = q;
          goto relax_no_scheme;
        }
    }

  /* authority = from end of scheme till the next '/', '?' or end */
  if (*p == '/' && *(p+1) == '/' && *(p+2) != '/')
    {
      p += 2;
      q = p;

    relax_no_scheme:
      while (*p && *p != '/' && *p != '?')
        p++;

      if (authority && (p != q))
        {
          *authority = ssh_memdup(q, p - q);
          if (*authority == NULL)
            goto failed;
        }
    }

  /* path = end of scheme or authority till the next '?', '#' or end */

  /* Now p points to either end of scheme (in case not having seen
     exactly two '/'s, or end of authority (eol, '?' or '/') */

  if (*p)
    {
      /* Get rid of slashes if file has two or more */
      if (scheme != NULL &&
          (*scheme != NULL) &&
          !strncmp((char *)*scheme, "file", 4))
        {
          if (!strncmp(p, "//", 2))
            {
              while (*p == '/')
                p++;
            }
        }
      else
        {
          while (*p == '/')
            p++;
        }

      q = p;
      while (*p && *p != '?' && *p != '#')
        p++;

      if (path && (p != q))
        {
          *path = ssh_memdup(q, p - q);
          if (*path == NULL)
            {
              rv = SSH_URL_NO_MEMORY;
              goto failed;
            }
        }
    }

  /* query = from '?' till the next '#' or end */
  if (queries && *p == '?')
    {
      const unsigned char *qs;

      p++;
      qs = q = p;

      rv = SSH_URL_OK;
      while ((rv == SSH_URL_OK) &&
             ((p = ssh_ustrchr(q, '&')) != NULL))
        {
          rv = ssh_url_query_new_entry(queries, q, p - q);
          q = p + 1;
        }
      if (rv != SSH_URL_OK)
        goto failed;

      p = q;
      while (*p && *p != '#')
        p++;

      rv = ssh_url_query_new_entry(queries, q, p - q);
      if (rv != SSH_URL_OK)
        goto failed;

      /* We may have had an empty query string, in which case queries
         points to a NULL container. */
      if (*queries && (p != qs))
        (*queries)->query_string = ssh_memdup(qs, p - qs);
    }

  /* fragment = from '#' till the end */
  if (*p == '#')
    {
      p++;
      q = p;
      while (*p) p++;
      if (fragment)
        {
          rv = url_data_decode(q, p - q, (unsigned char **)fragment, NULL);
          if (rv != SSH_URL_OK)
            {
              goto failed;
            }
        }
    }

  return SSH_URL_OK;

 failed:

  if (scheme) { ssh_free(*scheme); *scheme = NULL; }
  if (authority) { ssh_free(*authority); *authority = NULL; }
  if (path) { ssh_free(*path); *path = NULL; }
  if (fragment) { ssh_free(*fragment); *fragment = NULL; }
  if (queries && *queries)
    {
      ssh_url_query_free(*queries);
      *queries = NULL;
    }

  return rv;
}

/* Authority handling.
   -> [[ user [":" password] "@"] host [":" port] */
SshUrlError
ssh_url_parse_authority(const unsigned char *authority,
                        unsigned char **username, unsigned char **password,
                        unsigned char **host, unsigned char **port)
{
  const unsigned char *p, *q;
  SshUrlError rv;

  p = authority;
  q = NULL;

  if (username) *username = NULL;
  if (password) *password = NULL;
  if (host) *host = NULL;
  if (port) *port = NULL;

  /* Scan to see if username and possibly password is present. */
  while (*p && *p != '@' && *p != '/')
    {
      if (*p == ':')
        q = p;
      p++;
    }

  if (*p == '@')
    {
      /* We have userinfo. Now, if q is not NULL from previous loop,
         we also have colon, thus password present between ]q,p[.
         username is between [authority, q ? q : p [*/
      if (q)
        {
          if (password)
            {
              rv = url_data_decode(q + 1, p - (q + 1), password, NULL);
              if (rv != SSH_URL_OK)
                goto failed;
            }
          if (username)
            {
              rv = url_data_decode(authority, q - authority, username, NULL);
              if (rv != SSH_URL_OK)
                goto failed;
            }
        }
      else
        {
          if (username)
            {
              rv = url_data_decode(authority, p - authority, username, NULL);
              if (rv != SSH_URL_OK)
                goto failed;
            }
        }

      /* Skip at sign to start host portion */
      p++;
    }
  else
    {
      /* No userinfo, authority starts host portion */
      p = authority;
    }

  /* Then enter host portion. First scan for IPv6 address.  */
  if (*p == '[')
    {
      q = p + 1;
      while (*q && (isxdigit((int)*q) || *q == '.' || *q == ':'))
        q++;

      if (*q == ']')
        {
          if (host)
            {
              *host = ssh_memdup(p, q - p + 1);
              if (*host == NULL)
                {
                  rv = SSH_URL_NO_MEMORY;
                  goto failed;
                }

              q++;
            }
        }
      else
        {
          /* IPv6 address was not terminated properly. Assume it is a
             host name */
          if (host)
            {
              q = p;
              while (*q && *q != ':' && *q != '/')
                q++;
              if (host)
                {
                  *host = ssh_memdup(p, q - p);
                  if (*host == NULL)
                    {
                      rv = SSH_URL_NO_MEMORY;
                      goto failed;
                    }
                }
            }
        }
    }
  else
    {
      q = p;
      while (*q && *q != ':' && *q != '/')
        q++;
      if (host)
        {
          *host = ssh_memdup(p, q - p);
          if (*host == NULL)
            {
              rv = SSH_URL_NO_MEMORY;
              goto failed;
            }
        }
    }

  /* Then process port. q points to either end of host, or colon
     after host, where post shoud begin. */
  if (*q == ':')
    {
      q++;
      p = q;

      while (isdigit((int)*q))
        q++;
      if (port)
        {
          *port = ssh_memdup(p, q - p);
          if (*port == NULL)
            {
              rv = SSH_URL_NO_MEMORY;
              goto failed;
            }
        }
    }
  return SSH_URL_OK;

 failed:
  if (username) { ssh_free(*username); *username = NULL; }
  if (password) { ssh_free(*password); *password = NULL; }
  if (host) { ssh_free(*host); *host = NULL; }
  if (port) { ssh_free(*port); *port = NULL; }
  return rv;
}

SshUrlError
ssh_url_construct_authority(const unsigned char *username,
                            const unsigned char *password,
                            const unsigned char *host,
                            const unsigned char *port,
                            unsigned char **authority)
{
  SshBufferStruct b;
  int bs;
  SshUrlError rv;
  SshIpAddrStruct ipaddr;
  Boolean host_is_ip6addr = FALSE;

  ssh_buffer_init(&b);

  bs = 0;

  if (username)
    bs += ssh_buffer_append_cstrs(&b, username, NULL);

  if (password)
    bs += ssh_buffer_append_cstrs(&b, ":", password, NULL);

  if (username || password)
    bs += ssh_buffer_append_cstrs(&b, "@", NULL);

  if (ssh_ipaddr_parse(&ipaddr, host))
    {
      if (SSH_IP_IS6(&ipaddr))
        host_is_ip6addr = TRUE;
      if (*host == '[')
        {
          host_is_ip6addr = FALSE;
        }
    }

  bs += ssh_buffer_append_cstrs(&b,
                                host_is_ip6addr ? "[" : "",
                                host,
                                host_is_ip6addr ? "]" : "",
                                NULL);

  if (port)
    bs += ssh_buffer_append_cstrs(&b, ":", port, NULL);

  bs += ssh_buffer_append(&b, (unsigned char *)"\000", 1);

  if (bs != 0)
    {
      *authority = NULL;
      rv = SSH_URL_NO_MEMORY;
    }
  else
    {
      *authority = ssh_buffer_steal(&b, NULL);
      rv = SSH_URL_OK;
    }

  ssh_buffer_uninit(&b);
  return rv;
}

static SshUrlError
url_construct_query(SshBuffer b, SshUrlQuery query)
{
  int bs = 0;
  unsigned char *p;
  size_t len;

  if (query)
    {
      bs += ssh_buffer_append_cstrs(b, "?", NULL);

      if (query->nentries)
        {
          SshUrlEntry entry, next;
          const unsigned char *key, *val;
          size_t key_len, val_len;

          for (entry = ssh_url_query_enumerate_start(query);
               bs == 0 && entry;
               entry = next)
            {
              next = ssh_url_query_enumerate_next(query, entry);

              key = ssh_url_entry_key(entry, &key_len);
              val = ssh_url_entry_value(entry, &val_len);

              if (key)
                {
                  if (url_data_encode(key, key_len, &p, &len,
                                      "-_.!~*'()")
                      == SSH_URL_OK)
                    {
                      bs += ssh_buffer_append(b, p, len);
                      ssh_free(p);
                    }
                }
              if (val)
                {
                  if (url_data_encode(val, val_len, &p, &len, "-_.!~*'()")
                      == SSH_URL_OK)
                    {
                      bs += ssh_buffer_append_cstrs(b, "=", NULL);
                      bs += ssh_buffer_append(b, p, len);
                      ssh_free(p);
                    }
                }
              if (next)
                {
                  bs += ssh_buffer_append_cstrs(b, "&", NULL);
                }
            }
        }
    }
  return bs == 0 ? SSH_URL_OK : SSH_URL_NO_MEMORY;
}

/* Construct URL get from scheme, authority, path, queries and fragment, and
   fills properly encoded URL into 'url'.

   Return value: SSH_URL_OK if url encoding was successful, or some of
   the URL error values. 'url' will be set to NULL in case of error
   return. */
SshUrlError
ssh_url_construct_get(const unsigned char *scheme,
                      const unsigned char *authority,
                      const unsigned char *path,
                      const SshUrlQuery query,
                      const unsigned char *fragment,
                      unsigned char **url)
{
  SshBufferStruct b;
  int bs = 0;
  unsigned char *p;
  size_t len;

  ssh_buffer_init(&b);

  if (scheme)
    bs += ssh_buffer_append_cstrs(&b, scheme, ":", NULL);

  if (authority)
    bs += ssh_buffer_append_cstrs(&b, "//", authority, NULL);

  if (path)
    {
      if (url_data_encode(path, ssh_ustrlen(path),
                          &p, &len, "@-_.!~*'()/")
          == SSH_URL_OK)
        {
          bs += ssh_buffer_append_cstrs(&b, p, NULL);
          ssh_free(p);
        }
    }

  if (query && query->nentries > 0)
    {
      if (url_construct_query(&b, query) != SSH_URL_OK)
        bs = 1;
    }

  if (fragment)
    {
      if (url_data_encode(fragment, ssh_ustrlen(fragment),
                          &p, &len, "-_.!~*'()")
          == SSH_URL_OK)
        {
          bs += ssh_buffer_append_cstrs(&b, "#", NULL);
          ssh_free(p);
        }
    }

  if (bs == 0)
    {
      ssh_buffer_append(&b, (unsigned char *)"\000", 1);
      p = ssh_buffer_steal(&b, NULL);
    }
  else
    {
      p = NULL;
    }

  ssh_buffer_uninit(&b);
  *url = p;

  return bs == 0 ? SSH_URL_OK: SSH_URL_NO_MEMORY;
}

/* Parse POST data. Decode URL escaped character sequences. */
SshUrlError
ssh_url_parse_post(const unsigned char *data, SshUrlQuery *queries)
{
  const unsigned char *p, *q;
  SshUrlError rv = SSH_URL_OK;

  q = data;
  while ((rv == SSH_URL_OK) &&
         ((p = ssh_ustrchr(q, '&')) != NULL))
    {
      rv = ssh_url_query_new_entry(queries, q, p - q);
      q = p + 1;
    }
  if (rv != SSH_URL_OK)
    goto failed;

  p = q;
  while (*p)
    p++;

  rv = ssh_url_query_new_entry(queries, q, p - q);
  if (rv != SSH_URL_OK)
    goto failed;

  return rv;

 failed:
  if (*queries)
    ssh_url_query_free(*queries);
  return rv;
}

/* Construct post data. URL encode entrys. */
SshUrlError
ssh_url_construct_post(SshUrlQuery query, unsigned char **data)
{
  SshBufferStruct b;
  int bs = 0;

  if (!data)
    return SSH_URL_OK;

  ssh_buffer_init(&b);

  if (url_construct_query(&b, query) != SSH_URL_OK)
    bs = 1;

  if (bs == 0)
    {
      ssh_buffer_append(&b, ssh_custr("\000"), 1);
      *data = ssh_buffer_steal(&b, NULL);
    }
  else
    {
      *data = NULL;
    }

  ssh_buffer_uninit(&b);

  return bs == 0 ? SSH_URL_OK: SSH_URL_NO_MEMORY;
}

/* Enumerate entries within the query. The entries are returned in
   oder they were at the url, post data, or inserted into query. */
SshUrlEntry
ssh_url_query_enumerate_start(SshUrlQuery query)
{
  SshADTHandle h;
  SshUrlEntry entry = NULL;

  h = ssh_adt_enumerate_start(query->by_position);
  if (h != SSH_ADT_INVALID)
    {
      entry = ssh_adt_get(query->by_position, h);
      entry->handle = h;
    }
  return entry;
}


SshUrlEntry
ssh_url_query_enumerate_next(SshUrlQuery query, SshUrlEntry current)
{
  SshADTHandle h;
  SshUrlEntry entry = NULL;

  h = ssh_adt_enumerate_next(query->by_position, current->handle);
  if (h != SSH_ADT_INVALID)
    {
      entry = ssh_adt_get(query->by_position, h);
      entry->handle = h;
    }

  return entry;
}

/* Insert a entry into the tail of the query. By ADT implementation we
   know this is fast. */
SshUrlError
ssh_url_query_entry_insert(SshUrlQuery query, SshUrlEntry entry)
{
  SshUrlEntry oldentry;
  const unsigned char *entry_key;
  size_t entry_key_len;

  entry_key = ssh_url_entry_key(entry, &entry_key_len);

  /* Update next same entry of the last possibly previously existing
     entry with the same key */
  if (entry_key &&
      (oldentry = ssh_url_query_get_entry(query, entry_key, entry_key_len))
      != NULL)
    {
      while (oldentry->next_same_entry != NULL)
        oldentry = oldentry->next_same_entry;

      oldentry->next_same_entry = entry;
      entry->prev_same_entry = oldentry;
    }

  ssh_adt_insert(query->by_name, entry);
  ssh_adt_insert_to(query->by_position, SSH_ADT_END, entry);
  query->nentries += 1;
  return SSH_URL_OK;
}

/* Remove the entry from the query. This removes only the exact
   entry entry, not other with the same key. The entry pointer
   given must originate from within the query. */
SshUrlError
ssh_url_query_entry_delete(SshUrlQuery query, SshUrlEntry entry)
{
  SshADTHandle mh, lh;

  mh = ssh_adt_get_handle_to(query->by_name, entry);
  if (mh != SSH_ADT_INVALID)
    {
      /* This will always be successful if the first one is, or we are
         corrupted internally. */
      lh = ssh_adt_get_handle_to(query->by_position, entry);

      if (entry->prev_same_entry)
        entry->prev_same_entry->next_same_entry = entry->next_same_entry;
      if (entry->next_same_entry)
        entry->next_same_entry->prev_same_entry = entry->prev_same_entry;

      ssh_adt_detach(query->by_name, mh);
      ssh_adt_detach(query->by_position, lh);
      query->nentries -= 1;
      return SSH_URL_OK;
    }
  return SSH_URL_NO_SUCH_OBJECT;
}

/* Get the entry with given key from query. */
SshUrlEntry
ssh_url_query_get_entry(SshUrlQuery query,
                        const unsigned char *name, size_t name_len)
{
  SshUrlEntryStruct probe;
  SshUrlEntry entry;
  SshADTHandle mh;

  probe.key = (unsigned char *)name;
  probe.key_len = name_len;

  mh = ssh_adt_get_handle_to_equal(query->by_name, &probe);
  if (mh != SSH_ADT_INVALID)
    {
      entry = ssh_adt_get(query->by_name, mh);
      if (entry)
        {
          /* Select the first of same entries. */
          while (entry->prev_same_entry)
            entry = entry->prev_same_entry;
        }
      return entry;
    }
  return NULL;
}

/* Get the next entry from query containing the same key the
   entry given contains. */
SshUrlEntry
ssh_url_query_get_next_same_entry(SshUrlQuery query,
                                  SshUrlEntry entry)
{
  return entry->next_same_entry;
}


/*****************************************************************************
 * OLD API convenience functions for parsing GET URI
 *
 * In priciple this API should disappear, however this is not likely
 */

static Boolean
url_parse_old(const unsigned char *url, unsigned char **scheme,
              unsigned char **host, unsigned char **port,
              unsigned char **username, unsigned char **password,
              unsigned char **path, Boolean relax)
{
  unsigned char *authority, *fragment;
  Boolean rv = FALSE;
  SshUrlQuery query;
  SshBufferStruct b;

  if (ssh_url_parse_get(url,
                        scheme, &authority, path, &query, &fragment, relax)
      == SSH_URL_OK)
    {
      rv = TRUE;
      if (authority)
        {

          if (host) *host = NULL;
          if (port) *port = NULL;
          if (username) *username = NULL;
          if (password) *password = NULL;

          if (host || port || username || password)
            {
              if (ssh_url_parse_authority(authority,
                                          username, password, host, port)
                  != SSH_URL_OK)
                {
                  if (scheme) { ssh_free(*scheme); *scheme = NULL; }
                  if (path) { ssh_free(*path); *path = NULL; }
                  rv = FALSE;
                }
            }
          ssh_free(authority);
        }

      /* Old API had query components as part of the path. If we have
         requested path, patch it. */
      if (path &&
          rv && query && query->query_string)
        {
          ssh_buffer_init(&b);

          ssh_buffer_append_cstrs(&b,
                                  *path ? *path : ssh_custr(""),
                                  "?", query->query_string,
                                  NULL);

          ssh_buffer_append(&b, (unsigned char *)"\000", 1);

          ssh_free(*path);
          *path = ssh_buffer_steal(&b, NULL);
          ssh_buffer_uninit(&b);
        }
      ssh_url_query_free(query);

      /* Old API returned fragment as part of path. Compensate this as
         well. */
      if (path && fragment)
        {
          ssh_buffer_init(&b);

          ssh_buffer_append_cstrs(&b,
                                  *path ? *path : ssh_custr(""),
                                  "#", fragment,
                                  NULL);
          ssh_buffer_append(&b, (unsigned char *)"\000", 1);

          ssh_free(*path);
          *path = ssh_buffer_steal(&b, NULL);
          ssh_buffer_uninit(&b);
        }
      ssh_free(fragment);
    }

  return rv;
}

Boolean
ssh_url_parse(const unsigned char *url, unsigned char **scheme,
              unsigned char **host, unsigned char **port,
              unsigned char **user, unsigned char **pass,
              unsigned char **path)
{
  return url_parse_old(url,
                       scheme, host, port, user, pass, path,
                       FALSE);
}

Boolean
ssh_url_parse_and_decode(const unsigned char *url, unsigned char **scheme,
                         unsigned char **host, unsigned char **port,
                         unsigned char **user, unsigned char **pass,
                         unsigned char **path)
{
  return url_parse_old(url,
                       scheme, host, port, user, pass, path,
                       FALSE);
}

Boolean
ssh_url_parse_relaxed(const unsigned char *url, unsigned char **scheme,
                      unsigned char **host, unsigned char **port,
                      unsigned char **user, unsigned char **pass,
                      unsigned char **path)
{
  return url_parse_old(url,
                       scheme, host, port, user, pass, path,
                       TRUE);
}

Boolean
ssh_url_parse_and_decode_relaxed(const unsigned char *url,
                                 unsigned char **scheme, unsigned char **host,
                                 unsigned char **port, unsigned char **user,
                                 unsigned char **pass, unsigned char **path)
{
  return url_parse_old(url,
                       scheme, host, port, user, pass, path,
                       TRUE);
}

/* eof */
