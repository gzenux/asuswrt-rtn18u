/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General HTTP utilities which are used in both client and server
   implementations.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshhttpi.h"
#include "sshhttp_status.h"
#include "sshenum.h"
#include "sshadt.h"
#include "sshadt_bag.h"

/*
 * Types and definitions.
 */

#define SSH_DEBUG_MODULE "SshHttpUtils"


/*
 * Static variables.
 */

static const SshKeywordStruct status_code_keywords[] =
{
  {"Continue",                          SSH_HTTP_STATUS_CONTINUE},
  {"Switching Protocols",               SSH_HTTP_STATUS_SWITCHING_PROTOCOLS},

  {"OK",                                SSH_HTTP_STATUS_OK},
  {"Created",                           SSH_HTTP_STATUS_CREATED},
  {"Accepted",                          SSH_HTTP_STATUS_ACCEPTED},
  {"Non-Authoritative Information",
   SSH_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION},
  {"No Content",                        SSH_HTTP_STATUS_NO_CONTENT},
  {"Reset Content",                     SSH_HTTP_STATUS_RESET_CONTENT},
  {"Partial Content",                   SSH_HTTP_STATUS_PARTIAL_CONTENT},

  {"Multiple Choices",                  SSH_HTTP_STATUS_MULTIPLE_CHOICES},
  {"Moved Permanently",                 SSH_HTTP_STATUS_MOVED_PERMANENTLY},
  {"Found",                             SSH_HTTP_STATUS_FOUND},
  {"See Other",                         SSH_HTTP_STATUS_SEE_OTHER},
  {"Not Modified",                      SSH_HTTP_STATUS_NOT_MODIFIED},
  {"Use Proxy",                         SSH_HTTP_STATUS_USE_PROXY},
  {"Temporary Redirect",                SSH_HTTP_STATUS_TEMPORARY_REDIRECT},

  {"Bad Request",                       SSH_HTTP_STATUS_BAD_REQUEST},
  {"Unauthorized",                      SSH_HTTP_STATUS_UNAUTHORIZED},
  {"Payment Required",                  SSH_HTTP_STATUS_PAYMENT_REQUIRED},
  {"Forbidden",                         SSH_HTTP_STATUS_FORBIDDEN},
  {"Not Found",                         SSH_HTTP_STATUS_NOT_FOUND},
  {"Method Not Allowed",                SSH_HTTP_STATUS_METHOD_NOT_ALLOWED},
  {"Not Acceptable",                    SSH_HTTP_STATUS_NOT_ACCEPTABLE},
  {"Proxy Authentication Required",
   SSH_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED},
  {"Request Time-out",                  SSH_HTTP_STATUS_REQUEST_TIMEOUT},
  {"Conflict",                          SSH_HTTP_STATUS_CONFLICT},
  {"Gone",                              SSH_HTTP_STATUS_GONE},
  {"Length Required",                   SSH_HTTP_STATUS_LENGTH_REQUIRED},
  {"Precondition Failed",               SSH_HTTP_STATUS_PRECONDITION_FAILED},
  {"Request Entity Too Large",
   SSH_HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE},
  {"Request-URI Too Large",             SSH_HTTP_STATUS_REQUEST_URI_TOO_LARGE},
  {"Unsupported Media Type",
   SSH_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE},
  {"Requested range not satisfiable",
   SSH_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE},
  {"Expectation Failed",                SSH_HTTP_STATUS_EXPECTATION_FAILED},

  {"Internal Server Error",             SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR},
  {"Not Implemented",                   SSH_HTTP_STATUS_NOT_IMPLEMENTED},
  {"Bad Gateway",                       SSH_HTTP_STATUS_BAD_GATEWAY},
  {"Service Unavailable",               SSH_HTTP_STATUS_SERVICE_UNAVAILABLE},
  {"Gateway Time-out",                  SSH_HTTP_STATUS_GATEWAY_TIMEOUT},
  {"HTTP Version not supported",
   SSH_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED},

  {"Unknown",                           SSH_HTTP_STATUS_UNKNOWN},
  {NULL, 0},
};


static const SshCharPtr rfc1123_wkdays[] =
{
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
};


static const SshCharPtr rfc1123_months[] =
{
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
  "Dec",
};


/*
 * Global functions.
 */

const char *
ssh_http_status_to_string(SshHttpStatusCode code)
{
  const char *str;

  str = ssh_find_keyword_name(status_code_keywords, code);
  if (str == NULL)
    str = "";

  return str;
}


unsigned char *
ssh_http_make_rfc1123_date(SshTime date)
{
  unsigned char buf[256];
  struct SshCalendarTimeRec cal[1];

  ssh_calendar_time(date, cal, FALSE);
  ssh_snprintf(buf, sizeof(buf), "%s, %02d %s %d %02d:%02d:%02d GMT",
               rfc1123_wkdays[cal->weekday], cal->monthday,
               rfc1123_months[cal->month], (int) cal->year,
               cal->hour, cal->minute, cal->second);

  return ssh_strdup(buf);
}

unsigned char *
ssh_http_unescape_attr_value(const unsigned char *value, size_t len)
{
  unsigned char *d, *new_value = ssh_malloc(len + 1);
  Boolean esc = FALSE;
  int n = 0;

  if (new_value == NULL)
    return NULL;

  for (d = new_value; n < len; n++)
    {
      if (value[n] == '\\' && esc == FALSE)
        {
          esc = TRUE;
          continue;
        }
      esc = FALSE;
      *d = value[n];
      d++;
    }
  *d = '\0';
  return new_value;
}

Boolean
ssh_http_get_av(const unsigned char *buf, unsigned int *position,
                const unsigned char **attr_return,
                unsigned int *attr_len_return,
                const unsigned char **val_return, unsigned int *val_len_return)
{
  unsigned int i = *position;
  unsigned int attr_start, attr_end;
  unsigned int val_start, val_end;

  /* Find the beginning of the next attribute (skip whitespace). */
  for (; buf[i] && isspace(buf[i]); i++)
    ;
  if (!buf[i])
    {
      /* The end of data. */
      *attr_return = NULL;
      return TRUE;
    }

  attr_start = i;

  /* Find the end of the attribute. */
  for (; buf[i] && !isspace(buf[i]) && buf[i] != '='; i++)
    ;
  attr_end = i;

  /* Find the separator '='. */
  for (; buf[i] && isspace(buf[i]); i++)
    ;
  if (!buf[i] || buf[i] != '=')
    return FALSE;

  /* Find the start of the value. */
  for (i++; buf[i] && isspace(buf[i]); i++)
    ;
  if (!buf[i])
    return FALSE;

  if (buf[i] == '"')
    {
      Boolean esc = FALSE;

      /* A '"' separated value. */
      i++;
      val_start = i;

      for (; buf[i]; i++)
        {
          if (buf[i] == '\\')
            {
              esc = TRUE;
              continue;
            }
          if (esc == TRUE)
            {
              esc = FALSE;
              continue;
            }
          if (buf[i] == '"')
            break;
        }
      if (!buf[i])
        return FALSE;

      val_end = i;
      i++;
    }
  else
    {
      /* A plain value. */
      val_start = i;

      for (; buf[i] && SSH_HTTP_IS_TOKEN_CH(buf[i]); i++)
        ;
      val_end = i;
    }

  *attr_return = buf + attr_start;
  *attr_len_return = attr_end - attr_start;

  *val_return = buf + val_start;
  *val_len_return = val_end - val_start;

  *position = i;

  return TRUE;
}



/****************************** Key-value hash ******************************/

/* A hash-table item. */
struct SshHttpKvHashItemRec
{
  /* Inlined ADT header structure. */
  SshADTHeaderStruct adt_header;

  /* The key. */
  unsigned char *key;

  /* Value. */
  unsigned char *value;
  size_t value_len;
};

typedef struct SshHttpKvHashItemRec SshHttpKvHashItemStruct;
typedef struct SshHttpKvHashItemRec *SshHttpKvHashItem;


/* The hash handle. */
struct SshHttpKvHashRec
{
  /* A mapping from keys to values. */
  SshADTContainer map;

  /* Is this hash case-insensitive. */
  Boolean case_insensitive;

  /* The last key, inserted in the hash. */
  unsigned char *last_key;

  /* Enumeration handle. */
  SshADTHandle enum_handle;
};


/* Methods for ADT bag. */

static SshUInt32
kvhash_hash(void *ptr, void *ctx)
{
  SshHttpKvHashItem item = (SshHttpKvHashItem) ptr;
  SshUInt32 hash = 0;
  int i;

  for (i = 0; item->key[i]; i++)
    hash = ((hash << 7)
            ^ ((hash >> 21) & 0xff)
            ^ ((unsigned char) item->key[i]));

  return hash;
}


static int
kvhash_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshHttpKvHashItem item1 = (SshHttpKvHashItem) ptr1;
  SshHttpKvHashItem item2 = (SshHttpKvHashItem) ptr2;

  return ssh_ustrcmp(item1->key, item2->key);
}


static void
kvhash_destroy(void *ptr, void *ctx)
{
  SshHttpKvHashItem item = (SshHttpKvHashItem) ptr;

  ssh_free(item->key);
  ssh_free(item->value);
  ssh_free(item);
}


SshHttpKvHash
ssh_http_kvhash_create(Boolean case_insensitive)
{
  SshHttpKvHash hash;

  hash = ssh_calloc(1, sizeof(*hash));
  if (hash == NULL)
    return NULL;

  hash->map = ssh_adt_create_generic(SSH_ADT_BAG,

                                     SSH_ADT_HEADER,
                                     SSH_ADT_OFFSET_OF(SshHttpKvHashItemStruct,
                                                       adt_header),

                                     SSH_ADT_HASH,      kvhash_hash,
                                     SSH_ADT_COMPARE,   kvhash_compare,
                                     SSH_ADT_DESTROY,   kvhash_destroy,
                                     SSH_ADT_ARGS_END);
  if (hash->map == NULL)
    {
      ssh_free(hash);
      return NULL;
    }

  hash->case_insensitive = case_insensitive;

  return hash;
}


void
ssh_http_kvhash_destroy(SshHttpKvHash hash)
{
  if (hash == NULL)
    return;

  ssh_adt_destroy(hash->map);
  ssh_free(hash->last_key);
  ssh_free(hash);
}


void
ssh_http_kvhash_clear(SshHttpKvHash hash)
{
  ssh_adt_clear(hash->map);

  if (hash->last_key)
    {
      ssh_free(hash->last_key);
      hash->last_key = NULL;
    }
}


Boolean
ssh_http_kvhash_put(SshHttpKvHash hash,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *value, size_t value_len)
{
  int i;
  SshADTHandle h;
  SshHttpKvHashItemStruct item_struct;

  if (hash->last_key)
    {
      ssh_free(hash->last_key);
      hash->last_key = NULL;
    }

  /* Copy the key. */
  if ((hash->last_key = ssh_memdup(key, key_len)) == NULL)
    return FALSE;

  if (hash->case_insensitive)
    /* Convert the key to upper-case. */
    for (i = 0; hash->last_key[i]; i++)
      if (islower((unsigned char) hash->last_key[i]))
        hash->last_key[i] = toupper((unsigned char) hash->last_key[i]);

  /* Do we have an old value? */

  item_struct.key = hash->last_key;
  h = ssh_adt_get_handle_to_equal(hash->map, &item_struct);
  if (h != SSH_ADT_INVALID)
    {
      SshHttpKvHashItem item = ssh_adt_get(hash->map, h);
      unsigned char *tmp;

      /* Yes we have.  The value is always null-terminated and the
         `value_len' in the item contains also the trailing null
         character. */

      if ((tmp = ssh_realloc(item->value,
                             item->value_len,
                             item->value_len + 1 + value_len)) == NULL)
        {
          return FALSE;
        }

      item->value = tmp;
      item->value[item->value_len - 1] = ',';
      memcpy(item->value + item->value_len, value, value_len);
      item->value_len += 1 + value_len;

      /* And remember the trailing null-character. */
      item->value[item->value_len - 1] = '\0';

      return TRUE;
    }
  else
    {
      SshHttpKvHashItem item;

      /* No old value. */

      if ((item = ssh_calloc(1, sizeof(*item))) != NULL)
        {
          item->key = ssh_memdup(hash->last_key, key_len);
          item->value = ssh_memdup(value, value_len);
          item->value_len = value_len + 1;

          if (item->key && item->value)
            {
              ssh_adt_insert(hash->map, item);
              return TRUE;
            }
          ssh_free(item);
        }
      return FALSE;
    }
}


Boolean
ssh_http_kvhash_put_cstrs(SshHttpKvHash hash, const unsigned char *key,
                          const unsigned char *value)
{
  return ssh_http_kvhash_put(hash, key, ssh_ustrlen(key), value,
                             ssh_ustrlen(value));
}


Boolean
ssh_http_kvhash_append_last(SshHttpKvHash hash, const unsigned char *value,
                            size_t value_len)
{
  SshADTHandle h;
  SshHttpKvHashItemStruct item_struct;
  SshHttpKvHashItem item;
  void *tmp;

  if (hash->last_key == NULL)
    return FALSE;

  item_struct.key = hash->last_key;
  h = ssh_adt_get_handle_to_equal(hash->map, &item_struct);
  if (h == SSH_ADT_INVALID)
    return FALSE;

  item = ssh_adt_get(hash->map, h);

  if ((tmp = ssh_realloc(item->value,
                         item->value_len,
                         item->value_len + value_len)) == NULL)
    return FALSE;

  item->value = tmp;
  memcpy(item->value + item->value_len - 1, value, value_len);
  item->value_len += value_len;

  /* Remember the trailing null-character. */
  item->value[item->value_len - 1] = '\0';
  return TRUE;
}


const unsigned char *
ssh_http_kvhash_get(SshHttpKvHash hash, const unsigned char *key)
{
  SshADTHandle h;
  SshHttpKvHashItemStruct item_struct;
  SshHttpKvHashItem item;

  item_struct.key = (unsigned char *) key;
  h = ssh_adt_get_handle_to_equal(hash->map, &item_struct);
  if (h == SSH_ADT_INVALID)
    return NULL;

  item = ssh_adt_get(hash->map, h);

  return item->value;
}


Boolean
ssh_http_kvhash_remove(SshHttpKvHash hash, const unsigned char *key)
{
  SshADTHandle h;
  SshHttpKvHashItemStruct item_struct;

  item_struct.key = (unsigned char *) key;
  h = ssh_adt_get_handle_to_equal(hash->map, &item_struct);
  if (h == SSH_ADT_INVALID)
    return FALSE;

  ssh_adt_delete(hash->map, h);

  return TRUE;
}


void
ssh_http_kvhash_reset_index(SshHttpKvHash hash)
{
  hash->enum_handle = ssh_adt_enumerate_start(hash->map);
}


Boolean
ssh_http_kvhash_get_next(SshHttpKvHash hash, unsigned char **key_return,
                         unsigned char **value_return)
{
  SshHttpKvHashItem item;

  if (hash->enum_handle == SSH_ADT_INVALID)
    return FALSE;

  item = ssh_adt_get(hash->map, hash->enum_handle);

  hash->enum_handle = ssh_adt_enumerate_next(hash->map, hash->enum_handle);

  if (key_return)
    *key_return = item->key;

  if (value_return)
    *value_return = item->value;

  return TRUE;
}


/*
 * Streams.
 */

/* Chunked Transfer Encoding. */

/* The maximum amount of chunked data buffered in memory. */
#define SSH_HTTP_CHUNKED_DATA_BUFFER_SIZE       4096

/* Each chunk has this much garbage at the end (the `CRLF' pair). */
#define SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE      2

/* The last-chunk and the default trailer that we will append to our
   chunked streams.  */
#define SSH_HTTP_CHUNKED_TRAILER                ((unsigned char *) "0\r\n\r\n")

/* The states in which the read part of the stream can be. */
typedef enum
{
  /* Reading the first line of a chunk.  We haven't seen a full line
     yet. */
  SSH_HTTP_CHUNKED_READING_CHUNK_SIZE_LINE,

  /* Reading the data portion of the current chunk.  We must still
     read <chunk_size> bytes to complete this chunk. */
  SSH_HTTP_CHUNKED_READING_CHUNK_DATA,

  /* All data chunks read.  Now we are reading the trailer fields. */
  SSH_HTTP_CHUNKED_READING_TRAILER,

  /* End of chunks received.  All subsequent read operations will
     return EOF. */
  SSH_HTTP_CHUNKED_READ_AT_EOF
} SshHttpChunkedStreamReadState;

/* The states in which the write part of the stream can be. */
typedef enum
{
  /* Collecting data for the next chunk. */
  SSH_HTTP_CHUNKED_WRITE_COLLECTING,

  /* Writing chunk. */
  SSH_HTTP_CHUNKED_WRITING,

  /* Writing the trailer and EOF marker. */
  SSH_HTTP_CHUNKED_WRITING_EOF,

  /* The stream has reached the EOF. */
  SSH_HTTP_CHUNKED_WRITE_AT_EOF
} SshHttpChunkedStreamWriteState;

/* Stream context. */
struct SshHttpChunkedStreamRec
{
  /* The source / destination stream for the chunked data. */
  SshStream chunked;

  /* Is the stream readable? */
  Boolean readable;

  /* Is the stream writable? */
  Boolean writable;

  /* Is the stream destroyed? */
  Boolean destroyed;

  /* Notification callback. */
  SshHttpChunkedStreamCb notification_callback;
  void *notification_callback_context;

  /* The user specified stream callback. */
  SshStreamCallback callback;
  void *callback_context;

  /* The read implementation. */
  struct
  {
    /* The read state of the stream. */
    SshHttpChunkedStreamReadState state;

    /* The number of bytes of data left in the current chunk. */
    size_t chunk_size;

    /* Buffer to hold pieces of the incoming chunked data stream. */
    SshBuffer buffer;
  } r;

  /* The write implementation. */
  struct
  {
    /* The write state of the stream. */
    SshHttpChunkedStreamWriteState state;

    /* Is the EOF seen in write? */
    Boolean eof_seen;

    /* Has the EOF been output to the stream? */
    Boolean eof_output;

    /* Did the user request an explicit flush for this stream? */
    Boolean flushed;

    /* The buffer to which the chunks are collected. */
    SshBuffer buffer;
  } w;
};

typedef struct SshHttpChunkedStreamRec SshHttpChunkedStream;


/* Read more data from the source stream.  Returns TRUE if more data
   was read or FALSE otherwise.  If more data could be read, the read
   status is returned in <rstatus_return>.  The function will call the
   notificatio callback if the in-buffer limit is exceeded. */
static Boolean
ssh_http_chunked_stream_read_more(SshHttpChunkedStream *stream,
                                  int *rstatus_return)
{
  size_t to_read = (SSH_HTTP_CHUNKED_DATA_BUFFER_SIZE
                    - ssh_buffer_len(stream->r.buffer));
  int rstatus;
  unsigned char *p;

  if (to_read > 0)
    {
      if (ssh_buffer_append_space(stream->r.buffer, &p, to_read)
          != SSH_BUFFER_OK)
        goto failed;

      rstatus = ssh_stream_read(stream->chunked, p, to_read);

      if (rstatus <= 0)
        ssh_buffer_consume_end(stream->r.buffer, to_read);
      else
        /* Got some new data. */
        ssh_buffer_consume_end(stream->r.buffer, to_read - rstatus);

      *rstatus_return = rstatus;
      return TRUE;
    }
 failed:
  /* Call the notification.  Can't buffer enought data in the memory. */
  if (stream->notification_callback)
    (*stream->notification_callback)(
                        SSH_HTTP_CHUNKED_STREAM_READ_MAX_BUFFER_SIZE_REACHED,
                        NULL, 0, NULL, 0,
                        stream->notification_callback_context);

  return FALSE;
}


static int
ssh_http_chunked_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;
  int rstatus;
  unsigned char *p;
  unsigned int i, j;
  size_t buflen;
  SshUInt32 start;

  if (!stream->readable)
    /* Read is not allowed.  We are at the EOF. */
    return 0;

  while (1)
    {
      buflen = ssh_buffer_len(stream->r.buffer);
      p = ssh_buffer_ptr(stream->r.buffer);

      /* What should we do? */
      switch (stream->r.state)
        {
        case SSH_HTTP_CHUNKED_READING_CHUNK_SIZE_LINE:
          /* Do we have one line of input? */
          for (i = 0; i < buflen && p[i] != '\n'; i++)
            ;

          if (i >= buflen)
            {
              /* We don't have one line of input.  Read more. */
              if (!ssh_http_chunked_stream_read_more(stream, &rstatus))
                return 0;

              if (rstatus < 0)
                /* Can't read more since we would block. */
                return -1;
              if (rstatus == 0)
                {
                  /* EOF reached. */
                  SSH_DEBUG(5, ("Premature EOF in size line"));
                  if (stream->notification_callback)
                    (*stream->notification_callback)(
                                SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_SIZE_LINE,
                                NULL, 0, NULL, 0,
                                stream->notification_callback_context);
                  return 0;
                }
              /* Retry. */
              continue;
            }

          /* Got one line of input. */

          /* Get the size (it is in hex). Forcing null-termination
           * for strtol. */
          if (ssh_buffer_append(stream->r.buffer, (unsigned char *)"\0", 1)
              != SSH_BUFFER_OK)
            {
              if (stream->notification_callback)
                (*stream->notification_callback)(
                       SSH_HTTP_CHUNKED_STREAM_READ_MAX_BUFFER_SIZE_REACHED,
                       NULL, 0, NULL, 0,
                       stream->notification_callback_context);
              return 0;
            }

          p = ssh_buffer_ptr(stream->r.buffer);
          stream->r.chunk_size = strtol((char *) p, NULL, 16);
          ssh_buffer_consume_end(stream->r.buffer, 1);

          SSH_DEBUG(9, ("chunk-size=%u", stream->r.chunk_size));

          /* Ignore all chunk extensions. */

          /* Remove the line from our input buffer.  Everything after
             that are our chunk data. */
          i++;
          ssh_buffer_consume(stream->r.buffer, i);

          if (stream->r.chunk_size == 0)
            /* Last chunk received. */
            stream->r.state = SSH_HTTP_CHUNKED_READING_TRAILER;
          else
            {
              /* The chunk data is terminated with the `CRLF'
                 sequence.  Its length is
                 SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE. */
              stream->r.chunk_size += SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE;
              stream->r.state = SSH_HTTP_CHUNKED_READING_CHUNK_DATA;
            }

          /* And proceed... */
          break;

        case SSH_HTTP_CHUNKED_READING_CHUNK_DATA:
          if (buflen == 0)
            {
              /* Try to read some. */
              if (!ssh_http_chunked_stream_read_more(stream, &rstatus))
                return 0;

              if (rstatus == 0)
                {
                  /* EOF reached. */
                  SSH_DEBUG(5, ("Premature EOF in data"));
                  if (stream->notification_callback)
                    (*stream->notification_callback)(
                                SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_DATA,
                                NULL, 0, NULL, 0,
                                stream->notification_callback_context);
                  return 0;
                }
              if (rstatus < 0)
                /* Can't read since we would block. */
                return -1;

              /* Ok, got some. */
              continue;
            }

          if (stream->r.chunk_size <= SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE)
            {
              if (buflen >= stream->r.chunk_size)
                {
                  /* We can get it all. */
                  ssh_buffer_consume(stream->r.buffer, stream->r.chunk_size);

                  /* Move to the next chunk. */
                  stream->r.state = SSH_HTTP_CHUNKED_READING_CHUNK_SIZE_LINE;
                }
              else
                {
                  /* Just skipping some bytes from the tail garbage. */
                  ssh_buffer_consume(stream->r.buffer, buflen);
                  stream->r.chunk_size -= buflen;

                  /* And read more. */
                }
            }
          else
            {
              /* Pass some data to the user. */
              if (size > (stream->r.chunk_size
                          - SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE))
                size = (stream->r.chunk_size
                        - SSH_HTTP_CHUNKED_DATA_TAIL_GARBAGE);
              if (size > buflen)
                size = buflen;

              memcpy(buf, ssh_buffer_ptr(stream->r.buffer), size);
              ssh_buffer_consume(stream->r.buffer, size);
              stream->r.chunk_size -= size;

              return size;
            }
          break;

        case SSH_HTTP_CHUNKED_READING_TRAILER:
          /* Do we have one line of input? */
          for (i = 0; i < buflen && p[i] != '\n'; i++)
            ;
          if (i >= buflen)
            {
              /* We don't have one line of input.  Try to read more
                 data. */
              if (!ssh_http_chunked_stream_read_more(stream, &rstatus))
                return 0;

              if (rstatus < 0)
                /* Can't read more because we would block. */
                return -1;
              if (rstatus == 0)
                {
                  /* EOF reached. */
                  SSH_DEBUG(5, ("Premature EOF in trailer"));
                  if (stream->notification_callback)
                    (*stream->notification_callback)(
                                SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_TRAILER,
                                NULL, 0, NULL, 0,
                                stream->notification_callback_context);
                  return 0;
                }

              /* Try again. */
              continue;
            }

          /* Got one line. */
          i++;

          /* Skip the leading whitespace. */
          for (j = 0; j < i && isspace(p[j]); j++)
            ;
          if (j >= i)
            {
              /* It was all whitespace.  This is the end of the
                 chunked stream. */
              stream->r.state = SSH_HTTP_CHUNKED_READ_AT_EOF;
            }
          else if (j > 0)
            {
              /* Whitespace in the beginning of the field.  This is a
                 continuation line. */
              start = j;

              /* Skip the trailing whitespace. */
              for (j = i - 1; j > start && isspace(p[j]); j--)
                ;
              j++;

              if (stream->notification_callback)
                (*stream->notification_callback)(
                        SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD_CONT,
                        NULL, 0, p + start, j - start,
                        stream->notification_callback_context);
            }
          else
            {
              /* Normal trailer field. */
              start = j;

              for (; j < i && p[j] != ':'; j++)
                ;
              if (j >= i)
                {
                  /* Malformed trailer field. */
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Malformed trailer line.  No ':' found"));
                }
              else
                {
                  SshUInt32 end = j;
                  SshUInt32 value_start;

                  /* Skip all whitespace from the beginning of the
                     value. */
                  for (j++; j < i && isspace(p[j]); j++)
                    ;
                  value_start = j;

                  /* Skip all whitespace from the end of the value. */
                  for (j = i - 1; j > value_start && isspace(p[j]); j--)
                    ;
                  j++;

                  if (stream->notification_callback)
                    (*stream->notification_callback)(
                                SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD,
                                p + start, end - start,
                                p + value_start, j - value_start,
                                stream->notification_callback_context);
                }
            }

          ssh_buffer_consume(stream->r.buffer, i);

          /* Move to the next line or state throught the big while
             loop. */
          break;

        case SSH_HTTP_CHUNKED_READ_AT_EOF:
          /* Just pass the EOF to our client. */
          if (stream->notification_callback)
            (*stream->notification_callback)(
                        SSH_HTTP_CHUNKED_STREAM_READ_EOF_REACHED,
                        NULL, 0, NULL, 0,
                        stream->notification_callback_context);
          return 0;
          break;
        }
    }

  /* NOTREACHED */
  return 0;
}

/* The write implementation. */

/* Finish the current (non-empty) chunk that is buffered in
   <stream>. */
static Boolean
ssh_http_chunked_stream_finish_chunk(SshHttpChunkedStream *stream)
{
  size_t len = ssh_buffer_len(stream->w.buffer);
  unsigned char buf[32];
  size_t l;
  unsigned char *p;

  /* Format the first-line. */
  SSH_DEBUG(9, ("chunk-size=%u", len));
  ssh_snprintf(buf, sizeof(buf), "%X\r\n", len);

  /* Insert it to the beginning of the buffer. */
  l = ssh_ustrlen(buf);
  if (ssh_buffer_append_space(stream->w.buffer, &p, l + 2) == SSH_BUFFER_OK)
    {
      p = ssh_buffer_ptr(stream->w.buffer);

      /* move beginning of buffer forward */
      memmove(p + l, p, len);
      /* write chunk length */
      memcpy(p, buf, l);
      /* Finish the chunk with the `CRLR' sequence. */
      memcpy(p + l + len, "\r\n", 2);

      return TRUE;
    }
  return FALSE;
}

/* Writes as much data as possible returning the status of the last
   write operation.  A positive return value means that all buffered
   data was written.  If the EOF was encountered, it is marked to the
   <stream>. */
static int
ssh_http_chunked_stream_write_all_you_can(SshHttpChunkedStream *stream)
{
  int i = 0;

  while (ssh_buffer_len(stream->w.buffer) > 0)
    {
      i = ssh_stream_write(stream->chunked, ssh_buffer_ptr(stream->w.buffer),
                           ssh_buffer_len(stream->w.buffer));
      if (i == 0)
        {
          SSH_DEBUG(5, ("EOF encountered"));
          stream->w.eof_seen = TRUE;
          return 0;
        }
      if (i < 0)
        return i;

      /* Wrote something. */
      ssh_buffer_consume(stream->w.buffer, i);
    }

  return i;
}


static int
ssh_http_chunked_stream_write(void *context, const unsigned char *buf,
                              size_t size)
{
   SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;
   int space;
   int i;

   if (!stream->writable || stream->w.eof_seen || stream->w.eof_output)
     /* Write is not allowed.  We are at the EOF. */
     return 0;

   if (size == 0)
     /* An explicit flush request.  FLUSH */
     stream->w.flushed = TRUE;

   if (stream->w.state == SSH_HTTP_CHUNKED_WRITING)
     /* We are writing our current chunk.  Must block the client for a
        while. */
     return -1;

   /* Ok, we are collecting a new chunk. */

   /* Can we buffer this chunk? */
   space = (SSH_HTTP_CHUNKED_DATA_BUFFER_SIZE
            - ssh_buffer_len(stream->w.buffer));
   SSH_ASSERT(space > 0);

   if (stream->w.flushed)
     /* Do not append any more data to the buffer. */
     space = 0;

   if ((size_t) space > size)
     {
       /* It fits to our buffer. */
       ssh_buffer_append(stream->w.buffer, buf, size);
       return size;
     }

   /* This write completes our chunk. */

   /* If the users did request an explicit flush and our currently
      collected chunk is still empty.  We must only flush our
      underlying stream.  FLUSH */
   if (ssh_buffer_len(stream->w.buffer) == 0 && size == 0)
     {
       stream->w.flushed = FALSE;
       return ssh_stream_write(stream->chunked, (unsigned char *) "", 0);
     }

   /* Write chunk */
   {
     size_t soff = ssh_buffer_len(stream->w.buffer);

     if (ssh_buffer_append(stream->w.buffer, buf, space) != SSH_BUFFER_OK)
       return -1;

     if (ssh_http_chunked_stream_finish_chunk(stream))
       stream->w.state = SSH_HTTP_CHUNKED_WRITING;
     else
       {
         ssh_buffer_consume_end(stream->w.buffer,
                                ssh_buffer_len(stream->w.buffer - soff));
         return -1;
       }
   }

   /* Try to write as much as possible. */
   i = ssh_http_chunked_stream_write_all_you_can(stream);
   if (i <= 0)
     return space;

   /* Wow!  We managed to write it all to our destination stream. */

   /* Flush our source stream?  FLUSH */
   if (stream->w.flushed)
     {
       (void) ssh_stream_write(stream->chunked, (unsigned char *) "", 0);
       stream->w.flushed = FALSE;
     }

   /* Start collecting a new chunk. */
   stream->w.state = SSH_HTTP_CHUNKED_WRITE_COLLECTING;

  return space;
}


static void
ssh_http_chunked_stream_output_eof(void *context)
{
   SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;
   unsigned char *str;
   int i;

   if (!stream->writable || stream->w.eof_output)
     return;

   stream->w.eof_output = TRUE;

   if (stream->w.state == SSH_HTTP_CHUNKED_WRITING)
     /* Writing our current chunk.  Just mark the EOF seen and
        return. */
     return;

   SSH_ASSERT(stream->w.state == SSH_HTTP_CHUNKED_WRITE_COLLECTING);

   if (ssh_buffer_len(stream->w.buffer) > 0)
     {
       /* Must finish this chunk. */
       stream->w.state = SSH_HTTP_CHUNKED_WRITING;
       ssh_http_chunked_stream_finish_chunk(stream);

       i = ssh_http_chunked_stream_write_all_you_can(stream);
       if (i == 0)
         {
           /* The destination stream is closed.  We can't do more. */
           stream->w.state = SSH_HTTP_CHUNKED_WRITE_AT_EOF;
           return;
         }

       if (i < 0)
         /* Ok, the stream callback will finish us. */
         return;
     }
   SSH_ASSERT(ssh_buffer_len(stream->w.buffer) == 0);

   /* Format the chunk trailer to the buffer and write it.  As buffers
      do not really shrink and do not get stolen here, we'll likely
      have enough space for the trailer (5 bytes) */

   str = SSH_HTTP_CHUNKED_TRAILER;
   ssh_buffer_append(stream->w.buffer, str, strlen((char *) str));
   stream->w.state = SSH_HTTP_CHUNKED_WRITING_EOF;

   i = ssh_http_chunked_stream_write_all_you_can(stream);
   if (i < 0)
     /* Let the callback finish us. */
     return;

   /* EOF or we managed to write the EOF to the stream. */

   /* Flush our source stream?  FLUSH */
   if (stream->w.flushed)
     {
       (void) ssh_stream_write(stream->chunked, (unsigned char *) "", 0);
       stream->w.flushed = FALSE;
     }

   /* Set our state to EOF. */
   stream->w.state = SSH_HTTP_CHUNKED_WRITE_AT_EOF;
}


static void
ssh_http_chunked_stream_set_callback(void *context, SshStreamCallback callback,
                                     void *callback_context)
{
  SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;

  stream->callback = callback;
  stream->callback_context = callback_context;
}

/* Really destroy and free the chunked stream <stream>. */
static void
ssh_http_chunked_stream_real_destroy(SshHttpChunkedStream *stream)
{
  if (stream->chunked)
    {
      ssh_stream_destroy(stream->chunked);
      stream->chunked = NULL;
    }

  if (stream->r.buffer)
    ssh_buffer_free(stream->r.buffer);
  if (stream->w.buffer)
    ssh_buffer_free(stream->w.buffer);

  ssh_free(stream);
}


static void
ssh_http_chunked_stream_destroy(void *context)
{
  SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;

  if (!stream->writable)
    {
      ssh_http_chunked_stream_real_destroy(stream);
      return;
    }

  /* The write is allowed for the stream. */

  /* Mark the stream as destroyed. */
  stream->destroyed = TRUE;

  /* Ouput an EOF to the stream.  It doesn't hurt if the EOF has
     already been output since the output_eof() function is smart
     enought to handle this. */
  ssh_http_chunked_stream_output_eof(stream);

  if (stream->w.state == SSH_HTTP_CHUNKED_WRITE_AT_EOF)
    {
      /* Ok, all done with this stream. */
      ssh_http_chunked_stream_real_destroy(stream);
      return;
    }

  /* The stream callback will finish us. */
}


static const SshStreamMethodsStruct
ssh_http_chunked_stream_methods_table =
{
  ssh_http_chunked_stream_read,
  ssh_http_chunked_stream_write,
  ssh_http_chunked_stream_output_eof,
  ssh_http_chunked_stream_set_callback,
  ssh_http_chunked_stream_destroy,
};


static void
ssh_http_chunked_stream_source_callback(SshStreamNotification notification,
                                        void *context)
{
  SshHttpChunkedStream *stream = (SshHttpChunkedStream *) context;
  int i;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
    case SSH_STREAM_DISCONNECTED:
      /* Just pass the notification to our client. */
    pass:
      if (stream->callback)
        (*stream->callback)(notification, stream->callback_context);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      if (!stream->writable)
        goto pass;

      switch (stream->w.state)
        {
        case SSH_HTTP_CHUNKED_WRITE_COLLECTING:
        case SSH_HTTP_CHUNKED_WRITE_AT_EOF:
          /* These shouldn't be reached.  But if they do, it doesn't
             hurt to pass them up. */
          SSH_ASSERT(!stream->destroyed);
          goto pass;
          break;

        case SSH_HTTP_CHUNKED_WRITING:
        case SSH_HTTP_CHUNKED_WRITING_EOF:
        write_more:
          if (ssh_buffer_len(stream->w.buffer) > 0)
            {
              i = ssh_http_chunked_stream_write_all_you_can(stream);
              if (i == 0)
                {
                  /* EOF reached at write. */
                  ssh_buffer_clear(stream->w.buffer);
                }
              else if (i < 0)
                {
                  /* Sorry, we would block. */
                  return;
                }

              /* Wrote it all. */
            }

          /* Did the user explicitly flush our stream?  FLUSH */
          if (stream->w.flushed)
            {
              /* Yes he did.  Let's flush our source stream. */
              (void) ssh_stream_write(stream->chunked, (unsigned char *) "",
                                      0);
              stream->w.flushed = FALSE;
            }

          /* Ok, the output is complete.  Check what we should do now. */
          if (stream->w.state == SSH_HTTP_CHUNKED_WRITING)
            {
              if (stream->w.eof_output)
                {
                  unsigned char *str = SSH_HTTP_CHUNKED_TRAILER;

                  /* The EOF was output while we were writing the
                     previous chunk. Likely to have space here. */

                  ssh_buffer_append(stream->w.buffer, str,
                                    strlen((char *) str));
                  stream->w.state = SSH_HTTP_CHUNKED_WRITING_EOF;
                  goto write_more;
                }

              /* Start collecting a new chunk and ask our client to
                 give us more data. */
              stream->w.state = SSH_HTTP_CHUNKED_WRITE_COLLECTING;
              goto pass;
            }
          else
            {
              /* SSH_HTTP_CHUNKED_WRITING_EOF */
              stream->w.state = SSH_HTTP_CHUNKED_WRITE_AT_EOF;
            }

          if (stream->destroyed)
            /* Ok, we should be able to destroy this stream. */
            ssh_http_chunked_stream_real_destroy(stream);
          break;
        }
      break;
    }
}


SshStream
ssh_http_chunked_stream_create(SshStream chunked, Boolean readable,
                               Boolean writable,
                               SshHttpChunkedStreamCb callback,
                               void *callback_context)
{
  SshHttpChunkedStream *stream_ctx;
  SshStream str;

  if ((stream_ctx = ssh_calloc(1, sizeof(*stream_ctx))) == NULL)
    {
      ssh_stream_destroy(chunked);
      return NULL;
    }

  stream_ctx->chunked = chunked;
  stream_ctx->readable = readable;
  stream_ctx->writable = writable;

  if (readable)
    {
      stream_ctx->r.state = SSH_HTTP_CHUNKED_READING_CHUNK_SIZE_LINE;
      if ((stream_ctx->r.buffer = ssh_buffer_allocate()) == NULL)
        goto failed;
    }
  if (writable)
    {
      stream_ctx->w.state = SSH_HTTP_CHUNKED_WRITE_COLLECTING;
      if ((stream_ctx->w.buffer = ssh_buffer_allocate()) == NULL)
        goto failed;
    }

  stream_ctx->notification_callback = callback;
  stream_ctx->notification_callback_context = callback_context;

  ssh_stream_set_callback(chunked, ssh_http_chunked_stream_source_callback,
                          stream_ctx);

  str = ssh_stream_create(&ssh_http_chunked_stream_methods_table, stream_ctx);

  if (str == NULL)
    goto failed;

  return str;

 failed:

  ssh_buffer_free(stream_ctx->w.buffer);
  ssh_buffer_free(stream_ctx->r.buffer);
  ssh_stream_destroy(chunked);
  return NULL;
}
