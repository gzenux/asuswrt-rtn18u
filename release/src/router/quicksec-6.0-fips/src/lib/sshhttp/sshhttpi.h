/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the SSH HTTP/1.1 library.
*/

#ifndef SSHHTTPI_H
#define SSHHTTPI_H

/*
 * Types and definitions.
 */

/* There are not content data for these status codes. */
#define SSH_HTTP_NO_CONTENT_STATUS(code)        \
 ((100 <= (code) && (code) < 200)               \
  || (code) == SSH_HTTP_STATUS_NO_CONTENT       \
  || (code) == SSH_HTTP_STATUS_NOT_MODIFIED)

/* Status codes for successful HTTP operation. */
#define SSH_HTTP_SUCCESS_STATUS(code) (200 <= (code) && (code) < 300)

/* RFC1945 specifies also HT (\t), but it can be omitted because it is
 * a control character (0-31) */
#define SSH_HTTP_IS_TOKEN_CH(ch)                                \
  (32 <= (ch) && (ch) < 127                                     \
   && (ch) != '(' && (ch) != ')' && (ch) != '<' && (ch) != '>'  \
   && (ch) != '@' && (ch) != ',' && (ch) != ';' && (ch) != ':'  \
   && (ch) != '\\' && (ch) != '"' && (ch) != '/' && (ch) != '[' \
   && (ch) != ']' && (ch) != '?' && (ch) != '=' && (ch) != '{'  \
   && (ch) != '}' && (ch) != ' ')


/*
 * Prototypes for global functions.
 */

/* Convert the time value <date> into the RFC 1123 date string.  The
   date value <date> must be given as UTC time.  The returned value is
   ssh_xmalloc() allocated and you must free it. */
unsigned char *ssh_http_make_rfc1123_date(SshTime date);

/* Copies the value and removes any '\' escaping from it. */
unsigned char *
ssh_http_unescape_attr_value(const unsigned char *value, size_t len);

/* Parse a attribute-value pair from the buffer <buf>, starting from
   position *<position>.  If the function can parse a av-pair, it
   returns TRUE and sets the argument <attr_return> and the argument
   <val_return> to point to the beginning of the attribute and the
   value.  The arguments <attr_len_return>, and <val_len_return> will
   hold the lengths of the attribute and the value.  The function will
   also update the <position> to point to the end of the value.  If
   the parsing fails, the function returns FALSE.

   If the buffer <buf> is empty, e.g. it does not contain any
   av-pairs, the function returns TRUE and set the <attr_return> to
   NULL.  This allows the caller to distinguish malformed av-pairs
   from the end-of-data condition. */
Boolean ssh_http_get_av(const unsigned char *buf, unsigned int *position,
                        const unsigned char **attr_return,
                        unsigned int *attr_len_return,
                        const unsigned char **val_return,
                        unsigned int *val_len_return);

/* Key-value hash for header fields and values.  The key-value hash
   implements the semantics that the HTTP protocol sets for the header
   fields and their values.  */

/* A handle for the key-value hash. */
typedef struct SshHttpKvHashRec *SshHttpKvHash;

/* Create a new key-value hash.  If the argument <case_insensitive> is
   TRUE, the stored keys are converted to upper-case before they are
   inserted or checked in the hash. */
SshHttpKvHash ssh_http_kvhash_create(Boolean case_insensitive);

/* Destroy the key-value hash <hash>.  The function frees the hash and
   releases all resources it has allocated.  The hash <hash> must not
   be used after this function. */
void ssh_http_kvhash_destroy(SshHttpKvHash hash);

/* Clear all keys and their values from the hash <hash>. */
void ssh_http_kvhash_clear(SshHttpKvHash hash);

/* Put a value <value>, <value_len> for key <key>, <key_len> to the
   hash <hash>.  If the key already existed in the hash, the new value
   is appended to the end of the old value, separated by a comma. */
Boolean ssh_http_kvhash_put(SshHttpKvHash hash,
                            const unsigned char *key, size_t key_len,
                            const unsigned char *value, size_t value_len);

/* Like ssh_http_kvahsh_put() but the arguments <key> and <value> are
   '\0' terminated C-strings. */
Boolean ssh_http_kvhash_put_cstrs(SshHttpKvHash hash, const unsigned char *key,
                                  const unsigned char *value);

/* Append a value <value>, <value_len> to the end of the last key that
   was inserted in the hash <hash>.  If this is the first insertion to
   the hash <hash>  the function returns FALSE. */
Boolean ssh_http_kvhash_append_last(SshHttpKvHash hash,
                                    const unsigned char *value,
                                    size_t value_len);

/* Get the value of the key <key> from the hash <hash>.  The function
   returns NULL if the key <key> is not defined.  The key <key> must
   be given in upper case letters.  Otherwise it is never found from
   the hash. */
const unsigned char *ssh_http_kvhash_get(SshHttpKvHash hash,
                                         const unsigned char *key);

/* Remove the key <key> from the hash <hash>.  Returns TRUE if the key
   was in the hash or FALSE otherwise. */
Boolean ssh_http_kvhash_remove(SshHttpKvHash hash, const unsigned char *key);

/* Reset the internal get_next() index. */
void ssh_http_kvhash_reset_index(SshHttpKvHash hash);

/* Return the next key-value pair from the hash <hash>.  Returns FALSE
   if the hash does not have more keys.  The get operation get be
   restarted by calling the ssh_http_kvhash_reset_index() function. */
Boolean ssh_http_kvhash_get_next(SshHttpKvHash hash,
                                 unsigned char **key_return,
                                 unsigned char **value_return);


/*
 * Streams.
 */

/* Chunked Transfer Encoding. */

/* The notifications which the chunked stream gives to the
   application. */
typedef enum
{
  /* A premature EOF was received from the source stream when the
     chunked stream was reading the chunk size line. */
  SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_SIZE_LINE,

  /* A premature EOF was received from the source stream when the
     chunked stream was reading the chunk data. */
  SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_DATA,

  /* A premature EOF was received from the source stream when the
     chunked stream was reading the trailer. */
  SSH_HTTP_CHUNKED_STREAM_READ_EOF_IN_TRAILER,

  /* A trailer field was found from the chunked stream.  The arguments
     <key>, <key_len> and <value>, <value_len> of the callback specify
     the key and the value of the field. */
  SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD,

  /* A trailer continuation field was found from the chunked stream.
     The arguments <value>, <value_len> of the callback specify the
     continuation value. */
  SSH_HTTP_CHUNKED_STREAM_READ_TRAILER_FIELD_CONT,

  /* The maximum in-memory buffer size was reached. */
  SSH_HTTP_CHUNKED_STREAM_READ_MAX_BUFFER_SIZE_REACHED,

  /* The chunked stream was processed successfully. */
  SSH_HTTP_CHUNKED_STREAM_READ_EOF_REACHED
} SshHttpChunkedStreamNotification;

/* A callback function that is called by the stream to notify the user
   about interesting events. */
typedef void (*SshHttpChunkedStreamCb)(
                        SshHttpChunkedStreamNotification notification,
                        const unsigned char *key, size_t key_len,
                        const unsigned char *value, size_t value_len,
                        void *context);

/* Constructor for the chunked data stream.  The argument <source> is
   the source and destination stream from the chunked data.  The
   arguments <readable> and <writable> specify whether the created
   stream could be read and write.  The argument <callback> is used to
   notify the user about different events in the stream. */
SshStream ssh_http_chunked_stream_create(SshStream source,
                                         Boolean readable,
                                         Boolean writable,
                                         SshHttpChunkedStreamCb callback,
                                         void *callback_context);

#endif /* not SSHHTTPI_H */
