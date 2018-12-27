/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Parse System.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshpsystem.h"
#include "sshbuffer.h"
#include "sshbase64.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshPSystem"




























const SshCharPtr ssh_psystem_msg[] =
{
  "success",
  "syntax error",
  "unknown language",
  "misplace close operator",
  "object was not created",
  "object addition failed",
  "no bind exists for given name",
  "same name used for environment and variable",
  "name not supported",
  "not an operator",
  "token was not expected here",
  "unsupported type requested",
  "type did not match the expected type",
  "list mismatch",
  "unknown type",
  "token string was empty, expected something else",
  "environment has no handler",
  "object addition failed",
  "could not open a list",
  "could not close a list",
  "initialization of an object failed",
  "expected assignment",
  NULL
};

char *ssh_psystem_error_msg(SshPSystemStatus status)
{
  if (status >= SSH_PSYSTEM_OK && status <= SSH_PSYSTEM_INIT_FAILED)
    return ssh_psystem_msg[status];
  return NULL;
}

typedef struct SshPSystemPosRec
{
  /* The more function. */
  int (*more)(void *context, unsigned char **buf, size_t *buf_len);
  void *more_context;

  Boolean eof;

  /* Our current buffer. */
  unsigned char *buf;
  size_t buf_len;

  /* LRU */
#define SSH_PSYSTEM_BYTE_LRU 5
  unsigned char lru[SSH_PSYSTEM_BYTE_LRU];
  size_t lru_pos;

  /* Position in the buffer and the line on which we currently are and
     index from start of that line. */
  size_t i, line, pos;

} SshPSystemPos;

void ssh_psystem_pos_init(SshPSystemPos *pos,
                          int (*more)(void *context, unsigned char **buf,
                                      size_t *buf_len),
                          void *more_context)
{
  pos->eof = FALSE;
  pos->buf = NULL;
  pos->buf_len = 0;
  pos->i = 0;
  pos->line = 0;
  pos->pos = 0;
  pos->lru_pos = 0;

  pos->more = more;
  pos->more_context = more_context;
}

void ssh_psystem_pos_free(SshPSystemPos *pos)
{
  if (pos->buf)
    ssh_xfree(pos->buf);
}

Boolean ssh_psystem_pos_lru(SshPSystemPos *pos, unsigned char byte)
{
  if (pos->lru_pos < SSH_PSYSTEM_BYTE_LRU)
    {
      pos->lru[pos->lru_pos] = byte;
      pos->lru_pos++;
      return TRUE;
    }
  return FALSE;
}

unsigned char ssh_psystem_next_byte(SshPSystemPos *pos)
{
  unsigned char *buf;
  size_t buf_len;
  unsigned char byte;
  int status;

  /* This feature is used only occasionally, and thus need not be
     handled with utmost care. That is we don't bother with little
     inconsistency with line numbers etc. */
  if (pos->lru_pos)
    {
      pos->lru_pos--;
      byte = pos->lru[pos->lru_pos];
      return byte;
    }

  if (pos->i < pos->buf_len)
    {
      byte = pos->buf[pos->i];
      pos->i++;
      pos->pos++;

      /* Detect line changes. */
      if (byte == '\n')
        {
          pos->line++;
          pos->pos = 0;
        }
      return byte;
    }

  /* Use the more functionality. */
  status = (*pos->more)(pos->more_context, &buf, &buf_len);
  if (status != 0)
    {
      pos->eof = TRUE;
      return 0x0;
    }

  /* Free the old buffer. */
  if (pos->buf)
    ssh_xfree(pos->buf);

  pos->i = 0;
  pos->buf = buf;
  pos->buf_len = buf_len;

  /* Recursively call oneself and get the byte requested. */
  return ssh_psystem_next_byte(pos);
}

#define NBYTE(pos) ssh_psystem_next_byte(pos)
#define PBYTE(pos, byte) ssh_psystem_pos_lru(pos, byte)

/* Thing that simplies greatly. */
char *buffer_to_str(SshBuffer buffer, size_t *len)
{
  char *str;

  *len = ssh_buffer_len(buffer);
  str = ssh_xmalloc((*len) + 1);
  memcpy(str, ssh_buffer_ptr(buffer), *len);
  str[*len] = '\0';
  return str;
}

/* This seems to be easy enough. */
Boolean ssh_psystem_integer_decoder(unsigned char *in, size_t in_len,
                                    void **out, size_t *out_len)
{
  SshMPInteger temp;

  temp = ssh_xmalloc(sizeof(*temp));
  ssh_mprz_init(temp);

  /* Put a string. */
  if (ssh_mprz_set_str(temp, (char *) in, 10) == 0)
    {
      ssh_mprz_clear(temp);
      ssh_xfree(temp);
      return FALSE;
    }

  *out = temp;
  *out_len = 0;
  return TRUE;
}

void ssh_psystem_integer_free(void *buf, size_t buf_len)
{
  SshMPInteger temp = buf;
  ssh_mprz_clear(temp);
  ssh_xfree(temp);
}

void ssh_psystem_string_free(void *buf, size_t buf_len)
{
  ssh_xfree(buf);
}

/* If another hex decoder is written somewhere use that. */

/* My own hex table. */
static const unsigned char ssh_hextable[128] =
{
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Our convention is to assume bit accuracy at the msb, not in the lsb. This
   makes decoding simpler. */
Boolean ssh_psystem_decode_hex(unsigned char *in, size_t in_len,
                               unsigned char **out, size_t *out_len)
{
  SshBufferStruct buffer;
  size_t i, len, s;
  unsigned char t, octet;

  if (out_len == 0 || out == NULL)
    return FALSE;

  for (len = 0; len < in_len; len++)
    {
      if (in[len] > 127)
        break;
      if (ssh_hextable[in[len]] == 0xff)
        break;
    }

  if (len < in_len)
    return FALSE;

  /* Check for zero length, which is correct but needs no work. */
  if (len == 0)
    {
      *out = NULL;
      *out_len = 0;
      return TRUE;
    }

  /* Make modification according the length of the hex string. */
  s = 1;
  if (len & 0x1)
    s ^= 1;

  /* Allocate a buffer. */
  ssh_buffer_init(&buffer);

  /* Loop through all hex information. */
  for (i = 0, octet = 0, t = 0; i < len; i++)
    {
      t = ssh_hextable[in[i]];
      if ((i & 0x1) == s)
        {
          octet |= t;
          ssh_xbuffer_append(&buffer, &octet, 1);
        }
      else
        octet = t << 4;
    }

  *out_len = ssh_buffer_len(&buffer);
  *out = ssh_xmalloc(*out_len);
  memcpy(*out, ssh_buffer_ptr(&buffer), *out_len);

  ssh_buffer_uninit(&buffer);
  return TRUE;
}

/* This should also work reasonably. */
Boolean ssh_psystem_hex_decoder(unsigned char *in, size_t in_len,
                                void **out, size_t *out_len)
{
  if (in_len < 2 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;
  if (in[0] != '0' || (in[1] != 'x' && in[1] != 'X'))
    return FALSE;

  return ssh_psystem_decode_hex(in + 2, in_len - 2,
                                (unsigned char **)out, out_len);
}

Boolean ssh_psystem_hex_decoder_int(unsigned char *in, size_t in_len,
                                    void **out, size_t *out_len)
{
  void *my_out;
  size_t my_len;
  SshMPInteger temp;

  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (ssh_psystem_hex_decoder(in, in_len,
                              &my_out, &my_len) == FALSE)
    return FALSE;

  temp = ssh_xmalloc(sizeof(*temp));
  ssh_mprz_init(temp);

  ssh_mprz_set_buf(temp, my_out, my_len);
  ssh_xfree(my_out);

  *out = temp;
  *out_len = 0;
  return TRUE;
}

Boolean ssh_psystem_hex_decoder_str(unsigned char *in, size_t in_len,
                                    void **out, size_t *out_len)
{
  void *my_out;
  size_t my_out_len;

  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (ssh_psystem_hex_decoder(in, in_len,
                              &my_out, &my_out_len) == FALSE)
    return FALSE;

  /* Force terminating zero, just in case. */
  *out = ssh_xmalloc(my_out_len + 1);
  memcpy(*out, my_out, my_out_len);
  ((unsigned char *)(*out))[my_out_len] = '\0';
  *out_len = my_out_len;
  ssh_xfree(my_out);
  return TRUE;
}

Boolean ssh_psystem_hex_decoder_ip(unsigned char *in, size_t in_len,
                                   void **out, size_t *out_len)
{
  if (ssh_psystem_hex_decoder(in, in_len,
                              out, out_len) == FALSE)
    return FALSE;

  if (*out_len != 4)
    {
      ssh_xfree(out);
      return FALSE;
    }
  return TRUE;
}

Boolean ssh_psystem_base64_decoder(unsigned char *in, size_t in_len,
                                   void **out, size_t *out_len)
{
  size_t len;
  unsigned char *str;

  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (in[0] != '#')
    return FALSE;

  len = ssh_is_base64_buf(in + 1, in_len - 1);

  if (len < in_len - 1)
    return FALSE;

  if (len == 0)
    {
      *out = NULL;
      *out_len = 0;
      return TRUE;
    }

  /* This is rather ugly but have do it. */
  str = ssh_xmalloc(len + 1);
  memcpy(str, in + 1, len);
  str[len] = '\0';

  *out = ssh_base64_to_buf(str, out_len);
  ssh_xfree(str);
  return TRUE;
}

Boolean ssh_psystem_base64_decoder_int(unsigned char *in, size_t in_len,
                                       void **out, size_t *out_len)
{
  void *my_out;
  size_t my_len;
  SshMPInteger temp;

  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (ssh_psystem_base64_decoder(in, in_len,
                                 &my_out, &my_len) == FALSE)
    return FALSE;

  temp = ssh_xmalloc(sizeof(*temp));
  ssh_mprz_init(temp);

  ssh_mprz_set_buf(temp, my_out, my_len);
  ssh_xfree(my_out);

  *out = temp;
  *out_len = 0;
  return TRUE;
}

Boolean ssh_psystem_base64_decoder_str(unsigned char *in, size_t in_len,
                                       void **out, size_t *out_len)
{
  void *my_out;
  size_t my_out_len;

  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (ssh_psystem_base64_decoder(in, in_len,
                                 &my_out, &my_out_len) == FALSE)
    return FALSE;

  /* Force terminating zero, just in case. */
  *out = ssh_xmalloc(my_out_len + 1);
  memcpy(*out, my_out, my_out_len);
  ((unsigned char *)(*out))[my_out_len] = '\0';
  *out_len = my_out_len;
  ssh_xfree(my_out);
  return TRUE;
}

Boolean ssh_psystem_base64_decoder_ip(unsigned char *in, size_t in_len,
                                      void **out, size_t *out_len)
{
  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  if (ssh_psystem_base64_decoder(in, in_len,
                                 out, out_len) == FALSE)
    return FALSE;

  if (*out_len != 4)
    {
      ssh_xfree(out);
      return FALSE;
    }
  return TRUE;
}

Boolean ssh_psystem_ip_decoder(unsigned char *in, size_t in_len,
                               void **out, size_t *out_len)
{
  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  *out_len = 16;
  *out = ssh_xmalloc(16);
  if (ssh_inet_strtobin(in, *out, out_len))
    return TRUE;
  else
    {
      ssh_xfree(*out);
      return FALSE;
    }
}

Boolean ssh_psystem_name_decoder(unsigned char *in, size_t in_len,
                                 void **out, size_t *out_len)
{
  if (in_len == 0 || in == NULL || out_len == NULL || out == NULL)
    return FALSE;

  *out = ssh_xmalloc(in_len + 1);
  *out_len = in_len;
  memcpy(*out, in, in_len);
  ((unsigned char*)(*out))[*out_len] = '\0';
  return TRUE;
}

typedef struct SshPSystemDecodersRec
{
  Boolean (*decoder)(unsigned char *in_buf, size_t in_len,
                     void **out_buf, size_t *out_len);
  void    (*free)(void *buf, size_t buf_len);
  unsigned int flag;
#define SSH_PSYSTEM_FLAG_NONE    0
#define SSH_PSYSTEM_FLAG_INTEGER 1
#define SSH_PSYSTEM_FLAG_STRING  2
#define SSH_PSYSTEM_FLAG_HEX     4
#define SSH_PSYSTEM_FLAG_BASE64  8
#define SSH_PSYSTEM_FLAG_IP      16
#define SSH_PSYSTEM_FLAG_LDAP_DN 32
#define SSH_PSYSTEM_FLAG_NAME    64
} SshPSystemDecoders;

const SshPSystemDecoders ssh_psystem_decoders[] =
{
  { ssh_psystem_integer_decoder,
    ssh_psystem_integer_free,
    SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_hex_decoder_int,
    ssh_psystem_integer_free,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_hex_decoder_ip,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_hex_decoder_str,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_STRING },
  { ssh_psystem_base64_decoder_int,
    ssh_psystem_integer_free,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_base64_decoder_str,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_STRING },
  { ssh_psystem_base64_decoder_ip,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_ip_decoder,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_name_decoder,
    ssh_psystem_string_free,
    SSH_PSYSTEM_FLAG_NAME },
  { NULL_FNPTR, 0 }
};

typedef struct SshPSystemMappingRec
{
  SshPSystemType type;
  unsigned int flag;
} SshPSystemMapping;

const SshPSystemMapping ssh_psystem_mapping[] =
{
  { SSH_PSYSTEM_INTEGER, SSH_PSYSTEM_FLAG_INTEGER },
  { SSH_PSYSTEM_STRING,  SSH_PSYSTEM_FLAG_STRING },
  { SSH_PSYSTEM_IP,      SSH_PSYSTEM_FLAG_IP },
  { SSH_PSYSTEM_LDAP_DN, SSH_PSYSTEM_FLAG_LDAP_DN },
  { SSH_PSYSTEM_NAME,    SSH_PSYSTEM_FLAG_NAME },
  { 0, SSH_PSYSTEM_FLAG_NONE }
};

unsigned int ssh_psystem_map(SshPSystemType type)
{
  int i;
  for (i = 0; ssh_psystem_mapping[i].flag != SSH_PSYSTEM_FLAG_NONE; i++)
    {
      if (ssh_psystem_mapping[i].type == type)
        return ssh_psystem_mapping[i].flag;
    }
  return SSH_PSYSTEM_FLAG_NONE;
}

SshPSystemStatus ssh_psystem_read_string(SshPSystemPos *pos,
                                         void **token_str,
                                         size_t *token_str_len)
{
  SshBufferStruct buffer;
  Boolean escaped = FALSE, escape_whitespace = FALSE;
  unsigned char byte;

  ssh_buffer_init(&buffer);

  for (; pos->eof == FALSE;)
    {
      byte = NBYTE(pos);
      if (escaped)
        {
          switch (byte)
            {
            case 'n':
              ssh_xbuffer_append(&buffer, (unsigned char *) "\n", 1);
              break;
            case 't':
              ssh_xbuffer_append(&buffer, (unsigned char *) "\t", 1);
              break;
            case 'r':
              ssh_xbuffer_append(&buffer, (unsigned char *) "\r", 1);
              break;
            case '"':
              ssh_xbuffer_append(&buffer, (unsigned char *) "\"", 1);
              break;
            case '\\':
              ssh_xbuffer_append(&buffer, (unsigned char *) "\\", 1);
              break;
            case '\n':
              escape_whitespace = TRUE;
              break;
            case ' ':
              break;
            case '\t':
              break;
            default:
              ssh_xbuffer_append(&buffer, &byte, 1);
              break;
            }
          escaped = FALSE;
        }
      else
        {
          switch (byte)
            {
            case '"':
              *token_str = (void *)buffer_to_str(&buffer, token_str_len);
              ssh_buffer_uninit(&buffer);
              return SSH_PSYSTEM_OK;
              break;

            case '\\':
              escaped = TRUE;
              break;

            case ' ':
            case '\n':
            case '\t':
            case '\r':
              if (escape_whitespace == TRUE)
                continue;
              /* fallthrough */
            default:
              ssh_xbuffer_append(&buffer, &byte, 1);
              break;
            }
          escape_whitespace = FALSE;
        }
    }
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_FAILURE;
}

SshPSystemStatus ssh_psystem_read_ldap_dn(SshPSystemPos *pos,
                                          void **token_str,
                                          size_t *token_str_len)
{
  SshBufferStruct buffer;
  Boolean escaped, quoted, prev_was_whitespace;
  unsigned char byte;

  escaped = FALSE;
  quoted = FALSE;
  prev_was_whitespace = FALSE;

  ssh_buffer_init(&buffer);

  for (; pos->eof == FALSE; )
    {
      byte = NBYTE(pos);
      if (quoted)
        {
          if (escaped)
            {
              switch (byte)
                {
                case ' ':
                case '\t':
                case '\n':
                case '\r':
                  break;
                default:
                  ssh_xbuffer_append(&buffer, &byte, 1);
                  break;
                }
              escaped = FALSE;
            }
          else
            {
              switch (byte)
                {
                case '\\':
                  escaped = TRUE;
                  break;
                case '"':
                  /* Finish quoting. */
                  ssh_xbuffer_append(&buffer, &byte, 1);
                  quoted = FALSE;
                  break;
                default:
                  ssh_xbuffer_append(&buffer, &byte, 1);
                  break;
                }
            }
        }
      else
        {
          /* We don't here concert ourselves with escaping. It is much
             too difficult, and leave it to some other function. :) */

          switch (byte)
            {
            case '>':
              /* Finished. */
              *token_str = buffer_to_str(&buffer, token_str_len);
              ssh_buffer_uninit(&buffer);
              return SSH_PSYSTEM_OK;
              break;

            case ' ':
            case '\t':
            case '\n':
            case '\r':
              if (!prev_was_whitespace)
                ssh_xbuffer_append(&buffer, &byte, 1);
              prev_was_whitespace = TRUE;
              continue;
            case '"':
              quoted = TRUE;
              ssh_xbuffer_append(&buffer, &byte, 1);
              break;
            default:
              ssh_xbuffer_append(&buffer, &byte, 1);
              break;
            }
        }
      prev_was_whitespace = FALSE;
    }
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_FAILURE;
}

/* Internal data types which are recognized at some point, and a flag that
   one should try recognization by the decoders listed. */
typedef enum
{
  SSH_PSYSTEM_READ_ENV_OPEN,
  SSH_PSYSTEM_READ_ENV_CLOSE,
  SSH_PSYSTEM_READ_LIST_OPEN,
  SSH_PSYSTEM_READ_LIST_CLOSE,
  SSH_PSYSTEM_READ_LDAP_DN,
  SSH_PSYSTEM_READ_STRING,
  SSH_PSYSTEM_READ_USE_RECOGNIZE
} SshPSystemToken;

/* Read the next token. */
SshPSystemStatus ssh_psystem_read_next(SshPSystemDef def,
                                       SshPSystemPos *pos,
                                       SshPSystemToken *token,
                                       void **token_str,
                                       size_t *token_str_len)
{
  Boolean name_read = FALSE, name_set = FALSE;
  Boolean escaped = FALSE, escape_whitespace = FALSE;
  SshBufferStruct buffer;
  unsigned char byte;

  /* Set to defaults. */
  *token = SSH_PSYSTEM_READ_USE_RECOGNIZE;
  *token_str = NULL;
  *token_str_len = 0;

  ssh_buffer_init(&buffer);

  for (; pos->eof == FALSE && name_read == FALSE;)
    {
      byte = NBYTE(pos);

      /* We allow a lot to be escaped. This might be indeed nice on many
         occasions. */
      if (escaped)
        {
          switch (byte)
            {
              /* Most useful operation, escaping the linefeed. */
            case '\n':
              escape_whitespace = TRUE;
              /* name_set = FALSE; */
              break;
              /* The rest, what might be, is not yet implemented. */
            default:
              ssh_xbuffer_append(&buffer, &byte, 1);
              name_set = TRUE;
              break;
            }
          escaped = FALSE;
        }
      else
        {
          switch (byte)
            {
            case '\n':
            case '\r':
            case ' ':
            case '\t':
              if (escape_whitespace)
                continue;
              if (name_set == TRUE)
                name_read = TRUE;
              break;
              /* Special characters, which need to be checked before
                 continuing. They are errorneous if not in the beginning
                 of appropriate sequence. */
            case '{':
              if (name_set == FALSE)
                {
                  *token = SSH_PSYSTEM_READ_ENV_OPEN;
                  ssh_buffer_uninit(&buffer);
                  return SSH_PSYSTEM_OK;
                }
              PBYTE(pos, byte);
              name_read = TRUE;
              break;

            case '}':
              if (name_set == FALSE)
                {
                  *token = SSH_PSYSTEM_READ_ENV_CLOSE;
                  ssh_buffer_uninit(&buffer);
                  return SSH_PSYSTEM_OK;
                }
              PBYTE(pos, byte);
              name_read = TRUE;
              break;

            case '[':
              if (name_set == FALSE)
                {
                  *token = SSH_PSYSTEM_READ_LIST_OPEN;
                  ssh_buffer_uninit(&buffer);
                  return SSH_PSYSTEM_OK;
                }
              PBYTE(pos, byte);
              name_read = TRUE;
              break;

            case ']':
              if (name_set == FALSE)
                {
                  *token = SSH_PSYSTEM_READ_LIST_CLOSE;
                  ssh_buffer_uninit(&buffer);
                  return SSH_PSYSTEM_OK;
                }
              PBYTE(pos, byte);
              name_read = TRUE;
              break;

            case '<':
              ssh_buffer_uninit(&buffer);
              if (name_set == TRUE)
                return SSH_PSYSTEM_FAILURE;

              /* Read the LDAP Distinguished Name. */
              *token = SSH_PSYSTEM_READ_LDAP_DN;
              return ssh_psystem_read_ldap_dn(pos, token_str, token_str_len);
              break;
            case '"':
              ssh_buffer_uninit(&buffer);
              if (name_set == TRUE)
                return SSH_PSYSTEM_FAILURE;

              /* Read the standard string. */
              *token = SSH_PSYSTEM_READ_STRING;
              return ssh_psystem_read_string(pos, token_str, token_str_len);
              break;
            case '%':
              for (; pos->eof == FALSE;)
                {
                  byte = NBYTE(pos);
                  if (byte == '\n')
                    break;
                }
              /* This is important, thus comments also separate things. */
              if (name_set == TRUE)
                name_read = TRUE;
              break;
            case '\\':
              escaped = TRUE;
              break;
            default:
              *token = SSH_PSYSTEM_READ_USE_RECOGNIZE;
              ssh_xbuffer_append(&buffer, &byte, 1);
              name_set = TRUE;
              break;
            }
          escape_whitespace = FALSE;
        }
    }
  *token_str = buffer_to_str(&buffer, token_str_len);
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_OK;
}

typedef struct SshPSystemStackEntryRec
{
  SshPSystemEnv env;
  void *tmp_context;
  int list_level;
} SshPSystemStackEntry;

typedef enum
{
  SSH_PSYSTEM_NEXT_ENV,
  SSH_PSYSTEM_NEXT_VAR,
  SSH_PSYSTEM_NEXT_VAGUE,
  SSH_PSYSTEM_NEXT_NAME,
  SSH_PSYSTEM_NEXT_DATA
} SshPSystemNextToken;


/* Simple stack. */
typedef struct SshDStackRec
{
  struct SshDStackRec *next;
  void *data;
} *SshDStack, SshDStackStruct;

static void *ssh_dstack_pop(SshDStack *stack)
{
  void *data;
  SshDStack next;

  if (stack == NULL)
    return NULL;

  if (*stack != NULL)
    {
      data = (*stack)->data;
      next = (*stack)->next;
      ssh_free(*stack);
      *stack = next;
      return data;
    }
  return NULL;
}

static void ssh_dstack_push(SshDStack *stack, void *data)
{
  SshDStack node;

  if (stack == NULL)
    return;

  if ((node = ssh_malloc(sizeof(*node))) != NULL)
    {
      node->data = data;
      node->next = *stack;
      *stack = node;
    }
}

static Boolean ssh_dstack_exists(SshDStack *stack)
{
  if (stack == NULL)
    return FALSE;
  if (*stack == NULL)
    return FALSE;
  return TRUE;
}

/* The main function which does it all. */

void *ssh_psystem_parse(SshPSystemDef def,
                        SshPSystemError ret_error)
{
  SshPSystemPos pos;
  SshPSystemEnv env = NULL, new_env = NULL, prev_env = NULL;
  SshPSystemVar var = NULL;
  SshPSystemStatus error;
  SshPSystemStackEntry *entry;
  SshPSystemNextToken token_type, token_to_expect;
  SshPSystemToken token, prev_type;
  SshDStack stack;
  void *token_str, *buf, *ret, *env_tmp_context,
    *object_context, *feed_context;
  size_t token_str_len, i, buf_len;
  Boolean object_taken;
  int level;
  int list_level;
  unsigned int flag;

  /* Mainly just call the right function at the right time. */

  /* Information of the position and the current token. */
  ssh_psystem_pos_init(&pos, def->more, def->more_context);

  /* Main loop. */

  level = 0;
  stack = NULL;
  env = def->root;
  token_type = SSH_PSYSTEM_NEXT_ENV;
  list_level = 0;

  if (env == NULL)
    {
      error = SSH_PSYSTEM_FAILURE;
      goto failed;
    }

  /* Initialize the root context. */
  env_tmp_context = NULL;

  /* Initialize the root. */
  if (env && env->handler)
    {
      if ((*env->handler)(SSH_PSYSTEM_INIT,
                          0,
                          NULL, 0,
                          0,
                          /* in = feeding, out = context */
                          def->feeding, &env_tmp_context) == FALSE)
        {
          error = SSH_PSYSTEM_FAILURE;
          goto failed;
        }
    }
  else
    {
      error = SSH_PSYSTEM_FAILURE;
      goto failed;
    }

  /* The token_str == NULL if not defined, hence we don't need to
     explicitly free it all the time. */
  token_str = NULL;

  for (token_to_expect = SSH_PSYSTEM_NEXT_NAME; ;)
    {
      if (token_to_expect == SSH_PSYSTEM_NEXT_NAME)
        {
          /* Free the token string if necessary. */
          if (token_str != NULL)
            {
              ssh_xfree(token_str);
              token_str = NULL;
            }

          /* Read first the name. */
          error = ssh_psystem_read_next(def, &pos, &token, &token_str,
                                        &token_str_len);
          if (error != SSH_PSYSTEM_OK)
            goto failed;
          if (pos.eof == TRUE)
            break;

          switch (token)
            {
            case SSH_PSYSTEM_READ_ENV_CLOSE:
              level--;
              if (level < 0 || list_level != 0)
                {
                  error = SSH_PSYSTEM_MISPLACED_CLOSE;
                  goto failed;
                }
              /* Finish the thing. */
              object_context = NULL;
              if ((*env->handler)(SSH_PSYSTEM_FINAL,
                                  0,
                                  NULL, 0, 0,
                                  /* in = temp, out = finalized, temp will
                                     be freed in the process. */
                                  env_tmp_context, &object_context) == FALSE)
                {
                  error = SSH_PSYSTEM_OBJECT_NOT_CREATED;
                  goto failed;
                }

              /* Get the object type. */
              prev_env  = env;
              prev_type = env->aptype;

              /* Get the old environment. */
              entry = ssh_dstack_pop(&stack);
              if (entry == NULL)
                {
                  error = SSH_PSYSTEM_FAILURE;
                  goto failed;
                }
              token_type = SSH_PSYSTEM_NEXT_ENV;

              /* Get information. */
              env = entry->env;
              list_level = entry->list_level;
              env_tmp_context = entry->tmp_context;
              ssh_xfree(entry);

              /* Add the object. */
              if ((*env->handler)(SSH_PSYSTEM_OBJECT,
                                  prev_type,
                                  object_context, 0,
                                  list_level,
                                  /* in = temp, out = NULL */
                                  env_tmp_context, NULL) == FALSE)
                {
                  error = SSH_PSYSTEM_ADD_FAILED;
                  goto failed;
                }

              /* What if we are still in middle of a list? */
              if (list_level)
                {
                  token_to_expect = SSH_PSYSTEM_NEXT_DATA;
                  new_env = prev_env;
                }
              continue;
            default:
              break;
            }

          /* Could try to find a match here, and thus report error
             message immediately. This would keep the line correct for
             error messages, if one searches for set operator then the
             line number might be totally different. */

          /* Check first for variable. */
          token_type = SSH_PSYSTEM_NEXT_VAGUE;

          if (env->var_bind == NULL &&
              env->env_bind == NULL)
            {
              error = SSH_PSYSTEM_NO_BIND;
              goto failed;
            }

          if (token_str == NULL)
            {
              error = SSH_PSYSTEM_TOKEN_STR_EMPTY;
              goto failed;
            }

          if (env->var_bind)
            {
              for (i = 0; env->var_bind[i].name; i++)
                {
                  if (strcmp(env->var_bind[i].name, token_str) == 0)
                    {
                      var = &env->var_bind[i];
                      token_type = SSH_PSYSTEM_NEXT_VAR;
                      goto match_success;
                    }
                }
            }

          if (env->env_bind)
            {
              for (i = 0; env->env_bind[i].name; i++)
                {
                  if (strcmp(env->env_bind[i].name, token_str) == 0)
                    {
                      if (token_type == SSH_PSYSTEM_NEXT_VAR)
                        {
                          error = SSH_PSYSTEM_SAME_NAME_USED;
                          goto failed;
                        }
                      else
                        token_type = SSH_PSYSTEM_NEXT_ENV;
                      new_env = &env->env_bind[i];
                      if (new_env->handler == NULL_FNPTR)
                        {
                          error = SSH_PSYSTEM_HANDLER_MISSING;
                          goto failed;
                        }

                      goto match_success;
                    }
                }
            }

          error = SSH_PSYSTEM_NOT_SUPPORTED_NAME;
          goto failed;

          /* We were successful. */
        match_success:

          /* Now check for very simple cases (without operators even). */
          if (token_type == SSH_PSYSTEM_NEXT_VAR)
            {
              switch (var->type)
                {
                case SSH_PSYSTEM_VOID:
                  /* Handle the void type, which is pretty easy. */
                  object_taken = FALSE;
                  if ((*env->handler)(SSH_PSYSTEM_OBJECT,
                                      var->aptype,
                                      NULL, 0,
                                      0,
                                      /* in = temp, out = NULL */
                                      env_tmp_context,
                                      (void **)((void *)&object_taken))
                      == FALSE)
                    {
                      error = SSH_PSYSTEM_COULD_NOT_ADD;
                      goto failed;
                    }

                  /* Object taken doesn't mean much here! */

                  continue;
                default:
                  break;
                }
            }

          /* Read then the set sign, if one used. */
          if (def->assign_operator)
            {
              /* Free the token string if necessary. */
              if (token_str != NULL)
                {
                  ssh_xfree(token_str);
                  token_str = NULL;
                }

              /* Read the next string. */
              error = ssh_psystem_read_next(def, &pos, &token,
                                            &token_str, &token_str_len);
              if (error != SSH_PSYSTEM_OK)
                goto failed;
              if (pos.eof == TRUE)
                break;
              if (token_str == NULL)
                {
                  error = SSH_PSYSTEM_EXPECTED_ASSIGNMENT;
                  goto failed;
                }
              if (strcmp(token_str, def->assign_operator) != 0)
                {
                  error = SSH_PSYSTEM_NOT_OPERATOR;
                  goto failed;
                }
            }
          token_to_expect = SSH_PSYSTEM_NEXT_DATA;
        }
      else
        {
          /* Free the token string if necessary. */
          if (token_str != NULL)
            {
              ssh_xfree(token_str);
              token_str = NULL;
            }

          /* Read the next string. */
          error = ssh_psystem_read_next(def, &pos,
                                        &token, &token_str, &token_str_len);
          if (error != SSH_PSYSTEM_OK)
            goto failed;
          if (pos.eof == TRUE)
            break;

          if (token_type == SSH_PSYSTEM_NEXT_ENV)
            {
              switch (token)
                {
                case SSH_PSYSTEM_READ_ENV_OPEN:
                  /* Read whether the parent environment wants to
                     feed off the children. */
                  /* Make sure that the feed_context is properly set. */
                  feed_context = NULL;
                  if ((*env->handler)(SSH_PSYSTEM_FEED,
                                      new_env->aptype,
                                      NULL, 0,
                                      0,
                                      env_tmp_context,
                                      &feed_context) == FALSE)
                    {
                      /* Didn't want to and gave an error! However, this
                         is not that bad. Things happen. Lets continue. */
                    }

                  /* Push the current environment. */
                  entry = ssh_xmalloc(sizeof(*entry));
                  entry->env = env;
                  entry->tmp_context = env_tmp_context;
                  entry->list_level = list_level;
                  ssh_dstack_push(&stack, entry);

                  /* Start a new environment. */
                  level++;
                  env = new_env;
                  list_level = 0;
                  if ((*env->handler)(SSH_PSYSTEM_INIT,
                                      0,
                                      NULL, 0,
                                      0,
                                      /* in = feeding?, out = temp. */
                                      feed_context,
                                      &env_tmp_context) == FALSE)
                    {
                      error = SSH_PSYSTEM_INIT_FAILED;
                      goto failed;
                    }

                  token_to_expect = SSH_PSYSTEM_NEXT_NAME;
                  break;
                case SSH_PSYSTEM_READ_LIST_OPEN:
                  list_level++;
                  if ((*env->handler)(SSH_PSYSTEM_LIST_OPEN,
                                      0,
                                      NULL, 0,
                                      list_level,
                                      /* in = temp, out = NULL */
                                      env_tmp_context, NULL) == FALSE)
                    {
                      error = SSH_PSYSTEM_COULD_NOT_OPEN_LIST;
                      goto failed;
                    }
                  break;
                case SSH_PSYSTEM_READ_LIST_CLOSE:
                  list_level--;
                  if (list_level < 0)
                    {
                      error = SSH_PSYSTEM_LIST_MISMATCH;
                      goto failed;
                    }
                  if ((*env->handler)(SSH_PSYSTEM_LIST_CLOSE,
                                      0, NULL, 0,
                                      list_level,
                                      /* in = temp, out = NULL */
                                      env_tmp_context, NULL) == FALSE)
                    {
                      error = SSH_PSYSTEM_COULD_NOT_CLOSE_LIST;
                      goto failed;
                    }
                  /* Handle here the case when list is over, however,
                     maybe one could do this nicer... */
                  if (list_level == 0)
                    token_to_expect = SSH_PSYSTEM_NEXT_NAME;
                  break;
                default:
                  error = SSH_PSYSTEM_TOKEN_NOT_EXPECTED;
                  goto failed;
                  break;
                }
              continue;
            }

          switch (token)
            {
            case SSH_PSYSTEM_READ_USE_RECOGNIZE:
              /* Recognize with all known methods. */
              flag = ssh_psystem_map(var->type);

              for (i = 0;
                   ssh_psystem_decoders[i].decoder != NULL_FNPTR; i++)
                {
                  if ((ssh_psystem_decoders[i].flag & flag) != 0)
                    {
                      if ((*ssh_psystem_decoders[i].decoder)
                          (token_str, token_str_len,
                           &buf, &buf_len) == TRUE)
                        break;
                    }
                }
              if (ssh_psystem_decoders[i].decoder == NULL_FNPTR)
                {
                  error = SSH_PSYSTEM_UNSUPPORTED_TYPE;
                  goto failed;
                }

              /* Free the token string. */
              object_taken = FALSE;
              if ((*env->handler)(SSH_PSYSTEM_OBJECT,
                                  var->aptype,
                                  buf, buf_len,
                                  list_level,
                                  /* in = temp, out = boolean */
                                  env_tmp_context,
                                  (void **)((void *)&object_taken))
                  == FALSE)
                {
                  (*ssh_psystem_decoders[i].free)(buf, buf_len);
                  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
                  goto failed;
                }

              /* Free the allocated token. */
              if (!object_taken)
                (*ssh_psystem_decoders[i].free)(buf, buf_len);

              break;
            case SSH_PSYSTEM_READ_LDAP_DN:
              if (var->type != SSH_PSYSTEM_LDAP_DN)
                {
                  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
                  goto failed;
                }
              object_taken = FALSE;
              if ((*env->handler)(SSH_PSYSTEM_OBJECT,
                                  var->aptype,
                                  token_str, token_str_len,
                                  list_level,
                                  /* in = temp, out = boolean */
                                  env_tmp_context,
                                  (void **)((void *)&object_taken))
                  == FALSE)
                {
                  error = SSH_PSYSTEM_COULD_NOT_ADD;
                  goto failed;
                }
              if (object_taken)
                token_str = NULL;
              break;
            case SSH_PSYSTEM_READ_STRING:
              if (var->type != SSH_PSYSTEM_STRING)
                {
                  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
                  goto failed;
                }
              object_taken = FALSE;
              if ((*env->handler)(SSH_PSYSTEM_OBJECT,
                                  var->aptype,
                                  token_str, token_str_len,
                                  list_level,
                                  /* in = temp, out = boolean */
                                  env_tmp_context,
                                  (void **)((void *)&object_taken))
                  == FALSE)
                {
                  error = SSH_PSYSTEM_COULD_NOT_ADD;
                  goto failed;
                }
              if (object_taken)
                token_str = NULL;
              break;
            case SSH_PSYSTEM_READ_LIST_OPEN:
              list_level++;
              if ((*env->handler)(SSH_PSYSTEM_LIST_OPEN,
                                  0, NULL, 0,
                                  list_level,
                                  /* in = temp, out = NULL */
                                  env_tmp_context, NULL) == FALSE)
                {
                  error = SSH_PSYSTEM_COULD_NOT_OPEN_LIST;
                  goto failed;
                }
              break;
            case SSH_PSYSTEM_READ_LIST_CLOSE:
              list_level--;
              if (list_level < 0)
                {
                  error = SSH_PSYSTEM_LIST_MISMATCH;
                  goto failed;
                }
              if ((*env->handler)(SSH_PSYSTEM_LIST_CLOSE,
                                  0, NULL, 0,
                                  list_level,
                                  /* in = temp, out = NULL */
                                  env_tmp_context, NULL) == FALSE)
                {
                  error = SSH_PSYSTEM_COULD_NOT_CLOSE_LIST;
                  goto failed;
                }
              break;
            default:
              error = SSH_PSYSTEM_UNKNOWN_TYPE;
              goto failed;
              break;
            }

          /* Only if the list level allows, use this. */
          if (list_level == 0)
            token_to_expect = SSH_PSYSTEM_NEXT_NAME;
        }
    }
  error = SSH_PSYSTEM_OK;
failed:

  /* Free current context. */
  if (env && ssh_dstack_exists(&stack))
    {
      if (env->handler &&
          (*env->handler)(SSH_PSYSTEM_ERROR,
                          0,
                          NULL,
                          0, 0,
                          /* in = temp, out = NULL */
                          env_tmp_context, NULL) == FALSE)
        {
          /* Ignore the error for now. At this point some earlier error
             must have also occurred. */
        }
      ret = NULL;
    }
  else
    {
      /* Have a environment at return. */
      ret = env;
    }

  while (ssh_dstack_exists(&stack))
    {
      entry = ssh_dstack_pop(&stack);
      env = entry->env;
      env_tmp_context = entry->tmp_context;
      if (env)
        {
          /* Free the environment context. */
          if ((*env->handler)(SSH_PSYSTEM_ERROR,
                              0, NULL, 0, 0,
                              /* in = temp, out = NULL */
                              env_tmp_context, NULL) == FALSE)
            {
              /* Ignore the error for now. At this point some earlier error
                 must have also occurred. */
            }
        }
    }

  /* Build the suitable error message. */
  ret_error->status = error;
  /* Make the line no and pos no emacs compatible. */
  ret_error->line   = pos.line + 1;
  ret_error->pos    = pos.pos + 1;

  /* Check the token string. */
  if (token_str != NULL)
    {
      ssh_xfree(token_str);
      token_str = NULL;
    }

  /* Free the position. */
  ssh_psystem_pos_free(&pos);

  return ret;
}

/************************* Alternate parser *********************************/

/* Token codes */
typedef enum {
  SSH_PSYSTEM_TOK_EOF,
  SSH_PSYSTEM_TOK_ID,       /* Identifier */
  SSH_PSYSTEM_TOK_ENV_OPEN,
  SSH_PSYSTEM_TOK_ENV_CLOSE,
  SSH_PSYSTEM_TOK_LIST_OPEN,
  SSH_PSYSTEM_TOK_LIST_CLOSE,
  SSH_PSYSTEM_TOK_LDAP,
  SSH_PSYSTEM_TOK_STRING,
  SSH_PSYSTEM_TOK_OTHER
} SshPSystemTok; /* Alas, SshPSystemToken was taken already */

/* Parser state is maintained in this structure */
typedef struct SshPSystemParseStateRec
{
  SshPSystemDef def;
  SshPSystemPos pos;
  SshPSystemTok token;
  void* token_str;
  size_t token_len;
  int token_line, token_col;
} SshPSystemParseState;

SshPSystemNode ssh_psystem_alloc_node(SshPSystemNode parent,
                                      int line, int col)
{
  SshPSystemNode node = ssh_xcalloc(1, sizeof(*node));

  node->parent = parent;
  node->node_type = SSH_PSYSTEM_VAR;
  node->var_type  = SSH_PSYSTEM_VOID;
  node->line      = line;
  node->column    = col;
  node->error     = SSH_PSYSTEM_OK;

  /* This is a trivial free routine -- just wraps ssh_xfree() */
  node->free_routine = ssh_psystem_string_free;

  node->first_unmatched_child = NULL;
  node->last_child = NULL;

  if (parent != 0)
    {
      /* Link this node to its parent */
      if (!parent->child)
        parent->child = node;
      else
        parent->last_child->next = node;
      parent->last_child = node;
    }
  return node;
}

/* Recursively frees a node and its children */
void ssh_psystem_free_node(SshPSystemNode node)
{
  /* Free children. */
  SshPSystemNode p = node->child;

  while (p)
    {
      SshPSystemNode next = p->next;

      ssh_psystem_free_node(p);
      p = next;
    }

  /* Free name and data */
  ssh_xfree(node->name);

  if (node->data)
    (*node->free_routine)(node->data, node->data_len);

  /* In the end free the node */
  ssh_xfree(node);
}

/* Read the next token. */
SshPSystemStatus ssh_psystem_read_token(SshPSystemParseState *st)
{
  SshPSystemToken token;
  SshPSystemStatus status;
  int prev_pos = st->pos.pos;

  status =  ssh_psystem_read_next(st->def, &st->pos, &token,
                                  &st->token_str, &st->token_len);

  /* Record the current source coordinates. This is a tricky task,
     because the position is now *past* the token we just read.
     Of course, the real solution would be to update the PSystem
     lexer to keep better track of positions. */
  if (st->pos.pos == 0) {
    st->token_line = st->pos.line;  /* On the previous line */
    st->token_col  = prev_pos + 1;  /* Best guess I could make */
  } else {
    st->token_line = st->pos.line + 1;
    st->token_col  = st->pos.pos  + 1 - st->token_len;
  }
  if (status != SSH_PSYSTEM_OK)
    return status;

  if (st->pos.eof)
    {
      /* Life will be simpler if EOF is a distinct token. */
      st->token = SSH_PSYSTEM_TOK_EOF;
    }
  else
    {
      switch (token)
        {
        case SSH_PSYSTEM_READ_USE_RECOGNIZE:
          {
            /* Check for an identifier token */
            size_t i;
            unsigned char *str = st->token_str;

            if (st->token_len == 0 || !isalpha(*str))
              {
                st->token = SSH_PSYSTEM_TOK_OTHER;
                break;
              }

            for (i = 0; i < st->token_len; i++)
              {
                if (!isalnum(str[i]))
                  {
                    st->token = SSH_PSYSTEM_TOK_OTHER;
                    return status;
                }
              }

            /* The token string consists of alphanumeric characters,
               so assume it is an identifier */
            st->token = SSH_PSYSTEM_TOK_ID;
            break;
          }
        case SSH_PSYSTEM_READ_ENV_OPEN:
          st->token = SSH_PSYSTEM_TOK_ENV_OPEN;
          break;
        case SSH_PSYSTEM_READ_ENV_CLOSE:
          st->token = SSH_PSYSTEM_TOK_ENV_CLOSE;
          break;
        case SSH_PSYSTEM_READ_LIST_OPEN:
          st->token = SSH_PSYSTEM_TOK_LIST_OPEN;
          break;
        case SSH_PSYSTEM_READ_LIST_CLOSE:
          st->token = SSH_PSYSTEM_TOK_LIST_CLOSE;
          break;
        case SSH_PSYSTEM_READ_LDAP_DN:
          st->token = SSH_PSYSTEM_TOK_LDAP;
          break;
        case SSH_PSYSTEM_READ_STRING:
          st->token = SSH_PSYSTEM_TOK_STRING;
          break;
        }
    }
  return status;
}

/* Forward declarations */
SshPSystemStatus ssh_psystem_parse_env(SshPSystemParseState *st,
                                        SshPSystemNode parent);
SshPSystemStatus ssh_psystem_parse_list(SshPSystemParseState *st,
                                        SshPSystemNode parent);

SshPSystemStatus ssh_psystem_parse_name(SshPSystemParseState *st,
                                        SshPSystemNode parent)
{
  SshPSystemStatus status;
  SshPSystemNode cur_node;
  Boolean assignment_seen = FALSE;

  if (parent == NULL)
    {
      return SSH_PSYSTEM_FAILURE;
    }

  cur_node = ssh_psystem_alloc_node(parent, st->token_line,
                                    st->token_col);

  if (st->token == SSH_PSYSTEM_TOK_ID)
    {
      cur_node->name = st->token_str;
      st->token_str = NULL;
      SSH_DEBUG(15, ("# Parse variable %s", cur_node->name));
    }

  status = ssh_psystem_read_token(st);
  if (status != SSH_PSYSTEM_OK)
    {
      ssh_psystem_free_node(cur_node);
      return status;
    }

  /* We need an assignment operator to be defined. Otherwise
     a construct such as "id1 id2" could be parsed as two
     void-assignments (both identifiers are keywords) or as
     one assignment "keyword := value". */
  if (st->token == SSH_PSYSTEM_TOK_OTHER &&
      strcmp(st->def->assign_operator, st->token_str) == 0)
    {
      ssh_xfree(st->token_str);
      st->token_str = NULL;

      status = ssh_psystem_read_token(st);
      if (status != SSH_PSYSTEM_OK)
        {
          ssh_psystem_free_node(cur_node);
          return status;
        }
      assignment_seen = TRUE;
    }

  switch (st->token)
    {
    case SSH_PSYSTEM_TOK_ENV_OPEN:
      cur_node->node_type = SSH_PSYSTEM_ENV;
      return ssh_psystem_parse_env(st, cur_node);

    case SSH_PSYSTEM_TOK_LIST_OPEN:
      cur_node->node_type = SSH_PSYSTEM_LIST;
      return ssh_psystem_parse_list(st, cur_node);

    case SSH_PSYSTEM_TOK_ID:
      /* ID ID is probably a void value followed by another;
         ID := ID is an assignment. */
      if (!assignment_seen)
        break;

      /* Fall through */

    case SSH_PSYSTEM_TOK_LDAP:
    case SSH_PSYSTEM_TOK_STRING:
    case SSH_PSYSTEM_TOK_OTHER:
      cur_node->node_type = SSH_PSYSTEM_VAR;
      cur_node->data = st->token_str;
      cur_node->data_len = st->token_len;
      st->token_str = NULL; /* CUR_NODE now owns the string. */
      switch (st->token)
        {
        case SSH_PSYSTEM_TOK_LDAP:
          cur_node->var_type = SSH_PSYSTEM_LDAP_DN;
          break;
        case SSH_PSYSTEM_TOK_STRING:
          cur_node->var_type = SSH_PSYSTEM_STRING;
          break;
        default:
          break;
        }
      status = ssh_psystem_read_token(st);
      if (status != SSH_PSYSTEM_OK)
        {
          ssh_psystem_free_node(cur_node);
          return status;
        }
      break;

    default:
      break;
    }
  return SSH_PSYSTEM_OK;
}

/* This function is called when the opening `{' of an environment
   has been scanned. It returns when it has scanned the closing
   `}', or when an error occurs. */
SshPSystemStatus ssh_psystem_parse_env(SshPSystemParseState *st,
                                       SshPSystemNode parent)
{
  SshPSystemStatus status;
  Boolean done = FALSE;

  SSH_DEBUG(15, ("# Parse environment %s",
                parent->name ? parent->name : "<unnamed>"));
  status = ssh_psystem_read_token(st);

  while (!done && status == SSH_PSYSTEM_OK)
    {
      switch (st->token)
        {
        case SSH_PSYSTEM_TOK_ENV_CLOSE:
          status = ssh_psystem_read_token(st);
          done = TRUE;
          break;
        case SSH_PSYSTEM_TOK_EOF:
          status = SSH_PSYSTEM_FAILURE;
          break;
        case SSH_PSYSTEM_TOK_ID:
          status = ssh_psystem_parse_name(st, parent);
          break;
        default:
          status = SSH_PSYSTEM_TOKEN_NOT_EXPECTED;
          break;
        }
    }

  SSH_DEBUG(15, (" Done environment %s (%d)",
                parent->name ? parent->name : "<unnamed>", status));
  return status;
}

/* This function is called when the opening `[' of a list
   has been scanned. It returns when it has scanned the closing
   `]', or when an error occurs. */
SshPSystemStatus ssh_psystem_parse_list(SshPSystemParseState *st,
                                        SshPSystemNode parent)
{
  SshPSystemStatus status;
  SshPSystemNode cur_node;
  Boolean done = FALSE;

  status = ssh_psystem_read_token(st);

  while (!done && status == SSH_PSYSTEM_OK)
    {
      switch (st->token)
        {
        case SSH_PSYSTEM_TOK_LIST_CLOSE:
          status = ssh_psystem_read_token(st);
          done = TRUE;
          break;
        case SSH_PSYSTEM_TOK_EOF:
          status = SSH_PSYSTEM_COULD_NOT_CLOSE_LIST;
          break;
        case SSH_PSYSTEM_TOK_ENV_OPEN:
          cur_node = ssh_psystem_alloc_node(parent,
                                            st->token_line, st->token_col);
          status = ssh_psystem_parse_env(st, cur_node);
          break;
        default:
          status = SSH_PSYSTEM_TOKEN_NOT_EXPECTED;
          break;
        }
    }
  return status;
}

/* This function parses top-level constructs, stopping when
   EOF is scanned. */
SshPSystemStatus ssh_psystem_parse_top_level(SshPSystemParseState *st,
                                             SshPSystemNode parent)
{
  SshPSystemStatus status;
  Boolean done = FALSE;
  status = ssh_psystem_read_token(st);
  while (!done && status == SSH_PSYSTEM_OK)
    {
      switch (st->token)
        {
        case SSH_PSYSTEM_TOK_EOF:
          done = TRUE;
          break;
        case SSH_PSYSTEM_TOK_ID:
          status = ssh_psystem_parse_name(st, parent);
          break;
        default:
          status = SSH_PSYSTEM_TOKEN_NOT_EXPECTED;
          break;
        }
    }
  return status;
}

/* Alternate parser. Instead of using a hairy callback architecture,
   this parser uses recursive descent to parse the input into tree
   form. The caller is then supposed to walk the resulting tree to
   perform semantic actions. */
void ssh_psystem_parse_tree(SshPSystemDef def,
                            SshPSystemError error,
                            SshPSystemNode* root)
{
  SshPSystemNode root_node;
  SshPSystemStatus status;
  SshPSystemParseState parse_state = { 0 };

  *root = NULL;

  parse_state.def = def;
  parse_state.token_str = NULL;

  ssh_psystem_pos_init(&parse_state.pos, def->more, def->more_context);

  /* Allocate root node and parse the input into tree structure. */
  root_node = ssh_psystem_alloc_node(NULL, 0, 0);
  status = ssh_psystem_parse_top_level(&parse_state, root_node);

  /* Build an suitable error message. */
  error->status = status;
  error->line   = parse_state.token_line;
  error->pos    = parse_state.token_col;

  if (parse_state.token_str)
    ssh_xfree(parse_state.token_str);

  ssh_psystem_pos_free(&parse_state.pos);

  if (status == SSH_PSYSTEM_OK)
    {
      *root = root_node;
    }
  else
    {
      /* Free whatever we managed to parse */
      ssh_psystem_free_node(root_node);
    }
}

/*********************** Matching routines ********************************/

SshPSystemNode ssh_psystem_find_node(SshPSystemNode node, const char* name)
{
  SshPSystemNode p;
  Boolean retry = FALSE;

  p = node->first_unmatched_child ? node->first_unmatched_child : node->child;

 try_all:
  for (; p; p = p->next)
    {
      if (!p->matched && (!name || strcmp(p->name, name) == 0))
        {
          p->matched = TRUE;
          if (!retry)
            node->first_unmatched_child = p->next;
          return p;
        }
    }
  if (retry)
    return NULL;

  retry = TRUE;
  p = node->child;
  goto try_all;
}

/* Find a variable node with VAR_NAME in children of NODE. If the
   variable is of (or can be converted to) type TYPE, return the value
   in BUFP. */
Boolean ssh_psystem_match(SshPSystemNode node, const char *var_name,
                          SshPSystemType type,
                          void **bufp, size_t *bufp_len,
                          SshPSystemNode *rnode)
{
  unsigned int flag;
  const SshPSystemDecoders *dec;
  void *buf;
  size_t buf_len;
  Boolean detach = FALSE;

  if (bufp)
    *bufp = NULL;

  /* Should the value (if we find one) be detached from the node? */
  if (var_name[0] == '*')
    {
      detach = TRUE;
      var_name++;
    }

  /* Find child node with given name. */
  node = ssh_psystem_find_node(node, var_name);
  if (!node)
    return FALSE;

  /* See if the node type matches */
  if (node->node_type != SSH_PSYSTEM_VAR)
    {
      node->error = SSH_PSYSTEM_SAME_NAME_USED;
      return FALSE;
    }

  /* Did we want a void node? */
  if (type == SSH_PSYSTEM_VOID)
    {
      if (node->var_type != SSH_PSYSTEM_VOID || node->data != 0)
        {
          node->error = SSH_PSYSTEM_UNSUPPORTED_TYPE;
          return FALSE;
        }
      else
        return TRUE;
    }

  /* If the node has never been decoded yet, try to decode the data. */
  if (node->var_type == SSH_PSYSTEM_VOID) {
    flag = ssh_psystem_map(type);
    for (dec = ssh_psystem_decoders; dec->decoder != NULL_FNPTR; dec++)
      {
        if (dec->flag & flag) {
          if ((*dec->decoder)(node->data, node->data_len, &buf, &buf_len))
            break;
        }
      }

    if (dec->decoder == NULL_FNPTR)
      {
        node->error = SSH_PSYSTEM_UNSUPPORTED_TYPE;
        return FALSE;
      }

    /* Free the unconverted data */
    (*node->free_routine)(node->data, node->data_len);

    node->var_type = type;
    node->data = buf;
    node->data_len = buf_len;
    node->free_routine = dec->free;
  }

  /* Test again: do we have correct type of data? */
  if (node->var_type == type)
    {
      /* Return results to the caller -- everything is optional */
      if (bufp)
        *bufp = node->data;
      if (bufp_len)
        *bufp_len = node->data_len;
      if (detach)
        node->data = NULL;
      if (rnode)
        *rnode = node;
      return TRUE;
    }
  else
    {
      node->error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
      return FALSE;
    }
}

/* Get an integer variable */
Boolean ssh_psystem_get_int(SshPSystemNode node, const char *var_name,
                            SshMPInteger *mp_int, SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_INTEGER,
                           (void**) mp_int, NULL, rnode);
}

/* Get a string variable */
Boolean ssh_psystem_get_string(SshPSystemNode node, const char *var_name,
                               char **string, SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_STRING,
                           (void**) string, NULL, rnode);
}

Boolean ssh_psystem_get_ldap(SshPSystemNode node, const char *var_name,
                             char **string, SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_LDAP_DN,
                           (void**) string, NULL, rnode);
}

Boolean ssh_psystem_get_ip(SshPSystemNode node, const char *var_name,
                           unsigned char **buf, size_t *buf_len,
                           SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_IP,
                           (void**) buf, buf_len, rnode);
}

Boolean ssh_psystem_get_name(SshPSystemNode node, const char* var_name,
                             char** string, SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_NAME,
                           (void**) string, NULL, rnode);
}

Boolean ssh_psystem_get_void(SshPSystemNode node, const char* var_name,
                             SshPSystemNode *rnode)
{
  return ssh_psystem_match(node, var_name, SSH_PSYSTEM_VOID,
                           NULL, NULL, rnode);
}

Boolean ssh_psystem_get_env(SshPSystemNode node, const char *env_name,
                            SshPSystemNode *env_node)
{
  /* Find child node with given name. */
  node = ssh_psystem_find_node(node, env_name);
  if (!node)
    return FALSE;

  /* See if the node type matches */
  if (node->node_type != SSH_PSYSTEM_ENV)
    {
      node->error = SSH_PSYSTEM_SAME_NAME_USED;
      return FALSE;
    }

  *env_node = node;
  return TRUE;
}

Boolean ssh_psystem_get_list(SshPSystemNode node, const char *list_name,
                             SshPSystemNode *list_node)
{
  /* Find child node with given name. */
  node = ssh_psystem_find_node(node, list_name);
  if (!node)
    return FALSE;

  /* See if the node type matches */
  if (node->node_type != SSH_PSYSTEM_LIST)
    {
      node->error = SSH_PSYSTEM_SAME_NAME_USED;
      return FALSE;
    }

  *list_node = node;
  return TRUE;
}

/* Find the first nonmatched entry in children of NODE */
Boolean ssh_psystem_get_any(SshPSystemNode node,
                            SshPSystemNode* any_node)
{
  SshPSystemNode p;
  Boolean retry = FALSE;

  p = node->first_unmatched_child ? node->first_unmatched_child : node->child;

 try_all:
  for (; p; p = p->next)
    {
      if (!p->matched)
        {
          p->matched = TRUE;
          if (!retry) node->first_unmatched_child = p->next;
          *any_node = p;
          return TRUE;
        }
    }
  if (retry)
    return FALSE;

  retry = TRUE;
  p = node->child;
  goto try_all;
}

/* Return the first node that either was not matched or
   contains an error. */
Boolean ssh_psystem_find_error(SshPSystemNode node,
                               SshPSystemNode *error_node,
                               SshPSystemStatus *status)
{
  SshPSystemNode p;

  for (p = node->child; p; p = p->next)
    {
      if (!p->matched)
        {
          p->matched = TRUE;
          p->error = SSH_PSYSTEM_NOT_SUPPORTED_NAME;
        }
      if (p->error)
        {
          *error_node = p;
          *status = p->error;
          return TRUE;
        }
    }
  return FALSE;
}

Boolean ssh_psystem_match_env_node(SshPSystemNode node, const char* env)
{
  if (node->node_type != SSH_PSYSTEM_ENV)
    return FALSE;
  if (env != NULL && strcmp(node->name ? node->name : "", env) != 0)
    return FALSE;
  return TRUE;
}

Boolean ssh_psystem_match_var_node(SshPSystemNode node, const char* var)
{
  if (node->node_type != SSH_PSYSTEM_VAR)
    return FALSE;
  if (var != NULL && strcmp(node->name ? node->name : "", var) != 0)
    return FALSE;
  return TRUE;
}
