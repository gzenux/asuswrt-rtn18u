/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is an implementation of the Privacy Enhancement for Internet
   Electronic Mail requests for comments 1421-1424, to the depth
   which is required by our library.

   Some most peculiar features might not be available, however.

   Following features should be available:

   - parsing of all valid PEM blobs
   - some degree of guesswork for nearly-valid PEM blobs
   - writing of valid PEM blobs
   - maintainable parser and writer.
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshbuffer.h"
#include "sshcrypt.h"
#include "sshpemi.h"
#include "sshpem.h"
#include "sshadt.h"
#include "sshadt_list.h"

#include "sshbase16.h"
#include "sshbase64.h"
#include "sshpkcs5.h"
#include "sshpkcs8.h"

#include "sshkeyblob2.h"

#define SSH_DEBUG_MODULE "SshPemFormat"

/*
  Basic PEM format is as follows:

  -----BEGIN <preheader>-----
  <pemheader>
  [<pemtext>]
  -----END <postheader>-----

  where
  <preheader> = <postheader> and it usually is something like
    "X509 CERTIFICATE"
    "PRIVACY-ENHANCED MESSAGE"
    etc.

  Then
  <pemheader> =
    [ Proc-Type: 4, something
      Content-Domain: something
      DEK-Info: algorithm, params
      Originator-ID-*: something,*
      Receiver-ID-*: something,* ] /
    [ Proc-Type: 4, CRL
      CRL: encrypted
      Originator-Certificate: something
      Issuer-Certificate: something ]

 */

/* Some basic allocation etc. routines. */

SshPemArg *ssh_pem_args_alloc(int num_args)
{
  SshPemArg *args = ssh_calloc(num_args, sizeof(*args));
  return args;
}

void ssh_pem_args_free(SshPemArg *args)
{
  int i;

  for (i = 0; args[i].type != SSH_PEM_ARG_END; i++)
    {
      switch (args[i].type)
        {
        case SSH_PEM_ARG_SSH2STRING:
        case SSH_PEM_ARG_IASTRING:
          ssh_free(args[i].ob.str);
          break;
        case SSH_PEM_ARG_BINARY:
          ssh_free(args[i].ob.bin.data);
          break;
        case SSH_PEM_ARG_NUMBER:
          break;
        case SSH_PEM_ARG_KEYWORD:
          break;
        default:
          ssh_fatal("sshcert/ssh_pem_free_args: invalid argument type.");
          break;
        }
    }
  ssh_free(args);
}

void ssh_pem_args_free_adt(void *obj, void *context)
{
  ssh_pem_args_free(obj);
}

SshPemBlob *ssh_pem_blob_alloc(void)
{
  SshPemBlob *blob;

  if ((blob = ssh_calloc(1, sizeof(*blob))) != NULL)
    {
      if ((blob->args =
           ssh_adt_create_generic(SSH_ADT_LIST,
                                  SSH_ADT_DESTROY, ssh_pem_args_free_adt,
                                  SSH_ADT_ARGS_END)) == NULL)
        {
          ssh_free(blob);
          return NULL;
        }
    }
  return blob;
}

void ssh_pem_blob_free(SshPemBlob *blob)
{
  ssh_free(blob->begin_header);
  ssh_free(blob->end_header);
  ssh_free(blob->text);

  /* Free the args. */
  ssh_adt_destroy(blob->args);

  ssh_free(blob);
}

void ssh_pem_blob_free_adt(void *obj, void *context)
{
  ssh_pem_blob_free(obj);
}

static void ssh_pem_msg(SshPemParser *p, SshPemMsgId id, ...)
{
  va_list ap;
  SshPemArg  *args;
  unsigned int num_args, used_args;
  SshPemArgType fmt;

  va_start(ap, id);

  num_args  = 10;
  args = ssh_pem_args_alloc(num_args);
  if (args == NULL)
    {
      va_end(ap);
      return;
    }

  /* Put the first. */
  args[0].type   = SSH_PEM_ARG_NUMBER;
  args[0].ob.num = (unsigned int)id;

  /* The line number. */
  args[1].type   = SSH_PEM_ARG_NUMBER;
  args[1].ob.num = p->data_num_lines;

  /* Start from two. */
  used_args = 2;

  for (; (fmt = va_arg(ap, SshPemArgType)) != SSH_PEM_ARG_END;)
    {
      if (used_args >= num_args)
        ssh_fatal("sshcert/ssh_pem_msg: too many arguments (id %u).", id);

      /* Set the argument type already. */
      args[used_args].type = fmt;

      switch (fmt)
        {
        case SSH_PEM_ARG_SSH2STRING:
        case SSH_PEM_ARG_IASTRING:
          args[used_args].ob.str = va_arg(ap, char *);
          break;
        case SSH_PEM_ARG_BINARY:
          args[used_args].ob.bin.data     = va_arg(ap, unsigned char *);
          args[used_args].ob.bin.data_len = va_arg(ap, size_t);
          break;
        case SSH_PEM_ARG_NUMBER:
          args[used_args].ob.num = va_arg(ap, unsigned int);
          break;
        default:
          ssh_fatal("sshcert/ssh_pem_msg: "
                    "invalid argument in message (id %u).",
                    id);
          break;
        }
      used_args++;
    }

  /* Denote the last terminating argument. */
  args[used_args].type = SSH_PEM_ARG_END;

  va_end(ap);

  /* Throw the message to the message list. */
  ssh_adt_insert(p->msg, args);
}

/* This is generated charset map code. Please do not modify. */
static const unsigned char charset_ia[122] =
  {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,1,1,0,0,1,0,1,1,1,0,1,0,1,1,1,
    1,1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,
    0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1
  };
int ssh_pem_iachar(unsigned char byte)
{
  if (byte >= 122)
    return 0;
  return (charset_ia[byte]) & 0x1;
}
/* End of generated charset code. */

/* Macros for handling the stepping through characters in the parser. */
#define SSH_PEM_GETBYTE(parser, byte) \
do { \
  SshPemParser *__p = (parser); \
  if (__p->data_pos >= __p->data_len || _-p->data[__p->data_pos] == '\0') \
    { \
      (byte) = '\0'; \
    } \
  else \
    { \
      if (__p->data[__p->data_pos] == '\n') \
        __p->data_num_lines++; \
      (byte) = __p->data[__p->data_pos]; \
      __p->data_pos++; \
    } \
} while (0)

#define SSH_PEM_SKIPBYTE(parser) \
do { \
  SshPemParser *__p = (parser); \
  if (__p->data_pos >= __p->data_len || __p->data[__p->data_pos] == '\0') \
    ; \
  else \
    { \
      if (__p->data[__p->data_pos] == '\n') \
        __p->data_num_lines++; \
      __p->data_pos++; \
    } \
} while (0)

#define SSH_PEM_LOOKUPBYTE(parser, pos, byte) \
do { \
  SshPemParser *__p = (parser); \
  size_t     __i = (pos) + __p->data_pos; \
  if (__i >= __p->data_len) \
    { \
      (byte) = '\0'; \
    } \
  else \
    { \
      (byte) = __p->data[__i]; \
    } \
} while (0)


/* Skipwhitespace. */
static void ssh_pem_skipwhite(SshPemParser *p)
{
  unsigned char byte;
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0' ||
          !isspace(byte))
        break;
      SSH_PEM_SKIPBYTE(p);
    }
}

static char *ssh_pem_gettoken_iastring(SshPemParser *p)
{
  SshBufferStruct buffer;
  unsigned char byte;
  char *str;

  /* Skip first the whitespace. */
  ssh_pem_skipwhite(p);

  ssh_buffer_init(&buffer);
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0' || !ssh_pem_iachar(byte))
        break;
      if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
        {
          ssh_buffer_uninit(&buffer);
          return NULL;
        }
      SSH_PEM_SKIPBYTE(p);
    }

  /* Create output. */
  byte = 0;
  if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
    {
      ssh_buffer_uninit(&buffer);
      return NULL;
    }
  str = (char *)ssh_buffer_steal(&buffer, NULL);
  ssh_buffer_uninit(&buffer);
  return str;
}

static char *ssh_pem_gettoken_ssh2string(SshPemParser *p)
{
  char *ret = NULL;
  size_t step;

  step = ssh_key_blob_get_string(p->data + p->data_pos,
                                 p->data_len - p->data_pos, &ret);
  if (ret)
    for (; step; step --)
      SSH_PEM_SKIPBYTE(p);
  return ret;
}

static unsigned int ssh_pem_gettoken_number(SshPemParser *p)
{
  SshBufferStruct buffer;
  unsigned char byte;
  char *str;
  unsigned int number;
  size_t len;

  /* Skip first the whitespace. */
  ssh_pem_skipwhite(p);

  ssh_buffer_init(&buffer);
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0' || !isdigit(byte))
        break;

      if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
        {
          ssh_buffer_uninit(&buffer);
          return SSH_PEM_MAXNUMBER;
        }
      SSH_PEM_SKIPBYTE(p);
    }

  /* Create output. */
  byte = 0;
  if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_PEM_MAXNUMBER;
    }
  str = (char *)ssh_buffer_steal(&buffer, &len);
  len--;
  ssh_buffer_uninit(&buffer);

  if (len > 4)
    {
      ssh_free(str);
      /* Too large integer. */
      return SSH_PEM_MAXNUMBER;
    }
  number = strtol(str, NULL, 0);
  ssh_free(str);

  return number;
}

static unsigned char *ssh_pem_gettoken_hex(SshPemParser *p,
                                           size_t *buf_len)
{
  SshBufferStruct buffer;
  unsigned char byte;
  char *str;
  unsigned char *buf;
  size_t len;

  *buf_len = 0;

  /* Skip first the whitespace. */
  ssh_pem_skipwhite(p);

  ssh_buffer_init(&buffer);
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0' || !ssh_is_base16(byte))
        break;

      if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
        {
          ssh_buffer_uninit(&buffer);
          return NULL;
        }
      SSH_PEM_SKIPBYTE(p);
    }

  /* Create output. */
  byte = 0;
  if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
    {
      ssh_buffer_uninit(&buffer);
      return NULL;
    }
  str = (char *)ssh_buffer_steal(&buffer, &len);
  ssh_buffer_uninit(&buffer);

  buf = ssh_base16_to_buf(str, buf_len);
  ssh_free(str);

  return buf;
}

static char ssh_pem_getsep(SshPemParser *p)
{
  unsigned char byte;
  ssh_pem_skipwhite(p);

  SSH_PEM_LOOKUPBYTE(p, 0, byte);

  /* The PEM format has only two separator characters. */
  if (byte == ',' || byte == ':')
    {
      SSH_PEM_SKIPBYTE(p);
      return byte;
    }
  return '\0';
}

static int ssh_pem_skipminus(SshPemParser *p)
{
  unsigned char byte;
  int i;

  for (i = 0; ; i++)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0' || !(isspace(byte) || byte == '-'))
        break;
      SSH_PEM_SKIPBYTE(p);
    }
  return i;
}

static char *ssh_pem_getheader(SshPemParser *p)
{
  unsigned char byte;
  int was_space = 0, i, minus_detected = 0;
  SshBufferStruct buffer;
  char *header = NULL;

  /* Check whether this might actually be the start of the header. */
  i = ssh_pem_skipminus(p);
  if (i < 3)
    return NULL;

  ssh_buffer_init(&buffer);

  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0')
        break;

      if (byte == '-')
        {
          minus_detected++;
          if (minus_detected > 1)
            break;
          goto skipbyte;
        }

      /* Remove duplicated whitespace. */
      if (isspace(byte))
        {
          was_space++;
          goto skipbyte;
        }

      if (byte != '-')
        {
          if (minus_detected)
            {
              if (ssh_buffer_append(&buffer, (unsigned char *)"-", 1)
                  != SSH_BUFFER_OK)
                goto failure;
            }
          minus_detected = 0;
        }

      if (was_space)
        {
          if (ssh_buffer_append(&buffer, (unsigned char *)" ", 1)
              != SSH_BUFFER_OK)
            goto failure;
        }
      was_space = 0;

      if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
        goto failure;

    skipbyte:
      SSH_PEM_SKIPBYTE(p);
    }


  byte = 0;
  if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
    goto failure;
  header = (char *)ssh_buffer_steal(&buffer, NULL);

  /* Check for enough minus signs. */
  i = ssh_pem_skipminus(p);
  if (i < 3)
    {
      ssh_free(header);
      header = NULL;;
    }

 failure:
  ssh_buffer_uninit(&buffer);
  return header;
}

static int ssh_pem_strcasecmp(char *op1, char *op2)
{
  size_t i, len;

  len = strlen(op2);
  if (strlen(op1) < len)
    return -1;
  for (i = 0; i < len; i++)
    if (tolower(((unsigned char *) op1)[i]) !=
        tolower(((unsigned char *) op2)[i]))
      {
        if (tolower(((unsigned char *) op1)[i]) <
            tolower(((unsigned char *) op2)[i]))
          return -1;
        return  1;
      }
  return 0;
}

static SshPemBlob *ssh_pem_getblock(SshPemParser *p)
{
  unsigned char byte;
  char *header;
  char *begin_header, *end_header;
  int   begin_pos = 0, end_pos = 0, begin_num_lines = 0;

  /* Initialize. */
  begin_header = NULL;
  end_header   = NULL;

  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0')
        break;

      if (byte != '-')
        goto skipbyte;

      header = ssh_pem_getheader(p);
      if (header == NULL)
        continue;

      if (begin_header == NULL)
        {
          begin_header = header;
          begin_pos = p->data_pos;
          begin_num_lines = p->data_num_lines;
          continue;
        }
      else
        {
          end_header = header;
          end_pos    = p->data_pos;
          break;
        }

    skipbyte:
      SSH_PEM_SKIPBYTE(p);
    }

  if (begin_header || end_header)
    {
      SshPemBlob *blob;

      if (begin_header == NULL || end_header   == NULL)
        {
        freeheaders:
          ssh_free(begin_header);
          ssh_free(end_header);
          return NULL;
        }

      /* Check that the headers begin correctly. */
      if (ssh_pem_strcasecmp(begin_header, "BEGIN") != 0 &&
          ssh_pem_strcasecmp(end_header, "END") != 0)
        goto freeheaders;

      /* Build the blob. */
      if ((blob = ssh_pem_blob_alloc()) == NULL)
        goto freeheaders;

      blob->begin_header = begin_header;
      blob->end_header   = end_header;
      blob->begin_num_lines = begin_num_lines;

      /* We don't allocate the new data block. */
      blob->block        = &p->data[begin_pos];
      blob->block_len    = end_pos - begin_pos;

      return blob;
    }
  return NULL;
}

static unsigned char *ssh_pem_gettoken_base64(SshPemParser *p,
                                              size_t *buf_len)
{
  SshBufferStruct buffer;
  int end_sign_detected = 0;
  int continuous_whitespace = 0;
  unsigned char byte;
  char *str;
  unsigned char *buf = NULL;
  size_t len;

  *buf_len = 0;

  ssh_buffer_init(&buffer);
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, 0, byte);
      if (byte == '\0')
        break;

      /* Handle the allowed whitespace. */
      if (isspace(byte))
        {
          /* Anything but linefeed is always acceptable. */
          if (byte != '\n')
            goto skipbyte;

          /* Due the structure of the PEM format we should not allow
             too many spaces between base64 blobs.

             Remark. If you are sure that this is not necessary then
             you probably should remove checking of this. At the
             moment of writing this I am a bit depressed by the fact
             that the PEM format is quite "implicit" about the
             relations between the data elements. It is not the format
             of my choice. */
          continuous_whitespace++;
          if (continuous_whitespace == 2)
            break;
          goto skipbyte;
        }
      else
        {
          if (continuous_whitespace)
            {
              unsigned char cbyte;
              unsigned int i;
              /* Lookahead for bad letters. */
              for (i = 0; ; i++)
                {
                  SSH_PEM_LOOKUPBYTE(p, i, cbyte);
                  if (cbyte == '\0' || isspace(cbyte) ||
                      cbyte == '=')
                    break;
                  if (!ssh_is_base64_buf(&cbyte, 1))
                    {
                      goto muststop;
                    }
                }
              /* Next token is not bad. */
            }
          /* Not whitespace. */
          continuous_whitespace = 0;
        }

      if (end_sign_detected)
        {
          /* Stop when last equal sign has been reached. */
          if (byte != '=')
            break;
          end_sign_detected++;

          /* Check whether we have observed too many equal signs. */
          if (end_sign_detected > 2)
            break;
        }
      else
        {
          if (byte == '=')
            end_sign_detected++;
        }

      /* Remark. This may not be the most efficient implementation but
         we don't want to duplicate the tables of the base-64 library.
         Eventually we probably should write a new interface function
         for this. */
      if (!ssh_is_base64_buf(&byte, 1))
        break;

      if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
        goto failure;

    skipbyte:
      SSH_PEM_SKIPBYTE(p);
    }

 muststop:
  /* Create output. */
  byte = 0;
  if (ssh_buffer_append(&buffer, &byte, 1) != SSH_BUFFER_OK)
    goto failure;
  str = (char *)ssh_buffer_steal(&buffer, &len);

  /* Convert from base64 to binary. */
  buf = ssh_base64_to_buf((const unsigned char *)str, buf_len);
  ssh_free(str);

 failure:
  ssh_buffer_uninit(&buffer);
  return buf;
}

static int  ssh_pem_lookupmatch(SshPemParser *p, char *pattern)
{
  int i, len;
  unsigned char byte;

  len = strlen(pattern);

  for (i = 0; i < len; i++)
    {
      SSH_PEM_LOOKUPBYTE(p, i, byte);
      if (tolower(byte) != tolower(((unsigned char *) pattern)[i]))
        break;
    }
  if (i < len)
    return 1;

  /* Check further that the separator ':' follows. */
  while (1)
    {
      SSH_PEM_LOOKUPBYTE(p, i, byte);
      if (byte == '\0')
        break;

      if (!isspace(byte) && byte != ':')
        break;

      if (byte == ':')
        {
          /* Found. */
          len = i+1;
          /* Skip the correct number of bytes. */
          for (i = 0; i < len; i++)
            {
              SSH_PEM_SKIPBYTE(p);
            }
          /* Return success. */
          return 0;
        }
      i++;
    }

  /* Apparently not valid match. */
  return 0;
}

#if 1

/* This is solely for debugging purposes. */
void ssh_pem_arg_dump(FILE *fp, int k, SshPemArg *args)
{
  int i;
  char *str;
  fprintf(fp, "  Args:\n");
  for (i = 0; args[i].type != SSH_PEM_ARG_END; i++)
    {
      int j;
      for (j = 0; j < k; j++)
        fprintf(fp, "  ");
      switch (args[i].type)
        {
        case SSH_PEM_ARG_NUMBER:
          fprintf(fp, "num: %u", args[i].ob.num);
          break;
        case SSH_PEM_ARG_BINARY:
          fprintf(fp, "bin: %lu, ", (unsigned long) args[i].ob.bin.data_len);
          if ((str = ssh_buf_to_base16(args[i].ob.bin.data,
                                       args[i].ob.bin.data_len)) != NULL)
            {
              fprintf(fp, "%s", str);
              ssh_free(str);
            }
          break;
        case SSH_PEM_ARG_SSH2STRING:
        case SSH_PEM_ARG_IASTRING:
          fprintf(fp, "str: %s", args[i].ob.str);
          break;
        case SSH_PEM_ARG_KEYWORD:
          fprintf(fp, "key: %s", args[i].ob.keyword->name);
          break;
        default:
          break;
        }
      fprintf(fp, "\n");
    }
}

void ssh_pem_blob_dump(FILE *fp, SshPemBlob *blob)
{
  SshADTHandle h;
  char *str;

  fprintf(fp, "Blob: \n");
  fprintf(fp, "  Begin = %s\n", blob->begin_header);
  fprintf(fp, "  End   = %s\n", blob->end_header);
  fprintf(fp, "  Line number = %lu\n", (unsigned long) blob->begin_num_lines);
  if (blob->text_len != 0)
    {
      fprintf(fp, "  Text: \n");
      fprintf(fp, "  Len = %lu\n", (unsigned long) blob->text_len);
      fprintf(fp, "  ");
      if ((str = ssh_buf_to_base16(blob->text, blob->text_len)) != NULL)
        {
          fprintf(fp, "%s\n", str);
          ssh_free(str);
        }
    }
  for (h = ssh_adt_enumerate_start(blob->args);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(blob->args, h))
    {
      SshPemArg *args;
      args = ssh_adt_get(blob->args, h);
      ssh_pem_arg_dump(fp, 2, args);
    }
}

void ssh_pem_parser_dump(FILE *fp, SshPemParser *p)
{
  SshADTHandle h;

  fprintf(fp, "BLOB DUMP:\n");
  for (h = ssh_adt_enumerate_start(p->list);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(p->list, h))
    {
      SshPemBlob *blob;
      blob = ssh_adt_get(p->list, h);
      ssh_pem_blob_dump(fp, blob);
    }

  fprintf(fp, "MSG DUMP:\n");
  for (h = ssh_adt_enumerate_start(p->msg);
       h;
       h = ssh_adt_enumerate_next(p->msg, h))
    {
      SshPemArg *args;
      args = ssh_adt_get(p->msg, h);
      ssh_pem_arg_dump(fp, 1, args);
    }
}

#endif

/* Handlers. */

int ssh_pem_proctype_handler(SshPemBlob *blob,
                             SshPemArg *args,
                             unsigned int num_args)
{
  return 0;
}

int ssh_pem_contentdomain_handler(SshPemBlob *blob,
                                  SshPemArg *args,
                                  unsigned int num_args)
{
  return 0;
}

int ssh_pem_dekinfo_handler(SshPemBlob *blob,
                            SshPemArg *args,
                            unsigned int num_args)
{
  return 0;
}

int ssh_pem_origidasym_handler(SshPemBlob *blob,
                               SshPemArg *args,
                               unsigned int num_args)
{
  return 0;
}

int ssh_pem_origidsym_handler(SshPemBlob *blob,
                              SshPemArg *args,
                              unsigned int num_args)
{
  return 0;
}

int ssh_pem_recipidsym_handler(SshPemBlob *blob,
                               SshPemArg *args,
                               unsigned int num_args)
{
  return 0;
}

int ssh_pem_recipidasym_handler(SshPemBlob *blob,
                                SshPemArg *args,
                                unsigned int num_args)
{
  return 0;
}


int ssh_pem_origcert_handler(SshPemBlob *blob,
                             SshPemArg *args,
                             unsigned int num_args)
{
  return 0;
}

int ssh_pem_issuercert_handler(SshPemBlob *blob,
                               SshPemArg *args,
                               unsigned int num_args)
{
  return 0;
}

int ssh_pem_micinfo_handler(SshPemBlob *blob,
                            SshPemArg *args,
                            unsigned int num_args)
{
  return 0;
}

int ssh_pem_keyinfo_handler(SshPemBlob *blob,
                            SshPemArg *args,
                            unsigned int num_args)
{
  return 0;
}

int ssh_pem_subject_handler(SshPemBlob *blob,
                             SshPemArg *args,
                             unsigned int num_args)
{
  return 0;
}

int ssh_pem_comment_handler(SshPemBlob *blob,
                            SshPemArg *args,
                            unsigned int num_args)
{
  return 0;
}

typedef struct
{
  char *name;
  Boolean asym, iv;
  char *cipher_type, *mac_type;
} SshPemAlgs;

static const SshPemAlgs ssh_pem_algs[] =
  {
    { "DES-CBC",  FALSE, TRUE, "des-cbc", "hmac-sha1"  },
    { "DES-EDE3-CBC", FALSE, TRUE, "3des-cbc", "hmac-sha1" },
    { "DES-EDE",  FALSE, FALSE, "3des-ecb", "hmac-sha1" },
    { "DES-ECB",  FALSE, FALSE, "des-ecb", "hmac-sha1" },
    { "RSA",      TRUE,  FALSE, NULL, NULL  },
    { "DSA",      TRUE,  FALSE, NULL, NULL  },
    { "RSA-MD2",  TRUE,  FALSE, NULL, NULL  },
    { "RSA-MD5",  TRUE,  FALSE, NULL, NULL  },
    { "RSA-SHA1", TRUE,  FALSE, NULL, NULL  },
    { NULL }
  };

const SshPemAlgs *ssh_pem_algs_find(SshPemParser *p, char *name)
{
  int i;
  char *tmp_name;

  for (i = 0; ssh_pem_algs[i].name; i++)
    {
      if (!strncmp(ssh_pem_algs[i].name, name, strlen(ssh_pem_algs[i].name)))
        {
          return &ssh_pem_algs[i];
        }
    }
  tmp_name = ssh_strdup(name);
  if (tmp_name == NULL)
    return NULL;

  ssh_pem_msg(p, SSH_PEM_ERROR_UNKNOWN_ALGORITHM,
              SSH_PEM_ARG_IASTRING, tmp_name,
              SSH_PEM_ARG_END);

  ssh_free(tmp_name);
  return NULL;
}

int ssh_pem_argsep(SshPemParser *p, SshPemArg *args)
{
  char sep;

  sep = ssh_pem_getsep(p);
  if (sep != ',')
    {
      const SshPemKeyword *keyword;
      char *keywname;
      if (args[0].type != SSH_PEM_ARG_KEYWORD)
        ssh_fatal("sshcert/ssh_pem_argsep: "
                  "called with invalid argument array.");

      keyword = args[0].ob.keyword;
      keywname = ssh_strdup(keyword->name);
      if (keywname == NULL)
        return 0;
      ssh_pem_msg(p, SSH_PEM_ERROR_MISSING_ARGUMENT,
                  SSH_PEM_ARG_IASTRING,
                  keywname,
                  SSH_PEM_ARG_END);
      ssh_free(keywname);
      return 0;
    }
  return 1;
}


/* Remark. Key-Info is troubling case mainly because its
   argument parsing is depended upon its first argument. So we currently
   have to do it the ugly way.

   Request: Invent something neater so that this can be removed. */
int ssh_pem_keyinfo_parser(SshPemParser *p,
                           SshPemArg *args,
                           unsigned int num_args)
{
  const SshPemAlgs *algs;
  int i;

  if (ssh_pem_argsep(p, args) == 0)
    return -1;

  /* Try to find the algorithm. */
  algs = ssh_pem_algs_find(p, args[num_args-1].ob.str);
  if (algs == NULL)
    return -1;

  i = num_args;
  if (algs->asym)
    {
      if ((args[i].ob.bin.data =
           ssh_pem_gettoken_base64(p, &args[i].ob.bin.data_len))
          != NULL)
        {
          args[i].type = SSH_PEM_ARG_BINARY;
          i++;
        }
    }
  else
    {
      if ((args[i].ob.str = ssh_pem_gettoken_iastring(p)) != NULL)
        {
          args[i].type = SSH_PEM_ARG_IASTRING;
          i++;
        }
      if (ssh_pem_argsep(p, args) == 0)
        return -1;

      if ((args[i].ob.bin.data =
           ssh_pem_gettoken_base64(p, &args[i].ob.bin.data_len)) != NULL)
        {
          args[i].type = SSH_PEM_ARG_BINARY;
          i++;
        }
      if (ssh_pem_argsep(p, args) == 0)
        return -1;

      if ((args[i].ob.bin.data =
           ssh_pem_gettoken_base64(p, &args[i].ob.bin.data_len)) != NULL)
        {
          args[i].type = SSH_PEM_ARG_BINARY;
          i++;
        }
    }
  return i;
}

int ssh_pem_dekinfo_parser(SshPemParser *p,
                           SshPemArg *args,
                           unsigned int num_args)
{
  const SshPemAlgs *algs;
  int i;

  if (ssh_pem_argsep(p, args) == 0)
    return -1;

  algs = ssh_pem_algs_find(p, args[num_args-1].ob.str);
  if (algs == NULL)
    return -1;

  i = num_args;
  if (!algs->iv)
    return-1;

  if ((args[i].ob.bin.data =
       ssh_pem_gettoken_hex(p, &args[i].ob.bin.data_len)) != NULL)
    {
      args[i].type = SSH_PEM_ARG_BINARY;
      i++;
    }

  return i;
}

int ssh_pem_crl_handler(SshPemBlob *blob,
                        SshPemArg *args,
                        unsigned int num_args)
{
  return 0;
}


static const SshPemKeyword ssh_pem_keywords[] =
  {
    { "Proc-Type",
      2, 2, { SSH_PEM_ARG_NUMBER, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_proctype_handler },
    { "X-Proc-Type",
      2, 2, { SSH_PEM_ARG_NUMBER, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_proctype_handler },
    { "Content-Domain",
      1, 1, { SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_contentdomain_handler },
    { "X-Content-Domain",
      1, 1, { SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_contentdomain_handler },
    { "DEK-Info",
      1, 2, { SSH_PEM_ARG_IASTRING, 0 },
      ssh_pem_dekinfo_parser,
      ssh_pem_dekinfo_handler },
    { "X-DEK-Info",
      1, 2, { SSH_PEM_ARG_IASTRING, 0 },
      ssh_pem_dekinfo_parser,
      ssh_pem_dekinfo_handler },
    { "Originator-ID-Asymmetric",
      2, 2, { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_origidasym_handler },
    { "X-Originator-ID-Asymmetric",
      2, 2, { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_origidasym_handler },
    { "Originator-ID-Symmetric",
      2, 3,
      { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_origidsym_handler },
    { "X-Originator-ID-Symmetric",
      2, 3,
      { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_origidsym_handler },
    { "Recipient-ID-Asymmetric",
      2, 2, { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_recipidasym_handler },
    { "X-Recipient-ID-Asymmetric",
      2, 2, { SSH_PEM_ARG_BINARY, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_recipidasym_handler },
    { "Recipient-ID-Symmetric",
      2, 3,
      { SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_recipidsym_handler },
    { "X-Recipient-ID-Symmetric",
      2, 3,
      { SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_recipidsym_handler },
    { "Originator-Certificate",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_origcert_handler },
    { "X-Originator-Certificate",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_origcert_handler },
    { "Issuer-Certificate",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_issuercert_handler },
    { "X-Issuer-Certificate",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_issuercert_handler },
    { "MIC-Info",
      3, 3,
      { SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_micinfo_handler },
    { "X-MIC-Info",
      3, 3,
      { SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_IASTRING, SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_micinfo_handler },
    { "Key-Info",
      1, 4,
      { SSH_PEM_ARG_IASTRING, 0 },
      ssh_pem_keyinfo_parser,
      ssh_pem_keyinfo_handler },
    { "X-Key-Info",
      1, 4,
      { SSH_PEM_ARG_IASTRING, 0 },
      ssh_pem_keyinfo_parser,
      ssh_pem_keyinfo_handler },
    { "CRL",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_crl_handler },
    { "X-CRL",
      1, 1, { SSH_PEM_ARG_BINARY, 0 },
      NULL_FNPTR,
      ssh_pem_crl_handler },

    { "Subject",
      1, 1,
      { SSH_PEM_ARG_IASTRING, 0 },
      NULL_FNPTR,
      ssh_pem_subject_handler },

    { "Comment",
      1, 1,
      { SSH_PEM_ARG_SSH2STRING, 0 },
      NULL_FNPTR,
      ssh_pem_comment_handler },

    { NULL }
  };


static const SshPemKeyword *ssh_pem_parsekeyword(SshPemParser *p)
{
  int i;

  for (i = 0; ssh_pem_keywords[i].name; i++)
    {
      if (ssh_pem_lookupmatch(p, ssh_pem_keywords[i].name) == 0)
        {
          /* Actual match. */
          return &ssh_pem_keywords[i];
        }
    }
  /* No match detected. */
  return NULL;
}

static void ssh_pem_parseblock(SshPemParser *p, SshPemBlob *blob)
{
  while (1)
    {
      const SshPemKeyword *keyword;
      /* We can skip whitespace here. */
      ssh_pem_skipwhite(p);
      /* Check for the keywords. */
      keyword = ssh_pem_parsekeyword(p);
      if (keyword != NULL)
        {
          SshPemArg *args;
          int        max_args, used, num_args;
          int        i, ok;

          /* Parse the arguments according to the keyword hints. */

          max_args = keyword->max_num_args + 2;
          used = 0;
          args = ssh_pem_args_alloc(max_args);

          /* Set the first default argument. */
          args[0].type       = SSH_PEM_ARG_KEYWORD;
          args[0].ob.keyword = keyword;

          /* Move the cursor. */
          used++;

          /* Determine by the existence of specialised parser
             function whether to use the maximum length or minimum
             while at this general code. */
          if (keyword->parser)
            {
              num_args = keyword->min_num_args;
            }
          else
            {
              num_args = keyword->max_num_args;
            }

          for (i = 0; i < num_args; i++)
            {
              if (i > 0)
                {
                  char sep;
                  sep = ssh_pem_getsep(p);

                  if (sep != ',')
                    {
                      char *keywname;
                      if (i >= keyword->min_num_args)
                        break;

                      /* TODO Write a message. */
                      keywname = ssh_strdup(keyword->name);
                      if (keywname == NULL)
                        break;
                      ssh_pem_msg(p, SSH_PEM_ERROR_MISSING_ARGUMENT,
                                  SSH_PEM_ARG_IASTRING,
                                  keywname,
                                  SSH_PEM_ARG_END);

                      ssh_free(keywname);
                      /* Bad mistake! Attempt to recover. */
                      break;
                    }
                }
              /* This is just a guess really, but when it works then the
                 switch case doesn't need to modify it. */
              ok = 1;
              switch (keyword->arg_types[i])
                {
                case SSH_PEM_ARG_NUMBER:
                  args[used].ob.num = ssh_pem_gettoken_number(p);
                  break;
                case SSH_PEM_ARG_BINARY:
                  if ((args[used].ob.bin.data =
                       ssh_pem_gettoken_base64(p,
                                               &args[used].ob.bin.data_len))
                      == NULL)
                    ok = 0;
                  break;
                case SSH_PEM_ARG_IASTRING:
                  if ((args[used].ob.str =
                       ssh_pem_gettoken_iastring(p)) == NULL)
                    ok = 0;
                  break;
                case SSH_PEM_ARG_SSH2STRING:
                  if ((args[used].ob.str =
                       ssh_pem_gettoken_ssh2string(p)) == NULL)
                    ok = 0;
                  break;
                default:
                  ssh_fatal("sshcert/ssh_pem_parseblob: "
                            "invalid argument type at %s.", keyword->name);
                  break;
                }
              if (ok)
                {
                  args[used].type = keyword->arg_types[i];
                  used++;
                }
            }

          if (keyword->parser)
            {
              int rv;
              /* Remark. We should probably check whether to call the
                 callback here. This could be done by considering whether
                 we happened upon an error previously. */
              rv = (*keyword->parser)(p, args, used);
              if (rv > 0)
                used = rv;
            }

          if (used >= max_args)
            {
              ssh_pem_args_free(args);
              break;
            }

          /* Set the terminating argument. */
          args[used].type = SSH_PEM_ARG_END;

          /* Now attempt to throw the read data to the blob as an
             keyword entry. */
          ssh_adt_insert(blob->args, args);

          continue;
        }

      /* Now we apparently have the actual contents. */
      ssh_pem_skipwhite(p);
      blob->text = ssh_pem_gettoken_base64(p, &blob->text_len);
      break;
    }

  /* If blob is available throw it to the list (at the end). */
  if (blob)
    ssh_adt_insert(p->list, blob);
}

static void ssh_pem_parsetext(SshPemParser *p)
{
  while (1)
    {
      SshPemBlob *blob;
      const unsigned char *old_data;
      size_t         old_data_len, old_data_pos, old_num_lines;

      /* Skip all the textual matter, to the actual PEM. */
      blob = ssh_pem_getblock(p);

      /* No blob found. */
      if (blob == NULL)
        break;

      /* Ok. Found a blob. Make it the current parseable object. */
      old_data     = p->data;
      old_data_len = p->data_len;
      old_data_pos = p->data_pos;
      old_num_lines = p->data_num_lines;

      /* Start parsing of the block. */
      p->data      = blob->block;
      p->data_len  = blob->block_len;
      p->data_pos  = 0;
      p->data_num_lines = blob->begin_num_lines;

      /* Delete the block information from the blob. */
      blob->block     = NULL;
      blob->block_len = 0;

      /* Now call the block parser. */
      ssh_pem_parseblock(p, blob);

      /* Retrieve the text position. */
      p->data      = old_data;
      p->data_len  = old_data_len;
      p->data_pos  = old_data_pos;
      p->data_num_lines = old_num_lines;
    }
}

SshPemParser *ssh_pem_parser_alloc(const unsigned char *data, size_t data_len)
{
  SshPemParser *p = ssh_calloc(1, sizeof(*p));

  if (p == NULL)
    return NULL;

  p->data     = data;
  p->data_len = data_len;
  p->data_num_lines = 1;

  /* Allocate the message list. */
  if ((p->msg =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_DESTROY, ssh_pem_args_free_adt,
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_pem_parser_free(p);
      return NULL;
    }
  /* Allocate the PEM blob list. */
  if ((p->list =
       ssh_adt_create_generic(SSH_ADT_LIST,
                              SSH_ADT_DESTROY, ssh_pem_blob_free_adt,
                              SSH_ADT_ARGS_END)) == NULL)
    {
      ssh_pem_parser_free(p);
      return NULL;
    }

  /* Parse the text. */
  ssh_pem_parsetext(p);
  return p;
}

void ssh_pem_parser_free(SshPemParser *p)
{
  if (p->msg) ssh_adt_destroy(p->msg);
  if (p->list) ssh_adt_destroy(p->list);
  ssh_free(p);
}

/* This is the simple interface. */

unsigned char *ssh_ssl_createkey(const char *hash_name,
                                 const unsigned char *salt,
                                 const unsigned char *passwd,
                                 size_t passwd_len,
                                 unsigned int c,
                                 size_t dk_len)
{
  SshHash hash;
  SshBufferStruct t;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned int l, i, hlen;
  unsigned char *tmp = NULL;

  if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
    return NULL;

  /* Calculate the sizes. */
  hlen = ssh_hash_digest_length(hash_name);

  SSH_ASSERT(hlen != 0);

  l = (dk_len + hlen - 1) / hlen;

  ssh_buffer_init(&t);

  for (i = 1; i <= l; i++)
    {
      int j;

      ssh_hash_reset(hash);
      if (i > 1)
        ssh_hash_update(hash, digest, hlen);
      ssh_hash_update(hash, passwd, passwd_len);
      if (salt != NULL)
        ssh_hash_update(hash, salt, 8);
      ssh_hash_final(hash, digest);

      for (j = 1; j < c; j++)
        {
          ssh_hash_reset(hash);
          ssh_hash_update(hash, digest, hlen);
          ssh_hash_final(hash, digest);
        }

      if (ssh_buffer_append(&t, digest, hlen) != SSH_BUFFER_OK)
        goto failure;
    }

  tmp = ssh_buffer_steal(&t, NULL);
 failure:
  ssh_hash_free(hash);
  ssh_buffer_uninit(&t);
  return tmp;
}

unsigned char *ssh_ssl_decode(const char *cipher_name,
                              const char *hash_name,
                              const unsigned char *passwd,
                              size_t passwd_len,
                              const unsigned char *salt,
                              size_t salt_len,
                              unsigned int c,
                              const unsigned char *src,
                              size_t src_len,
                              size_t *ret_len)
{
  unsigned char *dk, *dest;
  SshCipher cipher;
  size_t dk_len;

  if (salt_len != 8)
    return NULL;

  *ret_len = 0;
  dk_len = ssh_cipher_get_key_length(cipher_name);

  dk = ssh_ssl_createkey(hash_name, salt, passwd, passwd_len, c, dk_len);
  if (dk == NULL)
    return NULL;

  if (ssh_cipher_allocate(cipher_name,
                          dk, dk_len, FALSE, &cipher) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      return NULL;
    }

  if (ssh_cipher_get_iv_length(cipher_name) != 8)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  if (ssh_cipher_set_iv(cipher, salt) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  ssh_free(dk);

  dest = ssh_malloc(src_len);
  if (dest)
    {
      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      if (ssh_cipher_transform(cipher, dest, src, src_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
    }
  ssh_cipher_free(cipher);

  *ret_len = src_len;

  /* Return the encrypted data. */
  return dest;
}

unsigned char *ssh_pem_decode_blob(SshPemParser *p,
                                   SshPemBlob *blob,
                                   const unsigned char *key,
                                   size_t key_len,
                                   size_t *ret_len)
{
  SshADTHandle h;
  unsigned char *ret;

  for (h = ssh_adt_enumerate_start(blob->args);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(blob->args, h))
    {
      SshPemArg *args;

      args = ssh_adt_get(blob->args, h);
      if (args[0].type != SSH_PEM_ARG_KEYWORD)
        continue;

      if (strcmp(args[0].ob.keyword->name, "Proc-Type") == 0)
        {
          if (args[1].type != SSH_PEM_ARG_NUMBER ||
              args[2].type != SSH_PEM_ARG_IASTRING)
            return NULL;

          if (args[1].ob.num == 4 &&
              strcmp(args[2].ob.str, "ENCRYPTED") == 0)
            {
              if (key == NULL)
                /* No key present, but should be for encrypted message. */
                return NULL;
            }
          else
            {
              /* Not encrypted, so perhaps directly viewable.

              Remark. This is not very rigorous.
              */
            }
          continue;
        }
      if (strcmp(args[0].ob.keyword->name, "DEK-Info") == 0)
        {
          const SshPemAlgs *algs;

          if (args[1].type != SSH_PEM_ARG_IASTRING ||
              args[2].type != SSH_PEM_ARG_BINARY)
            return NULL;

          if (key == NULL)
            return NULL;

          algs = ssh_pem_algs_find(p, args[1].ob.str);
          if (algs == NULL)
            return NULL;

          if (algs->cipher_type == NULL)
            return NULL;

          ret = ssh_ssl_decode(algs->cipher_type,
                               "md5",
                               key, key_len,
                               args[2].ob.bin.data,
                               args[2].ob.bin.data_len,
                               1,
                               blob->text, blob->text_len,
                               ret_len);
          return ret;
        }
    }

  if (key == NULL && blob->text)
    {
      *ret_len = 0;
      if ((ret = ssh_memdup(blob->text, blob->text_len)) != NULL)
        *ret_len = blob->text_len;
      return ret;
    }

  /* Encrypted PKCS8 keys are dealt with as a special case. */








  if (key && blob->text &&
      (0 == strcmp(blob->begin_header, "BEGIN ENCRYPTED PRIVATE KEY")))
    {
      SshPrivateKey tmpkey;

      if (SSH_X509_OK !=
          ssh_pkcs8_decrypt_private_key(key, key_len,
                                        blob->text, blob->text_len,
                                        &tmpkey))
        return NULL;

      if (SSH_X509_OK !=
          ssh_pkcs8_encode_private_key(tmpkey,
                                       &ret, ret_len))
        {
          ssh_private_key_free(tmpkey);
          return NULL;
        }
      ssh_private_key_free(tmpkey);
      return ret;

    }

  return NULL;
}

unsigned char *ssh_pem_decode_with_key(const unsigned char *data,
                                       size_t data_len,
                                       const unsigned char *key,
                                       size_t key_len,
                                       size_t *ret_len)
{
  SshPemParser *p;
  unsigned char *ret;
  SshADTHandle h;

  ret = NULL;

  p = ssh_pem_parser_alloc(data, data_len);

  for (h = ssh_adt_enumerate_start(p->list);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(p->list, h))
    {
      SshPemBlob *blob;
      blob = ssh_adt_get(p->list, h);

      /* Now do some basic verifications. */
      ret = ssh_pem_decode_blob(p, blob, key, key_len, ret_len);
      if (ret != NULL)
        break;
    }
  ssh_pem_parser_free(p);
  return ret;
}


/* End. */

#endif /* SSHDIST_CERT */
