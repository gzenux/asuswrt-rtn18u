/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encode and decode SSH2 format keyblob.
*/

#include "sshincludes.h"

#ifdef SSHDIST_APPUTIL_KEYUTIL
#include "sshencode.h"
#include "ssh2pubkeyencode.h"
#include "sshbase64.h"
#include "sshmp.h"
#include "sshkeyblob1.h"
#include "sshkeyblob2.h"
#include "sshdsprintf.h"

#define SSH_DEBUG_MODULE "SshUserFiles"

/* List of identifier strings for public key blobs. */
typedef struct Ssh2PkFormatNameListRec
{
  const char *head, *tail;
  unsigned long magic;
} Ssh2PkFormatNameList;

const Ssh2PkFormatNameList ssh2_pk_format_name_list[] =
{
  { "---- BEGIN SSH2 PUBLIC KEY ----",
    "---- END SSH2 PUBLIC KEY ----", SSH_KEY_MAGIC_PUBLIC },
  { "---- BEGIN SSH2 PRIVATE KEY ----",
    "---- END SSH2 PRIVATE KEY ----", SSH_KEY_MAGIC_PRIVATE },
  { "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
    "---- END SSH2 ENCRYPTED PRIVATE KEY ----",
    SSH_KEY_MAGIC_PRIVATE_ENCRYPTED },
  { NULL, NULL, SSH_KEY_MAGIC_FAIL }
};

/* Miscellenous routines for ascii key format handling. */
static unsigned int
ssh_key_blob_match(const unsigned char *buf, size_t buf_size,
                   int type,
                   size_t *ret_start, size_t *ret_end)
{
  char tmp[1024];
  size_t i, j, start, end, keep, tmp_pos;

  /* First check out the possible ssh1 key blobs.
     - ssh1 public key is 3 integers + free form string
     - ssh1 private key has an identifier string.
     - there are no actual nonencrypted ssh1 keys but they
       are encrypted with cipher `none'. */

  /* If it begins with 3-5 ascii-digits + one space, it can't be nothing
     else than ssh1 public key. */
  if ((buf_size > 16) &&
      (((isdigit(buf[0])) &&
        (isdigit(buf[1])) &&
        (isdigit(buf[2])) &&
        (buf[3] == ' ')) ||
       ((isdigit(buf[0])) &&
        (isdigit(buf[1])) &&
        (isdigit(buf[2])) &&
        (isdigit(buf[3])) &&
        (buf[4] == ' ')) ||
       ((isdigit(buf[0])) &&
        (isdigit(buf[1])) &&
        (isdigit(buf[2])) &&
        (isdigit(buf[3])) &&
        (isdigit(buf[4])) &&
        (buf[5] == ' '))))
    {
      *ret_start = 0;
      for (i = 0;
           (i < buf_size) && (buf[i] != '\n') && (buf[i] != '\r');
           i++)
        /*NOTHING*/;
      *ret_end = i + 1;
      return SSH_KEY_MAGIC_SSH1_PUBLIC;
    }

  /* Check ssh1 private key tag followd by nul character and cipher
     identifier byte. */
  if ((buf_size > (strlen(SSH1_PRIVATE_KEY_ID_STRING) + 2)) &&
      (strncmp(SSH1_PRIVATE_KEY_ID_STRING,
               (char *)buf,
               strlen(SSH1_PRIVATE_KEY_ID_STRING)) == 0) &&
      (buf[strlen(SSH1_PRIVATE_KEY_ID_STRING)] == 0))
    {
      *ret_start = 0;
      *ret_end = buf_size;
      if (buf[strlen(SSH1_PRIVATE_KEY_ID_STRING) + 1] == SSH1_CIPHER_NONE)
        return SSH_KEY_MAGIC_SSH1_PRIVATE;
      else
        return SSH_KEY_MAGIC_SSH1_PRIVATE_ENCRYPTED;
    }

  /* Canonical key formats are handled with the format name list. */
  for (i = 0, keep = 0, tmp_pos = 0, start = 0, end = 0; i < buf_size; i++)
    {
      if (buf[i] == '\n')
        {
          tmp[tmp_pos] = '\0';
          end = i;

          /* Try to match against the strings. */
          switch (type)
            {
            case 0:
              for (j = 0; ssh2_pk_format_name_list[j].head; j++)
                {
                  if (strcmp(ssh2_pk_format_name_list[j].head,
                             tmp) == 0)
                    {
                      *ret_start = start;
                      *ret_end   = end;
                      return ssh2_pk_format_name_list[j].magic;
                    }
                }
              break;
            case 1:
              for (j = 0; ssh2_pk_format_name_list[j].tail; j++)
                {
                  if (strcmp(ssh2_pk_format_name_list[j].tail,
                             tmp) == 0)
                    {
                      *ret_start = start;
                      *ret_end   = end;
                      return ssh2_pk_format_name_list[j].magic;
                    }
                }
              break;
            default:
              return SSH_KEY_MAGIC_FAIL;
            }
          tmp_pos = 0;
          start = i + 1;
          keep = 0;
          continue;
        }

      switch (buf[i])
        {
          /* Handle these whitespace values with some care. */
        case '\n':
        case ' ':
        case '\t':
        case '\r':
          if (tmp_pos == 0)
            {
              keep = 0;
              break;
            }
          keep = 1;
          break;
        default:
          if (keep)
            {
              tmp[tmp_pos] = ' ';
              tmp_pos++;
              keep = 0;
            }
          if (tmp_pos >= sizeof(tmp))
            tmp_pos = 0;
          tmp[tmp_pos] = buf[i];
          tmp_pos++;
          break;
        }

      /* Sadly we will now just overlap? */
      if (tmp_pos >= sizeof(tmp))
        tmp_pos = 0;
    }

  return SSH_KEY_MAGIC_FAIL;
}

static size_t
ssh_key_blob_match_keywords(const unsigned char *buf, size_t len,
                            const char *keyword)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      /* Skip whitespace. */
      switch (buf[i])
        {
        case ' ':
        case '\n':
        case '\t':
        case '\r':
          continue;
        default:
          break;
        }

      if (buf[i] == keyword[0])
        {
          if (len - i < strlen(keyword))
            return 0;
          if (memcmp(&buf[i], keyword, strlen(keyword)) == 0)
            return i + strlen(keyword);
        }
      break;
    }
  return 0;
}

/* Handle the quoted string parsing. */
size_t
ssh_key_blob_get_string(const unsigned char *buf, size_t len,
                        char **string)
{
  unsigned int quoting, ret_quoting;
  SshBufferStruct buffer;
  size_t step, i, j;

  ssh_buffer_init(&buffer);
  for (i = 0, step = 0, quoting = 0, ret_quoting = 0; i < len; i++)
    {
      switch (quoting)
        {
        case 0:
          switch (buf[i])
            {
            case ' ':
            case '\n':
            case '\r':
            case '\t':
              /* Skip! */
              break;
            case '\"': /* " */
              quoting = 2;
              ret_quoting = 0;
              break;
            default:
              /* End! */
              step = i;
              goto end;
            }
          break;
        case 1:
          if (buf[i] == '\n')
            {
              for (j = 0; isspace(buf[i + j]) && i + j < len;
                   j++)
                ;
              i = i + j - 1;
            }
          quoting = ret_quoting;
          ret_quoting = 0;
          break;
        case 2:
          switch (buf[i])
            {
            case '\\':
              quoting = 1;
              ret_quoting = 2;
              break;
            case '\"': /* " */
              quoting = 0;
              ret_quoting = 0;
              break;
            default:
              ssh_xbuffer_append(&buffer, &buf[i], 1);
              break;
            }
        }
    }

end:

  /* Make a string. */
  *string = ssh_xmalloc(ssh_buffer_len(&buffer) + 1);
  memcpy(*string, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  (*string)[ssh_buffer_len(&buffer)] = '\0';

  ssh_buffer_uninit(&buffer);

  return step;
}

/* Handle the parsing of the single line string. */
static size_t
ssh_key_blob_get_line(const unsigned char *buf, size_t len,
                      char **string)
{
  size_t i, step, keep;
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);
  for (i = 0, step = 0, keep = 0; i < len; i++)
    {
      switch (buf[i])
        {
        case '\n':
          /* End. */
          step = i;
          goto end;
        case ' ':
        case '\t':
        case '\r':
          if (ssh_buffer_len(&buffer) == 0)
            {
              keep = 0;
              break;
            }
          keep = 1;
          break;
        default:
          if (keep)
            {
              ssh_xbuffer_append(&buffer, (const unsigned char *)" ", 1);
              keep = 0;
            }
          ssh_xbuffer_append(&buffer, &buf[i], 1);
          break;
        }
    }

end:

  /* Make a string. */
  *string = ssh_xmalloc(ssh_buffer_len(&buffer) + 1);
  memcpy(*string, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  (*string)[ssh_buffer_len(&buffer)] = '\0';

  ssh_buffer_uninit(&buffer);

  return step;
}

/* This is not very smart way of doing anything. But should be sufficient
   for the first implementation. */
static size_t
ssh_key_blob_keywords(const unsigned char *buf, size_t len,
                      char **name, char **comment)
{
  size_t total, change;

  /* Initialize. */
  *name    = NULL;
  *comment = NULL;

  for (total = 0, change = 1; change;)
    {
      size_t pos;

      change = 0;
      /* Check for subject. */
      pos = ssh_key_blob_match_keywords(buf + total, len - total,
                                        "Subject:");
      if (pos)
        {
          /* Read the line. */
          total += pos;
          pos = ssh_key_blob_get_line(buf + total, len - total,
                                      name);
          if (pos == 0)
            return total;
          total += pos;

          /* Something changed. */
          change++;
        }

      /* Check for comment. */
      pos = ssh_key_blob_match_keywords(buf + total, len - total,
                                        "Comment:");

      if (pos)
        {
          /* Read the comment string. */
          total += pos;
          pos = ssh_key_blob_get_string(buf + total, len - total,
                                        comment);

          if (pos == 0)
            return total;

          /* Move forward again. */
          total += pos;

          /* Something changed. */
          change++;
        }
    }
  return total;
}


/* Decoding of the SSH2 ascii key blob format. */
unsigned long
ssh2_key_blob_decode(unsigned char *data, size_t len,
                     Boolean try_convert_ssh1_cert,
                     char **subject,
                     char **comment,
                     unsigned char **blob, size_t *bloblen)
{
  unsigned char *tmp, *whitened;
  char *my_name, *my_comment;
  size_t step, start, end, start2, end2;
  unsigned long magic, magic2;

  /* Match first the heading. */
  magic = ssh_key_blob_match(data, len,
                             0, /* head */
                             &start, &end);


  if (magic == SSH_KEY_MAGIC_FAIL)
    goto fail;

  /* Match then the tail. */
  magic2 = ssh_key_blob_match(data, len,
                              1, /* tail */
                              &start2, &end2);

  if (magic2 != magic)
    goto fail;

  if ((magic != SSH_KEY_MAGIC_SSH1_PUBLIC) &&
      (magic != SSH_KEY_MAGIC_SSH1_PRIVATE) &&
      (magic != SSH_KEY_MAGIC_SSH1_PRIVATE_ENCRYPTED))
    {
      /* Check. */
      if (len - end == 0)
        goto fail;

      /* Read the keywords. */
      step = ssh_key_blob_keywords(data + end + 1, len - end - 1,
                                   &my_name, &my_comment);

      /* If name is available pass it up. */
      if (subject)
        *subject = my_name;
      else
        ssh_xfree(my_name);

      /* If comment is available pass it up. */
      if (comment)
        *comment = my_comment;
      else
        ssh_xfree(my_comment);

      /* Convert the remainder to a string. */
      tmp = ssh_xmalloc(start2 - end - step);
      memcpy(tmp, data + end + 1 + step, start2 - end - step - 1);

      /* Remove whitespace. */
      whitened = ssh_base64_remove_whitespace(tmp, start2 - end - step - 1);
      ssh_xfree(tmp);

      /* Decode the base64 blob. */
      if (whitened != NULL)
        *blob = ssh_base64_to_buf(whitened, bloblen);
      else
        *blob = NULL;
      ssh_xfree(whitened);
      ssh_xfree(data);
    }
#ifdef SSHDIST_APPUTIL_SSH1ENCODE
  else if ((magic == SSH_KEY_MAGIC_SSH1_PUBLIC) &&
           (try_convert_ssh1_cert != FALSE))
    {
      SshPublicKey tmpkey;
      unsigned char *tmpblob;
      size_t tmpbloblen;

      if (ssh1_decode_pubkeyblob(data, len, &my_comment, &tmpkey)
          == SSH_CRYPTO_OK)
        {
          tmpbloblen = ssh_encode_pubkeyblob(tmpkey, &tmpblob);
          ssh_public_key_free(tmpkey);
          if (tmpbloblen > 0)
            {
              ssh_xfree(data);
              data = tmpblob;
              len = tmpbloblen;
              magic = SSH_KEY_MAGIC_PUBLIC;
              SSH_DEBUG(5, ("converted ssh1 pubkey to ssh2 certs"));
            }
          else
            {
              ssh_xfree(my_comment);
              if (tmpblob != NULL)
                ssh_free(tmpblob);
              tmpblob = NULL;
              goto fail;
            }
        }
      else
        {
          goto fail;
        }
      if (comment)
        *comment = my_comment;
      else
        ssh_xfree(my_comment);
      *blob = data;
      if (bloblen)
        *bloblen = len;
    }
  else if (magic == SSH_KEY_MAGIC_SSH1_PUBLIC)
    {
      SshPublicKey tmpkey;
      unsigned char *tmpblob;
      size_t tmpbloblen;

      if (ssh1_decode_pubkeyblob(data, len, &my_comment, &tmpkey)
          == SSH_CRYPTO_OK)
        {
          size_t l;
          SshMPIntegerStruct e, n;
          char *estr, *nstr;

          ssh_mprz_init(&e);
          ssh_mprz_init(&n);
          if (ssh_public_key_get_info(tmpkey,
                                      SSH_PKF_MODULO_N, &n,
                                      SSH_PKF_PUBLIC_E, &e,
                                      SSH_PKF_END) == SSH_CRYPTO_OK)
            {
              ssh_public_key_free(tmpkey);
              l = ssh_mprz_get_size(&n, 2);
              estr = ssh_mprz_get_str(&e, 10);
              nstr = ssh_mprz_get_str(&n, 10);
              ssh_mprz_clear(&e);
              ssh_mprz_clear(&n);
              tmpbloblen = ssh_xdsprintf(&tmpblob,
                                         "%u %s %s -",
                                         (unsigned int)l,
                                         estr,
                                         nstr);
              ssh_xfree(estr);
              ssh_xfree(nstr);
            }
          else
            {
              ssh_public_key_free(tmpkey);
              ssh_mprz_clear(&e);
              ssh_mprz_clear(&n);
              ssh_xfree(my_comment);
              goto fail;
            }
          data = tmpblob;
          len = tmpbloblen;
        }
      else
        {
          goto fail;
        }
      if (comment)
        *comment = my_comment;
      else
        ssh_xfree(my_comment);
      *blob = data;
      if (bloblen)
        *bloblen = len;
    }
#endif /* SSHDIST_APPUTIL_SSH1ENCODE */
  else
    {
      /* If it's an ssh1 private key we just push entire blob up. */
      *blob = data;
      if (bloblen)
        *bloblen = len;
    }
  SSH_DEBUG(5, ("key blob magic = 0x%08lx", magic));
  return magic;

fail:
  ssh_xfree(data);
  return SSH_KEY_MAGIC_FAIL;
}


/* Encoding of the SSH2 ascii key blob format. The format is
   as follows:

   ---- BEGIN SSH2 PUBLIC KEY ----
   Subject: login-name
   Comment: "Some explanatorial message."
   Base64 encoded blob.... =
   ---- END SSH2 PUBLIC KEY  ----

   */

void ssh_key_blob_dump_quoted_str(SshBuffer buffer, size_t indend,
                                  const char *buf)
{
  size_t pos = indend;
  size_t i, buf_len = strlen(buf);
  ssh_xbuffer_append(buffer, (const unsigned char *)"\"", 1);
  pos++;

  for (i = 0; i < buf_len; i++)
    {
      if (pos > 0 && (pos % 70) == 0)
        {
          ssh_xbuffer_append(buffer, (const unsigned char *)"\\\n", 2);
          pos = 0;
        }
      ssh_xbuffer_append(buffer, (const unsigned char *)&buf[i], 1);
      pos++;
    }
  ssh_xbuffer_append(buffer, (const unsigned char *)"\"", 1);
}

void ssh_key_blob_dump_line_str(SshBuffer buffer, const char *str)
{
  ssh_xbuffer_append(buffer, (const unsigned char *)str, strlen(str));
}

void ssh_key_blob_dump_str(SshBuffer buffer, const char *str)
{
  size_t pos;
  size_t i, str_len = strlen(str);
  for (i = 0, pos = 0; i < str_len; i++)
    {
      if (pos > 0 && (pos % 70) == 0)
        {
          ssh_xbuffer_append(buffer, (const unsigned char *)"\n", 1);
          pos = 0;
        }
      ssh_xbuffer_append(buffer, (const unsigned char *)&str[i], 1);
      pos++;
    }
}

void ssh_key_blob_dump_lf(SshBuffer buffer)
{
  ssh_xbuffer_append(buffer, (const unsigned char *)"\n", 1);
}

Boolean
ssh2_key_blob_encode(unsigned long magic,
                     const char *subject, const char *comment,
                     const unsigned char *key, size_t keylen,
                     unsigned char **encoded, size_t *encoded_len)
{
  SshBufferStruct buffer;
  char *base64;
  unsigned int key_index;

  /* Translate to index. */
  switch (magic)
    {
    case SSH_KEY_MAGIC_PUBLIC:            key_index = 0; break;
    case SSH_KEY_MAGIC_PRIVATE:           key_index = 1; break;
    case SSH_KEY_MAGIC_PRIVATE_ENCRYPTED: key_index = 2; break;
    default:                                             return FALSE;
    }

  base64 = (char *)ssh_buf_to_base64(key, keylen);
  if (base64 == NULL)
    {
      return FALSE;
    }

  ssh_buffer_init(&buffer);

  /* Add the head for the key. */
  ssh_key_blob_dump_line_str(&buffer,
                             ssh2_pk_format_name_list[key_index].head);
  ssh_key_blob_dump_lf(&buffer);

  /* Handle key words. */
  if (subject)
    {
      ssh_key_blob_dump_line_str(&buffer, "Subject: ");
      ssh_key_blob_dump_line_str(&buffer, subject);
      ssh_key_blob_dump_lf(&buffer);
    }

  if (comment)
    {
      ssh_key_blob_dump_line_str(&buffer, "Comment: ");
      ssh_key_blob_dump_quoted_str(&buffer, 9, comment);
      ssh_key_blob_dump_lf(&buffer);
    }

  /* Now add the base64 formatted stuff. */
  ssh_key_blob_dump_str(&buffer, base64);
  ssh_key_blob_dump_lf(&buffer);
  ssh_xfree(base64);

  /* Add the tail for the key. */
  ssh_key_blob_dump_line_str(&buffer,
                             ssh2_pk_format_name_list[key_index].tail);
  ssh_key_blob_dump_lf(&buffer);

  *encoded_len = ssh_buffer_len(&buffer);
  *encoded = ssh_xmemdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
  ssh_buffer_uninit(&buffer);
  return TRUE;
}
#endif /* SSHDIST_APPUTIL_KEYUTIL */
