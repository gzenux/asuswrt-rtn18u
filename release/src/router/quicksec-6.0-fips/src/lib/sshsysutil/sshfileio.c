/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Read and write file from and to the disk in various formats.
*/

#include "sshincludes.h"
#include "sshfileio.h"
#include "sshbase64.h"

#define FILEBUF_SIZE 1024

/* Check for the max size */
#define SSH_FILEIO_CHECK_MAX_SIZE                                             \
do {                                                                          \
  if (size_limit && size_limit < offset)                                      \
    {                                                                         \
      SSH_DEBUG(SSH_D_FAIL, ("File '%s': Size limit (%zd) exceeded (%zd)",    \
                             file_name, (size_t) size_limit, offset));        \
      goto failed;                                                            \
    }                                                                         \
} while (0)

#define SSH_DEBUG_MODULE "SshUtilFile"

/* Read binary file from the disk giving a size limit for the
   file. Return mallocated buffer and the size of the buffer. If the
   reading of file failes return FALSE. If the file name is NULL or
   "-" then read from the stdin. The size_limit is in bytes. If zero
   is used, the read file will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned.  */
Boolean ssh_read_file_with_limit(const char *file_name,
                                 SshUInt32 size_limit,
                                 unsigned char **buf,
                                 size_t *buf_len)
{
  FILE *fp = NULL;
  unsigned char *iobuf = NULL, *tmp;
  size_t len, plen, growth, t, offset, ret;

#ifdef WINDOWS
  WCHAR *file = NULL;
  DWORD name_len;
#endif /* WINDOWS */

  /* Read the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    {
      fp = stdin;
      file_name = NULL;
    }
  else

#ifdef WINDOWS
    {
      if ((name_len = MultiByteToWideChar(CP_UTF8, 0,
                                          file_name, -1, NULL, 0)) == 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Multibyte conversion failed"));
          goto failed;
        }
      if (!(file = ssh_malloc((name_len) * sizeof *file)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("allocation failed for file name"));
          goto failed;
        }
      if ((MultiByteToWideChar(CP_UTF8, 0, file_name, -1,
                                       file, name_len)) == 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Multibyte conversion failed"));
          goto failed;
        }

      fp = _wfopen(file, L"rb");
    }
#else /* WINDOWS */
    fp = fopen(file_name, "rb");
#endif /* WINDOWS */

  if (fp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Can't open file for reading: %s", file_name));
      goto failed;
    }

  offset = 0;
  growth = len = plen = FILEBUF_SIZE;
  if ((iobuf = ssh_malloc(len)) == NULL)
    goto failed;

  /* Read the file */
  while ((ret = fread(iobuf + offset, 1, growth, fp)) == growth)
    {
      offset += growth;
      SSH_FILEIO_CHECK_MAX_SIZE;

      /* Fibonacci series on buffer size growth */
      t = len;
      len += plen;
      growth = plen;
      plen = t;

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Growing input buffer from %zd to %zd bytes",
                 plen, len));
      if ((tmp = ssh_realloc(iobuf, plen, len)) == NULL)
        goto failed;
      iobuf = tmp;
    }

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Last read from file %zd bytes to offset %zd, total %zd bytes.",
             ret, offset, ret+offset));

  if (ferror(fp))
    goto failed;

  offset += ret;
  SSH_FILEIO_CHECK_MAX_SIZE;

#ifdef WINDOWS
  if (file)
    {
      fclose(fp);
      ssh_free(file);
    }
#else /* WINDOWS */

  if (file_name)
    fclose(fp);
#endif /* WINDOWS */

  *buf = iobuf;
  *buf_len = offset;
  return TRUE;

 failed:

#ifdef WINDOWS
  if (file)
    ssh_free(file);
#endif /* WINDOWS */

  if (file_name && fp)
    fclose(fp);

  if (iobuf)
    ssh_free(iobuf);

  return FALSE;
}


/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
Boolean ssh_read_file(const char *file_name,
                      unsigned char **buf,
                      size_t *buf_len)
{
  return ssh_read_file_with_limit(file_name, SSH_READ_FILE_NO_LIMIT,
                                  buf, buf_len);
}

/* Read base 64 encoded file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_file_base64_with_limit(const char *file_name,
                                        SshUInt32 size_limit,
                                        unsigned char **buf,
                                        size_t *buf_len)
{
  unsigned char *tmp, *cp;
  size_t len, start, end;

  if (!ssh_read_file_with_limit(file_name, size_limit, &tmp, &len))
    return FALSE;

  if (ssh_base64_remove_headers(tmp, len, &start, &end) == FALSE)
    {
      ssh_free(tmp);
      return FALSE;
    }

  cp = ssh_base64_remove_whitespace(tmp + start, end - start);
  if (cp == NULL)
    {
      ssh_free(tmp);
      return FALSE;
    }
  *buf = ssh_base64_to_buf(cp, &len);
  *buf_len = len;

  ssh_free(cp);
  ssh_free(tmp);
  return TRUE;
}


/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_base64(const char *file_name, unsigned char **buf,
                             size_t *buf_len)
{
  return ssh_read_file_base64_with_limit(file_name, SSH_READ_FILE_NO_LIMIT,
                                         buf, buf_len);
}


/* Read hexl encoded file from the disk. Return mallocated buffer and
   the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_file_hexl_with_limit(const char *file_name,
                                      SshUInt32 size_limit,
                                      unsigned char **buf,
                                      size_t *buf_len)
{
  unsigned char *tmp, *p, *q;
  size_t len, i = 0;
  int state, l = 0;

  if (!ssh_read_file_with_limit(file_name, size_limit, &tmp, &len))
    return FALSE;

  *buf_len = 0;
  if ((*buf = ssh_malloc(len + 1)) == NULL)
    {
      ssh_free(tmp);
      return FALSE;
    }

  for (state = 0, p = *buf, q = tmp; len > 0; len--, q++)
    {
      if (state == 0)
        {
          i = 0;
          l = 0;
          if (*q == ':')
            state++;
          continue;
        }
      if (state == 1)
        {
          if (isxdigit(*q))
            {
              if (isdigit(*q))
                l = (l << 4) | (*q - '0');
              else
                l = (l << 4) | (tolower(*q) - 'a' + 10);
              i++;
              if ((i & 1) == 0)
                {
                  *p++ = l;
                  (*buf_len)++;
                  l = 0;
                }
              if (i == 32)
                state++;
            }
          else
            if (q[0] == ' ' && q[1] == ' ')
              state++;
          continue;
        }
      if (*q == '\n' || *q == '\r')
        state = 0;
    }

  ssh_free(tmp);
  return TRUE;
}


/* Read hexl encoded file from the disk. Return mallocated buffer and the size
   of the buffer. If the reading of file failes return FALSE. If the file name
   is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_hexl(const char *file_name, unsigned char **buf,
                           size_t *buf_len)
{
  return ssh_read_file_hexl_with_limit(file_name, SSH_READ_FILE_NO_LIMIT,
                                       buf, buf_len);
}

/* Read pem/hexl/binary file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name starts with :p: then assume file is pem
   encoded, if it starts with :h: then it is assumed to be hexl
   format, and if it starts with :b: then it is assumed to be
   binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning
   message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdin (":p:-" == stdin in pem encoded
   format). The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_gen_file_with_limit(const char *file_name,
                                     SshUInt32 size_limit,
                                     unsigned char **buf,
                                     size_t *buf_len)
{
  if (strlen(file_name) < 3 || file_name[0] != ':' || file_name[2] != ':')
    return ssh_read_file_with_limit(file_name, size_limit, buf, buf_len);
  if (file_name[1] == 'b')
    return ssh_read_file_with_limit(file_name + 3, size_limit, buf, buf_len);
  if (file_name[1] == 'p')
    return ssh_read_file_base64_with_limit(file_name + 3, size_limit,
                                           buf, buf_len);
  if (file_name[1] == 'h')
    return ssh_read_file_hexl_with_limit(file_name + 3, size_limit,
                                         buf, buf_len);
  ssh_warning("Unknown file format given to ssh_read_gen_file");
  return FALSE;
}

/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then read from
   the stdin (":p:-" == stdin in pem encoded format). */
Boolean ssh_read_gen_file(const char *file_name,
                          unsigned char **buf,
                          size_t *buf_len)
{
  return ssh_read_gen_file_with_limit(file_name, SSH_READ_FILE_NO_LIMIT,
                                      buf, buf_len);
}


/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
Boolean ssh_write_file(const char *file_name,
                       const unsigned char *buf,
                       size_t buf_len)
{
  FILE *fp;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    {
      fp = stdout;
      file_name = NULL;
    }
  else
    fp = fopen(file_name, "wb");

  if (fp == NULL)
    return FALSE;

  if (fwrite(buf, 1, buf_len, fp) != buf_len)
    {
      if (file_name)
        fclose(fp);
      return FALSE;
    }
  if (file_name)
    fclose(fp);
  return TRUE;
}

/* Write base 64 encoded file to the disk. If the write fails retuns FALSE. If
   the file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_base64(const char *file_name,
                              const char *begin,
                              const char *end,
                              const unsigned char *buf,
                              size_t buf_len)
{
  FILE *fp;
  char *tmp = NULL;
  size_t len, i;

  tmp = (char *) ssh_buf_to_base64(buf, buf_len);
  if (tmp == NULL)
    return FALSE;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    {
      fp = stdout;
      file_name = NULL;
    }
  else
    fp = fopen(file_name, "w");

  if (fp == NULL)
    {
      ssh_free(tmp);
      return FALSE;
    }

  if (begin)
    if (fprintf(fp, "%s\n", begin) < 0)
      goto error;

  len = strlen(tmp);
  for (i = 0; i + 64 < len; i += 64)
    {
      if (fwrite(tmp + i, 1, 64, fp) != 64 || fprintf(fp, "\n") < 0)
        goto error;
    }
  if (fwrite(tmp + i, 1, len - i, fp) != (len - i))
    goto error;

  if (end)
    if (fprintf(fp, "\n%s\n", end) < 0)
      goto error;
  if (file_name)
    fclose(fp);
  ssh_free(tmp);
  return TRUE;

 error:
  if (file_name)
    fclose(fp);
  ssh_free(tmp);
  return FALSE;
}

/* Write hexl encoded file to the disk. If the write fails retuns FALSE. If the
   file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_hexl(const char *file_name,
                            const unsigned char *buf,
                            size_t buf_len)
{
  FILE *fp;
  size_t i, j;

  /* Write the file */
  if (file_name == NULL || strcmp(file_name, "-") == 0)
    {
      fp = stdout;
      file_name = NULL;
    }
  else
    fp = fopen(file_name, "w");

  if (fp == NULL)
    return FALSE;

  for (i = 0; i < buf_len; i += 16)
    {
      if (fprintf(fp, "%08lx: ", (unsigned long)i) < 0)
        goto error;
      for (j = 0; j < 16; j++)
        {
          if (i + j < buf_len)
            {
              if (fprintf(fp, "%02x", (unsigned int)buf[i + j]) < 0)
                goto error;
            }
          else
            {
              if (fprintf(fp, "  ") < 0)
                goto error;
            }
          if ((j % 2) == 1)
            {
              if (fprintf(fp, " ") < 0)
                goto error;
            }
        }
      if (fprintf(fp, " ") < 0)
        goto error;

      for (j = 0; j < 16; j++)
        {
          if (i + j < buf_len)
            {
              if (isprint(buf[i + j]))
                {
                  if (fprintf(fp, "%c", buf[i + j]) < 0)
                    goto error;
                }
              else
                {
                  if (fprintf(fp, ".") < 0)
                    goto error;
                }
            }
          else
            {
              if (fprintf(fp, " ") < 0)
                goto error;
            }
        }
      if (fprintf(fp, "\n") < 0)
        goto error;
    }

  if (file_name)
    fclose(fp);
  return TRUE;
error:
  if (file_name)
    fclose(fp);
  return FALSE;
}

/* Write pem/hexl/binary file from the disk. If the write fails retuns FALSE.
   If the file name starts with :p: then assume file is pem encoded, if it
   starts with :h: then it is assumed to be hexl format, and if it starts with
   :b: then it is assumed to be binary. If no :[bph]: is given then file is
   assumed to be binary. If any other letter is given between colons then
   warning message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdout (":p:-" == stdout in pem encoded format). */
Boolean ssh_write_gen_file(const char *file_name,
                           const char *begin,
                           const char *end,
                           const unsigned char *buf,
                           size_t buf_len)
{
  if (strlen(file_name) < 3 || file_name[0] != ':' || file_name[2] != ':')
    return ssh_write_file(file_name, buf, buf_len);
  if (file_name[1] == 'b')
    return ssh_write_file(file_name + 3, buf, buf_len);
  if (file_name[1] == 'p')
    return ssh_write_file_base64(file_name + 3, begin, end, buf, buf_len);
  if (file_name[1] == 'h')
    return ssh_write_file_hexl(file_name + 3, buf, buf_len);
  ssh_warning("Unknown file format given to ssh_read_gen_file");
  return FALSE;
}
