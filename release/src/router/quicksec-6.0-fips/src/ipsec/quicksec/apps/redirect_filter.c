/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sample filtering for IKE redirect authetication phase.
*/

#include <string.h>

#include "sshincludes.h"
#include "quicksecpm_xmlconf_i.h"

#ifdef SSHDIST_IKE_REDIRECT

#define SSH_DEBUG_MODULE "SshRedirectFilter"
#define FILTER_FILE "redirect.txt"

#ifndef SSH_PM_IS_HEX
#define SSH_PM_IS_HEX(ch)               \
(('0' <= (ch) && (ch) <= '9')           \
 || ('a' <= (ch) && (ch) <= 'f')        \
 || ('A' <= (ch) && (ch) <= 'F'))
#endif /* SSH_PM_IS_HEX */

#ifndef SSH_PM_HEX_TO_INT
#define SSH_PM_HEX_TO_INT(ch)   \
('0' <= (ch) && (ch) <= '9'     \
 ? (ch) - '0'                   \
 : ('a' <= (ch) && (ch) <= 'f'  \
    ? (ch) - 'a' + 10           \
    : (ch) - 'A' + 10))
#endif /* SSH_PM_HEX_TO_INT */


static unsigned char* decode_hex2bin(const unsigned char *src, size_t src_len,
                                     size_t *dst_len)
{
  unsigned char *dst = NULL;
  size_t i;
  *dst_len = src_len / 2;
  unsigned char temp;

  dst = ssh_malloc(*dst_len);
  if (dst == NULL)
    return NULL;

  for (i = 0; i < *dst_len; i++)
    {
      if (!SSH_PM_IS_HEX(src[0]) || !SSH_PM_IS_HEX(src[1]))
        {
          ssh_free(dst);
          return NULL;
        }
      temp = SSH_PM_HEX_TO_INT(src[0]);
      temp <<= 4;
      temp += SSH_PM_HEX_TO_INT(src[1]);
      dst[i] = temp;

      i++;
      src += 2;
    }

  return dst;
}


static char* client_redirected(unsigned char *client_id, size_t client_id_len)
{
  char *line;
  unsigned char *buf = NULL, *parse_buf = NULL;
  char *temp = NULL, *ret = NULL;
  size_t len = 0;
  size_t buf_len, cid_len = 0;;
  char *save_buf = NULL, *save_line = NULL; /* save pointers for parsing */
  SshPmSecretEncoding encoding = SSH_PM_ENCODING_UNKNOWN;
  Boolean multi_encoding = FALSE;
  unsigned char *cid = NULL;      /* client id from file */


  if (ssh_read_file(FILTER_FILE, &buf, &buf_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to read file: '%s'", FILTER_FILE));
      goto error;
    }
  buf[buf_len - 1] = '\0';
  parse_buf = buf;

  /* the file contains IKE IDs type, IKE IDs and redirect IPs separated by
   * space with the IKE ID in quotes e.g.:
   * email "a@ipsec.com" 192.168.0.2
   * IKE ID's encoded in hes must start with '0x' */

  while ( (line = strtok_r(parse_buf, "\n", &save_buf)) )
    {
      parse_buf = NULL; /* for strok_r() */
      cid_len = 0;
      encoding = SSH_PM_ENCODING_UNKNOWN;
      multi_encoding = FALSE;
      temp = strtok_r(line, " ", &save_line);

      if (temp ==  NULL)  /* no tokens */
        continue;

      if (*temp == '#')  /* comment line */
        continue;

      /* check id types */
      if (strncmp("key-id", temp, 6) == 0)
        {
          encoding = SSH_PM_HEX;
        }
      else if (strncmp("dn", temp, 2) == 0)
        {
          multi_encoding = TRUE;
        }
      else if (strncmp("email", temp, 5)  != 0 &&
               strncmp("fqdn", temp, 4)   != 0 &&
               strncmp("ip", temp, 2)     != 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("IKE ID type '%s' unsupported", temp));
          continue;
        }

      /* client id */
      temp = strtok_r(NULL, "\"", &save_line);
      if (temp ==  NULL)  /* no tokens */
        {
          SSH_DEBUG(SSH_D_ERROR, ("Line missing client ID"));
          continue;
        }
      if (multi_encoding == TRUE)
        {
          if (temp[0] == '0' && (temp[1] == 'x'))
            encoding = SSH_PM_HEX;
        }

      len = strlen(temp);
      if (encoding == SSH_PM_HEX)
        {
          cid = decode_hex2bin(temp + 2, len - 2, &cid_len);
          if (cid == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Bad key-id %s", temp));
              cid_len = 0;
              break;
            }
        }
      else
        {
          cid = temp;
        }

      if (memcmp(client_id, cid, client_id_len) == 0)
        {
          /* found a match - get the redirect IP */
          temp = strtok_r(NULL, " ", &save_line);

          if (temp == NULL)  /* no redirect ip */
            {
              SSH_DEBUG(SSH_D_ERROR,
                       ("Missing redirect IP for client ID %s", client_id));
              break;
            }

          SSH_DEBUG(SSH_D_NICETOKNOW, ("redirecting '%s' to: %s",
                                      client_id, temp));
          ret = ssh_strdup(temp);
          break;
        }

      if (cid_len)
        {
          ssh_free(cid);
          cid_len = 0;
        }
    }

error:
  if (buf)
    ssh_free(buf);
  if (cid_len)
    ssh_free(cid);
  return ret;
}

void
ssh_ike_redirect_decision_cb(unsigned char *client_id,
                             size_t client_id_len,
                             SshPmIkeRedirectResultCB result_cb,
                             void *result_cb_context,
                             void *context)
{
  char* redirect_addr = NULL;

  redirect_addr = client_redirected(client_id, client_id_len);

  if (redirect_addr != NULL)
    {
      (result_cb) (redirect_addr, result_cb_context);
      ssh_free(redirect_addr);
    }
  else
    {
      (result_cb) (NULL, result_cb_context);
    }
}

#endif /* SSHDIST_IKE_REDIRECT */
