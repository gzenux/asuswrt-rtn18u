/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Distinguished name LDAP string encoding and decoding.
*/

#include "sshincludes.h"

#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshasn1.h"
#include "x509.h"
#include "dn.h"
#include "oid.h"
#include "sshstr.h"

#include <ctype.h>

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertDNLdap"

/* Thing that simplifies things a lot. */
char *ssh_buffer_to_str(SshBuffer buffer, size_t *len)
{
  char *str;

  *len = ssh_buffer_len(buffer);
  str = ssh_memdup(ssh_buffer_ptr(buffer), *len);
  return str;
}

/* This encodes the DN according to LDAP encoding rules. */
int
ssh_dn_encode_ldap_cs(SshDN dn, SshCharset cs, char **ldap_dn)
{
  char hextable[16] = "0123456789abcdef";
  SshBufferStruct buffer;
  SshRDN temp;
  const SshOidStruct *table_oid;
  unsigned char *temp_str;
  size_t temp_str_length;
  int i, j;
  size_t len;
  SshStr converted;
  Boolean visible = FALSE;
  SshBufferStatus rv;

  ssh_buffer_init(&buffer);

  for (i = 0; i < dn->rdn_count; i++)
    {
      for (temp = dn->rdn[i]; temp; temp = temp->next)
        {
          /* Try to find the human readable version of the data. If
             found, mark is as type, else print in the standard
             OID.x.x.x. format.*/

          if ((table_oid =
               ssh_oid_find_by_oid_of_type(temp->oid, SSH_OID_DN)) != NULL)
            rv = ssh_buffer_append_cstrs(&buffer, table_oid->std_name, NULL);
          else if ((table_oid =
                    ssh_oid_find_by_oid_of_type(temp->oid, SSH_OID_UCL))
                   != NULL)
            rv = ssh_buffer_append_cstrs(&buffer, table_oid->std_name, NULL);
          else if ((table_oid =
                    ssh_oid_find_by_oid_of_type(temp->oid,
                                                SSH_OID_DIRECTORYATTR)) !=
                    NULL)
            rv = ssh_buffer_append_cstrs(&buffer, table_oid->std_name, NULL);
          else
            rv = ssh_buffer_append_cstrs(&buffer, "OID.", temp->oid, NULL);

          if (rv != SSH_BUFFER_OK)
            {
            failed:
              ssh_buffer_uninit(&buffer);
              *ldap_dn = NULL;
              return 0;
            }

          /* Add the separator. */
          if (ssh_buffer_append(&buffer, (const unsigned char *) "=", 1)
              != SSH_BUFFER_OK)
            goto failed;

          if (temp->c)
            {
              /* Check if the string can be represented in a suitable
                 visible string format. If not then dump it in
                 UTF-8. */
              visible = TRUE;
              converted = ssh_str_charset_convert(temp->c, cs);
              if (converted == NULL)
                {
                  if (cs != SSH_CHARSET_UTF8 &&
                      (converted = ssh_str_charset_convert(temp->c,
                                                           SSH_CHARSET_UTF8))
                      != NULL)
                    visible = FALSE;

                  if (converted == NULL)
                    {
                      /* Return with an error. */
                      ssh_buffer_uninit(&buffer);
                      *ldap_dn = NULL;
                      return 0;
                    }
                }
              temp_str = ssh_str_get(converted, &temp_str_length);

              /* Free the string used in the conversion. */
              ssh_str_free(converted);
            }
          else
            {
              temp_str = ssh_strdup("");
              temp_str_length = 0;
            }

          if (visible == FALSE)
            {
              /* Conversion to hexadecimal. */
              if (ssh_buffer_append(&buffer, (unsigned char *) "#", 1))
                {
                  ssh_free(temp_str);
                  goto failed;
                }

              for (j = 0; j < temp_str_length; j++)
                {
                  if (ssh_buffer_append(&buffer,
                                        (unsigned char *)
                                        &hextable[(temp_str[j] >> 4) & 0xf],
                                        1)
                      != SSH_BUFFER_OK)
                    {
                      ssh_free(temp_str);
                      goto failed;
                    }
                  if (ssh_buffer_append(&buffer,
                                        (unsigned char *)
                                        &hextable[(temp_str[j]     ) & 0xf],
                                        1)
                      != SSH_BUFFER_OK)
                    {
                      ssh_free(temp_str);
                      goto failed;
                    }
                }
            }
          else
            {
              /* Quote everything and be happy, we can use either the
                 method with quotation marks, or just backslashes.

                 Here we assume that the text usually quoted has only
                 a small amount of places to quote thus we use
                 backslashes. */

              for (j = 0; j < temp_str_length; j++)
                {
                  switch (temp_str[j])
                    {
                    case '"':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\\"", 2);
                      break;
                    case '#':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\#", 2);
                      break;
                    case '<':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\<", 2);
                      break;
                    case '>':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\>", 2);
                      break;
                    case '=':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\=", 2);
                      break;
                    case '\\':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\\\", 2);
                      break;
                    case ',':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\,", 2);
                      break;
                    case ';':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\;", 2);
                      break;
                    case '+':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\+", 2);
                      break;
                    case '\0':
                      rv = ssh_buffer_append(&buffer,
                                             (unsigned char *) "\\00", 3);
                      break;
                    default:
                      rv = ssh_buffer_append(&buffer, &temp_str[j], 1);
                      break;
                    }

                  if (rv != SSH_BUFFER_OK)
                    {
                      ssh_free(temp_str);
                      goto failed;
                    }
                }
            }

          ssh_free(temp_str);
          /* Now check whether we are still having another part of the
             RDN in a list. */
          if (temp->next)
            {
              if (ssh_buffer_append(&buffer, (unsigned char *) " + ", 3)
                  != SSH_BUFFER_OK)
                goto failed;
            }
        }
      if (i + 1 < dn->rdn_count)
        {
          if (ssh_buffer_append(&buffer, (unsigned char *) ", ", 2)
              != SSH_BUFFER_OK)
            goto failed;
        }
    }

  /* Build the name. */
  *ldap_dn = ssh_buffer_to_str(&buffer, &len);
  ssh_buffer_uninit(&buffer);

  if (*ldap_dn == NULL)
    return 0;
  else
    return 1;
}

int ssh_dn_encode_ldap(SshDN dn, char **ldap_dn)
{
  return ssh_dn_encode_ldap_cs(dn, SSH_CHARSET_UTF8, ldap_dn);
}

/* Convert DN structure into UTF-8 SshStr string. */
int ssh_dn_encode_ldap_str(SshDN dn, SshStr *str)
{
  char *ldap_dn;
  int rv;

  *str = NULL;

  rv = ssh_dn_encode_ldap_cs(dn, SSH_CHARSET_UTF8, &ldap_dn);
  if (rv != 1 || ldap_dn == NULL)
    return 0;

  *str = ssh_str_make(SSH_CHARSET_UTF8,
                      (unsigned char *)ldap_dn, strlen(ldap_dn));
  return 1;
}

/* Linking RDN's together. */

void ssh_rdn_link(SshRDN prev, SshRDN next)
{
  prev->next = next;
}

/* Converting LDAP DN into the generic DN structure. */

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

int ssh_dn_decode_ldap_cs(SshCharset cs, const unsigned char *ldap_dn,
                          SshDN dn)
{
  SshRDN temp, first, prev, next;
  const SshOidStruct *table_oid;
  unsigned char *buf, *temp_buf;
  unsigned char *oid = NULL;
  int rv, value, finished, quoting, k, rdn_cont = 0, half,
    hex_d, byte, ret_quoting = 0;
  size_t oid_len;
  size_t ldap_dn_len, i, j, start;
  SshBufferStruct buffer;

  ldap_dn_len = ssh_ustrlen(ldap_dn);
  /* Some nasty defines. */
#define SKIP_WHITESPACE(i) \
do { \
  Boolean done = FALSE;\
  do {\
    if ((i) < ldap_dn_len) {\
        switch (ldap_dn[(i)]) {\
          case ' ': case '\f': case '\n': case '\r': case '\t': case '\v': \
                   (i)++;       break; \
          default: done = TRUE; break;\
          }\
      }\
    else\
      done = TRUE;\
  } while (!done);\
} while (0)

#define SKIP_NAME(i) do { \
  while ((isalpha(ldap_dn[i]) || isdigit(ldap_dn[i])) && \
         (i < ldap_dn_len)) \
    i++; \
  } while(0)

#define SKIP_HEX(i) \
  while (isxdigit(ldap_dn[i]) && i < ldap_dn_len) i++;

  /* A bit more complicated digit skipper. */
#define SKIP_DIGIT(i, value)  \
  for (value = 0; isdigit(ldap_dn[i]) && i < ldap_dn_len; i++) \
    { \
      value *= 10; \
      value += ldap_dn[i] - '0'; \
    }

  /* Set to default failure. */
  rv = 0;

  /* Allocate temporary buffer to fill while parsing the string. */
  buf = ssh_malloc(ldap_dn_len + 1);
  if (!buf)
    return rv;

  /* Initialize some workspace */
  ssh_buffer_init(&buffer);

  for (i = 0, prev = NULL, first = NULL; i < ldap_dn_len;)
    {
      /* Read the first name component. */
      SKIP_WHITESPACE(i);
      start = i;
      SKIP_NAME(i);

      /* Check for OID definition. */
      if (i - start >= 3 &&
          ssh_dn_memcmp((const unsigned char *)(ldap_dn + start),
                        (const unsigned char *)"OID", 3) == 0)
        {
          /* Read the '.' separate object identifier. */
          for (oid_len = 0; ; oid_len++)
            {
              /* Check that dot exists. */
              SKIP_WHITESPACE(i);
              if (ldap_dn[i] != '.')
                break;
              /* Skip it. */
              i++;

              if (oid_len > 0)
                if (ssh_buffer_append(&buffer, (const unsigned char *)".", 1)
                    != SSH_BUFFER_OK)
                  goto failed;

              /* Read the number. */
              SKIP_WHITESPACE(i);
              start = i;
              while (isdigit(ldap_dn[i]) && i < ldap_dn_len)
                {
                  if (ssh_buffer_append(&buffer,
                                        (const unsigned char *)&ldap_dn[i], 1)
                      != SSH_BUFFER_OK)
                    goto failed;
                  i++;
                }

              SKIP_DIGIT(i, value);
              if (start - i == 0)
                {
                  /* This must be an error! */
                  goto failed;
                }
            }
          /* Check for errors. */
          if (oid_len == 0)
            goto failed;

          if (ssh_buffer_append(&buffer, (const unsigned char *)"\0", 1)
              != SSH_BUFFER_OK)
            goto failed;
          oid = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
          if (oid == NULL)
            goto failed;

          ssh_buffer_consume(&buffer, ssh_buffer_len(&buffer));
        }
      else
        {
          memcpy(buf, ldap_dn + start, i - start);
          buf[i - start] = '\0';
          if (((table_oid =
               ssh_oid_find_by_std_name_of_type((char *) buf, SSH_OID_DN))
               == NULL) &&
              ((table_oid =
               ssh_oid_find_by_std_name_of_type((char *) buf,
                                                SSH_OID_DIRECTORYATTR))
               == NULL) &&
              ((table_oid =
               ssh_oid_find_by_std_name_of_type((char *) buf, SSH_OID_UCL))
               == NULL))
            goto failed;

          /* Point to the table OID. */
          if ((oid = ssh_strdup(table_oid->oid)) == NULL)
            goto failed;
        }

      SKIP_WHITESPACE(i);
      if (ldap_dn[i] != '=')
        {
          /* Must be an error! */
          goto failed;
        }

      /* Skip equal sign. */
      i++;

      /* Read the name. */
      SKIP_WHITESPACE(i);

      /* Check whether we are dealing here with actual text or hexadecimal
         stuff. */
      if (ldap_dn[i] == '#')
        {
          /* Skip the first character. */
          i++;
          /* Skip whitespace? */
          SKIP_WHITESPACE(i);

          /* We first convert the hex string into our buffer. And
             at the same time compute the length of the hex string. In
             this pass we will be able to deduce the length also. */

          for (j = 0, finished = 0, quoting = 0, k = 0;
               j < ldap_dn_len - i && finished == 0; j++)
            {
              switch (quoting)
                {
                case 0:
                  switch (ldap_dn[i + j])
                    {
                    case '\\':
                      /* Lets do some quoting, useful for longer
                         hex strings. */
                      quoting = 1;
                      break;
                    default:
                      if (isxdigit(ldap_dn[i + j]))
                        {
                          buf[k + 1] = ldap_dn[i + j];
                          k++;
                        }
                      else
                        {
                          /* Stopping, and checking. */
                          i += j;
                          SKIP_WHITESPACE(i);

                          /* Check whether syntactic error found. */
                          if (ldap_dn[i] != ',' &&
                              ldap_dn[i] != ';' &&
                              ldap_dn[i] != '+' &&
                              ldap_dn[i] != '\0')
                            goto failed;

                          rdn_cont = 0;
                          /* Figure out who is following us. */
                          if (ldap_dn[i] == '+')
                            rdn_cont = 1;

                          if (ldap_dn[i] != '\0')
                            /* Skip the end marker. */
                            i++;
                          /* Finish this off now! */
                          finished = 1;
                        }
                      break;
                    }
                  break;
                case 1:
                  switch (ldap_dn[i + j])
                    {
                    case '\n':
                      /* Skip whitespace. */
                      for (; ldap_dn[i + j] == ' ' ||
                             ldap_dn[i + j] == '\t'; j++)
                        ;
                      j--;
                      break;
                    default:
                      break;
                    }
                  quoting = 0;
                  break;
                }
            }

          /* Just for checking. */
          if (quoting)
            goto failed;

          if (!finished)
            {
              i += j;
              rdn_cont = 0;
            }

          /* Check the half. */
          half = k & 0x1;
          buf[0] = 0;

          for (j = 0, hex_d = 0; j < k; j++)
            {
              byte = ssh_hextable[buf[j + 1]];
              /* Check for error. */
              if (byte == 255)
                goto failed;

              if (half)
                {
                  buf[hex_d] |= byte;
                  hex_d++;
                }
              else
                {
                  buf[hex_d] = byte << 4;
                }
              /* Alternate between 1 and 0. */
              half = 1 - half;
            }

          /* Set the length of the buffer to 'j'. */
          j = hex_d;
        }
      else
        {
          /* This part is slightly more involved. We have to do explicit
             testing for each part here, and wonder whether we should quit yet
             or not. */

          /* Quotation rules per RFC2253.
             special characters that need backslash quotation are:
             "," | "+" | """ | "\" | "<" | ">" | ";"

             If backslash appears in front of any other character,
             that character starts a two character hexadecimal
             sequence. */

          for (j = 0, quoting = 0, finished = 0, k = 0;
               j < ldap_dn_len - i && finished == 0;
               j++)
            {
              switch (quoting)
                {
                case 0:
                  switch (ldap_dn[j + i])
                    {
                    case '\\':
                      /* Start either single character, or hexadecimal
                         character quotation, depending on if the input
                         is special. */
                      quoting = 1;
                      if ((1 + j) < (ldap_dn_len - i))
                        {
                          if (!strchr("#,;<=>+\"\\", ldap_dn[j + i + 1]))
                            quoting = 3;
                        }
                      ret_quoting = 0;
                      break;

                    case '\"':
                      /* Start character string quotation. */
                      quoting = 2;
                      ret_quoting = 0;
                      break;

                      /* End quotation */
                    case ',':
                    case ';':
                      finished = 1;
                      break;
                    case '+':
                      finished = 2;
                      break;

                    default:
                      /* Copy verbatim. */
                      buf[k] = ldap_dn[j + i];
                      k++;
                      break;
                    }
                  break;

                case 1:
                  /* Quoting that lasts only for one character. It
                     works for every character, as far as we are
                     concerned. */
                  if (ldap_dn[j + i] == '\n')
                    {
                      /* Special case dealt in this kludgy way. */
                      start = j + i;
                      SKIP_WHITESPACE(start);
                      j = start - i - 1;
                      buf[k] = ' ';
                      k++;
                    }
                  else
                    {
                      buf[k] = ldap_dn[j + i];
                      k++;
                    }
                  quoting = ret_quoting;
                  ret_quoting = 0;
                  break;

                case 2:
                  switch (ldap_dn[j + i])
                    {
                    case '\\':
                      quoting = 1;
                      ret_quoting = 2;
                      break;
                      /* End of quotation. */
                    case '\"': /* " */
                      quoting = 0;
                      ret_quoting = 0;
                      break;
                    default:
                      buf[k] = ldap_dn[j + i];
                      k++;
                      break;
                    }
                  break;
                case 3:

#define VALUE(_c) \
  (unsigned char )(((_c) >= 'A' && (_c) <= 'F') ? ((_c) - ('A' - 10)) : \
    ((_c) >= 'a' && (_c) <= 'f') ? ((_c) - ('a' - 10)) : \
    ((_c) - '0'))

                  if ((j + 1) < (ldap_dn_len - i))
                    {
                      if (strchr("abcdefABCDEF0123456789",
                                 ldap_dn[0 + j + i]) &&
                          strchr("abcdefABCDEF0123456789",
                                 ldap_dn[1 + j + i]))
                        {
                          buf[k] =
                            VALUE(ldap_dn[j + i]) << 4 |
                            VALUE(ldap_dn[j + i + 1]);
                          j += 1;
                          k += 1;
                          quoting = ret_quoting;
                          ret_quoting = 0;
                        }
                      else
                        goto failed;
                    }
                  else
                    goto failed;
                  break;
                }
            }

          i += j;
          /* Check for errors. */
          if (quoting)
            goto failed;

          /* Remove trailing whitespace. */
          while (k > 0 && isspace(buf[k - 1]))
            k--;

          buf[k] = '\0';
          j = k;

          /* Check whether to continue with the same RDN or not. */
          rdn_cont = 0;
          if (finished == 2)
            rdn_cont = 1;
        }

      /* Allocate some new space for the oid and buffer. */
      temp_buf = ssh_memdup(buf, j);
      if (!temp_buf)
        goto failed;

      /* Make the new RDN. */

      /* Make conversion in given character set. */
      if ((temp = ssh_rdn_alloc(oid, cs, temp_buf, j)) == NULL)
        {
          /* RDN alloc stole the temp_buf */
          goto failed;
        }

      /* Forget. */
      oid      = NULL;
      temp_buf = NULL;

      /* Check whether there is a previous RDN to link to. */
      if (prev)
        ssh_rdn_link(prev, temp);

      /* Check whether there will be a following RDN. */
      if (rdn_cont)
        {
          /* If first in a RDN then remember. */
          if (first == NULL)
            first = temp;
          /* Will be the previous. */
          prev = temp;
        }
      else
        {
          if (first == NULL)
            first = temp;
          /* Finally ending into DN. */
          if (!ssh_dn_put_rdn(dn, first))
            {
              goto failed;
            }
          /* Forget the list. */
          first = NULL;
          prev  = NULL;
        }
    } /* end for (rdsn) */

  /* We were successful. */
  rv = 1;

failed:
  ssh_buffer_uninit(&buffer);
  ssh_free(oid);
  ssh_free(buf);
  /* Free the list of RDN's if available. */
  for (temp = first; temp; temp = next)
    {
      next = temp->next;
      ssh_free(temp->oid);
      ssh_str_free(temp->c);
      ssh_free(temp);
    }

  return rv;
  /* Lets undefine the helpful macros. */
#undef SKIP_WHITESPACE
#undef SKIP_NAME
#undef SKIP_HEX
#undef SKIP_DIGIT
}

/* Create DN from LDAP name so that the RDN's in the resulting DN have
   ISO latin encoding. */
int ssh_dn_decode_ldap(const unsigned char *ldap_dn, SshDN dn)
{
  return ssh_dn_decode_ldap_cs(SSH_CHARSET_UTF8, ldap_dn, dn);
}

/* Create DN from LDAP name given in 'str' so that the RDN's in the
   resulting DN have UTF8 encoding. The input string 'str' is first
   converted into UTF8. */
int ssh_dn_decode_ldap_str(const SshStr str, SshDN dn)
{
  unsigned char *ldap_dn;
  size_t ldap_dn_len;
  SshStr utf8str;
  int rv = 0;

  if (ssh_str_charset_get(str) == SSH_CHARSET_UTF8)
    {
      ldap_dn = ssh_str_get(str, &ldap_dn_len);
    }
  else
    {
      utf8str = ssh_str_charset_convert(str, SSH_CHARSET_UTF8);
      ldap_dn = ssh_str_get(utf8str, &ldap_dn_len);
      ssh_str_free(utf8str);
    }

  if (ldap_dn)
    {
      ldap_dn[ldap_dn_len] = '\0';
      rv = ssh_dn_decode_ldap_cs(SSH_CHARSET_UTF8, ldap_dn, dn);
      ssh_free(ldap_dn);
    }
  return rv;
}
#endif /* SSHDIST_CERT */
