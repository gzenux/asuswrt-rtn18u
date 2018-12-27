/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshmalloc.h"

#define SSH_DEBUG_MODULE "SshTlsSuites"

#define REC(kex, sign, ciph, mac, crippled, friendly_name, cipher_code) \
  {                                                                     \
    SSH_TLS_KEX_ ## kex,                                                \
    SSH_TLS_SIGN_ ## sign,                                              \
    SSH_TLS_CIPH_ ## ciph,                                              \
    SSH_TLS_MAC_ ## mac,                                                \
    crippled,                                                           \
    friendly_name,                                                      \
    cipher_code                                                         \
  }

static const SshTlsCipherSuiteDetailsStruct
ssh_tls_suite_details[SSH_TLS_NUM_CIPHERSUITES] =
{
  /* The friendly names of the ciphers follow no clear logic. The are
   * compatible with the way OpenSSL names its ciphers. */
  REC(NULL, NONE, NULL, NULL, TRUE, "NULL",
      SSH_TLS_NO_CIPHERSUITE),

  REC(RSA,  NONE, NULL, MD5, TRUE,  "NULL-MD5",
      SSH_TLS_RSA_WITH_NULL_MD5),
  REC(RSA,  NONE, NULL, SHA, TRUE,  "NULL-SHA",
      SSH_TLS_RSA_WITH_NULL_SHA),
  REC(RSA,  NONE, RC4,  MD5, TRUE,  "EXP-RC4-MD5",
      SSH_TLS_RSA_EXPORT_WITH_RC4_40_MD5),
  REC(RSA,  NONE, RC4,  MD5, FALSE, "RC4-MD5",
      SSH_TLS_RSA_WITH_RC4_128_MD5),
  REC(RSA,  NONE, RC4,  SHA, FALSE, "RC4-SHA",
      SSH_TLS_RSA_WITH_RC4_128_SHA),
  REC(RSA,  NONE, RC2,  MD5, TRUE,  "EXP-RC2-CBC-MD5",
      SSH_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5),
  REC(RSA,  NONE, IDEA, SHA, FALSE, "IDEA-CBC-SHA",
      SSH_TLS_RSA_WITH_IDEA_CBC_SHA),
  REC(RSA,  NONE, DES,  SHA, TRUE,  "EXP-DES-CBC-SHA",
      SSH_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA),
  REC(RSA,  NONE, DES,  SHA, FALSE, "DES-CBC-SHA",
      SSH_TLS_RSA_WITH_DES_CBC_SHA),
  REC(RSA,  NONE, 3DES, SHA, FALSE, "DES-CBC3-SHA",
      SSH_TLS_RSA_WITH_3DES_EDE_CBC_SHA),


  REC(DH, DSS, DES,  SHA, TRUE,  "EXP-DH-DSS-DES-CBC-SHA",
      SSH_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA),
  REC(DH, DSS, DES,  SHA, FALSE, "DH-DSS-DES-CBC-SHA",
      SSH_TLS_DH_DSS_WITH_DES_CBC_SHA),
  REC(DH, DSS, 3DES, SHA, FALSE, "DH-DSS-DES-3CBC-SHA",
      SSH_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA),
  REC(DH, RSA, DES,  SHA, TRUE,  "EXP-DH-RSA-DES-CBC-SHA",
      SSH_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA),
  REC(DH, RSA, DES,  SHA, FALSE, "DH-RSA-DES-CBC-SHA",
      SSH_TLS_DH_RSA_WITH_DES_CBC_SHA),
  REC(DH, RSA, 3DES, SHA, FALSE, "DH-RSA-DES-CBC3-SHA",
      SSH_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA),


  REC(DHE, DSS, DES,  SHA, TRUE, "EXP-EDH-DSS-DES-CBC-SHA",
      SSH_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA),
  REC(DHE, DSS, DES,  SHA, FALSE, "EDH-DSS-CBC-SHA",
      SSH_TLS_DHE_DSS_WITH_DES_CBC_SHA),
  REC(DHE, DSS, 3DES, SHA, FALSE, "EDH-DSS-DES-CBC3-SHA",
      SSH_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA),
  REC(DHE, RSA, DES,  SHA, TRUE,  "EXP-EDH-RSA-DES-CBC-SHA",
      SSH_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA),
  REC(DHE, RSA, DES,  SHA, FALSE, "EDH-RSA-DES-CBC-SHA",
      SSH_TLS_DHE_RSA_WITH_DES_CBC_SHA),
  REC(DHE, RSA, 3DES, SHA, FALSE, "EDH-RSA-DES-CBC3-SHA",
      SSH_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA),


  REC(DH_ANON, NONE, RC4, MD5,  TRUE,  "EXP-ADH-RC4-MD5",
      SSH_TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5),
  REC(DH_ANON, NONE, RC4, MD5,  FALSE, "ADH-RC4-MD5",
      SSH_TLS_DH_ANON_WITH_RC4_128_MD5),
  REC(DH_ANON, NONE, DES, SHA,  TRUE,  "EXP-ADH-DES-CBC-SHA",
      SSH_TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA),
  REC(DH_ANON, NONE, DES, SHA,  FALSE, "ADH-DES-CBC-SHA",
      SSH_TLS_DH_ANON_WITH_DES_CBC_SHA),
  REC(DH_ANON, NONE, 3DES, SHA, FALSE, "ADH-DES-CBC3-SHA",
      SSH_TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA),


  REC(RSA,  NONE, AES128, SHA, FALSE, "AES128-SHA",
      SSH_TLS_RSA_WITH_AES_128_CBC_SHA),
  REC(DH,   DSS,  AES128, SHA, FALSE, "DH-DSS-AES128-SHA",
      SSH_TLS_DH_DSS_WITH_AES_128_CBC_SHA),
  REC(DH,   RSA,  AES128, SHA, FALSE, "DH-RSA-AES128-SHA",
      SSH_TLS_DH_RSA_WITH_AES_128_CBC_SHA),
  REC(DHE,  DSS,  AES128, SHA, FALSE, "DHE-DSS-AES128-SHA",
      SSH_TLS_DHE_DSS_WITH_AES_128_CBC_SHA),
  REC(DHE,  RSA,  AES128, SHA, FALSE, "DHE-RSA-AES128-SHA",
      SSH_TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
  REC(DH_ANON,NONE,AES128,SHA, FALSE, "ADH-AES128-SHA",
      SSH_TLS_DH_ANON_WITH_AES_128_CBC_SHA),

  REC(RSA, NONE, AES256 , SHA, FALSE, "AES256-SHA",
      SSH_TLS_RSA_WITH_AES_256_CBC_SHA),
  REC(DH,  DSS,  AES256,  SHA, FALSE, "DH-DSS-AES256-SHA",
      SSH_TLS_DH_DSS_WITH_AES_256_CBC_SHA),
  REC(DH,  RSA,  AES256,  SHA, FALSE, "DH-RSA-AES256-SHA",
      SSH_TLS_DH_RSA_WITH_AES_256_CBC_SHA),
  REC(DHE, DSS,  AES256,  SHA, FALSE, "DHE-DSS-AES256-SHA",
      SSH_TLS_DHE_DSS_WITH_AES_256_CBC_SHA),
  REC(DHE, RSA,  AES256,  SHA, FALSE, "DHE-RSA-AES256-SHA",
      SSH_TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
  REC(DH_ANON,NONE,AES256,SHA, FALSE, "ADH-AES256-SHA",
      SSH_TLS_DH_ANON_WITH_AES_256_CBC_SHA)

};

void ssh_tls_get_ciphersuite_details(SshTlsCipherSuite suite,
                                     SshTlsCipherSuiteDetails details)
{
  /* Check that the enumeration has not changed significantly. */

  SSH_ASSERT(SSH_TLS_RSA_WITH_NULL_MD5 == 0x0001 &&
             SSH_TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA == 0x001B &&
             SSH_TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA == 0x001B &&
             SSH_TLS_DH_ANON_WITH_AES_128_CBC_SHA == 0x0034 &&
             SSH_TLS_NUM_CIPHERSUITES == 0x0028);

  if (suite >= SSH_TLS_RSA_WITH_NULL_MD5 &&
      suite <= SSH_TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA)
    {
      memcpy(details, &ssh_tls_suite_details[suite],
             sizeof(*details));
      return;
    }

  if (suite >= SSH_TLS_RSA_WITH_AES_128_CBC_SHA &&
      suite <= SSH_TLS_DH_ANON_WITH_AES_256_CBC_SHA)
    {
      memcpy(details, &ssh_tls_suite_details[suite - 19],
             sizeof(*details));
      return;
    }

  details->kex_method = SSH_TLS_UNKNOWN_SUITE;
  return;
}

SshTlsCipherSuite ssh_tls_parse_suite(const char *suite_name)
{
  SshTlsCipherSuite i;
  for (i = SSH_TLS_NO_CIPHERSUITE; i < SSH_TLS_NUM_CIPHERSUITES; i++)
    if (!strcmp(ssh_tls_suite_details[i].friendly_name, suite_name))
      return (ssh_tls_suite_details[i].ciphersuite_code);
  return SSH_TLS_CIPHERSUITE_NOT_AVAILABLE;
}

SshTlsCipherSuite *ssh_tls_parse_suitelist(const char *suite_names,
                                           SshUInt32 protocol_flags)
{
  const char *s;
  int num_of_ciphers = 1, i = 0;
  SshTlsCipherSuite *ret_list = NULL, suite;
  char *suite_names_tmp = NULL;

  if (!suite_names)
    return NULL;

  if (!protocol_flags)
    protocol_flags = SSH_TLS_SSL2 | SSH_TLS_SSL3
                        | SSH_TLS_TLS | SSH_TLS_TLS1_1;

  /* Count the number of ciphers listed in the string... */
  for (s = suite_names; *s ; s++)
    if (*s == ':')
      num_of_ciphers++;

  ret_list = ssh_calloc(sizeof(SshTlsCipherSuite), num_of_ciphers);
  suite_names_tmp = ssh_strdup(suite_names);
  if (!ret_list || !suite_names_tmp)
    goto failed;


  if ((s = strtok(suite_names_tmp, ":")))
    do
    {
      SSH_DEBUG(7, ("Parsing cipher name %s", s));
      suite = ssh_tls_parse_suite(s);
      if (suite != SSH_TLS_CIPHERSUITE_NOT_AVAILABLE &&
          ssh_tls_supported_suite(protocol_flags, suite))
        ret_list[i++] = suite;
    } while ((s = strtok(NULL, ":")));

  ret_list[i++] = SSH_TLS_NO_CIPHERSUITE;

  ssh_free(suite_names_tmp);
  return ret_list;

 failed:
  ssh_free(suite_names_tmp);
  ssh_free(ret_list);
  return NULL;
}


const char *ssh_tls_format_suite(SshTlsCipherSuite suite)
{
  SshTlsCipherSuiteDetailsStruct temp_details;
  ssh_tls_get_ciphersuite_details(suite, &temp_details);
  if (temp_details.kex_method != SSH_TLS_UNKNOWN_SUITE)
    return temp_details.friendly_name;
  else
    return "UNKNOWN";
}

/* These are used by `sort_suites' to interface with qsort(3).

   [As a point aside, qsort should take a context IMHO.]

   */

static int *suite_ordering;

static int suite_cmp(const void *a, const void *b)
{
  SshTlsCipherSuite suite_a = *((SshTlsCipherSuite *) a);
  SshTlsCipherSuite suite_b = *((SshTlsCipherSuite *) b);

  return suite_ordering[suite_a] - suite_ordering[suite_b];
}

/* Sort [destructively] the cipher suites given in the array `suites'
   according to the preference list `prefs'. `prefs' is an array of
   CipherSuites ends with the item SSH_TLS_NO_CIPHERSUITE.

   After calling this functions, `suites' contains only those
   ciphersuites that are present in `prefs', and contains them in the
   same relative order in which they are in `prefs'.

   Duplicates are NOT removed from `suites'.

   */

#define MARKER 10000

void ssh_tls_sort_suites(SshTlsCipherSuite *suites,
                         int *number_suites,
                         SshTlsCipherSuite *prefs)
{
  int i;
  int ordering[SSH_TLS_NUM_CIPHERSUITES];

  SSH_ASSERT(*number_suites <= SSH_TLS_NUM_CIPHERSUITES);

  for (i = 0; i < SSH_TLS_NUM_CIPHERSUITES; i++)
    {
      ordering[i] = MARKER;
    }

  i = 0;

  while (*prefs != SSH_TLS_NO_CIPHERSUITE)
    {
      SSH_ASSERT(*prefs >= SSH_TLS_RSA_WITH_NULL_MD5);
      SSH_ASSERT(*prefs <= SSH_TLS_MAX_CIPHERSUITE);
      ordering[*prefs++] = i++;
    }

  /* Sort. */
  suite_ordering = ordering;
  qsort(suites, *number_suites, sizeof(SshTlsCipherSuite),
        suite_cmp);

  for (i = 0; i < *number_suites; i++)
    {
      if (ordering[suites[i]] == MARKER)
        {
          *number_suites = i;
          break;
        }
    }
}


/* Returns a colon separated list of the TLS suites supported with the
   configuration flags set. */
char *ssh_tls_get_supported_suites(SshUInt32 conf_flags)
{
  SshTlsCipherSuite suite;
  unsigned char *list, *tmp;
  int i;
  size_t offset, list_len;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; i < SSH_TLS_NUM_CIPHERSUITES; i++)
    {
      suite = ssh_tls_suite_details[i].ciphersuite_code;

      if (ssh_tls_supported_suite(conf_flags, suite))
        {
          size_t newsize;

          newsize = offset + 1 + !!offset +
            strlen(ssh_tls_suite_details[i].friendly_name);

          if (list_len < newsize)
            {
              newsize *= 2;

              if ((tmp = ssh_realloc(list, list_len, newsize)) == NULL)
                {
                  ssh_free(list);
                  return NULL;
                }
              list = tmp;
              list_len = newsize;
            }

          SSH_ASSERT(list_len > 0);
          SSH_ASSERT(list != NULL);

          offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                                 offset ? ":" : "",
                                 ssh_tls_suite_details[i].friendly_name);
        }
    }

  return ssh_sstr(list);
}
