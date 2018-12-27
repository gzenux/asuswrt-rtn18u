/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Canonialize comma-separated cipher lists.
*/

#include "sshincludes.h"

#ifdef SSHDIST_APPUTIL_KEYUTIL
#include "sshcipherlist.h"
#include "ssh2pubkeyencode.h"
#include "sshcrypt.h"
#include "sshsnlist.h"

char *ssh_public_key_name_ssh_to_cryptolib(const char *str)
{
  char *r;

  r = NULL;
  if (str == NULL)
    r = NULL;
  else if (strcmp(str, SSH_SSH_DSS) == 0)
    r = ssh_xstrdup(SSH_CRYPTO_DSS);
#ifdef SSHDIST_CRYPT_RSA
  else if (strcmp(str, SSH_SSH_RSA) == 0)
    r = ssh_xstrdup(SSH_CRYPTO_RSA);
#endif /* SSHDIST_CRYPT_RSA */

  return r;
}

char *ssh_public_key_name_cryptolib_to_ssh(const char *str)
{
  char *r;

  r = NULL;
  if (str == NULL)
    return NULL;
  else if (strcmp(str, SSH_SSH_DSS) == 0)
    r = ssh_xstrdup(SSH_SSH_DSS);
  else if (strcmp(str, SSH_CRYPTO_DSS) == 0)
    r = ssh_xstrdup(SSH_SSH_DSS);
#ifdef SSHDIST_CRYPT_RSA
  else if (strcmp(str, SSH_SSH_RSA) == 0)
    r = ssh_xstrdup(SSH_SSH_RSA);
  else if (strcmp(str, SSH_CRYPTO_RSA) == 0)
    r = ssh_xstrdup(SSH_SSH_RSA);
#endif /* SSHDIST_CRYPT_RSA */
  else
    r = NULL;

  return r;
}

/* When given a list of public key algorithms (ssh-dss,...)
   constructs an xmallocated list of corresponding X509 versions
   (x509v3-sign-dss,...) and returns it. */
char *
ssh_cipher_list_x509_from_pk_algorithms(const char *alglist)
{
  char *result = NULL;

  if (ssh_snlist_contains(alglist, SSH_SSH_DSS))
    {
      ssh_snlist_append(&result, SSH_SSH_X509_DSS);
    }
  if (ssh_snlist_contains(alglist, SSH_SSH_RSA))
    {
      ssh_snlist_append(&result, SSH_SSH_X509_RSA);
    }

  return result;
}
#endif /* SSHDIST_APPUTIL_KEYUTIL */
