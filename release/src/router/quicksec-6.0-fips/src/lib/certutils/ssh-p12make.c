/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"
#include "x509.h"
#include "sshfileio.h"
#include "sshurl.h"
#include "sshdsprintf.h"
#include "sshglobals.h"
#include "sshprvkey.h"
#include "sshpkcs12.h"

#define SSH_DEBUG_MODULE "t-p12make"

char *
my_getpass(const char *prompt)
{
#ifdef HAVE_GETPASS
  return getpass(prompt);
#else  /* HAVE_GETPASS */
  static char line[128];
  size_t len;
  fputs(prompt, stdout); fflush(stdout);
  fgets(line, sizeof(line), stdin);
  len = strlen(line);
  if (len > 0 && line[len - 1] == '\n')
    line[len - 1] = '\0';
  return line;
#endif /* HAVE_GETPASS */
}

Boolean ssh_cert_and_key_to_pkcs12(unsigned char *cert, size_t cert_len,
                                   SshPrivateKey key,
                                   SshStr friendly_name,
                                   unsigned char **ca,
                                   size_t *ca_len, int ca_count,
                                   SshStr passwd,
                                   unsigned char **data, size_t *data_len)
{
  SshPkcs12PFX p12;
  SshPkcs12Safe safe;
  SshPkcs12Bag bag;
  unsigned char kid[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t kid_len;
  SshHash hash;
  char *pbe = NULL;

  /* One of the following:
     pbeWithSHAAnd128BitRC4           pbeWithSHAAnd40BitRC4
     pbeWithSHAAnd3-KeyTripleDES-CBC  pbeWithSHAAnd2-KeyTripleDES-CBC
     pbeWithSHAAnd128BitRC2-CBC   pbeWithSHAAnd40BitRC2-CBC       */
  pbe = "pbeWithSHAAnd3-KeyTripleDES-CBC";

  p12 = ssh_pkcs12_pfx_create();
  /* Add private key to separate safe. */
  safe = ssh_pkcs12_create_safe();

  if (ssh_pkcs12_create_shrouded_key_bag(key, pbe, passwd,
                                         &bag) != SSH_PKCS12_OK)
    {
      SSH_DEBUG(2, ("Failed to create shrouded key bag"));
      ssh_pkcs12_pfx_free(p12);
      return FALSE;
    }

  /* Calculate local id attribute from the certificate. This key is used
     to map the private key to corresponding certificate. */
  ssh_hash_allocate("sha1", &hash);
  kid_len = ssh_hash_digest_length("sha1");
  ssh_hash_update(hash, cert, cert_len);
  ssh_hash_final(hash, kid);
  ssh_hash_free(hash);

  ssh_pkcs12_bag_add_local_key_id_attr(bag, kid, kid_len);

  if (friendly_name)
    ssh_pkcs12_bag_add_friendly_name_attr(bag, friendly_name);

  ssh_pkcs12_safe_add_bag(safe, bag);
  ssh_pkcs12_pfx_add_safe(p12, safe);

  /* Allocate new safe for user certificate. */
#if 0
  safe = ssh_pkcs12_create_safe();
#else
  safe = ssh_pkcs12_create_password_protected_safe((const char *)pbe,
                                                   passwd);
#endif

  if (ssh_pkcs12_create_cert_bag(cert, cert_len, &bag) != SSH_PKCS12_OK)
    {
      SSH_DEBUG(2, ("Failed to create certificate bag"));
      ssh_pkcs12_pfx_free(p12);
      return FALSE;
    }

  ssh_pkcs12_bag_add_local_key_id_attr(bag, kid, kid_len);

  if (friendly_name)
    ssh_pkcs12_bag_add_friendly_name_attr(bag, friendly_name);

  ssh_pkcs12_safe_add_bag(safe, bag);

  if (ca_count > 0)
    {
      int n;

      for (n = 0; n < ca_count; n++)
        {
          ssh_pkcs12_create_cert_bag(ca[n], ca_len[n], &bag);

#if 0
          ssh_hash_allocate("sha1", &hash);
          kid_len = ssh_hash_digest_length("sha1");
          ssh_hash_update(hash, ca[n], ca_len[n]);
          ssh_hash_final(hash, kid);
          ssh_hash_free(hash);
          ssh_pkcs12_bag_add_local_key_id_attr(bag, kid, kid_len);
#endif

          ssh_pkcs12_safe_add_bag(safe, bag);
        }
    }

  ssh_pkcs12_pfx_add_safe(p12, safe);

  if (ssh_pkcs12_encode_hmac(p12, passwd, data, data_len) != SSH_PKCS12_OK)
    {
      ssh_pkcs12_pfx_free(p12);
      return FALSE;
    }
  ssh_pkcs12_pfx_free(p12);
  return TRUE;
}

SshPrivateKey ssh_read_private_key(char *filename)
{
  char *passwd = NULL;
  unsigned char *cp = NULL;
  size_t len;
  SshPrivateKey prv;
  SshSKBType kind;
  char *comment;
  char *cipher, *hash;

  if (!ssh_read_file((const char *)filename, &cp, &len))
    {
      printf("error; failed to read private key file '%s'.\n", filename);
      return NULL;
    }

  if (cp == NULL)
    {
      printf("error; failed to read private key file '%s'.\n", filename);
      return NULL;
    }

  if (ssh_skb_get_info(cp, len, &cipher, &hash, NULL, NULL, &kind, &comment)
      == SSH_CRYPTO_OK)
    {
      if (kind == SSH_SKB_PKCS8_SHROUDED)
        {
          printf("Private key file '%s' is encrypted. Password needed.\n",
                 filename);
          passwd = my_getpass("Old private key passphrase: ");

        }
      if (ssh_skb_decode(kind, cp, len,
                         NULL, NULL,
                         (unsigned char *)
                         (passwd == NULL ? "" : passwd),
                         passwd == NULL ? 0  : strlen(passwd),
                         &prv) == SSH_CRYPTO_OK)
        {
          ssh_free(cp);
          return prv;
        }
    }
  ssh_free(cp);
  printf("error; failed to decode private key.\n");
  return NULL;
}


int main(int ac, char **av)
{
  SshX509ConfigStruct x509_conf;
  unsigned char *p12;
  unsigned char *cert = NULL, *ca[100];
  char *pword, *outfile = "-";
  size_t cert_len, ca_len[100], p12len;
  int ca_count = 0;
  SshStr passwd = NULL, friendly = NULL;
  SshPrivateKey pkey = NULL;
  SshCharset charset = SSH_CHARSET_ISO_8859_1;
  int opt, rv = 0, i;

  ssh_global_init();

  ssh_x509_library_set_default_config(&x509_conf);
  ssh_x509_library_initialize(&x509_conf);
#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */

  while ((opt = ssh_getopt(ac, av, "huo:f:c:", NULL)) != -1)
    {
      switch (opt)
        {
        case 'h':
        show_usage:
          printf("ssh-p12make\n");
          printf("usage: ssh-p12make [options] certificate privatekey\n");
          printf("       -o file      output PKCS#12 file\n");
          printf("       -c cert      additional CA certificate\n");
          printf("       -u           UTF-8 charset for input\n");
          printf("       -f name      Friendly name attribute (some versions\n"
                 "                    of Netscape strongly require this).\n");
          printf("\n");

          rv = 0;
          goto failed;

          break;

        case 'o':
          outfile = ssh_optarg;
          break;

        case 'u':
          charset = SSH_CHARSET_UTF8;
          break;

        case 'f':
          if ((friendly =
               ssh_str_make(charset,
                            (unsigned char *)ssh_strdup(ssh_optarg),
                            strlen(ssh_optarg))) == NULL)
            {
              printf("error; Invalid friendly name '%s'\n", ssh_optarg);
              rv = 3;
              goto failed;
            }
          break;

        case 'c':
          if (!ssh_read_file(ssh_optarg, (unsigned char **)&ca[ca_count],
                             &ca_len[ca_count]))
            {
              printf("error; failed to read CA certificate '%s'\n",
                     ssh_optarg);
              rv = 2;
              goto failed;
            }
          ca_count++;
          break;

        }
    }
  ac -= ssh_optind;
  av += ssh_optind;

  if (ac != 2)
    goto show_usage;

  if (!ssh_read_file((const char *)av[0], (unsigned char **)&cert, &cert_len))
    {
      printf("error; missing certificate\n");
      rv = 1;
      goto failed;
    }

  pkey = ssh_read_private_key(av[1]);
  if (pkey == NULL)
    {
      printf("error; failed to read private key\n");
      rv = 1; goto failed;
    }

  pword = my_getpass("New PKCS#12 passphrase: ");
  passwd = ssh_str_make(charset,
                        (unsigned char *)ssh_strdup(pword),
                        strlen(pword));
  if (passwd == NULL)
    {
      printf("error; missing password\n");
      rv = 1; goto failed;
    }

  if (ssh_cert_and_key_to_pkcs12(cert, cert_len, pkey, friendly,
                                 ca, ca_len, ca_count,
                                 passwd,
                                 &p12, &p12len) == FALSE)
    {
      printf("error; failed to encode PKCS#12\n");
      rv = 1; goto failed;
    }
  ssh_write_gen_file(outfile, SSH_PEM_GENERIC, p12, p12len);
  ssh_free(p12);

 failed:
  ssh_free(cert);
  for (i = 0; i < ca_count; i++) ssh_free(ca[i]);
  if (pkey) ssh_private_key_free(pkey);
  if (passwd) ssh_str_free(passwd);
  if (friendly) ssh_str_free(friendly);
  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return rv;
}
