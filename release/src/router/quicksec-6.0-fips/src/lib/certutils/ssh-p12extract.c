/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "sshpkcs12.h"
#include "sshfileio.h"
#include "x509.h"

#define SSH_DEBUG_MODULE "t-p12extract"

char *prefix = NULL;

static Boolean
read_key_pair(char *prefix,
              SshPrivateKey *pkey,
              SshX509Certificate *cert,
              unsigned char **certber, size_t *certber_len)
{
  char inputfile[128];
  unsigned char *data;
  size_t len;

  ssh_snprintf(inputfile, sizeof(inputfile), "%s.prv", prefix);
  if (ssh_read_gen_file(inputfile, &data, &len))
    {
      if ((*pkey = ssh_x509_decode_private_key(data, len)) == NULL)
        {
          ssh_xfree(data);
          return FALSE;
        }
      ssh_xfree(data);

      ssh_snprintf(inputfile, sizeof(inputfile), "%s.crt", prefix);
      if (ssh_read_gen_file(inputfile, certber, certber_len))
        {
          *cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
          if (ssh_x509_cert_decode(*certber, *certber_len, *cert)
              == SSH_X509_OK)
            return TRUE;
          else
            {
              ssh_x509_cert_free(*cert);
              ssh_xfree(*certber);
              return FALSE;
            }
        }
      else
        return FALSE;
    }
  else
    return FALSE;
}

static SshStr
get_passwd(const char *label)
{
  SshStr passwd;
  char pw[512];

  memset(pw, 0x00, 512);

  printf("%s: ", label);

  fgets(pw, 512, stdin);

  /* Decrease len by one to omit newline */
  passwd = ssh_str_make(SSH_CHARSET_ISO_8859_1,
                        ssh_xmemdup(pw, strlen(pw) - 1),
                        strlen(pw) - 1);
  return passwd;

}

static void
write_key(SshPrivateKey key)
{
  char file_name[127];
  unsigned char *buf;
  size_t buf_len;
  static int num_keys = 0;

  if (ssh_x509_encode_private_key(key, &buf, &buf_len) != SSH_X509_OK)
    {
      printf("Couldn't export SshPrivateKey.\n");
      return;
    }

  ssh_snprintf(file_name,
               sizeof(file_name),
               "%skey_%d.bin",
               (prefix)?(prefix):(""), ++num_keys);

  if (ssh_write_file(file_name, buf, buf_len))
    printf("Private key written to file %s.\n", file_name);
  else
    printf("Error writing private key to file %s.\n", file_name);
  ssh_xfree(buf);
}

static void
write_cert(const unsigned char *data,
           size_t data_len)
{
  char file_name[127];
  static int num_certs = 0;

  ssh_snprintf(file_name,
               sizeof(file_name),
               "%scert_%d.bin",
               (prefix)?(prefix):(""), ++num_certs);

  if (ssh_write_file(file_name, data, data_len))
    printf("Certificate written to file %s.\n", file_name);
  else
    printf("Couldn't write certificate to file %s.\n", file_name);
}

static void dump_safe(SshPkcs12Safe safe,
                      SshPkcs12SafeProtectionType prot,
                      SshStr passwd, SshPrivateKey privkey);

static void dump_bag(SshPkcs12Safe safe, SshUInt32 index,
                     SshStr defaultpass, SshPrivateKey privkey);

static void dump_bags(SshPkcs12Safe safe,  SshStr passwd,
                      SshPrivateKey privkey);

static void dump_bag(SshPkcs12Safe safe, SshUInt32 index,
                     SshStr defaultpass, SshPrivateKey privkey)
{
  SshPrivateKey key;
  unsigned char const *cert;
  size_t cert_len;
  SshPkcs12BagType bag_type;
  SshPkcs12Bag bag;
  SshStr passwd = NULL;
  SshPkcs12SafeProtectionType prot;

  ssh_pkcs12_safe_get_bag(safe, index, &bag_type, &bag);

  switch (bag_type)
    {
    case SSH_PKCS12_BAG_SHROUDED_KEY:
      /* Bag contains a shrouded private key key. We must use password
         to decrypt the key. */
      if (defaultpass)
        if (!ssh_pkcs12_bag_get_shrouded_key(bag, defaultpass, &key))
          {
            printf("Shrouded key decrypted with integrity password\n");
            goto dump_key;
          }
      passwd = get_passwd("Password needed for decrypting the private key");
      if (!ssh_pkcs12_bag_get_shrouded_key(bag, passwd, &key))
        {
        dump_key:
          write_key(key);
          ssh_private_key_free(key);
        }
      else
        {
          printf("Error getting shrouded key from bag %u.\n",
                 (unsigned int) index);
        }
      ssh_str_free(passwd);
      break;
    case SSH_PKCS12_BAG_KEY:
      /* Bag contains plaintext private key. */
      if (!ssh_pkcs12_bag_get_key(bag, &key))
        {
          write_key(key);
          ssh_private_key_free(key);
        }
      else
        {
          printf("Error getting key from bag %u.\n",
                 (unsigned int) index);
        }
      break;
    case SSH_PKCS12_BAG_CERT:
      /* Certificate bag */
      if (!ssh_pkcs12_bag_get_cert(bag, &cert, &cert_len))
        {
          write_cert(cert, cert_len);
        }
      else
        {
          printf("Error getting certificate from bag %u.\n",
                 (unsigned int) index);
        }
      break;
    case SSH_PKCS12_BAG_SAFE:
      ssh_pkcs12_bag_get_safe(bag, &prot, &safe);
      dump_safe(safe, prot, defaultpass, privkey);
      break;

    default:
      printf("Nothing done with bag %u.\n", (unsigned int) index);
    }
}

static void dump_bags(SshPkcs12Safe safe,  SshStr passwd,
                      SshPrivateKey privkey)
{
  int num_bags;
  SshUInt32 j;

  num_bags = ssh_pkcs12_safe_get_num_bags(safe);
  for (j = 0; j < num_bags; j++)
    {
      dump_bag(safe, j, passwd, privkey);
    }
}

static void dump_safe(SshPkcs12Safe safe,
                      SshPkcs12SafeProtectionType prot,
                      SshStr passwd, SshPrivateKey privkey)
{
  SshPkcs7RecipientInfo *recipients;
  SshStr local_passwd;
  SshUInt32 j;

  /* Traverse through all the Safes */
  switch (prot)
    {
    case SSH_PKCS12_SAFE_ENCRYPT_NONE:
      /* Safe is not encrypted, we can traverse bags immediately */
      dump_bags(safe, passwd, privkey);
      break;

    case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
      /* Safe is encrypted with password. WE must first decrypt
         the safe before we can access the bags. */
      if (passwd)
        {
          if (!ssh_pkcs12_safe_decrypt_password(safe, passwd))
            {
              printf("Safe decrypted with integrity passwd\n");
              dump_bags(safe, passwd, privkey);
              return;
            }
        }

      local_passwd = get_passwd("Password for decrypting the safe");
      if (!ssh_pkcs12_safe_decrypt_password(safe, local_passwd))
        {
          printf("Safe decrypted.\n");
          dump_bags(safe, local_passwd, privkey);
        }
      else
        printf("Couldn't decrypt the safe.\n");

      ssh_str_free(local_passwd);
      break;

    case SSH_PKCS12_SAFE_ENCRYPT_PUBKEY:
      ssh_pkcs12_safe_get_recipient(safe, &j, &recipients);
      ssh_pkcs12_safe_decrypt_private_key(safe, recipients[0], privkey,
                                          NULL_FNPTR, NULL);
      dump_bags(safe, passwd, privkey);
      break;
    }
}

int main (int ac, char **av)
{
  SshPkcs12PFX pfx;
  SshPkcs12Safe safe;
  SshPkcs12IntegrityMode type;
  unsigned char *data, *certber;
  size_t data_len, certber_len;
  SshPkcs12SafeProtectionType prot;
  int i, num_safes, opt;
  SshStr passwd;
  SshPrivateKey privkey;
  SshX509Certificate cert;

  char *pkfile = NULL;

  ssh_x509_library_initialize(NULL);
#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */
  i = 1;
  while ((opt = ssh_getopt(ac, av, "P:p:h?", NULL)) != EOF)
    {
      i+=2;
      switch (opt)
        {
        case 'P':
          pkfile = ssh_optarg;
          break;
        case 'p':
          prefix = ssh_optarg;
          break;
        case 'h':
        case '?':
          printf("usage: %s [-p prefix] filename\n", av[0]);
          return 0;
          break;
        }
    }
  if (ac - 1 < i)
    {
      printf("usage: %s [-p prefix] filename\n", av[0]);
      return 1;
    }

  /* Read the PKCS#12 file to buffer */
  if (!ssh_read_file(av[i], &data, &data_len))
    {
      printf("Couldn't read the PKCS12 file.\n");
      return 1;
    }

  /* Decode it */
  if (ssh_pkcs12_pfx_decode(data, data_len, &type, &pfx))
    {
      printf("Decoding of PKCS12 file failed.\n");
      ssh_xfree(data);
      return 1;
    }

  if (pkfile)
    {
      if (!read_key_pair(pkfile, &privkey, &cert, &certber, &certber_len))
        {
          ssh_warning("reading key pair from %s", pkfile);
          return 2;
        }
    }

  passwd = NULL;

  /* Check integrity of the blob if needed */
  if (type == SSH_PKCS12_INTEGRITY_PASSWORD)
    {
      passwd = get_passwd("Password needed for PFX integrity check");
      if (ssh_pkcs12_pfx_verify_hmac(pfx, passwd))
        {
          printf("Integrity check failed.\n");
          ssh_str_free(passwd);
          passwd = NULL;
        }
      else
        printf("Integrity check ok.\n");
    }

  num_safes = ssh_pkcs12_pfx_get_num_safe(pfx);
  for (i = 0; i < num_safes; i++)
    {
      ssh_pkcs12_pfx_get_safe(pfx, i, &prot, &safe);
      dump_safe(safe, prot, passwd, privkey);
    }

  if (passwd) ssh_str_free(passwd);
  ssh_xfree(data);
  ssh_pkcs12_pfx_free(pfx);
  ssh_x509_library_uninitialize();
  ssh_util_uninit();
  return 0;
}
