/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Perform private key format conversions
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshfileio.h"
#include "sshprvkey.h"
#include "sshgetopt.h"
#include "sshpem.h"
#include "iprintf.h"
#include "sshglobals.h"
#include "x509.h"
#include "sshpkcs1.h"

/* Kludge for the time being as the new PEM library is tested. */
static int read_gen_file(const char *file,
                         const char *passphrase,
                         unsigned char **buf, size_t *buf_len)
{
#ifdef SSHDIST_CERT
  if (strncmp(file, ":p:", 3) == 0)
    {
      unsigned char *data;
      size_t data_len;

      if (ssh_read_file(file+3, &data, &data_len) == 0)
        return 0;
      /* Utilize the new PEM library. */
      *buf =
        ssh_pem_decode_with_key(data, data_len,
                                (const unsigned char *)passphrase,
                                (passphrase == NULL ? 0 : strlen(passphrase)),
                                buf_len);
      ssh_xfree(data);
      if (*buf == NULL)
        return ssh_read_gen_file(file, buf, buf_len);
      return 1;
    }
#endif /* SSHDIST_CERT */
  return ssh_read_gen_file(file, buf, buf_len);
}

#define MAX_ENTROPY 64

int main(int ac, char **av)
{
  int opt, keylen = 0;
  SshCryptoStatus crypto_status;
  unsigned char *data, *outdata;
  char *input_passphrase = NULL, *output_passphrase = NULL, *colon, *keytype;
  const unsigned char *outcipher = ssh_custr("des-cbc");
  char *comment = NULL, *subject = NULL, *hash, *incipher = NULL;
  size_t len, outlen;
  SshSKBType kind, outform = SSH_SKB_PKCS8;
  SshPrivateKey key;
  SshPublicKey pubkey;
  Boolean derivepub = FALSE;
  char *infile = "-", *outfile = "-";
  char *generate = NULL, *entropy = NULL;

  iprintf("#I");

  ssh_global_init();
  ssh_x509_library_initialize(NULL);

#ifdef SSHDIST_CRYPT_ECP
  ssh_pk_provider_register(&ssh_pk_ec_modp);
#endif /* SSHDIST_CRYPT_ECP */

  while ((opt = ssh_getopt(ac, av, "g:e:dPo:s:S:c:r:i:h", NULL)) != -1)
    {
      switch (opt)
        {
        case 'g': generate = ssh_optarg; break;
        case 'e': entropy = ssh_optarg; break;
        case 'd': derivepub = TRUE; break;
        case 'c': outcipher = ssh_custr(ssh_optarg); break;
        case 'r': comment = ssh_optarg; break;
        case 'i': subject = ssh_optarg; break;
        case 'o':
            if (!strcasecmp(ssh_optarg, "secsh1"))
              outform = SSH_SKB_SECSH_1;
            else if (!strcasecmp(ssh_optarg, "ssh1"))
              outform = SSH_SKB_SSH_1;
            else if (!strcasecmp(ssh_optarg, "ssh2"))
              outform = SSH_SKB_SSH_2;
            else if (!strcasecmp(ssh_optarg, "pkcs1"))
              outform = SSH_SKB_PKCS1;
            else if (!strcasecmp(ssh_optarg, "pkcs8s"))
              outform = SSH_SKB_PKCS8_SHROUDED;
            else if (!strcasecmp(ssh_optarg, "pkcs8"))
              outform = SSH_SKB_PKCS8;
            else if (!strcasecmp(ssh_optarg, "x509"))
              outform = SSH_SKB_SSH_X509;
            else if (!strcasecmp(ssh_optarg, "noout"))
              outform = SSH_SKB_UNKNOWN;
            else
              {
                iprintf("%s: unknown output format: %s", av[0], ssh_optarg);
                goto usage;
              }
          break;

        case 'P':
          iprintf("SSH Private Key Conversion utility\n"
                  "Copyright (c) 2002 - 2014, INSIDE Secure Oy."
                  " All rights reserved.\n");
          exit(1);

        case 's':
          output_passphrase = ssh_optarg;

          break;
        case 'S':
          input_passphrase  = ssh_optarg;

          break;
        case 'h':
        default:
          iprintf("\n");
        usage:
          iprintf("Usage: %s [options] [:pbh:inputfile :pbh:outputfile] "
                  "where\n"
                  "#I"
                  ":p:file   PEM or BAS64 encoded file\n"
                  ":b:file   binary encoded file\n"
                  ":h:file   hexl encoded file\n"
                  "#i"
                  "and options denote\n"
                  "#I"
                  "h         help.\n"
                  "c         cipher used to encrypt the output.\n"
                  "i         issue, the subject (if supported) at output.\n"
                  "r         remark, the comment (if supported) at output.\n"
                  "s         output password (alnum only) or passphrase.\n"
                  "S         input password (alnum only) or passphrase.\n"
                  "g         generate key, takes arg {rsa|dsa}[:size].\n"
                  "e         file to read entropy from.\n"
                  "d         output public key to file. "
                            "Format is internal.\n"
                  "o         output private key format, "
                            "one of the following:\n"
                  "#I"
                  "ssh       Encrypted SSH proprietary private key,\n"
                  "ssh1      Encrypted SSH client version 1 RSA key\n"
                  "ssh2      Encrypted SSH client version 2 RSA or DSA key,\n"
                  "x509      Plaintext private key as in PKCS#11,\n"
                  "pkcs1     Plaintext PKCS#1 RSA private key,\n"
                  "pkcs8     Plaintext PKCS#8 private key,\n"
                  "pkcs8s    Encrypted PKCS#8 private key.\n"
                  "#i\n"
                  "Input key format is automatically detected.\n"
                  "#i",
                  av[0]);
          exit(1);
        }
    }

  av += ssh_optind;
  ac -= ssh_optind;

  if (entropy)
    {
      unsigned char *rndbuf;
      size_t rndbuflen;

      if (ssh_read_file_with_limit(entropy, MAX_ENTROPY, &rndbuf, &rndbuflen))
        {
          ssh_random_add_noise(rndbuf, rndbuflen, 8 * rndbuflen);
          ssh_random_stir();
          memset(rndbuf, 0, rndbuflen); ssh_xfree(rndbuf);
        }
      else
        {
          iprintf("Can't open entropy file '%s' for reading.", entropy);
          exit(1);
        }
    }

  if (generate)
    {
      if ((colon = strchr(generate, ':')) != NULL)
        keylen = atoi(++colon);
      else
        keylen = 1024;

      if (!strncmp(generate, "rsa", 3))
        keytype = "if-modn{encrypt{rsa-pkcs1-none},sign{rsa-pkcs1-md5}}";
      else if (!strncmp(ssh_optarg, "dsa", 3))
        keytype = "dl-modp{sign{dsa-nist-sha1}}";
      else
        keytype = NULL;

      if (keytype == NULL)
        {
          iprintf("Can't generate keypair. Unknown key type '%s'", keytype);
          exit(2);
        }

      if (ssh_private_key_generate(&key, keytype,
                                   SSH_PKF_SIZE, keylen, SSH_PKF_END)
          != SSH_CRYPTO_OK)
        {
          iprintf("Can't generate keypair. Private key generate failed.");
          exit(2);
        }
    }

  if (keylen && ac == 1)
    {
      infile = av[-1];
      outfile = av[0];
    }
  else if (!keylen && ac == 2)
    {
      infile = av[0]; outfile = av[1];
    }
  else if (outform == SSH_SKB_UNKNOWN && ac == 1)
    {
      infile = av[0]; outfile = NULL;
    }

  if (output_passphrase && (outform == SSH_SKB_PKCS8 ||
                            outform == SSH_SKB_PKCS1))
    {
      iprintf("Error: output passphrase specified with plaintext key type.\n");
      exit(3);
    }
  if (keylen)
    goto write_keys;

  key = NULL;

  if (read_gen_file(infile, input_passphrase, &data, &len))
    {
      crypto_status = ssh_skb_get_info(data, len,
                                       &incipher, &hash,
                                       NULL, NULL, &kind, &comment);
      if (crypto_status == SSH_CRYPTO_OK)
        {
          if (kind == SSH_SKB_PKCS8_SHROUDED && !input_passphrase)
            {
              iprintf("error: must provide passphrase for file %s\n",
                      infile);
              exit(2);
            }
          crypto_status =
            ssh_skb_decode(kind,
                           data, len,
                           incipher, hash,
                           (const unsigned char *)input_passphrase,
                           input_passphrase ? strlen(input_passphrase) : 0,
                           &key);
          if (crypto_status != SSH_CRYPTO_OK)
            {
              iprintf("Error: can not decode private key of type %s: %s\n",
                      ssh_skb_type_to_name(kind),
                      ssh_crypto_status_message(crypto_status));
              exit(1);
            }
        }
      else
        {
          iprintf("Error: can not determine type of key from file %s: %s\n",
                  infile, ssh_crypto_status_message(crypto_status));
          exit(2);
        }
    }
  else
    {
      iprintf("Error: can not read in keydata from file %s: %s\n", infile,
              strerror(errno));
      exit(2);
    }

  if (outform == SSH_SKB_UNKNOWN)
    exit(0);

  if (derivepub)
    {
      if (ssh_private_key_derive_public_key(key, &pubkey) == SSH_CRYPTO_OK)
        {
          if (outform == SSH_SKB_PKCS1)
            {
              unsigned char *data;
              size_t data_len;

              if (!ssh_pkcs1_encode_public_key(pubkey, &data, &data_len) ||
                  !ssh_write_gen_file(outfile,
                                      "-----BEGIN RSA PUBLIC KEY-----",
                                      "-----END RSA PUBLIC KEY-----",
                                      data, data_len))
                {
                  ssh_xfree(data);
                }
              ssh_xfree(data);
              exit(0);
            }

          crypto_status = ssh_public_key_export(pubkey, &outdata, &outlen);
          if (crypto_status == SSH_CRYPTO_OK)
            {
                goto write_key;
            }
          else
            {
              iprintf("Error: can not derive public key: %s.\n",
                      ssh_crypto_status_message(crypto_status));
              exit(5);
            }
        }
    }

 write_keys:
  crypto_status = ssh_skb_encode(outform,
                                 key, subject, comment, outcipher,
                                 (const unsigned char *)output_passphrase,
                                 output_passphrase
                                 ? strlen(output_passphrase)
                                 : 0,
                                 &outdata, &outlen);
  if (crypto_status == SSH_CRYPTO_OK)
    {
      char *header_begin, *header_end; /* the -----BEGIN PEM SOMETHINGIES */
    write_key:
      switch (outform)
        {
        case SSH_SKB_PKCS8_SHROUDED:
          header_begin = SSH_PEM_ENCRYPTED_PKCS8_BEGIN;
          header_end   = SSH_PEM_ENCRYPTED_PKCS8_END;
          break;
        case SSH_SKB_PKCS8:
          header_begin = SSH_PEM_PKCS8_BEGIN;
          header_end   = SSH_PEM_PKCS8_END;
          break;
        case SSH_SKB_SSH_X509:
          header_begin = SSH_PEM_SSH_PRV_KEY_BEGIN;
          header_end   = SSH_PEM_SSH_PRV_KEY_END;
          break;



        case SSH_SKB_PKCS1:
          if (output_passphrase == NULL || *output_passphrase == '\0')
            {
              char *kt = NULL;
              if (SSH_CRYPTO_OK !=
                  ssh_private_key_get_info(key, SSH_PKF_KEY_TYPE, &kt,
                                           SSH_PKF_END))
                goto default_pem;

              if (0 == strcmp("if-modn", kt))
                {
                  header_begin = SSH_PEM_PKCS1_RSA_BEGIN;
                  header_end   = SSH_PEM_PKCS1_RSA_END;
                }
              else if (0 == strcmp("dl-modp", kt))
                {
                  header_begin = SSH_PEM_PKCS1_DSA_BEGIN;
                  header_end   = SSH_PEM_PKCS1_DSA_END;
                }
              else
                goto default_pem;
              break;
            }
          /* else fallthru */
          header_begin = header_end = NULL;    /* SSH2 keys are already pem */
          if (0 == strncmp(outfile, ":p:", 3))
            outfile += 3;
          break;
        case SSH_SKB_SSH_1:
        case SSH_SKB_SSH_2:
        case SSH_SKB_SECSH_1:
        default:
        default_pem:
          header_begin = SSH_PEM_GENERIC_BEGIN;
          header_end   = SSH_PEM_GENERIC_END;
          break;
        }
      if (!ssh_write_gen_file(outfile,
                              header_begin, header_end,
                              outdata, outlen))
        {
          iprintf("Error: can not write to output file %s: %s\n",
                  outfile, strerror(errno));
          exit(3);
        }
    }
  else
    {
      iprintf("Error: can not encode key to format %s: %s\n",
              ssh_skb_type_to_name(outform),
              ssh_crypto_status_message(crypto_status));
      exit(4);
    }
  return 0;
}
