/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Make vendor ID entries from a plain-text version string using MD5.
*/

#include "sshincludes.h"
#include "sshcrypt.h"

int
main(int argc, char *argv[])
{
  SshHash hash;
  unsigned char buf[16];
  int i, j;

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    ssh_fatal("Could not initialize the crypto library.");

  if (ssh_hash_allocate("md5", &hash) != SSH_CRYPTO_OK)
    {
      fprintf(stderr, "could not allocate MD5 hash\n");
      exit(1);
    }

  for (i = 1; i < argc; i++)
    {
      ssh_hash_reset(hash);

      ssh_hash_update(hash, argv[i], strlen(argv[i]));
      if (ssh_hash_final(hash, buf) != SSH_CRYPTO_OK)
        {
          fprintf(stderr, "could not compute MD5 hash digest\n");
          exit(1);
        }

      printf("\
  {\"%s\",\n\
   \"",
             argv[i]);

      for (j = 0; j < sizeof(buf); j++)
        printf("\\x%02x", buf[j]);

      printf("\", %lu , %lu,\n\
   0, 0, 0, 0},\n",
             (unsigned long) sizeof(buf),
             (unsigned long) sizeof(buf));
    }

  return 0;
}
