/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshfingerprint.h"
#include "sshdsprintf.h"

char *ssh_fingerprint_babble(const unsigned char *digest,
                             size_t digest_len);
char *ssh_fingerprint_babble_upper(const unsigned char *digest,
                                   size_t digest_len);
char *ssh_fingerprint_pgp2(const unsigned char *digest,
                           size_t digest_len);
char *ssh_fingerprint_pgp5(const unsigned char *digest,
                           size_t digest_len);
char *ssh_fingerprint_hex(const unsigned char *digest,
                          size_t digest_len);
char *ssh_fingerprint_hex_upper(const unsigned char *digest,
                                size_t digest_len);

/* vowel table */
static const char ssh_fingerprint_vowels[] =
  {
    'a', 'e', 'i', 'o', 'u', 'y'
  };

/* consonant table */
static const char ssh_fingerprint_consonants[] =
  {
    'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l',
    'm', 'n', 'p', 'r', 's', 't', 'v', 'z', 'x'
  };

char *ssh_fingerprint_babble(const unsigned char *digest,
                             size_t digest_len)
{
  size_t i, n;
  unsigned int a, b, c, d, e, s;
  char *r;

  n = ((((digest_len | 1) + 1) >> 1) * 6) - 1;
  r = ssh_xmalloc(n + 1);
  r[0] = ssh_fingerprint_consonants[16];
  r[n - 1] = ssh_fingerprint_consonants[16];
  r[n] = '\0';
  for (i = 5; i < n; i += 6)
    r[i] = '-';

  s = 1;
  for (i = 0; i <= digest_len; i += 2)
    {
      n = (i >> 1) * 5;
      if ((i + 1) < digest_len)
        {
          a = (((((unsigned int)(digest[i])) >> 6) & 3) + s) % 6;
          b = (((unsigned int)(digest[i])) >> 2) & 15;
          c = ((((unsigned int)(digest[i])) & 3) + (s / 6)) % 6;
          d = (((unsigned int)(digest[i + 1])) >> 4) & 15;
          e = (((unsigned int)(digest[i + 1]))) & 15;
          s = ((s * 5) + ((((unsigned int)(digest[i])) * 7) +
                          ((unsigned int)(digest[i + 1])))) % 36;
          r[(n + 4) + ((n + 4) / 5)] = ssh_fingerprint_consonants[d];
          r[(n + 5) + ((n + 5) / 5)] = ssh_fingerprint_consonants[e];
        }
      else if ((digest_len % 2) != 0)
        {
          a = (((((unsigned int)(digest[i])) >> 6) & 3) + s) % 6;
          b = (((unsigned int)(digest[i])) >> 2) & 15;
          c = (((((unsigned int)(digest[i]))) & 3) + (s / 6)) % 6;
        }
      else
        {
          a = s % 6;
          b = 16;
          c = s / 6;
        }
      r[(n + 1) + ((n + 1) / 5)] = ssh_fingerprint_vowels[a];
      r[(n + 2) + ((n + 2) / 5)] = ssh_fingerprint_consonants[b];
      r[(n + 3) + ((n + 3) / 5)] = ssh_fingerprint_vowels[c];
    }
  return r;
}

char *ssh_fingerprint_babble_upper(const unsigned char *digest,
                                   size_t digest_len)
{
  char *r;
  char *tmp;

  r = ssh_fingerprint_babble(digest, digest_len);
  for (tmp = r; *tmp != '\0'; tmp++)
    if (isalpha(*(unsigned char *) tmp))
      *tmp = toupper(*(unsigned char *)tmp);
  return r;
}

char *ssh_fingerprint_pgp2(const unsigned char *digest,
                           size_t digest_len)
{
  unsigned char *a, *b;
  size_t x;

  a = ssh_xmalloc(1);
  a[0] = '\0';
  for (x = 0; x < digest_len; x++)
    {
      const char *c;

      if (x == 0)
        c = "";
      else if ((x % 8) == 0)
        c = "  ";
      else
        c = " ";
      ssh_dsprintf(&b, "%s%s%02X", a, c, (unsigned int)digest[x]);
      ssh_xfree(a);
      a = b;
    }
  return (char *) a;
}

char *ssh_fingerprint_pgp5(const unsigned char *digest,
                           size_t digest_len)
{
  unsigned char *a, *b;
  size_t x;

  a = ssh_xmalloc(1);
  a[0] = '\0';
  for (x = 0; x < digest_len; x++)
    {
      const char *c;

      if (x == 0)
        c = "";
      else if ((x % 10) == 0)
        c = "  ";
      else if ((x % 2) == 0)
        c = " ";
      else
        c = "";
      ssh_dsprintf(&b, "%s%s%02X", a, c, (unsigned int)digest[x]);
      ssh_xfree(a);
      a = b;
    }
  return (char *) a;
}

char *ssh_fingerprint_hex(const unsigned char *digest,
                          size_t digest_len)
{
  unsigned char *a, *b;
  size_t x;

  a = ssh_xmalloc(1);
  a[0] = '\0';
  for (x = 0; x < digest_len; x++)
    {
      ssh_dsprintf(&b, "%s%02x", a, (unsigned int)digest[x]);
      ssh_xfree(a);
      a = b;
    }
  return (char *) a;
}

char *ssh_fingerprint_hex_upper(const unsigned char *digest,
                                size_t digest_len)
{
  unsigned char *a, *b;
  size_t x;

  a = ssh_xmalloc(1);
  a[0] = '\0';
  for (x = 0; x < digest_len; x++)
    {
      ssh_dsprintf(&b, "%s%02x", a, (unsigned int)digest[x]);
      ssh_xfree(a);
      a = b;
    }
  return (char *) a;
}

char *ssh_fingerprint(const unsigned char *digest,
                      size_t digest_len,
                      SshFingerPrintType fingerprint_type)
{
  switch (fingerprint_type)
    {
    case SSH_FINGERPRINT_BABBLE:
      return ssh_fingerprint_babble(digest,  digest_len);
      /*NOTREACHED*/

    case SSH_FINGERPRINT_BABBLE_UPPER:
      return ssh_fingerprint_babble_upper(digest,  digest_len);
      /*NOTREACHED*/

    case SSH_FINGERPRINT_PGP2:
      return ssh_fingerprint_pgp2(digest,  digest_len);
      /*NOTREACHED*/

    case SSH_FINGERPRINT_PGP5:
      return ssh_fingerprint_pgp5(digest,  digest_len);
      /*NOTREACHED*/

    case SSH_FINGERPRINT_HEX:
      return ssh_fingerprint_hex(digest,  digest_len);
      /*NOTREACHED*/

    case SSH_FINGERPRINT_HEX_UPPER:
      return ssh_fingerprint_hex_upper(digest,  digest_len);
      /*NOTREACHED*/

    }
  ssh_fatal("ssh_fingerprint: Unknown fingerprint type.");
  /*NOTREACHED*/
  return NULL;
}

const char *ssh_fingerprint_name(SshFingerPrintType fingerprint_type)
{
  switch (fingerprint_type)
    {
    case SSH_FINGERPRINT_BABBLE:
      return "SSH Babble Fingerprint";
      /*NOTREACHED*/

    case SSH_FINGERPRINT_BABBLE_UPPER:
      return "SSH Babble Fingerprint (uppercase)";
      /*NOTREACHED*/

    case SSH_FINGERPRINT_PGP2:
      return "PGP 2.x Fingerprint";
      /*NOTREACHED*/

    case SSH_FINGERPRINT_PGP5:
      return "PGP 5.x Fingerprint";
      /*NOTREACHED*/

    case SSH_FINGERPRINT_HEX:
      return "Plain Hexadecimal Fingerprint";
      /*NOTREACHED*/

    case SSH_FINGERPRINT_HEX_UPPER:
      return "Plain Hexadecimal Fingerprint (uppercase)";
      /*NOTREACHED*/
    }
  ssh_fatal("ssh_fingerprint_name: Unknown fingerprint type.");
  /*NOTREACHED*/
  return NULL;
}
