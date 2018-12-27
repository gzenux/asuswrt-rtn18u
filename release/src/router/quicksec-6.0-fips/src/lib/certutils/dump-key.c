/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to output public and private keys (on certtools).
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshmp.h"
#include "sshcrypt.h"
#include "x509.h"
#include "iprintf.h"

Boolean cu_dump_number(SshMPInteger number, int base)
{
  char *buf;

  buf = ssh_mprz_get_str(number, base);
  iprintf("%s\n", buf);
  ssh_xfree(buf);
  return TRUE;
}

/* Return TRUE if the public key was successfully printed, and
   FALSE in case of errors. */
Boolean cu_dump_pub(SshPublicKey pub, int base)
{
  SshMPIntegerStruct e, n, p, q, g, y;
  SshMPIntegerStruct a, b, gx, gy, y_x, y_y;
  const SshX509PkAlgorithmDefStruct *alg;
  const char *key_type = NULL;
  char *curve_name = NULL;
  Boolean pc;

  iprintf("PublicKey =#I\n");

  if (pub == NULL)
    {
      iprintf("[Public key invalid.]\n");
      iprintf("#i");
      return FALSE;
    }

  alg = ssh_x509_public_key_algorithm(pub);
  if (alg == NULL)
    {
      iprintf("[Corrupted public key.]\n");
      iprintf("#i");
      return FALSE;
    }

  iprintf("Algorithm name (SSH) : %s{sign{%s}}\n", alg->name, alg->sign);

  if (ssh_public_key_get_info(pub,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      iprintf("Can not get the key type\n");
      iprintf("#i");
      return FALSE;
    }

  if (strcmp(key_type, "if-modn") == 0)
    {
      /* Handle RSA keys. */
      ssh_mprz_init(&e);
      ssh_mprz_init(&n);

      if (ssh_public_key_get_info(pub,
                                  SSH_PKF_MODULO_N, &n,
                                  SSH_PKF_PUBLIC_E, &e,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          iprintf("[Internal error, could not get RSA parameters.]\n");
          iprintf("#i");
          ssh_mprz_clear(&e);
          ssh_mprz_clear(&n);
          return FALSE;
        }

      iprintf("Modulus n  (%4d bits) :#I\n", ssh_mprz_get_size(&n, 2));
      cu_dump_number(&n, base);
      iprintf("#i"); ssh_mprz_clear(&n);

      iprintf("Exponent e (%4d bits) :#I\n", ssh_mprz_get_size(&e, 2));
      cu_dump_number(&e, base);
      iprintf("#i"); ssh_mprz_clear(&e);

      iprintf("#i");
      return TRUE;
    }

  if (strcmp(key_type, "dl-modp") == 0)
    {
      /* Handle DSA keys. */
      ssh_mprz_init(&p);
      ssh_mprz_init(&g);
      ssh_mprz_init(&q);
      ssh_mprz_init(&y);

      if (ssh_public_key_get_info(pub,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_PRIME_Q, &q,
                                  SSH_PKF_GENERATOR_G, &g,
                                  SSH_PKF_PUBLIC_Y, &y,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&g);
          ssh_mprz_clear(&y);
          iprintf( "[Internal error, could not get DSA parameters.]\n");
          return FALSE;
        }

      iprintf("Modulus p     (%4d bits) :#I\n", ssh_mprz_get_size(&p, 2));
      cu_dump_number(&p, base);
      iprintf("#i"); ssh_mprz_clear(&p);

      iprintf("Group order q (%4d bits) :#I\n", ssh_mprz_get_size(&q, 2));
      cu_dump_number(&q, base);
      iprintf("#i"); ssh_mprz_clear(&q);

      iprintf( "Generator g   (%4d bits) :#I\n", ssh_mprz_get_size(&g, 2));
      cu_dump_number(&g, base);
      iprintf("#i"); ssh_mprz_clear(&g);

      iprintf("Public key y  (%4d bits) :#I\n", ssh_mprz_get_size(&y, 2));
      cu_dump_number(&y, base);
      iprintf("#i"); ssh_mprz_clear(&y);

      iprintf("#i");
      return TRUE;
    }

  if (strcmp(key_type, "ec-modp") == 0)
    {
      /* Handle ECDSA keys */
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&gx);
      ssh_mprz_init(&gy);
      ssh_mprz_init(&a);
      ssh_mprz_init(&b);
      ssh_mprz_init(&y_x);
      ssh_mprz_init(&y_y);


      if (ssh_public_key_get_info(pub,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_GENERATOR_G, &gx, &gy,
                                  SSH_PKF_PRIME_Q, &q,
                                  SSH_PKF_CURVE_A, &a,
                                  SSH_PKF_CURVE_B, &b,
                                  SSH_PKF_PUBLIC_Y, &y_x, &y_y,
                                  SSH_PKF_PREDEFINED_GROUP, &curve_name,
                                  SSH_PKF_POINT_COMPRESS, &pc,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&gx);
          ssh_mprz_clear(&gy);
          ssh_mprz_clear(&a);
          ssh_mprz_clear(&b);
          ssh_mprz_clear(&y_x);
          ssh_mprz_clear(&y_y);
          iprintf( "[Internal error, could not get ECDSA paramaters.]\n");
          return FALSE;
       }

     if (curve_name != NULL)
       {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&gx);
          ssh_mprz_clear(&gy);
          ssh_mprz_clear(&a);
          ssh_mprz_clear(&b);
          iprintf("Fixed Curve     : %s\n",curve_name);
       }
     else
       {
          iprintf("Curve prime modulus P(%4d bits): #I\n",
                                   ssh_mprz_get_size(&p, 2));
          cu_dump_number(&p, base);
          iprintf("#i");ssh_mprz_clear(&p);

          iprintf("Curve generator Gx : #I\n");
          cu_dump_number(&gx, base);
          iprintf("#i");ssh_mprz_clear(&gx);

          iprintf("Curve generator Gy : #I\n");
          cu_dump_number(&gy, base);
          iprintf("#i");ssh_mprz_clear(&gy);

          iprintf("Order of Curve n   : #I\n");
          cu_dump_number(&q, base);
          iprintf("#i");ssh_mprz_clear(&q);

          iprintf("Curve Constant a    : #I\n");
          cu_dump_number(&a, base);
          iprintf("#i");ssh_mprz_clear(&a);

          iprintf("Curve Constant b    : #I\n");
          cu_dump_number(&b, base);
          iprintf("#i");ssh_mprz_clear(&b);
       }

     iprintf("Public key x coordinate : #I\n");
     cu_dump_number(&y_x, base);
     iprintf("#i");ssh_mprz_clear(&y_x);
     iprintf("Public key y coordinate : #I\n");
     cu_dump_number(&y_y, base);
     iprintf("#i");ssh_mprz_clear(&y_y);
     return TRUE;
    }

  iprintf("[Pretty print doesn't support this key type (%s).]\n", key_type);
  iprintf("#i");
  return FALSE;
}

/* Return TRUE if the private key was successfully printed, and
   FALSE in case of errors. */
Boolean cu_dump_prv(SshPrivateKey prv, int base)
{
  const char *name;
  char *key_name;

  iprintf("PrivateKey =#I\n");

  key_name = ssh_private_key_name(prv);
  iprintf("Algorithm name (SSH) : %s\n", key_name);
  ssh_xfree(key_name);

  if (ssh_private_key_get_info(prv,
                               SSH_PKF_KEY_TYPE, &name,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    goto failed;

  if (strcmp(name, "if-modn") == 0)
    {
      SshMPIntegerStruct n, e, d, p, q, u;

      ssh_mprz_init(&n);
      ssh_mprz_init(&e);
      ssh_mprz_init(&d);
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&u);

      /* Get the necessary information of the SSH style RSA key. */
      if (ssh_private_key_get_info(prv,
                                   SSH_PKF_MODULO_N,  &n,
                                   SSH_PKF_PUBLIC_E,  &e,
                                   SSH_PKF_SECRET_D,  &d,
                                   SSH_PKF_PRIME_P,   &p,
                                   SSH_PKF_PRIME_Q,   &q,
                                   SSH_PKF_INVERSE_U, &u,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&n);
          ssh_mprz_clear(&e);
          ssh_mprz_clear(&d);
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&u);
          goto failed;
        }

      iprintf("algorithm = RSA\n");

      iprintf("e =#I\n"); cu_dump_number(&e, base); iprintf("#i");
      ssh_mprz_clear(&e);
      iprintf("n =#I\n"); cu_dump_number(&n, base); iprintf("#i");
      ssh_mprz_clear(&n);
      iprintf("d =#I\n"); cu_dump_number(&d, base); iprintf("#i");
      ssh_mprz_clear(&d);
      iprintf("p =#I\n"); cu_dump_number(&p, base); iprintf("#i");
      ssh_mprz_clear(&p);
      iprintf("q =#I\n"); cu_dump_number(&q, base); iprintf("#i");
      ssh_mprz_clear(&q);
      iprintf("u =#I\n"); cu_dump_number(&u, base); iprintf("#i");
      ssh_mprz_clear(&u);

      iprintf("#i");
      return TRUE;
    }

  if (strcmp(name, "dl-modp") == 0)
    {
      SshMPIntegerStruct p, q, g, y, x;

      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);
      ssh_mprz_init(&y);
      ssh_mprz_init(&x);

      if (ssh_private_key_get_info(prv,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_PRIME_Q, &q,
                                   SSH_PKF_GENERATOR_G, &g,
                                   SSH_PKF_PUBLIC_Y, &y,
                                   SSH_PKF_SECRET_X, &x,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&g);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&y);
          ssh_mprz_clear(&x);

          goto failed;
        }


      /* DSA */
      iprintf("algorithm = DSA\n");

      iprintf("p =#I\n"); cu_dump_number(&p, base); iprintf("#i");
      ssh_mprz_clear(&p);
      iprintf("g =#I\n"); cu_dump_number(&g, base); iprintf("#i");
      ssh_mprz_clear(&g);
      iprintf("q =#I\n"); cu_dump_number(&q, base); iprintf("#i");
      ssh_mprz_clear(&q);
      iprintf("y =#I\n"); cu_dump_number(&y, base); iprintf("#i");
      ssh_mprz_clear(&y);
      iprintf("x =#I\n"); cu_dump_number(&x, base); iprintf("#i");
      ssh_mprz_clear(&x);

      iprintf("#i");
      return TRUE;
    }

  if (strcmp(name, "ec-modp") == 0)
    {
      /* Handle ECDSA keys */
      SshMPIntegerStruct p, q, gx, gy, a, b, x;
      Boolean pc;
      const char * curve_name = NULL;
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&gx);
      ssh_mprz_init(&gy);
      ssh_mprz_init(&a);
      ssh_mprz_init(&b);
      ssh_mprz_init(&x);

      if (ssh_private_key_get_info(prv,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_GENERATOR_G, &gx, &gy,
                                   SSH_PKF_PRIME_Q, &q,
                                   SSH_PKF_CURVE_A, &a,
                                   SSH_PKF_CURVE_B, &b,
                                   SSH_PKF_SECRET_X, &x,
                                   SSH_PKF_PREDEFINED_GROUP, &curve_name,
                                   SSH_PKF_POINT_COMPRESS, &pc,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&gx);
          ssh_mprz_clear(&gy);
          ssh_mprz_clear(&a);
          ssh_mprz_clear(&b);
          ssh_mprz_clear(&x);
          iprintf( "[Internal error, could not get ECDSA paramaters.]\n");
          return FALSE;
        }
      if (curve_name != NULL)
        {
          ssh_mprz_clear(&p);
          ssh_mprz_clear(&q);
          ssh_mprz_clear(&gx);
          ssh_mprz_clear(&gy);
          ssh_mprz_clear(&a);
          ssh_mprz_clear(&b);
          iprintf("Fixed Curve     : %s\n",curve_name);
        }
      else
        {
          iprintf("Curve prime modulus P(%4d bits): #I\n",
                                   ssh_mprz_get_size(&p, 2));
          cu_dump_number(&p, base);
          iprintf("#i");ssh_mprz_clear(&p);

          iprintf("Curve generator Gx : #I\n");
          cu_dump_number(&gx, base);
          iprintf("#i");ssh_mprz_clear(&gx);

          iprintf("Curve generator Gy : #I\n");
          cu_dump_number(&gy, base);
          iprintf("#i");ssh_mprz_clear(&gy);

          iprintf("Order of Curve n   : #I\n");
          cu_dump_number(&q, base);
          iprintf("#i");ssh_mprz_clear(&q);

          iprintf("Curve Constant a    : #I\n");
          cu_dump_number(&a, base);
          iprintf("#i");ssh_mprz_clear(&a);

          iprintf("Curve Constant b    : #I\n");
          cu_dump_number(&b, base);
          iprintf("#i");ssh_mprz_clear(&b);
        }
      iprintf("Secret x (%4d bits): #I\n",
                                   ssh_mprz_get_size(&x, 2));
      cu_dump_number(&x, base);
      iprintf("#i");ssh_mprz_clear(&x);
      return TRUE;
    }


 failed:
  iprintf("#i");
  return FALSE;
}
#endif /* SSHDIST_CERT */
