/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPTest"

#ifdef SSHDIST_MATH
/*************************************************************************/


/* The Self Tests Function that is called on Library Initialization.
   These are mostly borrowed from the tests subdirectory.*/


/* Helper functions for generating multiple precision integers */

/* Generate a random multiple precision integer with 'bits' bits. */
static void true_rand(SshMPInteger op, int bits)
{
  SSH_ASSERT(bits);

  ssh_mprz_rand(op, ssh_rand() % bits);

  /* Occasionally make also negative. */
  if (ssh_rand() & 0x1)
    ssh_mprz_neg(op, op);
}


#ifdef SSHDIST_MATH_INTMOD
/* Generate a pseudo random multiple precision modular integer with
   'bits' bits */
static void my_rand_mod(SshMPIntMod a, SshMPInteger b, int bits)
{
  int n;
  SSH_ASSERT(bits);

  n = ssh_rand() % bits;
  ssh_mprz_rand(b, n);
  ssh_mprzm_set_mprz(a, b);
}

static int check_mod(SshMPIntMod b, SshMPInteger a)
{
  SshMPIntegerStruct t;
  int rv;

  ssh_mprz_init(&t);
  ssh_mprz_set_mprzm(&t, b);
  rv = ssh_mprz_cmp(a, &t);
  ssh_mprz_clear(&t);

  return rv;
}
#endif /* SSHDIST_MATH_INTMOD */


/* The integer test function, this tests randomly chosed integers with
   'bits' bits. The addition, subtraction, squaring, multiplication,
   division, greatest common divisor, different forms of modular
   exponentation, conversion of integers to strings and buffers
   routines are all tested . */
static Boolean test_int(int bits)
{
  SshMPIntegerStruct a, b, c, d, e, f, g;
  SshUInt32 j, k, i;

  /* Initialize the mp integers */
  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);
  ssh_mprz_init(&d);
  ssh_mprz_init(&e);
  ssh_mprz_init(&f);
  ssh_mprz_init(&g);

  /* Run the integer tests */

  /* test addition/subtraction */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);

      ssh_mprz_sub(&c, &a, &b);
      ssh_mprz_add(&d, &c, &b);

      if (ssh_mprz_cmp(&d, &a) != 0)
        goto fail;
    }

  /* test addition/multiplication  */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_set_ui(&b, 0);

      k = ssh_rand() % 1000;
      for (i = 0; i < k; i++)
        ssh_mprz_add(&b, &b, &a);

      ssh_mprz_mul_ui(&c, &a, k);

      if (ssh_mprz_cmp(&c, &b) != 0)
        goto fail;
    }

  /* test subtraction/multiplication */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_set_ui(&b, 0);

      k = ssh_rand() % 1000;
      for (i = 0; i < k; i++)
        ssh_mprz_sub(&b, &b, &a);

      ssh_mprz_neg(&c, &a);
      ssh_mprz_mul_ui(&c, &c, k);
      if (ssh_mprz_cmp(&c, &b) != 0)
        goto fail;
    }

  /* test division */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mprz_cmp_ui(&b, 0) == 0 ||
          ssh_mprz_cmp_ui(&a, 0) == 0)
        continue;
      ssh_mprz_mul(&c, &a, &b);
      ssh_mprz_divrem(&d, &e, &c, &b);
      ssh_mprz_divrem(&e, &f, &c, &a);

      if (ssh_mprz_cmp(&d, &a) != 0 ||
          ssh_mprz_cmp(&e, &b) != 0)
        goto fail;
    }

  /* test division */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mprz_cmp_ui(&b, 0) == 0)
        continue;

      ssh_mprz_divrem(&c, &d, &a, &b);
      ssh_mprz_mul(&e, &c, &b);
      ssh_mprz_add(&e, &e, &d);

      if (ssh_mprz_cmp(&e, &a) != 0)
        goto fail;
    }

  /* multiplication/squaring test */;
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);

      ssh_mprz_mul(&b, &a, &a);
      ssh_mprz_square(&c, &a);

      if (ssh_mprz_cmp(&c, &b) != 0)
        goto fail;
    }

  /* multiplication/gcd tests */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits / 4);
      true_rand(&b, bits / 4);
      if (ssh_mprz_cmp_ui(&a, 0) == 0 ||
          ssh_mprz_cmp_ui(&b, 0) == 0)
        continue;

      /* Make positive. */
      ssh_mprz_abs(&a, &a);
      ssh_mprz_abs(&b, &b);

      ssh_mprz_mul(&c, &a, &b);
      ssh_mprz_gcd(&d, &c, &a);
      ssh_mprz_gcd(&e, &c, &b);

      if (ssh_mprz_cmp(&d, &a) != 0 ||
          ssh_mprz_cmp(&e, &b) != 0)
        goto fail;
    }

  /* squaring test */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);

      ssh_mprz_square(&b, &a);
      ssh_mprz_sqrt(&c, &b);

      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp(&a, &c) != 0)
        goto fail;
    }

  /* exponentiation test */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      /* Make the modulus odd. */
      if ((ssh_mprz_get_ui(&a) & 0x1) == 0)
        ssh_mprz_add_ui(&a, &a, 1);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;

      k = ssh_rand();
      ssh_mprz_set_ui(&b, k);
      ssh_mprz_mod(&b, &b, &a);
      ssh_mprz_set(&c, &b);

      for (i = 1; i < 3; i++)
        {
          ssh_mprz_set_ui(&e, i);
          ssh_mprz_powm_ui_g(&d, k, &e, &a);
          if (ssh_mprz_cmp(&d, &c) != 0)
            goto fail;

          ssh_mprz_mul(&c, &c, &b);
          ssh_mprz_mod(&c, &c, &a);
        }
    }

  /* full exponentiation test */
  for (j = 0; j < 2; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;

      /* Make the modulus odd. */
      if ((ssh_mprz_get_ui(&a) & 0x1) == 0)
        ssh_mprz_add_ui(&a, &a, 1);

      k = ssh_rand();
      ssh_mprz_set_ui(&b, k);
      ssh_mprz_mod(&b, &b, &a);
      ssh_mprz_set(&c, &b);

      for (i = 1; i < 3; i++)
        {
          ssh_mprz_set_ui(&e, i);
          ssh_mprz_powm(&d, &b, &e, &a);
          if (ssh_mprz_cmp(&d, &c) != 0)
            goto fail;

          ssh_mprz_mul(&c, &c, &b);
          ssh_mprz_mod(&c, &c, &a);
        }
    }

  /* double exponentiation test, computes two exponentations and then
     their product */
  for (j = 0; j < 1; j++)
    {
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      if (ssh_mprz_cmp_ui(&a, 3) < 0)
        continue;

      /* Make the modulus odd. */
      if ((ssh_mprz_get_ui(&a) & 0x1) == 0)
        ssh_mprz_add_ui(&a, &a, 1);

      true_rand(&b, bits);
      ssh_mprz_mod(&b, &b, &a);

      true_rand(&c, bits / 4);
      ssh_mprz_abs(&c, &c);
      true_rand(&d, bits);
      ssh_mprz_abs(&d, &d);

      ssh_mprz_mod(&d, &d, &a);
      true_rand(&e, bits / 4);
      ssh_mprz_abs(&e, &e);

      ssh_mprz_powm(&f, &b, &c, &a);
      ssh_mprz_powm(&g, &d, &e, &a);
      ssh_mprz_mul(&f, &f, &g);
      ssh_mprz_mod(&f, &f, &a);

      ssh_mprz_powm_gg(&g, &b, &c, &d, &e, &a);
      if (ssh_mprz_cmp(&f, &g) != 0)
        goto fail;
    }

  /* square tests */
  true_rand(&a, bits);

  ssh_mprz_square(&b, &a);

#ifdef SSHDIST_MATH_ARITHMETIC
  if (ssh_mprz_is_perfect_square(&b) == 0)
    goto fail;
#endif /* SSHDIST_MATH_ARITHMETIC */

  /* buffer testing. */
  for (i = 0; i < 2; i++)
    {
      Boolean dynamic;
      unsigned char buf_array[128], *buffer;
      size_t buffer_len;

      memset(buf_array, 0, sizeof(buf_array));
      true_rand(&a, bits);
      ssh_mprz_abs(&a, &a);

      buffer_len = (bits + 7) / 8;

      if (buffer_len > sizeof(buf_array))
        {
          dynamic = TRUE;
          buffer = ssh_malloc(buffer_len);

          /* no memory */
          if (!buffer)
            goto fail;
        }
      else
        {
          dynamic = FALSE;
          buffer = buf_array;
        }

      ssh_mprz_get_buf(buffer, buffer_len, &a);
      ssh_mprz_set_buf(&b, buffer, buffer_len);

      if (dynamic)
        ssh_free(buffer);

      if (ssh_mprz_cmp(&a, &b) != 0)
        goto fail;
    }

  /* conversion testing. */
  for (i = 0; i < 2; i++)
    {
      char *str;
      int base;

      do
        {
          base = ssh_rand() % 65;
        }
      while (base < 2);

      true_rand(&a, bits);

      str = ssh_mprz_get_str(&a, base);
      ssh_mprz_set_str(&b, str, base);

      ssh_free(str);

      if (ssh_mprz_cmp(&a, &b) != 0)
        goto fail;

      /* Test for automatic recognition. */

      switch (ssh_rand() % 3)
        {
        case 0:
          base = 8;
          break;
        case 1:
          base = 10;
          break;
        case 2:
          base = 16;
          break;
        }

      str = ssh_mprz_get_str(&a, base);
      ssh_mprz_set_str(&b, str, 0);

      ssh_free(str);

      if (ssh_mprz_cmp(&a, &b) != 0)
        goto fail;
    }


  /* clear the mp integers */
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&f);
  ssh_mprz_clear(&g);

  /* all tests passed */
  return TRUE;

 fail:
  /* clear the mp integers */
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&f);
  ssh_mprz_clear(&g);

  /* some test has failed */
  return FALSE;
}


/* The modular integer test function, this tests randomly chosen
   modular integers with 'bits' bits. The addition, subtraction,
   squaring, multiplication, inversion routines are all tested.
   The code that is tested here is used mainly for the internal
   computation of the modular exponentation operation. */
static Boolean test_mod(int bits)
{
#ifdef SSHDIST_MATH_INTMOD
  /* Montgomery testing. */
  SshMPIntModStruct a0, b0, c0;
  SshMPIntegerStruct  a1, b1, c1, m1, d;
  SshMPIntIdealStruct m0;
  int i;

  ssh_mprz_init(&a1);
  ssh_mprz_init(&b1);
  ssh_mprz_init(&c1);
  ssh_mprz_init(&m1);
  ssh_mprz_init(&d);

  /* random moduli search */
  ssh_mprz_rand(&m1, bits);

  /* Make the modulus odd. */
  if ((ssh_mprz_get_ui(&m1) & 0x1) == 0)
    ssh_mprz_add_ui(&m1, &m1, 1);

  /* Init the ideal */
  ssh_mprzm_init_ideal(&m0, &m1);

  /* Init modular integers with respect ot this ideal */
  ssh_mprzm_init(&a0, &m0);
  ssh_mprzm_init(&b0, &m0);
  ssh_mprzm_init(&c0, &m0);

  /* Addition test */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_add(&c0, &a0, &b0);

      ssh_mprz_add(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }

  /* Subtraction tests. */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_sub(&c0, &a0, &b0);

      ssh_mprz_sub(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }

  /* Multiplication tests. */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mprzm_mul(&c0, &a0, &b0);

      ssh_mprz_mul(&c1, &a1, &b1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }

  /* Squaring test. */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_square(&c0, &a0);

      ssh_mprz_square(&c1, &a1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }

  /* mul ui test */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_mul_ui(&c0, &a0, i + 1);

      ssh_mprz_mul_ui(&c1, &a1, i + 1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }

  /* mul 2exp test  */
  for (i = 0; i < 2; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mprzm_mul_2exp(&c0, &a0, (i % 50) + 1);

      ssh_mprz_mul_2exp(&c1, &a1, (i % 50) + 1);
      ssh_mprz_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
        goto fail;
    }


  ssh_mprzm_clear(&a0);
  ssh_mprzm_clear(&b0);
  ssh_mprzm_clear(&c0);
  ssh_mprzm_clear_ideal(&m0);

  ssh_mprz_clear(&a1);
  ssh_mprz_clear(&b1);
  ssh_mprz_clear(&c1);
  ssh_mprz_clear(&m1);
  ssh_mprz_clear(&d);

  /* all tests passed */
  return TRUE;

 fail:

  ssh_mprzm_clear(&a0);
  ssh_mprzm_clear(&b0);
  ssh_mprzm_clear(&c0);
  ssh_mprzm_clear_ideal(&m0);

  ssh_mprz_clear(&a1);
  ssh_mprz_clear(&b1);
  ssh_mprz_clear(&c1);
  ssh_mprz_clear(&m1);
  ssh_mprz_clear(&d);

  /* some test failed */
  return FALSE;

#else /* SSHDIST_MATH_INTMOD */
  /* Return TRUE if SSHDIST_MATH_INTMOD is undefined */
  return TRUE;
#endif /* SSHDIST_MATH_INTMOD */
}


/* The math library self tests */
Boolean ssh_math_library_self_tests(void)
{
  /* The integer bit size with which we test the math library functions */
  int bits = 512;

  /* Seed the weak PRNG. */
  ssh_rand_seed((SshUInt32)ssh_time());

  /* Test the integer and modular integer math functions for
     integers of 512 and 1024 bits */
  while (bits <= 1024)
    {
      /* if either function fails, return FALSE */
      if (!test_mod(bits) || !test_int(bits))
        return FALSE;
      bits += 512;
    }

  return TRUE;
}
#endif /* SSHDIST_MATH */
