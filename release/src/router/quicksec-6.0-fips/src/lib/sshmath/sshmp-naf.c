/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#ifdef SSHDIST_MATH
/* Transform computations. */

/* Computation of signed bit representation as in Morain & Olivos. */

unsigned int ssh_mprz_transform_mo(SshMPIntegerConst k,
                                   char **transform_table)
{
  unsigned int maxbit, bit, b, end, transform_index;
  char *transform;

  /* Seek the maximum number of bits. */

  maxbit = ssh_mprz_get_size(k, 2);

  /* Set up scanning. */

  bit = 0;
  b = 0;
  end = 0;
  transform_index = 0;

  /* Allocate and compute transform bit table.
     As suggested by Morain & Olivos. (This is equal to the P1363 method.)
     */

  transform = ssh_xmalloc(maxbit + 3);

  while (!end)
    {
      unsigned int scanbit = bit;

      while (scanbit < maxbit)
        {
          if (ssh_mprz_get_bit(k, scanbit) == 1)
            break;
          scanbit++;
        }
      if (scanbit >= maxbit)
        break;

      while (bit < scanbit)
        {
          if (b == 11)
            {
              b = 1;
            }
          else
            {
              if (b == 1)
                {
                  transform[transform_index++] = 1;
                  b = 0;
                }
              transform[transform_index++] = 0;
            }
          bit++;
        }

      scanbit = bit;
      while (scanbit < maxbit)
        {
          if (ssh_mprz_get_bit(k, scanbit) == 0)
            break;
          scanbit++;
        }
      if (scanbit >= maxbit)
        {
          scanbit = maxbit;
          end = 1;
        }

      while (bit < scanbit)
        {
          if (b == 0)
            {
              b = 1;
            }
          else
            {
              if (b == 1)
                {
                  transform[transform_index++] = -1;
                  b = 11;
                }
              transform[transform_index++] = 0;
            }
          bit++;
        }
    }

  /* Set the highest bit. */
  transform[transform_index] = 1;

  /* Return with transform index and table. */
  *transform_table = transform;
  return transform_index + 1;
}

unsigned int ssh_mprz_transform_binary(SshMPIntegerConst k,
                                       char **transform_table)
{
  unsigned int i, maxbit;
  char *transform;

  /* Seek the maximum number of bits. */

  maxbit    = ssh_mprz_get_size(k, 2);
  transform = ssh_xmalloc(maxbit);
  for (i = 0; i < maxbit; i++)
    transform[i] = ssh_mprz_get_bit(k, i);

  /* Return with transform index and table. */
  *transform_table = transform;
  return maxbit;
}

/* Unoptimized. */
unsigned int ssh_mprz_transform_kmov(SshMPIntegerConst k,
                                   char **transform_table)
{
  char *T;
  int m, j, y, x, u, v, w, z;
  unsigned int log_d;

  log_d = ssh_mprz_get_size(k, 2) + 3;
  T     = ssh_xmalloc(log_d + 3);

  m = j = y = x = u = v = w = z = 0;

  /* Koyama and Tsuruoka method for computing signed representation. */

  while (x < log_d - 1)
    {
      if (ssh_mprz_get_bit(k, x) == 1)
        y++;
      else
        y--;
      x++;

      if (m == 0)
        {
          if (y - z >= 3)
            {
              while (j < w)
                {
                  T[j] = ssh_mprz_get_bit(k, j);
                  j++;
                }
              T[j] = -1;
              j++;
              v = y;
              u = x;
              m = 1;
            }
          else
            {
              if (y < z)
                {
                  z = y;
                  w = x;
                }
            }
        }
      else
        {
          if (v - y >= 3)
            {
              while (j < u)
                {
                  T[j] = ssh_mprz_get_bit(k, j) - 1;
                  j++;
                }
              T[j] = 1;
              j++;
              z = y;
              w = x;
              m = 0;
            }
          else
            {
              if (y > v)
                {
                  v = y;
                  u = x;
                }
            }
        }
    }
  if (m == 0 || (m == 1 && v <= y))
    {
      while (j < x)
        {
          T[j] = ssh_mprz_get_bit(k, j) - m;
          j++;
        }
      T[j] = 1 - m;
      if (m)
        {
          j++;
          T[j] = m;
        }
    }
  else
    {
      while (j < u)
        {
          T[j] = ssh_mprz_get_bit(k, j) - 1;
          j++;
        }
      T[j] = 1;
      j++;
      while (j < x)
        {
          T[j] = ssh_mprz_get_bit(k, j);
          j++;
        }
      T[j] = 1;
    }

  *transform_table = T;
  return j + 1;
}

/* naf.c */
#endif /* SSHDIST_MATH */
