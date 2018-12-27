/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the pseudo-random number generator.
*/

#include "sshincludes.h"
#include "sshrand.h"
#include "sshglobals.h"

/* This is a list of ICG(p,a,1) parameters. That is, the polynomials
   X^2 - X - a \in (Z/pZ)[X] are primitive.

   Remark. Unfortunately at this time I have not been able to locate
   the relevant literature, and thus these might not be the best
   choices. There exists an algorithm by Chou for generating things
   called IMP polynomials, whether it is anything but another way
   of saying primitive polynomials that I do not know currently.
*/

#define PRIME_V0 1073741741UL
#define COEFF_A0 3UL
#define PRIME_V1 1073741723UL
#define COEFF_A1 4UL

typedef struct SshICGStateRec SshICGStateStruct;

struct SshICGStateRec
{
  SshUInt32 a[2],b[2],x[2];
};

/* Lagged fibonacci generator parameters. */
#define LAG_L2  98
#define LAG_L1  11
#define LAG_L0  0

/***** ICG code. */

#define ICG_STEP(X, A, B, __p) \
do { \
  SshUInt32 __x = (X), __a = (A), __b = (B); \
  __x = ((__a * icg_invert(__x, (__p)) % (__p)) + __b); \
  X   = ((__x > (__p)) ? (__x - (__p)) : __x); \
} while(0)

























/* A somewhat complication implementation of the extended GCD algorithm
   of Euclid. The complication is due to hopes of working entirely
   with positive numbers of 32-bits. */
static SshUInt32 icg_invert(SshUInt32 x, SshUInt32 p)
{
  SshUInt32 u00,u10,u1,v00,v10,v1;

  if (x == 0) return 0;
  if (x == 1) return 1;

  u00 = 1; u10 = 0; u1 = x; v00 = 0; v10 = 0; v1 = p;
  while (v1 != 0)
    {
      SshUInt32 t00,t10,t2,t3,beta;

      t2 = u1 / v1;
      t3 = u1 - t2*v1;

      beta = t2*v00;

      /* Deduce the "optimal" direction of subtraction. */
      if (u10 == v10)
        {
          if (u00 >= beta)
            {
              t00 = u00 - beta;
              t10 = u10;
            }
          else
            {
              t00 = beta - u00;
              t10 = 1 - u10;
            }
        }
      else
        {
          t00 = u00 + beta;
          t10 = u10;
        }

      u00 = v00;
      u10 = v10;

      u1 = v1;

      v00 = t00;
      v10 = t10;

      v1 = t3;
    }
  if (u10)
    return p - u00;
  return u00;
}

static void icg_update(SshICGStateStruct *state)
{
  ICG_STEP(state->x[0], state->a[0], state->b[0], PRIME_V0);
  ICG_STEP(state->x[1], state->a[1], state->b[1], PRIME_V1);
}

#define ICG_TO_SHORT(X, __p) (((X)<<2)/((__p) >> 14))

static SshUInt32 icg_combine_short(SshICGStateStruct *state)
{
  SshUInt32 t;
  t =
    ICG_TO_SHORT(state->x[0], PRIME_V0) +
    ICG_TO_SHORT(state->x[1], PRIME_V1);
  /* Return the last bits. */
  return t & 0xffff;
}

#define ICG_INSTANCE(__a, __b, __x, __A, __B, __p, __t, __s) \
do { \
  SshUInt32 __c = __s % __p; \
  while (__c == 0) { __c = (__c + __t) % __p; }; \
  __a = ((__A * __c) % __p) * __c % __p; \
  __b = (__B * __c) % __p; \
  __x = (__t + __s) % __p; \
  while (__x == 0) { __x = (__x + __t) % __p; }; \
} while(0)


static SshUInt32 icg_rand(SshICGStateStruct *state)
{
  SshUInt32 rv;
  icg_update(state);
  rv = icg_combine_short(state);
  icg_update(state);
  return rv | (icg_combine_short(state) << 16);
}

static void icg_seed(SshICGStateStruct *state, SshUInt32 seed)
{
  ICG_INSTANCE(state->a[0], state->b[0], state->x[0],
               COEFF_A0, 1, PRIME_V0, 1018562692UL, seed);
  ICG_INSTANCE(state->a[1], state->b[1], state->x[1],
               COEFF_A1, 1, PRIME_V1, 1036060063UL, seed);
}

/***** Lagged Fibonacci Generator. */

#define ROT(s, x, r) \
do { SshUInt32 __t = (x); \
      r = ((__t >> s) | (__t << (32 - s))) & 0xffffffffUL; } while(0)

#define LGF_UPDATE(state) \
do { \
  SshUInt32 l2,l1,p2,p1; \
  state->pos--; \
  state->pos = (state->pos >= SSH_RAND_LGF_VSIZE) ? \
                SSH_RAND_LGF_VSIZE-1 : state->pos; \
  l2 = state->pos; \
  l1 = state->pos + LAG_L1; \
  l1 = (l1 >= SSH_RAND_LGF_VSIZE) ? l1 - SSH_RAND_LGF_VSIZE : l1; \
  p2 = state->v[l2]; \
  p1 = state->v[l1] ^ 1270789179UL; \
  p2 = (p2 + p1) & 0xffffffffUL; \
  ROT(11, p2, state->v[l2]); \
} while(0)

static SshUInt32 lfg_rand(SshLFGStateStruct *state)
{
  LGF_UPDATE(state);
  return state->v[state->pos];
}

static void lfg_seed(SshLFGStateStruct *state, SshUInt32 seed)
{
  SshICGStateStruct icg_state;
  SshUInt32 i;

  /* Initialize a ICG. */
  icg_seed(&icg_state, seed);

  /* Obtain enough randomness. This is rather slow, but hopefully
     applications do not seed very often. */
  for (i = 0; i < SSH_RAND_LGF_VSIZE; i++)
    state->v[i] = icg_rand(&icg_state);

  state->pos = 0;
}

/* A simple algorithm equivalent to the one below was posted on
   sci.math.research by Herman Rubin on 16 May 2001.

  It produces uniformly distributed values in [0, b-1]. It is an
  optimal (in a quite well defined way) way of generating such
  numbers.
*/

static SshUInt32 lfg_range(SshLFGStateStruct *state,
                           SshUInt32 lo, SshUInt32 hi)
{
  SshUInt32 n, j, i, b, r, rv, rvs;

  /* Handle invalid intervals. */
  if (hi <= lo)
    ssh_fatal("ssh_rand: too narrow or invalid range ([%u,%u]).",
              (int) lo, (int) hi);

  /* Initialize. */
  n  = (hi - lo) + 1;
  b  = 1;
  j  = 0;

  if (n > 0x80000000)
    ssh_fatal("ssh_rand: too wide range ([%u,%u]).",
              (int) lo, (int) hi);

  /* Some initial randomness. */
  LGF_UPDATE(state);
  r = state->v[state->pos];
  i = 32;

  /* Return values. */
  rv  = 0;
  rvs = 0;

  /* Handle the even part. */
  while ((n & 0x1) == 0)
    {
      rv = (rv << 1) | (r & 1);
      rvs++;
      r >>= 1;
      i--;
      n >>= 1;
    }

  /* The odd part. */
  while (n > 1)
    {
      /* Check whether new randomness is required. */
      if (i == 0)
        {
          LGF_UPDATE(state);
          r = state->v[state->pos];
          i = 32;
        }

      b = b << 1;
      j = (j << 1) | (r & 0x1);
      r >>= 1;
      i--;

      /* Check whether the b and j registers are nicely bound. */
      if (b < n) continue;
      if (j < n) { rv = rv | (j << rvs); break; }
      j = j - n;
      b = b - n;
    }

  return rv + lo;
}


/***** Interface. */

SSH_GLOBAL_DECLARE_F(SshRandStruct, rand_default_state,
                     SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK);
SSH_GLOBAL_DEFINE_INIT_F(SshRandStruct, rand_default_state,
                         SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK) =
#define rand_default_state SSH_GLOBAL_USE_INIT_F(\
  rand_default_state,SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK)
{
  {
    /* Default LFG. */
    { 2481392845UL, 4019112225UL, 2604509847UL, 1381271154UL, 195982935UL,
      919578789UL, 2248019313UL, 2479556797UL, 1317887575UL, 1347205099UL,
      630747590UL, 30787272UL, 2071396359UL, 2795894942UL, 1088295472UL,
      2616631965UL, 2468212577UL, 272561959UL, 2220987913UL, 829422854UL,
      1072759072UL, 1463251633UL, 3396565355UL, 1765989772UL, 2653303485UL,
      3245606182UL, 1663530289UL, 3392150138UL, 61706866UL, 2559953712UL,
      1548674804UL, 3267199194UL, 3359188793UL, 2986150968UL, 3380295950UL,
      2972318837UL, 222091468UL, 4140753513UL, 201280153UL, 3950493654UL,
      2246465446UL, 3958039212UL, 451794799UL, 3345640519UL, 1059783935UL,
      972276909UL, 3407274027UL, 2726443473UL, 1740495571UL, 894110420UL,
      386667046UL, 3926007615UL, 403526619UL, 1712630347UL, 1730293625UL,
      585955867UL, 441275281UL, 271627006UL, 3647633153UL, 4060264110UL,
      2993688112UL, 3141662613UL, 2310343765UL, 600209412UL, 1713893553UL,
      3131684218UL, 3650445264UL, 3027943396UL, 3303377101UL, 3045670105UL,
      3093141133UL, 3626014427UL, 802909440UL, 784701594UL, 3944673893UL,
      41595953UL, 2717656196UL, 217986664UL, 1420442098UL, 4010452465UL,
      2012811089UL, 580226732UL, 1033117838UL, 2836527333UL, 944000546UL,
      3048066193UL, 2620304979UL, 2475909270UL, 1527818866UL, 136934913UL,
      1552525340UL, 1901190991UL, 307199610UL, 3752399782UL, 2826434434UL,
      1825369625UL, 296918324UL, 227596521UL },
    0
  }
};

SshUInt32 ssh_rand(void)
{
  return lfg_rand(&rand_default_state.lfg);
}

SshUInt32 ssh_rand_state(SshRand state)
{
  if (state == NULL)
    state = &rand_default_state;
  return lfg_rand(&state->lfg);
}

void ssh_rand_state_seed(SshRand state, SshUInt32 seed)
{
  if (state == NULL)
    state = &rand_default_state;
  lfg_seed(&state->lfg, seed);
}

void ssh_rand_seed(SshUInt32 seed)
{
  lfg_seed(&rand_default_state.lfg, seed);
}

void ssh_rand_state_copy(SshRand dst, SshRand src)
{
  if (src == NULL && dst == NULL)
    return;

  if (src == NULL)
    src = &rand_default_state;
  if (dst == NULL)
    dst = &rand_default_state;

  memcpy(dst, src, sizeof(*src));
}

/* Good functions for producing random numbers in particular ranges. */

SshUInt32 ssh_rand_state_range(SshRand state, SshUInt32 lo, SshUInt32 hi)
{
  return lfg_range(&state->lfg, lo, hi);
}

SshUInt32 ssh_rand_range(SshUInt32 lo, SshUInt32 hi)
{
  return lfg_range(&rand_default_state.lfg, lo, hi);
}

/* End. */
