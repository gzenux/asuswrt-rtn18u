/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the "icept_attach.h" implementation for PowerPC
   processors.
*/

#include "sshincludes.h"
#include "icept_attach.h"

#include <machine/spl.h>

#define SSH_DEBUG_MODULE "SshInterceptorAttach"

static struct {
  /* length of the signature */
  unsigned int len;

  /* a free register, other typically 0 (r0) */
  unsigned int free_register;

  /* signature: every other is insn, every other is mask, like:
        ins[0], mask[0], ins[1], mask[1], ...
     and they are compared as ((mem[i] & mask[i]) == ins[i]). */
  unsigned int signature[8 * 2]; /* 8 pairs */
} ssh_ppc_func_starts[] = {
  /* this is 'int xx(void)' for 'cc -g' */
  {
    16, /* 4 instructions */
    0, /* r0 is free, since first mflr anyway overwrites it */
    {
      0x7c0802a6, 0xffffffff, /* mflr r0 */
      0xbfc1fff8, 0xffffffff, /* stmw r30,-8(r1) */
      0x90010008, 0xffffffff, /* stw r0,8(r1) */
      0x9421ffb0, 0xffffffff  /* stwu r1,-80(r1) */
    }
  },
  /* this is 'int xx(void) for 'cc -g -O3' */
  {
    16,
    0,
    {
      0x7c0802a6, 0xffffffff, /* mflr r0 */
      0x93e1fffc, 0xffffffff, /* stw r31, -4(r1) */
      0x90010008, 0xffffffff, /* stw, r0, 8(r1) */
      0x9421ffb0, 0xffffffff  /* stw r1,-80(r1) */
    }
  },
  { 0, 0 },
};

/*
  http://www.chips.ibm.com/products/powerpc/newsletter/\
  jun2001/design-h-t.html
  specifies the following method to assert that instruction cache
  has correct data for self-modifyin dcode:

  * Store modified instruction
  * Issue dcbst instruction to force new instruction to main store
  * Issue sync instruction to ensure DCBST is completed
  * Issue icbi instruction to invalidate instruction cache line
  * Issue isync instruction to clear instruction pipeline
  * It is now OK to execute the modified instruction

  Notice: Apparently dcbst r0, rX is invalid -- r0 not accepted for
  first dcbst argument?? So we mark r0 as clobbered to prevent it
  from being used.

  Notice: We must flush every instruction, since we cannot be sure how
  large the cache lines are (4 instructions?). */

#define flushi(addr,len)                        \
do {                                            \
  int _i;                                       \
  for (_i = 0; _i <= len; _i += 4)              \
    asm("dcbst 0, %0\n"                         \
        "icbi 0, %0\n"                          \
        : /* no return value */                 \
        : "r" (addr + _i)                       \
        : "r0");                                \
  asm("sync\n"                                  \
      "isync\n");                               \
} while (0)

#define dumpi(prefix,addr,ncount)                       \
do {                                                    \
  int _i;                                               \
  unsigned char *_addr =                                \
    (unsigned char *) (addr);                           \
  for (_i = 0; _i < ncount; _i++)                       \
    {                                                   \
      printf(prefix "  0x%02x 0x%02x 0x%02x 0x%02x\n",  \
             _addr[_i * 4 + 0],                         \
             _addr[_i * 4 + 1],                         \
             _addr[_i * 4 + 2],                         \
             _addr[_i * 4 + 3]);                        \
    }                                                   \
} while (0)

void ssh_attach_substitutions()
{
  int i, k, free_register, x;
  unsigned int *scratch, *origcode, *newcode;
  int trap;
  SshAttachRec *sub;
  unsigned int *lr_scratch, *substitute, *original_with_bias;

  x = splhigh();

  for (sub = ssh_get_substitutions(); sub->type != SSH_ATTACH_END; sub++)
    {
      trap = 0;
      newcode = NULL;

      for (i = 0; ssh_ppc_func_starts[i].len != 0; i++)
        {
          for (k = 0; k < ssh_ppc_func_starts[i].len; k++)
            {
              if ((((unsigned int *) sub->original)[k] &
                   ssh_ppc_func_starts[i].signature[k * 2 + 1]) !=
                  ssh_ppc_func_starts[i].signature[k * 2])
                break;
            }

          if (k == ssh_ppc_func_starts[i].len)
            break;
        }

      if (ssh_ppc_func_starts[i].len == 0)
        {
          printf("ssh_attach_attach_substitutions: unexpected original %p\n",
                 sub->original);

          dumpi("original ", sub->original, 8);
          continue;
        }

      if (ssh_ppc_func_starts[i].len < 16)
        {
          printf("ssh_attach_attach_substitutions: too short func start\n");
          continue;
        }

      sub->len = ssh_ppc_func_starts[i].len;
      memcpy(sub->scratch, sub->original, ssh_ppc_func_starts[i].len);

#if 0
      dumpi("orig    ", sub->original, ssh_ppc_func_starts[i].len/4);
      dumpi("saved   ", sub->scratch, ssh_ppc_func_starts[i].len / 4);
#endif

      origcode = sub->original;
      scratch = (unsigned int*) (sub->scratch + ssh_ppc_func_starts[i].len);

      newcode = NULL;

#define rD(X) (((X) << 21) & 0x3e00000)
#define rA(X) (((X) << 16) & 0x01f0000)
#define rS(X) rD(X)

#define r12 12
#define r13 13

#define lis(R,V) (0x3c000000 | rD(R) | (((unsigned int) (V)&0xffff0000) >> 16))
#define ori(R1,R2,V) (0x60000000 | rD(R2) | rA(R1) |    \
                      ((unsigned int) (V) & 0xffff))
#define mtctr(R) (0x7c0003a6 | 0x120 << 11 | rD(R))
#define mtlr(R) (0x7c0003a6 | 0x100 << 11 | rD(R))
#define bctr() 0x4e800420
#define bctrl() 0x4e800421
#define mflr(R) (0x7c0802a6 | rD(R))
#define stw(R1,R2,D) (0x90000000 | rD(R1) | rA(R2) | ((D) & 0xffff))
#define lwz(R1,R2,D) (0x80000000 | rD(R1) | rA(R2) | ((D) & 0xffff))
#define trap() (0x7c000008 | 31 << 21)
#define bl(N) (0x48000000 | ((N) & 0x1fffffc) | 1)
#define addi(R1,R2,D) (0x38000000 | rD(R1) | rA(R2) | ((D) & 0xffff))

      switch (sub->type)
        {
        case SSH_ATTACH_REPLACE:
          newcode = sub->substitute;
          trap = 1;

          printf("Replace: original=%p, substitute=%p, "
                 "newcode=%p, add trap.\n",
                 sub->original, sub->substitute, newcode);

          break;

        case SSH_ATTACH_BEFORE:

          /* First call the substitution, then run the original
             instructions:

                a: call substitution
                b: execute original first instructions
                c: jump to original code start (sans our hook)

             Problems:

                1. The substitution function must return to b, not to
                   original caller. So, we must store link register
                   LR. But where?

                2. We have somehow to construct a correct jump to the
                   original code sequence, but what if the first N
                   bytes of the routine perform something evil? We
                   have just to assume it doesn't.

             We handle the first one by using part of the scratch area
             to store original LR (we cannot use stack, since some
             arguments will be stored in stack if there are a lot of
             arguments, or varargs). */

          /* Try something like:

             ; save lr to lr_scratch
             mflr r12
             lis r13, hi16(lr_scratch)
             ori r13, r13, lo16(lr_scratch)
             stw r12, (r13)

             ; then perform lr-storing jump to substitute
             lis r12, hi16(substitute)
             ori r12, r12, lo16(substitute)
             mtctr r12
             bctrl

             ; substitute routine has now been called, retrieve
             ; original lr, run the first n instructions, and then
             ; perform jump to the original code (with bias)

             lis r12, hi16(lr_scratch)
             ori r12, r12, lo16(lr_scratch)
             lwz r12, (r12)
             mtlr r12

             lis r12, hi16(original_with_bias)
             ori r12, r12, lo16(original_with_bias)
             mtctr r12

             ; copy here the original N instructions
                .
                .
                .

             ; jump
             bctr

          */

          substitute = sub->substitute;
          original_with_bias = sub->original + sub->len;
          lr_scratch = scratch++;

          newcode = scratch;

          if (sizeof(sub->scratch) - sub->len < 16 * 4)
            {
              printf("Before: Scratch memory area is too small for "
                     "hook routine.\n");
              continue;
            }

          printf("Before: original=%p, original_with_vias=%p, "
                 "substitute=%p, lr_scratch=%p, newcode=%p, "
                 "no trap.\n",
                 sub->original, original_with_bias, substitute,
                 lr_scratch, newcode);

          /* move substitute addr to ctr (early to allow
               prefetching) */
          *scratch++ = lis(r12, substitute);
          *scratch++ = ori(r12, r12, substitute);
          *scratch++ = mtctr(r12);

          /* save lr */
          *scratch++ = mflr(r12);
          *scratch++ = lis(r13, lr_scratch);
          *scratch++ = ori(r13, r13, lr_scratch);
          *scratch++ = stw(r12, r13, 0);

            /* call substitute */
          *scratch++ = bctrl();

          /* substitute has been called, restore lr */
          *scratch++ = lis(r12, lr_scratch);
          *scratch++ = ori(r12, r12, lr_scratch);
          *scratch++ = lwz(r12, r12, 0);
          *scratch++ = mtlr(r12);

            /* put biased original address to ctr */
          *scratch++ = lis(r12, original_with_bias);
          *scratch++ = ori(r12, r12, original_with_bias);
          *scratch++ = mtctr(r12);

          /* copy head */
          memcpy(scratch, sub->scratch, ssh_ppc_func_starts[i].len);
          scratch += ssh_ppc_func_starts[i].len / 4;

            /* perform jump */
          *scratch++ = bctr();

          flushi(newcode, scratch - newcode);
          break;

        case SSH_ATTACH_AFTER:

          /* First, call the original code, then run the hook
             routine. Notice that the return value of the hook
             overrides the original. Also, original routine arguments
             are not preserved.

                a: store original lr
                b: execute original first instructions
                c: jump to original code start (sans our hook), with lr store
                d: restore lr
                e: jump to hook routine (which returns through restored
                   lr to original caller)

             Problems:

                1. The original header stores lr, we have to store a
                   *new* lr before executing original instructions.

          */

          /* Actual code is like:

             ; put original with bias to ctr
             lis r12, hi16(original_with_bias)
             ori r12, r12, lo16(original_with_bias)
             mtctr r12

             ; save lr to lr_scratch
             mflr r12
             lis r13, hi16(lr_scratch)
             ori r13, r13, lo16(lr_scratch)
             stw r12, (r13)

             ; calculate new lr
             bl 4
             mflr r12
             addi r12, r12, return-.
             mtlr r12

             ; copy here original N instructions
                .
                .
                .

             ; call original
             bctrl

           return:

             ; substitute to ctr
             lis r12, hi16(substitute)
             ori r12, r12, lo16(substitute)
             mtctr r12

             ; retrieve lr
             lis r12, hi16(lr_scratch)
             ori r12, r12, lo16(lr_scratch)
             lwz r12, (r12)
             mtlr r12

             ; jump to substitute
             bctr

          */


          substitute = sub->substitute;
          original_with_bias = sub->original + sub->len;
          lr_scratch = scratch++;

          newcode = scratch;

          if (sizeof(sub->scratch) - sub->len < 20 * 4)
            {
              printf("Before: Scratch memory area is too small for "
                     "hook routine.\n");
              continue;
            }

          printf("After: original=%p, original_with_vias=%p, "
                 "substitute=%p, lr_scratch=%p, newcode=%p, "
                 "no trap.\n",
                 sub->original, original_with_bias, substitute,
                 lr_scratch, newcode);

          /* save lr */
          *scratch++ = mflr(r12);
          *scratch++ = lis(r13, lr_scratch);
          *scratch++ = ori(r13, r13, lr_scratch);
          *scratch++ = stw(r12, r13, 0);

            /* put biased original address to ctr */
          *scratch++ = lis(r12, original_with_bias);
          *scratch++ = ori(r12, r12, original_with_bias);
          *scratch++ = mtctr(r12);

          /* calculate new lr */
          *scratch++ = bl(4);
          *scratch++ = mflr(r12);
          *scratch++ = addi(r12, r12, ssh_ppc_func_starts[i].len + 4 * 4);
          *scratch++ = mtlr(r12);

            /* copy head */
          memcpy(scratch, sub->scratch, ssh_ppc_func_starts[i].len);
          scratch += ssh_ppc_func_starts[i].len / 4;

            /* call original */
          *scratch++ = bctrl();

          /* original has been called, load ctr (we do this early,
               as it makes prefetching ctr target possible) */
          *scratch++ = lis(r12, substitute);
          *scratch++ = ori(r12, r12, substitute);
          *scratch++ = mtctr(r12);

          /* restore lr */
          *scratch++ = lis(r12, lr_scratch);
          *scratch++ = ori(r12, r12, lr_scratch);
          *scratch++ = lwz(r12, r12, 0);
          *scratch++ = mtlr(r12);

            /* jump to substitute */
          *scratch++ = bctr();

          flushi(newcode, scratch - newcode);
          break;

        default:
          printf("ssh_attach_attach_substitutions: bad type %d\n", sub->type);
          break;
        }

      if (!newcode)
        {
          printf("ssh_attach_attach_substitutions: no hook code target!\n");
          continue;
        }

      free_register = ssh_ppc_func_starts[i].free_register;

      /* rX = free_register */

      /* lis rX, hi16(newcode) */
      origcode[0] = lis(free_register, newcode);

      /* ori rX, rX, lo16(newcode) */
      origcode[1] = ori(free_register, free_register, newcode);

      /* mtctr rX */
      origcode[2] = mtctr(free_register);

      /* bctr */
      origcode[3] = bctr();

      if (trap)
        {
          printf("Adding trap to %p.\n", &origcode[4]);

          memcpy(sub->scratch + ssh_ppc_func_starts[i].len,
                 sub->original + sub->len, 4);
          sub->len += 4;

          origcode[4] = trap();
        }

      flushi(origcode, 16);

#if 0
      dumpi("altered ", origcode, 4);
#endif
    }

  splx(x);
}

void ssh_detach_substitutions()
{
  int x;
  unsigned int *origcode;
  SshAttachRec *sub;

  x = splhigh();

  for (sub = ssh_get_substitutions(); sub->type != SSH_ATTACH_END; sub++)
    {
      printf("Detaching: original=%p, len=%ld\n",
             sub->original, sub->len);

      memcpy(sub->original, sub->scratch, sub->len);
      origcode = sub->original;

      flushi(origcode, 16);

#if 0
      dumpi("restored", origcode, 4);
#endif
    }

  splx(x);
}
