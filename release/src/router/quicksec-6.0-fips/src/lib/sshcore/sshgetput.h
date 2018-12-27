/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Macros for storing and retrieving integers in MSB first and LSB first
   order.  This interface can also be called from an other thread than
   the SSH main thread.

   <keywords getput, utility functions/getput, storing integers,
   retrieving integers, integer/storing & retrieving>
*/

#ifndef SSHGETPUT_H
#define SSHGETPUT_H

#define SSH_GET_8BIT(cp) (*(unsigned char *)(cp))
#define SSH_PUT_8BIT(cp, value) (*(unsigned char *)(cp)) = \
  (unsigned char)(value)
#define SSH_GET_4BIT_LOW(cp) (*(unsigned char *)(cp) & 0x0f)
#define SSH_GET_4BIT_HIGH(cp) ((*(unsigned char *)(cp) >> 4) & 0x0f)
#define SSH_PUT_4BIT_LOW(cp, value) (*(unsigned char *)(cp) = \
  (unsigned char)((*(unsigned char *)(cp) & 0xf0) | ((value) & 0x0f)))
#define SSH_PUT_4BIT_HIGH(cp, value) (*(unsigned char *)(cp) = \
  (unsigned char)((*(unsigned char *)(cp) & 0x0f) | (((value) & 0x0f) << 4)))

#ifdef SSHUINT64_IS_64BITS

#ifndef ASM_PLATFORM_OCTEON
#define SSH_GET_64BIT(cp) (((SshUInt64)SSH_GET_32BIT((cp)) << 32) | \
                           ((SshUInt64)SSH_GET_32BIT((cp) + 4)))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), (SshUInt32)((SshUInt64)(value) >> 32)); \
  SSH_PUT_32BIT((cp) + 4, (SshUInt32)(value)); } while (0)
#endif /* ASM_PLATFORM_OCTEON */

#define SSH_GET_64BIT_LSB_FIRST(cp) \
     (((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp))) | \
      ((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp) + 4) << 32))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, (SshUInt32)((SshUInt64)(value) >> 32)); \
} while (0)

#define SSH_GET_40BIT(cp) (((SshUInt64)SSH_GET_8BIT((cp)) << 32) | \
                           ((SshUInt64)SSH_GET_32BIT((cp) + 1)))
#define SSH_PUT_40BIT(cp, value) do { \
  SSH_PUT_8BIT((cp), (SshUInt32)((SshUInt64)(value) >> 32)); \
  SSH_PUT_32BIT((cp) + 1, (SshUInt32)(value)); } while (0)

#define SSH_GET_40BIT_LSB_FIRST(cp) \
     (((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp))) | \
      ((SshUInt64)SSH_GET_8BIT((cp) + 4) << 32))
#define SSH_PUT_40BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_8BIT((cp) + 4, (SshUInt32)((SshUInt64)(value) >> 32)); } while (0)

#else /* SSHUINT64_IS_64BITS */

#define SSH_GET_64BIT(cp) ((SshUInt64)SSH_GET_32BIT((cp) + 4))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), 0L); \
  SSH_PUT_32BIT((cp) + 4, (SshUInt32)(value)); } while (0)
#define SSH_GET_64BIT_LSB_FIRST(cp) ((SshUInt64)SSH_GET_32BIT((cp)))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, 0L); } while (0)

#define SSH_GET_40BIT(cp) ((SshUInt64)SSH_GET_32BIT((cp) + 1))
#define SSH_PUT_40BIT(cp, value) do { \
  SSH_PUT_8BIT((cp), 0); \
  SSH_PUT_32BIT((cp) + 1, (SshUInt32)(value)); } while (0)
#define SSH_GET_40BIT_LSB_FIRST(cp) ((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp)))
#define SSH_PUT_40BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_8BIT((cp) + 4, 0); } while (0)

#endif /* SSHUINT64_IS_64BITS */

#define SSH_GET_24BIT(cp) \
     ((((unsigned long) ((unsigned char *) (cp))[0]) << 16) | \
      (((unsigned long) ((unsigned char *) (cp))[1]) << 8) | \
      ((unsigned long) ((unsigned char *) (cp))[2]))
#define SSH_GET_24BIT_LSB_FIRST(cp) \
     ((((unsigned long) ((unsigned char *) (cp))[2]) << 16) | \
      (((unsigned long) ((unsigned char *) (cp))[1]) << 8) | \
      ((unsigned long) ((unsigned char *) (cp))[0]))
#define SSH_PUT_24BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[2] = (unsigned char)(value); } while (0)
#define SSH_PUT_24BIT_LSB_FIRST(cp, value) do { \
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[0] = (unsigned char)(value); } while (0)

/*------------ macros for storing/extracting msb first words -------------*/


#ifdef ASM_PLATFORM_OCTEON

#define SSH_GET_64BIT(cp) (*(SshUInt64 *)(cp))
#define SSH_GET_32BIT(cp) (*(SshUInt32 *)(cp))
#define SSH_GET_16BIT(cp) (*(SshUInt16 *)(cp))
#define SSH_PUT_64BIT(cp, value) (*(SshUInt64 *)(cp)) = (SshUInt64)(value)
#define SSH_PUT_32BIT(cp, value) (*(SshUInt32 *)(cp)) = (SshUInt32)(value)
#define SSH_PUT_16BIT(cp, value) (*(SshUInt16 *)(cp)) = (SshUInt16)(value)

#else /* ASM_PLATFORM_OCTEON */

#define SSH_GET_32BIT(cp) \
  ((((unsigned long)((unsigned char *)(cp))[0]) << 24) | \
   (((unsigned long)((unsigned char *)(cp))[1]) << 16) | \
   (((unsigned long)((unsigned char *)(cp))[2]) << 8) | \
   ((unsigned long)((unsigned char *)(cp))[3]))

#define SSH_GET_16BIT(cp) \
     ((SshUInt16) ((((unsigned long)((unsigned char *)(cp))[0]) << 8) | \
      ((unsigned long)((unsigned char *)(cp))[1])))

#define SSH_PUT_32BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 24); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[3] = (unsigned char)(value); } while (0)

#define SSH_PUT_16BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[1] = (unsigned char)(value); } while (0)

#endif /* ASM_PLATFORM_OCTEON */

/*------------ macros for storing/extracting lsb first words -------------*/

#define SSH_GET_32BIT_LSB_FIRST(cp) \
  (((unsigned long)((unsigned char *)(cp))[0]) | \
  (((unsigned long)((unsigned char *)(cp))[1]) << 8) | \
  (((unsigned long)((unsigned char *)(cp))[2]) << 16) | \
  (((unsigned long)((unsigned char *)(cp))[3]) << 24))

#define SSH_GET_16BIT_LSB_FIRST(cp) \
  ((SshUInt16) (((unsigned long)((unsigned char *)(cp))[0]) | \
  (((unsigned long)((unsigned char *)(cp))[1]) << 8)))

#define SSH_PUT_32BIT_LSB_FIRST(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)(value); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[3] = (unsigned char)((value) >> 24); } while (0)

#define SSH_PUT_16BIT_LSB_FIRST(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)(value); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); } while (0)

#if defined(_MSC_VER) && !defined(_WIN64) && !defined(_WIN32_WCE) && \
  (defined (WIN32) || defined(KERNEL) && (defined(WIN95) || defined(WINNT)))
/* optimizations for microsoft visual C++ */

#undef SSH_GET_32BIT_LSB_FIRST
#undef SSH_GET_16BIT_LSB_FIRST
#undef SSH_PUT_32BIT_LSB_FIRST
#undef SSH_PUT_16BIT_LSB_FIRST
#undef SSH_GET_32BIT
#undef SSH_GET_16BIT
#undef SSH_PUT_32BIT
#undef SSH_PUT_16BIT

#define SSH_GET_32BIT_LSB_FIRST(cp) (*(SshUInt32 *)(cp))
#define SSH_GET_16BIT_LSB_FIRST(cp) (*(SshUInt16 *)(cp))
#define SSH_PUT_32BIT_LSB_FIRST(cp,x) (*(SshUInt32 *)(cp)) = (x)
#define SSH_PUT_16BIT_LSB_FIRST(cp,x) (*(SshUInt16 *)(cp)) = (x)

/* Getting bytes msb first */
#define SSH_GET_16BIT(cp) \
     ((SshUInt16) ((((unsigned long)((unsigned char *)(cp))[0]) << 8) | \
      ((unsigned long)((unsigned char *)(cp))[1])))

#define SSH_PUT_16BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[1] = (unsigned char)(value); } while (0)


#pragma warning( disable : 4035 )
static __inline void SSH_PUT_32BIT(void *cp, unsigned long value)
{
  __asm
    {
      mov eax, value
      mov ebx, cp
#ifdef NO_386_COMPAT
      bswap eax
#else
      rol ax,8
      rol eax,16
      rol ax,8
#endif
      mov [ebx], eax
    }
}

static __inline SshUInt32 SSH_GET_32BIT(const char *cp)
{
  __asm
    {
      mov ebx, cp
      mov eax, [ebx]
#ifdef NO_386_COMPAT
      bswap eax
#else
      rol ax,8
      rol eax,16
      rol ax,8
#endif

    }
  /* eax is interpreted as return value */
}

#pragma warning( default : 4035 )

#else

/* This `|| 1' thing disables the GCC i386 optimizations.  They seem
   to be very mysticly broken so it is better to disable them. */
#if !defined(NO_INLINE_GETPUT) && defined(__i386__) && defined(__GNUC__)

/* Intel i386 processor, using AT&T syntax for gcc compiler. */

#undef SSH_GET_32BIT_LSB_FIRST
#undef SSH_GET_16BIT_LSB_FIRST
#undef SSH_PUT_32BIT_LSB_FIRST
#undef SSH_PUT_16BIT_LSB_FIRST
#undef SSH_GET_32BIT
#undef SSH_PUT_32BIT

/* LSB first cases could be done efficiently also with just C definitions
   to just copy values.  i386 has no alignment restrictions. */

#define SSH_GET_32BIT_LSB_FIRST(cp) (*(SshUInt32 *)(cp))
#define SSH_GET_16BIT_LSB_FIRST(cp) (*(SshUInt16 *)(cp))
#define SSH_PUT_32BIT_LSB_FIRST(cp,x) (*(SshUInt32 *)(cp)) = (x)
#define SSH_PUT_16BIT_LSB_FIRST(cp,x) (*(SshUInt16 *)(cp)) = (x)

/* Getting bytes MSB first */

#ifdef NO_386_COMPAT
#define SSH_GET_32BIT(cp) \
({  \
  SshUInt32 __v__; \
  __asm__ volatile ("movl (%1), %%ecx; " \
                    "bswap %%ecx;" \
          : "=c" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})
#else
#define SSH_GET_32BIT(cp) \
({  \
  SshUInt32 __v__; \
  __asm__ volatile ("movl (%1), %%ecx; rolw $8, %%cx; " \
                    "roll $16, %%ecx; rolw $8, %%cx;" \
          : "=c" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})

#endif
#if 0
#define SSH_GET_16BIT(cp) \
({ \
  SshUInt16 __v__; \
  __asm__ volatile ("movw (%1), %0; rolw $8, %0;" \
          : "=r" (__v__) \
          : "r" (cp) : "cc"); \
  __v__; \
})
#endif

#define SSH_PUT_32BIT(cp, v) \
__asm__ volatile ("movl %1, %%ecx; rolw $8, %%cx; " \
                  "roll $16, %%ecx; rolw $8, %%cx;" \
         "movl %%ecx, (%0);" \
         : : "S" (cp), "a" ((SshUInt32) (v)) : "%ecx", "memory", "cc")

#if 0
/* Note that the following code is broken on newer GCCs
   with optimizations, as it does not tell that the code
   globbers ax. This could be fixed by adding rolw $8, %%ax; at
   the end which would set the ax back to its original
   state. */
#define SSH_PUT_16BIT(cp,v)  \
__asm__ volatile ("rolw $8, %%ax; movw %%ax, (%0); " \
        : : "S" (cp), "a" ((SshUInt16) (v)) : "memory", "cc")
#endif

#endif /* __i386__ */

#endif /* GETPUT_MSVC */

#endif /* GETPUT_H */
