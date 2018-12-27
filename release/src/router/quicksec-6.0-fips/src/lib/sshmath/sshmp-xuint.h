/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple extension for sshmp-integer.h that gives exactly 64 and
   128 bit integers without any dynamic memory management and using
   only minimal amount of memory. 64bit integer is implemented using
   built-in 64bit type if such type exists.
   Unlike other parts of the mathematics library, this file is also
   usable in kernel space.
*/

#ifndef SSHMP_XUINT_H
#define SSHMP_XUINT_H

#include "sshincludes.h"
#include "sshmp-kernel.h"

#if SSH_WORD_BITS != 32 && SSH_WORD_BITS != 64
#error "This code assumes word size of 32 or 64 bits."
#endif /* SSH_WORD_BITS != 32 && SSH_WORD_BITS != 64 */

/* Macro for implementing and, or and xor operations */
#define SSH_XUINT_OP(r,a_,b_,s,op) \
do { int m_i; for(m_i=0;m_i<s;m_i++){r[m_i]=(a_)[m_i] op (b_)[m_i];} } while(0)

#if defined(SSHUINT64_IS_64BITS) && (SIZEOF_LONG == 8 || \
    (SIZEOF_LONG < 8 && defined(HAVE_LONG_LONG) && (SIZEOF_LONG_LONG == 8))) \
    && !defined(SSH_XUINT64_FORCE_32BIT_OPERATIONS)
/* We have 64-bit type available, use it for SshXUInt64. */

typedef SshUInt64 SshXUInt64;

#define SSH_XUINT64_ASSIGN(r,a_) do {(r) = (a_); } while(0)
#define SSH_XUINT64_ADD(r,a_,b_) do { r=(a_) + (b_); } while(0)
#define SSH_XUINT64_SUB(r,a_,b_) do { r=(a_) - (b_); } while(0)
#define SSH_XUINT64_AND(r,a_,b_) do { r=(a_) & (b_); } while(0)
#define SSH_XUINT64_OR(r,a_,b_) do { r=(a_) | (b_); } while(0)
#define SSH_XUINT64_XOR(r,a_,b_) do { r=(a_) ^ (b_); } while(0)
#define SSH_XUINT64_NOT(r,a_) do { r=~(a_); } while(0)
#define SSH_XUINT64_ZERO(r) do { r=0; } while(0)
#define SSH_XUINT64_BUILD(r,a_32,b_32) do { \
                                           r = ((a_32)&0xffffffffu)\
                                               |(((SshXUInt64)(b_32)\
                                               &0xffffffffu)<<32);\
                                         } while(0)
#define SSH_XUINT64_STATIC_BUILD(a_32,b_32) ((a_32)&0xffffffffu) \
                                            |(((SshXUInt64)(b_32)&\
                                            0xffffffffu)<<32)
#define SSH_XUINT64_EXTRACT_UINT32(r,pos) ((SshUInt32)((r)>>(32*pos)))
/* SLL, SLR, ROL, and ROR only need to work with values 1 <= i <= 31. */
#define SSH_XUINT64_ROL(r,a_,i) do { r=((a_) << (i)) | ((a_) >> (64-(i))); \
                                   } while(0)
#define SSH_XUINT64_ROR(r,a_,i) do { r=((a_) >> (i)) | ((a_) << (64-(i))); \
                                   } while(0)
#define SSH_XUINT64_SLL(r,a_,i) do { r=(a_) << (i); } while(0)
#define SSH_XUINT64_SLR(r,a_,i) do { r=(a_) >> (i); } while(0)
#else
#define SSH_XUINT64_WORDS ((64+SSH_WORD_BITS-1)/SSH_WORD_BITS)
typedef SshWord SshXUInt64[SSH_XUINT64_WORDS];
#define SSH_XUINT64_EMULATED_2X32
#define SSH_XUINT64_ASSIGN(r,a_) \
do { memcpy((r), (a_), sizeof(SshXUInt64)); } while (0)
#define SSH_XUINT64_ADD(r,a_,b_) \
do { ssh_mpk_add((r),((void*)(a_)),SSH_XUINT64_WORDS, \
     ((void*)(b_)),SSH_XUINT64_WORDS); \
   } while(0)
#define SSH_XUINT64_SUB(r,a_,b_) \
do { ssh_mpk_sub((r),((void*)(a_)),SSH_XUINT64_WORDS, \
     ((void*)(b_)),SSH_XUINT64_WORDS); \
   } while(0)
#define SSH_XUINT64_AND(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT64_WORDS,&)
#define SSH_XUINT64_OR(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT64_WORDS,|)
#define SSH_XUINT64_XOR(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT64_WORDS,^)
#define SSH_XUINT64_NOT(r,a_) \
do { (r)[0] = ~(a_)[0]; (r)[1] = ~(a_)[1]; } while(0)
#define SSH_XUINT64_ZERO(r) SSH_XUINT_OP(r,r,r,SSH_XUINT64_WORDS,^)
void ssh_xuint64_build(SshXUInt64 r,SshUInt32 a,SshUInt32 b);
#define SSH_XUINT64_BUILD(r,a_32,b_32) ssh_xuint64_build(r,a_32,b_32)
#define SSH_XUINT64_STATIC_BUILD(a_32,b_32) { (a_32)&0xffffffffu, \
                                              (b_32)&0xffffffffu }

#define SSH_XUINT64_EXTRACT_UINT32(r,pos) ((SshUInt32)((r)[(pos)]))
/* SLL, SLR, ROL, and ROR only need to work with values 1 <= i <= 31. */
#define SSH_XUINT64_ROL(r,a_,i) \
do { SshUInt32 t; \
     t = ((a_)[0] << (i)) | ((a_)[1] >> (32-i)); \
     r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (32-i)); \
     r[0] = t; \
   } while(0)
#define SSH_XUINT64_ROR(r,a_,i) \
do { SshUInt32 t; \
     t = ((a_)[0] >> (i)) | ((a_)[1] << (32-i)); \
     r[1] = ((a_)[1] >> (i)) | ((a_)[0] << (32-i)); \
     r[0] = t; \
   } while(0)
#define SSH_XUINT64_SLL(r,a_,i) \
do { r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (32-i)); \
     r[0] = (a_)[0] << (i); \
   } while(0)
#define SSH_XUINT64_SLR(r,a_,i) \
do { r[0] = ((a_)[0] >> (i)) | ((a_)[1] << (32-i)); \
     r[1] = (a_)[1] >> (i); \
   } while(0)
#endif

#define SSH_XUINT64_TO_UINT32_SATURATED(r) \
((SSH_XUINT64_EXTRACT_UINT32((r),1) == 0 ?\
  SSH_XUINT64_EXTRACT_UINT32((r),0) : (SshUInt32) 0xffffffffU)

#include "sshgetput.h"
#define SSH_XUINT64_GET(r,cp) SSH_XUINT64_BUILD(r,\
                                SSH_GET_32BIT(((unsigned char*)(cp))+4),\
                                SSH_GET_32BIT(((unsigned char*)(cp))))

#define SSH_XUINT64_PUT(r,cp)                           \
do                                                      \
  {                                                     \
    SSH_PUT_32BIT((((unsigned char*)(cp))+4),           \
    SSH_XUINT64_EXTRACT_UINT32(r,0));                   \
    SSH_PUT_32BIT((((unsigned char*)(cp))),             \
    SSH_XUINT64_EXTRACT_UINT32(r,1));                   \
  }                                                     \
while (0)

#define SSH_XUINT64_CMP(a,b_)                                   \
(SSH_XUINT64_CMP_HELPER(SSH_XUINT64_EXTRACT_UINT32((a_), 0),    \
                        SSH_XUINT64_EXTRACT_UINT32((b_), 0)):   \
 SSH_XUINT64_CMP_HELPER(SSH_XUINT64_EXTRACT_UINT32((a_), 1),    \
                        SSH_XUINT64_EXTRACT_UINT32((b_), 1)):0)

#define SSH_XUINT64_CMP_HELPER(a,b_)            \
((a_) != (b_))? ((a_) < (b_) ? -1 : 1)

/* ------------------------------------------------------------------- */

/* Emulation for 128-bit (unsigned) integers. Some platforms currently
   have either __uint128 or __uint128_t etc. but we do not provide special
   support for those datatypes for now... */
#define SSH_XUINT128_WORDS ((128+SSH_WORD_BITS-1)/SSH_WORD_BITS)

typedef SshWord SshXUInt128[SSH_XUINT128_WORDS];

#define SSH_XUINT128_ADD(r,a_,b_) do { ssh_mpk_add((r),(a_),\
                                                 SSH_XUINT128_WORDS,(b_),\
                                                 SSH_XUINT128_WORDS); }while(0)
#define SSH_XUINT128_SUB(r,a_,b_) do { ssh_mpk_sub((r),(a_),\
                                                 SSH_XUINT128_WORDS,(b_),\
                                                 SSH_XUINT128_WORDS); }while(0)
#define SSH_XUINT128_AND(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT128_WORDS,&)
#define SSH_XUINT128_OR(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT128_WORDS,|)
#define SSH_XUINT128_XOR(r,a_,b_) SSH_XUINT_OP(r,a_,b_,SSH_XUINT128_WORDS,^)
#define SSH_XUINT128_ZERO(r) do { SSH_XUINT128_BUILD((r),0,0,0,0); } while(0)
#define SSH_XUINT128_ASSIGN(r,a_) \
do { memcpy((r), (a_), sizeof(SshXUInt128)); } while (0)
#if SSH_WORD_BITS == 32
#define SSH_XUINT128_BUILD(r,a_32,b_32,c_32,d_32) do { \
                                                  (r)[0] = (a_32)&0xffffffffu;\
                                                  (r)[1] = (b_32)&0xffffffffu;\
                                                  (r)[2] = (c_32)&0xffffffffu;\
                                                  (r)[3] = (d_32)&0xffffffffu;\
                                             } while(0)
#define SSH_XUINT128_EXTRACT_UINT32(r,pos) ((SshUInt32)((r)[(pos)]))

/* SLL, SLR, ROL, and ROR only need to work with values 1 <= i <= 31. */
#define SSH_XUINT128_ROL(r,a_,i)                     \
do { r[3] = ((a_)[3] << (i)) | ((a_)[2] >> (32-i)); \
     r[2] = ((a_)[2] << (i)) | ((a_)[1] >> (32-i)); \
     r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (32-i)); \
     r[0] = ((a_)[0] << (i)) | ((a_)[3] >> (32-i)); \
   } while(0)
#define SSH_XUINT128_ROR(r,a_,i)                    \
do { r[0] = ((a_)[0] >> (i)) | ((a_)[1] << (32-i)); \
     r[1] = ((a_)[1] >> (i)) | ((a_)[2] << (32-i)); \
     r[2] = ((a_)[2] >> (i)) | ((a_)[3] << (32-i)); \
     r[3] = ((a_)[3] >> (i)) | ((a_)[0] << (32-i)); \
   } while(0)
#define SSH_XUINT128_SLL(r,a_,i)                    \
do { r[3] = ((a_)[3] << (i)) | ((a_)[2] >> (32-i)); \
     r[2] = ((a_)[2] << (i)) | ((a_)[1] >> (32-i)); \
     r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (32-i)); \
     r[0] = (a_)[0] << (i);                         \
   } while(0)
#define SSH_XUINT128_SLR(r,a_,i)                    \
do { r[0] = ((a_)[0] >> (i)) | ((a_)[1] << (32-i)); \
     r[1] = ((a_)[1] >> (i)) | ((a_)[2] << (32-i)); \
     r[2] = ((a_)[2] >> (i)) | ((a_)[3] << (32-i)); \
     r[3] = (a_)[3] >> (i);                         \
   } while(0)

#else
# if SSH_WORD_BITS == 64
# define SSH_XUINT128_BUILD(r,a_32,b_32,c_32,d_32) do { \
                                                  (r)[0] =((a_32)&0xffffffffu)\
                                                   |(((SshUInt64)(b_32))<<32);\
                                                  (r)[1] =((c_32)&0xffffffffu)\
                                                   |(((SshUInt64)(d_32))<<32);\
                                             } while(0)
# define SSH_XUINT128_EXTRACT_UINT32(r,pos) \
((SshUInt32)((((SshUInt64)((r)[(pos)/2]))>>(32*(pos&1)))&0xffffffffu))

/* SLL, SLR, ROL, and ROR only need to work with values 1 <= i <= 31. */
#define SSH_XUINT128_ROL(r,a_,i)                    \
do { r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (64-i)); \
     r[0] = ((a_)[0] << (i)) | ((a_)[1] >> (64-i)); \
   } while(0)
#define SSH_XUINT128_ROR(r,a_,i)                    \
do { r[1] = ((a_)[1] >> (i)) | ((a_)[0] << (64-i)); \
     r[0] = ((a_)[0] >> (i)) | ((a_)[1] << (64-i)); \
   } while(0)
#define SSH_XUINT128_SLL(r,a_,i)                    \
do { r[1] = ((a_)[1] << (i)) | ((a_)[0] >> (64-i)); \
     r[0] = (a_)[0] << (i);                         \
   } while(0)
#define SSH_XUINT128_SLR(r,a_,i)                    \
do { r[0] = ((a_)[0] >> (i)) | ((a_)[1] << (64-i)); \
     r[1] = (a_)[1] >> (i);                         \
   } while(0)

# else
# error "SshXUInt128 only implemented for platforms with 32 or 64-bit long."
# endif
#endif

#define SSH_XUINT128_TO_UINT32_SATURATED(r) \
((SSH_XUINT128_EXTRACT_UINT32((r),1) == 0 && \
  SSH_XUINT128_EXTRACT_UINT32((r),2) == 0 && \
  SSH_XUINT128_EXTRACT_UINT32((r),3) == 0) ? \
  SSH_XUINT128_EXTRACT_UINT32((r),0) : (SshUInt32) 0xffffffffU)

#include "sshgetput.h"
#define SSH_XUINT128_GET(r,cp) SSH_XUINT128_BUILD(r,\
                                SSH_GET_32BIT(((unsigned char*)(cp))+12),\
                                SSH_GET_32BIT(((unsigned char*)(cp))+8),\
                                SSH_GET_32BIT(((unsigned char*)(cp))+4),\
                                SSH_GET_32BIT(((unsigned char*)(cp))))

#define SSH_XUINT128_PUT(r,cp)                          \
do                                                      \
  {                                                     \
    SSH_PUT_32BIT((((unsigned char*)(cp))+12),          \
    SSH_XUINT128_EXTRACT_UINT32(r,0));                  \
    SSH_PUT_32BIT((((unsigned char*)(cp))+8),           \
    SSH_XUINT128_EXTRACT_UINT32(r,1));                  \
    SSH_PUT_32BIT((((unsigned char*)(cp))+4),           \
    SSH_XUINT128_EXTRACT_UINT32(r,2));                  \
    SSH_PUT_32BIT((((unsigned char*)(cp))),             \
    SSH_XUINT128_EXTRACT_UINT32(r,3));                  \
  }                                                     \
while (0)

#include "sshinet.h"

#define SSH_XUINT128_FROM_IP(i, r)                                   \
do                                                                   \
  {                                                                  \
    switch(SSH_IP_ADDR_LEN((r)))                                     \
      {                                                              \
      case 4:                                                        \
        SSH_XUINT128_BUILD((i), SSH_IP4_TO_INT((r)), 0, 0, 0);       \
        break;                                                       \
      case 16:                                                       \
        {                                                            \
          unsigned char sshxuint128_ip_input_buffer[16];             \
          int sshxuint128_addr_length;                               \
          SSH_IP_ENCODE((r), sshxuint128_ip_input_buffer,            \
                             sshxuint128_addr_length);               \
          SSH_XUINT128_GET((i), sshxuint128_ip_input_buffer);        \
        }                                                            \
        break;                                                       \
      default:                                                       \
        SSH_XUINT128_ZERO((i));                                      \
      }                                                              \
  }                                                                  \
while (0)

#define SSH_XUINT128_TO_IP(i, r, length)                                \
do                                                                      \
  {                                                                     \
    if ((length) == 4)                                                  \
      {                                                                 \
        SSH_INT_TO_IP4((r), SSH_XUINT128_EXTRACT_UINT32((i), 0));       \
      }                                                                 \
    else if ((length) == 16)                                            \
      {                                                                 \
        unsigned char sshxuint128_ip_input_buffer[16];                  \
        SSH_XUINT128_PUT((i), sshxuint128_ip_input_buffer);             \
        SSH_IP_DECODE((r), sshxuint128_ip_input_buffer, 16 );           \
      }                                                                 \
    else                                                                \
      {                                                                 \
        SSH_IP_UNDEFINE((r));                                           \
      }                                                                 \
  }                                                                     \
while (0)

#define SSH_XUINT128_CMP(a,b_)                                  \
(SSH_XUINT128_CMP_HELPER(SSH_XUINT128_EXTRACT_UINT32((a_), 0),  \
                        SSH_XUINT128_EXTRACT_UINT32((b_), 0)):  \
 SSH_XUINT128_CMP_HELPER(SSH_XUINT128_EXTRACT_UINT32((a_), 1),  \
                        SSH_XUINT128_EXTRACT_UINT32((b_), 1)):  \
 SSH_XUINT128_CMP_HELPER(SSH_XUINT128_EXTRACT_UINT32((a_), 2),  \
                        SSH_XUINT128_EXTRACT_UINT32((b_), 2)):  \
 SSH_XUINT128_CMP_HELPER(SSH_XUINT128_EXTRACT_UINT32((a_), 3),  \
                        SSH_XUINT128_EXTRACT_UINT32((b_), 3)):0)

#define SSH_XUINT128_CMP_HELPER(a,b_)           \
((a_) != (b_))? ((a_) < (b_) ? -1 : 1)

#endif /* SSHMP_XUINT_H */
