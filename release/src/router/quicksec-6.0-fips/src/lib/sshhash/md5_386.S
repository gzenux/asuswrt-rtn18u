/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   MD5 transform in GCC assembler

   Optimized for pentium processors (somewhat). More optimizations might
   be done combining sequences of MD5STEP's.

   Note: As far as I have thought about it you could actually quite easily
   interleave consecutive steps. Thus saving few clock cycles here and
   there. Possibly 10 - 20 % speed-up is possible, but it doesn't seem
   very simple with macros.
*/

.file "md5_386.S"
.text
	.align 2
.globl ssh_md5_transform
	.type ssh_md5_transform,@function
.globl _ssh_md5_transform
	.type _ssh_md5_transform,@function

ssh_md5_transform:
_ssh_md5_transform:
	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi

#define BUF   8(%ebp)
#define INEXT 12(%ebp)

	/* Definitions of four basic MD5 steps. */

#define MD5STEPF1(w, t, x, y, z, buffer, data, s) \
      	movl y, t; \
	addl buffer, w; \
	xorl z, t; \
	addl data, w; \
	andl x, t; \
	xorl z, t; \
	addl t, w; \
	roll s, w; \
	addl x, w;

#define MD5STEPF2(w, t, x, y, z, buffer, data, s) \
      	movl x, t; \
	addl buffer, w; \
	xorl y, t; \
	addl data, w; \
	andl z, t; \
	xorl y, t; \
	addl t, w; \
	roll s, w; \
	addl x, w;

#define MD5STEPF3(w, t, x, y, z, buffer, data, s) \
	movl x, t; \
	addl buffer, w; \
	xorl y, t; \
	addl data, w; \
	xorl z, t; \
	addl t, w; \
	roll s, w; \
	addl x, w;

#define MD5STEPF4(w, t, x, y, z, buffer, data, s) \
	movl z, t; \
	addl buffer, w; \
	notl t; \
	addl data, w; \
	orl  x, t; \
	xorl y, t; \
	addl t, w; \
	roll s, w; \
	addl x, w;

	/* Set esi */
	movl INEXT, %esi

	/* Set edi */
	movl BUF, %edi

	/* Copy */
	movl 0(%edi), %eax
	movl 4(%edi), %ebx
	movl 8(%edi), %ecx
	movl 12(%edi), %edx

	/* Actual hashing */

	MD5STEPF1(%eax, %edi, %ebx, %ecx, %edx, 0*4(%esi), $0xd76aa478, $7);
       	MD5STEPF1(%edx, %edi, %eax, %ebx, %ecx, 1*4(%esi), $0xe8c7b756, $12);
        MD5STEPF1(%ecx, %edi, %edx, %eax, %ebx, 2*4(%esi), $0x242070db, $17);
        MD5STEPF1(%ebx, %edi, %ecx, %edx, %eax, 3*4(%esi), $0xc1bdceee, $22);
        MD5STEPF1(%eax, %edi, %ebx, %ecx, %edx, 4*4(%esi), $0xf57c0faf, $7);
        MD5STEPF1(%edx, %edi, %eax, %ebx, %ecx, 5*4(%esi), $0x4787c62a, $12);
        MD5STEPF1(%ecx, %edi, %edx, %eax, %ebx, 6*4(%esi), $0xa8304613, $17);
        MD5STEPF1(%ebx, %edi, %ecx, %edx, %eax, 7*4(%esi), $0xfd469501, $22);
        MD5STEPF1(%eax, %edi, %ebx, %ecx, %edx, 8*4(%esi), $0x698098d8, $7);
        MD5STEPF1(%edx, %edi, %eax, %ebx, %ecx, 9*4(%esi), $0x8b44f7af, $12);
        MD5STEPF1(%ecx, %edi, %edx, %eax, %ebx, 10*4(%esi), $0xffff5bb1, $17);
        MD5STEPF1(%ebx, %edi, %ecx, %edx, %eax, 11*4(%esi), $0x895cd7be, $22);
        MD5STEPF1(%eax, %edi, %ebx, %ecx, %edx, 12*4(%esi), $0x6b901122, $7);
        MD5STEPF1(%edx, %edi, %eax, %ebx, %ecx, 13*4(%esi), $0xfd987193, $12);
        MD5STEPF1(%ecx, %edi, %edx, %eax, %ebx, 14*4(%esi), $0xa679438e, $17);
        MD5STEPF1(%ebx, %edi, %ecx, %edx, %eax, 15*4(%esi), $0x49b40821, $22);

        MD5STEPF2(%eax, %edi, %ebx, %ecx, %edx, 1*4(%esi), $0xf61e2562, $5);
        MD5STEPF2(%edx, %edi, %eax, %ebx, %ecx, 6*4(%esi), $0xc040b340, $9);
        MD5STEPF2(%ecx, %edi, %edx, %eax, %ebx, 11*4(%esi), $0x265e5a51, $14);
        MD5STEPF2(%ebx, %edi, %ecx, %edx, %eax, 0*4(%esi), $0xe9b6c7aa, $20);
        MD5STEPF2(%eax, %edi, %ebx, %ecx, %edx, 5*4(%esi), $0xd62f105d, $5);
        MD5STEPF2(%edx, %edi, %eax, %ebx, %ecx, 10*4(%esi), $0x02441453, $9);
        MD5STEPF2(%ecx, %edi, %edx, %eax, %ebx, 15*4(%esi), $0xd8a1e681, $14);
        MD5STEPF2(%ebx, %edi, %ecx, %edx, %eax, 4*4(%esi), $0xe7d3fbc8, $20);
        MD5STEPF2(%eax, %edi, %ebx, %ecx, %edx, 9*4(%esi), $0x21e1cde6, $5);
        MD5STEPF2(%edx, %edi, %eax, %ebx, %ecx, 14*4(%esi), $0xc33707d6, $9);
        MD5STEPF2(%ecx, %edi, %edx, %eax, %ebx, 3*4(%esi), $0xf4d50d87, $14);
        MD5STEPF2(%ebx, %edi, %ecx, %edx, %eax, 8*4(%esi), $0x455a14ed, $20);
        MD5STEPF2(%eax, %edi, %ebx, %ecx, %edx, 13*4(%esi), $0xa9e3e905, $5);
        MD5STEPF2(%edx, %edi, %eax, %ebx, %ecx, 2*4(%esi), $0xfcefa3f8, $9);
        MD5STEPF2(%ecx, %edi, %edx, %eax, %ebx, 7*4(%esi), $0x676f02d9, $14);
        MD5STEPF2(%ebx, %edi, %ecx, %edx, %eax, 12*4(%esi), $0x8d2a4c8a, $20);

        MD5STEPF3(%eax, %edi, %ebx, %ecx, %edx, 5*4(%esi), $0xfffa3942, $4);
        MD5STEPF3(%edx, %edi, %eax, %ebx, %ecx, 8*4(%esi), $0x8771f681, $11);
        MD5STEPF3(%ecx, %edi, %edx, %eax, %ebx, 11*4(%esi), $0x6d9d6122, $16);
        MD5STEPF3(%ebx, %edi, %ecx, %edx, %eax, 14*4(%esi), $0xfde5380c, $23);
        MD5STEPF3(%eax, %edi, %ebx, %ecx, %edx, 1*4(%esi), $0xa4beea44, $4);
        MD5STEPF3(%edx, %edi, %eax, %ebx, %ecx, 4*4(%esi), $0x4bdecfa9, $11);
        MD5STEPF3(%ecx, %edi, %edx, %eax, %ebx, 7*4(%esi), $0xf6bb4b60, $16);
        MD5STEPF3(%ebx, %edi, %ecx, %edx, %eax, 10*4(%esi), $0xbebfbc70, $23);
        MD5STEPF3(%eax, %edi, %ebx, %ecx, %edx, 13*4(%esi), $0x289b7ec6, $4);
        MD5STEPF3(%edx, %edi, %eax, %ebx, %ecx, 0*4(%esi), $0xeaa127fa, $11);
        MD5STEPF3(%ecx, %edi, %edx, %eax, %ebx, 3*4(%esi), $0xd4ef3085, $16);
        MD5STEPF3(%ebx, %edi, %ecx, %edx, %eax, 6*4(%esi), $0x04881d05, $23);
        MD5STEPF3(%eax, %edi, %ebx, %ecx, %edx, 9*4(%esi), $0xd9d4d039, $4);
        MD5STEPF3(%edx, %edi, %eax, %ebx, %ecx, 12*4(%esi), $0xe6db99e5, $11);
        MD5STEPF3(%ecx, %edi, %edx, %eax, %ebx, 15*4(%esi), $0x1fa27cf8, $16);
        MD5STEPF3(%ebx, %edi, %ecx, %edx, %eax, 2*4(%esi), $0xc4ac5665, $23);

        MD5STEPF4(%eax, %edi, %ebx, %ecx, %edx, 0*4(%esi), $0xf4292244, $6);
        MD5STEPF4(%edx, %edi, %eax, %ebx, %ecx, 7*4(%esi), $0x432aff97, $10);
        MD5STEPF4(%ecx, %edi, %edx, %eax, %ebx, 14*4(%esi), $0xab9423a7, $15);
        MD5STEPF4(%ebx, %edi, %ecx, %edx, %eax, 5*4(%esi), $0xfc93a039, $21);
        MD5STEPF4(%eax, %edi, %ebx, %ecx, %edx, 12*4(%esi), $0x655b59c3, $6);
        MD5STEPF4(%edx, %edi, %eax, %ebx, %ecx, 3*4(%esi), $0x8f0ccc92, $10);
        MD5STEPF4(%ecx, %edi, %edx, %eax, %ebx, 10*4(%esi), $0xffeff47d, $15);
        MD5STEPF4(%ebx, %edi, %ecx, %edx, %eax, 1*4(%esi), $0x85845dd1, $21);
        MD5STEPF4(%eax, %edi, %ebx, %ecx, %edx, 8*4(%esi), $0x6fa87e4f, $6);
        MD5STEPF4(%edx, %edi, %eax, %ebx, %ecx, 15*4(%esi), $0xfe2ce6e0, $10);
        MD5STEPF4(%ecx, %edi, %edx, %eax, %ebx, 6*4(%esi), $0xa3014314, $15);
        MD5STEPF4(%ebx, %edi, %ecx, %edx, %eax, 13*4(%esi), $0x4e0811a1, $21);
        MD5STEPF4(%eax, %edi, %ebx, %ecx, %edx, 4*4(%esi), $0xf7537e82, $6);
        MD5STEPF4(%edx, %edi, %eax, %ebx, %ecx, 11*4(%esi), $0xbd3af235, $10);
        MD5STEPF4(%ecx, %edi, %edx, %eax, %ebx, 2*4(%esi), $0x2ad7d2bb, $15);
        MD5STEPF4(%ebx, %edi, %ecx, %edx, %eax, 9*4(%esi), $0xeb86d391, $21);

	/* Copy the result */

	movl BUF, %edi

	addl %eax, 0(%edi)
	addl %ebx, 4(%edi)
	addl %ecx, 8(%edi)
	addl %edx, 12(%edi)

	/* Return */

	popl %edi
	popl %esi
	popl %ebx

	movl %ebp, %esp
	popl %ebp
	ret
