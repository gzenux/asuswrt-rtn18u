/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SSH MP arithmetics i386 compatible assembler subroutines.

   This code implements the most time consuming loops and
   subroutines for the SSH MP library.

   Routines given here for i386 can be further optimized using
   e.g. Pentium pipelining, unrolling, etc.
*/

	.file "sshmp-asmopt_i386-att.S"
	.text

	.align 2
	.globl ssh_mpk_add_n
	.type  ssh_mpk_add_n, @function
	.globl _ssh_mpk_add_n
	.type  _ssh_mpk_add_n, @function

ssh_mpk_add_n:
_ssh_mpk_add_n:
	pushl %ebx /*  8 */
	pushl %esi /* 12 */
	pushl %edi /* 16 */

	/* ret, op1, op2, op len */
	movl 16(%esp), %esi
	movl 20(%esp), %ebx
	movl 24(%esp), %edi
	movl 28(%esp), %ecx

	/* Use edx as a carry. And eax as temp. */
	xorl %eax, %eax

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_add_n_finished

        leal (%ebx, %ecx, 4), %ebx
	leal (%edi, %ecx, 4), %edi
	leal (%esi, %ecx, 4), %esi

	negl %ecx
	jmp ssh_mpk_add_n_loop

	.align 2

ssh_mpk_add_n_loop:
	/* Try to interleave these operations. */
	xorl %edx,   %edx
	addl (%ebx, %ecx, 4), %eax
	adcl $0,     %edx
	addl (%edi, %ecx, 4), %eax
	adcl $0,     %edx
	movl %eax,  (%esi, %ecx, 4)

	/* Move carry to temp. */
	movl %edx, %eax
	incl %ecx
	jnz ssh_mpk_add_n_loop

ssh_mpk_add_n_finished:

	popl %edi
	popl %esi
	popl %ebx
	ret

	.align 2
	.globl ssh_mpk_add_1
	.type  ssh_mpk_add_1, @function
	.globl _ssh_mpk_add_1
	.type  _ssh_mpk_add_1, @function

ssh_mpk_add_1:
_ssh_mpk_add_1:
	pushl %ebx /*  8 */
	pushl %esi /* 12 */
	pushl %edi /* 16 */

	/* ret, op, op len */
	movl 16(%esp), %esi
	movl 20(%esp), %edi
	movl 24(%esp), %ecx

	movl $1, %eax

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_add_1_finished

	leal (%esi, %ecx, 4), %esi
	leal (%edi, %ecx, 4), %edi

	negl %ecx

	jmp ssh_mpk_add_1_loop

	.align 2

ssh_mpk_add_1_loop:
	/* Try to interleave these operations. */
	movl (%edi, %ecx, 4), %eax
	addl $1,     %eax
	movl %eax,   (%esi, %ecx, 4)
	jnc  ssh_mpk_add_1_no_carry

	incl %ecx
	jnz  ssh_mpk_add_1_loop

	movl $1, %eax
	jmp ssh_mpk_add_1_finished

ssh_mpk_add_1_no_carry:
	incl %ecx
	jnz  ssh_mpk_add_1_no_add

	xorl %eax, %eax
	jmp ssh_mpk_add_1_finished

	.align 2

	/* This can be written much faster using string instructions etc. */
ssh_mpk_add_1_no_add:
	movl (%edi, %ecx, 4), %eax
	movl %eax, (%esi, %ecx, 4)
	incl %ecx
	jnz  ssh_mpk_add_1_no_add

	xorl %eax, %eax

ssh_mpk_add_1_finished:
	popl %edi
	popl %esi
	popl %ebx
	ret

	.align 2
	.globl ssh_mpk_sub_n
	.type  ssh_mpk_sub_n, @function
	.globl _ssh_mpk_sub_n
	.type  _ssh_mpk_sub_n, @function

ssh_mpk_sub_n:
_ssh_mpk_sub_n:
	pushl %ebp /*  8 */
	pushl %ebx /* 12 */
	pushl %esi /* 16 */
	pushl %edi /* 20 */

	/* ret, op1, op2, op len */
	movl 20(%esp), %esi
	movl 24(%esp), %ebx
	movl 28(%esp), %edi
	movl 32(%esp), %ecx

	/* Use edx as a carry. And eax as temp. */
	xorl %eax, %eax

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_sub_n_finished

	leal (%ebx, %ecx, 4), %ebx
	leal (%edi, %ecx, 4), %edi
	leal (%esi, %ecx, 4), %esi

	negl %ecx

	jmp ssh_mpk_sub_n_loop

	.align 2

ssh_mpk_sub_n_loop:
	/* Try to interleave these operations. */
	xorl %edx,   %edx
	addl (%edi, %ecx, 4), %eax
	adcl $0,     %edx
	movl (%ebx, %ecx, 4), %ebp
	subl %eax,   %ebp
	adcl $0,     %edx
	movl %ebp,   (%esi, %ecx, 4)

	/* Move carry to temp. */
	movl %edx, %eax
	incl %ecx
	jnz ssh_mpk_sub_n_loop

ssh_mpk_sub_n_finished:

	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

	.align 2
	.globl ssh_mpk_sub_1
	.type  ssh_mpk_sub_1, @function
	.globl _ssh_mpk_sub_1
	.type  _ssh_mpk_sub_1, @function

ssh_mpk_sub_1:
_ssh_mpk_sub_1:
	pushl %ebx /*  8 */
	pushl %esi /* 12 */
	pushl %edi /* 16 */

	/* ret, op, op len */
	movl 16(%esp),  %esi
	movl 20(%esp), %edi
	movl 24(%esp), %ecx

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_sub_1_finished

	leal (%esi, %ecx, 4), %esi
	leal (%edi, %ecx, 4), %edi

	negl %ecx

	jmp ssh_mpk_sub_1_loop

	.align 2

ssh_mpk_sub_1_loop:
	/* Try to interleave these operations. */
	movl (%edi, %ecx, 4), %eax
	subl $1,     %eax
	movl %eax,   (%esi, %ecx, 4)
	jnc  ssh_mpk_sub_1_no_carry

	incl %ecx
	jnz  ssh_mpk_sub_1_loop

	movl $1, %eax
	jmp ssh_mpk_sub_1_finished

ssh_mpk_sub_1_no_carry:
	incl %ecx
	jnz  ssh_mpk_sub_1_no_add

	xorl %eax, %eax
	jmp ssh_mpk_sub_1_finished

	.align 2

ssh_mpk_sub_1_no_add:
	movl (%edi, %ecx, 4), %eax
	movl %eax,  (%esi, %ecx, 4)
	incl %ecx
	jnz  ssh_mpk_sub_1_no_add

	xorl %eax, %eax

ssh_mpk_sub_1_finished:
	popl %edi
	popl %esi
	popl %ebx
	ret


	.align 2
	.globl ssh_mpk_addmul_n
	.type  ssh_mpk_addmul_n, @function
	.globl _ssh_mpk_addmul_n
	.type  _ssh_mpk_addmul_n, @function

ssh_mpk_addmul_n:
_ssh_mpk_addmul_n:

	pushl %ebp /*  8 */
	pushl %ebx /* 12 */
	pushl %esi /* 16 */
	pushl %edi /* 20 */

	/* ret, k, op, op len */
	movl 20(%esp),  %esi
	movl 24(%esp), %ebx
	movl 28(%esp), %edi
	movl 32(%esp), %ecx

	/* Use ebp as carry. */
	xorl %ebp, %ebp

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_addmul_finished

	leal (%edi, %ecx, 4), %edi
	leal (%esi, %ecx, 4), %esi

	negl %ecx

	movl %ecx, %eax
	andl $3,   %eax

	/* A switching... */
	cmpl $0, %eax
	je   ssh_mpk_addmul_loop0
	subl %eax, %ecx
	cmpl $1, %eax
	je   ssh_mpk_addmul_loop1
	cmpl $2, %eax
	je   ssh_mpk_addmul_loop2
	jmp ssh_mpk_addmul_loop3

	.align 4

ssh_mpk_addmul_loop0:

	/* Multiply and add. */
	movl (%edi, %ecx, 4), %eax
	mull %ebx

	/* Now add to the ret. */
	addl (%esi, %ecx, 4), %eax
	adcl $0, %edx

	/* Add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Copy. */
	movl %eax, (%esi, %ecx, 4)
	movl %edx, %ebp

ssh_mpk_addmul_loop1:

	/* Multiply and add. */
	movl 4(%edi, %ecx, 4), %eax
	mull %ebx

	/* Now add to the ret. */
	addl 4(%esi, %ecx, 4), %eax
	adcl $0, %edx

	/* Add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Copy. */
	movl %eax, 4(%esi, %ecx, 4)
	movl %edx, %ebp

ssh_mpk_addmul_loop2:

	/* Multiply and add. */
	movl 8(%edi, %ecx, 4), %eax
	mull %ebx

	/* Now add to the ret. */
	addl 8(%esi, %ecx, 4), %eax
	adcl $0, %edx

	/* Add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Copy. */
	movl %eax, 8(%esi, %ecx, 4)
	movl %edx, %ebp

ssh_mpk_addmul_loop3:

	/* Multiply and add. */
	movl 12(%edi, %ecx, 4), %eax
	mull %ebx

	/* Now add to the ret. */
	addl 12(%esi, %ecx, 4), %eax
	adcl $0, %edx

	/* Add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Copy. */
	movl %eax, 12(%esi, %ecx, 4)
	movl %edx, %ebp

	/* Move forward. */
	addl $4, %ecx
	jnz ssh_mpk_addmul_loop0

ssh_mpk_addmul_finished:

	/* Finish nicely. */
	movl %ebp, %eax

	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

	.align 2
	.globl ssh_mpk_submul_n
	.type  ssh_mpk_submul_n, @function
	.globl _ssh_mpk_submul_n
	.type  _ssh_mpk_submul_n, @function

ssh_mpk_submul_n:
_ssh_mpk_submul_n:

	pushl %ebp /*  8 */
	pushl %ebx /* 12 */
	pushl %esi /* 16 */
	pushl %edi /* 20 */

	/* ret, k, op, op len */
	movl 20(%esp),  %esi
	movl 24(%esp), %ebx
	movl 28(%esp), %edi
	movl 32(%esp), %ecx

	/* Use ebp as carry as above. */
	xorl %ebp, %ebp

	/* Check that there is something to do after all. */
	cmpl $0, %ecx
	jz   ssh_mpk_submul_finished

	leal (%esi, %ecx, 4), %esi
	leal (%edi, %ecx, 4), %edi

	negl %ecx

	jmp ssh_mpk_submul_loop

	.align 2

ssh_mpk_submul_loop:
	/* Multiply and add. */
	movl (%edi, %ecx, 4), %eax
	mull %ebx

	/* Add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Now add to the ret. */
	subl %eax, (%esi, %ecx, 4)
	adcl $0, %edx

	/* Set the new carry. */
	movl %edx, %ebp

	incl %ecx
	jnz ssh_mpk_submul_loop

ssh_mpk_submul_finished:

	/* Finish nicely. */
	movl %ebp, %eax

	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret


	.align 2
	.globl ssh_mpk_shift_up_1
	.type  ssh_mpk_shift_up_1, @function
	.globl _ssh_mpk_shift_up_1
	.type  _ssh_mpk_shift_up_1, @function

ssh_mpk_shift_up_1:
_ssh_mpk_shift_up_1:

	pushl %ebx /*  8 */
	pushl %esi /* 12 */

	/* Get the parameters */
	movl 12(%esp), %esi
	movl 16(%esp), %ecx

	leal (%esi, %ecx, 4), %esi
	negl %ecx

	/* Clear the carry flag! */
	clc

	jmp ssh_mpk_shift_loop
	.align 2

	/* This might not be the fastest loop around, but it certainly
	   is rather quick. */
ssh_mpk_shift_loop:
	rcll $1, (%esi, %ecx, 4)
	incl %ecx
	jnz ssh_mpk_shift_loop

	/* Finish. */
	popl %esi
	popl %ebx
	ret


	.align 2
	.globl ssh_mpk_square_words_n
	.type  ssh_mpk_square_words_n, @function
	.globl _ssh_mpk_square_words_n
	.type  _ssh_mpk_square_words_n, @function

ssh_mpk_square_words_n:
_ssh_mpk_square_words_n:

	pushl %ebp /*  8 */
	pushl %ebx /* 12 */
	pushl %esi /* 16 */
	pushl %edi /* 20 */

	/* Get the parameters */
	movl 20(%esp), %esi
	movl 24(%esp), %edi
	movl 28(%esp), %ecx

	xorl %ebp, %ebp
	xorl %ebx, %ebx

	leal (%esi, %ecx, 8), %esi
	leal (%edi, %ecx, 4), %edi

	negl %ecx

	jmp ssh_mpk_square_loop

	.align 2

	/* This might not be the fastest loop around, but it certainly
	   is rather quick. */
ssh_mpk_square_loop:
	movl (%edi, %ecx, 4), %eax
	movl %eax, %ebx
	mull %ebx

	/* Now do the addition phase. */
	addl (%esi, %ecx, 8), %eax
	adcl $0, %edx

	/* Still add the carry. */
	addl %ebp, %eax
	adcl $0, %edx

	/* Now set the result. */
	movl %eax, (%esi, %ecx, 8)

	/* Add with the next word. */
	xorl %ebp, %ebp
	addl 4(%esi, %ecx, 8), %edx
	adcl $0, %ebp
	movl %edx, 4(%esi, %ecx, 8)

	/* Increment and check the ending condition. */
	incl %ecx
	jnz  ssh_mpk_square_loop

	/* Finish the squaring phase nicely. */
	movl %ebp, %eax
	xorl %edx, %edx
	addl (%esi, %ecx, 8), %ebp
	adcl $0, %edx
	movl %eax, (%esi, %ecx, 8)
	movl %edx, 4(%esi, %ecx, 8)

	/* Finish. */
	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret


	.align 2
	.globl ssh_mpmk_addmul_n
	.type  ssh_mpmk_addmul_n, @function
	.globl _ssh_mpmk_addmul_n
	.type  _ssh_mpmk_addmul_n, @function

ssh_mpmk_addmul_n:
_ssh_mpmk_addmul_n:

	pushl %ebp /*  8 */
	pushl %ebx /* 12 */
	pushl %esi /* 16 */
	pushl %edi /* 20 */

	/* ret, mp, m, m length */
	movl 20(%esp), %esi
	movl 24(%esp), %ebx
	movl 28(%esp), %edi
	movl 32(%esp), %ecx

	/* Do the first multiply. */
	movl (%esi), %eax
	mull %ebx

	/* Move lower part to ebx. */
	movl %eax, %ebx
	xorl %eax, %eax

	/* Check that there is something to do after all. In fact, this
	   case is impossible. But lets check anyway. */
	cmpl $0, %ecx
	jz   ssh_mpmk_mont_addmul_finished

	/* Carry. */
	xorl %ebp, %ebp

	leal (%esi, %ecx, 4), %esi
	leal (%edi, %ecx, 4), %edi

	negl %ecx

	movl %ecx, %eax
	andl $3,   %eax

	/* A switching... */
	cmpl $0, %eax
	je   ssh_mpmk_mont_addmul0
	subl %eax, %ecx
	cmpl $1, %eax
	je   ssh_mpmk_mont_addmul1
	cmpl $2, %eax
	je   ssh_mpmk_mont_addmul2
	jmp ssh_mpmk_mont_addmul3

	.align 4

ssh_mpmk_mont_addmul0:

	/* Multiply and add. */
	movl (%edi, %ecx, 4), %eax
	mull %ebx

	/* Add with carry. */
	addl %ebp, %eax
	adcl $0,   %edx

	/* Now add to the ret. */
	addl (%esi, %ecx, 4), %eax
	adcl $0,     %edx

	/* Copy back to ret. */
	movl %eax, (%esi, %ecx, 4)

	/* Change carry. */
	movl %edx, %ebp

ssh_mpmk_mont_addmul1:

	/* Multiply and add. */
	movl 4(%edi, %ecx, 4), %eax
	mull %ebx

	/* Add with carry. */
	addl %ebp, %eax
	adcl $0,   %edx

	/* Now add to the ret. */
	addl 4(%esi, %ecx, 4), %eax
	adcl $0,     %edx

	/* Copy back to ret. */
	movl %eax, 4(%esi, %ecx, 4)

	/* Change carry. */
	movl %edx, %ebp

ssh_mpmk_mont_addmul2:

	/* Multiply and add. */
	movl 8(%edi, %ecx, 4), %eax
	mull %ebx

	/* Add with carry. */
	addl %ebp, %eax
	adcl $0,   %edx

	/* Now add to the ret. */
	addl 8(%esi, %ecx, 4), %eax
	adcl $0,     %edx

	/* Copy back to ret. */
	movl %eax, 8(%esi, %ecx, 4)

	/* Change carry. */
	movl %edx, %ebp

ssh_mpmk_mont_addmul3:

	/* Multiply and add. */
	movl 12(%edi, %ecx, 4), %eax
	mull %ebx

	/* Add with carry. */
	addl %ebp, %eax
	adcl $0,   %edx

	/* Now add to the ret. */
	addl 12(%esi, %ecx, 4), %eax
	adcl $0,     %edx

	/* Copy back to ret. */
	movl %eax, 12(%esi, %ecx, 4)

	/* Change carry. */
	movl %edx, %ebp

	/* Move forward. */
	addl $4, %ecx
	jnz ssh_mpmk_mont_addmul0

	/* Get the high carry. */
	movl 36(%esp), %ebx
	xorl %eax, %eax
	addl %ebp, %ebx
	adcl $0,   %eax

	/* Add the carry to ret. */
	addl (%esi, %ecx, 4), %ebx
	adcl $0,     %eax
	movl %ebx,   (%esi, %ecx, 4)

ssh_mpmk_mont_addmul_finished:

	/* Finish nicely. */
	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

/* End. */
