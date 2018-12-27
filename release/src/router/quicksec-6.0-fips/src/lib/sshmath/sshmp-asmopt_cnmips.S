/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include <asm/asm.h>
#include <asm/regdef.h>

.set noreorder
.set noat

LEAF(ssh_mpk_add_n)
#define ret	a0
#define op1     a1
#define op2	a2
#define len	a3

	beq     zero, len, ssh_mpk_add_n_nop
        li      t0, 1
        dsll    len, len, 3
        mtm0    t0
        daddu   len, len, op2

ssh_mpk_add_n_loop:
        ld	ta1, 0(op1)
        ld	ta2, 0(op2)
        daddiu  op1, op1, 8
        daddiu  op2, op2, 8
        vmulu   ta1, ta1, ta2
        daddiu  ret, ret, 8
        bne     op2, len, ssh_mpk_add_n_loop
        sd      ta1, -8(ret)

ssh_mpk_add_n_finished:
        jr	ra
        vmulu   v0, zero, zero

ssh_mpk_add_n_nop:
        jr	ra
        li      v0, 0

#undef ret
#undef op1
#undef op2
#undef len
END(ssh_mpk_add_n)


LEAF(ssh_mpk_add_1)
#define ret	a0
#define op      a1
#define len	a2
#define i       v0

	li       ta0, 1
	beq      zero, len, ssh_mpk_add_1_nop

        daddiu   i, len, 0

ssh_mpk_add_1_loop:
        daddiu   ret, ret, 8
        ld	 ta1, 0(op)
        daddiu   op, op, 8
        daddu    ta2, ta1, ta0
        daddiu   i,   i, -1
        sd       ta2, -8(ret)
        bne      i, zero, ssh_mpk_add_1_loop
        sltu     ta0, ta2, ta1

ssh_mpk_add_1_finished:
        jr	 ra
        move     v0, ta0

ssh_mpk_add_1_nop:
        jr       ra
        li       v0, 0

#undef ret
#undef op
#undef len
#undef i
END(ssh_mpk_add_1)


LEAF(ssh_mpk_sub_n)
#define ret	a0
#define op1     a1
#define op2	a2
#define len	a3

	beq     zero, len, ssh_mpk_sub_n_nop
        dsll    len, len, 3
        daddiu  ta3, zero, -1
        daddu   len, len, op2
        li      t0, 1
        mtm0    t0
        mtp0    t0

ssh_mpk_sub_n_loop:
        ld	ta1, 0(op1)
        ld	ta2, 0(op2)
        daddiu  op2, op2, 8
        daddiu  op1, op1, 8
        xor     ta2, ta2, ta3
        vmulu   ta1, ta1, ta2
        daddiu  ret, ret, 8
        bne     op2, len, ssh_mpk_sub_n_loop
        sd      ta1, -8(ret)

ssh_mpk_sub_n_finished:
        jr	ra
        vmulu   v0, zero, ta3

ssh_mpk_sub_n_nop:
        jr      ra
        li      v0, 0

#undef ret
#undef op1
#undef op2
#undef len
END(ssh_mpk_sub_n)


LEAF(ssh_mpk_sub_1)
#define ret	a0
#define op      a1
#define len	a2

	beq     zero, len, ssh_mpk_sub_1_nop
        li      t0, 1
        dsll    len, len, 3
        daddiu  ta3, zero, -1
        mtm0    t0
        daddu   len, len, op

ssh_mpk_sub_1_loop:
        ld	ta1, 0(op)
        daddiu  op, op, 8
        vmulu   ta1, ta1, ta3
        daddiu  ret, ret, 8
        bne     op, len, ssh_mpk_sub_1_loop
        sd      ta1, -8(ret)

ssh_mpk_sub_1_finished:
        jr	ra
        vmulu   v0, zero, ta3

ssh_mpk_sub_1_nop:
        jr      ra
        li      v0, 0

#undef ret
#undef op
#undef len
END(ssh_mpk_sub_1)


LEAF(ssh_mpmk_addmul_n)
#define ret   a0
#define mp    a1
#define op    a2
#define len   a3

        daddiu  len, -1
        ld      t1, 0(ret)
        dsll    len, len, 3
        mtm0    mp
        andi    v0, len, 0x1f
        ld      t3, 0(op)
        vmm0    t2, t1, zero
        dsubu   len, len, v0
        daddiu  op, 8
        daddiu  ret, 8
        vmulu   zero, t3, t1
        blez    len, ssh_mpmk_addmul_n_the_rest
        daddu   len, len, op

ssh_mpmk_addmul_n_loop_unroll:
        ld      a4, 0(op)
        ld      t0, 0(ret)
        daddiu  op, 32
        ld      a5, -24(op)
        ld      t1, 8(ret)
        vmulu   t0, a4, t0
        ld      a6, -16(op)
        ld      t2, 16(ret)
        vmulu   t1, a5, t1
        ld      a7, -8(op)
        ld      t3, 24(ret)
        vmulu   t2, a6, t2
        sd      t0, 0(ret)
        sd      t1, 8(ret)
        vmulu   t3, a7, t3
        sd      t2, 16(ret)
        daddiu  ret, 32
        bne     op, len, ssh_mpmk_addmul_n_loop_unroll
        sd      t3, -8(ret)

ssh_mpmk_addmul_n_the_rest:
        blez    v0, ssh_mpmk_addmul_n_finish
        daddu   v0, v0, op

ssh_mpmk_addmul_n_loop:
        ld      t2, 0(op)
        ld      t1, 0(ret)
        daddiu  op, 8
        vmulu   t1, t2, t1
        daddiu  ret, 8
        bne     op, v0, ssh_mpmk_addmul_n_loop
        sd      t1, -8(ret)

ssh_mpmk_addmul_n_finish:
        ld      t1, 0(ret)
        vmulu   t2, zero, t1
        nop
        sd      t2, 0(ret)

ssh_mpmk_addmul_n_finish_loop:
        ld      t1, 8(ret)
        vmulu   t2, zero, t1
        daddiu  ret, 8
        dsubu   t1, t2, t1
        bltz    t1, ssh_mpmk_addmul_n_finish_loop
        sd      t2, 0(ret)

ssh_mpmk_mont_addmul_finished:
        jr      ra
        li      v0, 0

#undef ret
#undef mp
#undef op
#undef len
END(ssh_mpmk_addmul_n)


LEAF(ssh_mpk_addmul_n)
#define ret   a0
#define mp    a1
#define op    a2
#define len   a3

        dsll    len, len, 3
        andi    v0, len, 0x1f
        dsubu   len, len, v0
        mtm0    mp
        beq     len, zero, ssh_mpk_addmul_the_rest
        daddu   len, len, op


ssh_mpk_addmul_loop_unroll:
        ld      a4, 0(op)
        ld      t0, 0(ret)
        daddiu  op, 32
        ld      a5, -24(op)
        ld      t1, 8(ret)
        vmulu   t0, a4, t0
        ld      a6, -16(op)
        ld      t2, 16(ret)
        vmulu   t1, a5, t1
        ld      a7, -8(op)
        ld      t3, 24(ret)
        vmulu   t2, a6, t2
        sd      t0, 0(ret)
        sd      t1, 8(ret)
        vmulu   t3, a7, t3
        sd      t2, 16(ret)
        daddiu  ret, 32
        bne     op, len, ssh_mpk_addmul_loop_unroll
        sd      t3, (ret)

ssh_mpk_addmul_the_rest:
        beq     v0, zero, ssh_mpk_addmul_finished
        daddu   v0, v0, op

ssh_mpk_addmul_loop:
        ld      t1, 0(ret)
        ld      t2, 0(op)
        daddiu  op, 8
        vmulu   t1, t2, t1
        daddiu  ret, 8
        bne     op, v0, ssh_mpk_addmul_loop
        sd      t1, -8(ret)

ssh_mpk_addmul_finished:
        jr      ra
        vmulu   v0, zero, zero

#undef ret
#undef mp
#undef op
#undef len
END(ssh_mpk_addmul_n)


LEAF(ssh_mpk_addmul_n_nc)
#define ret   a0
#define mp    a1
#define op    a2
#define len   a3

        dsll    len, len, 3
        andi    v0, len, 0x1f
        dsubu   len, len, v0
        mtm0    mp
        beq     len, zero, ssh_mpk_addmul_nc_the_rest
        daddu   len, len, op

ssh_mpk_addmul_nc_loop_unroll:
        ld      a4, 0(op)
        ld      t0, 0(ret)
        daddiu  op, 32
        ld      a5, -24(op)
        ld      t1, 8(ret)
        vmulu   t0, a4, t0
        ld      a6, -16(op)
        ld      t2, 16(ret)
        vmulu   t1, a5, t1
        ld      a7, -8(op)
        ld      t3, 24(ret)
        vmulu   t2, a6, t2
        sd      t0, 0(ret)
        sd      t1, 8(ret)
        vmulu   t3, a7, t3
        sd      t2, 16(ret)
        daddiu  ret, 32
        bne     op, len, ssh_mpk_addmul_nc_loop_unroll
        sd      t3, -8(ret)

ssh_mpk_addmul_nc_the_rest:
        beq     v0, zero, ssh_mpk_addmul_nc_finished
        daddu   v0, v0, op

ssh_mpk_addmul_nc_loop:
        ld      t1, 0(ret)
        ld      t2, 0(op)
        daddiu  op, 8
        vmulu   t1, t2, t1
        daddiu  ret, 8
        bne     op, v0, ssh_mpk_addmul_nc_loop
        sd      t1, -8(ret)

ssh_mpk_addmul_nc_finished:
        vmulu   v0, zero, zero
        jr      ra
        sd      v0, 0(ret)

#undef ret
#undef mp
#undef op
#undef len
END(ssh_mpk_addmul_n_nc)


LEAF(ssh_mpk_shift_up_1)
#define op  a0
#define len a1

        beq     len, zero, ssh_mpk_shift_up_1_finished
        dsll    len, len, 3
        daddu   v0, op, len
        nor     t3, zero, zero
        dsll    t3, t3, 1
        li      t0, 0

ssh_mpk_shift_up_1_loop:
        ld      t1, 0(op)
        daddiu  op, op, 8
        drotr32 t2, t1, 31
        dsll    t1, t1, 1
        or      t1, t1, t0
        andi    t0, t2, 1
        bne     op, v0, ssh_mpk_shift_up_1_loop
        sd      t1, -8(op)

ssh_mpk_shift_up_1_finished:
        jr      ra
        nop

#undef op
#undef len
END(ssh_mpk_shift_up_1)


LEAF(ssh_mpk_addmul_n_192)
#define ret   a0
#define mp    a1
#define op    a2
#define len   a3

        dsll    len, len, 3
        ld      t1, 0(mp)
        ld      t2, 8(mp)
        andi    v0, len, 0x1f
        ld      t3, 16(mp)
        mtm0    t1
        dsubu   len, len, v0
        mtm1    t2
        mtm2    t3
        beq     len, zero, ssh_mpk_addmul_n_192_rest
        daddu   len, len, op

ssh_mpk_addmul_n_192_loop_3:
        ld      t0, 0(op)
        ld      a4, 0(ret)
        daddiu  op, 32
        ld      t1, -24(op)
        ld      a5, 8(ret)
        v3mulu  t0, t0, a4
        ld      t2, -16(op)
        ld      a6, 16(ret)
        v3mulu  t1, t1, a5
        ld      t3, -8(op)
        ld      a7, 24(ret)
        v3mulu  t2, t2, a6
        sd      t0, 0(ret)
        sd      t1, 8(ret)
        v3mulu  t3, t3, a7
        sd      t2, 16(ret)
        daddiu  ret, 32
        bne     op, len, ssh_mpk_addmul_n_192_loop_3
        sd      t3, -8(ret)

ssh_mpk_addmul_n_192_rest:
        beq     v0, zero, ssh_mpk_addmul_n_192_finish
        daddu   v0, v0, op

ssh_mpk_addmul_n_192_loop:
        ld      a4, 0(ret)
        ld      t0, 0(op)
        daddiu  op, 8
        v3mulu  t0, t0, a4
        daddiu  ret, 8
        bne     op, v0, ssh_mpk_addmul_n_192_loop
        sd      t0, -8(ret)


ssh_mpk_addmul_n_192_finish:
        v3mulu  t2, zero, zero
        nop
        v3mulu  t1, zero, zero
        nop
        v3mulu  t0, zero, zero
        sd      t2, 0(ret)
        sd      t1, 8(ret)
        jr      ra
        sd      t0, 16(ret)

ssh_mpk_addmul_n_192_finished:
        jr      ra
        nop

#undef ret
#undef mp
#undef op
#undef len
END(ssh_mpk_addmul_n_192)


LEAF(ssh_mpmk_addmul_n_192)
#define ret   a0
#define mp    a1
#define op    a2
#define len   a3

        ld      t1, 0(mp)
        daddiu  len, -3
        ld      t2, 8(mp)
        ld      t3, 16(mp)
        mtm0    t1
        mtm1    t2
        mtm2    t3
        ld      t1, 0(ret)
        ld      t2, 8(ret)
        v3mulu  a4, t1, zero
        dsll    len, len, 3
        ld      t3, 16(ret)
        v3mulu  a5, t2, zero
        andi    v0, len, 0x1f
        daddiu  ret, 24
        v3mulu  a6, t3, zero
        mtm0    a4
        ld      a4, 0(op)
        mtm1    a5
        mtm2    a6
        v3mulu  zero, a4, t1
        ld      a5, 8(op)
        dsubu   len, len, v0
        v3mulu  zero, a5, t2
        ld      a6, 16(op)
        daddiu  op, 24
        v3mulu  zero, a6, t3
        blez    len, ssh_mpmk_addmul_n_192_rest
        daddu   len, len, op

ssh_mpmk_addmul_n_192_loop_unroll:
        ld      t0, 0(op)
        ld      mp, 0(ret)
        daddiu  op, 32
        ld      t1, -24(op)
        ld      a5, 8(ret)
        v3mulu  t0, t0, mp
        ld      t2, -16(op)
        ld      a6, 16(ret)
        v3mulu  t1, t1, a5
        ld      t3, -8(op)
        ld      a7, 24(ret)
        v3mulu  t2, t2, a6
        sd      t0, 0(ret)
        sd      t1, 8(ret)
        v3mulu  t3, t3, a7
        sd      t2, 16(ret)
        daddiu  ret, 32
        bne     op, len, ssh_mpmk_addmul_n_192_loop_unroll
        sd      t3, -8(ret)

ssh_mpmk_addmul_n_192_rest:
        beq     v0, zero, ssh_mpmk_addmul_n_192_finish
        daddu   v0, op

ssh_mpmk_addmul_n_192_loop:
        ld      t1, 0(ret)
        ld      t2, 0(op)
        daddiu  op, 8
        v3mulu  t1, t2, t1
        daddiu  ret, 8
        bne     op, v0, ssh_mpmk_addmul_n_192_loop
        sd      t1, -8(ret)

ssh_mpmk_addmul_n_192_finish:
        ld      t0, 0(ret)
        ld      t1, 8(ret)
        ld      t2, 16(ret)
        v3mulu  t0, zero, t0
        ld      t3, 24(ret)
        v3mulu  t1, zero, t1
        sd      t0, 0(ret)
        v3mulu  t2, zero, t2
        sd      t1, 8(ret)
        v3mulu  v0, zero, t3
        sd      t2, 16(ret)
        dsubu   t3, t3, v0
        bltz    t3, ssh_mpmk_addmul_n_192_high_carry
        sd      v0, 24(ret)

ssh_mpmk_addmul_n_192_finished:
        jr      ra
        li      v0, 0

ssh_mpmk_addmul_n_192_high_carry:
        ld      t0, 32(ret)
        daddiu  ret, 8
        v3mulu  t1, zero, t0
        dsubu   t0, t1, t0
        bltz    t0, ssh_mpmk_addmul_n_192_high_carry
        sd      t1, 24(ret)
        jr      ra
        li      v0, 0

#undef ret
#undef mp
#undef op
#undef len
END(ssh_mpmk_addmul_n_192)


LEAF(ssh_mpk_memcopy)
#define dst a0
#define src a1
#define len a2

        dsll    len, len, 3
        pref    0, 0(src)
        andi    v0, len, 0x1f
        pref    1, 0(dst)
        dsubu   len, len, v0
        blez    len, ssh_mpk_memcopy_the_rest
        daddu   len, len, src

ssh_mpk_memcopy_unrolled_loop:
        ld    t0, 0(src)
        ld    t1, 8(src)
        ld    t2, 16(src)
        ld    t3, 24(src)
        daddu src, 32
        sd    t0, 0(dst)
        sd    t1, 8(dst)
        sd    t2, 16(dst)
        sd    t3, 24(dst)
        bne   src, len, ssh_mpk_memcopy_unrolled_loop
        daddu dst, 32

ssh_mpk_memcopy_the_rest:
        beq   v0, zero, ssh_mpk_memcopy_finished
        daddu v0, src

ssh_mpk_memcopy_the_rest_loop:
        ld    t1, 0(src)
        daddu src, 8
        sd    t1, 0(dst)
        bne   src, v0, ssh_mpk_memcopy_the_rest_loop
        daddu dst, 8

ssh_mpk_memcopy_finished:
        jr    ra
        nop

#undef len
#undef src
#undef dst
END(ssh_mpk_memcopy)



ssh_mpk_memzero_unrolled_jump:
        .dword  ssh_mpk_memzero_unrolled_memcopy

LEAF(ssh_mpk_memzero)
#define dst a0
#define len a1

        dsll    v0, len, 2
        beq     len, zero, ssh_mpk_memzero_finished
        dsll    len, len, 3
        andi    v0, v0, 0x1f
        ld      t0, ssh_mpk_memzero_unrolled_jump
        andi    t1, len, 0x3f
        dsubu   t0, t0, v0
        daddu   len, len, dst
        jr      t0
        daddu   dst, dst, t1

ssh_mpk_memzero_unrolled_loop:
        sd      zero, -64(dst)
        sd      zero, -56(dst)
        sd      zero, -48(dst)
        sd      zero, -40(dst)
        sd      zero, -32(dst)
        sd      zero, -24(dst)
        sd      zero, -16(dst)
        sd      zero, -8(dst)
ssh_mpk_memzero_unrolled_memcopy:
        bne     dst, len, ssh_mpk_memzero_unrolled_loop
        daddiu  dst, dst, 64

ssh_mpk_memzero_finished:
        jr    ra
        nop

#undef len
#undef dst
END(ssh_mpk_memzero)
