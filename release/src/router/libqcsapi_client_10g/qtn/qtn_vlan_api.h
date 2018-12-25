/*
 * Copyright (c) 2016 - Quantenna Communications, Inc.
 * All rights reserved.
 */

#ifndef _QTN_VLAN_API_H_
#define _QTN_VLAN_API_H_

#define QVLAN_MODE_ACCESS		0
#define QVLAN_MODE_TRUNK		1
#define QVLAN_MODE_HYBRID		2
#define QVLAN_MODE_DYNAMIC		3
#define QVLAN_MODE_MAX			QVLAN_MODE_DYNAMIC
#define QVLAN_MODE_DISABLED		(QVLAN_MODE_MAX + 1)
#define QVLAN_SHIFT_MODE		16
#define QVLAN_MASK_MODE			0xffff0000
#define QVLAN_MASK_VID			0x00000fff

#define QVLAN_MODE(x)			(uint16_t)((x) >> QVLAN_SHIFT_MODE)
#define QVLAN_VID(x)			(uint16_t)((x) & QVLAN_MASK_VID)

#define QVLAN_MODE_STR_ACCESS	"Access mode"
#define QVLAN_MODE_STR_TRUNK	"Trunk mode"
#define QVLAN_MODE_STR_HYBRID	"Hybrid mode"
#define QVLAN_MODE_STR_DYNAMIC	"Dynamic mode"

/* default port vlan id */
#define QVLAN_DEF_PVID			1

#define QVLAN_VID_MAX			4096
#define QVLAN_VID_MAX_S			12
#define QVLAN_VID_ALL			0xffff

#ifndef NBBY
#define NBBY		8
#endif

#ifndef NBDW
#define NBDW		32
#endif

#ifndef howmany
#define howmany(x, y)			(((x) + ((y) - 1)) / (y))
#endif

#define bitsz_var(var)			(sizeof(var) * 8)
#define bitsz_ptr(ptr)			bitsz_var((ptr)[0])

#define set_bit_a(a, i)			((a)[(i) / bitsz_ptr(a)] |= 1 << ((i) % bitsz_ptr(a)))
#define clr_bit_a(a, i)			((a)[(i) / bitsz_ptr(a)] &= ~(1 << ((i) % bitsz_ptr(a))))
#define is_set_a(a, i)			((a)[(i) / bitsz_ptr(a)] & (1 << ((i) % bitsz_ptr(a))))
#define is_clr_a(a, i)			(is_set_a(a, i) == 0)

struct qtn_vlan_info_s {
#define QVLAN_TAGRX_UNTOUCH		0
#define QVLAN_TAGRX_STRIP		1
#define QVLAN_TAGRX_TAG			2
#define QVLAN_TAGRX_BITMASK		0x3
#define QVLAN_TAGRX_BITWIDTH		2
#define QVLAN_TAGRX_BITSHIFT		1
#define QVLAN_TAGRX_NUM_PER_DW		(32 / QVLAN_TAGRX_BITWIDTH)
#define QVLAN_TAGRX_NUM_PER_DW_S	4
	uint32_t vlan_tagrx_bitmap[howmany(QVLAN_VID_MAX * QVLAN_TAGRX_BITWIDTH, NBDW)];
};

#if defined(__KERNEL__) || defined(MUC_BUILD) || defined(AUC_BUILD)
RUBY_INLINE int
#else
static inline int
#endif
qtn_vlan_get_tagrx(uint32_t *tagrx_bitmap, uint16_t vlanid)
{
	return (tagrx_bitmap[vlanid >> QVLAN_TAGRX_NUM_PER_DW_S] >>
			((vlanid & (QVLAN_TAGRX_NUM_PER_DW - 1)) << QVLAN_TAGRX_BITSHIFT)) &
		QVLAN_TAGRX_BITMASK;
}

struct qtn_vlan_config {
	uint32_t	vlan_cfg;
	union {
		struct vlan_dev_config {
			uint32_t	member_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
			uint32_t	tag_bitmap[howmany(QVLAN_VID_MAX, NBDW)];
		} dev_config;
		uint32_t	tagrx_config[howmany(QVLAN_VID_MAX * QVLAN_TAGRX_BITWIDTH, NBDW)];
	} u;
};

#endif
