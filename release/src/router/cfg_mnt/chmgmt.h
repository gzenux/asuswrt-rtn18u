#ifndef __CHMGMT_H__
#define __CHMGMT_H__

typedef uint32_t chmgmt_chinfo_t;
#define	CHINFO_2G	0
#define	CHINFO_5G	(1<<0)
#define	CHINFO_UAVL	(1<<1)
#define	CHINFO_AVBL	(1<<2)
#define	CHINFO_BLK	(1<<3)
#define	CHINFO_CMNFMT_V1	1

#define MAX_CH_DATA_BUFLEN	450
#define MAX_CH_NUM	224

#define CH_APART_5M	1
#define CH_APART_10M	2
#define CH_APART_20M	4
#define CH_APART_40M	8
#define CH_APART_80M	16

typedef uint16_t chmgmt_chconf_t;
#define CHCONF_CH_MASK	0x00FF
#define CHCONF_CH(chconf)	(chconf & CHCONF_CH_MASK)
#define CHCONF_CH_SET(chconf, channel)	(chconf = (chconf&(~CHCONF_CH_MASK))|(channel&CHCONF_CH_MASK))

#define CHCONF_SB_MASK	0x0700
#define CHCONF_SB_SHIFT	8
#define CHCONF_SB_LLL	(0<<CHCONF_SB_SHIFT)
#define CHCONF_SB_LLU	(1<<CHCONF_SB_SHIFT)
#define CHCONF_SB_LUL	(2<<CHCONF_SB_SHIFT)
#define CHCONF_SB_LUU	(3<<CHCONF_SB_SHIFT)
#define CHCONF_SB_ULL	(4<<CHCONF_SB_SHIFT)
#define CHCONF_SB_ULU	(5<<CHCONF_SB_SHIFT)
#define CHCONF_SB_UUL	(6<<CHCONF_SB_SHIFT)
#define CHCONF_SB_UUU	(7<<CHCONF_SB_SHIFT)
#define CHCONF_SB_MASK80	0x0300
#define CHCONF_SB_LL	CHCONF_SB_LLL
#define CHCONF_SB_LU	CHCONF_SB_LLU
#define CHCONF_SB_UL	CHCONF_SB_LUL
#define CHCONF_SB_UU	CHCONF_SB_LUU
#define CHCONF_SB_MASK40	0x0100
#define CHCONF_SB_LO	CHCONF_SB_LLL
#define CHCONF_SB_UP	CHCONF_SB_LLU
#define CHCONF_SB(chconf)	((chconf & CHCONF_SB_MASK) >> CHCONF_SB_SHIFT)
#define CHCONF_SB_SET(chconf, sb)	(chconf = (chconf&(~CHCONF_SB_MASK))|(sb&CHCONF_SB_MASK))

#define CHCONF_BW_MASK	0x7000
#define CHCONF_BW_SHIFT	12
#define CHCONF_BW_5		(0<<CHCONF_BW_SHIFT)
#define CHCONF_BW_10	(1<<CHCONF_BW_SHIFT)
#define CHCONF_BW_20	(2<<CHCONF_BW_SHIFT)
#define CHCONF_BW_40	(3<<CHCONF_BW_SHIFT)
#define CHCONF_BW_80	(4<<CHCONF_BW_SHIFT)
#define CHCONF_BW_160	(5<<CHCONF_BW_SHIFT)
#define CHCONF_BW_IS20(chconf)	(((chconf) & CHCONF_BW_MASK) == CHCONF_BW_20)
#define CHCONF_BW_IS40(chconf)	(((chconf) & CHCONF_BW_MASK) == CHCONF_BW_40)
#define CHCONF_BW_IS80(chconf)	(((chconf) & CHCONF_BW_MASK) == CHCONF_BW_80)
#define CHCONF_BW_IS160(chconf)	(((chconf) & CHCONF_BW_MASK) == CHCONF_BW_160)
#define CHCONF_BW(chconf)	((chconf & CHCONF_BW_MASK) >> CHCONF_BW_SHIFT)
#define CHCONF_BW_SET20(chconf)	(chconf = (chconf&(~CHCONF_BW_MASK))|CHCONF_BW_20)
#define CHCONF_BW_SET40(chconf)	(chconf = (chconf&(~CHCONF_BW_MASK))|CHCONF_BW_40)
#define CHCONF_BW_SET80(chconf)	(chconf = (chconf&(~CHCONF_BW_MASK))|CHCONF_BW_80)
#define CHCONF_BW_SET160(chconf)	(chconf = (chconf&(~CHCONF_BW_MASK))|CHCONF_BW_160)

#define LO_SB(channel)	(((channel) > CH_APART_10M) ? ((channel) - CH_APART_10M) : 0)
#define UP_SB(channel)	(((channel) < (MAX_CH_NUM - CH_APART_10M)) ? ((channel) + CH_APART_10M) : 0)

#define LL_SB(channel)	(((channel) > (CH_APART_10M + CH_APART_20M)) ? ((channel) - (CH_APART_10M + CH_APART_20M)) : 0)
#define UU_SB(channel)	(((channel) < (MAX_CH_NUM - (CH_APART_10M + CH_APART_20M))) ? ((channel) + (CH_APART_10M + CH_APART_20M)) : 0)
#define LU_SB(channel)	LO_SB(channel)
#define UL_SB(channel)	UP_SB(channel)

int chmgmt_get_chan_info(char *buf, size_t len);
int chmgmt_notify();
int chmgmt_get_ctl_ch(chmgmt_chconf_t chconf);
int chmgmt_get_bw(chmgmt_chconf_t chconf);

#endif
