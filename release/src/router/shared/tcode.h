#ifndef __TCODE_H__
#define __TCODE_H__

#ifdef RTCONFIG_TCODE
struct tcode_nvram_s {
	int model;
	char *odmpid;
	char *tcode;
	char *name;
	char *value;
};

struct tcode_rc_support_s {
	int model;
	char *tcode;
	char *features;
};

struct tcode_location_s {
	int model;
	char *location;
	char *prefix_fmt;
	int idx_base;
	char *ccode_2g;
	char *regrev_2g;	/* non-BRCM model, this maybe NULL */
	char *ccode_5g;		/* For 2.4G model, this should be NULL */
	char *regrev_5g;	/* For 2.4G model, this should be NULL */
	char *ccode_5g_2;	/* For 2.4G model, this should be NULL */
	char *regrev_5g_2;	/* For 2.4G model, this should be NULL */
	unsigned int flag;	/* hardware compatibility flag */
};

#ifdef RTAC68U
#define RTAC68U_V1	0x00000001
#define RTAC68U_V2	0x00000002
#define RTAC68U_V1_C0	0x00000004
#define RTAC68U_V2_C0	0x00000008
#define RTAC68U_ALL	(RTAC68U_V1 | RTAC68U_V2 | RTAC68U_V1_C0 | RTAC68U_V2_C0)
#define RTAC68U_V1_ALL	(RTAC68U_V1 | RTAC68U_V1_C0)
#define RTAC68U_V2_ALL	(RTAC68U_V2 | RTAC68U_V2_C0)
#endif

extern struct tcode_nvram_s tcode_nvram_list[];
extern struct tcode_nvram_s tcode_init_nvram_list[];
extern struct tcode_rc_support_s tcode_rc_support_list[];

extern char *tcode_default_get(const char *name);

#endif	/* RTCONFIG_TCODE */
#endif	/* !__TCODE_H__ */
