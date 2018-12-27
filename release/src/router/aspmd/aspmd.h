/*
 * ASPMD include file
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _EAPD_H_
#define _EAPD_H_

/* Message levels */
#define ASPMD_ERROR_VAL		0x00000001
#define ASPMD_INFO_VAL		0x00000002

#define STA_MAX_COUNT		256
#define ASPMD_EAPD_READ_MAX_LEN	2048

#define ASPMD_WKSP_FLAG_SHUTDOWN	0x1

typedef struct aspm_policy {
	char *sys_conf;
	uint ep_conf;
} aspm_policy_t;

typedef struct plat_chip {
	uint chipid;            /* Router CHIP ID */
	uint chiprev;           /* This rev starts to support ASPM */
	uint chippkg;           /* Package option */
	uint api;               /* ASPM policy index */
} plat_chip_t;

typedef struct pcie_ep {
	char name[IFNAMSIZ];    /* Interface name */
	uint chipid;            /* PCIe DEV CHIP ID */
	uint chiprev;           /* CHIP revision */
	uint chippkg;           /* Package option */
	uint bustype;           /* 0: SI_BUS, 1: PCI_BUS */
	char iov_cmd[8];        /* "wl": for NIC,  "dhd": for FD */
	uint aspm_supported;	/* 0: not support aspm, 1: support aspm */
	uint aspm_forced;	/* 0: ASPM support in IDLE mode (No wifi STA connected)
				 * 1: ASPM support in ACTIVE mode (wifi STA connected)
				 */
	uint aspm_policy;	/* ASPM policy */
} pcie_ep_t;

typedef struct aspm_info {
	plat_chip_t plat;
	uint ep_nums;	/* Total enpoints. Max is 3 */
	pcie_ep_t ep[3];
} aspm_info_t;

/* ASPM configuration via nvram control
 * 0: ASPMD isn't running and ASPM is disabled
 * 1: ASPMD is running and ASPM is enabled only in IDLE mode
 * 2: ASPMD isn't running but ASPM is always enabled in ACTIVE mode
 */
#define ASPM_CONFIG_NONE		(-1)
#define ASPM_CONFIG_DISABLE		0
#define ASPM_CONFIG_IDLE		1
#define ASPM_CONFIG_FORCE		2

extern uint aspmd_msg_level;

#define ASPMDBANNER(fmt, arg...)	do { \
		printf(" ASPMD>> %s(%d): "fmt, __FUNCTION__, __LINE__ , ##arg);} while (0)

#ifdef BCMDBG
#define ASPMD_ERROR(fmt, arg...)	do { \
		if (aspmd_msg_level & ASPMD_ERROR_VAL) ASPMDBANNER(fmt , ##arg);} while (0)
#define ASPMD_INFO(fmt, arg...)	do { \
		if (aspmd_msg_level & ASPMD_INFO_VAL) ASPMDBANNER(fmt , ##arg);} while (0)
#else	/* #if BCMDBG */
#define ASPMD_ERROR(fmt, arg...)
#define ASPMD_INFO(fmt, arg...)
#endif	/* #if BCMDBG */

typedef struct aspmd_wksp {
	fd_set fdset;
	int	eapd_socket;	/* socket communicated with eapd */
	char aspm_readbuf[ASPMD_EAPD_READ_MAX_LEN];
	int	flags;
} aspmd_wksp_t;
#endif /* _EAPD_H_ */
