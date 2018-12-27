/*
 * ASPM deamon (Linux)
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

#include <typedefs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <proto/ethernet.h>
#include <bcmnvram.h>
#include <wlutils.h>
#include <bcmutils.h>
#include <bcmdevs.h>
#include <shutils.h>
#include <security_ipc.h>
#include <wlif_utils.h>

#include <aspmd.h>

/* ASPM ploicy define is to hide the details, but match the lcreg
 * #define PCIE_CLKREQ_ENAB		0x100
 * #define PCIE_ASPM_L1_ENAB		2
 * #define PCIE_ASPM_L0s_ENAB		1
 */
#define ASPM_CMD_SYS   "echo %s > /sys/module/pcie_aspm/parameters/policy"
#define ASPM_CMD_EP    "%s -i %s aspm 0x%x"

#define ASPM_POLICY_DEFAULT    0
#define ASPM_POLICY_PERF       1
#define ASPM_POLICY_L0SL1_PS   2
#define ASPM_POLICY_L0S_PS     3
#define ASPM_POLICY_L1_PS      4

const aspm_policy_t aspm_policies[5] = {
	{"default",         0x0},
	{"performance",     0x0},
	{"powersave",     0x103},
	{"l0s_powersave",   0x1},
	{"l1_powersave",  0x102}
};

/* The following router chips have been verified on ASPM mode */
const plat_chip_t plat_chips[] = {
	{BCM4707_CHIP_ID,  0, 0, ASPM_POLICY_L1_PS},
	{BCM47094_CHIP_ID, 0, 0, ASPM_POLICY_L1_PS},
	/* BCM53573/BCM53574/BCM47189 A0 and A1 are unsupported */
	{BCM53573_CHIP_ID, 2, 0, ASPM_POLICY_L1_PS},
	{BCM53574_CHIP_ID, 2, 0, ASPM_POLICY_L1_PS},
	{0, 0, 0, 0}
};

/* The following wifi chips have been verified on ASPM mode */
const uint wifi_chips[] = {
	BCM4360_CHIP_ID,
	BCM43602_CHIP_ID,
	BCM43217_CHIP_ID,
	0
};

static aspm_info_t aspminfo;
static int aspm_config = ASPM_CONFIG_NONE;
static int aspm_policy = 0;

static aspmd_wksp_t *aspmd_nwksp = NULL;

uint aspmd_msg_level =
#ifdef BCMDBG
	ASPMD_ERROR_VAL;
#else
	0;
#endif /* BCMDBG */

static void
aspmd_wksp_cleanup(aspmd_wksp_t *nwksp)
{
	if (nwksp) {
		if (nwksp->eapd_socket >= 0) {
			ASPMD_INFO("close eapd_socket %d\n", nwksp->eapd_socket);
			close(nwksp->eapd_socket);
		}
		ASPMD_INFO("free nwksp memory\n");
		free(nwksp);
	}
}

static int
aspmd_open_eapd(void)
{
	int reuse = 1;
	int sock_fd;
	struct sockaddr_in sockaddr;

	/* open loopback socket to communicate with EAPD */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_ASPM_UDP_MPORT);

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		ASPMD_ERROR("Unable to create loopback socket\n");
		return -1;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		ASPMD_ERROR("Unable to setsockopt to loopback socket %d.\n", sock_fd);
		return -1;
	}

	if (bind(sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		ASPMD_ERROR("Unable to bind to loopback socket %d\n", sock_fd);
		return -1;
	}
	ASPMD_INFO("opened loopback socket %d in port %d\n", sock_fd, EAPD_WKSP_ASPM_UDP_MPORT);

	aspmd_nwksp->eapd_socket = sock_fd;
	return 0;
}

static int
aspmd_ep_config(char *name)
{
	aspm_info_t *ai = &aspminfo;
	int idx = 0;
	uint ep_conf = 0;
	char cmd_buf[128];
	struct maclist *mac_list;
	int mac_list_size;
	int i;
#ifdef BCMDBG
	char ea_str[ETHER_ADDR_STR_LEN];
#endif

	/* Check if EP supports ASPM */
	for (i = 0; i < ai->ep_nums; i++) {
		if (strcmp(name, ai->ep[i].name))
			continue;

		idx = i;

		if (BCM53573_CHIP(ai->ep[i].chipid)) {
			/* Not need to config the embedded WIFI chips */
			return 0;
		} else if ((ai->ep[i].aspm_forced == 1) || (ai->ep[i].aspm_supported == 0)) {
			/* ASPM has been configured in first_time_config();
			 * Just return for these cases.
			 */
			return 0;
		}
	}

	/* Check if ASPM needs to be enabled or disabled on EP */
	mac_list_size = sizeof(mac_list->count) + STA_MAX_COUNT * sizeof(struct ether_addr);
	if (!(mac_list = calloc(mac_list_size, 1))) {
		ASPMD_ERROR("ASPMD: calloc failed!");
		aspmd_nwksp->flags |= ASPMD_WKSP_FLAG_SHUTDOWN;
		return -1;
	}

	mac_list->count = STA_MAX_COUNT;
	wl_ioctl(name, WLC_GET_ASSOCLIST, mac_list, mac_list_size);
#ifdef BCMDBG
	ASPMD_INFO("Interface: %s\n", name);
	for (i = 0; i < mac_list->count; i++) {
		ASPMD_INFO("Associated:%s\n",
			ether_etoa((unsigned char *)&mac_list->ea[i], ea_str));
	}
#endif
	if (mac_list->count > 0) {
		/* ASPM OFF */
		ep_conf = 0;
	} else {
		/* ASPM ON */
		ep_conf = ai->ep[idx].aspm_policy;
	}

	free(mac_list);

	/* Do config */
	sprintf(cmd_buf, ASPM_CMD_EP, ai->ep[idx].iov_cmd, name, ep_conf);
	system(cmd_buf);
	ASPMD_INFO("CMD: %s\n", cmd_buf);

	return 0;
}

static int
aspmd_process_msg(char *readbuf, int bytes)
{
	bcm_event_t *pvt_data;

	/* check is it bcmevent? */
	pvt_data = (bcm_event_t *)(readbuf + IFNAMSIZ);

	if (ntohs(pvt_data->eth.ether_type) == ETHER_TYPE_BRCM) {
		wl_event_msg_t *event = &(pvt_data->event);
		uint32 event_type = ntohl(event->event_type);

		if (event_type == WLC_E_ASSOC_IND ||
			event_type == WLC_E_REASSOC_IND ||
			event_type == WLC_E_DISASSOC_IND) {
			ASPMD_INFO("%s event type: %d\n", event->ifname, event_type);
			aspmd_ep_config(event->ifname);
		}
	}

	return 0;
}

static int
aspmd_dispatch(void)
{
	fd_set *fdset = &aspmd_nwksp->fdset;
	int handle = aspmd_nwksp->eapd_socket;
	char *readbuf = aspmd_nwksp->aspm_readbuf;
	struct timeval timeout;
	int status, bytes;

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	FD_ZERO(fdset);
	FD_SET(handle, fdset);

	status = select(handle + 1, fdset, NULL, NULL, &timeout);
	if (status > 0 && FD_ISSET(handle, fdset)) {
		bytes = recv(handle, readbuf, ASPMD_EAPD_READ_MAX_LEN, 0);
		if (bytes > 0) {
			aspmd_process_msg(readbuf, bytes);
		}
	}

	return 0;
}

static int
aspmd_first_time_config(void)
{
	aspm_info_t *ai = &aspminfo;
	char cmd_buf[128];
	int i;

	sprintf(cmd_buf, ASPM_CMD_SYS, aspm_policies[ai->plat.api].sys_conf);
	system(cmd_buf);
	ASPMD_INFO("CMD: %s\n", cmd_buf);

	for (i = 0; i < ai->ep_nums; i++) {
		if ((ai->ep[i].aspm_forced == 1) || (ai->ep[i].aspm_supported == 0)) {
			sprintf(cmd_buf, ASPM_CMD_EP,
				ai->ep[i].iov_cmd, ai->ep[i].name, ai->ep[i].aspm_policy);
			system(cmd_buf);
			ASPMD_INFO("CMD: %s\n", cmd_buf);
		} else {
			aspmd_ep_config(ai->ep[i].name);
		}
	}

	return 0;
}

static int
aspmd_mainloop(void)
{
	if (aspmd_open_eapd()) {
		aspmd_wksp_cleanup(aspmd_nwksp);
		return -1;
	}

	/* Daemonize */
	if (daemon(1, 1) == -1) {
		aspmd_wksp_cleanup(aspmd_nwksp);
		perror("aspm_main_loop: daemon\n");
		exit(errno);
	}

	aspmd_first_time_config();

	/* Main loop to dispatch message */
	while (1) {
		if (aspmd_nwksp->flags & ASPMD_WKSP_FLAG_SHUTDOWN) {
			aspmd_wksp_cleanup(aspmd_nwksp);
			return 0;
		}

		/* Do packets dispatch */
		aspmd_dispatch();
	}

	return 0;
}

static void
aspmd_hup_hdlr(int sig)
{
	ASPMD_INFO("Shuting down aspmd ..........\n");
	if (aspmd_nwksp)
		aspmd_nwksp->flags |= ASPMD_WKSP_FLAG_SHUTDOWN;
	return;
}

aspmd_wksp_t *
aspmd_wksp_alloc_workspace(void)
{
	aspmd_wksp_t *nwksp = (aspmd_wksp_t *)calloc(sizeof(aspmd_wksp_t), 1);
	if (!nwksp)
		return NULL;

	nwksp->eapd_socket = -1;

	return nwksp;
}

static int
aspmd_plat_info(void)
{
	aspm_info_t *ai = &aspminfo;
	int found = 0;
	FILE *fp;
	char buf[128];
	uint chipid = 0, chiprev = 0, chippkg = 0;
	const plat_chip_t *plat;

	/* Get PlatSoc CHIP info */
	if ((fp = fopen("/proc/bcm_chipinfo", "r")) != NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "ChipID") != NULL) {
				sscanf(buf, "ChipID: 0x%x", &chipid);
				continue;
			}
			if (strstr(buf, "ChipRevision") != NULL) {
				sscanf(buf, "ChipRevision: 0x%x", &chiprev);
				continue;
			}
			if (strstr(buf, "PackageOption") != NULL) {
				sscanf(buf, "PackageOption: 0x%x", &chippkg);
				continue;
			}
		}
		fclose(fp);
	}

	/* ASPM has been configured by nvram */
	if (aspm_config == ASPM_CONFIG_IDLE || aspm_config == ASPM_CONFIG_FORCE) {
		found = 1;
		ai->plat.api = ASPM_POLICY_L1_PS;
	} else {
		/* Lookup the supported platform chip table */
		for (plat = plat_chips; plat->chipid; plat++) {
			if ((chipid == plat->chipid) && (chiprev >= plat->chiprev)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ASPMD_ERROR("PlatSoC chipid(0x%x) rev(0x%x) is unsupported\n",
				plat->chipid, plat->chiprev);
			return -1;
		}
		ai->plat.api = plat->api;
	}

	ai->plat.chipid = chipid;
	ai->plat.chiprev = chiprev;
	ai->plat.chippkg = chippkg;

	ASPMD_INFO("PlatSoC chipid(0x%x) rev(0x%x), pkg(0x%x), policy(%s)\n",
		ai->plat.chipid, ai->plat.chiprev, ai->plat.chippkg,
		aspm_policies[ai->plat.api].sys_conf);

	return 0;
}

static uint
aspmd_ep_aspm_forced(uint ep_chipid)
{
	aspm_info_t *ai = &aspminfo;
	uint aspm_forced = 0;

	/* Enable ASPM in IDLE mode by nvram */
	if (aspm_config == ASPM_CONFIG_IDLE)
		return aspm_forced;

	/* 53573/47189 + 43217: ASPM is enabled in ACTIVE mode. */
	if (BCM53573_CHIP(ai->plat.chipid)) {
		if (ep_chipid == BCM43217_CHIP_ID)
			 aspm_forced = 1;
	}
	/* 4709/4708 + 43217/43602/4360: ASPM is enabled in ACTIVE mode. */
	else if (BCM4707_CHIP(ai->plat.chipid)) {
		if ((ep_chipid == BCM43217_CHIP_ID) ||
			(ep_chipid == BCM43602_CHIP_ID) ||
			(ep_chipid == BCM4360_CHIP_ID))
			 aspm_forced = 1;
	}

	return aspm_forced;
}

static int
aspmd_ep_info(void)
{
	const uint *wchip = wifi_chips;
	int found;
	aspm_info_t *ai = &aspminfo;
	int i = 0;
	wlc_rev_info_t revinfo;
	char *ifnames, *next;
	char name[IFNAMSIZ];
	uint aspm_supported, unsupported_nums = 0;

	ifnames = nvram_safe_get("lan_ifnames");
	foreach(name, ifnames, next) {
		/* Get revision info */
		if (!strncmp(name, "eth", strlen("eth")) &&
			!wl_ioctl(name, WLC_GET_REVINFO, &revinfo, sizeof(revinfo))) {

			/* ASPM has been configured by nvram */
			if (aspm_config == ASPM_CONFIG_IDLE || aspm_config == ASPM_CONFIG_FORCE) {
				found = 1;
				aspm_supported = 1;
			} else {
				/* NOT enable ASPM on all PCIE links
				 * once 4366 is detected on the router platform
				 */
				if (BCM4365_CHIP(revinfo.chipnum)) {
					ASPMD_INFO("NOT enable ASPM on all EPs\n");
					return -1;
				}

				/* Lookup the supported wifi chip table */
				found = 0;
				aspm_supported = 1;
				for (wchip = wifi_chips; *wchip; wchip++) {
					if (revinfo.chipnum == *wchip) {
						found = 1;
						break;
					}
				}
				if (!found) {
					ASPMD_ERROR("%s chipid(0x%x) is unsupported\n",
						name, revinfo.chipnum);
					aspm_supported = 0;
				}
			}

			if (revinfo.bus == PCI_BUS)
				strcpy(ai->ep[i].iov_cmd, "wl");
			else if (revinfo.bus == SI_BUS)
				strcpy(ai->ep[i].iov_cmd, "dhd");
			else {
				ASPMD_ERROR("%s unknow bustype(%d)\n", name, revinfo.bus);
				aspm_supported = 0;
			}

			strcpy(ai->ep[i].name, name);
			ai->ep[i].chipid = revinfo.chipnum;
			ai->ep[i].chiprev = revinfo.chiprev;
			ai->ep[i].chippkg = revinfo.chippkg;
			ai->ep[i].bustype = revinfo.bus;
			ai->ep[i].aspm_supported = aspm_supported;
			/* ASPM is configured as force by nvram */
			if (aspm_config == ASPM_CONFIG_FORCE)
				ai->ep[i].aspm_forced = 1;
			else
				ai->ep[i].aspm_forced = aspmd_ep_aspm_forced(revinfo.chipnum);

			/* ASPM policy is configured by nvram */
			if (aspm_policy) {
				ai->ep[i].aspm_policy = aspm_policy;
			} else if (!aspm_supported) {
				ai->ep[i].aspm_policy = 0;
			} else {
				ai->ep[i].aspm_policy = aspm_policies[ai->plat.api].ep_conf;
			}

			ai->ep_nums++;

			ASPMD_INFO("%s chipid(0x%x) rev(0x%x), pkg(0x%x), bus(0x%x),"
				"aspm_supported(%d), aspm_forced(%d), aspm_policy(0x%03x)\n",
				ai->ep[i].name, ai->ep[i].chipid, ai->ep[i].chiprev,
				ai->ep[i].chippkg, ai->ep[i].bustype, ai->ep[i].aspm_supported,
				ai->ep[i].aspm_forced, ai->ep[i].aspm_policy);

			if (!aspm_supported)
				unsupported_nums++;

			i++;
		}
	}

	if (ai->ep_nums == unsupported_nums) {
		ASPMD_INFO("ASPM is unsupported on all EPs\n");
		return -1;
	}

	return 0;
}

static bool
aspmd_check_config_once(void)
{
	aspm_info_t *ai = &aspminfo;
	int i;
	bool ret = TRUE;

	if (aspm_config == ASPM_CONFIG_FORCE)
		return ret;

	for (i = 0; i < ai->ep_nums; i++) {
		if ((ai->ep[i].aspm_supported == 1) && (ai->ep[i].aspm_forced == 0)) {
			ret = FALSE;
			break;
		}
	}

	return ret;
}

static int
aspmd_config_once(void)
{
	aspm_info_t *ai = &aspminfo;
	char cmd_buf[128];
	int i;

	if (!aspmd_check_config_once())
		return 0;

	/* ASPM ON */
	sprintf(cmd_buf, ASPM_CMD_SYS, aspm_policies[ai->plat.api].sys_conf);
	system(cmd_buf);
	ASPMD_INFO("CMD: %s\n", cmd_buf);

	for (i = 0; i < ai->ep_nums; i++) {
		sprintf(cmd_buf, ASPM_CMD_EP,
			ai->ep[i].iov_cmd, ai->ep[i].name, ai->ep[i].aspm_policy);
		system(cmd_buf);
		ASPMD_INFO("CMD: %s\n", cmd_buf);
	}

	return -1;
}

static int
aspmd_init(void)
{
	aspm_info_t *ai = &aspminfo;
	char cmd_buf[128];

	/* ASPM OFF */
	sprintf(cmd_buf, ASPM_CMD_SYS, aspm_policies[0].sys_conf);
	system(cmd_buf);
	ASPMD_INFO("CMD: %s\n", cmd_buf);

	/* Aspmd isn't running and ASPM is disabled */
	if (aspm_config == ASPM_CONFIG_DISABLE) {
		ASPMD_INFO("ASPMD is disabled\n");
		return -1;
	}

	/* Reset aspm info */
	memset(ai, 0, sizeof(aspm_info_t));

	/* Get platform info */
	if (aspmd_plat_info() < 0)
		return -1;

	/* Get PCIe Endpoints info */
	if (aspmd_ep_info() < 0)
		return -1;

	/* Only do ASPM configuration once */
	if (aspmd_config_once() < 0)
		return -1;

	return 0;
}

int
main(int argc, char *argv[])
{
#ifdef BCMDBG
	char *dbg;
#endif
	char *nv_config, *nv_aspm_policy;
	int ret = 0;

#ifdef BCMDBG
	/* Get aspmd_msg_level from nvram */
	if ((dbg = nvram_get("aspmd_dbg")) != NULL) {
		aspmd_msg_level = (uint)strtoul(dbg, NULL, 0);
	}
#endif

	/* Get nvram setting */
	if ((nv_config = nvram_get("aspm_config")) != NULL) {
		aspm_config = (uint)strtoul(nv_config, NULL, 0);
		ASPMD_INFO("Config ASPM operation as %d "
			"(0: Disable, 1: Enable ASPM in IDLE mode, 2: Force)\n", aspm_config);
	}
	if ((nv_aspm_policy = nvram_get("aspm_policy")) != NULL) {
		/* This nvram is bitmap definition.
		 * Only use bit0, bit1 and bit8 to comply with PCIE Link Control register.
		 *   Bit0: Enable/Disable ASPM L0s
		 *   Bit1: Enable/Disable ASPM L1
		 *   Bit8: Enable/Disable CLKREQ
		 */
		aspm_policy = (uint)strtoul(nv_aspm_policy, NULL, 0);
		aspm_policy &= 0x103;
		ASPMD_INFO("Config EP's ASPM policy as 0x%03x\n", aspm_policy);
	}

	/* Aspmd initialization */
	if (aspmd_init() < 0) {
		ASPMD_INFO("ASPMD exit\n");
		return -1;
	}

	/* Alloc eapd work space */
	if (!(aspmd_nwksp = aspmd_wksp_alloc_workspace())) {
		ASPMD_ERROR("Unable to allocate wksp memory. Quitting...\n");
		return -1;
	}

	/* Establish a handler to handle SIGTERM. */
	signal(SIGTERM, aspmd_hup_hdlr);

	ret = aspmd_mainloop();

	return ret;
}
