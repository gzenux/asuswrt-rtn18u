/*
 * BSD shared include file
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bsd.h 398225 2013-04-23 22:33:56Z $
 */

#ifndef _bsd_h_
#define _bsd_h_

#include <proto/ethernet.h>
#include <proto/bcmeth.h>
#include <proto/bcmevent.h>
#include <proto/802.11.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <assert.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <bcmparams.h>
#include <bcmtimer.h>
#include <bcmendian.h>

#include <shutils.h>
#include <bcmendian.h>
#include <bcmwifi_channels.h>
#include <wlioctl.h>
#include <wlutils.h>

#include <security_ipc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>


#define BSD_OK	0
#define BSD_FAIL -1


/* default polling interval */
#define BSD_POLL_INTERVAL 		1
/* defalt sta_info poll interval */
#define BSD_STATUS_POLL_INTV	10
#define BSD_COUNTER_POLL_INTV	0
/* defalt interval to cleanup assoclist */
#define BSD_STA_TIMEOUT			120
/* defalt sta dwell time after channel band */
#define BSD_STEER_TIMEOUT		60
/* defalt stahisto timeout */
#define BSD_STA_HISTO_TIMEOUT	3600
/* defalt probe list timeout */
#define BSD_PROBE_TIMEOUT	3600
/* time intv of last probe seen */
#define BSD_PROBE_GAP		30
/* defalt probe list timeout */
#define BSD_MACLIST_TIMEOUT	30

#define BSD_BUFSIZE_4K	4096

typedef enum {
	BSD_MODE_DISABLE = 0,
	BSD_MODE_MONITOR = 1,
	BSD_MODE_STEER = 2,
	BSD_MODE_MAX = 3
} bsd_mode_t;

typedef enum {
	BSD_ROLE_NONE = 0,
	BSD_ROLE_PRIMARY = 1,
	BSD_ROLE_HELPER = 2,
	BSD_ROLE_STANDALONE = 3,
	BSD_ROLE_MAX = 4
} bsd_role_t;

#define BSD_BSS_PRIO_DISABLE	0xff

#define BSD_VERSION		1
#define BSD_DFLT_FD		-1

/* Debug Print */
extern int bsd_msglevel;
#define BSD_DEBUG_ERROR		0x000001
#define BSD_DEBUG_WARNING	0x000002
#define BSD_DEBUG_INFO		0x000004
#define BSD_DEBUG_TO		0x000008
#define BSD_DEBUG_STEER		0x000010
#define BSD_DEBUG_EVENT		0x000020
#define BSD_DEBUG_HISTO		0x000040
#define BSD_DEBUG_CCA		0x000080
#define BSD_DEBUG_AT		0x000100
#define BSD_DEBUG_RPC		0x000200
#define BSD_DEBUG_RPCD		0x000400
#define BSD_DEBUG_RPCEVT	0x000800

#define BSD_DEBUG_DUMP		0x100000
#define BSD_DEBUG_PROBE		0x400000
#define BSD_DEBUG_ALL		0x800000

#define BSD_ERROR(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_ERROR) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_WARNING(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_WARNING) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_INFO(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_INFO) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_TO(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_TO) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_STEER(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_STEER) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_EVENT(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_EVENT) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_HISTO(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_HISTO) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_CCA(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_CCA) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_CCA_PLAIN(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_CCA) printf(fmt, ##arg); } while (0)

#define BSD_AT(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_AT) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)
#define BSD_AT_PLAIN(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_AT) printf(fmt, ##arg); } while (0)

#define BSD_RPC(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPC) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)
#define BSD_RPC_PLAIN(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPC) printf(fmt, ##arg); } while (0)

#define BSD_RPCD(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPCD) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)
#define BSD_RPCD_PLAIN(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPCD) printf(fmt, ##arg); } while (0)

#define BSD_RPCEVT(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPCEVT) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)
#define BSD_RPCEVT_PLAIN(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_RPCEVT) printf(fmt, ##arg); } while (0)

#define BSD_PROB(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_PROBE) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_ALL(fmt, arg...) \
		do { if (bsd_msglevel & BSD_DEBUG_ALL) \
			printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_PRINT(fmt, arg...) \
		do { printf("BSD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define BSD_PRINT_PLAIN(fmt, arg...) \
		do { printf(fmt, ##arg); } while (0)

#define BSD_DUMP_ENAB	(bsd_msglevel & BSD_DEBUG_DUMP)
#define BSD_PROB_ENAB	(bsd_msglevel & BSD_DEBUG_PROBE)
#define BSD_STEER_ENAB	(bsd_msglevel & BSD_DEBUG_STEER)

#define tr() do { if (BSD_DUMP_ENAB) printf("%s@%d\n", __FUNCTION__, __LINE__); } while (0)
#define BSD_ENTER()	BSD_ALL("Enter...\n")
#define BSD_EXIT() 	BSD_ALL("Exit...\n")

#define BSD_RPC_ENAB	(bsd_msglevel & BSD_DEBUG_RPC)
#define BSD_RPCEVT_ENAB	(bsd_msglevel & BSD_DEBUG_RPCEVT)


#define BSD_EVTENTER()	BSD_EVENT("Enter...\n")
#define BSD_EVTEXIT() 	BSD_EVENT("Exit...\n")

#define BSD_CCAENTER()	BSD_CCA("Enter...\n")
#define BSD_CCAEXIT() 	BSD_CCA("Exit...\n")
#define BSD_CCA_ENAB	(bsd_msglevel & BSD_DEBUG_CCA)

#define BSD_ATENTER()	BSD_AT("Enter...\n")
#define BSD_ATEXIT() 	BSD_AT("Exit...\n")
#define BSD_AT_ENAB		(bsd_msglevel & BSD_DEBUG_AT)

#define BSD_MAX_PRIO 		0x4
#define BSD_IFNAME_SIZE		16
#define BSD_MAX_INTF		3
#define BSD_MAXBSSCFG		WL_MAXBSSCFG

#define BSD_SCHEME			0

typedef struct bsd_staprio_config {
	struct ether_addr addr;
	uint8 prio;			/* 1-Video STA, 0-data-STA */
	uint8 steerflag;	/* assoc'ed STAs can steer?  */
	struct bsd_staprio_config *next;
} bsd_staprio_config_t;

typedef struct bsd_sta_info {
	time_t timestamp; 	/* assoc timestamp */
	time_t active; 		/* activity timestamp */

	struct ether_addr addr; /* mac addr */
	struct ether_addr paddr; /* psta intf */
	uint8 prio;			/* 1-Video STA, 0-data-STA */
	uint8 steerflag;	/* assoc'ed STAs can steer?  */

	uint8 band;
	int32 rssi;;	/* per antenna rssi */
	uint32 phy_rate;	/* unit Mbps */
	uint32 tx_rate;		/* unit Mbps */
	uint32 rx_rate;		/* unit Mbps */
	uint32 rx_pkts;	/* # of data packets recvd */
	uint32 tx_pkts;		/* # of packets transmitted */
	uint32 rx_bps;	/* txbps, in Kbps */
	uint32 tx_bps;	/* txbps, in Kbps */
	uint32 tx_failures;	/* tx retry */
	uint32 idle;		/* time since data pkt rx'd from sta */
	uint32 in;

	uint8 at_ratio;		/* airtime ratio */
	uint32 phyrate;		/* txsucc rate */
	uint32 datarate;		/* txsucc rate */

	uint score;			/* STA's score */
	uint32 rx_tot_pkts;	/* # of data packets recvd */
	uint32 tx_tot_failures;	/* tx retry */
	uint32 tx_tot_pkts;		/* # of packets transmitted */
	struct bsd_sta_info *snext, *sprev;
	struct bsd_sta_info *next, *prev;
	struct bsd_bssinfo *bssinfo;
} bsd_sta_info_t;

#define BSD_INIT_ASSOC	(1 << 0)
#define BSD_INIT_BS_5G	(1 << 1)
#define BSD_INIT_BS_2G	(1 << 2)

#define BSD_BAND_2G	WLC_BAND_2G
#define BSD_BAND_5G	WLC_BAND_5G
#define BSD_BAND_ALL WLC_BAND_ALL

typedef struct bsd_maclist {
	struct ether_addr addr;
	time_t timestamp; 	/* assoc timestamp */
	uint8 band;
	struct bsd_maclist *next;
} bsd_maclist_t;

typedef struct bsd_policy {
	int idle_rate;	/* data rate threshold to measure STA is idle */
	int rssi;		/* rssi threshold */
	int wprio;		/* weight for prio */
	int wrssi;			/* weight for RSSI */
	int wphy_rate;	/* weight for phy_rate */
	int wtx_failures;		/* weight for tx retry */
	int wtx_rate;		/* weight for tx_rate */
	int wrx_rate;	/* weight for rx_rate */
} bsd_policy_t;


#define BSD_BSSCFG_NOTSTEER	(1 << 0)

#define BSD_POLICY_LOW_RSSI 0
#define BSD_POLICY_HIGH_RSSI 1
#define BSD_POLICY_LOW_PHYRATE 2
#define BSD_POLICY_HIGH_PHYRATE 3

typedef struct bsd_bssinfo {
	bool valid;
	char ifnames[BSD_IFNAME_SIZE]; /* interface names */
	char prefix[BSD_IFNAME_SIZE];	/* Prefix name */
	char ssid[32];
	struct ether_addr bssid;
	chanspec_t chanspec;
	uint8 rclass;
	txpwr_target_max_t txpwr;

	int idx;
	uint8 prio;
	uint8 steerflag;	/* STAs can steer?  */
	struct bsd_bssinfo *steer_bssinfo;
	char steer_prefix[BSD_IFNAME_SIZE];
	uint8 algo;
	uint8 policy;
	bsd_policy_t policy_params;
	struct bsd_intf_info *intf_info;
	uint8 assoc_cnt;	/* no of data-sta assoc-ed */
	bsd_sta_info_t *assoclist;
	bsd_sta_info_t *scorelist;
	bsd_maclist_t *maclist;
	int macmode;	/* deny, allow, disable */

	struct maclist *static_maclist;
	int static_macmode;

	/* hack:jhc */
	uint32 tx_tot_pkts, rx_tot_pkts;
	bool video_idle;
} bsd_bssinfo_t;

#define BSD_PROBE_STA_HASH	32
#define BSD_MAC_HASH(ea) 	(((ea).octet[4]+(ea).octet[5])% BSD_PROBE_STA_HASH)

#define BSD_CHANIM_STATS_MAX	60
typedef struct bsd_chanim_stats {
	chanim_stats_t stats;
	uint8 valid;
} bsd_chanim_stats_t;

#define BSD_CHAN_STEER_MASK	0x80
typedef enum {
	BSD_CHAN_BUSY_UNKNOWN = 0,
	BSD_CHAN_BUSY = 1,
	BSD_CHAN_IDLE = 2,
	BSD_CHAN_UTIL_MAX = 3
} bsd_chan_state_t;

#define BSD_CHAN_BUSY_MIN		20
#define BSD_CHAN_BUSY_MAX		80
#define BSD_CHAN_BUSY_CNT		3	/* continuous sample cnt */
#define BSD_CHAN_BUSY_PERIOD	5	/* sample persiod. 5 sec */

typedef struct bsd_chan_util_info {
	bsd_chanim_stats_t rec[BSD_CHANIM_STATS_MAX];
	uint8 idx;
	uint8 ticks;
	int period;
	int cnt;
	int chan_busy_max;
	int chan_busy_min;
	bsd_chan_state_t state;
} bsd_chan_util_info_t;

typedef struct bsd_intf_info {
	uint8 band;
	uint8 phytype;

	uint8 remote;	/* adapter is remote? */
	uint8 enabled;
	int idx;
	bsd_chan_util_info_t chan_util_info;
	bsd_bssinfo_t bsd_bssinfo[WL_MAXBSSCFG];
} bsd_intf_info_t;

#define BSD_MAX_STA_HISTO	30

typedef enum {
	BSD_STA_INVALID = 0,
	BSD_STA_ASSOCLIST = 1,
	BSD_STA_AUTH = 2,
	BSD_STA_ASSOC = 3,
	BSD_STA_STEERED = 4,
	BSD_STA_DEAUTH = 5,
	BSD_STA_DISASSOC = 6,
	BSD_STA_MAX = 7
} bsd_sta_state_t;

typedef struct bsd_sta_status {
	bsd_bssinfo_t *bssinfo;
	bsd_sta_state_t state;
	time_t timestamp;	/* timestamp */
} bsd_sta_status_t;

typedef struct bsd_sta_histo {
	struct ether_addr addr;
	uint8 band;
	bsd_sta_status_t status[BSD_MAX_STA_HISTO];
	uint8 idx;
	time_t timestamp;	/* last updated timestamp */
	struct bsd_sta_histo *next;
} bsd_sta_histo_t;

#define BSD_MAX_AT_SCB			5
#define BSD_VIDEO_AT_RATIO_BASE	5
#define BSD_SLOWEST_AT_RATIO	40
#define BSD_PHYRATE_DELTA		200

typedef struct bsd_info {
	int version;
	int event_fd;
	int rpc_listenfd;
	int rpc_eventfd, rpc_ioctlfd;

	/* config info */
	bsd_role_t role;
	char helper_addr[32], primary_addr[32];
	int hport, pport;
	bsd_mode_t mode; /* monitor, or steer */
	uint poll_interval; /* polling interval */
	uint ticks;		/* number of polling intervals */
	uint8 status_poll;
	uint8 counter_poll, idle_rate;
	uint probe_timeout, probe_gap;
	uint maclist_timeout;
	uint steer_timeout;
	uint sta_timeout;
	uint stahisto_timeout;
	uint8 prefer_5g;
	uint8 scheme;

	/* v/(v+d) threshold. video_at_ratio[n] is threshold for n+1 data-stas */
	/* n data-sta actively assoc, v/(v+d) > video_at_ratio[n]. steer */
	uint32 video_at_ratio[BSD_MAX_AT_SCB];

	/* for all data-STA, if delta(phyrate) > phyrate_delat
	 * && at_time(lowest phyrate sta) > at_rati: steer
	 */
	/* slowest data-sta airtime ratio */
	uint32 slowest_at_ratio;
	/* data-sta phyrate Delat threshold */
	uint32 phyrate_delta;

	uint8 ifidx, bssidx;
	uint8 over; /* tmp var: 1: 5G oversubscrioption, 2: 5G undersubscription, 0:no steer */
	bsd_staprio_config_t *staprio;

	/* info/data for each intf */
	bsd_maclist_t *prbsta[BSD_PROBE_STA_HASH];
	bsd_sta_histo_t *stahisto[BSD_PROBE_STA_HASH];
	bsd_intf_info_t intf_info[BSD_MAX_INTF];
} bsd_info_t;


/* Data structiure or rpc operation */
#define BSD_DEFT_HELPER_ADDR	"192.168.1.2"
#define BSD_DEFT_PRIMARY_ADDR	"192.168.1.1"

#define	HELPER_PORT		9877	/* Helper TCP Server port */
#define	PRIMARY_PORT	9878	/* Primary TCP Server port  */

typedef enum {
	BSD_RPC_ID_IOCTL = 0,
	BSD_RPC_ID_EVENT = 1,
	BSD_RPC_ID_NVRAM = 2,
	BSD_RPC_ID_MAX = 3
} bsd_rpc_id_t;

typedef  struct  bsd_rpc_cmd {
	int ret;
	char name[BSD_IFNAME_SIZE];
	int cmd;
	int len;
} bsd_rpc_cmd_t;

typedef struct {
	bsd_rpc_id_t  id;
	bsd_rpc_cmd_t cmd;
} bsd_rpc_pkt_t;

#define BSD_RPC_HEADER_LEN	(sizeof(bsd_rpc_pkt_t) + 1)

#define BSD_IOCTL_MAXLEN 4096
extern char ioctl_buf[BSD_IOCTL_MAXLEN];
extern char ret_buf[BSD_IOCTL_MAXLEN];
extern char cmd_buf[BSD_IOCTL_MAXLEN];
extern char maclist_buf[BSD_IOCTL_MAXLEN];

#define DIV_QUO(num, div) ((num)/div)  /* Return the quotient of division to avoid floats */
#define DIV_REM(num, div) (((num%div) * 100)/div) /* Return the remainder of division */

#define BSDSTRNCPY(dst, src, len)	 \
	do { \
		if (strlen(src) < len) \
			strcpy(dst, src); \
		else {	\
			strncpy(dst, src, len -1); dst[len - 1] = '\0'; \
		} \
	} while (0)

extern int bs_safe_get_conf(char *outval, int outval_size, char *name);
extern void sleep_ms(const unsigned int ms);
extern void bsd_dump_info(bsd_info_t *info);
extern void bsd_retrieve_config(bsd_info_t *info);
extern int bsd_info_init(bsd_info_t *bsd_info);
extern void bsd_assoc_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr);
extern void bsd_auth_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr);
extern void bsd_deauth_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr);
extern void bsd_disassoc_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr);
extern void bsd_remove_sta_reason(bsd_info_t *info, char *ifname, uint8 remote,
	struct ether_addr *addr, bsd_sta_state_t reason);
extern void bsd_bssinfo_cleanup(bsd_info_t *info);
extern void bsd_update_psta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr,
	struct ether_addr *paddr);
extern void bsd_update_stainfo(bsd_info_t *info);

extern void bsd_update_stb_info(bsd_info_t *info);
extern void bsd_update_cca_stats(bsd_info_t *info);
extern void bsd_reset_chan_busy(bsd_info_t *info);

extern void bsd_add_prbsta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr);
extern void bsd_timeout_prbsta(bsd_info_t *info);
extern void bsd_timeout_maclist(bsd_info_t *info);
extern void bsd_dump_info(bsd_info_t *info);
extern void bsd_steer_sta(bsd_info_t *info, bsd_sta_info_t *sta);
extern void bsd_check_steer(bsd_info_t *info);
extern int bsd_get_max_policy(bsd_info_t *info);
extern bsd_policy_t *bsd_get_policy_params(bsd_bssinfo_t *bssinfo);
extern int bsd_get_max_algo(bsd_info_t *info);
extern int bsd_get_max_scheme(bsd_info_t *info);
extern void bsd_set_maclist(bsd_bssinfo_t *bssinfo);
extern void bsd_stamp_maclist(bsd_info_t *info, bsd_bssinfo_t *bssinfo, struct ether_addr *addr);
extern void bsd_remove_maclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr);
extern void bsd_addto_maclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr);
extern bsd_maclist_t *bsd_maclist_by_addr(bsd_bssinfo_t *bssinfo, struct ether_addr *addr);
extern void bsd_timeout_sta(bsd_info_t *info);
extern void bsd_timeout_stahisto(bsd_info_t *info);
extern bool bsd_is_sta_dualband(bsd_info_t *info, struct ether_addr *addr);
extern int bsd_wl_ioctl(bsd_bssinfo_t *bssinfo, int cmd, void *buf, int len);
extern void bsd_rpc_dump(char *ptr, int len, int enab);
extern void bsd_proc_socket(bsd_info_t*info, struct timeval *tv);
extern void bsd_close_rpc_eventfd(bsd_info_t*info);
extern void bsd_close_eventfd(bsd_info_t*info);
extern int bsd_open_rpc_eventfd(bsd_info_t*info);
extern int bsd_open_eventfd(bsd_info_t*info);
#endif /*  _bsd_h_ */
