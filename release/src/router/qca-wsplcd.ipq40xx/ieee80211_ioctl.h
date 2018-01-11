/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2013-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _NET80211_IEEE80211_IOCTL_H_
#define _NET80211_IEEE80211_IOCTL_H_

/*
 * IEEE 802.11 ioctls.
 */
#ifndef EXTERNAL_USE_ONLY
#include <_ieee80211.h>
/* duplicate defination - to avoid including ieee80211_var.h */
#ifndef __ubicom32__
#define IEEE80211_ADDR_COPY(dst,src)    OS_MEMCPY(dst, src, IEEE80211_ADDR_LEN)
#else
#define IEEE80211_ADDR_COPY(dst,src)    OS_MACCPY(dst, src)
#endif
#define IEEE80211_KEY_XMIT      0x01    /* key used for xmit */
#define IEEE80211_KEY_RECV      0x02    /* key used for recv */
#ifndef __ubicom32__
#define IEEE80211_ADDR_EQ(a1,a2)        (OS_MEMCMP(a1, a2, IEEE80211_ADDR_LEN) == 0)
#else
#define IEEE80211_ADDR_EQ(a1,a2)        (OS_MACCMP(a1, a2) == 0)
#endif
#define IEEE80211_APPIE_MAX                  1024 /* max appie buffer size */
#define IEEE80211_KEY_GROUP     0x04    /* key used for WPA group operation */
#define IEEE80211_SCAN_MAX_SSID     10
#define IEEE80211_CHANINFO_MAX           1000 /* max Chaninfo buffer size */
#endif /* EXTERNAL_USE_ONLY */

 /*
  * Macros used for Tr069 objects
  */
#define TR069MAXPOWERRANGE 30
#define TR69MINTXPOWER 1
#define TR69MAX_RATE_POWER 63
#define TR69SCANSTATEVARIABLESIZE 20

#if 0
/*
 * Per/node (station) statistics available when operating as an AP.
 */
struct ieee80211_nodestats {
	u_int32_t	ns_rx_data;		/* rx data frames */
	u_int32_t	ns_rx_mgmt;		/* rx management frames */
	u_int32_t	ns_rx_ctrl;		/* rx control frames */
	u_int32_t	ns_rx_ucast;		/* rx unicast frames */
	u_int32_t	ns_rx_mcast;		/* rx multi/broadcast frames */
	u_int64_t	ns_rx_bytes;		/* rx data count (bytes) */
	u_int64_t	ns_rx_beacons;		/* rx beacon frames */
	u_int32_t	ns_rx_proberesp;	/* rx probe response frames */

	u_int32_t	ns_rx_dup;		/* rx discard 'cuz dup */
	u_int32_t	ns_rx_noprivacy;	/* rx w/ wep but privacy off */
	u_int32_t	ns_rx_wepfail;		/* rx wep processing failed */
	u_int32_t	ns_rx_demicfail;	/* rx demic failed */
	u_int32_t	ns_rx_decap;		/* rx decapsulation failed */
	u_int32_t	ns_rx_defrag;		/* rx defragmentation failed */
	u_int32_t	ns_rx_disassoc;		/* rx disassociation */
	u_int32_t	ns_rx_deauth;		/* rx deauthentication */
    u_int32_t   ns_rx_action;       /* rx action */
	u_int32_t	ns_rx_decryptcrc;	/* rx decrypt failed on crc */
	u_int32_t	ns_rx_unauth;		/* rx on unauthorized port */
	u_int32_t	ns_rx_unencrypted;	/* rx unecrypted w/ privacy */

	u_int32_t	ns_tx_data;		/* tx data frames */
	u_int32_t	ns_tx_mgmt;		/* tx management frames */
	u_int32_t	ns_tx_ucast;		/* tx unicast frames */
	u_int32_t	ns_tx_mcast;		/* tx multi/broadcast frames */
	u_int64_t	ns_tx_bytes;		/* tx data count (bytes) */
	u_int32_t	ns_tx_probereq;		/* tx probe request frames */
	u_int32_t	ns_tx_uapsd;		/* tx on uapsd queue */

	u_int32_t	ns_tx_novlantag;	/* tx discard 'cuz no tag */
	u_int32_t	ns_tx_vlanmismatch;	/* tx discard 'cuz bad tag */
#ifdef ATH_SUPPORT_IQUE
	u_int32_t	ns_tx_dropblock;	/* tx discard 'cuz headline block */
#endif

	u_int32_t	ns_tx_eosplost;		/* uapsd EOSP retried out */

	u_int32_t	ns_ps_discard;		/* ps discard 'cuz of age */

	u_int32_t	ns_uapsd_triggers;	     /* uapsd triggers */
	u_int32_t	ns_uapsd_duptriggers;	 /* uapsd duplicate triggers */
	u_int32_t	ns_uapsd_ignoretriggers; /* uapsd duplicate triggers */
	u_int32_t	ns_uapsd_active;         /* uapsd duplicate triggers */
	u_int32_t	ns_uapsd_triggerenabled; /* uapsd duplicate triggers */

	/* MIB-related state */
	u_int32_t	ns_tx_assoc;		/* [re]associations */
	u_int32_t	ns_tx_assoc_fail;	/* [re]association failures */
	u_int32_t	ns_tx_auth;		/* [re]authentications */
	u_int32_t	ns_tx_auth_fail;	/* [re]authentication failures*/
	u_int32_t	ns_tx_deauth;		/* deauthentications */
	u_int32_t	ns_tx_deauth_code;	/* last deauth reason */
	u_int32_t	ns_tx_disassoc;		/* disassociations */
	u_int32_t	ns_tx_disassoc_code;	/* last disassociation reason */
	u_int32_t	ns_psq_drops;		/* power save queue drops */
};

/*
 * Summary statistics.
 */
struct ieee80211_stats {
	u_int32_t	is_rx_badversion;	/* rx frame with bad version */
	u_int32_t	is_rx_tooshort;		/* rx frame too short */
	u_int32_t	is_rx_wrongbss;		/* rx from wrong bssid */
	u_int32_t	is_rx_dup;		/* rx discard 'cuz dup */
	u_int32_t	is_rx_wrongdir;		/* rx w/ wrong direction */
	u_int32_t	is_rx_mcastecho;	/* rx discard 'cuz mcast echo */
	u_int32_t	is_rx_notassoc;		/* rx discard 'cuz sta !assoc */
	u_int32_t	is_rx_noprivacy;	/* rx w/ wep but privacy off */
	u_int32_t	is_rx_unencrypted;	/* rx w/o wep and privacy on */
	u_int32_t	is_rx_wepfail;		/* rx wep processing failed */
	u_int32_t	is_rx_decap;		/* rx decapsulation failed */
	u_int32_t	is_rx_mgtdiscard;	/* rx discard mgt frames */
	u_int32_t	is_rx_ctl;		/* rx discard ctrl frames */
	u_int32_t	is_rx_beacon;		/* rx beacon frames */
	u_int32_t	is_rx_rstoobig;		/* rx rate set truncated */
	u_int32_t	is_rx_elem_missing;	/* rx required element missing*/
	u_int32_t	is_rx_elem_toobig;	/* rx element too big */
	u_int32_t	is_rx_elem_toosmall;	/* rx element too small */
	u_int32_t	is_rx_elem_unknown;	/* rx element unknown */
	u_int32_t	is_rx_badchan;		/* rx frame w/ invalid chan */
	u_int32_t	is_rx_chanmismatch;	/* rx frame chan mismatch */
	u_int32_t	is_rx_nodealloc;	/* rx frame dropped */
	u_int32_t	is_rx_ssidmismatch;	/* rx frame ssid mismatch  */
	u_int32_t	is_rx_auth_unsupported;	/* rx w/ unsupported auth alg */
	u_int32_t	is_rx_auth_fail;	/* rx sta auth failure */
	u_int32_t	is_rx_auth_countermeasures;/* rx auth discard 'cuz CM */
	u_int32_t	is_rx_assoc_bss;	/* rx assoc from wrong bssid */
	u_int32_t	is_rx_assoc_notauth;	/* rx assoc w/o auth */
	u_int32_t	is_rx_assoc_capmismatch;/* rx assoc w/ cap mismatch */
	u_int32_t	is_rx_assoc_norate;	/* rx assoc w/ no rate match */
	u_int32_t	is_rx_assoc_badwpaie;	/* rx assoc w/ bad WPA IE */
	u_int32_t	is_rx_deauth;		/* rx deauthentication */
	u_int32_t	is_rx_disassoc;		/* rx disassociation */
    u_int32_t   is_rx_action;       /* rx action mgt */
	u_int32_t	is_rx_badsubtype;	/* rx frame w/ unknown subtype*/
	u_int32_t	is_rx_nobuf;		/* rx failed for lack of buf */
	u_int32_t	is_rx_decryptcrc;	/* rx decrypt failed on crc */
	u_int32_t	is_rx_ahdemo_mgt;	/* rx discard ahdemo mgt frame*/
	u_int32_t	is_rx_bad_auth;		/* rx bad auth request */
	u_int32_t	is_rx_unauth;		/* rx on unauthorized port */
	u_int32_t	is_rx_badkeyid;		/* rx w/ incorrect keyid */
	u_int32_t	is_rx_ccmpreplay;	/* rx seq# violation (CCMP) */
	u_int32_t	is_rx_ccmpformat;	/* rx format bad (CCMP) */
	u_int32_t	is_rx_ccmpmic;		/* rx MIC check failed (CCMP) */
	u_int32_t	is_rx_tkipreplay;	/* rx seq# violation (TKIP) */
	u_int32_t	is_rx_tkipformat;	/* rx format bad (TKIP) */
	u_int32_t	is_rx_tkipmic;		/* rx MIC check failed (TKIP) */
	u_int32_t	is_rx_tkipicv;		/* rx ICV check failed (TKIP) */
	u_int32_t	is_rx_badcipher;	/* rx failed 'cuz key type */
	u_int32_t	is_rx_nocipherctx;	/* rx failed 'cuz key !setup */
	u_int32_t	is_rx_acl;		/* rx discard 'cuz acl policy */
	u_int32_t	is_rx_ffcnt;		/* rx fast frames */
	u_int32_t	is_rx_badathtnl;   	/* driver key alloc failed */
	u_int32_t	is_tx_nobuf;		/* tx failed for lack of buf */
	u_int32_t	is_tx_nonode;		/* tx failed for no node */
	u_int32_t	is_tx_unknownmgt;	/* tx of unknown mgt frame */
	u_int32_t	is_tx_badcipher;	/* tx failed 'cuz key type */
	u_int32_t	is_tx_nodefkey;		/* tx failed 'cuz no defkey */
	u_int32_t	is_tx_noheadroom;	/* tx failed 'cuz no space */
	u_int32_t	is_tx_ffokcnt;		/* tx fast frames sent success */
	u_int32_t	is_tx_fferrcnt;		/* tx fast frames sent success */
	u_int32_t	is_scan_active;		/* active scans started */
	u_int32_t	is_scan_passive;	/* passive scans started */
	u_int32_t	is_node_timeout;	/* nodes timed out inactivity */
	u_int32_t	is_crypto_nomem;	/* no memory for crypto ctx */
	u_int32_t	is_crypto_tkip;		/* tkip crypto done in s/w */
	u_int32_t	is_crypto_tkipenmic;	/* tkip en-MIC done in s/w */
	u_int32_t	is_crypto_tkipdemic;	/* tkip de-MIC done in s/w */
	u_int32_t	is_crypto_tkipcm;	/* tkip counter measures */
	u_int32_t	is_crypto_ccmp;		/* ccmp crypto done in s/w */
	u_int32_t	is_crypto_wep;		/* wep crypto done in s/w */
	u_int32_t	is_crypto_setkey_cipher;/* cipher rejected key */
	u_int32_t	is_crypto_setkey_nokey;	/* no key index for setkey */
	u_int32_t	is_crypto_delkey;	/* driver key delete failed */
	u_int32_t	is_crypto_badcipher;	/* unknown cipher */
	u_int32_t	is_crypto_nocipher;	/* cipher not available */
	u_int32_t	is_crypto_attachfail;	/* cipher attach failed */
	u_int32_t	is_crypto_swfallback;	/* cipher fallback to s/w */
	u_int32_t	is_crypto_keyfail;	/* driver key alloc failed */
	u_int32_t	is_crypto_enmicfail;	/* en-MIC failed */
	u_int32_t	is_ibss_capmismatch;	/* merge failed-cap mismatch */
	u_int32_t	is_ibss_norate;		/* merge failed-rate mismatch */
	u_int32_t	is_ps_unassoc;		/* ps-poll for unassoc. sta */
	u_int32_t	is_ps_badaid;		/* ps-poll w/ incorrect aid */
	u_int32_t	is_ps_qempty;		/* ps-poll w/ nothing to send */
};
#endif

/*
 * Max size of optional information elements.  We artificially
 * constrain this; it's limited only by the max frame size (and
 * the max parameter size of the wireless extensions).
 */
#define	IEEE80211_MAX_OPT_IE	512
#define	IEEE80211_MAX_WSC_IE	256

/*
 * WPA/RSN get/set key request.  Specify the key/cipher
 * type and whether the key is to be used for sending and/or
 * receiving.  The key index should be set only when working
 * with global keys (use IEEE80211_KEYIX_NONE for ``no index'').
 * Otherwise a unicast/pairwise key is specified by the bssid
 * (on a station) or mac address (on an ap).  They key length
 * must include any MIC key data; otherwise it should be no
 more than IEEE80211_KEYBUF_SIZE.
 */
struct ieee80211req_key {
	u_int8_t	ik_type;	/* key/cipher type */
	u_int8_t	ik_pad;
	u_int16_t	ik_keyix;	/* key index */
	u_int8_t	ik_keylen;	/* key length in bytes */
	u_int8_t	ik_flags;
/* NB: IEEE80211_KEY_XMIT and IEEE80211_KEY_RECV defined elsewhere */
#define	IEEE80211_KEY_DEFAULT	0x80	/* default xmit key */
	u_int8_t	ik_macaddr[IEEE80211_ADDR_LEN];
	u_int64_t	ik_keyrsc;	/* key receive sequence counter */
	u_int64_t	ik_keytsc;	/* key transmit sequence counter */
	u_int8_t	ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
} __packed;

/*
 * Delete a key either by index or address.  Set the index
 * to IEEE80211_KEYIX_NONE when deleting a unicast key.
 */
struct ieee80211req_del_key {
	u_int8_t	idk_keyix;	/* key index */
	u_int8_t	idk_macaddr[IEEE80211_ADDR_LEN];
};

/*
 * MLME state manipulation request.  IEEE80211_MLME_ASSOC
 * only makes sense when operating as a station.  The other
 * requests can be used when operating as a station or an
 * ap (to effect a station).
 */
struct ieee80211req_mlme {
	u_int8_t	im_op;		/* operation to perform */
#define	IEEE80211_MLME_ASSOC		1	/* associate station */
#define	IEEE80211_MLME_DISASSOC		2	/* disassociate station */
#define	IEEE80211_MLME_DEAUTH		3	/* deauthenticate station */
#define	IEEE80211_MLME_AUTHORIZE	4	/* authorize station */
#define	IEEE80211_MLME_UNAUTHORIZE	5	/* unauthorize station */
#define	IEEE80211_MLME_STOP_BSS		6	/* stop bss */
#define IEEE80211_MLME_CLEAR_STATS	7	/* clear station statistic */
#define IEEE80211_MLME_AUTH	        8	/* auth resp to station */
#define IEEE80211_MLME_REASSOC	        9	/* reassoc to station */
	u_int8_t	im_ssid_len;	/* length of optional ssid */
	u_int16_t	im_reason;	/* 802.11 reason code */
	u_int16_t	im_seq;	        /* seq for auth */
	u_int8_t	im_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	im_ssid[IEEE80211_NWID_LEN];
	u_int8_t        im_optie[IEEE80211_MAX_OPT_IE];
	u_int16_t       im_optie_len;
} __packed;

/*
 * request to add traffic stream for an associated station.
 */
struct ieee80211req_ts {
	u_int8_t    macaddr[IEEE80211_ADDR_LEN];
	u_int8_t    tspec_ie[IEEE80211_MAX_OPT_IE];
	u_int8_t    tspec_ielen;
	u_int8_t    res;
};

/*
 * Net802.11 scan request
 *
 */
enum {
    IEEE80211_SCANREQ_BG        = 1,    /*start the bg scan if vap is connected else fg scan */
    IEEE80211_SCANREQ_FORCE    = 2,    /*start the fg scan */
    IEEE80211_SCANREQ_STOP        = 3,    /*cancel any ongoing scanning*/
    IEEE80211_SCANREQ_PAUSE      = 4,    /*pause any ongoing scanning*/
    IEEE80211_SCANREQ_RESUME     = 5,    /*resume any ongoing scanning*/
};

/*
 * Set the active channel list.  Note this list is
 * intersected with the available channel list in
 * calculating the set of channels actually used in
 * scanning.
 */
struct ieee80211req_chanlist {
	u_int8_t	ic_channels[IEEE80211_CHAN_BYTES];
};

/*
 * Get the active channel list info.
 */
struct ieee80211req_chaninfo {
	u_int	ic_nchans;
	struct ieee80211_channel ic_chans[IEEE80211_CHAN_MAX];
};

/*
* Ressource request type from app
*/
enum {
    IEEE80211_RESREQ_ADDTS = 0,
    IEEE80211_RESREQ_ADDNODE,
};
/*
 * Resource request for adding Traffic stream
 */
struct ieee80211req_res_addts {
	u_int8_t	tspecie[IEEE80211_MAX_OPT_IE];
	u_int8_t	status;
};
/*
 * Resource request for adding station node
 */
struct ieee80211req_res_addnode {
	u_int8_t	auth_alg;
};
/*
 * Resource request from app
 */
struct ieee80211req_res {
	u_int8_t	macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	type;
        union {
            struct ieee80211req_res_addts addts;
            struct ieee80211req_res_addnode addnode;
        } u;
};

/*
 * Retrieve the WPA/RSN information element for an associated station.
 */
struct ieee80211req_wpaie {
	u_int8_t	wpa_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	wpa_ie[IEEE80211_MAX_OPT_IE];
	u_int8_t    rsn_ie[IEEE80211_MAX_OPT_IE];
#ifdef ATH_WPS_IE
	u_int8_t    wps_ie[IEEE80211_MAX_OPT_IE];
#endif /* ATH_WPS_IE */
};

/*
 * Retrieve the WSC information element for an associated station.
 */
struct ieee80211req_wscie {
	u_int8_t	wsc_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	wsc_ie[IEEE80211_MAX_WSC_IE];
};


/*
 * Retrieve per-node statistics.
 */
struct ieee80211req_sta_stats {
	union {
		/* NB: explicitly force 64-bit alignment */
		u_int8_t	macaddr[IEEE80211_ADDR_LEN];
		u_int64_t	pad;
	} is_u;
	struct ieee80211_nodestats is_stats;
};

enum {
	IEEE80211_STA_OPMODE_NORMAL,
	IEEE80211_STA_OPMODE_XR
};

/*
 * Retrieve per-station information; to retrieve all
 * specify a mac address of ff:ff:ff:ff:ff:ff.
 */
struct ieee80211req_sta_req {
	union {
		/* NB: explicitly force 64-bit alignment */
		u_int8_t	macaddr[IEEE80211_ADDR_LEN];
		u_int64_t	pad;
	} is_u;
	struct ieee80211req_sta_info info[1];	/* variable length */
};

/*
 * Get/set per-station tx power cap.
 */
struct ieee80211req_sta_txpow {
	u_int8_t	it_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	it_txpow;
};

/*
 * WME parameters are set and return using i_val and i_len.
 * i_val holds the value itself.  i_len specifies the AC
 * and, as appropriate, then high bit specifies whether the
 * operation is to be applied to the BSS or ourself.
 */
#define	IEEE80211_WMEPARAM_SELF	0x0000		/* parameter applies to self */
#define	IEEE80211_WMEPARAM_BSS	0x8000		/* parameter applies to BSS */
#define	IEEE80211_WMEPARAM_VAL	0x7fff		/* parameter value */

/*
 * Scan result data returned for IEEE80211_IOC_SCAN_RESULTS.
 */
struct ieee80211req_scan_result {
	u_int16_t	isr_len;		/* length (mult of 4) */
	u_int16_t	isr_freq;		/* MHz */
	u_int32_t	isr_flags;		/* channel flags */
	u_int8_t	isr_noise;
	u_int8_t	isr_rssi;
	u_int8_t	isr_intval;		/* beacon interval */
	u_int16_t	isr_capinfo;		/* capabilities */
	u_int8_t	isr_erp;		/* ERP element */
	u_int8_t	isr_bssid[IEEE80211_ADDR_LEN];
	u_int8_t	isr_nrates;
	u_int8_t	isr_rates[IEEE80211_RATE_MAXSIZE];
	u_int8_t	isr_ssid_len;		/* SSID length */
	u_int16_t	isr_ie_len;		/* IE length */
	u_int8_t	isr_pad[4];
	/* variable length SSID followed by IE data */
};

/* Options for Mcast Enhancement */
enum {
		IEEE80211_ME_DISABLE =	0,
		IEEE80211_ME_TUNNELING =	1,
		IEEE80211_ME_TRANSLATE =	2
};

/*
 * athdbg request
 */
enum {
    IEEE80211_DBGREQ_SENDADDBA     =	0,
    IEEE80211_DBGREQ_SENDDELBA     =	1,
    IEEE80211_DBGREQ_SETADDBARESP  =	2,
    IEEE80211_DBGREQ_GETADDBASTATS =	3,
    IEEE80211_DBGREQ_SENDBCNRPT    =	4, /* beacon report request */
    IEEE80211_DBGREQ_SENDTSMRPT    =	5, /* traffic stream measurement report */
    IEEE80211_DBGREQ_SENDNEIGRPT   =	6, /* neigbor report */
    IEEE80211_DBGREQ_SENDLMREQ     =	7, /* link measurement request */
    IEEE80211_DBGREQ_SENDBSTMREQ   =	8, /* bss transition management request */
    IEEE80211_DBGREQ_SENDCHLOADREQ =    9, /* bss channel load  request */
    IEEE80211_DBGREQ_SENDSTASTATSREQ =  10, /* sta stats request */
    IEEE80211_DBGREQ_SENDNHIST     =    11, /* Noise histogram request */
    IEEE80211_DBGREQ_SENDDELTS     =	12, /* delete TSPEC */
    IEEE80211_DBGREQ_SENDADDTSREQ  =	13, /* add TSPEC */
    IEEE80211_DBGREQ_SENDLCIREQ    =    14, /* Location config info request */
    IEEE80211_DBGREQ_GETRRMSTATS   =    15, /* RRM stats */
    IEEE80211_DBGREQ_SENDFRMREQ    =    16, /* RRM Frame request */
    IEEE80211_DBGREQ_GETBCNRPT     =    17, /* GET BCN RPT */
    IEEE80211_DBGREQ_SENDSINGLEAMSDU=   18, /* Sends single VHT MPDU AMSDUs */
    IEEE80211_DBGREQ_GETRRSSI	   =	19, /* GET the Inst RSSI */
    IEEE80211_DBGREQ_GETACSREPORT  =	20, /* GET the ACS report */
    IEEE80211_DBGREQ_SETACSUSERCHANLIST  =    21, /* SET ch list for acs reporting  */
    IEEE80211_DBGREQ_GETACSUSERCHANLIST  =    22, /* GET ch list used in acs reporting */
    IEEE80211_DBGREQ_BLOCK_ACS_CHANNEL	 =    23, /* Block acs for these channels */
    IEEE80211_DBGREQ_TR069  	         =    24, /* to be used for tr069 */
    IEEE80211_DBGREQ_CHMASKPERSTA        =    25, /* to be used for chainmask per sta */
    IEEE80211_DBGREQ_FIPS		   = 26, /* to be used for setting fips*/
    IEEE80211_DBGREQ_FW_TEST	   = 27, /* to be used for firmware testing*/
    IEEE80211_DBGREQ_SETQOSMAPCONF       =    28, /* set QoS map configuration */
    IEEE80211_DBGREQ_BSTEERING_SET_PARAMS =   29, /* Set the static band steering parameters */
    IEEE80211_DBGREQ_BSTEERING_GET_PARAMS =   30, /* Get the static band steering parameters */
    IEEE80211_DBGREQ_BSTEERING_SET_DBG_PARAMS =   31, /* Set the band steering debugging parameters */
    IEEE80211_DBGREQ_BSTEERING_GET_DBG_PARAMS =   32, /* Get the band steering debugging parameters */
    IEEE80211_DBGREQ_BSTEERING_ENABLE         =   33, /* Enable/Disable band steering */
    IEEE80211_DBGREQ_BSTEERING_SET_OVERLOAD   =   34, /* SET overload status */
    IEEE80211_DBGREQ_BSTEERING_GET_OVERLOAD   =   35, /* GET overload status */
    IEEE80211_DBGREQ_BSTEERING_GET_RSSI       =   36, /* Request RSSI measurement */
    IEEE80211_DBGREQ_INITRTT3       = 37, /* to test RTT3 feature*/
    IEEE80211_DBGREQ_SET_ANTENNA_SWITCH       = 38, /* Dynamic Antenna Selection */
    IEEE80211_DBGREQ_SETSUSERCTRLTBL          = 39, /* set User defined control table*/
    IEEE80211_DBGREQ_OFFCHAN_TX               = 40, /* Offchan tx*/
    IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_WH  = 41,/* Control whether probe responses are withheld for a MAC */
    IEEE80211_DBGREQ_BSTEERING_GET_PROBE_RESP_WH  = 42,/* Query whether probe responses are withheld for a MAC */
    IEEE80211_DBGREQ_GET_RRM_STA_LIST             = 43, /* to get list of connected rrm capable station */
    /* bss transition management request, targetted to a particular AP (or set of APs) */
    IEEE80211_DBGREQ_SENDBSTMREQ_TARGET           = 44,
    /* Get data rate related info for a VAP or a client */
    IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO  = 45,
    /* Enable/Disable band steering events on a VAP */
    IEEE80211_DBGREQ_BSTEERING_ENABLE_EVENTS      = 46,
#if QCA_LTEU_SUPPORT
    IEEE80211_DBGREQ_MU_SCAN                      = 47, /* do a MU scan */
    IEEE80211_DBGREQ_LTEU_CFG                     = 48, /* LTEu specific configuration */
    IEEE80211_DBGREQ_AP_SCAN                      = 49, /* do a AP scan */
#endif
    IEEE80211_DBGREQ_ATF_DEBUG_SIZE               = 50, /* Set the ATF history size */
    IEEE80211_DBGREQ_ATF_DUMP_DEBUG               = 51, /* Dump the ATF history */
#if QCA_LTEU_SUPPORT
    IEEE80211_DBGREQ_SCAN_REPEAT_PROBE_TIME       = 52, /* scan probe time, part of scan params */
    IEEE80211_DBGREQ_SCAN_REST_TIME               = 53, /* scan rest time, part of scan params */
    IEEE80211_DBGREQ_SCAN_IDLE_TIME               = 54, /* scan idle time, part of scan params */
    IEEE80211_DBGREQ_SCAN_PROBE_DELAY             = 55, /* scan probe delay, part of scan params */
    IEEE80211_DBGREQ_MU_DELAY                     = 56, /* delay between channel change and MU start (for non-gpio) */
    IEEE80211_DBGREQ_WIFI_TX_POWER                = 57, /* assumed tx power of wifi sta */
#endif
    /* Cleanup all STA state (equivalent to disassociation, without sending the frame OTA) */
    IEEE80211_DBGREQ_BSTEERING_LOCAL_DISASSOCIATION = 58,
    IEEE80211_DBGREQ_BSTEERING_SET_STEERING       = 59, /* Set steering in progress flag for a STA */
    IEEE80211_DBGREQ_CHAN_LIST                    =60,
    IEEE80211_DBGREQ_MBO_BSSIDPREF                = 61,
#if UMAC_SUPPORT_VI_DBG
    IEEE80211_DBGREQ_VOW_DEBUG_PARAM        	  = 62,
    IEEE80211_DBGREQ_VOW_DEBUG_PARAM_PERSTREAM	  = 63,
#endif
#if QCA_LTEU_SUPPORT
    IEEE80211_DBGREQ_SCAN_PROBE_SPACE_INTERVAL     = 64,
#endif
    IEEE80211_DBGREQ_ASSOC_WATERMARK_TIME         = 65,  /* Get the date when the max number of devices has been associated crossing the threshold */
    IEEE80211_DBGREQ_DISPLAY_TRAFFIC_STATISTICS   = 66, /* Display the traffic statistics of each connected STA */
    IEEE80211_DBGREQ_ATF_DUMP_NODESTATE           = 67,
    IEEE80211_DBGREQ_BSTEERING_SET_DA_STAT_INTVL  = 68,
    IEEE80211_DBGREQ_BSTEERING_SET_AUTH_ALLOW     = 69,
    IEEE80211_DBGREQ_BSTEERING_SET_PROBE_RESP_ALLOW_24G = 70, /* Control whether probe responses are allowed for a MAC in 2.4g band */
};

typedef struct ieee80211req_acs_r{
    u_int32_t index;
    u_int32_t data_size;
    void *data_addr;
}ieee80211req_acs_t;

typedef struct ieee80211_user_chanlist_r {
    u_int8_t  n_chan;
    u_int8_t *chan;
} ieee80211_user_chanlist_t;

typedef struct ieee80211_offchan_tx_test {
    u_int8_t ieee_chan;
    u_int16_t dwell_time;
} ieee80211_offchan_tx_test_t;

#if UMAC_SUPPORT_VI_DBG
typedef struct ieee80211_vow_dbg_stream_param {
	u_int8_t  stream_num;         /* the stream number whose markers are being set */
	u_int8_t  marker_num;         /* the marker number whose parameters (offset, size & match) are being set */
	u_int32_t marker_offset;      /* byte offset from skb start (upper 16 bits) & size in bytes(lower 16 bits) */
	u_int32_t marker_match;       /* marker pattern match used in filtering */
} ieee80211_vow_dbg_stream_param_t;

typedef struct ieee80211_vow_dbg_param {
	u_int8_t  num_stream;        /* Number of streams */
	u_int8_t  num_marker;       /* total number of markers used to filter pkts */
	u_int32_t rxq_offset;      /* Rx Seq num offset skb start (upper 16 bits) & size in bytes(lower 16 bits) */
	u_int32_t rxq_shift;         /* right-shift value in case field is not word aligned */
	u_int32_t rxq_max;           /* Max Rx seq number */
	u_int32_t time_offset;       /* Time offset for the packet*/
} ieee80211_vow_dbg_param_t;
#endif

typedef struct ieee80211_rrm_sta_info {
    u_int16_t count; /* In application layer this variable is used to store the STA count and in the driver it is used as an index */
    u_int8_t *dest_addr;
}ieee80211_rrm_sta_info_t;

typedef struct ieee80211_noise_stats{
    u_int8_t noise_value;
    u_int8_t min_value;
    u_int8_t max_value;
    u_int8_t median_value;
}ieee80211_noise_stats_t;

typedef struct ieee80211_node_info {
    u_int16_t count;
    u_int16_t bin_number;
    u_int32_t traf_rate;
    u_int8_t *dest_addr;
    struct ieee80211_noise_stats *noise_stats;
}ieee80211_node_info_t;
/* User defined control table for calibrated data */
typedef struct ieee80211_user_ctrl_tbl_r {
    u_int16_t ctrl_len;
    u_int8_t *ctrl_array;
} ieee80211_user_ctrl_tbl_t;
/*
 * command id's for use in tr069 request
 */
typedef enum _ieee80211_tr069_cmd_ {
    TR069_CHANHIST           = 1,
    TR069_TXPOWER            = 2,
    TR069_GETTXPOWER         = 3,
    TR069_GUARDINTV          = 4,
    TR069_GET_GUARDINTV      = 5,
    TR069_GETASSOCSTA_CNT    = 6,
    TR069_GETTIMESTAMP       = 7,
    TR069_GETDIAGNOSTICSTATE = 8,
    TR069_GETNUMBEROFENTRIES = 9,
    TR069_GET11HSUPPORTED    = 10,
    TR069_GETPOWERRANGE      = 11,
    TR069_SET_OPER_RATE      = 12,
    TR069_GET_OPER_RATE      = 13,
    TR069_GET_POSIBLRATE     = 14,
    TR069_SET_BSRATE         = 15,
    TR069_GET_BSRATE         = 16,
    TR069_GETSUPPORTEDFREQUENCY  = 17,
    TR069_GET_PLCP_ERR_CNT   = 18,
    TR069_GET_FCS_ERR_CNT    = 19,
    TR069_GET_PKTS_OTHER_RCVD = 20,
    TR069_GET_FAIL_RETRANS_CNT = 21,
    TR069_GET_RETRY_CNT      = 22,
    TR069_GET_MUL_RETRY_CNT  = 23,
    TR069_GET_ACK_FAIL_CNT   = 24,
    TR069_GET_AGGR_PKT_CNT   = 25,
    TR069_GET_STA_BYTES_SENT = 26,
    TR069_GET_STA_BYTES_RCVD = 27,
    TR069_GET_DATA_SENT_ACK  = 28,
    TR069_GET_DATA_SENT_NOACK = 29,
    TR069_GET_CHAN_UTIL      = 30,
    TR069_GET_RETRANS_CNT    = 31,
}ieee80211_tr069_cmd;

typedef struct {
	u_int32_t value;
	int value_array[TR069MAXPOWERRANGE];
}ieee80211_tr069_txpower_range;

typedef struct{
    u_int8_t         chanid;
    struct timespec chan_time;
}ieee80211_chanlhist_t;

typedef struct{
    u_int8_t act_index;
    ieee80211_chanlhist_t chanlhist[IEEE80211_CHAN_MAXHIST+1];
}ieee80211_channelhist_t;

/*
 * common structure to handle tr069 commands;
 * the cmdid and data pointer has to be appropriately
 * filled in
 */
typedef struct{
    u_int32_t data_size;
    ieee80211_tr069_cmd cmdid;
    void *data_addr;
}ieee80211req_tr069_t;

typedef struct ieee80211req_fips {
	u_int32_t data_size;
  	void *data_addr;
}ieee80211req_fips_t;

#if QCA_LTEU_SUPPORT

typedef enum {
    MU_ALGO_1 = 0x1, /* Basic binning algo */
    MU_ALGO_2 = 0x2, /* Enhanced binning algo */
    MU_ALGO_3 = 0x4, /* Enhanced binning including accounting for hidden nodes */
    MU_ALGO_4 = 0x8, /* TA based MU calculation */
} mu_algo_t;

typedef struct {
    u_int8_t     mu_req_id;             /* MU request id */
    u_int8_t     mu_channel;            /* IEEE channel number on which to do MU scan */
    mu_algo_t    mu_type;               /* which MU algo to use */
    u_int32_t    mu_duration;           /* duration of the scan in ms */
    u_int32_t    lteu_tx_power;         /* LTEu Tx power */
    u_int32_t    mu_rssi_thr_bssid;     /* RSSI threshold to account for active APs */
    u_int32_t    mu_rssi_thr_sta;       /* RSSI threshold to account for active STAs */
    u_int32_t    mu_rssi_thr_sc;        /* RSSI threshold to account for active small cells */
    u_int32_t    home_plmnid;           /* to be compared with PLMN ID to distinguish same and different operator WCUBS */
    u_int32_t    alpha_num_bssid;       /* alpha for num active bssid calculation,kept for backward compatibility */
} ieee80211req_mu_scan_t;

#define LTEU_MAX_BINS        10

typedef struct {
    u_int8_t     lteu_gpio_start;        /* start MU/AP scan after GPIO toggle */
    u_int8_t     lteu_num_bins;          /* no. of elements in the following arrays */
    u_int8_t     use_actual_nf;          /* whether to use the actual NF obtained or a hardcoded one */
    u_int32_t    lteu_weight[LTEU_MAX_BINS];  /* weights for MU algo */
    u_int32_t    lteu_thresh[LTEU_MAX_BINS];  /* thresholds for MU algo */
    u_int32_t    lteu_gamma[LTEU_MAX_BINS];   /* gamma's for MU algo */
    u_int32_t    lteu_scan_timeout;      /* timeout in ms to gpio toggle */
    u_int32_t    alpha_num_bssid;      /* alpha for num active bssid calculation */
    u_int32_t    lteu_cfg_reserved_1;    /* used to indicate to fw whether or not packets with phy error are to
                                            be included in MU calculation or not */

} ieee80211req_lteu_cfg_t;

#define MAX_SCAN_CHANS       32

typedef enum {
    SCAN_PASSIVE,
    SCAN_ACTIVE,
} scan_type_t;

typedef struct {
    u_int8_t     scan_req_id;          /* AP scan request id */
    u_int8_t     scan_num_chan;        /* Number of channels to scan, 0 for all channels */
    u_int8_t     scan_channel_list[MAX_SCAN_CHANS]; /* IEEE channel number of channels to scan */
    scan_type_t  scan_type;            /* Scan type - active or passive */
    u_int32_t    scan_duration;        /* Duration in ms for which a channel is scanned, 0 for default */
    u_int32_t    scan_repeat_probe_time;   /* Time before sending second probe request, (u32)(-1) for default */
    u_int32_t    scan_rest_time;       /* Time in ms on the BSS channel, (u32)(-1) for default */
    u_int32_t    scan_idle_time;       /* Time in msec on BSS channel before switching channel, (u32)(-1) for default */
    u_int32_t    scan_probe_delay;     /* Delay in msec before sending probe request, (u32)(-1) for default */
} ieee80211req_ap_scan_t;



#endif /* QCA_LTEU_SUPPORT */

#define MAX_CUSTOM_CHANS     101

typedef struct {
    u_int8_t     scan_numchan_associated;        /* Number of channels to scan, 0 for all channels */
    u_int8_t     scan_numchan_nonassociated;
    u_int8_t     scan_channel_list_associated[MAX_CUSTOM_CHANS]; /* IEEE channel number of channels to scan */
    u_int8_t     scan_channel_list_nonassociated[MAX_CUSTOM_CHANS];
}ieee80211req_custom_chan_t;

#if QCA_AIRTIME_FAIRNESS
struct atf_stats {
    u_int32_t tokens;               /* tokens distributed by strictq/fairq */
    u_int32_t act_tokens;           /* tokens available, after adjustemnt of excess consumed in prev cycle */
    u_int32_t total;                /* total tokens distributed by strictq/fairq */
    u_int32_t contribution;         /* tokens contributed by this node */
    u_int32_t tot_contribution;     /* tokens contributed by all nodes */
    u_int32_t borrow;               /* tokens borrowed by this node */
    u_int32_t unused;               /* tokens not used */
    u_int32_t pkt_drop_nobuf;       /* packets dropped as node is already holding it's share of tx buffers */
    u_int16_t allowed_bufs;         /* max tx buffers that this node can hold */
    u_int16_t max_num_buf_held;     /* max tx buffers held by this node */
    u_int16_t min_num_buf_held;     /* min tx buffers held by this node */
    u_int16_t num_tx_bufs;          /* packets sent for this node */
    u_int32_t num_tx_bytes;         /* bytes sent for this node */
    u_int32_t tokens_common;        /* tokens distributed by strictq/fairq (for non-atf nodes) */
    u_int32_t act_tokens_common;    /* tokens available, after adjustemnt of excess consumed in prev cycle (for non-atf nodes) */
    u_int32_t timestamp;            /* time when stats are updated */
    u_int32_t weighted_unusedtokens_percent; /* weighted unused tokens percent */
    u_int32_t raw_tx_tokens;        /* raw tokens */
    u_int32_t throughput;           /* attainable throughput assuming 100% airtime */
    u_int64_t total_used_tokens;    /* total of used tokens */
};

typedef struct {
    void *ptr;
    u_int32_t size;
} ieee80211req_atf_debug_t;
#endif


struct ieee80211req_athdbg {
    u_int8_t cmd;
    u_int8_t dstmac[IEEE80211_ADDR_LEN];
    union {
        int param[4];
        ieee80211_rrm_beaconreq_info_t bcnrpt;
        ieee80211_rrm_tsmreq_info_t    tsmrpt;
        ieee80211_rrm_nrreq_info_t     neigrpt;
        struct ieee80211_bstm_reqinfo   bstmreq;
        struct ieee80211_bstm_reqinfo_target   bstmreq_target;
        struct ieee80211_user_bssid_pref bssidpref;
        ieee80211_tspec_info     tsinfo;
        ieee80211_rrm_chloadreq_info_t chloadrpt;
        ieee80211_rrm_stastats_info_t  stastats;
        ieee80211_rrm_nhist_info_t     nhist;
        ieee80211_rrm_frame_req_info_t frm_req;
        ieee80211_rrm_lcireq_info_t    lci_req;
        ieee80211req_rrmstats_t        rrmstats_req;
        ieee80211req_acs_t             acs_rep;
        ieee80211req_tr069_t           tr069_req;
        ieee80211req_fips_t fips_req;
        struct ieee80211_qos_map       qos_map;
        ieee80211_bsteering_param_t    bsteering_param;
        ieee80211_bsteering_dbg_param_t bsteering_dbg_param;
        ieee80211_bsteering_rssi_req_t bsteering_rssi_req;
        u_int8_t                       bsteering_probe_resp_wh;
        u_int8_t                       bsteering_auth_allow;
        u_int8_t bsteering_enable;
        u_int8_t bsteering_overload;
        u_int8_t bsteering_rssi_num_samples;
        ieee80211_bsteering_datarate_info_t bsteering_datarate_info;
        u_int8_t bsteering_steering_in_progress;
        ieee80211_offchan_tx_test_t offchan_req;
#if UMAC_SUPPORT_VI_DBG
	ieee80211_vow_dbg_stream_param_t   vow_dbg_stream_param;
	ieee80211_vow_dbg_param_t	   vow_dbg_param;
#endif

#if QCA_LTEU_SUPPORT
        ieee80211req_mu_scan_t         mu_scan_req;
        ieee80211req_lteu_cfg_t        lteu_cfg;
        ieee80211req_ap_scan_t         ap_scan_req;
#endif
        ieee80211req_custom_chan_t     custom_chan_req;
#if QCA_AIRTIME_FAIRNESS
        ieee80211req_atf_debug_t       atf_dbg_req;
#endif
        u_int32_t                      bsteering_sta_stats_update_interval_da;
        u_int8_t                       bsteering_probe_resp_allow_24g;
    } data;
} __packed;

#ifdef __linux__
/*
 * Wireless Extensions API, private ioctl interfaces.
 *
 * NB: Even-numbered ioctl numbers have set semantics and are privileged!
 *	(regardless of the incorrect comment in wireless.h!)
 *
 *	Note we can only use 32 private ioctls, and yes they are all claimed.
 */
#ifndef _NET_IF_H
#include <linux/if.h>
#endif
#define	IEEE80211_IOCTL_SETPARAM	(SIOCIWFIRSTPRIV+0)
#define	IEEE80211_IOCTL_GETPARAM	(SIOCIWFIRSTPRIV+1)
#define	IEEE80211_IOCTL_SETKEY		(SIOCIWFIRSTPRIV+2)
#define	IEEE80211_IOCTL_SETWMMPARAMS	(SIOCIWFIRSTPRIV+3)
#define	IEEE80211_IOCTL_DELKEY		(SIOCIWFIRSTPRIV+4)
#define	IEEE80211_IOCTL_GETWMMPARAMS	(SIOCIWFIRSTPRIV+5)
#define	IEEE80211_IOCTL_SETMLME		(SIOCIWFIRSTPRIV+6)
#define	IEEE80211_IOCTL_GETCHANINFO	(SIOCIWFIRSTPRIV+7)
#define	IEEE80211_IOCTL_SETOPTIE	(SIOCIWFIRSTPRIV+8)
#define	IEEE80211_IOCTL_GETOPTIE	(SIOCIWFIRSTPRIV+9)
#define	IEEE80211_IOCTL_ADDMAC		(SIOCIWFIRSTPRIV+10)        /* Add ACL MAC Address */
#define	IEEE80211_IOCTL_DELMAC		(SIOCIWFIRSTPRIV+12)        /* Del ACL MAC Address */
#define	IEEE80211_IOCTL_GETCHANLIST	(SIOCIWFIRSTPRIV+13)
#define	IEEE80211_IOCTL_SETCHANLIST	(SIOCIWFIRSTPRIV+14)
#define IEEE80211_IOCTL_KICKMAC		(SIOCIWFIRSTPRIV+15)
#define	IEEE80211_IOCTL_CHANSWITCH	(SIOCIWFIRSTPRIV+16)
#define	IEEE80211_IOCTL_GETMODE		(SIOCIWFIRSTPRIV+17)
#define	IEEE80211_IOCTL_SETMODE		(SIOCIWFIRSTPRIV+18)
#define IEEE80211_IOCTL_GET_APPIEBUF	(SIOCIWFIRSTPRIV+19)
#define IEEE80211_IOCTL_SET_APPIEBUF	(SIOCIWFIRSTPRIV+20)
#define IEEE80211_IOCTL_SET_ACPARAMS	(SIOCIWFIRSTPRIV+21)
#define IEEE80211_IOCTL_FILTERFRAME	(SIOCIWFIRSTPRIV+22)
#define IEEE80211_IOCTL_SET_RTPARAMS	(SIOCIWFIRSTPRIV+23)
#define IEEE80211_IOCTL_DBGREQ	        (SIOCIWFIRSTPRIV+24)
#define IEEE80211_IOCTL_SEND_MGMT	(SIOCIWFIRSTPRIV+26)
#define IEEE80211_IOCTL_SET_MEDENYENTRY (SIOCIWFIRSTPRIV+27)
#define IEEE80211_IOCTL_CHN_WIDTHSWITCH (SIOCIWFIRSTPRIV+28)
#define IEEE80211_IOCTL_GET_MACADDR	(SIOCIWFIRSTPRIV+29)        /* Get ACL List */
#define IEEE80211_IOCTL_SET_HBRPARAMS	(SIOCIWFIRSTPRIV+30)
#define IEEE80211_IOCTL_SET_RXTIMEOUT	(SIOCIWFIRSTPRIV+31)
/*
 * MCAST_GROUP is used for testing, not for regular operation.
 * It is defined unconditionally (overlapping with SET_RXTIMEOUT),
 * but only used for debugging (after disabling SET_RXTIMEOUT).
 */
#define IEEE80211_IOCTL_MCAST_GROUP     (SIOCIWFIRSTPRIV+31)

enum {
	IEEE80211_WMMPARAMS_CWMIN	= 1,
	IEEE80211_WMMPARAMS_CWMAX	= 2,
	IEEE80211_WMMPARAMS_AIFS	= 3,
	IEEE80211_WMMPARAMS_TXOPLIMIT	= 4,
	IEEE80211_WMMPARAMS_ACM		= 5,
	IEEE80211_WMMPARAMS_NOACKPOLICY	= 6,
#if UMAC_VOW_DEBUG
    IEEE80211_PARAM_VOW_DBG_CFG     = 7,  /*Configure VoW debug MACs*/
#endif
};
enum {
	IEEE80211_IOCTL_RCPARAMS_RTPARAM	= 1,
	IEEE80211_IOCTL_RCPARAMS_RTMASK		= 2,
};
enum {
	IEEE80211_PARAM_TURBO		= 1,	/* turbo mode */
	IEEE80211_PARAM_MODE		= 2,	/* phy mode (11a, 11b, etc.) */
	IEEE80211_PARAM_AUTHMODE	= 3,	/* authentication mode */
	IEEE80211_PARAM_PROTMODE	= 4,	/* 802.11g protection */
	IEEE80211_PARAM_MCASTCIPHER	= 5,	/* multicast/default cipher */
	IEEE80211_PARAM_MCASTKEYLEN	= 6,	/* multicast key length */
	IEEE80211_PARAM_UCASTCIPHERS	= 7,	/* unicast cipher suites */
	IEEE80211_PARAM_UCASTCIPHER	= 8,	/* unicast cipher */
	IEEE80211_PARAM_UCASTKEYLEN	= 9,	/* unicast key length */
	IEEE80211_PARAM_WPA		= 10,	/* WPA mode (0,1,2) */
	IEEE80211_PARAM_ROAMING		= 12,	/* roaming mode */
	IEEE80211_PARAM_PRIVACY		= 13,	/* privacy invoked */
	IEEE80211_PARAM_COUNTERMEASURES	= 14,	/* WPA/TKIP countermeasures */
	IEEE80211_PARAM_DROPUNENCRYPTED	= 15,	/* discard unencrypted frames */
	IEEE80211_PARAM_DRIVER_CAPS	= 16,	/* driver capabilities */
	IEEE80211_PARAM_MACCMD		= 17,	/* MAC ACL operation */
	IEEE80211_PARAM_WMM		= 18,	/* WMM mode (on, off) */
	IEEE80211_PARAM_HIDESSID	= 19,	/* hide SSID mode (on, off) */
	IEEE80211_PARAM_APBRIDGE	= 20,	/* AP inter-sta bridging */
	IEEE80211_PARAM_KEYMGTALGS	= 21,	/* key management algorithms */
	IEEE80211_PARAM_RSNCAPS		= 22,	/* RSN capabilities */
	IEEE80211_PARAM_INACT		= 23,	/* station inactivity timeout */
	IEEE80211_PARAM_INACT_AUTH	= 24,	/* station auth inact timeout */
	IEEE80211_PARAM_INACT_INIT	= 25,	/* station init inact timeout */
	IEEE80211_PARAM_DTIM_PERIOD	= 28,	/* DTIM period (beacons) */
	IEEE80211_PARAM_BEACON_INTERVAL	= 29,	/* beacon interval (ms) */
	IEEE80211_PARAM_DOTH		= 30,	/* 11.h is on/off */
	IEEE80211_PARAM_PWRTARGET	= 31,	/* Current Channel Pwr Constraint */
	IEEE80211_PARAM_GENREASSOC	= 32,	/* Generate a reassociation request */
	IEEE80211_PARAM_COMPRESSION	= 33,	/* compression */
	IEEE80211_PARAM_FF		= 34,	/* fast frames support */
	IEEE80211_PARAM_XR		= 35,	/* XR support */
	IEEE80211_PARAM_BURST		= 36,	/* burst mode */
	IEEE80211_PARAM_PUREG		= 37,	/* pure 11g (no 11b stations) */
	IEEE80211_PARAM_AR		= 38,	/* AR support */
	IEEE80211_PARAM_WDS		= 39,	/* Enable 4 address processing */
	IEEE80211_PARAM_BGSCAN		= 40,	/* bg scanning (on, off) */
	IEEE80211_PARAM_BGSCAN_IDLE	= 41,	/* bg scan idle threshold */
	IEEE80211_PARAM_BGSCAN_INTERVAL	= 42,	/* bg scan interval */
	IEEE80211_PARAM_MCAST_RATE	= 43,	/* Multicast Tx Rate */
	IEEE80211_PARAM_COVERAGE_CLASS	= 44,	/* coverage class */
	IEEE80211_PARAM_COUNTRY_IE	= 45,	/* enable country IE */
	IEEE80211_PARAM_SCANVALID	= 46,	/* scan cache valid threshold */
	IEEE80211_PARAM_ROAM_RSSI_11A	= 47,	/* rssi threshold in 11a */
	IEEE80211_PARAM_ROAM_RSSI_11B	= 48,	/* rssi threshold in 11b */
	IEEE80211_PARAM_ROAM_RSSI_11G	= 49,	/* rssi threshold in 11g */
	IEEE80211_PARAM_ROAM_RATE_11A	= 50,	/* tx rate threshold in 11a */
	IEEE80211_PARAM_ROAM_RATE_11B	= 51,	/* tx rate threshold in 11b */
	IEEE80211_PARAM_ROAM_RATE_11G	= 52,	/* tx rate threshold in 11g */
	IEEE80211_PARAM_UAPSDINFO	= 53,	/* value for qos info field */
	IEEE80211_PARAM_SLEEP		= 54,	/* force sleep/wake */
	IEEE80211_PARAM_QOSNULL		= 55,	/* force sleep/wake */
	IEEE80211_PARAM_PSPOLL		= 56,	/* force ps-poll generation (sta only) */
	IEEE80211_PARAM_EOSPDROP	= 57,	/* force uapsd EOSP drop (ap only) */
	IEEE80211_PARAM_MARKDFS		= 58,	/* mark a dfs interference channel when found */
	IEEE80211_PARAM_REGCLASS	= 59,	/* enable regclass ids in country IE */
	IEEE80211_PARAM_CHANBW		= 60,	/* set chan bandwidth preference */
	IEEE80211_PARAM_WMM_AGGRMODE	= 61,	/* set WMM Aggressive Mode */
	IEEE80211_PARAM_SHORTPREAMBLE	= 62, 	/* enable/disable short Preamble */
	IEEE80211_PARAM_BLOCKDFSCHAN	= 63, 	/* enable/disable use of DFS channels */
	IEEE80211_PARAM_CWM_MODE	= 64,	/* CWM mode */
	IEEE80211_PARAM_CWM_EXTOFFSET	= 65,	/* CWM extension channel offset */
	IEEE80211_PARAM_CWM_EXTPROTMODE	= 66,	/* CWM extension channel protection mode */
	IEEE80211_PARAM_CWM_EXTPROTSPACING = 67,/* CWM extension channel protection spacing */
	IEEE80211_PARAM_CWM_ENABLE	= 68,/* CWM state machine enabled */
	IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD = 69,/* CWM extension channel busy threshold */
	IEEE80211_PARAM_CWM_CHWIDTH	= 70,	/* CWM STATE: current channel width */
	IEEE80211_PARAM_SHORT_GI	= 71,	/* half GI */
	IEEE80211_PARAM_FAST_CC		= 72,	/* fast channel change */

	/*
	 * 11n A-MPDU, A-MSDU support
	 */
	IEEE80211_PARAM_AMPDU		= 73,	/* 11n a-mpdu support */
	IEEE80211_PARAM_AMPDU_LIMIT	= 74,	/* a-mpdu length limit */
	IEEE80211_PARAM_AMPDU_DENSITY	= 75,	/* a-mpdu density */
	IEEE80211_PARAM_AMPDU_SUBFRAMES	= 76,	/* a-mpdu subframe limit */
	IEEE80211_PARAM_AMSDU		= 77,	/* a-msdu support */
	IEEE80211_PARAM_AMSDU_LIMIT	= 78,	/* a-msdu length limit */

	IEEE80211_PARAM_COUNTRYCODE	= 79,	/* Get country code */
	IEEE80211_PARAM_TX_CHAINMASK	= 80,	/* Tx chain mask */
	IEEE80211_PARAM_RX_CHAINMASK	= 81,	/* Rx chain mask */
	IEEE80211_PARAM_RTSCTS_RATECODE	= 82,	/* RTS Rate code */
	IEEE80211_PARAM_HT_PROTECTION	= 83,	/* Protect traffic in HT mode */
	IEEE80211_PARAM_RESET_ONCE	= 84,	/* Force a reset */
	IEEE80211_PARAM_SETADDBAOPER	= 85,	/* Set ADDBA mode */
	IEEE80211_PARAM_TX_CHAINMASK_LEGACY = 86, /* Tx chain mask for legacy clients */
	IEEE80211_PARAM_11N_RATE	= 87,	/* Set ADDBA mode */
	IEEE80211_PARAM_11N_RETRIES	= 88,	/* Tx chain mask for legacy clients */
	IEEE80211_PARAM_DBG_LVL		= 89,	/* Debug Level for specific VAP */
	IEEE80211_PARAM_WDS_AUTODETECT	= 90,	/* Configurable Auto Detect/Delba for WDS mode */
	IEEE80211_PARAM_ATH_RADIO	= 91,	/* returns the name of the radio being used */
	IEEE80211_PARAM_IGNORE_11DBEACON = 92,	/* Don't process 11d beacon (on, off) */
	IEEE80211_PARAM_STA_FORWARD	= 93,	/* Enable client 3 addr forwarding */

	/*
	 * Mcast Enhancement support
	 */
	IEEE80211_PARAM_ME          = 94,   /* Set Mcast enhancement option: 0 disable, 1 tunneling, 2 translate  4 to disable snoop feature*/
	IEEE80211_PARAM_MEDUMP		= 95,	/* Dump the snoop table for mcast enhancement */
	IEEE80211_PARAM_MEDEBUG		= 96,	/* mcast enhancement debug level */
	IEEE80211_PARAM_ME_SNOOPLENGTH	= 97,	/* mcast snoop list length */
	IEEE80211_PARAM_ME_TIMER	= 98,	/* Set Mcast enhancement timer to update the snoop list, in msec */
	IEEE80211_PARAM_ME_TIMEOUT	= 99,	/* Set Mcast enhancement timeout for STA's without traffic, in msec */
	IEEE80211_PARAM_PUREN		= 100,	/* pure 11n (no 11bg/11a stations) */
	IEEE80211_PARAM_BASICRATES	= 101,	/* Change Basic Rates */
	IEEE80211_PARAM_NO_EDGE_CH	= 102,	/* Avoid band edge channels */
	IEEE80211_PARAM_WEP_TKIP_HT	= 103,	/* Enable HT rates with WEP/TKIP encryption */
	IEEE80211_PARAM_RADIO		= 104,	/* radio on/off */
	IEEE80211_PARAM_NETWORK_SLEEP	= 105,	/* set network sleep enable/disable */
	IEEE80211_PARAM_DROPUNENC_EAPOL	= 106,

	/*
	 * Headline block removal
	 */
	IEEE80211_PARAM_HBR_TIMER	= 107,
	IEEE80211_PARAM_HBR_STATE	= 108,

	/*
	 * Unassociated power consumpion improve
	 */
	IEEE80211_PARAM_SLEEP_PRE_SCAN	= 109,
	IEEE80211_PARAM_SCAN_PRE_SLEEP	= 110,

	/* support for wapi: set auth mode and key */
	IEEE80211_PARAM_SETWAPI		= 112,
	IEEE80211_IOCTL_GREEN_AP_PS_ENABLE = 113,
	IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT = 114,
	IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME = 115,
	IEEE80211_PARAM_WPS		= 116,
	IEEE80211_PARAM_RX_RATE		= 117,
	IEEE80211_PARAM_CHEXTOFFSET	= 118,
	IEEE80211_PARAM_CHSCANINIT	= 119,
	IEEE80211_PARAM_MPDU_SPACING	= 120,
	IEEE80211_PARAM_HT40_INTOLERANT	= 121,
	IEEE80211_PARAM_CHWIDTH		= 122,
	IEEE80211_PARAM_EXTAP		= 123,   /* Enable client 3 addr forwarding */
        IEEE80211_PARAM_COEXT_DISABLE    = 124,
	IEEE80211_PARAM_ME_DROPMCAST	= 125,	/* drop mcast if empty entry */
	IEEE80211_PARAM_ME_SHOWDENY	= 126,	/* show deny table for mcast enhancement */
	IEEE80211_PARAM_ME_CLEARDENY	= 127,	/* clear deny table for mcast enhancement */
	IEEE80211_PARAM_ME_ADDDENY	= 128,	/* add deny entry for mcast enhancement */
    IEEE80211_PARAM_GETIQUECONFIG = 129, /*print out the iQUE config*/
    IEEE80211_PARAM_CCMPSW_ENCDEC = 130,  /* support for ccmp s/w encrypt decrypt */

      /* Support for repeater placement */
    IEEE80211_PARAM_CUSTPROTO_ENABLE = 131,
    IEEE80211_PARAM_GPUTCALC_ENABLE  = 132,
    IEEE80211_PARAM_DEVUP            = 133,
    IEEE80211_PARAM_MACDEV           = 134,
    IEEE80211_PARAM_MACADDR1         = 135,
    IEEE80211_PARAM_MACADDR2         = 136,
    IEEE80211_PARAM_GPUTMODE         = 137,
    IEEE80211_PARAM_TXPROTOMSG       = 138,
    IEEE80211_PARAM_RXPROTOMSG       = 139,
    IEEE80211_PARAM_STATUS           = 140,
    IEEE80211_PARAM_ASSOC            = 141,
    IEEE80211_PARAM_NUMSTAS          = 142,
    IEEE80211_PARAM_STA1ROUTE        = 143,
    IEEE80211_PARAM_STA2ROUTE        = 144,
    IEEE80211_PARAM_STA3ROUTE        = 145,
    IEEE80211_PARAM_STA4ROUTE        = 146,
    IEEE80211_PARAM_PERIODIC_SCAN = 179,
#if ATH_SUPPORT_AP_WDS_COMBO
    IEEE80211_PARAM_NO_BEACON     = 180,  /* No beacon xmit on VAP */
#endif
    IEEE80211_PARAM_VAP_COUNTRY_IE   = 181, /* 802.11d country ie per vap */
    IEEE80211_PARAM_VAP_DOTH         = 182, /* 802.11h per vap */
    IEEE80211_PARAM_STA_QUICKKICKOUT = 183, /* station quick kick out */
    IEEE80211_PARAM_AUTO_ASSOC       = 184,
    IEEE80211_PARAM_RXBUF_LIFETIME   = 185, /* lifetime of reycled rx buffers */
    IEEE80211_PARAM_2G_CSA           = 186, /* 2.4 GHz CSA is on/off */
    IEEE80211_PARAM_WAPIREKEY_USK = 187,
    IEEE80211_PARAM_WAPIREKEY_MSK = 188,
    IEEE80211_PARAM_WAPIREKEY_UPDATE = 189,
#if ATH_SUPPORT_IQUE
    IEEE80211_PARAM_RC_VIVO          = 190, /* Use separate rate control algorithm for VI/VO queues */
#endif
    IEEE80211_PARAM_CLR_APPOPT_IE    = 191,  /* Clear Cached App/OptIE */
    IEEE80211_PARAM_SW_WOW           = 192,   /* wow by sw */
    IEEE80211_PARAM_QUIET_PERIOD    = 193,
    IEEE80211_PARAM_QBSS_LOAD       = 194,
    IEEE80211_PARAM_RRM_CAP         = 195,
    IEEE80211_PARAM_WNM_CAP         = 196,
#if UMAC_SUPPORT_WDS
    IEEE80211_PARAM_ADD_WDS_ADDR    = 197,  /* add wds addr */
#endif
#ifdef QCA_PARTNER_PLATFORM
    IEEE80211_PARAM_PLTFRM_PRIVATE = 198, /* platfrom's private ioctl*/
#endif

#if UMAC_SUPPORT_VI_DBG
    /* Support for Video Debug */
    IEEE80211_PARAM_DBG_CFG            = 199,
    IEEE80211_PARAM_DBG_NUM_STREAMS    = 200,
    IEEE80211_PARAM_STREAM_NUM         = 201,
    IEEE80211_PARAM_DBG_NUM_MARKERS    = 202,
    IEEE80211_PARAM_MARKER_NUM         = 203,
    IEEE80211_PARAM_MARKER_OFFSET_SIZE = 204,
    IEEE80211_PARAM_MARKER_MATCH       = 205,
    IEEE80211_PARAM_RXSEQ_OFFSET_SIZE  = 206,
    IEEE80211_PARAM_RX_SEQ_RSHIFT      = 207,
    IEEE80211_PARAM_RX_SEQ_MAX         = 208,
    IEEE80211_PARAM_RX_SEQ_DROP        = 209,
    IEEE80211_PARAM_TIME_OFFSET_SIZE   = 210,
    IEEE80211_PARAM_RESTART            = 211,
    IEEE80211_PARAM_RXDROP_STATUS      = 212,
#endif
#if ATH_SUPPORT_IBSS_DFS
    IEEE80211_PARAM_IBSS_DFS_PARAM     = 225,
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    IEEE80211_PARAM_IBSS_SET_RSSI_CLASS     = 237,
    IEEE80211_PARAM_IBSS_START_RSSI_MONITOR = 238,
    IEEE80211_PARAM_IBSS_RSSI_HYSTERESIS    = 239,
#endif
#ifdef ATH_SUPPORT_TxBF
    IEEE80211_PARAM_TXBF_AUTO_CVUPDATE = 240,       /* Auto CV update enable*/
    IEEE80211_PARAM_TXBF_CVUPDATE_PER = 241,        /* per theshold to initial CV update*/
#endif
    IEEE80211_PARAM_MAXSTA              = 242,
    IEEE80211_PARAM_RRM_STATS               =243,
    IEEE80211_PARAM_RRM_SLWINDOW            =244,
    IEEE80211_PARAM_MFP_TEST    = 245,
    IEEE80211_PARAM_SCAN_BAND   = 246,                /* only scan channels of requested band */
#if ATH_SUPPORT_FLOWMAC_MODULE
    IEEE80211_PARAM_FLOWMAC            = 247, /* flowmac enable/disable ath0*/
#endif
    IEEE80211_PARAM_STA_PWR_SET_PSPOLL      = 255,  /* Set ips_use_pspoll flag for STA */
    IEEE80211_PARAM_NO_STOP_DISASSOC        = 256,  /* Do not send disassociation frame on stopping vap */
#if UMAC_SUPPORT_IBSS
    IEEE80211_PARAM_IBSS_CREATE_DISABLE = 257,      /* if set, it prevents IBSS creation */
#endif
#if ATH_SUPPORT_WIFIPOS
    IEEE80211_PARAM_WIFIPOS_TXCORRECTION = 258,      /* Set/Get TxCorrection */
    IEEE80211_PARAM_WIFIPOS_RXCORRECTION = 259,      /* Set/Get RxCorrection */
#endif
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    IEEE80211_PARAM_CHAN_UTIL_ENAB      = 260,
    IEEE80211_PARAM_CHAN_UTIL           = 261,      /* Get Channel Utilization value (scale: 0 - 255) */
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
    IEEE80211_PARAM_DBG_LVL_HIGH        = 262, /* Debug Level for specific VAP (upper 32 bits) */
    IEEE80211_PARAM_PROXYARP_CAP        = 263, /* Enable WNM Proxy ARP feature */
    IEEE80211_PARAM_DGAF_DISABLE        = 264, /* Hotspot 2.0 DGAF Disable feature */
    IEEE80211_PARAM_L2TIF_CAP           = 265, /* Hotspot 2.0 L2 Traffic Inspection and Filtering */
    IEEE80211_PARAM_WEATHER_RADAR_CHANNEL = 266, /* weather radar channel selection is bypassed */
    IEEE80211_PARAM_SEND_DEAUTH           = 267,/* for sending deauth while doing interface down*/
    IEEE80211_PARAM_WEP_KEYCACHE          = 268,/* wepkeys mustbe in first fourslots in Keycache*/
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    IEEE80211_PARAM_REJOINT_ATTEMP_TIME   = 269, /* Set the Rejoint time */
#endif
    IEEE80211_PARAM_WNM_SLEEP           = 270,      /* WNM-Sleep Mode */
    IEEE80211_PARAM_WNM_BSS_CAP         = 271,
    IEEE80211_PARAM_WNM_TFS_CAP         = 272,
    IEEE80211_PARAM_WNM_TIM_CAP         = 273,
    IEEE80211_PARAM_WNM_SLEEP_CAP       = 274,
    IEEE80211_PARAM_WNM_FMS_CAP         = 275,
    IEEE80211_PARAM_RRM_DEBUG           = 276, /* RRM debugging parameter */
    IEEE80211_PARAM_SET_TXPWRADJUST     = 277,
    IEEE80211_PARAM_TXRX_DBG              = 278,    /* show txrx debug info */
    IEEE80211_PARAM_VHT_MCS               = 279,    /* VHT MCS set */
    IEEE80211_PARAM_TXRX_FW_STATS         = 280,    /* single FW stat */
    IEEE80211_PARAM_TXRX_FW_MSTATS        = 281,    /* multiple FW stats */
    IEEE80211_PARAM_NSS                   = 282,    /* Number of Spatial Streams */
    IEEE80211_PARAM_LDPC                  = 283,    /* Support LDPC */
    IEEE80211_PARAM_TX_STBC               = 284,    /* Support TX STBC */
    IEEE80211_PARAM_RX_STBC               = 285,    /* Support RX STBC */
    IEEE80211_PARAM_APONLY                  = 293,
    IEEE80211_PARAM_TXRX_FW_STATS_RESET     = 294,
    IEEE80211_PARAM_TX_PPDU_LOG_CFG         = 295,  /* tx PPDU log cfg params */
    IEEE80211_PARAM_OPMODE_NOTIFY           = 296,  /* Op Mode Notification */
    IEEE80211_PARAM_NOPBN                   = 297, /* don't send push button notification */
    IEEE80211_PARAM_DFS_CACTIMEOUT          = 298, /* override CAC timeout */
    IEEE80211_PARAM_ENABLE_RTSCTS           = 299, /* Enable/disable RTS-CTS */

    IEEE80211_PARAM_MAX_AMPDU               = 300,   /* Set/Get rx AMPDU exponent/shift */
    IEEE80211_PARAM_VHT_MAX_AMPDU           = 301,   /* Set/Get rx VHT AMPDU exponent/shift */
    IEEE80211_PARAM_BCAST_RATE              = 302,   /* Setting Bcast DATA rate */
    IEEE80211_PARAM_PARENT_IFINDEX          = 304,   /* parent net_device ifindex for this VAP */
#if WDS_VENDOR_EXTENSION
    IEEE80211_PARAM_WDS_RX_POLICY           = 305,  /* Set/Get WDS rx filter policy for vendor specific WDS */
#endif
    IEEE80211_PARAM_ENABLE_OL_STATS         = 306,   /*Enables/Disables the
                                                        stats in the Host and in the FW */
    IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT   = 307,  /* Enable/Disable Green-AP debug prints */
    IEEE80211_PARAM_RC_NUM_RETRIES          = 308,
    IEEE80211_PARAM_GET_ACS                 = 309,/* to get status of acs */
    IEEE80211_PARAM_GET_CAC                 = 310,/* to get status of CAC period */
    IEEE80211_PARAM_EXT_IFACEUP_ACS         = 311,  /* Enable external auto channel selection entity
                                                       at VAP init time */
    IEEE80211_PARAM_ONETXCHAIN              = 312,  /* force to tx with one chain for legacy client */
    IEEE80211_PARAM_DFSDOMAIN               = 313,  /* Get DFS Domain */
    IEEE80211_PARAM_SCAN_CHAN_EVENT         = 314,  /* Enable delivery of Scan Channel Events during
                                                       802.11 scans (11ac offload, and IEEE80211_M_HOSTAP
                                                       mode only). */
    IEEE80211_PARAM_DESIRED_CHANNEL         = 315,  /* Get desired channel corresponding to desired
                                                       PHY mode */
    IEEE80211_PARAM_DESIRED_PHYMODE         = 316,  /* Get desired PHY mode */
    IEEE80211_PARAM_SEND_ADDITIONAL_IES     = 317,  /* Control sending of additional IEs to host */
    IEEE80211_PARAM_START_ACS_REPORT        = 318,  /* to start acs scan report */
    IEEE80211_PARAM_MIN_DWELL_ACS_REPORT    = 319,  /* min dwell time for  acs scan report */
    IEEE80211_PARAM_MAX_DWELL_ACS_REPORT    = 320,  /* max dwell time for  acs scan report */
    IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR     = 321,  /* channel long duration timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR   = 322,  /* No hopping timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR  = 323,  /* counter window timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH     = 324,  /* Noise threshold used in acs channel hopping */
    IEEE80211_PARAM_ACS_CH_HOP_CNT_TH       = 325,  /* counter threshold used in acs channel hopping */
    IEEE80211_PARAM_ACS_ENABLE_CH_HOP       = 326,  /* Enable/Disable acs channel hopping */
    IEEE80211_PARAM_SET_CABQ_MAXDUR         = 327,  /* set the max tx percentage for cabq */
    IEEE80211_PARAM_256QAM_2G               = 328,  /* 2.4 GHz 256 QAM support */
    IEEE80211_PARAM_MAX_SCANENTRY           = 330,  /* MAX scan entry */
    IEEE80211_PARAM_SCANENTRY_TIMEOUT       = 331,  /* Scan entry timeout value */
    IEEE80211_PARAM_PURE11AC                = 332,  /* pure 11ac(no 11bg/11a/11n stations) */
#if UMAC_VOW_DEBUG
    IEEE80211_PARAM_VOW_DBG_ENABLE  = 333,  /*Enable VoW debug*/
#endif
    IEEE80211_PARAM_SCAN_MIN_DWELL          = 334,  /* MIN dwell time to be used during scan */
    IEEE80211_PARAM_SCAN_MAX_DWELL          = 335,  /* MAX dwell time to be used during scan */
    IEEE80211_PARAM_BANDWIDTH               = 336,
    IEEE80211_PARAM_FREQ_BAND               = 337,
    IEEE80211_PARAM_EXTCHAN                 = 338,
    IEEE80211_PARAM_MCS                     = 339,
    IEEE80211_PARAM_CHAN_NOISE              = 340,
    IEEE80211_PARAM_VHT_SGIMASK             = 341,   /* Set VHT SGI MASK */
    IEEE80211_PARAM_VHT80_RATEMASK          = 342,   /* Set VHT80 Auto Rate MASK */
#if ATH_PERF_PWR_OFFLOAD
    IEEE80211_PARAM_VAP_TX_ENCAP_TYPE       = 343,
    IEEE80211_PARAM_VAP_RX_DECAP_TYPE       = 344,
#endif /* ATH_PERF_PWR_OFFLOAD */
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
    IEEE80211_PARAM_TSO_STATS               = 345, /* Get TSO Stats */
    IEEE80211_PARAM_TSO_STATS_RESET         = 346, /* Reset TSO Stats */
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_LRO_ENABLE
    IEEE80211_PARAM_LRO_STATS               = 347, /* Get LRO Stats */
    IEEE80211_PARAM_LRO_STATS_RESET         = 348, /* Reset LRO Stats */
#endif /* HOST_SW_LRO_ENABLE */
#if RX_CHECKSUM_OFFLOAD
    IEEE80211_PARAM_RX_CKSUM_ERR_STATS      = 349, /* Get RX CKSUM Err Stats */
    IEEE80211_PARAM_RX_CKSUM_ERR_RESET      = 350, /* Reset RX CKSUM Err Stats */
#endif /* RX_CHECKSUM_OFFLOAD */

    IEEE80211_PARAM_VHT_STS_CAP             = 351,
    IEEE80211_PARAM_VHT_SOUNDING_DIM        = 352,
    IEEE80211_PARAM_VHT_SUBFEE              = 353,   /* set VHT SU beamformee capability */
    IEEE80211_PARAM_VHT_MUBFEE              = 354,   /* set VHT MU beamformee capability */
    IEEE80211_PARAM_VHT_SUBFER              = 355,   /* set VHT SU beamformer capability */
    IEEE80211_PARAM_VHT_MUBFER              = 356,   /* set VHT MU beamformer capability */
    IEEE80211_PARAM_IMPLICITBF              = 357,
    IEEE80211_PARAM_SEND_WOWPKT             = 358, /* Send Wake-On-Wireless packet */
    IEEE80211_PARAM_STA_FIXED_RATE          = 359, /* set/get fixed rate for associated sta on AP */
    IEEE80211_PARAM_11NG_VHT_INTEROP        = 360,  /* 2.4ng Vht Interop */
#if HOST_SW_SG_ENABLE
    IEEE80211_PARAM_SG_STATS                = 361, /* Get SG Stats */
    IEEE80211_PARAM_SG_STATS_RESET          = 362, /* Reset SG Stats */
#endif /* HOST_SW_SG_ENABLE */
    IEEE80211_PARAM_SPLITMAC                = 363,
    IEEE80211_PARAM_SHORT_SLOT              = 364,   /* Set short slot time */
    IEEE80211_PARAM_SET_ERP                 = 365,   /* Set ERP protection mode  */
    IEEE80211_PARAM_SESSION_TIMEOUT         = 366,   /* STA's session time */
#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    IEEE80211_PARAM_RAWMODE_SIM_TXAGGR      = 367,   /* Enable/disable raw mode simulation
                                                        Tx A-MSDU aggregation */
    IEEE80211_PARAM_RAWMODE_PKT_SIM_STATS   = 368,   /* Get Raw mode packet simulation stats. */
    IEEE80211_PARAM_CLR_RAWMODE_PKT_SIM_STATS = 369, /* Clear Raw mode packet simulation stats. */
    IEEE80211_PARAM_RAWMODE_SIM_DEBUG       = 370,   /* Enable/disable raw mode simulation debug */
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    IEEE80211_PARAM_PROXY_STA               = 371,   /* set/get ProxySTA */
    IEEE80211_PARAM_BW_NSS_RATEMASK         = 372,   /* Set ratemask with specific Bandwidth and NSS  */
    IEEE80211_PARAM_RX_SIGNAL_DBM           = 373,  /*get rx signal strength in dBm*/
    IEEE80211_PARAM_VHT_TX_MCSMAP           = 374,   /* Set VHT TX MCS MAP */
    IEEE80211_PARAM_VHT_RX_MCSMAP           = 375,   /* Set VHT RX MCS MAP */
    IEEE80211_PARAM_WNM_SMENTER             = 376,
    IEEE80211_PARAM_WNM_SMEXIT              = 377,
    IEEE80211_PARAM_HC_BSSLOAD              = 378,
    IEEE80211_PARAM_OSEN                    = 379,
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_OPT                 = 380,   /* set airtime feature */
    IEEE80211_PARAM_ATF_PER_UNIT            = 381,
#endif
    IEEE80211_PARAM_TX_MIN_POWER            = 382, /* Get min tx power */
    IEEE80211_PARAM_TX_MAX_POWER            = 383, /* Get max tx power */
    IEEE80211_PARAM_MGMT_RATE               = 384, /* Set mgmt rate, will set mcast/bcast/ucast to same rate*/
    IEEE80211_PARAM_NO_VAP_RESET            = 385, /* Disable the VAP reset in NSS */
    IEEE80211_PARAM_STA_COUNT               = 386, /* TO get number of station associated*/
#if ATH_SSID_STEERING
    IEEE80211_PARAM_VAP_SSID_CONFIG         = 387, /* Vap configuration  */
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    IEEE80211_PARAM_DSCP_OVERRIDE           = 388,
    IEEE80211_PARAM_DSCP_TID_MAP            = 389,
#endif
    IEEE80211_PARAM_RX_FILTER_MONITOR       = 390,
    IEEE80211_PARAM_SECOND_CENTER_FREQ      = 391,
    IEEE80211_PARAM_STRICT_BW               = 392,  /* BW restriction in pure 11ac */
    IEEE80211_PARAM_ADD_LOCAL_PEER          = 393,
    IEEE80211_PARAM_SET_MHDR                = 394,
    IEEE80211_PARAM_ALLOW_DATA              = 395,
    IEEE80211_PARAM_SET_MESHDBG             = 396,
    IEEE80211_PARAM_RTT_ENABLE              = 397,
    IEEE80211_PARAM_LCI_ENABLE              = 398,
    IEEE80211_PARAM_VAP_ENHIND              = 399, /* Independent VAP mode for Repeater and AP-STA config */
    IEEE80211_PARAM_VAP_PAUSE_SCAN          = 400, /* Pause VAP mode for scanning */
    IEEE80211_PARAM_EXT_ACS_IN_PROGRESS     = 401, /* Whether external auto channel selection is in
                                                    progress */
    IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE  = 402,  /* a-mpdu density override */
    IEEE80211_PARAM_SMART_MESH_CONFIG       = 403,  /* smart MESH configuration */
    IEEE80211_DISABLE_BCN_BW_NSS_MAP        = 404, /* To set & get Bandwidth-NSS mapping in beacon as vendor specific IE*/
    IEEE80211_DISABLE_STA_BWNSS_ADV         = 405, /* To disable all Bandwidth-NSS mapping feature in STA mode*/
    IEEE80211_PARAM_MIXED_MODE              = 406, /* In case of STA, this tells whether the AP we are associated
                                                      to supports TKIP alongwith AES */
    IEEE80211_PARAM_RX_FILTER_NEIGHBOUR_PEERS_MONITOR = 407,  /* filter out /drop invalid peers packet to upper stack */
#if ATH_DATA_RX_INFO_EN
    IEEE80211_PARAM_RXINFO_PERPKT          = 408,  /* update rx info per pkt */
#endif
    IEEE80211_PARAM_WHC_APINFO_WDS          = 415, /* Whether associated AP supports WDS
                                                      (as determined from the vendor IE) */
    IEEE80211_PARAM_WHC_APINFO_ROOT_DIST    = 416, /* Distance from the root AP (in hops);
                                                      only valid if the WDS flag is set
                                                      based on the param above */
    IEEE80211_PARAM_ATH_SUPPORT_VLAN        = 417,
    IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W   = 418, /* Configure association WAR for 160 MHz width (i.e.
                                                      160/80+80 MHz modes). Some STAs may have an issue
                                                      associating with us if we advertise 160/80+80 MHz related
                                                      capabilities in probe response/association response.
                                                      Hence this WAR suppresses 160/80+80 MHz related
                                                      information in probe responses, and association responses
                                                      for such STAs.
                                                      Starting from LSB
                                                      First bit set        = Default WAR behavior (VHT_OP modified)
                                                      First+second bit set = (VHT_OP+ VHT_CAP modified)
                                                      No bit set (default) = WAR disabled
                                                     */
#if DBG_LVL_MAC_FILTERING
    IEEE80211_PARAM_DBG_LVL_MAC             = 419, /* Enable/disable mac based filtering for debug logs */
#endif
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_TXBUF_MAX           = 420,
    IEEE80211_PARAM_ATF_TXBUF_MIN           = 421,
    IEEE80211_PARAM_ATF_TXBUF_SHARE         = 422, /* For ATF UDP */
    IEEE80211_PARAM_ATF_MAX_CLIENT          = 423, /* Support of ATF+non-ATF clients */
    IEEE80211_PARAM_ATF_SSID_GROUP          = 424, /* Support to enable/disable SSID grouping */
#endif
    IEEE80211_PARAM_11N_TX_AMSDU            = 425, /* Enable/Disable HT Tx AMSDU only */
    IEEE80211_PARAM_BSS_CHAN_INFO           = 426,
    IEEE80211_PARAM_LCR_ENABLE              = 427,
    IEEE80211_PARAM_WHC_APINFO_SON          = 428, /* Whether associated AP supports SON mode
                                                      (as determined from the vendor IE) */
    IEEE80211_PARAM_SON                     = 429, /* Mark/query AP as SON enabled */
    IEEE80211_PARAM_CTSPROT_DTIM_BCN        = 430, /* Enable/Disable CTS2SELF protection for DTIM Beacons */
    IEEE80211_PARAM_RAWMODE_PKT_SIM         = 431, /* Enable/Disable RAWMODE_PKT_SIM*/
    IEEE80211_PARAM_CONFIG_RAW_DWEP_IND     = 432, /* Enable/disable indication to WLAN driver that
                                                      dynamic WEP is being used in RAW mode. If the indication
                                                      is enabled and we are in RAW mode, we plumb a dummy key for
                                                      each of the keys corresponding to WEP cipher
                                                   */
#if ATH_GEN_RANDOMNESS
    IEEE80211_PARAM_RANDOMGEN_MODE           = 433,
#endif

   IEEE80211_PARAM_CUSTOM_CHAN_LIST         = 434,
#if UMAC_SUPPORT_ACFG
    IEEE80211_PARAM_DIAG_WARN_THRESHOLD     = 435,
    IEEE80211_PARAM_DIAG_ERR_THRESHOLD      = 436,
#endif
    IEEE80211_PARAM_MBO                           = 437,     /*  Enable MBO */
    IEEE80211_PARAM_MBO_CAP                       = 438,     /*  Enable MBO capability */
    IEEE80211_PARAM_MBO_ASSOC_DISALLOW            = 439,     /*  MBO  reason code for assoc disallow attribute */
    IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE       = 440,     /*  MBO cellular preference */
    IEEE80211_PARAM_MBO_TRANSITION_REASON         = 441,     /*  MBO Tansition reason */
    IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY         = 442,     /*  MBO  assoc retry delay */
#if ATH_SUPPORT_DSCP_OVERRIDE
    IEEE80211_PARAM_VAP_DSCP_PRIORITY        = 443,  /* VAP Based DSCP - Vap priority */
#endif
    IEEE80211_PARAM_TXRX_VAP_STATS           = 444,
    IEEE80211_PARAM_CONFIG_REV_SIG_160W      = 445, /* Enable/Disable revised signalling for 160/80+80 MHz */
    IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP = 446, /* Enable/Disable selective HT-MCS for this vap. */
    IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP = 447, /* Enable/Disable selective VHT-MCS for this vap. */
    IEEE80211_PARAM_RDG_ENABLE              = 448,
    IEEE80211_PARAM_DFS_SUPPORT             = 449,
    IEEE80211_PARAM_DFS_ENABLE              = 450,
    IEEE80211_PARAM_ACS_SUPPORT             = 451,
    IEEE80211_PARAM_SSID_STATUS             = 452,
    IEEE80211_PARAM_DL_QUEUE_PRIORITY_SUPPORT = 453,
    IEEE80211_PARAM_CLEAR_MIN_MAX_RSSI        = 454,
    IEEE80211_PARAM_CLEAR_QOS            = 455,
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT = 456, /* Override the airtime estimated */
#endif
#if MESH_MODE_SUPPORT
    IEEE80211_PARAM_MESH_CAPABILITIES      = 457, /* For providing Mesh vap capabilities */
#endif
#if UMAC_SUPPORT_ACL
    IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY = 458,  /* Enable/disable assoc denial notification to userspace */
    IEEE80211_PARAM_ADD_MAC_LIST_SEC = 459, /* To check if the mac address is to added in secondary ACL list */
    IEEE80211_PARAM_GET_MAC_LIST_SEC = 460, /* To get the mac addresses from the secondary ACL list */
    IEEE80211_PARAM_DEL_MAC_LIST_SEC = 461, /* To delete the given mac address from the secondary ACL list */
    IEEE80211_PARAM_MACCMD_SEC = 462, /* To set/get the acl policy of the secondary ACL list */
#endif /* UMAC_SUPPORT_ACL */
    IEEE80211_PARAM_UMAC_VERBOSE_LVL           = 463, /* verbose level for UMAC specific debug */
    IEEE80211_PARAM_VAP_TXRX_FW_STATS          = 464, /* Get per VAP MU-MIMO stats */
    IEEE80211_PARAM_VAP_TXRX_FW_STATS_RESET    = 465, /* Reset per VAp MU-MIMO stats */
    IEEE80211_PARAM_PEER_TX_MU_BLACKLIST_COUNT = 466, /* Get number of times a peer has been blacklisted due to sounding failures */
    IEEE80211_PARAM_PEER_TX_COUNT              = 467, /* Get count of MU MIMO tx to a peer */
    IEEE80211_PARAM_PEER_MUMIMO_TX_COUNT_RESET = 468, /* Reset count of MU MIMO tx to a peer */
    IEEE80211_PARAM_PEER_POSITION              = 469, /* Get peer position in MU group */
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_SSID_SCHED_POLICY    = 470, /* support to set per ssid atf sched policy, 0-fair 1-strict */
#endif
    IEEE80211_PARAM_CONNECTION_SM_STATE        = 471, /* Get the current state of the connectionm SM */
#if MESH_MODE_SUPPORT
    IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH    = 472,
    IEEE80211_PARAM_CONFIG_RX_MESH_FILTER      = 473,
#endif
    IEEE80211_PARAM_TRAFFIC_STATS              = 474,   /* Enable/disable the measurement of traffic statistics */
    IEEE80211_PARAM_TRAFFIC_RATE               = 475,   /* set the traffic rate, the rate at which the received signal statistics are be measured */
    IEEE80211_PARAM_TRAFFIC_INTERVAL           = 476,   /* set the traffic interval,the time till which the received signal statistics are to be measured */
    IEEE80211_PARAM_WATERMARK_THRESHOLD        = 477,
    IEEE80211_PARAM_WATERMARK_REACHED          = 478,
    IEEE80211_PARAM_ASSOC_REACHED              = 479,
    IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP = 480,      /* Enable/Disable selective Legacy Rates for this vap. */
    IEEE80211_PARAM_RTSCTS_RATE                = 481,   /* Set rts and cts rate*/
    IEEE80211_PARAM_REPT_MULTI_SPECIAL         = 482,
    IEEE80211_PARAM_VSP_ENABLE                 = 483,   /* Video Stream Protection */
    IEEE80211_PARAM_ENABLE_VENDOR_IE           = 484,    /* Enable/ disable Vendor ie advertise in Beacon/ proberesponse*/
    IEEE80211_PARAM_WHC_APINFO_SFACTOR         = 485,  /* Set Scaling factor for best uplink selection algorithm */
    IEEE80211_PARAM_WHC_APINFO_BSSID           = 486,  /* Get the best uplink BSSID for scan entries */
    IEEE80211_PARAM_WHC_APINFO_RATE            = 487,  /* Get the current uplink data rate(estimate) */
    IEEE80211_PARAM_CONFIG_MON_DECODER         = 488,  /* Monitor VAP decoder format radiotap/prism */
    IEEE80211_PARAM_DYN_BW_RTS                 = 489,   /* Enable/Disable the dynamic bandwidth RTS */
    IEEE80211_PARAM_CONFIG_MU_CAP_TIMER        = 490,  /* Set/Get timer period in seconds(1 to 300) for de-assoc dedicated client when
                                                       mu-cap client joins/leaves */
    IEEE80211_PARAM_CONFIG_MU_CAP_WAR          = 491,   /* Enable/Disable Mu Cap WAR function */
    IEEE80211_PARAM_CONFIG_BSSID               = 492,  /* Configure hidden ssid AP's bssid */
    IEEE80211_PARAM_CONFIG_NSTSCAP_WAR         = 493,  /* Enable/Disable NSTS CAP WAR */
    IEEE80211_PARAM_WHC_APINFO_CAP_BSSID       = 494,   /* get the CAP BSSID from scan entries */
    IEEE80211_PARAM_BEACON_RATE_FOR_VAP        = 495,      /*Configure beacon rate to user provided rate*/
    IEEE80211_PARAM_CHANNEL_SWITCH_MODE        = 496,   /* channel switch mode to be used in CSA and ECSA IE*/
    IEEE80211_PARAM_ENABLE_ECSA_IE             = 497,   /* ECSA IE  enable/disable*/
    IEEE80211_PARAM_ECSA_OPCLASS               = 498,   /* opClass to be announced in ECSA IE */
#if DYNAMIC_BEACON_SUPPORT
    IEEE80211_PARAM_DBEACON_EN                 = 499, /* Enable/disable the dynamic beacon feature */
    IEEE80211_PARAM_DBEACON_RSSI_THR           = 500, /* Set/Get the rssi threshold */
    IEEE80211_PARAM_DBEACON_TIMEOUT            = 501, /* Set/Get the timeout of timer */
#endif
    IEEE80211_PARAM_TXPOW_MGMT                 = 502,   /* set/get the tx power per vap */
    IEEE80211_PARAM_CONFIG_TX_CAPTURE          = 503, /* Configure pkt capture in Tx direction */
    IEEE80211_PARAM_GET_CONFIG_BSSID           = 504, /* get configured hidden ssid AP's bssid */
    IEEE80211_PARAM_OCE                        = 505,  /* Enable OCE */
    IEEE80211_PARAM_OCE_ASSOC_REJECT           = 506,  /* Enable OCE RSSI-based assoc reject */
    IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI         = 507,  /* Min RSSI for assoc accept */
    IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY      = 508,  /* Retry delay for subsequent (re-)assoc */
    IEEE80211_PARAM_OCE_WAN_METRICS            = 509,  /* Enable OCE reduced WAN metrics */
    IEEE80211_PARAM_BACKHAUL                   = 510,
};
#define WOW_CUSTOM_PKT_LEN 102
#define WOW_SYNC_PATTERN 0xFF
#define WOW_SYNC_LEN 6
#define WOW_MAC_ADDR_COUNT 16
#define ETH_TYPE_WOW 0x0842

/*
 * New get/set params for p2p.
 * The first 16 set/get priv ioctls know the direction of the xfer
 * These sub-ioctls, don't care, any number in 16 bits is ok
 * The param numbers need not be contiguous, but must be unique
 */
#define IEEE80211_IOC_P2P_GO_OPPPS        621    /* IOCTL to turn on/off oppPS for P2P GO */
#define IEEE80211_IOC_P2P_GO_CTWINDOW     622    /* IOCTL to set CT WINDOW size for P2P GO*/
#define IEEE80211_IOC_P2P_GO_NOA          623    /* IOCTL to set NOA for P2P GO*/

//#define IEEE80211_IOC_P2P_FLUSH           616    /* IOCTL to flush P2P state */
#define IEEE80211_IOC_SCAN_REQ            624    /* IOCTL to request a scan */
//needed, below
#define IEEE80211_IOC_SCAN_RESULTS        IEEE80211_IOCTL_SCAN_RESULTS

#define IEEE80211_IOC_SSID                626    /* set ssid */
#define IEEE80211_IOC_MLME                IEEE80211_IOCTL_SETMLME
#define IEEE80211_IOC_CHANNEL             628    /* set channel */

#define IEEE80211_IOC_WPA                 IEEE80211_PARAM_WPA    /* WPA mode (0,1,2) */
#define IEEE80211_IOC_AUTHMODE            IEEE80211_PARAM_AUTHMODE
#define IEEE80211_IOC_KEYMGTALGS          IEEE80211_PARAM_KEYMGTALGS    /* key management algorithms */
#define IEEE80211_IOC_WPS_MODE            632    /* Wireless Protected Setup mode  */

#define IEEE80211_IOC_UCASTCIPHERS        IEEE80211_PARAM_UCASTCIPHERS    /* unicast cipher suites */
#define IEEE80211_IOC_UCASTCIPHER         IEEE80211_PARAM_UCASTCIPHER    /* unicast cipher */
#define IEEE80211_IOC_MCASTCIPHER         IEEE80211_PARAM_MCASTCIPHER    /* multicast/default cipher */
//unused below
#define IEEE80211_IOC_START_HOSTAP        636    /* Start hostap mode BSS */

#define IEEE80211_IOC_DROPUNENCRYPTED     637    /* discard unencrypted frames */
#define IEEE80211_IOC_PRIVACY             638    /* privacy invoked */
#define IEEE80211_IOC_OPTIE               IEEE80211_IOCTL_SETOPTIE    /* optional info. element */
#define IEEE80211_IOC_BSSID               640    /* GET bssid */
//unused below 3
#define IEEE80211_IOC_P2P_CANCEL_CHANNEL  642    /* Cancel current set-channel operation */
#define IEEE80211_IOC_P2P_SEND_ACTION     643    /* Send Action frame */

#define IEEE80211_IOC_P2P_OPMODE          644    /* set/get the opmode(STA,AP,P2P GO,P2P CLI) */
#define IEEE80211_IOC_P2P_FETCH_FRAME     645    /* get rx_frame mgmt data, too large for an event */

#define IEEE80211_IOC_SCAN_FLUSH          646
#define IEEE80211_IOC_CONNECTION_STATE    647 	/* connection state of the iface */
#define IEEE80211_IOC_P2P_NOA_INFO        648   /*  To get NOA sub element info from p2p client */
#define IEEE80211_IOC_CANCEL_SCAN           650   /* To cancel scan request */
#define IEEE80211_IOC_P2P_RADIO_IDX         651   /* Get radio index */
#ifdef HOST_OFFLOAD
#endif

struct ieee80211_p2p_go_neg {
    u_int8_t peer_addr[IEEE80211_ADDR_LEN];
    u_int8_t own_interface_addr[IEEE80211_ADDR_LEN];
    u_int16_t force_freq;
    u_int8_t go_intent;
    char pin[9];
} __attribute__ ((packed));

struct ieee80211_p2p_prov_disc {
    u_int8_t peer_addr[IEEE80211_ADDR_LEN];
    u_int16_t config_methods;
} __attribute__ ((packed));

struct ieee80211_p2p_serv_disc_resp {
    u_int16_t freq;
    u_int8_t dst[IEEE80211_ADDR_LEN];
    u_int8_t dialog_token;
    /* followed by response TLVs */
} __attribute__ ((packed));

struct ieee80211_p2p_go_noa {
    u_int8_t  num_iterations;   /* Number of iterations (equal 1 if one shot)
                                   and 1-254 if periodic) and 255 for continuous */
    u_int16_t offset_next_tbtt; /* offset in msec from next tbtt */
    u_int16_t duration;         /* duration in msec */
} __attribute__ ((packed));

struct ieee80211_p2p_set_channel {
    u_int32_t freq;
    u_int32_t req_id;
    u_int32_t channel_time;
} __attribute__ ((packed));

struct ieee80211_p2p_send_action {
    u_int32_t freq;
    u_int8_t dst_addr[IEEE80211_ADDR_LEN];
    u_int8_t src_addr[IEEE80211_ADDR_LEN];
    u_int8_t bssid[IEEE80211_ADDR_LEN];
    /* Followed by Action frame payload */
} __attribute__ ((packed));

struct ieee80211_send_action_cb {
    u_int8_t dst_addr[IEEE80211_ADDR_LEN];
    u_int8_t src_addr[IEEE80211_ADDR_LEN];
    u_int8_t bssid[IEEE80211_ADDR_LEN];
    u_int8_t ack;
    /* followed by frame body */
} __attribute__ ((packed));

/* Optional parameters for IEEE80211_IOC_SCAN_REQ */
struct ieee80211_scan_req {
#define MAX_SCANREQ_FREQ 16
    u_int32_t freq[MAX_SCANREQ_FREQ];
    u_int8_t num_freq;
    u_int8_t num_ssid;
    u_int16_t ie_len;
#define MAX_SCANREQ_SSID 4
    u_int8_t ssid[MAX_SCANREQ_SSID][32];
    u_int8_t ssid_len[MAX_SCANREQ_SSID];
    /* followed by ie_len octets of IEs to add to Probe Request frames */
} __attribute__ ((packed));

struct ieee80211_ioc_channel {
    u_int32_t phymode; /* enum ieee80211_phymode */
    u_int32_t channel; /* IEEE channel number */
} __attribute__ ((packed));

#define LINUX_PVT_SET_VENDORPARAM       (SIOCDEVPRIVATE+0)
#define LINUX_PVT_GET_VENDORPARAM       (SIOCDEVPRIVATE+1)
#define	SIOCG80211STATS		(SIOCDEVPRIVATE+2)
/* NB: require in+out parameters so cannot use wireless extensions, yech */
#define	IEEE80211_IOCTL_GETKEY		(SIOCDEVPRIVATE+3)
#define	IEEE80211_IOCTL_GETWPAIE	(SIOCDEVPRIVATE+4)
#define	IEEE80211_IOCTL_STA_STATS	(SIOCDEVPRIVATE+5)
#define	IEEE80211_IOCTL_STA_INFO	(SIOCDEVPRIVATE+6)
#define	SIOC80211IFCREATE		(SIOCDEVPRIVATE+7)
#define	SIOC80211IFDESTROY	 	(SIOCDEVPRIVATE+8)
#define	IEEE80211_IOCTL_SCAN_RESULTS	(SIOCDEVPRIVATE+9)
#define IEEE80211_IOCTL_RES_REQ         (SIOCDEVPRIVATE+10)
#define IEEE80211_IOCTL_GETMAC          (SIOCDEVPRIVATE+11)
#define IEEE80211_IOCTL_CONFIG_GENERIC  (SIOCDEVPRIVATE+12)
#define SIOCIOCTLTX99                   (SIOCDEVPRIVATE+13)
#define IEEE80211_IOCTL_P2P_BIG_PARAM   (SIOCDEVPRIVATE+14)
#define SIOCDEVVENDOR                   (SIOCDEVPRIVATE+15)    /* Used for ATH_SUPPORT_LINUX_VENDOR */
#define	IEEE80211_IOCTL_GET_SCAN_SPACE  (SIOCDEVPRIVATE+16)

#define IEEE80211_IOCTL_ATF_ADDSSID     0xFF01
#define IEEE80211_IOCTL_ATF_DELSSID     0xFF02
#define IEEE80211_IOCTL_ATF_ADDSTA      0xFF03
#define IEEE80211_IOCTL_ATF_DELSTA      0xFF04
#define IEEE80211_IOCTL_ATF_SHOWATFTBL  0xFF05
#define IEEE80211_IOCTL_ATF_SHOWAIRTIME 0xFF06
#define IEEE80211_IOCTL_ATF_FLUSHTABLE  0xFF07                 /* Used to Flush the ATF table entries */

#define IEEE80211_IOCTL_ATF_ADDGROUP    0xFF08
#define IEEE80211_IOCTL_ATF_CONFIGGROUP 0xFF09
#define IEEE80211_IOCTL_ATF_DELGROUP    0xFF0a
#define IEEE80211_IOCTL_ATF_SHOWGROUP   0xFF0b

#define IEEE80211_IOCTL_ATF_ADDSTA_TPUT     0xFF0C
#define IEEE80211_IOCTL_ATF_DELSTA_TPUT     0xFF0D
#define IEEE80211_IOCTL_ATF_SHOW_TPUT       0xFF0E

#define ATF_TPUT_MASK         0x00ffffff
#define ATF_AIRTIME_MASK      0xff000000
#define ATF_AIRTIME_SHIFT     24

/* added APPIEBUF related definations */
#define    IEEE80211_APPIE_FRAME_BEACON      0
#define    IEEE80211_APPIE_FRAME_PROBE_REQ   1
#define    IEEE80211_APPIE_FRAME_PROBE_RESP  2
#define    IEEE80211_APPIE_FRAME_ASSOC_REQ   3
#define    IEEE80211_APPIE_FRAME_ASSOC_RESP  4
#define    IEEE80211_APPIE_FRAME_TDLS_FTIE   5   /* TDLS SMK_FTIEs */
#define    IEEE80211_APPIE_FRAME_AUTH        6
#define    IEEE80211_APPIE_NUM_OF_FRAME      7
#define    IEEE80211_APPIE_FRAME_WNM         8

#define    DEFAULT_IDENTIFIER 0
#define    HOSTAPD_IE 1
#define    HOSTAPD_WPS_IE 2

struct ieee80211req_getset_appiebuf {
    u_int32_t app_frmtype; /*management frame type for which buffer is added*/
    u_int32_t app_buflen;  /*application supplied buffer length */
    u_int8_t  identifier;
    u_int8_t  app_buf[];
} __packed;

struct ieee80211req_mgmtbuf {
    u_int8_t  macaddr[IEEE80211_ADDR_LEN]; /* mac address to be sent */
    u_int32_t buflen;  /*application supplied buffer length */
    u_int8_t  buf[];
};

/* the following definations are used by application to set filter
 * for receiving management frames */
enum {
     IEEE80211_FILTER_TYPE_BEACON      =   0x1,
     IEEE80211_FILTER_TYPE_PROBE_REQ   =   0x2,
     IEEE80211_FILTER_TYPE_PROBE_RESP  =   0x4,
     IEEE80211_FILTER_TYPE_ASSOC_REQ   =   0x8,
     IEEE80211_FILTER_TYPE_ASSOC_RESP  =   0x10,
     IEEE80211_FILTER_TYPE_AUTH        =   0x20,
     IEEE80211_FILTER_TYPE_DEAUTH      =   0x40,
     IEEE80211_FILTER_TYPE_DISASSOC    =   0x80,
     IEEE80211_FILTER_TYPE_ACTION      =   0x100,
     IEEE80211_FILTER_TYPE_ALL         =   0xFFF  /* used to check the valid filter bits */
};

struct ieee80211req_set_filter {
      u_int32_t app_filterype; /* management frame filter type */
};

struct ieee80211_wlanconfig_atf {
    u_int8_t     macaddr[IEEE80211_ADDR_LEN];    /* MAC address (input) */
    u_int32_t    short_avg;                      /* AirtimeShortAvg (output) */
    u_int64_t    total_used_tokens;              /* AirtimeTotal    (output) */
};

struct ieee80211_wlanconfig_nawds {
    u_int8_t num;
    u_int8_t mode;
    u_int32_t defcaps;
    u_int8_t override;
    u_int8_t mac[IEEE80211_ADDR_LEN];
    u_int32_t caps;
};

struct ieee80211_wlanconfig_hmwds {
    u_int8_t  wds_ni_macaddr[IEEE80211_ADDR_LEN];
    u_int16_t wds_macaddr_cnt;
    u_int8_t  wds_macaddr[0];
};

struct ieee80211_wlanconfig_ald_sta {
    u_int8_t  macaddr[IEEE80211_ADDR_LEN];
    u_int32_t enable;
};

struct ieee80211_wlanconfig_ald {
    union {
        struct ieee80211_wlanconfig_ald_sta ald_sta;
    } data;
};

struct ieee80211_wlanconfig_wnm_bssmax {
    u_int16_t idleperiod;
    u_int8_t idleoption;
};

struct ieee80211_wlanconfig_wds {
    u_int8_t destmac[IEEE80211_ADDR_LEN];
    u_int8_t peermac[IEEE80211_ADDR_LEN];
    u_int32_t flags;
};

struct ieee80211_wlanconfig_wds_table {
    u_int16_t wds_entry_cnt;
    struct ieee80211_wlanconfig_wds wds_entries[0];
};

struct ieee80211_wlanconfig_hmmc {
    u_int32_t ip;
    u_int32_t mask;
};

struct ieee80211_wlanconfig_setmaxrate {
    u_int8_t mac[IEEE80211_ADDR_LEN];
    u_int8_t maxrate;
};

#define TFS_MAX_FILTER_LEN 50
#define TFS_MAX_TCLAS_ELEMENTS 2
#define TFS_MAX_SUBELEMENTS 2
#define TFS_MAX_REQUEST 2
#define TFS_MAX_RESPONSE 600

#define FMS_MAX_SUBELEMENTS    2
#define FMS_MAX_TCLAS_ELEMENTS 2
#define FMS_MAX_REQUEST        2
#define FMS_MAX_RESPONSE       2

typedef enum {
    IEEE80211_WNM_TFS_AC_DELETE_AFTER_MATCH = 0,
    IEEE80211_WNM_TFS_AC_NOTIFY = 1,
} IEEE80211_WNM_TFS_ACTIONCODE;

typedef enum {
    IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE0 = 0,
    IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE1 = 1,
    IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE2 = 2,
    IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE3 = 3,
    IEEE80211_WNM_TCLAS_CLASSIFIER_TYPE4 = 4,
} IEEE80211_WNM_TCLAS_CLASSIFIER;

typedef enum {
    IEEE80211_WNM_TCLAS_CLAS14_VERSION_4 = 4,
    IEEE80211_WNM_TCLAS_CLAS14_VERSION_6 = 6,
} IEEE80211_WNM_TCLAS_VERSION;

#ifndef IEEE80211_IPV4_LEN
#define IEEE80211_IPV4_LEN 4
#endif

#ifndef IEEE80211_IPV6_LEN
#define IEEE80211_IPV6_LEN 16
#endif

/*
 * TCLAS Classifier Type 1 and Type 4 are exactly the same for IPv4.
 * For IPv6, Type 4 has two more fields (dscp, next header) than
 * Type 1. So we use the same structure for both Type 1 and 4 here.
 */
struct clas14_v4 {
    u_int8_t     version;
    u_int8_t     source_ip[IEEE80211_IPV4_LEN];
    u_int8_t     reserved1[IEEE80211_IPV6_LEN - IEEE80211_IPV4_LEN];
    u_int8_t     dest_ip[IEEE80211_IPV4_LEN];
    u_int8_t     reserved2[IEEE80211_IPV6_LEN - IEEE80211_IPV4_LEN];
    u_int16_t    source_port;
    u_int16_t    dest_port;
    u_int8_t     dscp;
    u_int8_t     protocol;
    u_int8_t     reserved;
    u_int8_t     reserved3[2];
};

struct clas14_v6 {
    u_int8_t     version;
    u_int8_t     source_ip[IEEE80211_IPV6_LEN];
    u_int8_t     dest_ip[IEEE80211_IPV6_LEN];
    u_int16_t    source_port;
    u_int16_t    dest_port;
    u_int8_t     clas4_dscp;
    u_int8_t     clas4_next_header;
    u_int8_t     flow_label[3];
};

struct clas3 {
    u_int16_t filter_offset;
    u_int32_t filter_len;
    u_int8_t  filter_value[TFS_MAX_FILTER_LEN];
    u_int8_t  filter_mask[TFS_MAX_FILTER_LEN];
};

struct tfsreq_tclas_element {
    u_int8_t classifier_type;
    u_int8_t classifier_mask;
    u_int8_t priority;
    union {
        union {
            struct clas14_v4 clas14_v4;
            struct clas14_v6 clas14_v6;
        } clas14;
        struct clas3 clas3;
    } clas;
};

struct tfsreq_subelement {
    u_int32_t num_tclas_elements;
    u_int8_t tclas_processing;
    struct tfsreq_tclas_element tclas[TFS_MAX_TCLAS_ELEMENTS];
};

struct ieee80211_wlanconfig_wnm_tfs_req {
    u_int8_t tfsid;
    u_int8_t actioncode;
    u_int8_t num_subelements;
    struct tfsreq_subelement subelement[TFS_MAX_SUBELEMENTS];
};

#define NAC_MAX_CLIENT  8
#define NAC_MAX_BSSID  3

typedef enum ieee80211_nac_mactype {
    IEEE80211_NAC_MACTYPE_BSSID  = 1,
    IEEE80211_NAC_MACTYPE_CLIENT = 2,
} IEEE80211_NAC_MACTYPE;

struct ieee80211_wlanconfig_nac {
    u_int8_t    mac_type;
    u_int8_t    mac_list[NAC_MAX_CLIENT][IEEE80211_ADDR_LEN]; /* client has max limit */
};


struct ieee80211_wlanconfig_wnm_tfs {
    u_int8_t num_tfsreq;
    struct ieee80211_wlanconfig_wnm_tfs_req tfs_req[TFS_MAX_REQUEST];
};

struct tfsresp_element {
	u_int8_t tfsid;
    u_int8_t status;
} __packed;

struct ieee80211_wnm_tfsresp {
    u_int8_t num_tfsresp;
    struct tfsresp_element  tfs_resq[TFS_MAX_RESPONSE];
} __packed;

typedef struct  ieee80211_wnm_rate_identifier_s {
    u_int8_t mask;
    u_int8_t mcs_idx;
    u_int16_t rate;
}__packed ieee80211_wnm_rate_identifier_t;

struct fmsresp_fms_subele_status {
    u_int8_t status;
    u_int8_t del_itvl;
    u_int8_t max_del_itvl;
    u_int8_t fmsid;
    u_int8_t fms_counter;
    ieee80211_wnm_rate_identifier_t rate_id;
    u_int8_t mcast_addr[6];
};

struct fmsresp_tclas_subele_status {
    u_int8_t fmsid;
    u_int8_t ismcast;
    u_int32_t mcast_ipaddr;
    ieee80211_tclas_processing tclasprocess;
    u_int32_t num_tclas_elements;
    struct tfsreq_tclas_element tclas[TFS_MAX_TCLAS_ELEMENTS];
};

struct fmsresp_element {
    u_int8_t fms_token;
    u_int8_t num_subelements;
    u_int8_t subelement_type;
    union {
        struct fmsresp_fms_subele_status fms_subele_status[FMS_MAX_TCLAS_ELEMENTS];
        struct fmsresp_tclas_subele_status tclas_subele_status[FMS_MAX_SUBELEMENTS];
    }status;
};

struct ieee80211_wnm_fmsresp {
    u_int8_t num_fmsresp;
    struct fmsresp_element  fms_resp[FMS_MAX_RESPONSE];
};

struct fmsreq_subelement {
    u_int8_t del_itvl;
    u_int8_t max_del_itvl;
    u_int8_t tclas_processing;
    u_int32_t num_tclas_elements;
    ieee80211_wnm_rate_identifier_t rate_id;
    struct tfsreq_tclas_element tclas[FMS_MAX_TCLAS_ELEMENTS];
} __packed;

struct ieee80211_wlanconfig_wnm_fms_req {
    u_int8_t fms_token;
    u_int8_t num_subelements;
    struct fmsreq_subelement subelement[FMS_MAX_SUBELEMENTS];
};

struct ieee80211_wlanconfig_wnm_fms {
    u_int8_t num_fmsreq;
    struct ieee80211_wlanconfig_wnm_fms_req  fms_req[FMS_MAX_REQUEST];
};

enum {
    IEEE80211_WNM_TIM_HIGHRATE_ENABLE = 0x1,
    IEEE80211_WNM_TIM_LOWRATE_ENABLE = 0x2,
};

struct ieee80211_wlanconfig_wnm_tim {
    u_int8_t interval;
    u_int8_t enable_highrate;
    u_int8_t enable_lowrate;
};

struct ieee80211_wlanconfig_wnm_bssterm {
    u_int16_t delay;    /* in TBTT */
    u_int16_t duration; /* in minutes */
};

struct ieee80211_wlanconfig_wnm {
    union {
        struct ieee80211_wlanconfig_wnm_bssmax bssmax;
        struct ieee80211_wlanconfig_wnm_tfs tfs;
        struct ieee80211_wlanconfig_wnm_fms fms;
        struct ieee80211_wlanconfig_wnm_tim tim;
        struct ieee80211_wlanconfig_wnm_bssterm bssterm;
    } data;
};

/* generic structure to support sub-ioctl due to limited ioctl */
typedef enum {
    IEEE80211_WLANCONFIG_NOP,
    IEEE80211_WLANCONFIG_NAWDS_SET_MODE,
    IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS,
    IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE,
    IEEE80211_WLANCONFIG_NAWDS_SET_ADDR,
    IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR,
    IEEE80211_WLANCONFIG_NAWDS_GET,
    IEEE80211_WLANCONFIG_WNM_SET_BSSMAX,
    IEEE80211_WLANCONFIG_WNM_GET_BSSMAX,
    IEEE80211_WLANCONFIG_WNM_TFS_ADD,
    IEEE80211_WLANCONFIG_WNM_TFS_DELETE,
    IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY,
    IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST,
    IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST,
    IEEE80211_WLANCONFIG_WDS_ADD_ADDR,
    IEEE80211_WLANCONFIG_HMMC_ADD,
    IEEE80211_WLANCONFIG_HMMC_DEL,
    IEEE80211_WLANCONFIG_HMMC_DUMP,
    IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE,
    IEEE80211_WLANCONFIG_HMWDS_READ_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_READ_TABLE,
    IEEE80211_WLANCONFIG_SET_MAX_RATE,
    IEEE80211_WLANCONFIG_WDS_SET_ENTRY,
    IEEE80211_WLANCONFIG_WDS_DEL_ENTRY,
    IEEE80211_WLANCONFIG_ALD_STA_ENABLE,
    IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION,
    IEEE80211_WLANCONFIG_GETCHANINFO_160,
    IEEE80211_WLANCONFIG_VENDOR_IE_ADD,
    IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE,
    IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE,
    IEEE80211_WLANCONFIG_VENDOR_IE_LIST,
    IEEE80211_WLANCONFIG_NAC_ADDR_ADD,
    IEEE80211_WLANCONFIG_NAC_ADDR_DEL,
    IEEE80211_WLANCONFIG_NAC_ADDR_LIST,
    IEEE80211_PARAM_STA_ATF_STAT,
    IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR,
} IEEE80211_WLANCONFIG_CMDTYPE;
/* Note: Do not place any of the above ioctls within compile flags,
   The above ioctls are also being used by external apps.
   External apps do not define the compile flags as driver does.
   Having ioctls within compile flags leave the apps and drivers to use
   a different values.
*/

typedef enum {
    IEEE80211_WLANCONFIG_OK          = 0,
    IEEE80211_WLANCONFIG_FAIL        = 1,
} IEEE80211_WLANCONFIG_STATUS;

struct ieee80211_wlanconfig {
    IEEE80211_WLANCONFIG_CMDTYPE cmdtype;  /* sub-command */
    IEEE80211_WLANCONFIG_STATUS status;     /* status code */
    union {
        struct ieee80211_wlanconfig_nawds nawds;
        struct ieee80211_wlanconfig_hmwds hmwds;
        struct ieee80211_wlanconfig_wnm wnm;
        struct ieee80211_wlanconfig_hmmc hmmc;
        struct ieee80211_wlanconfig_wds_table wds_table;
        struct ieee80211_wlanconfig_ald ald;
        struct ieee80211_wlanconfig_nac nac;
        struct ieee80211_wlanconfig_atf atf;
    } data;

    struct ieee80211_wlanconfig_setmaxrate smr;
};

#define VENDORIE_OUI_LEN 3
#define MAX_VENDOR_IE_LEN 128
#define MAX_VENDOR_BUF_LEN 2048

struct ieee80211_wlanconfig_vendorie {

    IEEE80211_WLANCONFIG_CMDTYPE cmdtype;  /* sub-command */
    u_int8_t    ftype_map; /* map which frames , thesse IE are included */
    u_int16_t    tot_len;   /* total vie struct length */
struct  {
    u_int8_t    id;
    u_int8_t    len;    /* len of oui + cap_info */
    u_int8_t    oui[VENDORIE_OUI_LEN];
    u_int8_t    cap_info[];
} ie;
};


/* kev event_code value for Atheros IEEE80211 events */
enum {
    IEEE80211_EV_SCAN_DONE,
    IEEE80211_EV_CHAN_START,
    IEEE80211_EV_CHAN_END,
    IEEE80211_EV_RX_MGMT,
    IEEE80211_EV_P2P_SEND_ACTION_CB,
    IEEE80211_EV_IF_RUNNING,
    IEEE80211_EV_IF_NOT_RUNNING,
    IEEE80211_EV_AUTH_COMPLETE_AP,
    IEEE80211_EV_ASSOC_COMPLETE_AP,
    IEEE80211_EV_DEAUTH_COMPLETE_AP,
    IEEE80211_EV_AUTH_IND_AP,
    IEEE80211_EV_AUTH_COMPLETE_STA,
    IEEE80211_EV_ASSOC_COMPLETE_STA,
    IEEE80211_EV_DEAUTH_COMPLETE_STA,
    IEEE80211_EV_DISASSOC_COMPLETE_STA,
    IEEE80211_EV_AUTH_IND_STA,
    IEEE80211_EV_DEAUTH_IND_STA,
    IEEE80211_EV_ASSOC_IND_STA,
    IEEE80211_EV_DISASSOC_IND_STA,
    IEEE80211_EV_DEAUTH_IND_AP,
    IEEE80211_EV_DISASSOC_IND_AP,
    IEEE80211_EV_ASSOC_IND_AP,
    IEEE80211_EV_REASSOC_IND_AP,
    IEEE80211_EV_MIC_ERR_IND_AP,
    IEEE80211_EV_KEYSET_DONE_IND_AP,
    IEEE80211_EV_BLKLST_STA_AUTH_IND_AP,
    IEEE80211_EV_WAPI,
    IEEE80211_EV_TX_MGMT,
    IEEE80211_EV_CHAN_CHANGE,
    IEEE80211_EV_RECV_PROBEREQ,
    IEEE80211_EV_STA_AUTHORIZED,
    IEEE80211_EV_STA_LEAVE,
    IEEE80211_EV_ASSOC_FAILURE,
#if QCA_LTEU_SUPPORT
    IEEE80211_EV_MU_RPT,
    IEEE80211_EV_SCAN,
#endif
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_EV_ATF_CONFIG,
#endif
#if MESH_MODE_SUPPORT
    IEEE80211_EV_MESH_PEER_TIMEOUT,
#endif
    IEEE80211_EV_UNPROTECTED_DEAUTH_IND_STA,
};

#endif /* __linux__ */

#define IEEE80211_VAP_PROFILE_NUM_ACL 64
#define IEEE80211_VAP_PROFILE_MAX_VAPS 16

struct rssi_info {
    u_int8_t avg_rssi;
    u_int8_t valid_mask;
    int8_t   rssi_ctrl[MAX_CHAINS];
    int8_t   rssi_ext[MAX_CHAINS];
};

struct ieee80211vap_profile  {
    char name[IFNAMSIZ];
    u_int32_t opmode;
    u_int32_t phymode;
    char  ssid[IEEE80211_NWID_LEN];
    u_int32_t bitrate;
    u_int32_t beacon_interval;
    u_int32_t txpower;
    u_int32_t txpower_flags;
    struct rssi_info bcn_rssi;
    struct rssi_info rx_rssi;
    u_int8_t  vap_mac[IEEE80211_ADDR_LEN];
    u_int32_t  rts_thresh;
    u_int8_t  rts_disabled;
    u_int8_t  rts_fixed;
    u_int32_t frag_thresh;
    u_int8_t frag_disabled;
    u_int8_t frag_fixed;
    u_int32_t   sec_method;
    u_int32_t   cipher;
    u_int8_t wep_key[4][256];
    u_int8_t wep_key_len[4];
    u_int8_t  maclist[IEEE80211_VAP_PROFILE_NUM_ACL][IEEE80211_ADDR_LEN];
   	u_int8_t  node_acl;
    int  num_node;
    u_int8_t wds_enabled;
    u_int8_t wds_addr[IEEE80211_ADDR_LEN];
    u_int32_t wds_flags;
};

struct ieee80211_profile {
    u_int8_t radio_name[IFNAMSIZ];
    u_int8_t channel;
    u_int32_t freq;
    u_int16_t cc;
    u_int8_t  radio_mac[IEEE80211_ADDR_LEN];
    struct ieee80211vap_profile vap_profile[IEEE80211_VAP_PROFILE_MAX_VAPS];
    int num_vaps;
};

/* FIPS Structures to be used by application */

#define FIPS_ENCRYPT 0
#define FIPS_DECRYPT 1
struct ath_ioctl_fips {
    u_int32_t fips_cmd;/* 1 - Encrypt, 2 - Decrypt*/
    u_int32_t mode;
    u_int32_t key_len;
#define MAX_KEY_LEN_FIPS 32
    u_int8_t  key[MAX_KEY_LEN_FIPS];
#define MAX_IV_LEN_FIPS  16
    u_int8_t iv[MAX_IV_LEN_FIPS];
    u_int32_t data_len;
    u_int32_t data[1];
};

struct ath_fips_output {
    u_int32_t error_status;
    u_int32_t data_len;
    u_int32_t data[1]; /* output from Fips Register*/
};

#define IS_UP_AUTO(_vap) \
    (IS_UP((_vap)->iv_dev) && \
    (_vap)->iv_ic->ic_roaming == IEEE80211_ROAMING_AUTO)

#if QCA_LTEU_SUPPORT

#define MU_MAX_ALGO          4
#define MU_DATABASE_MAX_LEN  32

typedef enum {
    MU_STATUS_SUCCESS,
    /* errors encountered in initiating MU scan are as below */
    MU_STATUS_BUSY_PREV_REQ_IN_PROG,      /* returned if previous request for MU scan is currently being processed */
    MU_STATUS_INVALID_INPUT,              /* returned if MU scan parameter passed has an invalid value */
    MU_STATUS_FAIL_BB_WD_TRIGGER,         /* returned if hardware baseband hangs */
    MU_STATUS_FAIL_DEV_RESET,             /* returned if hardware hangs and driver needs to perform a reset to recover */
    MU_STATUS_FAIL_GPIO_TIMEOUT,          /* returned if GPIO trigger has timed out*/
} mu_status_t;

typedef enum {
    DEVICE_TYPE_AP,
    DEVICE_TYPE_STA,
    DEVICE_TYPE_SC_SAME_OPERATOR,
    DEVICE_TYPE_SC_DIFF_OPERATOR,
} mu_device_t;

typedef struct{
    /* specifying device type(AP/STA/SameOPClass/DiffOPClass)for each entry of the MU database*/
    mu_device_t mu_device_type;
    /* specifying BSSID of each entry */
    u_int8_t mu_device_bssid[IEEE80211_ADDR_LEN];
    /* Mac address of each entry */
    u_int8_t mu_device_macaddr[IEEE80211_ADDR_LEN];
    /* average packet duration for each device in micro secs to avoid decimals */
    u_int32_t mu_avg_duration;
    /* average rssi recorded for the device */
    u_int32_t mu_avg_rssi;
    /* percentage of medium utilized by the device */
    u_int32_t mu_percentage;
}mu_database;

struct event_data_mu_rpt {
    u_int8_t        mu_req_id;                                  /* MU request id, copied from the request */
    u_int8_t        mu_channel;                                 /* IEEE channel number on which MU was done */
    mu_status_t     mu_status;                                  /* whether the MU scan was successful or not */
    u_int32_t       mu_total_val[MU_MAX_ALGO-1];                /* the aggregate MU computed by the 3 algos */
    u_int32_t       mu_num_bssid;                               /* number of active BSSIDs */
    u_int32_t       mu_actual_duration;                         /* time in ms for which the MU scan was done */
    u_int32_t       mu_hidden_node_algo[LTEU_MAX_BINS];         /* The MU computed by the hidden node algo, reported on a per bin basis */
    u_int32_t       mu_num_ta_entries;                          /* number of active TA entries in the database */
    mu_database     mu_database_entries[MU_DATABASE_MAX_LEN];   /* the MU report for each TA */
};

typedef enum {
    SCAN_SUCCESS,
    SCAN_FAIL,
} scan_status_t;

struct event_data_scan {
    u_int8_t        scan_req_id;               /* AP scan request id, copied from the request */
    scan_status_t   scan_status;               /* whether the AP scan was successful or not */
};

#endif /* QCA_LTEU_SUPPORT */

#if QCA_AIRTIME_FAIRNESS
struct event_data_atf_config {
    u_int8_t     macaddr[IEEE80211_ADDR_LEN];
    int          config;
};
#endif

#endif /* _NET80211_IEEE80211_IOCTL_H_ */
