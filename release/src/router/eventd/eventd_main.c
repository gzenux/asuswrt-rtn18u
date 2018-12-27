/*
 * eventd deamon (Linux)
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */

#include <proto/ethernet.h>
#include <proto/bcmeth.h>
#include <proto/bcmevent.h>
#include <proto/802.11.h>

#include "eventd.h"

int eventd_debug_level = EVENTD_DEBUG_ERROR;

static void eventd_hexdump_ascii(const char *title, char *buf, int len)
{
	int i;
	if (!(eventd_debug_level & EVENTD_DEBUG_DETAIL))
		return;

	printf("%s[%d]:", title, len);
	for (i = 0; i < len; i++) {
		if ((i&0xf) == 0)
			printf("\n%04x: ", i);
		printf("%02X ", buf[i]);
	}
	printf("\n\n");
}

static void eventd_lm_report_parser(char *body, int len)
{
	dot11_lmrep_t *lmrep = (dot11_lmrep_t *)body;

	EVENTD_INFO("LM report: len=%d token=%d rxant=%d txant=%d tx_pwr=%d "
		"linkMargin=%d rcpi=%d rsni=%d\n",
		len, lmrep->token, lmrep->rxant, lmrep->txant,
		(int)(lmrep->tpc.tx_pwr), (int)(lmrep->tpc.margin),
		(int8)(lmrep->rcpi), (int8)(lmrep->rsni));
}

static void eventd_nbr_report_parser(char *body, int len)
{
	dot11_rm_action_t *rm_rep;
	bcm_tlv_t *tlvs;
	int tlv_len;
	dot11_neighbor_rep_ie_t *nbr_rep_ie;
	char tmp[32];

	rm_rep = (dot11_rm_action_t *)body;
	tlvs = (bcm_tlv_t *)&rm_rep->data[0];
	tlv_len = len - DOT11_RM_ACTION_LEN;

	EVENTD_INFO("Neighbor report: len=%d\n", len);

	while (tlvs && tlvs->id == DOT11_MNG_NEIGHBOR_REP_ID) {
		nbr_rep_ie = (dot11_neighbor_rep_ie_t *)tlvs;

		if (nbr_rep_ie->len < DOT11_NEIGHBOR_REP_IE_FIXED_LEN) {
			EVENTD_ERROR("malfomed Neighbor Report element with length %d\n",
				nbr_rep_ie->len);
			tlvs = bcm_next_tlv(tlvs, &tlv_len);
			continue;
		}
		EVENTD_INFO("bssid=%s bssinfo=0x%x reg %d: channel %d: phytype %d\n",
			ether_etoa(nbr_rep_ie->bssid.octet, tmp),
			ntoh32_ua(&nbr_rep_ie->bssid_info),
			nbr_rep_ie->reg, nbr_rep_ie->channel, nbr_rep_ie->phytype);

		tlvs = bcm_next_tlv(tlvs, &tlv_len);
	}
}

static void eventd_main_loop(int sock)
{
	struct timeval tv = {1, 0};    /* timed out every second */
	fd_set fdset;
	int status, fdmax;

	char tmp[32];
	char pkt[EVENTD_BUFSIZE_4K];
	int bytes, len;

	bcm_event_t *pvt_data;
	wl_rrm_event_t *evt;
	struct ether_header *eth_hdr = (struct ether_header *)(pkt + IFNAMSIZ);
	uint16 ether_type = 0;
	uint32 evt_type;

	dot11_rm_ie_t *ie;
	dot11_rmrep_chanload_t *rmrep_chload;
	dot11_rmrep_noise_t *rmrep_noise;
	dot11_rmrep_frame_t *rmrep_frame;
	dot11_rmrep_frmentry_t *frm_e;
	dot11_rmrep_bcn_t *rmrep_bcn;
	dot11_rmrep_stat_t *rmrep_stat;

	FD_ZERO(&fdset);
	fdmax = -1;

	if (sock >= 0) {
		FD_SET(sock, &fdset);
		if (sock > fdmax)
			fdmax = sock;
	}
	else {
		EVENTD_ERROR("Err: wrong socket\n");
		return;
	}

	status = select(fdmax+1, &fdset, NULL, NULL, &tv);
	if ((status > 0) && FD_ISSET(sock, &fdset)) {
		if ((bytes = recv(sock, pkt, EVENTD_BUFSIZE_4K, 0)) > IFNAMSIZ) {

			eventd_hexdump_ascii("REVD Raw", pkt, bytes);

			if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
				EVENTD_ERROR("recved ether type %x\n", ether_type);
				return;
			}


			pvt_data = (bcm_event_t *)(pkt + IFNAMSIZ);
			evt_type = ntoh32(pvt_data->event.event_type);

			EVENTD_INFO("Received event %d, MAC=%s\n",
				evt_type, ether_etoa(pvt_data->event.addr.octet, tmp));
			len = bytes - IFNAMSIZ - sizeof(*pvt_data);

			evt = (wl_rrm_event_t *)(pvt_data + 1);
			EVENTD_INFO("version:0x%02x len:0x%02x cat:0x%02x subversion:0x%02x\n",
				evt->version, evt->len, evt->cat, evt->subevent);
			eventd_hexdump_ascii("PVT_Data", (char *)(pvt_data + 1), len);

			if (evt->cat == DOT11_RM_ACTION_LM_REP) {
				EVENTD_INFO("Link Measurement report is received...\n");
				eventd_lm_report_parser((char *)(evt->payload), evt->len);
				return;
			}

			if (evt->cat == DOT11_RM_ACTION_NR_REP) {
				EVENTD_INFO("Neighbor report response is received...\n");
				eventd_nbr_report_parser((char *)(evt->payload), evt->len);
				return;
			}

			if (evt->cat != DOT11_RM_ACTION_RM_REP) {
				EVENTD_ERROR("Not RM, LM and NR report: cat[0x%02x]...\n",
					evt->cat);
				return;
			}

			/* measurement payload. Format is defined in Fig.8-439 of 802.11 Spec */
			eventd_hexdump_ascii("Payload", (char *)(evt->payload), evt->len);

			switch (evt->subevent) {
				case DOT11_MEASURE_TYPE_CHLOAD:
					EVENTD_INFO("DOT11_MEASURE_TYPE_CHLOAD\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_chload = (dot11_rmrep_chanload_t *)&ie[1];
					EVENTD_INFO("%s: regulatory: %d, channel: %d, "
						"duration: %d, chan load: %d\n",
						__FUNCTION__, rmrep_chload->reg,
						rmrep_chload->channel,
						rmrep_chload->duration,
						rmrep_chload->channel_load);
					break;
				case DOT11_MEASURE_TYPE_NOISE:
					EVENTD_INFO("DOT11_MEASURE_TYPE_NOISE\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_noise = (dot11_rmrep_noise_t *)&ie[1];
					EVENTD_INFO("%s: regulatory: %d, channel: %d, "
						"duration: %d, antid: 0x%x, anpi: %d\n",
						__FUNCTION__, rmrep_noise->reg,
						rmrep_noise->channel,
						rmrep_noise->duration,
						rmrep_noise->antid, (int8)rmrep_noise->anpi);
					EVENTD_INFO("IPI Level: [0] %d; [1] %d; [2] %d; "
						"[3] %d; [4] %d; [5] %d; [6] %d; "
						"[7] %d; [8] %d; [9] %d; [10] %d\n",
						rmrep_noise->ipi0_dens, rmrep_noise->ipi1_dens,
						rmrep_noise->ipi2_dens, rmrep_noise->ipi3_dens,
						rmrep_noise->ipi4_dens, rmrep_noise->ipi5_dens,
						rmrep_noise->ipi6_dens, rmrep_noise->ipi7_dens,
						rmrep_noise->ipi8_dens,	rmrep_noise->ipi9_dens,
						rmrep_noise->ipi10_dens);
					break;
				case DOT11_MEASURE_TYPE_FRAME:
					EVENTD_INFO("DOT11_MEASURE_TYPE_FRAME\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_frame = (dot11_rmrep_frame_t *)&ie[1];
					frm_e = (dot11_rmrep_frmentry_t *)
						((uint8 *)&rmrep_frame[1] + 2);
					EVENTD_INFO("%s: phy_type: %d, avg_rcpi: %d, "
						"last_rsni: %d, last_rcpi: %d, "
						"ant_id: %d, frame_cnt: %d\n",
						__FUNCTION__, frm_e->phy_type,
						(int8)frm_e->avg_rcpi, (int8)frm_e->last_rsni,
						(int8)frm_e->last_rcpi, frm_e->ant_id,
						frm_e->frame_cnt);
					break;
				case DOT11_MEASURE_TYPE_BASIC:
					break;
				case DOT11_MEASURE_TYPE_CCA:
					break;
				case DOT11_MEASURE_TYPE_RPI:
					break;
				case DOT11_MEASURE_TYPE_BEACON:
					EVENTD_INFO("DOT11_MEASURE_TYPE_BEACON\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_bcn = (dot11_rmrep_bcn_t *)&ie[1];

					EVENTD_INFO("%s: channel: %d, duration: %d, "
						"frame info: %d, rcpi: %d, rsni: %d, bssid: %s, "
						"antenna id: %d, parent tsf: %u\n",
						__FUNCTION__, rmrep_bcn->channel,
						rmrep_bcn->duration, rmrep_bcn->frame_info,
						(int8)rmrep_bcn->rcpi, (int8)rmrep_bcn->rsni,
						ether_etoa((uchar *)&rmrep_bcn->bssid, tmp),
						rmrep_bcn->antenna_id, rmrep_bcn->parent_tsf);
					break;
				case DOT11_MEASURE_TYPE_STAT:
					EVENTD_INFO("DOT11_MEASURE_TYPE_STAT\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_stat = (dot11_rmrep_stat_t *)&ie[1];
					EVENTD_INFO("%s: duration: %d, group_id: %d\n",
						__FUNCTION__, rmrep_stat->duration,
						rmrep_stat->group_id);
					switch (rmrep_stat->group_id) {
					case DOT11_RRM_STATS_GRP_ID_0:
						{
						rrm_stat_group_0_t *data0;
						data0 = (rrm_stat_group_0_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-0: txmulti: %d, txfail: %d, "
							"rxframe: %d, rxmulti: %d, txframe: %d\n",
							data0->txmulti, data0->txfail,
							data0->rxframe, data0->rxmulti,
							data0->txframe);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_1:
						{
						rrm_stat_group_1_t *data1;
						data1 = (rrm_stat_group_1_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-1: txretry: %d, txretries: %d, "
							"rxdup: %d, txrts: %d, ackfail: %d\n",
							data1->txretry, data1->txretries,
							data1->rxdup, data1->txrts,
							data1->ackfail);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_2:
					case DOT11_RRM_STATS_GRP_ID_3:
					case DOT11_RRM_STATS_GRP_ID_4:
					case DOT11_RRM_STATS_GRP_ID_5:
					case DOT11_RRM_STATS_GRP_ID_6:
					case DOT11_RRM_STATS_GRP_ID_7:
					case DOT11_RRM_STATS_GRP_ID_8:
					case DOT11_RRM_STATS_GRP_ID_9:
						{
						rrm_stat_group_qos_t *dataqos;
						dataqos = (rrm_stat_group_qos_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-%d (tid: %d): txframe: %d, "
							"txdrop: %d, rxmpdu: %d, rxretries: %d\n",
							rmrep_stat->group_id,
							rmrep_stat->group_id - 2,
							dataqos->txframe, dataqos->txdrop,
							dataqos->rxmpdu, dataqos->rxretries);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_10:
						{
						rrm_stat_group_10_t *data10;
						data10 = (rrm_stat_group_10_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-10: avgdelaybe: %d, "
							"avgdelaybg: %d, avgdelayvi: %d, "
							"avgdelayvo: %d, stacount: %d, "
							"chanutil: %d\n",
							data10->avgdelaybe, data10->avgdelaybg,
							data10->avgdelayvi,	data10->avgdelayvo,
							data10->stacount, data10->chanutil);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_11:
						{
						rrm_stat_group_11_t *data11;
						data11 = (rrm_stat_group_11_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-11: txamsdu: %d, "
							"amsdufail: %d, amsduretry: %d, "
							"amsduretries: %d, amsduackfail: %d, "
							"rxamsdu: %d\n",
							data11->txamsdu, data11->amsdufail,
							data11->amsduretry, data11->amsduretries,
							data11->amsduackfail, data11->rxamsdu);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_12:
						{
						rrm_stat_group_12_t *data12;
						data12 = (rrm_stat_group_12_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-12: txampdu: %d, "
							"txmpdu: %d, rxampdu: %d, "
							"rxmpdu: %d, ampducrcfail: %d\n",
							data12->txampdu, data12->txmpdu,
							data12->rxampdu, data12->rxmpdu,
							data12->ampducrcfail);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_13:
						{
						rrm_stat_group_13_t *data13;
						data13 = (rrm_stat_group_13_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-13: chanwidthsw: %d, "
							"txframe20mhz: %d, txframe40mhz: %d, "
							"rxframe20mhz: %d, rxframe40mhz: %d\n",
							data13->chanwidthsw, data13->txframe20mhz,
							data13->txframe40mhz, data13->rxframe20mhz,
							data13->rxframe40mhz);
						}
						break;
					case DOT11_RRM_STATS_GRP_ID_16:
						{
						rrm_stat_group_16_t *data16;
						data16 = (rrm_stat_group_16_t *)&rmrep_stat[1];
						EVENTD_INFO("GROUP-16: mgmtccmpreplay: %d, "
							"tkipicverr: %d, tkipicvreplay: %d, "
							"cmpdecrypterr: %d, ccmpreplay: %d\n",
							data16->rsnarobustmgmtccmpreplay,
							data16->rsnatkipicverr,
							data16->rsnatkipicvreplay,
							data16->rsnaccmpdecrypterr,
							data16->rsnaccmpreplay);
						}
						break;
					default:
						EVENTD_ERROR("unhandled stats group ID: %d\n",
						rmrep_stat->group_id);
						break;
					}
					break;
				case DOT11_MEASURE_TYPE_LCI:
					break;
				case DOT11_MEASURE_TYPE_TXSTREAM:
					break;
				default:
					EVENTD_ERROR("unhandled subtype: 0x%2X\n", evt->subevent);
					break;
			}
		}
	}

	return;
}


static int eventd_eapd_socket_init(void)
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int event_socket = -1;

	/* open loopback socket to communicate with EAPD */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_EVENTD_UDP_SPORT);

	if ((event_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		EVENTD_ERROR("Unable to create loopback socket\n");
		return -1;
	}

	if (setsockopt(event_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		EVENTD_ERROR("Unable to setsockopt to loopback socket %d.\n", event_socket);
		goto exit1;
	}

	if (bind(event_socket, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		EVENTD_ERROR("Unable to bind to loopback socket %d\n", event_socket);
		goto exit1;
	}

	EVENTD_INFO("opened loopback socket %d\n", event_socket);
	return event_socket;

	/* error handling */
exit1:
	close(event_socket);
	return -1;
}

int
main(int argc, char **argv)
{
	int sock;
	char *dbg;

	/* get eapd_msg_level from nvram */
	if ((dbg = nvram_get("eventd_msglevel"))) {
		eventd_debug_level = (uint)strtoul(dbg, NULL, 0);
	}


	/* UDP socket to eapd init */
	if ((sock = eventd_eapd_socket_init()) < 0) {
		EVENTD_ERROR("Err: fail to init socket\n");
		return sock;
	}


	/* receive wl event from event-eap via UDP */
	while (1) {
		eventd_main_loop(sock);
	}

	close(sock);
	return 0;
}
