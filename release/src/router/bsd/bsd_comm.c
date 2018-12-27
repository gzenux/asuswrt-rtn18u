/*
 * bsd deamon (Linux)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bsd_main.c $
 */
#include "bsd.h"

/* open a UDP packet to event dispatcher for receiving/sending data */
int bsd_open_eventfd(bsd_info_t*info)
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int fd = BSD_DFLT_FD;

	BSD_ENTER();
	/* open loopback socket to communicate with event dispatcher */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_BSD_UDP_SPORT);

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		BSD_ERROR("Unable to create loopback socket\n");
		goto error;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		BSD_ERROR("Unable to setsockopt to loopback socket %d.\n", fd);
		goto error;
	}

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		BSD_ERROR("Unable to bind to loopback socket %d\n", fd);
		goto error;
	}

	BSD_INFO("opened loopback socket %d\n", fd);
	info->event_fd = fd;

	BSD_EXIT();
	return BSD_OK;

	/* error handling */
error:
	if (fd != BSD_DFLT_FD)
		close(fd);
	BSD_EXIT();
	return BSD_FAIL;
}

/* open TCP socket to receive rpc event */
int bsd_open_rpc_eventfd(bsd_info_t*info)
{
	int reuse = 1;
	int	listenfd = BSD_DFLT_FD;
	struct sockaddr_in	sockaddr;

	BSD_ENTER();

	if ((info->role != BSD_ROLE_PRIMARY) &&
		(info->role != BSD_ROLE_HELPER)) {
		BSD_INFO("no rpc socket created for standalone mode\n");
		goto done;
	}

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		BSD_ERROR("Unable to create rpc listen socket\n");
		goto error;
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		BSD_ERROR("Unable to setsockopt to rpc listen socket %d.\n", listenfd);
		goto error;
	}

	bzero(&sockaddr, sizeof(sockaddr));
	sockaddr.sin_family      = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	switch (info->role) {
		case BSD_ROLE_PRIMARY:
			sockaddr.sin_port = htons(info->pport);
			break;
		case BSD_ROLE_HELPER:
			sockaddr.sin_port = htons(info->hport);
			break;
		default:
			BSD_INFO("no rpc socket created\n");
			break;
	}

	if (bind(listenfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
		BSD_ERROR("Unable to bind socket %d.\n", listenfd);
		goto error;
	}

	if (listen(listenfd, 2) < 0) {
		BSD_ERROR("listen() fails.\n");
		goto error;
	}
	info->rpc_listenfd = listenfd;

done:
	BSD_EXIT();
	return BSD_OK;

error:
	if (listenfd != BSD_DFLT_FD)
		close(listenfd);
	BSD_EXIT();
	return BSD_FAIL;
}


void bsd_close_rpc_eventfd(bsd_info_t*info)
{
	BSD_ENTER();
	if (info->rpc_listenfd != BSD_DFLT_FD) {
		BSD_INFO("close rpc_listenfd %d\n", info->rpc_listenfd);
		close(info->rpc_listenfd);
		info->rpc_listenfd = BSD_DFLT_FD;
	}
	if (info->rpc_eventfd != BSD_DFLT_FD) {
		BSD_INFO("close rpc_eventfd %d\n", info->rpc_eventfd);
		close(info->rpc_eventfd);
		info->rpc_eventfd = BSD_DFLT_FD;
	}
	if (info->rpc_ioctlfd != BSD_DFLT_FD) {
		BSD_INFO("close rpc_ioctlfd %d\n", info->rpc_ioctlfd);
		close(info->rpc_ioctlfd);
		info->rpc_ioctlfd = BSD_DFLT_FD;
	}
	BSD_EXIT();
	return;
}

void bsd_close_eventfd(bsd_info_t*info)
{
	BSD_ENTER();
	/* close event dispatcher socket */
	if (info->event_fd != BSD_DFLT_FD) {
		BSD_INFO("close loopback event_fd %d\n", info->event_fd);
		close(info->event_fd);
		info->event_fd = BSD_DFLT_FD;
	}
	BSD_EXIT();
	return;
}


/* Msg dispatch */
static int bsd_validate_message(int bytes, uint8 *dpkt)
{
	bcm_event_t *pvt_data;

	BSD_EVTENTER();
	/* the message should be at least the header to even look at it */
	if (bytes < sizeof(bcm_event_t) + 2) {
		BSD_ERROR("Invalid length of message\n");
		return BSD_FAIL;
	}
	pvt_data  = (bcm_event_t *)dpkt;
	if (ntohs(pvt_data->bcm_hdr.subtype) != BCMILCP_SUBTYPE_VENDOR_LONG) {
		BSD_ERROR("%s: not vendor specifictype\n",
		       pvt_data->event.ifname);
		return BSD_FAIL;
	}
	if (pvt_data->bcm_hdr.version != BCMILCP_BCM_SUBTYPEHDR_VERSION) {
		BSD_ERROR("%s: subtype header version mismatch\n",
			pvt_data->event.ifname);
		return BSD_FAIL;
	}
	if (ntohs(pvt_data->bcm_hdr.length) < BCMILCP_BCM_SUBTYPEHDR_MINLENGTH) {
		BSD_ERROR("%s: subtype hdr length not even minimum\n",
			pvt_data->event.ifname);
		return BSD_FAIL;
	}
	if (bcmp(&pvt_data->bcm_hdr.oui[0], BRCM_OUI, DOT11_OUI_LEN) != 0) {
		BSD_ERROR("%s: bsd_validate_wlpvt_message: not BRCM OUI\n",
			pvt_data->event.ifname);
		return BSD_FAIL;
	}
	/* check for wl dcs message types */
	switch (ntohs(pvt_data->bcm_hdr.usr_subtype)) {
		case BCMILCP_BCM_SUBTYPE_EVENT:
			BSD_EVENT("subtype: event\n");
			break;
		default:
			return BSD_FAIL;
	}
	BSD_EVTEXIT();
	return BSD_OK; /* good packet may be this is destined to us */
}

static int bsd_proc_event(bsd_info_t*info, uint8 remote, char *pkt, int bytes)
{
	bcm_event_t *pvt_data;
	unsigned char *addr;
	char *ifname;
	struct ether_header *eth_hdr;
	uint16 ether_type;
	uint32 evt_type;
	int err;
	wl_psta_primary_intf_event_t *event;

	BSD_EVTENTER();

	ifname = (char *)pkt;
	eth_hdr = (struct ether_header *)(ifname + IFNAMSIZ);

	BSD_EVENT("recved %d bytes from eventfd, ifname: %s\n",	bytes, ifname);

	if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
		BSD_EVENT("recved ether type %x\n", ether_type);
		return BSD_FAIL;
	}

	if ((err = bsd_validate_message(bytes - IFNAMSIZ, (uint8 *)eth_hdr))) {
		BSD_EVENT("Err msg\n");
		return BSD_FAIL;
	}

	pvt_data = (bcm_event_t *)(ifname + IFNAMSIZ);
	evt_type = ntoh32(pvt_data->event.event_type);

	addr = (unsigned char *)(&(pvt_data->event.addr));

	if ((evt_type != WLC_E_PROBREQ_MSG) ||
		((evt_type == WLC_E_PROBREQ_MSG) && BSD_PROB_ENAB)) {
		/* too many probe. only handle proble for dump level */
		BSD_EVENT("Evttype:%d info:%s Mac:"MACF"bsscfgidx=0x%x ifidx=0x%x\n",
			evt_type, ifname, ETHERP_TO_MACF(addr),
			pvt_data->event.bsscfgidx, pvt_data->event.ifidx);
	}


	switch (evt_type) {
		case WLC_E_DEAUTH:
		case WLC_E_DEAUTH_IND:
			BSD_EVENT("Deauth_ind\n");
			bsd_deauth_sta(info, ifname, remote, (struct ether_addr *)addr);
			break;
		case WLC_E_DISASSOC_IND:
			/* update sta info list */
			BSD_EVENT("Disassoc\n");
			bsd_disassoc_sta(info, ifname,  remote, (struct ether_addr *)addr);
			break;
		case WLC_E_AUTH_IND:
			BSD_EVENT("WLC_E_AUTH_IND\n");
			bsd_auth_sta(info, ifname,  remote, (struct ether_addr *)addr);
			break;
		case WLC_E_REASSOC_IND:
			BSD_EVENT("ReAssoc\n");
			bsd_assoc_sta(info, ifname,  remote, (struct ether_addr *)addr);
			break;
		case WLC_E_ASSOC_IND:
			BSD_EVENT("Assoc\n");
			bsd_assoc_sta(info, ifname,  remote, (struct ether_addr *)addr);
			break;

		case WLC_E_PSTA_PRIMARY_INTF_IND:
			event = (wl_psta_primary_intf_event_t *)(pvt_data + 1);

			BSD_EVENT("p-Mac:"MACF"\n", ETHER_TO_MACF(event->prim_ea));

			bsd_update_psta(info, ifname,  remote, (struct ether_addr *)addr,
				(struct ether_addr *)(&event->prim_ea));

			if (BSD_DUMP_ENAB)
				bsd_dump_info(info);
			break;

		case WLC_E_PROBREQ_MSG:
			BSD_EVENT("Probe-req...\n");
			bsd_add_prbsta(info, ifname,  remote, (struct ether_addr *)addr);
			break;

		default:
			BSD_INFO("recved event type: 0x%x\n", evt_type);
			break;
	}

	BSD_EVTEXIT();
	return BSD_OK; /* good packet may be this is destined to us */
}

static int bsd_helper_proc_rpc(bsd_info_t*info)
{
	bsd_rpc_pkt_t *pkt = (bsd_rpc_pkt_t *)ret_buf;
	char *ptr;
	int bytes;

	char name[128], val[128];
	int size, resp_len;
	int status = BSD_OK, ret;

	BSD_ENTER();

	memset(ret_buf, 0, sizeof(ret_buf));
	if ((bytes = read(info->rpc_ioctlfd, ret_buf, sizeof(ret_buf))) <= 0) {
		BSD_RPCD("Err: Socket: Recv rpc ioctl. close rpc_ioctlfd[%d]"
			", bytes:%d. errno=%d\n", info->rpc_ioctlfd, bytes, errno);
		close(info->rpc_ioctlfd);
		info->rpc_ioctlfd = BSD_DFLT_FD;

		BSD_RPCD("Err: Socket: Also close Event[%d] socket.\n",
			info->rpc_eventfd);
		close(info->rpc_eventfd);
		info->rpc_eventfd = BSD_DFLT_FD;
		status = BSD_FAIL;
		goto done;
	}

	BSD_RPCD("\n\nRecv ioctl rpc_ioctlfd[%d]: bytes:%d"
		"(sizeof(ret_buf)=%d) id:%d \n",
		info->rpc_ioctlfd, bytes, sizeof(ret_buf), pkt->id);
	BSD_RPC("raw Rcv buff[sock:%d]: cmd:%d name:%s len:%d\n",
		info->rpc_ioctlfd, pkt->cmd.cmd, pkt->cmd.name, pkt->cmd.len);
	bsd_rpc_dump((char *)pkt, 64, BSD_RPC_ENAB);

	if (pkt->cmd.name[0] == '\0') {
		BSD_ERROR("null intf name skipped\n");
		status = BSD_FAIL;
		goto done;
	}

	switch (pkt->id) {
		case BSD_RPC_ID_NVRAM:
		{
			BSDSTRNCPY(name, (char *)(pkt+1), sizeof(name));
			BSDSTRNCPY(val, nvram_safe_get(name), sizeof(val) - 1);

			BSD_RPCD("nvram:%s=%s\n", name, val);

			strcpy((char *)(pkt + 1), val);
			pkt->cmd.len = strlen(val) + 4;
			resp_len = sizeof(ret_buf);

			size = write(info->rpc_ioctlfd, (void *)pkt, resp_len);
			BSD_RPC("nvram writing: size=%d sent:%d\n",
				resp_len, size);

			if (size != resp_len) {
				BSD_RPCD("Err: Socket: sending[%d] Sent[%d] "
					"close rpc_ioctlfd[%d]\n",
					resp_len, size, info->rpc_ioctlfd);
				status = BSD_FAIL;
				/*
				close(info->rpc_ioctlfd);
				info->rpc_ioctlfd = BSD_DFLT_FD;
				*/
			}
			break;
		}
		case BSD_RPC_ID_IOCTL:
		{
			BSD_RPCD("BSD_RPC_ID_IOCTL: id:%d name:%s cmd:%d len:%d"
				" bytes:%d (sizeof(ret_buf))=%d \n",
				pkt->id, pkt->cmd.name, pkt->cmd.cmd, pkt->cmd.len,
				bytes, sizeof(ret_buf));
			ptr = (char *)(pkt+1);

			BSD_RPC("raw Rcv ioctl buff:\n");
			bsd_rpc_dump(ptr, 64, BSD_RPC_ENAB);

			ret = wl_ioctl(pkt->cmd.name, pkt->cmd.cmd,
				ptr, pkt->cmd.len);
			BSD_RPCD("ret=%d\n", ret);
			if (ret < 0) {
				BSD_ERROR("wl_ioctl fails: cmd:%d name:%s len:%d\n",
					pkt->cmd.cmd, pkt->cmd.name, pkt->cmd.len);
				status = BSD_FAIL;
				break;
			}

			BSD_RPC("raw Send buff[sock:%d: cmd:%d name:%s len:%d\n",
				info->rpc_ioctlfd, pkt->cmd.cmd,
				pkt->cmd.name, pkt->cmd.len);
			bsd_rpc_dump((char *)pkt, 64, BSD_RPC_ENAB);

			pkt->cmd.ret = ret;
			resp_len = bytes;

			size = write(info->rpc_ioctlfd, (void *)pkt,
				sizeof(ret_buf));
			BSD_RPC("ioctl writing: size=%d, sent:%d\n",
				sizeof(ret_buf), size);

			if (size != sizeof(ret_buf)) {
				BSD_RPCD("Err: Socket: sending[%d] Sent[%d]"
					" close rpc_ioctlfd[%d]\n",
					resp_len, size, info->rpc_ioctlfd);
				status = BSD_FAIL;
				/*
				close(info->rpc_ioctlfd);
				info->rpc_ioctlfd = BSD_DFLT_FD;
				*/
			}
			break;
		}
		default:
			BSD_ERROR("Wrong cmd id. Ignose\n");
			break;
	}

done:
	BSD_EXIT();
	return status;
}

/* coverity[ -tainted_string_sanitize_content : arg-1 ]  */
static int bsd_helper_proc_event(bsd_info_t*info, char *pkt, int bytes)
{
	bcm_event_t *pvt_data;
	unsigned char *addr;
	char *ifname;
	struct ether_header *eth_hdr;
	uint16 ether_type = 0;
	uint32 evt_type;
	int err;

	int	sockfd = BSD_DFLT_FD;
	struct sockaddr_in	servaddr;
	int size;
	int status = BSD_OK;

	BSD_EVTENTER();

	ifname = (char *)pkt;
	eth_hdr = (struct ether_header *)(ifname + IFNAMSIZ);

	BSD_EVENT("recved %d bytes from eventfd, ifname: %s\n",	bytes, ifname);
	BSD_EVENT("[1]time=%lu\n", (unsigned long)time(NULL));

	if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
		BSD_EVENT("recved ether type %x\n", ether_type);
		status = BSD_FAIL;
		goto done;
	}

	if ((err = bsd_validate_message(bytes - IFNAMSIZ, (uint8 *)eth_hdr))) {
		BSD_EVENT("Err msg\n");
		status = BSD_FAIL;
		goto done;
	}

	pvt_data = (bcm_event_t *)(ifname + IFNAMSIZ);
	evt_type = ntoh32(pvt_data->event.event_type);

	addr = (unsigned char *)(&(pvt_data->event.addr));

	if ((evt_type != WLC_E_PROBREQ_MSG) ||
		((evt_type == WLC_E_PROBREQ_MSG) && BSD_PROB_ENAB)) {
		/* too many probe. only handle proble for dump level */
		BSD_EVENT("Evt:%d ifname:%s Mac:"MACF" bsscfgidx:0x%x "
			"ifidx:0x%x\n",
			evt_type, ifname, ETHERP_TO_MACF(addr),
			pvt_data->event.bsscfgidx, pvt_data->event.ifidx);
	}


	BSD_RPCEVT("Forward event to %s[%d]\n", info->primary_addr, info->pport);

	BSD_RPCEVT("Raw Event[sock:%d] [ifname:%s]\n",
		info->rpc_eventfd, (char *)pkt);
	bsd_rpc_dump((char *)pkt, 64, BSD_RPCEVT_ENAB);

	if (info->rpc_eventfd < 0) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		BSD_RPCEVT("Create sock to forward event%d\n", sockfd);
		if (sockfd < 0) {
			BSD_ERROR("Err: open socket=%d\n", sockfd);
			status = BSD_FAIL;
			goto done;
		}

		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(info->pport);

		servaddr.sin_addr.s_addr = inet_addr(info->primary_addr);
		if (connect(sockfd, (const struct sockaddr *)&servaddr,
			sizeof(servaddr)) < 0) {
			BSD_ERROR("Err: Cannot connect to Primary: %s[%d]\n",
				info->primary_addr, info->pport);
			status = BSD_FAIL;
			if (info->rpc_eventfd != BSD_DFLT_FD) {
				close(info->rpc_eventfd);
				info->rpc_eventfd = BSD_DFLT_FD;
			}
			if (sockfd !=  BSD_DFLT_FD) {
				close(sockfd);
			}
			goto done;
		}

		info->rpc_eventfd = sockfd;
	}

	if (info->rpc_eventfd > 0) {
		BSD_RPCEVT("RPCEVENT[%s] : Writing:[%d]\n",
			(char *)pkt, bytes);
		size = write(info->rpc_eventfd, pkt, bytes);
		BSD_RPCEVT("RPCEVENT[%s] : Wrote:[%d]\n", (char *)pkt, size);

		if (size != bytes) {
			BSD_RPCEVT("Err: Socket: close rpc_eventfd[%d]: writing:%d"
				"Wrote:%d Close to reopen\n",
				info->rpc_eventfd, bytes, size);
			if (info->rpc_eventfd != BSD_DFLT_FD) {
				close(info->rpc_eventfd);
				info->rpc_eventfd = BSD_DFLT_FD;
			}
			status = BSD_FAIL;
		}
	}

	BSD_RPCEVT("[2]time=%lu\n", (unsigned long)time(NULL));

done:
	BSD_EVTEXIT();
	return status;
}

/* listen to sockets and call handlers to process packets */
void bsd_proc_socket(bsd_info_t*info, struct timeval *tv)
{
	fd_set fdset;
	int fdmax;
	int width, status = 0, bytes;
	uint8 pkt[BSD_BUFSIZE_4K];

	BSD_ENTER();

	/* init file descriptor set */
	FD_ZERO(&fdset);
	fdmax = -1;

	/* build file descriptor set now to save time later */
	if (info->event_fd != BSD_DFLT_FD) {
		FD_SET(info->event_fd, &fdset);
		fdmax = info->event_fd;
	}

	/* build file descriptor set now to save time later */
	if (info->rpc_listenfd != BSD_DFLT_FD) {
		FD_SET(info->rpc_listenfd, &fdset);
		if (fdmax < info->rpc_listenfd)
			fdmax = info->rpc_listenfd;
	}


	if (info->role == BSD_ROLE_PRIMARY) {
		/* build file descriptor set now to save time later */
		if (info->rpc_eventfd != BSD_DFLT_FD) {
			FD_SET(info->rpc_eventfd, &fdset);
			if (fdmax < info->rpc_eventfd)
				fdmax = info->rpc_eventfd;
		}
	}

	if (info->role == BSD_ROLE_HELPER) {
		/* build file descriptor set now to save time later */
		if (info->rpc_ioctlfd != BSD_DFLT_FD) {
			FD_SET(info->rpc_ioctlfd, &fdset);
			if (fdmax < info->rpc_ioctlfd)
				fdmax = info->rpc_ioctlfd;
		}
	}

	width = fdmax + 1;

	/* listen to data availible on all sockets */
	status = select(width, &fdset, NULL, NULL, tv);

	if ((status == -1 && errno == EINTR) || (status == 0)) {
		BSD_EVENT("No event\n");
		goto done;
	}

	if (status <= 0) {
		BSD_ERROR("err from select: %s", strerror(errno));
		goto done;
	}


		/* handle rpc brcm event */
	if (info->rpc_listenfd !=  BSD_DFLT_FD && FD_ISSET(info->rpc_listenfd, &fdset)) {
		int	 connfd = -1;
		socklen_t			clilen;
		struct sockaddr_in	cliaddr;
		struct timeval ltv;

		clilen = sizeof(cliaddr);
		connfd = accept(info->rpc_listenfd, (struct sockaddr *)&cliaddr, &clilen);
		if (connfd < 0) {
			BSD_ERROR("Err: accept error[%d]\n", connfd);
			goto done;
		}
		ltv.tv_sec = 5;
		ltv.tv_usec = 0;
		if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&ltv,
			sizeof(struct timeval)) < 0) {
			close(connfd);
			BSD_ERROR("Err: setsockopt error[%d]\n", connfd);
			goto done;
		}

		BSD_RPCD("New rpc from addr:%s, port:%d connfd:%d\n",
			inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), connfd);

		switch (info->role) {
			case BSD_ROLE_PRIMARY:
				BSD_RPCD("Err: Socket: close pervious rpc_event_fd:%d\n",
					info->rpc_eventfd);
				if (info->rpc_eventfd !=  BSD_DFLT_FD)
					close(info->rpc_eventfd);

				info->rpc_eventfd = connfd;
				break;
			case BSD_ROLE_HELPER:
				BSD_RPCD("Err: Socket: close pervious rpc_ioctlfd:%d\n",
					info->rpc_ioctlfd);
				if (info->rpc_ioctlfd !=  BSD_DFLT_FD)
					close(info->rpc_ioctlfd);

				info->rpc_ioctlfd = connfd;
				break;
			default:
				BSD_ERROR("Err: Error role:%d\n", info->role);
				break;
		}
	}

	if (info->role == BSD_ROLE_HELPER) {
		if (info->rpc_ioctlfd !=  BSD_DFLT_FD && FD_ISSET(info->rpc_ioctlfd, &fdset)) {
			bsd_helper_proc_rpc(info);
		}
	}

	if (info->role == BSD_ROLE_PRIMARY &&
		(info->rpc_eventfd !=  BSD_DFLT_FD) && FD_ISSET(info->rpc_eventfd, &fdset)) {
		bsd_rpc_pkt_t *rpc_pkt = (bsd_rpc_pkt_t *)ret_buf;
		memset(ret_buf, 0, sizeof(ret_buf));
		bytes = read(info->rpc_eventfd, ret_buf, sizeof(ret_buf));

		if (bytes <= 0) {
			BSD_RPCD("Err: Socket: Recv rpc event. rpc_eventfd[%d]"
				" bytes=%d errno=%d\n",
				info->rpc_eventfd, bytes, errno);
			close(info->rpc_eventfd);
			info->rpc_eventfd = BSD_DFLT_FD;
			goto done;
		}
		else {
			BSD_RPCEVT("Recv rpc event: %d [%s]\n", bytes, (char *)rpc_pkt);

			/*
				if(rpc_pkt.id != BSD_RPC_ID_EVENT) {
					return;
				}
			*/
			bsd_proc_event(info, 1, (char *)rpc_pkt, bytes);
			BSD_RPCEVT("Done rpc event\n");
		}
	}

	/* handle brcm event */
	if (info->event_fd !=  BSD_DFLT_FD && FD_ISSET(info->event_fd, &fdset)) {

		memset(pkt, 0, sizeof(pkt));
		if ((bytes = recv(info->event_fd, pkt, sizeof(pkt), 0)) <= 0) {
			goto done;
		}

		BSD_EVENT("Recv Local event: %d\n", bytes);

		if ((info->role == BSD_ROLE_PRIMARY) || (info->role == BSD_ROLE_STANDALONE)) {
			bsd_proc_event(info, 0, (char *)pkt, bytes);
		}

		if (info->role == BSD_ROLE_HELPER) {
			 bsd_helper_proc_event(info, (char *)pkt, bytes);
		}

		BSD_EVENT("Done Local Event\n");
	}

done:
	BSD_EXIT();
}
