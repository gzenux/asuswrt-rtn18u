/*
 *  Copyright (c) 2010 Atheros Communications Inc.
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
 * Copyright (c) 2012, 2015 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include "mcnl.h"

/* Use this internal structure for caching table entry size and commands */
typedef struct {
	size_t size;
	u_int32_t get_command;
	u_int32_t set_command;
	u_int32_t netlink_key;

} bridgeTableParams_t;

static const bridgeTableParams_t tableParams[] = {
	{sizeof(struct __mc_mdb_entry), MC_MSG_GET_MDB, ~0, NETLINK_QCA_MC},
	{sizeof(struct __mc_param_acl_rule), MC_MSG_GET_ACL, ~0, NETLINK_QCA_MC},
	{sizeof(struct __mc_encaptbl_entry), ~0, MC_MSG_SET_PSW_ENCAP, NETLINK_QCA_MC},
	{sizeof(struct __mc_floodtbl_entry), ~0, MC_MSG_SET_PSW_FLOOD, NETLINK_QCA_MC},
};

/* print debug information */
const char *mcctl_status_debug[] = {
	"MC_STATUS_SUCCESS",
	"MC_STATUS_NOT_SUPPORTED",
	"MC_STATUS_RESOURCES",
	"MC_STATUS_INVALID_PARAMETER",
	"MC_STATUS_BUFFER_OVERFLOW",
	"MC_STATUS_FAILURE",
	"MC_STATUS_NOT_FOUND"
};

//#define DEBUG_MC_NETLINK

/*-F- netlink_msg --
 */
int32_t netlink_msg(int32_t msg_type, u_int8_t *data, int32_t msgdatalen, int32_t netlink_key,
	int sync)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	socklen_t fromlen;
	int32_t ret = MC_STATUS_FAILURE;
	int32_t sock_fd;
	struct __mcctl_msg_header *msgheader;
	static pid_t myPid = 0;

	/* Do it only once per context, save a system call */
	if (!myPid)
		myPid = getpid();

	do {
		sock_fd = socket(AF_NETLINK, SOCK_RAW, netlink_key);
		if (sock_fd <= 0) {
#ifdef DEBUG_MC_NETLINK
			printf("netlink socket create failed\n");
#endif
			break;
		}

		/* Set nonblock. */
		if (fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL) | O_NONBLOCK)) {
#ifdef DEBUG_MC_NETLINK
			perror("fcntl():");
#endif
			break;
		}

		fromlen = sizeof(src_addr);
		memset(&src_addr, 0, sizeof(src_addr));
		src_addr.nl_family = AF_NETLINK;
		src_addr.nl_pid = myPid;	/* self pid */
		src_addr.nl_groups = 0;	/* not in mcast groups */

		bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;
		dest_addr.nl_pid = 0;	/* For Linux Kernel */
		dest_addr.nl_groups = 0;	/* unicast */
		nlh = (struct nlmsghdr *)data;
		/* Fill the netlink message header */
		nlh->nlmsg_type = msg_type;
		nlh->nlmsg_len = NLMSG_SPACE(MC_MSG_HDRLEN + msgdatalen);
		nlh->nlmsg_pid = myPid;	/* self pid */
		nlh->nlmsg_flags = 0;

		if (sendto(sock_fd,
				(void *)nlh,
				nlh->nlmsg_len,
				0,
				(struct sockaddr *)&dest_addr, sizeof(struct sockaddr_nl)) <= 0) {
#ifdef DEBUG_MC_NETLINK
			printf("netlink socket send failed\n");
#endif
			break;
		}

		if (!sync) {
			ret = MC_STATUS_SUCCESS;
			break;
		}

		struct pollfd pollfd = {
			sock_fd,
			POLLIN,
			0
		};

		if (poll(&pollfd, 1, 2000) <= 0) {	/* timeout:2s */
#ifdef DEBUG_MC_NETLINK
			perror("poll():");
#endif
			break;
		}

		if (recvfrom(sock_fd,
				(void *)nlh,
				NLMSG_SPACE(MC_MSG_HDRLEN + msgdatalen),
				MSG_WAITALL, (struct sockaddr *)&src_addr, &fromlen) <= 0) {
#ifdef DEBUG_MC_NETLINK
			printf("netlink socket receive failed\n");
#endif
			break;
		}
		msgheader = (struct __mcctl_msg_header *)NLMSG_DATA(nlh);

		ret = msgheader->status;

#ifdef DEBUG_MC_NETLINK
		if (ret != MC_STATUS_SUCCESS)
			printf("netlink socket status failed %d\n", ret);
#endif

	} while (0);

	if (sock_fd > 0)
		close(sock_fd);

	return ret;
}

void *bridgeAllocTableBuf(int32_t Size, const char *BridgeName)
{
	u_int8_t *data = malloc(MC_BRIDGE_MESSAGE_SIZE(Size));

	if (data == NULL) {
		return NULL;
	}

	bridgeInitBuf(data, Size + MC_BRIDGE_MESSAGE_SIZE(0), BridgeName);

	/* Provide a pointer to the calling application without the header */
	return (void *)(data + MC_BRIDGE_MESSAGE_SIZE(0));
}

void bridgeFreeTableBuf(void *Buf)
{
	if (Buf) {
		/* Walking back, restoring the original pointer */
		u_int8_t *data = (u_int8_t *) (Buf) - MC_BRIDGE_MESSAGE_SIZE(0);

		free(data);
	}
}

void bridgeInitBuf(void *Buf, size_t Size, const char *BridgeName)
{
	struct __mcctl_msg_header *msghdr;

	/* Clear the buffer and initialize bridge name and buffer size */
	memset(Buf, 0, Size);
	msghdr = NLMSG_DATA(Buf);

	if (BridgeName)
		strlcpy(msghdr->if_name, BridgeName, IFNAMSIZ - 1);

	msghdr->buf_len = Size - MC_BRIDGE_MESSAGE_SIZE(0);
}

int32_t bridgeTableAction(const char *BridgeName, bridgeTable_e TableType, int32_t *NumEntries,
	void *TableEntry, bridgeTableAction_e TableAction, int sync)
{
	int32_t retval;
	void *nlmsgbuf = NULL;
	struct __mcctl_msg_header *msghdr;
	size_t entrySize;
	u_int32_t action;
	u_int32_t size;

	/* Sanity check */
	if (TableType >= MC_BRIDGE_TABLE_LAST || !TableEntry) {
		printf("%s: Invalid request\n", __FUNCTION__);
		return -1;
	}

	/* Get the message header pointer. */
	nlmsgbuf = (u_int8_t *) (TableEntry) - MC_BRIDGE_MESSAGE_SIZE(0);

	/* Get the table's entry size and get command */
	entrySize = tableParams[TableType].size;
	if (TableAction == MC_BRIDGE_ACTION_GET)
		action = tableParams[TableType].get_command;
	else
		action = tableParams[TableType].set_command;

	/* Get the pointer to the message header */
	msghdr = NLMSG_DATA(nlmsgbuf);

	size = *NumEntries * entrySize;

	/* Sanity check, make sure the buffer is large enough */
	if (size > msghdr->buf_len) {
		printf("%s: Buffer too small (requested %d, allocated %d)\n", __FUNCTION__, size,
			msghdr->buf_len);
		return -1;
	}

	/* Get the table data from the bridge */
	retval = netlink_msg(action, nlmsgbuf, size, tableParams[TableType].netlink_key, sync);
	if (!sync) {
		*NumEntries = 0;
		return (retval == MC_STATUS_SUCCESS) ? 0 : (-1);
	}

	if (retval == MC_STATUS_SUCCESS) {
		*NumEntries = msghdr->bytes_written / entrySize;
		return 0;
	} else {
		printf("%s: netlink failed, error: %s \n", __FUNCTION__,
			mcctl_status_debug[retval]);
		*NumEntries = msghdr->bytes_needed / entrySize;
	}

	return -1;
}


/*-F- bridgeSetEventInfo --
 */
int32_t bridgeSetEventInfo(const char *BridgeName, u_int32_t Pid, u_int32_t Cmd,
	u_int32_t netlinkKey)
{
	int32_t retval;
	u_int8_t nlmsgbuf[MC_BRIDGE_MESSAGE_SIZE(sizeof(u_int32_t))];
	u_int32_t *p;

	bridgeInitBuf(nlmsgbuf, sizeof(nlmsgbuf), BridgeName);

	p = MC_MSG_DATA(nlmsgbuf);
	*p = Pid;

	retval = netlink_msg(Cmd, nlmsgbuf, sizeof(u_int32_t), netlinkKey, 1);

	if (retval != MC_STATUS_SUCCESS)
		return -1;
	else
		return 0;
}

/*-F- bridgeSetSnoopingParam --
 */
int32_t bridgeSetSnoopingParam(const char *BridgeName, int Cmd, void *MCParam, u_int32_t ParamLen)
{
	int32_t retval;
	u_int8_t nlmsgbuf[MC_BRIDGE_MESSAGE_SIZE(ParamLen)];
	void *pentry;

	bridgeInitBuf(nlmsgbuf, sizeof(nlmsgbuf), BridgeName);

	pentry = MC_MSG_DATA(nlmsgbuf);

	memcpy(pentry, MCParam, ParamLen);

	retval = netlink_msg(Cmd, nlmsgbuf, ParamLen, NETLINK_QCA_MC, 1);

	if (retval != MC_STATUS_SUCCESS)
		return -1;

	return 0;
}

