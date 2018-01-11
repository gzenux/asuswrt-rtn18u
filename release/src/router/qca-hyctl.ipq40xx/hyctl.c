/*
 *  Copyright (c) 2011 Atheros Communications Inc.
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
 * hyctl implementation
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <ctype.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hyfi-bridge.h"
#include "hyfi_api.h"
#include "mc_api.h"

/* Maximum number of ports supported per bridge interface.  */
#ifndef MAX_PORTS
#define MAX_PORTS 32
#endif

#define MC_IP4_FMT(ip4)     (ip4)[0], (ip4)[1], (ip4)[2], (ip4)[3]
#define MC_IP4_STR          "%03d.%03d.%03d.%03d"
#define MC_IP6_FMT(ip6)     ntohs((ip6)[0]), ntohs((ip6)[1]), ntohs((ip6)[2]), ntohs((ip6)[3]), ntohs((ip6)[4]), ntohs((ip6)[5]), ntohs((ip6)[6]), ntohs((ip6)[7])
#define MC_IP6_STR          "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define MC_MAC_FMT(addr)    (addr)[0], (addr)[1], (addr)[2], (addr)[3], (addr)[4], (addr)[5]
#define MC_MAC_STR          "%02x:%02x:%02x:%02x:%02x:%02x"

#define HYFI_CHECK_ARGS_AND_USAGE( args_num ) if(argc != args_num) { usage = 1; break; }

#define HYCTL_DEFAULT_BRIDGE "br-lan"

static const char *interface_type[] = {"Wi-Fi 2GHz", "Wi-Fi 5GHz", "PLC", "Ethernet", "Unknown"};

/* Covert a string format MAC address to u_int8_t array */
static void mac_addr_str2uchar(char* str, u_int8_t *mac)
{
	char *ptr;
	int i = 0;
	static const char delims[]=":-.";

	ptr = strtok(str, delims);

	while(ptr) {
		unsigned long val = strtoul(ptr, NULL, 16);

		if(val > 0xff || i >= ETH_ALEN) {
			printf("Invalid MAC address\n");
			exit(1);
		}

		mac[i] = (u_int8_t)val;
		i++;
		ptr = strtok(NULL, delims);
	}

	if(i != ETH_ALEN) {
		printf("Invalid MAC address\n");
		exit(1);
	}
}

void show_usage(void);
void show_usage(void)
{
	printf("\nUsage:\n");
	printf("hyctl show\n");
	printf("hyctl attach brname\n");
	printf("hyctl detach brname\n");
	printf("hyctl addhdtbl brname mac_addr id udp_ifname other_ifname static\n");
	printf("hyctl addhatbl brname hash mac_addr id ifname sub_class(udp or other) priority\n");
	printf("hyctl sethatbl brname hash mac_addr ifname sub_class(udp or other) priority\n");
	printf("hyctl delhdtbl brname [-m mac_addr]/[-i id] (by mac or by id)\n");
	printf("hyctl gethatbl brname num_entries\n");
	printf("hyctl gethdtbl brname num_entries\n");
	printf("hyctl getfdb brname num_entries\n");
	printf("hyctl setbrmode brname mode(relovr or grprel)\n");
	printf("hyctl setifgrp brname ifname group_num type(r or n)\n");
	printf("hyctl flushatbl brname \n");
	printf("hyctl flushdtbl brname \n");
	printf("hyctl setifbcast brname ifname state(enable or disable)\n");
	printf("hyctl settcpsp brname state(enable or disable)\n");
	printf("hyctl setiftype brname ifname type(w2|w5|plc|eth)\n");
	printf("hyctl setmc brname state state(enable or disable)\n");
	printf("hyctl setmc brname debug state(enable or disable)\n");
	printf("hyctl setmc brname policy value(flood or drop)\n");
	printf("hyctl setmc brname aging time(s)\n");
	printf("hyctl setmc brname retag state(enable or disable) dscp\n");
	printf("hyctl setmc brname route type(flood, drop, specify or default) ifname\n");
	printf("hyctl setmc brname acl add type(igmp or mld) rule(Disable, Multicast, SystemWideManagement, Management, NonSnooping or Internal) pattern(ipv4, ipv6 or mac) ip(mac) ipmask(macmask)\n");
	printf("hyctl setmc brname acl flush type(igmp or mld)\n");
	printf("hyctl setmc brname convertall state(enable or disable)\n");
	printf("hyctl setmc brname timeout from(GroupSpecificQueries, AllSystemQueries or GroupMembershipInterval) state(enable or disable)\n");
	printf("hyctl setmc brname IGMPv3MLDv2Filter state(enable or disable)\n");
	printf("hyctl setmc brname IgnoreTbit state(enable or disable)\n");
	printf("hyctl setmc brname LocalQueryInterval value\n");
	printf("hyctl setmc brname LocalInspect state(enable or disable)\n");
	printf("hyctl setmc brname extraqueryresponse value\n");
	printf("hyctl setmc brname QRVThreshold value\n");
	printf("hyctl setmc brname mcrouter state(enable or disable)\n");
	printf("hyctl getmc brname acltbl num_entries\n");
	printf("hyctl getmc brname mdbtbl num_entries\n");
	printf("hyctl setpsmseto brname timeout_msec\n");
	printf("hyctl setpsdropmrk brname val(1=yes, 0=no)\n");
    printf("hyctl setpsquiet brname quiet_time\n");
    printf("hyctl setpsflushq brname flush_quota\n");
    printf("hyctl setaggr brname hash mac_addr sub_class(udp or other) priority ifname1 quota1 ifname2 quota2 ifname3 quota3\n");
	printf("hyctl sethatblage brname max_age\n");

	printf("\n\nexample:\n");
    printf("hyctl attach br-lan\n");
    printf("hyctl detach br-lan\n");
	printf("hyctl addhdtbl br-lan 00:03:7f:01:02:03 00:03:7f:01:02:01 eth0.1 eth0.5 static\n");
	printf("hyctl sethatbl br-lan 30 00:03:7f:01:02:03 ath0 udp 0x80000000\n");
	printf("hyctl addhatbl br-lan 30 00:03:7f:01:02:03 00:03:7f:00:11:22 ath0 udp 0x80000000\n");
	printf("hyctl gethatbl br-lan 5\n");
	printf("hyctl setbrmode br-lan relovr\n");
	printf("hyctl setifgrp br-lan eth0.1 1 r\n");
	printf("hyctl flushatbl br-lan \n");
	printf("hyctl flushdtbl br-lan \n");
	printf("hyctl delhdtbl br-lan -m 00:03:7f:01:02:03\n");
	printf("hyctl delhdtbl br-lan -i 00:03:7f:01:02:03\n");
	printf("hyctl setifbcast br-lan eth0.1 enable\n");
	printf("hyctl settcpsp br-lan enable\n");
	printf("hyctl setiftype br-lan eth0.1024 plc\n");
	printf("hyctl setmc br-lan state enable\n");
	printf("hyctl setmc br-lan debug enable\n");
	printf("hyctl setmc br-lan policy flood\n");
	printf("hyctl setmc br-lan aging 260\n");
	printf("hyctl setmc br-lan retag enable 40\n");
	printf("hyctl setmc br-lan route specify eth0.5\n");
	printf("hyctl setmc br-lan acl add igmp SystemWideManagement ipv4 224.0.0.1 255.255.255.255\n");
	printf("hyctl setmc br-lan acl add igmp Multicast mac 01:00:5e:00:00:00 ff:ff:ff:00:00:00\n");
	printf("hyctl setmc br-lan acl flush igmp\n");
	printf("hyctl setmc br-lan convertall enable\n");
	printf("hyctl setmc br-lan timeout AllSystemQueries disable\n");
	printf("hyctl setmc br-lan LocalQueryInterval 125\n");
	printf("hyctl getmc br-lan acltbl 20\n");
	printf("hyctl getmc br-lan mdbtbl 20\n");
	printf("hyctl setpsmseto br-lan 1000\n");
	printf("hyctl setpsdropmrk br-lan 0\n");
	printf("hyctl setpsquiet br-lan 10\n");
	printf("hyctl setpsflushq br-lan 2\n");
	printf("hyctl setaggr br-lan fa 00:03:7f:01:02:03 udp 0x80000000 eth0 30 ath0 20 ath1 10\n");
	printf("hyctl sethatblage br-lan 120000\n");
}

static int get_key_index(const char *str, const char *key)
{
	unsigned i = 0;

	while (*str)
	{
		if (strcmp(str, key) == 0)
		{
			return i;
		}
		str += strlen(str) + 1;
		i++;
	}
	return -1;
}

void mc_acltbl_dump(struct __mc_param_acl_rule *entry, int num_entries, unsigned short pro)
{
    int i, igmp_cnt = 0, mld_cnt = 0;
    const u_int16_t *pIp, *pMask;
    const char *Pattern[MC_ACL_RULE_MAX] = {
        "DISABLE",
        "MULTICAST",
        "SYSTEM WIDE MANAGEMENT",
        "MANAGEMENT",
        "NON SNOOPING",
        /* todo "INTERNAL" */
    };

    if (pro == ETH_P_IP && entry->pattern_type == MC_ACL_PATTERN_IGMP)
        printf("\nIGMP ACL TABLE:\n");
    else
        printf("\nMLD ACL TABLE:\n");

    for (i = 0; i < num_entries; i++, entry++) {
        if (entry->pattern.rule >= MC_ACL_RULE_MAX)
            continue;
        if (pro == ETH_P_IP && entry->pattern_type == MC_ACL_PATTERN_IGMP) {
            printf("\tPATTEN %02d:"MC_IP4_STR "/" MC_IP4_STR " - " MC_MAC_STR"/"MC_MAC_STR" -- %s\n",
                    igmp_cnt + 1,
                    MC_IP4_FMT((unsigned char *)(entry->pattern.ip)),
                    MC_IP4_FMT((unsigned char *)(entry->pattern.ip_mask)),
                    MC_MAC_FMT(entry->pattern.mac),
                    MC_MAC_FMT(entry->pattern.mac_mask),
                    Pattern[entry->pattern.rule]);
            igmp_cnt++;
        } else if (pro == ETH_P_IPV6 && entry->pattern_type == MC_ACL_PATTERN_MLD) {
		pIp = (u_int16_t *)((entry->pattern).ip);
		pMask = (u_int16_t *)((entry->pattern).ip_mask);
            printf("\tPATTEN %02d:"MC_IP6_STR "/" MC_IP6_STR " - " MC_MAC_STR"/"MC_MAC_STR" -- %s\n",
                    mld_cnt + 1,
                    MC_IP6_FMT(pIp),
                    MC_IP6_FMT(pMask),
                    MC_MAC_FMT(entry->pattern.mac),
                    MC_MAC_FMT(entry->pattern.mac_mask),
                    Pattern[entry->pattern.rule]);
            mld_cnt++;
        }
    }
}

void mc_mdbtbl_dump(struct __mc_mdb_entry *entry, int num_entries, unsigned short pro)
{
    int i, j, num = 1;
    const u_int16_t *pIp6;
    char group_string[64];
    char ifname[IFNAMSIZ];

    if (pro == ETH_P_IP) {
        printf("\n\n----------------------------Bridge Snooping Hash Table -- IPv4----------------------------------\n");
        printf("NUM   GROUP                                                       FDB               PORT      AGE\n");
    } else {
        printf("\n\n----------------------------Bridge Snooping Hash Table -- IPv6----------------------------------\n");
        printf("NUM   GROUP                                                       FDB               PORT      AGE\n");
    }

    for (i = 0; i < num_entries; i++, entry++) {
        if (pro == ETH_P_IP && entry->group.pro == htons(ETH_P_IP)) {
            snprintf(group_string, sizeof group_string, MC_IP4_STR, 
                    MC_IP4_FMT((unsigned char *)&entry->group.u.ip4));
            if_indextoname(entry->ifindex, ifname);
            printf("%-6d%-60s"MC_MAC_STR" %-10s%-10lu\n",
                    num++, group_string, 
                    MC_MAC_FMT(entry->mac),
                    ifname,
                    (long unsigned int)entry->aging);
                    
            if (entry->filter_mode) {
                unsigned int *source = (unsigned int *)entry->srcs;
                printf("      |--Source Mode:%s\n", entry->filter_mode == HYFI_MC_INCLUDE ?
                        "Nonblock Listed Sources" : "Block Listed Sources");
                if (entry->nsrcs)
                    printf("      |--Num of Sources:%d\n", entry->nsrcs);
                else
                    printf("      `--Num of Sources:%d\n", entry->nsrcs);
                    
                for (j = 0; j < entry->nsrcs; j++) {
                    snprintf(group_string, sizeof group_string, MC_IP4_STR, 
                            MC_IP4_FMT((unsigned char *)(&source[j])));
                    if (j == entry->nsrcs - 1)
                        printf("      `--Source %d of %d:%s\n", j+1, entry->nsrcs, group_string);
                    else
                        printf("      |--Source %d of %d:%s\n", j+1, entry->nsrcs, group_string);
                }
            }
        } else if (pro == ETH_P_IPV6 && entry->group.pro == htons(ETH_P_IPV6)) {
            pIp6 = (u_int16_t *)&(entry->group.u.ip6);
            snprintf(group_string, sizeof group_string, MC_IP6_STR, 
                    MC_IP6_FMT(pIp6));
            if_indextoname(entry->ifindex, ifname);
            printf("%-6d%-60s"MC_MAC_STR" %-10s%-10lu\n",
                    num++, group_string, 
                    MC_MAC_FMT(entry->mac),
                    ifname,
                    (long unsigned int)entry->aging);
                    
            if (entry->filter_mode) {
                struct in6_addr *source = (struct in6_addr *)entry->srcs;
                printf("      |--Source Mode:%s\n", entry->filter_mode == HYFI_MC_INCLUDE ?
                        "Nonblock Listed Sources" : "Block Listed Sources");
                if (entry->nsrcs)
                    printf("      |--Num of Sources:%d\n", entry->nsrcs);
                else
                    printf("      `--Num of Sources:%d\n", entry->nsrcs);
                for (j = 0; j < entry->nsrcs; j++) {
                    snprintf(group_string, sizeof group_string, MC_IP6_STR, 
                            MC_IP6_FMT((unsigned short *)(&source[j])));
                    if (j == entry->nsrcs - 1)
                        printf("      `--Source %d of %d:%s\n", j+1, entry->nsrcs, group_string);
                    else
                        printf("      |--Source %d of %d:%s\n", j+1, entry->nsrcs, group_string);
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
	static const char keywords[] =
		"showmacs\0" "show\0"
		"addhdtbl\0" "delhdtbl\0" "gethatbl\0" "gethdtbl\0" "getfdb\0"
		"setbrmode\0" "setifgrp\0" "sethatbl\0" "flushdtbl\0" "flushatbl\0"
		"addhatbl\0" "setifbcast\0" "settcpsp\0"
		"setmc\0" "getmc\0" "setpsmseto\0" "setpsdropmrk\0" "setpsquiet\0"
		"setpsflushq\0" "attach\0" "detach\0" "setaggr\0" "sethatblage\0";

	enum
	{
		ARG_showmacs, ARG_show,
		ARG_addhdtbl, ARG_delhdtbl, ARG_gethatbl, ARG_gethdtbl, ARG_getfdb,
		ARG_setbrmode, ARG_setifgrp, ARG_sethatbl, ARG_flushdtbl,
		ARG_flushatbl, ARG_addhatbl, ARG_setifbcast, ARG_settcpsp, 
		ARG_setmc, ARG_getmc, ARG_setpsmseto, ARG_setpsdropmrk, ARG_setpsquiet,
		ARG_setpsflushq, ARG_attach, ARG_detach, ARG_setaggr, ARG_sethatblage
	};

	int num_entries, i, retval = EXIT_SUCCESS, size;
	int key;
	char *br = NULL;
	unsigned int usage =  0;

	argv++;
	do {
		if (argc == 1) {
			show_usage();
			break;
		}
		key = get_key_index(keywords, *argv++);
		if (key == -1) {/* no match found in keywords array, bail out. */
			printf("Invalid argument %s\n", *argv);
			show_usage();
			break;
		}

		br = *argv++;

		switch(key)
		{
		    case ARG_attach:
	            /* Check number of arguments and show usage if wrong */
	            HYFI_CHECK_ARGS_AND_USAGE(3);

	            /* Call hybrid bridge API */
	            retval = bridgeAttach( br );
	            break;

		    case ARG_detach:
                /* Check number of arguments and show usage if wrong */
                HYFI_CHECK_ARGS_AND_USAGE(3);

                /* Call hybrid bridge API */
                retval = bridgeDetach( br );
                break;

		case ARG_show:
			{
				char ifname[IFNAMSIZ];
				struct __brport_group *pg;
				struct __hybr_info *brinfo;
				struct __hyctl_msg_header *hymsghdr;
				enum __hyInterfaceType port_type;
				void *nlmsgbuf;

				/* Check number of arguments and show usage if wrong */
				if ((argc != 3) && (argc != 2)) {
					usage = 1;
					break;
				}
				if(argc == 2) {
					br = HYCTL_DEFAULT_BRIDGE;
				}

				size = MAX_PORTS * sizeof(struct __brport_group);

				/* Allocate buffer */
				if( ( nlmsgbuf = bridgeAllocTableBuf( size, NULL ) ) == NULL )
				{
					retval = -1;
					break;
				}
				else
				{
				    /* Get the message header pointer. */
				    nlmsgbuf = (char *)(nlmsgbuf) - HYFI_BRIDGE_MESSAGE_SIZE(0);
				}

				printf("\nbr_name\tbr_mode\ttcp_sp\tinterfaces\ttype\tgrp_num\tbcast\tport_type\n");

				/* There is no API for this function, send a netlink message directly */
				hymsghdr = NLMSG_DATA(nlmsgbuf);
				strncpy(hymsghdr->if_name, br, IFNAMSIZ);
				hymsghdr->buf_len = size;

				if (netlink_msg(HYFI_GET_BRIDGE, nlmsgbuf, size, NETLINK_QCA_HYFI) != HYFI_STATUS_SUCCESS)
				{
					free(nlmsgbuf);
					break;
				}

				brinfo = HYFI_MSG_DATA(nlmsgbuf);

				if (!if_indextoname(brinfo->ifindex, ifname))
				{
					free(nlmsgbuf);
					break;
				}

				printf("%s\t%s\t%s\t",
					ifname,
					brinfo->flags & HYFI_BRIDGE_MODE_RELAY_OVERRIDE ? "RELOVR" : "GRPREL",
					brinfo->flags & HYFI_BRIDGE_FLAG_MODE_TCP_SP ? "enable" : "disable");

				/* Setup parameters */
				memset(nlmsgbuf, 0, NLMSG_LENGTH(0) + HYFI_MSG_HDRLEN + size);
				strcpy(hymsghdr->if_name, ifname);
				hymsghdr->buf_len = size;

				if (netlink_msg(HYFI_GET_PORT_LIST, nlmsgbuf, size, NETLINK_QCA_HYFI) != HYFI_STATUS_SUCCESS)
				{
					free(nlmsgbuf);
					break;
				}

				pg = HYFI_MSG_DATA(nlmsgbuf);

				/* Display all table entries */
				for (i=0; i<hymsghdr->bytes_written/sizeof(struct __brport_group); i++, pg++)
				{
					if (!if_indextoname(pg->ifindex, ifname))
					{
						printf("can't get interface name for index %d", pg->ifindex);
						break;
					}

					port_type = pg->port_type > __hyInterface_NumberOfChildInterfaces ? __hyInterface_NumberOfChildInterfaces : pg->port_type;

					if (i == 0)
					{
						printf("%-9s\t%s\t%d\t%s\t%s\n",
							ifname,
							pg->group_type == HYFI_PORTGRP_TYPE_RELAY ? "relay" : "norelay",
							pg->group_num, pg->bcast_enable ? "enable" : "disable", interface_type[port_type]);
					}
					else
					{
						printf("\t\t\t%-9s\t%s\t%d\t%s\t%s\n",
							ifname,
							pg->group_type == HYFI_PORTGRP_TYPE_RELAY ? "relay" : "norelay",
							pg->group_num, pg->bcast_enable ? "enable" : "disable", interface_type[port_type]);
					}
				}
				printf("\n");
				free(nlmsgbuf);
			}
			break;

		case ARG_gethdtbl:
			{ /* get hd table */
				struct __hdtbl_entry *p;
				struct __hdtbl_entry *pHead;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				/* Setup parameters */
				num_entries = atoi(*argv++);

				/* Allocate buffer */
				if( ( p = bridgeAllocTableBuf( num_entries * sizeof( struct __hdtbl_entry ), br ) ) == NULL )
				{
					retval = -1;
					break;
				}
				pHead = p;

				/* Call hybrid bridge API */
				if( ( retval = bridgeGetTable( br, HYFI_BRIDGE_HD_TABLE, &num_entries, p ) ) == 0 )
				{
					char udpname[IFNAMSIZ];
					char othername[IFNAMSIZ];

					printf("\nmac_addr          id                udp         other       static \n");

					for (i=0; i<num_entries; i++, p++)
					{
						if (!if_indextoname(p->udp_port, udpname))
						{
							printf("can't get interface name for index %d", p->udp_port);
							break;
						}

						if (!if_indextoname(p->other_port, othername))
						{
							printf("can't get interface name for index %d", p->other_port);
							break;
						}

						/* Display table info */
						printf("%02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X %-12s%-12s%s\n",
							p->mac_addr[0], p->mac_addr[1], p->mac_addr[2], p->mac_addr[3], p->mac_addr[4], p->mac_addr[5],
							p->id[0], p->id[1], p->id[2], p->id[3], p->id[4], p->id[5],
							udpname, othername, p->static_entry ? "yes" : "no");
					}
					printf("\n");
				}

				bridgeFreeTableBuf(pHead);
			}
			break;

		case ARG_getfdb:
			{
				char ifname[IFNAMSIZ];
				struct __hfdb_entry *p;
				struct __hfdb_entry *pHead;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				num_entries = atoi(*argv++);

				/* Allocate buffer */
				if( ( p = bridgeAllocTableBuf( num_entries * sizeof( struct __hfdb_entry ), br ) ) == NULL )
				{
					retval = -1;
					break;
				}
				pHead = p;

				/* Call hybrid bridge API */
				if( ( retval = bridgeGetTable( br, HYFI_BRIDGE_FDB_TABLE, &num_entries, p ) ) == 0 )
				{
					printf("\nMAC address        Local Age      Device\n");
					for (i=0; i<num_entries; i++, p++)
					{
						unsigned int ifindex = ((p->ifindex_hi << 8) | p->ifindex);

						if (!if_indextoname(ifindex, ifname))
						{
							printf("can't get interface name for index %d",
								ifindex);
							break;
						}

						/* Display table info */
						printf("%02X:%02X:%02X:%02X:%02X:%02X  %02X    %08X %s\n",
							p->mac_addr[0], p->mac_addr[1], p->mac_addr[2], p->mac_addr[3], p->mac_addr[4], p->mac_addr[5],
							p->is_local, p->ageing_timer_value, ifname);
					}
					printf("\n");
				}

				bridgeFreeTableBuf(pHead);
			}
			break;

		case ARG_gethatbl: /* get ha table */
			{
				struct __hatbl_entry *p;
				struct __hatbl_entry *pHead;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				num_entries = atoi(*argv++);

				if( ( p = bridgeAllocTableBuf( num_entries * sizeof( struct __hatbl_entry ), br ) ) == NULL )
				{
					retval = -1;
					break;
				}
				pHead = p;

				/* Call hybrid bridge API */
				if( ( retval = bridgeGetTable( br, HYFI_BRIDGE_HA_TABLE, &num_entries, p ) ) == 0 )
				{
					char if_name[ IF_NAMESIZE ];

					printf("\n");
					printf("num  hash mac_addr          id                age      npackets nbytes   udp act local static aggr accl priority create_time port\n");
					for (i=0; i<num_entries; i++, p++)
					{
					    u_int32_t j;
						u_int32_t max_quota = 0;

						if( p->aggr_entry )
						{
						    for( j = 0; j < HYFI_AGGR_MAX_IFACE; j++ )
						    {
						        if( !p->port_list[ j ].port )
						             break;
						        max_quota += p->port_list[ j ].quota;
						    }
						}

						for( j = 0; j < HYFI_AGGR_MAX_IFACE; j++ )
						{
						    u_int32_t npackets, nbytes;

                            if( !p->port_list[ j ].port )
                                break;

						    if (!if_indextoname(p->port_list[ j ].port, if_name))
                            {
                                printf("can't get interface name for index %d", p->port_list[ j ].port);
                                break;
                            }

						    if(p->aggr_entry)
						    {
						        /* That's an estimation */
						        npackets = ( p->num_packets * p->port_list[ j ].quota ) / max_quota;
						        nbytes = ( p->num_bytes * p->port_list[ j ].quota ) / max_quota;
						    }
						    else
						    {
						        npackets = p->num_packets;
						        nbytes = p->num_bytes;
						    }

                            /* Display the table info */
                            printf("%04d %04d %02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X "
                                   "%08X %08X %08X %02X  %02X  %-5s %-6s %-4s %-4s %08X %08X    %s\n", 
                                   i, p->hash,
                                   p->da[0], p->da[1], p->da[2], p->da[3], p->da[4], p->da[5],
                                   p->id[0], p->id[1], p->id[2], p->id[3], p->id[4], p->id[5],
                                   p->age, npackets, nbytes,  p->sub_class, p->action, p->local ? "yes" : "no", p->static_entry ? "yes" : "no",
                                   p->aggr_entry ? "yes" : "no", p->accl_entry ? "yes" : "no", 
                                   p->priority, p->create_time, if_name);
						}
					}
					printf("\n");
				}

				bridgeFreeTableBuf(pHead);
			}
			break;

		case ARG_flushatbl:
			/* Check number of arguments and show usage if wrong */
			HYFI_CHECK_ARGS_AND_USAGE(3);

			/* Call hybrid bridge API */
			retval = bridgeFlushHATable( br );
			break;

		case ARG_flushdtbl:
			/* Check number of arguments and show usage if wrong */
			HYFI_CHECK_ARGS_AND_USAGE(3);

			/* Call hybrid bridge API */
			retval = bridgeFlushHDTable( br );
			break;

		case ARG_addhdtbl:
			{
				unsigned char id[ ETH_ALEN ];
				unsigned char mac_addr[ ETH_ALEN ];
				char *if_udp, *if_other;
				int static_entry = 0;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(8);

				/* Setup parameters */
				mac_addr_str2uchar(*argv++, mac_addr);
				mac_addr_str2uchar(*argv++, id);
				if_udp = *argv++;
				if_other = *argv++;
				if (!strcmp(*argv++, "static"))
				    static_entry = 1;

				/* Call hybrid bridge API */
				retval = bridgeAddHDTableEntries( br, mac_addr, id, if_udp, if_other, static_entry);
			}
			break;

		case ARG_delhdtbl:
			{ /* del hd table */
				unsigned char addr_id[ ETH_ALEN ];

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(5);

				mac_addr_str2uchar(*argv++, addr_id);

				/* Call hybrid bridge API */
				if (!strcmp(*argv++, "-m"))
					retval = bridgeDelHDTableEntriesByMAC(br, addr_id);
				else
					retval = bridgeDelHDTableEntriesByID(br, addr_id);
			}
			break;

		case ARG_addhatbl:
			{ /* add ha table */
				unsigned char id[ ETH_ALEN ];
				unsigned char mac_addr[ ETH_ALEN ];
				char *if_name;
				int hash, priority;
				int class = 0;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(9);

				/* Setup parameters */
				sscanf(*argv++, "%x", &hash);
				mac_addr_str2uchar(*argv++, mac_addr);
				mac_addr_str2uchar(*argv++, id);
				if_name = *argv++;
				if (!strcmp(*argv++, "udp"))
					class = HYFI_TRAFFIC_CLASS_UDP;
				sscanf(*argv++, "%x", &priority);

				/* Call hybrid bridge API */
				retval = bridgeAddHATableEntries(br, hash, mac_addr, id, if_name, class, priority );
			}
			break;

		case ARG_sethatbl:
			{ /* update ha table */
				unsigned char mac_addr[ ETH_ALEN ];
				char *if_name;
				int hash, priority;
				int class = 0;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(8);

				/* Setup parameters */
				sscanf(*argv++, "%x", &hash);
				mac_addr_str2uchar(*argv++, mac_addr);
				if_name = *argv++;
				if (!strcmp(*argv++, "udp"))
					class = HYFI_TRAFFIC_CLASS_UDP;
				sscanf(*argv++, "%x", &priority);

				/* Call hybrid bridge API */
				retval = bridgeSetHATableEntries(br, hash, mac_addr, if_name, class, priority);
			}
			break;

        case ARG_setaggr:
            { /* update ha table */
                unsigned char mac_addr[ ETH_ALEN ];
                int i;
                int hash, priority;
                int class = 0;
                hyfiBridgeAggrEntry_t aggrData;

                /* Check number of arguments and show usage if wrong */
                HYFI_CHECK_ARGS_AND_USAGE(13);

                /* Setup parameters */
                sscanf(*argv++, "%x", &hash);
                mac_addr_str2uchar(*argv++, mac_addr);
                if (!strcmp(*argv++, "udp"))
                    class = HYFI_TRAFFIC_CLASS_UDP;
                sscanf(*argv++, "%x", &priority);

                for( i = 0; i < HYFI_AGGR_MAX_IFACE; i++ )
                {
                    aggrData.interfaceName[ i ] = *argv++;
                    aggrData.quota[ i ] = atoi( *argv++ );
                }

                /* Call hybrid bridge API */
                retval = bridgeSetHATableAggrEntry(br, hash, mac_addr, &aggrData, class, priority );

            }
            break;

		case ARG_setbrmode:
			{
				unsigned int brmode=0;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				if (!strcmp(*argv, "grprel"))
					brmode = !HYFI_BRIDGE_MODE_RELAY_OVERRIDE;
				else if (!strcmp(*argv, "relovr"))
					brmode = HYFI_BRIDGE_MODE_RELAY_OVERRIDE;
				else {
					printf("Invalid bridge mode\n");
					break;
				}

				retval = bridgeSetBridgeMode( br, brmode );
			}
			break;

		case ARG_setifgrp:
			{
				char *if_name;
				int group_id, group_type;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(6);

				/* Setup parameters */
				if_name = *argv++;
				group_id = atoi(*argv++);
				if (!strcmp(*argv, "r"))
					group_type = HYFI_PORTGRP_TYPE_RELAY;
				else
					group_type = !HYFI_PORTGRP_TYPE_RELAY;

				/* Call hybrid bridge API */
				retval = bridgeSetIFGroup(br, if_name, group_id, group_type );
			}
			break;

		case ARG_setifbcast:
			{
				unsigned int bcast_enable;
				char *if_name;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(5);

				/* Setup parameters */
				if_name = *argv++;
				if (!strcmp(*argv, "enable"))
					bcast_enable = 1;
				else
					bcast_enable = 0;

				/* Call hybrid bridge API */
				retval = bridgeSetIFBroadcast( br, if_name, bcast_enable );
			}
			break;

		case ARG_settcpsp:
			{
				unsigned int tcpsp_enable;

				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				/* Setup parameters */
				if (!strcmp(*argv, "enable"))
					tcpsp_enable = 1;
				else
					tcpsp_enable = 0;

				/* Call hybrid bridge API */
				retval = bridgeSetTcpSP( br, tcpsp_enable );
			}
			break;

        /* Generic code to setup advanced path switching parameters */
		case ARG_setpsmseto:
		case ARG_setpsdropmrk:
		case ARG_setpsquiet:
		case ARG_setpsflushq:
        {
            static const struct pswParams {
                u_int32_t arg;
                u_int32_t param;

            } pswParams[] = {
                    { ARG_setpsmseto, HYFI_SET_PSW_MSE_TIMEOUT },
                    { ARG_setpsdropmrk, HYFI_SET_PSW_DROP_MARKERS },
                    { ARG_setpsquiet, HYFI_SET_PSW_OLD_IF_QUIET_TIME },
                    { ARG_setpsflushq, HYFI_SET_PSW_DUP_PKT_FLUSH_QUOTA },
            };

            u_int32_t val, i;

            /* Check number of arguments and show usage if wrong */
            HYFI_CHECK_ARGS_AND_USAGE(4);

            /* Setup parameters */
            val = atoi( *argv );
            retval = -1;

            for(i = 0; i < sizeof(pswParams)/sizeof(pswParams[0]); i++ )
            {
                if( pswParams[ i ].arg == key )
                {
                    /* Call hybrid bridge API */
                    retval = bridgeSetPathSwitchAdvancedParam( br, pswParams[i].param, val );
                    break;
                }
            }
        }
        break;

        case ARG_setmc:
			{
                if (!strcmp(*argv, "state")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_ENABLE, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "debug")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_DEBUG, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "policy")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value policy = {};
                    argv++;
                    if (!strcmp(*argv, "flood"))
                        policy.val = MC_POLICY_FLOOD;
                    else if (!strcmp(*argv, "drop"))
                        policy.val = MC_POLICY_DROP;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_POLICY, &policy, sizeof(policy));
                } else if (!strcmp(*argv, "aging")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    argv++;
                    struct __mc_param_value aging = {};
                    aging.val = atoi(*argv);
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_MEMBERSHIP_INTERVAL, &aging, sizeof(aging));
                } else if (!strcmp(*argv, "retag")) {
                    if (argc != 5 && argc != 6) {
                        usage = 1;
                        break;
                    }
                    argv++;
                    struct __mc_param_retag retag = {};
                    if (argc == 6 && !strcmp(*argv, "enable")) {
                        retag.enable  = 1;
                        argv++;
                        retag.dscp = atoi(*argv);
                    } else if (argc == 5 && !strcmp(*argv, "disable")) {
                        retag.enable  = 0;
                    } else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_RETAG, &retag, sizeof(retag));
                } else if (!strcmp(*argv, "route")) {
                    if (argc != 5 && argc != 6) {
                        usage = 1;
                        break;
                    }
                    argv++;
                    struct __mc_param_router_port route = {};
                    if (argc == 6 && !strcmp(*argv, "specify")) {
                        route.type = MC_RTPORT_SPECIFY;
                        argv++;
                        route.ifindex = if_nametoindex(*argv);
                    } else if (argc == 5 && !strcmp(*argv, "drop")) {
                        route.type = MC_RTPORT_DROP;
                    } else if (argc == 5 && !strcmp(*argv, "flood")) {
                        route.type = MC_RTPORT_FLOOD;
                    } else if (argc == 5 && !strcmp(*argv, "default")) {
                        route.type = MC_RTPORT_DEFAULT;
                    } else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_ROUTER_PORT, &route, sizeof(route));
                } else if (!strcmp(*argv, "acl")) {
                    argv++;
                    struct __mc_param_acl_rule acl = {};
                    if (argc == 10 && !strcmp(*argv, "add")) {
                        argv++;
                        if (!strcmp(*argv, "mld"))
                            acl.pattern_type = MC_ACL_PATTERN_MLD;
                        else if (!strcmp(*argv, "igmp"))
                            acl.pattern_type = MC_ACL_PATTERN_IGMP;
                        else {
                            usage = 1;
                            break;
                        }
                        argv++;
                        if (!strcmp(*argv, "Multicast")) {
                            acl.pattern.rule = MC_ACL_RULE_MULTICAST;
                        } else if (!strcmp(*argv, "SystemWideManagement")) {
                            acl.pattern.rule = MC_ACL_RULE_SWM;
                        } else if (!strcmp(*argv, "Management")) {
                            acl.pattern.rule = MC_ACL_RULE_MANAGEMENT;
                        } else if (!strcmp(*argv, "NonSnooping")) {
                            acl.pattern.rule = MC_ACL_RULE_NON_SNOOPING;
                        } else if (!strcmp(*argv, "Disable")) {
                            acl.pattern.rule = MC_ACL_RULE_DISABLE;
                        }
#if 0 /* todo */
                        else if (!strcmp(*argv, "Internal")) {
                            acl.pattern.rule = MC_ACL_RULE_INTERNAL;
                        }
#endif
                        else {
                            usage = 1;
                            break;
                        }
                        argv++;
                        if (!strcmp(*argv, "ipv4")) {
                            unsigned char buf[sizeof(struct in_addr)];

                            if (acl.pattern_type == MC_ACL_PATTERN_MLD) {
                                printf("Error, please specify the ipv6 address.\n");
                                break;
                            }
                            argv++;
                            if (inet_pton(AF_INET, *argv, buf) <= 0) {
                                printf("Invalid ipv4 address %s\n", *argv);
                                break;
                            }
                            memcpy(acl.pattern.ip, buf, sizeof buf);
                            argv++;
                            if (inet_pton(AF_INET, *argv, buf) <= 0) {
                                printf("Invalid ipv4 mask address %s\n", *argv);
                                break;
                            }
                            memcpy(acl.pattern.ip_mask, buf, sizeof buf);
                        }
                        else if (!strcmp(*argv, "ipv6")) {
                            unsigned char buf[sizeof(struct in6_addr)];

                            if (acl.pattern_type == MC_ACL_PATTERN_IGMP) {
                                printf("Error, please specify the ipv4 address.\n");
                                break;
                            }
                            argv++;
                            if (inet_pton(AF_INET6, *argv, buf) <= 0) {
                                printf("Invalid ipv6 address %s\n", *argv);
                                break;
                            }
                            memcpy(acl.pattern.ip, buf, sizeof buf);
                            argv++;
                            if (inet_pton(AF_INET6, *argv, buf) <= 0) {
                                printf("Invalid ipv6 mask address %s\n", *argv);
                                break;
                            }
                            memcpy(acl.pattern.ip_mask, buf, sizeof buf);
                        }
                        else if (!strcmp(*argv, "mac")) {
                            argv++;
				            mac_addr_str2uchar(*argv++, acl.pattern.mac);
				            mac_addr_str2uchar(*argv, acl.pattern.mac_mask);
                        } else {
                            usage = 1;
                            break;
                        }
                        retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_ADD_ACL_RULE, &acl, sizeof(acl));
                    } else if (argc == 6 && !strcmp(*argv, "flush")) {
                        argv++;
                        if (!strcmp(*argv, "mld"))
                            acl.pattern_type = MC_ACL_PATTERN_MLD;
                        else if (!strcmp(*argv, "igmp"))
                            acl.pattern_type = MC_ACL_PATTERN_IGMP;
                        else {
                            usage = 1;
                            break;
                        }
                        retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_FLUSH_ACL_RULE, &acl, sizeof(acl));
                    } else {
                        usage = 1;
                        break;
                    }
                } else if (!strcmp(*argv, "convertall")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_CONVERT_ALL, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "timeout")) {
                    if (argc != 6) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_timeout timeout = {};
                    argv++;
                    if (!strcmp(*argv, "GroupSpecificQueries"))
                        timeout.from = MC_TIMEOUT_FROM_GROUP_SPECIFIC_QUERIES;
                    else if (!strcmp(*argv, "AllSystemQueries"))
                        timeout.from = MC_TIMEOUT_FROM_ALL_SYSTEM_QUERIES;
                    else if (!strcmp(*argv, "GroupMembershipInterval"))
                        timeout.from = MC_TIMEOUT_FROM_GROUP_MEMBERSHIP_INTERVAL;
                    else {
                        usage = 1;
                        break;
                    }
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        timeout.enable = 1;
                    else if (!strcmp(*argv, "disable"))
                        timeout.enable = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_TIMEOUT, &timeout, sizeof(timeout));
                } else if (!strcmp(*argv, "IGMPv3MLDv2Filter")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_M2I3_FILTER, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "IgnoreTbit")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_TBIT, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "LocalQueryInterval")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value interval = {};
                    argv++;
                    interval.val = atoi(*argv);
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_LOCAL_QUERY_INTERVAL, &interval, sizeof(interval));
                }
#if 0 /* todo */
                else if (!strcmp(*argv, "LocalInspect")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_LOCAL_INSPECT, &enable, sizeof(enable));
                } else if (!strcmp(*argv, "extraqueryresponse")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value interval = {};
                    argv++;
                    interval.val = atoi(*argv);
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_EXTRA_QUERY_RESPONSE_TIME, &interval, sizeof(interval));
                } else if (!strcmp(*argv, "QRVThreshold")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value threshold = {};
                    argv++;
                    threshold.val = atoi(*argv);
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_QRV_THRESHOLD, &threshold, sizeof(threshold));
                }
#endif
                else if (!strcmp(*argv, "mcrouter")) {
                    if (argc != 5) {
                        usage = 1;
                        break;
                    }
                    struct __mc_param_value enable = {};
                    argv++;
                    if (!strcmp(*argv, "enable"))
                        enable.val  = 1;
                    else if (!strcmp(*argv, "disable"))
                        enable.val  = 0;
                    else {
                        usage = 1;
                        break;
                    }
                    retval = bridgeSetSnoopingParam(br, HYFI_SET_MC_ROUTER, &enable, sizeof(enable));
                }
                else {
                    usage = 1;
                    break;
                }
			}
            break;
        case ARG_getmc:
			{
                if (!strcmp(*argv, "mdbtbl")) {
				    struct __mc_mdb_entry *p;

				    /* Check number of arguments and show usage if wrong */
				    HYFI_CHECK_ARGS_AND_USAGE(5);

				    num_entries = atoi(*(++argv));

				    if( ( p = bridgeAllocTableBuf( num_entries * sizeof( struct __mc_mdb_entry ), br ) ) == NULL )
				    {
					    retval = -1;
					    break;
				    }

				    if( !( retval = bridgeGetTable( br, HYFI_BRIDGE_MDB_TABLE, &num_entries, p ) ) ) {
                        mc_mdbtbl_dump(p, num_entries, ETH_P_IP);
                        mc_mdbtbl_dump(p, num_entries, ETH_P_IPV6);
                    }
				    bridgeFreeTableBuf(p);
                } else if (!strcmp(*argv, "acltbl")) {
				    struct __mc_param_acl_rule *p;

				    /* Check number of arguments and show usage if wrong */
				    HYFI_CHECK_ARGS_AND_USAGE(5);

				    num_entries = atoi(*(++argv));

				    if( ( p = bridgeAllocTableBuf( num_entries * sizeof( struct __mc_param_acl_rule ), br ) ) == NULL )
				    {
					    retval = -1;
					    break;
				    }

				    if( !( retval = bridgeGetTable( br, HYFI_BRIDGE_ACL_TABLE, &num_entries, p ) ) ) {
                        mc_acltbl_dump(p, num_entries, ETH_P_IP);
                        mc_acltbl_dump(p, num_entries, ETH_P_IPV6);
                    }
				    bridgeFreeTableBuf(p);
                } else {
                    usage = 1;
                    break;
                }
            }
            break;
		case ARG_sethatblage:
			{
				/* Check number of arguments and show usage if wrong */
				HYFI_CHECK_ARGS_AND_USAGE(4);

				/* Setup parameters */
				unsigned int age = atoi(*argv);
				// Only check minimum value here - maxiumum checked by bridge
				if (!age)
				{
					printf("Must have non-zero maximum H-Active age\n");
					break;
				}

				/* Call hybrid bridge API */
				retval = bridgeSetHATableAgingParams(br, age);

				break;
			}
		default:
			/* An invalid command */
			printf("command is not supported\n");
			usage = 1;
			break;
		}

		/* Show usage if argument number is wrong */
		if (usage)
			show_usage();

	} while (0);

	if (retval)
	{
		printf("Error running command\n");
	}
	return retval ? 1 : EXIT_SUCCESS;
}
