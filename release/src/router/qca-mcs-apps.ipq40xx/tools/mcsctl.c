/*
 *  Copyright (c) 2011, 2017 Atheros Communications Inc.
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
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/*
 * mcsctl implementation
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
#include "mcnl.h"

#define MC_IP4_FMT(ip4)     (ip4)[0], (ip4)[1], (ip4)[2], (ip4)[3]
#define MC_IP4_STR          "%03d.%03d.%03d.%03d"
#define MC_IP6_FMT(ip6)     ntohs((ip6)[0]), ntohs((ip6)[1]), ntohs((ip6)[2]), ntohs((ip6)[3]), ntohs((ip6)[4]), ntohs((ip6)[5]), ntohs((ip6)[6]), ntohs((ip6)[7])
#define MC_IP6_STR          "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define MC_MAC_FMT(addr)    (addr)[0], (addr)[1], (addr)[2], (addr)[3], (addr)[4], (addr)[5]
#define MC_MAC_STR          "%02x:%02x:%02x:%02x:%02x:%02x"
#define MC_CHECK_ARGS_AND_USAGE( args_num ) if(argc != args_num) { usage = 1; break; }
#define MC_CHECK_ARGS_MAX_TBL_ENTRY(num) if(num > 2048) {retval = -1; break; }

/* Covert a string format MAC address to u_int8_t array */
static void mac_addr_str2uchar(char *str, u_int8_t *mac)
{
	char *ptr, *saveptr;
	int i = 0;
	static const char delims[] = ":-.";

	ptr = strtok_r(str, delims, &saveptr);

	while (ptr) {
		unsigned long val = strtoul(ptr, NULL, 16);

		if (val > 0xff || i >= ETH_ALEN) {
			printf("Invalid MAC address\n");
			exit(1);
		}

		mac[i] = (u_int8_t) val;
		i++;
		ptr = strtok_r(NULL, delims, &saveptr);
	}

	if (i != ETH_ALEN) {
		printf("Invalid MAC address\n");
		exit(1);
	}
}

void show_usage(void)
{
	printf("\nUsage:\n");
	printf("mcsctl -s brname state state(enable or disable)\n");
	printf("mcsctl -s brname debug state(enable or disable)\n");
	printf("mcsctl -s brname policy value(flood or drop)\n");
	printf("mcsctl -s brname aging time(s)\n");
	printf("mcsctl -s brname retag state(enable or disable) dscp\n");
	printf("mcsctl -s brname route type(flood, drop, specify or default) ifname\n");
	printf("mcsctl -s brname acl add type(igmp or mld) rule(Disable, Multicast, SystemWideManagement, Management, NonSnooping or Internal) pattern(ipv4, ipv6 or mac) ip(mac) ipmask(macmask)\n");
	printf("mcsctl -s brname acl flush type(igmp or mld)\n");
	printf("mcsctl -s brname convertall state(enable or disable)\n");
	printf("mcsctl -s brname timeout from(GroupSpecificQueries, AllSystemQueries or GroupMembershipInterval) state(enable or disable)\n");
	printf("mcsctl -s brname IGMPv3MLDv2Filter state(enable or disable)\n");
	printf("mcsctl -s brname IgnoreTbit state(enable or disable)\n");
	printf("mcsctl -s brname LocalQueryInterval value\n");
	printf("mcsctl -s brname LocalInspect state(enable or disable)\n");
	printf("mcsctl -s brname extraqueryresponse value\n");
	printf("mcsctl -s brname QRVThreshold value\n");
	printf("mcsctl -s brname mcrouter state(enable or disable)\n");
	printf("mcsctl -g brname acltbl num_entries\n");
	printf("mcsctl -g brname mdbtbl num_entries\n");

	printf("\n\nexample:\n");
	printf("mcsctl -s br-lan state enable\n");
	printf("mcsctl -s br-lan debug enable\n");
	printf("mcsctl -s br-lan policy flood\n");
	printf("mcsctl -s br-lan aging 260\n");
	printf("mcsctl -s br-lan retag enable 40\n");
	printf("mcsctl -s br-lan route specify eth0.5\n");
	printf("mcsctl -s br-lan acl add igmp SystemWideManagement ipv4 224.0.0.1 255.255.255.255\n");
	printf("mcsctl -s br-lan acl add igmp Multicast mac 01:00:5e:00:00:00 ff:ff:ff:00:00:00\n");
	printf("mcsctl -s br-lan acl flush igmp\n");
	printf("mcsctl -s br-lan convertall enable\n");
	printf("mcsctl -s br-lan timeout AllSystemQueries disable\n");
	printf("mcsctl -s br-lan LocalQueryInterval 125\n");
	printf("mcsctl -g br-lan acltbl 20\n");
	printf("mcsctl -g br-lan mdbtbl 20\n");
}

void mc_acltbl_dump(struct __mc_param_acl_rule *entry, int num_entries, unsigned short pro)
{
	int i, igmp_cnt = 0, mld_cnt = 0;
	u_int16_t *pIp, *pMask;

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
			printf("\tPATTEN %02d:" MC_IP4_STR "/" MC_IP4_STR " - " MC_MAC_STR "/"
				MC_MAC_STR " -- %s\n", igmp_cnt + 1,
				MC_IP4_FMT((unsigned char *)(entry->pattern.ip)),
				MC_IP4_FMT((unsigned char *)(entry->pattern.ip_mask)),
				MC_MAC_FMT(entry->pattern.mac), MC_MAC_FMT(entry->pattern.mac_mask),
				Pattern[entry->pattern.rule]);
			igmp_cnt++;
		} else if (pro == ETH_P_IPV6 && entry->pattern_type == MC_ACL_PATTERN_MLD) {
			pIp = (u_int16_t *)entry->pattern.ip;
			pMask = (u_int16_t *)entry->pattern.ip_mask;
			printf("\tPATTEN %02d:" MC_IP6_STR "/" MC_IP6_STR " - " MC_MAC_STR "/"
				MC_MAC_STR " -- %s\n", mld_cnt + 1,
				MC_IP6_FMT(pIp),
				MC_IP6_FMT(pMask),
				MC_MAC_FMT(entry->pattern.mac), MC_MAC_FMT(entry->pattern.mac_mask),
				Pattern[entry->pattern.rule]);
			mld_cnt++;
		}
	}
}

void mc_mdbtbl_dump(struct __mc_mdb_entry *entry, int num_entries, unsigned short pro)
{
	int i, j, num = 1;
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
			printf("%-6d%-60s" MC_MAC_STR " %-10s%-10lu\n",
				num++, group_string,
				MC_MAC_FMT(entry->mac), ifname, (long unsigned int)entry->aging);

			if (entry->filter_mode) {
				unsigned int *source = (unsigned int *)entry->srcs;

				printf("      |--Source Mode:%s\n",
					entry->filter_mode ==
					MC_DEF_FILTER_INCLUDE ? "Nonblock Listed Sources" :
					"Block Listed Sources");
				if (entry->nsrcs)
					printf("      |--Num of Sources:%d\n", entry->nsrcs);
				else
					printf("      `--Num of Sources:%d\n", entry->nsrcs);

				for (j = 0; j < entry->nsrcs; j++) {
					snprintf(group_string, sizeof group_string, MC_IP4_STR,
						MC_IP4_FMT((unsigned char *)(&source[j])));
					if (j == entry->nsrcs - 1)
						printf("      `--Source %d of %d:%s\n", j + 1,
							entry->nsrcs, group_string);
					else
						printf("      |--Source %d of %d:%s\n", j + 1,
							entry->nsrcs, group_string);
				}
			}
		} else if (pro == ETH_P_IPV6 && entry->group.pro == htons(ETH_P_IPV6)) {
			u_int16_t *pIp = (u_int16_t *)&entry->group.u.ip6;
			snprintf(group_string, sizeof group_string, MC_IP6_STR,
				MC_IP6_FMT(pIp));
			if_indextoname(entry->ifindex, ifname);
			printf("%-6d%-60s" MC_MAC_STR " %-10s%-10lu\n",
				num++, group_string,
				MC_MAC_FMT(entry->mac), ifname, (long unsigned int)entry->aging);

			if (entry->filter_mode) {
				struct in6_addr *source = (struct in6_addr *)entry->srcs;

				printf("      |--Source Mode:%s\n",
					entry->filter_mode ==
					MC_DEF_FILTER_INCLUDE ? "Nonblock Listed Sources" :
					"Block Listed Sources");
				if (entry->nsrcs)
					printf("      |--Num of Sources:%d\n", entry->nsrcs);
				else
					printf("      `--Num of Sources:%d\n", entry->nsrcs);
				for (j = 0; j < entry->nsrcs; j++) {
					snprintf(group_string, sizeof group_string, MC_IP6_STR,
						MC_IP6_FMT((unsigned short *)(&source[j])));
					if (j == entry->nsrcs - 1)
						printf("      `--Source %d of %d:%s\n", j + 1,
							entry->nsrcs, group_string);
					else
						printf("      |--Source %d of %d:%s\n", j + 1,
							entry->nsrcs, group_string);
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	enum {
		ARG_set,
		ARG_get,
	};

	int num_entries, retval = EXIT_SUCCESS;
	char *arg_type;
	int key;
	char *br = NULL;
	unsigned int usage = 0;

	argv++;
	if (argc < 5) {
		show_usage();
		return 1;
	}
	arg_type = *argv++;
	if (strcmp(arg_type, "-s") == 0) {
		key = ARG_set;
	} else if (strcmp(arg_type, "-g") == 0) {
		key = ARG_get;
	} else {
		printf("Invalid argument %s\n", *argv);
		show_usage();
		return 1;
	}

	br = *argv++;

	switch (key) {

	case ARG_set:
		{
			if (!strcmp(*argv, "state")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_ENABLE,
					&enable, sizeof(enable));
			} else if (!strcmp(*argv, "debug")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_DEBUG,
					&enable, sizeof(enable));
			} else if (!strcmp(*argv, "policy")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value policy = { };
				argv++;
				if (!strcmp(*argv, "flood"))
					policy.val = MC_POLICY_FLOOD;
				else if (!strcmp(*argv, "drop"))
					policy.val = MC_POLICY_DROP;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_POLICY,
					&policy, sizeof(policy));
			} else if (!strcmp(*argv, "aging")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				argv++;
				struct __mc_param_value aging = { };
				aging.val = atoi(*argv);
				retval = bridgeSetSnoopingParam(br,
					MC_MSG_SET_MEMBERSHIP_INTERVAL, &aging,
					sizeof(aging));
			} else if (!strcmp(*argv, "retag")) {
				if (argc != 5 && argc != 6) {
					usage = 1;
					break;
				}
				argv++;
				struct __mc_param_retag retag = { };
				if (argc == 6 && !strcmp(*argv, "enable")) {
					retag.enable = 1;
					argv++;
					retag.dscp = atoi(*argv);
				} else if (argc == 5 && !strcmp(*argv, "disable")) {
					retag.enable = 0;
				} else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_RETAG,
					&retag, sizeof(retag));
			} else if (!strcmp(*argv, "route")) {
				if (argc != 5 && argc != 6) {
					usage = 1;
					break;
				}
				argv++;
				struct __mc_param_router_port route = { };
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
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_ROUTER_PORT,
					&route, sizeof(route));
			} else if (!strcmp(*argv, "acl")) {
				argv++;
				struct __mc_param_acl_rule acl = { };
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
#if 0				/* todo */
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
							printf("Invalid ipv4 address %s\n",
								*argv);
							break;
						}
						memcpy(acl.pattern.ip, buf, sizeof buf);
						argv++;
						if (inet_pton(AF_INET, *argv, buf) <= 0) {
							printf("Invalid ipv4 mask address %s\n", *argv);
							break;
						}
						memcpy(acl.pattern.ip_mask, buf,
							sizeof buf);
					} else if (!strcmp(*argv, "ipv6")) {
						unsigned char buf[sizeof(struct in6_addr)];

						if (acl.pattern_type == MC_ACL_PATTERN_IGMP) {
							printf("Error, please specify the ipv4 address.\n");
							break;
						}
						argv++;
						if (inet_pton(AF_INET6, *argv, buf) <= 0) {
							printf("Invalid ipv6 address %s\n",
								*argv);
							break;
						}
						memcpy(acl.pattern.ip, buf, sizeof buf);
						argv++;
						if (inet_pton(AF_INET6, *argv, buf) <= 0) {
							printf("Invalid ipv6 mask address %s\n", *argv);
							break;
						}
						memcpy(acl.pattern.ip_mask, buf,
							sizeof buf);
					} else if (!strcmp(*argv, "mac")) {
						argv++;
						mac_addr_str2uchar(*argv++,
							acl.pattern.mac);
						mac_addr_str2uchar(*argv,
							acl.pattern.mac_mask);
					} else {
						usage = 1;
						break;
					}
					retval = bridgeSetSnoopingParam(br,
						MC_MSG_SET_ADD_ACL_RULE, &acl, sizeof(acl));
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
					retval = bridgeSetSnoopingParam(br,
						MC_MSG_SET_FLUSH_ACL_RULE, &acl,
						sizeof(acl));
				} else {
					usage = 1;
					break;
				}
			} else if (!strcmp(*argv, "convertall")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_CONVERT_ALL,
					&enable, sizeof(enable));
			} else if (!strcmp(*argv, "timeout")) {
				if (argc != 6) {
					usage = 1;
					break;
				}
				struct __mc_param_timeout timeout = { };
				argv++;
				if (!strcmp(*argv, "GroupSpecificQueries"))
					timeout.from =
						MC_TIMEOUT_FROM_GROUP_SPECIFIC_QUERIES;
				else if (!strcmp(*argv, "AllSystemQueries"))
					timeout.from = MC_TIMEOUT_FROM_ALL_SYSTEM_QUERIES;
				else if (!strcmp(*argv, "GroupMembershipInterval"))
					timeout.from =
						MC_TIMEOUT_FROM_GROUP_MEMBERSHIP_INTERVAL;
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
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_TIMEOUT,
					&timeout, sizeof(timeout));
			} else if (!strcmp(*argv, "IGMPv3MLDv2Filter")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_M2I3_FILTER,
					&enable, sizeof(enable));
			} else if (!strcmp(*argv, "IgnoreTbit")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_TBIT,
					&enable, sizeof(enable));
			} else if (!strcmp(*argv, "LocalQueryInterval")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value interval = { };
				argv++;
				interval.val = atoi(*argv);
				retval = bridgeSetSnoopingParam(br,
					MC_MSG_SET_LOCAL_QUERY_INTERVAL, &interval,
					sizeof(interval));
			} else if (!strcmp(*argv, "mcrouter")) {
				if (argc != 5) {
					usage = 1;
					break;
				}
				struct __mc_param_value enable = { };
				argv++;
				if (!strcmp(*argv, "enable"))
					enable.val = 1;
				else if (!strcmp(*argv, "disable"))
					enable.val = 0;
				else {
					usage = 1;
					break;
				}
				retval = bridgeSetSnoopingParam(br, MC_MSG_SET_ROUTER,
					&enable, sizeof(enable));
			} else {
				usage = 1;
				break;
			}
		}
		break;
	case ARG_get:
		{
			if (!strcmp(*argv, "mdbtbl")) {
				struct __mc_mdb_entry *p;

				/* Check number of arguments and show usage if wrong */
				MC_CHECK_ARGS_AND_USAGE(5);

				num_entries = atoi(*(++argv));
				MC_CHECK_ARGS_MAX_TBL_ENTRY(num_entries);

				if ((p = bridgeAllocTableBuf(num_entries *
							sizeof(struct __mc_mdb_entry),
							br)) == NULL) {
					retval = -1;
					break;
				}

				if (!(retval = bridgeGetTable(br, MC_BRIDGE_MDB_TABLE,
							&num_entries, p))) {
					mc_mdbtbl_dump(p, num_entries, ETH_P_IP);
					mc_mdbtbl_dump(p, num_entries, ETH_P_IPV6);
				}
				bridgeFreeTableBuf(p);
			} else if (!strcmp(*argv, "acltbl")) {
				struct __mc_param_acl_rule *p;

				/* Check number of arguments and show usage if wrong */
				MC_CHECK_ARGS_AND_USAGE(5);

				num_entries = atoi(*(++argv));
				MC_CHECK_ARGS_MAX_TBL_ENTRY(num_entries);

				if ((p = bridgeAllocTableBuf(num_entries *
							sizeof(struct __mc_param_acl_rule),
							br)) == NULL) {
					retval = -1;
					break;
				}

				if (!(retval = bridgeGetTable(br, MC_BRIDGE_ACL_TABLE,
							&num_entries, p))) {
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
	default:
		/* An invalid command */
		printf("command is not supported\n");
		usage = 1;
		break;
	}

	/* Show usage if argument number is wrong */
	if (usage)
		show_usage();

	return retval ? 1 : EXIT_SUCCESS;
}
