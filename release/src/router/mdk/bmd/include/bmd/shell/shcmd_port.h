/*
 * $Id: shcmd_vlan.h,v 1.5 Broadcom SDK $
 * $Copyright: Copyright 2009 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

extern int bmd_shcmd_port(int argc, char *argv[]);

#define BMD_SHCMD_PORT_DESC "Manage Per Port Configuration"
#define BMD_SHCMD_PORT_SYNOP \
"jumbo <ports> [enable|disable] \n" \
"pause <ports> [onlyrx|onlytx|both|none] \n" \
"pbvlan <ports> [<portmap>] \n" \
"irc <ports> [<rateinkbps> <burstinkbits>] \n"  \
"erc <ports> [<rateinkbps> <burstinkbits>] \n" \
"remaptag <ports> [<vlan_tag>] \n" \
"remapmatchvid <ports> [<vlan>] \n" \
"remaptagop <ports> [tpid|pid|cid|vid] [enable|disable] \n" \
"traffic <ports> [onlyrx|onlytx|both|none] \n" \
"pvlanpri <ports> [<priority>]"
#define BMD_SHCMD_PORT_HELP \
"\n" \
"Enable or disable jumbo packets\n" \
"port jumbo 0 enable\n" \
"port jumbo 0\n\n" \
"Enable or disable flow control\n" \
"port pause 0-3 onlyrx\n" \
"port pause 0-8\n" \
"port pause 8 both \n\n" \
"Configure rate control\n" \
"port irc 0 100  300\n" \
"port erc 2 50 100 \n" \
"port erc 2 \n\n" \
"Configure pbvlanmap\n" \
"port pbvlan 0-4 0-6\n" \
"port pbvlan all \n\n" \
"Configure egress tag replacment (6816 only)\n" \
"port remaptag 0 0x88740024 \n" \
"port remaptag 0 \n" \
"port remapmatchvid 0 0xfff \n" \
"port remapmatchvid 0\n" \
"port remaptagop tpid enable \n" \
"port remaptagop tpid \n\n" \
"Configure port traffic control \n" \
"port traffic 0-4 onlyrx \n" \
"port traffic 0-4\n\n" \
"Configure port default vlan tag priority \n" \
"port pvlanpri 1-3 5 \n" \
"port pvlanpri 1-3\n\n" 

