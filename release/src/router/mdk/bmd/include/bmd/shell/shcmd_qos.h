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

extern int bmd_shcmd_qos(int argc, char *argv[]);

#define BMD_SHCMD_QOS_DESC "Configure the switch QoS"
#define BMD_SHCMD_QOS_SYNOP \
"multiq [enable|disable] \n" \
"dscpmap <dscp> [<priority>] \n" \
"portprimap <ports> <prio> [<queue>] \n" \
"method [port|mac|8021p|diffserv|traffictype|combo|combohigh] \n" \
"qtodma <queue> [<dmachannel>] \n" \
"dmatoq <dmachannel> [<queue>] \n" \
"sched [strict|wrr|combo [<strict_endq>]] \n" \
"txqsel [usebd|usedmaq] \n" \
"wrr <queue> [<weight>] "
#define BMD_SHCMD_QOS_HELP \
"Enable or disable multiple queues (QoS) \n" \
"qos multiq enable \n\n" \
"Configure QoS method \n" \
"qos method port\n" \
"qos method diffserv\n" \
"qos method\n\n" \
"Configure DSCP to priority mapping \n" \
"qos dscpmap 35 6 \n" \
"qos dscpmap 35 \n\n" \
"Configure port priority to egress queue mapping \n" \
"qos portprimap 1-3 3 5 \n" \
"qos portprimap 2-3 3 \n\n" \
"Configure egress queue scheduling \n" \
"qos sched strict \n" \
"qos sched combo 4 \n" \
"qos sched\n\n" \
"Configure WRR queue weights (< 0x31) \n" \
"qos wrr 0 10 \n\n" \
"Configure Queue (<=7 for 6816 and <=3 for others) to DMA channel (<= 3) mapping \n" \
"qos qtodma 0 2 \n\n" \
"Configure DMA channel (<= 3) to Queue (<=7 for 6816 and <=3 for others) mapping \n" \
"qos dmatoq 2 7 \n\n" \
"Configure the method to determine egress queue for ingress packets on IMP port \n" \
"qos txqsel usebd \n"

