/*
 * $Id: shcmd_tx.h,v 1.6 Broadcom SDK $
 * $Copyright: Copyright 2013 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

extern int bmd_shcmd_tx(int argc, char *argv[]);

#define BMD_SHCMD_TX_DESC "Transmit packet"
#define BMD_SHCMD_TX_SYNOP \
"count [port] [size=n] [shdr=xx:xx ... ] [dmac=mac] [smac=mac] [vlan=n] [untag]"
#define BMD_SHCMD_TX_HELP \
"Transmit packet from the CPU. By default a valid Ethernet packet\n" \
"of 68 bytes (incl. CRC and VLAN tag) will be sent. If the port\n"\
"parameter is omitted, the packet will be ingressed on the CPU port\n" \
"if supported by the switch device.\n\n" \
"Use the size parameter to change the packet size and the dmac/smac\n" \
"parameters to change the destination MAC and source MAC addresses.\n" \
"The MAC address must be specified as 6 hex bytes separated by\n" \
"colons, e.g. 00:01:02:03:04:05.\n"
#define BMD_SHCMD_TX_HELP_2 \
"By default the packet will contain a valid VLAN tag. Use the untag\n" \
"parameter to send the packet untagged.\n\n" \
"The shdr parameter is used to prepend the packet with a stacking\n" \
"header when a packet is sent out on e.g. a HiGig port. The header\n" \
"is specified as hex bytes (up to 16) separated by colons. The number\n" \
"of bytes to specify depends on the stacking protocol, but is typically\n" \
"12 bytes for an XGS HiGig packet.\n\n" \
"Note that the size, dmac, smac and vlan parameters are sticky."

