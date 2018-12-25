/***********************************************************************
 *
 *  Copyright (c) 2007  Broadcom Corporation
 *  All Rights Reserved
 *
<:label-BRCM:2012:proprietary:standard

 This program is the proprietary software of Broadcom and/or its
 licensors, and may only be used, duplicated, modified or distributed pursuant
 to the terms and conditions of a separate, written license agreement executed
 between you and Broadcom (an "Authorized License").  Except as set forth in
 an Authorized License, Broadcom grants no license (express or implied), right
 to use, or waiver of any kind with respect to the Software, and Broadcom
 expressly reserves all rights in and to the Software and all intellectual
 property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
 NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
 BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.

 Except as expressly set forth in the Authorized License,

 1. This program, including its structure, sequence and organization,
    constitutes the valuable trade secrets of Broadcom, and you shall use
    all reasonable efforts to protect the confidentiality thereof, and to
    use this information only in connection with your use of Broadcom
    integrated circuit products.

 2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
    AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
    WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
    RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
    ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
    FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
    COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
    TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
    PERFORMANCE OF THE SOFTWARE.

 3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
    ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
    INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
    WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
    IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
    OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
    SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
    SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
    LIMITED REMEDY.
:>
 *
 ************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include "bcm/bcmswapitypes.h"
#include "boardparms.h"
#include "bcmnet.h"
#include "ethctl_api.h"

#ifdef DESKTOP_LINUX

/* when running on DESKTOP_LINUX, redirect ioctl's to a fake one */
static int fake_ethsw_ioctl(int fd, int cmd, void *data);
#define ETHSW_IOCTL_WRAPPER  fake_ethsw_ioctl

#else

/* When running on actual target, call the real ioctl */
#define ETHSW_IOCTL_WRAPPER  ioctl

#endif

int mdio_read(int skfd, struct ifreq *ifr, int phy_id, int location)
{
    struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;
    void *ifr_data_bk = ifr->ifr_data;

    PHYID_2_MII_IOCTL(phy_id, mii);
    mii->reg_num = location;
    if (ioctl(skfd, SIOCGMIIREG, ifr) < 0) {
        fprintf(stderr, "SIOCGMIIREG on %s failed: %s\n", ifr->ifr_name,
            strerror(errno));
        ifr->ifr_data = ifr_data_bk;
        return 0;
    }

    ifr->ifr_data = ifr_data_bk;
    return mii->val_out;
}

#if 0
/* This structure is used in all SIOCxMIIxxx ioctl calls */
154 struct mii_ioctl_data {
155         __u16           phy_id;
156         __u16           reg_num;
157         __u16           val_in;
158         __u16           val_out;
159 };
160
#endif

void mdio_write(int skfd, struct ifreq *ifr, int phy_id, int location, int value)
{
    struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;
    void *ifr_data_bk = ifr->ifr_data;

    PHYID_2_MII_IOCTL(phy_id, mii);
    mii->reg_num = location;
    mii->val_in = value;

    if (ioctl(skfd, SIOCSMIIREG, ifr) < 0) {
        fprintf(stderr, "SIOCSMIIREG on %s failed: %s\n", ifr->ifr_name,
            strerror(errno));
    }
    ifr->ifr_data = ifr_data_bk;
}

static int et_dev_subports_query(int skfd, struct ifreq *ifr)
{
    int port_list = 0;
    void *ifr_data_bk = ifr->ifr_data;

    ifr->ifr_data = (char*)&port_list;
    if (ioctl(skfd, SIOCGQUERYNUMPORTS, ifr) < 0) {
        fprintf(stderr, "Error: Interface %s ioctl SIOCGQUERYNUMPORTS error!\n", ifr->ifr_name);
        ifr->ifr_data = ifr_data_bk;
        return -1;
    }
    ifr->ifr_data = ifr_data_bk;
    return port_list;;
}

static int get_bit_count(int bitmap)
{
    int i, j = 0;
    for(i=0; i<32; i++)
        if((bitmap & (1<<i)))
            j++;
    return j;
}

static int et_get_phyid2(int skfd, struct ifreq *ifr, int sub_port)
{
    unsigned long phy_id;
    void *ifr_data_bk = ifr->ifr_data;
    struct mii_ioctl_data *mii = (void *)&ifr->ifr_data;

    mii->val_in = sub_port;

    if (ioctl(skfd, SIOCGMIIPHY, ifr) < 0)
        return -1;

    phy_id = MII_IOCTL_2_PHYID(mii);
    /*
     * returned phy id carries mii->val_out flags if phy is
     * internal/external phy/phy on ext switch.
     * we save it in higher byte to pass to kernel when
     * phy is accessed.
     */
    ifr->ifr_data = ifr_data_bk;
    return phy_id;
}

int et_get_phyid(int skfd, struct ifreq *ifr, int sub_port)
{
    int sub_port_map;
#define MAX_SUB_PORT_BITS (sizeof(int)*8)

    if ((sub_port_map = et_dev_subports_query(skfd, ifr)) < 0) {
        return -1;
    }

    if (sub_port_map > 0) {
        if (sub_port == -1) {
            if(get_bit_count(sub_port_map) > 1) {
                fprintf(stderr, "Error: Interface %s has sub ports, please specified one of port map: 0x%x\n",
                        ifr->ifr_name, sub_port_map);
                return -1;
            }
            else if (get_bit_count(sub_port_map) == 1) {
                // get bit position
                for(sub_port = 0; sub_port < MAX_SUB_PORT_BITS; sub_port++) {
                    if((sub_port_map & (1 << sub_port)))
                        break;
                }
            }
        }

        if ((sub_port_map & (1 << sub_port)) == 0) {
            fprintf(stderr, "Specified SubPort %d is not interface %s's member port with map %x\n",
                    sub_port, ifr->ifr_name, sub_port_map);
            return -1;
        }
    } else {
        if (sub_port != -1) {
            fprintf(stderr, "Interface %s has no sub port\n", ifr->ifr_name);
            return -1;
        }
    }

    return et_get_phyid2(skfd, ifr, sub_port);
}

int get_link_speed(int skfd, struct ifreq *ifr, int phy_id, int sub_port)
{
    int err;
    struct ethswctl_data *ifdata = ifr->ifr_data;

    ifdata->op = ETHSWPHYMODE;
    ifdata->type = TYPE_GET;
    ifdata->addressing_flag = ETHSW_ADDRESSING_DEV;
    if (sub_port != -1) {
        ifdata->sub_unit = -1; /* Set sub_unit to -1 so that main unit of dev will be used */
        ifdata->sub_port = sub_port;
        ifdata->addressing_flag |= ETHSW_ADDRESSING_SUBPORT;
    }

    if((err = ioctl(skfd, SIOCETHSWCTLOPS, ifr))) {
        fprintf(stderr, "ioctl command return error %d!\n", err);
        return -1;
    }
    return 0;
}

/* 
    Function: Get PHY configuration, speed, duplex from ethernet driver
    Input: *ifname
    Output: *speed: current link speed in Mbps unit, if 0, link is down.
            *duplex: current link duplex
            *phycfg: Values are defined in bcmdrivers/opensource/include/bcm963xx/bcm/bcmswapitypes.h, phy_cfg_flag
            *subport: subport with highest current link up speed.
*/
int bcm_get_linkspeed(char *ifname, int *speed, int *duplex, enum phy_cfg_flag *phycfg, int *subport)
{
    struct ifreq ifr;
    struct ethswctl_data ifdata;
    int skfd;
    int sub_port = -1, sub_port_max = -1, portmap;
    int max_speed = 0, phy_id;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "socket open error\n");
        return -1;
    }

    if ((portmap = et_dev_subports_query(skfd, &ifr)) < 0) {
        fprintf(stderr, "ioctl failed. check if %s exists\n", ifr.ifr_name);
        close(skfd);
        return -1;
    }
 
    if (portmap > 0)
    {
        // Select the maximum link speed as the answer
        for (sub_port = 0 ; sub_port < MAX_SUB_PORT_BITS ; sub_port++)
        {

            if ((portmap & (1 << sub_port)) == 0) continue;

            phy_id = et_get_phyid2(skfd, &ifr, sub_port);
            ifr.ifr_data = &ifdata;
            get_link_speed(skfd, &ifr, phy_id, sub_port);

            if ( max_speed < ifdata.speed) {
                max_speed = ifdata.speed;
                sub_port_max = sub_port;
            }
        }
    }
    else
    {
        phy_id = et_get_phyid2(skfd, &ifr, sub_port);
        ifr.ifr_data = &ifdata;
        get_link_speed(skfd, &ifr, phy_id, sub_port);
        max_speed = ifdata.speed;
    }

    if (speed) *speed = max_speed;
    if (duplex) *duplex = ifdata.duplex;
    if (phycfg) *phycfg = ifdata.phycfg;
    if (subport) *phycfg = sub_port_max;

    return 0;
}

#ifdef unused_code
static int mdio_read_shadow(int skfd, struct ifreq *ifr, int phy_id,
        int shadow_reg)
{
    int reg = 0x1C;
    int val = (shadow_reg & 0x1F) << 10;
    mdio_write(skfd, ifr, phy_id, reg, val);
    return mdio_read(skfd, ifr, phy_id, reg);
}

static void mdio_write_shadow(int skfd, struct ifreq *ifr, int phy_id,
        int shadow_reg, int val)
{
    int reg = 0x1C;
    int value = ((shadow_reg & 0x1F) << 10) | (val & 0x3FF) | 0x8000;
    mdio_write(skfd, ifr, phy_id, reg, value);
}
#endif

