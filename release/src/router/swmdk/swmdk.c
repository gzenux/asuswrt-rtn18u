/*
* <:copyright-BRCM:2012:proprietary:standard
* 
*    Copyright (c) 2012 Broadcom 
*    All Rights Reserved
* 
*  This program is the proprietary software of Broadcom and/or its
*  licensors, and may only be used, duplicated, modified or distributed pursuant
*  to the terms and conditions of a separate, written license agreement executed
*  between you and Broadcom (an "Authorized License").  Except as set forth in
*  an Authorized License, Broadcom grants no license (express or implied), right
*  to use, or waiver of any kind with respect to the Software, and Broadcom
*  expressly reserves all rights in and to the Software and all intellectual
*  property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
*  NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
*  BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
* 
*  Except as expressly set forth in the Authorized License,
* 
*  1. This program, including its structure, sequence and organization,
*     constitutes the valuable trade secrets of Broadcom, and you shall use
*     all reasonable efforts to protect the confidentiality thereof, and to
*     use this information only in connection with your use of Broadcom
*     integrated circuit products.
* 
*  2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
*     AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
*     WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
*     RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
*     ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
*     FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
*     COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
*     TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
*     PERFORMANCE OF THE SOFTWARE.
* 
*  3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
*     ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
*     INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
*     WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
*     IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
*     OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
*     SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
*     SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
*     LIMITED REMEDY.
* :>
 
*/
/******************************************************************************
 *
 * Linux User mode CDK/BMD Application
 *
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <signal.h>
#include "prctl.h"

#ifdef BRCM_CMS_BUILD
#include "cms.h"
#include "cms_eid.h"
#include "cms_util.h"
#include "cms_log.h"
#endif

/* CDK Package Headers */
#include <cdk_config.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_readline.h>

/* BMD Package Headers */
#include <bmd_config.h>
#include <bmd/bmd.h>
#include <bmd/bmd_phy_ctrl.h>

/* PHY Package Headers */
#include <phy_config.h>
#include <phy/phy_drvlist.h>

#include "ethswctl_api.h"
#include "boardparms.h"

#if !defined(BCM63100_VENDOR_ID)
#if defined(CHIP_4908)
#define BCM63100_VENDOR_ID 0xae02
#else
#define BCM63100_VENDOR_ID 0x600d
#endif
#endif

void link_poll_function(void *);
void mdkshell_start(void);

/*
 * Function: _usleep
 *
 * Purpose:
 *   Function used by the BMD package and PHY packages for sleeps.
 *   Specifed as the value of BMD_SYS_USLEEP and PHY_SYS_USLEEP.
 *
 */
int
_usleep(uint32_t usecs)
{
    return usleep(usecs);
}

/*
 * Function:
 *      _bus_flags
 * Purpose:
 *      Get bus endian settings
 * Parameters:
 *      None
 * Returns:
 *      CDK bus endian device flags.
 * Notes:
 *      These settings are platform dependent and are specified by the build
 *      This data is passed to cdk_dev_create().
 */

/* These defines must be specified for this sample to work in a real system */
#if !defined(SYS_BE_PIO) || !defined(SYS_BE_PACKET) || !defined(SYS_BE_OTHER)
#error PCI bus endian flags SYS_BE_PIO, SYS_BE_PACKET and SYS_BE_OTHER not defined
#endif

SINT32 swmdk_ppid;
static SINT32 sync_cont=0;
static void sighup_catcher()
{
   sync_cont=1;
}
static SINT32 c;

static uint32_t
_bus_flags(uint32_t bus_type)
{
    uint32_t flags = 0;

    if (bus_type == MBUS_SPI || bus_type == MBUS_HS_SPI) {
        flags = CDK_DEV_MBUS_SPI;
    } else if (bus_type == MBUS_MDIO) {
        flags = CDK_DEV_MBUS_MII;
    } else if (bus_type == MBUS_MMAP) {
        flags = CDK_DEV_MBUS_MII;
    } else {
        flags = CDK_DEV_MBUS_PCI;
    }

#if SYS_BE_PIO == 1
    flags |= CDK_DEV_BE_PIO;
#endif
#if SYS_BE_PACKET == 1
    flags |= CDK_DEV_BE_PACKET;
#endif
#if SYS_BE_OTHER == 1
    flags |= CDK_DEV_BE_OTHER;
#endif
    return flags;
}



/*
 * Function:
 *      _create_cdk_device
 * Purpose:
 *      This function creates a CDK device context
 * Parameters:
 *      vendor_id:      Vendor Id
 *      device_id:      Device Id
 *      rev_id:         Revision Id
 *      base_addr:      Physical Base Address of the device
 * Returns:
 *      Unit number >= 0 on success,
 *      -1 on failure.
 */

static int
_create_cdk_device(int unit, uint32_t vendor_id, uint32_t device_id, uint32_t rev_id,
   uint32_t base_addr, uint32_t bus_type, void *dvc, uint32_t pbmp, uint32_t phypbmp, int epon_port)
{
    /* Added unit as a passed in parameter - caller expect it to be the same unit as it is going to use further. */
    cdk_dev_id_t id;
    cdk_dev_vectors_t dv;
    int rc;

   /*
     * Setup the device identification structure
     */
    memset(&id, 0, sizeof(id));
    id.vendor_id = vendor_id;
    id.device_id = device_id;
    id.revision = rev_id;
    id.config_pbmp = pbmp;
    id.phy_pbmp = phypbmp;
	id.epon_port = epon_port;


    /*
     * Setup the device vectors structure
     */
    memset(&dv, 0, sizeof(dv));

    if ((bus_type == MBUS_SPI) || (bus_type == MBUS_HS_SPI)) {
      dv.dvc = dvc;
        dv.read = &linux_user_spi_read;
        dv.write = &linux_user_spi_write;
    } else if (bus_type == MBUS_MDIO) {
        dv.read = &linux_user_mdio_read;
        dv.write = &linux_user_mdio_write;
    } else if (bus_type == MBUS_MMAP){
        dv.read = &linux_user_mmap_read;
        dv.write = &linux_user_mmap_write;
    } else {
        dv.read = &linux_user_ubus_read;
        dv.write = &linux_user_ubus_write;
        /* mmap the physical address into our virtual address space */
        /* and provide this as the base address for the device */
//        dv.base_addr = _mmap(base_addr, 64*1024);
    }

    /*
     * Create the CDK Device Context
     */
    rc = cdk_dev_create_id(unit, &id, &dv, _bus_flags(bus_type));
    if(rc < 0) {
        fprintf(stderr, "cdk_dev_create: could not create device 0x%x:0x%x:0x%x @ 0x%x: %s (%d)\n",
                vendor_id, device_id, rev_id, base_addr,
                CDK_ERRMSG(rc), rc);
        exit(1);
    }

    /*
     * This unit is ready to use
     */
    return rc;
}

/*
 * Including Internal and External PHY Support in your system.
 * This enables PHY programming in the BMD and requires the PHY package.
 */

#if BMD_CONFIG_INCLUDE_PHY == 1

#include <phy/phy_drvlist.h>

#if 0
/*
 * Supported PHY drivers
 */
static phy_driver_t *phy_drv_list[] = {
    &bcmi_fusioncore_xgxs_drv,
    &bcmi_fusioncore12g_xgxs_drv,
    &bcmi_unicore_xgxs_drv,
    &bcmi_unicore16g_xgxs_drv,
    &bcmi_hypercore_xgxs_drv,
    &bcmi_hyperlite_xgxs_drv,
    &bcmi_xgs_serdes_drv,
    &bcmi_nextgen_serdes_drv,
    &bcmi_nextgen65_serdes_drv,
    &bcmi_combo_serdes_drv,
    &bcmi_combo65_serdes_drv,
    &bcmi_hyperlite_serdes_drv,
    &bcmi_unicore16g_serdes_drv,
    &bcm5228_drv,
    &bcm5238_drv,
    &bcm5248_drv,
    &bcm53314_drv,
    &bcm5395_drv,
    &bcm5421_drv,
    &bcm5461_drv,
    &bcm5464_drv,
    &bcm54684_drv,
    &bcm5482_drv,
    &bcm5488_drv,
    &bcm54980_drv,
    &bcm8705_drv,
    &bcm8706_drv,
    NULL
};
#endif

#define MAX_PHY_DRIVERS 10
static phy_driver_t *phy_drv_list[] = {
#if BRCM_EXT_SWITCH_TYPE == 63100
    &bcm63100_drv,
#endif
#if BRCM_EXT_SWITCH_TYPE == 53101
    &bcm53101_drv,
#endif
#if BRCM_EXT_SWITCH_TYPE == 53115
    &bcm53115_drv,
#endif
#if defined BCM_PHY_54616
    &bcm54616_drv,
#endif
    &bcm_generic_drv,
    NULL
};
#endif /* BMD_CONFIG_INCLUDE_PHY */

/* TBD: to use the defines in config.h files.  */
#define MAX_SWITCH_PORTS 8
int thread_lock = 1;
#if BMD_CONFIG_INCLUDE_PHY == 1
typedef struct link_poll_info_s {
    int unit;
    unsigned int phypbmp;
    unsigned int pbmp;
    unsigned int vendor_id;
} link_poll_info_t;
#endif


#ifdef BRCM_CMS_BUILD

static CmsLogLevel logLevel=DEFAULT_LOG_LEVEL;

static CmsRet swmdkCmsLogInit()
{

    cmsLog_initWithName(EID_SWMDK, "swmdk");
    cmsLog_setLevel(logLevel);

    /* detach from terminal and detach from smd session group. */
    if (setsid() < 0)
    {
        cmsLog_error("could not detach from terminal");
        return CMSRET_INTERNAL_ERROR;
    }

    /* ignore some common, problematic signals */
    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    return CMSRET_SUCCESS;
}
#endif  /* BRCM_CMS_BUILD */

#ifndef BRCM_CMS_BUILD
int oal_signalProcess(SINT32 pid, SINT32 sig)
{
   SINT32 rc;

   if (pid <= 0)
   {
      fprintf(stderr, "bad pid %d", pid);
      return CMSRET_INVALID_ARGUMENTS;
   }

   if ((rc = kill(pid, sig)) < 0)
   {
      fprintf(stderr, "invalid signal(%d) or pid(%d)", sig, pid);
      return CMSRET_INVALID_ARGUMENTS;
   }

   return CMSRET_SUCCESS;
}
#endif


#define ALIGNMENT_SIZE 3
static int num_switches = 0;
static unsigned int vendor_id, device_id, rev_id;
int main(int argc, char* argv[])
{
    int rv, unit, sw_idx;
    spi_device spi_dev;
    int bus_type;
    unsigned int base_addr = 0;
    unsigned int spi_id, spi_cid;
    unsigned int pbmp, phypbmp;
#if BMD_CONFIG_INCLUDE_PHY == 1
    pthread_t linkpoll_thread[BMD_CONFIG_MAX_UNITS];
    link_poll_info_t poll_info[BMD_CONFIG_MAX_UNITS];
    pthread_t mdkshell_thread;
#endif
    SINT32 pid;

    int epon_port;
    int sw_unit_map[BMD_CONFIG_MAX_UNITS] = {[0 ... (BMD_CONFIG_MAX_UNITS-1)] = -1};

/* CONFIG_MDK_BCA_BEGIN */

    swmdk_ppid = getpid();
    pid = fork();
    if (pid < 0)
    {
        printf("SWMDK could not fork!  Startup failed.\n");
        exit(-1);
    }

    if (pid  > 0)
    {
        /* Let parent process wait here to garantee SWMDK HW initialization 
            is done before SMD HW configuration */
        signal(SIGHUP, sighup_catcher);
        signal(SIGCHLD, sighup_catcher);
        for(; sync_cont == 0; sleep(1));
        exit(0);
    }

    while ((c = getopt(argc, argv, "v:m:")) != -1)
    {
       switch(c)
       {
#ifdef BRCM_CMS_BUILD
            case 'v':
            {
                SINT32 logLevelNum;
                logLevelNum = atoi(optarg);
                if (logLevelNum == 0)
                {
                    logLevel = LOG_LEVEL_ERR;
       }
                else if (logLevelNum == 1) 
    {
                    logLevel = LOG_LEVEL_NOTICE;
    }
                else
    {
                    logLevel = LOG_LEVEL_DEBUG;
    }
                break;
            }
#endif
            default:
                break;
        }
    }

    for(unit = 0; unit < BMD_CONFIG_MAX_UNITS; unit++) {
        bcm_get_switch_info(unit, &vendor_id, &device_id, &rev_id, &bus_type,
            &spi_id, &spi_cid, &pbmp, &phypbmp, &epon_port);
        if (rev_id != 0) {
            fprintf(stderr, "Note: forcing rev_id to zero for now \n");
            rev_id = 0;
        }
        if ((device_id & 0xfff0) == 0x6810) {
            fprintf(stderr, "Note: Loading 6816 MDK driver for %X chip \n", device_id);
            device_id = 0x6816;
        } else if (device_id == 0x6369) {
            fprintf(stderr, "Note: Loading 6368 MDK driver for 6369 chip \n");
            device_id = 0x6368;
        } 
        if ((unit == 0) && (device_id != 0x6816) && (device_id != 0x6368)){
            fprintf(stderr, "Note: Loading 6300 MDK (default) driver for %X chip \n", device_id);
            device_id = 0x6300;
        }
        if ((device_id == 0x5f24) && (vendor_id == 0x362)) {
            fprintf(stderr, "Note: Forcing 53115 driver for 53125 \n");
            device_id = 0xbf80;
            vendor_id = 0x0143;
        }
        if ((device_id == 0x5ed4) && (vendor_id == 0x362)) {  /* External switch 53101 support */
            fprintf(stderr, "Note: Forcing 53115 driver for 53101 \n");
            device_id = 0xbf80;
            vendor_id = 0x0143;
        }
	if (((device_id == 0x5100) || (device_id == 0x5350)) && (vendor_id == 0xae02)) {  /* External switch 53134 support */
            fprintf(stderr, "Note: Forcing 53115 driver for 53134 \n");
            device_id = 0xbf80;
            vendor_id = 0x0143;
        }

        if (bus_type != MBUS_NONE) {
            spi_dev.spi_id = spi_id;
            spi_dev.chip_id = spi_cid;
            /* Create the specified cdk device */
            rv = _create_cdk_device(unit, vendor_id, device_id, rev_id, base_addr,
                bus_type, (void *)&spi_dev, pbmp, phypbmp, epon_port);
            if (rv < 0)
                return -1;
            sw_unit_map[num_switches] = unit;  /* CDK device created - store the sw-unit to CDK-device map */
            num_switches++;
        }
    }

#if BMD_CONFIG_INCLUDE_PHY == 1
    bmd_phy_probe_init(bmd_phy_probe_default, phy_drv_list);
#endif

    printf("Switch MDK: num_switches = %d\n", num_switches);
    for(sw_idx = 0; sw_idx < num_switches; sw_idx++) {
        if(CDK_DEV_EXISTS(sw_unit_map[sw_idx])) {
            bmd_attach(sw_unit_map[sw_idx]);
            bmd_init(sw_unit_map[sw_idx]);
        } else {
            fprintf(stderr, "CDK Device %d was created but CDK_DEV_EXISTS failed \n", sw_unit_map[sw_idx]);
        }
    }

    if (num_switches <= 0)
       goto cleanup_n_exit;

#if BMD_CONFIG_INCLUDE_PHY == 1
    for(sw_idx = 0; sw_idx < num_switches; sw_idx++) {
        if(CDK_DEV_EXISTS(sw_unit_map[sw_idx])) {
            pbmp = CDK_DEV_CONFIG_PBMP(sw_unit_map[sw_idx]);
            phypbmp = CDK_DEV_PHY_PBMP(sw_unit_map[sw_idx]);
            if (pbmp) {  /* If the switch has any ports in-use; start the linkpoll */
                poll_info[sw_idx].unit = sw_unit_map[sw_idx];
                poll_info[sw_idx].phypbmp = phypbmp;
                poll_info[sw_idx].pbmp = pbmp;
                poll_info[sw_idx].vendor_id = CDK_DEV_VENDOR_ID(sw_unit_map[sw_idx]);
                pthread_create(&linkpoll_thread[sw_idx], NULL,
                   (void *)&link_poll_function, (void *)&poll_info[sw_idx]);
            }
            else
            {
                linkpoll_thread[sw_idx] = 0;
        }
    }
    }
#endif

/* 63268/6828 will always be in managed mode */
#if !defined(BRCM_PORTS_ON_INT_EXT_SW)
    if (num_switches > 1) { 
	/* Note : This is implicit assumption that if there are more than one switch - put all but last one in unmanaged mode */
        for(sw_idx = 0; sw_idx < num_switches-1; sw_idx++) {   
            printf("Initializing unit %d in unmanaged mode \n", sw_unit_map[sw_idx]);
            bmd_switching_init(sw_unit_map[sw_idx]);
        }
    }
#endif

    /* Notify parent process that SWMDK HW initialization is done now,
        it is safe to start further configuration on the top */
#ifdef BRCM_CMS_BUILD
    prctl_signalProcess(swmdk_ppid, SIGHUP);
#else
    oal_signalProcess(swmdk_ppid, SIGHUP);
#endif

#ifdef BRCM_CMS_BUILD
    if(swmdkCmsLogInit() != CMSRET_SUCCESS)
    {
        /* Cancel pthread generated */
        for(sw_idx = 0; sw_idx < num_switches; sw_idx++)
        {
            if(linkpoll_thread[sw_idx])
            {
                pthread_cancel(linkpoll_thread[sw_idx]);
            }
        }
        exit(-1);
    }
#endif

    /* start a mdkshell thread */
    if (num_switches > 0) {
        pthread_create(&mdkshell_thread, NULL,
                   (void *)&mdkshell_start, (void *)NULL);
    }
#if BMD_CONFIG_INCLUDE_PHY == 1
    for(sw_idx = 0; sw_idx < num_switches; sw_idx++) {
     if(linkpoll_thread[sw_idx]) {
            pthread_join(linkpoll_thread[sw_idx], NULL);
      }
    }
#endif

cleanup_n_exit:
#ifdef BRCM_CMS_BUILD
    cmsLog_cleanup();
#endif
    return 0;
}

#if BMD_CONFIG_INCLUDE_PHY == 1
#define USEC_PER_SEC 1000000
void link_poll_function(void *ptr)
{
    int unit, port, link, an, an_done, speed, duplex, prev_link, prev_dplx, phycfg = 0, setlink = 0;
    unsigned int linkChanged = 0;
    unsigned int prev_link_status_map = 0, mask, phypbmp;
    link_poll_info_t *pinfo = (link_poll_info_t *)ptr;
    unsigned int prev_duplex_status_map = 0;
    unsigned int prev_speed[MAX_SWITCH_PORTS] = {0};
    struct mdk_kernel_poll mdk_kernel_poll;
    unsigned int slept;

    unit = pinfo->unit;
    phypbmp = pinfo->phypbmp;
    printf("Switch MDK link poll thread: unit=%d; phypbmp=0x%x config_pbmp=0x%x\n", unit, phypbmp, pinfo->pbmp);

    for (port = 0; port < MAX_SWITCH_PORTS; port++) {
        bmd_port_mode_t mode = bmdPortModeDisabled;

        mask = 1 << port;
        if ((pinfo->pbmp & mask) & (~phypbmp & mask)) {
            bcm_phy_config_get(unit, port, &phycfg);
            setlink = 0;
            if (phycfg & PHY_LNK_CFG_VALID) {
                setlink = 1;
                link = 1;
                switch(phycfg & (PHY_LNK_CFG_M << PHY_LNK_CFG_S)) {
                    case FORCE_LINK_DOWN:
                        speed = 1000;
                        duplex = 1;
                        link = 0;
                        mode  = bmdPortModeDisabled;
                        break;

                    case FORCE_LINK_10HD:
                        speed = 10;
                        duplex = 0;
                        mode  = bmdPortMode10hd;
                        break;

                    case FORCE_LINK_10FD:
                        speed = 10;
                        duplex = 1;
                        mode  = bmdPortMode10fd;
                        break;

                    case FORCE_LINK_100HD:
                        speed = 100;
                        duplex = 0;
                        mode  = bmdPortMode100hd;
                        break;

                    case FORCE_LINK_200FD:
                        speed = 200;
                        duplex = 1;
                        mode  = bmdPortMode200fd;
                        /* Internal ROBO switch and SF2 does not support 200 link speed;
                           SF2 will support 200M based on the clock 25MHz or 50MHz */
                        if (unit == 0 || pinfo->vendor_id == BCM63100_VENDOR_ID) 
                        {
                            speed = 100;
                            duplex = 1;
                            mode  = bmdPortMode100fd;
                            printf ("WARNING : SWMDK : %s does not support 200 link speed; Overwriting to 100M\n",
                                    unit==0 ? "Internal ROBO" : "SF2");
                        }
                        break;

                    case FORCE_LINK_100FD:
                        speed = 100;
                        duplex = 1;
                        mode  = bmdPortMode100fd;
                        break;

                    case FORCE_LINK_1000FD:
                        speed = 1000;
                        duplex = 1;
                        mode  = bmdPortMode1000fd;
                        break;

                    default:
                        setlink = 0;
                        break;
                }
            }
            if (setlink) {
                bcm_set_linkstatus(unit, port, link, speed, duplex);
                bmd_port_mode_set(unit, port, mode, 0);
            }
        }
    }

    while(thread_lock) {
        bcm_ethsw_kernel_poll(&mdk_kernel_poll);
        linkChanged = mdk_kernel_poll.link_change;
        slept = 0;
        if(linkChanged) {
            for (port = 0; port < MAX_SWITCH_PORTS; port++) {
                mask = 1 << port;
                if (phypbmp & mask) {
                    int phy_link_changed = 0;
                    bmd_phy_link_get(unit, port, &link, &an_done);
                    bmd_phy_autoneg_get(unit, port, &an);
                    prev_link = (prev_link_status_map & mask) >> port;
                    if ((linkChanged & ETHSW_LINK_MIGHT_CHANGED) || (link != prev_link)) {
                        phy_link_changed = 1;
                    }
                    if (!an || phy_link_changed) {
                        prev_dplx = (prev_duplex_status_map & mask) >> port;
                        bmd_phy_duplex_get(unit, port, &duplex);
                        bmd_phy_speed_get(unit, port, (uint32_t *)&speed);
                        if  ((duplex != prev_dplx) || (speed != prev_speed[port])) {
                            phy_link_changed = 1;
                        }
                        if (!an) {
                            if (duplex != prev_dplx)
                                printf ("AutoNeg is disabled and Duplex has changed\n\n");
                            if (speed != prev_speed[port])
                                printf ("AutoNeg is disabled and Speed has changed\n\n");
                        }
                    }

                    if (phy_link_changed) {
                        bcm_set_linkstatus(unit, port, link, speed, duplex);
                        // link state upadate in MAC for RGMII MAC-Phy interfaces.
                        if (pinfo->vendor_id == 0x6300 || pinfo->vendor_id == BCM63100_VENDOR_ID)
                        {
                            bmd_port_mode_update(unit, port);
                        }
                        prev_link_status_map &= ~mask;
                        prev_link_status_map |= (link << port);
                        prev_duplex_status_map &= ~mask;
                        prev_duplex_status_map |= (duplex << port);
                        prev_speed[port] = speed;
                    }
                    usleep(USEC_PER_SEC/40);
                    if (slept < USEC_PER_SEC)
                        slept += USEC_PER_SEC/40;
                }
            }
        }

        usleep(USEC_PER_SEC - slept);
    }
    printf("link poll exiting... \n");
}
#endif

