/******************************************************************************
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
 ******************************************************************************
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
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* CDK Package Headers */
#include <cdk_config.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_readline.h>
#include <cdk/cdk_shell.h>
#include <cdk/shell/chip_cmds.h>

#ifdef CDK_CONFIG_ARCH_ROBO_INSTALLED
#include <cdk/arch/robo_cmds.h>
#endif

#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED
#include <cdk/arch/xgs_cmds.h>
#endif

/* BMD Package Headers */
#include <bmd_config.h>
#include <bmd/bmd.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmd/shell/bmd_cmds.h>
/* PHY Package Headers */
#include <phy_config.h>
#include <phy/phy_drvlist.h>
#include "ethswctl_api.h"

#define ALIGNMENT_SIZE 3


#include <mdkshell_ipc.h>

static int pthread_rval;

#define TRUE 1
#define FALSE 0
int mdksh_sock_conn;

/* TBD: to use the defines in config.h files.  */
#define MAX_SWITCH_PORTS 8
/*
 * invoked by pthread creation.
 */
void mdkshell_start(void)
{
    int listen_sock;
    /* Initialize CDK Shell */
    cdk_shell_init();

    /* Add RoboSwitch architecture commands if installed */
#ifdef CDK_CONFIG_ARCH_ROBO_INSTALLED
    cdk_shell_add_robo_core_cmds();
#endif

    /* Add XGS architecture commands if installed */
#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED
    cdk_shell_add_xgs_core_cmds();
#endif

    /* Add BMD commands */
    bmd_shell_add_bmd_cmds();

    /* 
     * set up socket listener for connection requests
     */
    if ((listen_sock = mdksh_open_listener(MDKSH_SOCK_NAME)) < 0)
    {
        printf("%s Socket listener error \n", __FUNCTION__);
        pthread_rval = -1;
        pthread_exit((void *)&pthread_rval);
    }

           // write to socket, param is a null terminated print buffer.
    cdk_printhook = mdksh_writeline_to_socket;
    mdksh_sock_conn = -1;
    /*
     * If no active connection,  look for incoming connection.
     * else look for input from socket connection
     * If input command, parse it and synchonously diapatch it.
     * when mdkshell exits, mark connection inactive.
     */
    do  {
        if (mdksh_sock_conn < 0) {  // No active connection, accept new connection
    
            //printf("%s No Active connection, yet\n", __FUNCTION__);
            mdksh_sock_conn = mdksh_accept_conn(listen_sock); 
        }
        if (mdksh_sock_conn < 0) {
            //printf("%s No Active connection Found!!\n", __FUNCTION__);
        }  else {
#if defined(SUPPORT_RDPA)  /* Forcing the unit=1 for External switch on Runner based devices; there is no internal switch device unit#0 */
            cdk_shell_unit_set(1);
#else
            cdk_shell_unit_set(0);
#endif
            cdk_shell("MDK", mdksh_readline_from_socket);
            /* exit command is typed at shell prompt or an error occured. */
            close(mdksh_sock_conn);
            mdksh_sock_conn = -1;
            continue;
        }
    } while (TRUE);
    return ;
}
