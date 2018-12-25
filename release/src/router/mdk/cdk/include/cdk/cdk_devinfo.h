/*
 * $Id: cdk_devinfo.h,v 1.7 Broadcom SDK $
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

#ifndef __CDK_DEVINFO_H__
#define __CDK_DEVINFO_H__

#include <cdk/cdk_device.h>
#include <cdk/cdk_symbols.h>

/*******************************************************************************
 *
 * CDK_DEVINFO Header
 *
 * This header can be included in your source files to define a datastructure
 * describing all devices in the current configuration. 
 *
 * This is provided as a simple convenience when you want to work programmatically
 * with the current device configuration. 
 *
 * NOTES:
 *      This header declares a datastructure in the file including it. 
 *
 ******************************************************************************/

/*
 * This structure describes each device. 
 * It contains the fields available in the CDK_DEVLIST_ENTRY macro. 
 */
typedef struct cdk_devinfo_s {
    
    /* 
     * The following members are populated directly from the 
     * CDK_DEVLIST_ENTRY macro. 
     *
     */
    cdk_dev_type_t dev_type; 
    const char* name; 
    uint32_t vendor_id; 
    uint32_t device_id; 
    uint32_t revision_id; 
    uint32_t model; 
    uint32_t probe_info; 
    const char* base_driver; 
    const char* base_configuration; 
    const char* fullname;     
    uint32_t flags; 
    const char* codename; 
    const char* product_family; 
    const char* description; 
    

#ifdef CDK_DEVINFO_INCLUDE_SYMBOLS
    /*
     * This device's symbol table. You will need to link against
     * the sym library or include the allsyms.c file. 
     */
    cdk_symbols_t* syms; 
#endif


    /*
     * Custom member for your use
     */
#ifdef CDK_DEVINFO_CUSTOM_MEMBERS
    CDK_DEVINFO_CUSTOM_MEMBERS ;
#endif

    void* cookie; 

} cdk_devinfo_t; 


/*
 * This is the default name for the generated table. 
 * Override if necessary. 
 */
#ifndef CDK_DEVINFO_TABLE_NAME
#define CDK_DEVINFO_TABLE_NAME cdk_devinfo_table
#endif

#ifdef CDK_DEVINFO_DEFINE

/* Define the actual table */

#ifdef CDK_DEVINFO_INCLUDE_ALL
#define CDK_DEVLIST_INCLUDE_ALL
#endif

cdk_devinfo_t CDK_DEVINFO_TABLE_NAME [] = 
    {
#ifdef CDK_DEVINFO_INCLUDE_SYMBOLS
#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
{ cdkDevType_##_bd, #_nm, _vn, _dv, _rv, _md, _pi, #_bd, #_bc, #_fn, _fl, _cn, _pf, _pd, &_bd##_symbols},
#else
#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
{ cdkDevType_##_bd, #_nm, _vn, _dv, _rv, _md, _pi, #_bd, #_bc, #_fn, _fl, _cn, _pf, _pd },
#endif

#include <cdk/cdk_devlist.h>

        /* Last Entry */
        { cdkDevTypeCount, NULL }

    };

#else

/* Extern the table. This should be defined elsewhere in your code with CDK_DEVINFO_DEFINE=1 */

extern cdk_devinfo_t CDK_DEVINFO_TABLE_NAME []; 

#endif


#endif /* __CDK_DEVINFO_H__ */
