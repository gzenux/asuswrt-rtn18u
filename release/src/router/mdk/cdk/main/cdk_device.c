/*
 * $Id: cdk_device.c,v 1.18 Broadcom SDK $
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

#include <cdk/cdk_device.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_error.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

typedef int (*cdk_chip_setup_f)(cdk_dev_t *dev);

/* Externs for the required functions */
#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
extern int _bc##_setup(cdk_dev_t *dev);
#define CDK_DEVLIST_INCLUDE_ALL
#include <cdk/cdk_devlist.h>

#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
    { _vn, _dv, _rv, _md, #_nm, cdkDevType_##_bd, _fl, _bc##_setup },
#define CDK_DEVLIST_INCLUDE_ALL
static struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t revision;
    uint16_t model;
    char *name;
    cdk_dev_type_t type;
    uint32_t flags;
    cdk_chip_setup_f setup;
} dev_table[] = {
#include <cdk/cdk_devlist.h>
    { 0, 0 } /* end-of-list */
};

/*
 * Global device structure
 */
/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
cdk_dev_t *cdk_device;
#else
cdk_dev_t cdk_device[CDK_CONFIG_MAX_UNITS];
#endif
/* CONFIG_MDK_BCA_END */

/*
 * Create CDK device
 */
int 
cdk_dev_create_id(int unit, cdk_dev_id_t *id, cdk_dev_vectors_t *dv, uint32_t flags)
{
    cdk_dev_t *dev;
    int idx, match_idx, rev;
    int rv = CDK_E_NOT_FOUND;

    if (unit < 0 || unit >= CDK_CONFIG_MAX_UNITS) {
        return CDK_E_UNIT;
    }
    if (CDK_DEV_TYPE(unit) != cdkDevTypeNone) {
        return CDK_E_EXISTS;
    }

    match_idx = -1;
    idx = 0;
    rev = -1;
    while (dev_table[idx].vendor_id) {
        if (id->vendor_id == dev_table[idx].vendor_id &&
            id->device_id == dev_table[idx].device_id &&
            id->model == dev_table[idx].model) {
            /* 
             * Vendor/device ID may match multiple entries,
             * so we look for highest matching revision.
             */
            if (id->revision >= dev_table[idx].revision &&
                rev < dev_table[idx].revision) {
                /* Found a (better) match */
                match_idx = idx;
                rev = dev_table[idx].revision;
            }
        }
        idx++;
    }
    if (match_idx >= 0) {
        /* Warn about possible incompatibility */
        if (id->revision > dev_table[match_idx].revision) {
            CDK_WARN(("Warning[%d]: Device revision (0x%02x) is newer "
                      "than driver revision (0x%02x)\n",
                      unit, id->revision, dev_table[match_idx].revision));
        }
        dev = &cdk_device[unit];
        /* Fill out device structure */
        CDK_MEMCPY(&dev->id, id, sizeof(*id));
        CDK_MEMCPY(&dev->dv, dv, sizeof(*dv));
        dev->unit = unit;
        dev->name = dev_table[match_idx].name;
        dev->type = dev_table[match_idx].type;
        dev->flags = dev_table[match_idx].flags | flags;
        /* Perform device-specific software setup */
        if ((rv = dev_table[match_idx].setup(dev)) < 0) {
            CDK_MEMSET(dev, 0, sizeof(*dev));
        } else {
            CDK_DEBUG_DEV(("cdk_dev_create[%d]: Created new device %s\n", 
                           unit, dev->name)); 
        }
    }

    /* Return an error on failure or the new unit number when successful */
    return (rv < 0) ? rv : unit; 
}

int 
cdk_dev_create(cdk_dev_id_t *id, cdk_dev_vectors_t *dv, uint32_t flags)
{
    int unit;

    for (unit = 0; unit < CDK_CONFIG_MAX_UNITS; unit++) {
        if (CDK_DEV_TYPE(unit) == cdkDevTypeNone) {
            break;
        }
    }
    if (unit == CDK_CONFIG_MAX_UNITS) {
        return CDK_E_RESOURCE;
    }

    return cdk_dev_create_id(unit, id, dv, flags);
}

int 
cdk_dev_destroy(int unit)
{
    if (CDK_DEV_EXISTS(unit)) {
        CDK_DEV_TYPE(unit) = cdkDevTypeNone;
        return CDK_E_NONE;
    }

    return CDK_E_NOT_FOUND;
}
