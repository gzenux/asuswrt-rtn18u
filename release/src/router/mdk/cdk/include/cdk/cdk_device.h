/*
 * $Id: cdk_device.h,v 1.27 Broadcom SDK $
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
 *
 * CDK device manager
 */

#ifndef __CDK_DEVICE_H__
#define __CDK_DEVICE_H__

/*******************************************************************************
 *
 * CDK Device Manager
 *
 ******************************************************************************/

#include <cdk/cdk_chip.h>

/*
 * Features not found in all CDK versions.
 * These defines allow applications to be backward-compatible.
 */
#define CDK_DEV_HAS_CHIP_MODEL

/* 
 * Global device flags
 *
 * Note: 
 * Architecture type flags are defined in cdk_devlist.h
 */

/* Management bus flags */
#define CDK_DEV_MBUS_PCI        0x00000100
#define CDK_DEV_MBUS_SPI        0x00000200
#define CDK_DEV_MBUS_MII        0x00000400
/* Endian configuration flags */
#define CDK_DEV_BE_PIO          0x00010000
#define CDK_DEV_BE_PACKET       0x00020000
#define CDK_DEV_BE_OTHER        0x00040000
#define CDK_DEV_BE_HOST         0x000f0000

#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
    cdkDevType_##_bd,
typedef enum {
    cdkDevTypeNone = 0,
#include <cdk/cdk_devlist.h>
    cdkDevTypeCount
} cdk_dev_type_t;

#if CDK_CONFIG_MAX_PORTS < 128
/* Use char type for small size */
typedef signed char cdk_port_map_port_t;
#else
/* Use short type when number of ports is large */
typedef signed short cdk_port_map_port_t;
#endif

/* Dynamic port configuration */
typedef struct cdk_port_config_s {

    /* Maximum speed for this port */
    uint32_t speed_max;

    /* Special port features */
#define CDK_DCFG_PORT_F_EXT_QUEUE       0x00000001
    uint32_t port_flags;

    /* Default port mode */
#define CDK_DCFG_PORT_MODE_IEEE         0
#define CDK_DCFG_PORT_MODE_HIGIG        1
#define CDK_DCFG_PORT_MODE_HIGIG2       2
#define CDK_DCFG_PORT_MODE_HIGIG3       3
#define CDK_DCFG_PORT_MODE_HGLITE       4
#define CDK_DCFG_PORT_MODE_EHG          5
#define CDK_DCFG_PORT_MODE_LMD          6
    int port_mode;

    /* System port mapping */
    int sys_port;

    /* For application use (not used by driver) */
    int app_port;

} cdk_port_config_t;

/* Used for indexing array of cdk_port_config_t */
typedef char cdk_port_config_id_t;

/*
 * CDK Device Identification
 */
typedef struct cdk_dev_id_s {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t revision;
    uint16_t model;
/* CONFIG_MDK_BCA_BEGIN */
    /* Board Specific Info */
    uint32_t config_pbmp;
    uint32_t phy_pbmp;
	int epon_port;
/* CONFIG_MDK_BCA_END */
} cdk_dev_id_t; 

/*
 * CDK Device Vectors
 */
typedef struct cdk_dev_vectors_s {

    /* Context pointer for device vector functions */
    void *dvc;

    /* Device base address (if memory mapped) */
    volatile uint32_t *base_addr;

    /* Register read/write vectors for 32-bit register entities */
    int (*read32)(void *dvc, uint32_t addr, uint32_t *data); 
    int (*write32)(void *dvc, uint32_t addr, uint32_t data); 

    /* Register read/write vectors for arbitrary register widths */
    int (*read)(void *dvc, uint32_t addr, uint8_t *data, uint32_t len); 
    int (*write)(void *dvc, uint32_t addr, const uint8_t *data, uint32_t len); 

} cdk_dev_vectors_t; 

/*
 * CDK Device
 */
typedef struct cdk_dev_s {

    int unit;

    /* Device identification */
    cdk_dev_id_t id;

    /* Hardware access */
    cdk_dev_vectors_t dv;

    /* Global chip flags */
    uint32_t flags;

    /* Device name and type*/
    char *name;
    cdk_dev_type_t type;
        
    /* Architecture-specific chip info */
    void *chip_info;

    /* Valid ports for this chip */
    cdk_pbmp_t valid_pbmps; 

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1
    /* Logical to physical port map */
    int port_map_size;
    cdk_port_map_port_t *port_map;
#endif

#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1
    /* Dynamic chip configuration for multi-mode devices */
    uint32_t chip_config;
    int num_port_configs;
    cdk_port_config_t *port_configs;
    cdk_port_config_id_t port_config_id[CDK_CONFIG_MAX_PORTS];
#endif

} cdk_dev_t; 

/*
 * Additional probing information.
 *
 * For some devices it is necessary to read additional device
 * registers to distinguish models/bond-outs. Since this extra
 * informtion is sometimes obtained in different ways for
 * different device families, we need a way to provide the
 * access information (register location, size, etc.).
 */
typedef struct cdk_dev_probe_info_s {
    /* Architecture-dependent info on how to obtain chip model */
    uint32_t model_info;
} cdk_dev_probe_info_t;

/*
 * Global device structure
 */
/* CONFIG_MDK_BCA_BEGIN */
#ifdef BCM_MDK_OS_DEP
extern cdk_dev_t *cdk_device;
#else
extern cdk_dev_t cdk_device[CDK_CONFIG_MAX_UNITS];
#endif
/* CONFIG_MDK_BCA_END */

/*
 * Special address used for directing reads and writes
 * to an Ethernet device driver, e.g. for use with an
 * in-band management port (IMP).
 */
#define CDK_DEV_ADDR_ETH        0xffff0000
/*
 * Special address used for external PHY bus of MDIO interface
 */
#define CDK_DEV_ADDR_EXT_PHY_BUS_MDIO    0xfffe0000

/*
 * Device structure access
 */
#define CDK_DEV(_u) (&cdk_device[_u])
#define CDK_DEV_TYPE(_u) (cdk_device[_u].type)
#define CDK_DEV_FLAGS(_u) (cdk_device[_u].flags)
#define CDK_DEV_VECT(_u) (&cdk_device[_u].dv)
#define CDK_DEV_DVC(_u) cdk_device[_u].dv.dvc
#define CDK_DEV_BASE_ADDR(_u) cdk_device[_u].dv.base_addr
/* CONFIG_MDK_BCA_BEGIN */
#define CDK_DEV_CONFIG_PBMP(_u) (cdk_device[_u].id.config_pbmp)
#define CDK_DEV_PHY_PBMP(_u) (cdk_device[_u].id.phy_pbmp)
#define CDK_DEV_VENDOR_ID(_u) (cdk_device[_u].id.vendor_id)
#define CDK_DEV_GET_EPON_PORT(_u) (cdk_device[_u].id.epon_port)

/* CONFIG_MDK_BCA_END */

/*
 * Device and unit checks
 */
#define CDK_UNIT_VALID(_u) (_u >= 0 && _u < CDK_CONFIG_MAX_UNITS)
#define CDK_DEV_EXISTS(_u) \
    (CDK_UNIT_VALID(_u) && CDK_DEV_TYPE(_u) != cdkDevTypeNone)

/*
 * Device register access
 */
#if CDK_CONFIG_MEMMAP_DIRECT == 1
#define CDK_DEV_READ32(_u,addr,pval) \
    (*(pval) = (CDK_DEV_BASE_ADDR(_u)[(addr)/4]), 0)
#define CDK_DEV_WRITE32(_u,addr,val) \
    ((CDK_DEV_BASE_ADDR(_u)[(addr)/4]) = val, 0)
#else
#define CDK_DEV_READ32(_u,addr,pval) \
    (cdk_dev_read32(_u,addr,pval))
#define CDK_DEV_WRITE32(_u,addr,val) \
    (cdk_dev_write32(_u,addr,val))
#endif /* CDK_CONFIG_MEMMAP_DIRECT */

/* Helper functions for port physical/logical conversion */
extern int cdk_dev_lport_get(int unit, int pport);
extern int cdk_dev_pport_get(int unit, int lport);

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1

#define CDK_PORT_MAP_LPORT_MAX 255

/* Macros for driver */
#define CDK_PORT_MAP_P2L(_u,_p) cdk_dev_lport_get(_u,_p)
#define CDK_PORT_MAP_L2P(_u,_p) cdk_dev_pport_get(_u,_p)

/* Macros for application */
#define CDK_PORT_MAP_SET(_u,_pm,_sz) \
do { \
    if ((_u) < CDK_CONFIG_MAX_UNITS) { \
        CDK_DEV(_u)->port_map = _pm; \
        CDK_DEV(_u)->port_map_size = _sz; \
    } \
} while(0)

#else

#define CDK_PORT_MAP_LPORT_MAX (CDK_CONFIG_MAX_PORTS-1)

#define CDK_PORT_MAP_P2L(_u,_p) (_p)
#define CDK_PORT_MAP_L2P(_u,_p) (_p)

#define CDK_PORT_MAP_SET(_u,_pm,_sz)

#endif

/* Helper functions for extracting port configuration */
extern uint32_t cdk_dev_port_speed_max_get(int unit, int port);
extern uint32_t cdk_dev_port_flags_get(int unit, int port);
extern int cdk_dev_port_mode_get(int unit, int port);
extern int cdk_dev_sys_port_get(int unit, int port);

#if CDK_CONFIG_INCLUDE_DYN_CONFIG == 1

/* Macros for driver */
#define CDK_CHIP_CONFIG(_u) CDK_DEV(_u)->chip_config
#define CDK_NUM_PORT_CONFIGS(_u) CDK_DEV(_u)->num_port_configs
#define CDK_PORT_CONFIG_SPEED_MAX(_u,_p) cdk_dev_port_speed_max_get(_u,_p)
#define CDK_PORT_CONFIG_PORT_FLAGS(_u,_p) cdk_dev_port_flags_get(_u,_p)
#define CDK_PORT_CONFIG_PORT_MODE(_u,_p) cdk_dev_port_mode_get(_u,_p)
#define CDK_PORT_CONFIG_SYS_PORT(_u,_p) cdk_dev_sys_port_get(_u,_p)

/* Macros for application */
#define CDK_CHIP_CONFIG_SET(_u,_c) \
do { \
    if ((_u) < CDK_CONFIG_MAX_UNITS) { \
        CDK_DEV(_u)->chip_config = _c; \
    } \
} while(0)

#define CDK_PORT_CONFIGS_SET(_u,_c,_n) \
do { \
    if ((_u) < CDK_CONFIG_MAX_UNITS) { \
        CDK_DEV(_u)->port_configs = _c; \
        CDK_DEV(_u)->num_port_configs = _n; \
    } \
} while(0)

#define CDK_PORT_CONFIG_ID_SET(_u,_p,_id) \
do { \
    if ((_u) < CDK_CONFIG_MAX_UNITS && (_id) < CDK_CONFIG_MAX_PORTS) { \
        CDK_DEV(_u)->port_config_id[_p] = _id; \
    } \
} while(0)

#else

#define CDK_CHIP_CONFIG(_u) ((uint32_t)0)
#define CDK_NUM_PORT_CONFIGS(_u) 0
#define CDK_PORT_CONFIG_SPEED_MAX(_u,_p) ((uint32_t)0)
#define CDK_PORT_CONFIG_PORT_FLAGS(_u,_p) ((uint32_t)0)
#define CDK_PORT_CONFIG_PORT_MODE(_u,_p) -1
#define CDK_PORT_CONFIG_SYS_PORT(_u,_p) -1

#define CDK_CHIP_CONFIG_SET(_u,_c)
#define CDK_PORT_CONFIGS_SET(_u,_c,_n)
#define CDK_PORT_CONFIG_ID_SET(_u,_p,_id)

#endif

#define CDK_LPORT_ITER(_u,_pbmp,_lp,_p) \
   for (_lp = 0; _lp < CDK_PORT_MAP_LPORT_MAX; _lp++) \
       if ((_p = CDK_PORT_MAP_L2P(_u, _lp)) >= 0 && \
           CDK_PBMP_MEMBER(_pbmp, _p))

/*
 * Create CDK device
 */
extern int 
cdk_dev_create_id(int unit, cdk_dev_id_t *id, cdk_dev_vectors_t *dv, uint32_t flags);

extern int 
cdk_dev_create(cdk_dev_id_t *id, cdk_dev_vectors_t *dv, uint32_t flags);

/*
 * Destroy CDK device
 */
extern int 
cdk_dev_destroy(int unit);

/*
 * Read a device register
 */
extern int
cdk_dev_read32(int unit, uint32_t addr, uint32_t *val);

extern int    
cdk_dev_read(int unit, uint32_t addr, uint8_t *data, uint32_t len);

/*
 * Write a device register
 */
extern int    
cdk_dev_write32(int unit, uint32_t addr, uint32_t val); 

extern int    
cdk_dev_write(int unit, uint32_t addr, uint8_t *data, uint32_t len);

/*
 * Extra device probing info
 */
extern int 
cdk_dev_probe_info_get(cdk_dev_id_t *id, cdk_dev_probe_info_t *pi);

#endif /* __CDK_DEVICE_H__ */
