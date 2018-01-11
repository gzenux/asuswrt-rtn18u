
#ifndef __BMD_DEVINFO_H__
#define __BMD_DEVINFO_H__

#include <bmd/bmd_device.h>
#include <bmdi/bmd_devtype.h>

/*******************************************************************************
 *
 * BMD_DEVINFO Header
 *
 * This header can be included in your source files to define a datastructure
 * describing all BMD devices in the current configuration. 
 *
 * This is provided as a simple convenience when you want to work programmatically
 * with the current device configuration. 
 *
 * NOTE: This header declares a datastructure in the file including it. 
 *
 ******************************************************************************/

/*
 * This structure describes each device. 
 * It contains the fields available in the BMD_DEVLIST_ENTRY macro. 
 */
typedef struct bmd_devinfo_s {
    
    /* 
     * The following members are populated directly from the 
     * BMD_DEVLIST_ENTRY macro. 
     *
     */
    bmd_dev_type_t dev_type; 
    const char* name; 
    uint32_t vendor_id; 
    uint32_t device_id; 
    uint32_t revision_id; 
    const char* base_driver; 
    const char* base_configuration; 
    const char* fullname;     
    uint32_t flags; 
    const char* codename; 
    const char* product_family; 
    const char* description; 
    
    /*
     * Custom member for your use
     */
#ifdef BMD_DEVINFO_CUSTOM_MEMBERS
    BMD_DEVINFO_CUSTOM_MEMBERS ;
#endif

    void* cookie; 

} bmd_devinfo_t; 

#ifndef BMD_DEVINFO_TABLE_NAME
#define BMD_DEVINFO_TABLE_NAME bmd_devinfo_table
#endif

#ifdef BMD_DEVINFO_DEFINE

/* Define the actual table */

bmd_devinfo_t BMD_DEVINFO_TABLE_NAME [] = 
    
{
#define BMD_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
{ cdkDevType_##_bd, #_nm, _vn, _dv, _rv, #_bd, #_bc, #_fn, _fl, _cn, _pf, _pd },

#include <bmdi/bmd_devlist.h>

        /* Last Entry */
        { bmdDevTypeCount, NULL }

    };

#else

/* Extern the table. This should be defined elsewhere in your code with BMD_DEVINFO_DEFINE=1 */

extern bmd_devinfo_t BMD_DEVINFO_TABLE_NAME []; 

#endif


#endif /* __BMD_DEVINFO_H__ */
