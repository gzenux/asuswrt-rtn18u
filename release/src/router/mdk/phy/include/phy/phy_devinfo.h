
#ifndef __PHY_DEVINFO_H__
#define __PHY_DEVINFO_H__

/*******************************************************************************
 *
 * PHY_DEVINFO Header
 *
 * This header can be included in your source files to define a datastructure
 * describing all PHY drivers in the current configuration. 
 *
 * This is provided as a simple convenience when you want to work programmatically
 * with the current device configuration. 
 *
 * NOTE: This header declares a datastructure in the file including it. 
 *
 ******************************************************************************/

/*
 * This structure describes each device. 
 * It contains the fields available in the PHY_DEVLIST_ENTRY macro. 
 */
typedef struct phy_devinfo_s {
    
    /* 
     * The following members are populated directly from the 
     * PHY_DEVLIST_ENTRY macro. 
     *
     */
    const char* name; 
    const char* base_driver; 
    uint32_t flags; 
    const char* description; 
    
    /*
     * Custom member for your use
     */
#ifdef PHY_DEVINFO_CUSTOM_MEMBERS
    PHY_DEVINFO_CUSTOM_MEMBERS ;
#endif

    void* cookie; 

} phy_devinfo_t; 


#ifndef PHY_DEVINFO_TABLE_NAME
#define PHY_DEVINFO_TABLE_NAME phy_devinfo_table
#endif

#ifdef PHY_DEVINFO_DEFINE

/* Define the actual table */

phy_devinfo_t PHY_DEVINFO_TABLE_NAME [] = 
    
{
#define PHY_DEVLIST_ENTRY(_nm, _bd, _fl, _ds, _r0, _r1) \
{ #_nm, #_bd, _fl, _ds  },

#include <phy/phy_devlist.h>

        /* Last Entry */
        { NULL }

    };

#else

/* Extern the table. This should be defined elsewhere in your code with PHY_DEVINFO_DEFINE=1 */

extern phy_devinfo_t PHY_DEVINFO_TABLE_NAME []; 

#endif


#endif /* __PHY_DEVINFO_H__ */
