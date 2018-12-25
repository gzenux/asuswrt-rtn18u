/*******************************************************************************
 * $Id: dsyms.h,v 1.5 Broadcom SDK $
 * $Copyright$
 *
 * dsyms.h
 ******************************************************************************/



/*^*****************************************************************************
 * 
 * Dynamic Symbol Generator
 * 
 *
 ******************************************************************************/


#ifndef __DSYM_DSYM_H__
#define __DSYM_DSYM_H__

#include "options.h"

#include <cdk/cdk_symbols.h>
#include <cdk/cdk_dsymbols.h>
#include <cdk/cdk_device.h>
#include <stdio.h>

/*
 * These Structures are used to merge and describe all symbol data
 */


/*
 * The allsyms table stores all symbols found in all chips, 
 * and the per-chip pointers to these symbols. This will give
 * us a database of all possible symbols, and on which chips 
 * they exist. 
 *
 * Not all chips will support all symbols, so some per-chip
 * pointers will be missing. This is really the whole point
 * of the exercise. 
 */

typedef struct {
    /* Symbol Name */
    const char* name; 
    /* Array of symbol structures, one for each device */
    cdk_symbol_t symbols[cdkDevTypeCount]; 
    /* Offset into device's new symbol table for this symbol */
    uint32_t symbol_offsets[cdkDevTypeCount]; 
    /* Symbol Flags */
    unsigned int flags; 
    /* Array of all fields in these symbols */
    const char* fields[DSYM_MAX_FIELDS_PER_SYMBOL]; 
    /* Array of max fields sizes in these symbols */
    int fsizes[DSYM_MAX_FIELDS_PER_SYMBOL]; 
    /* Internal Flags processing */
    #define ALLSYM_IFLAG_SYMBOL_INDEXED 0x1
    #define ALLSYM_IFLAG_SYMBOL_32 0x2
    unsigned int iflags; 
} allsyms_t; 

extern allsyms_t* allsyms; /* Allocated as [DSYM_MAX_SYM_COUNT] */
extern int allsyms_count; 


/*
 * These tables store all information related to field names
 * and unique field layouts
 */

/* All Field Names */
extern const char** allfields; /* Allocated as [DSYM_MAX_FIELD_COUNT] */
extern int allfields_count; 


/* All Unique Field Layouts and the device symbols that use them */
typedef struct {
    cdk_field_info_t finfo[DSYM_MAX_FIELDS_PER_SYMBOL]; 
    int count; 
    const char* elements[cdkDevTypeCount][1024];     
} allfield_info_t; 

extern allfield_info_t* allfield_info; /* Allocated as [DSYM_MAX_SYM_COUNT] */
extern int allfield_entry_count; 


/*
 * Various Statistics about the symbols
 */
typedef struct dsym_stats_s {
    
    int sym_count; 
    int field_count; 

} dsym_stats_t; 

extern dsym_stats_t dsym_stats; 



/*******************************************************************************
 *q
 * Building Structures and Generating Files
 *
 ******************************************************************************/

/*
 * Retrieve the available chips.
 * These are all chips built into the image. 
 */
extern const char* dsym_chips[]; 

/*
 * Select a subset of chips to include in the generation.
 */
extern int dsym_include(int devtype, int include);
extern int dsym_included(int devtype); 
    
/* 
 * After this call, you may access
 * the generated structures above. 
 */
extern int dsym_build_structures(void); 


/*
 * Generate output files
 */

extern int dsym_gen_defs_header(FILE* fp, const char* name, const char* includes); 

extern int dsym_gen_field_objects(FILE* fp, const char* includes); 

extern int dsym_gen_field_header(FILE* fp, const char* name, const char* includes); 

extern int dsym_gen_chip_objects(FILE* fp, const char* includes); 

extern int dsym_gen_dispatch_objects(FILE* fp, const char* includes); 

extern int dsym_gen_dispatch_tables(FILE* fp, const char* includes); 

extern int dsym_gen_symbol_offset_header(FILE* fp, const char* name, const char* includes); 

extern int dsym_gen_string_header(FILE* fp, const char* name, const char* includes); 

extern int dsym_gen_string_file(FILE* fp, const char* includes); 

extern int dsym_gen_symbol_tables(FILE* fp, const char* includes);     

extern const char* dsym_devname(int dev); 

extern int dsym_list_symbols(FILE* fp); 

#endif /* __DSYM_DSYM_H__ */
