/*
 * $Id: cdk_dsymbols.c,v 1.11 Broadcom SDK $
 * $Copyright: Copyright 2009 Broadcom Corporation.
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
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$1,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 */

/*******************************************************************************
 *
 * CDK Dynamic Symbol Routines
 *
 *
 ******************************************************************************/

#include <cdk/cdk_dsymbols.h>
#include <cdk/cdk_symbols.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_field.h>
#include <cdk/cdk_error.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_printf.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_debug.h>

#ifndef CDK_CONFIG_INCLUDE_DSYM_NAMES
#define CDK_CONFIG_INCLUDE_DSYM_NAMES           0
#endif

#ifndef CDK_CONFIG_INCLUDE_DSYM_FIELD_NAMES
#define CDK_CONFIG_INCLUDE_DSYM_FIELD_NAMES     0
#endif

#ifndef CDK_CONFIG_INCLUDE_DSYM_IDS
#define CDK_CONFIG_INCLUDE_DSYM_IDS             0
#endif

#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED

#include <cdk/arch/xgs_mem.h>
#include <cdk/arch/xgs_reg.h>

#endif /* CDK_CONFIG_ARCH_XGS_INSTALLED */


#ifdef CDK_CONFIG_ARCH_ROBO_INSTALLED

#include <cdk/arch/robo_mem.h>
#include <cdk/arch/robo_reg.h>

#endif /* CDK_CONFIG_ARCH_ROBO_INSTALLED */


/*
 * The following are the memory and register read/write vectors
 * defined for each architecture. 
 */

typedef int (*arch_mem_read)(int unit, uint32_t addr, uint32_t idx, void* vptr, int size); 
typedef int (*arch_mem_write)(int unit, uint32_t addr, uint32_t idx, void* vptr, int size); 
typedef int (*arch_reg_read)(int unit, uint32_t addr, void *data, int size); 
typedef int (*arch_reg_write)(int unit, uint32_t addr, void *data, int size); 
typedef int (*arch_reg_port_read)(int unit, int port, uint32_t addr, void *vptr, int size);
typedef int (*arch_reg_port_write)(int unit, int port, uint32_t addr, void *vptr, int size);
typedef int (*arch_reg_blocks_read)(int unit, uint32_t flags, int port, uint32_t addr, void *vptr, int size);
typedef int (*arch_reg_blocks_write)(int unit, uint32_t flags, int port, uint32_t addr, void *vptr, int size);

struct {

    arch_mem_read mem_read; 
    arch_mem_write mem_write; 
    arch_reg_read reg_read; 
    arch_reg_write reg_write; 
    arch_reg_port_read reg_port_read; 
    arch_reg_port_write reg_port_write; 
    arch_reg_blocks_read reg_blocks_read; 
    arch_reg_blocks_write reg_blocks_write; 

} _arch_vectors[] = 

    {

        /* This table MUST be indexable by (CDK_DEV_ARCH_FLAG - 1) */

        /* CDK_DEV_ARCH_ROBO 0x1 */
        {
#ifdef CDK_CONFIG_ARCH_ROBO_INSTALLED
            cdk_robo_mem_read, 
            cdk_robo_mem_write,
            cdk_robo_reg_read, 
            cdk_robo_reg_write, 
            cdk_robo_reg_port_read, 
            cdk_robo_reg_port_write,
            NULL,
            NULL
#else
            NULL
#endif /* CDK_CONFIG_ARCH_ROBO_INSTALLED */
        },
        
        /* CDK_DEV_ARCH_XGS 0x2 */
        {
#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED
            cdk_xgs_mem_read, 
            cdk_xgs_mem_write, 
            (arch_reg_read) cdk_xgs_reg_read, 
            (arch_reg_write) cdk_xgs_reg_write, 
            cdk_xgs_reg_port_read, 
            cdk_xgs_reg_port_write,
            cdk_xgs_reg_blocks_read, 
            cdk_xgs_reg_blocks_write
#else
            NULL
#endif /* CDK_CONFIG_ARCH_XGS_INSTALLED */       
        },
    }; 

/*
 * These macros are used to index the above vector tables based on device architecture. 
 */
#define VINDEX(unit) ((CDK_DEV_FLAGS(unit) & CDK_DEV_ARCH_MASK) - 1)
#define VECTORS(unit) _arch_vectors[VINDEX(unit)]


/*
 * Find the requested symbol and field for a given device. 
 */
static int
_dsym_entry(int unit, cdk_dsymbol_t* dispatch[], int* fid, cdk_dsymbol_t** dp, cdk_field_info_t* fp)
{
    cdk_dsymbol_t* d; 
    cdk_field_info_t finfo; 
    cdk_dsym_multifield_t mf; 
    int i;
#ifdef CONFIG_MDK_BCA
    extern cdk_dsym_multifield_t dsym_multifield_map[]; 
#endif

    CDK_ASSERT(CDK_UNIT_VALID(unit));
    
    d = dispatch[CDK_DEV_TYPE(unit)-1]; 

    if(d->addr == 0xFFFFFFFF) {
        /* This entry is not valid on this device */
        return CDK_E_UNAVAIL; 
    }   
   
    if(dp) {
        *dp = d; 
    }
    
    /* Find the requested field if specified */
    if(fid == NULL) {
        /* Only requesting the symbol */
        return 0; 
    }       
           
    /*
     * Find the requested field id(s)
     */
#ifdef CONFIG_MDK_BCA
    if(*fid & CDK_DSYM_FLAG_MULTIFIELD) {
        /* This can be any fid in the multifield group */
        mf = dsym_multifield_map[*fid - CDK_DSYM_FLAG_MULTIFIELD]; 
    }   
    else 
#endif
    {
        mf.fids[0] = *fid;
        mf.fids[1] = -1; 
    }   
        
    for(i = 0; mf.fids[i] != -1; i++) {
        
        CDK_SYMBOL_FIELDS_ITER_BEGIN(d->fields, finfo, NULL) {
        
            if(finfo.fid == mf.fids[i]) {
                /* Field exists */
                if(fp) {
                    *fp = finfo; 
                }   
                return 0; 
            }               
        
        } CDK_SYMBOL_FIELDS_ITER_END(); 
    }   

    /* If we get here, the field doesn't exist */
    /* Return an fid appropriate for debug information */
    *fid = mf.fids[0]; 
    return CDK_E_BADID; 
}       

              
/*
 * Find and validate the requested symbol and field. 
 * Outputs and error message and ABORTs if they are not found. 
 */
static void
_dsym_entry_valid(int unit, cdk_dsymbol_t* dispatch[], int fid, cdk_dsymbol_t** dp, cdk_field_info_t* fp, 
                  const char* file, int line)
{
    int rc; 

    if((rc = _dsym_entry(unit, dispatch, (fid == -1) ? NULL : &fid, dp, fp)) < 0) {

        /* 
         * Some kind of error. Prepare debug information. 
         */
        char scratch[64]; 
        const char* sname;  

        cdk_dev_t* dev = CDK_DEV(unit); 

        /* In case debug info is compiled out */
        COMPILER_REFERENCE(dev);

        /*
         * If no debug information is present, the best we can do is output the address of the dispatch table. 
         * This can be cross-referenced with the linker map to determine the name of the symbol. 
         */
        CDK_SPRINTF(scratch, "(address %p)", (void *)dispatch); 
        sname = scratch; 



#if CDK_CONFIG_DSYMS_USE_SYMTAB == 1

        /*
         * The dispatch pointer is actually a pointer to a cdk_symbol_t structure. 
         * This structure contains the name of the symbol. 
         */
        sname = ((cdk_symbol_t*)dispatch[CDK_DEV_TYPE(unit)-1])->name; 

#else /* CDK_CONFIG_DSYMS_USE_SYMTAB */

#if CDK_CONFIG_INCLUDE_DSYM_NAMES == 1
        
        /*
         * The last entry of this dispatch table is a string pointer. 
         */
        sname = (char*) dispatch[cdkDevTypeCount-1]; 
#endif

#endif
        
        /*
         * Output debug message based on error 
         */
        CDK_ERR(("FATAL: Request to program non-existant ")); 

        switch (rc)
            {

            case CDK_E_UNAVAIL:
                {                    
                    /*
                     * This symbol does not exist on this device. 
                     */
                    CDK_ERR(("symbol %s ", sname)); 
                    break; 
                }

            case CDK_E_BADID:
                {
                    /* Symbol exists, but the field does not */

#if CDK_CONFIG_INCLUDE_DSYM_FIELD_NAMES == 1
                    /*
                     * The mapping between field names and field ids was generated by
                     * the dsym program and stored in the following table:
                     */
                    extern const char* cdk_dsym_field_names[]; 
                    CDK_ERR(("field %s in symbol %s ", cdk_dsym_field_names[fid], sname)); 
#else
                    CDK_ERR(("field %d in symbol %s ", fid, sname)); 
#endif
                    break;
                }       
            default:
                {
                    /* Should not be here */
                    CDK_ERR(("<unknown error %d> ", rc)); 
                    break; 
                }
            }   


        if(file) {
            CDK_ERR(("at %s:%d ", file, line)); 
        }       
        
        CDK_ERR(("on unit %d (devtype=%d name=%s dev=0x%.4x rev=0x%.2x)\n", 
                 unit, CDK_DEV_TYPE(unit), dev->name, dev->id.device_id, dev->id.revision)); 
        CDK_ABORT(); 
    }
}       


static int
_word_aligned_bytes(int size)
{
    while(size%4) size++; 
    return size; 
}       

static int
_sword_size(cdk_dsymbol_t* s)
{
    return _word_aligned_bytes(CDK_SYMBOL_INDEX_SIZE_GET(s->index))/4; 
}


int 
cdk_dsym_mem_read(int unit, int idx, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                  const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).mem_read(unit, d->addr, idx, dst, _sword_size(d)); 
}       

int 
cdk_dsym_mem_write(int unit, int idx, cdk_dsymbol_t* dispatch[], uint32_t* src,
                   const char* file, int line)

{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).mem_write(unit, d->addr, idx, src, _sword_size(d)); 
}       

int
cdk_dsym_reg_read(int unit, cdk_dsymbol_t* dispatch[], uint32_t* dst,
                  const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_read(unit, d->addr, dst, _sword_size(d)); 
}


int
cdk_dsym_reg_write(int unit, cdk_dsymbol_t* dispatch[], uint32_t* src,
                   const char* file, int line)
{
    cdk_dsymbol_t* d; 
    CDK_UNIT_CHECK(unit); 

    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_write(unit, d->addr, src, _sword_size(d)); 
}

int
cdk_dsym_port_reg_read(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* dst,
                       const char* file, int line)
{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line);
    return VECTORS(unit).reg_port_read(unit, p, d->addr+offset, dst, _sword_size(d)); 
}

int
cdk_dsym_port_reg_write(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* src,
                        const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_port_write(unit, p, d->addr+offset, src, _sword_size(d)); 
}

int
cdk_dsym_blocks_reg_read(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                         const char* file, int line)
{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line) ;
    return VECTORS(unit).reg_blocks_read(unit, d->flags, p+offset, d->addr, dst, _sword_size(d)); 
}

int
cdk_dsym_blocks_reg_write(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* src,
                          const char* file, int line) 
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_blocks_write(unit, d->flags, p+offset, d->addr, src, _sword_size(d)); 
}

int
cdk_dsym_indexed_reg_read(int unit, int i, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                          const char* file, int line)
{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_read(unit, d->addr+i, dst, _sword_size(d)); 
}

int
cdk_dsym_indexed_reg_write(int unit, int i, cdk_dsymbol_t* dispatch[], uint32_t* src, 
                           const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return VECTORS(unit).reg_write(unit, d->addr+i, src, _sword_size(d)); 
}


uint32_t 
cdk_dsym_field32_get(int unit, uint32_t* src, cdk_dsymbol_t* dispatch[], int field, int be, 
                     const char* file, int line)
{ 
    cdk_dsymbol_t* d; 
    cdk_field_info_t f; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, field, &d, &f, file, line); 

    if(be) {
        return cdk_field32_be_get(src, _sword_size(d), f.minbit, f.maxbit); 
    }   
    else {
        return cdk_field32_get(src, f.minbit, f.maxbit); 
    }   
} 


int 
cdk_dsym_field32_set(int unit, uint32_t* dst, cdk_dsymbol_t* dispatch[], int field, uint32_t v, int be, 
                     const char* file, int line) 
{ 
    cdk_dsymbol_t* d; 
    cdk_field_info_t f; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, field, &d, &f, file, line); 
    
    if(be) {
        cdk_field32_be_set(dst, _sword_size(d), f.minbit, f.maxbit, v); 
    }   
    else {
        cdk_field32_set(dst, f.minbit, f.maxbit, v); 
    }   
    return 0; 
} 


int 
cdk_dsym_field_get(int unit, uint32_t* src, cdk_dsymbol_t* dispatch[], int field, uint32_t* dst, int be, 
                   const char* file, int line)
{ 
    cdk_dsymbol_t* d; 
    cdk_field_info_t f; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, field, &d, &f, file, line); 

    if(be) {
        cdk_field_be_get(src, _sword_size(d), f.minbit, f.maxbit, dst); 
    }   
    else {
        cdk_field_get(src, f.minbit, f.maxbit, dst); 
    }   
    return 0; 
} 

int
cdk_dsym_field_set(int unit, uint32_t* dst, cdk_dsymbol_t* dispatch[], int field, uint32_t* src, int be, 
                   const char* file, int line)
{ 
    cdk_dsymbol_t* d; 
    cdk_field_info_t f; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, field, &d, &f, file, line); 

    if(be) {
        cdk_field_be_set(dst, _sword_size(d), f.minbit, f.maxbit, src); 
    }   
    else {
        cdk_field_set(dst, f.minbit, f.maxbit, src); 
    }   
    return 0; 
} 

void*
cdk_dsym_field_ptr_get(int unit, cdk_dsymbol_t* dispatch[], int field, void* src, int be, 
                       const char* file, int line)
{ 
    cdk_dsymbol_t* d; 
    cdk_field_info_t f; 
    int offset; 

    CDK_ASSERT(CDK_UNIT_VALID(unit)); 
    _dsym_entry_valid(unit, dispatch, field, &d, &f, file, line); 
    
    if(be) {
        int maxbit = f.maxbit; 
        while(maxbit%32) maxbit++; 
        offset = _sword_size(d) - maxbit/32;         
    }   
    else {
        offset = f.minbit/32; 
    }   

    return ((uint32_t*)src) + offset; 
} 

uint32_t
cdk_dsym_addr(int unit, cdk_dsymbol_t* dispatch[], 
              const char* file, int line)
{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return d->addr; 
}       
    
int 
cdk_dsym_min(int unit, cdk_dsymbol_t* dispatch[], 
             const char* file, int line)
{
    cdk_dsymbol_t* d; 

    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return CDK_SYMBOL_INDEX_MIN_GET(d->index); 
}

int 
cdk_dsym_max(int unit, cdk_dsymbol_t* dispatch[], 
             const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return CDK_SYMBOL_INDEX_MAX_GET(d->index); 
}

int 
cdk_dsym_size(int unit, cdk_dsymbol_t* dispatch[], 
              const char* file, int line)
{
    cdk_dsymbol_t* d; 
    
    CDK_UNIT_CHECK(unit); 
    _dsym_entry_valid(unit, dispatch, -1, &d, NULL, file, line); 
    return CDK_SYMBOL_INDEX_SIZE_GET(d->index); 
}

int 
cdk_dsym_valid(int unit, cdk_dsymbol_t* dispatch[])
{
    CDK_UNIT_CHECK(unit); 
    return _dsym_entry(unit, dispatch, NULL, NULL, NULL) == 0; 
}       
   
int
cdk_dsym_field_valid(int unit, cdk_dsymbol_t* dispatch[], int field)
{
    return _dsym_entry(unit, dispatch, &field, NULL, NULL) == 0; 
}


