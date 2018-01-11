#ifndef __CDK_DSYMBOLS_H__
#define __CDK_DSYMBOLS_H__

#include <cdk/cdk_types.h>

/*
 * This structure is used to store the minimum information
 * needed to support multi-chip symbols. 
 *
 * This is a subset of the information in the cdk_symbol_t structure. 
 * The fields MUST be in the same order so that the structures
 * are interchangeable. 
 *
 */
typedef struct cdk_dsymbol_s {
    uint32_t addr; 
    uint32_t* fields; 
    uint32_t index; 
    uint32_t flags; 
} cdk_dsymbol_t; 


#define CDK_DSYM_MAX_MULTIFIELDS 6
#define CDK_DSYM_FLAG_MULTIFIELD 0x80000000

typedef struct cdk_dsym_multifield_s {
    int fids[CDK_DSYM_MAX_MULTIFIELDS]; 
} cdk_dsym_multifield_t; 

extern int 
cdk_dsym_mem_read(int unit, int idx, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                  const char* file, int line);

extern int 
cdk_dsym_mem_write(int unit, int idx, cdk_dsymbol_t* dispatch[], uint32_t* src,
                  const char* file, int line);

extern uint32_t 
cdk_dsym_field32_get(int unit, uint32_t* src, cdk_dsymbol_t* dispatch[], int field, int be,
                  const char* file, int line); 

extern int 
cdk_dsym_field32_set(int unit, uint32_t* dst, cdk_dsymbol_t* dispatch[], int field, uint32_t v, int be, 
                     const char* file, int line);

extern int 
cdk_dsym_field_get(int unit, uint32_t* src, cdk_dsymbol_t* dispatch[], int field, uint32_t* dst, int be,
                  const char* file, int line);

extern int
cdk_dsym_field_set(int unit, uint32_t* dst, cdk_dsymbol_t* dispatch[], int field, uint32_t* src, int be,
                  const char* file, int line);

extern int
cdk_dsym_reg_read(int unit, cdk_dsymbol_t* dispatch[], uint32_t* dst,
                  const char* file, int line);

extern int
cdk_dsym_reg_write(int unit, cdk_dsymbol_t* dispatch[], uint32_t* src,
                  const char* file, int line);

extern int
cdk_dsym_port_reg_read(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* dst,
                  const char* file, int line);

extern int
cdk_dsym_port_reg_write(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* src, 
                  const char* file, int line);

extern int
cdk_dsym_blocks_reg_read(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                  const char* file, int line);

extern int
cdk_dsym_blocks_reg_write(int unit, int p, int offset, cdk_dsymbol_t* dispatch[], uint32_t* src, 
                  const char* file, int line);

extern int
cdk_dsym_indexed_reg_read(int unit, int i, cdk_dsymbol_t* dispatch[], uint32_t* dst, 
                  const char* file, int line);

extern int
cdk_dsym_indexed_reg_write(int unit, int i, cdk_dsymbol_t* dispatch[], uint32_t* src, 
                  const char* file, int line);

extern void*
cdk_dsym_field_ptr_get(int unit, cdk_dsymbol_t* dispatch[], int field, void* src, int be,
                  const char* file, int line);

extern uint32_t 
cdk_dsym_addr(int unit, cdk_dsymbol_t* dispatch[], 
              const char* file, int line);

extern int 
cdk_dsym_min(int unit, cdk_dsymbol_t* dispatch[], 
             const char* file, int line);

extern int 
cdk_dsym_max(int unit, cdk_dsymbol_t* dispatch[], 
             const char* file, int line);

extern int 
cdk_dsym_size(int unit, cdk_dsymbol_t* dispatch[], 
              const char* file, int line);

extern int 
cdk_dsym_valid(int unit, cdk_dsymbol_t* dispatch[]); 

extern int
cdk_dsym_field_valid(int unit, cdk_dsymbol_t* dispatch[], int field); 



/*
 * This structure is defined for debug and testing purposes only. 
 */

typedef struct cdk_dsym_map_s {
    const char* name; 
    cdk_dsymbol_t** dispatch; 
} cdk_dsym_map_t; 

#endif /* __CDK_DSYMBOLS_H__ */
