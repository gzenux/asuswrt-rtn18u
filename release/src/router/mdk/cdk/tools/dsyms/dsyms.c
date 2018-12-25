/*
 * $Id: dsyms.c,v 1.19 Broadcom SDK $
 * $Copyright$
 *
 *
 * DSYMS
 *
 * This tool generates all dynamic symbol information for a given 
 * configuration of the CDK. 
 *
 * This tool is built and run on the host compilation system after
 * the existing chipset configuration for the CDK has been modified. 
 *
 */

#include "dsyms.h"
#include "util.h"
#include "cg.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

/*******************************************************************************
 *
 * DYNAMIC SYMBOL GENERATION
 *
 *
 ******************************************************************************/

/*
 * The CDK source file 'allsyms.c' contains all possible chip symbols
 * for a given CDK installation. We need to include this structure
 * to access the information. It is assumed we will be built with 
 * a -I$(CDK) directive to give us access to the top of the CDK source tree. 
 */
#include <sym/cdk_allsyms.c>


/*
 * We need to borrow some symbol processing code from the CDK as well. 
 */
uint32_t* 
cdk_field_info_decode(uint32_t* fp, cdk_field_info_t* finfo, const char** fnames)
{
    uint32_t fid; 

    if(!fp) {
        return NULL; 
    }

    if(finfo) {
        /*
         * Single or Double Word Descriptor?
         */
        if(CDK_SYMBOL_FIELD_EXT(*fp)) {
            /* Double Word */
            fid = CDK_SYMBOL_FIELD_EXT_ID_GET(*fp); 
            finfo->maxbit = CDK_SYMBOL_FIELD_EXT_MAX_GET(*(fp+1)); 
            finfo->minbit = CDK_SYMBOL_FIELD_EXT_MIN_GET(*(fp+1)); 
        }       
        else {
            /* Single Word */
            fid = CDK_SYMBOL_FIELD_ID_GET(*fp); 
            finfo->maxbit = CDK_SYMBOL_FIELD_MAX_GET(*fp); 
            finfo->minbit = CDK_SYMBOL_FIELD_MIN_GET(*fp); 
        }       

#if CDK_CONFIG_INCLUDE_FIELD_NAMES
        if(fnames) {
            finfo->name = fnames[fid]; 
        }
#endif
    }

    if(CDK_SYMBOL_FIELD_LAST(*fp)) {
        return NULL; 
    }

    if(CDK_SYMBOL_FIELD_EXT(*fp)) {
        return fp+2; 
    }

    return fp+1; 
}

uint32_t
cdk_field_info_count(uint32_t* fp)
{    
    int count = 0; 
    while(fp) {
        fp = cdk_field_info_decode(fp, NULL, NULL); 
        count++; 
    }   
    return count; 
}



/*
 * The first structure we need is a mapping of chip names to
 * their symbol table pointers. 
 */
typedef struct {
    /* Chip Name */
    const char* name;
    /* CDK Device Type */
    cdk_dev_type_t dev_type; 
    /* Symbol Table Pointer */
    cdk_symbols_t* syms; 
} symtab_map_t; 


/*
 * We will create the symtab map table using the CDK_DEVLIST_ENTRY macros
 * for the current configuration:
 */
static symtab_map_t _maps[] = {

#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \
{ #_bd, cdkDevType_##_bd, &_bd##_symbols },

    { "None", cdkDevTypeNone, NULL},
#include <cdk/cdk_devlist.h>
    { NULL, cdkDevTypeCount, NULL}
}; 


/*
 * All chips supported. Public table. 
 */

const char* dsym_chips[] = 
    {   
#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1)      \
        #_bd,

        "None",
#include <cdk/cdk_devlist.h>
        NULL
    }; 

/*
 * Table for included chips.
 */
static unsigned char _included[cdkDevTypeCount]; 

int
dsym_include(int devtype, int include)
{
    if(devtype == -1) {
        memset(_included, include, sizeof(_included)); 
    }        
    else {
        if(devtype < 0 || devtype >= cdkDevTypeCount) {
            internal_error(__LINE__, "devtype=%d out of range in dsym_include()", devtype); 
        }    
        _included[devtype] = include; 
    }   
    _included[cdkDevTypeNone] = 0; 
    return 0; 
}       

int
dsym_included(int devtype)
{
    if(devtype < 0 || devtype >= cdkDevTypeCount) {
        internal_error(__LINE__, "devtype=%d out of range in dsym_included()", devtype); 
    }                   
    return _included[devtype]; 
}       
            


/* Public Data */

allsyms_t* allsyms = NULL; 
int allsyms_count; 
const char** allfields; 
int allfields_count; 

typedef struct { 
    const char* name; 
    int fids[CDK_DSYM_MAX_MULTIFIELDS]; 
    int count; 
    int index; 
} allfield_alias_t; 

allfield_alias_t* allfield_aliases;
int allfield_aliases_count = 0; 

allfield_info_t* allfield_info; /* [DSYM_MAX_SYM_COUNT] */
int allfield_entry_count; 
dsym_stats_t dsym_stats; 


/*
 * Retrieve the field names array for a given device
 */
static const char** 
_field_names(int d)
{
    return _maps[d].syms->field_names; 
}
    
/*
 * Return the name of the given cdk_devtype index
 */
static const char* 
_dev_type_name(int t)
{
    symtab_map_t* m; 
    for(m = _maps; m->name; m++) {
        if(m->dev_type == t) {
            return m->name; 
        }
    }

    internal_error(__LINE__, "unkown devtype (%d)\n", t); 
    return NULL; 
}

/*
 * Normalize multi-view encoded field names
 * Note that if needed we currently just allocate memory without
 * any intent of ever freeing it again.
 */
static char*
_normalize_field_name(const char* fname)
{
    char* fp;
    char* cp;

    if((cp = strchr(fname, '}')) != NULL) {
        cp++;
        if ((fp = strdup(cp)) == NULL) {
            internal_error(__LINE__, "out of memory\n"); 
        }
        cp = fp;
        while((cp = strchr(cp, ':')) != NULL) {
            *cp = '_';
        }
    }
    else {
        fp = (char*)fname;
    }

    return fp;
}


/******************************************************************************/


/*
 * Retrieve a symbol table entry from a given symbol table. 
 */
static int 
_symbols_get(const cdk_symbols_t* symbols, int index, cdk_symbol_t* rsym)
{
    if (symbols) {
	if (index >= 0 && index < symbols->size) {
	    /* Index is within the symbol table */
	    *rsym = symbols->symbols[index]; 
	    return 0;
	}
    }
    return -1; 
}


/*
 * Return the index in the allsym table of a given symbol name. 
 */
static int
_find_allsym_index(const char* name)
{
    int i; 

    for(i = 0; allsyms[i].name; i++) {
        if(!strcmp(allsyms[i].name, name)) {
            /* Entry exists in the table already at this location */
            return i; 
        }
    }
    
    /* Arbitrary size choice not large enough for symbols... */
    assert(i < DSYM_MAX_SYM_COUNT - 1); 
    
    /* Return the next unused entry in the table */
    allsyms_count++; 
    return i; 
}

/* 
 * Return the index in the allfields table of a given field name
 */
static int
_find_allfield_index(const char* name)
{
    int i; 

    for(i = 0; allfields[i]; i++) {
        if(!strcmp(allfields[i], name)) {
            return i; 
        }       
    }   

    internal_error(__LINE__, "field name '%s' not found", name); 
    return -1; 
}       

/*
 * Return the index in the allfields_alias table of a given field name
 */
static int
_find_allfield_alias_index(const char* name)
{
    int i; 

    for(i = 0; allfield_aliases[i].name; i++) {
        if(!strcmp(allfield_aliases[i].name, name)) {
            return i; 
        }       
    }   

    internal_error(__LINE__, "field name '%s' not found", name); 
    return -1; 
}

/*
 * Take a given symbol from a given chip and 
 * merge it into the allsyms table. 
 */
static int
_merge_symbol(cdk_dev_type_t type, cdk_symbol_t* s, const char** fnames)
{
    /*
     * Retrieve the existing index for this symbol, or 
     * a free entry with which we can start
     */
    int i = _find_allsym_index(s->name); 
    unsigned int iflags = 0; 

    /* Store this symbol in the given's devices slot */
    allsyms[i].symbols[type] = *s; 
    allsyms[i].name = s->name; 

    if((allsyms[i].flags) &&
       (allsyms[i].flags & (CDK_SYMBOL_FLAG_SOFT_PORT|CDK_SYMBOL_FLAG_PORT)) !=
       (s->flags & (CDK_SYMBOL_FLAG_SOFT_PORT|CDK_SYMBOL_FLAG_PORT))) {
        /* Symbols have mismatching port/softport settings */
        if(ioption("warn") == 1) {
            printf("Warning: PORT/SOFT PORT error in %s on %s (index=%d, type=%d, old=0x%x, new=0x%x)\n", 
                   s->name, _dev_type_name(type), i, type, allsyms[i].flags, s->flags); 
        }       
    }   

    allsyms[i].flags |= s->flags; 

    if(CDK_SYMBOL_INDEX_MIN_GET(s->index) != CDK_SYMBOL_INDEX_MAX_GET(s->index)) {
        iflags = ALLSYM_IFLAG_SYMBOL_INDEXED; 
    }
    if(allsyms[i].iflags && allsyms[i].iflags != iflags) {
        /* Symbol is indexed on one chip but not another */
        if(ioption("warn") == 1) {
            printf("Warning: index error in %s on %s (index=%d, type=%d, old=0x%x, new=0x%x)\n", 
                   s->name, _dev_type_name(type), i, type, allsyms[i].iflags, iflags); 
        }       
    }
    allsyms[i].iflags = iflags; 
    return 0; 
}       

/*
 * Merge all symbols from a chip's symbol table
 * into the allsyms table. 
 * 
 * The chip's identification and symbol information come
 * the symtab_map_t entry. 
 */    
static int
_merge_symbols(symtab_map_t* m)
{
    cdk_symbol_t s; 
    int i = 0, rc = 0;  
    
    /* Foreach symbol in this chip's symbol table */
    while((rc = _symbols_get(m->syms, i++, &s)) >= 0) {
        /* Merge it into the allsyms */
        _merge_symbol(m->dev_type, &s, m->syms->field_names); 
    }
    return 0; 
}       


static int
_compare_allsyms(const void* a, const void* b)
{
    /*  
     * Need to remove the trailing "r" or "m" from the strings as 
     * the original symbols were sorted prior to appending the suffix
     * when the symbol table was generated. 
     * We try to keep an approximation of the original sort order for
     * verification purposes. 
     */

    char as[128];
    char bs[128]; 
    strcpy(as, ((allsyms_t*)a)->name); 
    strcpy(bs, ((allsyms_t*)b)->name); 
    as[strlen(as)-1]=0; 
    bs[strlen(bs)-1]=0;
    return strcmp(as, bs); 
}

static int
_compare_strings(const void* a, const void* b)
{
    return strcmp(*(char**)a, *(char**)b); 
}       
  
const char * 
_flag_string(cdk_symbol_t* s, char* dst)
{
    sprintf(dst, "%s%s%s%s%s%s%s%s", 
            (s->flags & CDK_SYMBOL_FLAG_REGISTER) ? "r " : "  ", 
            (s->flags & CDK_SYMBOL_FLAG_PORT) ? "p " : "  ", 
            (s->flags & CDK_SYMBOL_FLAG_COUNTER) ? "c " : "  ",
            (s->flags & CDK_SYMBOL_FLAG_MEMORY) ? "m " : "  ", 
            (s->flags & CDK_SYMBOL_FLAG_R64) ? "64 " : "   ", 
            (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? "be " : "   ", 
            (s->flags & CDK_SYMBOL_FLAG_MEMMAPPED) ? "mm " : "   ", 
            (s->flags & CDK_SYMBOL_FLAG_SOFT_PORT) ? "sp " : "   "); 
    return dst; 
}
    
static int
_check_symbols(void)
{
    /*
     * All symbols have been merged. 
     * Check flag consistency. 
     */    
    allsyms_t* s; 
    for(s = allsyms; s->name; s++) {

        int d; 

        /* First flagset */
        uint32_t mask = ~(CDK_SYMBOL_FLAG_START-1); 
        uint32_t flags = 0; 

        /* Check consistency with all devices */
        for(d = 1; d < cdkDevTypeCount; d++) {
            if(!_included[d]) {
                continue; 
            }   
            if(s->symbols[d].name == NULL) {
                /* Symbol is not valid on this device */
                continue;                 
            }   

            /* First flagset */
            if(flags == 0 ) {
                flags = s->symbols[d].flags & mask; 
            }   

            if((s->symbols[d].flags & mask) != flags) {
                int i; 
                char flagstr[256]; 

                if(ioption("warn") == 1) {
                    fprintf(stderr, "Flag Error in %s:\n", s->name); 
                    for(i = 1; i < cdkDevTypeCount; i++) {
                        if(!_included[i]) continue; 
                        if(!(s->symbols[i].name)) continue; 
                        fprintf(stderr, "    %15.15s: %s\n", _dev_type_name(i), _flag_string(s->symbols+i, flagstr)); 
                    }           
                }       
                break; 
            }
        }       
    }   
    return 0; 
}
    
  
/*
 * Generate the allsyms table
 */
static int
_build_allsyms(void)
{
    symtab_map_t* m; 
    int i; 

    /* Walk the symtab_map table and merge all chip symbols */
    /* into the allsyms table */
    
    for(i=0, m = _maps; m->name; m++, i++) {
        if(_included[i]) {
            _merge_symbols(m); 
        }       
    }

    /* Resort all symbols alphabetically */
    qsort(allsyms, allsyms_count, sizeof(allsyms_t), _compare_allsyms); 

    /* Flag and symbol type checking */
    _check_symbols(); 
    return 0; 
}




/*
 * Merge the given symbol into the given field array
 */
static int
_merge_field(const char* name, const char* farray[], int max)
{
    int i; 
    for(i = 0; i < max && farray[i]; i++) {
        if(!strcmp(farray[i], name)) {
            /* Already in the table */
            return i; 
        }       
    }

    /* Add it to the table */
    if(i >= max) {
        internal_error(__LINE__, "out of space: max=%d\n", max); 
    }   
    farray[i] = name;     
    return i; 
}

/*
 * Merge a field_info_t structure into the global field set
 */

static int
_find_field_set(cdk_symbol_t* symbol, int dev, int* index)
{
    int i; 
    for(i = 0; allfield_info[i].finfo[0].name; i++) {
        allfield_info_t* afi = allfield_info+i; 
        cdk_field_info_t finfo; 
        const char **fnames = _field_names(dev);
        int j = 0; 
        int match = 1; 

        /* Are the number of fields equal? */
        if(afi->count != cdk_field_info_count(symbol->fields)) {
            continue; 
        }       

        /* Are the field descriptions equal? */
        CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol->fields, finfo, fnames) {
            if(finfo.name   != afi->finfo[j].name ||
               finfo.minbit != afi->finfo[j].minbit ||
               finfo.maxbit != afi->finfo[j].maxbit) {

                /* No match */
                match=0; 
                break;
            }       
            j++; 
        } CDK_SYMBOL_FIELDS_ITER_END(); 

        if(match == 1) {
            *index=i; 
            return 0; 
        }       
    }   
    *index = i; 
    return -1; 
}       
                                                                    

static int
_merge_field_set(int dev, cdk_symbol_t* symbol)
{    
    int i, j; 
    cdk_field_info_t finfo; 
    const char **fnames = _field_names(dev);

    _find_field_set(symbol, dev, &i); 
    
    /* Decode and Merge Field Info */
    allfield_info[i].count=0; 
    CDK_SYMBOL_FIELDS_ITER_BEGIN(symbol->fields, finfo, fnames) {
        allfield_info[i].finfo[allfield_info[i].count++] = finfo; 
    } CDK_SYMBOL_FIELDS_ITER_END(); 
    
    /* Add this device and symbol name */
    for(j = 0; j < sizeof(allfield_info[i].elements[dev])/sizeof(allfield_info[i].elements[dev][0]); j++) {
        if(allfield_info[i].elements[dev][j] == NULL) {
            allfield_info[i].elements[dev][j] = symbol->name; 
            break; 
        }       
    }   
    return 0; 
}


/*
 * Calculate the width of the given field
 */
static int
_field_size(cdk_field_info_t* field)
{
    return field->maxbit - field->minbit + 1; 
}



/*
 * Build the allfields table from the combined allsyms database
 */
static int
_build_allfields(void)
{
    /* Walk all fields in the combined symbol table and store the names */
    int s; 
    
    /* Foreach symbol */
    for(s = 0; allsyms[s].name; s++) {
        /* Foreach device */
        int d; 
        for(d = 0; d < cdkDevTypeCount; d++) {
            if(!_included[d]) {
                continue; 
            }   
            if(allsyms[s].symbols[d].name) {

                /* Foreach field in this symbol */
                int i; 
                cdk_field_info_t finfo; 
                const char **fnames = _field_names(d);

                /*
                 * Merge this field set into the global field set
                 */
                
                _merge_field_set(d, allsyms[s].symbols+d); 

                CDK_SYMBOL_FIELDS_ITER_BEGIN(allsyms[s].symbols[d].fields, finfo, fnames) {

                    /* Merge it into the global allfields table */
                    _merge_field(finfo.name, allfields, 
                                 DSYM_MAX_FIELD_COUNT); 

                    /* Merge it into the fields table for this symbol */
                    i = _merge_field(finfo.name, allsyms[s].fields, 
                                     DSYM_MAX_FIELDS_PER_SYMBOL); 

                    /* Update the minimum field size */
                    if(allsyms[s].fsizes[i] == 0) {
                        allsyms[s].fsizes[i] = 1024; 
                    }   
                    allsyms[s].fsizes[i] = MIN(allsyms[s].fsizes[i], 
                                                _field_size(&finfo)); 
                } CDK_SYMBOL_FIELDS_ITER_END(); 
            }
        }
    }


    /*
     * We want the field indices to be sorted alphabetically 
     */
    for(allfields_count = 0; allfields[allfields_count]; allfields_count++); 
    qsort(allfields, allfields_count, sizeof(char*), _compare_strings); 




    /*
     * Generate field aliases. Some normalized field names can map to multiple field ids. 
     */
    {
        int acount = 0; 
        int i;

        for(s = 0; s < allfields_count; s++) {
            const char* normal = _normalize_field_name(allfields[s]); 
            
            for(i = 0; i < acount; i++) {
                if(!strcmp(allfield_aliases[i].name, normal)) {

                    /* Aliases name */
                    if(allfield_aliases[i].count == CDK_DSYM_MAX_MULTIFIELDS) {
                        internal_error(__LINE__, "Field alias count exceeds CDK_DSYM_MAX_MULTIFIELDS (%d)", CDK_DSYM_MAX_MULTIFIELDS); 
                    }   

                    allfield_aliases[i].fids[allfield_aliases[i].count++] = s; 
                    break; 
                }       
            }   
            if(i == acount) {
                /* Not in table */
                memset(allfield_aliases[i].fids, 0xFF, sizeof(allfield_aliases[i].fids)); 
                allfield_aliases[i].name = normal; 
                allfield_aliases[i].fids[0] = s; 
                allfield_aliases[i].count = 1; 
                acount++; 
            }   
        }     

        /* Collapse Aliases for later */
        for(i = 0, acount = 0; allfield_aliases[i].name; i++) {
            if(allfield_aliases[i].count > 1) { 
                allfield_aliases[i].index=acount++; 
            }   
        }       
        allfield_aliases_count = acount; 
    }


    return 0; 
}


/*
 * Generate the allfields enumeration type. 
 * This will be used to identify fields dynamically 
 *
 */
static int
_generate_allfields_enumeration(FILE* fp)
{
    const char** field = NULL; 
    int i; 
    char* fname;
    char* comment = 
        "ALLFIELDS Enumeration\n"
        " \n"
        "This enumeration specifies all possible dynamic\n"
        "field references for the current configuration."; 
    
    cg_bcommentf(fp, comment); 
    cg_nl(fp, 1); 

    fprintf(fp, "typedef enum %s {\n", OPT_ALLFIELDS_ENUM_E);     
    for(i = 0, field = allfields; *field; field++, i++) {
        fname = _normalize_field_name(*field);
        fprintf(fp, "    %s%s_f%d,\n", OPT_ALLFIELDS_ENUM_PREFIX, fname, i); 
    }
    fprintf(fp, "    %sLast\n", OPT_ALLFIELDS_ENUM_PREFIX); 
    
    fprintf(fp, "} %s;\n", OPT_ALLFIELDS_ENUM_T); 
    
    return 0; 
}

/*
 * Generate the dynamic Structure Union definition for a given symbol
 * and the accessor macros needed to use it. 
 */
static int
_generate_definition(FILE* fp, allsyms_t* s)
{
    /*
     * Calculate the maximum size of this symbol for all chips
     */
    int d, f; 
    int size = 0; 
    char sname[128]; 
    char* fname;

    /*
     * Calculate the maximum size of this symbol
     */
    for(d = 0; d < cdkDevTypeCount; d++) {
        if(_included[d]) {
            size = MAX(size, CDK_SYMBOL_INDEX_SIZE_GET(s->symbols[d].index));
        }       
    }


    /* Output a description header for this symbol */
    cg_bcomment_start(fp); 
    
    if(s->flags & CDK_SYMBOL_FLAG_REGISTER) {
        cg_mcommentf(fp, "REGISTER: %s", s->name); 
    }
    else if(s->flags & CDK_SYMBOL_FLAG_MEMORY) {
        cg_mcommentf(fp, "MEMORY: %s", s->name);
    }
    else {
        cg_mcommentf(fp, "FORMAT: %s", s->name);
    }    
    cg_mcommentf(fp, "CHIPS:"); 
    for(d = 0; d < cdkDevTypeCount; d++) {
        if(_included[d]) {
            if(s->symbols[d].name) {
                /* Symbol is in this chip */
                cg_mcommentf(fp, "    %s", _dev_type_name(d)); 
            }
        }       
    }       
    cg_bcomment_end(fp);
    

    /* Extern the dispatch table for this symbol */
    fprintf(fp, "extern %s* %s%s[];\n\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX,
            s->name); 
    
    /* Address of the register or Memory */
    fprintf(fp, "#define %s (%s(unit, %s%s, __FILE__, __LINE__))\n", 
            s->name, OPT_ADDR_GET, OPT_DSYM_PREFIX, s->name); 

    
    /* MIN index */
    fprintf(fp, "#define %s_MIN (%s(unit, %s%s,__FILE__,__LINE__))\n", 
            s->name, OPT_INDEX_MIN, OPT_DSYM_PREFIX, s->name); 

    /* MAX index */
    fprintf(fp, "#define %s_MAX (%s(unit, %s%s,__FILE__,__LINE__))\n", 
            s->name, OPT_INDEX_MAX, OPT_DSYM_PREFIX, s->name); 

    /* SIZE */
    fprintf(fp, "#define %s_SIZE (%s(unit, %s%s,__FILE__,__LINE__))\n", 
            s->name, OPT_INDEX_SIZE, OPT_DSYM_PREFIX, s->name); 


    /* Generate the union structure for this symbol */
    stolower(s->name, sname); 
    {
        int sz = size; 
        while (sz%4) sz++; 
        cg_commentf(fp, "This structure should be used to declare and program %s", s->name);
        fprintf(fp, "typedef union %s_s {\n", s->name); 
        fprintf(fp, "    %s v[%d];\n", OPT_UINT32_T, sz/4); 
        fprintf(fp, "    %s %s[%d];\n", OPT_UINT32_T, sname, sz/4);
        fprintf(fp, "    %s _%s;\n", OPT_UINT32_T, sname); 
        fprintf(fp, "} %s_t; \n", s->name); 
        fprintf(fp, "\n"); 
    }
    
    /* Generate CLR, SET, and GET */    
    if(size == 4) {
        /* Single Word Sizes */
        fprintf(fp, "#define %s_CLR(r) (r).%s[0] = 0\n", s->name, sname); 
        fprintf(fp, "#define %s_SET(r,d) (r).%s[0] = d\n", s->name, sname); 
        fprintf(fp, "#define %s_GET(r) (r).%s[0]\n", s->name, sname); 
    }
    else {
        /* Multiword Sizes */
        fprintf(fp, "#define %s_CLR(r) CDK_MEMSET(&(r), 0, sizeof(%s_t))\n", 
                s->name, s->name); 
        fprintf(fp, "#define %s_SET(r,i,d) (r).%s[i] = d\n", 
                s->name, sname); 
        fprintf(fp, "#define %s_GET(r,i) (r).%s[i]\n", 
                s->name, sname); 
    }
    
    cg_commentf(fp, "These macros can be used to access individual fields.");

    /*
     * Output the field accessor macros for all fields in these symbols. 
     */
    
    for(f = 0; s->fields[f]; f++) {
        allfield_alias_t* a; 
        int fid; 
        char fdesc[128]; 

        fname = _normalize_field_name(s->fields[f]);
        fid = _find_allfield_index(s->fields[f]); 

        /* Is this field aliased? */
        a = &allfield_aliases[_find_allfield_alias_index(fname)]; 

        if(a->count == 1) {
            sprintf(fdesc, "%d", fid); 
        }
        else {
            sprintf(fdesc, "CDK_DSYM_FLAG_MULTIFIELD | %d", a->index); 
        }
        
        /* Single Field Accessors */
        if(s->fsizes[f] <= 32) {
            
            /* GET Macro */
            fprintf(fp, "#define %s_%sf_GET(r) %s(unit,(r).%s,%s%s,%s,%d,__FILE__,__LINE__)\n", 
                    s->name, fname, OPT_FIELD32_GET, sname,
                    OPT_DSYM_PREFIX, s->name,
                    fdesc, 
                    (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? 1 : 0); 
            
            /* SET Macro */
            fprintf(fp, "#define %s_%sf_SET(r,f) %s(unit,(r).%s,%s%s,%s,f,%d,__FILE__,__LINE__)\n", 
                    s->name, fname, OPT_FIELD32_SET, sname,
                    OPT_DSYM_PREFIX, s->name, 
                    fdesc, 
                    (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? 1 : 0); 
        }                       
        
        else {
            /* Multi Word Sizes */
            
            /* GET Macro */
            fprintf(fp, "#define %s_%sf_GET(r,a) %s(unit,(r).%s,%s%s,%s, a, %d,__FILE__,__LINE__)\n",
                    s->name, fname, OPT_FIELD_GET, sname,
                    OPT_DSYM_PREFIX, s->name,
                    fdesc, 
                    (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? 1 : 0); 
            fprintf(fp, "#define %s_%sf_SET(r,a) %s(unit,(r).%s,%s%s,%s, a, %d,__FILE__,__LINE__)\n",
                    s->name, fname, OPT_FIELD_SET, sname,
                    OPT_DSYM_PREFIX, s->name,
                    fdesc, 
                    (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? 1 : 0); 
        }       
        
        /* PTR Macro */
        fprintf(fp, "#define %s_%sf_PTR(r) %s(unit, %s%s, %s, &(r), %d,__FILE__,__LINE__)\n", 
                s->name, fname, OPT_FIELD_PTR_GET, 
                OPT_DSYM_PREFIX,s->name, fdesc, 
                (s->flags & CDK_SYMBOL_FLAG_BIG_ENDIAN) ? 1 : 0); 
    }               
       

    /*
     * Output the Read/Write macros 
     */
    cg_commentf(fp, "These macros can be used to access %s", s->name); 
    if(s->flags & CDK_SYMBOL_FLAG_REGISTER) {
        if(!(s->iflags & ALLSYM_IFLAG_SYMBOL_INDEXED)) {
            //_wasted_index_count++; 
        }       
        if(s->flags & CDK_SYMBOL_FLAG_MEMMAPPED) {
            /* CMIC Register */
            if(s->iflags & ALLSYM_IFLAG_SYMBOL_INDEXED) {
                fprintf(fp, "#define READ_%s(u,i,r) CDK_DEV_READ32(u,(%s)+(4*i), (r._%s))\n", 
                        s->name, s->name, sname); 
                fprintf(fp, "#define WRITE_%s(u,i,r) CDK_DEV_WRITE32(u,(%s)+(4*i), (r._%s))\n", 
                        s->name, s->name, sname); 

            }   
            else {
                fprintf(fp, "#define READ_%s(u,r) CDK_DEV_READ32(u,%s, (r._%s))\n", 
                        s->name, s->name, sname); 
                fprintf(fp, "#define WRITE_%s(u,r) CDK_DEV_WRITE32(u,%s, (r._%s))\n", 
                        s->name, s->name, sname); 
            }   
        }       
        else if(s->flags & CDK_SYMBOL_FLAG_SOFT_PORT) {
            
            if(s->iflags & ALLSYM_IFLAG_SYMBOL_INDEXED) {
                /* Indexed block register */
                fprintf(fp, "#define READ_%s(u,i,r,p) %s(u,p,i,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_BLOCKS_READ, OPT_DSYM_PREFIX, s->name, sname);
                fprintf(fp, "#define WRITE_%s(u,i,r,p) %s(u,p,i,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_BLOCKS_WRITE, OPT_DSYM_PREFIX, s->name, sname);
            } else {
                /* Regular block register */
                fprintf(fp, "#define READ_%s(u,r,p) %s(u,p,0,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_BLOCKS_READ, OPT_DSYM_PREFIX, s->name, sname);
                fprintf(fp, "#define WRITE_%s(u,r,p) %s(u,p,0,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_BLOCKS_WRITE, OPT_DSYM_PREFIX, s->name, sname);
            }   
        }
        else if(s->flags & CDK_SYMBOL_FLAG_PORT) {
            
            if(s->iflags & ALLSYM_IFLAG_SYMBOL_INDEXED) {
                /* Indexed port register */
                fprintf(fp, "#define READ_%s(u,p,i,r) %s(u,p,i,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_PORT_READ, OPT_DSYM_PREFIX, s->name, sname);
                fprintf(fp, "#define WRITE_%s(u,p,i,r) %s(u,p,i,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_PORT_WRITE, OPT_DSYM_PREFIX, s->name, sname);
            } else {
                /* Regular port register */
                fprintf(fp, "#define READ_%s(u,p,r) %s(u,p,0,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_PORT_READ, OPT_DSYM_PREFIX, s->name, sname);
                fprintf(fp, "#define WRITE_%s(u,p,r) %s(u,p,0,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                        s->name, OPT_REG_PORT_WRITE, OPT_DSYM_PREFIX, s->name, sname);
            }   
        }
        else if(s->iflags & ALLSYM_IFLAG_SYMBOL_INDEXED) {
            fprintf(fp, "#define READ_%s(u,i,r) %s(u,i,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                    s->name, OPT_REG_INDEXED_READ, OPT_DSYM_PREFIX, s->name, sname);
            fprintf(fp, "#define WRITE_%s(u,i,r) %s(u,i,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                    s->name, OPT_REG_INDEXED_WRITE, OPT_DSYM_PREFIX, s->name, sname);
        }       
        else {
            fprintf(fp, "#define READ_%s(u,r) %s(u,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                    s->name, OPT_REG_READ, OPT_DSYM_PREFIX, s->name, sname); 
            fprintf(fp, "#define WRITE_%s(u,r) %s(u,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                    s->name, OPT_REG_WRITE, OPT_DSYM_PREFIX, s->name, sname); 
        }       
    }
    if(s->flags & CDK_SYMBOL_FLAG_MEMORY) {     
        fprintf(fp, "#define READ_%s(u,i,r) %s(u,i,%s%s, (r._%s),__FILE__,__LINE__)\n", 
                s->name, OPT_MEM_READ, OPT_DSYM_PREFIX, s->name, sname);
        fprintf(fp, "#define WRITE_%s(u,i,r) %s(u,i,%s%s, &(r._%s),__FILE__,__LINE__)\n", 
                s->name, OPT_MEM_WRITE, OPT_DSYM_PREFIX, s->name, sname);
    }
    fprintf(fp, "\n\n"); 
    return 0; 
}


/*
 * Generate register and field read/write macros for all symbols. 
 * These macros are compatible with the compile-time definitions
 * provided by the per-chip static register files. 
 *
 */

static int
_generate_definitions(FILE* fp)
{
    int s; 
    char* comments = 
        "Dynamic Register and Memory Structures and Macros\n" 
        "\n"
        "All programming of registers and memories should be done\n"
        "using these structures and macros.\n"
        "\n"
        "These structures and macros are also compatible with the\n"
        "static versions provided for each chip."; 
    
    cg_bcommentf(fp, comments); 
    cg_nl(fp, 1); 

    /* Foreach symbol */
    for(s = 0; allsyms[s].name; s++) {
        /* Generate the storage union */ 
        _generate_definition(fp, allsyms+s); 
    }
    return 0; 
}


static void
_document_config(FILE* fp)
{
    int d; 
    cg_bcomment_start(fp);
    cg_mcommentf(fp, "Generated for the following devices:"); 
    for(d = 0; d < cdkDevTypeCount; d++) {
        if(_included[d]) {
            cg_mcommentf(fp, "    %s", _dev_type_name(d));
        }       
    }
    cg_bcomment_end(fp); 
    cg_nl(fp, 1);
}


static int
_generate_device_symbol_table(FILE* sfp, int dev, const char* includes)
{
    allsyms_t* s;
    char sname[128];
    int count = 0; 
    FILE* fp = NULL; 
    int i; 
    const char* devname = _dev_type_name(dev); 
    
    if(sfp == NULL) {
        fp = file_open(OPT_DYN_SYMS_DIR, NULL, "%s_sym.c", devname); 
        assert(fp); 
    }   
    else {
        fp = sfp; 
    }

    cg_file_start(fp, NULL, NULL, includes); 

    /* Table Definition */
    fprintf(fp, "#define CDK_EXCLUDE_CHIPLESS_TYPES\n"); 
    fprintf(fp, "#include <cdk/chip/%s_defs.h>\n\n\n", devname); 
    fprintf(fp, "cdk_symbol_t %s_dsyms[] = \n", devname); 
    fprintf(fp, "{\n"); 

    /* Foreach symbol */
    for(i = 0, s = allsyms; s->name; i++, s++) {
        cdk_symbol_t* sym = s->symbols+dev; 

        /* If it exists on this device */
        if(sym->name) {
            int index; 

            /* Output Symbol Table Entry */
            if(sym->flags & CDK_SYMBOL_FLAG_COUNTER) {
                /* Counters do not get fields descriptors */
                index = -1; 
            }   
            else if(_find_field_set(sym, dev, &index) == -1) {
                /* This should not happen */
                internal_error(__LINE__, "Cannot find fieldset index %s (%s:%d)", sym->name, 
                                devname, dev); 
            }

            fprintf(fp, "  /* %d */\n", i); 
            fprintf(fp, "  {\n"); 
            fprintf(fp, "    %s_%s,\n", stoupper(devname, sname), s->name); 
            fprintf(fp, "#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1\n"); 
            fprintf(fp, "#ifndef CDK_CONFIG_EXCLUDE_FIELD_INFO_%s\n", stoupper(devname, sname)); 
            if(index == -1) {
                fprintf(fp, "    0,\n"); 
            } else {
                fprintf(fp, "    %stype%.4d_fields,\n", OPT_DSYM_PREFIX, index); 
            }
            fprintf(fp, "#else\n"); 
            fprintf(fp, "    0,\n"); 
            fprintf(fp, "#endif\n"); 
            fprintf(fp, "#endif\n"); 
            fprintf(fp, "    0x%x,\n", sym->index); 
            fprintf(fp, "    0x%x,\n", sym->flags); 
            fprintf(fp, "    \"%s\"\n", s->name); 
            fprintf(fp, "  },\n"); 
                    

            /* Record the offset of this symbol in the table */
            s->symbol_offsets[dev] = count++; 
        }       
        else {
            /* Symbol is invalid. Set to the invalid entry for this table */
            s->symbol_offsets[dev] = _maps[dev].syms->size; 
        }       
    }   

    /* 
     * Every regenerated symbol table has an "invalid" entry
     * at the end with addr=0xFFFFFFFF. The index of this invalid entry is used 
     * for the symbol offset when the symbol does not exist on this chip. 
     */
    fprintf(fp, "  /* Invalid Entry */\n"); 
    fprintf(fp, "  { 0xFFFFFFFF }\n"); 

    fprintf(fp, "};\n\n"); 


    /*
     * Output the cdk_symbols_t structure
     */
    fprintf(fp, "#if CDK_CONFIG_INCLUDE_FIELD_NAMES == 1\n"); 
    fprintf(fp, "extern const char* cdk_dsym_field_names[];\n"); 
    fprintf(fp, "#endif\n\n"); 

    fprintf(fp, "cdk_symbols_t %s_dsymbols =\n", devname); 
    fprintf(fp, "{\n"); 
    fprintf(fp, "  %s_dsyms, sizeof(%s_dsyms)/sizeof(%s_dsyms[0]) - 1,\n", 
            devname, devname, devname); 
    fprintf(fp, "#if CDK_CONFIG_INCLUDE_FIELD_NAMES == 1\n");
    fprintf(fp, "  cdk_dsym_field_names\n"); 
    fprintf(fp, "#else\n"); 
    fprintf(fp, "  NULL\n"); 
    fprintf(fp, "#endif\n"); 
    fprintf(fp, "};\n");            

    cg_file_end(fp, NULL);     

    if(!sfp) {
        fclose(fp); 
    }   


    /*
     * A Little sanity checking.
     * The table we just output should have the same number of entries
     * as the original symbol table. 
     *
     * The original table size can be retrieved from the symtab_map. 
     */
    if(count != _maps[dev].syms->size) {
        internal_error(__LINE__, 
                        "Regenerated symbol table for %s has count %d."
                        " Original symbol count was %d\n", 
                        devname, count, 
                        _maps[dev].syms->size); 
    }
    
    return 0; 
}

static int
_generate_device_symbol_object(FILE* cfp, allsyms_t* s, int dev, const char* includes)
{
    /* Output the symbol information for this device */
    const char* device = _dev_type_name(dev); 
    cdk_symbol_t* sym = s->symbols+dev; 
    FILE* fp = NULL; 

    
    if(cfp) {
        fp = cfp;
    }
    else {
        fp = file_open(OPT_DYN_CHIP_DIR, device, "%s_%s.c", device, s->name); 
        printf("\rWriting %s/%s_%s.c...                    ", device, device, s->name); 
    }


    cg_file_start(fp, NULL, NULL, includes); 

    /*
     * Does this symbol exist on this device?
     */
    if(sym->name == NULL) {
        /*
         * Symbol does not exist on this device
         */
        cg_commentf(fp, "%s does not exist on %s", s->name, device); 
        fprintf(fp, "%s %s_%s%s = {0xFFFFFFFF};\n", 
                OPT_DSYM_STRUCT_T, device, OPT_DSYM_PREFIX, s->name); 
    }
    else {
        
        
        /*
         * Determine which unique field structure defines this symbol for this chip
         */
        int index; 

        if(!(sym->flags & CDK_SYMBOL_FLAG_COUNTER)) {
            
            if(_find_field_set(sym, dev, &index) == -1) {
                /* This should not happen */
                internal_error(__LINE__, "Cannot find fieldset index %s (%s:%d)", sym->name, 
                                _dev_type_name(dev), dev); 
            }

            /*
             * Output the extern for the unique field structure
             */
            cg_commentf(fp, "%s:%s uses field structure %d", device, sym->name, index); 
            fprintf(fp, "extern %s %stype%.4d_fields[];\n\n", 
                    OPT_DSYM_FIELD_T, OPT_DSYM_PREFIX, index); 

            /*
             * Output symbol definition structure
             */

            fprintf(fp, "%s %s_%s%s =\n", 
                    OPT_DSYM_STRUCT_T, device, OPT_DSYM_PREFIX, s->name); 
            fprintf(fp, "{ 0x%x, %stype%.4d_fields, 0x%x, 0x%x };\n", 
                    sym->addr, OPT_DSYM_PREFIX, index, sym->index, sym->flags); 
        }       
        else {
            /*
             * Output symbol definition structure
             */

            fprintf(fp, "%s %s_%s%s =\n", 
                    OPT_DSYM_STRUCT_T, device, OPT_DSYM_PREFIX, s->name); 
            fprintf(fp, "{ 0x%x, NULL, 0x%x, 0x%x };\n", 
                    sym->addr, sym->index, sym->flags); 
        }
    }

    if(!cfp) {
        fclose(fp); 
    }   
    return 0; 
}

static int
_generate_dispatch_object(FILE* dfp, allsyms_t* s, const char* includes)
{

    FILE* fp = NULL; 
    int d; 

    if(dfp) {
        fp = dfp; 
    }
    else {
        fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, "dispatch_%s.c", s->name); 
        printf("\rWriting dispatch_%s.c...                    ", s->name); 
    }   
    
    cg_file_start(fp, NULL, NULL, includes); 

    /*
     * Generate the dispatch table for every symbol. 
     */
    
    fprintf(fp, "#if CDK_CONFIG_DSYMS_USE_SYMTAB == 1 || CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n"); 
  
    fprintf(fp, "\n"); 
    cg_commentf(fp, "These are the offsets for this symbol in each device's symtab"); 

    for(d = 0; d < cdkDevTypeCount; d++) {            
        char b[256]; 

        if(!_included[d]) {
            continue; 
        }   

        sprintf(b, "%s_%s_SO", 
                _dev_type_name(d), s->name); 
        
        fprintf(fp, "#define %-65s %5d\n", 
                b, s->symbol_offsets[d]); 
    }       
    fprintf(fp, "\n"); 

    cg_commentf(fp, "Extern the chip symbol table"); 
    fprintf(fp, "#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \\\n"); 
    fprintf(fp, "extern cdk_symbol_t _bd##_dsyms[];\n");  
    fprintf(fp, "#include <cdk/cdk_devlist.h>\n\n"); 

    cg_commentf(fp, "The actual dispatch table for %s", s->name); 
    fprintf(fp, "#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \\\n"); 
    fprintf(fp, "(cdk_dsymbol_t*)(_bd##_dsyms + _bd##_%s_SO),\n", s->name); 
    fprintf(fp, "#if CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n"); 
    fprintf(fp, "%s* %s%s_s[] = \n{\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#else\n"); 
    fprintf(fp, "%s* %s%s[] = \n{\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#endif\n"); 
    fprintf(fp, "#include <cdk/cdk_devlist.h>\n\n"); 
    fprintf(fp, "};\n"); 

    fprintf(fp, "#endif\n"); 
    
    fprintf(fp, "#if CDK_CONFIG_DSYMS_USE_SYMTAB == 0 || CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n"); 
    cg_commentf(fp, "Use individual structures"); 
    cg_commentf(fp, "Externs for the required symbol structures for %s", s->name); 
    fprintf(fp, "#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \\\n"); 
    fprintf(fp, "extern %s %s_%s%s;\n", 
            OPT_DSYM_STRUCT_T, "_bd##", OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#include <cdk/cdk_devlist.h>\n\n"); 

    cg_commentf(fp, "The actual dispatch table for %s", s->name); 
    fprintf(fp, "#define CDK_DEVLIST_ENTRY(_nm,_vn,_dv,_rv,_md,_pi,_bd,_bc,_fn,_fl,_cn,_pf,_pd,_r0,_r1) \\\n"); 
    fprintf(fp, "& %s_%s%s,\n", "_bd##", OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#if CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n"); 
    fprintf(fp, "%s* %s%s_d[] = \n{\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#else\n"); 
    fprintf(fp, "%s* %s%s[] = \n{\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX, s->name); 
    fprintf(fp, "#endif\n");             
    fprintf(fp, "#include <cdk/cdk_devlist.h>\n\n"); 
    fprintf(fp, "#if CDK_CONFIG_DSYMS_INCLUDE_NAMES == 1\n"); 
    fprintf(fp, "(cdk_dsymbol_t*) \"%s\"\n", s->name); 
    fprintf(fp, "#endif /* CDK_CONFIG_DSYMS_INCLUDE_NAMES == 1 */\n"); 
    fprintf(fp, "};\n"); 

    fprintf(fp, "#endif\n"); 

    if(!dfp) {
        fclose(fp); 
    }

    return 0; 
}


/*******************************************************************************
 *
 * Public DSYM routines
 *
 ******************************************************************************/



/*
 * Generate the public dynamic header. 
 * This header defines all register read/write macros
 * and all field enumerations. 
 */

int
dsym_gen_defs_header(FILE* hfp, const char* name, const char* includes)
{
    FILE* fp; 
    
    if(!hfp) {
        fp = file_open(NULL, NULL, OPT_DYN_HEADER_FILE); 
        assert(fp); 
    }   
    else {
        fp = hfp; 
    }


    /* Conditional, comments, and includes */
    cg_file_start(fp, name, NULL, includes); 

    /* Document the configuration from which we are generating */
    _document_config(fp); 

    /* Start with the Field Enumeration definitions */
    cg_next_section(fp); 
    _generate_allfields_enumeration(fp); 

    /* Externs, Structures and Macros for all symbols */
    cg_next_section(fp); 
    _generate_definitions(fp); 


    cg_file_end(fp, name); 

    if(!hfp) {
        fclose(fp); 
    }
    return 0; 
}



int
dsym_gen_chip_objects(FILE* fp, const char* includes)
{    
    allsyms_t* s; 
    
    /* Foreach symbol */
    for(s = allsyms; s->name; s++) {
        /* Foreach device */
        int d; 
        for(d = 0; d < cdkDevTypeCount; d++) {
            if(_included[d]) {
                _generate_device_symbol_object(fp, s, d, includes); 
            }   
            //_allsym_entry_count++; 
        }       
    }   

    return 0; 
}

int
dsym_gen_symbol_tables(FILE* fp, const char* includes)
{
    int i; 
    /* Regenerate all chip symbol tables */
    for(i = 0; i < cdkDevTypeCount; i++) {
        if(_included[i]) {
            _generate_device_symbol_table(fp, i, includes); 
        }
    }       
    return 0; 
}



int
dsym_gen_symbol_offset_header(FILE* fp, const char* name, 
                              const char* includes)
{       
    allsyms_t* s;

    const char* comments =
        "This file defines the offsets for each symbol in each device's symbol table.\n"
        "\n"
        "These offsets are used to produce the pointers that go in each symbol's\n"
        "dispatch table when the full symbol table for each device is included in\n"
        "the build."; 


    cg_file_start(fp, name, NULL, includes); 
    
    cg_commentf(fp, comments); 
    
    fprintf(fp, "#if CDK_CONFIG_DSYMS_USE_SYMTAB == 1 || CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n\n"); 

    /* Foreach symbol */
    for(s = allsyms; s->name; s++) {        

        /* Foreach Device */
        int d; 
        for(d = 0; d < cdkDevTypeCount; d++) {            
            char b[256]; 

            if(!_included[d]) {
                continue; 
            }   

            sprintf(b, "%s_%s_SO", 
                    _dev_type_name(d), s->name); 
                        
            fprintf(fp, "#define %-65s %5d\n", 
                    b, s->symbol_offsets[d]); 
        }       
    }   
    
    fprintf(fp, "\n#endif /* CDK_CONFIG_DSYMS_USE_SYMTAB */\n"); 
    cg_file_end(fp, name); 
    return 0; 
}       

/*
 * Not used anymore
 */
#if NOTDEF
int
dsym_gen_string_header(FILE* hfp, const char* name, 
                       const char* includes)
{
    allsyms_t* s; 
    FILE* fp; 

    if(hfp == NULL) {
        fp = file_open(NULL, NULL, OPT_DYN_ALLSTRINGS_HEADER); 
        assert(fp); 
    }   
    else {
        fp = hfp; 
    }   
    
    cg_file_start(fp, name, NULL, includes); 

    /* Foreach Symbol */
    for(s = allsyms; s->name; s++) {
        /* Extern the string pointer */
        fprintf(fp, "extern const char %s_str[];\n", s->name); 
    }   
    
    cg_file_end(fp, name); 
    
    if(!hfp) {
        fclose(fp); 
    }   
    return 0; 
}
#endif /* NOTDEF */


int
dsym_gen_string_file(FILE *sfp, const char* includes)
{
    FILE* fp; 
    const char** str; 

    if(sfp == NULL) {
        fp = file_open(NULL, NULL, OPT_DYN_ALLSTRINGS_FILE); 
        assert(fp); 
    }   
    else {
        fp = sfp; 
    }       

    cg_file_start(fp, NULL, NULL, includes); 

    fprintf(fp, "const char* cdk_dsym_field_names[] = \n"); 
    fprintf(fp, "{\n"); 
    for(str = allfields; *str; str++) {
        fprintf(fp, "  \"%s\",\n", *str); 
    }
    fprintf(fp, "};\n\n"); 
            
            
    cg_file_end(fp, NULL); 

    if(!sfp) {
        fclose(fp); 
    }
    return 0; 
}       
    

int 
dsym_gen_field_header(FILE* ffp, const char* name, const char* includes)
{       
        int i;
        FILE* fp; 

        if(ffp) {
                fp = ffp; 
        }       
        else {
                fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLFIELDS_HEADER_FILE); 
        }       
                
        cg_file_start(fp, name, NULL, includes); 
        
        fprintf(fp, "#if CDK_CONFIG_INCLUDE_FIELD_INFO == 1\n\n"); 

        for(i = 0; allfield_info[i].count; i++) {
                fprintf(fp, "extern %s %stype%.4d_fields[];\n", 
                        OPT_DSYM_FIELD_T, OPT_DSYM_PREFIX, i);  
        }       

        cg_nl(fp, 1); 
        fprintf(fp, "#endif /* CDK_CONFIG_INCLUDE_FIELD_INFO */\n"); 
        cg_file_end(fp, name); 
        return 0; 
}

int
dsym_gen_field_objects(FILE* ffp, const char* includes)
{
    /*
     * Generate the field structures for all unique fieldsets
     */ 
    FILE* fp = NULL; 
    
    int i, j;  
    
    for(i = 0; allfield_info[i].count; i++) {
        
        /*
         * If 'ffp' is NULL we should output this definition
         * in to its own file
         */
        if(ffp) {
            fp = ffp; 
        }
        else {
            fp = file_open(OPT_DYN_FIELD_DIR, NULL, "field_type%.4d.c", i); 
            printf("\rWriting field_type%.4d.c...                    ", i); 
        }       

        cg_file_start(fp, NULL, NULL, includes); 
        
        /*
         * Document which devices use this field structure
         */        
        cg_bcomment_start(fp);
        cg_mcommentf(fp, "Field Structure %d is used for the following:\n \n", i); 
        for(j = 0; j < cdkDevTypeCount; j++) {
            const char** s; 
            if(!_included[j]) {
                continue; 
            }   
            for(s = allfield_info[i].elements[j]; *s; s++) {            
                cg_mcommentf(fp, "    %s:%s", _dev_type_name(j), *s);
            }
        }       
        cg_bcomment_end(fp); 
        cg_nl(fp,1); 

        /* Field Definition */
        fprintf(fp, "%s %stype%.4d_fields[] = \n", 
                OPT_DSYM_FIELD_T, OPT_DSYM_PREFIX, i); 
        fprintf(fp, "{\n"); 

        for(j = 0; j < allfield_info[i].count; j++) {
            cdk_field_info_t* finfo = allfield_info[i].finfo+j; 
            int fid = _find_allfield_index(finfo->name); 
            int last; 
            const char* ext=NULL; 

            
            fprintf(fp, "    /* %s:%d:%d */\n", finfo->name, finfo->minbit, finfo->maxbit); 
            
            /* Is this the last field? */
            last = (j == allfield_info[i].count - 1); 

            /* Single Word or Double Word format? */
            if(fid < (1<<14) && finfo->maxbit < 256 && finfo->minbit < 256) {
                /* Single Word Format */
                ext=""; 
            }
            else {
                /* Double Word Format */
                ext="_EXT"; 
            }   

            if(last) {
                fprintf(fp, "    CDK_SYMBOL_FIELD_FLAG_LAST | CDK_SYMBOL_FIELD%s_ENCODE(%d, %d, %d)", 
                        ext, fid, finfo->maxbit, finfo->minbit); 
            } else {            
                fprintf(fp, "    CDK_SYMBOL_FIELD%s_ENCODE(%d, %d, %d)", ext, fid, finfo->maxbit, finfo->minbit); 
            }           
            
            if(!last) {
                fprintf(fp, ","); 
            }
            fprintf(fp, "\n");                 

            allfield_entry_count++; 
        }       
        fprintf(fp, "};\n"); 


        /* If we created a new file, close it */
        if(!ffp) {
            fclose(fp); 
        }

    }   

    return 0; 
}


int
dsym_gen_dispatch_objects(FILE* fp, const char* includes)
{    
    allsyms_t* s; 
    
    /* Foreach symbol */
    for(s = allsyms; s->name; s++) {
        _generate_dispatch_object(fp, s, includes); 
    }   

    
    return 0; 
}

static int
_generate_dispatch_table(FILE* fp, const char* name,
                         const char* suffix)
{
    allsyms_t* s; 

    /* Foreach symbol */
    for(s= allsyms; s->name; s++) {
        /* Extern each dsym object */
        fprintf(fp, "extern %s* %s%s%s[];\n", OPT_DSYM_STRUCT_T, OPT_DSYM_PREFIX, s->name, suffix); 
    }   
    
    fprintf(fp, "\n\ncdk_dsym_map_t %s[] = \n", name); 
    fprintf(fp, "{\n"); 
           
    /* Foreach symbol */
    for(s = allsyms; s->name; s++) {
        /* Produce the map structure for this symbol */
        fprintf(fp, "  {\n"); 
        fprintf(fp, "    \"%s\",\n", s->name); 
        fprintf(fp, "    %s%s%s,\n", OPT_DSYM_PREFIX, s->name, suffix); 
        fprintf(fp, "  },\n"); 
    }
    fprintf(fp, "  { NULL, NULL }\n"); 
    fprintf(fp, "};\n"); 

    return 0; 
}

int
dsym_gen_dispatch_tables(FILE* fp, const char* includes)
{
    int i; 

    fprintf(fp, "#include <cdk_config.h>\n"); 
    fprintf(fp, "#include <cdk/cdk_dsymbols.h>\n"); 


    fprintf(fp, "\n");
    fprintf(fp, "/*\n"); 
    fprintf(fp, " * The following table describes all field alias mappings for FIDs with the MULTIFIELD bit set.\n"); 
    fprintf(fp, " */\n"); 
    fprintf(fp, "cdk_dsym_multifield_t dsym_multifield_map[] = \n"); 
    fprintf(fp, "{\n"); 
    for(i = 0; allfield_aliases[i].name; i++) {
        int j;

        if(allfield_aliases[i].count > 1) {
            fprintf(fp, "    /* Multifield group %d Aliases for field %s */\n", allfield_aliases[i].index, allfield_aliases[i].name); 
            fprintf(fp, "    {{ "); 
            for(j = 0; j < CDK_DSYM_MAX_MULTIFIELDS-1; j++) {
                fprintf(fp, "%d,", allfield_aliases[i].fids[j]); 
            }   
            fprintf(fp, "%d }},\n", allfield_aliases[i].fids[j]); 
        }       
    }   
    fprintf(fp, "    /* Unused entry to avoid compilation errors */\n"); 
    fprintf(fp, "    {{ 0 }}\n"); 
    fprintf(fp, "};\n\n\n"); 


    fprintf(fp, "#if CDK_CONFIG_DSYMS_INCLUDE_ALL == 1\n\n"); 

    cg_file_start(fp, NULL, NULL, includes); 

    cg_commentf(fp, "Symbol Table DSYM Objects"); 
    _generate_dispatch_table(fp, "cdk_dsym_map_s_table", "_s"); 
    cg_commentf(fp, "Individual DSYM Objects\n"); 
    _generate_dispatch_table(fp, "cdk_dsym_map_d_table", "_d"); 
    
    fprintf(fp, "#endif /* CDK_CONFIG_DSYMS_INCLUDE_ALL == 1 */\n"); 
    return 0; 
}       

int
dsym_build_structures(void)
{    
    
    if((allsyms = malloc(DSYM_MAX_SYM_COUNT*sizeof(allsyms_t))) == NULL) {
        internal_error(__LINE__, "could not allocate allsyms array\n"); 
    }   
    if((allfields = malloc(DSYM_MAX_FIELD_COUNT*sizeof(char*))) == NULL) {
        internal_error(__LINE__, "could not allocate allfields array\n"); 
    }
    if((allfield_aliases = malloc(DSYM_MAX_FIELD_COUNT * sizeof(allfield_alias_t))) == NULL) {
        internal_error(__LINE__, "could not allocate allfield_aliases array\n"); 
    }   
    if((allfield_info = malloc(DSYM_MAX_SYM_COUNT*sizeof(allfield_info_t))) == NULL) {
        internal_error(__LINE__, "could not allocate allfield_info array\n"); 
    }   

    /*
     * Build the allsyms table
     */
    _build_allsyms(); 

    /* 
     * Build the allfields table
     */
    _build_allfields(); 

    return 0; 
}

const char* dsym_devname(int dev)
{
    return _dev_type_name(dev); 
}

int 
dsym_list_symbols(FILE* fp)
{
    allsyms_t* s; 
    
    for(s = allsyms; s->name; s++) {
        int d; 
        fprintf(fp, "%s,", s->name); 

        for(d = 0; d < cdkDevTypeCount; d++) {
            
            if(_included[d] && s->symbols[d].name) {
                /* Exists on this device */
                fprintf(fp, "%s,", dsym_devname(d)); 
            }   
        }       
        fprintf(fp, "\n"); 
    }
    return 0; 
}       
