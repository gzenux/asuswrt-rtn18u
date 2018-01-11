#include "options.h"
#include "dsyms.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char* argv[])
{       
    FILE* defs_fp = NULL; 
    FILE* dispatch_fp = NULL;
    FILE* fields_fp = NULL; 
    FILE* fieldsh_fp = NULL; 
    FILE* chips_fp = NULL;  
    FILE* symbols_fp = NULL; 
    /* FILE* stringsh_fp = NULL; */
    FILE* stringsf_fp = NULL;
    /* FILE* soffset_fp = NULL; */
    FILE* dispatch_tables_fp = NULL; 
    int i; 

    /*
     * parse options
     */
    parse_options(--argc, ++argv); 

    /*
     * Help? 
     */
    if(ioption("help") || ioption("h") || argc==0) {
        dsym_help(); 
    }

    /*
     * Chips?
     */
    if(ioption("chips")) {
        /* Display all chips in this build */
        int i; 
        
        printf("The following chips are available:\n"); 

        for(i = 1; dsym_chips[i]; i++) {
            printf("    %s\n", dsym_chips[i]); 
        }
        printf("\n"); 
        exit(0); 
    }           

    /* 
     * Process chip includes
     */
    dsym_include(-1, OPT_INCLUDE_ALL); 

    for(i = 1; dsym_chips[i]; i++) {
        int s = ioption(dsym_chips[i]); 
        if(s >= 0) {
            dsym_include(i, s); 
        }       
    }           

    dsym_build_structures(); 

    /*
     * List?
     */
    if(ioption("list")) {
        dsym_list_symbols(stdout); 
        exit(0); 
    }   

    /*
     * Build Output Layout
     */
    if(OPT_DYN_OUTPUT_DIR && OPT_DYN_OUTPUT_DIR[0]) {
        create_dir(OPT_DYN_OUTPUT_DIR); 
        change_dir(OPT_DYN_OUTPUT_DIR); 
    }

    if(!strcmp(OPT_DYN_OUTPUT_TYPE, "stdout")) {
        /* Output everything to stdout */
        defs_fp = stdout; 
        dispatch_fp = stdout; 
        fields_fp = stdout; 
        fieldsh_fp = stdout; 
        chips_fp = stdout; 
        symbols_fp = stdout; 
        /* stringsh_fp = stdout; */
        stringsf_fp = stdout;
        /* soffset_fp = stdout; */
        dispatch_tables_fp = stdout; 
    }   
    else if(!strcmp(OPT_DYN_OUTPUT_TYPE, "single")) {

        /* Output each object type to a single file in the output directory */
        defs_fp = file_open(OPT_DYN_HEADER_DIR, NULL, OPT_DYN_HEADER_FILE); 
        dispatch_fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, "dispatch.c"); 
        fields_fp = file_open(OPT_DYN_FIELD_DIR,  NULL, "fields.c"); 
        fieldsh_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLFIELDS_HEADER_FILE); 
        chips_fp = file_open(OPT_DYN_CHIP_DIR, NULL, "chips.c"); 
        symbols_fp = file_open(OPT_DYN_SYMS_DIR, NULL, "allsyms.c"); 
        /* stringsh_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLSTRINGS_HEADER); */
        stringsf_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLSTRINGS_FILE); 
        /* soffset_fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, OPT_DYN_OFFSETS_HEADER); */
        dispatch_tables_fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, "dispatch_tables.c"); 
    }   
    else if(!strcmp(OPT_DYN_OUTPUT_TYPE, "files")) {
        /* Output each object into a separate file */
        defs_fp = file_open(OPT_DYN_HEADER_DIR, NULL, OPT_DYN_HEADER_FILE); 
        dispatch_fp = NULL; 
        fields_fp = NULL; 
        fieldsh_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLFIELDS_HEADER_FILE); 
        chips_fp = NULL; 
        symbols_fp = NULL;
        /* stringsh_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLSTRINGS_HEADER); */
        stringsf_fp = file_open(OPT_DYN_SYMS_DIR, NULL, OPT_DYN_ALLSTRINGS_FILE); 
        /* soffset_fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, OPT_DYN_OFFSETS_HEADER); */
        dispatch_tables_fp = file_open(OPT_DYN_DISPATCH_DIR, NULL, "dispatch_tables.c"); 
    }   
    else {
        fprintf(stderr, "Unnown output type '%s'\n", OPT_DYN_OUTPUT_TYPE); 
        exit(-1); 
    }

    
    /* Generate Files */
    dsym_gen_defs_header(defs_fp, OPT_DYN_HEADER_NAME, OPT_DYN_HEADER_HEADERS); 
    dsym_gen_field_objects(fields_fp, OPT_DYN_FIELD_HEADERS); 
    dsym_gen_field_header(fieldsh_fp, OPT_DYN_ALLFIELDS_HEADER_NAME, OPT_DYN_ALLFIELDS_HEADERS); 
    dsym_gen_chip_objects(chips_fp, OPT_DYN_CHIP_HEADERS); 
    dsym_gen_symbol_tables(symbols_fp, OPT_DYN_SYMS_HEADERS); 
    dsym_gen_dispatch_objects(dispatch_fp, OPT_DYN_DISPATCH_HEADERS); 
    dsym_gen_dispatch_tables(dispatch_tables_fp, OPT_DYN_DISPATCH_HEADERS); 
    /* dsym_gen_symbol_offset_header(soffset_fp, OPT_DYN_OFFSETS_HEADER_NAME, NULL); */
    /* dsym_gen_string_header(stringsh_fp, OPT_DYN_ALLSTRINGS_HEADER_NAME, NULL); */
    dsym_gen_string_file(stringsf_fp, NULL); 

    if(ioption("quiet") == 0 && ioption("q") == 0) {        
        int i; 
        int syms; 
        printf("Generated for the following chips:\n"); 
        for(i = 0; i < cdkDevTypeCount; i++) {
            if(dsym_included(i)) {
                printf("    %s\n", dsym_devname(i)); 
            }   
        }
        printf("\n"); 
        for(i = 0; allsyms[i].name; i++); 
        printf("Total Unique Symbols: %d\n", syms=i); 
    }           

    return 0; 
}
