/*******************************************************************************
 * $Id: options.c,v 1.4 Broadcom SDK $
 * $Copyright$
 *
 * options.c
 *
 ******************************************************************************/


/*^*****************************************************************************
 * 
 * PROGRAM OPTIONS AND OPTION PROCESSING
 * 
 *
 ******************************************************************************/
#include "options.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

/* Program option storage and processing */
#define MAX_OPTIONS 64

struct options_s {
    char name[64]; 
    char value[128]; 
} options[MAX_OPTIONS+1] = {

#define OPT_ENTRY(name) { DSYM_OPTION_##name, DSYM_##name }

    /* Output Directory */
    OPT_ENTRY(DYN_OUTPUT_DIR), 

    /* Output Type */
    OPT_ENTRY(DYN_OUTPUT_TYPE), 

    { "help", "0" }, 
    { "h", "0" }, 
    { "chips", "0" },
    { "all", "1" }, 
    { "list", "0" },
    { "warn", "0" },
    { "quiet", "0" }, 
    { "q", "0" }, 
    { "", "" }, 
}; 

void
dsym_help(void)
{
    printf("\n"); 
    printf("DSYMS\n"); 
    printf("\n"); 
    printf("    Generates Dynamic Symbol Definitions for the current CDK installation.\n"); 
    printf("\n"); 
    printf("USAGE\n"); 
    printf("\n"); 
    printf("    dsyms [options]+n\n"); 
    printf("\n"); 
    printf("    where options are:\n"); 
    printf("        ot=<type>    -- Specifies the type of output. Options are:\n"); 
    printf("           stdout    -- Output everything to stdout. Mainly for testing purposes.\n"); 
    printf("           single    -- Output a single file for each generation type.\n");
    printf("           files     -- Output individual files for all functions and data.\n"); 
    printf("\n"); 
    printf("        od=<dir>     -- Specifies the output directory for the generated files.\n"); 
    printf("\n"); 
    printf("        chips        -- Displays the chips included in this build of the program.\n"); 
    printf("\n"); 
    printf("        all=<0,1>    -- Include or exclude all chips by default. This is the default.\n"); 
    printf("                        All chips are included by default. \n"); 
    printf("\n"); 
    printf("        <chip>=<0,1> -- Include or exclude support for the given chip.\n"); 
    printf("\n"); 
    printf("        help         -- displays this help message.\n"); 
    printf("\n"); 
    printf("        quiet        -- Restrict output.\n"); 
    printf("\n"); 
    printf("EXAMPLES\n"); 
    printf("\n"); 
    printf("    <addme>\n"); 
    printf("\n"); 

    exit(0); 
}



/*
 * Parse the program options
 */
int
parse_options(int argc, char* argv[])
{
    int i; 
    char line[128]; 

    for(i = 0; argv[i]; i++) {
        int j; 
        char* opt, *val; 

        ASTRNCPY(line, argv[i]); 

        opt = line; 

        /* Allow "-"/"--" in front of the option */
        while(opt[0] && opt[0] == '-') {
            opt++; 
        }
        if(!opt[0]) {
            continue;
        }
                    
        /* Allow values */
        val = strchr(line, '='); 
        if(val) {
            *val = 0; 
            val++; 
        }
        
        for(j = 0; options[j].name[0]; j++) {
            if(!strcmp(opt, options[j].name)) {
                /* Found an option */
                if(val) {
                    /* Option has a value */
                    ASTRNCPY(options[j].value, val); 
                }
                else {
                    /* Option is a switch */
                    ASTRNCPY(options[j].value, "1"); 
                }
                break; 
            }
        }       

        /* 
         * Any options not in the table should will be 
         * added and the option will be reparsed. 
         * This is mainly for the chip options. 
         */
        if(options[j].name[0] == 0 && j < MAX_OPTIONS) {
            ASTRNCPY(options[j].name, opt); 
            i--;
        }       
    }   

    return 0; 
}

/*
 * Retreive a string option value
 */
const char* 
soption(const char* name)
{
    int i;
    for(i = 0; options[i].name[0]; i++) {
        if(!strcmp(name, options[i].name)) {
            return options[i].value; 
        }
    }
    return NULL; 
}

/*
 * Retrieve an integer option value
 */
int
ioption(const char* name)
{
    if(soption(name)) {
        return atoi(soption(name)); 
    }   
    else {
        return -1; 
    }   
}
