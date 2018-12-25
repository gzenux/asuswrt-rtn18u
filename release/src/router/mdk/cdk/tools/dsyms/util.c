/*******************************************************************************
 * $Id: util.c,v 1.3 Broadcom SDK $
 * $Copyright$
 *
 * util.c
 *
 ******************************************************************************/

/*******************************************************************************
 *
 * Utility Functions
 *
 ******************************************************************************/

#include "util.h"
#include "options.h"

#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
      
#include <unistd.h>

/*
 * Open an output file
 */

FILE* 
file_open(const char* dir, const char* subdir, const char* format, ...)
{
    FILE* fp = NULL; 
    va_list args; 
    char bname[1024]; 
    char fname[1024]; 
    char parent[1024]; 

    /* Build the base filename */
    va_start(args, format);    
    vsnprintf(bname, sizeof(bname), format, args); 
    va_end(args);

    /*
     * No Filename?
     */
    if(bname[0] == 0) {
        internal_error(__LINE__, "no file specified"); 
    }
    
    /*
     * Filename is stdout?
     */
    if(!strcmp(bname, "stdout")) {
        return stdout; 
    }


    if(dir) {
        if(subdir) {
            sprintf(parent, "%s%s%s", dir, OPT_DIR_SEPARATOR, subdir); 
        }
        else {
            ASTRNCPY(parent, dir); 
        }                       
        /* Create directory */
        sprintf(fname, "%s%s%s", parent, OPT_DIR_SEPARATOR, bname);        
    }   
    else {
        strcpy(fname, bname); 
    }   
    
    
    if(!(fp = fopen(fname, "w"))) {
        create_dir(parent); 
        fp = fopen(fname, "w"); 
    }
                
    if(!fp) {
        internal_error(__LINE__, "could not open output file '%s'\n", fname); 
    }   

    return fp;        
}       


/*
 * Convert strings to upper/lowercase
 */
char* 
stolower(const char* s, char* d)
{
    char* r = d; 
    while(*s) {
        *d++ = tolower(*s++); 
    }
    *d = 0; 
    return r;
}

char*
stoupper(const char* s, char* d)
{
    char* r = d; 
    while(*s) {
        *d++ = toupper(*s++); 
    }   
    *d = 0; 
    return r; 
}       

/*
 * Report an internal error
 */
int
internal_error(int line, const char* format, ...)
{
    va_list args; 
    va_start(args, format);     
    fprintf(stderr, "*** internal error (%d): ", line); 
    vfprintf(stderr, format, args); 
    fprintf(stderr, "\n"); 
    exit(-1); 
    return 0; 
}

/*
 * Report an internal warning
 */
int
warning(int line, const char* format, ...)
{
    va_list args; 
    va_start(args, format);     
    fprintf(stderr, "*** warning (%d): ", line); 
    vfprintf(stderr, format, args); 
    fprintf(stderr, "\n"); 
    va_end(args); 
    return 0; 
}



/* TODO: Windows Porting support */
int create_dir(const char* path)
{
    char cmd[256];
    int rc; 

    snprintf(cmd, sizeof(cmd), "mkdir -p %s", path); 
    rc = system(cmd); 

    if(rc != 0) {
        internal_error(__LINE__, "Could not create directory path '%s'\n", path); 
    }   

    return 0; 
}       


int change_dir(const char* path)
{
    if(chdir(path) != 0) {
        internal_error(__LINE__, "Could not change directory to %s\n", path); 
    }   
    return 0; 
}
    
    
    
/*
 * Parse a string based on delimiter. Simple static data return. 
 */
static char _scopy[2048];
static const char* _results[128]; 

const char** 
parse_string(const char* src, const char* delim)
{
    char* s; 
    const char** dst; 

    if(!src) {
        return NULL; 
    }

    ASTRNCPY(_scopy, src); 
    memset(_results, 0, sizeof(_results)); 

    s = strtok(_scopy, delim); 
    dst = _results; 
    
    while(s) {
        *dst++ = s; 
        s = strtok(NULL, delim); 
    }

    return _results; 
}
    
