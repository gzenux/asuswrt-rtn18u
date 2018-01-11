/*******************************************************************************
 * $Id: util.h,v 1.2 Broadcom SDK $
 * $Copyright$
 *
 * util.h
 *
 ******************************************************************************/
#ifndef __DSYM_UTIL_H__
#define __DSYM_UTIL_H__


/*******************************************************************************
 *
 * Utility Functions
 *
 ******************************************************************************/

#include <stdlib.h>
#include <stdio.h>

      
/*
 * Open an output file in the current directory. 
 */

extern FILE* file_open(const char* dir, const char* subdir, const char* format, ...); 
 
/* 
 * Create a Directory
 */
extern int create_dir(const char* path); 

/*
 * Change Directory
 */
extern int change_dir(const char* path); 


/*
 * Convert strings to upper/lowercase
 */
extern char* stolower(const char* s, char* d); 

extern char* stoupper(const char* s, char* d); 

/*
 * Report an internal error
 */
int internal_error(int line, const char* format, ...); 

/*
 * Report a warning
 */
int warning(int line, const char* format, ...);


/*
 * Parse a string based on delimiter. Static return data. 
 */
const char** parse_string(const char* src, const char* delim); 

#define MAX(a,b) (((a) < (b)) ? (b) : (a))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

/* Safe strncpy, like strlcpy */
#define ASTRNCPY(dst, src) do { dst[0] = 0; strncat(dst, src, sizeof((dst))); } while(0)

#endif /* __DSYM_UTIL_H__ */
