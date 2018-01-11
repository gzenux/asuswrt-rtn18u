/*******************************************************************************
 * $Id: cg.h,v 1.2 Broadcom SDK $
 * $Copyright$
 *
 * cg.h
 *
 ******************************************************************************/
#ifndef __DSYM_CG_H__
#define __DSYM_CG_H__


/*******************************************************************************
 *
 * C CODE GENERATION PRIMITIVES
 *
 ******************************************************************************/

#include <stdio.h>
#include <stdarg.h>

/*
 * Set indentation level
 */
extern int cg_indent_set(int level); 

/*
 * Newlines
 */
extern void cg_nl(FILE* fp, int lines); 
 
/* 
 * Single and multiline comments, like this one. 
 */
extern void cg_commentf(FILE* fp, const char* format, ...);
extern void cg_vcommentf(FILE* fp, const char* format, va_list args);


/*
 * Multi-line comments
 */
extern void cg_mcomment_start(FILE* fp); 
extern void cg_mcommentf(FILE* fp, const char* format, ...); 
extern void cg_vmcommentf(FILE* fp, const char* format, va_list args); 
extern void cg_mcomment_end(FILE* fp); 


/*
 * Block comments
 */
extern void cg_bcommentf(FILE* fp, const char* format, ...); 
extern void cg_bcomment_start(FILE* fp); 
extern void cg_bcomment_end(FILE* fp); 

/*
 * Preprocessor expressions
 */
extern void cg_if(FILE* fp, const char* expr, int indent); 
extern void cg_else(FILE* fp); 
extern void cg_endif(FILE* fp); 

/*
 * Insert newlines between code sections 
 */
extern void cg_next_section(FILE* fp); 


/*
 * Start a C source or header file with optional comments and include files. 
 */
extern void cg_file_start(FILE* fp, const char* name, char* comments, 
                          const char* includes); 

/*
 * End a source or header definition
 */
extern void cg_file_end(FILE* fp, const char* name); 



#endif /* __DSYM_CG_H__ */
