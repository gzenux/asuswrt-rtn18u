/*
 * @File: config.c
 *
 * @Abstract: configuration file reader;
 *
 * @Notes:
 * configuration files contain named parts where each part may
 * contain one of more named items that have text definitions;
 *
 * the named file can be searched for the first occurrence of a
 * named part then the first occurrence of a named item;
 *
 *   [part1]
 *   item1=text
 *   item2=text
 *
 *   [part1]
 *   item1=text
 *   item2=text
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef CONFIG_SOURCE
#define CONFIG_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#ifndef __USE_ISOC99
#define isblank(c) (((c) == ' ') || ((c) == '\t'))
#endif

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

static char buffer [1024] = "";
static signed c;

/*====================================================================*
 *
 *   int compare (FILE * fp, const char *sp);
 *
 *   compare file and text characters until they differ or until end
 *   of text, line or file; a match occurs when the text ends before 
 *   the line or file ends; 
 *
 *   spaces and tabs within the argument string or file string are
 *   ignored such that "item1", " item1 " and "item 1" all match;
 *
 *--------------------------------------------------------------------*/

static int compare (FILE * fp, const char * sp) 

{
    while (isblank (*sp)) {    
        sp++;
    }
    while ((*sp) && (c != '\n') && (c != EOF)) {    
        if (toupper (c) != toupper (*sp)) {        
            return (0);
        }
        do {        
            sp++;
        }
        while (isblank (*sp));
        do {        
            c = getc (fp);
        }
        while (isblank (c));
    }
    return (!*sp);
}


/*====================================================================*
 *
 *   void collect (FILE * fp);
 *
 *   collect text to end-of-line; remove leading and trailing space
 *   but preserve embedded space; replace selected escape sequences;
 *
 *   an unescaped semicolon ends the text and starts a comment that
 *   continues to the end-of-line;
 *
 *--------------------------------------------------------------------*/

static void collect (FILE * fp) 

{
    char *bp = buffer;
    char *cp = buffer;
    while ((c != ';') && (c != '\n') && (c != EOF)) {    
        if (c == '\\') {        
            c = getc (fp);
            if (c == 'n') {            
                c = '\n';
            }
            if (c == 't') {            
                c = '\t';
            }
        }
        if ((cp - buffer) < (sizeof (buffer) - 1)) {        
            *cp++ = c;
        }
        if (!isblank (c)) {        
            bp = cp;
        }
        c = getc (fp);
    }
    *bp = (char) (0);
    return;
}


/*====================================================================*
 *
 *   void discard (FILE * fp);
 *
 *   read and discard characters until end-of-line or end-of-file 
 *   is detected; read the first character of next line if end of 
 *   file has not been detected;
 *
 *--------------------------------------------------------------------*/

static void discard (FILE * fp) 

{
    while ((c != '\n') && (c != EOF)) {    
        c = getc (fp);
    }
    if (c != EOF) {    
        c = getc (fp);
    }
    return;
}


/*====================================================================*
 *
 *   Const char * configstring (const char * file, const char * part, const char * item, const char * text)
 *
 *   open the named file, locate the named part and return the named
 *   item text, if present; return alternative text if the file part
 *   or item is missing; the calling function must free returned
 *   text as it will have been dynamically allocated using strdup
 *
 *--------------------------------------------------------------------*/

const char * configstring (const char * file, const char * part, const char * item, const char * text) 

{
    FILE *fp;
    if (file && part && item) {
        if ((fp = fopen (file, "rb"))) {
            for (c = getc (fp); c != EOF; discard (fp)) {
                while (isblank (c)) {                
                    c = getc (fp);
                }
                if (c != '[') {
                    continue;
                }
                do {
                    c = getc (fp);
                }
                while (isblank (c));
                if (!compare (fp, part)) {
                    continue;
                }
                if (c != ']') {
                    continue;
                }
                for (discard (fp); (c != '[') && (c != EOF); discard (fp)) {
                    while (isblank (c)) {
                        c = getc (fp);
                    }
                    if (c == ';') {
                        continue;
                    }
                    if (!compare (fp, item)) {
                        continue;
                    }
                    if (c != '=') {
                        continue;
                    }
                    do {
                        c = getc (fp);
                    }
                    while (isblank (c));
                    collect (fp);
                    text = buffer;
                    break;
                }
                break;
            }
            fclose (fp);
        }
    }

    if (text) {
        text = strdup(text);
    }

    return text;
}


/*====================================================================*
 *
 *   int main (int argc, const char * argv []);
 *
 *   demo/test program; arguments are file, part, item and text in 
 *   that order; you can construct your own configuration file and
 *   observe behaviour; 
 *
 *--------------------------------------------------------------------*/

#if 0

#include <stdio.h>

int main (int argc, const char * argv []) 

{
    const char * text = configstring (argv [1], argv [2], argv [3], argv [4]);
    printf ("file=[%s] part=[%s] item=[%s] text=[%s]\n", argv [1], argv [2], argv [3], text);
    return (0);
}


#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif

