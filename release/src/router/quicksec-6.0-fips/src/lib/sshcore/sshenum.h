/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for mapping keywords to numbers and vice versa.

   <keywords mapping keywords and numbers, keyword mapping, number
   mapping, utility functions/mapping>

   @internal
*/

#ifndef SSHENUM_H
#define SSHENUM_H

/** Array of keyword - numeric value pairs.  The array is terminated by
    an entry with NULL name. */
typedef struct
{
  const char *name;     /** Name. */
  long code;            /** Code. */
} *SshKeyword, SshKeywordStruct;


/** Finds the name of a keyword corresponding to the numeric value.

    @return
    Returns a pointer to a constant name string, or NULL if there is
    no keyword matching the numeric value.

    */
const char *ssh_find_keyword_name(const SshKeywordStruct *keywords, long code);

/** Finds the number corresponding to the given keyword.
    The comparison is case-sensitive.

    @return
    Returns the number, or -1 if there is no matching keyword.

    */
long ssh_find_keyword_number(const SshKeywordStruct *names,
                             const char *name);

/** Finds the longest prefix from the keyword table.
    The comparison is case-sensitive.

    @param endp
    Modifier to points to the end of found keyword if it is not NULL.

    @return
    Returns the associated number, or -1 if there is no matching
    keyword.

    */
long ssh_find_partial_keyword_number(const SshKeywordStruct *names,
                                     const char *name, const char **endp);

/** Finds the number corresponding to the given keyword.
    The comparison is case-insensitive.

    @return
    Returns the number, or -1 if there is no matching keyword.

    */
long ssh_find_keyword_number_case_insensitive(const SshKeywordStruct *names,
                                              const char *name);

/** Finds the longest prefix from the keyword table.
    The comparison is case-insensitive.

    @param endp
    Modifier that points to the end of the found keyword, if it is not
    NULL.

    @return
    Returns the associated number, or -1 if there is no matching
    keyword.

    */
long ssh_find_partial_keyword_number_case_insensitive(const
                                                      SshKeywordStruct *names,
                                                      const char *name,
                                                      const char **endp);


#endif /* SSHENUM_H */
