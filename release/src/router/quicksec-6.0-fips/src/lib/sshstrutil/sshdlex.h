/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This interface can be used to create and use `dynamic lexers', that is,
   lexical analyzers that are created on the fly during execution.

   The underlying implementation is shared with the SSH's regular expression
   package, so the resulting lexer will be slower than those generated
   statically by special-purpose tools, such as UNIX `lex'.
*/

#ifndef SSH_DLEX_H_INCLUDED
#define SSH_DLEX_H_INCLUDED

#include "sshbuffer.h"
#include "sshregex.h"

typedef SshRegexMatcher SshDLexer;

/* These are understood flags that can be passed to `ssh_dlex_create'. */

/* SSH_DLEX_LONGEST_MATCH is not implemented yet, so SSH_DLEX_FIRST_MATCH
   is mandatory for now. */
/* The tokens returned will correspond to the longest possible match among all
   matches for the different regular expressions.  THIS IS THE DEFAULT, and
   therefore the flag has the value zero. */
/* #define SSH_DLEX_LONGEST_MATCH 0x0000 */

/* The tokens returned will correspond to first regular expression that
   matches, when the regular expressions are enumerated as regexs[0],
   regexs[1], .... This is not the default.  (Corresponds to PERL-style
   handling of disjuncts, differing from the POSIX standard.) */
#define SSH_DLEX_FIRST_MATCH   0x0001

/* Create a new dynamic lexer.  It is not much more than a collection of the
   regular expressions, specially handled.

   `context' must have been created by calling ssh_regex_create_context.

   This function returns NULL if at least one the regular expressions could not
   be parsed or if the system is out of memory. */
SshDLexer ssh_dlex_create(SshRegexContext context,
                          const char **regexs,
                          int n_regexs,
                          SshRegexSyntax syntax,
                          unsigned int flags);

/* Destroy a dynamic lexer. */
void ssh_dlex_destroy(SshDLexer dlex);

/* Return the next `token' from the pointer `data'.  If a token was found, its
   length is returned in *match_len, the index of the regular expression that
   matched in *token, and the function returns TRUE.  If no tokens were found,
   the function returns FALSE.

   It is possible that *match_len == 0.  This happens if you have a regular
   expression that can match the empty string (e.g. `(foo)?'), and it is the
   only matching regular expression (this example assuming that
   SSH_DLEX_LONGEST_MATCH is used).

   You can `lex' a complete string by a loop like this:

   int len, token;
   unsigned char *ptr = string_to_lex;
   unsigned char *end = string_to_lex + strlen(string_to_lex);

   while (ptr < end && ssh_dlex_next(dlex, ptr, end - ptr, &len, &token))
     {
       printf("Got token `%.*s' (token = %d).\n", ptr, len, token);
       ptr += len;
     }

   if (ptr < end)
     {
       printf("Garbage at the end of the string: `%s'.\n", ptr);
     }

   This can return FALSE also if memory runs out.  To distinguish between the
   two possible error conditions, call `ssh_dlex_get_scan_error' to get a
   similar error code to those return by `ssh_regex_get_match_error'.

*/

Boolean ssh_dlex_next(SshDLexer dlex, const unsigned char *data, int data_len,
                      int *match_len, int *token);

SshRegexError ssh_dlex_get_scan_error(SshDLexer dlex);

#endif /* !SSH_DLEX_H_INCLUDED */
