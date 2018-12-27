/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshregex.h
*/

#ifndef SSH_REGEX_H_INCLUDED
#define SSH_REGEX_H_INCLUDED

#include "sshbuffer.h"

typedef struct ssh_rex_matcher *SshRegexMatcher;
typedef struct ssh_rex_global_context *SshRegexContext;

/* For the descriptions of the syntaxes, please see the separate
   file `REGEX-SYNTAX'. */
typedef enum {
  SSH_REGEX_SYNTAX_SSH,
  SSH_REGEX_SYNTAX_EGREP,
  SSH_REGEX_SYNTAX_ZSH_FILEGLOB
} SshRegexSyntax;

/* Error codes. */
typedef enum {
  SSH_REGEX_OK = 0,
  SSH_REGEX_OUT_OF_MEMORY,
  SSH_REGEX_PARSE_ERROR,
  SSH_REGEX_SEMANTIC_ERROR,
  SSH_REGEX_NO_MATCH
} SshRegexError;

typedef struct {
  unsigned char *literal;
  size_t literal_len;
  int subexpr;
} *SshRegexSubstitutionItem, SshRegexSubstitutionItemStruct;

/*********************************************************** Global context. */

/* Create a global regex allocation context which must be passed to
   ssh_regex_create.

   Returns NULL if the context cannot be allocated due to lack of memory. */
SshRegexContext ssh_regex_create_context(void);

/* Free a regex context. When the context is freed, no more regular expressions
   created with this context should exist but they must have been freed by
   calling ssh_regex_free. */
void ssh_regex_free_context(SshRegexContext c);

/********************************************** Create and destroy matchers. */

/* Create a matcher that matches the regular expression `regex'.  Returns NULL
   if `regex' is invalid or if not enough memory is available.

   `syntax' chooses the syntax which is used to parse the regular
   expression. See the file REGEX-SYNTAX in the source directory for
   descriptions of the syntaxes. */
SshRegexMatcher ssh_regex_create(SshRegexContext context,
                                 const char *regex,
                                 SshRegexSyntax syntax);

/* Free a matcher and data associated with it. */
void ssh_regex_free(SshRegexMatcher matcher);

/* Get error code corresponding to the last call to `ssh_regex_create'.  If the
   call returned a valid pointer then the code returned is
   SSH_REGEX_OK. Otherwise it is SSH_REGEX_OUT_OF_MEMORY to denote lack of
   memory, SSH_REGEX_PARSE_ERROR to denote a syntactic error in the regular
   expression, and SSH_REGEX_SEMANTIC_ERROR to denote a regular expression that
   contains a subexpression that matches the empty string and that is under a
   repetition construct (+, *, ...). */
SshRegexError ssh_regex_get_compile_error(SshRegexContext context);

/******************************** Match regular expressions against strings. */

/* Try to match against the NUL-terminated string `data'. Return TRUE if match
   succeeded, otherwise FALSE. Can return FALSE also if memory run out.  If you
   must make a distinction, call `ssh_regex_get_match_error', which will return
   either SSH_REGEX_OUT_OF_MEMORY or SSH_REGEX_NO_MATCH. */
Boolean ssh_regex_match_cstr(SshRegexMatcher matcher,
                             const char *data);

/* As above, but do not treat NUL specially. */
Boolean ssh_regex_match(SshRegexMatcher matcher,
                        const unsigned char *data,
                        size_t data_len);

/* As above, but use an SshBuffer instead. */
Boolean ssh_regex_match_buffer(SshRegexMatcher matcher,
                               SshBuffer buffer);

/* Try to match against the NUL-terminated string `data'. Return TRUE if match
   succeeded or end of the string was reached before a match completed,
   otherwise FALSE. */
Boolean ssh_regex_match_cstr_prefix(SshRegexMatcher matcher,
                                    const char *data);

/* Return an explanation why a matching attempt failed. Returns either
   SSH_REGEX_NO_MATCH or SSH_REGEX_OUT_OF_MEMORY. If last match was succesful
   returns SSH_REGEX_OK. */
SshRegexError ssh_regex_get_match_error(SshRegexMatcher matcher);

/*********************************************************** Get submatches. */

/* Return the number of subexpressions in the regular expression represented by
   `matcher'.  If this returns N, then for all K >= N,
   ssh_regex_access_submatch(m, K, ...) always returns FALSE. */
int ssh_regex_n_subexpressions(SshRegexMatcher matcher);

/* Access, after a succesful match, the `subexpr_num'th subexpression.
   `index' points to the start of the matched text and `match_len' is set
   to the length of the matched text. If the subexpression did not match,
   returns FALSE, otherwise TRUE.

   subexpr_num == 0 denotes the whole matched string.  The first parenthesized
   subexpression is obtained by setting subexpr_num == 1. */
Boolean ssh_regex_access_submatch(SshRegexMatcher matcher,
                                  int subexpr_num,
                                  int *index,
                                  size_t *match_len);

/* Get the `subexpr_num'th submatch as a NUL-terminated string. The string is
   allocated by the regex library and you should NOT free it. The string will
   be freed later, at least when `matcher' is freed.

   This returns NULL if (1) the corresponding subexpression was not used in the
   match, or (2) there doesn't exist enough memory to be allocated for the
   NUL-terminated string. If you need to make a distinction between these two
   cases, call `ssh_regex_submatch_exists'. */
unsigned char *ssh_regex_get_submatch(SshRegexMatcher matcher,
                                      int subexpr_num);

/* Return TRUE if the `subexpr_num' subexpression was employed in the current
   match, FALSE otherwise. This interface can be used to distinguish between
   the two cases where `ssh_regex_get_submatch' can return NULL. */
Boolean ssh_regex_submatch_exists(SshRegexMatcher matcher,
                                  int subexpr_num);

/****************************************** Build strings from (sub)matches. */

/* `Substitution', basically creating a new string composed of some
   submatches. This is a convenience function.

   This composes a dynamically allocated, always NUL-terminated string of
   constant data and subexpressions as given by the array `items' which
   contains `num_items' elements. If items[x].literal != NULL, the
   items[x].literal_len characters starting at this pointer are inserted;
   otherwise the match corresponding to items[x].subexpr, if the match exists.

   Returns NULL if not enough memory can be allocated. */
unsigned char *ssh_regex_compose(SshRegexMatcher matcher,
                                 SshRegexSubstitutionItem items,
                                 int num_items,
                                 size_t *length_return);

#endif /* SSH_REGEX_H_INCLUDED */
