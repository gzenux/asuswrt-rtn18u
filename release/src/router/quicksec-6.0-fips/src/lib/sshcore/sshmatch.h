/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Pattern matching utility functions.

   <keywords pattern matching, matching patterns,
   utility functions/pattern matching>
*/

#ifndef SSHMATCH_H
#define SSHMATCH_H

/** Returns TRUE if the given string matches the pattern (which may
    contain ? and * as wildcards), and FALSE if it does not match. */

Boolean ssh_match_pattern(const char *s, const char *pattern);

/** Returns true if the given port matches the port number pattern
    (which may contain '*' as wildcard for all ports, or '\<xxx',
    '\>xxx' or 'xxx..yyy' formats to specify less than, greater
    than or port range), and zero if it does not match. */

Boolean ssh_match_port(SshUInt32 port, const char *pattern);

#endif /* SSHMATCH_H */
