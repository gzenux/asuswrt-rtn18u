/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Debug functions for Windows used e.g to find a stacktrace for memory
   leaks.

   <keywords Windows/debugging, debugging/Windows,
   utility functions/debugging, utility functions/Windows>

   @internal
*/


#ifndef SSHWINDEBUG_H_INCLUDED
#define SSHWINDEBUG_H_INCLUDED

/**  The handle representing the windebug context. */
typedef struct SshWinDebugRec *SshWinDebug;

/**  Allocate the windebug context, used for other functions. */
SshWinDebug ssh_debug_win_allocate();

/**  Free the windebug context. */
void ssh_debug_win_free(SshWinDebug windebug);


/** Find the line name and the line number for a given program
    counter.  Returns a non zero if success.

    The windebug may be NULL, in which case the windebug context is
    allocated and freed internally, but when used many times
    successively, the functions is faster if you provide it a ready
    initialized windebug context.

    Filename is returned in file_name which must be a pointer to a
    character array with the size MAX_PATH. The line number is
    returned in line_number.

    Note: Requires the imagehlp.dll file in the system (which comes at
    least with the platform SDK). */

int ssh_debug_win_find_line_by_pc(SshWinDebug windebug,
                                  void *pc, char file_name[],
                                  unsigned long *line_number);

#endif /* SSHWINDEBUG_H_INCLUDED */




