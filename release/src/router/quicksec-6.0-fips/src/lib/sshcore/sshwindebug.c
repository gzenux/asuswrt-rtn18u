/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Contains debug functions for Windows used e.g to find a stacktrace
   for the memory leaks.
*/

#include "sshwindebug.h"

#ifdef WIN32

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <imagehlp.h>

/* Typedefs for the functions that will be dynamically loaded from
   imagehlp.dll */

typedef BOOL (__stdcall *SymInitializeCB)(
  HANDLE hProcess,
  PSTR UserSearchPath,
  BOOL fInvadeProcess
);

typedef BOOL (__stdcall *SymCleanupCB)(
  HANDLE hProcess
);

typedef DWORD (__stdcall *SymGetOptionsCB)(VOID);

typedef DWORD (__stdcall *SymSetOptionsCB)(DWORD SymOptions);

typedef BOOL (__stdcall *SymGetLineFromAddrCB)(
  HANDLE hProcess,
  DWORD dwAddr,
  PDWORD pdwDisplacement,
  PIMAGEHLP_LINE Line
);

struct SshWinDebugRec
{
  HMODULE hm;
  SymInitializeCB pSymInitialize;
  SymCleanupCB pSymCleanup;
  SymGetOptionsCB pSymGetOptions;
  SymSetOptionsCB pSymSetOptions;
  SymGetLineFromAddrCB pSymGetLineFromAddr;
};

/* Allocate the windebug context, used for other functions */
SshWinDebug ssh_debug_win_allocate()
{
  SshWinDebug dbg;
  HMODULE hm;
  DWORD options;
  TCHAR file_path[MAX_PATH], *tmp;

  /* Load the imagehlp library which provides the stack walk functions */
  hm = LoadLibrary("imagehlp.dll");
  if (hm == NULL)
    return NULL;

  /* Dynamically load the functions from DLL */
  dbg = malloc(sizeof(*dbg));
  if (dbg == NULL)
    {
      FreeLibrary(hm);
      return NULL;
    }
  dbg->hm = hm;
  dbg->pSymInitialize = (SymInitializeCB) GetProcAddress(hm, "SymInitialize");
  dbg->pSymCleanup = (SymCleanupCB) GetProcAddress(hm, "SymCleanup");
  dbg->pSymGetOptions = (SymGetOptionsCB) GetProcAddress(hm, "SymGetOptions");
  dbg->pSymSetOptions = (SymSetOptionsCB) GetProcAddress(hm, "SymSetOptions");
  dbg->pSymGetLineFromAddr = (SymGetLineFromAddrCB)
    GetProcAddress(hm, "SymGetLineFromAddr");

  if (dbg->pSymInitialize == NULL ||
      dbg->pSymCleanup == NULL ||
      dbg->pSymGetOptions == NULL ||
      dbg->pSymSetOptions == NULL ||
      dbg->pSymGetLineFromAddr == NULL)
    {
      /* Could not load some of the functions from imagehlp.dll */
      FreeLibrary(hm);
      free(dbg);
      return NULL;
    }

  /* Find the location the executable resides. */
  GetModuleFileName(NULL, file_path, MAX_PATH);

  /* Rip the filename out from  the full path */
  tmp = strrchr(file_path, '\\');
  if (tmp)
    *tmp = 0;

  /* Initialize */
  (*dbg->pSymInitialize)(GetCurrentProcess(), file_path, TRUE);
  options = (*dbg->pSymGetOptions)();
  options |= SYMOPT_LOAD_LINES;
  (*dbg->pSymSetOptions)(options);
  return dbg;
}

/* Free the windebug context */
void ssh_debug_win_free(SshWinDebug dbg)
{
  if (dbg)
    {
      (*dbg->pSymCleanup)(GetCurrentProcess());
      FreeLibrary(dbg->hm);
      free(dbg);
    }
}

/* Finds the line name and the line number for a given program
   counter.  Returns a non zero if success.

   Filename is returned in file_name which must be a pointer to an
   character array with the size MAX_PATH. The line number is
   returned in line_number.

   Requires the imagehlp.dll in the system (which comes at least with
   platform SDK) */
int ssh_debug_win_find_line_by_pc(SshWinDebug windebug,
                                  void *pc, char file_name[],
                                  unsigned long *line_number)
{
  /* Integers used for boolean values here, beause we do not include
     sshinclude.h */
  int rv = 0;
  int windebug_allocated = 0;
  DWORD displacement;
  PIMAGEHLP_SYMBOL pis = 0;
  IMAGEHLP_LINE il;

  if (windebug == NULL)
    {
      windebug = ssh_debug_win_allocate();
      if (windebug == NULL)
        return 0;

      windebug_allocated = 1;
    }

  if ((*windebug->pSymGetLineFromAddr)(GetCurrentProcess(),
                                       (unsigned long)pc,
                                       &displacement,
                                       &il))
    {
      strncpy(file_name, il.FileName, MAX_PATH - 1);
      *line_number = il.LineNumber;
      rv = 1;
    }

  if (windebug_allocated)
    ssh_debug_win_free(windebug);

  return rv;
}

#endif /* WIN32 */
