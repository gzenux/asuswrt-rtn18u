/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdlib.h"

#ifndef WIN32
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif /* HAVE_DLFCN_H */
#endif /* WIN32 */

#define SSH_DEBUG_MODULE "SshDLib"

SshDLib
ssh_dlib_load(const char *path)
{
#if defined(WIN32)
#ifndef UNICODE
  const char *lib_path = path;
#else
  WCHAR lib_path[MAX_PATH];

  ssh_ascii_to_unicode(lib_path, sizeof(lib_path), path);
#endif /* UNICODE */
  return LoadLibrary(lib_path);
#elif defined(HAVE_DLFCN_H) && defined(HAVE_DLOPEN)
  return dlopen(path, RTLD_LAZY);
#else /* !WIN32 && !HAVE_DLFCN_H */
  SSH_DEBUG(0, ("No way to perform dynamic loading."));
  return NULL;
#endif /* !WIN32 && !HAVE_DLFCN_H */
}

void *
ssh_dlib_get_address(SshDLib lib, const char *name)
{
#if defined(WIN32)
#ifndef UNICODE
  const char *fn_name = name;
#else
  WCHAR fn_name[MAX_PATH];

  ssh_ascii_to_unicode(fn_name, sizeof(fn_name), name);
#endif /* UNICODE */
  return (void *)GetProcAddress(lib, fn_name);
#elif defined(HAVE_DLFCN_H) && defined(HAVE_DLSYM)
  return dlsym(lib, name);
#else /* !WIN32 && !HAVE_DLFCN_H */
  return NULL;
#endif /* !WIN32 && !HAVE_DLFCN_H */
}

void
ssh_dlib_free(SshDLib lib)
{
#if defined(WIN32)
  FreeLibrary(lib);
#elif defined(HAVE_DLFCN_H) && defined(HAVE_DLCLOSE)
  dlclose(lib);
#endif /* !WIN32 && !HAVE_DLFCN_H */
}
