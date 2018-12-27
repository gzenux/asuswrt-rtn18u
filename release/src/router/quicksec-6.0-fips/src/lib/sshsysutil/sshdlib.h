/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for handling dynamic libraries.
   Basically, open, get function address, and close.
*/

#ifndef SSHDLIB_H
#define SSHDLIB_H

#ifdef WIN32
typedef HMODULE SshDLib;
#else
typedef void * SshDLib;
#endif

/* Loads and links library dynamically. Return NULL, if
   load failed. */
SshDLib
ssh_dlib_load(const char *path);

/* Returns a function address by name. */
void *
ssh_dlib_get_address(SshDLib lib, const char *name);

/* Frees dynamically loaded library. */
void
ssh_dlib_free(SshDLib lib);

#endif /* SSHDLIB_H */
