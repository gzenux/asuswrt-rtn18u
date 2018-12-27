/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Portable directory access interface.
*/

#ifndef SSHDIRECTORY_H
#define SSHDIRECTORY_H

/*
 * Types and definitions.
 */

/* Handle identifying an open directory. */
typedef struct SshDirectoryRec *SshDirectoryHandle;


/*
 * Prototypes for global functions.
 */

/* Opens the directory <directory> and returns a handle that can be
   used to enumerate its contents.  The function returns NULL if the
   directory could not be opened. */
SshDirectoryHandle ssh_directory_open(const char *directory);

/* Reads the next item from the directory <directory>.  The function
   returns TRUE if the directory did have more items, or FALSE
   otherwise. */
Boolean ssh_directory_read(SshDirectoryHandle directory);

/* Closes the directory handle <directory> and frees all resources
   associated with it.  The directory handle <directory> must not be
   used after this call. */
void ssh_directory_close(SshDirectoryHandle directory);


/* Access function for directory entries.  These functions can be
   called to the directory handle <directory> after the
   ssh_directory_read() function has returned TRUE.  It is an error to
   call these functions without first calling the ssh_directory_read()
   function. */

/* Returns the name of the current file in the directory <directory>.
   The returned file name is valid until the next call of the
   ssh_directory_read() and ssh_directory_close() functions. */
const char *ssh_directory_file_name(SshDirectoryHandle directory);


#ifdef SSHDIST_PLATFORM_WIN32
/* These functions are currently implemented on Windows only. Someone
   could port them to Unix if need be. <tomi@ssh.com> */

/* Creates the desired directories. Creates not just the last directory
   of the path but makes sure that the whole path gets created.
   mode is not yet implemented on Windows. */
Boolean ssh_directory_create(const char *directory, mode_t mode);

/* Returns the path of the current process. For c:\test\test2\test3.exe
   it would be c:\test\test2. Returned path must be freed with ssh_xfree. */
char *ssh_directory_get_process_path(void);

/* Replace backslashes with slashes. This is a MBCS (multibyte)
   aware function. */
char *ssh_directory_replace_backslashes(const char *path);

/* Checks whether the path ends with slash or backslash. MBCS aware. */
const char *ssh_directory_slash_at_end(const char *path);

/* Checks whether the given subdir is a dir below root. MBCS aware.*/
Boolean ssh_directory_is_sub_dir(const char *root, const char *subdir);

/* Checks whether the two paths are the same. MBCS aware. */
Boolean ssh_directory_is_same(const char *dir1, const char *dir2);

#endif /* SSHDIST_PLATFORM_WIN32 */

#endif /* not SSHDIRECTORY_H */
