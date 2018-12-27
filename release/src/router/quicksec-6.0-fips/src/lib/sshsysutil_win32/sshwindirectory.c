/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows implementation of the portable directory access interface.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshdirectory.h"

/*
 * Types and definitions.
 */

#define SSH_DEBUG_MODULE "SshDirectory"

struct SshDirectoryRec
{
  HANDLE dir;
  Boolean directory_read;
  WIN32_FIND_DATA dirent;
#ifdef UNICODE
  char ascii_filename[MAX_PATH];
#endif /* UNICODE */
};


/*
 * Global functions.
 */

SshDirectoryHandle
ssh_directory_open(const char *directory)
{
  SshDirectoryHandle dir;
  SshBufferStruct buffer;
#ifdef UNICODE
  WCHAR uc_buffer[MAX_PATH];
#endif /* UNICODE */

  dir = ssh_calloc(1, sizeof(*dir));
  if (dir == NULL)
    return NULL;

  ssh_buffer_init(&buffer);
  ssh_buffer_append_cstrs(&buffer, directory, "\\*.*", NULL);
  ssh_buffer_append(&buffer, "\0", 1);

#ifdef UNICODE
  ssh_ascii_to_unicode(uc_buffer, sizeof(uc_buffer), ssh_buffer_ptr(&buffer));
  dir->dir = FindFirstFile(uc_buffer, &dir->dirent);
#else
  dir->dir = FindFirstFile(ssh_buffer_ptr(&buffer), &dir->dirent);
#endif /* UNICODE */
  ssh_buffer_uninit(&buffer);

  if (dir->dir == INVALID_HANDLE_VALUE)
    {
      ssh_free(dir);
      return NULL;
    }

  return dir;
}


Boolean
ssh_directory_read(SshDirectoryHandle directory)
{
  Boolean result = TRUE;

  SSH_ASSERT(directory != NULL);

  if (!directory->directory_read)
    directory->directory_read = TRUE;
  else
    result = FindNextFile(directory->dir, &directory->dirent);

  return result;
}


void
ssh_directory_close(SshDirectoryHandle directory)
{
  SSH_ASSERT(directory != NULL);

  FindClose(directory->dir);
  ssh_free(directory);
}


/* Directory entry access functions. */

const char *
ssh_directory_file_name(SshDirectoryHandle directory)
{
  SSH_ASSERT(directory != NULL);
  SSH_ASSERT(directory->directory_read);

#ifdef UNICODE
  ssh_unicode_to_ascii(directory->ascii_filename,
                       sizeof(directory->ascii_filename),
                       directory->dirent.cFileName);
  return directory->ascii_filename;
#else
  return directory->dirent.cFileName;
#endif /* UNICODE */
}

Boolean ssh_directory_create(const char *directory, mode_t mode)
{
  char *dir_orig;
#ifdef UNICODE
  WCHAR uc_dir_orig[MAX_PATH];
#endif /* UNICODE */
  char *dir;
  char *dir2;
  DWORD attr;

  SSH_ASSERT(directory != NULL);
  dir_orig = ssh_directory_replace_backslashes(directory);
  dir = dir_orig;

  while (dir)
  {
    dir2 = strchr(dir, '/');
    if (dir2)
      *dir2 = 0;

    /* skip drive letter */
    if (dir[1] != ':')
    {
      /* create the dir if it doesn't exist. */
#ifdef UNICODE
      ssh_ascii_to_unicode(uc_dir_orig, sizeof(uc_dir_orig), dir_orig);
      attr = GetFileAttributes(uc_dir_orig);
      if (attr == 0xFFFFFFFF && !CreateDirectory(uc_dir_orig, NULL))
#else
      attr = GetFileAttributes(dir_orig);
      if (attr == 0xFFFFFFFF && !CreateDirectory(dir_orig, NULL))
#endif /* UNICODE */
      {
        ssh_free(dir_orig);
        return FALSE;
      }
    }

    if (dir2)
    {
      *dir2 = '/';
      dir = dir2+1;
    }
    else
      dir = NULL;
  }

  ssh_free(dir_orig);
  return TRUE;
}

char *ssh_directory_get_process_path(void)
{
#ifdef UNICODE
  WCHAR uc_path[MAX_PATH];
#endif /* UNICODE */
  char path[MAX_PATH];
  char *path2;
  char *back_slash;

#ifdef UNICODE
  GetModuleFileName(NULL, uc_path, sizeof(uc_path));
  ssh_unicode_to_ascii(path, sizeof(path), uc_path);
#else
  GetModuleFileName(NULL, path, sizeof(path));
#endif /* UNICODE */
  back_slash = strrchr(path, '\\');
  path[back_slash - path] = '\0';

  path2 = ssh_strdup(path);
  return path2;
}

char *ssh_directory_replace_backslashes(const char *path)
{
  char *orig;
  unsigned char *p, *str;

  if (path == NULL)
    return NULL;

  if ((orig = ssh_strdup(path)) == NULL)
    return NULL;

  str = orig;
  while (p = strchr(str, '\\'))
  {
    *p = '/';
    p++;
    str = p;
  }

  return orig;
}

const char *ssh_directory_slash_at_end(const char *path)
{
  unsigned const char *pos;
  size_t len;

  if (path == NULL)
    return NULL;

  len = strlen(path);

  /* find if last char is a separator */
  pos = strrchr(path, '/');
  if (pos == NULL)
    pos = strrchr(path, '\\');
  if (pos == NULL || pos != (path+len-1))
    return NULL;
  else
    return (const char*)pos;
}

Boolean ssh_directory_is_sub_dir(const char *root, const char *subdir)
{
  char *dir_root;
  char *dir_sub;
  size_t len;
  Boolean ret;

  if (root == NULL || subdir == NULL)
    return FALSE;

  dir_root = ssh_directory_replace_backslashes(root);
  if (dir_root == NULL)
    return FALSE;
  _strlwr(dir_root);

  dir_sub = ssh_directory_replace_backslashes(subdir);
  if (dir_sub == NULL)
    return FALSE;
  _strlwr(dir_sub);

  /* remove ending slash */
  len = strlen(dir_root);
  if (dir_root[len-1] == '/')
    len--;

  SSH_DEBUG(7, ("is_a_sub_dir(%s, %s, %d)", dir_root, dir_sub, len));
  if (strncmp(dir_root, dir_sub, len) == 0)
    ret = TRUE;
  else
    ret = FALSE;
  ssh_free(dir_root);
  ssh_free(dir_sub);
  return ret;
}

Boolean ssh_directory_is_same(const char *dir1, const char *dir2)
{
  char *copy1;
  char *copy2;
  size_t len;
  Boolean ret;

  if (dir1 == NULL || dir2 == NULL)
    return FALSE;

  /* replace backslashes and convert to lower */
  copy1 = ssh_directory_replace_backslashes(dir1);
  if (copy1 == NULL)
    return FALSE;
  _strlwr(copy1);

  copy2 = ssh_directory_replace_backslashes(dir2);
  if (copy2 == NULL)
  {
    ssh_free(copy1);
    return FALSE;
  }
  _strlwr(copy2);

  /* remove slash from end */
  if (ssh_directory_slash_at_end(copy1))
  {
    len = strlen(copy1);
    if (len > 0)
      copy1[len-1] = 0;
  }
  if (ssh_directory_slash_at_end(copy2))
  {
    len = strlen(copy2);
    if (len > 0)
      copy2[len-1] = 0;
  }

  ret = strcmp(copy1, copy2) == 0;
  ssh_free(copy1);
  ssh_free(copy2);
  return ret;
}
