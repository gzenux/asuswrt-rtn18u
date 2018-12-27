/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode event registry handling functions for Windows NT series
   operating systems.
*/

#ifndef SSH_REGISTRY_H
#define SSH_REGISTRY_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  INCLUDES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/* Type definitions for various registry-related data types */
typedef HANDLE SshRegKey;

typedef WCHAR *SshRegPath;

typedef UNICODE_STRING *SshRegPathUnicode;

typedef WCHAR *SshRegString;
typedef unsigned char *SshRegAnsiString;
typedef UNICODE_STRING *SshRegUnicodeString;

typedef WCHAR *SshRegValue;

typedef unsigned int SshRegDataType;

typedef void *SshRegData;

typedef ULONG SshRegDWord;

typedef ULONG SshRegSize;

typedef ULONG SshRegIndex;

typedef BOOLEAN SshRegBool;

typedef enum
{
  SSH_REG_KEY_INFO_SUBKEYS,      /* Number of subkeys */
  SSH_REG_KEY_INFO_SUBKEY_SIZE,  /* Size of longest subkey name */
  SSH_REG_KEY_INFO_VALUES,       /* Number of value entries */
  SSH_REG_KEY_INFO_VALUE_SIZE,   /* Size of longest value name */
  SSH_REG_KEY_INFO_DATA_SIZE,    /* Size of longest value data */
} SshRegKeyQueryType;

/* Bogus registry key representing HKEY_LOCAL_MACHINE */
#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE  (SshRegKey)-1
#endif /* HKEY_LOCAL_MACHINE */

/* Returns the length (in wide characters, not bytes) of a registry string */
#define SSH_REG_STR_LEN(str)  (wcslen((void *)(str)))

/* This macro returns the size (in bytes) of a registry string */
#define SSH_REG_STR_SIZE(str) \
  ((SSH_REG_STR_LEN((str))+1) * sizeof(WCHAR))


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_registry_key_open()

  Opens the specified registry key. The key to be opened is specified using
  up to three parameters; "parent_key", "parent_path" and "path".  

  The 'parent_key' can specify either previously opened registry key or
  HKEY_LOCAL_MACHINE.

  'parent_path' is optional and can contain either a string specifying a
  registry path or NULL if 'path' contains the full registry path.
  --------------------------------------------------------------------------*/
SshRegKey
ssh_registry_key_open(SshRegKey parent_key,
                      SshRegPath parent_path,
                      SshRegPath path);


/*--------------------------------------------------------------------------
  ssh_registry_key_open_unicode()

  UNICODE version of ssh_registry_key_open().
  --------------------------------------------------------------------------*/
SshRegKey
ssh_registry_key_open_unicode(SshRegKey parent_key,
                              SshRegPathUnicode parent_path,
                              SshRegPathUnicode path);


/*--------------------------------------------------------------------------
  ssh_registry_key_open_by_index()

  Opens the existing subkey specified by subkey index 'index'. Returns either
  an opened registry key or NULL if the specified subkey doesn't exist or if
  an error occurs.
  --------------------------------------------------------------------------*/
SshRegKey
ssh_registry_key_open_by_index(SshRegKey parent_key,
                               SshRegIndex index);

/*--------------------------------------------------------------------------
  ssh_registry_key_create()

  Creates the specified registry key.  
  --------------------------------------------------------------------------*/
SshRegKey
ssh_registry_key_create(SshRegKey parent_key,
                        SshRegPath path);


/*--------------------------------------------------------------------------
  ssh_registry_key_create_unicode()

  UNICODE version of ssh_registry_key_create().
  --------------------------------------------------------------------------*/
SshRegKey
ssh_registry_key_create_unicode(SshRegKey parent_key,
                                SshRegPathUnicode path);


/*--------------------------------------------------------------------------
  ssh_registry_key_delete()

  Deletes the specified registry key.  
  --------------------------------------------------------------------------*/
SshRegBool
ssh_registry_key_delete(SshRegKey parent_key,
                        SshRegPath path);


/*--------------------------------------------------------------------------
  ssh_registry_key_delete_unicode()

  UNICODE version of ssh_registry_key_delete().
  --------------------------------------------------------------------------*/
SshRegBool
ssh_registry_key_delete_unicode(SshRegKey parent_key,
                                SshRegPathUnicode path);


/*--------------------------------------------------------------------------
  ssh_registry_subkey_find_by_ansi_data()

  Searches the registy subkey containing registry value named 'value_name'
  containin the specified ASCII/ANSI string.   

  Arcument 'recursive' specifies whether it's allowed to perform recursive
  search under the given parent key. If 'recursive' is FALSE, only the next
  level in registry path is searched.
  --------------------------------------------------------------------------*/
SshRegKey 
ssh_registry_subkey_find_by_ansi_data(SshRegKey parent_key,
                                      SshRegValue value_name,
                                      SshRegAnsiString ansi_data,
                                      SshRegSize ansi_data_len,
                                      SshRegBool recursive);


/*--------------------------------------------------------------------------
  ssh_registry_key_info_get()

  Returns the requested information (e.g. the number of subkeys) about the 
  specified registry key. 
  --------------------------------------------------------------------------*/
SshRegSize
ssh_registry_key_info_get(SshRegKey key,
                          SshRegKeyQueryType query_type);


/*--------------------------------------------------------------------------
  ssh_registry_key_close()

  Closes a registry key previosuly opened either with ssh_registry_key_open()
  or ssh_registry_key_open_unicode().
  --------------------------------------------------------------------------*/
void
ssh_registry_key_close(SshRegKey registry_key);


/*--------------------------------------------------------------------------
  ssh_registry_***_get()

  Reads a value data from a system registry database. Returns NULL if the
  value does not exist in registry or some other error occurred.
  --------------------------------------------------------------------------*/
void *
ssh_registry_data_get(SshRegKey registry_key,
                      SshRegValue value_name,
                      SshRegSize *size_return);


SshRegBool
ssh_registry_dword_get(SshRegKey registry_key,
                       SshRegValue value_name,
                       SshRegDWord *data_return);

/* If string->Buffer and string->MaximumLenght are set, this function will
   use the specified buffer. If these fields are intitialized to zero, 
   ssh_registry_unicode_string_get() allocates the buffer for the unicode
   string and the caller is responsible for freeing it with ssh_free().

   NOTICE! The returned string->Buffer is not necessarily terminated by 
           UNICODE_NULL and thus you MUST NOT use functions like wcslen()
           with it! */
SshRegBool
ssh_registry_unicode_string_get(SshRegKey registry_key,
                                SshRegValue value_name,
                                UNICODE_STRING *string);

/* This function queries NULL-terminated ASCII/ANSI string from registry.
   The caller is responsible for freeing it with ssh_free(). */
SshRegBool
ssh_registry_asciiz_string_get(SshRegKey registry_key,
                               SshRegValue value_name,
                               unsigned char **string);

SshRegBool
ssh_registry_binary_data_get(SshRegKey registry_key,
                             SshRegValue value_name,
                             void *data_return,
                             SshRegSize data_size);

/*--------------------------------------------------------------------------
  ssh_registry_***_set()

  Writes the given value data into a system registry database.
  --------------------------------------------------------------------------*/
SshRegBool
ssh_registry_dword_set(SshRegKey registry_key,
                       SshRegValue value_name,
                       SshRegDWord data);

SshRegBool
ssh_registry_string_set(SshRegKey registry_key,
                        SshRegValue value_name,
                        SshRegString string);

SshRegBool
ssh_registry_multi_string_set(SshRegKey registry_key,
                              SshRegValue value_name,
                              SshRegString data,
                              SshRegSize data_size);

SshRegBool
ssh_registry_unicode_string_set(SshRegKey registry_key,
                                SshRegValue value_name,
                                UNICODE_STRING *string);

SshRegBool
ssh_registry_binary_data_set(SshRegKey registry_key,
                             SshRegValue value_name,
                             void *data,
                             SshRegSize data_size);

/*--------------------------------------------------------------------------
  ssh_registry_value_delete()

  Deletes the given value from a system registry database.
  --------------------------------------------------------------------------*/
SshRegBool
ssh_registry_value_delete(SshRegKey registry_key,
                          SshRegValue value_name);

#ifdef __cplusplus
}
#endif

#endif /* SSH_REGISTRY_H */

