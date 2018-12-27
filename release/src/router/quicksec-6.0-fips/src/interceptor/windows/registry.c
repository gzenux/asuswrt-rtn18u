/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of registry handling functions for
   Windows CE and Windows NT series operating systems.
*/








/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "registry.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE  "SshInterceptorRegistry"

/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

/* Platform dependent functions for Windows XP (or later) kernel mode */

typedef NTSTATUS (*SshCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                 ULONG, PUNICODE_STRING, ULONG, PULONG);

typedef NTSTATUS (*SshSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, 
                                   ULONG, PVOID, ULONG);

typedef NTSTATUS (*SshDeleteKey)(HANDLE);

static SshRegKey
ssh_registry_platform_open_hklm(void)
{
  OBJECT_ATTRIBUTES attrs;
  UNICODE_STRING uc_path;
  SshRegKey key = NULL;

  RtlInitUnicodeString(&uc_path, L"\\Registry\\Machine");

  InitializeObjectAttributes(&attrs, &uc_path, 
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                             NULL, NULL);

  if (NT_SUCCESS(ZwOpenKey(&key, KEY_ALL_ACCESS, &attrs)))
    return key;

  return NULL;
}

static SshRegKey
ssh_registry_platform_open_key(SshRegKey parent_key,
                               SshRegPathUnicode parent_path,
                               SshRegPathUnicode path)
{
  OBJECT_ATTRIBUTES attrs;
  SshRegKey key = NULL;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (parent_key == HKEY_LOCAL_MACHINE)
    {
      parent_key = ssh_registry_platform_open_hklm();
      if (parent_key)
        {
          key = ssh_registry_key_open_unicode(parent_key, parent_path, path);
          ssh_registry_key_close(parent_key);
          return key;
        }
    }
  else if (parent_path)
    {
      InitializeObjectAttributes(&attrs, parent_path, 
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                                 parent_key, NULL);

      if (NT_SUCCESS(ZwOpenKey(&parent_key, KEY_ALL_ACCESS, &attrs)))
        {
          key = ssh_registry_key_open_unicode(parent_key, NULL, path);
          ssh_registry_key_close(parent_key);
          return key;
        }
    }
  else
    {
      InitializeObjectAttributes(&attrs, path,
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                                 parent_key, NULL);

      if (NT_SUCCESS(ZwOpenKey(&parent_key, KEY_ALL_ACCESS, &attrs)))
        return parent_key;
    }

  return NULL;
}


static SshRegKey
ssh_registry_platform_open_key_by_index(SshRegKey parent_key,
                                        SshRegIndex index)
{
  SshRegKey key;
  SshRegSize size;
  PKEY_NODE_INFORMATION info;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  size = ssh_registry_key_info_get(parent_key, SSH_REG_KEY_INFO_SUBKEY_SIZE);
  if (size == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get subkey size"));
      return NULL;
    }

  size += sizeof(*info);

  info = ssh_calloc(1, size);
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for subkey information"));
      return NULL;
    }

  if (!NT_SUCCESS(ZwEnumerateKey(parent_key, index, 
                  KeyNodeInformation, info, size, &size)))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to get information about subkey %d", index));

      ssh_free(info);
      return NULL;
    }

  key = ssh_registry_key_open(parent_key, NULL, info->Name);

  ssh_free(info);

  return key;
}


static SshRegKey
ssh_registry_platform_create_key(SshRegKey parent_key,
                                 SshRegPathUnicode path)
{
  OBJECT_ATTRIBUTES attrs;
  SshCreateKey fn_create_key;
  UNICODE_STRING fn_name;
  Boolean close_parent_key = FALSE;
  SshRegKey ret_key = NULL;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (parent_key == HKEY_LOCAL_MACHINE)
    {
      parent_key = ssh_registry_platform_open_hklm();
      if (parent_key == NULL)
        return NULL;

      close_parent_key = TRUE;
    }

  InitializeObjectAttributes(&attrs, path,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                             parent_key, NULL);

  RtlInitUnicodeString(&fn_name, L"ZwCreateKey");
  fn_create_key = MmGetSystemRoutineAddress(&fn_name);
  if (fn_create_key != NULL_FNPTR)
    {
      (*fn_create_key)(&ret_key, KEY_ALL_ACCESS, &attrs,
                       0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    }

  if (close_parent_key)
    ssh_registry_key_close(parent_key);

  return ret_key;
}


static SshRegBool
ssh_registry_platform_delete_key(SshRegKey parent_key,
                                 SshRegPathUnicode path)
{
  SshRegBool status = FALSE;
  SshRegKey key;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  key = ssh_registry_platform_open_key(parent_key, NULL, path);
  if (key != NULL)
    {
      SshDeleteKey fn_delete_key;
      UNICODE_STRING fn_name;

      RtlInitUnicodeString(&fn_name, L"ZwDeleteKey");
      fn_delete_key = MmGetSystemRoutineAddress(&fn_name);
      if ((fn_delete_key != NULL_FNPTR)
          && (NT_SUCCESS((*fn_delete_key)(key))))
        status = TRUE;
    }

  return status;
}


static void
ssh_registry_platform_close_key(SshRegKey registry_key)
{
  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  ZwClose(registry_key);
}


static SshRegSize
ssh_registry_platform_get_key_info(SshRegKey key,
                                   SshRegKeyQueryType query_type)
{
  KEY_FULL_INFORMATION info;
  ULONG len_required;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (!NT_SUCCESS(ZwQueryKey(key, KeyFullInformation, 
                             &info, sizeof(info), &len_required)))
    return 0;

  switch (query_type)
    {
    case SSH_REG_KEY_INFO_SUBKEYS:
      return info.SubKeys;

    case SSH_REG_KEY_INFO_SUBKEY_SIZE:
      return info.MaxNameLen;

    case SSH_REG_KEY_INFO_VALUES:
      return info.Values;

    case SSH_REG_KEY_INFO_VALUE_SIZE:
      return info.MaxValueNameLen;

    case SSH_REG_KEY_INFO_DATA_SIZE:
      return info.MaxValueDataLen;

    default:
      SSH_NOTREACHED;
      break;
    }

  return 0;
}


static SshRegData
ssh_registry_platform_get_value(SshRegKey registry_key,
                                SshRegUnicodeString value_name,
                                SshRegSize *size_return)
{
  PKEY_VALUE_PARTIAL_INFORMATION info;
  ULONG data_size;
  SshRegData ret_ptr = NULL;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (ZwQueryValueKey(registry_key, value_name, KeyValuePartialInformation,
                      NULL, 0, &data_size) != STATUS_BUFFER_TOO_SMALL)
    goto error;

  info = ssh_malloc(data_size);
  if (info == NULL)
    goto error;

  if (NT_SUCCESS(ZwQueryValueKey(registry_key, value_name,
                                 KeyValuePartialInformation, info,
                                 data_size, &data_size)))
    {
      if (data_size > info->DataLength)
        {
          ret_ptr = ssh_malloc(info->DataLength);
          if (ret_ptr)
            {
              memcpy(ret_ptr, info->Data, info->DataLength);

              if (size_return)
                *size_return = info->DataLength;
            }
        }
    }

  ssh_free(info);

 error:
  
  return ret_ptr;
}


static SshRegBool
ssh_registry_platform_set_value(SshRegKey key,
                                SshRegUnicodeString value,
                                SshRegDataType type,
                                SshRegData data,
                                SshRegSize data_size)
{
  SshSetValueKey fn_set_value_key;
  UNICODE_STRING fn_name;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  RtlInitUnicodeString(&fn_name, L"ZwSetValueKey");
  fn_set_value_key = MmGetSystemRoutineAddress(&fn_name);
  if ((fn_set_value_key != NULL_FNPTR)
      && (NT_SUCCESS((*fn_set_value_key)(key, value, 0, type, 
                                         data, data_size))))
    return TRUE;
  else
    return FALSE;
}


static SshRegBool
ssh_registry_platform_delete_value(SshRegKey registry_key,
                                   SshRegUnicodeString value)
{
  SshRegBool ret_value = FALSE;

  SSH_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  if (NT_SUCCESS(ZwDeleteValueKey(registry_key, value)))
    ret_value = TRUE;

  return ret_value;
}


static SshRegBool
ssh_registry_value_is_equal(SshRegKey key,
                            SshRegValue value_name,
                            void *ref_data,
                            SshRegSize ref_size,
                            Boolean allow_extra_zeros)
{
  SshRegBool is_equal = FALSE;
  SshRegSize data_size = 0;
  void *data;

  data = ssh_registry_data_get(key, value_name, &data_size);
  if (data != NULL)
    {
      if ((data_size == ref_size) 
          && (memcmp(data, ref_data, ref_size) == 0))
        {
          /* Exactly the same data */
          is_equal = TRUE;
        }
      else if ((data_size > ref_size) && (allow_extra_zeros))
        {
          /* Check whether this is otherwise the same data, but appended 
             with additional zero bytes. This is normal case if we compare 
             REG_SZ and REG_MULTI_SZ strings (REG_MULTI_SZ is terminated 
             with two UNICODE_NULLs. */

          if (memcmp(data, ref_data, ref_size) == 0)
            {
              SshRegSize extra_bytes = data_size - ref_size;
              unsigned char *ucp = (unsigned char *)data + ref_size;

              while (extra_bytes && (*ucp == 0))
                {
                  extra_bytes--;
                  ucp++;
                }

              if (extra_bytes == 0)
                is_equal = TRUE;
            }
        }

      ssh_free(data);
    }

  return is_equal;
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/
void *
ssh_registry_data_get(SshRegKey registry_key,
                      SshRegValue value_name,
                      SshRegSize *size_return)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_get_value(registry_key, &uc_name, size_return);
}


/* Opens the specified registry key */
SshRegKey
ssh_registry_key_open(SshRegKey parent_key,
                      SshRegPath parent_path,
                      SshRegPath path)
{
  UNICODE_STRING parent_path_uc;
  UNICODE_STRING path_uc;
  PUNICODE_STRING parent_path_ptr = NULL;

  if (parent_path)
    {
      RtlInitUnicodeString(&parent_path_uc, parent_path);
      parent_path_ptr = &parent_path_uc;
    }

  RtlInitUnicodeString(&path_uc, path);

  return ssh_registry_key_open_unicode(parent_key, parent_path_ptr, &path_uc);
}


/* Opens the specified registry key. (This function is UNICODE version of
   ssh_registry_key_open) */
SshRegKey
ssh_registry_key_open_unicode(SshRegKey parent_key,
                              SshRegPathUnicode parent_path,
                              SshRegPathUnicode path)
{
  return ssh_registry_platform_open_key(parent_key, parent_path, path);
}


SshRegKey
ssh_registry_key_create(SshRegKey parent_key,
                        SshRegPath path)
{
  UNICODE_STRING path_uc;

  RtlInitUnicodeString(&path_uc, path);

  return ssh_registry_key_create_unicode(parent_key, &path_uc);
}


SshRegKey
ssh_registry_key_create_unicode(SshRegKey parent_key,
                                SshRegPathUnicode path)
{
  return ssh_registry_platform_create_key(parent_key, path);
}


SshRegBool
ssh_registry_key_delete(SshRegKey parent_key,
                        SshRegPath path)
{
  UNICODE_STRING path_uc;

  RtlInitUnicodeString(&path_uc, path);

  return ssh_registry_key_delete_unicode(parent_key, &path_uc);
}


SshRegBool
ssh_registry_key_delete_unicode(SshRegKey parent_key,
                                SshRegPathUnicode path)
{
  return ssh_registry_platform_delete_key(parent_key, path);
}


SshRegKey
ssh_registry_subkey_find_by_data(SshRegKey parent_key,
                                 SshRegValue value_name,
                                 void *data,
                                 SshRegSize data_len,
                                 SshRegBool recursive)
{
  SshRegIndex subkey_index;
  SshRegSize total_subkeys;
  SshRegKey key = NULL;

  total_subkeys = ssh_registry_key_info_get(parent_key,
                                            SSH_REG_KEY_INFO_SUBKEYS);

  for (subkey_index = 0;
       (key == NULL) && (subkey_index < total_subkeys);
       subkey_index++)
    {
      SshRegKey subkey;

      subkey = ssh_registry_key_open_by_index(parent_key, subkey_index);
      if (subkey)
        {
          if (ssh_registry_value_is_equal(subkey, value_name, 
                                          data, data_len, TRUE))
            {
              key = subkey;
            } 
          else
            {
              if (recursive == TRUE)
                key = ssh_registry_subkey_find_by_data(subkey, value_name,
                                                       data, data_len, TRUE);

              ssh_registry_key_close(subkey);
            }
        }
    }

  return key;
}


SshRegKey 
ssh_registry_subkey_find_by_ansi_data(SshRegKey parent_key,
                                      SshRegValue value_name,
                                      SshRegAnsiString ansi_data,
                                      SshRegSize ansi_data_len,
                                      SshRegBool recursive)
{
  SshRegKey key;
  ANSI_STRING ansistr;
  UNICODE_STRING ucstr;

  /* We don't use RtlIntiAnsiString(), because 'ansi_data' is not necessarily
     NULL-terminated string. */
  ansistr.Buffer = ansi_data;
  ansistr.Length = (USHORT)ansi_data_len;
  ansistr.MaximumLength = ansistr.Length;

  memset(&ucstr, 0, sizeof(ucstr));

  if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&ucstr, &ansistr, TRUE)))
    {
      key = ssh_registry_subkey_find_by_data(parent_key, value_name,
                                             ucstr.Buffer, ucstr.Length,
                                             recursive);

      RtlFreeUnicodeString(&ucstr);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to convert ANSI to UNICODE"));
      return NULL;
    }

  return key;
}


SshRegKey
ssh_registry_key_open_by_index(SshRegKey parent_key,
                               SshRegIndex index)
{
  return ssh_registry_platform_open_key_by_index(parent_key, index);
}


SshRegSize
ssh_registry_key_info_get(SshRegKey key,
                          SshRegKeyQueryType query_type)
{
  return ssh_registry_platform_get_key_info(key, query_type);
}


/* Closes the specified registry key */
void
ssh_registry_key_close(SshRegKey registry_key)
{
  ssh_registry_platform_close_key(registry_key);
}


/* Reads the specified DWORD value from system registry database */
SshRegBool
ssh_registry_dword_get(SshRegKey registry_key,
                       SshRegValue value_name,
                       SshRegDWord *data_return)
{
  SshRegBool success = FALSE;
  SshRegSize data_len;
  void *data;

  data = ssh_registry_data_get(registry_key, value_name, &data_len);
  if (data)
    {
      if (data_len >= sizeof(SshRegDWord));
        {
          memcpy(data_return, data, sizeof(SshRegDWord));
          success = TRUE;
        }

      ssh_free(data);
    }

  return success;
}


/* Reads the specified UNICODE string value from system registry */
SshRegBool
ssh_registry_unicode_string_get(SshRegKey registry_key,
                                SshRegValue value_name,
                                UNICODE_STRING *string)
{
  SshRegBool success = FALSE;
  SshRegSize data_len;
  void *data;

  data = ssh_registry_data_get(registry_key, value_name, &data_len);
  if (data)
    {
      if (data_len > 0xFFFFL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Maximum length exceeded!"));
          ssh_free(data);
          return FALSE;
        }

      if (string->Buffer && string->MaximumLength)
        {
          if (string->MaximumLength >= data_len)
            {
              memcpy(string->Buffer, data, data_len);
              string->Length = (USHORT)data_len;

              success = TRUE;
            }

          ssh_free(data);
        }
      else
        {
          string->Length = (USHORT)data_len;
          string->MaximumLength = (USHORT)data_len;
          string->Buffer = data;

          success = TRUE;
        }
    }
  
  return success;
}


/* Reads the specified ASCII/ANSI string value from system registry */
SshRegBool
ssh_registry_asciiz_string_get(SshRegKey registry_key,
                               SshRegValue value_name,
                               unsigned char **string)
{
  SshRegBool success = FALSE;
  UNICODE_STRING uc_value;

  memset(&uc_value, 0x00, sizeof(uc_value));
  if (ssh_registry_unicode_string_get(registry_key, value_name, &uc_value))
    {
      SshUInt32 buf_size;
      ANSI_STRING ansi_str;

      buf_size = ((uc_value.Length / sizeof(uc_value.Buffer[0])) + 1);

      ansi_str.Length = 0;
      ansi_str.MaximumLength = (SshUInt16)buf_size;
      ansi_str.Buffer = ssh_calloc(1, ansi_str.MaximumLength);
      if (ansi_str.Buffer != NULL)
        {
          if (RtlUnicodeStringToAnsiString(&ansi_str, &uc_value, 
                                           FALSE) == STATUS_SUCCESS)
            {
              *string = ansi_str.Buffer;
              success = TRUE;
            }
          else
            {
              ssh_free(ansi_str.Buffer);
            }
        }

      ssh_free(uc_value.Buffer);
    }
  
  return success;
}


/* Read the specified amount of binary data from a registry value. Returns
   false if enough data does not exist */
SshRegBool
ssh_registry_binary_data_get(SshRegKey registry_key,
                             SshRegValue value_name,
                             void *data_return,
                             SshRegSize data_size)
{
  SshRegBool success = FALSE;
  SshRegSize data_len;
  void *data;

  data = ssh_registry_data_get(registry_key, value_name, &data_len);
  if (data)
    {
      if (data_len >= data_size);
        {
          memcpy(data_return, data, data_size);
          success = TRUE;
        }

      ssh_free(data);
    }

  return success;
}


/* Writes the given DWORD value into system registry database */
SshRegBool
ssh_registry_dword_set(SshRegKey registry_key,
                       SshRegValue value_name,
                       SshRegDWord data)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_set_value(registry_key, &uc_name, REG_DWORD, 
                                         &data, sizeof(data));
}


/* Writes the given string value into system registry database */
SshRegBool
ssh_registry_string_set(SshRegKey registry_key,
                        SshRegValue value_name,
                        SshRegString string)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_set_value(registry_key, &uc_name, 
                                         REG_SZ, string, 
                                         (ULONG)SSH_REG_STR_SIZE(string));
}


/* Writes the given multi-string value into system registry database */
SshRegBool
ssh_registry_multi_string_set(SshRegKey registry_key,
                              SshRegValue value_name,
                              SshRegString data,
                              SshRegSize data_size)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_set_value(registry_key, &uc_name, 
                                         REG_MULTI_SZ, data, data_size);
}


/* Writes the unicode given string value into system registry database */
SshRegBool
ssh_registry_unicode_string_set(SshRegKey registry_key,
                                SshRegValue value_name,
                                UNICODE_STRING *string)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_set_value(registry_key, &uc_name, 
                                         REG_SZ, string->Buffer,
                                         string->Length); 
}


/* Write the given binary data into system registry database */
SshRegBool
ssh_registry_binary_data_set(SshRegKey registry_key,
                             SshRegValue value_name,
                             void *data,
                             SshRegSize data_size)
{
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_set_value(registry_key, &uc_name,
                                         REG_BINARY, data, data_size);
}


/* Deletes the specified value from system registry database */
SshRegBool
ssh_registry_value_delete(SshRegKey registry_key,
                          SshRegValue value_name)
{
  SshRegBool ret_value = FALSE;
  UNICODE_STRING uc_name;

  RtlInitUnicodeString(&uc_name, value_name);

  return ssh_registry_platform_delete_value(registry_key, &uc_name);
}

