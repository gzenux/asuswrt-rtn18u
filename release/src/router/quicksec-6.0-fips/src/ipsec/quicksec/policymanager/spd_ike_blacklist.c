/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation for the QuickSec Blacklisting functionality.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSH_PM_BLACKLIST_ENABLED

#define SSH_DEBUG_MODULE "SshPmBlacklist"

/* Maximum length of id data */
#define SSH_PM_BLACKLIST_MAX_ID_DATA_LEN 65535

/** A blacklist object. */
typedef struct SshPmBlacklistRec
{
  /** ADT header */
  SshADTBagHeaderStruct adt_header;

  /** IKE ID */
  SshIkev2PayloadID ike_id;

  /** ID encoding */
  SshPmSecretEncoding id_encoding;

#ifdef SSH_IPSEC_STATISTICS
  /** Statistics counter for blocked attempts */
  SshUInt32 stat_blocked;
#endif /* SSH_IPSEC_STATISTICS */

} SshPmBlacklistStruct, *SshPmBlacklist;

/* Number of entries in active database */
SshUInt32 ssh_pm_blacklist_active_db_entries;

/* Internal statistics object for Blacklisting functionality */
typedef struct SshPmBlacklistInternalStatsRec
{
  SshUInt32 allowed[SSH_PM_BLACKLIST_CHECK_LAST];
  SshUInt32 blocked[SSH_PM_BLACKLIST_CHECK_LAST];

} SshPmBlacklistInternalStatsStruct, *SshPmBlacklistInternalStats;

/* Blacklist statistics structure for internal use */
SshPmBlacklistInternalStatsStruct ssh_pm_blacklist_internal_stats;

/* Keyword table for Blacklist Errors */
const SshKeywordStruct ssh_pm_blacklist_error_to_string_table[] = {
  { "Successful",
    SSH_PM_BLACKLIST_OK },
  { "Database limit exceeded",
    SSH_PM_BLACKLIST_ERROR_DB_LIMIT_EXCEEDED },
  { "Out of memory",
    SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY },
  { "Syntax error in configuration data",
    SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR },
  { "Decode failure of IKE ID",
    SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE },
  { "Invalid argument",
    SSH_PM_BLACKLIST_ERROR_INVALID_ARGUMENT },
  { "Duplicate IKE ID in configuration data",
    SSH_PM_BLACKLIST_ERROR_DUPLICATE_IKE_ID },
  {NULL, 0}
};

/* Keyword table for Blacklist Check Codes */
const SshKeywordStruct ssh_pm_blacklist_check_code_to_string_table[] = {
  { "Responder initial exchange",
    SSH_PM_BLACKLIST_CHECK_IKEV2_R_INITIAL_EXCHANGE },
  { "Responder create child exchange",
    SSH_PM_BLACKLIST_CHECK_IKEV2_R_CREATE_CHILD_EXCHANGE },
  { "Responder IPsec SA rekey",
    SSH_PM_BLACKLIST_CHECK_IKEV2_R_IPSEC_SA_REKEY },
  { "Responder IKE SA rekey",
    SSH_PM_BLACKLIST_CHECK_IKEV2_R_IKE_SA_REKEY },
  { "Initiator IPsec SA rekey",
    SSH_PM_BLACKLIST_CHECK_IKEV2_I_IPSEC_SA_REKEY },
  { "Initiator IKE SA rekey",
    SSH_PM_BLACKLIST_CHECK_IKEV2_I_IKE_SA_REKEY },
  { "Responder main mode exchange",
    SSH_PM_BLACKLIST_CHECK_IKEV1_R_MAIN_MODE_EXCHANGE },
  { "Responder aggressive mode exchange",
    SSH_PM_BLACKLIST_CHECK_IKEV1_R_AGGRESSIVE_MODE_EXCHANGE },
  { "Responder quick mode exchange",
    SSH_PM_BLACKLIST_CHECK_IKEV1_R_QUICK_MODE_EXCHANGE },
  { "Initiator IPsec SA rekey",
    SSH_PM_BLACKLIST_CHECK_IKEV1_I_IPSEC_SA_REKEY },
  { "Initiator DPD SA creation",
    SSH_PM_BLACKLIST_CHECK_IKEV1_I_DPD_SA_CREATION },
  {NULL, 0}
};

/* Keyword table for IKE ID Types */
const SshKeywordStruct ssh_pm_blacklist_ikev2_id_type_to_string_table[] = {
  { "ip", SSH_IKEV2_ID_TYPE_IPV4_ADDR },
  { "fqdn", SSH_IKEV2_ID_TYPE_FQDN },
  { "email", SSH_IKEV2_ID_TYPE_RFC822_ADDR },
  { "ip", SSH_IKEV2_ID_TYPE_IPV6_ADDR },
  { "dn", SSH_IKEV2_ID_TYPE_ASN1_DN },
  { "key-id", SSH_IKEV2_ID_TYPE_KEY_ID },
  {NULL, 0}
};

const char *
ssh_pm_blacklist_error_to_string(SshPmBlacklistError error)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_pm_blacklist_error_to_string_table, error);
  if (name)
    return name;

  return "Unknown error";
}

static const char *
ssh_pm_blacklist_check_code_to_string(SshPmBlacklistCheckCode check_code)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_pm_blacklist_check_code_to_string_table,
                               check_code);
  if (name)
    return name;

  return "Unknown check code";
}

static const unsigned char *
ssh_pm_blacklist_ikev2_id_type_to_string(SshIkev2IDType type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_pm_blacklist_ikev2_id_type_to_string_table,
                               type);
  if (name)
    return (unsigned char *) name;

  return (unsigned char *) "Unknown";
}

/*************************** Blacklist database ******************************/

static SshUInt32
ssh_pm_blacklist_adt_hash(void *ptr,
                          void *ctx)
{
  SshUInt32 hash = ssh_ikev2_payload_id_hash(((SshPmBlacklist) ptr)->ike_id);

  return hash;
}

static int
ssh_pm_blacklist_adt_compare(void *ptr1,
                             void *ptr2,
                             void *ctx)
{
  SshIkev2PayloadID ike_id1 = ((SshPmBlacklist) ptr1)->ike_id;
  SshIkev2PayloadID ike_id2 = ((SshPmBlacklist) ptr2)->ike_id;

  if ((ike_id1->id_type != ike_id2->id_type)
      || (ike_id1->id_data_size != ike_id2->id_data_size))
    {
      return 1;
    }

  return memcmp(ike_id1->id_data, ike_id2->id_data, ike_id1->id_data_size);
}

static void
ssh_pm_blacklist_adt_destroy(void *ptr,
                             void *ctx)
{
  SshPmBlacklist entry = ptr;

  ssh_pm_ikev2_payload_id_free(entry->ike_id);
  ssh_free(entry);
}

static SshADTContainer
ssh_pm_blacklist_adt_create(SshPm pm)
{
  SshADTContainer container
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmBlacklistStruct,
                                               adt_header),

                             SSH_ADT_HASH,     ssh_pm_blacklist_adt_hash,
                             SSH_ADT_COMPARE,  ssh_pm_blacklist_adt_compare,
                             SSH_ADT_DESTROY,  ssh_pm_blacklist_adt_destroy,
                             SSH_ADT_CONTEXT,  pm,

                             SSH_ADT_ARGS_END);

  return container;
}

static SshPmBlacklistError
ssh_pm_blacklist_adt_insert(SshADTContainer container,
                            SshIkev2PayloadID ike_id,
                            SshPmSecretEncoding id_encoding)
{
  SshPmBlacklist entry;

  /* Check if there is room for new entry. */
  if (ssh_adt_num_objects(container) >= SSH_PM_BLACKLIST_MAX_DB_ENTRIES)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Database limit exceeded"));
      return SSH_PM_BLACKLIST_ERROR_DB_LIMIT_EXCEEDED;
    }

  entry = ssh_calloc(1, sizeof(*entry));
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when allocating entry"));
      return SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
    }

  /* Store IKE ID and ID encoding. */
  entry->ike_id = ike_id;
  entry->id_encoding = id_encoding;

  /* Insert entry to database */
  ssh_adt_insert(container, entry);

  return SSH_PM_BLACKLIST_OK;
}

static SshPmBlacklist
ssh_pm_blacklist_adt_get(SshADTContainer container,
                         SshIkev2PayloadID ike_id)
{
  SshPmBlacklistStruct search_entry;
  SshADTHandle handle;

  /* Prepare entry and search IKE ID */
  search_entry.ike_id = ike_id;

  handle = ssh_adt_get_handle_to_equal(container, &search_entry);
  if (handle == SSH_ADT_INVALID)
    return NULL;
  else
    return ssh_adt_get(container, handle);
}

/***************************** Decode IKE ID *********************************/

static SshPmBlacklistError
ssh_pm_blacklist_decode_ike_id(SshPmSecretEncoding id_encoding,
                               SshPmIdentityType id_type,
                               unsigned char *id_data,
                               SshIkev2PayloadID *ike_id)
{
  SshPmBlacklistError err = SSH_PM_BLACKLIST_OK;
  Boolean malformed;
  unsigned char *identity;
  size_t identity_len;

  /* Manipulate identity based on encoding type */
  identity = ssh_pm_decode_secret(id_encoding,
                                  id_data,
                                  strlen((char *) id_data),
                                  &identity_len,
                                  &malformed);
  if (identity == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failure when manipulating identity based on encoding type"));
      return SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE;
    }

  if (id_encoding == SSH_PM_BINARY)
    {

      /* Decode identity */
      *ike_id = ssh_pm_decode_identity(id_type,
                                       identity,
                                       identity_len,
                                       &malformed);
      if (*ike_id == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failure when decoding binary identity"));
          err = SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE;
          goto out;
        }
    }
  else if (id_encoding == SSH_PM_HEX)
    {
      *ike_id = ssh_calloc(1, sizeof(**ike_id));
      if (*ike_id == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Out of memory when allocating IKE ID"));
          err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
          goto out;
        }

      /* Convert id type to IKEv2 type. */
      switch (id_type)
        {
        case SSH_PM_IDENTITY_DN:
          (*ike_id)->id_type = SSH_IKEV2_ID_TYPE_ASN1_DN;
          break;

        case SSH_PM_IDENTITY_KEY_ID:
          (*ike_id)->id_type = SSH_IKEV2_ID_TYPE_KEY_ID;
          break;

        default:
          SSH_DEBUG(SSH_D_ERROR, ("Unsupported identity type for hex format"));
          ssh_free(*ike_id);
          err = SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE;
          goto out;
        }

      (*ike_id)->id_data_size = identity_len;
      (*ike_id)->id_data = ssh_memdup(identity, identity_len);
      if ((*ike_id)->id_data == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory when allocating IKE ID data"));
          ssh_free(*ike_id);
          err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
          goto out;
        }
    }
  else
    {
      err = SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE;
    }

 out:

  ssh_free(identity);

  return err;
}

/************************* Configuration parsing *****************************/

static Boolean
ssh_pm_blacklist_is_line_break(unsigned char *conf_data,
                               size_t conf_len)
{
  if (conf_len == 0)
    return TRUE;
  if (*conf_data == '\n')
    return TRUE;
  if (conf_len > 1 && *conf_data == '\r' && *(conf_data + 1) == '\n')
    return TRUE;

  return FALSE;
}

static size_t
ssh_pm_blacklist_scan_end_of_line(unsigned char *conf_data,
                                  size_t conf_len)
{
  size_t i;

  /* Find out end of data or line break. */
  for (i = 0; i < conf_len; i++)
    {
      if (conf_data[i] == '\n')
        return i + 1;
    }

  return i;
}

static void
ssh_pm_blacklist_goto_end_of_line(unsigned char **conf_data,
                                  size_t *conf_len)
{
  size_t line_len;

  line_len = ssh_pm_blacklist_scan_end_of_line(*conf_data, *conf_len);

  /* Update return values */
  *conf_data = *conf_data + line_len;
  *conf_len = *conf_len - line_len;
}

static Boolean
ssh_pm_blacklist_skip_comment_line(unsigned char **conf_data,
                                   size_t *conf_len)
{
  /* Check if first character is commenting character. */
  if (*conf_len >= 1 && **conf_data == '#')
    {
      /* Ignore rest of the line. */
      ssh_pm_blacklist_goto_end_of_line(conf_data, conf_len);
      return TRUE;
    }
  else
    {
      return FALSE;
    }
}

static Boolean
ssh_pm_blacklist_skip_empty_line(unsigned char **conf_data,
                                 size_t *conf_len)
{
  unsigned char *p;
  int is_empty = 1;
  size_t i;

  if (*conf_len == 0)
    return FALSE;

  /* Parse all spaces and tabulators */
  for (i = 0, p = *conf_data; i < *conf_len; i++, p++)
    {
      if (!SSH_PM_IS_BLANK(*p))
        {
          /* Check if there is line break. */
          if (*p == '\n')
            {
              i++;
              p++;
              is_empty = 1;
            }
          else if (*conf_len - i > 1 && *p == '\r' && *(p + 1) == '\n')
            {
              i+=2;
              p+=2;
              is_empty = 1;
            }
          else
            {
              is_empty = 0;
            }
          break;
        }
    }

  if (!is_empty)
    return FALSE;

 /* Update return values */
  *conf_data = p;
  *conf_len = *conf_len - i;

  return TRUE;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_separator(unsigned char **conf_data,
                                 size_t *conf_len)
{
  unsigned char *p;
  size_t i;

  /* Parse all spaces and tabulators */
  for (i = 0, p = *conf_data; i < *conf_len; i++, p++)
    {
      if (!SSH_PM_IS_BLANK(*p))
        break;
    }

  /* Check if separator found */
  if (i == 0)
    return SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;

 /* Update return values */
  *conf_data = *conf_data + i;
  *conf_len = *conf_len - i;

  return SSH_PM_BLACKLIST_OK;
}

static size_t
ssh_pm_blacklist_scan_separator(unsigned char *conf_data,
                                size_t conf_len)
{
  size_t i;

  /* Scan space, tabulator or line break */
  for (i = 0; i < conf_len; i++)
    {
      if (SSH_PM_IS_BLANK(conf_data[i])
          || conf_data[i] == '\n'
          || conf_data[i] == '\r')
        return i;
    }

  return i;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_id_type(unsigned char **conf_data,
                               size_t *conf_len,
                               SshPmIdentityType *id_type)
{
  size_t parse_cnt;

  /* Find out where separator is. */
  parse_cnt = ssh_pm_blacklist_scan_separator(*conf_data, *conf_len);

  /* Check identity type */
  if (parse_cnt == 6 && (memcmp("key-id", *conf_data, 6) == 0))
    {
      *id_type = SSH_PM_IDENTITY_KEY_ID;
    }
  else if (parse_cnt == 5 && (memcmp("email", *conf_data, 5) == 0))
    {
      *id_type = SSH_PM_IDENTITY_RFC822;
    }
  else if (parse_cnt == 4 && (memcmp("fqdn", *conf_data, 4) == 0))
    {
      *id_type = SSH_PM_IDENTITY_FQDN;
    }
  else if (parse_cnt == 2 && (memcmp("ip", *conf_data, 2) == 0))
    {
      *id_type = SSH_PM_IDENTITY_IP;
    }
  else if (parse_cnt == 2 && (memcmp("dn", *conf_data, 2) == 0))
    {
      *id_type = SSH_PM_IDENTITY_DN;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration doesn't contain valid type"));
      return SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
    }

  /* Update return values */
  *conf_data = *conf_data + parse_cnt;
  *conf_len = *conf_len - parse_cnt;

  return SSH_PM_BLACKLIST_OK;
}

static SshPmBlacklistError
ssh_pm_blacklist_check_comment(unsigned char *conf_data,
                               size_t line_len)
{
  SshPmBlacklistError err;

  if (ssh_pm_blacklist_is_line_break(conf_data, line_len) == TRUE)
    return SSH_PM_BLACKLIST_OK;

  err = ssh_pm_blacklist_parse_separator(&conf_data, &line_len);
  if (err != SSH_PM_BLACKLIST_OK)
    return err;

  if (ssh_pm_blacklist_is_line_break(conf_data, line_len) == TRUE)
    return SSH_PM_BLACKLIST_OK;

  if (ssh_pm_blacklist_skip_comment_line(&conf_data, &line_len))
    return SSH_PM_BLACKLIST_OK;
  else
    return SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_id_data_binary(unsigned char *conf_data,
                                      size_t line_len,
                                      unsigned char **id_data,
                                      Boolean do_esc_char_removal)
{
  SshPmBlacklistError err = SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
  SshBufferStruct buffer[1];
  SshBufferStatus status;
  unsigned char tmp_char;
  size_t parse_cnt;

  /* Init buffer */
  ssh_buffer_init(buffer);

  /* Data should always contain at least 3 characters */
  if (line_len < 3)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data too short"));
      goto error;
    }

  /* It should start with '"' character */
  if (conf_data[0] != '"')
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Configuration data doesn't start with correct character"));
      goto error;
    }

  /* It cannot be empty string. */
  if (conf_data[1] == '"')
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data cannot be empty string"));
      goto error;
    }

  /* Copy identity */
  for (parse_cnt = 1;
       (parse_cnt < line_len &&
        parse_cnt < SSH_PM_BLACKLIST_MAX_ID_DATA_LEN &&
        conf_data[parse_cnt] != '"');
       parse_cnt++)
    {
      /* Check escape character. */
      if (conf_data[parse_cnt] == '\\')
        {
          if ((parse_cnt + 1) >= line_len)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Configuration data ended too early"));
              goto error;
            }

          /* Do escape character removal when it is requested. */
          if (do_esc_char_removal)
            {
              /* Increment parse counter and remove escape character only if
                 '"' or '\' character follows it. */
              parse_cnt++;
              if (conf_data[parse_cnt] == '"' || conf_data[parse_cnt] == '\\')
                {
                  status = ssh_buffer_append(buffer, &conf_data[parse_cnt], 1);
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Invalid character after escape character"));
                  goto error;
                }
            }
          /* Check if escape character is followed by '"' character. */
          else if (conf_data[parse_cnt + 1] == '"')
            {
              /* Copy escape and '"' character. */
              status = ssh_buffer_append(buffer, &conf_data[parse_cnt], 2);
              parse_cnt++;
            }
          else
            {
              status = ssh_buffer_append(buffer, &conf_data[parse_cnt], 1);
            }
        }
      else
        {
          status = ssh_buffer_append(buffer, &conf_data[parse_cnt], 1);
        }

      /* Check if append failed. */
      if (status == SSH_BUFFER_ERROR)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory when allocating space for identity"));
          err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
          goto error;
        }
    }

  /* Check if data ended too early. */
  if (parse_cnt >= line_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data ended too early"));
      goto error;
    }

  /* Check if data too long. */
  if (parse_cnt >= SSH_PM_BLACKLIST_MAX_ID_DATA_LEN)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data too long"));
      goto error;
    }

  /* Append termination character */
  tmp_char = '\0';
  status = ssh_buffer_append(buffer, &tmp_char, 1);
  if (status == SSH_BUFFER_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory when allocating space for identity"));
      err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Skip '"' character */
  parse_cnt++;

  /* Check if line contains comment. */
  err = ssh_pm_blacklist_check_comment(&conf_data[parse_cnt],
                                       line_len - parse_cnt);
  if (err != SSH_PM_BLACKLIST_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data contains extra characters"));
      goto error;
    }

  /* Get id_data and uninit buffer before return */
  *id_data = ssh_buffer_steal(buffer, NULL);
  if (*id_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when stealing data from buffer"));
      err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  ssh_buffer_uninit(buffer);

  return SSH_PM_BLACKLIST_OK;

 error:

  /* Uninit buffer before return. */
  ssh_buffer_uninit(buffer);

  *id_data = NULL;

  return err;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_id_data_hex(unsigned char *conf_data,
                                   size_t line_len,
                                   unsigned char **id_data)
{
  SshPmBlacklistError err = SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
  SshBufferStruct buffer[1];
  SshBufferStatus status;
  unsigned char tmp_char;
  size_t parse_cnt;

  /* Init buffer */
  ssh_buffer_init(buffer);

  /* Data should always contain at least 3 characters */
  if (line_len < 3)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data too short"));
      goto error;
    }

  /* It should start with "0x" string */
  if (!(conf_data[0] == '0' && conf_data[1] == 'x'))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Configuration data doesn't start with correct characters"));
      goto error;
    }

  /* It should contain at least one hex character. */
  if (!SSH_PM_IS_HEX(conf_data[2]))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Configuration data doesn't contain hex characters"));
      goto error;
    }

  /* Copy identity */
  for (parse_cnt = 2;
       (parse_cnt < line_len &&
        parse_cnt <= SSH_PM_BLACKLIST_MAX_ID_DATA_LEN &&
        SSH_PM_IS_HEX(conf_data[parse_cnt]));
       parse_cnt++)
    {
      status = ssh_buffer_append(buffer, &conf_data[parse_cnt], 1);
      if (status == SSH_BUFFER_ERROR)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory when allocating space for identity"));
          err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
          goto error;
        }
    }

  /* Check if data too long. */
  if (parse_cnt > SSH_PM_BLACKLIST_MAX_ID_DATA_LEN)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data too long"));
      goto error;
    }

  /* Check if line contains comment. */
  err = ssh_pm_blacklist_check_comment(&conf_data[parse_cnt],
                                       line_len - parse_cnt);
  if (err != SSH_PM_BLACKLIST_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data contains extra characters"));
      goto error;
    }

  /* Append termination character */
  tmp_char = '\0';
  status = ssh_buffer_append(buffer, &tmp_char, 1);
  if (status == SSH_BUFFER_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory when allocating space for identity"));
      err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Get id_data and uninit buffer before return. */
  *id_data = ssh_buffer_steal(buffer, NULL);
  if (*id_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory when stealing data from buffer"));
      err = SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  ssh_buffer_uninit(buffer);

  return SSH_PM_BLACKLIST_OK;

 error:

  /* Uninit buffer before return. */
  ssh_buffer_uninit(buffer);

  *id_data = NULL;

  return err;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_id_data(unsigned char *conf_data,
                               size_t line_len,
                               SshPmSecretEncoding *id_encoding,
                               SshPmIdentityType id_type,
                               unsigned char **id_data)
{
  SshPmBlacklistError err;
  Boolean do_esc_char_removal;

  if (line_len < 1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Configuration data too short"));
      return SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
    }

  /* Check data format and call proper parse function. */
  if (conf_data[0] == '"')
    {
      /* Solve when escape charater removal has to be done. */
      if (id_type == SSH_PM_IDENTITY_DN)
        do_esc_char_removal = FALSE;
      else
        do_esc_char_removal = TRUE;

      *id_encoding = SSH_PM_BINARY;
      err = ssh_pm_blacklist_parse_id_data_binary(conf_data,
                                                  line_len,
                                                  id_data,
                                                  do_esc_char_removal);
    }
  else if (conf_data[0] == '0')
    {
      *id_encoding = SSH_PM_HEX;
      err = ssh_pm_blacklist_parse_id_data_hex(conf_data, line_len, id_data);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Configuration data doesn't start with correct character"));
      err = SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR;
    }

  return err;
}

static SshPmBlacklistError
ssh_pm_blacklist_parse_config_line(unsigned char **conf_data,
                                   size_t *conf_len,
                                   SshPmSecretEncoding *id_encoding,
                                   SshPmIdentityType *id_type,
                                   unsigned char **id_data)
{
  SshPmBlacklistError err;
  size_t line_len;

  *id_data = NULL;

  /* Parse id type */
  err = ssh_pm_blacklist_parse_id_type(conf_data, conf_len, id_type);
  if (err != SSH_PM_BLACKLIST_OK)
    goto error;

  /* Skip separator(s) */
  err = ssh_pm_blacklist_parse_separator(conf_data, conf_len);
  if (err != SSH_PM_BLACKLIST_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Configuration doesn't contain mandatory separator "
                 "after type"));
      goto error;
    }

  /* Find end of line. */
  line_len = ssh_pm_blacklist_scan_end_of_line(*conf_data, *conf_len);

  /* Parse id data */
  err = ssh_pm_blacklist_parse_id_data(*conf_data,
                                       line_len,
                                       id_encoding,
                                       *id_type,
                                       id_data);
  if (err != SSH_PM_BLACKLIST_OK)
    goto error;

  /* Update return values. */
  *conf_data = *conf_data + line_len;
  *conf_len = *conf_len - line_len;

  return SSH_PM_BLACKLIST_OK;

 error:

  if (*id_data)
    ssh_free(*id_data);

  *id_encoding = SSH_PM_ENCODING_UNKNOWN;
  *id_type = SSH_PM_IDENTITY_ANY;
  *id_data = NULL;

  return err;
}

/**************************** Initialization ********************************/

Boolean
ssh_pm_blacklist_init(SshPm pm)
{
  /* Clear pending database pointer. */
  pm->pending_blacklist = NULL;

  /* Create active database. */
  pm->active_blacklist = ssh_pm_blacklist_adt_create(pm);
  if (pm->active_blacklist)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Initialization done"));
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Initialization failed"));
      return FALSE;
    }
}

void
ssh_pm_blacklist_uninit(SshPm pm)
{
  /* Destroy active database. */
  if (pm->active_blacklist)
    {
      ssh_adt_destroy(pm->active_blacklist);
      pm->active_blacklist = NULL;
    }

  /* Destroy pending database. */
  if (pm->pending_blacklist)
    {
      ssh_adt_destroy(pm->pending_blacklist);
      pm->pending_blacklist = NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Uninitialization done"));
}

/***************************** Commit/Abort *********************************/

void
ssh_pm_blacklist_commit(SshPm pm)
{
  SshADTContainer blacklist_tmp;

  /* Check if pending database is available. */
  if (pm->pending_blacklist == NULL)
    return;

  /* Switch pending database to active one. */
  blacklist_tmp = pm->active_blacklist;
  pm->active_blacklist = pm->pending_blacklist;

  /* Update statistics counter. */
  ssh_pm_blacklist_active_db_entries
    = ssh_adt_num_objects(pm->active_blacklist);

  /* Destroy deactivated database and clear pending database pointer. */
  ssh_adt_destroy(blacklist_tmp);
  pm->pending_blacklist = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Commit done"));
}

void
ssh_pm_blacklist_abort(SshPm pm)
{
  /* Check if pending database is available. */
  if (pm->pending_blacklist == NULL)
    return;

  /* Destroy pending database */
  ssh_adt_destroy(pm->pending_blacklist);
  pm->pending_blacklist = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Abort done"));
}

/****************************** Statistics *********************************/

#ifdef SSH_IPSEC_STATISTICS
static void
ssh_pm_blacklist_copy_stats(SshPmBlacklistStats stats)
{
  SshPmBlacklistInternalStats istats = &ssh_pm_blacklist_internal_stats;

  /* Copy number of entries in blacklist database */
  stats->blacklist_entries = ssh_pm_blacklist_active_db_entries;

  /* Copy allowed statistics */
  stats->allowed_ikev2_r_initial_exchanges =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_R_INITIAL_EXCHANGE];
  stats->allowed_ikev2_r_create_child_exchanges =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_R_CREATE_CHILD_EXCHANGE];
  stats->allowed_ikev2_r_ipsec_sa_rekeys =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_R_IPSEC_SA_REKEY];
  stats->allowed_ikev2_r_ike_sa_rekeys =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_R_IKE_SA_REKEY];
  stats->allowed_ikev2_i_ipsec_sa_rekeys =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_I_IPSEC_SA_REKEY];
  stats->allowed_ikev2_i_ike_sa_rekeys =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV2_I_IKE_SA_REKEY];
  stats->allowed_ikev1_r_main_mode_exchanges =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV1_R_MAIN_MODE_EXCHANGE];
  stats->allowed_ikev1_r_aggressive_mode_exchanges =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV1_R_AGGRESSIVE_MODE_EXCHANGE];
  stats->allowed_ikev1_r_quick_mode_exchanges =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV1_R_QUICK_MODE_EXCHANGE];
  stats->allowed_ikev1_i_ipsec_sa_rekeys =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV1_I_IPSEC_SA_REKEY];
  stats->allowed_ikev1_i_dpd_sa_creations =
    istats->allowed[SSH_PM_BLACKLIST_CHECK_IKEV1_I_DPD_SA_CREATION];

  /* Copy blocked statistics */
  stats->blocked_ikev2_r_initial_exchanges =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_R_INITIAL_EXCHANGE];
  stats->blocked_ikev2_r_create_child_exchanges =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_R_CREATE_CHILD_EXCHANGE];
  stats->blocked_ikev2_r_ipsec_sa_rekeys =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_R_IPSEC_SA_REKEY];
  stats->blocked_ikev2_r_ike_sa_rekeys =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_R_IKE_SA_REKEY];
  stats->blocked_ikev2_i_ipsec_sa_rekeys =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_I_IPSEC_SA_REKEY];
  stats->blocked_ikev2_i_ike_sa_rekeys =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV2_I_IKE_SA_REKEY];
  stats->blocked_ikev1_r_main_mode_exchanges =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV1_R_MAIN_MODE_EXCHANGE];
  stats->blocked_ikev1_r_aggressive_mode_exchanges =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV1_R_AGGRESSIVE_MODE_EXCHANGE];
  stats->blocked_ikev1_r_quick_mode_exchanges =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV1_R_QUICK_MODE_EXCHANGE];
  stats->blocked_ikev1_i_ipsec_sa_rekeys =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV1_I_IPSEC_SA_REKEY];
  stats->blocked_ikev1_i_dpd_sa_creations =
    istats->blocked[SSH_PM_BLACKLIST_CHECK_IKEV1_I_DPD_SA_CREATION];
}

static void
ssh_pm_blacklist_inc_stats(Boolean inc_allowed_counter,
                           SshPmBlacklistCheckCode check_code)
{
  if (check_code >=  SSH_PM_BLACKLIST_CHECK_LAST)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too big check code"));
      return;
    }

  if (inc_allowed_counter)
    ssh_pm_blacklist_internal_stats.allowed[check_code]++;
  else
    ssh_pm_blacklist_internal_stats.blocked[check_code]++;
}
#endif /* SSH_IPSEC_STATISTICS */

/**************************** Blacklist check *******************************/

Boolean
ssh_pm_blacklist_check(SshPm pm,
                       SshIkev2PayloadID ike_id,
                       SshPmBlacklistCheckCode check_code)
{
  SshPmBlacklist entry;

  SSH_ASSERT(pm->active_blacklist != NULL);

  /* Check if IKE ID exists in blacklist. */
  entry = ssh_pm_blacklist_adt_get(pm->active_blacklist, ike_id);
  if (entry == NULL)
    {
      /* IKE ID not found in blacklist. */

#ifdef SSH_IPSEC_STATISTICS
      /* Increment global statistics */
      ssh_pm_blacklist_inc_stats(TRUE, check_code);
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IKE_ID_LIST
      if (ike_id->id_type == (int) IPSEC_ID_LIST)
        SSH_DEBUG(SSH_D_FAIL,
                  ("check done for ID LIST identity which is not currently "
                   "supported"));
#endif /* SSHDIST_IKE_ID_LIST */

      SSH_DEBUG(SSH_D_LOWOK,
                ("Allowing IKE ID %@, %s (%u)",
                 ssh_pm_ike_id_render, ike_id,
                 ssh_pm_blacklist_check_code_to_string(check_code),
                 check_code));

      return TRUE;
    }
  else
    {
      /* IKE ID found in blacklist. */

#ifdef SSH_IPSEC_STATISTICS
      /* Increment global statistics */
      ssh_pm_blacklist_inc_stats(FALSE, check_code);

      /* Increment blocked statistics counter of blacklist entry */
      entry->stat_blocked++;
#endif /* SSH_IPSEC_STATISTICS */

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Blacklist blocking IKE ID %@, %s (%u)",
                    ssh_pm_ike_id_render, ike_id,
                    ssh_pm_blacklist_check_code_to_string(check_code),
                    check_code);

      return FALSE;
    }
}

/*************************** Set configuration *******************************/

SshPmBlacklistError
ssh_pm_blacklist_set(SshPm pm,
                     unsigned char *config,
                     size_t config_len)
{
  SshPmBlacklistError err = SSH_PM_BLACKLIST_OK;
  SshADTContainer pending_blacklist = NULL;
  unsigned char *conf_data = config;
  int i = 0;

  /* Check arguments */
  if (config == NULL && config_len > 0)
    return SSH_PM_BLACKLIST_ERROR_INVALID_ARGUMENT;

  SSH_ASSERT(pm != NULL);

  /* Abort previous configuration change. */
  ssh_pm_blacklist_abort(pm);

  /* Create database for new config. */
  pending_blacklist = ssh_pm_blacklist_adt_create(pm);
  if (pending_blacklist == NULL)
    return SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY;

  /* Parse configuration */
  for (i = 1; config_len > 0; i++)
    {
      SshPmSecretEncoding id_encoding;
      SshPmIdentityType id_type;
      unsigned char *id_data;
      SshIkev2PayloadID ike_id;

      /* Skip possible comment and empty lines. */
      if (ssh_pm_blacklist_skip_comment_line(&conf_data, &config_len))
        continue;

      if (ssh_pm_blacklist_skip_empty_line(&conf_data, &config_len))
        continue;

      /* Parse configuration line. */
      err = ssh_pm_blacklist_parse_config_line(&conf_data,
                                               &config_len,
                                               &id_encoding,
                                               &id_type,
                                               &id_data);
      if (err != SSH_PM_BLACKLIST_OK)
        break;

      /* Decode IKE ID and free memory allocated during parse phase. */
      err = ssh_pm_blacklist_decode_ike_id(id_encoding,
                                           id_type,
                                           id_data,
                                           &ike_id);
      ssh_free(id_data);
      if (err != SSH_PM_BLACKLIST_OK)
        break;

      /* Check if IKE ID already stored to blacklist database. */
      if (ssh_pm_blacklist_adt_get(pending_blacklist, ike_id) == NULL)
        {
          /* Insert IKE ID to config database. */
          err = ssh_pm_blacklist_adt_insert(pending_blacklist,
                                            ike_id,
                                            id_encoding);
          if (err != SSH_PM_BLACKLIST_OK)
            {
              ssh_pm_ikev2_payload_id_free(ike_id);
              break;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Duplicate IKE ID %@ found from configuration",
                     ssh_pm_ike_id_render, ike_id));

          ssh_pm_ikev2_payload_id_free(ike_id);

#ifdef SSH_PM_BLACKLIST_DENY_DUPLICATE_IKE_ID_ENTRIES
          /* Set proper error code if duplicate IKE IDs are denied. */
          err = SSH_PM_BLACKLIST_ERROR_DUPLICATE_IKE_ID;
          break;
#endif /* SSH_PM_BLACKLIST_DENY_DUPLICATE_IKE_ID_ENTRIES */
        }
    }

  if (err != SSH_PM_BLACKLIST_OK)
    {
      /* Destroy pending database */
      ssh_adt_destroy(pending_blacklist);

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Blacklist set failed in line %d, %s (%u)",
                    i, ssh_pm_blacklist_error_to_string(err), err);
      return err;
    }
  else
    {
      /* Save pending database. */
      pm->pending_blacklist = pending_blacklist;

      SSH_DEBUG(SSH_D_LOWOK, ("Set done"));
      return SSH_PM_BLACKLIST_OK;
    }
}

/**************************** Get statistics ********************************/

Boolean
ssh_pm_blacklist_get_stats(SshPm pm,
                           SshPmBlacklistStatsCB callback,
                           void *context)
{
#ifdef SSH_IPSEC_STATISTICS
  SshPmBlacklistStatsStruct stats = { 0 };
#endif /* SSH_IPSEC_STATISTICS */

  /* Check argument */
  if (callback == NULL)
    return FALSE;

  SSH_ASSERT(pm != NULL);

#ifdef SSH_IPSEC_STATISTICS
  /* Copy statistics from internal structures to external one. */
  ssh_pm_blacklist_copy_stats(&stats);

  if ((*callback)(pm, &stats, context) == FALSE)
    return FALSE;
#else /* SSH_IPSEC_STATISTICS */
  if ((*callback)(pm, NULL, context) == FALSE)
    return FALSE;
#endif /* SSH_IPSEC_STATISTICS*/

  return TRUE;
}

/************************ Delete IKE and IPsec SAs ***************************/

SshPmBlacklistError
ssh_pm_blacklist_delete_sas_by_ike_id(SshPm pm,
                                      unsigned char *ike_id,
                                      size_t ike_id_len)
{
  SshPmBlacklistError err;
  SshPmSecretEncoding id_encoding;
  SshPmIdentityType id_type;
  unsigned char *id_data;
  SshIkev2PayloadID id;

  /* Check arguments */
  if (ike_id == NULL || ike_id_len == 0)
    return SSH_PM_BLACKLIST_ERROR_INVALID_ARGUMENT;

  SSH_ASSERT(pm != NULL);

  /* Parse remote IKE ID. */
  err = ssh_pm_blacklist_parse_config_line(&ike_id,
                                           &ike_id_len,
                                           &id_encoding,
                                           &id_type,
                                           &id_data);
  if (err != SSH_PM_BLACKLIST_OK)
    goto out;

  /* Check if IKE ID contains something extra */
  if (ike_id_len > 0)
    {
      ssh_free(id_data);
      err = SSH_PM_BLACKLIST_ERROR_INVALID_ARGUMENT;
      SSH_DEBUG(SSH_D_FAIL, ("Extra characters found after IKE ID"));
      goto out;
    }

  /* Decode IKE ID and free memory allocated during parse phase. */
  err = ssh_pm_blacklist_decode_ike_id(id_encoding, id_type, id_data, &id);
  ssh_free(id_data);
  if (err != SSH_PM_BLACKLIST_OK)
    goto out;

  /* Delete all IKE and IPsec SA associated with a particular remote IKE ID.
     By default delete notifications are sent to other end if matching remote
     IKE ID is found. It is possible to change this behavior by passing
     SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION value in third argument. This
     prevents sending of delete notifications. */
  ssh_pm_delete_by_remote_id(pm, id, 0);

  /* Free memory allocated for IKE ID. */
  ssh_pm_ikev2_payload_id_free(id);

 out:

  return err;
}

/************************ Blacklist database dump ***************************/

static Boolean
ssh_pm_blacklist_is_esc_chars_needed(unsigned char *buf,
                                     size_t check_len)
{
  int i;

  /* Check if escape characters has to be added. */
  for (i = 0; i < check_len; i++)
    {
      if (buf[i] == '"' || buf[i] == '\\')
        return TRUE;
    }

  return FALSE;
}

static Boolean
ssh_pm_blacklist_add_esc_chars_to_str(unsigned char *buf,
                                      SshBuffer new_buffer)
{
  unsigned char tmp_char = '\\';
  int i;

  /* Copy starting character */
  if (ssh_buffer_append(new_buffer, &buf[0], 1) == SSH_BUFFER_ERROR)
    goto error;

  /* Copy buffer content and add escape characters */
  for (i = 1; buf[i] != '\0'; i++)
    {
      if ((buf[i] == '"' || buf[i] == '\\') && buf[i + 1] != '\0')
        {
          if (ssh_buffer_append(new_buffer, &tmp_char, 1) == SSH_BUFFER_ERROR)
            goto error;
        }

      if (ssh_buffer_append(new_buffer, &buf[i], 1) == SSH_BUFFER_ERROR)
        goto error;
    }

  /* Add termination character */
  tmp_char = '\0';
  if (ssh_buffer_append(new_buffer, &tmp_char, 1) == SSH_BUFFER_ERROR)
    goto error;

  return TRUE;

 error:

  return FALSE;
}

static int
ssh_pm_blacklist_id_data_hex_to_str(unsigned char *buf,
                                    int buf_len,
                                    unsigned char *data,
                                    size_t data_len)
{
  size_t cnt = 0;
  int i;

  for(i = 0; i < data_len; i++)
    {
      if (cnt >= buf_len)
        return cnt;
      buf[cnt++] = "0123456789abcdef"[data[i] >> 4];
      if (cnt >= buf_len)
        return cnt;
      buf[cnt++] = "0123456789abcdef"[data[i] & 0xf];
    }
  return cnt;
}

static unsigned char *
ssh_pm_blacklist_ike_id_to_str(SshPmBlacklist entry)
{
  const size_t buf_len = SSH_PM_BLACKLIST_MAX_ID_DATA_LEN + 1;
  unsigned char *buf;
  SshIkev2PayloadID ike_id;
  Boolean do_esc_chars_check;
  int cnt = 0;

  SSH_ASSERT(entry != NULL);

  /* Allocate memory for data buffer */
  buf = ssh_malloc(buf_len);
  if (buf == NULL)
    return NULL;

  /* Put ending character in place. */
  buf[0] = '\0';

  /* Get IKE ID from entry */
  ike_id = entry->ike_id;

  /* Check if encoding is hex */
  if (entry->id_encoding == SSH_PM_HEX)
    {
      /* Hex string starts with "0x" */
      buf[cnt++] = '0';
      buf[cnt++] = 'x';

      /* Convert data to string. */
      cnt += ssh_pm_blacklist_id_data_hex_to_str(buf + cnt,
                                                 buf_len - cnt - 1,
                                                 ike_id->id_data,
                                                 ike_id->id_data_size);
      /* Put ending character */
      buf[cnt] = '\0';

      return buf;
    }

  /* Encoding type is binary */

  /* By default do this check */
  do_esc_chars_check = TRUE;

  switch (ike_id->id_type)
    {
    case SSH_IKEV2_ID_TYPE_KEY_ID:
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      {
        char *name = ssh_malloc(ike_id->id_data_size + 1);
        if (name)
          {
            memcpy(name, ike_id->id_data, ike_id->id_data_size);
            name[ike_id->id_data_size] = '\0';
            cnt = ssh_snprintf(buf,
                               buf_len,
                               "\"%s\"",
                               ike_id->id_data);
            ssh_free(name);
          }
        break;
      }
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      cnt = ssh_snprintf(buf,
                         buf_len,
                         "\"%@\"",
                         ssh_ipaddr4_uint32_render,
                         (void *) (size_t) SSH_GET_32BIT(ike_id->id_data));
      do_esc_chars_check = FALSE;
      break;

    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      cnt = ssh_snprintf(buf,
                         buf_len,
                         "\"%@\"",
                         ssh_ipaddr6_byte16_render,
                         ike_id->id_data);
      do_esc_chars_check = FALSE;
      break;

#ifdef SSHDIST_CERT
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
      {
        SshDNStruct dn[1];
        char *name;

        ssh_dn_init(dn);
        if (ssh_dn_decode_der(ike_id->id_data, ike_id->id_data_size, dn, NULL))
          {
            if (ssh_dn_encode_ldap(dn, &name))
              {
                cnt = ssh_snprintf(buf, buf_len, "\"%s\"", name);
                ssh_free(name);
              }
          }
        ssh_dn_clear(dn);
        do_esc_chars_check = FALSE;
        break;
      }
#endif /* SSHDIST_CERT */
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
      {
        char *name;

        name = ssh_pm_mscapi_dn_to_str(id);
        if (name)
          {
            cnt = ssh_snprintf(buf, buf_len, "\"%s\"", name);
            ssh_free(name);
          }
        do_esc_chars_check = FALSE;
        break;
      }
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
    default:

      SSH_DEBUG(SSH_D_FAIL, ("Unknown IKE ID type found from database"));
      do_esc_chars_check = FALSE;
      break;
    }

  if (cnt)
    {
      /* Check if escape character check has to be done.
         Please note that buffer pointer is incremented by one and count is
         increment by two because string already contains starting and ending
         '"' characters. */
      if (do_esc_chars_check &&
          ssh_pm_blacklist_is_esc_chars_needed(buf + 1, cnt - 2))
        {
          SshBufferStruct new_buffer[1];

          /* Init buffer */
          ssh_buffer_init(new_buffer);

          /* Add escape characters */
          if (ssh_pm_blacklist_add_esc_chars_to_str(buf, new_buffer) == TRUE)
            {
              /* Successful case free old buffer and
                 switch pointer to new one. */
              ssh_free(buf);
              buf = ssh_buffer_steal(new_buffer, NULL);
            }
          else
            {
              /* Failure case free buffer and nullify it. */
              ssh_free(buf);
              buf = NULL;
            }

          /* Uninit buffer */
          ssh_buffer_uninit(new_buffer);
        }
    }

  return buf;
}

Boolean
ssh_pm_blacklist_foreach_ike_id(SshPm pm,
                                SshPmBlacklistIkeIdInfoCB callback,
                                void *context)
{
  SshPmBlacklistIkeIdInfoStruct info = { 0 };
  unsigned char *data;
  SshPmBlacklist entry;
  SshADTHandle handle;
  Boolean ret = TRUE;

  /* Check argument */
  if (callback == NULL)
    return FALSE;

  SSH_ASSERT(pm != NULL);

  /* Iterate through the database */
  for (handle = ssh_adt_enumerate_start(pm->active_blacklist);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->active_blacklist, handle))
    {
      entry = ssh_adt_get(pm->active_blacklist, handle);
      SSH_ASSERT(entry != NULL);

      /* Get type */
      info.type =
        ssh_pm_blacklist_ikev2_id_type_to_string(entry->ike_id->id_type);

      /* Get data */
      data = ssh_pm_blacklist_ike_id_to_str(entry);
      info.data = data;
      if (data == NULL)
        {
          /* Call with NULL to indicate that iteration doesn't continue. */
          (*callback)(pm, NULL, context);

          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Blacklist foreach ike id failed, out of memory");
          ret = FALSE;
          goto out;
        }

#ifdef SSH_IPSEC_STATISTICS
      /* Copy statistics counter */
      info.stat_blocked = entry->stat_blocked;
#endif /* SSH_IPSEC_STATISTICS */

      /* Pass IKE ID information and free buffer */
      ret = (*callback)(pm, &info, context);
      ssh_free(data);
      if (ret == FALSE)
        {
          /* In failure case cancel iteration immediately. */
          ret = FALSE;
          goto out;
        }
    }

  /* Call with NULL to indicate that iteration is completed. */
  if ((*callback)(pm, NULL, context) == FALSE)
    return FALSE;

 out:

  return ret;
}

static Boolean
ssh_pm_blacklist_dump_cb(SshPm pm,
                         SshPmBlacklistIkeIdInfo info,
                         void *context)
{
  SshBuffer buffer = (SshBuffer) context;
  unsigned char tmp_char;
  SshBufferStatus status;

  SSH_ASSERT(pm != NULL);
  SSH_ASSERT(context != NULL);

  /* Check if iteration has ended */
  if (info == NULL)
    {
      /* Append termination character */
      tmp_char = '\0';
      status = ssh_buffer_append(buffer, &tmp_char, 1);
      if (status == SSH_BUFFER_ERROR)
        return FALSE;

      /* Termination character should not be included to the length of the
         buffer. Therefore adjust buffer length by -1. */
      ssh_buffer_consume_end(buffer, 1);
      return TRUE;
    }

  /* Append type, data and other character */
  status = ssh_buffer_append(buffer, info->type, ssh_ustrlen(info->type));
  if (status == SSH_BUFFER_ERROR)
    return FALSE;

  tmp_char = '\t';
  status = ssh_buffer_append(buffer, &tmp_char, 1);
  if (status == SSH_BUFFER_ERROR)
    return FALSE;

  status = ssh_buffer_append(buffer, info->data, ssh_ustrlen(info->data));
  if (status == SSH_BUFFER_ERROR)
    return FALSE;

  tmp_char = '\n';
  status = ssh_buffer_append(buffer, &tmp_char, 1);
  if (status == SSH_BUFFER_ERROR)
    return FALSE;

  return TRUE;
}

Boolean
ssh_pm_blacklist_dump(SshPm pm,
                      unsigned char **content,
                      size_t *content_len)
{
  SshBufferStruct buffer[1];
  Boolean ret;

  SSH_ASSERT(pm != NULL);
  SSH_ASSERT(content != NULL);
  SSH_ASSERT(content_len != NULL);

  /* Init buffer */
  ssh_buffer_init(buffer);

  /* Dump content to the buffer by iterating through the database. */
  ret = ssh_pm_blacklist_foreach_ike_id(pm, ssh_pm_blacklist_dump_cb, &buffer);
  if (ret == TRUE)
    {
      /* Get return values from buffer. */
      *content_len = ssh_buffer_len(buffer);
      *content = ssh_buffer_steal(buffer, NULL);
      if (*content == NULL)
        {
          *content_len = 0;
          ret = FALSE;
        }
    }
  else
    {
      *content = NULL;
      *content_len = 0;
    }

  /* Uninit buffer before return. */
  ssh_buffer_uninit(buffer);

  return ret;
}

#endif /* SSH_PM_BLACKLIST_ENABLED */
