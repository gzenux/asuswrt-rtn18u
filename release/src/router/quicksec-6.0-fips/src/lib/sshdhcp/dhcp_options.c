/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"

#define SSH_DEBUG_MODULE "SshDHCPOptions"

/* Magic cookie from RFC 2132 */
static const unsigned char magic_cookie[4]  = { 99, 130, 83, 99 };

/*****************************************************************************

                           DHCP Option encoding

 *****************************************************************************/

/* Put the magic cookie. This must presede all options. */

void ssh_dhcp_option_put_cookie(SshDHCPMessage message)
{
  SSH_ASSERT(message != NULL);

  memcpy(message->options, magic_cookie, 4);
  message->options_len = 4;
}

/* Put new option to the DHCP options. The order of the option data in
   the options buffer will be {option code, option length, option
   data} as defined by the protocol. */
void ssh_dhcp_option_put(SshDHCPMessage message,
                         SshDHCPOption option,
                         size_t len, unsigned char *data)
{
  int i;

  if (!message)
    return;

  i = message->options_len;
  if (message->options_end)
    i--;

  if ((option == SSH_DHCP_OPTION_PAD) || (option == SSH_DHCP_OPTION_END))
    len = 1;

  if ((i + len + 2) > sizeof(message->options))
    return;

  message->options[i] = (char)option;

  if (option != SSH_DHCP_OPTION_PAD && option != SSH_DHCP_OPTION_END)
    {
      message->options[i + 1] = (SshUInt8) len;
      memcpy(&message->options[i + 2], data, len);
      message->options_len += 2 + len;

      if (message->options_end)
        message->options[message->options_len - 1] = SSH_DHCP_OPTION_END;
    }
  else
    {
      /* PAD and END are fixed in length */
      message->options_len += 1;
    }
}

/* Adds buffers `options' of length `options_len' to the message's
   options. The `options' must be already a encoded buffer containing
   the DHCP options and their parameters. The `options' must no
   include the SSH_DHCP_OPTION_END option. */

void ssh_dhcp_options_put(SshDHCPMessage message,
                          unsigned char *options, size_t options_len)
{
  int i;

  SSH_ASSERT(message != NULL);

  i = message->options_len;
  if (message->options_end)
    i--;

  if (i + options_len > sizeof(message->options))
    return;

  memcpy(message->options + i, options, options_len);
  message->options_len += options_len;

  if (message->options_end)
    message->options[message->options_len - 1] = SSH_DHCP_OPTION_END;
}

/* Add variable amount of parameters to be requested from the DHCP server.
   The caller may request various session parameters from the server by
   setting the preferred options using this function. The options will
   be added as parameters request list into the DHCP packet. The variable
   arguments are SshDHCPOption and is terminated by SSH_DHCP_OPTION_END.
   These options will be added as parameter request list into the DHCP
   packet. This function is called before running the DHCP session. If
   this is not called then the library use some default options that
   suites for normal DHCP sessions. */

Boolean ssh_dhcp_option_put_params(SshDHCPInformation info, ...)
{
  va_list va;
  unsigned char option;

  SSH_ASSERT(info != NULL);

  va_start(va, info);

  if (info->params == NULL)
    {
      info->params = ssh_buffer_allocate();
      if (info->params == NULL)
        {
          va_end(va);
          return FALSE;
        }
    }

  option = (unsigned char)va_arg(va, int);
  while (option != SSH_DHCP_OPTION_END)
    {
      if (ssh_buffer_append(info->params, &option, 1) != SSH_BUFFER_OK)
        {
          va_end(va);
          return FALSE;
        }
      option = (unsigned char)va_arg(va, int);
    }

  va_end(va);
  return TRUE;
}

/* Explicitly sets `message_type' as the packet's message type. If the type
   is already set, this will replace the old type. */

void ssh_dhcp_option_set_message_type(SshDHCPMessage message,
                                      unsigned char message_type)
{
  unsigned char *cp, *end, *opt;

  if (!ssh_dhcp_option_get(message, SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
                           NULL, 0, NULL))
    {
      ssh_dhcp_option_put(message, SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
                          1, &message_type);
      return;
    }

  /* Replace old type */

  cp = message->options + 4;    /* + 4 ignores cookie */
  end = cp + (message->options_len - 4);

  while ((cp < end) && (*cp != SSH_DHCP_OPTION_END)) {
    opt = cp++;

    if (*cp == SSH_DHCP_OPTION_PAD)
      continue;

    /* Skip option and its length */
    cp += *cp + 1;

    if (*opt == SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE)
      {
        cp = opt + 2;
        *cp = message_type;
        return;
      }
  }
}

/*****************************************************************************

                           DHCP Option decoding

 *****************************************************************************/

/* Returns TRUE if cookie is correct */

Boolean ssh_dhcp_option_check_cookie(SshDHCPMessage message)
{
  SSH_DEBUG(9, ("ssh_dhcp_option_check_cookie"));
  if (memcmp(message->options, magic_cookie, 4) == 0)
    return TRUE;

  return FALSE;
}

/* Returns TRUE and the option data if it exists. Same options that
   were encoded can be attempted to decode. Return FALSE if such
   option does not exist in the packet. If data exists it and its
   length are returned. Note, that `data' must have already memory
   allocated for the option content. */

Boolean
ssh_dhcp_option_get(SshDHCPMessage message, SshDHCPOption option,
                    unsigned char *data, size_t data_len, size_t *ret_len)
{
  unsigned char *cp, *end, *opt;
  size_t optlen;

  if (message->options_len < 4)
    return FALSE;

  cp = message->options + 4;    /* + 4 ignores cookie */
  end = cp + (message->options_len - 4);

  while ((cp < end) && (*cp != SSH_DHCP_OPTION_END))
    {
      opt = cp++;

      if (*cp == SSH_DHCP_OPTION_PAD)
        continue;

      /* Skip option and its length */
      cp += *cp + 1;

      if (*opt == (unsigned char)option)
        {
          cp = opt + 1;
          optlen = (size_t) *cp;

          if (data)
            {
              if (optlen <= data_len)
                memcpy(data, cp + 1, optlen);
              else
                return FALSE;
            }
          if (ret_len) *ret_len = optlen;
          return TRUE;
        }
    }

  return FALSE;
}

Boolean ssh_dhcp_option_check(SshDHCPMessage message, SshDHCPOption option)
{
  return ssh_dhcp_option_get(message, option, NULL, 0, NULL);
}

/* Removes the specified option from the DHCP message. If it option does
   not exist this returns FALSE. */

Boolean ssh_dhcp_option_remove(SshDHCPMessage message, SshDHCPOption option)
{
  unsigned char *cp, *end, *opt;

  if (ssh_dhcp_option_get(message, option, NULL, 0, NULL) == FALSE)
    return FALSE;

  /* Remove the option */
  cp = message->options + 4;    /* + 4 ignores cookie */
  end = cp + (message->options_len - 4);

  while ((cp < end) && (*cp != SSH_DHCP_OPTION_END))
    {
      opt = cp++;

      if (*cp == SSH_DHCP_OPTION_PAD)
        continue;

      /* Skip option and its length */
      cp += *cp + 1;

      if (*opt == (unsigned char)option)
        {
          cp = opt + 1;
          memmove(opt, opt + 2 + (*cp), (end - (opt + 2 + (*cp))));

          break;
        }
    }

  return TRUE;
}

/* Get the requested parameter. This function may be used to get the
   requested parameters that has been received from the server. Note that
   the server may not return the paramters that was requested using
   ssh_dhcp_option_put_params. This function returns TRUE and the data
   associated to the parameter if it was returned by the server and FALSE
   otherwise. Note that `data' must have already memory allocated for the
   data. The `option' is the option that is being searched from the
   returned parameters. */

SshDHCPStatus ssh_dhcp_option_get_param(SshDHCPInformation info,
                                        SshDHCPOption option, size_t *ret_len,
                                        unsigned char *data, size_t data_len)
{
  unsigned char *cp, *end, *opt;
  size_t len;

  if (info->params == NULL)
    return SSH_DHCP_STATUS_ERROR;

  cp = ssh_buffer_ptr(info->params) + 4;
  end = cp + (ssh_buffer_len(info->params) - 4);

  while (cp < end && *cp != SSH_DHCP_OPTION_END) {
    opt = cp++;

    if (*cp == SSH_DHCP_OPTION_PAD)
      continue;

    /* Skip option and its length */
    cp += *cp + 1;

    if (*opt == (unsigned char)option)
      {
        cp = opt + 1;
        len = (size_t)*cp;

        if (len > data_len)
          len = data_len;

        if (ret_len)
          *ret_len = len;

        if (data)
          memcpy(data, cp + 1, len);

        return SSH_DHCP_STATUS_OK;
      }
  }

  return SSH_DHCP_STATUS_OK;
}
