/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode event logging services for Windows NT series packet
   interceptor drivers.
*/

#ifndef SSH_EVENT_LOG_H
#define SSH_EVENT_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  INCLUDES
  --------------------------------------------------------------------------*/

#include "event_log_msg.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_event_log_activate()

  Activates the event logging for the given driver object (i.e. us). This 
  function must be called before any ssh_log_event() calls.

  NOTICE: This functions internally calls ssh_log_register_callback(), so
          you should not call it again.
  --------------------------------------------------------------------------*/

void
ssh_event_log_activate(PDRIVER_OBJECT driver);


#ifdef __cplusplus
}
#endif

#endif /* SSH_EVENT_LOG_H */

