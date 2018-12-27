/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Support for writing a debug trace into persistent storage.
*/

#ifndef SSH_DEBUG_TRACE_H
#define SSH_DEBUG_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for debug trace object */
typedef struct SshDebugTraceRec *SshDebugTrace;

#ifdef DEBUG_LIGHT

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_debug_trace_create()

  Creates a debug trace object for storing diagnostic messages into a
  permanent storage (e.g. text file or system registry).
  
  Arguments:
  reg_path - 2nd argument to DriverEntry(), i.e. registry path to driver
             config under HKLM, as a UNICODE string.
  
  Returns:
  Pointer to created debug trace object or NULL if an error occurred.
  ------------------------------------------------------------------------*/
SshDebugTrace
ssh_debug_trace_create(PUNICODE_STRING reg_path);

/*-------------------------------------------------------------------------
  ssh_debug_trace_destroy()
  
  Destroys a previously created debug trace object.
  
  Arguments:

  debug_trace - debug trace object to be destroyed.
  
  Returns:
  -
  ------------------------------------------------------------------------*/
void
ssh_debug_trace_destroy(SshDebugTrace debug_trace);

/*-------------------------------------------------------------------------
  ssh_debug_trace()
  
  Adds a new string to debug trace. 
  
  Arguments:
  debug_trace - pointer to debug trace object
  msg         - message string
  
  Returns:
  -  
  ------------------------------------------------------------------------*/
void
ssh_debug_trace(SshDebugTrace debug_trace,
                const unsigned char *msg);


#else /* DEBUG_LIGHT */

#define ssh_debug_trace_create(reg_path) 
#define ssh_debug_trace_destroy(trace)
#define ssh_debug_trace_flush(trace) 
#define ssh_debug_trace(trace,msg) 

#endif /* DEBUG_LIGHT */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_DEBUG_TRACE_H */
