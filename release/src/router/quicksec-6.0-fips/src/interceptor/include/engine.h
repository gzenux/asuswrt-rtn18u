/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public interface to the portable code of the engine.  This interface
   is used by the machine-dependent main program that takes care of
   starting and stopping the engine (e.g., loading and unloading it
   into the kernel, or starting/stopping it as a service or daemon).
*/

#ifndef ENGINE_H
#define ENGINE_H

/******************************** Data types ********************************/

/* Definition of the type for the engine object. */
typedef struct SshEngineRec *SshEngine;

/* A function of this type is used to send messages from the engine to
   the policy manager.  The function should return TRUE if the message
   was actually sent, and FALSE otherwise.  This should always
   eventually free `data' with ssh_xfree.  The packet in the buffer
   starts with a 32-bit length MSB first.  If the connection to the
   policy manager is not open, this should return FALSE and free
   `data' using ssh_xfree.  Warning: this function is called from
   ssh_debug and ssh_warning; thus, this is not allowed to emit
   debugging or warning messages.  This function can be called
   concurrently, and must perform appropriate locking. */
typedef Boolean (*SshEngineSendProc)(unsigned char *data, size_t len,
                                     Boolean reliable,
                                     void *machine_context);

/***************************************************************************
 * Functions called by the machine-dependent main program
 ***************************************************************************/

/* Flags for the ssh_engine_start function. */
#define SSH_ENGINE_DROP_IF_NO_IPM       0x00000001
#define SSH_ENGINE_NO_FORWARDING        0x00000002

/* Creates the engine object.  Among other things, this opens the
   interceptor, initializes filters to default values, and arranges to send
   messages to the policy manager using the send procedure.  The send
   procedure will not be called until from the bottom of the event loop.
   The `machine_context' argument is passed to the interceptor and the
   `send' callback, but is not used otherwise.  This function can be
   called concurrently for different machine contexts, but not otherwise.
   The first packet and interface callbacks may arrive before this has
   returned. */
SshEngine ssh_engine_start(SshEngineSendProc send,
                           void *machine_context,
                           SshUInt32 flags);

/* Stops the engine, closes the interceptor, and destroys the
   engine object.  This does not notify IPM interface of the close;
   that must be done by the caller before calling this.  This returns
   TRUE if the engine was successfully stopped (and the object freed),
   and FALSE if the engine cannot yet be freed because there are
   threads inside the engine or uncancellable callbacks expected to
   arrive.  When this returns FALSE, the engine has started stopping,
   and this should be called again after a while.  This function can
   be called concurrently with packet/interface callbacks or timeouts
   for this engine, or any functions for other engines.*/
Boolean ssh_engine_stop(SshEngine engine);

/* Suspends the engine. This causes engine to flush all the packets
   being held, and unregister all the timeouts related to ongoing
   operations. The engine can be resumed - and will continue with a
   valid state - by calling ssh_engine_resume. Interceptor may not
   send packets to a suspended engine. */
Boolean ssh_engine_suspend(SshEngine engine);

/* Resumes a suspended engine. This causes engine to start to accept
   new packets and to establish state based on these. */
Boolean ssh_engine_resume(SshEngine engine);

/* The machine-specific main program should call this when the policy
   manager has opened the connection to the engine.  This also
   sends the version packet to the policy manager.  This function can
   be called concurrently with packet/interface callbacks or timeouts. */
void ssh_engine_notify_ipm_open(SshEngine engine);

/* This function is called whenever the policy manager closes the
   connection to the engine.  This is also called when the engine is
   stopped.  This function can be called concurrently with
   packet/interface callbacks or timeouts. */
void ssh_engine_notify_ipm_close(SshEngine engine);

/* This function should be called by the machine-dependent main
   program whenever a packet for this engine is received from
   the policy manager.  The data should not contain the 32-bit length
   or the type (they have already been processed at this stage, to
   check for possible machine-specific packets).  The `data' argument
   remains valid until this function returns; it should not be freed
   by this function.  This function can be called concurrently. */
void ssh_engine_packet_from_ipm(SshEngine engine,
                                SshUInt32 type,
                                const unsigned char *data, size_t len);


/**********************************************************************
 * Some internal functions that may be useful for machine-dependent
 * code.
 **********************************************************************/

/* Formats the message, and tries to send it to the policy manager.  This
   returns FALSE if sending the message fails (e.g., the queue is full).
   Every argument list should start with SSH_FORMAT_UINT32, (SshUInt32) 0,
   SSH_FORMAT_CHAR, type.  The first integer will be set to the length
   of the resulting packet.  This function can be called concurrently. */
Boolean ssh_engine_send(SshEngine engine, Boolean locked,
                        Boolean reliable, ...);

/* Sends a debugging message to the policy manager. */
void ssh_engine_send_debug(SshEngine engine, const char *msg);

/* Sends a warning message to the policy manager. */
void ssh_engine_send_warning(SshEngine engine, const char *msg);


/**************** Version global ****************************/

/* This is statically (compile-time) initialized to SSH_ENGINE_VERSION */
extern const char ssh_engine_version[];

/* This is statically (compile-time) initialized to a value containing
   information about the SSH_ENGINE_VERSION, compilation time,
   compiler etc. etc. etc. It can be used by interceptors, usermode
   engine etc. for startup output or somesuch. Debug information,
   basically, and can vary quite much depending on the compilation
   environment. */
extern const char ssh_engine_compile_version[];

/* Suffix to append to the device name.  This is defined by the
   engine. */
extern const char ssh_device_suffix[];

#endif /* ENGINE_H */
