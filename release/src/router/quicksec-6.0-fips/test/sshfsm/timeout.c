/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple asynchronous call with FSM.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfsm.h"

#define SSH_DEBUG_MODULE "timeout"

/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(order_timeout);
SSH_FSM_STEP(after_timeout);

/***************************** Static variables *****************************/

SshUInt32 timeout = 2;

/************************** Static help functions ***************************/

static void
timeout_cb(void *context)
{
  SshFSMThread thread = context;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/***************************** State functions ******************************/

SSH_FSM_STEP(order_timeout)
{
  printf("Sleeping for %u seconds...\n", (unsigned int) timeout);
  SSH_FSM_SET_NEXT(after_timeout);
  SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(timeout, 0, timeout_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(after_timeout)
{
  printf("Ring, ring!  Wake up!\n");
  return SSH_FSM_FINISH;
}

/***************************** Global functions *****************************/

int
main(int argc, char *argv[])
{
  SshFSMStruct fsm;
  SshFSMThreadStruct thread;

  ssh_event_loop_initialize();

  /* Initialize a new FSM with NULL context data. */
  ssh_fsm_init(&fsm, NULL);

  if (argc > 1)
    timeout = atoi(argv[1]);

  /* Start a thread. */
  ssh_fsm_thread_init(&fsm, &thread, order_timeout, NULL_FNPTR, NULL_FNPTR,
                      NULL);

  /* Start event loop. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_fsm_uninit(&fsm);
  ssh_event_loop_uninitialize();

  return 0;
}
