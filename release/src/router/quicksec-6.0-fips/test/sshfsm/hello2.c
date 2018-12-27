/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The `Hello, world!' application without dynamic memory allocation.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshfsm.h"

/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(hello);
SSH_FSM_STEP(world);

/***************************** State functions ******************************/

SSH_FSM_STEP(hello)
{
  char *message = (char *) thread_context;

  printf("%s from the state `hello'\n", message);

  SSH_FSM_SET_NEXT(world);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(world)
{
  char *message = (char *) thread_context;

  printf("%s from the state `world'\n", message);

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

  /* Start a thread.  The context data is the greeting to display to
     the user. */
  ssh_fsm_thread_init(&fsm, &thread, hello, NULL_FNPTR, NULL_FNPTR,
                      "Hello, world!");

  /* Start event loop. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_fsm_uninit(&fsm);
  ssh_event_loop_uninitialize();

  return 0;
}
