/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The `Hello, world!' application with FSM.
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
  SshFSM fsm;
  SshFSMThread thread;

  ssh_event_loop_initialize();

  /* Create a new FSM with NULL context data. */
  fsm = ssh_fsm_create(NULL);
  if (fsm == NULL)
    {
      fprintf(stderr, "Could not create FSM\n");
      goto error;
    }

  /* Start a thread.  The context data is the greeting to display to
     the user. */
  thread = ssh_fsm_thread_create(fsm, hello, NULL_FNPTR, NULL_FNPTR,
                                 "Hello, world!");
  if (thread == NULL)
    {
      fprintf(stderr, "Could not start thread\n");
      goto error;
    }

  /* Start event loop. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_fsm_destroy(fsm);
  ssh_event_loop_uninitialize();

  return 0;

  /* Error handling. */

 error:
  if (fsm)
    ssh_fsm_destroy(fsm);

  ssh_event_loop_uninitialize();

  return 1;
}
