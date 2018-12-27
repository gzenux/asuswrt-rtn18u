/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The SSH_FSM_YIELD return value.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshfsm.h"

SSH_FSM_STEP(print)
{
  char *name = (char *) thread_context;

  printf("%s\n", name);

  return SSH_FSM_YIELD;
}

static void
thread_destructor(SshFSM fsm,void *context)
{
  ssh_xfree(context);
}

int
main(int argc, char *argv[])
{
  SshFSMStruct fsm;
  SshFSMThread thread;
  int count = 0, i;

  ssh_event_loop_initialize();

  ssh_fsm_init(&fsm, NULL);

  if (argc > 1)
    count = atoi(argv[1]);
  if (count < 1)
    count = 2;

  /* Create threads. */
  for (i = 0; i < count; i++)
    {
      char buf[64];

      /* Create thread context data. */
      ssh_snprintf(buf, sizeof(buf), "Thread %d", i);

      /* Start thread. */
      thread = ssh_fsm_thread_create(&fsm, print, NULL_FNPTR,
                                     thread_destructor, ssh_xstrdup(buf));
      if (thread == NULL)
        {
          fprintf(stderr, "Could not create thread %d\n", i);
          exit(1);
        }
    }

  /* Start the event loop. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_fsm_uninit(&fsm);
  ssh_event_loop_uninitialize();

  return 0;
}
