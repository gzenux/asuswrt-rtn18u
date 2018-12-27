/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The classic producer-consumer example with FSM.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshfsm.h"

/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(producer);
SSH_FSM_STEP(consumer);

/***************************** Static variables *****************************/

#define QUEUE_SIZE 10

static SshUInt32 queue[QUEUE_SIZE];
static SshUInt32 head = 0;
static SshUInt32 tail = 0;

static SshFSMConditionStruct space_cond;
static SshFSMConditionStruct data_cond;

#define QUEUE_EMPTY() (head == tail)
#define QUEUE_FULL() ((head + 1) % QUEUE_SIZE == tail)

#define QUEUE_ENQUEUE(item)     \
do                              \
  {                             \
    queue[head++] = item;       \
    head %= QUEUE_SIZE;         \
  }                             \
while (0)

#define QUEUE_DEQUEUE(item)     \
do                              \
  {                             \
    item = queue[tail++];       \
    tail %= QUEUE_SIZE;         \
  }                             \
while (0)


/***************************** State functions ******************************/

SSH_FSM_STEP(producer)
{
  SshUInt32 id = (SshUInt32) thread_context;

  if (QUEUE_FULL())
    SSH_FSM_CONDITION_WAIT(&space_cond);

  QUEUE_ENQUEUE(id);
  SSH_FSM_CONDITION_SIGNAL(&data_cond);

  return SSH_FSM_YIELD;
}

SSH_FSM_STEP(consumer)
{
  SshUInt32 id = (SshUInt32) thread_context;
  SshUInt32 item;

  if (QUEUE_EMPTY())
    SSH_FSM_CONDITION_WAIT(&data_cond);

  QUEUE_DEQUEUE(item);
  SSH_FSM_CONDITION_SIGNAL(&space_cond);

  printf("Consumer %u: %u\n", (unsigned int) id, (unsigned int) item);

  return SSH_FSM_CONTINUE;
}

/***************************** Global functions *****************************/

int
main(int argc, char *argv[])
{
  SshFSMStruct fsm;
  SshUInt32 num_producers = 0;
  SshUInt32 num_consumers = 0;
  SshUInt32 i;
  SshFSMThread thread;

  ssh_event_loop_initialize();

  ssh_fsm_init(&fsm, NULL);

  if (argc > 1)
    num_producers = atoi(argv[1]);
  if (argc > 2)
    num_consumers = atoi(argv[2]);

  if (num_producers < 1)
    num_producers = 3;
  if (num_consumers < 1)
    num_consumers = 3;

  /* Create consumers. */
  for (i = 0; i < num_consumers; i++)
    {
      thread = ssh_fsm_thread_create(&fsm, consumer, NULL_FNPTR, NULL_FNPTR,
                                     (void *) i);
      if (thread == NULL)
        {
          fprintf(stderr, "Could not create consumer %u\n", (unsigned int) i);
          exit(1);
        }
    }

  /* Create producers. */
  for (i = 0; i < num_producers; i++)
    {
      thread = ssh_fsm_thread_create(&fsm, producer, NULL_FNPTR, NULL_FNPTR,
                                     (void *) i);
      if (thread == NULL)
        {
          fprintf(stderr, "Could not create producer %u\n", (unsigned int) i);
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
