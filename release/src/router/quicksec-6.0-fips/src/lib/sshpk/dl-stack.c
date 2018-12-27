/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Stack Utility Functions
*/

#include "sshincludes.h"
#ifdef SSHDIST_CRYPT_DL
#include "sshmp.h"
#include "dl-stack.h"

/* Crypto Stack implementation. */

void ssh_cstack_push(SshCStack *head, void *thisp)
{
  SshCStack stack = thisp;

  stack->next = *head;
  *head = stack;
}

unsigned int ssh_cstack_count(SshCStack *head, SshCStackToken token)
{
  SshCStack temp;
  unsigned int count;

  for (temp = *head, count = 0; temp; temp = temp->next)
    if (temp->token == token)
      count++;
  return count;
}

SshCStack ssh_cstack_pop(SshCStack *head, SshCStackToken token)
{
  SshCStack temp, prev;

  temp = *head;
  prev = NULL;
  while (temp)
    {
      /* Compare */
      if (temp->token == token)
        {
          /* Remove from list (our stack). */
          if (prev)
            prev->next = temp->next;
          else
            *head = temp->next;
          temp->next = NULL;
          break;
        }
      prev = temp;
      temp = temp->next;
    }

  /* Return either NULL or valid stack entry. */
  return temp;
}

/* Free any stack element or stack itself! */
void *ssh_cstack_free(void *head)
{
  SshCStack temp, temp2;

  temp = head;
  while (temp)
    {
      temp2 = temp->next;
      /* Free. */
      (*temp->destructor)(temp);
      temp = temp2;
    }

  /* Tell upper-layer that all were freed successfully. */
  return NULL;
}

/* Allocation and deletion of stack elements. */

/* Randomizer */

SSH_CSTACK_DESTRUCTOR_BEGIN( SshDLStackRandomizer, stack )
     ssh_mprz_clear(&stack->k);
     ssh_mprz_clear(&stack->gk);
SSH_CSTACK_DESTRUCTOR_END( SshDLStackRandomizer, stack )

SSH_CSTACK_CONSTRUCTOR_BEGIN( SshDLStackRandomizer, stack, context,
                              SSH_DLP_STACK_RANDOMIZER )
     ssh_mprz_init(&stack->k);
     ssh_mprz_init(&stack->gk);
SSH_CSTACK_CONSTRUCTOR_END( SshDLStackRandomizer, stack )

#endif /* SSHDIST_CRYPT_DL */
