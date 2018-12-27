/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Stack Internal Header
*/

#ifndef DL_STACK_H
#define DL_STACK_H

/* Crypto Stack for DL family functions. */
typedef unsigned int SshCStackToken;
typedef struct SshCStackRec
{
  SshCStackToken token;
  struct SshCStackRec *next;
  void (*destructor)(struct SshCStackRec *thisp);
} *SshCStack, SshCStackStruct;

/*
   Macros to make the prefix for the structure.

   SSH_CSTACK_BEGIN( stack )
   char *hello_world;
   SSH_CSTACK_END( stack );
*/

#define SSH_CSTACK_BEGIN(name) \
typedef struct name##Rec  \
{                         \
  SshCStackToken token;   \
  SshCStack next;         \
  void (*destructor)(SshCStack thisp);

#define SSH_CSTACK_END(name) \
} name

/*
   Macros for generating the destructor code for prefixes. These are
   called having 'type' some selected type name, which you are willing
   to use.  'name' some variable which you are willing to use. Then

   SSH_CSTACK_DESTRUCTOR_BEGIN( MyType, stack )
     free(stack->hello_world);
   SSH_CSTACK_DESTRUCTOR_END( MyType, stack )
   destroys your MyType structure.
*/

#define SSH_CSTACK_DESTRUCTOR_BEGIN(type, name)                 \
void ssh_cstack_##type##_destructor(SshCStack name##_cstack)    \
{                                                               \
  type *name = (type *)name##_cstack;                           \
  if (name) {                                                   \

#define SSH_CSTACK_DESTRUCTOR_END(type, name)                   \
    ssh_free(name);                                             \
  }                                                             \
}

/*
   Macros for generating the constructor code for prefixes. Generates
   constructor with name e.g.

     MyType *ssh_cstack_MyType_constructor();

   use as

   SSH_CSTACK_CONSTRUCTOR_BEGIN( MyType, stack, context,
                                 MY_TYPE_DISTINCT_TOKEN )
     stack->hello_world = NULL;
   SSH_CSTACK_CONSTRUCTOR_END( MyType, stack )

   Note! if name differs in _BEGIN and _END then compiler will state
   an error.
*/

#define SSH_CSTACK_CONSTRUCTOR_BEGIN(type,stack_name,context_name,t)    \
type *ssh_cstack_##type##_constructor(void *context_name)               \
{                                                                       \
  type *stack_name = ssh_malloc(sizeof(*stack_name));                   \
  if (stack_name) {                                                     \
     stack_name->token = t;                                             \
     stack_name->next = NULL;                                           \
     stack_name->destructor = ssh_cstack_##type##_destructor;           \

#define SSH_CSTACK_CONSTRUCTOR_END(type,stack_name)                     \
  }                                                                     \
  return stack_name;                                                    \
}

/* Push a element (this) into the stack pointed by (head). */
void ssh_cstack_push(SshCStack *head, void *thisp);

/* Pop element with (token) out of the stack. */
SshCStack ssh_cstack_pop(SshCStack *head, SshCStackToken token);

/* Free the full stack. */
void *ssh_cstack_free(void *head);

/* Count number of elements of type token in the stack. */
unsigned int ssh_cstack_count(SshCStack *head, SshCStackToken token);


#define SSH_DLP_STACK_RANDOMIZER  0x1

/* Randomizer */

SSH_CSTACK_BEGIN( SshDLStackRandomizer )
  SshMPIntegerStruct k;
  SshMPIntegerStruct gk;
SSH_CSTACK_END( SshDLStackRandomizer );

#endif /* DL_STACK_H */
