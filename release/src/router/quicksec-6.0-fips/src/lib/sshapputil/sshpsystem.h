/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The Parse System for Configuration files.
*/

#ifndef PSYSTEM_H
#define PSYSTEM_H

/* Types which are of interest to the developer of configure file
   parser. */

/* Following data types are supported. Note that Hex and Base64 could
   be anything. Thus when data of hex or base64 type is found then it
   is automagically converted into a suitable format. However, the
   callback should take some care in checking input (as always
   naturally).  */
typedef enum
{
  /* Some environment. */
  SSH_PSYSTEM_OBJECT,

  /* These are not always necessary to handle. */
  SSH_PSYSTEM_LIST_OPEN,
  SSH_PSYSTEM_LIST_CLOSE,

  /* Basic operations which must be handled. */
  SSH_PSYSTEM_INIT,
  SSH_PSYSTEM_ERROR,
  SSH_PSYSTEM_FINAL,
  SSH_PSYSTEM_FEED
} SshPSystemEvent;

typedef enum
{
  SSH_PSYSTEM_INTEGER,
  SSH_PSYSTEM_STRING,
  SSH_PSYSTEM_LDAP_DN,
  SSH_PSYSTEM_IP,
  SSH_PSYSTEM_NAME,
  SSH_PSYSTEM_VOID
} SshPSystemType;

/* Definition of a variable. */
typedef struct SshPSystemVarRec
{
  const char *name;
  unsigned int aptype;
  /* The data type of the name. */
  SshPSystemType type;
} *SshPSystemVar, SshPSystemVarStruct;

/* The structure to define a environment. */
typedef struct SshPSystemEnvRec
{
  /* The name of the given environment. */
  const char *name;
  /* Type by which this is known in the handler. */
  unsigned int aptype;

  /* Generic handler for all cases. */
  Boolean (*handler)(SshPSystemEvent event,
                     unsigned int aptype,
                     void *data, size_t data_len,
                     unsigned int list_level,
                     void *context_in, void **context_out);

  /* Define suitable namespaces. It might be easiest at start to just
     use one global list of both. However, later one could build
     hierachial systems with namespaces. */
  struct SshPSystemEnvRec *env_bind;
  SshPSystemVar var_bind;
} *SshPSystemEnv, SshPSystemEnvStruct;

typedef struct SshPSystemDefRec
{
  /* The root. */
  SshPSystemEnv root;
  /* Must be NULL if nothing to feed. */
  void *feeding;

  /* The operators. */

  /* The assignment operator (e.g. "=" or "::=" etc.). */
  char *assign_operator;

  /* The more function. This reads additional information for the
     parser. */
  int (*more)(void *context, unsigned char **buf, size_t *buf_len);
  void *more_context;
} *SshPSystemDef, SshPSystemDefStruct;

/* Just to help us out in writing many handlers. */
#define SSH_PSYSTEM_HANDLER(name) \
Boolean name##_handler(SshPSystemEvent event, \
                       unsigned int aptype,  \
                       void *data, size_t data_len, \
                       unsigned int list_level,  \
                       void *context_in, void **context_out)

#define SSH_PSYSTEM_DATA_TAKEN \
  do { *((Boolean *)context_out) = TRUE; } while(0)

/* Following routines can be used from the callbacks. */

/* Error status table (global). */
typedef enum
{
  SSH_PSYSTEM_OK,
  SSH_PSYSTEM_FAILURE,
  SSH_PSYSTEM_UNKNOWN_LANGUAGE,
  SSH_PSYSTEM_MISPLACED_CLOSE,
  SSH_PSYSTEM_OBJECT_NOT_CREATED,
  SSH_PSYSTEM_ADD_FAILED,
  SSH_PSYSTEM_NO_BIND,
  SSH_PSYSTEM_SAME_NAME_USED,
  SSH_PSYSTEM_NOT_SUPPORTED_NAME,
  SSH_PSYSTEM_NOT_OPERATOR,
  SSH_PSYSTEM_TOKEN_NOT_EXPECTED,
  SSH_PSYSTEM_UNSUPPORTED_TYPE,
  SSH_PSYSTEM_TYPE_DID_NOT_MATCH,
  SSH_PSYSTEM_LIST_MISMATCH,
  SSH_PSYSTEM_UNKNOWN_TYPE,
  SSH_PSYSTEM_TOKEN_STR_EMPTY,
  SSH_PSYSTEM_HANDLER_MISSING,
  SSH_PSYSTEM_COULD_NOT_ADD,
  SSH_PSYSTEM_COULD_NOT_OPEN_LIST,
  SSH_PSYSTEM_COULD_NOT_CLOSE_LIST,
  SSH_PSYSTEM_INIT_FAILED,
  SSH_PSYSTEM_EXPECTED_ASSIGNMENT
  /* etc. */
} SshPSystemStatus;

typedef struct
{
  SshPSystemStatus status;
  unsigned int line, pos;
} *SshPSystemError, SshPSystemErrorStruct;

/* Return a standard error message. */
char *ssh_psystem_error_msg(SshPSystemStatus status);

/* The function which runs the parse system for the selected input. */
void *ssh_psystem_parse(SshPSystemDef def,
                        SshPSystemError error);

typedef enum {
  /* Variable (leaf) node */
  SSH_PSYSTEM_VAR,

  /* Environment */
  SSH_PSYSTEM_ENV,

  /* List */
  SSH_PSYSTEM_LIST
} SshPSystemNodeType;

typedef struct SshPSystemNodeRec
{
  struct SshPSystemNodeRec *parent;
  struct SshPSystemNodeRec *next;

  /* First descendant node */
  struct SshPSystemNodeRec *child;

  /* Name of an environment or variable */
  char* name;

  /* Type of the node */
  SshPSystemNodeType node_type;

  /* Type of a leaf item, not used for environment/list nodes. */
  SshPSystemType var_type;

  /* Describes the leaf data. Pointer must be freed with free_routine. */
  void* data;
  size_t data_len;
  void (*free_routine)(void*, size_t);

  /* This is set when some match operation has found this node */
  Boolean matched;

  /* Error state which occurred when processing this node */
  SshPSystemStatus error;

  /* Source file coordinates of this item, for error messages */
  unsigned int line, column;

  struct SshPSystemNodeRec *first_unmatched_child;
  struct SshPSystemNodeRec *last_child;
} SshPSystemNodeStruct, *SshPSystemNode;

/* Recursively frees a parse node */
void ssh_psystem_free_node(SshPSystemNode);

/* Parse the input into tree format. */
void ssh_psystem_parse_tree(SshPSystemDef def,
                            SshPSystemError error,
                            SshPSystemNode* root);

/* The function ssh_psystem_get_integer looks at children of NODE.
   If there is an integer variable with name VAR, converts the value
   into SshMPInteger type and returns the value and the child node.

   The value is still owned by the node; the caller can take the responsibility
   of freeing the value by setting the data field of *rnode to NULL.
   The same effect is accomplished by prefixing the variable name with '*'.
*/
Boolean ssh_psystem_get_int(SshPSystemNode node, const char* var,
                            SshMPInteger* mp_int,
                            SshPSystemNode* rnode);

/* Matchers for other types work similarly. */
Boolean ssh_psystem_get_string(SshPSystemNode node,
                               const char* var, char** string,
                               SshPSystemNode* rnode);
Boolean ssh_psystem_get_ldap(SshPSystemNode node,
                             const char* var,
                             char** ldap,
                             SshPSystemNode* rnode);
Boolean ssh_psystem_get_ip(SshPSystemNode node,
                           const char* var,
                           unsigned char** buf, size_t* buf_len,
                           SshPSystemNode* rnode);
Boolean ssh_psystem_get_name(SshPSystemNode node,
                             const char* var,
                             char** name,
                             SshPSystemNode* rnode);
Boolean ssh_psystem_get_void(SshPSystemNode node,
                             const char* var,
                             SshPSystemNode* rnode);

/* Matches an environment */
Boolean ssh_psystem_get_env(SshPSystemNode node,
                            const char* env,
                            SshPSystemNode* env_node);
Boolean ssh_psystem_get_list(SshPSystemNode node,
                             const char* env,
                             SshPSystemNode* list_node);

/* Matches the first non-matched node of any type. Calling it again
   returns the second non-matched node, if any. If all nodes have
   been matched, returns SSH_PSYSTEM_NO_MATCH. */
Boolean ssh_psystem_get_any(SshPSystemNode node,
                            SshPSystemNode* rnode);

/* These functions look at a node itself, not its children.
   They see if the node is an environment (or variable) with
   given name. If name is NULL, only test the node type. */
Boolean ssh_psystem_match_env_node(SshPSystemNode node, const char* env);
Boolean ssh_psystem_match_var_node(SshPSystemNode node, const char* var);

/* After all valid variables and environments have been processed,
   the rest are either unmatched or caused type conversion errors.
   This function finds the first such node in children of NODE, if
   there are any. Returns TRUE if error node is found. */
Boolean ssh_psystem_find_error(SshPSystemNode node,
                               SshPSystemNode *error_node,
                               SshPSystemStatus *status);

#if 0
/* An example of a handler, use this if you don't want to figure out
   more suitable format to your application. (And still want to
   use PSystem). */

SSH_PSYSTEM_HANDLER(name)
{
  NameCtx *c;
#if 0
  if (list_level)
    return FALSE;
#endif
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
    case SSH_PSYSTEM_ERROR:
    case SSH_PSYSTEM_FINAL:
    case SSH_PSYSTEM_OBJECT:
      switch (aptype)
        {
        default:
          break;
        }
      break;
    default:
      break;
    }
  return FALSE;
}
#endif

#endif /* PSYSTEM_H */
