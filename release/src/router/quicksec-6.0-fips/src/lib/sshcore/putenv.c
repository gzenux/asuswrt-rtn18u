/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is a replacement function for putenv for systems that do not
   have this function. Putenv adds or changes the value of environment
   variables. The argument 'string' is of the form 'name=value'. If
   'name' does not already exist in the environment, then 'string' is
   added to the environment.  If 'name' does exist, then the value of
   'name' in the environment is changed to 'value'. The string pointed
   to by 'string' becomes part of the environment, so altering the
   string changes the environment. The putenv() function returns zero
   on success, or non-zero if an error occurs.
*/

#include "sshincludes.h"
#include "sshglobals.h"

SSH_GLOBAL_DECLARE(char **, sshenvp);
SSH_GLOBAL_DEFINE_INIT(char **, sshenvp);
#define sshenvp SSH_GLOBAL_USE_INIT(sshenvp)

int putenv(char *string)
{
  extern char **environ;
  char **envp;
  size_t name_len, num_env;

  /* If string is of the form name=value get the length of
     the name substring. */
  if (strchr(string, '=') != NULL)
    name_len = strchr(string, '=') - string;
  else
    name_len = strlen(string);

  num_env = 0;
  /* Lookup 'string' in the current environment */
 for (envp = environ; *envp != NULL; envp++)
   {
     /* 'string' is known and its value is unchanged */
     if (!strcmp(*envp, string))
       return 0;

     /* Check if the 'name' portion of the string matches the current
        environment variable, if so then update the 'value'. */
     if (!strncmp(*envp, string, name_len) && strchr(*envp, '=') &&
         (strchr(*envp, '=') - *envp == name_len))
       {
         *envp = string;
         return 0;
       }

     num_env++;
   }

 /* 'name' is not known, add 'string' to the environment. */
 if (sshenvp == NULL)
   {
     envp = (char **)ssh_malloc((num_env + 2) * sizeof(char *));

     if (envp && num_env)
       memcpy((char *)envp, (char *)environ, num_env * sizeof(*envp));
   }
 else
   {
     envp = (char **)ssh_realloc((char *)sshenvp,
                                 (num_env + 1) * sizeof(char *),
                                 (num_env + 2) * sizeof(char *));
   }

 if (envp == NULL)
   return 1;

 /* Add 'sting', and update environ */
 envp[num_env] = string;
 envp[num_env + 1] = NULL;
 environ = sshenvp = envp;
 return 0;
}
