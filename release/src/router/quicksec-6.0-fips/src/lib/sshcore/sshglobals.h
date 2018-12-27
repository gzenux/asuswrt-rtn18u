/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Support for global variables.

   <keywords global variables, variable/global, utility
   functions/variables, utility functions/global variables>

   @internal

   @description
   To use global variables in code you have to do following:

   <CODE>
      old code                     new code

      // Declaration of global variable

      extern int foobar;           SSH_GLOBAL_DECLARE(int, foobar);
                                   #define foobar SSH_GLOBAL_USE(foobar)

      // Definiation of global variable
      int foobar;                  SSH_GLOBAL_DEFINE(int, foobar);

      // Initialization of global variable (this must be inside the
      // init function or similar, all global variables are initialized to
      // zero at the beginning). If SSH_GLOBAL_INIT is not called then
      // first use of variable might print out warning about use of
      // uninitialized global variable (if warnings are enabled).
      // Warning might also be printed out if the SSH_GLOBAL_INIT is called
      // multiple times without calls to ssh_global_reset or
      // ssh_global_uninit + init.


      int foobar = 1;              // this is not allowed

      foobar = 1;                  SSH_GLOBAL_INIT(foobar,1);

      // Using the global variable

      foobar = 1;                  foobar = 1; // i.e no changes
      foobar = foobar++;           foobar = foobar++;
   </CODE>
*/


#ifndef SSHGLOBALS_H
#define SSHGLOBALS_H

/* Flags that can be used with global definitions. */
#define SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK 1

#ifndef SSH_GLOBAL_FLAGS
#define SSH_GLOBAL_FLAGS SSH_GLOBAL_F_VXWORKS_ALLOW_NETTASK
#endif /* SSH_GLOBAL_FLAGS */

#ifndef SSH_GLOBALS_EMULATION

# define SSH_GLOBAL_USE(var) ssh_global_ ## var
# define SSH_GLOBAL_USE_INIT(var) ssh_global_ ## var
# define SSH_GLOBAL_DECLARE(type,var) extern type ssh_global_ ## var
# define SSH_GLOBAL_DEFINE(type,var) type ssh_global_ ## var
# define SSH_GLOBAL_DEFINE_INIT(type,var) type ssh_global_ ## var
# define SSH_GLOBAL_INIT(var,value) (ssh_global_ ## var) = (value)
/* Cannot check that var actually exists, let's return 1 always. */
# define SSH_GLOBAL_CHECK(var) 1

# define SSH_GLOBAL_USE_F(var,f) ssh_global_ ## var
# define SSH_GLOBAL_USE_INIT_F(var,f) ssh_global_ ## var
# define SSH_GLOBAL_DECLARE_F(type,var,f) extern type ssh_global_ ## var
# define SSH_GLOBAL_DEFINE_F(type,var,f) type ssh_global_ ## var
# define SSH_GLOBAL_DEFINE_INIT_F(type,var,f) type ssh_global_ ## var
# define SSH_GLOBAL_INIT_F(var,value,f) (ssh_global_ ## var) = (value)
/* Cannot check that var actually exists, let's return 1 always. */
# define SSH_GLOBAL_CHECK_F(var,f) 1

#else /* SSH_GLOBALS_EMULATION */

# define SSH_GLOBAL_TYPE(var) ssh_global_ ## var ## _type
# define SSH_GLOBAL_USE(var) \
   (*((SSH_GLOBAL_TYPE(var) *) \
      ssh_global_get(#var, sizeof(SSH_GLOBAL_TYPE(var)), \
                     SSH_GLOBAL_FLAGS)))
# define SSH_GLOBAL_USE_INIT(var) \
   (*((SSH_GLOBAL_TYPE(var) *) \
      ssh_global_get_init(#var, sizeof(SSH_GLOBAL_TYPE(var)), \
                          SSH_GLOBAL_FLAGS, \
                          &ssh_global_ ## var ## _initial)))
# define SSH_GLOBAL_DECLARE(type,var) \
  typedef type SSH_GLOBAL_TYPE(var); \
  extern const type ssh_global_ ## var ## _initial
# define SSH_GLOBAL_DEFINE(type,var) \
typedef enum { SSH_GLOBAL_NOT_EMPTY_ ## var } SshGlobalNotEmpty_ ## var
# define SSH_GLOBAL_DEFINE_INIT(type,var) \
SSH_RODATA const type ssh_global_ ## var ## _initial
# define SSH_GLOBAL_INIT(var,value) \
   (ssh_global_init_variable(#var, sizeof(ssh_global_ ## var ## _type), \
    SSH_GLOBAL_FLAGS), (var = value))
# define SSH_GLOBAL_CHECK(var) (ssh_global_check(#var, SSH_GLOBAL_FLAGS))

# define SSH_GLOBAL_TYPE_F(var, f) ssh_global_ ## var ## _type
# define SSH_GLOBAL_USE_F(var, f) \
   (*((SSH_GLOBAL_TYPE_F(var,f) *) \
      ssh_global_get(#var, sizeof(SSH_GLOBAL_TYPE_F(var,f)), f)))
# define SSH_GLOBAL_USE_INIT_F(var, f) \
   (*((SSH_GLOBAL_TYPE_F(var,f) *) \
      ssh_global_get_init(#var, sizeof(SSH_GLOBAL_TYPE_F(var,f)), f, \
                          &ssh_global_ ## var ## _initial)))
# define SSH_GLOBAL_DECLARE_F(type,var,f) \
  typedef type SSH_GLOBAL_TYPE_F(var,f); \
  extern const type ssh_global_ ## var ## _initial
# define SSH_GLOBAL_DEFINE_F(type,var,f) \
typedef enum { SSH_GLOBAL_NOT_EMPTY_ ## var } SshGlobalNotEmpty_ ## var
# define SSH_GLOBAL_DEFINE_INIT_F(type,var,f) \
SSH_RODATA const type ssh_global_ ## var ## _initial
# define SSH_GLOBAL_INIT_F(var,value,f) \
   (ssh_global_init_variable(#var, sizeof(ssh_global_ ## var ## _type), f), \
    (var = value))
# define SSH_GLOBAL_CHECK_F(var,f) (ssh_global_check(#var,f))

#endif /* SSH_GLOBALS_EMULATION */

/** Example code:

  SSH_GLOBAL_DECLARE(int, foobar);
  #define foobar SSH_GLOBAL_USE(foobar)

  SSH_GLOBAL_DEFINE(int, foobar);

  void test(void)
    {
      foobar = 1;
      SSH_GLOBAL_INIT(foobar,2);
      foobar++;
    }

   The code above expands to this code when SSH_GLOBALS_EMULATION is undefined:

   extern int ssh_global_foobar;
   int ssh_global_foobar;

   void test(void)
     {
       ssh_global_foobar = 1;
       (ssh_global_foobar) = ( 2 ) ;
       ssh_global_foobar++;
     }

   And if SSH_GLOBALS_EMULATION is defined then it expands to
   following code:

   typedef int ssh_global_foobar_type;

   ;

   void test(void)
     {
       (*((ssh_global_foobar_type *)
          ssh_global_get("foobar", sizeof(ssh_global_foobar_type)))) = 1;
       (ssh_global_init_variable("foobar", sizeof(ssh_global_foobar_type)),
        (*((ssh_global_foobar_type *)
           ssh_global_get("foobar", sizeof(ssh_global_foobar_type)))) = ( 2 ));
       (*((ssh_global_foobar_type *)
          ssh_global_get("foobar", sizeof(ssh_global_foobar_type))))++;
     }

*/

/** Function that returns pointer to the global variable based on the name of
    the global variable. If the variable is used before it is initialized (i.e
    the ssh_global_init_variable is not called before the first use of the
    ssh_global_get), then ssh_global_get might print out warning, and the value
    of the variable will be all zeros. Note, str is assumed to be constant
    string whose lifetime is unlimited. */
void *ssh_global_get(const char *str, size_t variable_size, int flags);

/** Function that returns pointer to the global variable based on the name of
    the global variable. If the variable is used before it is initialized (i.e
    the ssh_global_init_variable is not called before the first use of the
    ssh_global_get), then ssh_global_get might print out warning, and the value
    of the variable will be all zeros. Note, str is assumed to be constant
    string whose lifetime is unlimited.
    Initializes varaible from given constant buffer when variable is first
    seen. */
void *ssh_global_get_init(const char *str, size_t variable_size,
                          int flags, const void *init);

/** Initialize variable to have value of all zeros. This makes the variable to
    be known to the system, and ssh_global_get will assume not print out
    warnings about use of uninitialized variables. Call this function twice
    will print out warning. This returns always returns 0. Note, str is assumed
    to be constant string whose lifetime is unlimited.*/
int ssh_global_init_variable(const char *str, size_t variable_size, int flags);

/** Initialize global variables system. Calling this will reset all
    global variables to uninitialized state. One UNIX platforms it not
    necessary to call this routine at all. */
void ssh_global_init(void);

/** Uninitialize global variables system. Calling this will reset all global
    variables to uninitialized state, and free all state allocated for the
    global variables. */
void ssh_global_uninit(void);

/** Allow checking if global variable with given name exists. */
Boolean ssh_global_check(const char *str, int flags);

#endif /* SSHGLOBALS_H */
