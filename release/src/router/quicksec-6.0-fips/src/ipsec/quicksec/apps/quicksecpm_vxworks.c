/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The VxWorks entry-point to the quicksecpm program.
*/

#define SSH_ALLOW_SYSTEM_ALLOCATORS
#include "sshincludes.h"
#include "quicksecpm_i.h"
#include "ssheloop.h"
#include "sshglobals.h"
#include "taskVarLib.h"
#ifdef SSH_GLOBALS_EMULATION
#include <wrn/coreip/netinet/vsLib.h>
#endif /* SSH_GLOBALS_EMULATION */
#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS




/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmVxWorks"


/********************** The entry point to the program **********************/

/* prototypes */
int quicksec(void);

/* message logging facility in VxWorks has one big limitation, see
   logMsg() manual page. It could be possible to circumvent that by
   having a ring buffer of messages processed here and pass only pointer
   to logMsg()... */

/* Initialize your file-system here. By default the file-system init
   code is turned off. The IPSec toolkit uses a filesystem only
   for a single purpose. This is to load the IPSec policyfile. On
   VxWorks, the file-system support varies. On Intel x86 architecture,
   VxWorks has support for a simple MS DOS floppy file-system, where
   the policyfiles can be retrieved. Otherwise HTTP is used to get the
   policyfiles from a web-server */
#define SSH_VX_HAVE_FILESYSTEM
#undef SSH_VX_HAVE_FILESYSTEM

#ifdef SSH_VX_HAVE_FILESYSTEM
#include <dosFsLib.h>
BLK_DEV *fdDevCreate(int fdType, int drive, int nBlks, int offset);
DOS_VOL_DESC *ssh_vxworks_dev;
#endif /* SSH_VX_HAVE_FILESYSTEM */

#ifdef HAVE_SIGNAL
/* Helper variable for signal handling */
SSH_GLOBAL_DECLARE(Boolean, do_indicate);
#define do_indicate SSH_GLOBAL_USE(do_indicate)
SSH_GLOBAL_DEFINE(Boolean, do_indicate);
#endif /* HAVE_SIGNAL */

int ssh_init_fs_vxworks(void)
{
#ifdef SSH_VX_HAVE_FILESYSTEM
  struct stat buf;

  ssh_vxworks_dev = dosFsDevInit("/fd0", fdDevCreate(0,0,0,0), NULL);

  if (!ssh_vxworks_dev)
    return 0;

  /* by now the file system should have been initialized */
  cd ("/fd0");

  if (stat("tmp", &buf))
    mkdir("tmp", 0777);
#endif /* SSH_VX_HAVE_FILESYSTEM */

  return 1;
}

void ssh_vxworks_fs_remount_hook(void)
{
#ifdef SSH_VX_HAVE_FILESYSTEM
  dosFsReadyChange(ssh_vxworks_dev);
#endif /* SSH_VX_HAVE_FILESYSTEM */
}

#ifdef HAVE_SIGNAL
/* Signal handlers for policy manager. These are optional and requires that
   VxWorks signal facility is configured (INCLUDE_SIGNALS in configAll.h or
   config.h )*/

/* Signal handler for stopping the policy manager. */
static void ssh_ipm_quit_handler(int sig, void *context)
{
  /* Stop the policy manager */
  ssh_ipm_stop();
}

/* Signal handler for doing the policy reconfiguration. */
static void ssh_ipm_reconfigure_handler(int sig, void *context)
{
  /* Reconfigure the policy manager. */
  do_indicate = TRUE;
  ssh_ipm_reconfigure();
}

/* Signal handler for doing the policy reconfiguration. */
static void ssh_ipm_reconfigure_handler_no_indicate(int sig, void *context)
{
  /* Reconfigure the policy manager. */
  do_indicate = FALSE;
  ssh_ipm_reconfigure();
}

/* Signal handler for re-evaluating all active flows against the
   policy. */
static void ssh_ipm_redo_handler(int sig, void *context)
{
  ssh_ipm_redo_flows();
}








#endif /* HAVE_SIGNAL */

/* the starting point of the IPSec policymanager task */
void ssh_ipsecpm_entry_point(int argc,
                             int argv,
                             int arg2,
                             int arg3,
                             int arg4,
                             int arg5,
                             int arg6,
                             int arg7,
                             int arg8,
                             int arg9)
{
  /* Init policy manager and SSH libraries. */
  ssh_ipm_init();

#ifdef HAVE_SIGNAL
  /* Register signal handlers. */
  ssh_register_signal(SIGINT, ssh_ipm_quit_handler, NULL);
  ssh_register_signal(SIGHUP, ssh_ipm_reconfigure_handler, NULL);
  ssh_register_signal(SIGALRM, ssh_ipm_reconfigure_handler_no_indicate, NULL);
  ssh_register_signal(SIGUSR2, ssh_ipm_redo_handler, NULL);



#endif /* HAVE_SIGNAL */

  /* Call the generic policy manager entry point. */
  ssh_ipm_start(argc, (char **)argv);

  ssh_debug_uninit();

  ssh_global_uninit();

  /* this frees both the argument table and the arguments */
  if (argv)
    free((char *)argv);
}

/* Declare ssh_globals as task variable. */
#ifdef SSH_GLOBALS_EMULATION
extern void *ssh_globals;

void ssh_ipsecpm_entry_point_ge(int arg0,
                                int arg1,
                                int arg2,
                                int arg3,
                                int arg4,
                                int arg5,
                                int arg6,
                                int arg7,
                                int arg8,
                                int vs)
{
  taskVarAdd(taskIdSelf(), (int *)(void *)&ssh_globals);
#ifdef VIRTUAL_STACK
  vsMyStackNumSet(vs);
#endif /* VIRTUAL_STACK */
  ssh_ipsecpm_entry_point(arg0, arg1, arg2, arg3, arg4,
                          arg5, arg6, arg7, arg8, 0);
}
#endif /* SSH_GLOBALS_EMULATION */


/* VxWorks boot line, currently not used */
extern char *sysBootLine;

/* 'str' argument is parsed into arguments for policymanger, if str
 * is NULL, then 'other' field of boot line is taken instead */

int quicksecpm(char *input)
{
  int taskid;
  int stacksize = -1, priority = -1, options = -1;
  char *prog = "quicksecpm ";
  int tblsize = 0, argsize = 0, inputsize = 0, prgsize = 0;
  char *s1;
  char *s2;
  int argc = 0;
  char *argv = NULL;

  /* allocate space for both the table and the arguments */
  if (input)
    inputsize = strlen(input);
  if (prog)
    prgsize = strlen(prog);
  tblsize = ((inputsize >> 1) + 2) * sizeof(char *);
  argsize = prgsize + inputsize + 1;
  argv = calloc(tblsize + argsize, 1);

  if (!argv)
    return 0;

  memcpy(argv + tblsize, prog, prgsize);
  memcpy(argv + tblsize + prgsize, input, inputsize);






  /* Parse args  */
  s1 = argv + tblsize;

  while (1)
    {
      while (*s1 == ' ')
        s1++;
      if (!*s1)
        break;

      s2 = s1;

      while (*s2 != '\0' && *s2 != ' ')
        s2++;

      *((char **)argv + argc) = (char *)s1;
      argc++;

      if (!*s2)
        break;

      *s2 = '\0';
      s2++;
      s1 = s2;
    }

  /* Stack size must be even, QuickSec policymanager "quicksecpm"
     requires about 14K of stack at most, however to be on the safe
     side here we set this to 32K by default, you may monitor the
     stack usage with the VxWorks "checkStack" command */
  if (stacksize == -1)
    stacksize = 32*1024;
  else
    stacksize = ((stacksize+1)/2)*2;

  /* Sshipm priority should be low, by default it is set to 20, where
     0 is the highest and 255 the lowest, higher values cause serious
     problems with applications requiring high priority like the
     netpipe test tool, and lower than tNetTask (50) problems with IKE
     packets */
  if (priority==-1) priority=20;

  /* +floating-point -private-environment +stack-fill +breakable */



  if (options==-1) options=VX_FP_TASK;

#ifdef VIRTUAL_STACK
 {
   char taskName[20];
   ssh_snprintf(taskName, 20, "tIpsec%d", myStackNum);

   taskid = taskSpawn(taskName, priority, options, stacksize,
                      (FUNCPTR)ssh_ipsecpm_entry_point_ge,
                      (int)argc,
                      (int)argv,
                      0, 0, 0, 0, 0, 0, 0, myStackNum);
 }
#else /* VIRTUAL_STACK */
#ifdef SSH_GLOBALS_EMULATION
  taskid = taskSpawn("tIpsec", priority, options, stacksize,
                     (FUNCPTR)ssh_ipsecpm_entry_point_ge,
                     (int)argc,
                     (int)argv,
                     0, 0, 0, 0, 0, 0, 0, 0);
#else /* SSH_GLOBALS_EMULATION */
  taskid = taskSpawn("tIpsec", priority, options, stacksize,
                     (FUNCPTR)ssh_ipsecpm_entry_point,
                     (int)argc,
                     (int)argv,
                     0, 0, 0, 0, 0, 0, 0, 0);
#endif /* SSH_GLOBALS_EMULATION */
#endif /* VIRTUAL_STACK */

  /* log smth if fails */
  if (taskid == ERROR)
    {
      perror("quicksecpm: taskSpawn");
      return 0;
    }
  return taskid;
}


/* Convenience startup function */
int ssh_init_vxworks(const unsigned char *policy)
{
  unsigned char args[512];

  /* Start the IPSec interceptor only, this blocks until the
     interceptor modules, including possible hardware acceleration
     drivers has been initialized */
  quicksec();

#ifdef SSH_VX_HAVE_FILESYSTEM
  {
    static int fs_inited = 0;
    if (!fs_inited)
      {
        ssh_init_fs_vxworks();
        fs_inited = 1;
      }

    /* Start the QuickSec, with some default parameters */
    ssh_snprintf(args, 512, "-i -f %s -D *=1 -n 0",
               policy != NULL ? policy : ssh_custr("sshqsec.xml"));
  }
#else /* SSH_VX_HAVE_FILESYSTEM */
  /* On PowerPC and possibly all other diskless systems we retrieve
     the policyfile(s) using a HTTP web server. Start with global
     debug level 1 (display errors) and IKE logging level 0 */
  ssh_snprintf(args, 512,
               "-i -f %s "
#ifdef ENABLE_EXTERNALKEY_HIFN_HSP
               /* If an accelerator card capable of asymmetric encryption
                  (modexp) is present start with the accelerator parameters */
               "--accel-type=genacc --accel-init-info=name(hifn-hsp) "
#endif /* ENABLE_EXTERNALKEY_HIFN_HSP */
               "-D *=1 -n 0",
               policy != NULL ?
               policy : ssh_custr("http://172.30.4.89/sshqsec.xml"));
#endif /* SSH_VX_HAVE_FILESYSTEM */

  quicksecpm(args);
  return 0;
}


/********************* Callbacks from the generic code **********************/

Boolean
ssh_ipm_make_service(void)
{
  return FALSE;
}


void
ssh_ipm_report_state(SshIpmState state)
{
  /* Nothing here. */
}
















#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */
