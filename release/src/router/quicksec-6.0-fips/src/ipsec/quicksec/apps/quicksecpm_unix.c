/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The Unix entry-point to the quicksecpm program.
*/

#include "sshincludes.h"
#ifndef VXWORKS
#include "quicksecpm_i.h"
#include "ssheloop.h"
#include "ipsec_params.h"
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
#include <sys/ioctl.h>

#include "quicksec_pm.h"
#include "core_pm.h"
#include "sshglobals.h"


SSH_GLOBAL_DECLARE(SshPm, ipm);
#define ipm SSH_GLOBAL_USE(ipm)


/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmUnix"


/***************************** Static variables *****************************/

/* The name of the program. */
static char *program;


/***************************** Static functions *****************************/

/* Signal handler for stopping the policy manager. */
static void
ssh_ipm_quit_handler(int sig, void *context)
{
  static unsigned int num_calls = 0;

  num_calls++;

  if (num_calls > 1)
    {
      if (num_calls == 5)
        exit(1);

      fprintf(stderr,
              "Policy manager is already stopping.  %s %u more time%s "
              "to exit immediately.\n",



              "Hit C-c",

              5 - num_calls,
              5 - num_calls > 1 ? "s" : "");

      return;
    }

  /* Stop the policy manager. */
  ssh_ipm_stop();
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
Boolean do_indicate = TRUE;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
/* Signal handler for doing the policy reconfiguration. */
static void
ssh_ipm_reconfigure_handler(int sig, void *context)
{
  /* Reconfigure the policy manager. */
#ifdef SSHDIST_IPSEC_DNSPOLICY
  do_indicate = TRUE;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  ssh_ipm_reconfigure();
}

/* Signal handler for doing the policy reconfiguration. */
static void
ssh_ipm_reconfigure_handler_no_indicate(int sig, void *context)
{
  /* Reconfigure the policy manager. */
#ifdef SSHDIST_IPSEC_DNSPOLICY
  do_indicate = FALSE;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  ssh_ipm_reconfigure();
}
#ifdef SSHDIST_IPSEC_DNSPOLICY

static void commit_cb(SshPm pm, Boolean success, void *context)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("DNS change committed"));
}

static void indicate_cb(SshPm pm, Boolean success, void *context)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("DNS change indicated"));
  ssh_pm_commit(pm, commit_cb, context);
}

static void
ssh_ipm_reconfigure_indicate_and_commit(int sig, void *context)
{
  ssh_pm_indicate_dns_change(ipm,
                             NULL, NULL,
                             indicate_cb, ipm);
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */
/* Signal handler for SIGPIPE. */
static void
ssh_ipm_pipe_handler(int sig, void *context)
{
  /* Just ignore. */
  SSH_DEBUG(SSH_D_FAIL, ("SIGPIPE received. Ignoring."));
}












/* Signal handler for re-evaluating all active flows against the
   policy. */
static void
ssh_ipm_redo_handler(int sig, void *context)
{
  ssh_ipm_redo_flows();
}


















































/* Event log callback which reports the events to the syslog. */
static void
ssh_pm_syslog_callback(SshLogFacility facility,
                       SshLogSeverity severity,
                       const char *message,
                       void *context)
{
  int sev, fac;

  switch (severity)
    {
    case SSH_LOG_WARNING:
#ifdef LOG_WARNING
      sev = LOG_WARNING;
#else /* LOG_WARNING */
      sev = 0;
#endif /* LOG_WARNING */
      break;

    case SSH_LOG_ERROR:
#ifdef LOG_ERR
      sev = LOG_ERR;
#else /* LOG_ERR */
      sev = 0;
#endif /* LOG_ERR */
      break;

    case SSH_LOG_CRITICAL:
#ifdef LOG_CRIT
      sev = LOG_CRIT;
#else /* LOG_CRIT */
      sev = 0;
#endif /* LOG_CRIT */
      break;

    case SSH_LOG_INFORMATIONAL:
#ifdef LOG_INFO
      sev = LOG_INFO;
#else /* LOG_INFO */
      sev = 0;
#endif /* LOG_INFO */
      break;

    case SSH_LOG_NOTICE:
    default:
#ifdef LOG_NOTICE
      sev = LOG_NOTICE;
#else /* LOG_NOTICE */
      sev = 0;
#endif /* LOG_NOTICE */
      break;
    }

  switch (facility)
    {
    case SSH_LOGFACILITY_AUTH:
    case SSH_LOGFACILITY_SECURITY:
#ifdef LOG_AUTH
      fac = LOG_AUTH;
#else /* LOG_AUTH */
      fac = 0;
#endif /* LOG_AUTH */
      break;

    case SSH_LOGFACILITY_DAEMON:
#ifdef LOG_DAEMON
      fac = LOG_DAEMON;
#else /* LOG_DAEMON */
      fac = 0;
#endif /* LOG_DAEMON */
      break;

    case SSH_LOGFACILITY_USER:
#ifdef LOG_USER
      fac = LOG_USER;
#else /* LOG_USER */
      fac = 0;
#endif /* LOG_USER */
      break;

    case SSH_LOGFACILITY_MAIL:
#ifdef LOG_MAIL
      fac = LOG_MAIL;
#else /* LOG_MAIL */
      fac = 0;
#endif /* LOG_MAIL */
      break;

    case SSH_LOGFACILITY_LOCAL0:
#ifdef LOG_LOCAL0
      fac = LOG_LOCAL0;
#else /* LOG_LOCAL0 */
      fac = 0;
#endif /* LOG_LOCAL0 */
      break;

    case SSH_LOGFACILITY_LOCAL1:
#ifdef LOG_LOCAL1
      fac = LOG_LOCAL1;
#else /* LOG_LOCAL1 */
      fac = 0;
#endif /* LOG_LOCAL1 */
      break;

    case SSH_LOGFACILITY_LOCAL2:
#ifdef LOG_LOCAL2
      fac = LOG_LOCAL2;
#else /* LOG_LOCAL2 */
      fac = 0;
#endif /* LOG_LOCAL2 */
      break;

    case SSH_LOGFACILITY_LOCAL3:
#ifdef LOG_LOCAL3
      fac = LOG_LOCAL3;
#else /* LOG_LOCAL3 */
      fac = 0;
#endif /* LOG_LOCAL3 */
      break;

    case SSH_LOGFACILITY_LOCAL4:
#ifdef LOG_LOCAL4
      fac = LOG_LOCAL4;
#else /* LOG_LOCAL4 */
      fac = 0;
#endif /* LOG_LOCAL4 */
      break;

    case SSH_LOGFACILITY_LOCAL5:
#ifdef LOG_LOCAL5
      fac = LOG_LOCAL5;
#else /* LOG_LOCAL5 */
      fac = 0;
#endif /* LOG_LOCAL5 */
      break;

    case SSH_LOGFACILITY_LOCAL6:
#ifdef LOG_LOCAL6
      fac = LOG_LOCAL6;
#else /* LOG_LOCAL6 */
      fac = 0;
#endif /* LOG_LOCAL6 */
      break;

    case SSH_LOGFACILITY_LOCAL7:
#ifdef LOG_LOCAL7
      fac = LOG_LOCAL7;
#else /* LOG_LOCAL7 */
      fac = 0;
#endif /* LOG_LOCAL7 */
      break;

    default:
#ifdef LOG_DAEMON
      fac = LOG_DAEMON;
#else /* LOG_DAEMON */
      fac = 0;
#endif /* LOG_DAEMON */
      break;
    }

  syslog(fac | sev, "%s", message);
}


/******************* The main entry point to the program ********************/

int
main(int argc, char *argv[])
{
  /* Resolve the program name. */
  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  /* Init policy manager and SSH libraries. */
  ssh_ipm_init();

  /* Register signal handlers. */

  ssh_register_signal(SIGINT, ssh_ipm_quit_handler, NULL);
  ssh_register_signal(SIGHUP, ssh_ipm_reconfigure_handler, NULL);
  ssh_register_signal(SIGALRM, ssh_ipm_reconfigure_handler_no_indicate, NULL);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  ssh_register_signal(SIGVTALRM, ssh_ipm_reconfigure_indicate_and_commit,
                      NULL);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  ssh_register_signal(SIGPIPE, ssh_ipm_pipe_handler, NULL);





  ssh_register_signal(SIGUSR2, ssh_ipm_redo_handler, NULL);










  /* Set some resource limits. */
#ifdef HAVE_SETRLIMIT
#ifdef RLIMIT_NOFILE
  if ((SSH_PM_MAX_FILEDESCRIPTORS) == 0)
    {
      struct rlimit rlp;
      rlp.rlim_cur = RLIM_INFINITY;
      rlp.rlim_max = RLIM_INFINITY;
      setrlimit(RLIMIT_NOFILE,&rlp);
    }
  else if ((SSH_PM_MAX_FILEDESCRIPTORS) != -1)
    {
      struct rlimit rlp;
      rlp.rlim_cur = (SSH_PM_MAX_FILEDESCRIPTORS);
      rlp.rlim_max = (SSH_PM_MAX_FILEDESCRIPTORS);
      setrlimit(RLIMIT_NOFILE,&rlp);
    }
#endif /* RLIMIT_NOFILE */
#endif /* HAVE_SETRLIMIT */






  /* Call the generic program entry point. */
  return ssh_ipm_start(argc, argv);
}

/********************* Callbacks from the generic code **********************/

Boolean
ssh_ipm_make_service(void)
{
  FILE *fd;
  char pidfile[64];
#ifdef TIOCNOTTY
  int ttyfd;
#endif /* TIOCNOTTY */

#ifdef HAVE_DAEMON
  if (daemon(0, 0) < 0)
    return FALSE;
#else /* HAVE_DAEMON */
  switch (fork())
    {
    case 0:
      /* at child, continue execution after switch. */
      break;
    case -1:
      /* failure, indicate this to caller. */
      return FALSE;
    default:
      /* success, parent exits now */
      exit(0);
    }

  /* Redirect stdin, stdout, and stderr to /dev/null. */
  freopen("/dev/null", "r", stdin);
  freopen("/dev/null", "w", stdout);
  freopen("/dev/null", "w", stderr);

  /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
  ttyfd = open("/dev/tty", O_RDWR|O_NOCTTY);
  if (ttyfd >= 0)
    {
      (void)ioctl(ttyfd, TIOCNOTTY, NULL);
      close(ttyfd);
    }
#endif /* TIOCNOTTY */

#ifdef HAVE_SETSID
  if (setsid() < 0)
    ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                  "Can not set session identifier for background process. "
                  "Operation (setsid) failed with error: %.100s",
                  strerror(errno));
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON */

  /* Save our process id in the pid file. */
  ssh_snprintf(pidfile, sizeof(pidfile), "/var/run/quicksecpm.pid");
  fd = fopen(pidfile, "w");
  if (fd != NULL)
    {
      fprintf(fd, "%ld\n", (long)getpid());
      fclose(fd);
    }

  /* Send syslog events to the syslog instead of stderr. */
  ssh_log_register_callback(ssh_pm_syslog_callback, NULL);

  return TRUE;
}


void
ssh_ipm_report_state(SshIpmState state)
{
#ifdef DEBUG_LIGHT
  char *s = "";

  switch (state)
    {
    case SSH_IPM_STARTING:
      s = "Starting";
      break;

    case SSH_IPM_RUNNING:
      s = "Running";
      break;

    case SSH_IPM_STOPPING:
      s = "Stopping";
      break;

    case SSH_IPM_STOPPED:
      s = "Stopped";
      break;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("%s", s));
#endif /* DEBUG_LIGHT */
}

#endif /* VXWORKS */
