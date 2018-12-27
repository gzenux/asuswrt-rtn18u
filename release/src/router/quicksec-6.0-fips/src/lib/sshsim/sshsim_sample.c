/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to the SIM/USIM access library. See 3GPP TS 33.102 for
   descriptions of authentication values and other abbreviation-based
   language.

   This is a sample implementation that returns hardcoded values. SIM
   access is simulated using a 500 ms timeout after which the
   appropriate values are returned. Hardcoding is as follows:

     IMSI: 555444333222111
     SRES: ASCII bytes of the string "SRES"
     Kc:   ASCII bytes of the string "KcKcKcKc"
     RES:  ASCII bytes of the string "RESRESRESRESRESR"
     CK:   ASCII bytes of the string "CKCKCKCKCKCKCKCK"
     IK:   ASCII bytes of the string "IKIKIKIKIKIKIKIK"
*/

#include "sshincludes.h"

#ifdef SSHDIST_SIM_SAMPLE

#include "sshsim.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshSim"

struct SshSimRec {
  SshOperationHandleStruct operation;
  SshTimeoutStruct timeout;
  void *callback;
  void *context;
  int busy;
};

Boolean
ssh_sim_check_autn(const unsigned char *autn, size_t autn_len)
{
  Boolean ok = TRUE;

  const unsigned char invalid_autn[16] = {
    0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0,
    0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa1
  };

  if (autn_len == 16)
    {
      if (memcmp(autn, invalid_autn, 16) == 0)
        ok = FALSE;
    }

  return ok;
}

SshSim
ssh_sim_open(void)
{
  SshSim sim;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Opening SIM/USIM"));

  if (!(sim = ssh_calloc(1, sizeof *sim)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot allocate SIM context"));
      return NULL;
    }

  return sim;
}

void
ssh_sim_close(SshSim sim)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Closing SIM/USIM"));
  ssh_free(sim);
}

static void
ssh_sim_get_imsi_abort(void *context)
{
  SshSim sim = context;

  ssh_cancel_timeout(&sim->timeout);
  sim->busy = 0;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("IMSI retrieval aborted"));
}

static void
ssh_sim_get_imsi_timeout(void *context)
{
  SshSim sim = context;
  const unsigned char imsi[15] = "555444333222111";

  ssh_operation_unregister(&sim->operation);
  sim->busy = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning IMSI '%.*s'", sizeof imsi, imsi));
  (*(SshSimGetImsiCB)sim->callback)(SSH_SIM_GET_IMSI_SUCCESSFUL,
                                    imsi, sizeof imsi,
                                    sim->context);
}

SshOperationHandle
ssh_sim_get_imsi(SshSim sim, SshSimGetImsiCB callback, void *context)
{
  /* Fail if SIM op already running. */
  if (sim->busy)
    {
      SSH_DEBUG(SSH_D_FAIL, ("another SIM operation in progress"));
      (*callback)(SSH_SIM_GET_IMSI_ERROR, NULL, 0, context);
      return NULL;
    }

  sim->callback = callback;
  sim->context = context;
  sim->busy = 1;
  ssh_operation_register_no_alloc(&sim->operation,
                                  ssh_sim_get_imsi_abort, sim);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Starting IMSI retrieval"));
  ssh_register_timeout(&sim->timeout, 0, 500000,
                       ssh_sim_get_imsi_timeout, sim);
  return &sim->operation;
}

static void
ssh_sim_gsm_authenticate_abort(void *context)
{
  SshSim sim = context;

  ssh_cancel_timeout(&sim->timeout);
  sim->busy = 0;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("GSM authenticate aborted"));
}

static void
ssh_sim_gsm_authenticate_timeout(void *context)
{
  SshSim sim = context;
  const unsigned char sres[4] = {
    0x53, 0x52, 0x45, 0x53
  };
  const unsigned char kc[8] = {
    0x4b, 0x63, 0x4b, 0x63, 0x4b, 0x63, 0x4b, 0x63
  };

  ssh_operation_unregister(&sim->operation);
  sim->busy = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning GSM authentication data:"));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("SRES:"), sres, sizeof sres);
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Kc:"), kc, sizeof kc);
  (*(SshSimGsmAuthenticateCB)sim->callback)(
                SSH_SIM_GSM_AUTHENTICATE_SUCCESSFUL,
                sres, sizeof sres,
                kc, sizeof kc,
                sim->context);

}

SshOperationHandle
ssh_sim_gsm_authenticate(SshSim sim,
                         const unsigned char *rand, size_t rand_len,
                         SshSimGsmAuthenticateCB callback, void *context)
{
  /* Fail if SIM op already running. */
  if (sim->busy)
    {
      SSH_DEBUG(SSH_D_FAIL, ("another SIM operation in progress"));
      (*callback)(SSH_SIM_GSM_AUTHENTICATE_ERROR,
                  NULL, 0,
                  NULL, 0,
                  context);
      return NULL;
    }

  sim->callback = callback;
  sim->context = context;
  sim->busy = 1;
  ssh_operation_register_no_alloc(&sim->operation,
                                  ssh_sim_gsm_authenticate_abort, sim);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Starting GSM authenticate"));
  ssh_register_timeout(&sim->timeout, 0, 500000,
                       ssh_sim_gsm_authenticate_timeout, sim);
  return &sim->operation;
}

static void
ssh_sim_3g_authenticate_abort(void *context)
{
  SshSim sim = context;

  ssh_cancel_timeout(&sim->timeout);
  sim->busy = 0;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("3G authenticate aborted"));
}

static void
ssh_sim_3g_authenticate_timeout(void *context)
{
  SshSim sim = context;
  const unsigned char res[16] = {
    0x52, 0x45, 0x53, 0x52, 0x45, 0x53, 0x52, 0x45,
    0x53, 0x52, 0x45, 0x53, 0x52, 0x45, 0x53, 0x52
  };
  const unsigned char ck[16] = {
    0x43, 0x4b, 0x43, 0x4b, 0x43, 0x4b, 0x43, 0x4b,
    0x43, 0x4b, 0x43, 0x4b, 0x43, 0x4b, 0x43, 0x4b
  };
  const unsigned char ik[16] = {
    0x49, 0x4b, 0x49, 0x4b, 0x49, 0x4b, 0x49, 0x4b,
    0x49, 0x4b, 0x49, 0x4b, 0x49, 0x4b, 0x49, 0x4b
  };

  ssh_operation_unregister(&sim->operation);
  sim->busy = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Returning 3G authentication data:"));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("RES:"), res, sizeof(res));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("CK:"), ck, sizeof(ck));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("IK:"), ik, sizeof(ik));
  (*(SshSim3GAuthenticateCB)sim->callback)(
                SSH_SIM_3G_AUTHENTICATE_SUCCESSFUL,
                res, sizeof(res) * 8,
                ck, sizeof(ck),
                ik, sizeof(ik),
                NULL, 0,
                sim->context);

}

SshOperationHandle
ssh_sim_3g_authenticate(SshSim sim,
                        const unsigned char *rand, size_t rand_len,
                        const unsigned char *autn, size_t autn_len,
                        SshSim3GAuthenticateCB callback, void *context)
{
  /* Fail if SIM op already running. */
  if (sim->busy)
    {
      SSH_DEBUG(SSH_D_FAIL, ("another SIM operation in progress"));
      (*callback)(SSH_SIM_3G_AUTHENTICATE_ERROR,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  context);
      return NULL;
    }

  /* Check value of AUTN. */
  if (ssh_sim_check_autn(autn, autn_len) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("AUTN check failed"));
      (*callback)(SSH_SIM_3G_AUTHENTICATE_ERROR,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  NULL, 0,
                  context);
      return NULL;
    }

  sim->callback = callback;
  sim->context = context;
  sim->busy = 1;
  ssh_operation_register_no_alloc(&sim->operation,
                                  ssh_sim_3g_authenticate_abort, sim);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Starting 3G authenticate"));
  ssh_register_timeout(&sim->timeout, 0, 500000,
                       ssh_sim_3g_authenticate_timeout, sim);
  return &sim->operation;
}

#endif /* SSHDIST_SIM_SAMPLE */
