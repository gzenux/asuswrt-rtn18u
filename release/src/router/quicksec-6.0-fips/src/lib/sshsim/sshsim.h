/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to the SIM/USIM access library. See 3GPP TS 33.102 for
   descriptions of authentication values and other abbreviation-based
   language.
*/

#include "sshoperation.h"

typedef struct SshSimRec SshSimStruct, *SshSim;

/** Begin SIM/USIM access.

    @return
    Returns a pointer to the SIM context if successful, NULL
    otherwise.
    */
SshSim
ssh_sim_open(void);

/** End SIM/USIM access. */
void
ssh_sim_close(SshSim sim);

/** Values of the 'result' argument of SshSimGetImsiCB. */
typedef enum {
  SSH_SIM_GET_IMSI_SUCCESSFUL, /** Command successful. */
  SSH_SIM_GET_IMSI_ERROR       /** General error. */
} SshSimGetImsiResult;

/** Callback called by ssh_sim_get_imsi().

    @param result
    The overall status of the operation.

    @param imsi
    A pointer to the buffer containing the IMSI.

    @param imsi_len
    The length of the buffer containing the IMSI.

    @param context
    The context pointer previously passed to ssh_sim_get_imsi().

    The buffer is owned by the caller and should not be accessed after
    this callback returns.

    @return
    The IMSI buffer is valid if the result is
    SSH_SIM_GET_IMSI_SUCCESSFUL, otherwise not.

    */
typedef void
(*SshSimGetImsiCB)(SshSimGetImsiResult result,
                   const unsigned char *imsi, size_t imsi_len,
                   void *context);

/** Asynchronously get the IMSI (International Mobile Subscriber
    Identity) of the SIM/USIM card. The operation can be interrupted
    using ssh_operation_abort() with the returned operation handle as
    parameter in which case the callback will not be called. */
SshOperationHandle
ssh_sim_get_imsi(SshSim sim, SshSimGetImsiCB callback, void *context);

/** Values of the 'result' argument of SshSimGsmAuthenticateCB. */
typedef enum {
  SSH_SIM_GSM_AUTHENTICATE_SUCCESSFUL, /** Command successful. */
  SSH_SIM_GSM_AUTHENTICATE_ERROR       /** General error. */
} SshSimGsmAuthenticateResult;

/** Callback called by ssh_sim_gsm_authenticate().

    The buffers are owned by the caller and should not be accessed
    after this callback returns.

    @param result
    Overall status of the operation.

    @param sres
    Pointer to the buffer containing the SRES return value.

    @param sres_len
    The length of the buffer containing the SRES return value.

    @param kc
    Pointer to the buffer containing the Kc return value.

    @param kc_len
    The length of the buffer containing the Kc return value.

    @param context
    Context pointer previously passed to ssh_sim_gsm_authenticate().

    @return
    If the result is SSH_SIM_GSM_AUTHENTICATE_SUCCESSFUL, then SRES
    and Kc are valid. If the result is SSH_SIM_GSM_AUTHENTICATE_ERROR
    then neither of the buffers is valid.
    */
typedef void
(*SshSimGsmAuthenticateCB)(SshSimGsmAuthenticateResult result,
                           const unsigned char *sres, size_t sres_len,
                           const unsigned char *kc, size_t kc_len,
                           void *context);

/** Asynchronously run the GSM authentication algorithm on the
    SIM/USIM.

    Buffer contents are copied by the function if necessary, and are
    not accessed after the call. The operation can be interrupted by
    using ssh_operation_abort() with the returned operation handle as
    a parameter, in which case the callback will not be called.

    @param rand
    A pointer to the buffer containing the RAND input value.

    @param rand_len
    The length of the buffer containing the RAND input value.

    @param context
    Context pointer passed to the callback function.

*/
SshOperationHandle
ssh_sim_gsm_authenticate(SshSim sim,
                         const unsigned char *rand, size_t rand_len,
                         SshSimGsmAuthenticateCB callback, void *context);

/** Values of the 'result' argument of SshSim3GAuthenticateCB. */
typedef enum {
  SSH_SIM_3G_AUTHENTICATE_SUCCESSFUL, /** Command successful. */
  SSH_SIM_3G_AUTHENTICATE_SYNCFAIL,   /** Synchronization failure. */
  SSH_SIM_3G_AUTHENTICATE_ERROR       /** General error. */
} SshSim3GAuthenticateResult;

/** Callback called by ssh_sim_3g_authenticate().

    The buffers are owned by the caller and should not be accessed
    after this callback returns.

    @param result
    The overall status of the operation.

    @param res
    Pointer to buffer containing the RES return value. The unused part of
    RES return value must be zeroes.

    @param res_len
    The length of the buffer containing the length of RES return value in bits.
    The value must be between 32 to 128.

    @param ck
    Pointer to the buffer containing the CK return value.

    @param
    The length of the buffer containing the CK return value.

    @param
    Pointer to the buffer containing the IK return value.

    @param ik_len
    The length of the buffer containing the IK return value.

    @param auts
    Pointer to the buffer containing the AUTS return value.

    @param auts_len
    The length of the buffer containing the AUTS return value.

    @param context
    The context pointer previously passed to ssh_sim_3g_authenticate().

    @return
    If the result is SSH_SIM_3G_AUTHENTICATE_SUCCESSFUL, then RES, CK
    and IK are valid, but not AUTS. If the result is
    SSH_SIM_3G_AUTHENTICATE_SYNCFAIL, then AUTS is valid but not the
    other buffers. If the result is SSH_SIM_3G_AUTHENTICATE_ERROR,
    then none of the buffers are valid.
    */
typedef void
(*SshSim3GAuthenticateCB)(SshSim3GAuthenticateResult result,
                          const unsigned char *res, size_t res_len,
                          const unsigned char *ck, size_t ck_len,
                          const unsigned char *ik, size_t ik_len,
                          const unsigned char *auts, size_t auts_len,
                          void *context);

/** Asynchronoulsy run the 3G authentication algorithm on the
    USIM.

    Buffer contents are copied by the function if necessary and are
    not accessed after the call. The operation can be interrupted
    using ssh_operation_abort() with the returned operation handle as
    a parameter, in which case the callback will not be called.

    @param rand
    Pointer to the buffer containing the RAND input value.

    @param rand_len
    The length of the buffer containing the RAND input value.

    @param autn
    Pointer to buffer containing the RAND input value.

    @param autn_len
    The length of the buffer containing the RAND input value.

    @param callback
    The function called when the command completes.

    @param context
    Context pointer passed to the callback function.

*/
SshOperationHandle
ssh_sim_3g_authenticate(SshSim sim,
                        const unsigned char *rand, size_t rand_len,
                        const unsigned char *autn, size_t autn_len,
                        SshSim3GAuthenticateCB callback, void *context);
