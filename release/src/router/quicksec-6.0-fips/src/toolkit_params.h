/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Global tunable configuration parameters.

   @description

   The setting defined in this file may be overridden by values supplied
   to the configure script on platforms where configure is available.
   The main purpose of this file is to allow parameter configuration on
   systems where configure is not available.
*/

#ifndef SSHPARAMS_H
#define SSHPARAMS_H

#ifdef SSHDIST_IPSEC
/** Include IPsec params if building QuickSec IPsec Toolkit. */
#ifdef SSH_BUILD_IPSEC
#include "ipsec_params.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/** The size in bytes of the global UDP datagram buffer. There is a single
    global buffer in the system which is used for receiving UDP datagrams to
    local UDP listeners. To receive a UDP datagram of arbitrary size this
    buffer should be of size at least 65537 bytes. In order to conserve memory
    this value may be lowered to a smaller size. However reducing this
    parameter lower than the default value will cause UDP datagrams to local
    listeners to be dropped if the datagram is larger than the configured
    value. */
#ifndef SSH_UDP_DATAGRAM_BUFFER_SIZE
#define SSH_UDP_DATAGRAM_BUFFER_SIZE 65537
#endif /* SSH_UDP_DATAGRAM_BUFFER_SIZE */


#ifdef SSHDIST_MSCAPI
/* Define this parameter to enable support for MSCAPI crypto and PKI
   functionality. */
/* #define WITH_MSCAPI 1 */
#endif /* SSHDIST_MSCAPI */


/** Undefine this parameter to remove support for IKE. Always undefined for IMS
    distribution */
#ifdef SSHDIST_QUICKSECPM
#ifndef WITH_IKE
#define WITH_IKE
#endif /* WITH_IKE */
#endif /* SSHDIST_QUICKSECPM */

#endif /* SSHPARAMS_H */
