/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp library linearize (import / export) code.
*/

#ifndef ISAKMP_LINEARIZE_H
#define ISAKMP_LINEARIZE_H

#include "isakmp.h"
#include "sshbuffer.h"

/* Export given IKE SA pointed by negotiation to buffer. Buffer is NOT cleared
   before the export. Returns size of packet added to the buffer, or 0 in case
   of error. In case of error the data added to the buffer is removed. */
size_t ssh_ike_sa_export(SshBuffer buffer, SshIkeNegotiation negotiation);

/* Expore identity payload to buffer. Buffer is NOT cleared, before the
   export. Returns size of the data added to the buffer, or 0 in case of error.
   In case of error the data added to the buffer is removed. */
size_t ssh_ike_sa_export_id(SshBuffer buffer, SshIkePayloadID id);

/* Import given buffer to the IKE Server given in the argument. Returns the IKE
   SA negotiation or NULL in case of error. The data that was parsed
   successfully is consumed from the buffer in any case. If there is extra data
   after the complete packet then it is left to the buffer. */
SshIkeNegotiation ssh_ike_sa_import(SshBuffer buffer,
                                    SshIkeServerContext server);

/* Import id from the buffer and store newly allocated id to the id pointer,
   freeing the old id if such was stored there. If the id_txt pointer is given
   then it is used to store the textual format of the id. If that pointer
   contained old id string it is freed before the new string stored there.
   Returns TRUE if successful and FALSE otherwise. In case of error the buffer
   is left unspecified state (i.e part of it might be consumed). */
Boolean ssh_ike_sa_import_id(SshBuffer buffer, SshIkePayloadID *id,
                             char **id_txt);

#define SSH_IKE_EXPORT_MAGIC1   0x496b650a
#define SSH_IKE_EXPORT_MAGIC2   0x456b692e
#define SSH_IKE_EXPORT_VERSION  0x00010000

#endif /* ISAKMP_LINEARIZE_H */
