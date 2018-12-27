/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef CMI_DEBUG_H
#define CMI_DEBUG_H
#include "sshenum.h"

extern const SshKeywordStruct ssh_cm_edb_data_types[];
extern const SshKeywordStruct ssh_cm_edb_key_types[];

int
ssh_cm_render_crl(unsigned char *buf, int len, int precision, void *datum);
int
ssh_cm_render_certificate(unsigned char *buf, int len,
                          int precision, void *datum);
int
ssh_cm_render_state(unsigned char *buf, int len, int precision, void *datum);
int
ssh_cm_render_mp(unsigned char *buf, int len, int precision, void *datum);

int
ssh_cm_edb_distinguisher_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

int
ssh_cm_render_cert_db_key(unsigned char *buf, int buf_size, int precision,
                          void *datum);

const char*
ssh_cm_status_to_string(SshCMStatus status);

#endif /* CMI_DEBUG_H */
/* eof */
