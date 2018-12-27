/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

typedef struct SshAnsiX962Rec *SshAnsiX962;

SshAnsiX962
ssh_ansi_x962_init();

void
ssh_ansi_x962_uninit(SshAnsiX962 state);

SshCryptoStatus
ssh_ansi_x962_add_entropy(SshAnsiX962 state,
                          const unsigned char *buf, size_t buflen);

SshCryptoStatus
ssh_ansi_x962_get_byte(SshAnsiX962 state,
                       unsigned char *byte_ret);

SshCryptoStatus
ssh_ansi_x962_get_bytes(SshAnsiX962 state,
                        unsigned char *buf, size_t buflen);
