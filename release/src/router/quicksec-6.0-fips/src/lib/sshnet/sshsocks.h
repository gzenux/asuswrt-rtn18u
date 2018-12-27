/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Socks library.
*/

#ifndef SSH_SOCKS_H
#define SSH_SOCKS_H

#include "sshbuffer.h"

/* SocksInfo SOCKS4 command codes (numbers defined in socks protocol) */
#define SSH_SOCKS4_COMMAND_CODE_CONNECT          1
#define SSH_SOCKS4_COMMAND_CODE_BIND             2

#define SSH_SOCKS4_REPLY_GRANTED         90
#define SSH_SOCKS4_REPLY_FAILED_REQUEST  91
#define SSH_SOCKS4_REPLY_FAILED_IDENTD   92
#define SSH_SOCKS4_REPLY_FAILED_USERNAME 93

/* SocksInfo SOCKS5 command codes. */

#define SSH_SOCKS5_COMMAND_CODE_CONNECT          1
#define SSH_SOCKS5_COMMAND_CODE_BIND             2
#define SSH_SOCKS5_COMMAND_CODE_UDP_ASSOCIATE    3
/* SOCKS 5 only extensions for name resolution.*/
#define SSH_SOCKS5_COMMAND_CODE_RESOLVE          0x80
#define SSH_SOCKS5_COMMAND_CODE_RESOLVE_PTR      0x81

/* Authentication method types. */
#define SSH_SOCKS5_AUTH_METHOD_NO_AUTH_REQD   0x00
#define SSH_SOCKS5_AUTH_METHOD_GSSAPI         0x01
#define SSH_SOCKS5_AUTH_METHOD_PASSWORD       0x02
#define SSH_SOCKS5_AUTH_METHOD_NO_ACCEPTABLE  0xff

/* Replies. */
#define SSH_SOCKS5_REPLY_SUCCESS              0x00
#define SSH_SOCKS5_REPLY_FAILURE              0x01
#define SSH_SOCKS5_REPLY_NOT_ALLOWED          0x02
#define SSH_SOCKS5_REPLY_NETWORK_UNREACHABLE  0x03
#define SSH_SOCKS5_REPLY_HOST_UNREACHABLE     0x04
#define SSH_SOCKS5_REPLY_CONNECTION_REFUSED   0x05
#define SSH_SOCKS5_REPLY_TTL_EXPIRED          0x06
#define SSH_SOCKS5_REPLY_CMD_NOT_SUPPORTED    0x07
#define SSH_SOCKS5_REPLY_ATYP_NOT_SUPPORTED   0x08

/* Address types in requests. */
/* IPv4, 4 bytes. */
#define SSH_SOCKS5_ATYP_IPV4                 0x01
/* FQDN, first byte is length, rest is the name, with no terminating
   NUL. */
#define SSH_SOCKS5_ATYP_FQDN                 0x03
/* IPv6, 16 bytes. */
#define SSH_SOCKS5_ATYP_IPV6                 0x04

/* SocksInfo structure. */
typedef struct SocksInfoRec {
  unsigned int socks_version_number; /* Socks version number, should be 4
                                        or 5*/
  unsigned int command_code;    /* Socks command code, see above */
  unsigned char *ip;            /* Ip number (as string) */
  unsigned char *port;          /* Port number (as string) */
  unsigned char *username;      /* Username (as string) */
} *SocksInfo, SocksInfoStruct;

typedef enum {
  SSH_SOCKS_SUCCESS = 0,        /* Everything ok */
  SSH_SOCKS_TRY_AGAIN,          /* Not enough data, read more data and call
                                   this function again later. */
  SSH_SOCKS_FAILED_REQUEST,     /* Request rejected or failed */
  SSH_SOCKS_FAILED_IDENTD,      /* Request rejected because socks server
                                   cannot connect to identd on the client
                                   (only SOCKS4) */
  SSH_SOCKS_FAILED_USERNAME,    /* Request rejected because identd and
                                   request reported different usernames
                                   (only SOCKS4) */
  SSH_SOCKS_FAILED_AUTH,        /* Request rejected because we didn't
                                   complete server's required
                                   authentications (only SOCKS5) */
  SSH_SOCKS_ERROR_PROTOCOL_ERROR,
                                /* Socks protocol error */
  SSH_SOCKS_ERROR_INVALID_ARGUMENT,
                                /* Invalid arguments to call */
  SSH_SOCKS_ERROR_UNSUPPORTED_SOCKS_VERSION
                                /* Unsupported socks version */

} SocksError;

/*
 * Free SocksInfo structure (all fields, and the structure itself).
 * Sets the pointer to socksinfo structure to NULL (NOTE this takes
 * pointer to socksinfo pointer for this purpose).
 */
void ssh_socks_free(SocksInfo *socksinfo);

/* Server functions */
/*
 * Parse methods array. This doesn't do anything with SOCKS4.
 */
SocksError ssh_socks_server_parse_methods(SshBuffer buffer,
                                          SocksInfo *socksinfo);

/*
 * Generate method reply (no authentication required, currently). This
 * doesn't do anything with SOCKS4.
 */
SocksError ssh_socks_server_generate_method(SshBuffer buffer,
                                            SocksInfo socksinfo);

/*
 * Parse incoming socks connection from buffer. Consume the request packet data
 * from buffer. If everything is ok it allocates SocksInfo strcture and store
 * the request fields in it (sets socks_version_number, command_code, ip, port,
 * username). Returns SSH_SOCKS_SUCCESS, SSH_SOCKS_TRY_AGAIN, or
 * SSH_SOCKS_ERROR_*. If anything other than SSH_SOCKS_SUCCESS is returned the
 * socksinfo is set to NULL.
 * Use ssh_socks_free to free socksinfo data.
 */
SocksError ssh_socks_server_parse_open(SshBuffer buffer,
                                       SocksInfo *socksinfo);

/*
 * Make socks reply packet that can be sent to client and store it to buffer.
 * If connection is granted set command_code to SSH_SOCKS_COMMAND_CODE_GRANTED,
 * otherwise set it to some error code (SSH_SOCKS_COMMAND_CODE_FAILED_*).
 * The port and ip from the socksinfo are sent along with reply and if
 * the request that was granted was bind they should indicate the port and ip
 * address of the other end of the socket.
 * Does NOT free the SocksInfo structure.
 */
SocksError ssh_socks_server_generate_reply(SshBuffer buffer,
                                           SocksInfo socksinfo);

/* Client functions */
/*
 * Send acceptable methods. This doesn't do anything with SOCKS4.
 */
SocksError ssh_socks_client_generate_methods(SshBuffer buffer,
                                             SocksInfo socksinfo);

/*
 * Parse reply method. This doesn't do anything with SOCKS4.
 */
SocksError ssh_socks_client_parse_method(SshBuffer buffer,
                                         SocksInfo *socksinfo);

/*
 * Make socks connect or bind request and store it to buffer.
 * Uses all fields in socksinfo structure. Returns SSH_SOCKS_SUCCESS, or
 * SSH_SOCKS_ERROR. Command_code must be either SSH_SOCKS_COMMAND_CODE_BIND,
 * or SSH_SOCKS_COMMAND_CODE_CONNECT.
 * Does NOT free the SocksInfo structure.
 */
SocksError ssh_socks_client_generate_open(SshBuffer buffer,
                                          SocksInfo socksinfo);

/*
 * Parse socks reply packet. Consume the reply packet data from buffer.
 * If the request was not granted (returns SSH_SOCKS_FAILED_*) the socket can
 * be immediately closed down (there will not be any additional data from the
 * socks server.
 * If the request is granted allocate socksinfo structure and store information
 * from request packet to there (sets socks_version_number, command_code, ip,
 * and port fields).
 * Use ssh_socks_free to free socksinfo data. If socksinfo pointer is NULL
 * then it is ignored.
 */
SocksError ssh_socks_client_parse_reply(SshBuffer buffer,
                                        SocksInfo *socksinfo);

/* Client and Server functions */
/*
 * Encapsulate UDP payload of length payload_len with SOCKS headers. This
 * returns an error if socksinfo indicates SOCKS4 protocol. Does not free
 * the SocksInfo structure.
 */
SocksError ssh_socks_generate_udp_request(SshBuffer buffer,
                                          SocksInfo socksinfo,
                                          SshUInt8 frag,
                                          const unsigned char *payload,
                                          size_t payload_len);

/*
 * Decapsulate UDP traffic from SOCKS headers. Consumes buffer upto the
 * end of SOCKS header.Use ssh_socks_free to free socksinfo structure.
 */
SocksError ssh_socks_parse_udp_request(SshBuffer buffer,
                                       SocksInfo * socksinfo,
                                       SshUInt8 * frag);
#endif /* SSH_SOCKS_H */
