/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS packet encode and decode routines.
*/

#ifndef SSHDNSPACKET_H
#define SSHDNSPACKET_H

/* DNS Response codes. Codes from 0-15 are defined by the
   DNS specification, codes starting from 65536 are internal
   to the DNS library. */
typedef enum {
  SSH_DNS_OK = 0,               /* No error condition */
  SSH_DNS_FORMAT_ERROR = 1,     /* The name server was unable to interpret the
                                   query. */
  SSH_DNS_SERVER_FAILURE = 2,   /* The name server was unable to process this
                                   query due to a problem with a name
                                   server. */
  SSH_DNS_NONEXISTENT_DOMAIN = 3, /* The domain name references in the query
                                     does not exist. */
  SSH_DNS_UNIMPLEMENTED = 4,    /* The name server does not support the
                                   requested kind of query. */
  SSH_DNS_QUERY_REFUSED = 5,    /* The name server refuses to perform the
                                   specified operation for policy reasons. */
  SSH_DNS_YXDOMAIN = 6,         /* Name exists when it should not */
  SSH_DNS_YXRRSET = 7,          /* RR set exists when it should not */
  SSH_DNS_NXRRSET = 8,          /* RR set that should exists does not */
  SSH_DNS_NOTAUTH = 9,          /* Server not authorative for zone */
  SSH_DNS_NOTZONE = 10,         /* Name not contained in zone */

  /* Extended response codes. */
  SSH_DNS_BADVERS = 16,         /* Bad OPT Version */
  SSH_DNS_BADSIG = 16,          /* TSIG Signature Failure */
  SSH_DNS_BADKEY = 17,          /* Key not recognized */
  SSH_DNS_BADTIME = 18,         /* Signature out of time window */
  SSH_DNS_BADMODE = 19,         /* Bad TKEY Mode */
  SSH_DNS_BADNAME = 20,         /* Duplicate key name */
  SSH_DNS_BADALG = 21,          /* Algorithm not supported */

  /* Internal codes. These are above 16 bit values, thus they cannot be used by
     extended response codes. */
  SSH_DNS_MEMORY_ERROR = 65536, /* Out of memory during operation. */
  SSH_DNS_TIMEOUT = 65537,      /* The operation timed out. */
  SSH_DNS_UNREACHABLE = 65538,  /* Host is unreachable. */
  SSH_DNS_REFUSED = 65539,      /* The connection was
                                   refused in transport
                                   protocol level (not by
                                   dns server). */
  SSH_DNS_UNABLE_TO_SEND = 65540, /* Lower layer cannot send
                                     packet now, because of
                                     some error (out of
                                     buffers, tcp stream
                                     blocked etc). */
  SSH_DNS_LIMIT_REACHED = 65541, /* The operation looped and was aborted
                                    after the limit was reached. */
  SSH_DNS_INTERNAL_ERROR = 65542, /* Internal error, something went wrong. */
  SSH_DNS_PARSE_ERROR = 65543   /* Error parsing the reply packet from name
                                   server. */
} SshDNSResponseCode;

/* Resource records type. */
typedef enum {
  SSH_DNS_RESOURCE_A = 1,               /* Host address, rfc1035 */
  SSH_DNS_RESOURCE_NS = 2,              /* Authoritative server, rfc1035 */
  SSH_DNS_RESOURCE_MD = 3,              /* Mail destination, obs rfc1035 */
  SSH_DNS_RESOURCE_MF = 4,              /* Mail forwarder, obs rfc1035 */
  SSH_DNS_RESOURCE_CNAME = 5,           /* Canonical name, rfc1035 */
  SSH_DNS_RESOURCE_SOA = 6,             /* Start of authority zone, rfc1035 */
  SSH_DNS_RESOURCE_MB = 7,              /* Mailbox domain name, exp rfc1035 */
  SSH_DNS_RESOURCE_MG = 8,              /* Mail group member, exp rfc1035 */
  SSH_DNS_RESOURCE_MR = 9,              /* Mail rename name, exp rfc1035 */
  SSH_DNS_RESOURCE_NULL = 10,           /* Null resource record, exp rfc1035*/
  SSH_DNS_RESOURCE_WKS = 11,            /* Well known service, rfc1035 */
  SSH_DNS_RESOURCE_PTR = 12,            /* Domain name pointer, rfc1035 */
  SSH_DNS_RESOURCE_HINFO = 13,          /* Host information, rfc1035 */
  SSH_DNS_RESOURCE_MINFO = 14,          /* Mailbox information, rfc1035 */
  SSH_DNS_RESOURCE_MX = 15,             /* Mail routing information, rfc1035 */
  SSH_DNS_RESOURCE_TXT = 16,            /* Text strings, rfc1035 */
  SSH_DNS_RESOURCE_RP = 17,             /* Responsible person, rfc1183 */
  SSH_DNS_RESOURCE_AFSDB = 18,          /* AFS cell database, rfc1183 */
  SSH_DNS_RESOURCE_X25 = 19,            /* X_25, calling address, rfc1183 */
  SSH_DNS_RESOURCE_ISDN = 20,           /* ISDN calling address, rfc1183 */
  SSH_DNS_RESOURCE_RT = 21,             /* Router through, rfc1183 */
  SSH_DNS_RESOURCE_NSAP = 22,           /* NSAP address, rfc1706 */
  SSH_DNS_RESOURCE_NSAP_PTR = 23,       /* Reverse NSAP lookup (deprecated) */
  SSH_DNS_RESOURCE_SIG = 24,            /* Security signature, rfc2931 */
  SSH_DNS_RESOURCE_KEY = 25,            /* Security key, rfc2535 */
  SSH_DNS_RESOURCE_PX = 26,             /* X.400, mail mapping, rfc2163 */
  SSH_DNS_RESOURCE_GPOS = 27,           /* Geographical position,
                                           withdrawn rfc1712 */
  SSH_DNS_RESOURCE_AAAA = 28,           /* IP6, Address */
  SSH_DNS_RESOURCE_LOC = 29,            /* Location Information */
  SSH_DNS_RESOURCE_NXT = 30,            /* Next Valid Name in Zone, rfc2535 */
  SSH_DNS_RESOURCE_EID = 31,            /* Endpoint identifier */
  SSH_DNS_RESOURCE_NIMLOC = 32,         /* Nimrod locator */
  SSH_DNS_RESOURCE_SRV = 33,            /* Server selection, rfc2782 */
  SSH_DNS_RESOURCE_ATMA = 34,           /* ATM Address */
  SSH_DNS_RESOURCE_NAPTR = 35,          /* Naming Authority PoinTeR,
                                           rfc2168, rfc2915 */
  SSH_DNS_RESOURCE_KX = 36,             /* Key Exchanger, rfc2230 */
  SSH_DNS_RESOURCE_CERT = 37,           /* Certificate, rfc2538 */
  SSH_DNS_RESOURCE_A6 = 38,             /* A6, rfc2874 */
  SSH_DNS_RESOURCE_DNAME = 39,          /* DNAME, rfc2672 */
  SSH_DNS_RESOURCE_SINK = 40,           /* SINK */
  SSH_DNS_RESOURCE_OPT = 41,            /* OPT, rfc2671 */
  SSH_DNS_RESOURCE_APL = 42,            /* APL, rfc3123 */
  SSH_DNS_RESOURCE_DS = 43,             /* Delegation Signer, rfc3658 */
  SSH_DNS_RESOURCE_SSHFP = 44,          /* SSH Key Fingerprint */
  SSH_DNS_RESOURCE_RRSIG = 46,          /* RRSIG */
  SSH_DNS_RESOURCE_NSEC = 47,           /* NSEC */
  SSH_DNS_RESOURCE_DNSKEY = 48,         /* DNSKEY */
  SSH_DNS_RESOURCE_UINFO = 100,         /* User (finger) information */
  SSH_DNS_RESOURCE_UID = 101,           /* User ID */
  SSH_DNS_RESOURCE_GID = 102,           /* Group ID */
  SSH_DNS_RESOURCE_UNSPEC = 103,        /* Unspecified format (binary data) */

  /* Query typedef values which do not appear in resource records */
  SSH_DNS_QUERY_TKEY = 249,             /* Transaction Key, rfc2930 */
  SSH_DNS_QUERY_TSIG = 250,             /* Transaction Signature, rfc2845 */
  SSH_DNS_QUERY_IXFR = 251,             /* Incremental zone transfer, rfc1995*/
  SSH_DNS_QUERY_AXFR = 252,             /* Transfer zone of authority,
                                           rfc1035 */
  SSH_DNS_QUERY_MAILB = 253,            /* Transfer mailbox records, rfc1035 */
  SSH_DNS_QUERY_MAILA = 254,            /* Transfer mail agent records,
                                           rfc1035 */
  SSH_DNS_QUERY_ANY = 255               /* Wildcard match, rfc1035 */
} SshDNSRRType;

/* Operation codes. */
typedef enum {
  SSH_DNS_OPCODE_QUERY = 0,             /* Normal Query */
  SSH_DNS_OPCODE_STATUS = 2,            /* Status */
  SSH_DNS_OPCODE_NOTIFY = 4,            /* Notify */
  SSH_DNS_OPCODE_UPDATE = 5             /* Update */
} SshDNSOpCode;

/* Protocol classes. Only INTERNET is really supported. */
typedef enum {
  SSH_DNS_CLASS_INTERNET        = 1,
  SSH_DNS_CLASS_CHAOS           = 3,
  SSH_DNS_CLASS_HESIOD          = 4,
  SSH_DNS_CLASS_ANY             = 255
} SshDNSProtocolClass;

/* These values correspond directly to the DNS standard. */
#define SSH_DNS_FLAG_IS_RESPONSE                0x8000
#define SSH_DNS_FLAG_AUTHORITATIVE              0x0400
#define SSH_DNS_FLAG_TRUNCATED                  0x0200
#define SSH_DNS_FLAG_RECURSION_DESIRED          0x0100
#define SSH_DNS_FLAG_RECURSION_AVAILABLE        0x0080
#define SSH_DNS_FLAG_AUTHENTIC_DATA             0x0020
#define SSH_DNS_FLAG_CHECKING_DISABLED          0x0010

#define SSH_DNS_FLAG_MASK                       0x87f0

/* DNS Questions structure. */
typedef struct SshDNSQuestionRec {
  /* Note, that this name is in the dns-format, i.e length byte followed by the
     label, not as in string (dot-separated). This field is nul terminated
     though, as there is root label at the end (marked as 0-length label). This
     will never be in the compressed format, the compression is always removed
     before data is stored here.*/
  unsigned char *qname;
  SshDNSRRType qtype;
  SshDNSProtocolClass qclass;
} *SshDNSQuestion, SshDNSQuestionStruct;

/* DNS Record structure. */
typedef struct SshDNSRecordRec {
  /* Note, that this name is in the dns-format, i.e length byte followed by the
     label, not as in string (dot-separated). This field is nul terminated
     though, as there is root label at the end (marked as 0-length label). This
     will never be in the compressed format, the compression is always removed
     before data is stored here. */
  unsigned char *name;
  SshDNSRRType type;
  SshDNSProtocolClass dns_class;
  SshUInt32 ttl;
  size_t rdlength;
  /* Note, that data in the rdata depends on the type, and it may contains
     names in the dns-format. The compression of the names is decoded before
     data is copied here. */
  unsigned char *rdata;
} *SshDNSRecord, SshDNSRecordStruct;

/* DNS Packet structure. */
typedef struct SshDNSPacketRec {
  /* Id of the packet. */
  SshUInt16 id;
  /* Flags. This has the opcode and rcode masked out. */
  SshUInt16 flags;
  /* Operation code for the request. Normally SSH_DNS_OPCODE_QUERY. */
  SshDNSOpCode op_code;
  /* Response code. */
  SshDNSResponseCode response_code;

  /* Number of questions in the packet. */
  SshUInt16 question_count;
  /* Array of questions. */
  SshDNSQuestion question_array;

  /* Number of answers in the packet. */
  SshUInt16 answer_count;
  /* Array of answers. */
  SshDNSRecord answer_array;

  /* Number of authority records in the packet. */
  SshUInt16 authority_count;
  /* Array of authority records (NS records). */
  SshDNSRecord authority_array;

  /* Number of additional records in the packet. */
  SshUInt16 additional_count;
  /* Array of additional records. */
  SshDNSRecord additional_array;

  /* All data pointed by above is allocated from this obstack, and if you
     modify anything in this structure, then you can allocate data from this
     obstack, and it will be automatically freed when the packet is freed. No
     other data is freed, so if you allocate some data using any other means,
     you need to make sure it is freed when the packet is freed. */
  SshObStackContext obstack;
} *SshDNSPacket, SshDNSPacketStruct;

/* Allocate new packet. This will also automatically allocate space for the
   given number of question, answer, authority, and additional records. Those
   records are initialized to zeros. Returns NULL if out of memory. */
SshDNSPacket ssh_dns_packet_allocate(SshUInt16 question_count,
                                     SshUInt16 answer_count,
                                     SshUInt16 authority_count,
                                     SshUInt16 additional_count);

/* Free dns packet. */
void ssh_dns_packet_free(SshDNSPacket packet);

/* Decode packet. This returns NULL if there is memory error or parse error,
   otherwise it will return the decoded packet. */
SshDNSPacket ssh_dns_packet_decode(const unsigned char *packet,
                                   size_t packet_length);

/* Encode packet. This will store the packet to the given buffer of size
   packet_length. This will return the number of bytes consumed from the
   packet, and if the packet cannot fit to the buffer given then the truncated
   flag is set on the packet, and return value is number of bytes actually used
   from the buffer, but it is given out as negative number. */
int ssh_dns_packet_encode(SshDNSPacket packet, unsigned char *buffer,
                          size_t buffer_length);

/* Render function to render dnspacket for %@ format string for ssh_e*printf */
int ssh_dns_packet_render(unsigned char *buf, int buf_size, int precision,
                          void *datum);

/* Indention string used for packet render etc. */
extern const char ssh_dns_packet_indent[];

#endif /* SSHDNSPACKET_H */
