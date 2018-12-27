/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IOCTL interface defitions for kernel mode NETCONFIG library.
*/

#ifndef SSH_NETCONFIG_IOCTL_H
#define SSH_NETCONFIG_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SSH_NETCONFIG_DEVICE_NAME  (TEXT("\\\\.\\MACsec"))

#define SSH_NETCONFIG_MAX_MCAST_ADDRLEN   SSH_ETHERH_ADDRLEN

#pragma pack(push)
#pragma pack(8)

/* IOCTL request for joining media-level multicast group. */
#define SSH_IOCTL_NETCONFIG_ADD_MULTICAST \
  CTL_CODE(0x8000, 101, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct SshIoctlRequestAddMulticastRec
{
  /* Locally unique identifier of the interface */
  SshUInt64 luid;

  /* Multicast address */
  SshUInt32 mcast_addr_len;
  unsigned char mcast_addr[SSH_NETCONFIG_MAX_MCAST_ADDRLEN];
} SshIoctlRequestAddMulticastStruct, *SshIoctlRequestAddMulticast;


/* IOCTL request for leaving media-level multicast group. */
#define SSH_IOCTL_NETCONFIG_DROP_MULTICAST \
  CTL_CODE(0x8000, 102, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef SshIoctlRequestAddMulticastStruct SshIoctlRequestDropMulticastStruct;
typedef SshIoctlRequestAddMulticast       SshIoctlRequestDropMulticast;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_NETCONFIG_IOCTL_H */
