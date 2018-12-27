/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common definitions for SSH virtual NIC miniport driver.
*/

#ifndef SSHVNIC_DEF_H
#define SSHVNIC_DEF_H

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/* Identifiers for querying the private interface of SSH virtual NIC
   miniport driver. */

/* Method 1: custom OID */
#define OID_SSH_QUERY_INTERFACE     0xFF535348

/* Method 2: device I/O control */
#define SSH_VNIC_IO_DEVICE_NAME     L"\\Device\\QuickSecVNIC"

#define IOCTL_SSH_QUERY_INTERFACE   \
  CTL_CODE(42042, 42, METHOD_BUFFERED, FILE_READ_ACCESS)





#endif /* SSHVNIC_DEF_H */

