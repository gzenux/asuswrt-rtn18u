/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshpcihw.h
*/

/*
  This is definition of a 'minimal' PCI hardware interface subset
  which should be portable to other platforms. The original reasoning
  behind this was to enable the Hi/Fn hardware acceleration driver(s)
  to be ported easily to other platforms without changing the logic in
  the code.

  This module provides functionality for:
   - enumerating PCI devices (optionally for specific classes of devices only).
   - handling PCI device's configuration space (getting and setting values).
   - mapping physical address to virtual address (and vice versa).
    - memory mapping physical address to virtual address in VM (ioremap).
   - requesting/freeing memory regions.
   - requesting/freeing interrupts.


  What is not found here (and is located elsewhere in the SSH source tree):
   - locking (ssh_kernel_mutex_{lock,unlock}).
   - debugging (SSH_DEBUG)
   - packet handling (out of scope; interceptor's ssh_packet_* API).
   - DMA-enabled memory allocation (kernel_alloc stuff). */





#ifndef SSHPCIHW_H
#define SSHPCIHW_H


/*************************************************************** PciHwDevice */

typedef struct SshPciHwDeviceRec *SshPciHwDevice;

/* Device availability control through this API.
   This functionality serves two purposes;

   - availability of a device for driver is easily available (i.e.
   two conflicting Ssh drivers cannot have conflict regarding a
   device).

   - all assigned resources are freed when pcihw_device_release is
   called. */

Boolean ssh_pcihw_device_reserve(SshPciHwDevice dev,
                                 const unsigned char *drivername);
void ssh_pcihw_device_release(SshPciHwDevice dev);

/* Set the device as PCI bus master. */
void ssh_pcihw_device_set_busmaster(SshPciHwDevice dev);

/* Individual PCI devices' content is platform dependant. However,
   following accessor functions are available. */
void ssh_pcihw_device_get_id(SshPciHwDevice dev,
                             SshUInt16 *vendor_id,
                             SshUInt16 *device_id,
                             SshUInt8 *rev_id);
void ssh_pcihw_device_get_irq(SshPciHwDevice dev,
                              SshUInt8 *irq);
void ssh_pcihw_device_get_resource(SshPciHwDevice dev,
                                   SshUInt32 idx,
                                   SshUInt32 *resource_start,
                                   SshUInt32 *resource_len);

/* Resource allocation functions (the resources are freed
   automatically when the device is released). */

/* Assigns the physical memory mapped by the
   ssh_pcihw_device_map_phys() function, so that no other driver can
   use the same physical memory for this particular PCI device */
Boolean
ssh_pcihw_device_assign_phys_mem(SshPciHwDevice dev,
                                 SshUInt32 phys_address_start,
                                 SshUInt32 len);

/* Maps the given physical address block of the PCI device to the
   virtual address space */
void *
ssh_pcihw_device_map_phys(SshPciHwDevice dev,
                          SshUInt32 phys_address_start,
                          SshUInt32 len);

typedef void (*SshPciHwSoftCallback)(void *context, SshUInt32 extra);

typedef void (*SshPciHwInterruptCallback)(SshUInt8 irq,
                                          void *context);

/* NOTE: at the moment API supports ONLY one interrupt. If more than
   one interrupts are needed, this API needs to be rethought (and
   backends rewritten). */
Boolean
ssh_pcihw_device_assign_irq(SshPciHwDevice dev,
                            SshUInt8 irq,
                            SshPciHwInterruptCallback cb,
                            void *cb_context);

/* Accessors for the PCI config block. */
SshUInt16
ssh_pcihw_device_config_get_word(SshPciHwDevice dev,
                                 SshUInt16 ofs);
SshUInt8
ssh_pcihw_device_config_get_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs);





void
ssh_pcihw_device_config_set_word(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt16 value);
void
ssh_pcihw_device_config_set_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt8 value);

/************************************************************** PciHwContext */

typedef struct SshPciHwContextRec *SshPciHwContext;

typedef Boolean (*SshPciHwEnumerateFunction)(SshPciHwDevice dev,
                                             void *enumeration_context);

/* Global PCI hardware context initialization/uninitialization. This
   can be used for storing the intermediate SshPciHwDevice structures,
   or other bookkeeping depending on the operation system involved. */
SshPciHwContext ssh_pcihw_init(void);
void ssh_pcihw_uninit(SshPciHwContext ctx);

typedef enum {
  SSH_PCIHW_CLASS_ANY = 0,
  SSH_PCIHW_CLASS_COPROCESSOR = 0xb40,
  SSH_PCIHW_CLASS_HIFN7751 = 0x40
} SshPciHwClass;

/* PCI device enumeration code.

   It will call the provided callback once for each found device, and
   it will stop when it either runs out of devices or the callback
   returns FALSE.
*/
void
ssh_pcihw_enumerate(SshPciHwContext ctx,
                    SshPciHwClass class_id,
                    SshPciHwEnumerateFunction callback,
                    void *callback_context);


/*********************************************************** General utility */

SshUInt32 ssh_pcihw_virt_to_phys(void *pointer);
void *ssh_pcihw_phys_to_virt(SshUInt32 address);
SshUInt32 ssh_pcihw_get_long(void *pointer); /* RAW access, not tainted
                                                by compiler. volatile et al. */
void ssh_pcihw_set_long(void *pointer, SshUInt32 value);
void ssh_pcihw_udelay(SshUInt32 delay);


/* Schedule softirq or equivalent (the typical drivers
   initial processing happens in hardirq; if hardirq is suitable,
   schedule can call callback directly). */
Boolean ssh_pcihw_schedule(SshPciHwSoftCallback callback,
                           void *arg1, SshUInt32 extra);


#define SSH_PCIHW_PCICONF_CMD           0x04

#define SSH_PCIHW_PCICONF_CMD_MEMORY    0x02
#define SSH_PCIHW_PCICONF_CMD_BUSMASTER 0x04

#define SSH_PCIHW_PCICONF_LATENCY 0x0d

/* Use memory write and invalidate */
#define SSH_PCIHW_PCICONF_CMD_INVALIDATE 0x10
#define SSH_PCIHW_PCICONF_CMD_SERR       0x100

/****************************************************** Locking (hw-enabled) */
typedef struct SshPciHwMutexRec *SshPciHwMutex;

/* These operations are similar to the operations in the
   engine_mutex.h, _except_ they HAVE to make sure that they are
   interrupt-safe. (for hardware-oriented operations) */

SshPciHwMutex ssh_pcihw_mutex_alloc(void);
void ssh_pcihw_mutex_free(SshPciHwMutex mutex);
void ssh_pcihw_mutex_lock(SshPciHwMutex mutex);
void ssh_pcihw_mutex_unlock(SshPciHwMutex mutex);


#endif /* SSHPCIHW_H */
