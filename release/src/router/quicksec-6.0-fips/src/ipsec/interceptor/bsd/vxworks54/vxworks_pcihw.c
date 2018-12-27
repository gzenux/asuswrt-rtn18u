/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VxWorks implementation of the SSH PCI hardware API (sshpcihw.h).

   This file works on most ix86 and PowerPC hardware, for PPC405GP see
   also: config/walnut/sysBusPci.c
*/

#define SSH_DEBUG_MODULE "SshIpsecInterceptorVxPciHw"

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "kernel_mutex.h"

#include <intLib.h>
#include <iosLib.h>
#include <vmLib.h>
/* NOTE. config.h is from $WIND_BASE/target/config/<arch>/config.h */
#include <config.h>
#include <netLib.h>
#include <iv.h>
#include <drv/pci/pciIntLib.h>
#include <drv/pci/pciConfigLib.h>
#include <drv/timer/timerDev.h>
#if (CPU==PPC860)
#include <drv/multi/ppc860Siu.h>
#endif /* (CPU==PPC860) */

#include "sshpcihw.h"

#define SSH_D_ERROR 0

/* temporary local debug info */
#define MY_DEBUG
#undef MY_DEBUG

/* Standard device configuration register offsets */

#define SSH_PCI_CFG_VENDOR_ID       0x00
#define SSH_PCI_CFG_DEVICE_ID       0x02
#define SSH_PCI_CFG_COMMAND         0x04
#define SSH_PCI_CFG_STATUS          0x06
#define SSH_PCI_CFG_REVISION        0x08
#define SSH_PCI_CFG_PROGRAMMING_IF  0x09
#define SSH_PCI_CFG_SUBCLASS        0x0a
#define SSH_PCI_CFG_CLASS           0x0b
#define SSH_PCI_CFG_CACHE_LINE_SIZE 0x0c
#define SSH_PCI_CFG_LATENCY_TIMER   0x0d
#define SSH_PCI_CFG_HEADER_TYPE     0x0e
#define SSH_PCI_CFG_BIST            0x0f
#define SSH_PCI_CFG_BASE_ADDRESS_0  0x10
#define SSH_PCI_CFG_BASE_ADDRESS_1  0x14
#define SSH_PCI_CFG_BASE_ADDRESS_2  0x18
#define SSH_PCI_CFG_BASE_ADDRESS_3  0x1c
#define SSH_PCI_CFG_BASE_ADDRESS_4  0x20
#define SSH_PCI_CFG_BASE_ADDRESS_5  0x24
#define SSH_PCI_CFG_CIS             0x28
#define SSH_PCI_CFG_SUB_VENDOR_ID   0x2c
#define SSH_PCI_CFG_SUB_SYSTEM_ID   0x2e
#define SSH_PCI_CFG_EXPANSION_ROM   0x30
#define SSH_PCI_CFG_RESERVED_0      0x34
#define SSH_PCI_CFG_RESERVED_1      0x38
#define SSH_PCI_CFG_DEV_INT_LINE    0x3c
#define SSH_PCI_CFG_DEV_INT_PIN     0x3d
#define SSH_PCI_CFG_MIN_GRANT       0x3e
#define SSH_PCI_CFG_MAX_LATENCY     0x3f
#define SSH_PCI_CFG_SPECIAL_USE     0x41
#define SSH_PCI_CFG_MODE            0x43

/* PCI-to-PCI bridge configuration register offsets */

#define SSH_PCI_CFG_PRIMARY_BUS     0x18
#define SSH_PCI_CFG_SECONDARY_BUS   0x19
#define SSH_PCI_CFG_SUBORDINATE_BUS 0x1a
#define SSH_PCI_CFG_SEC_LATENCY     0x1b
#define SSH_PCI_CFG_IO_BASE         0x1c
#define SSH_PCI_CFG_IO_LIMIT        0x1d
#define SSH_PCI_CFG_SEC_STATUS      0x1e
#define SSH_PCI_CFG_MEM_BASE        0x20
#define SSH_PCI_CFG_MEM_LIMIT       0x22
#define SSH_PCI_CFG_PRE_MEM_BASE    0x24
#define SSH_PCI_CFG_PRE_MEM_LIMIT   0x26
#define SSH_PCI_CFG_PRE_MEM_BASE_U  0x28
#define SSH_PCI_CFG_PRE_MEM_LIMIT_U 0x2c
#define SSH_PCI_CFG_IO_BASE_U       0x30
#define SSH_PCI_CFG_IO_LIMIT_U      0x32
#define SSH_PCI_CFG_ROM_BASE        0x38
#define SSH_PCI_CFG_BRG_INT_LINE    0x3c
#define SSH_PCI_CFG_BRG_INT_PIN     0x3d
#define SSH_PCI_CFG_BRIDGE_CONTROL  0x3e



/* Implementation of VxWorks version of PciHw API.

   This is mainly a proof of concept code to verify that it is indeed
   possible to do this with reasonable effort. */

#define NUM_MEMORY_BLOCKS 4

typedef struct SshPciHwConfigHdrRec *SshPciHwConfigHdr;

/* structure for the device & bridge header */
struct SshPciHwConfigHdrRec
{
  short       vendorId;       /* vendor ID */
  short       deviceId;       /* device ID */
  short       command;        /* command register */
  short       status;         /* status register */
  char        revisionId;     /* revision ID */
  char        progIf;         /* programming interface */
  char        subClass;       /* sub class code */
  char        classCode;      /* class code */
  char        cacheLine;      /* cache line */
  char        latency;        /* latency time */
  char        headerType;     /* header type */
  char        bist;           /* BIST */
  int         base0;          /* base address 0 */
  int         base1;          /* base address 1 */
  int         base2;          /* base address 2 */
  int         base3;          /* base address 3 */
  int         base4;          /* base address 4 */
  int         base5;          /* base address 5 */
  int         cis;            /* cardBus CIS pointer */
  short       subVendorId;    /* sub system vendor ID */
  short       subSystemId;    /* sub system ID */
  int         romBase;        /* expansion ROM base address */
  int         reserved0;      /* reserved */
  int         reserved1;      /* reserved */
  char        intLine;        /* interrupt line */
  char        intPin;         /* interrupt pin */
  char        minGrant;       /* min Grant */
  char        maxLatency;     /* max Latency */
};


struct SshPciHwDeviceRec {
  SshPciHwContext context;

  SshUInt32 bus;
  SshUInt32 slot;
  SshUInt32 func;
  SshUInt32 class;
  struct SshPciHwConfigHdrRec cfg_hdr;

  const unsigned char *reserved_by; /* NULL by default. */

  /* irq is 0 if it hasn't been given a callback yet. */
  SshUInt8 irq;
  SshPciHwInterruptCallback irq_cb;
  void *irq_cb_context;

  void *mapped_memory[NUM_MEMORY_BLOCKS];
  SshUInt8 num_mapped_memory;

  SshUInt32 reserved_memory[NUM_MEMORY_BLOCKS][2]; /* addr, len pairs. */
  SshUInt8 num_reserved_memory;

  SshPciHwDevice next; /* next in the pcihwcontext. */
};

struct SshPciHwContextRec {
  SshPciHwDevice first_device;
};

#if (CPU_FAMILY==I80X86)
/* defined in sysLib.c */
extern STATUS sysMmuMapAdd(void * address, UINT len, UINT initialStateMask,
  UINT initialState);
#endif

static Boolean ssh_pcihw_read_cfg_hdr(SshUInt32 bus,
                                      SshUInt32 slot,
                                      SshUInt32 func,
                                      SshPciHwConfigHdr cfg_hdr)
{

  /* Read the whole PCI configuration header */
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_VENDOR_ID,
                  &cfg_hdr->vendorId);
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_DEVICE_ID,
                  &cfg_hdr->deviceId);
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_COMMAND,
                  &cfg_hdr->command);
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_STATUS,
                  &cfg_hdr->status);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_REVISION,
                  &cfg_hdr->revisionId);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_PROGRAMMING_IF,
                  &cfg_hdr->progIf);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_SUBCLASS,
                  &cfg_hdr->subClass);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_CLASS,
                  &cfg_hdr->classCode);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_CACHE_LINE_SIZE,
                  &cfg_hdr->cacheLine);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_LATENCY_TIMER,
                  &cfg_hdr->latency);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_HEADER_TYPE,
                  &cfg_hdr->headerType);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_BIST,
                  &cfg_hdr->bist);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_0,
                  &cfg_hdr->base0);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_1,
                  &cfg_hdr->base1);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_2,
                  &cfg_hdr->base2);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_3,
                  &cfg_hdr->base3);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_4,
                  &cfg_hdr->base4);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_BASE_ADDRESS_5,
                  &cfg_hdr->base5);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_CIS,
                  &cfg_hdr->cis);
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_SUB_VENDOR_ID,
                  &cfg_hdr->subVendorId);
  pciConfigInWord(bus, slot, func, SSH_PCI_CFG_SUB_SYSTEM_ID,
                  &cfg_hdr->subSystemId);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_EXPANSION_ROM,
                  &cfg_hdr->romBase);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_RESERVED_0,
                  &cfg_hdr->reserved0);
  pciConfigInLong(bus, slot, func, SSH_PCI_CFG_RESERVED_1,
                  &cfg_hdr->reserved1);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_DEV_INT_LINE,
                  &cfg_hdr->intLine);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_DEV_INT_PIN,
                  &cfg_hdr->intPin);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_MIN_GRANT,
                  &cfg_hdr->minGrant);
  pciConfigInByte(bus, slot, func, SSH_PCI_CFG_MAX_LATENCY,
                  &cfg_hdr->maxLatency);

  return TRUE;
}

Boolean ssh_pcihw_device_reserve(SshPciHwDevice dev,
                                 const unsigned char *drivername)
{
  if (dev->reserved_by) return FALSE;
  dev->reserved_by = drivername;
  return TRUE;
}


void ssh_pcihw_device_set_busmaster(SshPciHwDevice dev)
{
  /* Enable Bus Mastering (preserve status bits) */
  pciConfigModifyLong(dev->bus, dev->slot, dev->func,
                      PCI_CFG_COMMAND,
                      (0xffff0000 | PCI_CMD_MASTER_ENABLE),
                      PCI_CMD_MASTER_ENABLE);
}

/* Individual PCI devices' content is platform dependant. However,
   following accessor functions are available. */
void ssh_pcihw_device_get_id(SshPciHwDevice dev,
                             SshUInt16 *vendor_id,
                             SshUInt16 *device_id,
                             SshUInt8 *rev_id)
{
  *vendor_id = dev->cfg_hdr.vendorId;
  *device_id = dev->cfg_hdr.deviceId;
  *rev_id = dev->cfg_hdr.revisionId;
}

void ssh_pcihw_device_get_irq(SshPciHwDevice dev,
                              SshUInt8 *irq)
{
  *irq = dev->cfg_hdr.intLine;
}

void ssh_pcihw_device_get_resource(SshPciHwDevice dev,
                                   SshUInt32 idx,
                                   SshUInt32 *resource_start,
                                   SshUInt32 *resource_len)
{

  unsigned offset, tmp, len, base;

  offset = SSH_PCI_CFG_BASE_ADDRESS_0 + idx * sizeof(int);

  /* read the original base address */
  pciConfigInLong(dev->bus, dev->slot, dev->func, offset, &base);

  /* trick to read the base address len */
  pciConfigOutLong(dev->bus, dev->slot, dev->func, offset, ~0x0);
  pciConfigInLong(dev->bus, dev->slot, dev->func, offset, &tmp);

  /* logically and the pci mask and negate */
  len = ~(tmp & ~0xf) + 1;

  /* restore the original base address */
  pciConfigOutLong(dev->bus, dev->slot, dev->func, offset, base);

  *resource_start = base;
  *resource_len = len;
}

Boolean
request_mem_region_compatible(SshUInt32 mem_start,
                              SshUInt32 mem_len,
                              const unsigned char *reserved_by)
{
  return TRUE;
}

/* Resource allocation. */
Boolean
ssh_pcihw_device_assign_phys_mem(SshPciHwDevice dev,
                                 SshUInt32 mem_start,
                                 SshUInt32 mem_len)
{
  /* Cannot assign on VxWorks */
  return TRUE;
}

/* maps physical memory to a virtual address */
void *
ssh_pcihw_device_map_phys(SshPciHwDevice dev,
                          SshUInt32 address,
                          SshUInt32 len)
{
  int i = dev->num_mapped_memory;
  void *p = NULL;

  if (i >= NUM_MEMORY_BLOCKS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("out of memory blocks."));
      return NULL;
    }

#if (CPU_FAMILY==I80X86)
  {
    int ii;
    /* Map the memory windows required by chip driver */
    if (sysMmuMapAdd((void *)((unsigned)address),
                    len,
                    VM_STATE_MASK_VALID |
                    VM_STATE_MASK_WRITABLE |
                    VM_STATE_MASK_CACHEABLE,
                    VM_STATE_VALID |
                    VM_STATE_WRITABLE |
                    VM_STATE_CACHEABLE_NOT) == ERROR)
      {
        SSH_DEBUG(SSH_D_ERROR, ("map failed."));
        return NULL;
      }

    for (ii = 0; ii < sysPhysMemDescNumEnt; ii++)
      {
        if (sysPhysMemDesc[ii].physicalAddr == (void *)address)
          {
            p = (void *)sysPhysMemDesc[ii].virtualAddr;
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("phys_addr %p mapped to vm_addr %p\n",
                      address, p));
          break;
        }
      }

    /* NOTE, NOTE, NOTE. vmBaseGlobalMapInit() takes about two seconds
      on intel Pentium / Pentium MMX, about one minute on Pentium II /
      Celeron, and it does not work at all on Pentium III */
    if (vmBaseGlobalMapInit(sysPhysMemDesc,
                            sysPhysMemDescNumEnt,
                            TRUE) == NULL)
      {
        SSH_DEBUG(SSH_D_ERROR, ("virtual map init failed."));
        return NULL;
      }
  }
#endif /* (CPU_FAMILY==I80X86) */

#if (CPU_FAMILY==PPC)
  /* convert the PCI-bus master window to host CPU virtual address,
     which is the same as the host CPU physical address. This is valid
     for IBM PPC405GP (walnut). See also ssh_pcihw_virt_to_phys() */
  p = (void *)PCI_MEM2LOCAL(address);
#endif

  dev->mapped_memory[i] = p;
  dev->num_mapped_memory++;
  return p;
}

static void
ssh_pcihw_schedule_internal(SshPciHwSoftCallback callback,
                            void *ctx, int extra, int i4, int i5)
{
  (*callback)(ctx, extra);
}

Boolean ssh_pcihw_schedule(SshPciHwSoftCallback callback,
                           void *ctx, SshUInt32 extra)

{

  /* let's _hope_ the code doesn't do rampant queueing, because
     we do not guard against it (yet - hifn seems like sensible chip). */
  if (netJobAdd((FUNCPTR)ssh_pcihw_schedule_internal,
                (int)callback, (int)ctx, (int)extra, 0, 0) != OK)
    return FALSE;

  return TRUE;
}

static void interrupt_wrapper(SshPciHwDevice dev)
{
  /* printf(" .. wrapped interrupt ..\n"); */
  dev->irq_cb(dev->irq, dev->irq_cb_context);
}

#if (CPU==PPC860)
static SshUInt32 immrSM = 0x00000000UL;
#endif /* (CPU==PPC860) */

Boolean
ssh_pcihw_device_assign_irq(SshPciHwDevice dev,
                            SshUInt8 irq,
                            SshPciHwInterruptCallback cb,
                            void *cb_context)
{
#if (CPU_FAMILY==PPC)
  void (**vector)(void) = (void(**)(void))(unsigned int)irq;
#elif (CPU_FAMILY==I80X86)
  VOIDFUNCPTR *vector;
#endif

  SSH_VERIFY(dev->irq == 0);
  SSH_ASSERT(dev->reserved_by != NULL);

  /* fill in the local pci-device parameters */
  dev->irq = irq;
  dev->irq_cb = cb;
  dev->irq_cb_context = cb_context;

#if (CPU_FAMILY==PPC)
#if (CPU==PPC860)
  immrSM  = vxImmrGet();




  *SIEL( immrSM ) |= (0x80000000 >> IVEC_TO_INUM(vector));
#endif /* (CPU==PPC860) */

  if (intConnect(vector, interrupt_wrapper, (unsigned)dev) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt connect failed."));
      dev->irq = 0; /* mark the device free. */
      return FALSE;
    }

  if (intEnable(IVEC_TO_INUM(vector)) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt enable failed."));
      dev->irq = 0; /* mark the device free. */
      return FALSE;
    }

  return TRUE;
#endif /* (CPU_FAMILY==PPC) */

#if (CPU_FAMILY==I80X86)

  /* Everything initialized, ready to start receiving interrupts */
  vector = INUM_TO_IVEC(irq + INT_NUM_IRQ0);

  if (pciIntConnect(vector, interrupt_wrapper, (unsigned)dev) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt connect failed."));
      dev->irq = 0; /* mark the device free. */
      return FALSE;
    }

  if (sysIntEnablePIC(irq) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt enable failed."));
      dev->irq = 0; /* mark the device free. */
      return FALSE;
    }

  return TRUE;
#endif /* (CPU_FAMILY==I80X86) */

  /* any other architecture here */

  return FALSE;
}

/* Accessors for the PCI config block. */

SshUInt16
ssh_pcihw_device_config_get_word(SshPciHwDevice dev,
                                 SshUInt16 ofs)
{
  SshUInt16 word;

  pciConfigInWord(dev->bus, dev->slot, dev->func, ofs, &word);
  return word;
}

void
ssh_pcihw_device_config_set_word(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt16 word)
{
  pciConfigOutWord(dev->bus, dev->slot, dev->func, ofs, word);
}

SshUInt8
ssh_pcihw_device_config_get_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs)
{
  SshUInt8 byte;

  pciConfigInWord(dev->bus, dev->slot, dev->func, ofs,
                  (short *)&byte);
  return byte;
}

void
ssh_pcihw_device_config_set_byte(SshPciHwDevice dev,
                                 SshUInt16 ofs,
                                 SshUInt8 byte)
{
  pciConfigOutByte(dev->bus, dev->slot, dev->func, ofs, byte);
}


void ssh_pcihw_device_release(SshPciHwDevice dev)
{
#if (CPU_FAMILY==PPC)
  void (**vector)(void) = (void(**)(void))(unsigned int)dev->irq;
#else
  VOIDFUNCPTR *vector;
#endif

  if (!dev->reserved_by) return;

  /* NOTE: this should be called with some form of lock held to
     prevent interrupts from happening during release (BAD). */

#if (CPU_FAMILY==PPC)
#if (CPU==PPC860)



  *SIPEND(immrSM) |= (0x80000000 >> IVEC_TO_INUM(vector));
#endif /* (CPU==PPC860) */

  if (intDisable(IVEC_TO_INUM(vector)) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt disconnect failed."));
    }

#else /* ! (CPU_FAMILY==PPC) */
  /* Release the IRQ. */
  vector = INUM_TO_IVEC(dev->irq + INT_NUM_IRQ0);

  if (pciIntDisconnect(vector, interrupt_wrapper) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interrupt disconnect failed."));
    }
#endif

  dev->irq = 0;




#if 0
  for (i = 0 ; i < dev->num_mapped_memory ; i++)
    iounmap(dev->mapped_memory[i]);
  dev->num_mapped_memory = 0;

  /* Free the memory regions. */
  for (i = 0 ; i < dev->num_reserved_memory ; i++)
    release_mem_region(dev->reserved_memory[i][0],
                       dev->reserved_memory[i][1]);
#endif
  dev->num_reserved_memory = 0;

  SSH_ASSERT(dev->reserved_by);
  dev->reserved_by = NULL;
}





/************************************************************** PciHwContext */

/* Import VxWorks x86 variables */

extern int pciLibInitStatus;
extern int pciConfigMech;

/* Global PCI hardware context initialization/uninitialization. This
   can be used for storing the intermediate SshPciHwDevice structures,
   or other bookkeeping depending on the operation system involved. */
SshPciHwContext ssh_pcihw_init(void)
{
  SshPciHwContext ctx;
  SshPciHwDevice dev;
  SshUInt32 slot, bus, func = 0, devices;
  SshUInt16 vendor;

  /* sanity check */
  if (pciLibInitStatus != OK)
    return NULL;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;

  /* main structure has been created. now, we iterate through all
     pci devices in system and create respective SshPciHwDevice
     structures. */
  if (pciConfigMech == PCI_MECHANISM_1)
    devices = 0x1f;
  else
    devices = 0x0f;




  for (bus = 0; bus < 4; bus++)
    for (slot = 0; slot < devices; slot++)
      {
        pciConfigInWord(bus, slot, func, PCI_CFG_VENDOR_ID, &vendor);

        /* There is something on this PCI slot */
        if (vendor != 0xffff)
          {
            /* Create device and push it to the device list. */
            dev = ssh_calloc(1, sizeof(*dev));
            if (!dev)
              {
                ssh_pcihw_uninit(ctx);
                return NULL;
              }

            /* Read the required config data to access and identify the
               device */
            ssh_pcihw_read_cfg_hdr(bus, slot, func, &dev->cfg_hdr);

            dev->context = ctx;
            dev->bus = bus;
            dev->slot = slot;
            dev->func = func;

            /* build the class variable from PCI config registers */
            dev->class =
              (dev->cfg_hdr.progIf & 0xff) |
              (dev->cfg_hdr.subClass & 0xff) << 8 |
              (dev->cfg_hdr.classCode & 0xff) << 16;

            /* Add to device list. */
            dev->next = ctx->first_device;
            ctx->first_device = dev;

#ifdef MY_DEBUG
            printf("vxworks_pcihw.c: %p: %04x:%04x:%02x, class=%08x\n", dev,
                   dev->cfg_hdr.vendorId & 0xffff,
                   dev->cfg_hdr.deviceId & 0xffff,
                   dev->cfg_hdr.revisionId & 0xff,
                   dev->class);
#endif /* MY_DEBUG */

          }
      }

#if 1
  /* Check that iteration is not broken. */
  ssh_pcihw_enumerate(ctx, SSH_PCIHW_CLASS_ANY, NULL_FNPTR, NULL);
#endif
  return ctx;
}

void ssh_pcihw_uninit(SshPciHwContext ctx)
{
  SshPciHwDevice dev, next;

  if (!ctx) return;

  while ((dev=ctx->first_device))
    {
      next = dev->next;
      ssh_pcihw_device_release(dev);
      ssh_free(dev);
      ctx->first_device = next;
    }
  ssh_free(ctx);
}

/* PCI device enumeration code.

   It will call the provided callback once for each found device, and
   it will stop when it either runs out of devices or the callback
   returns FALSE.
*/
void
ssh_pcihw_enumerate(SshPciHwContext ctx,
                    SshPciHwClass class,
                    SshPciHwEnumerateFunction callback,
                    void *callback_context)
{
  SshPciHwDevice dev;

  SSH_ASSERT(ctx != NULL);
  for (dev = ctx->first_device ; dev ; dev = dev->next)
    {
#ifdef MY_DEBUG
      printf("vxworks_pcihw.c test-iter-%p-%x(%x)\n",
             dev, class, dev->class);
#endif /* MY_DEBUG */

      if (class != SSH_PCIHW_CLASS_ANY &&
          (class << 8) != dev->class)
        continue;
      if (dev->reserved_by)
        continue;
      if (!callback)
        continue;
      if (!callback(dev, callback_context))
        return; /* no further callbacks desired. */
    }
}


/*********************************************************** General utility */

SshUInt32 ssh_pcihw_virt_to_phys(void *pointer)
{
#if (CPU_FAMILY==PPC)
  /* convert the host CPU virtual address, which is the same as the
     host CPU physical address to the PCI-bus slave window.
     NOTE that in order for the host CPU data to be cache coherent,
     the data MUST have been allocated using the VxWorks
     cacheLib, otherwise. This is valid for IBM PPC405GP (walnut) */
  return (SshUInt32)LOCAL2PCI_MEMIO(pointer);
#endif


  return (SshUInt32)pointer;
}

void *ssh_pcihw_phys_to_virt(SshUInt32 address)
{
#if (CPU_FAMILY==PPC)
  /* convert the PCI-bus slave window address back to the local CPU
     virtual address. This is valid for IBM PPC405GP (walnut) */
  return (void *)(address - (SshUInt32)LOCAL2PCI_MEMIO(0));
#endif

  return (void *)address;
}

#define SSH_PCIHW_ENDIAN(x)   \
  (((x & 0x000000ff) << 24) | \
   ((x & 0x0000ff00) << 8)  | \
   ((x & 0x00ff0000) >> 8)  | \
   ((x & 0xff000000) >> 24))


SshUInt32 ssh_pcihw_get_long(void *pointer)
{
#if (CPU_FAMILY==PPC)
  SshUInt32 v = *(SshUInt32 *)pointer;
  v = SSH_PCIHW_ENDIAN(v);
#else
  SshUInt32 v = *(SshUInt32 *)pointer;
#endif
  return v;
}

void ssh_pcihw_set_long(void *pointer, SshUInt32 value)
{
#if (CPU_FAMILY==PPC)
  *(SshUInt32 *)pointer = SSH_PCIHW_ENDIAN(value);
#else
  *(SshUInt32 *)pointer = value;
#endif
}

void ssh_pcihw_udelay(SshUInt32 delay)
{



  taskDelay((sysClkRateGet() * delay) / 1000000);
}

/********************************************************************* Mutex */

/* IMPORTANT NOTE! On VxWorks binary semaphores can only be given at
   interrupt level, but not taken */
SshPciHwMutex ssh_pcihw_mutex_alloc(void)
{
  SEMAPHORE *mutex;

  /* init locking mechanism, set the lock available */
  mutex = semBCreate(SEM_Q_PRIORITY, SEM_FULL);

  if (mutex == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("mutex alloc failed"));
      return NULL;
    }

  return (SshPciHwMutex)mutex;
}

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */
void ssh_pcihw_mutex_free(SshPciHwMutex mutex)
{
  semDelete((SEMAPHORE *)mutex);
}

/* Locks the mutex.  Only one thread of execution can have a mutex locked
   at a time.  This will block until execution can continue.  One should
   not keep mutexes locked for extended periods of time. */
void ssh_pcihw_mutex_lock(SshPciHwMutex ctx)
{
  semTake((SEMAPHORE *)ctx, WAIT_FOREVER);
}

/* Unlocks the mutex.  If other threads are waiting to lock the mutex,
   one of them will get the lock and continue execution. */
void ssh_pcihw_mutex_unlock(SshPciHwMutex ctx)
{
  semGive((SEMAPHORE *)ctx);
}

#ifdef DEBUG_LIGHT
/* Check that the mutex is locked.  It is a fatal error if it is not. */
void ssh_pcihw_mutex_assert_is_locked(SshPciHwMutex ctx)
{
  SSH_ASSERT(semTake((SEMAPHORE *)ctx, NO_WAIT) == ERROR);
}
#endif /* DEBUG_LIGHT */

