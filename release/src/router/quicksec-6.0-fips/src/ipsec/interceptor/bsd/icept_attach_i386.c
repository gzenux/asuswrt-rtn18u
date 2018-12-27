/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file is a kludge to replace some kernel functions by code in the
   loadable kernel module.  This goes and modifies the code.
*/

#include "sshincludes.h"
#include "icept_attach.h"

#define SSH_DEBUG_MODULE "SshInterceptorAttach"

/***********************************************************************
 * KLUDGE BEGINS!  We modify the binary of the kernel to redirect
 * calls to ip_output and ipintr to our modified code.  This is horrible,
 * I know, but NetBSD 1.3 does not provide the required interfaces to do
 * this cleanly.  I believe it is important to be able to do this as a
 * loadable module, so that is why I'm opening this bag of horrors!
 * 980710 Tatu Ylonen <ylo@ssh.fi>
 **********************************************************************/

/* On 3.0 newer with pfil also on interfaces, we do not need the code
   on this file at all. For 2.0, having pfil, but no on the interfaces
   we attach to the ifioct with old technology. */
#if SSH_NetBSD < 300

#ifdef KERNEL
#if SSH_NetBSD >= 150
/* Too bad.  At least in NetBSD, the kernel memory is mapped read-only
   unless the kernel is compiled with the build-in debugger DDB.  So,
   here is a function to change a protection for given kernel pages.
   This is taken from the `uvm/uvm_glue.c' almost as-is.  Only the
   semantics of the `rw' argument and the name of the function has
   been changed. */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/buf.h>
#include <sys/user.h>

#if SSH_NetBSD < 160
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>
#endif /* SSH_NetBSD < 150 */

#if SSH_NetBSD >= 160
#include <uvm/uvm.h>
#endif /* SSH_NetBSD >= 160 */

/*
 * Change protections on kernel pages from addr to addr+len
 * (presumably so debugger can plant a breakpoint).
 *
 * We force the protection change at the pmap level.  If we were
 * to use vm_map_protect a change to allow writing would be lazily-
 * applied meaning we would still take a protection fault, something
 * we really don't want to do.  It would also fragment the kernel
 * map unnecessarily.  We cannot use pmap_protect since it also won't
 * enforce a write-enable request.  Using pmap_enter is the only way
 * we can ensure the change takes place properly.
 */
static void
ssh_chgkprot(addr, len, rw)
        caddr_t addr;
        size_t len;
        int rw;
{
        vm_prot_t prot;
        paddr_t pa;
        vaddr_t sva, eva;

        prot = rw == B_READ ? VM_PROT_READ : VM_PROT_READ|VM_PROT_WRITE;
        eva = round_page((vaddr_t)addr + len);
        for (sva = trunc_page((vaddr_t)addr); sva < eva; sva += PAGE_SIZE) {
                /*
                 * Extract physical address for the page.
                 * We use a cheezy hack to differentiate physical
                 * page 0 from an invalid mapping, not that it
                 * really matters...
                 */
                if (pmap_extract(pmap_kernel(), sva, &pa) == FALSE)
                        panic("chgkprot: invalid page");
                pmap_enter(pmap_kernel(), sva, pa, prot, PMAP_WIRED);
        }
#if SSH_NetBSD >= 160
        pmap_update(pmap_kernel());
#endif /* SSH_NetBSD >= 160 */
}
#endif /* SSH_NetBSD >= 150 */
#else /* not KERNEL */
/* This is for testing; see ../tests/t-icept-attach. */
#undef splhigh
#undef splx
#define splhigh() 23
#define splx(x) do { SSH_ASSERT((x) == 23); } while (0)
#define ssh_chgkprot(addr, len, rw)
#endif /* not KERNEL */

/* We must save the first four bytes of the original function, and determine
   the next clean instruction boundary.  This array should contain all
   possible function starts (the first four bytes).  The first value
   is the real length of the instructions that start in the first four
   bytes, and the second value is the number of bytes that actually need to be
   compared to identify the instruction well enough to know its length).
   The remaining bytes specify the code to compare.  */
struct
{
  unsigned int real_len;   /* number of bytes to next insn, at least 5 */
  unsigned int fixed_len;  /* number of bytes in signature */
  unsigned char signature[8];
} ssh_i386_func_starts[] =
{
  { 6, 5,  { 0x55, 0x89, 0xe5, 0x83, 0xec }},
  { 6, 4,  { 0x55, 0x89, 0xe5, 0x8b }},
  { 8, 4,  { 0x55, 0x89, 0xe5, 0x68 }},
  { 8, 4,  { 0x55, 0x89, 0xe5, 0xa1 }},
  { 10, 5, { 0x55, 0x89, 0xe5, 0x83, 0x3d }},
  { 13, 5, { 0x55, 0x89, 0xe5, 0xc7, 0x05 }},
  { 9, 5,  { 0x55, 0x89, 0xe5, 0x53, 0xe8 }},
  { 10, 5, { 0x55, 0x89, 0xe5, 0x53, 0x8b }},
  { 6, 5,  { 0x55, 0x89, 0xe5, 0x57, 0x56 }},
  { 9, 4,  { 0x55, 0x89, 0xe5, 0x81 }},
  { 0, 0 }
};

#if SSH_NetBSD == 200
void ssh_attach_ifioctl(void)
#else /* SSH_NetBSD == 200 */
void ssh_attach_substitutions()
#endif /* SSH_NetBSD == 200 */
{
  unsigned char *origcode, *scratchcode, *ucp;
  int x, i, real_len, fixed_len;
  SshAttachRec *sub;

  x = splhigh();

  /* Iterate over substitutions. */
  for (sub = ssh_get_substitutions(); sub->type != SSH_ATTACH_END; sub++)
    {
#if SSH_NetBSD >= 150
      ssh_chgkprot(sub->original, 8, B_WRITE);
#endif /* SSH_NetBSD >= 150 */

      for (i = 0; ssh_i386_func_starts[i].real_len != 0; i++)
        {
          real_len = ssh_i386_func_starts[i].real_len;
          fixed_len = ssh_i386_func_starts[i].fixed_len;
          SSH_ASSERT(real_len >= 5); /* Need five bytes! */
          /* Check if the original starts with this signature. */
          if (memcmp(sub->original, ssh_i386_func_starts[i].signature,
                     fixed_len) == 0)
            break;
        }
      if (ssh_i386_func_starts[i].real_len == 0)
        {
          printf("\nssh_attach_substitutions: unexpected original 0x%lx\n",
                 (unsigned long)sub->original);
          for (i = 0; i < 8; i++)
            printf(" 0x%02x", ((unsigned char *)sub->original)[i]);
          printf("\n");
          printf("You should decode the instructions and add an entry to\n");
          printf("the ssh_i386_func_starts array in icept_attach_i386.c.\n");
          continue;
        }
      /* real_len and fixed_len are set appropriately. */

      /* Save the original start of the function. */
      memcpy(sub->scratch, sub->original, 8);

      origcode = sub->original;
      scratchcode = sub->scratch + 8;
      ucp = scratchcode;

      switch (sub->type)
        {
        case SSH_ATTACH_REPLACE:
          /* Just fake the substitute function to be the scratch code. */
          scratchcode = sub->substitute;
          break;

        case SSH_ATTACH_BEFORE:
          /* Build scratch binary code that first calls the substitute
             function, then executes the first instructions of the
             original function, and jumps to the original. */
          /* Build call to substitute. */
          *ucp++ = 0xe8; /* Call with 32-bit displacement. */
          *(SshUInt32 *)ucp = ((unsigned long)sub->substitute -
                               (unsigned long)ucp - 4);
          ucp += 4;
          /* Perform code at start of original.  Note that the code
             we compared above may not end at instruction boundary, so
             the length copied here may not be the same as in the compare. */
          memcpy(ucp, origcode, real_len);
          ucp += real_len;

          /* Jump to original after replaced code. */
          *ucp++ = 0xe9; /* Jump with 32-bit displacement. */
          *(SshUInt32 *)ucp = ((unsigned long)origcode + real_len -
                               (unsigned long)ucp - 4);
          break;

        case SSH_ATTACH_AFTER:

          /* Build scratch binary code that fakes a function call from the
             scratch code to the original (after performing the starting
             instructions), and after return jumps to the replacement code,
             with return address being the original return address. */
          /* Push the fake return address. */
          *ucp++ = 0x58; /* popl %eax   ; real return address */
          *ucp++ = 0xa3; /* movl %eax, ($store) ; save return address */
          *(SshUInt32 *)ucp = (unsigned long)&sub->scratch[90];
          ucp += 4;
          *ucp++ = 0x68; /* pushl $32bit   ; force return to our code */
          *(SshUInt32 *)ucp = (unsigned long)&scratchcode[40];
          ucp += 4;
          /* Copy original starting instructions here. */
          memcpy(ucp, origcode, real_len);
          ucp += real_len;
          *ucp++ = 0xe9; /* jmp disp32 */
          *(SshUInt32 *)ucp = ((unsigned long)sub->original + real_len -
                               (unsigned long)ucp - 4);

          /* Create code where the original function returns. */
          ucp = scratchcode + 40;

          /* Original code returns here. */
          *ucp++ = 0x50; /* pushl %eax    ; save return value from orig fn */
          *ucp++ = 0xe8;  /* call disp32 */
          *(SshUInt32 *)ucp = ((unsigned long)sub->substitute -
                               (unsigned long)ucp - 4);
          ucp += 4;
          *ucp++ = 0x58; /* popl %eax   ; restore original return value */
          *ucp++ = 0xff; /* jmp *store  ; jump to original return address */
          *ucp++ = 0x25;
          *(SshUInt32 *)ucp = (unsigned long)&sub->scratch[90];
          ucp += 4;
          break;

        default:
          printf("ssh_attach_substitutions: bad type %d\n", sub->type);
          splx(x);
          return;
        }

      /* Modify the original function to jump to the scratch code. */
      origcode[0] = 0xe9; /* Jump with 32-bit displacement. */
      *(SshUInt32 *)&origcode[1] = ((unsigned long)scratchcode -
                                    (unsigned long)&origcode[5]);
    }

  splx(x);
}

#if SSH_NetBSD == 200
void ssh_detach_ifioctl(void)
#else /* SSH_NetBSD == 200 */
void ssh_detach_substitutions()
#endif /* SSH_NetBSD == 200 */
{
  int x;
  SshAttachRec *sub;

  x = splhigh();

  /* Loop over all substitutions. */
  for (sub = ssh_get_substitutions(); sub->type != SSH_ATTACH_END; sub++)
    {
      /* Restore the saved original code. */
      memcpy(sub->original, sub->scratch, 8);
    }

  splx(x);
}

#endif /* SSH_NetBSD < 300 */
