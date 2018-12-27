/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   icept_vxworks.h
*/

#ifndef ICEPT_VXWORKS_H
#define ICEPT_VXWORKS_H

#include "ipsec_params.h"
#include <engine.h>
#include "interceptor.h"
#include <end.h>
#include <endLib.h>

/* Store mbufs to a ring buffer when the driver is temporarily out
   of data transmit resources, increase this value to better reflect
   the amount of memory blocks in the system, also avoid storing
   too old packets if the driver is really jammed. The equation
   to set this value should have the NUM_NET_MBLKS from netBufLib.h
   and the network adapter speed divided by some coefficient. */

#ifndef NUM_NET_MBLKS
# ifdef NUM_DAT_MBLKS
#  define NUM_NET_MBLKS NUM_DAT_MBLKS
# endif
#endif

typedef struct SshVxInterfaceRec
{
  struct ifnet *ifp;
  END_OBJ *end;
  void *mux_cookie;
  int (*old_if_output)(struct ifnet *, struct mbuf *, struct sockaddr *,
		       struct rtentry *);
#ifdef DEBUG_LIGHT
  int icept_from_network;
  int icept_from_protocol;
#endif /* DEBUG_LIGHT */
#ifdef VIRTUAL_STACK
  unsigned int vsNum;
#endif /* VIRTUAL_STACK */
} SshVxInterfaceStruct, *SshVxInterface;

#ifdef VIRTUAL_STACK
extern SshVxInterface ssh_vx_interfaces_per_vs[VSNUM_MAX];
#define SSH_VX_INTERFACE(stack,idx) (&ssh_vx_interfaces_per_vs[stack][idx])
#else /* VIRTUAL_STACK */
extern SshVxInterface ssh_vx_interfaces;
#define SSH_VX_INTERFACE(stub,idx) (&ssh_vx_interfaces[idx])
#endif /* VIRTUAL_STACK */
extern int ssh_vx_interfaces_num;

/* finds the pCookie based on the end pointer */
void *ssh_interceptor_find_vx_end_node(END_OBJ *pEnd);

/* Initialize the character special device */
int ssh_vx_dev_init(const char *devname);

/* Uninitialize the character special device */
int ssh_vx_dev_uninit(const char *devname);

/* ssh_icept_attach_interface_vxworks - This function attaches an
   interface of type struct ifnet *, from if.h, to the SSH IPSEC
   interceptor, returns TRUE on success, FALSE on failure */
extern Boolean ssh_icept_attach_interface_vxworks(struct ifnet *ifp);

/* Scan OS interface list and try attaching interfaces that are not
   already attached. */
void ssh_vxworks_attach_interfaces(void);

#ifdef VIRTUAL_STACK
typedef struct SshVxEngineRec
{
  struct SshVxEngineRec *next;
  const void *machine_context;
  SshEngine engine;
} *SshVxEngine;
extern SshVxEngine ssh_engines;
#define SSH_ENGINE_BY_MACHINE_CONTEXT(mc) ssh_engine_by_mc(mc)

static
#ifdef __GNUC__
__attribute__((__unused__))
#endif /* __GNUC__ */
SshEngine ssh_engine_by_mc(const void *mc)
{
  SshVxEngine vxe = ssh_engines;
  while (vxe)
    {
      if (vxe->machine_context == mc)
	return vxe->engine;

      vxe = vxe->next;
    }
  return NULL;
}
#else /* VIRTUAL_STACK */
extern SshEngine ssh_engine;
#define SSH_ENGINE_BY_MACHINE_CONTEXT(ignored) (ssh_engine)
#endif /* VIRTUAL_STACK */
extern Boolean ssh_send_to_ipm(unsigned char* data, size_t len,
                               Boolean reliable, void* machine_context);

/* init / uninit kernel timeouts */
void ssh_vx_kernel_timeout_init(void);
void ssh_vx_kernel_timeout_uninit(void);

/* The VxWorks platform specific init function */
void ssh_vxworks_interceptor_open(void);

/* Initialize/uninitialize virtual adapter interfaces. */
void ssh_vxworks_virtual_adapter_init(void);
void ssh_vxworks_virtual_adapter_uninit(void);

#ifdef VXWORKS_IPV6
void ssh_vx_set_ext_size(struct mbuf *m);
Boolean shh_create_if_change_notifier(void);
Boolean shh_delete_if_change_notifier(void);
#endif

int ssh_netjob_synchronous_invoke(FUNCPTR function, void *context);

/* If this function was invoked in context of task other than
   tNetTask, this contruct will switch to execute code in nettask.
   Different macros are provided according to number of arguments. */
#define SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function,\
                                            struct_assign, \
                                            ret) \
  while (ssh_net_id != taskIdSelf()) \
    { \
      struct this_function##_invoke_context myctx; \
      struct_assign; \
      if (ssh_netjob_synchronous_invoke(this_function##_invoke_helper, \
                                        &myctx) == 0) return ret; \
      taskDelay(1); \
    }

#define SSH_COND_SWITCH_TO_NETTASK_P0_R(this_function, ret) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, do { } while(0), myctx.r)

#define SSH_COND_SWITCH_TO_NETTASK_P0(this_function) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, do { } while(0),)

#define SSH_COND_SWITCH_TO_NETTASK_P1(this_function,t1,a1) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;,)

#define SSH_COND_SWITCH_TO_NETTASK_P2(this_function,t1,a1,t2,a2) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;myctx.p2=a2;,)

#define SSH_COND_SWITCH_TO_NETTASK_P3(this_function,t1,a1,t2,a2,t3,a3) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;myctx.p2=a2;myctx.p3=a3;,)

#define SSH_COND_SWITCH_TO_NETTASK_P4(this_function,t1,a1,t2,a2,t3,a3,t4,a4)\
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;myctx.p2=a2;myctx.p3=a3;myctx.p4=a4;,)

#define SSH_COND_SWITCH_TO_NETTASK_P4_R(this_function,t1,a1,t2,a2,t3,a3,t4,a4)\
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;myctx.p2=a2;myctx.p3=a3;myctx.p4=a4;, myctx.r)

#define SSH_COND_SWITCH_TO_NETTASK_P5(this_function,t1,a1,t2,a2,t3,a3,\
                                      t4,a4,t5,a5) \
  SSH_COND_SWITCH_TO_NETTASK_INTERNAL(this_function, \
    myctx.p1=a1;myctx.p2=a2;myctx.p3=a3;myctx.p4=a4;myctx.p5=a5;,)

/* This macro constructs "function call adapter" required by
   SSH_COND_SWITCH_TO_NETTASK_* */
#define SSH_COND_SWITCH_HELPER_INTERNAL(this_function, ret_type, ret_assign, \
                                        struct_content, \
                                        arg_string, arg_invoke) \
ret_type this_function arg_string; \
struct this_function##_invoke_context { struct_content }; \
int this_function##_invoke_helper(int ctx, int s, int p3, int p4, int p5) \
  { \
    struct this_function##_invoke_context *myctxp = (void*)ctx; \
    ret_assign this_function arg_invoke; \
    semGive((SEMAPHORE*)s); \
    return 0; \
  }

#define SSH_COND_SWITCH_HELPER_P0_R(this_function, ret) \
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, ret, myctxp->r =, ret r;, \
                                  (void), ())

#define SSH_COND_SWITCH_HELPER_P0(this_function) \
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,\
                                  myctxp->stub = 1;, char stub;,(void),())

#define SSH_COND_SWITCH_HELPER_P1(this_function,t1,a1)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,,\
                                  t1 p1;, \
                                  (t1 a1),\
    (myctxp->p1))

#define SSH_COND_SWITCH_HELPER_P2(this_function,t1,a1,t2,a2)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,,\
                                  t1 p1; t2 p2;, \
                                  (t1 a1,t2 a2),\
    (myctxp->p1, myctxp->p2))

#define SSH_COND_SWITCH_HELPER_P3(this_function,t1,a1,t2,a2,t3,a3)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,,\
                                  t1 p1; t2 p2; t3 p3;, \
                                  (t1 a1,t2 a2,t3 a3),\
    (myctxp->p1, myctxp->p2, myctxp->p3))

#define SSH_COND_SWITCH_HELPER_P4(this_function,t1,a1,t2,a2,t3,a3,t4,a4)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,,\
                                  t1 p1; t2 p2; t3 p3; t4 p4;, \
                                  (t1 a1,t2 a2,t3 a3,t4 a4),\
    (myctxp->p1, myctxp->p2, myctxp->p3, myctxp->p4))

#define SSH_COND_SWITCH_HELPER_P4_R(this_function,ret,t1,a1,t2,a2,t3,a3,t4,a4)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, ret, myctxp->r =,\
                                  t1 p1; t2 p2; t3 p3; t4 p4; ret r;, \
                                  (t1 a1,t2 a2,t3 a3,t4 a4),\
    (myctxp->p1, myctxp->p2, myctxp->p3, myctxp->p4))

#define SSH_COND_SWITCH_HELPER_P5(this_function,t1,a1,t2,a2,t3,a3,t4,a4,t5,a5)\
  SSH_COND_SWITCH_HELPER_INTERNAL(this_function, void,,\
                                  t1 p1; t2 p2; t3 p3; t4 p4; t5 p5;, \
                                  (t1 a1,t2 a2,t3 a3,t4 a4,t5 a5),\
    (myctxp->p1, myctxp->p2, myctxp->p3, myctxp->p4, myctxp->p5))

#endif /* ICEPT_VXWORKS_H */
