/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Safenet Look-Aside Accelerator Packet Engine Interface implementation
   for SafeXcel chips with the use of the PEC APIs.
*/

#include "sshincludes.h"
#include "ipsec_params.h"
#include "kernel_mutex.h"

#include "safenet_pe.h"
#include "safenet_la_params.h"
#include "safenet_pe_utils.h"

#include "api_dmabuf.h"
#include "api_pec.h"

#if defined(SAFENET_PE_PLATFORM_1742)
#include "safenet_pe_pec.h"
#elif defined(SAFENET_PE_PLATFORM_1746)
#include "safenet_pe_pec.h"
#else
#error "Safenet Packet Engine API platform is not defined !!!"
#endif /* SAFENET_PE_PLATFORM_1742 */


/******** Debug stuff ***********/
#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshSafenetPePec"

/*  Move them to appropriate place */
#define SAFENETPEC_MAX_HANDLES SSH_ENGINE_MAX_TRANSFORM_CONTEXTS

static PEC_CommandDescriptor_t Descriptors[2 * SSH_SAFENET_PDR_GET_COUNT];
static PEC_ResultDescriptor_t ResultDescriptors[2 * SSH_SAFENET_PDR_GET_COUNT];

/*  Globals */

typedef struct SafenetPECDeviceCB
{
  void (*CBFunc)(unsigned int);
  uint32_t PacketPutCount;
} SafenetPECDeviceCB_t;

static SafenetPECDeviceCB_t SafenetPEC_Callbacks[PE_MAX_DEVICES];

typedef struct
{
  DMABuf_HostAddress_t SA_HostAddr;
  DMABuf_Handle_t SAHandle;
  size_t SA_Size;
  DMABuf_HostAddress_t Srec_HostAddr;
  DMABuf_Handle_t SrecHandle;
  size_t SRecSize;
} SafenetPEC_SARecord_t;

#ifndef SSH_SAFENET_POLLING
static void
SafenetPEC_CBFunc(void)
{
  SafenetPEC_Callbacks[0].CBFunc(0);
}
#endif

/*----------------------------------------------------------------------------
 * safenet_pe_uninit
 *
 * Accelerator-specific de-initialization function.
 */
void
safenet_pe_uninit(SshUInt32 device_num)
{
  PEC_UnInit();

  SSH_DEBUG(SSH_D_LOWOK, ("safenet_pe_uninit PEC un-initialized."));
}

/*----------------------------------------------------------------------------
 * safenet_pe_init
 *
 * Accelerator-specific initialization function.
 * Finds all accelerators, builds corresponding init blocks and initializes
 * the driver.
 *
 * device_callbacks - an array of glue layer callback functions, which should
 * be called when packets are processed by the Packet Engine and ready to be
 * received.
 *
 * device_count - as input is an expected number of accelerator devices and
 * the size of the device_callbacks[]. This value should be big enough to
 * possibly provide callbacks for a maximum number of devices.
 *
 * device_count - as output is a number of actually found accelerator devices.
 */
Boolean
safenet_pe_init(PE_DEVICE_INIT device_init[],
		SshUInt32 *device_count)
{
  SshUInt32 i;
  PEC_InitBlock_t initblock;
  PEC_Status_t status;
  PEC_Capabilities_t capabilities;

  SSH_ASSERT(device_init != NULL);
  SSH_ASSERT(device_count != NULL);

  if (*device_count  < 1)
    return FALSE;

  SSH_ASSERT(*device_count <= PE_MAX_DEVICES);

  for (i = 0; i < *device_count; i++)
    {
      device_init[i].found = false;
      device_init[i].device_number = i;
      SafenetPEC_Callbacks[i].CBFunc =
	(void *)device_init[i].device_callback.callback;
      SafenetPEC_Callbacks[i].PacketPutCount = 0;
    }

  *device_count = 0;
  initblock.fUseDynamicSA = false;
  if ((status = PEC_Init(&initblock)) == PEC_STATUS_OK)
    {
      device_init[0].found = true;
      device_init[0].device_number = 0;
      *device_count = 1;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_init PEC_Init failed, status=%d", status));
      return FALSE;
    }

  status = PEC_Capabilities_Get(&capabilities);

  if (status != PEC_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_init PEC_capabilities_Get failed, status = %d",
		 status));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK,
	    ("safenet_pe_init: \n"
	     "Packet engine capabilities info - %s\n",
	     capabilities.szTextDescription));

#ifndef SSH_SAFENET_POLLING
  PEC_ResultNotify_Request((PEC_NotifyFunction_t)SafenetPEC_CBFunc,1);
#endif

  SSH_DEBUG(SSH_D_LOWOK,( "safenet_pe_init: PEC sucessfully initialized."));

  return TRUE;
}

/* ---------------------------------------------------------------------------
 * safenet_pe_build_sa
 *
 * Allocates memory and builds SAs and related data for AH or ESP transforms
 *
 * type        - in: for which transforms to build the SA (AH, ESP)
 * flags     - in: transform options for building the SA
 * sa_params - in: parameters for building the SA (algorithms, keys,
 other items), see PE_SA_PARAMS
 * sa_data   - out: pointer to a memory block with initialized SA data
 */
Boolean
safenet_pe_build_sa(int device_num, PE_SA_TYPE type, PE_FLAGS flags,
		    PE_SA_PARAMS *sa_params, void **sa_data)
{
  PEC_Status_t status;
  DMABuf_Properties_t requestedpropsa, requestedpropsrec;
  DMABuf_Handle_t null_handle1 = { 0 };
  DMABuf_Handle_t localsahandle = { 0 };
  DMABuf_Handle_t localsrechandle = { 0 };
  DMABuf_HostAddress_t sabuffer, srecbuffer;
  DMABuf_Status_t dmastatus;
  SafenetPEC_SARecord_t *sarecord = NULL;
  uint32_t seq;

  SSH_ASSERT(sa_data != NULL);

  /* we have to decrement seq because Packet Engine
     initially increments the received initial value of the sequence number
     for Outbound transforms
     so we have to compensate for that initial increment */
  seq = (sa_params->seq > 0) ? sa_params->seq - 1 : 0;

  *sa_data = NULL;

  sarecord = ssh_kernel_alloc(sizeof(SafenetPEC_SARecord_t),
				SSH_KERNEL_ALLOC_NOWAIT);
  if (sarecord == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_build_sa: SafenetPEC_SARecord_t"
		 " allocation FAILED"));
      return FALSE;
    }

  /*  Fill properties for SA */
  requestedpropsa.Size = sizeof (SafenetPEC_SA_t);
  requestedpropsa.Alignment = 4;
  requestedpropsa.Bank = 0;
  requestedpropsa.fCached = true;

  /*  Fill properties for state record */
  requestedpropsrec.Size = sizeof(SafenetPEC_StateRecord_t);
  requestedpropsrec.Alignment = 4;
  requestedpropsrec.Bank = 0;
  requestedpropsrec.fCached = true;

  /*  Allocate DMA buffer for SA and state record. */
  dmastatus = DMABuf_Alloc(requestedpropsa, &sabuffer, &localsahandle);
  if (dmastatus != DMABUF_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_build_sa: SA allocation FAILED. "
		 "DMABuf_Alloc status %d",
		 dmastatus));
      goto fail;
    }

  dmastatus = DMABuf_Alloc(requestedpropsrec, &srecbuffer, &localsrechandle);
  if (dmastatus != DMABUF_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_build_sa: SRec allocation FAILED. "
		 "DMABuf_Alloc status %d",
		 dmastatus));
      goto fail;
    }

  /* Fill SA */
  memset (sabuffer.p, 0x0, sizeof(SafenetPEC_SA_t));
  memset (srecbuffer.p, 0x0, sizeof(SafenetPEC_StateRecord_t));

  /*  Implement safenet_pe_populate_sa */
  if (SafenetPEC_PopulateSA(type, flags, sabuffer.p, srecbuffer.p,
			    sa_params->spi, seq, sa_params->hash_alg,
			    sa_params->ciph_alg, sa_params->ciph_key,
			    sa_params->ciph_key_len, sa_params->mac_key,
			    sa_params->mac_key_len, sa_params->esp_iv,
			     sa_params->esp_ivlen) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,("safenet_pe_build_sa: Failed to populate SA."));
      goto fail;
    }

  /*  register SA and state record. */
  status = PEC_SA_Register(localsahandle, localsrechandle, null_handle1);
  if (status != PEC_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,("safenet_pe_build_sa : "
			    " PEC_SA_Register failed with error %x",
			    status));
      goto fail;
    }

  /*  Get a valid handle for storing SA and state record's
      DMA buffer pointers and handles.*/
  memset (sarecord, 0x0, sizeof(SafenetPEC_SARecord_t));
  sarecord->SA_HostAddr = sabuffer;
  sarecord->Srec_HostAddr = srecbuffer;
  sarecord->SA_Size = sizeof(SafenetPEC_SA_t);
  sarecord->SAHandle = localsahandle;
  sarecord->SrecHandle = localsrechandle;
  sarecord->SRecSize = sizeof(SafenetPEC_StateRecord_t);

  *sa_data = sarecord;

  SSH_DEBUG(SSH_D_LOWOK,("safenet_pe_build_sa successfully installed SA "));
  return TRUE;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_build_sa FAILED!"));

  if (localsahandle.p)
    DMABuf_Release(localsahandle);

  if (localsrechandle.p)
    DMABuf_Release(localsrechandle);

  if (sarecord)
    ssh_kernel_free(sarecord);

  return FALSE;
}


/*---------------------------------------------------------------------------
 * safenet_pe_destroy_sa
 *
 * Frees any memory allocated with safenet_pe_build_sa for SAs and related
 * data for AH or ESP transforms
 *
 * sa_data - in: pointer to a memory block with SA data
 */
void
safenet_pe_destroy_sa(const void *sa_data)
{
  PEC_Status_t status;
  DMABuf_Handle_t null_handle1 = { 0 };
  SafenetPEC_SARecord_t *sarecord = (SafenetPEC_SARecord_t *)sa_data;

  SSH_ASSERT(sarecord != NULL);

  if (sarecord == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_destroy_sa: Invalid SA handle received."));
      return;
    }

  /* Unregister SA and state record. */
  status = PEC_SA_UnRegister(sarecord->SAHandle, sarecord->SrecHandle,
			     null_handle1);
  if (status != PEC_STATUS_OK)
    SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa"
			  " PEC_SA_Unregister failed with error %x",
			  status));

  /* Release the SA and state record handles allocated during
     safenet_pe_build_sa */
  status = DMABuf_Release(sarecord->SAHandle);
  if (status != PEC_STATUS_OK)
    SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa"
			  " DMABuf_Release of SA failed with error %x",
			  status));

  status = DMABuf_Release(sarecord->SrecHandle);
  if (status != PEC_STATUS_OK)
    SSH_DEBUG(SSH_D_FAIL,("safenet_pe_destroy_sa : "
			  " DMABuf_Release of Srec failed with error %x",
			  status));

  ssh_kernel_free(sarecord);

  SSH_DEBUG(SSH_D_LOWOK,("safenet_pe_destroy_sa: destroyed SA."));
}


#if defined(SAFENET_PE_PLATFORM_1746)
/*----------------------------------------------------------------------------
 * SafenetPEC_PEPacketDescr_BlockSize_Sanity_Check
 *
 *Checks a if a inbound packet could be decapsulated with current selected
 algorithms. !Only checked for esp inbound AES_CBC or (3)DES_CBC!

 pkt - in: pointer to a PE_PKT_DESCRIPTOR.

 Return: False when encrypted payload not a multiple of algorithms.
*/
static Boolean
SafenetPEC_PEPacketDescr_BlockSize_Sanity_Check(PE_PKT_DESCRIPTOR *pkt)
{
  size_t block_size;

  /* ESP and inbound AES-CBC or (3)DES-CBC*/
  if ((pkt->flags & PE_FLAGS_ESP) &&
      !(pkt->flags & PE_FLAGS_OUTBOUND) &&
      (pkt->flags & (PE_FLAGS_AES_CBC | PE_FLAGS_DES_CBC)))
    {
      block_size = (pkt->flags & PE_FLAGS_AES_CBC)? 16 : 8;

      if ((pkt->src_len-pkt->iv_size-8-pkt->icv_size) & (block_size-1))
        {
	  SSH_DEBUG(SSH_D_FAIL,("Inbound blocksize error prevention: "
				"pkt->src_len:0x%x "
				"pkt->iv_size:0x%x "
				"pkt->icv_size:0x%x "
				"block_size:0x%x",
				pkt->src_len,pkt->iv_size,
				pkt->icv_size,block_size));
	  return FALSE;
        }
    }

  return TRUE;
}
#endif /* SAFENET_PE_PLATFORM_1746 */

/*----------------------------------------------------------------------------
 * safenet_pe_pktput
 *
 * Use this to put a packet to be processed to the Packet Engine
 * pkt is a points to a PE_PKT_DESCRIPTOR object for the packet
 * to be sent to the Packet Engine for processing.
 *
 * Returns a number of packets sucessfully sent to the Packet Engine.
 */
int
safenet_pe_pktput(int device_num, PE_PKT_DESCRIPTOR pkt[], SshUInt32 count)
{
  PEC_Status_t status;
  int i;
  int packetdone = 0;

  SSH_ASSERT(pkt != NULL && count > 0);
  SSH_DEBUG(SSH_D_HIGHOK,
	    ("safenet_pe_pktput: Try to put %d packets ", count));

  for (i = 0; i < count; i++)
    {
      SafenetPEC_SARecord_t *SA_p = pkt[i].sa_data;

      SSH_ASSERT(SA_p != NULL);

      /*  Fill PEC command descriptors for each packet received. */
      if (!SafenetPEC_PEPacketDescr_To_PECCommandDescr(&Descriptors[i],
						       &pkt[i],
						       SA_p->SAHandle,
						       SA_p->SA_Size,
						       SA_p->SrecHandle)
	  )
        {
	  SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: "
				 "Could not convert packet %d/%d.",
				 i, count));

          /* the packet causing the error may not be freed since it
             has not been been registered */
	  while (i > 0)
	    {
              i--;
              safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);
	    }

          return 0;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("safenet_pe_pktput: Converted %d packets.",
	     count));

  status = PEC_Packet_Put(Descriptors, count, &packetdone);
  if (status != PEC_STATUS_OK)
    {
      /* No packets should be sent if an error was set... */
      SSH_ASSERT(packetdone == 0);
      SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: "
			     "Failed to put packets, error %d.", status));

      for (i = 0; i < count; i++)
	safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);

      return 0;
    }
  else if (packetdone < count)
    {
      SSH_DEBUG(SSH_D_FAIL, ("safenet_pe_pktput: PACKET LOSS!.\n"
			     "PEC_Packet_Put: \n"
			     "Status = %d\n"
			     " PacketDone returned by PE - %d, "
			     " NumPackets sent to packet engine- %d\n",
			     status,
			     packetdone,
			     count));
      for (i = packetdone; i < count; i++)
	safenet_peccmddesc_free(Descriptors[i].DstPkt_Handle);
    }

  SSH_DEBUG(SSH_D_HIGHOK,
	    ("safenet_pe_pktput: Done putting %d packets.\n",
	     packetdone));

  return packetdone;
}

/*---------------------------------------------------------------------------
 *  safenet_pe_pktget
 *
 *  Use this to get completed packets from the Packet Engine
 *  The function returns PE_PKT_DESCRIPTOR objects in pkt if the
 *  packets were successfully processed by the Packet Engine and available for
 *  receiving.
 *
 *  pcount is an output parameter and is the number of packets received.
 *
 *  Returns FALSE if the packets cannot be received because of the Packet
 *  Engine  error
 */
Boolean
safenet_pe_pktget(int device_num, PE_PKT_DESCRIPTOR pkt[], SshUInt32 *count)
{
  PEC_Status_t status;
  int i;
  unsigned int resultlimit = SSH_SAFENET_PDR_GET_COUNT;

  SSH_ASSERT(pkt != NULL && count != NULL);

#ifndef SSH_SAFENET_POLLING
  PEC_ResultNotify_Request((PEC_NotifyFunction_t)SafenetPEC_CBFunc,1);
#endif

  *count = 0;
  status = PEC_Packet_Get(ResultDescriptors, resultlimit, (uint32_t *)count);
  if (status != PEC_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("safenet_pe_pktget: Failed to retrieve packets.\n"
		 "PEC_Packet_Get: \n"
		 "Status = %d\n"
		 " ResultCount returned by PE - %d, "
		 " ResultLimit sent to packet engine- %d\n",
		 status,
		 *count,
		 resultlimit));
      return FALSE;
    }

  if (*count > 0)
    SSH_DEBUG(SSH_D_HIGHOK,
	      ("safenet_pe_pktget: Done getting %d packets.\n",
	       *count));

  for (i = 0; i < *count; i++)
    {
      SafenetPEC_PECResultDescr_To_PEPacketDescr(&ResultDescriptors[i],
						 &pkt[i]);
    }

  return TRUE;
}
