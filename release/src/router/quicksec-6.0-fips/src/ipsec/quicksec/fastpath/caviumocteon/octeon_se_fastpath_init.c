/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file implements the SE fastpath initialization routines.
*/

#include "octeon_se_fastpath_internal.h"


/** Shared fastpath object. */
CVMX_SHARED SeFastpath shared_fastpath = NULL;

/** Shared variable for control group. */
CVMX_SHARED int octeon_se_fastpath_control_grp =
  OCTEON_SE_FASTPATH_CONTROL_GROUP;

/** Shared variable for the Octeon cpu number. */
CVMX_SHARED int octeon_se_fastpath_cpu_num = 0;

/** Flag for checking when to break out of the main loop. */
CVMX_SHARED int octeon_se_fastpath_run = 1;

/** Flag for checking when to break out of the packet process loop. */
CVMX_SHARED int octeon_se_fastpath_process = 0;

/** Has shared init been done. */
CVMX_SHARED int octeon_se_fastpath_shared_init_done = 0;

/** Core local object. */
static SeFastpathCoreContextStruct core[1];

/** Core local fastpath variable. */
static SeFastpath fastpath = NULL;

/************************ Control wqe handling ******************************/

static int
octeon_se_fastpath_shared_init()
{
  cvmx_bootmem_named_block_desc_t *bootmem_block;

  OCTEON_SE_DEBUG(5, "Performing global shared init\n");

  /* Fetch shared fastpath object from shared memory. */
  bootmem_block =
    cvmx_bootmem_find_named_block(OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
  if (bootmem_block == NULL)
    {
      OCTEON_SE_DEBUG(3, "Could not fetch bootmem block for \"%s\"\n",
                      OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
      return -1;
    }

  if (bootmem_block->size < sizeof(SeFastpathStruct))
    {
      OCTEON_SE_DEBUG(3, "Bootmem block \"%s\" is too small\n",
                      OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
      return -1;
    }
  OCTEON_SE_ASSERT(shared_fastpath == NULL);
  shared_fastpath = (SeFastpath) cvmx_phys_to_ptr(bootmem_block->base_addr);

  /* Copied from OCTEON SDK linux_filter.c example:

     We need to call cvmx_cmd_queue_initialize() to get the pointer to
     the named block. The queues are already setup by the ethernet
     driver, so we don't actually need to setup a queue. Pass some
     invalid parameters to cause the queue setup to fail */
  cvmx_cmd_queue_initialize(0, 0, -1, 0);
#if CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES
#error "SE fastpath cannot be built with CVMX_PKO_USE_FAU_FOR_OUTPUT_QUEUES"
#endif

  return 0;
}

static void
octeon_se_fastpath_control_callback(cvmx_wqe_t *wqe)
{
  uint64_t core_num;
  cvmx_sysinfo_t *sysinfo;
  unsigned int se_fastpath_coremask;
  SeFastpathControlCmd ctrl;

  sysinfo = cvmx_sysinfo_get();
  se_fastpath_coremask = sysinfo->core_mask;

  OCTEON_SE_ASSERT(wqe->grp == core->control_grp);
  ctrl = (SeFastpathControlCmd) wqe->packet_data;

  if (ctrl->cmd == OCTEON_SE_FASTPATH_CONTROL_CMD_ENABLE)
    {
      OCTEON_SE_DEBUG(3, "Enabling SE fastpath %d, coremask %x\n",
                      octeon_se_fastpath_cpu_num, se_fastpath_coremask);

      /* Perform delayed initialization of shared variables now,
         as it is guaranteed that the hw is properly initialized
         at this stage. */
      if (octeon_se_fastpath_shared_init_done == 0)
        {
          if (octeon_se_fastpath_shared_init() != 0)
            goto out;

          octeon_se_fastpath_shared_init_done = 1;
        }

      /* Start packet processing loop */
      octeon_se_fastpath_process = 1;

      /* Accept work from packet and deschedule groups on all cores
         running the SE fastpath. */
      for (core_num = 0; core_num < CVMX_MAX_CORES; core_num++)
        {
          if (se_fastpath_coremask & (1 << core_num))
            {
              if (core_num == cvmx_get_core_num())
                cvmx_pow_set_group_mask(core_num,
                                        (1<< core->control_grp)
                                        | (1<<OCTEON_SE_FASTPATH_DESCHED_GROUP)
                                        | (1<<OCTEON_SE_FASTPATH_PKT_GROUP));
              else
                cvmx_pow_set_group_mask(core_num,
                                        (1<<OCTEON_SE_FASTPATH_DESCHED_GROUP)
                                        | (1<<OCTEON_SE_FASTPATH_PKT_GROUP));
            }
        }
    }

  else if (ctrl->cmd == OCTEON_SE_FASTPATH_CONTROL_CMD_DISABLE)
    {
      OCTEON_SE_DEBUG(3, "Disabling SE fastpath %d\n",
                      octeon_se_fastpath_cpu_num);

      /* Stop packet processing loop */
      octeon_se_fastpath_process = 0;

      /* Allow only the first core to accept work from packet and
         deschedule groups. This is done to ensure that other cores
         (which may still be waiting for work inside the packet processing
         loop) will time out and step out of the packet processing loop.
         The first core is already out of the packet processing loop, since
         it is running this piece of code here. */
      for (core_num = 0; core_num < CVMX_MAX_CORES; core_num++)
        {
          if (se_fastpath_coremask & (1 << core_num))
            {
              if (core_num == cvmx_get_core_num())
                cvmx_pow_set_group_mask(core_num,
                                        (1<< core->control_grp)
                                        | (1<<OCTEON_SE_FASTPATH_DESCHED_GROUP)
                                        | (1<<OCTEON_SE_FASTPATH_PKT_GROUP));
              else
                cvmx_pow_set_group_mask(core_num, 0);
            }
        }
    }

  else if (ctrl->cmd == OCTEON_SE_FASTPATH_CONTROL_CMD_STOP)
    {
      OCTEON_SE_DEBUG(3, "SE fastpath %d exiting\n",
                      octeon_se_fastpath_cpu_num);

      /* Stop packet processing loop */
      octeon_se_fastpath_process = 0;

      /* Re-initialize on next ENABLE. */
      octeon_se_fastpath_shared_init_done = 0;
    }

 out:
  cvmx_helper_free_packet_data(wqe);
  cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
}


/************************* Work multiplexing ********************************/

static inline void
octeon_se_fastpath_submit_to_slowpath(SeFastpathCoreContext core,
                                      SeFastpath fastpath,
                                      cvmx_wqe_t *wqe)
{
  SeFastpathControlCmd ctrl;

  OCTEON_SE_CORE_STATS({
    if (core->stats != NULL)
      core->stats->pkt_slow++;
  });

  OCTEON_SE_DEBUG(9, "Submitting packet to slowpath\n");

  /* Encode tunnel_id and previous_transform_index to wqe */
  ctrl = (SeFastpathControlCmd) wqe->packet_data;
  memset(ctrl, 0, sizeof(*ctrl));
  ctrl->cmd = OCTEON_SE_FASTPATH_CONTROL_CMD_SLOW;
  ctrl->tunnel_id = 0;
  ctrl->prev_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;

  /* Submit to _SLOWPATH_GROUP. Use normal prio queue indexed by input port. */
  cvmx_pow_work_submit(wqe,
                       OCTEON_SE_FASTPATH_SLOWPATH_TAG(wqe->ipprt),
                       CVMX_POW_TAG_TYPE_ORDERED,
                       OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE(wqe->ipprt),
                       OCTEON_SE_FASTPATH_SLOWPATH_GROUP);
}

static inline void
octeon_se_fastpath_main_loop()
{
  cvmx_wqe_t *wqe;

  OCTEON_SE_DEBUG(5, "SE fastpath %d mainloop starting\n",
                  octeon_se_fastpath_cpu_num);

  while (octeon_se_fastpath_run)
    {
      /* Wait for work entries */
      wqe = cvmx_pow_work_request_sync(CVMX_POW_WAIT);

      /* Process control work entries */
      if (cvmx_unlikely(wqe != NULL && wqe->grp == core->control_grp))
        {
          octeon_se_fastpath_control_callback(wqe);
          wqe = NULL;
        }

      /* Check if need to perform per core local variable initialization
         now that shared init has been done. */
      if (cvmx_unlikely(octeon_se_fastpath_process
                        && octeon_se_fastpath_shared_init_done))
        {
          OCTEON_SE_DEBUG(5, "Performing local shared init\n");
          fastpath = shared_fastpath;
          core->salt = fastpath->salt;
#ifdef OCTEON_SE_FASTPATH_COLLECT_CORE_STATS
          core->stats =&fastpath->core_stats[(core->core_num +
                                              (octeon_se_fastpath_cpu_num *
                                               CVMX_MAX_CORES))].s;
#endif /* OCTEON_SE_FASTPATH_COLLECT_CORE_STATS */
        }

      /* SE fastpath is enabled, enter packet processing main loop */
      while (octeon_se_fastpath_process)
        {
          /* Wait for work entries. */
          if (cvmx_likely(wqe == NULL))
            wqe = cvmx_pow_work_request_sync(CVMX_POW_WAIT);

          if (cvmx_unlikely(wqe == NULL))
            continue;

          if (cvmx_unlikely(wqe->grp == core->control_grp))
            octeon_se_fastpath_control_callback(wqe);

          else if (cvmx_likely(wqe->grp == OCTEON_SE_FASTPATH_DESCHED_GROUP
                               || wqe->grp == OCTEON_SE_FASTPATH_PKT_GROUP))
            {
#ifdef OCTEON_SE_FASTPATH_DEBUG
              /* Assert that wqe was scheduled with ATOMIC tag. */
              if (wqe->grp == OCTEON_SE_FASTPATH_DESCHED_GROUP)
                OCTEON_SE_ASSERT(wqe->tag_type == CVMX_POW_TAG_TYPE_ATOMIC);
              /* Assert that shared init has been performed. */
              OCTEON_SE_ASSERT(fastpath != NULL);
#endif /* OCTEON_SE_FASTPATH_DEBUG */

              octeon_se_fastpath_packet_callback(core, fastpath, wqe);
            }

          else
            {
              OCTEON_SE_FORCE_DEBUG("Received work for group %d, dropping\n",
                                    wqe->grp);
              cvmx_helper_free_packet_data(wqe);
              cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
            }

          wqe = NULL;
        }

      /* SE fastpath is disabled, submit everything to slowpath */
      if (wqe != NULL)
        {
          OCTEON_SE_ASSERT(wqe->grp != core->control_grp);
          octeon_se_fastpath_submit_to_slowpath(core, fastpath, wqe);
        }
    }

  OCTEON_SE_DEBUG(5, "SE fastpath %d mainloop exiting\n",
                  octeon_se_fastpath_cpu_num);
}


/************************* Initialization ***********************************/

static int
octeon_se_fastpath_global_init()
{
  OCTEON_SE_DEBUG(5, "Performing global init\n");

  octeon_se_fastpath_run = 1;

  /* Initialize random number generator */
  cvmx_rng_enable();

  return 0;
}

static int
octeon_se_fastpath_local_init(int first_core)
{
  uint64_t core_num = cvmx_get_core_num();

  OCTEON_SE_DEBUG(5, "Performing local init\n");

  memset(core, 0, sizeof(core));
  core->core_num = (uint32_t) core_num;
  core->control_grp = octeon_se_fastpath_control_grp;

  /* Enable work scheduling for control, packet and deschedule groups
     for the first core only. */
  if (first_core)
    {
      cvmx_pow_set_group_mask(core_num,
                              (1 << core->control_grp)
                              | (1 << OCTEON_SE_FASTPATH_DESCHED_GROUP)
                              | (1 << OCTEON_SE_FASTPATH_PKT_GROUP));
    }
  else
    {
      cvmx_pow_set_group_mask(core_num, 0);
    }

  return 0;
}

int main(int argc, char **argv)
{
  cvmx_sysinfo_t *sysinfo;
  unsigned int se_fastpath_coremask;
  int first_core = 0;
  int i;

  cvmx_user_app_init();

  /* Parse arguments. */
  for (i = 0; i < argc; i++)
    {
      if (strcmp(argv[i], "-se_fastpath_0") == 0)
        {
          octeon_se_fastpath_control_grp = OCTEON_SE_FASTPATH_CONTROL_GROUP;
          octeon_se_fastpath_cpu_num = 0;
        }
      else if (strcmp(argv[i], "-se_fastpath_1") == 0)
        {
#if (OCTEON_SE_FASTPATH_MAX_NUM_CPUS >= 2)
          octeon_se_fastpath_control_grp = OCTEON_SE_FASTPATH_CONTROL_GROUP1;
          octeon_se_fastpath_cpu_num = 1;
#else /* (OCTEON_SE_FASTPATH_MAX_NUM_CPUS >= 2) */
          OCTEON_SE_DEBUG(3, "This build supports only one SE fastpath.\n");
          return -1;
#endif /* (OCTEON_SE_FASTPATH_MAX_NUM_CPUS >= 2) */
        }
    }

  OCTEON_SE_DEBUG(3, "SE fastpath %d Starting\n", octeon_se_fastpath_cpu_num);

  /* Perform global init. Only first core needs to do this. */
  sysinfo = cvmx_sysinfo_get();
  se_fastpath_coremask = sysinfo->core_mask;
  if (cvmx_coremask_first_core(se_fastpath_coremask))
    {
      if (octeon_se_fastpath_global_init() != 0)
        return -1;
      first_core = 1;
    }
  cvmx_coremask_barrier_sync(se_fastpath_coremask);

  /* Perform local init on all cores. */
  if (octeon_se_fastpath_local_init(first_core) != 0)
    return -1;

  cvmx_coremask_barrier_sync(se_fastpath_coremask);

  /* Run fastpath main loop */
  octeon_se_fastpath_main_loop();





  cvmx_coremask_barrier_sync(se_fastpath_coremask);

  return 0;
}
