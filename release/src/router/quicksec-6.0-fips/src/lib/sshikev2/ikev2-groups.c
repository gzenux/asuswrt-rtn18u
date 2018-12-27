/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Diffie-Hellman groups.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshIkev2Groups"

#ifdef SSHDIST_EXTERNALKEY
/* This callback is called when the acceleration of a group
   is finished. */
void ikev2_generate_acc_grp_cb(SshEkStatus status,
                               SshPkGroup accelerated_group,
                               void *context)
{
  SshIkev2EkGroupContext op = context;

  op->operation = NULL;

  if (status == SSH_EK_OK)
    {
      /* We got the accelerated group. Swap the groups so that all the
         subsequent operations use this accelerated group. */
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Group acceleration succeeded for group %d",
                 (int) op->group_number));

      op->old_pk_grp =
        ssh_adt_intmap_get(op->ikev2->group_intmap,
                           (SshUInt32) op->group_number);
      SSH_ASSERT(op->old_pk_grp != NULL);

      ssh_adt_intmap_set(op->ikev2->group_intmap,
                         (SshUInt32) op->group_number,
                         accelerated_group);
    }
  else
    {
      /* We did not manage to accelerate a group using the
         EK. Continue using the software group. */
      SSH_DEBUG(SSH_D_UNCOMMON, ("Could not accelerate group %d",
                                 (int) op->group_number));
    }
}

/* This callback is called when getting an extenalkey group is
   finished. */
void ikev2_get_grp_cb(SshEkStatus status,
                      SshPkGroup group,
                      void *context)
{
  SshIkev2EkGroupContext op = context;
  SshCryptoStatus cret;
  SshPkGroup pk_grp;

  op->operation = NULL;

  if (status == SSH_EK_OK)
    {
      /* We got the group. */
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Externalkey group retrieval succeeded for group %d",
                 (int) op->group_number));

      pk_grp = group;
    }
  else
    {
      /* We did not get an externalkey group. Initialize a software one. */
      SSH_DEBUG(SSH_D_UNCOMMON, ("Could not retrieve externalkey group %d",
                                 (int) op->group_number));
      cret = ssh_pk_group_generate(&pk_grp,
                                   ssh_ikev2_predefined_group_types
                                   [op->group_number],
                                   SSH_PKF_PREDEFINED_GROUP,
                                   ssh_ikev2_predefined_group_names
                                   [op->group_number],
                                   SSH_PKF_DH, "plain",
                                   SSH_PKF_RANDOMIZER_ENTROPY,
                                   (ssh_ikev2_predefined_group_strengths
                                    [op->group_number]
                                    * 5) >> 1,
                                   SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_UNCOMMON, ("Error %s when initializing group %d: %s",
                                     ssh_crypto_status_message(cret),
                                     (int) op->group_number,
                                     ssh_ikev2_predefined_group_names
                                     [op->group_number]));
          return;
        }
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Initialized software group %d", (int) op->group_number));
    }

  ssh_adt_intmap_add(op->ikev2->group_intmap,
                     (SshUInt32)op->group_number, pk_grp);

  /* Try fetching an accelerated group. */
  SSH_DEBUG(SSH_D_MIDRESULT,
            ("Starting to accelerate group %d: %s", (int) op->group_number,
             ssh_ikev2_predefined_group_names[op->group_number]));
  op->operation =
    ssh_ek_generate_accelerated_group(op->ikev2->params.external_key,
                                      op->ikev2->params.
                                      accelerator_short_name,
                                      pk_grp,
                                      ikev2_generate_acc_grp_cb,
                                      op);
}
#endif /* SSHDIST_EXTERNALKEY */

/* Initialize default groups. */
SshCryptoStatus
ikev2_groups_init(SshIkev2 ikev2)
{
  SshCryptoStatus cret;
  SshPkGroup pk_grp;
  int i;

  SSH_DEBUG(SSH_D_LOWSTART, ("Initializing groups"));
  for(i = 0; i < SSH_IKEV2_TRANSFORM_D_H_MAX; i++)
    {
      if (ssh_ikev2_predefined_group_names[i] == NULL)
        continue;
#ifdef SSHDIST_EXTERNALKEY
      /* Try getting the group, if we have externalkey configured. */
      if (ikev2->params.external_key &&
          ikev2->params.accelerator_short_name != NULL)
        {
          const char *sname = ikev2->params.accelerator_short_name;
          SshIkev2EkGroupContext op = NULL;
          char *gpath = NULL; /* short_name + "ike-n" + NULL */
          size_t gpath_size = strlen(sname) + 16;

          op = ssh_calloc(1, sizeof(*op));
          gpath = ssh_calloc(1, gpath_size);
          if (op == NULL || gpath == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Out of memory while trying to get group %d: %s",
                         i, ssh_ikev2_predefined_group_names[i]));
              if (op)
                ssh_free(op);
              if (gpath)
                ssh_free(gpath);
            }
          else
            {
              SSH_DEBUG(SSH_D_MIDRESULT,
                        ("Starting to get group %d: %s",
                         i, ssh_ikev2_predefined_group_names[i]));
              ssh_snprintf(gpath, gpath_size, "%sike-%d", sname, i);
              op->old_pk_grp = NULL;
              op->group_number = i;
              op->ikev2 = ikev2;
              op->next = ikev2->ek_group_contexts;
              ikev2->ek_group_contexts = op;
              op->operation =
                ssh_ek_get_group(ikev2->params.external_key,
                                 gpath,
                                 ikev2_get_grp_cb,
                                 op);
              ssh_free(gpath);
            }
        }
      else
#endif /* SSHDIST_EXTERNALKEY */
        {
          cret = ssh_pk_group_generate(&pk_grp,
                                       ssh_ikev2_predefined_group_types[i],
                                       SSH_PKF_PREDEFINED_GROUP,
                                       ssh_ikev2_predefined_group_names[i],
                                       SSH_PKF_DH, "plain",
                                       SSH_PKF_RANDOMIZER_ENTROPY,
                                       (ssh_ikev2_predefined_group_strengths[i]
                                        * 5) >> 1,
                                       SSH_PKF_END);
          if (cret != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(SSH_D_UNCOMMON, ("Error %s when initializing "
                                         "group %d: %s",
                                         ssh_crypto_status_message(cret),
                                         i,
                                         ssh_ikev2_predefined_group_names[i]));
              return cret;
            }
          ssh_adt_intmap_add(ikev2->group_intmap, (SshUInt32) i, pk_grp);
        }
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Successfully initialized groups"));
  return SSH_CRYPTO_OK;
}

/* Uninitialize default groups. */
void ikev2_groups_uninit(SshIkev2 ikev2)
{
  SshPkGroup pk_grp;
  SshADTHandle h;
  SshUInt32 id;
#ifdef SSHDIST_EXTERNALKEY
  SshIkev2EkGroupContext op,  prev_op;
#endif /* SSHDIST_EXTERNALKEY */

  SSH_DEBUG(SSH_D_LOWSTART, ("Uninitializing groups"));

#ifdef SSHDIST_EXTERNALKEY
  op = ikev2->ek_group_contexts;
  ikev2->ek_group_contexts = NULL;
  while (op != NULL)
    {
      if (op->operation)
        ssh_operation_abort(op->operation);
      op->operation = NULL;
      if (op->old_pk_grp)
        ssh_pk_group_free(op->old_pk_grp);
      op->old_pk_grp = NULL;
      prev_op = op;
      op = op->next;
      ssh_free(prev_op);
    }
#endif /* SSHDIST_EXTERNALKEY */


  while (ikev2->group_intmap
         && ssh_adt_num_objects(ikev2->group_intmap) > 0)
    {
      h = ssh_adt_enumerate_start(ikev2->group_intmap);
      id = *(SshUInt32 *) ssh_adt_get(ikev2->group_intmap, h);
      SSH_DEBUG(SSH_D_LOWOK, ("Removing group %d", (int) id));
      pk_grp = ssh_adt_intmap_get(ikev2->group_intmap, id);
      ssh_pk_group_free(pk_grp);
      ssh_adt_intmap_remove(ikev2->group_intmap, id);
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Successfully uninitialized groups"));
}
