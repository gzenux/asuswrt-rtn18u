/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 SA utility functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshdebug.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshIkev2SaUtil"

/* Duplicate SA payload. This will take new entry from the
   free list and copy data from the current SA data in to
   it. This will return NULL if no free SA payloads
   available. */
SshIkev2PayloadSA
ssh_ikev2_sa_dup(SshSADHandle sad_handle,
                 SshIkev2PayloadSA sa)
{
  SshIkev2PayloadSA sa_copy;
  int i;

  sa_copy = ssh_ikev2_sa_allocate(sad_handle);
  if (sa_copy == NULL)
    return NULL;

  sa_copy->proposal_number = sa->proposal_number;
  memcpy(sa_copy->protocol_id, sa->protocol_id, sizeof(sa->protocol_id));
  memcpy(sa_copy->number_of_transforms, sa->number_of_transforms,
         sizeof(sa->number_of_transforms));

  /* Copy items. */
  if (sa->number_of_transforms_used > sa_copy->number_of_transforms_allocated)
    {
      sa_copy->transforms =
        ssh_realloc(sa_copy->transforms,
                    sa_copy->number_of_transforms_allocated *
                    sizeof(*(sa_copy->transforms)),
                    sa->number_of_transforms_used *
                    sizeof(*(sa_copy->transforms)));
      if (sa_copy->transforms == NULL)
        {
          sa_copy->number_of_transforms_allocated = 0;
          ssh_ikev2_sa_free(sad_handle, sa_copy);
          return NULL;
        }
      sa_copy->number_of_transforms_allocated = sa->number_of_transforms_used;
    }
  memcpy(sa_copy->transforms, sa->transforms,
         sa->number_of_transforms_used * sizeof(*(sa->transforms)));
  sa_copy->number_of_transforms_used = sa->number_of_transforms_used;


  for(i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
    {
      if (sa->proposals[i] != NULL)
        {
          sa_copy->proposals[i] =
            &(sa_copy->transforms[(sa->proposals[i] - sa->transforms)]);
        }
    }
  return sa_copy;
}

/* Take extra reference to the SA payload. */
void
ssh_ikev2_sa_take_ref(SshSADHandle sad_handle,
                      SshIkev2PayloadSA sa)
{
  sa->ref_cnt++;
}

/* Add transform to the SA payload. This will add new entry
   to the end of the list. */
SshIkev2Error
ssh_ikev2_sa_add(SshIkev2PayloadSA sa,
                 SshUInt8 proposal_index,
                 SshIkev2TransformType type,
                 SshIkev2TransformID id,
                 SshUInt32 transform_attribute)
{
  SshIkev2PayloadTransform transform;

  if (sa->number_of_transforms_used >= sa->number_of_transforms_allocated)
    {
      transform = sa->transforms;
      /* NOTE: Check memory limits here */
      if (!ssh_recalloc(&(sa->transforms),
                        &(sa->number_of_transforms_allocated),
                        sa->number_of_transforms_allocated +
                        SSH_IKEV2_SA_TRANSFORMS_ADD,
                        sizeof(*(sa->transforms))))
        {
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
      if (transform != sa->transforms)
        {
          int i;
          for(i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
            {
              if (sa->proposals[i] != NULL)
                {
                  sa->proposals[i] =
                    &(sa->transforms[(sa->proposals[i] - transform)]);
                }
            }
        }
    }
  transform = &(sa->transforms[sa->number_of_transforms_used]);
  transform->type = type;
  transform->id = id;
  transform->transform_attribute = transform_attribute;
  sa->number_of_transforms[proposal_index]++;
  if (sa->proposals[proposal_index] == NULL)
    sa->proposals[proposal_index] = transform;
  sa->number_of_transforms_used++;
  return SSH_IKEV2_ERROR_OK;
}


static Boolean
ikev2_find_matching_policy_transform_index(
        SshIkev2PayloadTransform input_transform,
        SshIkev2PayloadTransform policy_transforms,
        int policy_transform_count)
{
  int i;
  Boolean type_in_policy = FALSE;

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("SA_SELECT: "
           "Considering input transform type %s (%d), id %s (%d); %@",
           ssh_ikev2_transform_type_to_string(
                   input_transform->type),
           (int) input_transform->type,
           ssh_ikev2_transform_to_string(
                   input_transform->type,
                   input_transform->id),
           (int) input_transform->id,
           ikev2_render_transform_attribute,
           &input_transform->transform_attribute));

  for (i = 0; i < policy_transform_count; i++)
    {
      SshIkev2PayloadTransform policy_transform = &policy_transforms[i];

      /* Skip policy transforms of other types */
      if (policy_transform->type != input_transform->type)
        {
          SSH_DEBUG(
                  SSH_D_LOWOK,
                  ("SA_SELECT: "
                   "Skipping policy transform index %d of type %s (%d)",
                   i,
                   ssh_ikev2_transform_type_to_string(policy_transform->type),
                   (int) policy_transform->type));

          continue;
        }

      /* Record that the type is seen in policy transform
         since omitting the type completely means that NONE is OK.
      */
      type_in_policy = TRUE;

      if (policy_transform->id == input_transform->id &&
          policy_transform->transform_attribute ==
          input_transform->transform_attribute)
        {
          SSH_DEBUG(
                  SSH_D_LOWOK,
                  ("SA_SELECT: "
                   "Selected matching policy transform index %d",
                   i));
          return TRUE;
        }

      SSH_DEBUG(
              SSH_D_LOWOK,
              ("SA_SELECT: "
               "Skipped non-matching policy transform index %d type %s (%d) "
               "id %s (%d); %@",
               i,
               ssh_ikev2_transform_type_to_string(
                       policy_transform->type),
               (int) policy_transform->type,
               ssh_ikev2_transform_to_string(
                       policy_transform->type,
                       policy_transform->id),
               (int) policy_transform->id,
               ikev2_render_transform_attribute,
               &policy_transform->transform_attribute));

    }

  /*
     If input says NONE is OK and the type was not in policy
     then "select" none by ignoring the missing type.
   */
  if (input_transform->id == 0 && type_in_policy == FALSE)
    {
      SSH_DEBUG(
              SSH_D_MIDRESULT,
              ("SA_SELECT: "
               "Selecting input transform id NONE"
               " of non-policy transform type %s (%d)",
               ssh_ikev2_transform_type_to_string(
                       input_transform->type),
               input_transform->type));

      return TRUE;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("SA_SELECT: "
           "No matching transform found for type %s (%d), id %s (%d); %@",
           ssh_ikev2_transform_type_to_string(
                   input_transform->type),
           (int) input_transform->type,
           ssh_ikev2_transform_to_string(
                   input_transform->type,
                   input_transform->id),
           (int) input_transform->id,
           ikev2_render_transform_attribute,
           &input_transform->transform_attribute));

  return FALSE;
}


static SshUInt32
ikev2_select_failure_mismatch_bit(
        SshIkev2TransformType transform_type)
{
  SshUInt32 bitmask;

  switch (transform_type)
    {
    case SSH_IKEV2_TRANSFORM_TYPE_ENCR:
      bitmask = SSH_IKEV2_SA_SELECTION_ERROR_ENCR_MISMATCH;
      break;

    case SSH_IKEV2_TRANSFORM_TYPE_PRF:
      bitmask = SSH_IKEV2_SA_SELECTION_ERROR_PRF_MISMATCH;
      break;

    case SSH_IKEV2_TRANSFORM_TYPE_INTEG:
      bitmask = SSH_IKEV2_SA_SELECTION_ERROR_INTEG_MISMATCH;
      break;

    case SSH_IKEV2_TRANSFORM_TYPE_D_H:
      bitmask = SSH_IKEV2_SA_SELECTION_ERROR_D_H_MISMATCH;
      break;

    case SSH_IKEV2_TRANSFORM_TYPE_ESN:
      bitmask = SSH_IKEV2_SA_SELECTION_ERROR_ESN_MISMATCH;
      break;

    default:
      bitmask = 0;
    }

  return bitmask;
}


static int
ikev2_set_types_used(
        Boolean types[SSH_IKEV2_TRANSFORM_TYPE_MAX],
        SshIkev2PayloadTransform transforms,
        int transform_count)
{
  int i;

  memset(types, 0, sizeof types[0] * SSH_IKEV2_TRANSFORM_TYPE_MAX);

  for (i = 0; i < transform_count; i++)
    {
      if (transforms[i].type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
        {
          return transforms[i].type;
        }

      types[transforms[i].type] = TRUE;
    }

  return 0; /* 0 == no unknown types detected */
}


static Boolean
ikev2_select_proposal_transforms(
        SshIkev2PayloadTransform selected[SSH_IKEV2_TRANSFORM_TYPE_MAX],
        SshIkev2PayloadTransform input_transforms,
        int input_transform_count,
        SshIkev2PayloadTransform policy_transforms,
        int policy_transform_count,
        Boolean input_types[SSH_IKEV2_TRANSFORM_TYPE_MAX],
        SshIkev2SaSelectionError *failure_mask)
{
  Boolean policy_types[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  int transform_type;
  int i;

  /* returns non-zero for unknown transform types */
  transform_type =
      ikev2_set_types_used(
              policy_types,
              policy_transforms,
              policy_transform_count);

  SSH_ASSERT(transform_type < SSH_IKEV2_TRANSFORM_TYPE_MAX);

  memset(selected, 0, SSH_IKEV2_TRANSFORM_TYPE_MAX * sizeof selected[0]);

  for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      int j;
      Boolean accepted = FALSE;

      /* Skip types proposed in input */
      if (input_types[i])
        {
          continue;
        }

      /* Skip types no included in policy; they are checked later */
      if (!policy_types[i])
        {
          continue;
        }

      /* Search for nil transform id */
      for (j = 0; j < policy_transform_count; j++)
        {
          /*
             Select transform id NONE from policy since
             proposal does not include the transform type.
          */
          if (policy_transforms[j].type == i &&
              policy_transforms[j].id == 0)
            {
              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("SA_SELECT: "
                       "Accepting non-proposed transform type %s (%d) as NONE",
                       ssh_ikev2_transform_type_to_string(
                               policy_transforms[j].type),
                       (int) policy_transforms[j].type));

              accepted = TRUE;
              break;
            }
        }

      /*
        Policy requires transform of this type; it is missin from the
        proposal so reject the input proposal.
       */
      if (accepted == FALSE)
        {
          *failure_mask |= ikev2_select_failure_mismatch_bit(i);

          SSH_DEBUG(
                  SSH_D_MIDRESULT,
                  ("SA_SELECT: "
                   "Rejecting proposal for non-policy transform type %s (%d).",
                   ssh_ikev2_transform_type_to_string(i),
                   i));

          return FALSE;
        }
    }

  for (transform_type = 0;
       transform_type < SSH_IKEV2_TRANSFORM_TYPE_MAX;
       transform_type++)
    {
      Boolean success = FALSE;

      /* Skip transform types not included in input */
      if (!input_types[transform_type])
        {
          continue;
        }

      /* Loop through transforms of the transform_type in from the
         input proposal
      */
      for (i = 0; i < input_transform_count && !success; i++)
        {
          SshIkev2PayloadTransform input_transform = &input_transforms[i];

          /* Skip types not interested now */
          if (input_transform->type != transform_type)
            {
              continue;
            }

          success =
              ikev2_find_matching_policy_transform_index(
                      input_transform,
                      policy_transforms,
                      policy_transform_count);
          if (success)
            {
              /* Matching transform was found; record the selection */

              SSH_DEBUG(
                      SSH_D_MIDRESULT,
                      ("SA_SELECT: "
                       "Selecting transform type %s (%d) "
                       "id %s (%d); %@",
                       ssh_ikev2_transform_type_to_string(
                               input_transform->type),
                       (int) input_transform->type,
                       ssh_ikev2_transform_to_string(
                                   input_transform->type,
                                   input_transform->id),
                       (int) input_transform->id,
                       ikev2_render_transform_attribute,
                       &input_transform->transform_attribute));

              selected[transform_type] = input_transform;
            }
        }

      if (!success)
        {
          *failure_mask |= ikev2_select_failure_mismatch_bit(transform_type);

          SSH_DEBUG(
                  SSH_D_MIDRESULT,
                  ("SA_SELECT: "
                   "Rejecting proposal for missing policy "
                   "transform type %s (%d).",
                   ssh_ikev2_transform_type_to_string(transform_type),
                   transform_type));

          return FALSE;
        }
    }

  return TRUE;
}



Boolean
ssh_ikev2_sa_select(
        SshIkev2PayloadSA input_sa,
        SshIkev2PayloadSA policy_sa,
        int *proposal_index,
        SshIkev2PayloadTransform
                selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
        SshIkev2SaSelectionError *failure_mask)
{
  SshIkev2PayloadTransform * selected = selected_transforms;
  SshIkev2SaSelectionError failure = SSH_IKEV2_SA_SELECTION_ERROR_OK;
  int i;

  SSH_DEBUG(
          SSH_D_MIDOK,
          ("SA_SELECT: Selecting IKEv2 proposal."));

  input_sa->proposal_number = 0;

  for (i = 0;
       i < SSH_IKEV2_SA_MAX_PROPOSALS && input_sa->protocol_id[i] != 0 &&
           input_sa->proposal_number == 0;
       i++)
    {
      int j;
      Boolean input_types[SSH_IKEV2_TRANSFORM_TYPE_MAX];
      SshIkev2PayloadTransform input_transforms = input_sa->proposals[i];
      int input_transform_count = input_sa->number_of_transforms[i];
      int unknown_type;

      unknown_type =
          ikev2_set_types_used(
                  input_types,
                  input_transforms,
                  input_transform_count);

      if (unknown_type != 0)
        {
          failure |= SSH_IKEV2_SA_SELECTION_ERROR_UNKNOWN_TRANSFORM;

          SSH_DEBUG(
                  SSH_D_MIDRESULT,
                  ("SA_SELECT: "
                   "Rejecting proposal for unknown transform type %s (%d).",
                           ssh_ikev2_transform_type_to_string(
                                   unknown_type),
                           (int) unknown_type));
        }

      for (j = 0;
           j < SSH_IKEV2_SA_MAX_PROPOSALS && policy_sa->protocol_id[j] != 0;
           j++)
        {
          SshIkev2PayloadTransform policy_transforms = policy_sa->proposals[j];
          int policy_transform_count = policy_sa->number_of_transforms[j];

          SSH_DEBUG(
                  SSH_D_MIDOK,
                  ("SA_SELECT: "
                   "Considering input proposal %d protocol %s (%d) "
                   "and policy proposal %d protocol %s (%d)",
                   i + 1,
                   ssh_ikev2_protocol_to_string(
                           input_sa->protocol_id[i]),
                   input_sa->protocol_id[i],
                   j + 1,
                   ssh_ikev2_protocol_to_string(
                           policy_sa->protocol_id[j]),
                   policy_sa->protocol_id[j]));

          if (input_sa->protocol_id[i] != policy_sa->protocol_id[j])
            {
              SSH_DEBUG(
                      SSH_D_MIDOK,
                      ("SA_SELECT: "
                       "Skipping policy proposal %d for protocol mismatch.",
                       j + 1));
              continue;
            }

          if (ikev2_select_proposal_transforms(
                      selected,
                      input_transforms,
                      input_transform_count,
                      policy_transforms,
                      policy_transform_count,
                      input_types,
                      &failure))
            {
              int protocol_id = input_sa->protocol_id[i];

              if ((protocol_id == SSH_IKEV2_PROTOCOL_ID_ESP ||
                   protocol_id == SSH_IKEV2_PROTOCOL_ID_AH) &&
                  selected[SSH_IKEV2_TRANSFORM_TYPE_ESN] == NULL)
                {
                  failure |=
                      ikev2_select_failure_mismatch_bit(
                              SSH_IKEV2_TRANSFORM_TYPE_ESN);

                  SSH_DEBUG(
                          SSH_D_MIDRESULT,
                          ("SA_SELECT: "
                           "Rejecting input proposal for missing IPsec ESN."));
                }
              else
                {
                  SSH_DEBUG(
                          SSH_D_MIDRESULT,
                          ("SA_SELECT: "
                           "Policy proposal %d accepted input proposal %d.",
                           j + 1,
                           i + 1));

                  input_sa->proposal_number = i + 1;
                  *proposal_index = i;
                  break;
                }
            }

          SSH_DEBUG(
                  SSH_D_MIDRESULT,
                  ("SA_SELECT: "
                   "Policy proposal %d rejected input proposal %d.",
                   i + 1,
                   j + 1));
        }
    }

  if (failure_mask)
    {
      *failure_mask = failure;
    }

  if (input_sa->proposal_number != 0)
    {
      SSH_DEBUG(
              SSH_D_MIDRESULT,
              ("SA_SELECT: "
               "Proposal chosen: proposal number %d protocol %s (%d).",
               input_sa->proposal_number,
               ssh_ikev2_protocol_to_string(
                       input_sa->protocol_id[*proposal_index]),
               input_sa->protocol_id[*proposal_index]));

      SSH_DEBUG(
              SSH_D_MIDRESULT,
              ("SA_SELECT: "
               "Selected transforms:"));

      for (i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
        {
          if (selected[i] != NULL)
            {
              SSH_DEBUG(
                      SSH_D_MIDRESULT,
                      ("SA_SELECT: "
                       "    %-5s (%d) : %s (%d); %@",
                       ssh_ikev2_transform_type_to_string(selected[i]->type),
                       selected[i]->type,
                       ssh_ikev2_transform_to_string(
                               selected[i]->type,
                               selected[i]->id),
                       selected[i]->id,
                       ikev2_render_transform_attribute,
                       &selected[i]->transform_attribute));
            }
        }

      return TRUE;
    }

  SSH_DEBUG(
          SSH_D_MIDRESULT,
          ("SA_SELECT: "
           "No proposal chosen."));

  return FALSE;
}


int
ssh_ikev2_payload_sa_debug(
        int debug_level,
        const char *topic,
        const char *line_header,
        SshIkev2PayloadSA input_sa)
{
  int i, j;

  if (input_sa == NULL)
    {
      SSH_DEBUG(
              debug_level,
              ("%s: "
               "%s: %s",
               line_header,
               topic,
               "(null)"));

      return 1;
    }

  SSH_DEBUG(
          debug_level,
          ("%s: "
           "%s:",
           line_header,
           topic));

  for (i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
    {
      SshIkev2PayloadTransform transform = input_sa->proposals[i];

      if (transform != NULL)
        {
          SSH_DEBUG(
                  debug_level,
                  ("%s: "
                   "[%d] protocol = %s (%d):",
                   line_header,
                   i,
                   ssh_ikev2_protocol_to_string(input_sa->protocol_id[i]),
                   input_sa->protocol_id[i]));

          for (j = 0; j < input_sa->number_of_transforms[i]; j++)
            {
              SSH_DEBUG(
                      debug_level,
                      ("%s: "
                       "  %-5s (%d) : %s (%d) %@",
                       line_header,
                       ssh_ikev2_transform_type_to_string(transform[j].type),
                       transform[j].type,
                       ssh_ikev2_transform_to_string(
                               transform[j].type,
                               transform[j].id),
                       transform[j].id,
                       ikev2_render_transform_attribute,
                       &transform[j].transform_attribute));
            }
        }
    }

    return 0;
}


int
ssh_ikev2_payload_conf_debug(
        int debug_level,
        const char *topic,
        const char *line_header,
        SshIkev2PayloadConf input_conf)
{
  unsigned char buf[256];
  const int buf_size = sizeof buf;
  int i;

  if (input_conf == NULL)
    {
      SSH_DEBUG(
              debug_level,
              ("%s: "
               "%s: %s",
               line_header,
               topic,
               "(null)"));

      return 1;
    }

  SSH_DEBUG(
          debug_level,
          ("%s: "
           "%s:",
           line_header,
           topic, buf_size));

  SSH_DEBUG(
          debug_level,
          ("%s: "
          "CONF(type = %d)",
          line_header,
          input_conf->conf_type));

  for(i = 0; i < input_conf->number_of_conf_attributes_used; i++)
    {
      int len = 0;
      int p;

      /* Print attribute */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                          "[%d] type = %s (%d), len = %d, ",
                       i,
                       ssh_ikev2_attr_to_string(input_conf->conf_attributes[i].
                                                attribute_type),
                       input_conf->conf_attributes[i].attribute_type,
                       input_conf->conf_attributes[i].length);

      if (len >= buf_size)
        {
          return 2;
        }

      if (input_conf->conf_attributes[i].length == 0)
        {
          len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                              "no value");
        }
      else
        {
          switch (input_conf->conf_attributes[i].attribute_type)
            {
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP:

              if (input_conf->conf_attributes[i].length == 4)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                    "value = %@",
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value));
                }
              else
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "error");
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET:

              if (input_conf->conf_attributes[i].length == 8)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                    "value = %@/%@",
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value),
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value + 4));
                }
              else
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "error");
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET:

              if (input_conf->conf_attributes[i].length == 17)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                    "value = %@/%d",
                                    ssh_ipaddr6_byte16_render,
                                    input_conf->conf_attributes[i].value,
                                    SSH_GET_8BIT(input_conf->
                                                 conf_attributes[i].
                                                 value + 16));
                }
              else
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "error");
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP:

              if (input_conf->conf_attributes[i].length == 16)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "value = %@",
                                      ssh_ipaddr6_byte16_render,
                                      input_conf->conf_attributes[i].value);
                }
              else
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "error");
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY:

              if (input_conf->conf_attributes[i].length == 4)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                    "value = %ld",
                                    (long)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value));
                }
              else
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                      "error");
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BANNER:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DEFAULT_DOMAIN:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_DNS_NAME:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_FW_TYPE:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BACKUP_SERVERS:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DDNS_HOSTNAME:
            case SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION:

              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                  "value = %.*@",
                                  input_conf->conf_attributes[i].length,
                                  ssh_safe_text_render,
                                  input_conf->conf_attributes[i].value);

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_LOCAL_LAN:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_NET_INCLUDE:

              for (p = 0;
                   p < input_conf->conf_attributes[i].length;
                   p = p + 14)
                {
                  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                    " value = %@/%@",
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value + p),
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(input_conf->
                                                  conf_attributes[i].
                                                  value + p + 4));
                }

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SAVE_PASSWD:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_NATT_PORT:

              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                  "value = %u",
                                  ((SshUInt16 *)
                                    input_conf->conf_attributes[i].value)[0]);

              break;

            case SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES:

              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                  "value = %.*@",
                                  input_conf->conf_attributes[i].length,
                                  ssh_hex_render,
                                  input_conf->conf_attributes[i].value);
              break;

            default:

              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len,
                                  "unknown value type");
              break;
            }
        }

      if (len >= buf_size)
        {
          return 2;
        }

      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len, "; ");

      if (len >= buf_size)
        {
          return 2;
        }

      SSH_DEBUG(
              debug_level,
              ("%s: "
               "%s",
               line_header,
               buf));
    }

    return 0;
}
