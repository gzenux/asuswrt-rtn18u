/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversion routines of IKE SA payloads between IKEv1 and IKEv2.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-payloads.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "isakmp_doi.h"
#include "isakmp_util.h"

#include "ikev2-fb.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackConvSa"


/*--------------------------------------------------------------------*/
/* SA Payload conversions                                             */
/*--------------------------------------------------------------------*/


#define TR_REALLOC(trans, idx, num)                                     \
  do {                                                                  \
    if ((idx) == (num))                                                 \
      {                                                                 \
        if (!ssh_recalloc((trans),                                      \
                          &(num), (num) + 10,                           \
                          sizeof(SshIkev2PayloadTransformStruct)))      \
          goto error;                                                   \
      }                                                                 \
  } while(0)

/*--------------------------------------------------------------------*/
/* IKE SA v2 - >v1 conversion                                         */
/*--------------------------------------------------------------------*/

SshIkePayloadSA
ikev2_fb_ike_sav2_to_sav1(SshIkev2PayloadSA sav2,
                          SshIkeAttributeAuthMethValues ike_auth_method,
                          SshUInt32 life_seconds,
                          SshUInt32 life_kbytes)
{
  SshIkePayloadSA sav1 = NULL;
  SshIkePayloadP prop = NULL;
  SshIkePayloadPProtocol proto;
  SshIkePayloadT trans;
  SshIkeSAAttributeList attr;
  SshIkev2PayloadTransform transform;
  SshUInt32 cipher_index, hash_index, dh_group_index;
  SshUInt32 num_ciphers, num_hashes, num_dh_groups;
  SshUInt32 i, j, k, transform_number = 0;

  if (sav2->number_of_transforms_used != sav2->number_of_transforms[0])
    return NULL;
  if (sav2->protocol_id[0] != SSH_IKEV2_PROTOCOL_ID_IKE)
    return NULL;

  num_ciphers = num_hashes = num_dh_groups = 0;

  for (i = 0; i < sav2->number_of_transforms_used; i++)
    {
      if (sav2->transforms[i].type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
        return NULL;

      if (sav2->transforms[i].id == 0)
        return NULL;

      if (sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_ENCR)
        num_ciphers++;
      if (sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_PRF)
        num_hashes++;
      if (sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H)
        num_dh_groups++;
    }

  if (num_ciphers == 0 || num_hashes == 0 || num_dh_groups == 0)
    return NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("IKEv2 transform has %d/%d/%d "
                          "ciphers/hashes/groups",
                          (int) num_ciphers, (int) num_hashes,
                          (int) num_dh_groups));

  /* Scope the Diffie-Hellman groups to one since multiple groups
     can cause severe interoperability problems for IKEv1. */
  num_dh_groups = 1;

  sav1 = ssh_calloc(1, sizeof(*sav1));
  if (sav1 == NULL)
    goto error;

  sav1->doi = SSH_IKE_DOI_IPSEC;
  sav1->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sav1->number_of_proposals = 1;
  sav1->proposals = ssh_calloc(sav1->number_of_proposals,
                               sizeof(*sav1->proposals));
  if (sav1->proposals == NULL)
    goto error;

  prop = sav1->proposals;
  prop->proposal_number = 0;
  prop->number_of_protocols = 1;
  /* Allocate protocols. */
  prop->protocols = ssh_calloc(prop->number_of_protocols,
                               sizeof(*prop->protocols));
  if (prop->protocols == NULL)
    goto error;

  proto = prop->protocols;
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
  proto->spi_size = 0;
  proto->spi = NULL;

  proto->transforms = ssh_calloc(num_ciphers * num_hashes * num_dh_groups,
                                 sizeof(*proto->transforms));
  if (proto->transforms == NULL)
    goto error;

  j = 0;
  k = 0;

  /* Create transforms. */
  for (i = 0, cipher_index = 0; i < num_ciphers; i++)
    {
      SshIkeAttributeEncrAlgValues encr_id;
      SshUInt32 cipher_key_size = 0;

      /* Search for the next transform of type ENCR */
      for (; cipher_index < sav2->number_of_transforms_used; cipher_index++)
        {
          if (sav2->transforms[cipher_index].type ==
              SSH_IKEV2_TRANSFORM_TYPE_ENCR)
            break;
        }
      if (cipher_index == sav2->number_of_transforms_used)
        goto error;

      transform = &sav2->transforms[cipher_index];
      cipher_index++;

      encr_id = ikev2_fb_v2_id_to_v1_encr_id(transform->id);
      if ((int) encr_id == -1)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot convert %d to a IKEv1 encryption "
                                 "identifier", transform->id));
          continue;
        }

      if (transform->transform_attribute)
        cipher_key_size = (transform->transform_attribute & 0xffff);

      for (j = 0, hash_index = 0; j < num_hashes; j++)
        {
          SshIkeAttributeHashAlgValues hash_id;

          /* Search for the next transform of type INTEG */
          for (; hash_index < sav2->number_of_transforms_used; hash_index++)
            {
              if (sav2->transforms[hash_index].type ==
                  SSH_IKEV2_TRANSFORM_TYPE_PRF)
                break;
            }
          if (hash_index == sav2->number_of_transforms_used)
            goto error;

          transform = &sav2->transforms[hash_index];
          hash_index++;

          hash_id = ikev2_fb_v2_id_to_v1_hash_id(transform->id);
          if ((int) hash_id == -1)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Cannot convert %d to a IKEv1 hash "
                                     "identifier", transform->id));
              continue;
            }

          for (k = 0, dh_group_index = 0; k < num_dh_groups; k++)
            {
              SshIkeAttributeGrpDescValues dh_group_id;

              /* Search for the next transform of type D_H */
              for ( ; dh_group_index < sav2->number_of_transforms_used;
                    dh_group_index++)
                {
                  if (sav2->transforms[dh_group_index].type ==
                      SSH_IKEV2_TRANSFORM_TYPE_D_H)
                    break;
                }
              if (dh_group_index == sav2->number_of_transforms_used)
                goto error;

              transform = &sav2->transforms[dh_group_index];
              dh_group_index++;

              dh_group_id = ikev2_fb_v2_id_to_v1_group_id(transform->id);
              if ((int) dh_group_id == -1)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot convert %d to a IKEv1 "
                                         "group identifier", transform->id));
                  continue;
                }

              SSH_DEBUG(SSH_D_LOWOK, ("Filling in %d'th transform",
                                      (int) transform_number));

              SSH_ASSERT(transform_number <
                         num_ciphers * num_hashes * num_dh_groups);
              trans = &proto->transforms[transform_number];

              SSH_DEBUG(SSH_D_LOWSTART,
                        ("Creating IKE SA[%s/%d]+HASH[%s]: auth=`%s', "
                         "group=%d, life=%ds",
                         ssh_find_keyword_name(ssh_ike_encryption_algorithms,
                                               encr_id),
                         (int) cipher_key_size,
                         ssh_find_keyword_name(ssh_ike_hash_algorithms,
                                               hash_id),
                         ssh_find_keyword_name(
                                        ikev2_fb_ike_authentication_methods,
                                        ike_auth_method),
                         dh_group_id,
                         (int) life_seconds));

              /* IKE SA transform numbers start from 0. */
              trans->transform_number = transform_number++;
              trans->transform_id.isakmp = SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE;

              proto->number_of_transforms++;

              attr = ssh_ike_data_attribute_list_allocate();
              if (attr == NULL)
                goto error;

              /* Encryption algorithm. */
              ssh_ike_data_attribute_list_add_basic(attr,
                                                    SSH_IKE_CLASSES_ENCR_ALG,
                                                    (SshUInt16)
                                                    encr_id);

              /* Key size for variable key size ciphers. */
              if (cipher_key_size != 0)
                ssh_ike_data_attribute_list_add_basic(attr,
                                                   SSH_IKE_CLASSES_KEY_LEN,
                                                   (SshUInt16)cipher_key_size);

              /* Hash algorithm. */
              ssh_ike_data_attribute_list_add_basic(attr,
                                                    SSH_IKE_CLASSES_HASH_ALG,
                                                    (SshUInt16)hash_id);

              /* Authentication method. */
              ssh_ike_data_attribute_list_add_basic(attr,
                                                    SSH_IKE_CLASSES_AUTH_METH,
                                                    ike_auth_method);

              /* Group. */
              ssh_ike_data_attribute_list_add_basic(attr,
                                                    SSH_IKE_CLASSES_GRP_DESC,
                                                    dh_group_id);

              /* Lifetime.  For compatibility reasons, we set only
                 time-based lifetime.  There are implementations which
                 reject kilobyte lifetimes for Phase-1 SAs. */
              ssh_ike_data_attribute_list_add_basic(attr,
                                             SSH_IKE_CLASSES_LIFE_TYPE,
                                             SSH_IKE_VALUES_LIFE_TYPE_SECONDS);

              ssh_ike_data_attribute_list_add_int(attr,
                                               SSH_IKE_CLASSES_LIFE_DURATION,
                                               life_seconds);

              /* And finally, fetch the encoded attributes. */
              trans->sa_attributes
                = ssh_ike_data_attribute_list_get(attr,
                                              &trans->number_of_sa_attributes);
              ssh_ike_data_attribute_list_free(attr);

              if (trans->sa_attributes == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not encode IKE attributes"));
                  goto error;
                }
            }
        }
    }
  /* None of the transforms could be converted */
  if (transform_number == 0)
    goto error;

  SSH_ASSERT(i == num_ciphers);
  SSH_ASSERT(j == num_hashes);
  SSH_ASSERT(k == num_dh_groups);

  SSH_DEBUG(SSH_D_LOWOK, ("IKEv2 SA payload successfully converted"));

  /* All done. */
  return sav1;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Error converting IKE SA payload"));
  if (sav1)
    ssh_ike_free_sa_payload(sav1);
  return NULL;
}


/*--------------------------------------------------------------------*/
/* IPSec SA v2 - >v1 conversion                                       */
/*--------------------------------------------------------------------*/


/* Set the generic attributes (which are common for all protocols) for
   the IPSec proposal attributes `attr'.  The attributes are taken
   from the input parameters. */
static void
ikev2_fb_util_set_generic_attributes(SshUInt32 life_seconds, SshUInt32 life_kb,
                                     SshUInt32 pfs_group_id,
                                     Boolean tunnel,
                                     Boolean ipcomp,
                                     Boolean longseq,
                                     SshUInt32 sa_flags,
                                     SshIkeSAAttributeList attr)
{
  SshUInt16 value;

  if (life_seconds == 0 && life_kb == 0)
    {
      /* No lifetime specified.  Use global default values. */
      life_seconds = SSH_IKE_FB_DEFAULT_IPSEC_SA_LIFE_SECONDS;
      life_kb = SSH_IKE_FB_DEFAULT_IPSEC_SA_LIFE_KB;
    }

  if (life_seconds)
    {
      ssh_ike_data_attribute_list_add_basic(attr,
                                            IPSEC_CLASSES_SA_LIFE_TYPE,
                                            IPSEC_VALUES_LIFE_TYPE_SECONDS);
      ssh_ike_data_attribute_list_add_int(attr,
                                          IPSEC_CLASSES_SA_LIFE_DURATION,
                                          life_seconds);
      SSH_DEBUG(SSH_D_HIGHOK, ("lifesec=%d", (int) life_seconds));
    }
  if (life_kb)
    {
      ssh_ike_data_attribute_list_add_basic(attr,
                                            IPSEC_CLASSES_SA_LIFE_TYPE,
                                            IPSEC_VALUES_LIFE_TYPE_KILOBYTES);
      ssh_ike_data_attribute_list_add_int(attr,
                                          IPSEC_CLASSES_SA_LIFE_DURATION,
                                          life_kb);
      SSH_DEBUG(SSH_D_HIGHOK, ("lifekb=%d", (int) life_kb));
    }

  /* PFS group.  It is not set for IPComp. */
  if (!ipcomp && pfs_group_id)
    {
      SshUInt16 dh_group_desc;

      dh_group_desc = ikev2_fb_v2_id_to_v1_group_id(pfs_group_id);

      ssh_ike_data_attribute_list_add_basic(attr,
                                            IPSEC_CLASSES_GRP_DESC,
                                            dh_group_desc);
      SSH_DEBUG(SSH_D_HIGHOK, ("pfsgroup=%d", dh_group_desc));
    }

  /* Encapsulation. */
  if (tunnel)
    {
      if (sa_flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
        {
          if (sa_flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
            value = IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TUNNEL;
          else
            value = IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TUNNEL;
        }
      else
        {
          value = IPSEC_VALUES_ENCAPSULATION_MODE_TUNNEL;
        }
    }
  else
    {
      if (sa_flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
        {
          if (sa_flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
            value = IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT;
          else
            value = IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT;
        }
      else
        {
          value = IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT;
        }
    }

  ssh_ike_data_attribute_list_add_basic(attr,
                                        IPSEC_CLASSES_ENCAPSULATION_MODE,
                                        value);
  SSH_DEBUG(SSH_D_HIGHOK,
            ("encapsulation=%s",
             ssh_find_keyword_name(ssh_ike_ipsec_encapsulation_modes, value)));

  /* Sequence number size */
  if (longseq)
    {
      value = IPSEC_VALUES_SA_LONGSEQ_64;

      ssh_ike_data_attribute_list_add_basic(attr,
                                            IPSEC_CLASSES_SA_LONGSEQ,
                                            value);
      SSH_DEBUG(SSH_D_HIGHOK,
                ("sequence number size=%s",
                 ssh_find_keyword_name(ssh_ike_ipsec_longseq_values, value)));
    }
}

Boolean
ikev2_fb_ipsec_fill_ikev1_proposal(SshIkev2PayloadSA sav2,
                                   SshUInt32 v2_proposal_index,
                                   SshIkePayloadP prop,
                                   SshUInt32 life_seconds,
                                   SshUInt32 life_kbytes,
                                   SshUInt32 sa_flags,
                                   Boolean tunnel_mode,
                                   SshUInt32 spi,
                                   SshUInt32 num_ciphers,
                                   SshUInt32 num_macs,
                                   SshUInt32 pfs_group_id,
                                   Boolean longseq,
                                   SshUInt8 ipcomp_num,
                                   SshUInt8 *ipcomp_algs,
                                   SshUInt16 ipcomp_cpi)

{
  SshIkePayloadPProtocol proto;
  SshIkePayloadT trans;
  SshIkeSAAttributeList attr;
  SshIkev2PayloadTransform transform;
  SshUInt32 cipher_index, mac_index;
  SshUInt32 i, j, transform_number = 0;
  Boolean authentication = FALSE;
  SshIkev2PayloadTransform v2_transforms = sav2->proposals[v2_proposal_index];
  int v2_transform_count = sav2->number_of_transforms[v2_proposal_index];

  /* AH-ESP bundles are not supported, there is only a single protocol
     unless IPCOMP is requested */
  prop->number_of_protocols = 1;
  if (ipcomp_num != 0)
    prop->number_of_protocols++;

  prop->protocols = ssh_calloc(prop->number_of_protocols,
                               sizeof(*prop->protocols));
  if (prop->protocols == NULL)
    goto error;

  proto = &prop->protocols[0];

  proto->spi_size = 4;
  proto->spi = ssh_malloc(proto->spi_size);
  if (proto->spi == NULL)
    goto error;

  SSH_ASSERT(spi != 0);
  SSH_PUT_32BIT(proto->spi, spi);

  if (sav2->protocol_id[0] == SSH_IKEV2_PROTOCOL_ID_ESP)
    proto->protocol_id = SSH_IKE_PROTOCOL_IPSEC_ESP;
  else
    proto->protocol_id = SSH_IKE_PROTOCOL_IPSEC_AH;

  if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
    {
      authentication = num_macs ? TRUE : FALSE;
      if (num_macs == 0)
        num_macs = 1;
      proto->number_of_transforms = num_ciphers * num_macs;
    }
  else
    {
      proto->number_of_transforms = num_macs;
    }
  if (proto->number_of_transforms == 0)
    goto error;

  proto->transforms = ssh_calloc(proto->number_of_transforms,
                                 sizeof(*proto->transforms));
  if (proto->transforms == NULL)
    goto error;

  if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
    {
      for (i = 0, mac_index = 0; i < num_macs; i++)
        {
          SshIkeIpsecAttributeAuthAlgorithmValues mac_id;
          SshUInt32 mac_key_size = 0;

          /* Search for the next transform of type INTEG */
          for (; mac_index < v2_transform_count; mac_index++)
            {
              if (v2_transforms[mac_index].type ==
                  SSH_IKEV2_TRANSFORM_TYPE_INTEG)
                break;
            }
          if (mac_index == v2_transform_count)
            goto error;

          transform = &v2_transforms[mac_index];
          mac_index++;

          if (transform->transform_attribute)
            mac_key_size = (transform->transform_attribute & 0xffff);

          mac_id = ikev2_fb_v2_id_to_v1_auth_id(transform->id);
          if ((int) mac_id == -1)
            goto error;

          SSH_ASSERT(transform_number < proto->number_of_transforms);
          trans = &proto->transforms[transform_number];

          /* Transform numbers start from 1. */
          trans->transform_number = ++transform_number;

          if ((int) ikev2_fb_v2_id_to_v1_ah_id(transform->id) == -1)
            goto error;

          trans->transform_id.ipsec_ah =
            ikev2_fb_v2_id_to_v1_ah_id(transform->id);

          /* Create attribute list. */
          attr = ssh_ike_data_attribute_list_allocate();
          if (attr == NULL)
            goto error;

          /* Authentication algorithm. */
          ssh_ike_data_attribute_list_add_basic(attr,
                                                IPSEC_CLASSES_AUTH_ALGORITHM,
                                                (SshUInt16)mac_id);

          /* Key size for variable key size MACs. */
          if (mac_key_size != 0)
            ssh_ike_data_attribute_list_add_basic(attr,
                                                  IPSEC_CLASSES_KEY_LENGTH,
                                                  (SshUInt16)mac_key_size);

          /* Add generic attributes which are added for all protocols. */
          ikev2_fb_util_set_generic_attributes(life_seconds, life_kbytes,
                                               pfs_group_id, tunnel_mode,
                                               FALSE, longseq, sa_flags,
                                               attr);

          /* Fetch the encoded attributes. */

          trans->sa_attributes
            = ssh_ike_data_attribute_list_get(attr,
                                              &trans->number_of_sa_attributes);
          ssh_ike_data_attribute_list_free(attr);

          if (trans->sa_attributes == NULL)
            goto error;
        }
    }
  else
    {
      /* ESP */
      for (i = 0, cipher_index = 0; i < num_ciphers; i++)
        {
          SshIkeIpsecESPTransformIdentifiers esp_id;
          SshUInt32 cipher_key_size = 0;

          /* Search for the next transform of type ENCR */
          for ( ; cipher_index < v2_transform_count;
                cipher_index++)
            {
              if (v2_transforms[cipher_index].type ==
                  SSH_IKEV2_TRANSFORM_TYPE_ENCR)
                break;
            }
          if (cipher_index == v2_transform_count)
            goto error;

          transform = &v2_transforms[cipher_index];
          cipher_index++;

          esp_id = ikev2_fb_v2_id_to_v1_esp_id(transform->id);
          if ((int) esp_id == -1)
            goto error;

          if (transform->transform_attribute)
            cipher_key_size = (transform->transform_attribute & 0xffff);

          for (j = 0, mac_index = 0; j < num_macs; j++)
            {
              SshIkeIpsecAttributeAuthAlgorithmValues mac_id = -1;

              if (authentication)
                {
                  /* Search for the next transform of type INTEG */
                  for ( ;
                        mac_index < v2_transform_count;
                        mac_index++)
                    {
                      if (v2_transforms[mac_index].type ==
                          SSH_IKEV2_TRANSFORM_TYPE_INTEG)
                        break;
                    }
                  transform = &v2_transforms[mac_index];
                  mac_index++;

                  mac_id = ikev2_fb_v2_id_to_v1_auth_id(transform->id);
                  if ((int) mac_id == -1)
                    goto error;
                }

              SSH_ASSERT(transform_number < proto->number_of_transforms);
              trans = &proto->transforms[transform_number];

              /* Transform numbers start from 1. */
              trans->transform_number = ++transform_number;

              trans->transform_id.ipsec_esp = esp_id;

              /* Create attribute list. */
              attr = ssh_ike_data_attribute_list_allocate();
              if (attr == NULL)
                goto error;

              /* Key size for variable key size ciphers. */
              if (cipher_key_size != 0)
                ssh_ike_data_attribute_list_add_basic(attr,
                                                  IPSEC_CLASSES_KEY_LENGTH,
                                                  (SshUInt16)cipher_key_size);

              /* Authentication algorithm. */
              if (authentication && (int) mac_id != -1)
                ssh_ike_data_attribute_list_add_basic(
                                                  attr,
                                                  IPSEC_CLASSES_AUTH_ALGORITHM,
                                                  (SshUInt16)mac_id);

              /* Add generic attributes which are added for all
                 protocols. */
              ikev2_fb_util_set_generic_attributes(life_seconds, life_kbytes,
                                                   pfs_group_id, tunnel_mode,
                                                   FALSE, longseq, sa_flags,
                                                   attr);

              /* Fetch the encoded attributes. */
              trans->sa_attributes
                = ssh_ike_data_attribute_list_get(attr,
                                              &trans->number_of_sa_attributes);
              ssh_ike_data_attribute_list_free(attr);

              if (trans->sa_attributes == NULL)
                goto error;
            }
        }
    }

  if (ipcomp_num)
    {
      proto = &prop->protocols[1];
      proto->spi_size = 2;
      proto->spi = ssh_malloc(proto->spi_size);
      if (proto->spi == NULL)
        goto error;
      SSH_PUT_16BIT(proto->spi, ipcomp_cpi);
      proto->protocol_id = SSH_IKE_PROTOCOL_IPCOMP;

      proto->number_of_transforms = ipcomp_num;
      proto->transforms = ssh_calloc(proto->number_of_transforms,
                                     sizeof(*proto->transforms));
      if (proto->transforms == NULL)
        goto error;

      for (i = 0; i < ipcomp_num; i++)
        {
          trans = &proto->transforms[i];
          trans->transform_id.ipcomp = ipcomp_algs[i];
          trans->transform_number = i + 1;

          attr = ssh_ike_data_attribute_list_allocate();
          if (attr == NULL)
            goto error;

          ikev2_fb_util_set_generic_attributes(life_seconds, life_kbytes,
                                               pfs_group_id, tunnel_mode,
                                               TRUE, longseq, sa_flags,
                                               attr);

          trans->sa_attributes
            = ssh_ike_data_attribute_list_get(attr,
                                              &trans->number_of_sa_attributes);
          ssh_ike_data_attribute_list_free(attr);

          if (trans->sa_attributes == NULL)
            goto error;
        }
    }

  return TRUE;

 error:
  return FALSE;

}


static Boolean
ikev2_fb_ipsec_v2_proposal_to_v1_proposals(
        SshIkev2PayloadSA sav2,
        int proposal_index,
        SshIkePayloadSA sav1,
        SshUInt32 pfs_group_id,
        SshUInt32 life_seconds,
        SshUInt32 life_kbytes,
        SshUInt32 sa_flags,
        Boolean tunnel_mode,
        SshUInt32 spi,
        SshUInt8 ipcomp_num,
        SshUInt8 *ipcomp_algs,
        SshUInt16 ipcomp_cpi)
{
  SshUInt32 num_ciphers, num_macs;
  SshUInt32 i;
  Boolean longseq, shortseq;

  num_ciphers = num_macs = 0;
  longseq = FALSE;
  shortseq = FALSE;

  if (sav2->protocol_id[proposal_index] != SSH_IKEV2_PROTOCOL_ID_AH &&
      sav2->protocol_id[proposal_index] != SSH_IKEV2_PROTOCOL_ID_ESP)
    return FALSE;

  for (i = 0; i < sav2->number_of_transforms[proposal_index]; i++)
    {
      SshIkev2PayloadTransform transform = &sav2->proposals[proposal_index][i];

      if (transform->type >= SSH_IKEV2_TRANSFORM_TYPE_MAX)
        return FALSE;

      if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_ESN &&
          transform->id  == SSH_IKEV2_TRANSFORM_ESN_ESN)
        longseq = TRUE;

      if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_ESN &&
          transform->id  == SSH_IKEV2_TRANSFORM_ESN_NO_ESN)
        shortseq = TRUE;

      /* Use the first available group */
      if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_D_H &&
          !pfs_group_id)
        pfs_group_id = transform->id;

      if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_ENCR)
        num_ciphers++;
      if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_INTEG)
        num_macs++;
    }

  for (i = 0; i < sav2->number_of_transforms[proposal_index]; i++)
    {
      SshIkev2PayloadTransform transform = &sav2->proposals[proposal_index][i];

      if (transform->id == 0)
        {
          if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_ENCR)
            num_ciphers = 0;
          if (transform->type == SSH_IKEV2_TRANSFORM_TYPE_INTEG)
            num_macs = 0;
        }
    }

  if (!longseq && !shortseq)
    {
      longseq = TRUE;
      shortseq = TRUE;
    }

  if (shortseq)
    {
      sav1->proposals[sav1->number_of_proposals].proposal_number =
          sav1->number_of_proposals;
      sav1->number_of_proposals++;

      if (!ikev2_fb_ipsec_fill_ikev1_proposal(
                  sav2,
                  proposal_index,
                  sav1->proposals + sav1->number_of_proposals - 1,
                  life_seconds,
                  life_kbytes,
                  sa_flags,
                  tunnel_mode,
                  spi,
                  num_ciphers,
                  num_macs,
                  pfs_group_id,
                  FALSE, /* longseq */
                  ipcomp_num,
                  ipcomp_algs,
                  ipcomp_cpi))
        {
          goto error;
        }
    }

  if (longseq)
    {
      sav1->proposals[sav1->number_of_proposals].proposal_number =
          sav1->number_of_proposals;
      sav1->number_of_proposals++;

      if (!ikev2_fb_ipsec_fill_ikev1_proposal(
                  sav2,
                  proposal_index,
                  sav1->proposals + sav1->number_of_proposals - 1,
                  life_seconds,
                  life_kbytes,
                  sa_flags,
                  tunnel_mode,
                  spi,
                  num_ciphers,
                  num_macs,
                  pfs_group_id,
                  TRUE, /* longseq */
                  ipcomp_num,
                  ipcomp_algs,
                  ipcomp_cpi))
        {
          goto error;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IKEv2 SA payload successfully converted"));

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Error converting IKE SA payload"));

  return FALSE;
}


SshIkePayloadSA
ikev2_fb_ipsec_sav2_to_sav1(SshIkev2PayloadSA sav2,
                            SshUInt32 life_seconds,
                            SshUInt32 life_kbytes,
                            SshUInt32 sa_flags,
                            Boolean tunnel_mode,
                            SshUInt32 spi,
                            SshUInt8 ipcomp_num,
                            SshUInt8 *ipcomp_algs, SshUInt16 ipcomp_cpi)
{
  SshIkePayloadSA sav1 = NULL;

  SshUInt32 i;




  SshUInt32 pfs_group_id = 0;
  int sav2_proposal_count;








  for (sav2_proposal_count = 0;
       sav2_proposal_count < SSH_IKEV2_SA_MAX_PROPOSALS &&
           sav2->proposals[sav2_proposal_count] != NULL;
       sav2_proposal_count++)
    ;

  for (i = 0; i < sav2->number_of_transforms_used; i++)
    {
      /* Use the first available group */
      if (sav2->transforms[i].type == SSH_IKEV2_TRANSFORM_TYPE_D_H &&
          !pfs_group_id)
        pfs_group_id = sav2->transforms[i].id;
    }











  sav1 = ssh_calloc(1, sizeof(*sav1));
  if (sav1 == NULL)
    goto error;

  sav1->doi = SSH_IKE_DOI_IPSEC;
  sav1->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sav1->number_of_proposals = 0;
  sav1->proposals =
      ssh_calloc(
              2 * sav2_proposal_count,
              sizeof(*sav1->proposals));

  if (sav1->proposals == NULL)
    goto error;


  for (i = 0; i < sav2_proposal_count; i++)
    {
      int proposal_count;

      proposal_count =
          ikev2_fb_ipsec_v2_proposal_to_v1_proposals(
                  sav2,
                  i,
                  sav1,
                  pfs_group_id,
                  life_seconds,
                  life_kbytes,
                  sa_flags,
                  tunnel_mode,
                  spi,
                  ipcomp_num,
                  ipcomp_algs,
                  ipcomp_cpi);

      if (proposal_count < 0)
        {
          goto error;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IKEv2 SA payload successfully converted"));

  return sav1;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Error converting IKE SA payload"));
  if (sav1)
    ssh_ike_free_sa_payload(sav1);

  return NULL;
}

/*--------------------------------------------------------------------*/
/* generic SA v2 - >v1 conversion                                       */
/*--------------------------------------------------------------------*/

SshIkePayloadSA
ikev2_fb_sav2_to_sav1(SshIkev2PayloadSA sav2,
                      SshIkeAttributeAuthMethValues ike_auth_method,
                      SshUInt32 life_seconds,
                      SshUInt32 life_kbytes,
                      Boolean tunnel_mode,
                      SshUInt32 sa_flags,
                      SshUInt32 spi,
                      SshUInt8 ipcomp_num,
                      SshUInt8 *ipcomp_algs, SshUInt16 ipcomp_cpi)
{
  ssh_ikev2_payload_sa_debug(SSH_D_MIDOK,
                             "Converting the IKEv2 payload to IKEv1 format",
                             "V2_TO_V1",
                             sav2);

  switch (sav2->protocol_id[0])
    {
    case SSH_IKEV2_PROTOCOL_ID_IKE:
      {
        if (sav2->number_of_transforms_used != sav2->number_of_transforms[0])
          {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("IKEv2 payloads with multiple proposals not supported"));
            return NULL;
          }

        return ikev2_fb_ike_sav2_to_sav1(sav2, ike_auth_method,
                                       life_seconds, life_kbytes);
      }

    case SSH_IKEV2_PROTOCOL_ID_ESP:
    case SSH_IKEV2_PROTOCOL_ID_AH:
      return ikev2_fb_ipsec_sav2_to_sav1(sav2,
                                         life_seconds, life_kbytes,
                                         sa_flags, tunnel_mode, spi,
                                         ipcomp_num,
                                         ipcomp_algs, ipcomp_cpi);
    default:
      return NULL;
    }
}

/*--------------------------------------------------------------------*/
/* IKE SA v1 - >v2 conversion                                         */
/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/
/* IPSec SA v1 - >v2 conversion                                       */
/*--------------------------------------------------------------------*/

/* This function gets called for each IPcomp protocol in a IKEv1 proposal.
   This saves all distinct IPcomp transforms to the array
   'ipcomp_algs' and the IPComp CPI is stored to the 'ipcomp_cpis'
   array. The maxiumum length of these arrays is 'max_ipcomp_num'. The
   number of currently used elements in the array is input from the
   '*ipsec_num' param. This parameter is updated by this function if
   new IPComp algorithms were found when parsing 'proto'. */
Boolean
ikev2_fb_sav1_ipcomp_proposal_to_sav2(SshIkePayloadPProtocol proto,
                                      SshUInt8 max_ipcomp_num,
                                      SshUInt8 *ipcomp_num,
                                      SshUInt8 *ipcomp_algs,
                                      SshUInt16 *ipcomp_cpis)
{
  SshUInt8 ipcomp_index, i, j;

  SSH_ASSERT(ipcomp_num != NULL && ipcomp_algs != NULL && ipcomp_cpis != NULL);
  SSH_ASSERT(*ipcomp_num <= max_ipcomp_num);

  if (proto->spi_size != 2)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("SPI size for IPCOMP %d (not 2)", proto->spi_size));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Parsing IPcomp transforms from proto %p, currently "
                          "have %d IPcomp transforms ",
                          proto, *ipcomp_num));

  ipcomp_index = *ipcomp_num;

  /* Check the IPcomp transforms and add it to 'ipcomp_algs' if this
     transform has not been previously seen. */
  for (i = 0; i < proto->number_of_transforms; i++)
    {
      SshIkePayloadT trans = &proto->transforms[i];

      if (ipcomp_index == max_ipcomp_num)
        break;

      for (j = 0; j < ipcomp_index; j++)
        if (trans->transform_id.ipcomp == ipcomp_algs[j])
          break;

      if (j == ipcomp_index)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Found a new IPcomp transform %d with "
                                  "CPI=%x, insert at index %d",
                                  trans->transform_id.ipcomp,
                                  SSH_GET_16BIT(proto->spi),
                                  ipcomp_index));
          ipcomp_algs[ipcomp_index] = trans->transform_id.ipcomp;
          ipcomp_cpis[ipcomp_index] = SSH_GET_16BIT(proto->spi);
          ipcomp_index++;
        }
      else
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring already seen IPcomp transform "
                                     "%d", trans->transform_id.ipcomp));
    }
  *ipcomp_num  = ipcomp_index;

  SSH_DEBUG(SSH_D_LOWOK, ("Parsed IPcomp protocol, have %d IPcomp transforms",
                          *ipcomp_num));

  return TRUE;
}

Boolean
ikev2_fb_sav1_ipsec_proposal_to_sav2(
                                  SshIkeNegotiation negotiation,
                                  SshIkePayloadPProtocol proto,
                                  SshIkev2PayloadTransform *transforms_return,
                                  SshUInt32 *num_transforms_return,
                                  SshUInt32 *life_seconds,
                                  SshUInt32 *life_kbytes,
                                  SshIkeIpsecAttributeEncapsulationModeValues
                                  *encapsulation,
                                  SshUInt8 max_ipcomp_num,
                                  SshUInt8 *ipcomp_num_return,
                                  SshUInt8 *ipcomp_algs,
                                  SshUInt16 *ipcomp_cpis)
{
  SshIkev2PayloadTransform transforms = NULL;
  Boolean longseq = FALSE;
  SshUInt32 num_transforms_allocated;
  int j, itrans, index;
  Boolean seen;

  SSH_ASSERT(transforms_return != NULL);
  SSH_ASSERT(num_transforms_return != NULL);
  SSH_ASSERT(life_seconds != NULL);
  SSH_ASSERT(life_kbytes != NULL);
  SSH_ASSERT(encapsulation != NULL);

  *life_seconds = *life_kbytes = *encapsulation = 0;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Proposal/protocol=%s, #transforms=%d",
             ssh_find_keyword_name(ikev2_fb_ike_protocol_identifiers,
                                   proto->protocol_id),
             proto->number_of_transforms));

  if (proto->protocol_id != SSH_IKE_PROTOCOL_IPSEC_ESP &&
      proto->protocol_id != SSH_IKE_PROTOCOL_IPSEC_AH)
    goto error;

  if (proto->spi_size != 4)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("SPI size for ESP/AH %d (not 4)", proto->spi_size));
      goto error;
    }

  num_transforms_allocated = 10;
  /* This array stores the SshIkev2PayloadTransform as extracted from
     the IKEv1 transforms encoded in 'prop'. */
  transforms = ssh_calloc(num_transforms_allocated,
                          sizeof(SshIkev2PayloadTransformStruct));
  if (!transforms)
    goto error;

  /* The number of indices in 'transforms' that are currently used. */
  index = 0;

  /* Check transforms until we found a matching one or until all
     transforms have been processed. */
  for (itrans = 0; itrans < proto->number_of_transforms; itrans++)
    {
      SshIkePayloadT trans = &proto->transforms[itrans];
      struct SshIkeIpsecAttributesRec attrs;

      /* Read transform attributes. */
      ssh_ike_clear_ipsec_attrs(&attrs);
      if (!ssh_ike_read_ipsec_attrs(negotiation, trans, &attrs))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid transform in IPSec proposal: "
                                 "transform is malformed or it contains "
                                 "unsupported attributes"));
          goto error;
        }

      /* Ignore encapsulation modes other than the ones defined in
         ISAKMP DOI (or NAT-T RFC3947 or ietf draft version of it). */
      if (attrs.encapsulation_mode != IPSEC_VALUES_ENCAPSULATION_MODE_TUNNEL
          && attrs.encapsulation_mode !=
          IPSEC_VALUES_ENCAPSULATION_MODE_TRANSPORT
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          && attrs.encapsulation_mode !=
          IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TUNNEL
          && attrs.encapsulation_mode !=
          IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT
          && attrs.encapsulation_mode !=
          IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TUNNEL
          && attrs.encapsulation_mode !=
          IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          )
        continue;

      /* We currently assume that the lifetimes are equal for all
         transforms in the IKEv1 payload. */
      if (*life_seconds == 0)
        *life_seconds = attrs.life_duration_secs;
      if (*life_kbytes == 0)
        *life_kbytes = attrs.life_duration_kb;
      if (*encapsulation == 0)
        *encapsulation = attrs.encapsulation_mode;

      /* Only consider protocols whose encapsulation matches that of the
         first transform. */
      if (*encapsulation != attrs.encapsulation_mode)
        continue;

      if (attrs.longseq_size == IPSEC_VALUES_SA_LONGSEQ_64)
        longseq = TRUE;

      if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
        {
          /* Check authentication algorithm. */
          if (attrs.auth_algorithm == 0)
            goto error;

          /* Have we seen this authentication algorithm before? */
          for (j = 0, seen = FALSE; j < index; j++)
            {
              if (transforms[j].type == SSH_IKEV2_TRANSFORM_TYPE_INTEG &&
                  transforms[j].id ==
                  ikev2_fb_v1_ah_id_to_v2_id(trans->transform_id.ipsec_ah) &&
                  (transforms[j].transform_attribute & 0xffff) ==
                  attrs.key_length)
                {
                  seen = TRUE;
                  break;
                }
            }
          /* If this authentication algorithm has not been seen before,
             then add a new IKEv2 transform for it. */
          if (!seen)
            {
              SSH_ASSERT(index < num_transforms_allocated);

              transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_INTEG;
              transforms[index].id =
                ikev2_fb_v1_ah_id_to_v2_id(trans->transform_id.ipsec_ah);

              if (attrs.key_length)
                transforms[index].transform_attribute =
                  (0x800e << 16 | attrs.key_length);

              index++;
              TR_REALLOC(&transforms, index, num_transforms_allocated);
            }
        }
      else /* ESP */
        {
          /* An attempt to negotiate ESP-none-none is an auditable event. */
          if (trans->transform_id.ipsec_esp
              == SSH_IKE_IPSEC_ESP_TRANSFORM_ESP_NULL
              && attrs.auth_algorithm == 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Initiator proposed ESP-none-none"));

              ssh_audit_event(NULL,
                              SSH_AUDIT_PM_ESP_NULL_NULL_NEGOTIATION,
                              SSH_AUDIT_ARGUMENT_END);
              goto error;
            }

          /* Have we seen this encryption algorithm before? */
          for (j = 0, seen = FALSE; j < index; j++)
            {
              if (transforms[j].type == SSH_IKEV2_TRANSFORM_TYPE_ENCR &&
                  transforms[j].id ==
                  ikev2_fb_v1_esp_id_to_v2_id(trans->transform_id.ipsec_esp) &&
                  (transforms[j].transform_attribute & 0xffff) ==
                  attrs.key_length)
                {
                  seen = TRUE;
                  break;
                }
            }
          /* If this encryption algorithm has not been seen before,
             then add a new IKEv2 transform for it. */
          if (!seen)
            {
              SSH_ASSERT(index < num_transforms_allocated);

              transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_ENCR;
              transforms[index].id =
                ikev2_fb_v1_esp_id_to_v2_id(trans->transform_id.ipsec_esp);

              if (attrs.key_length)
                transforms[index].transform_attribute =
                  (0x800e << 16 | attrs.key_length);
              index++;
              TR_REALLOC(&transforms, index, num_transforms_allocated);
            }

          /* Check authentication algorithm. */

            {
              int id;

              if (attrs.auth_algorithm == 0)
                {
                  /*
                     No authentication algorithm in a
                     transform. Add it explicitly to v2 transform
                     in case initiator proposed authenticating
                     ciphers together with cipher/auth algorithm combo.
                  */
                  id = SSH_IKEV2_TRANSFORM_AUTH_NONE;
                }
              else
                {
                  id = ikev2_fb_v1_auth_id_to_v2_id(attrs.auth_algorithm);
                }

              /* Have we seen this authentication algorithm before? */
              for (j = 0, seen = FALSE; j < index; j++)
                {
                  if (transforms[j].type == SSH_IKEV2_TRANSFORM_TYPE_INTEG &&
                      transforms[j].id == id)
                    {
                      seen = TRUE;
                      break;
                    }
                }

              /* If this authentication algorithm has not been seen before,
                 then add a new IKEv2 transform for it. */
              if (!seen)
                {
                  SSH_ASSERT(index < num_transforms_allocated);

                  transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_INTEG;
                  transforms[index].id = id;
                  index++;
                  TR_REALLOC(&transforms, index, num_transforms_allocated);
                }
            }
        }

      /* Check for PFS group. */
      if (attrs.group_desc)
        {
          /* Have we seen this group before? */
          for (j = 0, seen = FALSE; j < index; j++)
            {
              if (transforms[j].type == SSH_IKEV2_TRANSFORM_TYPE_D_H &&
                  transforms[j].id ==
                  ikev2_fb_v1_group_id_to_v2_id((int) attrs.group_desc))
                {
                  seen = TRUE;
                  break;
                }
            }
          /* If this DH group has not been seen before, then add a new IKEv2
             transform for it. */
          if (!seen)
            {
              SSH_ASSERT(index < num_transforms_allocated);

              transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_D_H;
              transforms[index].id =
                  ikev2_fb_v1_group_id_to_v2_id((int) attrs.group_desc);
              index++;
              TR_REALLOC(&transforms, index, num_transforms_allocated);
            }
        }
    }

  /* Check for long sequence numbers. */
  SSH_ASSERT(index < num_transforms_allocated);

  TR_REALLOC(&transforms, (index + 1), num_transforms_allocated);

  if (longseq)
    {
      transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_ESN;
      transforms[index].id = SSH_IKEV2_TRANSFORM_ESN_ESN;
      index++;
    }
  else
    {
      transforms[index].type = SSH_IKEV2_TRANSFORM_TYPE_ESN;
      transforms[index].id = SSH_IKEV2_TRANSFORM_ESN_NO_ESN;
      index++;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Extracted %d transforms from the IKEv1 payload",
                          index));

  *transforms_return = transforms;
  *num_transforms_return = index;
  return TRUE;

 error:
  if (transforms != NULL)
    ssh_free(transforms);
  return FALSE;
}


static Boolean
ikev2_fb_v1transform_to_v2transforms_ike(
        SshIkeNegotiation negotiation,
        SshIkePayloadT v1_transform,
        SshIkev2PayloadTransform v2_transforms,
        int *v2_transform_count,
        SshIkeAttributeAuthMethValues *ike_auth_method,
        SshUInt32 *life_seconds)
{
  struct SshIkeAttributesRec attrs;
  int v2_transform_index = 0;

  /* Read attributes. */
  ssh_ike_clear_isakmp_attrs(&attrs);

  if (!ssh_ike_read_isakmp_attrs(negotiation, v1_transform, &attrs))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid transform in IKE proposal: "
                             "transform is malformed or it contains "
                             "unsupported attributes"));
      return FALSE;
    }

  *ike_auth_method = attrs.auth_method;
  *life_seconds = attrs.life_duration_secs;

  /* Encryption algorithm. */
  if (attrs.encryption_algorithm != 0)
    {
      v2_transforms[v2_transform_index].type = SSH_IKEV2_TRANSFORM_TYPE_ENCR;
      v2_transforms[v2_transform_index].id =
          ikev2_fb_v1_encr_id_to_v2_id(
                  attrs.encryption_algorithm);

      if (attrs.key_length)
        {
          v2_transforms[v2_transform_index].transform_attribute =
              (0x800e << 16 | attrs.key_length);
        }

      v2_transform_index++;
    }

  if (attrs.hash_algorithm != 0)
    {
      v2_transforms[v2_transform_index].type = SSH_IKEV2_TRANSFORM_TYPE_INTEG;
      v2_transforms[v2_transform_index].id =
          ikev2_fb_v1_hash_id_to_v2_integ_id(
                  attrs.hash_algorithm);
      v2_transform_index++;
    }

  if (attrs.group_desc != NULL)
    {
      v2_transforms[v2_transform_index].type = SSH_IKEV2_TRANSFORM_TYPE_D_H;
      v2_transforms[v2_transform_index].id =
          ikev2_fb_v1_group_id_to_v2_id(
                  attrs.group_desc->descriptor);
      v2_transform_index++;
    }

  if (attrs.prf_algorithm != 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("IKEv1 SA proposal defines unknown prf algorithm: %d",
                 (int) attrs.prf_algorithm));
      return FALSE;
    }
  else
  if (attrs.hash_algorithm != 0)
    {
      v2_transforms[v2_transform_index].type = SSH_IKEV2_TRANSFORM_TYPE_PRF;
      v2_transforms[v2_transform_index].id =
          ikev2_fb_v1_hash_id_to_v2_prf_id(
                  attrs.hash_algorithm);
      v2_transform_index++;
    }


  *v2_transform_count = v2_transform_index;

  return TRUE;
}


SshIkev2PayloadSA
ikev2_fb_ikesav1_to_ikesav2(
        SshSADHandle sad_handle,
        SshIkeNegotiation negotiation,
        SshIkePayloadSA sav1,
        SshIkeAttributeAuthMethValues *ike_auth_method,
        SshUInt32 *life_seconds)
{
  SshIkev2PayloadSA v2_sa;
  SshIkePayloadP prop;
  SshIkePayloadPProtocol proto;
  int transforms_needed;

  SSH_ASSERT(ike_auth_method != NULL);
  SSH_ASSERT(life_seconds != NULL);

  if (sav1->situation.situation_flags != SSH_IKE_SIT_IDENTITY_ONLY)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid situation; %x; only %x is supported",
                             (int) sav1->situation.situation_flags,
                             SSH_IKE_SIT_IDENTITY_ONLY));
      return NULL;
    }

  if (sav1->number_of_proposals != 1)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Invalid number of proposals in IKEv1 phase1: %d",
               sav1->number_of_proposals));
      return NULL;
    }

  prop = &sav1->proposals[0];

  if (prop->number_of_protocols != 1)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Invalid number of proposal protocols IKEv1 phase1: %d",
               prop->number_of_protocols));
      return NULL;
    }

  proto = &prop->protocols[0];

  if (proto->protocol_id != SSH_IKE_PROTOCOL_ISAKMP)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Invalid protocol (not ISAKMP) in IKEv1 phase1: %d",
               proto->protocol_id));
      return NULL;
    }


  if (proto->number_of_transforms <= 0)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("No transforms within proposal in IKEv1 phase1"));

      return NULL;
    }

  v2_sa = ssh_ikev2_sa_allocate(sad_handle);
  if (v2_sa == NULL)
    {
      return NULL;
    }

  transforms_needed = proto->number_of_transforms;

  transforms_needed *= 4; /* number of IKEv2 transforms produced by
                                one IKEv1 IKE-tranform. */
  if (transforms_needed > v2_sa->number_of_transforms_allocated)
    {
      if (!ssh_recalloc(
                  &(v2_sa->transforms),
                  &(v2_sa->number_of_transforms_allocated),
                  transforms_needed,
                  sizeof(*(v2_sa->transforms))))
        {
          ssh_ikev2_sa_free(sad_handle, v2_sa);

          return NULL;
        }
    }


    {
      int proposal_index = 0;
      int transforms_used = 0;
      int v1_transform_index = 0;

      while (proposal_index < SSH_IKEV2_SA_MAX_PROPOSALS &&
             v1_transform_index < proto->number_of_transforms)
        {
          int transform_count;
          SshUInt32 life;
          SshIkeAttributeAuthMethValues auth_method;

          if ((ikev2_fb_v1transform_to_v2transforms_ike(negotiation,
                                   &proto->transforms[v1_transform_index],
                                   &v2_sa->transforms[transforms_used],
                                   &transform_count,
                                   &auth_method,
                                   &life) == FALSE))
            {
              ++v1_transform_index;
              continue;
            }

          ++v1_transform_index;

          if (proposal_index == 0)
            {
              *ike_auth_method = auth_method;
              *life_seconds = life;
            }

          v2_sa->protocol_id[proposal_index] = SSH_IKEV2_PROTOCOL_ID_IKE;
          v2_sa->number_of_transforms[proposal_index] = transform_count;
          v2_sa->proposals[proposal_index] =
              &v2_sa->transforms[transforms_used];
          ++proposal_index;
          transforms_used += transform_count;
        }

      SSH_ASSERT(transforms_used <= transforms_needed);

      v2_sa->number_of_transforms_used = transforms_used;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Converted %d of %d IKEv1 transforms to %d IKEv2 transforms",
                 v1_transform_index,
                 proto->number_of_transforms,
                 transforms_used));

#ifdef DEBUG_LIGHT
      /*
        Dummy loop to read rest of the v1 transforms to get them
        debug logged.
      */
      while (v1_transform_index < proto->number_of_transforms)
        {
          struct SshIkeAttributesRec attrs;

          ssh_ike_clear_isakmp_attrs(&attrs);

          if (ssh_ike_read_isakmp_attrs(negotiation,
                                        &proto->transforms[v1_transform_index],
                                        &attrs) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Invalid transform in IKE proposal: "
                                     "transform is malformed or it contains "
                                     "unsupported attributes"));
            }

          ++v1_transform_index;
        }
#endif /* DEBUG_LIGHT */
    }

  return v2_sa;
}


/*--------------------------------------------------------------------*/
/* generic SA v1 - >v2 conversion                                     */
/*--------------------------------------------------------------------*/

SshIkev2PayloadSA
ikev2_fb_sav1_to_sav2(SshSADHandle sad_handle,
                      SshIkeNegotiation negotiation,
                      SshIkePayloadSA sav1,
                      Boolean only_ipcomp_proposals,
                      SshIkeAttributeAuthMethValues *ike_auth_method,
                      SshUInt32 *life_seconds,
                      SshUInt32 *life_kbytes,
                      SshIkeIpsecAttributeEncapsulationModeValues
                      *encapsulation,
                      SshUInt8 max_ipcomp_num,
                      SshUInt8 *ipcomp_num_return,
                      SshUInt8 *ipcomp_algs, /* Array of IPcomp alg id's */
                      SshUInt16 *ipcomp_cpis)
{
  SshIkev2PayloadSA sav2 = NULL;
  SshIkev2PayloadTransform transform, transforms = NULL;
  Boolean ipsec_proposal_seen, ipcomp_present;
  Boolean ah_present, esp_present;
  SshIkeIpsecAttributeEncapsulationModeValues encaps;
  Boolean encaps_set = FALSE;
  int esp_proposal_index = 0, ah_proposal_index = 0;
  SshUInt32 num_transforms, num_new_transforms;
  int j, k, iprop, iproto, proposal_index = 0;

  SSH_ASSERT(ike_auth_method != NULL);
  SSH_ASSERT(life_seconds != NULL);
  SSH_ASSERT(life_kbytes != NULL);
  SSH_ASSERT(encapsulation != NULL);

  if (sav1->situation.situation_flags != SSH_IKE_SIT_IDENTITY_ONLY)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid situation; %x; only %x is supported",
                             (int) sav1->situation.situation_flags,
                             SSH_IKE_SIT_IDENTITY_ONLY));
      return NULL;
    }

  ipsec_proposal_seen = FALSE;

  if ((sav2 = ssh_ikev2_sa_allocate(sad_handle)) == NULL)
    return NULL;

  /* Check all proposals. */
  for (iprop = 0; iprop < sav1->number_of_proposals; iprop++)
    {
      SshIkePayloadP prop = &sav1->proposals[iprop];

      ipcomp_present = esp_present = ah_present = FALSE;
      for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
        {
          SshIkePayloadPProtocol proto = &prop->protocols[iproto];

          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
            ipcomp_present = TRUE;

          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP)
            esp_present = TRUE;

          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH)
            ah_present = TRUE;
        }

      if (esp_present && ah_present)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ESP-AH bundles not supported, skipping "
                                 "proposal containing ESP and AH"));
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Received proposal contains unsupported ESP-AH "
                        "transform bundle");
          continue;
        }

      /* Skip proposals that do not have an IPComp protocol ID if only
         searching for proposals that contain IPComp */
      if (only_ipcomp_proposals && !ipcomp_present)
        continue;
      /* Skip proposals that have an IPComp protocol ID if only
         searching for proposals that do not contain IPComp */
      if (!only_ipcomp_proposals && ipcomp_present)
        continue;

      for (iproto = 0; iproto < prop->number_of_protocols; iproto++)
        {
          SshIkePayloadPProtocol proto = &prop->protocols[iproto];

          switch (proto->protocol_id)
            {
            case SSH_IKE_PROTOCOL_ISAKMP:

              goto error; /* Not handling IKE SA proposals here */

              break;

            case SSH_IKE_PROTOCOL_IPCOMP:
              SSH_ASSERT(only_ipcomp_proposals == TRUE);
              if (!ipsec_proposal_seen)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("IPcomp without accompanying IPsec proposed."));
                  goto error;
                }

              /* This terminates IPCOMP protocol processing by collecting
                 algorithms and SPI values. */
              if (!ikev2_fb_sav1_ipcomp_proposal_to_sav2(proto,
                                                         max_ipcomp_num,
                                                         ipcomp_num_return,
                                                         ipcomp_algs,
                                                         ipcomp_cpis))
                goto error;
              break;

            case SSH_IKE_PROTOCOL_IPSEC_ESP:
              /* Assign proposal numbers for AH, ESP if not already done, the
                 first seen protocol (ESP) gets proposal number 0. */
              if (!ipsec_proposal_seen)
                {
                  ipsec_proposal_seen = TRUE;
                  esp_proposal_index = 0;
                  ah_proposal_index = 1;
                }

              /* All IKEv1 ESP proposals are mapped to a single IKEv2 ESP
                 proposal */
              proposal_index = esp_proposal_index;
              if (proposal_index >= SSH_IKEV2_SA_MAX_PROPOSALS)
                goto error;

              if (!sav2->protocol_id[proposal_index])
                sav2->protocol_id[proposal_index] = SSH_IKEV2_PROTOCOL_ID_ESP;

              if (!ikev2_fb_sav1_ipsec_proposal_to_sav2(negotiation,
                                                        proto, &transforms,
                                                        &num_transforms,
                                                        life_seconds,
                                                        life_kbytes,
                                                        &encaps,
                                                        max_ipcomp_num,
                                                        ipcomp_num_return,
                                                        ipcomp_algs,
                                                        ipcomp_cpis))
                goto error;

              /* All proposals must have the same encapsulation value,
                 ignore proposals that have different encapsulation to the
                 first one received. */
              if (encaps_set && encaps != *encapsulation)
                {
                  ssh_free(transforms);
                  transforms = NULL;
                  continue;
                }
              encaps_set = TRUE;
              *encapsulation = encaps;
              break;

            case SSH_IKE_PROTOCOL_IPSEC_AH:
              /* Assign proposal numbers for AH, ESP if not already done, the
                 first seen protocol (AH) gets proposal number 0. */
              if (!ipsec_proposal_seen)
                {
                  ipsec_proposal_seen = TRUE;
                  ah_proposal_index = 0;
                  esp_proposal_index = 1;
                }
              /* All IKEv1 AH proposals are mapped to a single IKEv2 AH
                 proposal */
              proposal_index = ah_proposal_index;
              if (proposal_index >= SSH_IKEV2_SA_MAX_PROPOSALS)
                goto error;

              if (!sav2->protocol_id[proposal_index])
                sav2->protocol_id[proposal_index] = SSH_IKEV2_PROTOCOL_ID_AH;

              if (!ikev2_fb_sav1_ipsec_proposal_to_sav2(negotiation,
                                                        proto, &transforms,
                                                        &num_transforms,
                                                        life_seconds,
                                                        life_kbytes,
                                                        &encaps,
                                                        max_ipcomp_num,
                                                        ipcomp_num_return,
                                                        ipcomp_algs,
                                                        ipcomp_cpis))
                goto error;

              /* All proposals must have the same encapsulation value,
                 ignore proposals that have different encapsulation to the
                 first one received. */
              if (encaps_set && encaps != *encapsulation)
                {
                  ssh_free(transforms);
                  transforms = NULL;
                  continue;
                }
              encaps_set = TRUE;
              *encapsulation = encaps;
              break;

            default:
              goto error;
            }

          /* Transforms have been processed for IPCOMP, no need to go
             further */
          if (proto->protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
            continue;

          if (sav2->number_of_transforms_used + num_transforms >
              sav2->number_of_transforms_allocated)
            {
              transform = sav2->transforms;
              /* NOTE: Check memory limits here */
              if (!ssh_recalloc(&(sav2->transforms),
                                &(sav2->number_of_transforms_allocated),
                                sav2->number_of_transforms_used +
                                num_transforms +
                                SSH_IKEV2_SA_TRANSFORMS_ADD,
                                sizeof(*(sav2->transforms))))
                goto error;
              if (transform != sav2->transforms)
                {
                  int i;
                  for (i = 0; i < SSH_IKEV2_SA_MAX_PROPOSALS; i++)
                    {
                      if (sav2->proposals[i] != NULL)
                        {
                          sav2->proposals[i] =
                            &(sav2->transforms[(sav2->proposals[i] -
                                                transform)]);
                        }
                    }
                }
            }

          if (sav2->proposals[proposal_index] == NULL)
            {
              sav2->proposals[proposal_index] =

                &(sav2->transforms[sav2->number_of_transforms_used]);
              sav2->number_of_transforms[proposal_index]  = 0;
            }

          /* Add the new (those not previously seen) transforms to sav2 */
          num_new_transforms = 0;
          for (j = 0; j < num_transforms; j++)
            {
              Boolean transform_seen = FALSE;

              /* Check if we have seen this transform in proposal number
                 'proposal_number' before. */
              for (k = 0; k < sav2->number_of_transforms[proposal_index]; k++)
                {
                  /* The offset into the sav2->transforms array where the
                     transforms for proposal number 'proposal_number' start. */
                  size_t offset =
                    sav2->proposals[proposal_index] - sav2->proposals[0];

                  if (transforms[j].type ==
                      sav2->transforms[offset + k].type
                      && transforms[j].id == sav2->transforms[offset + k].id
                      && transforms[j].transform_attribute ==
                      sav2->transforms[offset + k].transform_attribute)
                    {
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("This transform has been seen before"));
                      transform_seen = TRUE;
                      break;
                    }
                }
              if (transform_seen)
                continue;

              /* This transform has not been seen before, add it to 'sav2' */
              transform = &(sav2->transforms[sav2->number_of_transforms_used]);

              num_new_transforms++;
              transform->type = transforms[j].type;
              transform->id = transforms[j].id;
              transform->transform_attribute =
                transforms[j].transform_attribute;

              sav2->number_of_transforms_used++;
            }
          sav2->number_of_transforms[proposal_index] += num_new_transforms;
          ssh_free(transforms);
          transforms = NULL;
        }
    }

  if (sav2->number_of_transforms_used == 0)
    goto error;

  ssh_ikev2_payload_sa_debug(SSH_D_MIDOK,
                             "Converted an IKEv1 payload to IKEv2 format",
                             "V1_TO_V2",
                             sav2);

  return sav2;

 error:
  SSH_DEBUG(SSH_D_FAIL,
            ("Error in converting IKEv1 SA payload to IKEv2 format"));

  if (transforms)
    ssh_free(transforms);
  if (sav2)
    ssh_ikev2_sa_free(sad_handle, sav2);
  return NULL;
}
#endif /* SSHDIST_IKEV1 */
