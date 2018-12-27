/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversion routines of identity payloads between IKEv1 and IKEv2.
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

#define SSH_DEBUG_MODULE "SshIkev2FallbackIdConv"



/*--------------------------------------------------------------------*/
/* Identity payload conversions                                       */
/*--------------------------------------------------------------------*/

/* Ikev2 ID payload to Ikev1 ID payload (for non traffic selectors) */
SshIkePayloadID
ikev2_fb_idv2_to_idv1(SshIkev2PayloadID idv2)
{
  SshIkePayloadID idv1;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Converting the IKEv2 payload ID %@ to IKEv1 ID",
              ssh_ikev2_payload_id_render, idv2));

  if (idv2 == NULL)
    return NULL;

#ifdef SSHDIST_IKE_ID_LIST
  if (idv2->id_type == (int) IPSEC_ID_LIST)
    {
      idv1 = ssh_ike_string_to_id(idv2->id_data);

      SSH_DEBUG(SSH_D_MIDSTART, ("IKEv2 payload ID converted to IKEv1 "
                                 "payload ID %@", ssh_ike_id_render, idv1));
      return idv1;
    }
#endif /* SSHDIST_IKE_ID_LIST */

  if ((idv1 = ssh_calloc(1, sizeof(*idv1))) == NULL)
    return NULL;

  idv1->id_type = (int) idv2->id_type;
  idv1->identification_len = idv2->id_data_size;

  switch (idv2->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      memcpy(idv1->identification.ipv4_addr,
             idv2->id_data, idv2->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
      if ((idv1->identification.fqdn =
           ssh_memdup(idv2->id_data, idv2->id_data_size)) == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      if ((idv1->identification.user_fqdn =
           ssh_memdup(idv2->id_data, idv2->id_data_size)) == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      memcpy(idv1->identification.ipv6_addr,
             idv2->id_data, idv2->id_data_size);
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
      if ((idv1->identification.asn1_data =
           ssh_memdup(idv2->id_data, idv2->id_data_size)) == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      if ((idv1->identification.key_id =
           ssh_memdup(idv2->id_data, idv2->id_data_size)) == NULL)
        goto failed;
      break;

    default:
      SSH_NOTREACHED;
    }

  SSH_DEBUG(SSH_D_MIDSTART,
            ("IKEv2 payload ID converted to IKEv1 payload ID %@",
              ssh_ike_id_render, idv1));

  return idv1;

 failed:
  ssh_free(idv1);
  return NULL;

}

/* Ikev1 ID payload (when used as identity) to Ikev2 ID payload */
SshIkev2PayloadID
ikev2_fb_idv1_to_idv2(SshIkev2ExchangeData ed, SshIkePayloadID idv1)
{
  SshIkev2PayloadID idv2;

  if (idv1 == NULL)
    return NULL;

  if ((idv2 = ssh_obstack_alloc(ed->obstack, sizeof(*idv2))) == NULL)
    return NULL;
  memset(idv2, 0, sizeof(*idv2));

  idv2->id_type = (int) idv1->id_type;
  idv2->id_reserved = 0;
  idv2->id_data_size = idv1->identification_len;

#ifdef SSHDIST_IKE_ID_LIST
  if(idv2->id_type == (int) IPSEC_ID_LIST)
      {
        char id_txt[255];
        ssh_ike_id_render_short(id_txt, sizeof(id_txt), 0, idv1);

        idv2->id_data_size = strlen(id_txt);
        idv2->id_data = ssh_obstack_memdup(ed->obstack,
                                           id_txt, strlen(id_txt));
        return idv2;
      }
#endif /* SSHDIST_IKE_ID_LIST */

  switch (idv2->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.ipv4_addr, 4))
          == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_FQDN:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.fqdn,
                              idv1->identification_len))
          == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.user_fqdn,
                              idv1->identification_len))
          == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.ipv6_addr, 16))
          == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.asn1_data,
                              idv1->identification_len))
          == NULL)
        goto failed;
      break;
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      if ((idv2->id_data =
           ssh_obstack_memdup(ed->obstack, idv1->identification.key_id,
                              idv1->identification_len))
          == NULL)
        goto failed;
      break;

    default:
      return NULL;
    }
  return idv2;

 failed:
  return NULL;
}
#endif /* SSHDIST_IKEV1 */
