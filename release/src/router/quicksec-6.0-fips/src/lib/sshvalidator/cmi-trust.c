/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Trust computations.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMiTrust"

/************ Trust computations *****************/

void
ssh_cm_trust_init(SshCMCertificate subject)
{
  /* Initialize the trusted root fields. */
  subject->trusted.trusted_issuer_id = 0;
  subject->trusted.trusted_root = FALSE;

  /* Set up the "user" trust information. */
  subject->trusted.trusted = FALSE;
  ssh_mprz_init(&subject->trusted.trusted_set);
  ssh_ber_time_zero(&subject->trusted.trusted_not_after);
  ssh_ber_time_zero(&subject->trusted.trusted_computed);

  ssh_ber_time_zero(&subject->trusted.valid_not_before);
  ssh_ber_time_zero(&subject->trusted.valid_not_after);

  subject->trusted.trusted_signature = FALSE;

  /* Set up the path length to "undefined". */
  subject->trusted.path_length = (size_t)-1;
}

void
ssh_cm_trust_clear(SshCMCertificate subject)
{
  ssh_mprz_clear(&subject->trusted.trusted_set);
  /* Just in case. */
  subject->trusted.trusted = FALSE;
  subject->trusted.trusted_root = FALSE;
  subject->trusted.trusted_issuer_id = 0;
}

Boolean
ssh_cm_trust_check_set(SshMPInteger op1, SshMPInteger op2)
{
  SshMPIntegerStruct tmp;

  /* If either set is "full" then necessarily the intersection is
     non-empty. (This is because set with no elements is considered as
     the set with all elements!) */

  if (ssh_mprz_cmp_ui(op1, 0) == 0 || ssh_mprz_cmp_ui(op2, 0) == 0)
    return TRUE;

  ssh_mprz_init(&tmp);
  ssh_mprz_and(&tmp, op1, op2);
  if (ssh_mprz_cmp_ui(&tmp, 0) == 0)
    {
      ssh_mprz_clear(&tmp);
      return FALSE;
    }
  ssh_mprz_clear(&tmp);
  return TRUE;
}

/* Check if the subject certificate is a trusted root. If context is
   given, this will check that the certificate belongs to trust set
   requested by the search, it is valid for the whole requested
   period. */
Boolean
ssh_cm_trust_is_root(SshCMCertificate subject, SshCMSearchContext *context)
{
  if (context)
    {
      /* Nothing yet. */
      if (!subject->trusted.trusted_root)
        return FALSE;

      /* Check the set. */
      if (!ssh_cm_trust_check_set(&subject->trusted.trusted_set,
                                  &context->end_cert->
                                    trusted_roots.trusted_set))
        return FALSE;

      /* Now check the time information. If the root is not valid for
         the full span of the validity interval then it must not be
         used. */
      if (ssh_ber_time_available(&subject->trusted.trusted_not_after) &&
          ssh_ber_time_cmp(&subject->trusted.trusted_not_after,
                           &context->valid_time_end) < 0)
        return FALSE;
    }
  return subject->trusted.trusted_root;
}

/* This function marks subject certificate as a trusted root anchor. */
void
ssh_cm_trust_make_root(SshCMCertificate subject,
                       SshCMSearchContext *context)
{
  /* At the moment we do not want to make roots in the search engine
     itself (it would be a very dubious operation). */
  SSH_ASSERT(context == NULL);

  subject->trusted.trusted_root = TRUE;
  subject->trusted.trusted      = TRUE;

  /* Clear the trusted not after field. This makes the subject
     trusted for indefinite time. */
  ssh_ber_time_zero(&subject->trusted.trusted_not_after);
  ssh_mprz_set_ui(&subject->trusted.trusted_set, 0);
}

/* This function clears the subject certificates status from the
   trusted root anchor. */
void
ssh_cm_trust_make_user(SshCMCertificate subject,
                       SshCMSearchContext *context)
{
  subject->trusted.trusted_root = FALSE;
  subject->trusted.trusted      = FALSE;

  /* Clear the trusted not after field. This makes the subject trusted
     for indefinite time. */
  ssh_ber_time_zero(&subject->trusted.trusted_not_after);

  /* Clear the time information. */
  ssh_ber_time_zero(&subject->trusted.valid_not_before);
  ssh_ber_time_zero(&subject->trusted.valid_not_after);

  /* Clear also the trust sets. */
  ssh_mprz_set_ui(&subject->trusted.trusted_set, 0);

  /* Path length information. */
  subject->trusted.path_length = (size_t)-1;
}

/* This function returns true, if the subject's signature has been found
   to be valid, or the subject is a trust anchor */
Boolean
ssh_cm_trust_in_signature_predicate(SshCMCertificate subject,
                                    SshCMSearchContext *context)
{
  if (ssh_cm_trust_is_root(subject, context))
    return TRUE;

  return subject->trusted.trusted_signature;
}

/* This function returns true, if the certificate 'c' is not marked as
   revoked at the time specified at the search context. */
Boolean
ssh_cm_trust_is_valid(SshCMCertificate c, SshCMSearchContext *context)
{
  if (c->status == SSH_CM_VS_OK)
    return TRUE;

  if (c->status == SSH_CM_VS_REVOKED || c->status == SSH_CM_VS_HOLD)
    {
      if (!ssh_ber_time_available(&context->end_cert->not_after))
        {
          if (ssh_ber_time_cmp(&c->trusted.trusted_not_after,
                               &context->cur_time) > 0)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Cert revoked at '%@' is in the future (1).",
                         ssh_ber_time_render, &c->trusted.trusted_not_after));
              return TRUE;
            }
        }
      else
        {
          if (ssh_ber_time_cmp(&c->trusted.trusted_not_after,
                               &context->end_cert->not_after) > 0)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Cert revoked at '%@' is in the future (2).",
                         ssh_ber_time_render, &c->trusted.trusted_not_after));
              return TRUE;
            }
        }
    }

  return FALSE;
}

/* If context is not given, this function returns the cached trust
   status for the subject certificate. In this case the ca does not
   need to be given either.

   If context is given, and subject is a trust anchor, the anchor
   validity is checked (e.g. it was valid at the search time).

   If the subject is not anchor, this function checks if the subject
   trust set is 'ca' trust set (if ca given), or search trust set. If
   it is, the trust status for the certificate is returned. */

Boolean
ssh_cm_trust_check(SshCMCertificate subject,
                   SshCMCertificate ca,
                   SshCMSearchContext *context)
{
  if (context)
    {
      /* Handle trusted roots separately. */
      if (subject->trusted.trusted_root)
        {
          /* Use the handy routine. */
          return ssh_cm_trust_is_root(subject, context);
        }

      if (subject->trusted.trusted == FALSE)
        return FALSE;

      /* Now we start the more complicated checking. */
      if (ca)
        {
          /* Check the CA set first. */
          if (!ssh_cm_trust_check_set(&subject->trusted.trusted_set,
                                      &ca->trusted.trusted_set))
            return FALSE;
        }
      else
        {
          if (!ssh_cm_trust_check_set(&subject->trusted.trusted_set,
                                      &context->
                                      end_cert->trusted_roots.trusted_set))
            return FALSE;
        }
    }
  /* Check that trust was actually given by this CA */
  if (ca)
    {
      if (ca->entry->id != subject->trusted.trusted_issuer_id)
        return FALSE;
    }
  return subject->trusted.trusted;
}

/* Marks the signature of subject certifiate checked. */
void
ssh_cm_trust_mark_signature_ok(SshCMCertificate subject,
                               SshCMCertificate issuer,
                               SshCMSearchContext *context)
{
  SSH_ASSERT(context != NULL);
  if (issuer != NULL)
    subject->trusted.trusted_issuer_id = issuer->entry->id;
  subject->trusted.trusted_signature = TRUE;
}

/* Update validity times for cached trust compututations. */
void
ssh_cm_trust_update_validity(SshCMCertificate subject,
                             SshCMCertificate ca,
                             SshBerTimeStruct *not_before,
                             SshBerTimeStruct *not_after,
                             SshCMSearchContext *context)
{
  SshMPInteger ca_set;
  SSH_ASSERT(context != NULL);

  /* Do not bother with trusted root certificates. */
  if (subject->trusted.trusted_root)
    return;

  /* Remark. This implementation is not entirely satisfactory. The problem
     is that we would like to have an "optimal" mechanism for deducing
     whether we can just "OR" the trusted sets together or whether we
     need to start a new set from scratch. This is the caching feature
     that should speed up searching a bit.

     However, currently we are not doing the caching optimally (or
     I would guess so). It seems to be possible analyze the problem
     more deeply, however, perhaps it is not vital for the workings of
     this function? */

  /* Constrain the "trusted not after" time. We need it later in
     this function. */
  if (ssh_ber_time_cmp(not_after, &context->max_cert_validity_time) < 0)
    {
      /* Now we have deduced that "not_after" is more restrictive than
         the hard limit. Thus we need to determine whether to modify
         the "trusted_not_after", however, as we know it might be
         trusted all ready by some other chain.

         Here we have a small problem. The "not_after" gives us
         explicit bound which we must satisfy (otherwise the search
         might fail).  However, the intervat at the certificate itself
         may be larger than that given by the "not_after" value. Thus
         we would be interested in keeping the old value if
         possible. */
      if (ssh_ber_time_cmp(not_after, &subject->trusted.trusted_not_after) > 0)
        {
          ssh_ber_time_set(&subject->trusted.trusted_not_after, not_after);
        }
    }
  else
    {
      ssh_ber_time_set(&subject->trusted.trusted_not_after,
                       &context->max_cert_validity_time);
    }

  if (ca)
    {
      /* Verify that the CA is actually a trusted one. */
      if (ca->trusted.trusted_root == FALSE &&
          ca->trusted.trusted == FALSE)
        return;

      ca_set = &ca->trusted.trusted_set;
    }
  else
    {
      ca_set = &context->end_cert->trusted_roots.trusted_set;
    }

  {
    int made_a_mod = 0;

    if (ssh_ber_time_cmp(&subject->trusted.valid_not_before, not_before) < 0
        || !ssh_ber_time_available(&subject->trusted.valid_not_after))
      {
        ssh_ber_time_set(&subject->trusted.valid_not_before, not_before);
        made_a_mod++;
      }
    if (ssh_ber_time_cmp(&subject->trusted.valid_not_after, not_after) > 0
        || !ssh_ber_time_available(&subject->trusted.valid_not_after))
      {
        ssh_ber_time_set(&subject->trusted.valid_not_after, not_after);
        made_a_mod++;
      }
    if (ssh_ber_time_cmp(&subject->trusted.valid_not_after,
                         &subject->trusted.valid_not_before) <= 0)
      {
        ssh_ber_time_zero(&subject->trusted.valid_not_after);
        ssh_ber_time_zero(&subject->trusted.valid_not_before);
        made_a_mod++;
      }

    if (ssh_ber_time_cmp(&subject->trusted.valid_not_after,
                         &context->valid_time_start) <= 0 ||
        ssh_ber_time_cmp(&subject->trusted.valid_not_before,
                         &context->valid_time_end) >= 0)
      {
        /* In case that the times were too 'old' set up new times. */
        ssh_ber_time_set(&subject->trusted.valid_not_before, not_before);
        ssh_ber_time_set(&subject->trusted.valid_not_after, not_after);
        ssh_mprz_set(&subject->trusted.trusted_set, ca_set);
      }
    else
      {
        /* Check the largest! */
        if (made_a_mod)
          {
            ssh_mprz_set(&subject->trusted.trusted_set, ca_set);
          }
        else
          {
            ssh_mprz_or(&subject->trusted.trusted_set,
                      &subject->trusted.trusted_set, ca_set);
          }
      }
  }

  SSH_DEBUG(SSH_D_MIDOK,
            ("CMI validity after update: not before: '%@' not after '%@'",
             ssh_ber_time_render,
             &subject->trusted.valid_not_before,
             ssh_ber_time_render,
             &subject->trusted.valid_not_after));
}

/* This function updates trust status for the subject certificate
   if the signature checks have been done, and validity times are
   sane. */
void
ssh_cm_trust_computed(SshCMCertificate subject,
                      SshCMSearchContext *context)
{
  if (subject->trusted.trusted_root)
    {
      subject->trusted.trusted =ssh_cm_trust_is_root(subject, context);
      return;
    }

  /* Signature ok and validity times are OK? */
  if (!subject->trusted.trusted_signature)
    return;

  if (ssh_ber_time_available(&subject->trusted.valid_not_before) &&
      ssh_ber_time_available(&subject->trusted.valid_not_after))
    {
      if (ssh_ber_time_cmp(&subject->trusted.valid_not_before,
                           &subject->trusted.valid_not_after) > 0)
        {
          return;
        }
    }
  else
    return;

  /* Set the date of trust computation and mark it trusted. */
  SSH_DEBUG(SSH_D_LOWOK, ("Mark certificate %@ as trusted.",
                          ssh_cm_render_certificate, subject->cert));

  ssh_ber_time_set(&subject->trusted.trusted_computed, &context->cur_time);
  subject->trusted.trusted = TRUE;
}
#endif /* SSHDIST_CERT */
