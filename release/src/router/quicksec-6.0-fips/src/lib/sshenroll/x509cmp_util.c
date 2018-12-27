/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Helper functions for allocating and freeing CMP message components.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "x509cmp.h"
#include "x509cmp-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshX509CmpUtil"
/* Initialize and clear the basic data types. */

/* PKI status. */
void cmp_pki_status_init(SshCmpStatusInfo pinfo)
{
  pinfo->status  = SSH_CMP_STATUS_UNDEF;
  pinfo->failure = 0;
  pinfo->freetext = NULL;
}

void cmp_pki_status_clear(SshCmpStatusInfo pinfo)
{
  ssh_str_free(pinfo->freetext);
  cmp_pki_status_init(pinfo);
}

void cmp_cert_init(SshCmpCertificate c)
{
  c->encrypted = FALSE;
  c->cert = NULL;
  c->cert_len = 0;
  c->prvkey = NULL;
  c->prvkey_len = 0;
}

void cmp_cert_clear(SshCmpCertificate c)
{
  if (c->cert) ssh_free(c->cert);
  if (c->prvkey) ssh_free(c->prvkey);
  cmp_cert_init(c);
}

/* Response node. */
void cmp_cert_response_node_init(SshCmpCertResponseNode r)
{
  ssh_mprz_init_set_si(&r->request_id, -1);
  cmp_pki_status_init(&r->pki_status);
  cmp_cert_init(&r->cert);

  r->rsp_info = NULL;
  r->rsp_info_len = 0;
}

void cmp_cert_response_node_clear(SshCmpCertResponseNode r)
{
  if (r == NULL)
    return;

  ssh_mprz_clear(&r->request_id);
  cmp_pki_status_clear(&r->pki_status);
  ssh_free(r->rsp_info);
  r->rsp_info = NULL;
  r->rsp_info_len = 0;
  cmp_cert_clear(&r->cert);
}

/* Response. */
void cmp_cert_response_init(SshCmpCertResponse r)
{
  /* Initialize the GList. */
  r->ca_pubs = ssh_glist_allocate();

  /* Initialize the response node list. */
  r->list    = NULL;
}

/* Free the glist. */
void cmp_cert_free_glist(SshGListNode node, void *context)
{
  SshCmpCertificate c = node->data;

  cmp_cert_clear(c);
  ssh_free(c);
}

void cmp_cert_response_clear(SshCmpCertResponse r)
{
  SshCmpCertResponseNode node, next_node;

  if (r == NULL)
    return;

  /* Free the glist. */
  ssh_glist_free_with_iterator(r->ca_pubs, cmp_cert_free_glist, NULL);
  r->ca_pubs = NULL;

  /* Free the otherlist. */
  for (node = r->list; node; node = next_node)
    {
      next_node = node->next;
      cmp_cert_response_node_clear(node);
      ssh_free(node);
    }
  r->list    = NULL;
}

/* Handle the error msgs. */
void cmp_error_msg_init(SshCmpErrorMsg e)
{
  cmp_pki_status_init(&e->status);
  ssh_mprz_init_set_si(&e->error_code, -1);
  e->details = NULL;
}

void cmp_error_msg_clear(SshCmpErrorMsg e)
{
  if (e == NULL)
    return;

  cmp_pki_status_clear(&e->status);
  ssh_mprz_clear(&e->error_code);
  if (e->details) ssh_str_free(e->details);
}

void cmp_cert_confirm_init(SshCmpCertConf c)
{
  ssh_mprz_init_set_si(&c->request_id, -1);
  cmp_pki_status_init(&c->pki_status);
  c->hash = NULL;
  c->hash_len = 0;
}

void cmp_cert_confirm_clear(SshCmpCertConf c)
{
  ssh_mprz_clear(&c->request_id);
  cmp_pki_status_clear(&c->pki_status);
  if (c->hash && c->hash_len) ssh_free(c->hash);
  c->hash = NULL;
  c->hash_len = 0;
}

void cmp_cert_confirm_free_glist(SshGListNode node, void *context)
{
  SshCmpCertConf cc = node->data;
  if (cc) cmp_cert_confirm_clear(cc);
  ssh_free(cc);
}

void cmp_poll_init(SshCmpPollMsg r)
{
  r->this_is_response = FALSE;
  ssh_mprz_init_set_si(&r->request_id, -1);
  r->poll_when = 0;
  r->reason = NULL;
}

void cmp_poll_clear(SshCmpPollMsg r)
{
  ssh_mprz_clear(&r->request_id);
  ssh_str_free(r->reason);
}

void cmp_poll_req_rep_free_glist(SshGListNode node, void *context)
{
  SshCmpPollMsg pm = node->data;
  cmp_poll_clear(pm);
  ssh_free(pm);
}

void cmp_rec_response_init(SshCmpRecResponse r)
{
  cmp_pki_status_clear(&r->pki_status);
  r->newsigcert = NULL;
  r->cacerts = ssh_glist_allocate();
  r->keypairhist = ssh_glist_allocate();
}

void cmp_rec_response_clear(SshCmpRecResponse r)
{
  if (r->newsigcert)
    {
      cmp_cert_clear(r->newsigcert);
      ssh_free(r->newsigcert);
    }
  ssh_glist_free_with_iterator(r->cacerts,
                               cmp_cert_free_glist, NULL);
  ssh_glist_free_with_iterator(r->keypairhist,
                               cmp_cert_free_glist, NULL);
}

void cmp_rev_response_init(SshCmpRevResponse r)
{
  if (r)
    {
      memset(&r->status, 0, sizeof(r->status));
      r->id = NULL;
      r->next = NULL;
      r->crl = NULL;
      r->crl_len = 0;
    }
}
void cmp_rev_response_clear(SshCmpRevResponse r)
{
  SshCmpRevResponse next;

  for (; r; r = next)
    {
      next = r->next;

      ssh_x509_cert_id_clear(r->id);
      ssh_free(r->id);
      if (r->crl && r->crl_len) ssh_free(r->crl);
      cmp_pki_status_clear(&r->status);
      ssh_free(r);

    }
}

void cmp_rev_announce_init(SshCmpRevAnn r) {}
void cmp_rev_announce_clear(SshCmpRevAnn r) {}
void cmp_cku_announce_init(SshCmpCKUAnn r) {}
void cmp_cku_announce_clear(SshCmpCKUAnn r) {}

/* Handle the body. */
void cmp_body_init(SshCmpBody b)
{
  b->type = SSH_CMP_MSG_UNKNOWN;

  /* Allocate a list and initialize it */
  b->cert_requests = ssh_glist_allocate();
  cmp_cert_response_init(&b->cert_response);
  b->pop_challenge = ssh_glist_allocate();
  b->pop_responses = ssh_glist_allocate();
  cmp_rec_response_init(&b->rec_response);
  b->rev_requests = ssh_glist_allocate();
  cmp_rev_response_init(b->rev_response);
  cmp_rev_announce_init(&b->rev_announce);
  cmp_cku_announce_init(&b->cku_announce);
  cmp_cert_init(&b->cert_announce);
  b->crl_announce = ssh_glist_allocate();
  cmp_error_msg_init(&b->error_msg);
  b->cert_confirm = ssh_glist_allocate();
  b->poll_req_rep = ssh_glist_allocate();
  b->nested_messages = NULL;
}

void cmp_pop_challenge_free_glist(SshGListNode node, void *context) { }
void cmp_pop_response_free_glist(SshGListNode node, void *context) { }
void cmp_rev_request_free_glist(SshGListNode node, void *context)
{
  SshCmpRevRequest revo = node->data;
  if (revo->cert_template)
    {
      cmp_cert_clear(revo->cert_template);
      ssh_free(revo->cert_template);
    }
  if (revo->crl_extensions)
    ssh_x509_revoked_free(revo->crl_extensions);
  ssh_free(revo);
}

void cmp_crl_announce_free_glist(SshGListNode node, void *context) { }
void cmp_nested_messages_free_glist(SshGListNode node, void *context)
{
  SshCmpCertSet c = (SshCmpCertSet) node->data;
  if (c->ber != NULL)
    ssh_free((unsigned char *)c->ber);
  ssh_free(c);
}

void cmp_body_clear(SshCmpBody b)
{
  ssh_glist_free_with_iterator(b->cert_requests, cmp_cert_free_glist, NULL);
  b->cert_requests = NULL;
  cmp_cert_response_clear(&b->cert_response);
  ssh_glist_free_with_iterator(b->pop_challenge,
                               cmp_pop_challenge_free_glist, NULL);
  ssh_glist_free_with_iterator(b->pop_responses,
                               cmp_pop_response_free_glist, NULL);
  cmp_rec_response_clear(&b->rec_response);
  ssh_glist_free_with_iterator(b->rev_requests,
                               cmp_rev_request_free_glist, NULL);

  cmp_rev_response_clear(b->rev_response);
  cmp_rev_announce_clear(&b->rev_announce);
  cmp_cku_announce_clear(&b->cku_announce);
  cmp_cert_clear(&b->cert_announce);
  ssh_glist_free_with_iterator(b->crl_announce,
                               cmp_crl_announce_free_glist, NULL);
  cmp_error_msg_clear(&b->error_msg);
  ssh_glist_free_with_iterator(b->cert_confirm,
                               cmp_cert_confirm_free_glist, NULL);
  ssh_glist_free_with_iterator(b->poll_req_rep,
                               cmp_poll_req_rep_free_glist, NULL);

  if (b->nested_messages != NULL)
    ssh_glist_free_with_iterator(b->nested_messages,
                                 cmp_nested_messages_free_glist, NULL);

  b->type = SSH_CMP_MSG_UNKNOWN;
}

/* Handle protection info. */
void cmp_protection_info_init(SshCmpProtectionInfo pinfo)
{
  pinfo->pswbmac = NULL;
  pinfo->key     = NULL;
  pinfo->key_length = 0;
  pinfo->prv_key = NULL;
  ssh_x509_signature_init(&pinfo->signature);
}

void cmp_protection_info_clear(SshCmpProtectionInfo pinfo)
{
  ssh_pswbmac_free(pinfo->pswbmac);
  pinfo->pswbmac = NULL;

  /* Clean the key. */
  memset(pinfo->key, 0, pinfo->key_length);
  ssh_free(pinfo->key);
  pinfo->key = NULL;
  pinfo->key_length = 0;
  pinfo->prv_key = NULL;
  ssh_x509_signature_clear(&pinfo->signature);
}

/* Handle the header. */
void cmp_header_init(SshCmpHeader h)
{
  h->pnvo = 0;

  h->transaction_id = NULL;
  h->transaction_id_len  = 0;

  h->sender = NULL;
  h->recipient = NULL;

  ssh_ber_time_zero(&h->message_time);
  cmp_protection_info_init(&h->protection_info);

  h->sender_kid = NULL;
  h->sender_kid_len = 0;
  h->recip_kid = NULL;
  h->recip_kid_len = 0;

  h->sender_nonce = NULL;
  h->sender_nonce_len = 0;
  h->recip_nonce = NULL;
  h->recip_nonce_len  = 0;

  /* TODO: freetext. */
  h->general_infos = NULL;
}

void cmp_header_clear(SshCmpHeader h)
{
  h->pnvo = 0;

  if (h->transaction_id)
    ssh_free(h->transaction_id);
  h->transaction_id = NULL;
  h->transaction_id_len = 0;

  if (h->sender)
    {
      ssh_x509_name_free(h->sender);
      h->sender = NULL;
    }
  if (h->recipient)
    {
      ssh_x509_name_free(h->recipient);
      h->recipient = NULL;
    }

  ssh_ber_time_zero(&h->message_time);
  cmp_protection_info_clear(&h->protection_info);

  if (h->sender_kid)
    ssh_free(h->sender_kid);
  h->sender_kid = NULL;
  h->sender_kid_len = 0;

  if (h->recip_kid)
    ssh_free(h->recip_kid);
  h->recip_kid = NULL;
  h->recip_kid_len = 0;

  if (h->sender_nonce)
    ssh_free(h->sender_nonce);
  h->sender_nonce = NULL;
  h->sender_nonce_len = 0;

  if (h->recip_nonce)
    ssh_free(h->recip_nonce);
  h->recip_nonce      = NULL;
  h->recip_nonce_len  = 0;

  if (h->freetext)
    ssh_str_free(h->freetext);

  if (h->general_infos)
    {
      SshX509Attribute p = h->general_infos, n;

      while (p)
        {
          n = p->next;
          if (p->oid)  ssh_free(p->oid);
          if (p->data) ssh_free(p->data);
          ssh_free(p);
          p = n;
        }
    }
}

/* Handle the PKI message. */
void cmp_message_init(SshCmpMessage msg)
{
  cmp_header_init(&msg->header);
  cmp_body_init(&msg->body);

  msg->protection = NULL;
  msg->protection_len = 0;
  msg->certificates = ssh_glist_allocate();

  memset(&msg->config, 0, sizeof(msg->config));
}

void cmp_message_clear(SshCmpMessage msg)
{
  cmp_header_clear(&msg->header);
  cmp_body_clear(&msg->body);

  if (msg->protection) ssh_free(msg->protection);
  msg->protection = NULL;
  msg->protection_len = 0;

  ssh_glist_free_with_iterator(msg->certificates,
                               cmp_cert_free_glist, NULL);
  msg->certificates = NULL;
}


SshUInt32 cmp_get_certs(SshGList list,
                        SshCmpCertSet *certs)
{
  SshGListNode gnode;
  SshUInt32 ncerts = 0, i;
  SshCmpCertSet ce;

  *certs = NULL;
  for (gnode = list->head; gnode; gnode = gnode->next)
    ncerts++;

  if (ncerts == 0)
    return 0;

  if ((*certs = ce = ssh_calloc(ncerts, sizeof(*ce))) == NULL)
    return 0;

  for (i = 0, gnode = list->head; gnode; i++, gnode = gnode->next)
    {
      SshCmpCertificate c = gnode->data;

      ce[i].ber = c->cert;
      ce[i].ber_len = c->cert_len;
    }
  return ncerts;
}

/* eof */
#endif /* SSHDIST_CERT */
