/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppChap"

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "md4.h"
#include "singledes.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"

static void
ssh_ppp_chap_get_challenge_buf(SshPppState gdata,
                               SshPppChap chap,
                               unsigned int len)
{
  if (chap->challenge != NULL && len != chap->challenge_length)
    {
      ssh_free(chap->challenge);
      chap->challenge = NULL;
      chap->challenge_length = 0;
    }

  if (chap->challenge == NULL && len > 0)
    {
      chap->challenge = ssh_malloc(len);
      if (chap->challenge == NULL)
        {
          ssh_ppp_fatal(gdata);
          return;
        }
    }
  chap->challenge_length = len;
}

void
ssh_ppp_chap_init_challenge(SshPppState gdata, SshPppChap chap)
{
  unsigned long i;

  ssh_ppp_chap_get_challenge_buf(gdata,chap, chap->challenge_length);

  if (chap->challenge == NULL)
    return;

  for (i = 0; i < chap->challenge_length; i++)
    chap->challenge[i] = ssh_random_get_byte();

  /* New challenge has been generated. Invalidate any responses. */
  chap->response_length = 0;
}

void
ssh_ppp_chap_init_peer_challenge(SshPppState gdata, SshPppChap chap)
{
  int i;

  if (chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      for (i = 0; i < SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH; i++)
        chap->response_buf[i] = ssh_random_get_byte();
    }
}

void
ssh_ppp_chap_inc_id(SshPppState gdata, SshPppChap chap)
{
  ssh_ppp_identifier_inc(&chap->id);
}

/* Local utility functions */

/* Convert a passphrase into UNICODE */
static unsigned char*
ssh_ppp_chap_string_tounicode(unsigned char *src, size_t srclen)
{
  unsigned char *tmpbuf;
  int i;

  tmpbuf = ssh_malloc(srclen*2);
  if (tmpbuf == NULL)
    return NULL;

  for (i = 0; i < srclen; i++)
    {
      tmpbuf[2*i] = src[i];
      tmpbuf[2*i+1] = '\0';
    }
  return tmpbuf;
}

static Boolean
ssh_ppp_chap_fromhexstring(unsigned char *dst, unsigned char *src,
                           size_t len)
{
  unsigned int hex1,hex2;

  SSH_ASSERT(src != NULL && dst != NULL);

  while (len--)
    {
      if (*src >= '0' && *src <= '9')
        hex2 = (*src - '0');
      else if (*src >= 'A' && *src <= 'F')
        hex2 = (*src - 'A') + 10;
      else if (*src >= 'a' && *src <= 'f')
        hex2 = (*src - 'a') + 10;
      else
        return FALSE;

      src++;

      if (*src >= '0' && *src <= '9')
        hex1 = (*src - '0');
      else if (*src >= 'A' && *src <= 'F')
        hex1 = (*src - 'A') + 10;
      else if (*src >= 'a' && *src <= 'f')
        hex1 = (*src - 'a') + 10;
      else
        return FALSE;
      src++;

      *dst++ = ((hex2 << 4) & 0xF0) | (hex1 & 0x0F);
    }
  return TRUE;
}

static void
ssh_ppp_chap_tohexstring(unsigned char *dst, unsigned char *src,
                         size_t srclen)
{
  int i;
  unsigned char hex;

  for (i = 0; i < srclen; i++)
    {
      hex = (src[i] >> 4) & 0x0F;
      hex = (hex >= 10 ? (hex - 10 + 'A') : (hex + '0'));
      *dst++ = hex;
      hex = src[i] & 0x0F;
      hex = (hex >= 10 ? (hex - 10 + 'A') : (hex + '0'));
      *dst++ = hex;
    }
}

static void
ssh_ppp_chap_md4(unsigned char *input,
                 size_t input_length,
                 unsigned char *dst,
                 size_t dstlen)
{
  SSH_ASSERT(dstlen >= 16);

  ssh_md4_of_buffer(dst, input, input_length);
}

static Boolean
ssh_ppp_chap_get_peer_name(SshPppChap chap, SshPppPktBuffer pkt)
{
  unsigned long length;

  if (chap->peer_name != NULL)
    {
      ssh_free(chap->peer_name);
      chap->peer_name = NULL;
      chap->peer_name_length = 0;
    }

  length = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  chap->peer_name_length = length;

  if (length != 0)
    {
      chap->peer_name = ssh_malloc(chap->peer_name_length);
      if (chap->peer_name == NULL)
        {
          chap->peer_name_length = 0;
          return FALSE;
        }
      ssh_ppp_pkt_buffer_get_buf(pkt,0,chap->peer_name,length);
    }
  else
    {
      ssh_free(chap->peer_name);
      chap->peer_name = NULL;
    }
  return TRUE;
}

SshPppPktBuffer
ssh_ppp_chap_get_output_buf(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshPppMuxProtocolStruct* mux;

  mux = ssh_ppp_thread_get_mux(chap->ppp_thread);

  if (ssh_ppp_flush_output_pkt_isavail(mux) == FALSE)
    return NULL;

  pkt = ssh_ppp_flush_get_output_pkt(mux);

  if (pkt == NULL)
    {
      ssh_ppp_fatal(gdata);
      return NULL;
    }

  SSH_ASSERT(ssh_ppp_pkt_buffer_isempty(pkt));

  ssh_ppp_pkt_buffer_offset(pkt,16);

  return pkt;
}

static SshIterationStatus
ssh_ppp_chap_frame_isvalid(SshPppPktBuffer pkt)
{
  return ssh_ppp_protocol_frame_isvalid(pkt);
}

static Boolean
ssh_ppp_chap_parse_mschap_failure(SshPppState gdata,
                                  unsigned char *buf,
                                  size_t buflen,
                                  unsigned int *error_code_return,
                                  unsigned int *retry_code_return,
                                  unsigned char **challenge_return,
                                  unsigned int *version_code_return)
{
  char *resp,*error_code,*version_code,*challenge,*retry,*ptr;

  resp = error_code = version_code = challenge = NULL;

  *error_code_return = 0;
  *retry_code_return = 0;
  *challenge_return = NULL;
  *version_code_return = 0;

  if (buflen < 3 || buf == NULL)
    goto fail;

  resp = ssh_malloc(buflen+1);

  if (resp == NULL)
    {
      ssh_ppp_fatal(gdata);
      goto fail;
    }

  memcpy(resp, buf, buflen);
  resp[buflen] = '\0';

  SSH_DEBUG(SSH_D_MY,("failure string: '%s'",resp));

  /* Extract the relevant fields from the failure packet */

  error_code = resp;
  retry = strchr(error_code,' ');

  if (retry != NULL)
    *retry++ = '\0';

  while (retry != NULL && *retry != '\0' && *retry == ' ')
    retry++;

  ptr = retry;

  if (ptr != NULL && *ptr != '\0')
    {
      ptr = strchr(ptr,' ');
      challenge = ptr;

      if (challenge != NULL)
        {
          challenge++;

          while (*challenge != '\0' && *challenge == ' ')
            challenge++;

          if (strlen(challenge) > 2 && memcmp(challenge,"C=",2) == 0)
            {
              *ptr = '\0';
              ptr = challenge;
            }
          else
            challenge = NULL;
        }
    }

  if (ptr != NULL && *ptr != '\0')
    {
      version_code = strchr(ptr,' ');

      if (version_code != NULL)
        {
          *version_code++ = '\0';

          while (*version_code != '\0' && *version_code == ' ')
            version_code++;

          if (strlen(version_code) < 3 || memcmp(version_code,"V=",2) != 0)
            version_code = NULL;
        }
    }

  /* Require that the "E=xxx" field is present */

  if (strlen(error_code) < 3 || memcmp(error_code,"E=",2) != 0)
    goto fail;

    {
      unsigned int error_value;
      unsigned int version_value = 0;
      unsigned int retry_value = 0;


      error_value = strtol(error_code+2,NULL,10);

      if (version_code != NULL && strlen(version_code) >= 3
          && memcmp(version_code,"V=",2) == 0)
        version_value = strtol(version_code+2,NULL,10);

      if (retry != NULL && strlen(retry) >= 3 && memcmp(retry,"R=",2) ==  0)
        retry_value = strtol(retry+2,NULL,10);

      /* Return parsed parameters */

      *error_code_return = error_value;
      *version_code_return = version_value;
      *retry_code_return = retry_value;
    }

  if (challenge != NULL)
    {
      *challenge_return = ssh_malloc(strlen(challenge)-1);
      if (*challenge_return == NULL)
        {
          ssh_ppp_fatal(gdata);
          goto fail;
        }
      /* Skip C= */
      memcpy(*challenge_return,challenge+2,strlen(challenge)-1);
    }

  ssh_free(resp);
  return TRUE;
 fail:
  ssh_free(resp);
  return FALSE;
}

SshPppEvent
ssh_ppp_chap_mschap_failure_to_event(SshPppState gdata,
                                     SshPppChap chap,
                                     unsigned char *ucp,
                                     size_t len)
{
  unsigned char *challenge;
  unsigned int error_value,version_value,retry_value;

  retry_value = 0;
  error_value = 0;
  version_value = 0;
  challenge = NULL;

  if (chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV1
      && chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    goto fail;

  if (ssh_ppp_chap_parse_mschap_failure(gdata, ucp, len,
                                        &error_value,
                                        &retry_value,
                                        &challenge,
                                        &version_value) == FALSE)
    goto fail;

  if (error_value == 648) /* Password expired. Do Change Password Protocol */
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("MS-CHAP password expired: "
                                  "algorithm=0x%x E=%u R=%u V=%u",
                                  chap->algorithm,
                                  error_value,retry_value,version_value));

      if (((version_value == 1 || version_value == 0)
           && chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
          || (version_value != 3
              && chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("unsupported MS-CHAP/CPW protocol"));
          goto fail;
        }

      ssh_free(challenge);
      return SSH_PPP_EVENT_AUTH_THIS_FAIL_CHANGEPW;
    }

  if (retry_value == 0)
    goto fail;

  SSH_DEBUG(SSH_D_NICETOKNOW,("MS-CHAP failure: E=%u R=%u",
                              error_value,retry_value));

  ssh_free(challenge);
  return SSH_PPP_EVENT_AUTH_THIS_FAIL_RECHALLENGE;
 fail:
  ssh_free(challenge);
  return SSH_PPP_EVENT_AUTH_THIS_FAIL;
}

/* Function to restart machine if we are waiting for a callback */

void
ssh_ppp_chap_get_secret_api(SshPppState gdata, void* ctx)
{
  SshPppChap chap;

  chap = (SshPppChap)ctx;

  ssh_ppp_chap_get_secret(gdata,chap,chap->is_secret_newpw);
}

void
ssh_ppp_chap_get_secret(SshPppState gdata, void* ctx, unsigned int is_changepw)
{
  SshPppEventsOutput out;
  SshPppChap chap;
  SshPppAuthType auth_type;

  chap = (SshPppChap)ctx;

  out = ssh_ppp_thread_get_cb_outputq(chap->ppp_thread);
  ssh_ppp_events_reserve(out);

  chap->is_secret_newpw = is_changepw;

  switch (chap->algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      SSH_ASSERT(is_changepw == FALSE);
      auth_type = SSH_PPP_AUTH_CHAP;
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
      if (is_changepw == FALSE)
        auth_type = SSH_PPP_AUTH_MSCHAPv1;
      else
        auth_type = SSH_PPP_AUTH_MSCHAP_CHPWv2;
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      if (is_changepw == FALSE)
        auth_type = SSH_PPP_AUTH_MSCHAPv2;
      else
        auth_type = SSH_PPP_AUTH_MSCHAP_CHPWv3;
      break;
    default:
      ssh_ppp_fatal(gdata);
      return;
    }

  /* Request a new secret.. any previously cached secret will
     be destroyed in ssh_ppp_chap_return_secret() */
  ssh_ppp_get_secret(gdata, chap, auth_type,
                     chap->peer_name, chap->peer_name_length);
}

void
ssh_ppp_chap_return_secret(SshPppState gdata,
                           void *ctx,
                           SshUInt8 *buf,
                           SshUInt32 length,
                           Boolean isvalid)
{
  SshPppEventsOutput op;
  SshPppChap chap;
  SshUInt8 *dupbuf;

  chap = (SshPppChap)ctx;

  SSH_ASSERT(chap != NULL);

  op = ssh_ppp_thread_get_cb_outputq(chap->ppp_thread);

  ssh_ppp_events_unreserve(op);

  if (chap->is_secret_newpw == 0)
    {
      ssh_ppp_forget_secret(chap->secret_buf, chap->secret_length);
      chap->secret_buf = NULL;
      chap->secret_length = 0;
    }
  else
    {
      ssh_ppp_forget_secret(chap->new_secret_buf,chap->new_secret_length);
      chap->new_secret_buf = NULL;
      chap->new_secret_length = 0;
    }

  if (isvalid == FALSE)
    {
      SSH_DEBUG(SSH_D_LOWOK,("received invalid passphrase, discarding"));
      return;
    }

#ifdef SSHDIST_RADIUS
  if (gdata->radius_config != NULL
      && chap->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
    {
      chap->is_radius_used = 1;
      ssh_ppp_events_signal(op, SSH_PPP_EVENT_RESPONSE);
      return;
    }
  chap->is_radius_used = 0;
#endif /* SSHDIST_RADIUS */

  dupbuf = NULL;
  if (buf != NULL)
    {
      dupbuf = ssh_malloc(length);

      if (dupbuf == NULL)
        {
          ssh_ppp_fatal(gdata);
          return;
        }

      memcpy(dupbuf, buf, length);
   }

  if (chap->is_secret_newpw == 0)
    {
      chap->secret_buf = dupbuf;
      chap->secret_length = length;
    }
  else
    {
      chap->new_secret_buf = dupbuf;
      chap->new_secret_length = length;
    }

  ssh_ppp_events_signal(op, SSH_PPP_EVENT_SECRET);
}

/* Callback functions to differentiate between CHAP authenticator
   and authenticatee machines */

SshIterationStatus
ssh_ppp_chap_isauthenticator(SshPppPktBuffer pkt)
{
  SshUInt8 type;

  if (ssh_ppp_chap_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  type = ssh_ppp_protocol_frame_get_code(pkt);

  if (type != SSH_PPP_CHAP_CODE_RESPONSE
      && type != SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv2
      && type != SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv3)
    {
      return SSH_PPP_ERROR;
    }

  return SSH_PPP_OK;
}

SshIterationStatus
ssh_ppp_chap_isauthenticatee(SshPppPktBuffer pkt)
{
  SshUInt8 type;

  if (ssh_ppp_chap_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  type = ssh_ppp_protocol_frame_get_code(pkt);

  if (type != SSH_PPP_CHAP_CODE_CHALLENGE
      && type != SSH_PPP_CHAP_CODE_FAILURE
      && type != SSH_PPP_CHAP_CODE_SUCCESS)
    {
      return SSH_PPP_ERROR;
    }

  return SSH_PPP_OK;
}

void
ssh_ppp_chap_boot(void* ctx)
{
  SshPppChap tdata;

  tdata = (SshPppChap)ctx;

  ssh_ppp_thread_boot(tdata->ppp_thread);
}

void
ssh_ppp_chap_destroy(void*ctx)
{
  SshPppChap chap;
  SshPppTimer timer;
  SshPppMuxProtocolStruct* mux;

  chap = (SshPppChap)ctx;

  SSH_DEBUG(SSH_D_LOWSTART,("destroying CHAP instance %p",ctx));

  ssh_fsm_kill_thread(ssh_ppp_thread_get_thread(chap->ppp_thread));

  timer = ssh_ppp_thread_get_timer(chap->ppp_thread);
  mux = ssh_ppp_thread_get_mux(chap->ppp_thread);

  ssh_ppp_timer_destroy(timer);
  ssh_ppp_flush_del_protocol(mux);
  ssh_ppp_thread_destroy(chap->ppp_thread);

  ssh_ppp_forget_secret(chap->secret_buf, chap->secret_length);
  ssh_ppp_forget_secret(chap->new_secret_buf, chap->new_secret_length);
  chap->secret_buf = NULL;
  chap->new_secret_buf = NULL;

#ifdef SSHDIST_RADIUS
  ssh_ppp_radius_uninit(&chap->radius_client);
#endif /* SSHDIST_RADIUS */

  if (chap->peer_name != NULL)
    ssh_free(chap->peer_name);

  if (chap->my_name != NULL)
    ssh_free(chap->my_name);

  if (chap->challenge != NULL)
    ssh_free(chap->challenge);

  ssh_free(chap);
}

static void*
ssh_ppp_chap_create_internal(SshPppState gdata,
                             SshPppAuthMode mode,
                             SshPppEvents eventq,
                             SshPppFlush output_mux,
                             SshUInt8 algorithm)
{
  SshPppChap chap;
  SshFSMThread chap_thread;
  SshFSM fsm;
  SshPppTimer timer;
  SshPppMuxProtocolStruct* mux;
  SshPppMuxAcceptanceCB pkt_cb;

  fsm = gdata->fsm;

  chap = ssh_malloc(sizeof(*chap));

  if (chap == NULL)
    return NULL;

  timer = NULL;
  chap_thread = NULL;
  chap->ppp_thread = NULL;
  chap->challenge = NULL;
  chap->challenge_length = 0;

  if (mode == SSH_PPP_AUTH_AUTHENTICATOR)
    {
      chap_thread = ssh_fsm_thread_create(fsm,
                                          ssh_chap_server_initial,
                                          NULL_FNPTR, NULL_FNPTR, chap);
    }
  else
    {
      chap_thread = ssh_fsm_thread_create(fsm,
                                          ssh_chap_client_initial,
                                          NULL_FNPTR, NULL_FNPTR, chap);
    }

  if (chap_thread == NULL)
    goto fail;

  chap->algorithm = algorithm;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Creating CHAP instance mode %d algorithm 0x%x",
             mode,algorithm));

  /* The MS IAS seems to discard all authentication attempts
     with CHAP-Challenge RADIUS attribute length != 16. The
     128 bit challenge should be sufficient though. */

  if (chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
    ssh_ppp_chap_get_challenge_buf(gdata,chap,8);
  else
    ssh_ppp_chap_get_challenge_buf(gdata,chap,16);

  if (chap->challenge == NULL)
    goto fail;

  chap->my_name_length = 0;
  chap->my_name = NULL;
  chap->peer_name_length = 0;
  chap->peer_name = NULL;
  chap->secret_length = 0;
  chap->secret_buf = NULL;
  chap->new_secret_buf = NULL;
  chap->new_secret_length = 0;
  chap->is_reauth_tmout_set = 0;

  chap->counter_current = 0;
  chap->counter_max = 10;
  chap->auth_status = SSH_PPP_EVENT_NONE;
  chap->auth_mode = mode;
  chap->is_secret_newpw = 0;
#ifdef SSHDIST_RADIUS
  chap->is_radius_used = (gdata->radius_config == NULL?0:1);
#endif /* SSHDIST_RADIUS */

  ssh_ppp_identifier_init(gdata,&chap->id);

  /* Prep scheduling and asynch stuff */

  chap->ppp_thread = ssh_ppp_thread_create(gdata,
                                           chap_thread,
                                           eventq,
                                           "CHAP");

  timer = ssh_ppp_timer_create(chap->ppp_thread);

  if (chap->ppp_thread == NULL || timer == NULL)
    goto fail;

  pkt_cb = (chap->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR ?
            ssh_ppp_chap_isauthenticator :
            ssh_ppp_chap_isauthenticatee);


  mux = ssh_ppp_flush_add_protocol(output_mux,
                                   SSH_PPP_PID_CHAP,
                                   chap->ppp_thread,
                                   1024,
                                   pkt_cb);

  if (mux == NULL)
    goto fail;

  ssh_ppp_thread_attach_timer(chap->ppp_thread, timer);
  ssh_ppp_thread_attach_mux(chap->ppp_thread, mux);

  ssh_ppp_flush_set_output_mru(mux,1024);

#ifdef SSHDIST_RADIUS
  ssh_ppp_radius_init(&chap->radius_client);
#endif /* SSHDIST_RADIUS */

  return chap;

 fail:
  if (timer != NULL)
    ssh_ppp_timer_destroy(timer);

  if (chap->ppp_thread != NULL)
    ssh_ppp_thread_destroy(chap->ppp_thread);

  if (chap_thread != NULL)
    ssh_fsm_kill_thread(chap_thread);

  if (chap->challenge != NULL)
    ssh_free(chap->challenge);

  if (chap != NULL)
    ssh_free(chap);

  return NULL;

}

void*
ssh_ppp_chap_create(SshPppState gdata,
                    SshPppAuthMode mode,
                    SshPppEvents eventq,
                    SshPppFlush output_mux)
{
  return ssh_ppp_chap_create_internal(gdata, mode, eventq, output_mux,
                                      SSH_PPP_CHAP_ALGORITHM_MD5);
}

void*
ssh_ppp_chap_create_mschapv1(SshPppState gdata,
                             SshPppAuthMode mode,
                             SshPppEvents eventq,
                             SshPppFlush output_mux)
{
  return ssh_ppp_chap_create_internal(gdata, mode, eventq, output_mux,
                                      SSH_PPP_CHAP_ALGORITHM_MSCHAPV1);
}

void*
ssh_ppp_chap_create_mschapv2(SshPppState gdata,
                             SshPppAuthMode mode,
                             SshPppEvents eventq,
                             SshPppFlush output_mux)
{
  return ssh_ppp_chap_create_internal(gdata, mode, eventq, output_mux,
                                      SSH_PPP_CHAP_ALGORITHM_MSCHAPV2);
}

SshPppEvent
ssh_ppp_chap_get_status(void* ctx)
{
  SshPppChap chap;

  chap = (SshPppChap)ctx;

  SSH_ASSERT(chap != NULL);

  return chap->auth_status;
}

SshPppAuthMode
ssh_ppp_chap_get_mode(void *auth_state)
{
  SshPppChap chap;

  chap = (SshPppChap)auth_state;

  SSH_ASSERT(chap != NULL);

  return chap->auth_mode;
}

SshPppEvents
ssh_ppp_chap_get_events(void* ctx)
{
  SshPppChap chap;

  chap = (SshPppChap)ctx;

  return ssh_ppp_thread_get_events(chap->ppp_thread);
}

Boolean
ssh_ppp_chap_set_name(void* ctx,
                      SshUInt8* buf,
                      unsigned long len)
{
  SshPppChap chap;
  SshUInt8 *name;

  chap = (SshPppChap)ctx;

  SSH_ASSERT(chap != NULL);

  if (buf != NULL)
    {
      name = ssh_malloc(len);

      if (name == NULL)
        return FALSE;

      memcpy(name, buf, len);
      ssh_free(chap->my_name);
      chap->my_name = name;
      chap->my_name_length = len;
    }
  else
    {
      ssh_free(chap->my_name);
      chap->my_name = NULL;
      chap->my_name_length = 0;
    }
  return TRUE;
}

void
ssh_ppp_chap_output_frame(SshPppState gdata,
                          SshPppChap chap, SshPppPktBuffer pkt,
                          SshUInt8 code, SshUInt8 id)
{
  unsigned long len;
  SshPppMuxProtocolStruct* mux;

  len = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  ssh_ppp_pkt_buffer_prepend_uint16(pkt,(SshUInt16)(len+4));
  ssh_ppp_pkt_buffer_prepend_uint8(pkt,id);
  ssh_ppp_pkt_buffer_prepend_uint8(pkt,code);

  mux = ssh_ppp_thread_get_mux(chap->ppp_thread);

  ssh_ppp_flush_send_pkt(gdata, mux);
}

void
ssh_ppp_chap_output_challenge(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  SSH_DEBUG(SSH_D_MIDSTART,("sending CHAP challenge "));

  if (chap->challenge == NULL)
    return;

  pkt = ssh_ppp_chap_get_output_buf(gdata, chap);
  ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)(chap->challenge_length));
  ssh_ppp_pkt_buffer_append_buf(pkt,chap->challenge,chap->challenge_length);

  if (chap->my_name != NULL
      && chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV1
      && chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      if (ssh_ppp_pkt_buffer_get_trailer(pkt) < chap->my_name_length)
        {
          chap->my_name_length = ssh_ppp_pkt_buffer_get_trailer(pkt);
        }
      ssh_ppp_pkt_buffer_append_buf(pkt,chap->my_name,chap->my_name_length);
    }

  id = ssh_ppp_identifier_get(&chap->id,SSH_PPP_CHAP_CODE_CHALLENGE);
  ssh_ppp_chap_output_frame(gdata,chap,pkt,SSH_PPP_CHAP_CODE_CHALLENGE,id);
}

const
static unsigned char mschap_v2_magic1[] =
  {
    0x4d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65,
    0x6e, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
    0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74
  };

const
static unsigned char mschap_v2_magic2[] =
  {
    0x50, 0x61, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6b,
    0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x6d, 0x6f,
    0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
    0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
    0x6e
  };

static Boolean
ssh_ppp_chap_generate_authenticator_response_ascii(
                                             unsigned char *secret,
                                             size_t secret_length,
                                             unsigned char *peer_challenge,
                                             size_t peer_challenge_length,
                                             unsigned char *auth_challenge,
                                             size_t auth_challenge_length,
                                             unsigned char *user_name,
                                             size_t user_name_length,
                                             unsigned char *ntresponse,
                                             size_t ntresponse_length,
                                             unsigned char *dst,
                                             size_t dstlen)
{
  Boolean ret;
  unsigned char *tmpbuf;

  tmpbuf = ssh_ppp_chap_string_tounicode(secret, secret_length);
  if (tmpbuf == NULL)
    return FALSE;

  ret = ssh_ppp_chap_generate_authenticator_response(tmpbuf,
                                                     2*secret_length,
                                                     peer_challenge,
                                                     peer_challenge_length,
                                                     auth_challenge,
                                                     auth_challenge_length,
                                                     user_name,
                                                     user_name_length,
                                                     ntresponse,
                                                     ntresponse_length,
                                                     dst,
                                                     dstlen);

  ssh_free(tmpbuf);
  return ret;
}

Boolean
ssh_ppp_chap_generate_authenticator_response(unsigned char *secret,
                                             size_t secret_length,
                                             unsigned char *peer_challenge,
                                             size_t peer_challenge_length,
                                             unsigned char *auth_challenge,
                                             size_t auth_challenge_length,
                                             unsigned char *user_name,
                                             size_t user_name_length,
                                             unsigned char *ntresponse,
                                             size_t ntresponse_length,
                                             unsigned char *dst,
                                             size_t dstlen)
{
  SshHash sha1;
  SshCryptoStatus hash_status;
  size_t sha1_len;
  unsigned char md4_out[32];
  unsigned char challenge[32];
  unsigned char sha1_out[32];

  memset(dst,0,dstlen);

  /* Compute HashNTPasswordHash() into md4_out */

  ssh_ppp_chap_md4(secret, secret_length, md4_out, 32);
  ssh_ppp_chap_md4(md4_out, 16, md4_out, 16);

  /* Compute "ChallengeHash" into 8 first bytes of sha1_out */
  sha1 = NULL;
  hash_status = ssh_hash_allocate("sha1",&sha1);

  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate SHA1 algorithm when generating "
                 "authenticator response"));
      return FALSE;
    }

  sha1_len = ssh_hash_digest_length(ssh_hash_name(sha1));

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, peer_challenge, peer_challenge_length);
  ssh_hash_update(sha1, auth_challenge, auth_challenge_length);




  if (user_name != NULL && user_name_length > 0)
    ssh_hash_update(sha1, user_name, user_name_length);

  if (sha1_len <= 32)
    ssh_hash_final(sha1, challenge);
  else
    memset(challenge,0,32);

  /* Compute the main skeleton of GenerateAuthenticatorResponse() */
  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, md4_out, 16);
  ssh_hash_update(sha1, ntresponse, ntresponse_length);
  ssh_hash_update(sha1, mschap_v2_magic1, 39);

  if (sha1_len <= 32)
    ssh_hash_final(sha1,sha1_out);
  else
    memset(sha1_out,0,32);

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, sha1_out, sha1_len);
  ssh_hash_update(sha1, challenge, 8);
  ssh_hash_update(sha1, mschap_v2_magic2, 41);

  if (sha1_len <= dstlen)
    ssh_hash_final(sha1,dst);

  ssh_hash_free(sha1);

  return TRUE;
}

void
ssh_ppp_chap_output_success(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_chap_get_output_buf(gdata, chap);
  id = ssh_ppp_identifier_get(&chap->id,SSH_PPP_CHAP_CODE_SUCCESS);

  /* *_build_success() must be called to correctly build response_buf
     before calling output_success() */
  ssh_ppp_pkt_buffer_append_buf(pkt,chap->response_buf,
                                chap->response_length);

  /* Accept responses with same id's after success has been sent */
  ssh_ppp_identifier_get(&chap->id,SSH_PPP_CHAP_CODE_CHALLENGE);
  ssh_ppp_chap_output_frame(gdata,chap,pkt,SSH_PPP_CHAP_CODE_SUCCESS,id);
}

void
ssh_ppp_chap_output_failure(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_chap_get_output_buf(gdata, chap);
  id = ssh_ppp_identifier_get(&chap->id,SSH_PPP_CHAP_CODE_FAILURE);

  /* *_build_failure() must be called to correctly build response_buf
     before calling output_success() */

  ssh_ppp_pkt_buffer_append_buf(pkt,
                                chap->response_buf,
                                chap->response_length);
  ssh_ppp_chap_output_frame(gdata,chap,pkt,SSH_PPP_CHAP_CODE_FAILURE,id);
}

/* Just dump the previously computed response_buf into the packet */
void
ssh_ppp_chap_output_response(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;
  size_t trunclen;

  pkt = ssh_ppp_chap_get_output_buf(gdata, chap);

  SSH_DEBUG(SSH_D_MIDSTART,("sending CHAP response"));

  ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)chap->response_length);
  ssh_ppp_pkt_buffer_append_buf(pkt,chap->response_buf, chap->response_length);

  if (chap->my_name != NULL)
    {
      /* Note that authentication will most likely fail if the transmitted
         username is truncated. */

      trunclen = chap->my_name_length;

      if (ssh_ppp_pkt_buffer_get_trailer(pkt) < trunclen)
        trunclen = ssh_ppp_pkt_buffer_get_trailer(pkt);

      ssh_ppp_pkt_buffer_append_buf(pkt,chap->my_name,trunclen);
    }

  id = ssh_ppp_identifier_get(&chap->id, SSH_PPP_CHAP_CODE_RESPONSE);

  ssh_ppp_chap_output_frame(gdata,chap,pkt,SSH_PPP_CHAP_CODE_RESPONSE,id);
}

void
ssh_ppp_chap_expand_des_key(unsigned char *out, unsigned char *in)
{
  int i, i2, lshift, rshift;
  unsigned char tmp;

  rshift = 0;
  lshift = 7;
  tmp = 0;
  i2 = 0;

  for (i = 0; i < 7; i++)
    {
      tmp |= in[i] >> rshift++;
      out[i2++] = tmp & 0xFE;
      tmp = in[i] << lshift--;
    }

  out[i2++] = tmp & 0xFE;
}

static Boolean
ssh_ppp_chap_generate_ntresponse_ascii(unsigned char *secret,
                                       size_t secret_length,
                                       unsigned char *peer_challenge,
                                       size_t peer_challenge_length,
                                       unsigned char *challenge,
                                       size_t challenge_length,
                                       unsigned char *user_name,
                                       size_t user_name_length,
                                       unsigned char *dst,
                                       size_t dstlen)
{
  unsigned char *tmpbuf;
  Boolean ret;

  tmpbuf = NULL;
  if (secret != NULL)
    {
      tmpbuf = ssh_ppp_chap_string_tounicode(secret,secret_length);

      if (tmpbuf == NULL)
        return FALSE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("No CHAP secret provided for ntresponse"));
      return FALSE;
    }

  ret = ssh_ppp_chap_generate_ntresponse(tmpbuf,
                                         2*secret_length,
                                         peer_challenge,
                                         peer_challenge_length,
                                         challenge,
                                         challenge_length,
                                         user_name,
                                         user_name_length,
                                         dst,
                                         dstlen);

  ssh_free(tmpbuf);
  return ret;
}

static Boolean
ssh_ppp_chap_generate_ntresponse_v1_ascii(unsigned char *secret,
                                          size_t secret_length,
                                          unsigned char *challenge,
                                          size_t challenge_length,
                                          unsigned char *dst,
                                          size_t dstlen)
{
  unsigned char *tmpbuf;
  Boolean ret;

  tmpbuf = ssh_ppp_chap_string_tounicode(secret,secret_length);
  if (tmpbuf == NULL)
    return FALSE;

  ret = ssh_ppp_chap_generate_ntresponse_v1(tmpbuf,
                                            2*secret_length,
                                            challenge,
                                            challenge_length,
                                            dst,
                                            dstlen);

  ssh_free(tmpbuf);
  return ret;
}


static Boolean
ssh_ppp_chap_generate_md5response(unsigned char *secret,
                                  size_t secret_length,
                                  unsigned char *challenge,
                                  size_t challenge_length,
                                  SshUInt8 id,
                                  unsigned char *dst,
                                  size_t dstlen)
{
  SshHash md5;
  SshCryptoStatus hash_status;
  size_t len;

  memset(dst,0,dstlen);

  if (dstlen < 16)
    return FALSE;

  hash_status = ssh_hash_allocate("md5",&md5);

  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate MD5 algorithm when generating "
                 "CHAP response"));
      return FALSE;
    }

  ssh_hash_reset(md5);

  ssh_hash_update(md5,&id,1);

  if (secret != NULL)
    ssh_hash_update(md5,secret,secret_length);

  ssh_hash_update(md5,challenge,challenge_length);

  len = ssh_hash_digest_length(ssh_hash_name(md5));

  if (len <= dstlen)
    ssh_hash_final(md5,dst);

  ssh_hash_free(md5);
  return TRUE;
}

Boolean
ssh_ppp_chap_generate_ntresponse_v1(unsigned char *secret,
                                    size_t secret_length,
                                    unsigned char *challenge,
                                    size_t challenge_length,
                                    unsigned char *dst,
                                    size_t dstlen)
{
  unsigned char md4_out[32];
  unsigned char des_key[8];
  int in_idx,out_idx;

  memset(dst,0,dstlen);

  if (dstlen < 24 || challenge_length != 8)
    return FALSE;

  memset(md4_out,0,32);

  ssh_ppp_chap_md4(secret, secret_length, md4_out, 32);

  /* Compute ChallengeResponse */
  in_idx = 0;
  out_idx = 0;

  do {
    ssh_ppp_chap_expand_des_key(des_key, md4_out + in_idx);

    if (ssh_single_des_cbc(des_key,
                           8,
                           dst + out_idx,
                           challenge,
                           challenge_length) == FALSE)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("DES-CBC operation failed"));
        return FALSE;
      }

    out_idx += 8;
    in_idx += 7;
  } while (in_idx < 21);

  return TRUE;
}

Boolean
ssh_ppp_chap_nt_oldpwhash_encrypt_with_newpwhash(unsigned char *old_secret,
                                                 size_t old_secret_length,
                                                 unsigned char *new_secret,
                                                 size_t new_secret_length,
                                                 unsigned char *dst,
                                                 size_t dstlen)
{
  unsigned char opw_hash[16];
  unsigned char npw_hash[16];
  unsigned char des_key[8];

  memset(dst,0,dstlen);

  if (dstlen < 16)
    return FALSE;

  ssh_ppp_chap_md4(old_secret, old_secret_length, opw_hash, 16);
  ssh_ppp_chap_md4(new_secret, new_secret_length, npw_hash, 16);

  ssh_ppp_chap_expand_des_key(des_key, npw_hash);

  if (ssh_single_des_cbc(des_key,
                         8,
                         dst,
                         opw_hash,
                         8) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("DES-CBC operation failed"));
      return FALSE;
    }

  ssh_ppp_chap_expand_des_key(des_key, npw_hash+7);

  if (ssh_single_des_cbc(des_key,
                         8, dst+8, opw_hash+8, 8) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("DES-CBC operation failed"));
      return FALSE;
    }

  return TRUE;
}

Boolean
ssh_ppp_chap_generate_ntresponse(unsigned char *secret,
                                 size_t secret_length,
                                 unsigned char *peer_challenge,
                                 size_t peer_challenge_length,
                                 unsigned char *challenge,
                                 size_t challenge_length,
                                 unsigned char *user_name,
                                 size_t user_name_length,
                                 unsigned char *dst,
                                 size_t dstlen)
{
  SshHash sha1;
  SshCryptoStatus hash_status;
  unsigned char sha1_out[32];

  /* Compute "ChallengeHash" into 8 first bytes of sha1_out */

  memset(dst,0,dstlen);

  if (dstlen < 24)
    return FALSE;

  sha1 = NULL;
  hash_status = ssh_hash_allocate("sha1",&sha1);

  if (hash_status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not instantiate SHA1 algorithm when generating "
                 "NTresponse"));
      return FALSE;
    }

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, peer_challenge, peer_challenge_length);
  ssh_hash_update(sha1, challenge, challenge_length);





  if (user_name != NULL && user_name_length > 0)
    ssh_hash_update(sha1, user_name, user_name_length);

  if (ssh_hash_digest_length(ssh_hash_name(sha1)) <= 32)
    ssh_hash_final(sha1, sha1_out);
  else
    memset(sha1_out,0,32);

  ssh_hash_free(sha1);
  sha1 = NULL;

  return ssh_ppp_chap_generate_ntresponse_v1(secret,secret_length,
                                             sha1_out,8,
                                             dst,dstlen);
}

void
ssh_ppp_chap_build_response(SshPppState gdata, SshPppChap chap)
{
  SshUInt8 id;
  int i;
  unsigned char buf[SSH_PPP_MSCHAPV2_RESPONSE_LENGTH];

  SSH_DEBUG(SSH_D_MIDSTART,("constructing CHAP response"));

  /* "The Response Value is the one-way hash calculated over a stream of
      octets consisting of the Identifier, followed by (concatenated
      with) the "secret", followed by (concatenated with) the Challenge
      Value." [RFC 1994]. */

  if (chap->challenge == NULL)
    return;

  chap->response_length = 0;

  switch (chap->algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      id = ssh_ppp_identifier_get(&chap->id, SSH_PPP_CHAP_CODE_CHALLENGE);

      if (ssh_ppp_chap_generate_md5response(chap->secret_buf,
                                            chap->secret_length,
                                            chap->challenge,
                                            chap->challenge_length,
                                            id,
                                            chap->response_buf,
                                            SSH_PPP_CHAP_RESPONSE_LENGTH)
          == FALSE)
        {
          ssh_ppp_fatal(gdata);
        }
      chap->response_length = SSH_PPP_CHAP_RESPONSE_LENGTH;
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      for (i = 0; i < SSH_PPP_MSCHAPV2_RESERVED_LENGTH; i++)
        chap->response_buf[i + SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH] = 0;

      /* Based on the above, fill in the NTresponse field */
      if (ssh_ppp_chap_generate_ntresponse_ascii(
                                     chap->secret_buf,
                                     chap->secret_length,
                                     chap->response_buf,
                                     SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH,
                                     chap->challenge,
                                     chap->challenge_length,
                                     chap->my_name,
                                     chap->my_name_length,
                                     buf,
                                     SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH)
           == FALSE)
        {
          ssh_ppp_fatal(gdata);
        }

      memcpy(chap->response_buf
             + SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
             + SSH_PPP_MSCHAPV2_RESERVED_LENGTH,
             buf,
             SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH);

      /* Set flag byte to 0 */
      chap->response_buf[SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
                         + SSH_PPP_MSCHAPV2_RESERVED_LENGTH
                         + SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH] = 0;





      chap->response_length = SSH_PPP_MSCHAPV2_RESPONSE_LENGTH;
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
      memset(chap->response_buf,0,SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH);

      SSH_ASSERT(chap->secret_buf != NULL);

      if (ssh_ppp_chap_generate_ntresponse_v1_ascii(
                                          chap->secret_buf,
                                          chap->secret_length,
                                          chap->challenge,
                                          chap->challenge_length,
                                          buf,
                                          sizeof(buf))
           == FALSE)
        {
          ssh_ppp_fatal(gdata);
        }

      memcpy(chap->response_buf + SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH,
             buf,
             SSH_PPP_MSCHAPV1_NTRESPONSE_LENGTH);

      chap->response_buf[SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH
                         + SSH_PPP_MSCHAPV1_NTRESPONSE_LENGTH] = 0x01;

      chap->response_length = SSH_PPP_MSCHAPV1_RESPONSE_LENGTH;
      break;
    default:
      ssh_ppp_fatal(gdata);
      chap->response_length = 0;
      break;
    }
  return;
}

SshPppEvent
ssh_ppp_chap_input_challenge(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBufferStruct buf;
  SshUInt8 valuesize;
  SshUInt8 id;
  SshPppPktBuffer pkt;

  SSH_DEBUG(SSH_D_MIDSTART,("handling CHAP challenge"));

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf, pkt);

  SSH_ASSERT(ssh_ppp_chap_frame_isvalid(pkt) == SSH_PPP_OK);

  id = ssh_ppp_protocol_frame_get_id(pkt);

  if (ssh_ppp_identifier_ismatch(&chap->id,
                                 SSH_PPP_CHAP_CODE_CHALLENGE,
                                 id) == TRUE)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("received duplicate challenge packet, discarding"));
      return SSH_PPP_EVENT_NONE;
    }

  ssh_ppp_protocol_skip_hdr(pkt);

  valuesize = ssh_ppp_pkt_buffer_get_uint8(pkt,0);
  ssh_ppp_pkt_buffer_skip(pkt,1);

  if (valuesize > ssh_ppp_pkt_buffer_get_contentlen(pkt))
    {
      return SSH_PPP_EVENT_NONE;
    }

  if (valuesize != 8 && chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("received MS-CHAPv1 challenge that is of unexpected length"));
      return SSH_PPP_EVENT_NONE;
    }

  if (valuesize != 16 && chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("received MS-CHAPv2 challenge that is of unexpected length"));
      return SSH_PPP_EVENT_NONE;
    }

  ssh_ppp_chap_get_challenge_buf(gdata, chap, valuesize);

  if (chap->challenge == NULL)
    return SSH_PPP_EVENT_NONE;

  ssh_ppp_pkt_buffer_get_buf(pkt, 0, chap->challenge, valuesize);

  ssh_ppp_identifier_mark(&chap->id, SSH_PPP_CHAP_CODE_CHALLENGE,id);

  ssh_ppp_pkt_buffer_skip(pkt,valuesize);

  if (ssh_ppp_chap_get_peer_name(chap, pkt) == FALSE)
    {
      ssh_ppp_fatal(gdata);
      return SSH_PPP_EVENT_NONE;
    }

  return SSH_PPP_EVENT_CHALLENGE;
}

/* It is the responsibility of the function generating the
   SSH_PPP_EVENT_AUTH*FAIL event to call ssh_ppp_chap_build_failure() */
Boolean
ssh_ppp_chap_build_failure(SshPppState gdata, SshPppChap chap,
                           unsigned char *payload,
                           size_t payload_len)
{
  unsigned char *challenge;
  unsigned int error_value,retry_value,version_value;

  challenge = NULL;

  if (chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV1
      && chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      chap->response_length = 0;
      return FALSE;
    }

#define SSH_MSCHAP1_FSTR "E=691 R=0 C=0000000000000000 V=2"
#define SSH_MSCHAP2_FSTR "E=691 R=0 C=00000000000000000000000000000000 V=3 M="

  if (payload == NULL)
    {
      if (chap->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
        {
          payload = (unsigned char*)SSH_MSCHAP1_FSTR;

           /* - 1 for nul termination */
          payload_len = sizeof(SSH_MSCHAP1_FSTR) - 1;
        }
      else
        {
          payload = (unsigned char*)SSH_MSCHAP2_FSTR;

          /* - 1 for nul termination */
          payload_len = sizeof(SSH_MSCHAP2_FSTR) - 1;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("using externally provided failure message"));
    }

  if (ssh_ppp_chap_parse_mschap_failure(gdata,payload,payload_len,
                                        &error_value,
                                        &retry_value,
                                        &challenge,
                                        &version_value) == FALSE)
    {
      goto fail;
    }

  if (payload_len > SSH_PPP_CHAP_MAX_RESPONSE_LENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("truncating failure message"));
      payload_len = SSH_PPP_CHAP_MAX_RESPONSE_LENGTH;
    }

  if (retry_value != 0)
    {
      if (challenge == NULL)
        {
          /* No challenge was provided, try to use the previous
             challenge if we still have it cached. */
          if (chap->challenge == NULL)
            goto fail;
        }
      else
        {
          /* A new challenge was provided. */
          ssh_ppp_chap_get_challenge_buf(gdata, chap, chap->challenge_length);

          if (chap->challenge == NULL)
            goto fail;

          if (ssh_ppp_chap_fromhexstring(chap->challenge,
                                         challenge,
                                         chap->challenge_length) == FALSE)
            goto fail;
        }
    }

  memcpy(chap->response_buf, payload, payload_len);
  chap->response_length = payload_len;
  ssh_free(challenge);
  return TRUE;

 fail:
  chap->response_length = 0;
  ssh_free(challenge);
  return FALSE;
}


/* It is the responsibility of the function generating the
   SSH_PPP_EVENT_AUTH_OK event to call ssh_ppp_chap_build_success() */
void
ssh_ppp_chap_build_success(SshPppState gdata, SshPppChap chap,
                           unsigned char *payload,
                           size_t payload_len)
{
  unsigned char authresp[SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH];

  if (chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      chap->response_length = 0;
      return;
    }

  if (payload != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("using externally provided response authenticator"));

      if (payload_len > SSH_PPP_CHAP_MAX_RESPONSE_LENGTH)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("truncating response authenticator string"));

          payload_len = SSH_PPP_CHAP_MAX_RESPONSE_LENGTH;
        }

      memcpy(chap->response_buf, payload, payload_len);
      chap->response_length = payload_len;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("computing response authenticator"));

      if (chap->response_length != SSH_PPP_MSCHAPV2_RESPONSE_LENGTH)
        {
          /* The execution should never proceed this far unless there
             exists a suitable MS-CHAPv2 response in the buffer. */
          SSH_NOTREACHED;
          ssh_ppp_fatal(gdata);
          return;
        }

      SSH_ASSERT(chap->secret_buf != NULL);

      if (ssh_ppp_chap_generate_authenticator_response_ascii(
                                     chap->secret_buf,
                                     chap->secret_length,
                                     chap->response_buf,
                                     SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH,
                                     chap->challenge,
                                     chap->challenge_length,
                                     chap->peer_name,
                                     chap->peer_name_length,
                                     chap->response_buf
                                     + SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
                                     + SSH_PPP_MSCHAPV2_RESERVED_LENGTH,
                                     SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH,
                                     authresp,
                                     SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH)
           == FALSE)
        {
          ssh_ppp_fatal(gdata);
        }
      SSH_ASSERT((SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH*2+2)
                 <= SSH_PPP_MSCHAPV2_RESPONSE_LENGTH);

      chap->response_buf[0] = 'S';
      chap->response_buf[1] = '=';

      ssh_ppp_chap_tohexstring(chap->response_buf+2,authresp,
                               SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH);
      chap->response_length = SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH*2+2;
    }
}


SshPppEvent
ssh_ppp_chap_input_response(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBufferStruct buf;
  SshUInt8 valuesize;
  SshUInt8 id;
  SshPppPktBuffer pkt;
  size_t expected_length;

  SSH_DEBUG(SSH_D_MIDSTART,("CHAP checking response"));

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf, pkt);
  SSH_ASSERT(ssh_ppp_chap_frame_isvalid(pkt) == SSH_PPP_OK);

  id = ssh_ppp_protocol_frame_get_id(pkt);
  ssh_ppp_protocol_skip_hdr(pkt);

  if (!ssh_ppp_identifier_ismatch(&chap->id,
                                  SSH_PPP_CHAP_CODE_CHALLENGE, id))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("id %d/%d mismatch (should be %d/%d) , discarding response",
                 SSH_PPP_CHAP_CODE_CHALLENGE,id,
                 chap->id.code,chap->id.id));
      return SSH_PPP_EVENT_NONE;
    }

  valuesize = ssh_ppp_pkt_buffer_get_uint8(pkt, 0);
  ssh_ppp_pkt_buffer_skip(pkt,1);

  if (valuesize > ssh_ppp_pkt_buffer_get_contentlen(pkt))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("value length exceeds frame content length"));
      return SSH_PPP_EVENT_NONE;
    }

  switch (chap->algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      expected_length = SSH_PPP_CHAP_RESPONSE_LENGTH;
      break;
    default:
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
      expected_length = SSH_PPP_MSCHAPV1_RESPONSE_LENGTH;
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      expected_length = SSH_PPP_MSCHAPV2_RESPONSE_LENGTH;
      break;
    }

  if (valuesize != expected_length
       || valuesize > SSH_PPP_CHAP_MAX_RESPONSE_LENGTH)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("value length %d is unexpcted (expecting %d)",
                 valuesize, expected_length));
      return SSH_PPP_EVENT_NONE;
    }

  if (gdata->get_server_secret_cb == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CHAP secrets not configured, failing authentication"));
      return SSH_PPP_EVENT_AUTH_PEER_FAIL;
    }

  ssh_ppp_pkt_buffer_get_buf(pkt, 0, chap->response_buf, valuesize);
  chap->response_length = valuesize;

  ssh_ppp_pkt_buffer_skip(pkt, valuesize);

  if (ssh_ppp_chap_get_peer_name(chap, pkt) == FALSE)
    {
      ssh_ppp_fatal(gdata);
      return SSH_PPP_EVENT_NONE;
    }

  return SSH_PPP_EVENT_RESPONSE;
}

static SshPppEvent
ssh_ppp_chap_check_server_secret(SshPppState gdata, SshPppChap chap)
{
  SshUInt8 hashbuf[SSH_PPP_CHAP_RESPONSE_LENGTH];
  unsigned char buf[SSH_PPP_MSCHAPV2_RESPONSE_LENGTH];
  SshUInt8 id;

  if (chap->secret_buf == NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,("Failing authentication because no secret"));
      return SSH_PPP_EVENT_AUTH_PEER_FAIL;
    }

  switch (chap->algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      id = ssh_ppp_identifier_get(&chap->id, SSH_PPP_CHAP_CODE_CHALLENGE);

      if (ssh_ppp_chap_generate_md5response(chap->secret_buf,
                                            chap->secret_length,
                                            chap->challenge,
                                            chap->challenge_length,
                                            id,
                                            hashbuf,
                                            SSH_PPP_CHAP_RESPONSE_LENGTH)
          == FALSE)
        {
          ssh_ppp_fatal(gdata);
          SSH_DEBUG(SSH_D_ERROR,
                    ("Error in computation of correct MD5 response, "
                     "failing authentication"));
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }

      if (memcmp(chap->response_buf, hashbuf,
                 SSH_PPP_CHAP_RESPONSE_LENGTH) == 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,("CHAP Authentication succeeded"));
          return SSH_PPP_EVENT_AUTH_OK;
        }
      break;

    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
      if (SSH_PPP_MSCHAPV1_RESPONSE_LENGTH != chap->response_length)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("MS-CHAPv1 response has incorrect length %ld"
                     " (expecting %d)",
                     chap->response_length,
                     SSH_PPP_MSCHAPV1_RESPONSE_LENGTH));
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }

      SSH_ASSERT(chap->secret_buf != NULL);
      if (ssh_ppp_chap_generate_ntresponse_v1_ascii(
                                        chap->secret_buf,
                                        chap->secret_length,
                                        chap->challenge,
                                        chap->challenge_length,
                                        buf,
                                        sizeof(buf))
          == FALSE)
        {
          ssh_ppp_fatal(gdata);
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }


      if (memcmp(chap->response_buf + SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH,
                 buf,
                 SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH) == 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,("MS-CHAPv1 Authentication succeeded"));
          return SSH_PPP_EVENT_AUTH_OK;
        }

      break;

    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      if (SSH_PPP_MSCHAPV2_RESPONSE_LENGTH != chap->response_length)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("MS-CHAPv2 response has incorrect length %ld"
                     " (expecting %d)",
                     chap->response_length,
                     SSH_PPP_MSCHAPV2_RESPONSE_LENGTH));
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }

      if (ssh_ppp_chap_generate_ntresponse_ascii(
                                       chap->secret_buf,
                                       chap->secret_length,
                                       chap->response_buf,
                                       SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH,
                                       chap->challenge,
                                       chap->challenge_length,
                                       chap->peer_name,
                                       chap->peer_name_length,
                                       buf,
                                       sizeof(buf))
           == FALSE)
        {
          ssh_ppp_fatal(gdata);
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }

      if (memcmp(chap->response_buf
                 + SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
                 + SSH_PPP_MSCHAPV2_RESERVED_LENGTH,
                 buf,
                 SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH) == 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,("MS-CHAPv2 Authentication succeeded"));
          return SSH_PPP_EVENT_AUTH_OK;
        }
      break;
    }

  SSH_DEBUG(SSH_D_MIDOK,("Authentication failed"));
  return SSH_PPP_EVENT_AUTH_PEER_FAIL;
}

SshPppEvent
ssh_ppp_chap_input_server_secret(SshPppState gdata, SshPppChap chap)
{
  SshPppEvent ret;

  ret = ssh_ppp_chap_check_server_secret(gdata,chap);

  if (ret == SSH_PPP_EVENT_AUTH_OK)
    ssh_ppp_chap_build_success(gdata,chap,NULL,0);
  else if (ret == SSH_PPP_EVENT_AUTH_PEER_FAIL)
    ssh_ppp_chap_build_failure(gdata,chap,NULL,0);

  return ret;
}

void
ssh_ppp_chap_get_changepw_status(SshPppState gdata, SshPppChap chap)
{
#ifdef SSHDIST_RADIUS
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct pktbuf;
  size_t contentlen;
  unsigned char *ucp;
  SshUInt8 id;
#else /* SSHDIST_RADIUS */
  /* NOTE: If RADIUS is not configured. NOTHING IS DONE. This
     will result in a timeout. This is not a problem, as we
     currently do not send out failure packets with pw expired
     errors unless RADIUS is used */
  return;
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_RADIUS

  if ((chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV1
       && chap->algorithm != SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
      || chap->is_radius_used == 0)
    return;

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&pktbuf,pkt);

  ssh_ppp_protocol_skip_hdr(pkt);
  contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);
  ucp = ssh_ppp_pkt_buffer_get_ptr(pkt,0,contentlen);

  id = ssh_ppp_identifier_get(&chap->id,SSH_PPP_CHAP_CODE_CHALLENGE);

  if (ssh_ppp_radius_make_changepw_query(gdata,
                                         &chap->radius_client,
                                         chap->algorithm,
                                         id,
                                         chap->peer_name,
                                         chap->peer_name_length,
                                         chap->challenge,
                                         chap->challenge_length,
                                         ucp,
                                         contentlen) == FALSE)
    {
      ssh_ppp_fatal(gdata);
      return;
    }
  return;
#endif /* SSHDIST_RADIUS */
}

SshPppEvent
ssh_ppp_chap_input_success(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct pktbuf;
  size_t len,contentlen,secretlen;
  unsigned char buf[SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH];
  unsigned char hexbuf[SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH*2];
  unsigned char *authresp;
  unsigned char *secret;
  Boolean res;

  SSH_DEBUG(SSH_D_MIDOK,("handling success"));

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&pktbuf,pkt);

  switch (chap->algorithm)
    {
      /* Success packets are identical for CHAP and MS-CHAPv1 */
    case SSH_PPP_CHAP_ALGORITHM_MD5:
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      len = ssh_ppp_protocol_frame_get_len(pkt);
      contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);

      if (len > contentlen)
        return SSH_PPP_EVENT_AUTH_PEER_FAIL;

      ssh_ppp_protocol_skip_hdr(pkt);

      if (len < (2*SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH + 6))
        return SSH_PPP_EVENT_AUTH_PEER_FAIL;

      authresp =
        ssh_ppp_pkt_buffer_get_ptr(pkt,0,2*SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH+2);

      if (memcmp(authresp,"S=",2) != 0)
        return SSH_PPP_EVENT_AUTH_PEER_FAIL;

      if (chap->is_secret_newpw == 1)
        {
          secret = chap->new_secret_buf;
          secretlen = chap->new_secret_length;
        }
      else
        {
          secret = chap->secret_buf;
          secretlen = chap->secret_length;
        }

      res = ssh_ppp_chap_generate_authenticator_response_ascii(
                                     secret,
                                     secretlen,
                                     chap->response_buf,
                                     SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH,
                                     chap->challenge,
                                     chap->challenge_length,
                                     chap->my_name,
                                     chap->my_name_length,
                                     chap->response_buf
                                     + SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
                                     + SSH_PPP_MSCHAPV2_RESERVED_LENGTH,
                                     SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH,
                                     buf,
                                     SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH);

      if (res == FALSE)
        {
          ssh_ppp_fatal(gdata);
          return SSH_PPP_EVENT_AUTH_PEER_FAIL;
        }

      ssh_ppp_chap_tohexstring(hexbuf,buf,SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH);

      if (memcmp(authresp+2,hexbuf,SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH*2) != 0)
        return SSH_PPP_EVENT_AUTH_PEER_FAIL;

      break;
    }

  return SSH_PPP_EVENT_AUTH_OK;
}

static SshPppEvent
ssh_ppp_chap_input_mschap_failure(SshPppState gdata, SshPppChap chap)
{
  SshPppPktBuffer pkt;
  SshPppPktBufferStruct pktbuf;
  size_t len,contentlen;
  unsigned char *ucp;

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&pktbuf,pkt);

  /* Attempt to parse the silly packet */

  len = ssh_ppp_protocol_frame_get_len(pkt);
  contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);

  if (len > contentlen)
    return SSH_PPP_EVENT_AUTH_THIS_FAIL;

  ssh_ppp_protocol_skip_hdr(pkt);
  contentlen = ssh_ppp_pkt_buffer_get_contentlen(pkt);
  ucp = ssh_ppp_pkt_buffer_get_ptr(pkt,0,contentlen);

  return ssh_ppp_chap_mschap_failure_to_event(gdata,chap,ucp,contentlen);
}

SshPppEvent
ssh_ppp_chap_input_failure(SshPppState gdata, SshPppChap chap)
{
  SSH_DEBUG(SSH_D_MIDOK,("handling failure"));

  switch (chap->algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      return ssh_ppp_chap_input_mschap_failure(gdata,chap);
    }

  return SSH_PPP_EVENT_AUTH_THIS_FAIL;
}

SshPppEvent
ssh_ppp_chap_input(SshPppState state, SshPppChap chap)
{
  SshUInt8 type;
  SshPppPktBuffer pkt;
  SshPppEvent ev;

  SSH_ASSERT(chap != NULL);

  pkt = ssh_ppp_thread_get_input_pkt(chap->ppp_thread);

  if (ssh_ppp_chap_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      SSH_DEBUG(SSH_D_NETGARB,("CHAP frame is not valid, discarding"));
      return SSH_PPP_EVENT_NONE;
    }

  type = ssh_ppp_protocol_frame_get_code(pkt);

  SSH_DEBUG(SSH_D_HIGHSTART,("Handling CHAP code %d id %d",type,
                             ssh_ppp_protocol_frame_get_id(pkt)));

  switch (type)
    {
    case SSH_PPP_CHAP_CODE_CHALLENGE:
      return ssh_ppp_chap_input_challenge(state,chap);

    case SSH_PPP_CHAP_CODE_RESPONSE:
      ev = ssh_ppp_chap_input_response(state,chap);
      return ev;

    case SSH_PPP_CHAP_CODE_SUCCESS:
      return ssh_ppp_chap_input_success(state,chap);

    case SSH_PPP_CHAP_CODE_FAILURE:
      return ssh_ppp_chap_input_failure(state,chap);

    case SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv2:
    case SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv3:
      SSH_DEBUG(SSH_D_NETGARB, ("Changing CHAP password is not supported"));
      break;

    default:
      SSH_DEBUG(SSH_D_NETGARB,("Unknown CHAP code %d received!",type));
    }

  return SSH_PPP_EVENT_NONE;
}

SshPppEvents
ssh_ppp_chap_get_eventq(SshPppChap chap)
{
  SshPppEvents evs;

  SSH_PRECOND(chap != NULL);

  evs = ssh_ppp_thread_get_events(chap->ppp_thread);
  return evs;
}
