/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Service object handling.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmServices"

SshPmService
ssh_pm_service_create(SshPm pm, const char *name)
{
  SshPmService service;

  service = ssh_pm_service_alloc(pm);
  if (service == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate service object"));
      return NULL;
    }

  service->service_name = NULL;

  if (name != NULL)
    {
      service->service_name = ssh_strdup(name);
      if (service->service_name == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate service object name"));
          goto error;
        }
    }

  service->pm = pm;
  service->unique_id = pm->next_service_id++;
  service->refcount = 1;

  return service;

 error:

  ssh_free(service->service_name);
  ssh_pm_service_free(pm, service);

  return NULL;

}


void
ssh_pm_service_destroy(SshPmService service)
{
  if (service == NULL)
    return;

  if (--service->refcount > 0)
    return;

  ssh_free(service->service_name);
  ssh_free(service->appgw_ident);
  ssh_free(service->appgw_config);
  ssh_free(service->new_appgw_config);

  ssh_pm_service_free(service->pm, service);
}

Boolean
ssh_pm_service_set_appgw(SshPmService service, const char *ident)
{
  if (service->appgw_ident)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Application gateway can be specified only once"));
      return FALSE;
    }

  service->appgw_ident = ssh_strdup(ident);

  if (service->appgw_ident == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for application "
                              "gateway identification"));
      ssh_free(service->appgw_ident);
      return FALSE;
    }

  return TRUE;
}


Boolean
ssh_pm_service_set_appgw_config(SshPmService service,
                                const unsigned char *config,
                                size_t config_len)
{
  unsigned char *tmp;

  if (service->appgw_ident == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("No application gateway configured for the service"));
      return FALSE;
    }

  /* Check if the configuration data changes. */
  if (service->appgw_config && service->appgw_config_len == config_len)
    {
      if (memcmp(service->appgw_config, config, config_len) == 0)
        /* No changes.  We are done here. */
        return TRUE;
    }

  tmp = ssh_memdup(config, config_len);
  if (tmp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not store configuration data"));
      return FALSE;
    }
  /* Free the possible old pending configuration data. */
  ssh_free(service->new_appgw_config);

  /* And store the new one. */
  service->new_appgw_config = tmp;
  service->new_appgw_config_len = config_len;

  return TRUE;
}


Boolean
ssh_pm_service_compare(SshPm pm, SshPmService service1, SshPmService service2)
{
  if (service1->service_name && service2->service_name)
    {
      if (strcmp(service1->service_name, service2->service_name) != 0)
        return FALSE;
    }
  else if (service1->service_name && !service2->service_name)
    return FALSE;
  else if (!service1->service_name && service2->service_name)
    return FALSE;

  if (service1->flags != service2->flags)
    return FALSE;

  if (service1->appgw_ident && service2->appgw_ident)
    {
      if (strcmp(service1->appgw_ident, service2->appgw_ident) != 0)
        return FALSE;
    }
  else if (service1->appgw_ident && !service2->appgw_ident)
    return FALSE;
  else if (!service1->appgw_ident && service2->appgw_ident)
    return FALSE;

  /* The appgw configuration data is not handled here. */

  /* They are equal. */
  return TRUE;
}
