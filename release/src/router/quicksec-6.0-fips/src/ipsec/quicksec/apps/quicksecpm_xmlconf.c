/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML configuration for QuickSec policy manager.
*/











#include "sshincludes.h"
#include "sshmp-xuint.h"
#include "quicksecpm_xmlconf.h"
#include "quicksecpm_xmlconf_i.h"


#ifdef SSH_IPSEC_XML_CONFIGURATION

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmXmlConf"

/* Make it easier to test for sha2. */
#ifdef SSHDIST_CRYPT_SHA256
#define SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
#else /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
#define SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
#endif /*  SSHDIST_CRYPT_SHA512 */
#endif /* SSHDIST_CRYPT_SHA256 */

/* Forward declarations for policy object handling */
void ssh_ipm_purge_ek_providers(SshIpmContext ctx, Boolean purge_old);



/**************************** ADT bag for rules *****************************/

static SshUInt32
ssh_ipm_xmlconf_rule_hash(void *ptr, void *ctx)
{
  SshIpmRule rule = (SshIpmRule) ptr;

  return rule->precedence;
}


static int
ssh_ipm_xmlconf_rule_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshIpmRule rule1 = (SshIpmRule) ptr1;
  SshIpmRule rule2 = (SshIpmRule) ptr2;

  if (rule1->precedence != rule2->precedence)
    return -1;

  return 0;
}


static void
ssh_ipm_xmlconf_rule_destroy(void *ptr, void *ctx)
{
  SshIpmRule rule = (SshIpmRule) ptr;

  ssh_free(rule);
}

/* Lookup a rule by the precedence `precedence'.  If there is no rule
   with the given precedence, the function creates a new rule object.
   The function returns the IPM rule object or NULL if the system ran
   out of memory. */
static SshIpmRule
ssh_ipm_xmlconf_rule_get(SshIpmContext ctx, SshUInt32 precedence)
{
  SshIpmRuleStruct rule_struct;
  SshIpmRule rule;
  SshADTHandle h;

  memset(&rule_struct, 0, sizeof(rule_struct));
  rule_struct.precedence = precedence;

  h = ssh_adt_get_handle_to_equal(ctx->rules, &rule_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* Create a new rule object. */
      rule = ssh_calloc(1, sizeof(*rule));
      if (rule == NULL)
        return NULL;

      rule->precedence = precedence;
      rule->rule = SSH_IPSEC_INVALID_INDEX;
      rule->new_rule = SSH_IPSEC_INVALID_INDEX;

      ssh_adt_insert(ctx->rules, rule);
    }
  else
    {
      rule = ssh_adt_get(ctx->rules, h);
    }

  return rule;
}

/********************* ADT bag for audit modules *********************/

static SshUInt32
ssh_ipm_xmlconf_audit_hash(void *ptr, void *ctx)
{
  SshIpmAudit audit = (SshIpmAudit) ptr;
  SshUInt32 h = 0;
  size_t i;

  for (i = 0; i < strlen(audit->audit_name); i++)
    {
      h += audit->audit_name[i];
      h += h << 10;
      h ^= h >> 6;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;

  return h;
}


static int
ssh_ipm_xmlconf_audit_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshIpmAudit audit1 = (SshIpmAudit) ptr1;
  SshIpmAudit audit2 = (SshIpmAudit) ptr2;

  if (audit1->format != audit2->format)
    return -1;
  if (strcmp(audit1->audit_name, audit2->audit_name))
    return -1;

  return 0;
}


static void
ssh_ipm_xmlconf_audit_destroy(void *ptr, void *ctx)
{
  SshIpmAudit audit = (SshIpmAudit) ptr;

  ssh_free(audit->audit_name);
  ssh_free(audit);
}


static SshIpmAudit
ssh_ipm_xmlconf_audit_get(SshIpmContext ctx, const char *audit_name,
                          SshUInt32 format)
{
  SshIpmAuditStruct audit_struct;
  SshIpmAudit audit;
  SshADTHandle h;

  memset(&audit_struct, 0, sizeof(audit_struct));
  audit_struct.audit_name = (char *)audit_name;
  audit_struct.format = format;

  h = ssh_adt_get_handle_to_equal(ctx->audit_modules, &audit_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* Create a new audit object. */
      audit = ssh_calloc(1, sizeof(*audit));
      if (audit == NULL)
        return NULL;

      audit->audit_name = ssh_strdup(audit_name);
      if (audit->audit_name == NULL)
        {
          ssh_free(audit);
          return NULL;
        }
      audit->format = format;

      ssh_adt_insert(ctx->audit_modules, audit);
    }
  else
    {
      audit = ssh_adt_get(ctx->audit_modules, h);
    }

  return audit;
}


/********************* ADT bag for other policy objects *********************/

static SshUInt32
ssh_ipm_xmlconf_object_hash(void *ptr, void *ctx)
{
  SshIpmPolicyObject object = (SshIpmPolicyObject) ptr;
  SshUInt32 h = 0;
  size_t i;

  for (i = 0; i < object->name_len; i++)
    {
      h += object->name[i];
      h += h << 10;
      h ^= h >> 6;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;

  return h;
}


static int
ssh_ipm_xmlconf_object_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshIpmPolicyObject object1 = (SshIpmPolicyObject) ptr1;
  SshIpmPolicyObject object2 = (SshIpmPolicyObject) ptr2;

  if (object1->name_len != object2->name_len)
    return -1;

  return memcmp(object1->name, object2->name, object1->name_len);
}


static void
ssh_ipm_policy_object_value_free(SshIpmContext ctx,
                                 SshIpmPolicyObjectValue value)
{
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  switch (value->type)
    {
    case SSH_IPM_POLICY_OBJECT_NONE:
      /* Nothing to destroy. */
      break;

    case SSH_IPM_POLICY_OBJECT_SERVICE:
      ssh_pm_service_destroy(value->u.service);
      break;

    case SSH_IPM_POLICY_OBJECT_PSK:
      ssh_free(value->u.psk.identity);
      ssh_free(value->u.psk.secret);
      break;

    case SSH_IPM_POLICY_OBJECT_TUNNEL:
      ssh_pm_tunnel_destroy(pm, value->u.tunnel);
      break;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    case SSH_IPM_POLICY_OBJECT_ADDRPOOL:
      ssh_pm_ras_remove_addrpool(pm, value->u.addrpool_name);
      ssh_free(value->u.addrpool_name);
      break;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }
}


static void
ssh_ipm_xmlconf_object_destroy(void *ptr, void *adt_ctx)
{
  SshIpmPolicyObject object = (SshIpmPolicyObject) ptr;
  SshIpmContext ctx = (SshIpmContext) adt_ctx;

  ssh_ipm_policy_object_value_free(ctx, &object->value);
  ssh_ipm_policy_object_value_free(ctx, &object->new_value);

  ssh_free(object->name);
  ssh_free(object);
}

/* Lookup a policy object by its name `name', `name_len'.  If the is
   no policy object matching the name, the function creates a new
   policy object.  The function returns a policy object or NULL if the
   system ran out of memory. */
static SshIpmPolicyObject
ssh_ipm_xmlconf_policy_object_get(SshIpmContext ctx, const unsigned char *name,
                                  size_t name_len)
{
  SshIpmPolicyObjectStruct object_struct;
  SshIpmPolicyObject object;
  SshADTHandle h;

  memset(&object_struct, 0, sizeof(object_struct));
  object_struct.name = (unsigned char *) name;
  object_struct.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(ctx->policy_objects, &object_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* Create a new policy object. */
      object = ssh_calloc(1, sizeof(*object));
      if (object == NULL)
        return NULL;

      object->name = ssh_memdup(name, name_len);
      if (object->name == NULL)
        {
          ssh_free(object);
          return NULL;
        }
      object->name_len = name_len;

      ssh_adt_insert(ctx->policy_objects, object);
    }
  else
    {
      object = ssh_adt_get(ctx->policy_objects, h);
    }

  /* This object is seen. */
  object->seen = 1;

  return object;
}

/* Return the value of the policy object `name', `name_len' of type
   `type'.  The function returns the value that will be the active
   value when the current reconfiguration operation completes.  The
   function returns the value of the policy object or NULL if the
   policy object is not of the required type. */
static void *
ssh_ipm_xmlconf_policy_object_value(SshIpmContext ctx,
                                    const unsigned char *name, size_t name_len,
                                    SshIpmPolicyObjectType type)
{
  SshIpmPolicyObject object;
  SshIpmPolicyObjectValue value;

  /* Lookup the object. */
  object = ssh_ipm_xmlconf_policy_object_get(ctx, name, name_len);
  if (object == NULL)
    return NULL;

  /* Does it have a new value? */
  if (object->new_value.type)
    {
      if (object->new_value.type != type)
        /* The new value is of invalid type. */
        return NULL;

      /* The new value is set and it is of correct type. */
      value = &object->new_value;
    }
  else
    {
      /* No new value.  The current one is also valid after the
         reconfiguration. */
      if (object->value.type != type)
        /* The current value is of invalid type. */
        return NULL;

      value = &object->value;
    }

  /* Return the value. */
  SSH_ASSERT(value->type == type);
  switch (value->type)
    {
    case SSH_IPM_POLICY_OBJECT_NONE:
      SSH_NOTREACHED;
      break;

    case SSH_IPM_POLICY_OBJECT_SERVICE:
      return value->u.service;
      break;


    case SSH_IPM_POLICY_OBJECT_PSK:
      return &value->u.psk;
      break;

    case SSH_IPM_POLICY_OBJECT_TUNNEL:
      return value->u.tunnel;
      break;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    case SSH_IPM_POLICY_OBJECT_ADDRPOOL:
      return value->u.addrpool_name;
      break;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

    }

  SSH_NOTREACHED;
  return NULL;
}




/****************** ADT bag for access control group names ******************/

static SshUInt32
ssh_ipm_xmlconf_group_hash(void *ptr, void *ctx)
{
  SshIpmAuthGroupId id = (SshIpmAuthGroupId) ptr;
  SshUInt32 h = 0;
  size_t i;

  for (i = 0; i < id->name_len; i++)
    {
      h += id->name[i];
      h += h << 10;
      h ^= h >> 6;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;

  return h;
}

static int
ssh_ipm_xmlconf_group_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshIpmAuthGroupId id1 = (SshIpmAuthGroupId) ptr1;
  SshIpmAuthGroupId id2 = (SshIpmAuthGroupId) ptr2;

  if (id1->name_len != id2->name_len)
    return -1;

  return memcmp(id1->name, id2->name, id1->name_len);
}


static void
ssh_ipm_xmlconf_group_destroy(void *ptr, void *ctx)
{
  SshIpmAuthGroupId id = (SshIpmAuthGroupId) ptr;

  ssh_free(id->name);
  ssh_free(id);
}

/* Lookup the group ID for the group `name', `name_len'.  The function
   returns the group ID or 0 if the group is unknown. */
static SshUInt32
ssh_ipm_lookup_group(SshIpmContext ctx, const unsigned char *name,
                     size_t name_len)
{
  SshIpmAuthGroupIdStruct id_struct;
  SshIpmAuthGroupId id;
  SshADTHandle h;

  /* Do we know this group? */

  memset(&id_struct, 0, sizeof(id_struct));
  id_struct.name = (unsigned char *) name;
  id_struct.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(ctx->auth_groups, &id_struct);
  if (h != SSH_ADT_INVALID)
    {
      id = ssh_adt_get(ctx->auth_groups, h);
      return id->group_id;
    }

  /* An unknown group. */
  return 0;
}

/* Allocate a new authorization group.  The function returns the group
   or NULL if the system ran out of memory. */
static SshPmAuthorizationGroup
ssh_ipm_create_group(SshIpmContext ctx, const unsigned char *name,
                     size_t name_len)
{
  SshUInt32 group_id;

  /* Do we know this group? */

  group_id = ssh_ipm_lookup_group(ctx, name, name_len);
  if (group_id == 0)
    {
      SshIpmAuthGroupId id;

      /* Create a new group. */
      id = ssh_calloc(1, sizeof(*id));
      if (id == NULL)
        return NULL;

      id->name = ssh_memdup(name, name_len);
      if (id->name == NULL)
        {
          ssh_free(id);
          return NULL;
        }
      id->name_len = name_len;
      group_id = id->group_id = ctx->next_group_id++;

      ssh_adt_insert(ctx->auth_groups, id);
    }

  /* Now the group ID is known.  Allocate and return the actual
     authorization group. */
  return ssh_pm_authorization_group_create(group_id);
}



/************************** Static help functions ***************************/


/* Clear the topmost item in the parse stack. */
static void
ssh_ipm_clear_frame(SshIpmContext ctx)
{
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  if (ctx->state == NULL)
    return;

  switch (ctx->state->type)
    {
    case SSH_IPM_XMLCONF_ADDR_POOL:
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      ssh_free(ctx->state->u.addrpool.remote_access_attr_own_ip);
      ssh_free(ctx->state->u.addrpool.remote_access_attr_dns);
      ssh_free(ctx->state->u.addrpool.remote_access_attr_wins);
      ssh_free(ctx->state->u.addrpool.remote_access_attr_dhcp);
      ssh_free(ctx->state->u.addrpool.remote_access_ipv6_prefix);
      ssh_free(ctx->state->u.addrpool.address_pool_name);

      while (ctx->state->u.addrpool.remote_access_attr_subnet_list != NULL)
        {
          SshIpmRasSubnetConfig subnet;

          subnet = ctx->state->u.addrpool.remote_access_attr_subnet_list;

          ctx->state->u.addrpool.remote_access_attr_subnet_list = subnet->next;
          ssh_free(subnet->address);
          ssh_free(subnet);
        }
      while (ctx->state->u.addrpool.remote_access_attr_address_list != NULL)
        {
          SshIpmRasAddressConfig address;

          address = ctx->state->u.addrpool.remote_access_attr_address_list;

          ctx->state->u.addrpool.remote_access_attr_address_list =
            address->next;
          ssh_free(address->address);
          ssh_free(address->netmask);
          ssh_free(address);
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
      break;

    case SSH_IPM_XMLCONF_MANUAL_KEY:
      ssh_free(ctx->state->u.manual_key.encr_key_i);
      ssh_free(ctx->state->u.manual_key.encr_key_o);
      ssh_free(ctx->state->u.manual_key.auth_key_i);
      ssh_free(ctx->state->u.manual_key.auth_key_o);
      break;

#ifdef SSHDIST_CERT
    case SSH_IPM_XMLCONF_CERTIFICATE:
    case SSH_IPM_XMLCONF_CRL:
    case SSH_IPM_XMLCONF_PRVKEY:
    case SSH_IPM_XMLCONF_PUBKEY:
      ssh_free(ctx->state->u.keycert.file);
      break;
#endif /* SSHDIST_CERT */

    case SSH_IPM_XMLCONF_PSK:
      ssh_free(ctx->state->u.psk.psk_ref);
      ssh_free(ctx->state->u.psk.identity);
      break;

    case SSH_IPM_XMLCONF_IDENTITY:
      ssh_free(ctx->state->u.tunnel.identity);
      break;

    case SSH_IPM_XMLCONF_ACCESS_GROUP:
      ssh_pm_authorization_group_destroy(ctx->state->u.group.group);
      break;

    case SSH_IPM_XMLCONF_SERVICE:
      if (ctx->state->u.service.service)
        ssh_pm_service_destroy(ctx->state->u.service.service);
      ssh_free(ctx->state->u.service.appgw_config);
      break;

    case SSH_IPM_XMLCONF_APPGW:
      ssh_free(ctx->state->u.appgw.id);

      /* Detach DOM object from the parser if it is attached. */
      if (ctx->state->u.appgw.attached)
        ssh_xml_dom_detach(ctx->state->u.appgw.dom);

      ssh_xml_dom_destroy(ctx->state->u.appgw.dom);
      break;

    case SSH_IPM_XMLCONF_TUNNEL:
      if (ctx->state->u.tunnel.tunnel)
        ssh_pm_tunnel_destroy(pm, ctx->state->u.tunnel.tunnel);
      break;

    case SSH_IPM_XMLCONF_CA:
      ssh_free(ctx->state->u.ca.file);
      break;
#ifdef SSHDIST_IKE_REDIRECT
    case SSH_IPM_XMLCONF_IKE_REDIRECT:
      ssh_free(ctx->state->u.ike_redirect.redirect_addr);
      break;
#endif /* SSHDIST_IKE_REDIRECT */
    case SSH_IPM_XMLCONF_TUNNEL_AUTH:
    case SSH_IPM_XMLCONF_PEER:
    case SSH_IPM_XMLCONF_LOCAL_IP:
    case SSH_IPM_XMLCONF_LOCAL_IFACE:
    case SSH_IPM_XMLCONF_LOCAL_PORT:
    case SSH_IPM_XMLCONF_IKE_VERSIONS:
    case SSH_IPM_XMLCONF_IKE_GROUPS:
    case SSH_IPM_XMLCONF_PFS_GROUPS:
    case SSH_IPM_XMLCONF_IKE_ALGORITHMS:
    case SSH_IPM_XMLCONF_IKE_WINDOW_SIZE:
#ifdef SSHDIST_IKE_REDIRECT
    case SSH_IPM_XMLCONF_REDIRECT_ADDRESS:
#endif /* SSHDIST_IKE_REDIRECT */
    case SSH_IPM_XMLCONF_LIFE:
    case SSH_IPM_XMLCONF_CFGMODE_ADDRESS:
    case SSH_IPM_XMLCONF_VIRTUAL_IFNAME:
    case SSH_IPM_XMLCONF_PARAMS:
    case SSH_IPM_XMLCONF_SUBNET:
    case SSH_IPM_XMLCONF_IPV6_PREFIX:
    case SSH_IPM_XMLCONF_TUNNEL_ADDRESS_POOL:
    case SSH_IPM_XMLCONF_ADDRESS:
    case SSH_IPM_XMLCONF_POLICY:
    case SSH_IPM_XMLCONF_AUDIT:
#ifdef SSH_IPSEC_TCPENCAP
    case SSH_IPM_XMLCONF_TCP_ENCAPS:
#endif /* SSH_IPSEC_TCPENCAP */
      break;

    case SSH_IPM_XMLCONF_AUTH_DOMAIN:
    case SSH_IPM_XMLCONF_RULE:
    case SSH_IPM_XMLCONF_DNS:
    case SSH_IPM_XMLCONF_SRC:
    case SSH_IPM_XMLCONF_DST:
    case SSH_IPM_XMLCONF_IFNAME:
    case SSH_IPM_XMLCONF_ENGINE_PARAMS:
    case SSH_IPM_XMLCONF_GROUP_REF:
    case SSH_IPM_XMLCONF_RADIUS_ACCOUNTING:
      break;
   }
}

/* Push a fresh stack frame into the context `ctx'. */
static void
ssh_ipm_push(SshIpmContext ctx, SshIpmXmlconfType type)
{
  size_t index;

  if (ctx->state == NULL)
    ctx->state = &ctx->stack[0];
  else
    {
      index = ctx->state - ctx->stack;
      SSH_ASSERT(index + 1 < SSH_IPM_STACK_DEPTH);
      ctx->state = &ctx->stack[index + 1];
    }

  /* Init the new stack frame. */
  memset(ctx->state, 0, sizeof(*ctx->state));
  ctx->state->type = type;
}

/* Pop a stack frame from the context `ctx'. */
static void
ssh_ipm_pop(SshIpmContext ctx)
{
  size_t index;

  SSH_ASSERT(ctx->state != NULL);

  /* Free character data. */
  ssh_free(ctx->state->data);

  /* Free all dynamic data from the topmost stack frame. */
  ssh_ipm_clear_frame(ctx);

  /* Pop the topmost stack frame. */
  index = ctx->state - ctx->stack;
  if (index == 0)
    ctx->state = NULL;
  else
    ctx->state = &ctx->stack[index - 1];
}

/* Return the parent of the stack item `item'. */
static SshIpmXmlconf
ssh_ipm_parent(SshIpmContext ctx, SshIpmXmlconf item)
{
  size_t index;

  SSH_ASSERT(item != NULL);
  index = item - ctx->stack;
  if (index == 0)
    return NULL;

  return &ctx->stack[index - 1];
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* Parse a string representation of a MAC address to binary form.
   The string  represenation must be of the form 'a:b:c:d:e:f'
   with each of a,b,c,d,e,f two hex characters. */
static Boolean
ssh_ipm_parse_media_addr(unsigned char data[6], const unsigned char *str)
{
  int i;

  if (strlen(str) != 17)
    return FALSE;

  for (i = 0; i < 6; i++)
    {
      if (!isxdigit(*str))
        return FALSE;

      if (isdigit(*str))
        data[i] = 16 * (*str - '0');
      else
        data[i] = 16 * (tolower(*str) - 'a' + 10);

      str++;
      if (!isxdigit(*str))
        return FALSE;

      if (isdigit(*str))
        data[i] += (*str - '0');
      else
        data[i] += (tolower(*str) - 'a' + 10);

      str++;
      if (i < 5 && *str++ != ':')
        return FALSE;
    }
  return TRUE;
}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#define NEED_IPM_PARSE_IP
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSH_IPSEC_TCPENCAP
#undef NEED_IPM_PARSE_IP
#define NEED_IPM_PARSE_IP
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef NEED_IPM_PARSE_IP
/* Parse IP address specification `value' and return the specified IP
   address range in `ip_low' and `ip_high' in textual (ASCII) format.
   `ip_low'and `ip_high' must have space for SSH_IP_ADDR_STRING_SIZE
   long strings. The function returns TRUE if the IP address specification
   was valid and FALSE otherwise. */
static Boolean
ssh_ipm_parse_ip(unsigned char *value,
                 unsigned char *ip_low,
                 unsigned char *ip_high)
{
  const unsigned char *cp;
  SshIpAddrStruct ip;
  SshIpAddrStruct ip2;
  unsigned int maskbits;
  unsigned char tmp[128];

  cp = ssh_ustrchr(value, '-');
  if (cp)
    {
      /* range detected */
      size_t len = cp - value;

      if (len + 1 > sizeof(tmp))
        return FALSE;

      memcpy(tmp, value, len);
      tmp[len] = '\0';
      cp++;

      if (!ssh_ipaddr_parse(&ip, tmp) || SSH_IP_IS_LOOPBACK(&ip))
        return FALSE;
      ssh_ipaddr_print(&ip, ip_low, SSH_IP_ADDR_STRING_SIZE);

      if (!ssh_ipaddr_parse(&ip, cp) || SSH_IP_IS_LOOPBACK(&ip))
        return FALSE;
      ssh_ipaddr_print(&ip, ip_high, SSH_IP_ADDR_STRING_SIZE);
    }
  else
    {
      if (ssh_ipaddr_parse_with_mask(&ip, value, NULL))
        {
          maskbits = SSH_IP_MASK_LEN(&ip);
        }
      else
        {
          /* A single IP address without explicit mask
             specification. */
          if (!ssh_ipaddr_parse(&ip, value) || SSH_IP_IS_LOOPBACK(&ip))
            return FALSE;

          if (SSH_IP_IS4(&ip))
            maskbits = 32;
          else
            maskbits = 128;
        }

      ssh_ipaddr_set_bits(&ip2, &ip, maskbits, 0);
      ssh_ipaddr_print(&ip2, ip_low, SSH_IP_ADDR_STRING_SIZE);

      ssh_ipaddr_set_bits(&ip2, &ip, maskbits, 1);
      ssh_ipaddr_print(&ip2, ip_high, SSH_IP_ADDR_STRING_SIZE);
    }

  return TRUE;
}
#endif /* NEED_IPM_PARSE_IP */

/* Parse a numeric argument `value' and return its value in
   `value_return'.  The function returns TRUE if the value was a valid
   numeric value and FALSE otherwise.  The function returns possible
   errors to the context `ctx'. */
static Boolean
ssh_ipm_parse_number(SshIpmContext ctx, const unsigned char *value,
                     SshUInt32 *value_return)
{
  char *end;

  errno = 0;
  *value_return = strtoul((char *) value, &end, 0);
  if (*end != '\0' || errno == ERANGE)
    {
      ssh_ipm_error(ctx, "Malformed numeric value `%s'", value);
      return FALSE;
    }

  return TRUE;
}

/* Append new data `data', `data_len' to the end of the value `value',
   `value_len'.  The function returns TRUE if the operation was
   successful and FALSE if the system ran our of memory. */
static Boolean
ssh_ipm_append_data(unsigned char **value, size_t *value_len,
                    const unsigned char *data, size_t data_len)
{
  unsigned char *ndata;

  if (*value)
    {
      /* Both ssh_memdup() and our realloc add extra byte for the
         trailing null-character.  Therefore the old size has the
         `+1'. */
      ndata = ssh_realloc(*value, *value_len + 1, *value_len + data_len + 1);
      if (ndata == NULL)
        return FALSE;

      memcpy(ndata + *value_len, data, data_len);
      ndata[*value_len + data_len] = '\0';

      *value = ndata;
      *value_len += data_len;
    }
  else
    {
      *value = ssh_memdup(data, data_len);
      if (*value == NULL)
        return FALSE;

      *value_len = data_len;
    }

  return TRUE;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
static Boolean
ssh_ipm_ras_addrpool_add_address(SshBuffer buf,
                                 unsigned char *address,
                                 unsigned char *netmask)
{
  unsigned char ip_low[SSH_IP_ADDR_STRING_SIZE];
  unsigned char ip_high[SSH_IP_ADDR_STRING_SIZE];

  if (!address || !buf || !netmask)
    return FALSE;

  if (!ssh_ipm_parse_ip(address, ip_low, ip_high))
    return FALSE;

  if (strcmp(ip_low, ip_high))
    {
      if (ssh_buffer_append(buf, ip_low, strlen(ip_low)) != SSH_BUFFER_OK)
        return FALSE;
      if (ssh_buffer_append(buf, "-", strlen("-")) != SSH_BUFFER_OK)
        return FALSE;
      if (ssh_buffer_append(buf, ip_high, strlen(ip_high)) != SSH_BUFFER_OK)
        return FALSE;
    }
  else
    {
      if (ssh_buffer_append(buf, ip_low, strlen(ip_low)) != SSH_BUFFER_OK)
        return FALSE;
    }

  if (ssh_buffer_append(buf, "/", 1) != SSH_BUFFER_OK)
    return FALSE;

  if (netmask == NULL || strlen(netmask) == 0)
    return FALSE;

  if (ssh_buffer_append(buf, netmask, strlen(netmask)) != SSH_BUFFER_OK)
    return FALSE;

  if (ssh_buffer_append(buf, ";", 1) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */


/*************************** Policy object handling **************************/

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* Switch to the new or to the old media/IP address mappings configuration,
   based on the argument `purge_old'. */
void
ssh_ipm_purge_media_mappings(SshIpmContext ctx, Boolean purge_old)
{
  SshIpmMediaConfig *ptr, media;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->media_list == NULL)
    return;

  for (ptr = &ctx->media_list; *ptr != NULL;)
    {
      media = *ptr;

      if (purge_old)
        {
          /* Remove mappings not seen in the current reconfiguration */
          if (media->seen)
            {
              media->old = 1;
              media->seen = 0;
              ptr = &media->next;
            }
          else
            {
              ssh_pm_media_address_mapping_remove(ctx->pm,
                                                   &media->ip, media->ifnum);
              *ptr = media->next;
              ssh_free(media);
            }
        }
      else
        {
          /* Remove mappings first seen in the current reconfiguration */
          if (media->old)
            {
              media->old = 1;
              media->seen = 0;
              ptr = &media->next;
            }
          else
            {
              ssh_pm_media_address_mapping_remove(pm,
                                                   &media->ip, media->ifnum);
              *ptr = media->next;
              ssh_free(media);
            }
        }
    }
}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Purge all old policy objects from the policy manager context.
   This is called when the rule commit operation succeeds.
   The function clears and frees all information about old policy
   rules, objects, etc, that do not belong to the new configuration. */
static void
ssh_ipm_purge_old_policy_objects(SshIpmContext ctx)
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  SSH_ASSERT(pm != NULL);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /* Purge disappeared authorization groups */
  ssh_pm_authorization_local_purge(ctx->authorization, TRUE);

#ifdef SSHDIST_EXTERNALKEY
  /* Remove old externalkey providers. */
  ssh_ipm_purge_ek_providers(ctx, TRUE);
#endif /* SSHDIST_EXTERNALKEY */


#ifdef SSHDIST_IPSEC_DNSPOLICY
  ssh_pm_dns_cache_purge(pm, TRUE);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSH_IPSEC_HTTP_INTERFACE
  /* Stop possible old HTTP statistics which is not running
     anymore. */
  if (!ctx->http_interface)
    (void) ssh_ipm_http_statistics_stop(ctx);
#endif /* SSH_IPSEC_HTTP_INTERFACE */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_ipm_purge_media_mappings(ctx, TRUE);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */









}

/* Purge all new policy objects from the policy manager context.  This
   is called both when the rule commit operation fails and if
   configuration file parsing fails.  The function clears and frees
   all information about new policy rules, objects, etc. */
static void
ssh_ipm_purge_new_policy_objects(SshIpmContext ctx)
{
  SshADTHandle h;
  SshIpmRule rule;
  SshIpmPolicyObject object;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* All `new_rule' rules are now invalid. */
  for (h = ssh_adt_enumerate_start(ctx->rules);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(ctx->rules, h))
    {
      rule = ssh_adt_get(ctx->rules, h);
      rule->new_rule = SSH_IPSEC_INVALID_INDEX;
    }

  /* All new policy object values are also invalid. */
  for (h = ssh_adt_enumerate_start(ctx->policy_objects);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(ctx->policy_objects, h))
    {
      object = ssh_adt_get(ctx->policy_objects, h);

      /* Clear the new value. */
      ssh_ipm_policy_object_value_free(ctx, &object->new_value);
      memset(&object->new_value, 0, sizeof(object->new_value));
    }

  /* If the current configuration object is a rule for which
     ssh_pm_rule_add() has not yet been called, then free the rule here. */
  if (ctx->state &&
      (ctx->state->type == SSH_IPM_XMLCONF_RULE) &&
      ctx->state->u.rule.rule)
    ssh_pm_rule_free(pm, ctx->state->u.rule.rule);
  else if (ctx->state)
    {
      SshIpmXmlconf parent;
      parent = ssh_ipm_parent(ctx, ctx->state);
      if (parent &&
          parent->type == SSH_IPM_XMLCONF_RULE &&
          parent->u.rule.rule)
        ssh_pm_rule_free(pm, parent->u.rule.rule);
    }


  /* Unroll authorization group changes. */
  ssh_pm_authorization_local_purge(ctx->authorization, FALSE);

#ifdef SSHDIST_EXTERNALKEY
  /* Remove new externalkey providers. */
  ssh_ipm_purge_ek_providers(ctx, FALSE);
#endif /* SSHDIST_EXTERNALKEY */


#ifdef SSHDIST_IPSEC_DNSPOLICY
  /* Remove all newly added host-entries from DNS cache. */
  ssh_pm_dns_cache_purge(pm, FALSE);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_ipm_purge_media_mappings(ctx, FALSE);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */









}

/* A completion callback for ssh_pm_commit(). */
static void
ssh_ipm_pm_commit_cb(SshPm pm, Boolean success, void *context)
{
  SshIpmContext ctx = (SshIpmContext)context;
  SshADTHandle h;
  SshIpmRule rule;
  SshIpmPolicyObject object;

  if (success)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Rules committed"));

      ctx->initial_done = 1;

      /* The `new_rule' rules are now the current rules and the old
         `rule' rules have been deleted. */
      for (h = ssh_adt_enumerate_start(ctx->rules);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(ctx->rules, h))
        {
          rule = ssh_adt_get(ctx->rules, h);
          if (rule->new_rule != SSH_IPSEC_INVALID_INDEX)
            {
              rule->rule = rule->new_rule;
              rule->new_rule = SSH_IPSEC_INVALID_INDEX;
            }
        }

      /* Update also other policy objects. */
      for (h = ssh_adt_enumerate_start(ctx->policy_objects);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(ctx->policy_objects, h))
        {
          object = ssh_adt_get(ctx->policy_objects, h);

          /* Do we have a new value. */
          if (object->new_value.type)
            {
              /* Yes.  It is now our current value. */
              ssh_ipm_policy_object_value_free(ctx, &object->value);
              object->value = object->new_value;
              memset(&object->new_value, 0, sizeof(object->new_value));
            }
        }
    }
  else
    {
      ctx->commit_failed = 1;

      SSH_DEBUG(SSH_D_FAIL, ("Rule commit failed"));
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Rule commit failed");

      /* Purge all new policy objects from the policy manager
         context. */
      ssh_ipm_purge_new_policy_objects(ctx);
    }

  /* ssh_pm_commit has completed */
  ctx->commit_called = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
}

/* A completion callback for ssh_pm_commit() when deleting unused
   rules. */
static void
ssh_ipm_unused_commit_cb(SshPm pm, Boolean success, void *context)
{
  SshIpmContext ctx = (SshIpmContext)context;
  SshADTHandle h, hnext;
  SshIpmRule rule;

  if (success)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Unused rules deleted"));

      /* Now, remove them from the rule container. */
      for (h = ssh_adt_enumerate_start(ctx->rules);
           h != SSH_ADT_INVALID;
           h = hnext)
        {
          hnext = ssh_adt_enumerate_next(ctx->rules, h);
          rule = ssh_adt_get(ctx->rules, h);

          if (rule->unused)
            ssh_adt_delete(ctx->rules, h);
        }
    }
  else
    {
      ctx->commit_failed = 1;

      SSH_DEBUG(SSH_D_FAIL, ("Removing of unused rules failed"));
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Removing of unused rules failed");

      /* Clear the unused marks. */
      for (h = ssh_adt_enumerate_start(ctx->rules);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(ctx->rules, h))
        {
          rule = ssh_adt_get(ctx->rules, h);
          rule->unused = 0;
        }
    }

  /* ssh_pm_commit has completed */
  ctx->commit_called = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* A completion callback for media/IP mapping entry addition  */
static void
ssh_ipm_media_add_cb(SshPm pm, Boolean success, void *context)
{
  if (success)
    SSH_DEBUG(SSH_D_MIDOK,
              ("Media address addition has loaded with status SUCCESS"));
  else
    SSH_DEBUG(SSH_D_ERROR,
              ("Media address addition has loaded with status FAILURE"));
}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Create a bootstrap policy rule that allows traffic to our policy
   server. */
static Boolean
ssh_ipm_create_bootstrap_policy(SshIpmContext ctx)
{
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  SshPmRule rule = NULL;

  if (ctx->bootstrap.traffic_selector == NULL)
    goto error;

  rule = ssh_pm_rule_create(pm, 1, SSH_PM_RULE_PASS,

                            NULL, NULL,

                            NULL);
  if (rule == NULL)
    goto error;

  /* Remote traffic selector. */
  if (!ssh_pm_rule_set_traffic_selector(rule, SSH_PM_TO,
                                        ctx->bootstrap.traffic_selector))
    {
      if (rule)
        ssh_pm_rule_free(pm, rule);

      goto error;
    }

  ssh_free(ctx->bootstrap.traffic_selector);
  ctx->bootstrap.traffic_selector = NULL;

  /* Local stack selector. */
  ssh_pm_rule_set_local_stack(rule, SSH_PM_FROM);

  /* Add the rule to our active configuration. */
  ctx->bootstrap.rule = ssh_pm_rule_add(pm, rule);
  if (ctx->bootstrap.rule == SSH_IPSEC_INVALID_INDEX)
    goto error;

  /* All done. */
  return TRUE;

  /* Error handling. */

 error:
  SSH_ASSERT(!ctx->commit_called);
  ssh_pm_abort(pm);

  if (ctx->bootstrap.traffic_selector)
    ssh_free(ctx->bootstrap.traffic_selector);
  ctx->bootstrap.traffic_selector = NULL;

  return FALSE;
}

/* An SshPmStatusCB for bootstrap policy commit operation. */
static void
ssh_ipm_bootstrap_commit_cb(SshPm pm, Boolean success, void *context)
{
  SshIpmContext ctx = (SshIpmContext)context;

  ctx->bootstrap.success = success;

  /* ssh_pm_commit has completed */
  ctx->commit_called = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
}

/* A completion callback for configuration URL stream resolving. */
static void
ssh_ipm_config_stream_cb(SshStream stream, const char *stream_name,
                         SshXmlDestructorCB destructor_cb,
                         void *destructor_cb_context,
                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmContext ctx = (SshIpmContext) ssh_fsm_get_tdata(thread);

  ctx->config.stream = stream;

  if (stream_name)
    ctx->config.stream_name = ssh_strdup(stream_name);
  else
    ctx->config.stream_name = NULL;

  ctx->config.destructor_cb = destructor_cb;
  ctx->config.destructor_cb_context = destructor_cb_context;

  /* Clear operation handle */
  ctx->parse_operation = NULL;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A completion callback for XML parse operation. */
static void
ssh_ipm_parse_result_cb(SshXmlResult result, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmContext ctx = (SshIpmContext) ssh_fsm_get_tdata(thread);

  ctx->parse_result = (result == SSH_XML_OK ? TRUE : FALSE);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("XML parse result '%s'",
                               (result == SSH_XML_OK ? "OK" : "FAILED")));

  /* Clear operation handle */
  ctx->parse_operation = NULL;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A timeout callback that notifies the user about the success of the
   current configuration operation. */
static void
ssh_ipm_parse_result_timeout(void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  SshPmStatusCB status_cb;
  void *status_cb_context;

  /* Save completion callback and clear it from our context. */

  status_cb = ctx->parse_status_cb;
  status_cb_context = ctx->parse_status_cb_context;

  ctx->parse_status_cb = NULL_FNPTR;
  ctx->parse_status_cb_context = NULL;

  /* Call the completion callback. */
  if (!ctx->aborted)
    {
      ssh_operation_unregister(ctx->operation);
      if (status_cb)
        (*status_cb)(pm, ctx->parse_result, status_cb_context);
    }
}


/* Update changed parameters into the policy manager.  The function
   returns TRUE if the parameters were updated and FALSE otherwise. */
static Boolean
ssh_ipm_update_params(SshIpmContext ctx)
{
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  ssh_pm_set_flags(pm, ctx->pm_flags);

  if (ctx->engine_params_set)
    ssh_pm_set_engine_params(pm, &ctx->engine_params);
  else
    ssh_pm_set_engine_params(pm, NULL);
  ctx->engine_params_set = 0;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_LDAP
  if (ctx->ldap_changed)
    {
      /* Terminate string properly */
      if (ssh_buffer_append(&ctx->ldap_servers, (unsigned char *)"\000", 1)
          != SSH_BUFFER_OK)
        return FALSE;

      if (!ssh_pm_set_ldap_servers(
                                pm,
                                (char *) ssh_buffer_ptr(&ctx->ldap_servers)))
        {
          ssh_ipm_error(ctx, "Could not configure LDAP servers");
          return FALSE;
        }
      ctx->ldap_changed = 0;
    }
#endif /* SSHDIST_LDAP */
#endif /* SSHDIST_IKE_CERT_AUTH */


#ifdef SSHDIST_IPSEC_NAT
  /* Commit NAT changes. */

  /* Clear old NAT configurations. */
  if (!ssh_pm_clear_interface_nat(pm))
    {
      ssh_ipm_error(ctx,
                    "Could not clear old interface NAT configuration");
      goto error;
    }

  /* Add new NAT configurations. */
  if (ctx->config_parameters.nat_list != NULL)
    {
      SshIpmNatConfig nat;
      for (nat = ctx->config_parameters.nat_list; nat != NULL; nat = nat->next)
        {
          if (!ssh_pm_set_interface_nat(pm, nat->flags,
                                        nat->ifname, nat->nat_type))
            {
              ssh_ipm_error(ctx, "Could not configure interface NAT");
              goto error;
            }
        }
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Commit new internal NAT configuration. */
  if (!ssh_pm_configure_internal_nat(pm,
                                     ctx->config_parameters.internal_nat_first,
                                     ctx->config_parameters.internal_nat_last,
                                     NULL_FNPTR, NULL))
    {
      ssh_ipm_error(ctx, "Could not configure internal NAT");
      goto error;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#endif /* SSHDIST_IPSEC_NAT */


  /* Commit new IKE default parameters. */
  if (!ssh_pm_set_default_ike_algorithms(pm,
                               ctx->config_parameters.default_ike_algorithms))
    {
      ssh_ipm_error(ctx, "Could not configure default IKE algorithms");
      goto error;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

  /* Disable accounting and send Accounting-Off */
  ssh_pm_ras_set_radius_acct_disabled(ctx->pm,
                                      SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_OFF);

  /* Delete old RADIUS configuration from PM */
  ssh_pm_ras_set_radius_acct_client(ctx->pm, NULL);

  if (ctx->radius_acct_client != NULL && ctx->radius_acct_servers != NULL)
    {
      /* We have complete setup */

      /* Set new client to PM */
      ssh_pm_ras_set_radius_acct_client(ctx->pm, ctx->radius_acct_client);

      /* Set new server list to PM */
      ssh_pm_ras_set_radius_acct_servers(ctx->pm, ctx->radius_acct_servers);

      /* Enable RADIUS Accounting and send Accounting-On */
      ssh_pm_ras_set_radius_acct_enabled(ctx->pm,
                                         SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_ON);


      /* PM took over references to RADIUS structures; forget them here. */
      ctx->radius_acct_client = NULL;
      ctx->radius_acct_servers = NULL;
    }

  if (ctx->radius_acct_client != NULL)
    {
      /* Destroy accounting client; server wasn't confiured */
      ssh_radius_client_destroy(ctx->radius_acct_client);
    }

  if (ctx->radius_acct_servers != NULL)
    {
      /* Destroy accounting servers; client wasn't configured.*/
      ssh_radius_client_server_info_destroy(ctx->radius_acct_servers);
    }

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  /* All parameters updated. */
  return TRUE;

 error:
  return FALSE;
}


/* Store manual key `data', `data_len' into `*key' and `*key_len'.
   The key data `data' is considered to be in hex format. */
static Boolean
ssh_ipm_store_manual_key(SshIpmContext ctx,
                         const unsigned char *data, size_t data_len,
                         unsigned char **key, size_t *key_len)
{
  unsigned char *ucp;
  size_t i = 0;
  unsigned char val;

  if (data == NULL)
    return TRUE;

  if ((data_len % 2) != 0)
    {
      ssh_ipm_error(ctx, "Invalid manual key data");
      return FALSE;
    }

  *key_len = data_len / 2;
  ucp = ssh_calloc(1, *key_len);
  if (ucp == NULL)
    {
      ssh_ipm_error(ctx, "Could not store manual key");
      return FALSE;
    }

  while (data_len)
    {
      if (!SSH_IPM_IS_HEX(data[0]) || !SSH_IPM_IS_HEX(data[1]))
        {
          ssh_ipm_error(ctx, "Invalid characters in manual key");
          ssh_free(ucp);
          return FALSE;
        }

      val = SSH_IPM_HEX_TO_INT(data[0]);
      val <<= 4;
      val += SSH_IPM_HEX_TO_INT(data[1]);


      ucp[i] = val;
      i++;
      data += 2;
      data_len -= 2;
    }

  *key = ucp;

  return TRUE;
}

static Boolean
ssh_ipm_store_identity(SshIpmContext ctx, Boolean psk,
                       const unsigned char *id, size_t id_len)
{
  unsigned char *identity;

  if (psk)
    SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_PSK);
  else
    SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_IDENTITY);

  /* Store the identity as-is. */
  identity = ssh_memdup(id, id_len);
  if (identity == NULL)
    {
      ssh_ipm_error(ctx, "Could not store IKE identity");
      return FALSE;
    }

  if (psk)
    {
      ctx->state->u.psk.identity = identity;
      ctx->state->u.psk.identity_len = id_len;
    }
  else
    {
      ctx->state->u.tunnel.identity = identity;
      ctx->state->u.tunnel.identity_len = id_len;
    }


  return TRUE;
}

#ifdef SSHDIST_EXTERNALKEY

#define SSH_IPM_EK_PROVIDER_FLAG_SEEN   0x40000000 /* Provider seen. */
#define SSH_IPM_EK_PROVIDER_FLAG_NEW    0x80000000 /* Added in this config. */

/* Lookup externalkey provider `type' with initialization info
   `init_info'.  The function returns TRUE if the lookup operation was
   successful and FALSE if the system could not query externalkey
   providers.  If the operation was successful, it updates the
   argument `found_return' to hold information whether the externalkey
   provider was found or not.  The arguments `mark_seen' and
   `mark_new' sets the SSH_IPM_EK_PROVIDER_FLAG_{SEEN,NEW} flags to
   the provider flags. */
Boolean
ssh_ipm_lookup_ek_provider(SshIpmContext ctx,
                           const char *type,
                           const char *init_info,
                           Boolean *found_return,
                           Boolean mark_seen,
                           Boolean mark_new)
{
  SshExternalKey ek;
  SshEkProvider providers;
  SshUInt32 num_providers;
  SshUInt32 i, j;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  ek = ssh_pm_get_externalkey(pm);
  SSH_ASSERT(ek != NULL);

  /* Get the list of currently configured providers. */
  if (!ssh_ek_get_providers(ek, &providers, &num_providers))
    return FALSE;

  if (num_providers == 0)
    {
      /* No providers configured so far. */
      *found_return = FALSE;
      return TRUE;
    }
  if (providers == NULL)
    /* Could not get providers. */
    return FALSE;

  /* Copy _SEEN and _NEW flags */
  for (i = 0; i < ctx->num_ek_providers; i++)
    {
      for (j = 0; j < num_providers; j++)
        {
          if (strcmp(ctx->ek_providers[i].short_name,
                     providers[j].short_name) == 0)
            {
              providers[j].provider_flags |=
                (ctx->ek_providers[i].provider_flags &
                 (SSH_IPM_EK_PROVIDER_FLAG_SEEN |
                  SSH_IPM_EK_PROVIDER_FLAG_NEW));
              break;
            }
        }
    }

  /* Free old list of providers */
  if (ctx->ek_providers)
    ssh_free(ctx->ek_providers);
  ctx->ek_providers = providers;
  ctx->num_ek_providers = num_providers;

  /* Do we know this provider? */
  for (i = 0; i < num_providers; i++)
    {
      /* Accelerator added from command line are not part of purge
         process, they are always seen. */
      if (providers[i].provider_flags == SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR)
        providers[i].provider_flags |= SSH_IPM_EK_PROVIDER_FLAG_SEEN;

      if (strcmp(providers[i].type, type) != 0)
        /* The type does not match. */
        continue;

      if ((providers[i].info != NULL && init_info == NULL)
          || (providers[i].info == NULL && init_info != NULL)
          || (providers[i].info && init_info
              && strcmp(providers[i].info, init_info) != 0))
        /* Init info does not match. */
        continue;

      /* Found it.  Now mark it according to mark flags. */
      if (mark_seen)
        providers[i].provider_flags |= SSH_IPM_EK_PROVIDER_FLAG_SEEN;
      if (mark_new)
        providers[i].provider_flags |= SSH_IPM_EK_PROVIDER_FLAG_NEW;

      *found_return = TRUE;

      return TRUE;
    }

  /* An unknown provider. */
  *found_return = FALSE;

  return TRUE;
}

/* Switch to the new or to the old externalkey configuration, based on
   the argument `purge_old'. */
void
ssh_ipm_purge_ek_providers(SshIpmContext ctx, Boolean purge_old)
{
  SshExternalKey ek;
  SshUInt32 i;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  ek = ssh_pm_get_externalkey(pm);
  SSH_ASSERT(ek != NULL);

  if (ctx->num_ek_providers == 0)
    {
      /* We might still have providers from previous configuration,
         remove them. */
      SshEkProvider providers;
      SshUInt32 num_providers;

      /* Get the list of currently configured providers. */
      if (!ssh_ek_get_providers(ek, &providers, &num_providers))
        return;

      /* There were no old providers */
      if (num_providers == 0)
        return;

      for (i = 0; i < num_providers; i++)
        {
          if (!(providers[i].provider_flags &
                SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR))
            {
              ssh_ek_remove_provider(ek, providers[i].short_name);
            }
        }

      ssh_free(providers);
      return;
    }
  if (ctx->ek_providers == NULL)
    {
      /* Could not get providers. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not get externalkey providers"));
      return;
    }

  /* Switch to the new or to the old configuration, specified by our
     `purge_old' argument. */
  for (i = 0; i < ctx->num_ek_providers; i++)
    if (purge_old)
      {
        /* Purge old providers. */
        if (!(ctx->ek_providers[i].provider_flags &
              SSH_IPM_EK_PROVIDER_FLAG_SEEN))
          {
            /* This provider does not belong to the active
               configuration anymore and we remove it */
            ssh_ek_remove_provider(ek, ctx->ek_providers[i].short_name);
          }
      }
    else
      {
        /* Purge new providers. */
        if (ctx->ek_providers[i].provider_flags & SSH_IPM_EK_PROVIDER_FLAG_NEW)
          {
            /* This is a new provider.  We remove it */
            ssh_ek_remove_provider(ek, ctx->ek_providers[i].short_name);
          }
      }

  /* Free the providers array. */
  ssh_free(ctx->ek_providers);
  ctx->ek_providers = NULL;
  ctx->num_ek_providers = 0;
}

/* Remove all installed external key providers */
void
ssh_ipm_reset_ek_providers(SshPm pm)
{
  SshExternalKey ek;
  SshUInt32 i;
  SshEkProvider ek_providers;
  SshUInt32 num_ek_providers;

  ek = ssh_pm_get_externalkey(pm);
  SSH_ASSERT(ek != NULL);

  /* Get the list of currently configured providers. */
  if (!ssh_ek_get_providers(ek, &ek_providers, &num_ek_providers))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get externalkey providers"));
      return;
    }

  if (num_ek_providers == 0)
    {
      /* No providers configured. */
      return;
    }

  for (i = 0; i < num_ek_providers; i++)
    {
      ssh_ek_remove_provider(ek, ek_providers[i].short_name);
    }

  /* Free the providers array. */
  ssh_free(ek_providers);
}


#endif /* SSHDIST_EXTERNALKEY */

/****************** Legacy authentication client callbacks ******************/

/* Query callback for legacy authentication client. This callback
   mimics asynchronous operation */

typedef struct SshIpmLegacyAuthResultRec
{
  /* Timeout and operation handle to cancel call to result_callback. */
  SshTimeoutStruct timeout[1];
  SshOperationHandleStruct handle[1];

  SshPmLegacyAuthClientQueryResultCB result_callback;
  void *result_callback_context;

  /* Payload data and its selectors */
  SshUInt32 selectors;
  SshIpmLegacyAuthClientAuth result;

  /* Operation has been aborted */
  unsigned int aborted : 1;

} * SshIpmLegacyAuthResult;

static void ipm_legacy_client_auth_unref(SshIpmLegacyAuthClientAuth auth)
{
  auth->references--;

  if (auth->references == 0)
    {
      /* No more references */
      ssh_free(auth->user_name);
      ssh_free(auth->password);
      ssh_free(auth);
    }
}

static void ipm_legacy_auth_client_query_result(void *context)
{
  unsigned char *user_name = NULL, *user_password = NULL, *passcode = NULL;
  size_t user_name_len = 0, user_password_len = 0, passcode_len = 0;
  unsigned char *next_pin = NULL, *answer = NULL;
  size_t next_pin_len = 0, answer_len = 0;
  SshIpmLegacyAuthResult op = context;

  if (op->aborted)
    {
      ssh_free(op);
      return;
    }

  if (op->result_callback)
    {
      /* Check which attributes should be returned. */
      if (op->selectors & SSH_PM_LA_ATTR_USER_NAME)
        {
          user_name = op->result->user_name;
          user_name_len = op->result->user_name_len;
        }
      if (op->selectors & SSH_PM_LA_ATTR_USER_PASSWORD)
        {
          user_password = op->result->password;
          user_password_len = op->result->password_len;
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Found client authentication info"));
      (*op->result_callback)(TRUE,
                             user_name, user_name_len,
                             user_password, user_password_len,
                             passcode, passcode_len,
                             next_pin, next_pin_len,
                             answer, answer_len,
                             op->result_callback_context);

      ssh_operation_unregister(op->handle);
    }

  ipm_legacy_client_auth_unref(op->result);
  ssh_free(op);
}

static void ipm_legacy_auth_client_query_abort(void *context)
{
  SshIpmLegacyAuthResult op = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting legacy authentication client  query"));

  /* Mark the operation as aborted */
  op->aborted = 1;
  ipm_legacy_client_auth_unref(op->result);

  /* The callback must be called even if the operation is aborted. */
  (*op->result_callback)(FALSE,
                         NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                         op->result_callback_context);
}

static SshOperationHandle
ssh_ipm_legacy_auth_client_query_cb(
                                SshUInt32 operation_id,
                                const SshIpAddr gateway_ip,
                                const unsigned char *domain,
                                size_t domain_len,
                                const unsigned char *message,
                                size_t message_len,
                                SshUInt32 flags,
                                SshUInt32 xauth_type,
                                SshPmLegacyAuthClientQueryResultCB result_cb,
                                void *result_cb_context,
                                void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;
  SshIpmLegacyAuthClientAuth auth;
  SshIpmLegacyAuthClientAuth best_auth = NULL;
  SshInt32 best_num_matches = -1, nthmatch = 0;
  SshIpmLegacyAuthResult op;

  /* Require that a valid completion callback is given. */
  SSH_ASSERT(result_cb != NULL);

  if (flags & SSH_PM_LA_XAUTH)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("XAUTH: type=%u",
                                   (unsigned int) xauth_type));
    }
  if (flags & SSH_PM_LA_L2TP)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("L2TP"));
    }
  if (flags & SSH_PM_LA_EAP)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP"));
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (flags & SSH_PM_LA_SECOND_ROUND)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Second authentication round"));
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (domain)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Domain: %.*s",
                                 (int) domain_len, domain));
  if (message)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Message: %.*s",
                                 (int) message_len, message));

  for (auth = ctx->la_client_auth; auth; auth = auth->next)
    {
      SshInt32 num_matches = 0;

      if (auth->flags)
        {
          if (auth->flags & flags)
            num_matches++;
          else
            continue;
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      /* Check authentication round */
      if (flags & 0x000000f0)
        {
          if ((auth->flags & flags) & 0x000000f0)
            num_matches++;
          else
            continue;
        }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

      if (SSH_IP_DEFINED(&auth->gateway_ip))
        {
          if (SSH_IP_EQUAL(&auth->gateway_ip, gateway_ip))
            num_matches++;
          else
            continue;
        }

      nthmatch++;

      if (num_matches > best_num_matches)
        best_auth = auth;

      if (nthmatch == operation_id)
        break;
    }

  if (best_auth == NULL)
    {
      /* No applicable client authentication available. */
      SSH_DEBUG(SSH_D_FAIL, ("No client authentication info found"));
      (*result_cb)(FALSE, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                   result_cb_context);
      return NULL;
    }

  op = ssh_calloc(1, sizeof(*op));
  if (op != NULL)
    {
      long timeout = 0;
      /* Fill in operation */
      op->selectors = flags;
      op->result = best_auth;
      op->result_callback = result_cb;
      op->result_callback_context = result_cb_context;

      ssh_operation_register_no_alloc(op->handle,
                                      ipm_legacy_auth_client_query_abort,
                                      op);









      SSH_DEBUG(SSH_D_HIGHOK, ("Register client query timeout of %d seconds",
                               (int) timeout));

      op->result->references++;

      /* Register a timeout to complete operation later point of time */
      ssh_register_timeout(op->timeout,
                           timeout, 0L,
                           ipm_legacy_auth_client_query_result,
                           op);
      return op->handle;
    }

  /* Failed on memory allocation */
  (*result_cb)(FALSE,
               NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
               result_cb_context);
  return NULL;
}

/* Result callback reporting the result of legacy client
   authentication. */
static void
ssh_ipm_legacy_auth_client_result_cb(SshUInt32 operation_id,
                                     Boolean success,
                                     const unsigned char *message,
                                     size_t message_len,
                                     void *context)
{
  if (message_len)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "Client authentication %s: %.*s\n",
                  success ? "successful" : "failed",
                  (int) message_len, (char *) message);
  else
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "Client authentication %s\n",
                  success ? "successful" : "failed");
}




/************************* Handlers for XML parser **************************/

#ifdef SSHDIST_IPSEC_DNSPOLICY

static void
ssh_pm_indicate_cb(SshPm pm, Boolean success, void *context)
{
  SshIpmContext ctx = context;

  SSH_DEBUG(SSH_D_LOWSTART, ("DNS change indicated."));

  ctx->sub_operation = NULL;

  if (ctx->dns_configuration_done)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Committing rules"));
      ctx->commit_called = 1;
      (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
                 ssh_ipm_pm_commit_cb, ctx);
    }
}

#ifdef VXWORKS
#include "sshglobals.h"
/* On vxworks do_indicate has switched to use sshglobals.h. */
SSH_GLOBAL_DECLARE(Boolean, do_indicate);
#define do_indicate SSH_GLOBAL_USE(do_indicate)
#else
extern int do_indicate;
#endif /* VXWORKS */

#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSHDIST_IPSEC_NAT

static Boolean process_nat_addresses(SshIpmContext ctx,
                                     const char *direction,
                                     const SshIpAddr ip,
                                     SshIpAddr ip_low,
                                     SshIpAddr ip_high,
                                     SshPmNatFlags flags_specific,
                                     SshPmNatFlags *flags_all )
{
  /* Return if no NAT addresses given (typical case) */
  if (SSH_PREDICT_TRUE(!SSH_IP_DEFINED(ip) &&
                       !SSH_IP_DEFINED(ip_low) && !SSH_IP_DEFINED(ip_high)))
    {
      return TRUE;
    }

  /* Check that only either, ip, or ip_low/ip_high has been specified */
  if (SSH_IP_DEFINED(ip) &&
      (SSH_IP_DEFINED(ip_low) || SSH_IP_DEFINED(ip_high)))
    {
      ssh_ipm_error(ctx,
                    "Cannot define NAT %s address and range simultaneously.",
                    direction);
      return FALSE;
    }

  /* NAT IP address have been given. Return it in both low and high. */
  if (SSH_IP_DEFINED(ip))
    {
      *ip_low = *ip;
      *ip_high = *ip;
    }

  *flags_all = *flags_all | flags_specific;
  return TRUE;
}

#endif /* SSHDIST_IPSEC_NAT */

/* Content handler. */

static SshOperationHandle
ssh_ipm_xml_start_element(SshXmlParser parser,
                          const unsigned char *name, size_t name_len,
                          SshADTContainer attributes,
                          SshXmlResultCB result_cb, void *result_cb_context,
                          void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;
  const unsigned char *value;
  size_t value_len;
  SshUInt32 ival;
  SshXmlAttrEnumCtxStruct attr_enum;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  SshIpmXmlconf parent;


  if (!ctx->dtd_specified)
    {
      ssh_ipm_error(ctx,
                    "Configuration is missing DTD specification");
      goto error;
    }

  if (ctx->auth_domain_reset_failed)
    {
      ssh_ipm_error(ctx,
                    "Resetting authentication domains failed, failing "
                    "policy reconfiguration.");
      goto error;
    }

  /********************************** Params ********************************/
  if (ssh_xml_match(name, name_len, ssh_custr("params"), 0))
    {

      SshUInt32 port;
#ifdef SSHDIST_IKE_CERT_AUTH
      Boolean cert_server = FALSE;
      SshUInt32 cert_server_flags = 0;
#endif /* SSHDIST_IKE_CERT_AUTH */

      /* Clear all possible old routes in the standalone configuration
         case.  But, clear them only from the `quicksec'-level params
         block. */
      if (ctx->state == NULL || ctx->state->type != SSH_IPM_XMLCONF_POLICY)
        ssh_pm_configure_clear_routes(pm);

#ifdef SSHDIST_IKE_REDIRECT
      /* Clear IKE redirect settings. */
      ssh_pm_clear_ike_redirect(pm);
#endif /* SSHDIST_IKE_REDIRECT */
      /* We are parsing a params block. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PARAMS);


      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("certificate-provider-port"),
                                     0, NULL);
      if (!ssh_ipm_parse_number(ctx, value, &port) || port > 65535)
        goto error;

      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("cookie-required"), 0))
            ctx->pm_flags |= SSH_PM_FLAG_REQUIRE_COOKIE;
#ifdef SSHDIST_IKE_CERT_AUTH
          if (ssh_xml_match(value, value_len,
                            ssh_custr("certificate-provider"), 0))
            cert_server = TRUE;
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
          if (ssh_xml_match(value, value_len,
                            ssh_custr("certificate-bundles"), 0))
            cert_server_flags |= SSH_PM_CERT_ACCESS_SERVER_FLAGS_SEND_BUNDLES;
#endif /* SSHDIST_IKE_CERT_AUTH */
        }

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_HTTP_SERVER
#ifdef SSHDIST_CERT
      if (cert_server)
        {
          if (!ssh_pm_cert_access_server_start(pm, port,
                                               cert_server_flags))
            {
              ssh_ipm_error(ctx,
                            "Can not start certificate access server on "
                            "port %d", port);
              goto error;
            }
        }
      else
        ssh_pm_cert_access_server_stop(pm);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_HTTP_SERVER */
#endif /* SSHDIST_IKE_CERT_AUTH */


      value = ssh_xml_get_attr_value(attributes, ssh_custr("debug"),
                                     0, NULL);
      if (value)
        ssh_debug_set_level_string(value);

      value = ssh_xml_get_attr_value(attributes, ssh_custr("kernel-debug"),
                                     0, NULL);
      if (value)
        ssh_pm_set_kernel_debug_level(pm, value);
     }
  /**************** Configuration of engine-params **************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("engine-params"), 0))
    {
      SshEngineParamsStruct params = ENGINE_DEFAULT_PARAMETERS;
      SshUInt32 decrement_ttl;
      SshUInt32 audit_corrupt;
      SshUInt32 drop_if_cannot_audit;
      SshUInt32 broadcast_icmp;

      const unsigned char *do_not_decrement_ttl;
      const unsigned char *min_ttl_value;
      const unsigned char *audit_corrupt_str;
      const unsigned char *drop_if_cannot_audit_str;
      const unsigned char *audit_total_rate_limit;
      const unsigned char *flow_rate_allow_threshold;
      const unsigned char *flow_rate_limit_threshold;
      const unsigned char *flow_rate_max_share;
      const unsigned char *fragment_monitoring;
      const unsigned char *routing;
      const unsigned char *transform_dpd_timeout;
      const unsigned char *natt_keepalive_interval;
      const unsigned char *broadcast_icmp_str;

      do_not_decrement_ttl = ssh_xml_get_attr_value(attributes,
                                                    ssh_custr("decrement-ttl"),
                                                    0, NULL);

      audit_corrupt_str = ssh_xml_get_attr_value(attributes,
                                                 ssh_custr("audit-corrupt"),
                                                 0, NULL);

      drop_if_cannot_audit_str = ssh_xml_get_attr_value(attributes,
                                         ssh_custr("drop-if-cannot-audit"),
                                         0, NULL);
      broadcast_icmp_str = ssh_xml_get_attr_value(attributes,
                              ssh_custr("broadcast-icmp"),
                              0, NULL);

      min_ttl_value = ssh_xml_get_attr_value(attributes,
                                             ssh_custr("min-ttl"),
                                             0, NULL);

      audit_total_rate_limit = ssh_xml_get_attr_value(attributes,
                                        ssh_custr("audit-total-rate-limit"),
                                        0, NULL);

      flow_rate_allow_threshold = ssh_xml_get_attr_value(attributes,
                                        ssh_custr("flow-rate-always-allow"),
                                        0, NULL);

      flow_rate_limit_threshold = ssh_xml_get_attr_value(attributes,
                                        ssh_custr("flow-rate-usage-threshold"),
                                        0,NULL);

      flow_rate_max_share = ssh_xml_get_attr_value(attributes,
                                              ssh_custr("flow-rate-max-share"),
                                              0, NULL);

      fragment_monitoring = ssh_xml_get_attr_value(attributes,
                                              ssh_custr("fragment-policy"),
                                              0, NULL);

      routing = ssh_xml_get_attr_value(attributes,
                                       ssh_custr("routing"),
                                       0, NULL);

      transform_dpd_timeout = ssh_xml_get_attr_value(attributes,
                                                     ssh_custr("dpd-timeout"),
                                                     0, NULL);

      natt_keepalive_interval =
        ssh_xml_get_attr_value(attributes,
                               ssh_custr("natt-keepalive-interval"), 0, NULL);

      if (do_not_decrement_ttl)
        {
          if (strcmp((char*)do_not_decrement_ttl, "yes") == 0
              || strcmp((char*)do_not_decrement_ttl, "true") == 0)
            decrement_ttl = 1;
          else if (strcmp((char*)do_not_decrement_ttl, "no") == 0
                   || strcmp((char*)do_not_decrement_ttl, "false") == 0)
            decrement_ttl = 0;
          else if (!ssh_ipm_parse_number(ctx, do_not_decrement_ttl,
                                         &decrement_ttl))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for "
                            "do-not-decrement-ttl",
                            do_not_decrement_ttl);
              goto error;
            }

          params.do_not_decrement_ttl = (decrement_ttl ? FALSE: TRUE);
        }


      if (audit_corrupt_str)
        {
          if (strcmp((char*)audit_corrupt_str, "yes") == 0
              || strcmp((char*)audit_corrupt_str, "true") == 0)
            audit_corrupt = 1;
          else if (strcmp((char*)audit_corrupt_str, "no") == 0
                   || strcmp((char*)audit_corrupt_str, "false") == 0)
            audit_corrupt = 0;
          else if (!ssh_ipm_parse_number(ctx, audit_corrupt_str,
                                         &audit_corrupt))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for audit-corrupt",
                            audit_corrupt_str);
              goto error;
            }

          params.audit_corrupt = (audit_corrupt ? TRUE : FALSE);
        }


      if (drop_if_cannot_audit_str)
        {
          if (strcmp((char*)drop_if_cannot_audit_str, "yes") == 0
              || strcmp((char*)drop_if_cannot_audit_str, "true") == 0)
            drop_if_cannot_audit = 1;
          else if (strcmp((char*)drop_if_cannot_audit_str, "no") == 0
                   || strcmp((char*)drop_if_cannot_audit_str, "false") == 0)
            drop_if_cannot_audit = 0;
          else if (!ssh_ipm_parse_number(ctx, drop_if_cannot_audit_str,
                                         &drop_if_cannot_audit))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for "
                            "drop-if-cannot-audit",
                            drop_if_cannot_audit_str);
              goto error;
            }

          params.drop_if_cannot_audit = (drop_if_cannot_audit ? TRUE : FALSE);
        }

      if (broadcast_icmp_str)
        {
          if (strcmp((char*)broadcast_icmp_str, "drop") == 0)
            broadcast_icmp = 0;
          else if (strcmp((char*)broadcast_icmp_str, "allow") == 0)
            broadcast_icmp = 1;
          else if (!ssh_ipm_parse_number(ctx, broadcast_icmp_str,
                                         &broadcast_icmp))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for "
                            "broadcast_icmp",
                            broadcast_icmp_str);
              goto error;
            }

          params.broadcast_icmp = (broadcast_icmp ? TRUE : FALSE);
        }


      if (min_ttl_value
          && !ssh_ipm_parse_number(ctx, min_ttl_value, &params.min_ttl_value))
        {
          ssh_ipm_error(ctx,
                        "Invalid integer value '%s for min-ttl-value'",
                        min_ttl_value);
          goto error;
        }

      if (audit_total_rate_limit
          && !ssh_ipm_parse_number(ctx, audit_total_rate_limit,
                                   &params.audit_total_rate_limit))
        {
          ssh_ipm_error(ctx,
                        "Invalid integer value '%s' for "
                        "audit-total-rate-limit",
                        audit_total_rate_limit);
          goto error;
        }

      if (flow_rate_allow_threshold)
        {
          if (!ssh_ipm_parse_number(ctx, flow_rate_allow_threshold,
                                    &params.flow_rate_allow_threshold))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for "
                            "flow-rate-allow-threshold",
                            flow_rate_allow_threshold);
              goto error;
            }
        }

      if (flow_rate_limit_threshold)
        {
          if (!ssh_ipm_parse_number(ctx, flow_rate_limit_threshold,
                                    &params.flow_rate_limit_threshold))
            {
              ssh_ipm_error(ctx,
                            "Invalid integer value '%s' for "
                            "flow-rate-limit-threshold",
                            flow_rate_limit_threshold);
              goto error;
            }
        }

      if (flow_rate_max_share
          && !ssh_ipm_parse_number(ctx, flow_rate_max_share,
                                   &params.flow_rate_max_share))
        {
          ssh_ipm_error(ctx,
                        "Invalid integer value '%s' for flow-rate-max-share",
                        flow_rate_max_share);
          goto error;
        }

      if (transform_dpd_timeout
          && !ssh_ipm_parse_number(ctx, transform_dpd_timeout,
                                   &params.transform_dpd_timeout))
        {
          ssh_ipm_error(ctx,
                        "Invalid integer value '%s' for dpd-timeout",
                        transform_dpd_timeout);
          goto error;
        }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if (natt_keepalive_interval
          && !ssh_ipm_parse_number(ctx, natt_keepalive_interval,
                                   &params.natt_keepalive_interval))
        {
          ssh_ipm_error(ctx,
                        "Invalid integer value '%s' for "
                        "natt-keepalive-interval",
                        natt_keepalive_interval);
          goto error;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      if (fragment_monitoring)
        {
          if (strcmp((char *)fragment_monitoring, "strict") == 0)
            params.fragmentation_policy = SSH_IPSEC_FRAGS_STRICT_MONITOR;
          else if (strcmp((char *)fragment_monitoring, "loose") == 0)
            params.fragmentation_policy = SSH_IPSEC_FRAGS_LOOSE_MONITOR;
          else if (strcmp((char *)fragment_monitoring, "nofrags") == 0)
            params.fragmentation_policy = SSH_IPSEC_FRAGS_NO_FRAGS;
          else if (strcmp((char *)fragment_monitoring, "none") == 0 )
            params.fragmentation_policy = SSH_IPSEC_FRAGS_NO_POLICY;
          else
            ssh_ipm_error(ctx,
                          "Invalid fragment monitoring policy '%s'",
                          (char *)fragment_monitoring);
        }

      if (routing && strcmp((char*)routing, "optimized") == 0)
        params.optimize_routing = TRUE;

      ctx->engine_params = params;
      ctx->engine_params_set = 1;
    }
  /**************** Configuration of ssh_pme_redo_flows *********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("engine-flows"), 0))
    {
      const unsigned char *refresh;
      SshUInt32 refresh_val;

      refresh = ssh_xml_get_attr_value(attributes, ssh_custr("refresh"),
                                       0, NULL);
      refresh_val = 0;
      if (refresh != NULL)
        {
          if (!ssh_ipm_parse_number(ctx, refresh, &refresh_val))
            {
              ssh_ipm_error(ctx, "Invalid integer value '%s'", refresh);
              goto error;
            }
        }
      ctx->refresh_flows = refresh_val;
    }
  /************* Configuration of Audit policy ********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("audit"), 0))
    {
      /* We are parsing audit config data. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_AUDIT);
    }
  /************* Configuration of Audit modules ********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("module"), 0))
    {
      SshIpmAudit audit;
      SshUInt32 format, subsystems;
      const unsigned char *audit_name;

      /* format. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("format"),
                                     0, &value_len);

      if (ssh_xml_match(value, value_len, ssh_custr("default"), 0))
        format = SSH_AUDIT_FORMAT_DEFAULT;
      else
        {
          ssh_ipm_error(ctx, "Unknown audit formatter `%.*s'",
                        value_len, value);
          goto error;
        }

      /* name. */
      audit_name  = ssh_xml_get_attr_value(attributes, ssh_custr("log-to"),
                                        0, NULL);

      /* subsystem. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("subsystem"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);

      subsystems = 0;
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("all"), 0))
            subsystems |= SSH_PM_AUDIT_ALL;
          else if (ssh_xml_match(value, value_len, ssh_custr("ike"), 0))
            subsystems |= SSH_PM_AUDIT_IKE;
          else if (ssh_xml_match(value, value_len, ssh_custr("pm"), 0))
            subsystems |= SSH_PM_AUDIT_POLICY;




          else if (ssh_xml_match(value, value_len, ssh_custr("engine"), 0))
            subsystems |= SSH_PM_AUDIT_ENGINE;
          else
            {
              ssh_ipm_error(ctx, "Unknown audit subsystem `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* Lookup this audit module. */
      audit = ssh_ipm_xmlconf_audit_get(ctx, audit_name, format);

      if (audit == NULL)
        {
          ssh_ipm_error(ctx, "Could not allocate audit object");
          goto error;
        }

      /* Do we have an old audit object. */
      if (audit->seen)
        {
          if (audit->subsystems == subsystems)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Audit module properties unchanged"));
            }
          else
            {
              /* The audit module properties have been changed. */
              ssh_ipm_error(ctx, "Audit module properties cannot be "
                            "reconfigured '%s'", audit_name);
              goto error;
            }
        }
      else /* No old module. */
        {
          SshAuditContext audit_context;

          SSH_DEBUG(SSH_D_LOWOK, ("No old audit module"));

          audit_context = ssh_pm_create_audit_module(pm, format,
                                                     (const char *)audit_name);

          if (audit_context == NULL)
            {
              ssh_ipm_error(ctx, "Could not allocate audit context '%s'",
                            audit_name);
              goto error;
            }

          if (!ssh_pm_attach_audit_module(pm, subsystems, audit_context))
            {
              ssh_ipm_error(ctx, "Cannot attach audit module '%s' to the "
                            "system", audit_name);
              goto error;
            }

          audit->subsystems = subsystems;
          audit->seen = 1;
        }
    }
#ifdef SSH_IPSEC_HTTP_INTERFACE
  /********************** HTTP interface for statistics *********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("http-interface"), 0))
    {
      SshIpmHttpStatisticsParamsStruct params;
      SshUInt32 port;

      memset(&params, 0, sizeof(params));

      /* IP address. */
      params.address = (char *) ssh_xml_get_attr_value(attributes,
                                                       ssh_custr("address"), 0,
                                                       NULL);

      /* Port number. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("port"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, value, &port) || port > 65535)
        goto error;
      params.port = (SshUInt16) port;

      /* Frames. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("frames"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("yes"), 0))
        params.frames = TRUE;
      else
        params.frames = FALSE;

      /* Refresh. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("refresh"), 0,
                                     &value_len);
      if (!ssh_ipm_parse_number(ctx, value, &params.refresh))
        goto error;

      /* Start the HTTP statistics interface. */
      if (!ssh_ipm_http_statistics_start(ctx, &params))
        {
          ssh_ipm_error(ctx, "Could not start HTTP statistics interface");
          goto error;
        }

      /* HTTP interface configured. */
      ctx->http_interface = 1;
    }
#endif /* SSH_IPSEC_HTTP_INTERFACE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /******************************* Address-pool *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("address-pool"), 0))
    {
      const unsigned char *own_ip;
      const unsigned char *dns;
      const unsigned char *wins;
      const unsigned char *dhcp;
      const unsigned char *ap_name;

      /* We are parsing address-pool. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_ADDR_POOL);

      /* Fetch attributes. */
      own_ip = ssh_xml_get_attr_value(attributes, ssh_custr("own-ip"), 0,
                                      NULL);
      dns = ssh_xml_get_attr_value(attributes, ssh_custr("dns"), 0, NULL);
      wins = ssh_xml_get_attr_value(attributes, ssh_custr("wins"), 0, NULL);
      dhcp = ssh_xml_get_attr_value(attributes, ssh_custr("dhcp"), 0, NULL);

      ap_name = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0, NULL);

      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          /* Handle tunnel flags. */
          if (ssh_xml_match(value, value_len, ssh_custr("dhcp-ras"), 0))
            ctx->state->u.addrpool.flags |= SSH_PM_REMOTE_ACCESS_DHCP_POOL;
          else if (ssh_xml_match(value, value_len, ssh_custr("dhcpv6"), 0))
            ctx->state->u.addrpool.flags |= SSH_PM_REMOTE_ACCESS_DHCPV6_POOL;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("extract-cn"), 0))
            ctx->state->u.addrpool.flags |=
              SSH_PM_REMOTE_ACCESS_DHCP_EXTRACT_CN;
          else
            {
              ssh_ipm_error(ctx, "Unknown address-pool flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      if (own_ip)
        ctx->state->u.addrpool.remote_access_attr_own_ip = ssh_strdup(own_ip);
      if (dns)
        ctx->state->u.addrpool.remote_access_attr_dns = ssh_strdup(dns);
      if (wins)
        ctx->state->u.addrpool.remote_access_attr_wins = ssh_strdup(wins);
      if (dhcp)
        ctx->state->u.addrpool.remote_access_attr_dhcp = ssh_strdup(dhcp);
      if (ap_name)
        ctx->state->u.addrpool.address_pool_name = ssh_strdup(ap_name);
    }
  /**************** Sub-network specification for address pool **************/
  else if (ssh_xml_match(name, name_len, ssh_custr("subnet"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_SUBNET);
    }






  /**************** IP address specification for address pool ***************/
  else if (ssh_xml_match(name, name_len, ssh_custr("address"), 0))
    {
      /* We are parsing an IP address specification. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_ADDRESS);

      /* Netmask. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("netmask"), 0,
                                     NULL);
      if (value)
        {
          if (!ssh_ipaddr_parse_with_mask(&ctx->state->u.addrpool.netmask,
                                          value, NULL))
            {
              if (!ssh_ipaddr_parse(&ctx->state->u.addrpool.netmask, value))
                {
                  ssh_ipm_error(ctx, "Malformed netmask `%s'", value);
                  goto error;
                }
            }
        }
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_EXTERNALKEY
  /******************************* Externalkey ******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("externalkey"), 0))
    {
      SshExternalKey ek;
      SshEkStatus status;
      const unsigned char *type;
      const unsigned char *init_info;
      char *short_name;
      Boolean provider_known;

      /* Type. */
      type = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0, NULL);

      /* Initialization info. */
      init_info = ssh_xml_get_attr_value(attributes, ssh_custr("init-info"), 0,
                                         NULL);





      /* Do we already know this provider? */
      if (!ssh_ipm_lookup_ek_provider(ctx, (char *) type, (char *) init_info,
                                      &provider_known, TRUE, FALSE))
        {
          ssh_ipm_error(ctx, "Could not query externalkey providers");
          goto error;
        }

      if (provider_known)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Provider `%s' already configured",
                                       type));
        }
      else
        {
          /* Add provider. */

          ek = ssh_pm_get_externalkey(pm);
          SSH_ASSERT(ek != NULL);

          status = ssh_ek_add_provider(ek, (char *) type, (char *) init_info,
                                       NULL, 0, &short_name);
          if (status != SSH_EK_OK)
            {
              ssh_ipm_error(ctx, "Could not add externalkey provider `%s': %s",
                            (char *) type,
                            ssh_ek_get_printable_status(status));
              goto error;
            }

          /* Cleanup. */
          ssh_free(short_name);

          /* And finally, mark it as seen and new. */
          if (!ssh_ipm_lookup_ek_provider(ctx, (char *) type,
                                          (char *) init_info,
                                          &provider_known, TRUE, TRUE))
            {
              ssh_ipm_error(ctx, "Could not query externalkey providers");
              goto error;
            }
          SSH_ASSERT(provider_known);
        }
    }
#endif /* SSHDIST_EXTERNALKEY */
#ifdef SSHDIST_IKE_CERT_AUTH
  /*********************************** LDAP *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ldap"), 0))
    {
      const unsigned char *server;
      const unsigned char *port;

      /* Server. */
      server = ssh_xml_get_attr_value(attributes, ssh_custr("server"), 0,
                                      NULL);
      /* Port. */
      port = ssh_xml_get_attr_value(attributes, ssh_custr("port"), 0, NULL);

      if (ssh_buffer_append_cstrs(&ctx->ldap_servers,
                                  (ssh_buffer_len(&ctx->ldap_servers) == 0
                                   ? "" : ","),
                                  server, ":", port,
                                  NULL) != SSH_BUFFER_OK)
        {
          ssh_ipm_error(ctx, "Could not configure LDAP server");
          goto error;
        }

      /* LDAP server info changed. */
      ctx->ldap_changed = 1;
    }
#endif /* SSHDIST_IKE_CERT_AUTH */
  /**************** Legacy authentication client functionality **************/
  else if (ssh_xml_match(name, name_len, ssh_custr("client-auth"), 0))
    {
      SshIpmLegacyAuthClientAuth auth;

      auth = ssh_calloc(1, sizeof(*auth));
      if (auth == NULL)
        {
        error_client_auth_memory:
          ssh_ipm_error(ctx, "Could not save client authentication");
        error_client_auth:
          if (auth)
            {
              ssh_free(auth->user_name);
              ssh_free(auth->password);
              ssh_free(auth);
            }
          goto error;
        }

      /* Type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("l2tp"), 0))
            auth->flags |= SSH_PM_LA_L2TP;
          else if (ssh_xml_match(value, value_len, ssh_custr("xauth"), 0))
            auth->flags |= SSH_PM_LA_XAUTH;
          else if (ssh_xml_match(value, value_len, ssh_custr("eap"), 0))
            auth->flags |= SSH_PM_LA_EAP;
          else
            SSH_XML_VERIFIER(0);
        }

      /* Gateway IP. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("gateway"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&auth->gateway_ip, value))
            {
              ssh_ipm_error(ctx, "Invalid gateway IP address `%s'", value);
              goto error_client_auth;
            }
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (auth->flags & SSH_PM_LA_EAP)
        {
          /* If client-auth should be used in second auth round */
          value = ssh_xml_get_attr_value(attributes, ssh_custr("order"), 0,
                                         &value_len);

          /* Order is set for only EAP client authentications */
          if (value)
            {
              if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
                auth->flags |= SSH_PM_LA_FIRST_ROUND;
              else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
                auth->flags |= SSH_PM_LA_SECOND_ROUND;
              else
                SSH_XML_VERIFIER(0);
            }
          else
            {
              /* Default value */
              auth->flags |= SSH_PM_LA_FIRST_ROUND;
            }
        }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

      /* User-name. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("user-name"), 0,
                                     &value_len);
      auth->user_name = ssh_memdup(value, value_len);
      if (auth->user_name == NULL)
        goto error_client_auth_memory;
      auth->user_name_len = value_len;

      /* Password. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("password"), 0,
                                     &value_len);
      auth->password = ssh_memdup(value, value_len);
      if (auth->password == NULL)
        goto error_client_auth_memory;
      auth->password_len = value_len;

      /* Initial reference count is 1 */
      auth->references = 1;

      /* One client authentication parsed. */
      auth->next = ctx->la_client_auth;
      ctx->la_client_auth = auth;
    }
  /************* User-name - password based legacy authentication ***********/
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  else if (ssh_xml_match(name, name_len, ssh_custr("password"), 0))
    {
      SshPmSecretEncoding user_name_encoding = 0;
      SshPmSecretEncoding password_encoding = 0;
      size_t user_name_len, password_len;
      const unsigned char *user_name, *password;
      SshPmAuthDomain ad = NULL;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN);

      ad = ctx->state->u.auth_domain.auth_domain;

      /* Fetch attributes. */
      user_name = ssh_xml_get_attr_value(attributes,
                                         ssh_custr("user-name"), 0,
                                         &user_name_len);
      password = ssh_xml_get_attr_value(attributes,
                                        ssh_custr("password"), 0,
                                        &password_len);

      /* Encoding. */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("user-name-encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        user_name_encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        user_name_encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);

      /* Encoding. */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("password-encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        password_encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        password_encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);

      if (!ssh_pm_add_user(pm, ad,
                           user_name, user_name_len, user_name_encoding,
                           password, password_len, password_encoding))
        {
          ssh_ipm_error(ctx, "Could not configure user-name and password");
          goto error;
        }

    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_CERT
  /*********************** Manual certificates and CRLs *********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("certificate"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("crl"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("private-key"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("public-key"), 0))
    {
      if (ssh_xml_match(name, name_len, ssh_custr("certificate"), 0))
        ssh_ipm_push(ctx, SSH_IPM_XMLCONF_CERTIFICATE);
      else if (ssh_xml_match(name, name_len, ssh_custr("crl"), 0))
        ssh_ipm_push(ctx, SSH_IPM_XMLCONF_CRL);
      else if (ssh_xml_match(name, name_len, ssh_custr("private-key"), 0))
        ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PRVKEY);
      else
        ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PUBKEY);

      /* File name. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("file"), 0,
                                     &value_len);
      if (value)
        {
          ctx->state->u.keycert.file = ssh_memdup(value, value_len);
          if (ctx->state->u.keycert.file == NULL)
            {
              ssh_ipm_error(ctx, "Could not store file name");
              goto error;
            }
        }
    }
#endif /* SSHDIST_CERT */
  /****************************** Pre-shared key ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("remote-secret"), 0))
    {
      Boolean id_type_given = FALSE;
      Boolean id_given = FALSE;

      /* We are parsing a preshared key. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PSK);

      /* ID type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id-type"), 0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("dn"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_DN;
          else if (ssh_xml_match(value, value_len, ssh_custr("ip"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_IP;
          else if (ssh_xml_match(value, value_len, ssh_custr("fqdn"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_FQDN;
          else if (ssh_xml_match(value, value_len, ssh_custr("email"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_RFC822;
          else if (ssh_xml_match(value, value_len, ssh_custr("key-id"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_KEY_ID;
#ifdef SSHDIST_IKE_ID_LIST
          else if (ssh_xml_match(value, value_len, ssh_custr("idlist"), 0))
            ctx->state->u.psk.id_type = SSH_PM_IDENTITY_ID_LIST;
#endif /* SSHDIST_IKE_ID_LIST */
          else
            {
              ssh_ipm_error(ctx, "Unsupported id-type %s", value);
              goto error;
            }

          id_type_given = TRUE;
        }

      /* Identity. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipm_store_identity(ctx, TRUE, value, value_len))
            goto error;

          id_given = TRUE;
        }

      /* Encoding. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id-encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        ctx->state->u.psk.id_encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        ctx->state->u.psk.id_encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);

      /* Encoding. */

      value = ssh_xml_get_attr_value(attributes, ssh_custr("encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        ctx->state->u.psk.encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        ctx->state->u.psk.encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);

      /* Post checks for identity and its type. */
      if (id_type_given != id_given)
        {
          ssh_ipm_error(ctx,
                        "You must specify both IKE identity and its type");
          goto error;
        }
    }
  else if (ssh_xml_match(name, name_len, ssh_custr("local-secret"), 0))
    {
      /* We are parsing a preshared key. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PSK);

      /* Encoding. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        ctx->state->u.psk.encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        ctx->state->u.psk.encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);
    }
  /************************** Access control groups *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("group"), 0))
    {
      /* Name. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                     &value_len);

      /* We are parsing an authorization group. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_ACCESS_GROUP);

      /* Create a new group object. */
      ctx->state->u.group.group = ssh_ipm_create_group(ctx, value, value_len);
      if (ctx->state->u.group.group == NULL)
        {
          ssh_ipm_error(ctx, "Could not create access control group");
          goto error;
        }
    }
  /*************** Constraints for access control group members *************/
  else if (ssh_xml_match(name, name_len, ssh_custr("constraint"), 0))
    {
      /* Constraint type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
      if (ssh_xml_match(value, value_len, ssh_custr("xauth"), 0))
        {
          SshPmConstraintType type;
          char *field = NULL;
          char *pattern = NULL;
          Boolean status;

          /* Optional field. */
          value = ssh_xml_get_attr_value(attributes, ssh_custr("field"), 0,
                                         &value_len);
          if (value == NULL)
            {
              /* Plain XAUTH. */
              type = SSH_PM_CONSTRAIN_XAUTH;
            }
          else if (ssh_xml_match(value, value_len, ssh_custr("radius"), 0))
            {
              /* XAUTH with RADIUS. */
              type = SSH_PM_CONSTRAIN_XAUTH_RADIUS;

              /* Optional reply AVP field and pattern. */
              value = ssh_xml_get_attr_value(attributes,
                                             ssh_custr("pattern"), 0,
                                             &value_len);
              if (value)
                {
                  pattern = strchr((char *) value, '=');
                  if (pattern == NULL)
                    {
                      ssh_ipm_error(ctx, "Invalid XAUTH pattern `%s'", value);
                      goto error;
                    }
                  field = ssh_memdup(value, pattern - (char *) value);
                  if (field == NULL)
                    {
                      ssh_ipm_error(ctx, "Could not store constraint");
                      goto error;
                    }
                  pattern++;
                }
            }
          else
            {
              type = 0;
              ssh_ipm_error(ctx, "Invalid xauth constraint `%s'", value);
              goto error;
            }

          status = ssh_authorization_group_add_xauth_constraint(
                                                ctx->state->u.group.group,
                                                type, field, pattern);
          ssh_free(field);

          if (!status)
            {
              ssh_ipm_error(ctx, "Could not add XAUTH constraint");
              goto error;
            }
        }
      else
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
#ifdef SSHDIST_IKE_EAP_AUTH
      if (ssh_xml_match(value, value_len, ssh_custr("eap"), 0))
        {
          SshPmAuthMethod auth_method = SSH_PM_AUTH_NONE;

          value = ssh_xml_get_attr_value(attributes, ssh_custr("field"), 0,
                                         &value_len);
          if (value != NULL)
            {
              if (ssh_xml_match(value, value_len,
                                     ssh_custr("auth-method"), 0))
                {
                  value = ssh_xml_get_attr_value(attributes,
                                                 ssh_custr("pattern"), 0,
                                                 &value_len);
                  if (value)
                    {
                      if (ssh_xml_match(value, value_len,
                                        ssh_custr("md5-challenge"), 0))
                        auth_method = SSH_PM_AUTH_EAP_MD5_CHALLENGE;





                      else if (ssh_xml_match(value, value_len,
                                             ssh_custr("sim"), 0))
                        auth_method = SSH_PM_AUTH_EAP_SIM;
                      else if (ssh_xml_match(value, value_len,
                                             ssh_custr("aka"), 0))
                        auth_method = SSH_PM_AUTH_EAP_AKA;





#ifdef SSHDIST_EAP_TLS
                      else if (ssh_xml_match(value, value_len,
                                             ssh_custr("tls"), 0))
                        auth_method = SSH_PM_AUTH_EAP_TLS;
#endif /* SSHDIST_EAP_TLS */
                      else if (ssh_xml_match(value, value_len,
                                 ssh_custr("mschapv2"), 0))
            auth_method = SSH_PM_AUTH_EAP_MSCHAP_V2;
                      else
                        {
                          ssh_ipm_error(ctx,
                                      "Invalid EAP authentication method '%s'",
                                        value);
                          goto error;
                        }
                    }
                  else
                    {
                      ssh_ipm_error(ctx, "No pattern specified");
                      goto error;
                    }
                }
              else
                {
                  ssh_ipm_error(ctx, "Invalid EAP constrain '%s'", value);
                  goto error;
                }
            }

          /* Add EAP constraint */
          if (!ssh_authorization_group_add_eap_constraint(
                                                     ctx->state->u.group.group,
                                                     auth_method))
            {
              ssh_ipm_error(ctx, "Could not add EAP constraint");
              goto error;
            }
        }
      else
#endif /* SSHDIST_IKE_EAP_AUTH */
        {
          SshPmIdentityType id_type;
          SshPmConstraintType constraint_type;

          if (ssh_xml_match(value, value_len, ssh_custr("cert-subject"), 0))
            constraint_type = SSH_PM_CONSTRAIN_SUBJECT;
          else if (ssh_xml_match(value, value_len, ssh_custr("cert-issuer"),
                                 0))
            constraint_type = SSH_PM_CONSTRAIN_ISSUER;
          else if (ssh_xml_match(value, value_len, ssh_custr("ca-subject"), 0))
            constraint_type = SSH_PM_CONSTRAIN_CA;
          else if (ssh_xml_match(value, value_len, ssh_custr("key-subject"),
                                 0))
            constraint_type = SSH_PM_CONSTRAIN_PSK_SUBJECT;
#ifdef SSHDIST_IKE_EAP_AUTH
          else if (ssh_xml_match(value, value_len, ssh_custr("eap-subject"),
                                 0))
            constraint_type = SSH_PM_CONSTRAIN_EAP_SUBJECT;
#endif /* SSHDIST_IKE_EAP_AUTH */
          else
            {
              ssh_ipm_error(ctx, "Invalid constraint type `%s'", value);
              goto error;
            }

          /* Check ID type. */
          value = ssh_xml_get_attr_value(attributes, ssh_custr("field"), 0,
                                         &value_len);
          if (value == NULL)
            {
              ssh_ipm_error(ctx, "No constraint field specified");
              goto error;
            }
          if (ssh_xml_match(value, value_len, ssh_custr("dn"), 0))
            id_type = SSH_PM_IDENTITY_DN;
          else if (ssh_xml_match(value, value_len, ssh_custr("ip"), 0))
            id_type = SSH_PM_IDENTITY_IP;
          else if (ssh_xml_match(value, value_len, ssh_custr("fqdn"), 0))
            id_type = SSH_PM_IDENTITY_FQDN;
          else if (ssh_xml_match(value, value_len, ssh_custr("email"), 0))
            id_type = SSH_PM_IDENTITY_RFC822;
          else if (ssh_xml_match(value, value_len, ssh_custr("key-id"), 0))
            id_type = SSH_PM_IDENTITY_KEY_ID;
          else
            {
              ssh_ipm_error(ctx, "Invalid field `%s'", value);
              goto error;
            }

          /* Pattern. */
          value = ssh_xml_get_attr_value(attributes, ssh_custr("pattern"), 0,
                                         &value_len);
          if (value == NULL)
            {
              ssh_ipm_error(ctx, "No pattern specified");
              goto error;
            }

          if (constraint_type == SSH_PM_CONSTRAIN_PSK_SUBJECT)
            {
              if (!ssh_authorization_group_add_psk_constraint(
                                              ctx->state->u.group.group,
                                              id_type,
                                              (char *) value))
                {
                  ssh_ipm_error(ctx, "Could not add PSK constraint");
                  goto error;
                }
            }
#ifdef SSHDIST_IKE_EAP_AUTH
          else if (constraint_type == SSH_PM_CONSTRAIN_EAP_SUBJECT)
            {
              if (!ssh_authorization_group_add_eap_subject_constraint(
                                                 ctx->state->u.group.group,
                                                 id_type,
                                                 (char *) value))
                    {
                      ssh_ipm_error(ctx, "Could not add EAP constraint");
                      goto error;
                    }
            }
#endif /* SSHDIST_IKE_EAP_AUTH */
            else
            {
              /* Configure this certificate constraint. */
              if (!ssh_authorization_group_add_cert_constraint(
                                              ctx->state->u.group.group,
                                              id_type,
                                              constraint_type,
                                              (char *) value))
                {
                  ssh_ipm_error(ctx, "Could not add certificate constraint");
                  goto error;
                }
            }
        }
    }

  /*********************************** DNS **********************************/
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("dns"), 0))
    {
      ctx->dns_names_allowed = 1;
      ctx->dns_configuration_done = 0;
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_DNS);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /********************** Standalone route configuration ********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("route"), 0))
    {
#ifdef SSH_IPSEC_INTERNAL_ROUTING
      char *dst;
      char *gw;
      SshUInt32 ifnum;

      /* Fetch attributes. */
      dst = (char *) ssh_xml_get_attr_value(attributes,
                                            ssh_custr("dst"), 0, NULL);
      gw = (char *) ssh_xml_get_attr_value(attributes,
                                           ssh_custr("gw"), 0, NULL);

      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("ifname"), 0, NULL);
      if (value == NULL ||
          !ssh_pm_get_interface_number(pm, value, &ifnum))
        {
          value = ssh_xml_get_attr_value(attributes,
                                         ssh_custr("ifnum"), 0, NULL);
          if (value == NULL || !ssh_ipm_parse_number(ctx, value, &ifnum))
            {
              ssh_ipm_error(ctx,
                            "Neither ifname, nor ifnum given for route.");
              goto error;
            }
        }

      /* Configure this route entry. */
      ssh_pm_configure_route(pm, dst, gw, ifnum, NULL_FNPTR, NULL);
#else /* SSH_IPSEC_INTERNAL_ROUTING */
      ssh_ipm_error(ctx,
                    "Internal routing is not supported.");
      goto error;
#endif /* SSH_IPSEC_INTERNAL_ROUTING */
    }
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  else if (ssh_xml_match(name, name_len, ssh_custr("media"), 0))
    {
      char *ip, *mac;
      unsigned char mac_addr[6];
      SshIpAddrStruct ip_addr;
      SshUInt32 ifnum = SSH_INVALID_IFNUM;
      SshUInt32 flags = 0;
      Boolean found = FALSE;
      SshIpmMediaConfig media;

      /* Fetch attributes. */
      ip = (char *) ssh_xml_get_attr_value(attributes,
                                            ssh_custr("ip"), 0, NULL);

      if (!ssh_ipaddr_parse(&ip_addr, ip))
        {
          ssh_ipm_error(ctx, "Invalid IP address `%s'", ip);
          goto error;
        }
      mac = (char *) ssh_xml_get_attr_value(attributes,
                                            ssh_custr("mac"), 0, NULL);

      if (!ssh_ipm_parse_media_addr(mac_addr, mac))
        {
          ssh_ipm_error(ctx, "Cannot parse media address");
          goto error;
        }
      SSH_DEBUG_HEXDUMP(SSH_D_MY, ("MAC address %s", mac), mac_addr, 6);

      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("ifname"), 0, NULL);
      if (value == NULL ||
          !ssh_pm_get_interface_number(pm, value, &ifnum))
        {
          value = ssh_xml_get_attr_value(attributes,
                                         ssh_custr("ifnum"), 0, NULL);
          if (value != NULL && !ssh_ipm_parse_number(ctx, value, &ifnum))
            {
              ssh_ipm_error(ctx, "Cannot parse ifnum given for media address "
                            "entry.");
              goto error;
            }
        }

      /* Lookup this MEDIA entry */
      for (media = ctx->media_list; media != NULL; media = media->next)
        {
          if (!SSH_IP_CMP(&media->ip, &ip_addr) &&
              (sizeof(media->mac) == sizeof(mac_addr)) &&
              !memcmp(media->mac, mac_addr, sizeof(media->mac)) &&
              media->flags == flags &&
              media->ifnum == ifnum)
            {
              media->seen = 1;
              media->old = 1;
              found = TRUE;
              break;
            }
        }

      if (!found)
        {
          media = ssh_calloc(1, sizeof(*media));
          if (media == NULL)
            goto error;

          media->seen = 1;
          media->old = 0;
          media->ifnum = ifnum;
          media->flags = flags;
          media->ip = ip_addr;
          memcpy(media->mac, mac_addr, sizeof(media->mac));

          media->next = ctx->media_list;
          ctx->media_list = media;

          /* Configure this media address mapping entry. */
          ssh_pm_media_address_mapping_add(pm, &ip_addr, ifnum,
                                           mac_addr, sizeof(mac_addr),
                                           flags, ssh_ipm_media_add_cb, NULL);
        }
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  /*********************************** NAT **********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("nat"), 0))
    {
#ifdef SSHDIST_IPSEC_NAT
      SshIpmNatConfig nat = NULL;

      nat = ssh_calloc(1, sizeof(*nat));
      if (nat == NULL)
        {
          ssh_ipm_error(ctx, "Could not configure interface NAT");
          goto error;
        }
      nat->next = ctx->config_parameters.nat_list;
      ctx->config_parameters.nat_list = nat;

      /* Type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("host"), 0))
        nat->nat_type = SSH_PM_NAT_TYPE_HOST_DIRECT;
      else
        nat->nat_type = SSH_PM_NAT_TYPE_PORT;

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          /* Handle flags. */
          if (ssh_xml_match(value, value_len, ssh_custr("ipv6"), 0))
            nat->flags |= SSH_PM_INTERFACE_NAT_IPV6;
          else
            {
              ssh_ipm_error(ctx, "Unknown flags value `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* More flags: Read src-port-preservation if it is available. */
      value = ssh_xml_get_attr_value(
        attributes, ssh_custr("src-port-preservation"), 0,
                              &value_len);
      if (value && ssh_xml_match(value, value_len,
                        ssh_custr("loose"), 0))
        nat->flags |= SSH_PM_NAT_FLAGS_EMPTY; /* "loose" behavior -
                                                 default flags */
      else if (value &&
               ssh_xml_match(value, value_len,
                             ssh_custr("overload"), 0))
        {
          nat->flags |= SSH_PM_NAT_KEEP_PORT;
          nat->flags |= SSH_PM_NAT_SHARE_PORT_SRC;
        }
      else if (value && ssh_xml_match(value, value_len,
                                      ssh_custr("strict"), 0))
        nat->flags |= SSH_PM_NAT_KEEP_PORT;
      else
        nat->flags |= SSH_PM_NAT_NO_TRY_KEEP_PORT; /* Port preservation off */

      /* Interface name. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("ifname"), 0,
                                     NULL);
      nat->ifname = ssh_strdup(value);
      if (!nat->ifname)
        {
          ssh_ipm_error(ctx, "Memory allocation failed for interface"
                        " name. Could not configure interface NAT.");
          goto error;
        }

#else /* SSHDIST_IPSEC_NAT */
      ssh_ipm_error(ctx, "NAT is not supported.");
      goto error;
#endif /* SSHDIST_IPSEC_NAT */
    }

  /****************** IP address pool for NAT-T internal NAT ****************/
  else if (ssh_xml_match(name, name_len, ssh_custr("internal-nat"), 0))
    {
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      const unsigned char *first;
      const unsigned char *last;
      SshIpAddrStruct first_ip;
      SshIpAddrStruct last_ip;

      /* Get attributes. */
      first = ssh_xml_get_attr_value(attributes, ssh_custr("first-ip"), 0,
                                     NULL);
      if (!ssh_ipaddr_parse(&first_ip, first))
        {
          ssh_ipm_error(ctx, "Invalid internal NAT IP address `%s'", first);
          goto error;
        }
      last = ssh_xml_get_attr_value(attributes, ssh_custr("last-ip"), 0, NULL);
      if (!ssh_ipaddr_parse(&last_ip, last))
        {
          ssh_ipm_error(ctx, "Invalid internal NAT IP address `%s'", last);
          goto error;
        }

      if (SSH_IP_CMP(&first_ip, &last_ip) > 0)
        {
          ssh_ipm_error(ctx, "Invalid internal NAT IP address range %s-%s",
                        first, last);
          goto error;
        }

      ctx->config_parameters.internal_nat_first = ssh_strdup(first);
      ctx->config_parameters.internal_nat_last = ssh_strdup(last);

#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      ssh_ipm_error(ctx, "NAT-T is not supported.");
      goto error;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#else /* SSHDIST_IPSEC_NAT */
      ssh_ipm_error(ctx, "NAT is not supported.");
#endif /* SSHDIST_IPSEC_NAT */
    }
  /****************************** RADIUS client *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("radius-client"), 0))
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
      SshRadiusClient radius_client;
      SshRadiusClientServerInfo radius_servers;

      SshRadiusClientParamsStruct params;
      SshPmAuthDomain ad = NULL;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN ||
                 ctx->state->type == SSH_IPM_XMLCONF_RADIUS_ACCOUNTING);

      memset(&params, 0, sizeof(params));

      /* Address */
      params.address = (unsigned char *)
        ssh_xml_get_attr_value(attributes, ssh_custr("address"), 0, NULL);

      /* Port. */
      params.port = (unsigned char *)
        ssh_xml_get_attr_value(attributes, ssh_custr("port"), 0, NULL);

      /* NAS IP address. */
      params.nas_ip_address = (unsigned char *)
        ssh_xml_get_attr_value(attributes, ssh_custr("nas-ip-address"), 0,
                               NULL);

      /* NAS identifier */
      params.nas_identifier = (unsigned char *)
        ssh_xml_get_attr_value(attributes, ssh_custr("nas-identifier"), 0,
                               NULL);

      if (params.nas_identifier != NULL &&
          strlen(params.nas_identifier) >
          /* Maximum length for RADIUS Attribute */ 253)
        {
          ssh_ipm_error(
                  ctx,
                  "RADIUS Client nas-identifier is too long (over 253).");
          goto error;
        }

      /* Maximum retransmit timer. */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("max-retransmit-timer"), 0,
                                     NULL);
      if (value
          && !ssh_ipm_parse_number(ctx, value,
                                   &params.max_retransmit_timer))
        goto error;

      /* Maximum number of retransmissions. */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("max-retransmissions"), 0,
                                     NULL);
      if (value
          && !ssh_ipm_parse_number(ctx, value,
                                   &params.max_retransmissions))
        goto error;


      /* Create the radius client. */
      radius_client = ssh_radius_client_create(&params);
      if (radius_client == NULL)
        {
          ssh_ipm_error(ctx, "Could not create RADIUS client");
          goto error;
        }

      /* Create an empty server info structure.  It is filled up
         later when RADIUS servers are configured. */
      radius_servers = ssh_radius_client_server_info_create();
      if (radius_servers == NULL)
        {
          ssh_radius_client_destroy(radius_client);
          radius_client = NULL;

          ssh_ipm_error(ctx, "Could not create RADIUS server info");
          goto error;
        }

      if (ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN)
        {
          ad = ctx->state->u.auth_domain.auth_domain;

          /* Configure authentication with RADIUS. */
          if (!ssh_pm_set_radius_servers(ctx->pm,
                                         ad,
                                         radius_client,
                                         radius_servers))
            {
              ssh_radius_client_destroy(radius_client);
              ssh_radius_client_server_info_destroy(radius_servers);

              ssh_ipm_error(ctx, "Could not configure RADIUS authentication");
              goto error;
            }
        }
      else
        {
          ctx->radius_acct_client = radius_client;
          ctx->radius_acct_servers = radius_servers;
        }

#else /* SSHDIST_RADIUS */
      ssh_ipm_error(ctx, "Radius not supported");
      goto error;
#endif /* SSHDIST_RADIUS */
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
      ssh_ipm_error(ctx, "Radius not supported");
      goto error;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }
  /****************************** RADIUS server *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("radius"), 0))
    {
#ifdef SSHDIST_RADIUS
      const char *server;
      const char *port;
      const char *acct_port;
      const unsigned char *secret;
      size_t secret_len;

      SshPmAuthDomain ad = NULL;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN ||
                 ctx->state->type == SSH_IPM_XMLCONF_RADIUS_ACCOUNTING);

      /* Fetch attributes. */
      server = (char *) ssh_xml_get_attr_value(attributes,
                                               ssh_custr("server"), 0, NULL);
      port = (char *) ssh_xml_get_attr_value(attributes,
                                             ssh_custr("port"), 0, NULL);
      acct_port = (char *) ssh_xml_get_attr_value(attributes,
                                                  ssh_custr("acct-port"), 0,
                                                  NULL);
      secret = ssh_xml_get_attr_value(attributes, ssh_custr("secret"), 0,
                                      &secret_len);

      if (ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN)
        {
          ad = ctx->state->u.auth_domain.auth_domain;

          if (!ssh_pm_auth_domain_radius_is_configured(ad))
            {
              ssh_ipm_error(ctx, "No RADIUS authentication configured. Please "
                            "configure radius-client before radius-element");
              goto error;
            }
          if (!ssh_pm_auth_domain_set_radius_server(ad, server, port,
                                                    acct_port, secret,
                                                    secret_len))
            {
              ssh_ipm_error(ctx, "Could not configure RADIUS server");
              goto error;
            }
        }
      else
        {
          SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_RADIUS_ACCOUNTING);

          if (!ssh_radius_client_server_info_add_server(
                      ctx->radius_acct_servers,
                      server, port, acct_port,
                      secret, secret_len))
            {
              ssh_ipm_error(
                      ctx,
                      "Could not configure RADIUS accounting server");

              goto error;
            }
        }
#else /* SSHDIST_RADIUS */
      ssh_ipm_error(ctx, "Radius not supported");
      goto error;
#endif /* SSHDIST_RADIUS */
    }
  /********************************XAUTH-METHOD *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("xauth-method"),0))
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
      SshIkeXauthType xauth_type = 0;
      SshPmXauthFlags flag = 0;

      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("generic"), 0))
            xauth_type = SSH_IKE_XAUTH_TYPE_GENERIC;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("radius-chap"),0))
            xauth_type = SSH_IKE_XAUTH_TYPE_RADIUS_CHAP;








          else
            {
              ssh_ipm_error(ctx, "Unknown xauth-method.");
              goto error;
            }
        }

      value = ssh_xml_get_attr_value(attributes, ssh_custr("flag"),0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("simple"),0))
            flag = SSH_PM_XAUTH_GENERIC_USER_NAME_PASSWORD;
          else if (ssh_xml_match(value, value_len, ssh_custr("securid"),0))
            flag = SSH_PM_XAUTH_GENERIC_SECURID;
          else
            {
              ssh_ipm_error(ctx, "Unknown flag value.");
              goto error;
            }
        }
      if (!ssh_pm_set_xauth_method(pm, xauth_type, flag))
        {
          ssh_ipm_error(ctx, "Unable to configure xauth-method");
          goto error;
        }
#else /* SSHDIST_IPSEC_XAUTH_SERVER */
      ssh_ipm_error(ctx, "xauth-method is supported on gateways only.");
      goto error;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
      ssh_ipm_error(ctx, "xauth-method is supported on gateways only.");
      goto error;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }
#ifdef SSHDIST_IPSEC_MOBIKE
  /*********************************** Mobike ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("mobike"), 0))
    {
      SshUInt32 mobike_rrc_policy = 0;

      ssh_xml_attr_value_enum_init(attributes, ssh_custr("rrc-policy"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("before-sa-update"), 0))
            {
              mobike_rrc_policy |= SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE;
            }
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("after-sa-update"), 0))
            {
              mobike_rrc_policy |= SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE;
            }
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("no-rrc"), 0))
            {
              mobike_rrc_policy |= SSH_PM_MOBIKE_POLICY_NO_RRC;
            }
          else
            {
              ssh_ipm_error(ctx, "Unknown rrc policy value `%.*s'.",
                            value_len, value);
              goto error;
            }
        }

      if (!ssh_pm_set_mobike_default_rrc_policy(pm, mobike_rrc_policy))
        {
          ssh_ipm_error(ctx, "Invalid rrc policy.");
          goto error;
        }
    }
#endif /* SSHDIST_IPSEC_MOBIKE */


  /********************************** Policy ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("policy"), 0))
    {
      /* Precedence. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("precedence"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipm_parse_number(ctx, value, &ctx->precedence_max))
            goto error;

          if (ctx->precedence_max >= ctx->precedence_used_min)
            {
              ssh_ipm_error(ctx, "Overlapping policy block");
              goto error;
            }
        }
      else
        ctx->precedence_max = ctx->precedence_used_min - 1;

      /* Size of the precedence range. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("size"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipm_parse_number(ctx, value, &ctx->precedence_min))
            goto error;

          if (ctx->precedence_min >= ctx->precedence_used_min)
            {
              ssh_ipm_error(ctx,
                            "Too large policy block: "
                            "size=%u, available size=%u",
                            ctx->precedence_min,
                            ctx->precedence_used_min - 1);
              goto error;
            }
          ctx->precedence_min = ctx->precedence_max - ctx->precedence_min - 1;
        }
      else
        ctx->precedence_min = 0;

      /* Refresh time. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("refresh"), 0,
                                     &value_len);
      if (!ssh_ipm_parse_number(ctx, value, &ival))
        goto error;

      if (ival)
        ctx->refresh = ival;
      else
        ctx->refresh = 0;

      SSH_DEBUG(SSH_D_LOWSTART, ("Policy: precedence=[%u...%u], refresh=%u",
                                 (unsigned int) ctx->precedence_max,
                                 (unsigned int) ctx->precedence_min,
                                 (unsigned int) ctx->refresh));





      /* And start consuming the precedence range from the maximum
         value. */
      ctx->precedence_next = ctx->precedence_max;

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_POLICY);
    }

  /****************** Default IKE parameters and algorithms *****************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-defaults"), 0))
    {
      SshUInt32 transform = 0;

      /* Algorithms. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("algorithms"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("cipher1"), 0))
            transform |= SSH_PM_CRYPT_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("cipher2"), 0))
            transform |= SSH_PM_CRYPT_EXT2;
#ifndef HAVE_FIPSLIB
#ifdef SSH_IPSEC_CRYPT_DES
          else if (ssh_xml_match(value, value_len, ssh_custr("des"), 0))
            transform |= SSH_PM_CRYPT_DES;
#endif /* SSH_IPSEC_CRYPT_DES */
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("3des"), 0))
            transform |= SSH_PM_CRYPT_3DES;
#ifdef SSHDIST_CRYPT_RIJNDAEL
          else if (ssh_xml_match(value, value_len, ssh_custr("aes"), 0))
            transform |= SSH_PM_CRYPT_AES;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ctr"), 0))
            transform |= SSH_PM_CRYPT_AES_CTR;
#ifdef SSHDIST_CRYPT_MODE_GCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-64"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-96"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM_12;
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-64"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-96"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM_12;
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else if (ssh_xml_match(value, value_len, ssh_custr("mac1"), 0))
            transform |= SSH_PM_MAC_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("mac2"), 0))
            transform |= SSH_PM_MAC_EXT2;
#ifndef HAVE_FIPSLIB
          else if (ssh_xml_match(value, value_len, ssh_custr("md5"), 0))
            transform |= SSH_PM_MAC_HMAC_MD5;
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("sha1"), 0))
            transform |= SSH_PM_MAC_HMAC_SHA1;
#ifdef SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
          else if (ssh_xml_match(value, value_len, ssh_custr("sha2"), 0))
            transform |= SSH_PM_MAC_HMAC_SHA2;
#endif /* SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSHDIST_CRYPT_XCBCMAC
          else if (ssh_xml_match(value, value_len, ssh_custr("xcbc-aes"), 0))
            transform |= SSH_PM_MAC_XCBC_AES;
#endif /* SSHDIST_CRYPT_XCBCMAC */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else
            {
              ssh_ipm_error(ctx, "Unknown algorithm `%.*s'",
                            value_len, value);
              goto error;
            }
        }
      if (transform)
        {
#ifdef TGX_ALGORITHMS
          if ((transform & SSH_PM_CRYPT_EXT1) != 0 ||
              (transform & SSH_PM_CRYPT_EXT2) != 0 ||
              (transform & SSH_PM_MAC_EXT1) != 0 ||
              (transform & SSH_PM_MAC_EXT2) != 0)
            {
              ssh_ipm_error(ctx, "Specified algorithm not valid for tilegx");
              goto error;
            }
#endif /* TGX_ALGORITHMS */
          if ((transform & SSH_PM_CRYPT_MASK) == 0)
            {
              ssh_ipm_error(ctx, "No cipher algorithm specified");
              goto error;
            }
          if ((transform &
               (SSH_PM_MAC_MASK | SSH_PM_COMBINED_MASK)) == 0)
            {
              ssh_ipm_error(ctx, "No hash algorithm specified");
              goto error;
            }
          ctx->config_parameters.default_ike_algorithms = transform;
        }
    }

  /********************************* Service ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("service"), 0))
    {
#ifdef SSHDIST_IPSEC_NAT
      ssh_ipm_error(ctx, "Service not supported");
      goto error;
#endif /* SSHDIST_IPSEC_NAT */

    }
#ifdef SSHDIST_IKE_REDIRECT
  /**************************** IKE redirect ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-redirect"), 0))
    {
      /* We are parsing an ike redirect object. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IKE_REDIRECT);

      ssh_xml_attr_value_enum_init(attributes, ssh_custr("phase"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          /* Handle tunnel flags. */
          if (ssh_xml_match(value, value_len, ssh_custr("ike-init"), 0))
            ctx->state->u.ike_redirect.phase |=  SSH_PM_IKE_REDIRECT_IKE_INIT;
          else if (ssh_xml_match(value, value_len, ssh_custr("ike-auth"), 0))
            ctx->state->u.ike_redirect.phase |=  SSH_PM_IKE_REDIRECT_IKE_AUTH;
          else
            {
              ssh_ipm_error(ctx, "Unknown IKE Redirect phase `%.*s'",
                            value_len, value);
              goto error;
            }
        }
    }
  /**************** Redirect address for IKE Redirect ***********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("redirect-address"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_REDIRECT_ADDRESS);
    }
#endif /* SSHDIST_IKE_REDIRECT */

  /************************* Authorization domain ***************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("auth-domain"), 0))
    {
      const unsigned char *auth_domain_name;
      size_t auth_domain_name_len;

      /* Name. */
      auth_domain_name = ssh_xml_get_attr_value(attributes,
                                                ssh_custr("name"),
                                                0,
                                                &auth_domain_name_len);

      /* We are parsing an auth domain object. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_AUTH_DOMAIN);

      if (auth_domain_name)
        {
          /* Create an auth domain object. */
          ctx->state->u.auth_domain.auth_domain =
            ssh_pm_auth_domain_create(pm,
                                      (char *) auth_domain_name);
        }
      else
        {
          /* No name specified, get default auth domain to configure.*/
          ctx->state->u.auth_domain.auth_domain =
            ssh_pm_auth_domain_get_default(pm);

          ctx->default_auth_domain_present = 1;
        }

      if (ctx->state->u.auth_domain.auth_domain == NULL)
        {
          ssh_ipm_error(ctx,
                        "Could not create authentication domain object");
          goto error;
        }

      ctx->auth_domains = 1;

#ifdef SSHDIST_IKE_EAP_AUTH
      /* Initialize the EAP default method preference */
      ctx->state->u.auth_domain.eap_preference_next = 255;
#endif /* SSHDIST_IKE_EAP_AUTH */
    }

  /********************************** Tunnel ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("tunnel"), 0))
    {

      const unsigned char *tunnel_name;
      size_t tunnel_name_len;
      SshUInt64 transform = 0;
      SshUInt32 flags = SSH_PM_TI_DELAYED_OPEN;
      SshUInt32 ike_life = 0;
      Boolean got_transform;
#ifdef SSHDIST_IPSEC_SA_EXPORT
      const unsigned char *app_id;
      size_t app_id_len;
#endif /* SSHDIST_IPSEC_SA_EXPORT */

      /* Name. */
      tunnel_name = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                           &tunnel_name_len);
      SSH_ASSERT(tunnel_name != NULL);

      /* Transform. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("transform"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      got_transform = (attr_enum.value != NULL);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          /* Handle the transform option. */
          if (ssh_xml_match(value, value_len, ssh_custr("cipher1"), 0))
            transform |= SSH_PM_CRYPT_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("cipher2"), 0))
            transform |= SSH_PM_CRYPT_EXT2;
          else if (ssh_xml_match(value, value_len, ssh_custr("null"), 0))
            transform |= SSH_PM_CRYPT_NULL;
#ifndef HAVE_FIPSLIB
#ifdef SSH_IPSEC_CRYPT_DES
          else if (ssh_xml_match(value, value_len, ssh_custr("des"), 0))
            transform |= SSH_PM_CRYPT_DES;
#endif /* SSH_IPSEC_CRYPT_DES */
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("3des"), 0))
            transform |= SSH_PM_CRYPT_3DES;
#ifdef SSHDIST_CRYPT_RIJNDAEL
          else if (ssh_xml_match(value, value_len, ssh_custr("aes"), 0))
            transform |= SSH_PM_CRYPT_AES;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ctr"), 0))
            transform |= SSH_PM_CRYPT_AES_CTR;
#ifdef SSHDIST_CRYPT_MODE_GCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-64"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-96"), 0))
            transform |= SSH_PM_CRYPT_AES_GCM_12;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("gmac-aes"), 0))
            transform |= SSH_PM_CRYPT_NULL_AUTH_AES_GMAC;
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-64"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-96"), 0))
            transform |= SSH_PM_CRYPT_AES_CCM_12;
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else if (ssh_xml_match(value, value_len, ssh_custr("mac1"), 0))
            transform |= SSH_PM_MAC_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("mac2"), 0))
            transform |= SSH_PM_MAC_EXT2;
#ifndef HAVE_FIPSLIB
          else if (ssh_xml_match(value, value_len, ssh_custr("md5"), 0))
            transform |= SSH_PM_MAC_HMAC_MD5;
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("sha1"), 0))
            transform |= SSH_PM_MAC_HMAC_SHA1;
#ifdef SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
          else if (ssh_xml_match(value, value_len, ssh_custr("sha2"), 0))
            transform |= SSH_PM_MAC_HMAC_SHA2;
#endif /* SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSHDIST_CRYPT_XCBCMAC
          else if (ssh_xml_match(value, value_len, ssh_custr("xcbc-aes"), 0))
            transform |= SSH_PM_MAC_XCBC_AES;
#endif /* SSHDIST_CRYPT_XCBCMAC */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else if (ssh_xml_match(value, value_len, ssh_custr("esp"), 0))
            transform |= SSH_PM_IPSEC_ESP;
#ifdef SSHDIST_IPSEC_IPCOMP
          else if (ssh_xml_match(value, value_len, ssh_custr("deflate"), 0))
            transform |= SSH_PM_COMPRESS_DEFLATE;
          else if (ssh_xml_match(value, value_len, ssh_custr("lzs"), 0))
            transform |= SSH_PM_COMPRESS_LZS;
          else if (ssh_xml_match(value, value_len, ssh_custr("ipcomp"), 0))
            transform |= SSH_PM_IPSEC_IPCOMP;
#endif /* SSHDIST_IPSEC_IPCOMP */
          else if (ssh_xml_match(value, value_len, ssh_custr("ah"), 0))
            transform |= SSH_PM_IPSEC_AH;
          else
            {
              ssh_ipm_error(ctx, "Unknown transform option `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* Reject AH + ESP transforms */
      if ((transform & SSH_PM_IPSEC_ESP) &&
          (transform & SSH_PM_IPSEC_AH))
        {
          ssh_ipm_error(ctx, "Unsupported transform 'ah esp'");
          goto error;
        }

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          /* Handle tunnel flags. */
          if (ssh_xml_match(value, value_len, ssh_custr("perhost"), 0))
            flags |= SSH_PM_T_PER_HOST_SA;
          else if (ssh_xml_match(value, value_len, ssh_custr("perport"), 0))
            flags |= SSH_PM_T_PER_PORT_SA;
          else if (ssh_xml_match(value, value_len, ssh_custr("dont-initiate"),
                                 0))
            flags |= SSH_PM_TI_DONT_INITIATE;
#ifdef SSHDIST_IKE_XAUTH
          else if (ssh_xml_match(value, value_len, ssh_custr("xauth-methods"),
                                 0))
            flags |= SSH_PM_T_XAUTH_METHODS;
#endif /* SSHDIST_IKE_XAUTH */
          else if (ssh_xml_match(value, value_len, ssh_custr("auto"), 0))
            flags &= ~SSH_PM_TI_DELAYED_OPEN;
#ifdef SSHDIST_IKEV1
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("aggressive-mode"), 0))
            flags |= SSH_PM_TI_AGGRESSIVE_MODE;
#endif /* SSHDIST_IKEV1 */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("interface-trigger"), 0))
            flags |= SSH_PM_TI_INTERFACE_TRIGGER;
#ifdef SSHDIST_ISAKMP_CFG_MODE
          else if (ssh_xml_match(value, value_len, ssh_custr("cfgmode"), 0))
            flags |= SSH_PM_TI_CFGMODE;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#ifdef SSHDIST_L2TP
          else if (ssh_xml_match(value, value_len, ssh_custr("l2tp"), 0))
            flags |= SSH_PM_TI_L2TP;
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#ifdef SSHDIST_IKE_EAP_AUTH
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("eap-request-id"), 0))
            flags |= SSH_PM_TR_EAP_REQUEST_ID;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("eap-only-authentication"), 0))
            flags |= SSH_PM_T_EAP_ONLY_AUTH;
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
          else if (ssh_xml_match(value, value_len, ssh_custr("allow-cfgmode"),
                                 0))
            flags |= SSH_PM_TR_ALLOW_CFGMODE;
          else if (ssh_xml_match(value, value_len, ssh_custr("allow-l2tp"), 0))
            flags |= SSH_PM_TR_ALLOW_L2TP;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("require-cfgmode"), 0))
            flags |= SSH_PM_TR_REQUIRE_CFGMODE;
          else if (ssh_xml_match(value, value_len, ssh_custr("proxy-arp"), 0))
            flags |= SSH_PM_TR_PROXY_ARP;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_IPSEC_MOBIKE
          else if (ssh_xml_match(value, value_len, ssh_custr("mobike"), 0))
            flags |= SSH_PM_T_MOBIKE;
#endif /* SSHDIST_IPSEC_MOBIKE */
          /* Note that some of these flags set also values for the
             `transport' variable. */
          else if (ssh_xml_match(value, value_len, ssh_custr("tunnel"), 0))
            transform |= SSH_PM_IPSEC_TUNNEL;
          else if (ssh_xml_match(value, value_len, ssh_custr("transport"), 0))
            flags |= SSH_PM_T_TRANSPORT_MODE;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("omit-trigger-packet"), 0))
            flags |= SSH_PM_TI_NO_TRIGGER_PACKET;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("start-with-natt"), 0))
            flags |= SSH_PM_TI_START_WITH_NATT;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("dont-initiate-natt"),
                                 0))
            flags |= SSH_PM_TI_DONT_INITIATE_NATT;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("disable-natt"),
                                 0))
            flags |= SSH_PM_T_DISABLE_NATT;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("no-nats-allowed"), 0))
            flags |= SSH_PM_T_NO_NATS_ALLOWED;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          else if (ssh_xml_match(value, value_len, ssh_custr("internal-nat"),
                                 0))
            transform |= SSH_PM_IPSEC_INT_NAT;
          else if (ssh_xml_match(value, value_len, ssh_custr("port-nat"), 0))
            flags |= SSH_PM_T_PORT_NAT;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("disable-anti-replay"), 0))
            flags |= SSH_PM_T_DISABLE_ANTI_REPLAY;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("enable-outbound-sa-selectors"), 0))
            flags |= SSH_PM_TR_ENABLE_OUT_SA_SEL;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("long-seq"), 0))
            transform |= SSH_PM_IPSEC_LONGSEQ;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("short-seq"), 0))
            transform |= SSH_PM_IPSEC_SHORTSEQ;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("no-cert-chains"), 0))
            flags |= SSH_PM_T_NO_CERT_CHAINS;
          else
            {
              ssh_ipm_error(ctx, "Unknown tunnel flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      if (!got_transform)
        {
          /* No transform given, insert suitable default transform. */
          transform |= SSH_PM_IPSEC_ESP
#ifdef SSHDIST_CRYPT_RIJNDAEL
            | SSH_PM_CRYPT_AES
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
            | SSH_PM_CRYPT_3DES
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_SHA
            | SSH_PM_MAC_HMAC_SHA1
#endif /* SSHDIST_CRYPT_SHA */
#ifndef HAVE_FIPSLIB
#ifdef SSHDIST_CRYPT_MD5
            | SSH_PM_MAC_HMAC_MD5
#endif /* SSHDIST_CRYPT_MD5 */
#endif /* !HAVE_FIPSLIB */
            ;
        }

      /* IKE SA lifetime. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("ike-life"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipm_parse_number(ctx, value, &ike_life))
            goto error;

          if (ike_life < 60)
            {
              ssh_warning("IKE life too short (%u), must be equal or above %u",
                          ike_life, 60);
              goto error;
            }
        }

      /* We are parsing a tunnel object. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_TUNNEL);

      /* Create a tunnel object. */
      ctx->state->u.tunnel.tunnel = ssh_pm_tunnel_create(pm, transform,
                                                         flags, tunnel_name);
      if (ctx->state->u.tunnel.tunnel == NULL)
        {
          ssh_ipm_error(ctx, "Could not create tunnel object");
          goto error;
        }

      /* Store tunnel object's transform flags. */
      ctx->state->u.tunnel.transform = transform;

      /* Configure IKE SA lifetime. */
      if (ike_life)
        ssh_pm_tunnel_set_ike_life(ctx->state->u.tunnel.tunnel, ike_life);

#ifdef SSHDIST_IPSEC_SA_EXPORT
      /* Optional application identifier. */
      app_id = ssh_xml_get_attr_value(attributes, ssh_custr("app-id"), 0,
                                      &app_id_len);

      /* If app-id is not specified set tunnel_name as the tunnel's
         application identifier. */
      if (app_id == NULL)
        {
          app_id = tunnel_name;
          app_id_len = tunnel_name_len;
        }
      if (!ssh_pm_tunnel_set_application_identifier(ctx->state->
                                                    u.tunnel.tunnel,
                                                    ssh_custr(app_id),
                                                    app_id_len))
        {
          ssh_ipm_error(ctx, "Could not set tunnel application identifier");
          goto error;
        }
#endif /* SSHDIST_IPSEC_SA_EXPORT */

      {
        const unsigned char *val;

        val = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("routing-instance"),
                                     0, NULL);

        if (val != NULL)
          {
            if (ssh_pm_tunnel_set_routing_instance(
                      ctx->state->u.tunnel.tunnel, val) == FALSE)
              {
                ssh_ipm_error(ctx, "Could not set tunnel VRI");
                goto error;
              }
          }
      }

      /* Lookup tunnel's policy object. */
      ctx->state->object = ssh_ipm_xmlconf_policy_object_get(ctx, tunnel_name,
                                                             tunnel_name_len);
      if (ctx->state->object == NULL)
        {
          ssh_ipm_error(ctx, "Could not allocate tunnel object");
          goto error;
        }
    }

  /*********************************** inbound-extension ********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("inbound-extension"), 0))
    {
      SshUInt32 dst, index;
      const unsigned char *val;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      val = ssh_xml_get_attr_value(attributes, ssh_custr("index"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, val, &index))
        goto error;

      val= ssh_xml_get_attr_value(attributes, ssh_custr("dst"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, val, &dst))
        goto error;

      if (!ssh_pm_tunnel_set_extension(ctx->state->u.tunnel.tunnel,
                                       index, dst))
        {
          ssh_ipm_error(ctx, "Invalid extension selector");
          goto error;
        }
    }

  /*********************************** Peer *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("peer"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PEER);
    }
  /********************************* Local IP *******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-ip"), 0))
    {
#ifdef SSH_IPSEC_TCPENCAP
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL
                 || ctx->state->type == SSH_IPM_XMLCONF_TCP_ENCAPS);
#else /* SSH_IPSEC_TCPENCAP */
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);
#endif /* SSH_IPSEC_TCPENCAP */

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_LOCAL_IP);

      if ((value =
           ssh_xml_get_attr_value(attributes,
                                  ssh_custr("precedence"), 0, &value_len))
          != NULL)
        {
          SshUInt32 precedence;

          if (!ssh_ipm_parse_number(ctx, value, &precedence))
            {
              goto error;
            }
          ctx->state->u.local_address.precedence = precedence;
        }
    }
  /********************************* Local Interface *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-interface"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_LOCAL_IFACE);

      if ((value =
           ssh_xml_get_attr_value(attributes,
                                  ssh_custr("precedence"), 0, &value_len))
          != NULL)
        {
          SshUInt32 precedence;

          if (!ssh_ipm_parse_number(ctx, value, &precedence))
            {
              goto error;
            }
          ctx->state->u.local_address.precedence = precedence;
        }
    }
  /*********************************** Peer *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-port"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_LOCAL_PORT);
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /************************** CFG mode address **************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("cfgmode-address"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_CFGMODE_ADDRESS);
    }
  else if (ssh_xml_match(name, name_len, ssh_custr("virtual-ifname"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_VIRTUAL_IFNAME);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
/********************** Diffie-Hellman groups for IKE ***********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-groups"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("system-preferences"), 0))
            ctx->state->u.tunnel.default_ike_preferences = TRUE;
          else
            {
              ssh_ipm_error(ctx, "Unknown IKE groups flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IKE_GROUPS);
    }
/********************** Supported IKE versions ***********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-versions"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);
      ctx->state->u.tunnel.ike_versions = 0;

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IKE_VERSIONS);
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  else if (ssh_xml_match(name, name_len, ssh_custr("tunnel-address-pool"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      value = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                     &value_len);
     if (value)
        {
          if (!ssh_pm_tunnel_add_address_pool(ctx->state->u.tunnel.tunnel,
                                              value))
            {
              ssh_ipm_error(ctx,
                            "Could not configure address pool to tunnel `%s'.",
                            value);
              goto error;
            }
        }
      else
        {
          ssh_ipm_error(ctx, "Missing address pool name");
          goto error;
        }
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_TUNNEL_ADDRESS_POOL);
    }
#endif  /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  /*********************************** PFS **********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("pfs-groups"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("system-preferences"), 0))
            ctx->state->u.tunnel.default_pfs_preferences = TRUE;
          else
            {
              ssh_ipm_error(ctx, "Unknown PFS flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_PFS_GROUPS);
    }
  /****************************** IKE identities ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("identity"), 0))
    {
      SshUInt32 flags = 0;

     /* We are parsing an identity . */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IDENTITY);

      /* Flags */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("enforce-identity"), 0))
            flags |= SSH_PM_TUNNEL_IDENTITY_ENFORCE;
          else
            {
              ssh_ipm_error(ctx, "Unknown IKE identity flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }
      ctx->state->u.tunnel.identity_flags = flags;

      /* ID type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id-type"), 0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("dn"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_DN;
          else if (ssh_xml_match(value, value_len, ssh_custr("ip"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_IP;
          else if (ssh_xml_match(value, value_len, ssh_custr("fqdn"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_FQDN;
          else if (ssh_xml_match(value, value_len, ssh_custr("email"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_RFC822;
          else if (ssh_xml_match(value, value_len, ssh_custr("key-id"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_KEY_ID;
#ifdef SSHDIST_IKE_ID_LIST
          else if (ssh_xml_match(value, value_len, ssh_custr("idlist"), 0))
            ctx->state->u.tunnel.id_type = SSH_PM_IDENTITY_ID_LIST;
#endif /* SSHDIST_IKE_ID_LIST */

          else
            {
              ssh_ipm_error(ctx, "Unsupported id-type %s", value);
              goto error;
            }
        }

      /* Identity. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipm_store_identity(ctx, FALSE, value, value_len))
            goto error;
        }

      /* Encoding. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id-encoding"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("binary"), 0))
        ctx->state->u.tunnel.id_encoding = SSH_PM_BINARY;
      else if (ssh_xml_match(value, value_len, ssh_custr("hex"), 0))
        ctx->state->u.tunnel.id_encoding = SSH_PM_HEX;
      else
        SSH_XML_VERIFIER(0);

      /* Type. */
      ctx->state->u.tunnel.remote_identity = 0;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);

      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("remote"), 0))
            ctx->state->u.tunnel.remote_identity = 1;
          else if (!ssh_xml_match(value, value_len,
                                  ssh_custr("local"), 0))
            {
              ssh_ipm_error(ctx, "Unknown identity type");
              goto error;
            }
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      value = ssh_xml_get_attr_value(attributes, ssh_custr("order"), 0,
                                     &value_len);

      if (value)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("1"), 0))
            ctx->state->u.tunnel.order = 1;

          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("2"), 0))
            ctx->state->u.tunnel.order = 2;

          else
            {
              ssh_ipm_error(ctx, "Unsupported order");
              goto error;
            }
        }
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        ctx->state->u.tunnel.order = 1;
    }
  /************************** Tunnel authentication **************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("authentication"), 0))
    {

     /* We are parsing an identity . */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_TUNNEL_AUTH);

      /* Check for authentication domain configuration */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("auth-domain-name"),
                                     0, &value_len);

      if (value)
        {
          ctx->state->u.tunnel.auth_domain_name = (char *) value;
          ctx->state->u.tunnel.auth_domain_name_len = value_len;
        }
      else
        {
          ssh_ipm_error(ctx, "You must specify the authentication domain "
                        "name in the authentication-element");
          goto error;
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      value = ssh_xml_get_attr_value(attributes, ssh_custr("order"), 0,
                                     &value_len);

      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
            ctx->state->u.tunnel.order = 1;
          else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
            ctx->state->u.tunnel.order = 2;
          else
            {
              ssh_ipm_error(ctx,
                            "Invalid order set for tunnel authentication");
              goto error;
            }
        }
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        ctx->state->u.tunnel.order = 1;
    }

  /*************************** Access control group *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("access-group"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_GROUP_REF);
      /* Nothing here. */
    }
  /******************************* SA lifetime ******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("life"), 0))
    {
      /* Parsing a life. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_LIFE);

      /* Type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("kbytes"), 0))
        ctx->state->u.life.type = SSH_PM_LIFE_KB;
      else
        ctx->state->u.life.type = SSH_PM_LIFE_SECONDS;
    }
  /************************************ CA **********************************/
#ifdef SSHDIST_IKE_CERT_AUTH
  else if (ssh_xml_match(name, name_len, ssh_custr("ca"), 0))
    {
      /* Parsing a trusted CA. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_CA);

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("no-crl"), 0))
            ctx->state->u.ca.flags |= SSH_PM_CA_NO_CRL;
#ifdef WITH_MSCAPI
          /* Encode identity type in the flags value. */
          else if (ssh_xml_match(value, value_len, ssh_custr("dn"), 0))
            ctx->state->u.ca.flags |= SSH_PM_IDENTITY_DN << 16;
          else if (ssh_xml_match(value, value_len, ssh_custr("ip"), 0))
            ctx->state->u.ca.flags |= SSH_PM_IDENTITY_IP << 16;
          else if (ssh_xml_match(value, value_len, ssh_custr("fqdn"), 0))
            ctx->state->u.ca.flags |= SSH_PM_IDENTITY_FQDN << 16;
          else if (ssh_xml_match(value, value_len, ssh_custr("email"), 0))
            ctx->state->u.ca.flags |= SSH_PM_IDENTITY_RFC822 << 16;
          else if (ssh_xml_match(value, value_len, ssh_custr("key-id"), 0))
            ctx->state->u.ca.flags |= SSH_PM_IDENTITY_KEY_ID << 16;
#endif /* WITH_MSCAPI */
          else
            {
              ssh_ipm_error(ctx, "Unknown CA flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* File name for the CA certificate? */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("file"), 0,
                                     &value_len);
      if (value)
        {
          ctx->state->u.ca.file = ssh_memdup(value, value_len);
          if (ctx->state->u.ca.file == NULL)
            {
              ssh_ipm_error(ctx, "Could not store CA certificate file name");
              goto error;
            }
        }
    }
#endif /* SSHDIST_IKE_CERT_AUTH */
  /*************************** Algorithm properties *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("algorithm-properties"), 0))
    {
      SshUInt32 algorithm = 0;
      SshUInt32 min_key_size = 0;
      SshUInt32 max_key_size = 0;
      SshUInt32 default_key_size = 0;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Algorithm. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("algorithm"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("cipher1"), 0))
            algorithm |= SSH_PM_CRYPT_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("cipher2"), 0))
            algorithm |= SSH_PM_CRYPT_EXT2;
#ifdef SSHDIST_CRYPT_RIJNDAEL
          else if (ssh_xml_match(value, value_len, ssh_custr("aes"), 0))
            algorithm |= SSH_PM_CRYPT_AES;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ctr"), 0))
            algorithm |= SSH_PM_CRYPT_AES_CTR;
#ifdef SSHDIST_CRYPT_MODE_GCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm"), 0))
            algorithm |= SSH_PM_CRYPT_AES_GCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-64"), 0))
            algorithm |= SSH_PM_CRYPT_AES_GCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-96"), 0))
            algorithm |= SSH_PM_CRYPT_AES_GCM_12;
          else if (ssh_xml_match(value, value_len, ssh_custr("gmac-aes"), 0))
            algorithm |= SSH_PM_CRYPT_NULL_AUTH_AES_GMAC;
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm"), 0))
            algorithm |= SSH_PM_CRYPT_AES_CCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-64"), 0))
            algorithm |= SSH_PM_CRYPT_AES_CCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-96"), 0))
            algorithm |= SSH_PM_CRYPT_AES_CCM_12;
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
          else if (ssh_xml_match(value, value_len, ssh_custr("sha2"), 0))
            algorithm |= SSH_PM_MAC_HMAC_SHA2;
#endif /* SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE */
          else if (ssh_xml_match(value, value_len, ssh_custr("mac1"), 0))
            algorithm |= SSH_PM_MAC_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("mac2"), 0))
            algorithm |= SSH_PM_MAC_EXT2;
          else
            {
              ssh_ipm_error(ctx, "Unknown algorithm `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* Key sizes. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("min-key-size"), 0,
                                     &value_len);
      if (!ssh_ipm_parse_number(ctx, value, &min_key_size))
        goto error;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("max-key-size"), 0,
                                     &value_len);
      if (!ssh_ipm_parse_number(ctx, value, &max_key_size))
        goto error;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("default-key-size"),
                                     0, &value_len);
      if (!ssh_ipm_parse_number(ctx, value, &default_key_size))
        goto error;

      /* Scope. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("scope"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("ike"), 0))
        algorithm |= SSH_PM_ALG_IKE_SA;
      else if (ssh_xml_match(value, value_len, ssh_custr("ipsec"), 0))
        algorithm |= SSH_PM_ALG_IPSEC_SA;
      else
        algorithm |= SSH_PM_ALG_IKE_SA | SSH_PM_ALG_IPSEC_SA;

      if (!ssh_pm_tunnel_set_algorithm_properties(ctx->state->u.tunnel.tunnel,
                                                  algorithm,
                                                  min_key_size,
                                                  max_key_size,
                                                  default_key_size))
        {
          ssh_ipm_error(ctx, "Could not set algorithm properties");
          goto error;
        }
#ifdef TGX_ALGORITHMS
      if ((algorithm & SSH_PM_CRYPT_AES) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_CTR) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_GCM) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_GCM_8) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_GCM_12) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_CCM) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_CCM_8) != 0 ||
          (algorithm & SSH_PM_CRYPT_AES_CCM_12) != 0 ||
          (algorithm & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC) != 0)
        {
          if (min_key_size < 128 || max_key_size > 256)
            {
              ssh_ipm_error(ctx, "Specified key size not valid for tilegx");
              goto error;
            }
        }

      if ((algorithm & SSH_PM_MAC_HMAC_SHA2) != 0)
        {
          if (min_key_size < 256 || max_key_size > 512)
            {
              ssh_ipm_error(ctx, "Specified key size not valid for tilegx");
              goto error;
            }
        }
#endif /* TGX_ALGORITHMS */
    }


  /*************************** EAP configuration *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("eap"), 0))
    {
#ifdef SSHDIST_IKE_EAP_AUTH
      SshUInt32 eap_type = SSH_EAP_TYPE_NONE;
      SshUInt32 eap_preference = 0;
      SshUInt32 transform = 0;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN);

      /* Type. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (value)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("md5-challenge"), 0))
            eap_type = SSH_EAP_TYPE_MD5_CHALLENGE;
          else if (ssh_xml_match(value, value_len, ssh_custr("sim"), 0))
            eap_type = SSH_EAP_TYPE_SIM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aka"), 0))
            eap_type = SSH_EAP_TYPE_AKA;




          else if (ssh_xml_match(value, value_len, ssh_custr("tls"), 0))
            eap_type = SSH_EAP_TYPE_TLS;




          else if (ssh_xml_match(value, value_len, ssh_custr("mschapv2"), 0))
            eap_type = SSH_EAP_TYPE_MSCHAP_V2;
        }

      /* Set the default transform for the EAP-AKA/EAP-AKA' as per the case */
      if (eap_type == SSH_EAP_TYPE_AKA)
        transform |= (SSH_PM_MAC_HMAC_SHA1
#ifdef SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
                      | SSH_PM_MAC_HMAC_SHA2
#endif /* SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE */
                     );







      /* EAP preference. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("preference"), 0,
                                     NULL);
      if (value)
        {
          if (!ssh_ipm_parse_number(ctx, value, &eap_preference) ||
              eap_preference > 255)
            {
              ssh_ipm_error(ctx, "Invalid EAP preference supplied. The "
                            "preference must be between 0 and 255");
              goto error;
            }

          if (eap_preference > ctx->state->u.auth_domain.eap_preference_next)
            ssh_ipm_warning(ctx,
                            "The EAP method preference values do not follow "
                            "lexical order or the configuration file.  "
                            "The resulting policy may differ from what you "
                            "thought.");
        }
      else
        {
          eap_preference = ctx->state->u.auth_domain.eap_preference_next;
        }

      if (eap_preference > 0)
        ctx->state->u.auth_domain.eap_preference_next = eap_preference - 1;

      if (!ssh_pm_auth_domain_accept_eap_auth(
                                   ctx->state->u.auth_domain.auth_domain,
                                   eap_type, eap_preference, transform))
        {
          ssh_ipm_error(ctx, "Could not configure EAP method");
          goto error;
        }

#else /* SSHDIST_IKE_EAP_AUTH */
      ssh_ipm_error(ctx, "EAP is not supported.");
      goto error;
#endif /* SSHDIST_IKE_EAP_AUTH */
    }
  /************************** Algorithms for IKE SAs ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-algorithms"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IKE_ALGORITHMS);
    }
  /************************** IKE SA window size ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-window-size"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IKE_WINDOW_SIZE);
    }

  /************************** Manually configured SA ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("manual-key"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_MANUAL_KEY);
    }
  /************************ Manually configured ESP SA **********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("esp"), 0))
    {
      SshUInt32 key_len;
      const unsigned char *key_i;
      size_t key_i_len;
      const unsigned char *key_o;
      size_t key_o_len;

      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_MANUAL_KEY);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if ((parent->u.tunnel.transform & SSH_PM_IPSEC_ESP) == 0)
        {
          ssh_ipm_error(ctx, "No ESP transform configured for the tunnel");
          goto error;
        }

      if (ctx->state->u.manual_key.encr_key_i)
        {
          ssh_ipm_error(ctx, "ESP transform already configured");
          goto error;
        }

      /* Encryption keys. */

      key_i = ssh_xml_get_attr_value(attributes, ssh_custr("encr-key-in"), 0,
                                     &key_i_len);
      key_o = ssh_xml_get_attr_value(attributes, ssh_custr("encr-key-out"), 0,
                                     &key_o_len);

      if (!ssh_ipm_store_manual_key(ctx, key_i, key_i_len,
                                    &ctx->state->u.manual_key.encr_key_i,
                                    &ctx->state->u.manual_key.encr_key_i_len))
        goto error;
      if (!ssh_ipm_store_manual_key(ctx, key_o, key_o_len,
                                    &ctx->state->u.manual_key.encr_key_o,
                                    &ctx->state->u.manual_key.encr_key_o_len))
        goto error;

      /* Check if encryption is configured for the tunnel. */
      if (!ssh_pm_tunnel_get_algorithm_properties(parent->u.tunnel.tunnel,
                                                  ((parent->u.tunnel.transform
                                                    & SSH_PM_CRYPT_MASK)
                                                   | SSH_PM_ALG_IPSEC_SA),
                                                  NULL, NULL, &key_len))
        {
          ssh_ipm_error(ctx,
                        "Could not resolve encryption key size: "
                        "tunnel might specify multiple encryption algorithms");
          goto error;
        }
      key_len /= 8;

      /* Try to set key size for encryption if default key size mismatchs. */
      if (ctx->state->u.manual_key.encr_key_i_len != key_len)
        {
          if (ssh_pm_tunnel_set_algorithm_properties(
                                parent->u.tunnel.tunnel,
                                ((parent->u.tunnel.transform
                                  & SSH_PM_CRYPT_MASK)
                                 | SSH_PM_ALG_IPSEC_SA),
                     (SshUInt32)(ctx->state->u.manual_key.encr_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.encr_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.encr_key_i_len * 8)))
            {
              key_len = (SshUInt32)ctx->state->u.manual_key.encr_key_i_len;
            }
        }

      /* Check that the keys were specified or omitted. */
      if (ctx->state->u.manual_key.encr_key_i_len != key_len)
        {
          ssh_ipm_error(ctx, "Invalid encryption key length %u for "
                        "inbound ESP transform (expected %u bytes)",
                        ctx->state->u.manual_key.encr_key_i_len, key_len);
          goto error;
        }
      if (ctx->state->u.manual_key.encr_key_o_len != key_len)
        {
          ssh_ipm_error(ctx, "Invalid encryption key length %u for "
                        "outbound ESP transform (expected %u bytes)",
                        ctx->state->u.manual_key.encr_key_o_len, key_len);
          goto error;
        }


      /* Check if authentication is configured for the tunnel. */
      if (((parent->u.tunnel.transform & SSH_PM_IPSEC_AH) == 0)
          && (parent->u.tunnel.transform & SSH_PM_MAC_MASK))
        {
          /* Yes it is and it is implemented with ESP. */

          if (!ssh_pm_tunnel_get_algorithm_properties(
                                                parent->u.tunnel.tunnel,
                                                ((parent->u.tunnel.transform
                                                  & SSH_PM_MAC_MASK)
                                                 | SSH_PM_ALG_IPSEC_SA),
                                                NULL, NULL, &key_len))
            {
              ssh_ipm_error(ctx,
                            "Could not resolve authentication key size: "
                            "tunnel might specify multiple authentication "
                            "algorithms");
              goto error;
            }
          key_len /= 8;

          /* Authentication keys. */

          key_i = ssh_xml_get_attr_value(attributes, ssh_ustr("auth-key-in"),
                                         0, &key_i_len);
          key_o = ssh_xml_get_attr_value(attributes, ssh_ustr("auth-key-out"),
                                         0, &key_o_len);

          if (!ssh_ipm_store_manual_key(
                                ctx, key_i, key_i_len,
                                &ctx->state->u.manual_key.auth_key_i,
                                &ctx->state->u.manual_key.auth_key_i_len))
            goto error;
          if (!ssh_ipm_store_manual_key(
                                ctx, key_o, key_o_len,
                                &ctx->state->u.manual_key.auth_key_o,
                                &ctx->state->u.manual_key.auth_key_o_len))
            goto error;

          /* Try to set key size for mac if default key size mismatchs. */
          if (ctx->state->u.manual_key.auth_key_i_len != key_len)
            {
              if (ssh_pm_tunnel_set_algorithm_properties(
                                parent->u.tunnel.tunnel,
                                ((parent->u.tunnel.transform
                                  & SSH_PM_MAC_MASK)
                                 | SSH_PM_ALG_IPSEC_SA),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8)))
                {
                  key_len = (SshUInt32)ctx->state->u.manual_key.auth_key_i_len;
                }
            }

          /* Check that the keys were of correct size. */
          if (ctx->state->u.manual_key.auth_key_i_len != key_len)
            {
              ssh_ipm_error(ctx, "Invalid authentication key length %u for "
                            "inbound ESP transform (expected %u bytes)",
                            ctx->state->u.manual_key.auth_key_i_len, key_len);
              goto error;
            }
          if (ctx->state->u.manual_key.auth_key_o_len != key_len)
            {
              ssh_ipm_error(ctx, "Invalid authentication key length %u for "
                            "outbound ESP transform (expected %u bytes)",
                            ctx->state->u.manual_key.auth_key_o_len, key_len);
              goto error;
            }
        }

      /* SPIs. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("spi-in"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No inbound SPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value,
                                &ctx->state->u.manual_key.esp_spi_i))
        goto error;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("spi-out"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No outbound SPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value,
                                &ctx->state->u.manual_key.esp_spi_o))
        goto error;
    }
  /************************ Manually configured AH SA ***********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ah"), 0))
    {
      SshUInt32 key_len;
      const unsigned char *key_i;
      size_t key_i_len;
      const unsigned char *key_o;
      size_t key_o_len;

      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_MANUAL_KEY);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if ((parent->u.tunnel.transform & SSH_PM_IPSEC_AH) == 0)
        {
          ssh_ipm_error(ctx, "No AH transform configured for the tunnel");
          goto error;
        }

      if (ctx->state->u.manual_key.auth_key_i)
        {
          ssh_ipm_error(ctx, "AH transform already configured");
          goto error;
        }

      /* Authentication keys. */
      key_i = ssh_xml_get_attr_value(attributes, ssh_custr("auth-key-in"), 0,
                                     &key_i_len);
      key_o = ssh_xml_get_attr_value(attributes, ssh_custr("auth-key-out"), 0,
                                     &key_o_len);

      if (!ssh_ipm_store_manual_key(ctx, key_i, key_i_len,
                                    &ctx->state->u.manual_key.auth_key_i,
                                    &ctx->state->u.manual_key.auth_key_i_len))
        goto error;
      if (!ssh_ipm_store_manual_key(ctx, key_o, key_o_len,
                                    &ctx->state->u.manual_key.auth_key_o,
                                    &ctx->state->u.manual_key.auth_key_o_len))
        goto error;

      /* Check if authentication is configured for the tunnel. */
      if (!ssh_pm_tunnel_get_algorithm_properties(parent->u.tunnel.tunnel,
                                                  ((parent->u.tunnel.transform
                                                    & SSH_PM_MAC_MASK)
                                                   | SSH_PM_ALG_IPSEC_SA),
                                                  NULL, NULL, &key_len))
        {
          ssh_ipm_error(ctx,
                        "Could not resolve authentication key size: "
                        "tunnel might specify multiple authentication "
                        "algorithms");
          goto error;
        }
      key_len /= 8;

      /* Try to set key size for mac if default key size mismatchs. */
      if (ctx->state->u.manual_key.auth_key_i_len != key_len)
        {
          if (ssh_pm_tunnel_set_algorithm_properties(
                                parent->u.tunnel.tunnel,
                                ((parent->u.tunnel.transform
                                  & SSH_PM_MAC_MASK)
                                 | SSH_PM_ALG_IPSEC_SA),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8),
                     (SshUInt32)(ctx->state->u.manual_key.auth_key_i_len * 8)))
            {
              key_len = (SshUInt32)ctx->state->u.manual_key.auth_key_i_len;
            }
        }

      /* Check that the keys were specified or omitted. */
      if (ctx->state->u.manual_key.auth_key_i_len != key_len)
        {
          ssh_ipm_error(ctx, "Invalid authentication key length %u for "
                        "inbound AH transform (expected %u bytes)",
                        ctx->state->u.manual_key.auth_key_i_len, key_len);
          goto error;
        }
      if (ctx->state->u.manual_key.auth_key_o_len != key_len)
        {
          ssh_ipm_error(ctx, "Invalid authentication key length %u for "
                        "outbound AH transform (expected %u bytes)",
                        ctx->state->u.manual_key.auth_key_o_len, key_len);
          goto error;
        }

      /* SPIs. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("spi-in"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No inbound SPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value,
                                &ctx->state->u.manual_key.ah_spi_i))
        goto error;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("spi-out"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No outbound SPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value,
                                &ctx->state->u.manual_key.ah_spi_o))
        goto error;
    }
  /*********************** Manually configure IPCOMP SA *********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ipcomp"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_MANUAL_KEY);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if ((parent->u.tunnel.transform & SSH_PM_IPSEC_IPCOMP) == 0)
        {
          ssh_ipm_error(ctx, "No IPCOMP transform configured for the tunnel");
          goto error;
        }

      if (ctx->state->u.manual_key.ipcomp_cpi_i)
        {
          ssh_ipm_error(ctx, "IPCOMP transform already configured");
          goto error;
        }

      /* CPIs. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("cpi-in"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No inbound CPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value, &ival))
        goto error;
      ctx->state->u.manual_key.ipcomp_cpi_i = (SshUInt16) ival;
      value = ssh_xml_get_attr_value(attributes, ssh_custr("cpi-out"), 0,
                                     &value_len);
      if (value == NULL)
        {
          ssh_ipm_error(ctx, "No outbound CPI specified");
          goto error;
        }
      if (!ssh_ipm_parse_number(ctx, value, &ival))
        goto error;
      ctx->state->u.manual_key.ipcomp_cpi_o = (SshUInt16) ival;
    }

  /*********************************** IPSec over TCP ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("tcpencap"), 0))
    {
#ifdef SSH_IPSEC_TCPENCAP
      SshUInt32 int_value = 0;

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_TCP_ENCAPS);

      /* Initialise configuration with default values. */
      SSH_IP_UNDEFINE(&ctx->state->u.tcp_encaps_config.local_addr);
      SSH_IP_UNDEFINE(&ctx->state->u.tcp_encaps_config.peer_lo_addr);
      SSH_IP_UNDEFINE(&ctx->state->u.tcp_encaps_config.peer_hi_addr);
      ctx->state->u.tcp_encaps_config.local_port = 0;
      ctx->state->u.tcp_encaps_config.peer_port = 0;
      ctx->state->u.tcp_encaps_config.local_ike_port = 0;

      /* Local port */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("local-port"), 0,
                                     &value_len);
      if (value && (!ssh_ipm_parse_number(ctx, value, &int_value)
                    || int_value > 65535))
        {
          ssh_ipm_error(ctx, "Invalid IPsec over TCP local port '%s'", value);
          goto error;
        }
      ctx->state->u.tcp_encaps_config.local_port = int_value;

      /* Peer port */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("peer-port"), 0,
                                     &value_len);
      if (value && (!ssh_ipm_parse_number(ctx, value, &int_value)
                    || int_value > 65535))
        {
          ssh_ipm_error(ctx, "Invalid IPsec over TCP peer port '%s'", value);
          goto error;
        }
      ctx->state->u.tcp_encaps_config.peer_port = int_value;

      /* Local IKE port */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("ike-port"), 0,
                                     &value_len);
      if (value && (!ssh_ipm_parse_number(ctx, value, &int_value)
                    || int_value > 65535))
        {
          ssh_ipm_error(ctx, "Invalid IPsec over TCP IKE port '%s'",
                        value);
          goto error;
        }
      ctx->state->u.tcp_encaps_config.local_ike_port = int_value;

#else /* SSH_IPSEC_TCPENCAP */
      ssh_ipm_error(ctx,
                    "IPsec over TCP is not supported by this build.");
      goto error;
#endif /* SSH_IPSEC_TCPENCAP */
    }
  /*********************************** Rule *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("outer-tunnel"), 0))
    {
      SshUInt32 flags = 0;
      SshPmTunnel outer_tunnel;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Flags */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {






            {
              ssh_ipm_error(ctx, "Unknown outer-tunnel flag `%s'", value);
              goto error;
            }
        }

      /* Outer tunnel name. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                     &value_len);

      if (value)
        {
          outer_tunnel =
            ssh_ipm_xmlconf_policy_object_value(ctx, value, value_len,
                                                SSH_IPM_POLICY_OBJECT_TUNNEL);

          if (outer_tunnel == NULL)
            {
              ssh_ipm_error(ctx, "Invalid outer tunnel name `%s'", value);
              goto error;
            }

          if (!ssh_pm_tunnel_set_outer_tunnel(ctx->state->u.tunnel.tunnel,
                                              outer_tunnel, flags))
            {
              ssh_ipm_error(ctx, "Could not configure outer-tunnel `%s'.",
                            value);
              goto error;
            }
        }
      else
        {
          ssh_ipm_error(ctx, "Missing outer-tunnel name");
          goto error;
        }
    }

  /*********************************** Rule *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("rule"), 0))
    {
#ifdef SSHDIST_IPSEC_SA_EXPORT
      const unsigned char *app_id;
      size_t app_id_len;
#endif /* SSHDIST_IPSEC_SA_EXPORT */
      SshUInt32 precedence;
      SshUInt32 flags = 0;
      SshPmTunnel from_tunnel = NULL;
      SshPmTunnel to_tunnel = NULL;
      SshPmService service = NULL;

#ifdef SSHDIST_IPSEC_NAT
      SshUInt32 nat_src_port = 0, nat_dst_port = 0;
      SshIpAddrStruct nat_src, nat_dst, nat_src_low,
                      nat_src_high, nat_dst_low,
                      nat_dst_high;
      SshPmNatFlags nat_src_flags = 0, nat_dst_flags = 0,
        nat_flags = 0;

      SSH_IP_UNDEFINE(&nat_src);
      SSH_IP_UNDEFINE(&nat_dst);
      SSH_IP_UNDEFINE(&nat_src_low);
      SSH_IP_UNDEFINE(&nat_dst_low);
      SSH_IP_UNDEFINE(&nat_src_high);
      SSH_IP_UNDEFINE(&nat_dst_high);
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_SA_EXPORT
      /* Optional application identifier. */
      app_id = ssh_xml_get_attr_value(attributes, ssh_custr("app-id"), 0,
                                      &app_id_len);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

      /* Rule precedence. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("precedence"), 0,
                                     NULL);
      if (value)
        {
          if (!ssh_ipm_parse_number(ctx, value, &precedence))
            goto error;

          if (precedence > ctx->precedence_next)
            ssh_ipm_warning(ctx,
                            "The rule precedence values do not follow "
                            "lexical order or the configuration file.  "
                            "The resulting policy can differ from what you "
                            "thought by investigating the policy file.");
        }
      else
        {
          precedence = ctx->precedence_next;
        }
      if (precedence < ctx->precedence_min || precedence > ctx->precedence_max)
        {
          ssh_ipm_error(ctx, "Rule precedence value %d out of range [%u...%u]",
                        (SshInt32) precedence,
                        ctx->precedence_max, ctx->precedence_min);
          goto error;
        }
      ctx->precedence_next = precedence - 1;

      /* Type of the rule. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("pass"), 0))
        flags |= SSH_PM_RULE_PASS;
      else if (ssh_xml_match(value, value_len, ssh_custr("reject"), 0))
        flags |= SSH_PM_RULE_REJECT;
      /* The `drop' case does not have any value for flags. */

      /* Logging. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("log"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS,
                                   &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("connections"), 0))
            flags |= SSH_PM_RULE_LOG;
          else
            {
              ssh_ipm_error(ctx, "Unknown logging type `%s'", value);
              goto error;
            }
        }

      /* Flags. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS,
                                   &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("no-flow"), 0))
            flags |= SSH_PM_RULE_NO_FLOW;





#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
          else if (ssh_xml_match(value, value_len,ssh_custr("multi-homed"), 0))
            flags |=  SSH_PM_RULE_MULTIHOME;
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("rate-limit"), 0))
            flags |= SSH_PM_RULE_RATE_LIMIT;

          else if (ssh_xml_match(value, value_len, ssh_custr("set-df"), 0))
            flags |= SSH_PM_RULE_DF_SET;
          else if (ssh_xml_match(value, value_len, ssh_custr("clear-df"), 0))
            flags |= SSH_PM_RULE_DF_CLEAR;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("match-local-ike"), 0))
            flags |= SSH_PM_RULE_MATCH_LOCAL_IKE;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("adjust-local-address"), 0))
            flags |= SSH_PM_RULE_ADJUST_LOCAL_ADDRESS;
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("cfgmode-rules"), 0))
            flags |= SSH_PM_RULE_CFGMODE_RULES;
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

          else
            {
              ssh_ipm_error(ctx, "Unknown rule flag `%s'", value);
              goto error;
            }
        }


      /* Tunnels. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("from-tunnel"), 0,
                                     &value_len);
      if (value)
        {
          from_tunnel = ssh_ipm_xmlconf_policy_object_value(
                                                ctx, value, value_len,
                                                SSH_IPM_POLICY_OBJECT_TUNNEL);
          if (from_tunnel == NULL)
            {
              ssh_ipm_error(ctx, "Unknown tunnel object `%s'", value);
              goto error;
            }
        }
      value = ssh_xml_get_attr_value(attributes, ssh_custr("to-tunnel"), 0,
                                     &value_len);
      if (value)
        {
          to_tunnel = ssh_ipm_xmlconf_policy_object_value(
                                                ctx, value, value_len,
                                                SSH_IPM_POLICY_OBJECT_TUNNEL);
          if (to_tunnel == NULL)
            {
              ssh_ipm_error(ctx, "Unknown tunnel object `%s'", value);
              goto error;
            }
        }

      /* Sanity checks for the rule */

      /* Check df-bit processing */
      if ((flags & SSH_PM_RULE_DF_SET) && (flags & SSH_PM_RULE_DF_CLEAR))
        {
          ssh_ipm_error(ctx,
                        "Tunnel defines invalid df bit policy "
                        "'df-set df-clear'");
          goto error;
        }

#ifdef SSHDIST_IPSEC_NAT
     /* Global Nat Flags: Read src-port-preservation if it is
         available. */
      value = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("nat-src-port-preservation"), 0,
                                     &value_len);

      if (value && ssh_xml_match(value, value_len,
                                 ssh_custr("off"), 0))
        nat_flags |= SSH_PM_NAT_NO_TRY_KEEP_PORT;
      else if (value &&
               ssh_xml_match(value, value_len,
                             ssh_custr("overload"), 0))
        {
          nat_flags |= SSH_PM_NAT_KEEP_PORT;
          nat_flags |= SSH_PM_NAT_SHARE_PORT_SRC;
        }
      else if (value && ssh_xml_match(value, value_len,
                                      ssh_custr("loose"), 0))
        nat_flags |= SSH_PM_NAT_FLAGS_EMPTY;
      else
        nat_flags |= SSH_PM_NAT_KEEP_PORT; /* "strict"
                                              behavior */

      /* Destination NAT type. */
      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-dst-type"), 0,
                                     &value_len);
      if (value && !strcmp(value,"one-to-one"))
          nat_dst_flags = SSH_PM_NAT_ONE_TO_ONE_DST;
      else
          nat_dst_flags = 0;

      /* Destination NAT addresses. */
      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-dst"), 0,
                                     &value_len);
      if (value)        {
          if (!ssh_ipaddr_parse(&nat_dst, value))
            {
              ssh_ipm_error(ctx, "Malformed NAT destination address `%s'",
                            value);
              goto error;
            }
        }

      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-dst-low"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&nat_dst_low, value))
            {
              ssh_ipm_error(ctx, "Malformed NAT destination low address `%s'",
                            value);
              goto error;
            }
        }

      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-dst-high"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&nat_dst_high, value))
            {
              ssh_ipm_error(ctx, "Malformed NAT destination high address `%s'",
                            value);
              goto error;
            }
        }

      if (!process_nat_addresses(ctx, "destination", &nat_dst,
                                 &nat_dst_low, &nat_dst_high,
                                 nat_dst_flags, &nat_flags))
        {
          goto error;
        }

      if ((value = ssh_xml_get_attr_value(attributes,
                                          ssh_ustr("nat-dst-port"), 0,
                                          &value_len)) == NULL)
        value = ssh_xml_get_attr_value(attributes,
                                       ssh_ustr("nat-port"), 0,
                                       &value_len);

      if (value && (!ssh_ipm_parse_number(ctx, value, &nat_dst_port)
                    || nat_dst_port > 65535))
        {
          ssh_ipm_error(ctx, "Invalid nat destination port '%s'", value);
          goto error;
        }

      /* Source NAT type. */
      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-src-type"), 0,
                                     &value_len);
      if (value && !strcmp(value,"one-to-one"))
          nat_src_flags = SSH_PM_NAT_ONE_TO_ONE_SRC;
      else
          nat_src_flags = 0;

      /* Source NAT addresses */
      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-src"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&nat_src, value)
              || SSH_IP_IS_LOOPBACK(&nat_src))
            {
              ssh_ipm_error(ctx, "Malformed NAT source address `%s'",
                            value);
              goto error;
            }
        }

      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-src-low"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&nat_src_low, value))
            {
              ssh_ipm_error(ctx, "Malformed NAT source low address `%s'",
                            value);
              goto error;
            }
        }

      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-src-high"), 0,
                                     &value_len);
      if (value)
        {
          if (!ssh_ipaddr_parse(&nat_src_high, value))
            {
              ssh_ipm_error(ctx, "Malformed NAT source high address `%s'",
                            value);
              goto error;
            }
        }

      if (!process_nat_addresses(ctx, "source", &nat_src,
                                 &nat_src_low, &nat_src_high,
                                 nat_src_flags, &nat_flags))
        {
          goto error;
        }

      value = ssh_xml_get_attr_value(attributes, ssh_ustr("nat-src-port"), 0,
                                     &value_len);

      if (value && (!ssh_ipm_parse_number(ctx, value, &nat_src_port)
                    || nat_src_port > 65535))
        {
          ssh_ipm_error(ctx, "Invalid nat source port '%s'", value);
          goto error;
        }
#else /* SSHDIST_IPSEC_NAT */
      if (ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-src-port"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-dst-port"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-src"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-src-low"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-src-high"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-dst"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-dst-low"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-dst-high"), 0, &value_len) ||
          ssh_xml_get_attr_value(attributes,
                                 ssh_ustr("nat-src-port-preservation"),
                                 0, &value_len))
        {
          ssh_ipm_error(ctx, "NAT is not supported");
          goto error;
        }
#endif /* SSHDIST_IPSEC_NAT */

      /* We are parsing a rule object. */
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_RULE);

      ctx->state->u.rule.precedence = precedence;

      /* Create a rule object. */
      ctx->state->u.rule.rule = ssh_pm_rule_create(pm, precedence, flags,

                                                   from_tunnel, to_tunnel,

                                                   service);
      if (ctx->state->u.rule.rule == NULL)
        {
          ssh_ipm_error(ctx, "Could not create policy rule");
          goto error;
        }

#ifdef SSHDIST_IPSEC_NAT
      ssh_pm_rule_set_forced_nat(ctx->state->u.rule.rule,
                                 &nat_src_low, &nat_src_high,
                                 (SshUInt16) nat_src_port,
                                 &nat_dst_low, &nat_dst_high,
                                 (SshUInt16) nat_dst_port,
                                 nat_flags);
#endif /* SSHDIST_IPSEC_NAT */

      {
        const unsigned char *val;

        val = ssh_xml_get_attr_value(attributes,
                                     ssh_custr("routing-instance"),
                                     0, NULL);

        if (val != NULL)
          {
            if (ssh_pm_rule_set_routing_instance(ctx->state->u.rule.rule,
                                                 val) == FALSE)
              {
                ssh_ipm_error(ctx, "Could not set rule VRI");
                goto error;
              }
          }
      }

#ifdef SSHDIST_IPSEC_SA_EXPORT
      if (app_id != NULL)
        {
          if (!ssh_pm_rule_set_application_identifier(ctx->state->u.rule.rule,
                                                      ssh_custr(app_id),
                                                      app_id_len))
            {
              ssh_ipm_error(ctx, "Could not set rule application identifier");
              goto error;
            }
        }
#endif /* SSHDIST_IPSEC_SA_EXPORT */
    }
  /**************************** Source IP address ***************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("src"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_SRC);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("src-dns"), 0))
    {
      if (!ctx->dns_names_allowed)
        {
          ssh_ipm_error(ctx, "DNS names are not allowed on the policy");
          goto error;
        }
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_SRC);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /************************** Destination IP address ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("dst"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_DST);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("dst-dns"), 0))
    {
      if (!ctx->dns_names_allowed)
        {
          ssh_ipm_error(ctx, "DNS names are not allowed on the policy");
          goto error;
        }
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_DST);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /****************************** Interface name ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ifname"), 0))
    {
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IFNAME);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("routed-ifname"), 0))
    {
      if (!ctx->dns_names_allowed)
        {
          ssh_ipm_error(ctx, "DNS names are not allowed on the policy");
          goto error;
        }
      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_IFNAME);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /******************************* Local stack ******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-stack"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_RULE);

      /* Direction. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("direction"), 0,
                                     &value_len);
      if (ssh_xml_match(value, value_len, ssh_custr("from"), 0))
        ssh_pm_rule_set_local_stack(ctx->state->u.rule.rule, SSH_PM_FROM);
      else
        ssh_pm_rule_set_local_stack(ctx->state->u.rule.rule, SSH_PM_TO);
    }
  /**************************** Extension selector **************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("extension"), 0))
    {
      SshUInt32 id, low, high;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_RULE);

      /* ID. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("id"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, value, &id))
        goto error;

      /* Low value. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("low"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, value, &low))
        goto error;

      /* High value. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("high"), 0, NULL);
      if (!ssh_ipm_parse_number(ctx, value, &high))
        goto error;

      if (low > high)
        {
          ssh_ipm_error(ctx, "Invalid extension selector value range %u-%u",
                        low, high);
          goto error;
        }

      if (!ssh_pm_rule_set_extension(ctx->state->u.rule.rule, id, low, high))
        {
          ssh_ipm_error(ctx, "Invalid extension selector number %u", id);
          goto error;
        }
    }
  else if (ssh_xml_match(name, name_len, ssh_custr("radius-accounting"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_PARAMS);

      ssh_ipm_push(ctx, SSH_IPM_XMLCONF_RADIUS_ACCOUNTING);
    }

  /* All done. */
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;

  /* Error handling. */

 error:
  (*result_cb)(SSH_XML_ERROR, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_ipm_xml_end_element(SshXmlParser parser,
                        const unsigned char *name, size_t name_len,
                        SshXmlResultCB result_cb, void *result_cb_context,
                        void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;
  SshADTHandle h, hnext;
  SshIpmRule rule;
  SshIpmPolicyObject object;
  SshIpmXmlconf parent;
  SshIpAddrStruct tmpip;
  SshXmlAttrEnumCtxStruct attr_enum;
  const unsigned char *value;
  size_t value_len;

  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /************************ End of configuration data ***********************/
  if (ssh_xml_match(name, name_len, ssh_custr("quicksec"), 0))
    {
      SshUInt32 num_unused = 0;

      /* For compatibility with the old command line way auditing was
         initialized, audit to the syslog if no auditing information was
         specified in the policy file. */
      if (ssh_adt_num_objects(ctx->audit_modules) == 0)
        {
          SshIpmAudit audit;
          SshAuditContext audit_context;

          SSH_DEBUG(SSH_D_MIDOK, ("Attaching default syslog audit context"));

          audit_context = ssh_pm_create_audit_module(pm,
                                                     SSH_AUDIT_FORMAT_DEFAULT,
                                                     "syslog");
          if (audit_context == NULL)
            goto error;

          if (!ssh_pm_attach_audit_module(pm, SSH_PM_AUDIT_ALL,
                                          audit_context))
            goto error;

          /* Add this audit module. */
          audit = ssh_ipm_xmlconf_audit_get(ctx, "syslog", SSH_PM_AUDIT_ALL);

          if (audit == NULL)
            goto error;

          audit->seen = 1;
          audit->subsystems = SSH_PM_AUDIT_ALL;
        }

      /* Free all unused policy objects. */
      for (h = ssh_adt_enumerate_start(ctx->policy_objects);
           h != SSH_ADT_INVALID;
           h = hnext)
        {
          object = ssh_adt_get(ctx->policy_objects, h);
          hnext = ssh_adt_enumerate_next(ctx->policy_objects, h);

          if (object->seen)
            object->seen = 0;
          else
            ssh_adt_delete(ctx->policy_objects, h);
        }

      /* Delete all unused rules. */
      for (h = ssh_adt_enumerate_start(ctx->rules);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(ctx->rules, h))
        {
          rule = ssh_adt_get(ctx->rules, h);
          if (rule->seen)
            {
              rule->seen = 0;
            }
          else
            {
              rule->seen = 0;
              rule->unused = 1;
              num_unused++;
              SSH_ASSERT(rule->rule != SSH_IPSEC_INVALID_INDEX);
              ssh_pm_rule_delete(pm, rule->rule);
            }
        }
#if 0
      if (num_unused)
        {
          /* Commit our changes. */

          SSH_DEBUG(SSH_D_LOWSTART, ("Deleting %u unused rules", num_unused));

          ctx->result_cb = result_cb;
          ctx->result_cb_context = result_cb_context;

          ctx->commit_called = 1;

          (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
                     ssh_ipm_unused_commit_cb, ctx);
          return NULL;          /* Note: SshOperationHandle */
        }
#endif /* 0 */
    }
  /********************************** Params ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("params"), 0))
    {
      if (ctx->auth_domains && !ctx->default_auth_domain_present)
        {
          ssh_ipm_error(ctx, "Configuration for default authentication "
                        "domain required");
          goto error;
        }

      ssh_ipm_pop(ctx);
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  else if (ssh_xml_match(name, name_len, ssh_custr("tunnel-address-pool"), 0))
    {
      ssh_ipm_pop(ctx);
    }
  /******************************* Address-pool *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("address-pool"), 0))
    {
      SshPmRemoteAccessParamsStruct params;
      SshBuffer addresses = NULL;
      SshBuffer subnets = NULL;

      memset(&params, 0, sizeof(params));

      /* Prepare the list of subnets. */
      if (ctx->state->u.addrpool.remote_access_attr_subnet_list != NULL)
        {
          SshIpmRasSubnetConfig subnet;
          subnets = ssh_buffer_allocate();
          if (subnets == NULL)
            goto error;

          for (subnet = ctx->state->u.addrpool.remote_access_attr_subnet_list;
               subnet != NULL;
               subnet = subnet->next)
            {
              if (ssh_buffer_append(subnets, subnet->address,
                                    strlen(subnet->address)) != SSH_BUFFER_OK)
                {
                  ssh_buffer_free(subnets);
                  goto error;
                }
              if (ssh_buffer_append(subnets, ";", 1) != SSH_BUFFER_OK)
                {
                  ssh_buffer_free(subnets);
                  goto error;
                }
            }
          /* Terminate string properly */
          if (ssh_buffer_append(subnets, (unsigned char *)"\000", 1)
              != SSH_BUFFER_OK)
            {
              ssh_buffer_free(subnets);
              goto error;
            }
        }

      /* Prepare the list of addresses. */
      if (ctx->state->u.addrpool.remote_access_attr_address_list != NULL)
        {
          SshIpmRasAddressConfig address;

          addresses = ssh_buffer_allocate();
          if (addresses == NULL)
            {
              if (subnets)
                ssh_buffer_free(subnets);
              goto error;
            }

          for (address =
                 ctx->state->u.addrpool.remote_access_attr_address_list;
               address != NULL;
               address = address->next)
            {
              if (!ssh_ipm_ras_addrpool_add_address(addresses,
                                                    address->address,
                                                    address->netmask))
                {
                  ssh_ipm_error(ctx,
                                "Could not configure address `%s/%s' to "
                                "address pool",
                                address->address, address->netmask);
                  if (subnets)
                    ssh_buffer_free(subnets);
                  ssh_buffer_free(addresses);
                  goto error;
                }
            }

          /* Terminate string properly */
          if (ssh_buffer_append(addresses, (unsigned char *)"\000", 1)
              != SSH_BUFFER_OK)
            {
              if (subnets)
                ssh_buffer_free(subnets);
              ssh_buffer_free(addresses);
              goto error;
            }
        }

      if (addresses != NULL)
        params.addresses = ssh_buffer_ptr(addresses);

      if (subnets)
        params.subnets = ssh_buffer_ptr(subnets);

      params.name = ctx->state->u.addrpool.address_pool_name;
      params.own_ip_addr = ctx->state->u.addrpool.remote_access_attr_own_ip;
      params.dns = ctx->state->u.addrpool.remote_access_attr_dns;
      params.wins = ctx->state->u.addrpool.remote_access_attr_wins;
      params.dhcp = ctx->state->u.addrpool.remote_access_attr_dhcp;
      params.flags |= ctx->state->u.addrpool.flags;




      if (!ssh_pm_ras_add_addrpool(pm, &params))
        {
          ssh_ipm_error(ctx, "Could not configure remote access attributes");
          if (subnets)
            ssh_buffer_free(subnets);
    if (addresses)
          ssh_buffer_free(addresses);
          goto error;
        }

      if (ctx->state->u.addrpool.address_pool_name == NULL)
        ctx->state->u.addrpool.address_pool_name = params.name;

      /* Lookup addrpool's policy object. */
      if (ctx->state->u.addrpool.address_pool_name)
        {
          ctx->state->object = ssh_ipm_xmlconf_policy_object_get(ctx,
                        ctx->state->u.addrpool.address_pool_name,
                        strlen(ctx->state->u.addrpool.address_pool_name));
        }
      else
        {
          ctx->state->object = NULL;
        }

      if (ctx->state->object == NULL)
        {
          ssh_ipm_error(ctx, "Could not allocate address pool object");
          if (subnets)
            ssh_buffer_free(subnets);
    if (addresses)
      ssh_buffer_free(addresses);
    goto error;
        }

      /* fill address pool name as value */
      ctx->state->object->value.type = SSH_IPM_POLICY_OBJECT_ADDRPOOL;
      ssh_free(ctx->state->object->value.u.addrpool_name);
      ctx->state->object->value.u.addrpool_name =
        ssh_strdup(ctx->state->u.addrpool.address_pool_name);

      if (addresses)
      ssh_buffer_free(addresses);
      if (subnets)
        ssh_buffer_free(subnets);
      ssh_ipm_pop(ctx);

    }
/**************** Sub-network specification for address pool **************/
  else if (ssh_xml_match(name, name_len, ssh_custr("subnet"), 0))
    {
      SshIpmRasSubnetConfig subnet;

      subnet = ssh_calloc(1, sizeof(*subnet));
      if (subnet == NULL)
        {
          ssh_ipm_error(ctx, "Could not configure subnet `%s'",
                        ctx->state->data);
          goto error;
        }
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_SUBNET);
      subnet->address = ssh_strdup(ctx->state->data);
      if (subnet->address == NULL)
        {
          ssh_ipm_error(ctx, "Could not configure subnet `%s'",
                        ctx->state->data);
          ssh_free(subnet);
          goto error;
        }

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_ADDR_POOL);

      subnet->next = parent->u.addrpool.remote_access_attr_subnet_list;
      parent->u.addrpool.remote_access_attr_subnet_list = subnet;
      ssh_ipm_pop(ctx);
    }




















  /**************** IP address specification for address pool ***************/
  else if (ssh_xml_match(name, name_len, ssh_custr("address"), 0))
    {
      SshIpmRasAddressConfig address;
      unsigned char netmask[SSH_IP_ADDR_STRING_SIZE];

      address = ssh_calloc(1, sizeof(*address));
      if (address == NULL)
        {
          ssh_ipm_error(ctx, "Could not configure remote access address `%s'",
                        ctx->state->data);
          goto error;
        }
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_ADDR_POOL);

      address->next = parent->u.addrpool.remote_access_attr_address_list;
      parent->u.addrpool.remote_access_attr_address_list = address;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_ADDRESS);
      address->address = ssh_strdup(ctx->state->data);

      ssh_ipaddr_print(&ctx->state->u.addrpool.netmask,
                       netmask, sizeof(netmask));
      address->netmask = ssh_strdup(netmask);

      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_REDIRECT
  /***************************** IKEv2 Redirect *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-redirect"), 0))
    {
      SshIpAddrStruct tmpip;

      if (ctx->state->u.ike_redirect.redirect_addr != NULL)
        {
          if (!ssh_ipaddr_parse(&tmpip,
                                ctx->state->u.ike_redirect.redirect_addr))
            {
              ssh_ipm_error(ctx, "IKE redirect is not a valid IP address");
              goto error;
            }
          if (!ssh_pm_set_ike_redirect(pm, &tmpip,
                                       ctx->state->u.ike_redirect.phase))
            {
              ssh_ipm_error(ctx, "Could not add IKE redirect `%s'",
                            ctx->state->u.ike_redirect.redirect_addr);
              goto error;
            }
        }
      else
        {
          if (!ssh_pm_set_ike_redirect(pm, NULL,
                                       ctx->state->u.ike_redirect.phase))
            {
              ssh_ipm_error(ctx, "Could not enable IKE redirect");
              goto error;
            }
        }

      /* Done with the ike redirect */
      ssh_ipm_pop(ctx);
    }

  /* ************************ Redirect address *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("redirect-address"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_REDIRECT_ADDRESS);
      parent = ssh_ipm_parent(ctx, ctx->state);

      if (parent->type == SSH_IPM_XMLCONF_IKE_REDIRECT)
        {

          parent->u.ike_redirect.redirect_addr = ssh_strdup(ctx->state->data);
          if (parent->u.ike_redirect.redirect_addr == NULL)
            {
              ssh_ipm_error(ctx, "Could not configure redirect address `%s'",
                            ctx->state->data);
              goto error;
            }
          if (!ssh_ipaddr_parse(&tmpip,
                                parent->u.ike_redirect.redirect_addr))
            {
              ssh_ipm_error(ctx, "Redirect address is not a valid IP address");
              goto error;
            }
        }
      else
        {
          SshIpAddrStruct tmpip;
          SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

          if (!ctx->state->data)
            {
              ssh_ipm_error(ctx, "No redirect address for tunnel specified");
              goto error;
            }

          if (!ssh_ipaddr_parse(&tmpip, ctx->state->data))
            {
              ssh_ipm_error(ctx,
                            "Redirect address is not a valid IP address");
              goto error;
            }

          if (ssh_pm_tunnel_set_ike_redirect(
                                    parent->u.tunnel.tunnel, &tmpip) == FALSE)
            {
              ssh_ipm_error(ctx, "Could not set IKE redirect for tunnel");
              goto error;
            }
        }
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IKE_REDIRECT */

  /*********************** Manual certificates and CRLs *********************/
#ifdef SSHDIST_CERT
  else if (ssh_xml_match(name, name_len, ssh_custr("certificate"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("crl"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("private-key"), 0)
           || ssh_xml_match(name, name_len, ssh_custr("public-key"), 0))
    {
      char *type;
      if (ctx->state->type == SSH_IPM_XMLCONF_CERTIFICATE)
        type = "certificate";
      else if (ctx->state->type == SSH_IPM_XMLCONF_CRL)
        type = "CRL";
      else if (ctx->state->type == SSH_IPM_XMLCONF_PRVKEY)
        type = "private key";
      else
        type = "public key";

      /* Was the data given in the config file? */
      if (ctx->state->data == NULL)
        {
          /* No it wasn't.  Do we have a file name? */
          if (ctx->state->u.keycert.file)
            {
              if (!ssh_read_gen_file(ctx->state->u.keycert.file,
                                     &ctx->state->data,
                                     &ctx->state->data_len))
                {
                  ssh_ipm_error(ctx, "Could not read %s file `%s'",
                                type, ctx->state->u.keycert.file);
                  goto error;
                }
            }
          else
            {
              ssh_ipm_error(ctx, "No %s specified", type);
              goto error;
            }
        }
      else
        {
          /* The data was given.  Give a warning if also the file name
             was specified. */
          if (ctx->state->u.keycert.file)
            ssh_ipm_warning(ctx,
                            "Both inlined %s and a file name specified: "
                            "ingoring file `%s'",
                            type, ctx->state->u.keycert.file);
        }

      /* Check our parent. */
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent != NULL);
      if (parent->type == SSH_IPM_XMLCONF_AUTH_DOMAIN)
        {
          /* Configure it for the certificate manager. */
          switch (ctx->state->type)
            {
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
            case SSH_IPM_XMLCONF_CERTIFICATE:
              if (!ssh_pm_auth_domain_add_cert(
                                        pm,
                                        parent->u.auth_domain.auth_domain,
                                        ctx->state->data,
                                        ctx->state->data_len))
                {
                  ssh_ipm_error(ctx, "Could not add certificate");
                  goto error;
                }
              break;

            case SSH_IPM_XMLCONF_CRL:
              if (!ssh_pm_auth_domain_add_crl(
                                        pm,
                                        parent->u.auth_domain.auth_domain,
                                        ctx->state->data,
                                        ctx->state->data_len))
                {
                  ssh_ipm_error(ctx, "Could not add CRL");
                  goto error;
                }
              break;






            case SSH_IPM_XMLCONF_PRVKEY:
              {
                SshPrivateKey prvkey;

                /* Read from PKCS1 encoded key in file to private key */
                prvkey = ssh_pkcs1_decode_private_key(ctx->state->data,
                                                      ctx->state->data_len);

                if (!prvkey ||
                    !ssh_pm_auth_domain_set_private_key(
                                          parent->u.auth_domain.auth_domain,
                                          prvkey))
                  {
                    if (prvkey)
                      ssh_private_key_free(prvkey);

                    ssh_ipm_error(ctx, "Could not set private key for "
                                  "authentication domain");
                    goto error;
                  }
                break;
              }

            case SSH_IPM_XMLCONF_PUBKEY:
              {
                SshPublicKey pubkey;

                /* Read from PKCS1 encoded key in file to public key */
                pubkey = ssh_pkcs1_decode_public_key(ctx->state->data,
                                                     ctx->state->data_len);

                if (!pubkey ||
                    !ssh_pm_auth_domain_set_public_key(
                                        parent->u.auth_domain.auth_domain,
                                        pubkey))
                  {
                    if (pubkey)
                      ssh_public_key_free(pubkey);

                    ssh_ipm_error(ctx, "Could not set public key for "
                                  "authentication domain");
                    goto error;
                  }
                break;
              }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

            default:
              ssh_ipm_error(ctx, "Unknown type");
              goto error;
              break;
            }
        }
      else if (parent->type == SSH_IPM_XMLCONF_TUNNEL)
        {
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
          /* Certificate specifies our certificate to be used in
             negotiations with this tunnel. */
          if (ctx->state->type == SSH_IPM_XMLCONF_CERTIFICATE &&
              !ssh_pm_tunnel_set_cert(parent->u.tunnel.tunnel,
                                      ctx->state->data,
                                      ctx->state->data_len))
            {
              ssh_ipm_error(ctx, "Could not set certificate for tunnel");
              goto error;
            }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

        }
      else
        SSH_XML_VERIFIER(0);

      /* We are done with this frame. */
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_CERT */
  /***************************** Pre Shared Keys ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("remote-secret"), 0))
    {
      SshPmAuthDomain ad;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_PSK);

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_AUTH_DOMAIN);

      ad = parent->u.auth_domain.auth_domain;

      /* Configure this preshared key secret. */
      if (!ssh_pm_add_ike_preshared_key(pm,
                                        ad,
                                        ctx->state->u.psk.id_type,
                                        ctx->state->u.psk.id_encoding,
                                        ctx->state->u.psk.identity,
                                        ctx->state->u.psk.identity_len,
                                        ctx->state->u.psk.encoding,
                                        ctx->state->data,
                                        ctx->state->data_len))
        {
          ssh_ipm_error(ctx, "Could not add IKE preshared key secret");
          goto error;
        }
      /* A preshared key object parsed. */
      ssh_ipm_pop(ctx);
    }
  else if (ssh_xml_match(name, name_len, ssh_custr("local-secret"), 0))
    {
      SshIpmXmlconf parent_parent;
      /* Currently only order 1 is supported for PSK */
      SshUInt32 order = 1;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_PSK);
      parent = ssh_ipm_parent(ctx, ctx->state);
      parent_parent = ssh_ipm_parent(ctx, parent);

      /* We must be configuring this secret for an identity */
      if (parent == NULL ||
          parent->type != SSH_IPM_XMLCONF_IDENTITY ||
          parent_parent == NULL ||
          parent_parent->type != SSH_IPM_XMLCONF_TUNNEL)
        goto error;

      if (parent->u.tunnel.remote_identity)
        {
          ssh_ipm_error(ctx, "Adding local secret to a remote identity is "
                        "not supported.");
          goto error;
        }

      if (!ssh_pm_tunnel_set_preshared_key(parent_parent->u.tunnel.tunnel,
                                           ctx->state->u.psk.flags,
                                           ctx->state->u.psk.encoding,
                                           ctx->state->data,
                                           ctx->state->data_len,
                                           order))
        goto error;

      /* A preshared key object parsed. */
      ssh_ipm_pop(ctx);
    }
  /***************************** IKE identities ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("identity"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (ctx->state->u.tunnel.remote_identity)
        {
          if (!ssh_pm_tunnel_set_remote_identity(
                                 parent->u.tunnel.tunnel,
                                 ctx->state->u.tunnel.identity_flags,
                                 ctx->state->u.tunnel.id_type,
                                 ctx->state->u.tunnel.id_encoding,
                                 ctx->state->u.tunnel.identity,
                                 ctx->state->u.tunnel.identity_len))
            {
              ssh_ipm_error(ctx,
                            "Could not add IKE remote identity for this "
                            "tunnel");
              goto error;
            }
        }
      else
        {
          if (!ssh_pm_tunnel_set_local_identity(
                                 parent->u.tunnel.tunnel,
                                 ctx->state->u.tunnel.identity_flags,
                                 ctx->state->u.tunnel.id_type,
                                 ctx->state->u.tunnel.id_encoding,
                                 ctx->state->u.tunnel.identity,
                                 ctx->state->u.tunnel.identity_len,
                                 ctx->state->u.tunnel.order))
            {
              ssh_ipm_error(ctx,
                            "Could not add IKE local identity for this "
                            "tunnel");
              goto error;
            }
        }

      /* A identity object parsed. */
      ssh_ipm_pop(ctx);
    }
  /************************** Tunnel authentication *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("authentication"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Configure authentication for the tunnel */
      if (ctx->state->u.tunnel.auth_domain_name)
        {
          if (!ssh_pm_tunnel_set_auth_domain
                            (parent->u.tunnel.tunnel,
                             ctx->state->u.tunnel.auth_domain_name,
                             ctx->state->u.tunnel.order))
            {
              ssh_ipm_error(ctx, "Could not add authentication domain "
                            "for this tunnel");
              goto error;
            }
        }

      /* A tunnel authentication object parsed. */
      ssh_ipm_pop(ctx);
    }

  /************************** Access control groups *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("group"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_ACCESS_GROUP);

      /* Add the group to the local authorization module.  The module
         adds a reference to the object.  Therefore we must free our
         copy. */
      ssh_pm_authorization_add_group(ctx->authorization,
                                     ctx->state->u.group.group);
      ssh_ipm_pop(ctx);
    }

  /*********************************** DNS **********************************/
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("dns"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_DNS);

      ctx->dns_configuration_done = 1;
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /************************** Audit params *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("audit"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUDIT);

      ssh_ipm_pop(ctx);
    }
  /********************************** Policy ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("policy"), 0))
    {
      /* Update precedence range. */
      ctx->precedence_used_min = ctx->precedence_min;

      /* Everything is ready for committing the changes.  But before
         that, we must delete all current rules which will be replaced
         by the new ones. */
      for (h = ssh_adt_enumerate_start(ctx->rules);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(ctx->rules, h))
        {
          rule = ssh_adt_get(ctx->rules, h);

          if (rule->new_rule != SSH_IPSEC_INVALID_INDEX
              && rule->rule != SSH_IPSEC_INVALID_INDEX)
            /* Request deletion for the old rule. */
            ssh_pm_rule_delete(pm, rule->rule);
        }

      /* Done parsing this policy block. */
      ssh_ipm_pop(ctx);
    }
  /********************************* Service ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("service"), 0))
    {
#ifdef SSHDIST_IPSEC_NAT
      ssh_ipm_error(ctx, "Service not supported");
      goto error;
#endif /* SSHDIST_IPSEC_NAT */
    }
  /********************************** Tunnel ********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("tunnel"), 0))
    {
      SshIpmPolicyObject obj = ctx->state->object;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_TUNNEL);
      SSH_ASSERT(ctx->state->u.tunnel.tunnel != NULL);
      SSH_ASSERT(obj != NULL);

#ifdef SSHDIST_IKEV1
      if (ctx->state->u.tunnel.ike_versions)
        {
          if (!ssh_pm_tunnel_set_ike_versions(ctx->state->u.tunnel.tunnel,
                                            ctx->state->u.tunnel.ike_versions))
            {
              ssh_ipm_error(ctx, "Invalid IKE versions");
              goto error;
            }
        }
#endif /* SSHDIST_IKEV1 */

      /* Do we have an old tunnel object. */
      if (obj->value.type == SSH_IPM_POLICY_OBJECT_TUNNEL)
        {

          /* Yes we have.  Let's see if this is a reconfiguration. */
          if (ssh_pm_tunnel_compare(pm, obj->value.u.tunnel,
                                    ctx->state->u.tunnel.tunnel))
            {
              /* They are identical. */
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Tunnel is identical to the old tunnel"));
              ssh_pm_tunnel_destroy(pm, ctx->state->u.tunnel.tunnel);
              ctx->state->u.tunnel.tunnel = NULL;
            }
          else
            {
              /* The tunnel has been reconfigured. */
              SSH_DEBUG(SSH_D_LOWOK, ("Tunnel reconfigured"));
            }
        }
      else
        {
          /* No old tunnel. */
          SSH_DEBUG(SSH_D_LOWOK, ("No old tunnel"));
        }

      if (ctx->state->u.tunnel.tunnel)
        {
          /* Steal the tunnel object. */
          obj->new_value.type = SSH_IPM_POLICY_OBJECT_TUNNEL;
          obj->new_value.u.tunnel = ctx->state->u.tunnel.tunnel;
          ctx->state->u.tunnel.tunnel = NULL;
        }

      /* Done with this tunnel object. */
      ssh_ipm_pop(ctx);
    }
  /******************************** Auth Domain *****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("auth-domain"), 0))
    {
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_AUTH_DOMAIN);
      SSH_ASSERT(ctx->state->u.auth_domain.auth_domain != NULL);

      /* Done with the auth domain */
      ssh_ipm_pop(ctx);
    }

  /*********************************** Peer *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("peer"), 0))
    {
#ifdef SSH_IPSEC_TCPENCAP
      unsigned char ip_low[SSH_IP_ADDR_STRING_SIZE];
      unsigned char ip_high[SSH_IP_ADDR_STRING_SIZE];
#endif /* SSH_IPSEC_TCPENCAP */

      parent = ssh_ipm_parent(ctx, ctx->state);

#ifdef SSH_IPSEC_TCPENCAP
      if (parent->type == SSH_IPM_XMLCONF_TCP_ENCAPS)
        {
          if (!ctx->state->data)
            {
              ssh_ipm_error(ctx, "No IPsec over TCP tunnel peer specified");
              goto error;
            }

          if (!ssh_ipm_parse_ip(ctx->state->data, ip_low, ip_high))
            {
              ssh_ipm_error(ctx,
                            "Malformed IPsec over TCP peer address range '%s'",
                            ctx->state->data);
              goto error;
            }

          if (!ssh_ipaddr_parse(&tmpip, ip_low))
            {
              ssh_ipm_error(ctx,
                            "Invalid IPsec over TCP peer address range");
              goto error;
            }
          memcpy(&parent->u.tcp_encaps_config.peer_lo_addr,
                 &tmpip, sizeof(tmpip));

          if (!ssh_ipaddr_parse(&tmpip, ip_high))
            {
              ssh_ipm_error(ctx,
                            "Invalid IPsec over TCP peer address range");
              goto error;
            }
          memcpy(&parent->u.tcp_encaps_config.peer_hi_addr,
                 &tmpip, sizeof(tmpip));

          if (SSH_IP_CMP(&parent->u.tcp_encaps_config.peer_lo_addr,
                         &parent->u.tcp_encaps_config.peer_hi_addr) > 0)
            {
              ssh_ipm_error(ctx,
                            "Invalid IPsec over TCP peer address range");
              goto error;
            }
        }
      else
#endif /* SSH_IPSEC_TCPENCAP */
        {
          SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

          if (!ctx->state->data)
            {
              ssh_ipm_error(ctx, "No tunnel peer specified");
              goto error;
            }

          if (!ctx->dns_names_allowed &&
              !ssh_ipaddr_parse(&tmpip, ctx->state->data))
            {
              ssh_ipm_error(ctx,
                            "DNS peer names are not allowed on the policy");
              goto error;
            }

          if (!ssh_pm_tunnel_add_peer(parent->u.tunnel.tunnel,
                                      ctx->state->data))
            {
              ssh_ipm_error(ctx,
                            "Could not configure tunnel peer address `%s'",
                            ctx->state->data);
              goto error;
            }
        }
      ssh_ipm_pop(ctx);
    }
  /********************************* Local IP *******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-ip"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);

#ifdef SSH_IPSEC_TCPENCAP
      if (parent->type == SSH_IPM_XMLCONF_TCP_ENCAPS)
        {
          if (!ctx->state->data)
            {
              ssh_ipm_error(ctx,
                            "No IPsec over TCP local-ip specified");
              goto error;
            }

          if (!ssh_ipaddr_parse(&tmpip, ctx->state->data))
            {
              ssh_ipm_error(ctx,
                            "Invalid IPsec over TCP local address");
              goto error;
            }

          memcpy(&parent->u.tcp_encaps_config.local_addr,
                 &tmpip, sizeof(tmpip));
        }
      else
#endif /* SSH_IPSEC_TCPENCAP */
        {
          SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

          if (!ctx->state->data)
            {
              ssh_ipm_error(ctx, "No local-ip address specified");
              goto error;
            }

          if (!ctx->dns_names_allowed &&
              !ssh_ipaddr_parse(&tmpip, ctx->state->data))
            {
              ssh_ipm_error(ctx,
                            "DNS local names are not allowed on the policy");
              goto error;
            }

          if (!ssh_pm_tunnel_add_local_ip(parent->u.tunnel.tunnel,
                                       ctx->state->data,
                                       ctx->state->u.local_address.precedence))
            {
              ssh_ipm_error(ctx,
                            "Could not configure tunnel's local address `%s'",
                            (char *) ctx->state->data);
              goto error;
            }

          /* We want to allow updating the precedence of a tunnel's
             local IP inplace, i.e. without creating a new tunnel and
             reconfiguring all policy rules that reference that tunnel.
             So here we directly modify the original tunnel's local IP. */
          if (parent->object->value.u.tunnel &&
              !ssh_pm_tunnel_add_local_ip(
                                      parent->object->value.u.tunnel,
                                      ctx->state->data,
                                      ctx->state->u.local_address.precedence))
            {
              ssh_ipm_error(ctx,
                            "Could not configure tunnel's local address `%s'",
                            (char *) ctx->state->data);
              goto error;
            }

        }
      ssh_ipm_pop(ctx);
    }
  /********************************* Local Interface *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-interface"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No local interface specified");
          goto error;
        }

      if (!ssh_pm_tunnel_add_local_interface(parent->u.tunnel.tunnel,
                                      ctx->state->data,
                                      ctx->state->u.local_address.precedence))
        {
          ssh_ipm_error(ctx,
                        "Could not configure tunnel's local interface `%s'",
                        (char *) ctx->state->data);
          goto error;
        }
      /* We want to allow updating the precedence of a tunnel's
         local interfaces inplace, i.e. without creating a new tunnel and
         reconfiguring all policy rules that reference that tunnel.
         So here we directly modify the original tunnel's local interfaces. */
      if (parent->object->value.u.tunnel &&
          !ssh_pm_tunnel_add_local_interface(
                                       parent->object->value.u.tunnel,
                                       ctx->state->data,
                                       ctx->state->u.local_address.precedence))
        {
          ssh_ipm_error(ctx,
                        "Could not configure tunnel's local interface `%s'",
                        (char *) ctx->state->data);
          goto error;
        }

      ssh_ipm_pop(ctx);
    }
  /********************************* Local Port ******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("local-port"), 0))
    {
      SshUInt32 port;

      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No local port specified");
          goto error;
        }

      if (!ssh_ipm_parse_number(ctx, ctx->state->data, &port)
          || port > 65535
          || !ssh_pm_tunnel_set_local_port(parent->u.tunnel.tunnel,
                                           port))
        {
          ssh_ipm_error(ctx,
                        "Could not configure tunnel's local port `%s'",
                        (char *) ctx->state->data);
          goto error;
        }
      ssh_ipm_pop(ctx);
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /***************************** CFGMODE address ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("cfgmode-address"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No address specified");
          goto error;
        }
      if (!ssh_pm_tunnel_set_remote_access_address(parent->u.tunnel.tunnel,
                                                   ctx->state->data))
        {
          ssh_ipm_error(ctx,
                        "Could not configure tunnel's IRAC address `%s'",
                        (char *) ctx->state->data);
          goto error;
        }
      ssh_ipm_pop(ctx);
    }
  /***************************** virtual-ifname ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("virtual-ifname"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No interface name specified");
          goto error;
        }
      if (!ssh_pm_tunnel_set_virtual_adapter(parent->u.tunnel.tunnel,
                                             ctx->state->data))
        {
          ssh_ipm_error(ctx,
                        "Could not configure tunnel's virtual adapter `%s'",
                        (char *) ctx->state->data);
          goto error;
        }
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  /****************** Diffie-Hellman groups for IKE *********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-groups"), 0))
    {
      SshPmTunnel tunnel;
      SshUInt32 algorithms = 0;
      Boolean set_preferences = TRUE;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      tunnel = parent->u.tunnel.tunnel;

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No IKE groups specified");
          goto error;
        }

      if (parent->u.tunnel.default_ike_preferences)
        set_preferences = FALSE;

      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);

      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
            algorithms |= SSH_PM_DH_GROUP_1;
          else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
            algorithms |= SSH_PM_DH_GROUP_2;
          else if (ssh_xml_match(value, value_len, ssh_custr("5"), 0))
            algorithms |= SSH_PM_DH_GROUP_5;
          else if (ssh_xml_match(value, value_len, ssh_custr("14"), 0))
            algorithms |= SSH_PM_DH_GROUP_14;
          else if (ssh_xml_match(value, value_len, ssh_custr("15"), 0))
            algorithms |= SSH_PM_DH_GROUP_15;
          else if (ssh_xml_match(value, value_len, ssh_custr("16"), 0))
            algorithms |= SSH_PM_DH_GROUP_16;
          else if (ssh_xml_match(value, value_len, ssh_custr("17"), 0))
            algorithms |= SSH_PM_DH_GROUP_17;
          else if (ssh_xml_match(value, value_len, ssh_custr("18"), 0))
            algorithms |= SSH_PM_DH_GROUP_18;
          else if (ssh_xml_match(value, value_len, ssh_custr("22"), 0))
            algorithms |= SSH_PM_DH_GROUP_22;
          else if (ssh_xml_match(value, value_len, ssh_custr("23"), 0))
            algorithms |= SSH_PM_DH_GROUP_23;
          else if (ssh_xml_match(value, value_len, ssh_custr("24"), 0))
            algorithms |= SSH_PM_DH_GROUP_24;
#ifdef SSHDIST_CRYPT_ECP
          else if (ssh_xml_match(value, value_len, ssh_custr("19"), 0))
            algorithms |= SSH_PM_DH_GROUP_19;
          else if (ssh_xml_match(value, value_len, ssh_custr("20"), 0))
            algorithms |= SSH_PM_DH_GROUP_20;
          else if (ssh_xml_match(value, value_len, ssh_custr("21"), 0))
            algorithms |= SSH_PM_DH_GROUP_21;
          else if (ssh_xml_match(value, value_len, ssh_custr("25"), 0))
            algorithms |= SSH_PM_DH_GROUP_25;
          else if (ssh_xml_match(value, value_len, ssh_custr("26"), 0))
            algorithms |= SSH_PM_DH_GROUP_26;
#endif /* SSHDIST_CRYPT_ECP  */
          else
            {
              ssh_ipm_error(ctx, "Invalid IKE group specification `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      if (!ssh_pm_tunnel_set_ike_groups(tunnel, algorithms))
        {
          ssh_ipm_error(ctx, "Invalid IKE group specification");
          goto error;
        }

      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);

      if (set_preferences)
        {
          SshUInt8 preference = 255;

          while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
                 != NULL)
            {
              if (ssh_xml_match(value, value_len, ssh_custr("0"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_0,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_1,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_2,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("5"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_5,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("14"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_14,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("15"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_15,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("16"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_16,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("17"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_17,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("18"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_18,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("22"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_22,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("23"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_23,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("24"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_24,
                                                            preference))
                    goto error;
                }
#ifdef SSHDIST_CRYPT_ECP
              else if (ssh_xml_match(value, value_len, ssh_custr("19"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_19,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("20"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_20,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("21"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_21,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("25"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_25,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("26"), 0))
                {
                  if (!ssh_pm_tunnel_set_ike_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_26,
                                                            preference))
                    goto error;
                }
#endif /* SSHDIST_CRYPT_ECP  */
              else
                {
                  ssh_ipm_error(ctx, "Invalid IKE group specification `%.*s'",
                                value_len, value);
                  goto error;
                }
              preference--;
            }
        }

      ssh_ipm_pop(ctx);
    }
  /****************** Diffie-Hellman groups for PFS ***********************/
  else if (ssh_xml_match(name, name_len, ssh_custr("pfs-groups"), 0))
    {
      SshPmTunnel tunnel;
      SshUInt32 algorithms = 0;
      Boolean set_preferences = TRUE;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      tunnel = parent->u.tunnel.tunnel;

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No PFS groups specified");
          goto error;
        }

      if (parent->u.tunnel.default_pfs_preferences)
        set_preferences = FALSE;

      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);

      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
            algorithms |= SSH_PM_DH_GROUP_1;
          else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
            algorithms |= SSH_PM_DH_GROUP_2;
          else if (ssh_xml_match(value, value_len, ssh_custr("5"), 0))
            algorithms |= SSH_PM_DH_GROUP_5;
          else if (ssh_xml_match(value, value_len, ssh_custr("14"), 0))
            algorithms |= SSH_PM_DH_GROUP_14;
          else if (ssh_xml_match(value, value_len, ssh_custr("15"), 0))
            algorithms |= SSH_PM_DH_GROUP_15;
          else if (ssh_xml_match(value, value_len, ssh_custr("16"), 0))
            algorithms |= SSH_PM_DH_GROUP_16;
          else if (ssh_xml_match(value, value_len, ssh_custr("17"), 0))
            algorithms |= SSH_PM_DH_GROUP_17;
          else if (ssh_xml_match(value, value_len, ssh_custr("18"), 0))
            algorithms |= SSH_PM_DH_GROUP_18;
          else if (ssh_xml_match(value, value_len, ssh_custr("22"), 0))
            algorithms |= SSH_PM_DH_GROUP_22;
          else if (ssh_xml_match(value, value_len, ssh_custr("23"), 0))
            algorithms |= SSH_PM_DH_GROUP_23;
          else if (ssh_xml_match(value, value_len, ssh_custr("24"), 0))
            algorithms |= SSH_PM_DH_GROUP_24;
#ifdef SSHDIST_CRYPT_ECP
          else if (ssh_xml_match(value, value_len, ssh_custr("19"), 0))
            algorithms |= SSH_PM_DH_GROUP_19;
          else if (ssh_xml_match(value, value_len, ssh_custr("20"), 0))
            algorithms |= SSH_PM_DH_GROUP_20;
          else if (ssh_xml_match(value, value_len, ssh_custr("21"), 0))
            algorithms |= SSH_PM_DH_GROUP_21;
          else if (ssh_xml_match(value, value_len, ssh_custr("25"), 0))
            algorithms |= SSH_PM_DH_GROUP_25;
          else if (ssh_xml_match(value, value_len, ssh_custr("26"), 0))
            algorithms |= SSH_PM_DH_GROUP_26;
#endif /* SSHDIST_CRYPT_ECP  */
          else
            {
              ssh_ipm_error(ctx, "Invalid PFS group specification `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      if (!ssh_pm_tunnel_set_pfs_groups(tunnel, algorithms))
        {
          ssh_ipm_error(ctx, "Invalid PFS group specification",
                        value_len, value);
          goto error;
        }

      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);

      if (set_preferences)
        {
          SshUInt8 preference = 255;

          while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
                 != NULL)
            {
              if (ssh_xml_match(value, value_len, ssh_custr("0"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_0,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_1,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_2,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("5"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_5,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("14"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_14,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("15"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_15,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("16"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_16,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("17"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_17,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("18"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_18,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("22"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_22,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("23"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_23,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("24"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_24,
                                                            preference))
                    goto error;
                }
#ifdef SSHDIST_CRYPT_ECP
              else if (ssh_xml_match(value, value_len, ssh_custr("19"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_19,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("20"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_20,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("21"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_21,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("25"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_25,
                                                            preference))
                    goto error;
                }
              else if (ssh_xml_match(value, value_len, ssh_custr("26"), 0))
                {
                  if (!ssh_pm_tunnel_set_pfs_group_preference(tunnel,
                                                            SSH_PM_DH_GROUP_26,
                                                            preference))
                    goto error;
                }
#endif /* SSHDIST_CRYPT_ECP  */

              else
                {
                  ssh_ipm_error(ctx, "Invalid IKE group specification `%.*s'",
                                value_len, value);
                  goto error;
                }
              preference--;
            }
        }

      ssh_ipm_pop(ctx);
    }
  /****************** Supported IKE versions *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-versions"), 0))
    {
      SshUInt8 *target;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      target = &parent->u.tunnel.ike_versions;

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No IKE version specified");
          goto error;
        }

      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
#ifdef SSHDIST_IKEV1
          if (ssh_xml_match(value, value_len, ssh_custr("1"), 0))
            *target |= SSH_PM_IKE_VERSION_1;
          else
#endif /* SSHDIST_IKEV1 */
            if (ssh_xml_match(value, value_len, ssh_custr("2"), 0))
              *target |= SSH_PM_IKE_VERSION_2;
            else
              {
                ssh_ipm_error(ctx, "Invalid IKE version specified `%.*s'",
                              value_len, value);
                goto error;
              }
        }

      ssh_ipm_pop(ctx);
    }
  /*************************** Access control group *************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("access-group"), 0))
    {
      SshUInt32 group_id;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (!ctx->state->data)
        {
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          ssh_ipm_error(ctx, "No access group specified");
          goto error;
        }

      group_id = ssh_ipm_lookup_group(ctx, ctx->state->data,
                                      ctx->state->data_len);
      if (group_id == 0)
        {
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          ssh_ipm_error(ctx, "Unknown access control group `%s'",
                        ctx->state->data);
          goto error;
        }

      if (!ssh_pm_rule_add_authorization_group_id(
                                                pm,
                                                parent->u.rule.rule,
                                                group_id))
        {
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          ssh_ipm_error(ctx, "Could not add access control group");
          goto error;
        }

      ssh_ipm_pop(ctx);
    }
  /******************************* SA lifetime ******************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("life"), 0))
    {
      SshUInt32 ival;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No life parameter specified");
          goto error;
        }

      if (!ssh_ipm_parse_number(ctx, ctx->state->data, &ival))
        {
          ssh_ipm_error(ctx,
                        "Invalid SA lifetime specification `%s'",
                        ctx->state->data);
          goto error;
        }

      if (ival)
        {
          if (ctx->state->u.life.type == SSH_PM_LIFE_SECONDS)
            {
              if (ival < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)
                {
                  ssh_ipm_error(ctx,
                                "SA lifetime %d seconds is too small. "
                                "Minimum allowed is %d seconds",
                                (unsigned long) ival,
                                2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME);
                  goto error;
                }
            }
          else
            {
              if (ival < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB)
                {
                  ssh_ipm_error(ctx,
                                "SA lifetime %d kB is too small. "
                                "Minimum allowed is %d kB",
                                (unsigned long) ival,
                                2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB);
                  goto error;
                }
            }
        }

      ssh_pm_tunnel_set_life(parent->u.tunnel.tunnel, ctx->state->u.life.type,
                             ival);

      /* Pop lifetime frame. */
      ssh_ipm_pop(ctx);
    }
  /************************************ CA **********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ca"), 0))
    {
#ifdef SSHDIST_IKE_CERT_AUTH
      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_CA);

      /* Was the CA certificate given in the config file? */
      if (ctx->state->data == NULL)
        {
          /* No it wasn't.  Do we have a file name? */
          if (ctx->state->u.ca.file)
            {
              /* Yes we have. */
              if (!ssh_read_gen_file(ctx->state->u.ca.file,
                                     &ctx->state->data, &ctx->state->data_len))
                {
                  ssh_ipm_error(ctx, "Could not read certificate file `%s'",
                                ctx->state->u.ca.file);
                  goto error;
                }
            }
          else
            {
              ssh_ipm_error(ctx, "No certificate specified");
              goto error;
            }
        }
      else
        {
          /* The certificate data was given.  Give a warning if also
             the file name was specified. */
          if (ctx->state->u.ca.file)
            ssh_ipm_warning(ctx,
                            "Both inlined CA certificate and a file name "
                            "specified: ignoring file `%s'",
                            ctx->state->u.ca.file);
        }
      /* Check our parent. */
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent != NULL);
      if (parent->type != SSH_IPM_XMLCONF_AUTH_DOMAIN)
        {
          SSH_XML_VERIFIER(0);
        }

      if (!ssh_pm_auth_domain_add_ca(pm,
                                     parent->u.auth_domain.auth_domain,
                                     ctx->state->data,
                                     ctx->state->data_len,
                                     ctx->state->u.ca.flags))
        {
          ssh_ipm_error(ctx, "Could not add CA certificate");
          goto error;
        }

      /* Pop the CA frame. */
      ssh_ipm_pop(ctx);
#else /* SSHDIST_IKE_CERT_AUTH */
      ssh_ipm_error(ctx, "Certificates not supported");
      goto error;
#endif /* SSHDIST_IKE_CERT_AUTH */
    }
  /************************** IKE SA window size ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-window-size"), 0))
    {
      SshUInt32 ike_window_size;
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

     if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No IKE window size specified");
          goto error;
        }

     if (!ssh_ipm_parse_number(ctx, ctx->state->data, &ike_window_size))
       {
         ssh_ipm_error(ctx,
                       "Invalid IKE window size specification `%s'",
                       ctx->state->data);
         goto error;
       }

     if (!ssh_pm_tunnel_set_ike_window_size(parent->u.tunnel.tunnel,
                                            ike_window_size))
       {
         ssh_ipm_error(ctx, "Cannot set IKE window size");
         goto error;
       }

     /* We want to allow updating the precedence of a tunnel's IKE
        window size inplace, i.e. without creating a new tunnel and
        reconfiguring all policy rules that reference that tunnel.
        So here we directly modify the original tunnel's IKE window. */
     if (parent->object->value.u.tunnel &&
         !ssh_pm_tunnel_set_ike_window_size(parent->object->value.u.tunnel,
                                            ike_window_size))
       {
         ssh_ipm_error(ctx, "Cannot set IKE window size");
         goto error;
       }
     ssh_ipm_pop(ctx);
    }
  /************************** Algorithms for IKE SAs ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ike-algorithms"), 0))
    {
      SshUInt32 algorithms = 0;

      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No IKE algorithms specified");
          goto error;
        }
      ssh_xml_value_enum_init(ctx->state->data, ctx->state->data_len,
                              SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len, ssh_custr("cipher1"), 0))
            algorithms |= SSH_PM_CRYPT_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("cipher2"), 0))
            algorithms |= SSH_PM_CRYPT_EXT2;
#ifndef HAVE_FIPSLIB
#ifdef SSH_IPSEC_CRYPT_DES
          else if (ssh_xml_match(value, value_len, ssh_custr("des"), 0))
            algorithms |= SSH_PM_CRYPT_DES;
#endif /* SSH_IPSEC_CRYPT_DES */
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("3des"), 0))
            algorithms |= SSH_PM_CRYPT_3DES;
#ifdef SSHDIST_CRYPT_RIJNDAEL
          else if (ssh_xml_match(value, value_len, ssh_custr("aes"), 0))
            algorithms |= SSH_PM_CRYPT_AES;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ctr"), 0))
            algorithms |= SSH_PM_CRYPT_AES_CTR;
#ifdef SSHDIST_CRYPT_XCBCMAC
          else if (ssh_xml_match(value, value_len, ssh_custr("xcbc-aes"), 0))
            algorithms |= SSH_PM_MAC_XCBC_AES;
#endif /* SSHDIST_CRYPT_XCBCMAC */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else if (ssh_xml_match(value, value_len, ssh_custr("mac1"), 0))
            algorithms |= SSH_PM_MAC_EXT1;
          else if (ssh_xml_match(value, value_len, ssh_custr("mac2"), 0))
            algorithms |= SSH_PM_MAC_EXT2;
#ifndef HAVE_FIPSLIB
          else if (ssh_xml_match(value, value_len, ssh_custr("md5"), 0))
            algorithms |= SSH_PM_MAC_HMAC_MD5;
#endif /* !HAVE_FIPSLIB */
          else if (ssh_xml_match(value, value_len, ssh_custr("sha1"), 0))
            algorithms |= SSH_PM_MAC_HMAC_SHA1;
#ifdef SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE
          else if (ssh_xml_match(value, value_len, ssh_custr("sha2"), 0))
            algorithms |= SSH_PM_MAC_HMAC_SHA2;
#endif /* SSH_QUICKSEC_PM_CRYPT_SHA2_AVAILABLE */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSHDIST_CRYPT_MODE_GCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm"), 0))
            algorithms |= SSH_PM_CRYPT_AES_GCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-64"), 0))
            algorithms |= SSH_PM_CRYPT_AES_GCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-gcm-96"), 0))
            algorithms |= SSH_PM_CRYPT_AES_GCM_12;
          else if (ssh_xml_match(value, value_len, ssh_custr("gmac-aes"), 0))
            {
              ssh_ipm_error(ctx,
                            "Algorithm `%.*s' cannot be used with IKE, "
                            "use `aes' instead",
                            value_len, value);
              goto error;
            }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm"), 0))
            algorithms |= SSH_PM_CRYPT_AES_CCM;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-64"), 0))
            algorithms |= SSH_PM_CRYPT_AES_CCM_8;
          else if (ssh_xml_match(value, value_len, ssh_custr("aes-ccm-96"), 0))
            algorithms |= SSH_PM_CRYPT_AES_CCM_12;
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
          else
            {
              ssh_ipm_error(ctx, "Unknown algorithm `%.*s'",
                            value_len, value);
              goto error;
            }
        }

      /* Check that all required algorithms were specified. */
      if ((algorithms & SSH_PM_CRYPT_MASK) == 0)
        {
          ssh_ipm_error(ctx, "No cipher algorithm specified for IKE SA");
          goto error;
        }
      if ((algorithms & SSH_PM_MAC_MASK) == 0)
        {
          ssh_ipm_error(ctx, "No hash algorithm specified for IKE SA");
          goto error;
        }

      if (!ssh_pm_tunnel_set_ike_algorithms(parent->u.tunnel.tunnel,
                                            algorithms))
        {
          ssh_ipm_error(ctx, "Cannot set algorithms for IKE SA");
          goto error;
        }

      ssh_ipm_pop(ctx);
    }
  /************************** Manually configured SA ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("manual-key"), 0))
    {
      unsigned char *key;
      size_t key_len;
      size_t pos = 0;
      Boolean success;

      parent = ssh_ipm_parent(ctx, ctx->state);

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_MANUAL_KEY);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_TUNNEL);

      /* Check that all transforms were specified. */
      if (parent->u.tunnel.transform & SSH_PM_IPSEC_ESP)
        {
          if (ctx->state->u.manual_key.esp_spi_i == 0
              || ctx->state->u.manual_key.esp_spi_o == 0)
            {
              ssh_ipm_error(ctx, "No ESP transform configured");
              goto error;
            }
        }
      if (parent->u.tunnel.transform & SSH_PM_IPSEC_AH)
        {
          if (ctx->state->u.manual_key.ah_spi_i == 0
              || ctx->state->u.manual_key.ah_spi_o == 0)
            {
              ssh_ipm_error(ctx, "No AH transform configured");
              goto error;
            }
        }
      if (parent->u.tunnel.transform & SSH_PM_IPSEC_IPCOMP)
        {
          if (ctx->state->u.manual_key.ipcomp_cpi_i == 0
              || ctx->state->u.manual_key.ipcomp_cpi_o == 0)
            {
              ssh_ipm_error(ctx, "No IPCOMP transform configured");
              goto error;
            }
        }

      /* Create a key array. */
      key_len = (ctx->state->u.manual_key.encr_key_i_len
                 + ctx->state->u.manual_key.auth_key_i_len) * 2;
      key = ssh_calloc(key_len, 1);
      if (key == NULL)
        {
          ssh_ipm_error(ctx, "Could not allocate memory for keys");
          goto error;
        }

      /* Inbound keys. */
      memcpy(key + pos,
             ctx->state->u.manual_key.encr_key_i,
             ctx->state->u.manual_key.encr_key_i_len);
      pos += ctx->state->u.manual_key.encr_key_i_len;
      memcpy(key + pos,
             ctx->state->u.manual_key.auth_key_i,
             ctx->state->u.manual_key.auth_key_i_len);
      pos += ctx->state->u.manual_key.auth_key_i_len;

      /* Outbound keys. */
      memcpy(key + pos,
             ctx->state->u.manual_key.encr_key_o,
             ctx->state->u.manual_key.encr_key_o_len);
      pos += ctx->state->u.manual_key.encr_key_o_len;
      memcpy(key + pos,
             ctx->state->u.manual_key.auth_key_o,
             ctx->state->u.manual_key.auth_key_o_len);

      /* Configure the tunnel to be a manually keyed tunnel. */
      success = ssh_pm_tunnel_set_manual(parent->u.tunnel.tunnel,
                                         ctx->state->u.manual_key.esp_spi_i,
                                         ctx->state->u.manual_key.esp_spi_o,
                                         ctx->state->u.manual_key.ah_spi_i,
                                         ctx->state->u.manual_key.ah_spi_o,
                                         ctx->state->u.manual_key.ipcomp_cpi_i,
                                         ctx->state->u.manual_key.ipcomp_cpi_o,
                                         SSH_PM_BINARY,
                                         key, key_len);
      /* Free key array. */
      memset(key, 0, key_len);
      ssh_free(key);

      if (!success)
        {
          ssh_ipm_error(ctx, "Could not configure manual key for tunnel");
          goto error;
        }

      /* Manually keyed SA parsed. */
      ssh_ipm_pop(ctx);
    }
#ifdef SSH_IPSEC_TCPENCAP
  /************************** IPSec over TCP *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("tcpencap"), 0))
    {
      SshPmTunnel tunnel = NULL;

      parent = ssh_ipm_parent(ctx, ctx->state);
      if (parent->type == SSH_IPM_XMLCONF_TUNNEL)
        tunnel = parent->u.tunnel.tunnel;

      if (!ssh_pm_tcp_encaps_add_configuration(pm, tunnel,
                        &ctx->state->u.tcp_encaps_config.local_addr,
                        ctx->state->u.tcp_encaps_config.local_port,
                        &ctx->state->u.tcp_encaps_config.peer_lo_addr,
                        &ctx->state->u.tcp_encaps_config.peer_hi_addr,
                        ctx->state->u.tcp_encaps_config.peer_port,
                        ctx->state->u.tcp_encaps_config.local_ike_port))
        {
          ssh_ipm_error(ctx,
                        "Could not configure IPsec over TCP encapsulation");
          goto error;
        }

      /* IPSec over TCP encapsulation parsed. */
      ssh_ipm_pop(ctx);
    }
#endif /* SSH_IPSEC_TCPENCAP */


  /*********************************** Rule *********************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("rule"), 0))
    {
      SshIpmRule ipm_rule;
      SshUInt32 index;

      SSH_ASSERT(ctx->state->type == SSH_IPM_XMLCONF_RULE);
      SSH_ASSERT(ctx->state->u.rule.rule != NULL);

      /* Add the rule to policy manager. */
      index = ssh_pm_rule_add(pm, ctx->state->u.rule.rule);
      if (index == SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not add rule"));
          ssh_pm_rule_free(pm, ctx->state->u.rule.rule);
          ctx->state->u.rule.rule = NULL;
          goto error;
        }
      ctx->state->u.rule.rule = NULL;

      /* Lookup the IPM rule object. */
      ipm_rule = ssh_ipm_xmlconf_rule_get(ctx, ctx->state->u.rule.precedence);
      if (ipm_rule == NULL)
        /* Out of memory. */
        goto error;

      /* This rule is seen. */
      ipm_rule->seen = 1;

      /* Do we have an old rule? */
      if (ipm_rule->rule != SSH_IPSEC_INVALID_INDEX)
        {
          /* Yes we have.  Let's see if this is a reconfiguration. */
          if (ssh_pm_rule_compare(pm, ipm_rule->rule, index))
            {
              /* The rule is identitical to the old one.  Delete the
                 new rule. */
              SSH_DEBUG(SSH_D_LOWOK, ("Rule is identical to the old rule"));
              ssh_pm_rule_delete(pm, index);
            }
          else
            {
              /* The rule has been reconfigured. */
              SSH_DEBUG(SSH_D_LOWOK, ("Rule reconfigured"));
              ipm_rule->new_rule = index;
            }
        }
      else
        {
          /* No old rule. */
          SSH_DEBUG(SSH_D_LOWOK, ("No old rule"));
          ipm_rule->new_rule = index;
        }

      /* Done with this rule object. */
      ssh_ipm_pop(ctx);
    }
  /**************************** Source IP address ***************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("src"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No source address specified");
          goto error;
        }
      if (!ssh_pm_rule_set_traffic_selector(parent->u.rule.rule,
                                            SSH_PM_FROM,
                                            ctx->state->data))
        {
          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;
        }

      ssh_ipm_pop(ctx);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("src-dns"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (!ssh_pm_rule_set_dns(parent->u.rule.rule, SSH_PM_FROM,
                               ctx->state->data))
        {
          ssh_ipm_error(ctx,
                        "Could not set source address DNS selector. This "
                        "field must contain a DNS name only.");

          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;

        }
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /************************** Destination IP address ************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("dst"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (!ctx->state->data)
        {
          ssh_ipm_error(ctx, "No destination address specified");
          goto error;
        }
      if (!ssh_pm_rule_set_traffic_selector(parent->u.rule.rule,
                                            SSH_PM_TO,
                                            ctx->state->data))
        {
          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;
        }

      ssh_ipm_pop(ctx);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("dst-dns"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (!ssh_pm_rule_set_dns(parent->u.rule.rule, SSH_PM_TO,
                               ctx->state->data))
        {
          ssh_ipm_error(ctx,
                        "Could not set destination address DNS selector. "
                        "This field must contain a DNS name only.");
          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;

        }
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /****************************** Interface name ****************************/
  else if (ssh_xml_match(name, name_len, ssh_custr("ifname"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (ctx->state->data == NULL)
        {
          ssh_ipm_error(ctx, "No interface name specified");
          goto error;
        }

      if (!ssh_pm_rule_set_ifname(parent->u.rule.rule,
                                  (char *) ctx->state->data))
        {
          ssh_ipm_error(ctx, "Could not configure interface selector `%s'",
                        (char *) ctx->state->data);

          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;
        }

      /* Interface name selector parsed. */
      ssh_ipm_pop(ctx);
    }
#ifdef SSHDIST_IPSEC_DNSPOLICY
  else if (ssh_xml_match(name, name_len, ssh_custr("routed-ifname"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_RULE);

      if (ctx->state->data == NULL)
        {
          ssh_ipm_error(ctx, "No remote address specified for ifname");
          goto error;
        }

      if (!ssh_pm_rule_set_interface_from_route(parent->u.rule.rule,
                                                (char *) ctx->state->data))
        {
          ssh_ipm_error(ctx,
                        "Could not configure interface selector remote=`%s'",
                        (char *) ctx->state->data);

          /* Free the rule. */
          ssh_pm_rule_free(pm, parent->u.rule.rule);
          parent->u.rule.rule = NULL;
          goto error;
        }

      /* Interface from routing selector parsed. */
      ssh_ipm_pop(ctx);
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  else if (ssh_xml_match(name, name_len, ssh_custr("radius-accounting"), 0))
    {
      parent = ssh_ipm_parent(ctx, ctx->state);
      SSH_ASSERT(parent->type == SSH_IPM_XMLCONF_PARAMS);

      ssh_ipm_pop(ctx);
    }

  /* All done. */
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;

  /* Error handling. */

 error:
  (*result_cb)(SSH_XML_ERROR, result_cb_context);
  return NULL;
}


static SshOperationHandle
ssh_ipm_xml_characters(SshXmlParser parser,
                       const unsigned char *data, size_t data_len,
                       Boolean all_whitespace,
                       SshXmlResultCB result_cb, void *result_cb_context,
                       void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;

  /* Append data if we are parsing an element. */
  if (ctx->state)
    {
      if (!ssh_ipm_append_data(&ctx->state->data, &ctx->state->data_len,
                               data, data_len))
        {
          ssh_ipm_error(ctx, "Could not store character data");
          (*result_cb)(SSH_XML_ERROR, result_cb_context);
          return NULL;
        }
    }

  /* All done. */
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

SSH_RODATA
static const SshXmlContentHandlerStruct ssh_ipm_xml_content_handler =
{
  NULL_FNPTR,
  NULL_FNPTR,
  ssh_ipm_xml_start_element,
  ssh_ipm_xml_end_element,
  ssh_ipm_xml_characters,
  NULL_FNPTR,
  NULL_FNPTR,
};


/* Error handler. */

static void
ssh_ipm_xml_warning(SshXmlParser parser,
                    const char *input_name, SshUInt32 line, SshUInt32 column,
                    const char *warning, void *context)
{
  fprintf(stderr, "%s:%lu: warning: %s\n",
          input_name, (unsigned long) line, warning);
}


static void
ssh_ipm_xml_error(SshXmlParser parser, const char *input_name,
                  SshUInt32 line, SshUInt32 column,
                  const char *error, void *context)
{
  fprintf(stderr, "%s:%lu: %s\n",
          input_name, (unsigned long) line, error);
}

SSH_RODATA
static const SshXmlErrorHandlerStruct ssh_ipm_xml_error_handler =
{
  ssh_ipm_xml_warning,
  ssh_ipm_xml_error,
  ssh_ipm_xml_error,
};


/* Handling system resources. */

/* HTTP resources. */
#ifdef SSHDIST_HTTP_CLIENT

/* Context structure for HTTP operations. */
struct SshIpmXmlHttpCtxRec
{
  SshHttpClientContext http_ctx;
  SshXmlStreamCB result_cb;
  void *result_cb_context;
  char *url;

  SshOperationHandle http_handle;
  SshOperationHandleStruct handle;
};

typedef struct SshIpmXmlHttpCtxRec SshIpmXmlHttpCtxStruct;
typedef struct SshIpmXmlHttpCtxRec *SshIpmXmlHttpCtx;

/* Destructor for the HTTP resource. */
static void
ssh_ipm_xml_http_destructor(void *context)
{
  SshIpmXmlHttpCtx ctx = (SshIpmXmlHttpCtx) context;

  ssh_http_client_uninit(ctx->http_ctx);
  ssh_free(ctx->url);
  ssh_free(ctx);
}

/* Abort callback for asynchronous HTTP system resource operations. */
static void
ssh_ipm_xml_http_abort_cb(void *context)
{
  SshIpmXmlHttpCtx ctx = (SshIpmXmlHttpCtx) context;

  /* Abort the pending HTTP operation. */
  SSH_ASSERT(ctx->http_handle != NULL);
  ssh_operation_abort(ctx->http_handle);

  /* And destroy our context. */
  ssh_ipm_xml_http_destructor(ctx);
}

/* Result callback for an HTTP operation. */
static void
ssh_ipm_xml_http_result_cb(SshHttpClientContext client_ctx,
                           SshHttpResult result,
                           SshTcpError ip_error,
                           SshStream stream,
                           void *callback_context)
{
  SshIpmXmlHttpCtx ctx = (SshIpmXmlHttpCtx) callback_context;

  /* This completes our system resource operation and invalidates the
     operation handle. */
  ssh_operation_unregister(&ctx->handle);

  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      (*ctx->result_cb)(NULL, NULL, NULL_FNPTR, NULL, ctx->result_cb_context);
      ssh_ipm_xml_http_destructor(ctx);
      return;
    }

  (*ctx->result_cb)(stream, ctx->url, ssh_ipm_xml_http_destructor, ctx,
                    ctx->result_cb_context);
}

/* HTTP resources. */
static SshOperationHandle
ssh_ipm_system_resource_http(SshXmlParser parser, const unsigned char *url,
                             SshXmlStreamCB result_cb, void *result_cb_context,
                             SshIpmContext ipm_ctx)
{
  SshIpmXmlHttpCtx ctx;
  SshHttpClientParams params;
  SshOperationHandle handle;

  memset(&params, 0, sizeof(params));
  params.socks = ssh_sstr(ipm_ctx->params->socks_url);
  params.http_proxy_url = ipm_ctx->params->http_proxy_url;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;

  ctx->url = ssh_strdup(url);
  if (ctx->url == NULL)
    goto error;

  ctx->http_ctx = ssh_http_client_init(&params);
  if (ctx->http_ctx == NULL)
    goto error;

  ctx->result_cb = result_cb;
  ctx->result_cb_context = result_cb_context;

  /* Start an HTTP operation. */
  handle = ssh_http_get(ctx->http_ctx, ssh_csstr(url),
                        ssh_ipm_xml_http_result_cb, ctx, SSH_HTTP_HDR_END);
  if (handle == NULL)
    {
      /* The HTTP operation was synchronous and our context is already
         freed and the result callback is called. */
      return NULL;
    }

  /* Asynchronous operation. */
  ctx->http_handle = handle;

  /* Create an operation handle for our operation. */
  ssh_operation_register_no_alloc(&ctx->handle, ssh_ipm_xml_http_abort_cb,
                                  ctx);

  return &ctx->handle;


  /* Error handling. */

 error:

  if (ctx)
    {
      ssh_free(ctx->url);
      ssh_free(ctx);
    }

  ssh_ipm_error(ipm_ctx,
                "Could not fetch HTTP resource `%s': out of memory", url);
  (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);

  return NULL;
}
#endif /* SSHDIST_HTTP_CLIENT */

/* File resources. */
static SshOperationHandle
ssh_ipm_system_resource_file(SshXmlParser parser, const unsigned char *name,
                             SshXmlStreamCB result_cb, void *result_cb_context,
                             SshIpmContext ipm_ctx)
{
#ifndef VXWORKS
  SshStream stream;

  stream = ssh_stream_fd_file(ssh_csstr(name), TRUE, FALSE);
  if (stream == NULL)
    {
      ssh_ipm_error(ipm_ctx, "Could not open file `%s'", name);
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
    }
  else
    {
      /* Stream opened. */
      (*result_cb)(stream, ssh_csstr(name), NULL_FNPTR, NULL,
                   result_cb_context);
    }

  return NULL;
#else
/* VxWorks ram-disk driver does not support select().
   Therefore configuration file is read using blocking read to avoid
   ssh_event_loop_run() doing select() on such file descriptors. */

  SshStream stream = NULL;
  unsigned char *data;
  size_t len;

  if (ssh_read_file(ssh_csstr(name), &data, &len))
    {
      stream = ssh_data_stream_create(data, len, FALSE);
      ssh_free(data);
    }

  if (stream == NULL)
    {
      ssh_ipm_error(ipm_ctx, "Could not open file `%s'", name);
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
    }
  else
    {
      /* Stream opened. */
      (*result_cb)(stream, ssh_csstr(name), NULL_FNPTR, NULL,
           result_cb_context);
    }

  return NULL;
#endif
}

/* Handling system resources. */
static SshOperationHandle
ssh_ipm_system_resource(SshXmlParser parser,
                        const unsigned char *sysid, size_t sysid_len,
                        SshXmlStreamCB result_cb, void *result_cb_context,
                        SshIpmContext ctx, Boolean recursive)
{
  unsigned char *scheme = NULL;
  unsigned char *path = NULL;
  SshOperationHandle handle = NULL;
  size_t len;

  /* First, consider system ID as an URL. */
  if (ssh_url_parse(sysid, &scheme, NULL, NULL, NULL, NULL, &path))
    {
      if (scheme != NULL)
        {
#ifdef SSHDIST_HTTP_CLIENT
          /* It is in an URL format. */
          if (ssh_usstrcmp(scheme, "http") == 0)
            {
              handle = ssh_ipm_system_resource_http(parser, sysid, result_cb,
                                                    result_cb_context, ctx);
            }
          else
#endif /* SSHDIST_HTTP_CLIENT */
          if ((ssh_usstrcmp(scheme, "file") == 0) && (path != NULL))
            {
              handle = ssh_ipm_system_resource_file(parser, path, result_cb,
                                                    result_cb_context, ctx);
            }
          else
            {
              /* An unsupported external resource scheme. */
            error:
              (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
            }
          ssh_free(scheme);
          ssh_free(path);

          return handle;
        }
      ssh_free(path);
    }

  /* Is it a relative path? */
  if (sysid[0] != '/' && sysid[0] != '.' && !recursive)
    {
      /* Yes it is.  Append it to our prefix and retry. */

      len = strlen(ctx->prefix) + ssh_ustrlen(sysid) + 1;
      path = ssh_calloc(1, len);
      if (path == NULL)
        goto error;

      path[0] = '\0';
      strcat(ssh_sstr(path), ctx->prefix);
      ssh_ustrcat(path, sysid);

      /* Retry with prefix. */
      handle = ssh_ipm_system_resource(parser, path, ssh_ustrlen(path),
                                       result_cb, result_cb_context, ctx,
                                       TRUE);
      ssh_free(path);

      return handle;
    }

  /* Let's try to read it as a file resource. */
  return ssh_ipm_system_resource_file(parser, sysid, result_cb,
                                      result_cb_context, ctx);
}


/* Entity resolver. */

/* Return string `string' as a stream using the callback `result_cb'.
   The argument `name' gives a name for the source of the string. */
static void
ssh_ipm_return_string(const unsigned char *string, const unsigned char *name,
                      SshXmlStreamCB result_cb, void *result_cb_context)
{
  SshStream stream;

  stream = ssh_data_stream_create(string, ssh_ustrlen(string), FALSE);
  (*result_cb)(stream, ssh_csstr(name), NULL_FNPTR, NULL, result_cb_context);
}

/* Function for handling `ifname()' entities. */

/* Interface type for resolving interface names. */
typedef enum
{
  SSH_IPM_XML_E_IFNAME_ANY,
  SSH_IPM_XML_E_IFNAME_LOOPBACK,
  SSH_IPM_XML_E_IFNAME_PHYSICAL
} SshIpmXmlEntityIfnameType;

static SshOperationHandle
ssh_ipm_xml_entity_ifname(SshIpmContext ctx,
                          const unsigned char *pubid, size_t pubid_len,
                          SshXmlStreamCB result_cb,
                          void *result_cb_context)
{
  size_t i;
  SshUInt32 ifnum = 0;
  SshUInt32 ifindex = 0;
  Boolean retval;
  SshIpmXmlEntityIfnameType type = SSH_IPM_XML_E_IFNAME_ANY;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  SSH_ASSERT(pubid_len > 0);
  SSH_ASSERT(pubid[0] == '(');

  pubid++;
  pubid_len--;

  /* Parse the interface number. */
  for (i = 0; i < pubid_len && SSH_IPM_IS_DEC(pubid[i]); i++)
    {
      ifnum *= 10;
      ifnum += pubid[i] - '0';
    }
  if (i == 0 || i >= pubid_len || (pubid[i] != ',' && pubid[i] != ')'))
    goto error;

  /* Check the type of the interface being queried. */
  if (pubid[i] == ',')
    {
      size_t start;

      /* Skip leading whitespace. */
      for (i++; i < pubid_len && SSH_IPM_IS_SPACE(pubid[i]); i++)
        ;
      if (i >= pubid_len)
        goto error;

      start = i;

      /* Find the end of the type. */
      for (;
           i < pubid_len && pubid[i] != ')' && !SSH_IPM_IS_SPACE(pubid[i]);
           i++)
        ;
      if (i == start || i >= pubid_len)
        goto error;

      if (ssh_xml_match(pubid + start, i - start, ssh_custr("any"), 0))
        type = SSH_IPM_XML_E_IFNAME_ANY;
      else if (ssh_xml_match(pubid + start, i - start, ssh_custr("loopback"),
                             0))
        type = SSH_IPM_XML_E_IFNAME_LOOPBACK;
      else if (ssh_xml_match(pubid + start, i - start, ssh_custr("physical"),
                             0))
        type = SSH_IPM_XML_E_IFNAME_PHYSICAL;
      else
        goto error;
    }

  /* Skip trailing whitespace. */
  for (; i < pubid_len && SSH_IPM_IS_SPACE(pubid[i]); i++)
    ;

  if (i >= pubid_len || pubid[i] != ')' || i + 1 != pubid_len)
    goto error;

  /* Lookup the interface name. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Looking up interface %u of type `%s'",
                             (unsigned int) ifnum,
                             (type == SSH_IPM_XML_E_IFNAME_ANY
                              ? "any"
                              : (type == SSH_IPM_XML_E_IFNAME_PHYSICAL
                                 ? "physical"
                                 : "loopback"))));

  /* Iterate through all interfaces. */
  ifindex = 0;
  for (retval = ssh_pm_interface_enumerate_start(pm, &ifindex);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifindex, &ifindex))
    {
      char *ifname;
      SshUInt32 addrcount;

      /* Consider only valid interfaces with IP addresses. */
      if (!ssh_pm_get_interface_name(pm, ifindex, &ifname))
        continue;
      if (!ssh_pm_interface_get_number_of_addresses(pm,
                                                    ifindex,
                                                    &addrcount))
        continue;
      if (addrcount == 0)
        continue;

      if (type == SSH_IPM_XML_E_IFNAME_ANY)
        {
          /* No special checks for any interfaces. */
        }
      else
        {
          SshUInt32 j;
          SshIpAddrStruct ip;

          /* Determine whether this interface is a loopback interface. */
          for (j = 0; j < addrcount; j++)
            {
              if (!ssh_pm_interface_get_address(pm, ifindex, j, &ip))
                continue;

              if (SSH_IP_IS_LOOPBACK(&ip))
                /* Found a loopback address. */
                break;
            }

          if (j < addrcount)
            {
              /* This is a loopback interface. */
              if (type != SSH_IPM_XML_E_IFNAME_LOOPBACK)
                /* We are not interested in this interface. */
                continue;
            }
          else
            {
              /* This is not a loopback interface. */
              if (type == SSH_IPM_XML_E_IFNAME_LOOPBACK)
                /* We are not interested in this interface. */
                continue;
            }
        }

      /* One more interface of correct type. */
      if (ifnum == 0)
        {
          /* This is our interface. */
          SSH_DEBUG(SSH_D_LOWOK, ("Found interface `%s'", ifname));
          ssh_ipm_return_string(ifname, pubid, result_cb, result_cb_context);
          return NULL;
        }

      /* Search more. */
      ifnum--;
    }

  /* No valid interface found. */
  SSH_DEBUG(SSH_D_FAIL, ("No valid interface found"));
  /* FALLTHROUGH */


  /* Error handling. */

 error:

  SSH_DEBUG(SSH_D_FAIL, ("Unknown public ID `ifname(%s'", pubid));
  (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);

  return NULL;
}

/* Entity resolver callback. */
static SshOperationHandle
ssh_ipm_xml_entity_resolver(SshXmlParser parser,
                            const char *where_defined,
                            Boolean general,
                            const unsigned char *name, size_t name_len,
                            const unsigned char *pubid, size_t pubid_len,
                            const unsigned char *sysid, size_t sysid_len,
                            SshXmlStreamCB result_cb,
                            void *result_cb_context,
                            void *context)
{
  SshIpmContext ctx = (SshIpmContext) context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Entity `%s'", name ? (char *) name : "<null>"));

  /* Handle built-in entities.  */
  if (pubid)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Public ID `%s'", pubid));

      if (ssh_xml_match(pubid, pubid_len,
                        ssh_custr("quicksec:hostname"), 0))
        {
          ssh_tcp_get_host_name(ctx->buf, sizeof(ctx->buf));
          ssh_ipm_return_string(ctx->buf, pubid, result_cb, result_cb_context);
        }
      else if (ssh_xml_match(pubid, pubid_len,
                             ssh_custr("quicksec:version"), 0))
        {
          ssh_ipm_return_string(ssh_custr(SSH_IPSEC_VERSION), pubid,
                                result_cb, result_cb_context);
        }
      else
        {
          size_t i;

          /* Handle function-like entities. */
          for (i = 0; i < pubid_len && pubid[i] != '('; i++)
            ;
          if (i < pubid_len)
            {
              if (ssh_xml_match(pubid, i, ssh_custr("quicksec:ifname"), 0))
                return ssh_ipm_xml_entity_ifname(ctx,
                                                 pubid + i, pubid_len - i,
                                                 result_cb, result_cb_context);
            }

          /* Unknown entity. */
          SSH_DEBUG(SSH_D_FAIL, ("Unknown public ID `%s'", pubid));
          (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
        }

      return NULL;
    }

  /* Handle system entities. */
  if (sysid)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("System ID `%s'", sysid));
      return ssh_ipm_system_resource(parser, sysid, sysid_len,
                                     result_cb, result_cb_context, ctx, FALSE);
    }

  /* Can't handle this entity. */
  (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
  return NULL;
}

/* DTD callback. */
static SshOperationHandle
ssh_ipm_xml_dtd_callback(SshXmlParser parser,
                         const unsigned char *pubid, size_t pubid_len,
                         const unsigned char *sysid, size_t sysid_len,
                         SshXmlStreamCB result_cb, void *result_cb_context,
                         void *context)
{
  SshStream stream = NULL;
  char *name = NULL;
  SshIpmContext ctx = context;

  /* Only pubid is supported. */
  if (pubid)
    {
      if (ssh_xml_match(pubid, pubid_len, ssh_custr("quicksec:dtd"), 0))
        {
          ctx->dtd_specified = 1;
          stream = ssh_data_stream_create(quicksec_dtd,
                                          quicksec_dtd_len, TRUE);
          if (stream)
            name = (char *) pubid;
        }
    }

  (*result_cb)(stream, name, NULL_FNPTR, NULL, result_cb_context);
  return NULL;
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_ipm_st_config_start);
SSH_FSM_STEP(ssh_ipm_st_config_bootstrap_rule);
SSH_FSM_STEP(ssh_ipm_st_config_bootstrap_commit);
SSH_FSM_STEP(ssh_ipm_st_config_auth_reset);
SSH_FSM_STEP(ssh_ipm_st_config_parse);
SSH_FSM_STEP(ssh_ipm_st_config_parse_stream);
SSH_FSM_STEP(ssh_ipm_st_config_parse_result);
SSH_FSM_STEP(ssh_ipm_st_config_commit);
SSH_FSM_STEP(ssh_ipm_st_config_commit_result);
SSH_FSM_STEP(ssh_ipm_st_config_commit_unused);
SSH_FSM_STEP(ssh_ipm_st_config_commit_unused_result);
SSH_FSM_STEP(ssh_ipm_st_config_commit_done);
SSH_FSM_STEP(ssh_ipm_st_config_error);
SSH_FSM_STEP(ssh_ipm_st_config_terminate);
SSH_FSM_STEP(ssh_ipm_st_config_done);


SSH_FSM_STEP(ssh_ipm_st_config_start)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  /* Handle the bootstrap configuration.

     The bootstrap rule is installed during PM startup before the
     configuration file is opened. The bootstrap rule is destroyed
     when the policy rules from the initial configuration are committed.

     The bootstrap rule is always of the following type:

     <rule>
       <local-stack direction="from"/>
       <dst> bootstrap traffic selector </dst>
     </rule>

     The bootstrap traffic selector can be given as a command line option,
     or, if it is not given and the configuration filename is a http or https
     url, the bootstrap traffic selector will be generated from the url. */
  if (!ctx->bootstrap_done)
    {
      unsigned char *scheme = NULL;
      unsigned char *host = NULL;
      unsigned char *port = NULL;

      SshUInt16 portnum;
      SshIpAddrStruct ip;
      char *ipproto;

      /* Check if bootstrap rule was given on command line. */
      if (ctx->params->bootstrap_traffic_selector != NULL)
        {

          SSH_ASSERT(ctx->bootstrap.traffic_selector == NULL);
          ctx->bootstrap.traffic_selector =
            ssh_strdup(ctx->params->bootstrap_traffic_selector);
        }

      /* Check the type of our configuration file. */
      else if (ssh_url_parse(ctx->params->config_file, &scheme, &host, &port,
                        NULL, NULL, NULL))
        {
          if ((scheme != NULL) && (ssh_usstrcmp(scheme, "file") != 0))
            {
              if (ssh_usstrcmp(scheme, "http") == 0)
                portnum = 80;
              else if (ssh_usstrcmp(scheme, "https") == 0)
                portnum = 443;
              else
                {
                  /* An unknown method. */
                  fprintf(stderr, "%s: Unknown protocol `%s'\n",
                          ctx->params->program, scheme);
                error:
                  ssh_free(scheme);
                  ssh_free(host);
                  ssh_free(port);
                  SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);

                  return SSH_FSM_CONTINUE;
                }

              if (port)
                portnum = ssh_uatoi(port);

              ipproto = "tcp";

              if (host == NULL)
                {
                  fprintf(stderr, "%s: No host specified in URL `%s'\n",
                          ctx->params->program,
                          ctx->params->config_file);
                  goto error;
                }

              if (!ssh_ipaddr_parse(&ip, host)
                  || (!SSH_IP_IS4(&ip) && SSH_IP_IS6(&ip)))
                {
                  fprintf(stderr, "%s: Invalid IP address `%s'\n",
                          ctx->params->program, host);
                  goto error;
                }

              SSH_ASSERT(ctx->bootstrap.traffic_selector == NULL);

              if (SSH_IP_IS4(&ip))
                ssh_dsprintf((unsigned char **)
                             &ctx->bootstrap.traffic_selector,
                             "ipv4(%s:%d,%@)",
                             ipproto, portnum, ssh_ipaddr_render, &ip);
              else
                ssh_dsprintf((unsigned char **)
                             &ctx->bootstrap.traffic_selector,
                             "ipv6(%s:%d,%@)",
                             ipproto, portnum, ssh_ipaddr_render, &ip);
            }
          else
            {
              /* A configuration file. */
              ctx->bootstrap_done = 1;
            }
          ssh_free(scheme);
          ssh_free(host);
          ssh_free(port);
        }
      else
        {
          /* A configuration file. */
          ctx->bootstrap_done = 1;
        }

      /* Do we need a rule to protect the bootstrap configuration? */
      if (!ctx->bootstrap_done)
        {
          /* Yes we need. */
          SSH_FSM_SET_NEXT(ssh_ipm_st_config_bootstrap_rule);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Parse policy file. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_auth_reset);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_bootstrap_rule)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  if (!ssh_ipm_create_bootstrap_policy(ctx))
    {
      fprintf(stderr, "%s: Could not create bootstrap pass policy\n",
              ctx->params->program);
      SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);
      return SSH_FSM_CONTINUE;
    }

  /* Commit the bootstrap policy */
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_bootstrap_commit);
  SSH_FSM_ASYNC_CALL({
    ctx->commit_called = 1;
    (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
               ssh_ipm_bootstrap_commit_cb, ctx);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_config_bootstrap_commit)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  if (!ctx->bootstrap.success)
    {
      fprintf(stderr, "%s: Could not create bootstrap policy\n",
              ctx->params->program);
      SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);
    }
  else
    {
      SSH_FSM_SET_NEXT(ssh_ipm_st_config_auth_reset);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_auth_reset)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx,
                        SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_pm_reset_auth_domains(pm))
    {
      /* This failure prevents us from succesfully reconfiguring policy.
         We will continue to xml-parsing and use failing mechanism there. */
      ctx->auth_domain_reset_failed = 1;
    }

  /* Reset the legacy authentication parameters also */
  while (ctx->la_client_auth)
    {
      SshIpmLegacyAuthClientAuth auth;

      auth = ctx->la_client_auth;
      ctx->la_client_auth = auth->next;

      ipm_legacy_client_auth_unref(auth);
    }

  ctx->la_client_auth = NULL;

  SSH_FSM_SET_NEXT(ssh_ipm_st_config_parse);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_parse)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  /* Resolve our configuration URL into a stream.  Call the system
     resource handler with `recursive' set to TRUE so that we won't
     consider the initial configuration file as relative path. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_parse_stream);
  SSH_FSM_ASYNC_CALL(ctx->parse_operation =
                     ssh_ipm_system_resource(ctx->parser,
                                             ctx->params->config_file,
                                             ssh_ustrlen(ctx->params->
                                                         config_file),
                                             ssh_ipm_config_stream_cb, thread,
                                             ctx, TRUE));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_config_parse_stream)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  if (ctx->config.stream == NULL)
    {
      fprintf(stderr, "%s: Could not open config file `%s'\n",
              ctx->params->program, ctx->params->config_file);
      SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);
      return SSH_FSM_CONTINUE;
    }

  /* Clear temporary configuration data. */
  memset(&ctx->config_parameters, 0,
         sizeof(ctx->config_parameters));

  /* Parse the configuration file. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_parse_result);
  SSH_FSM_ASYNC_CALL({
    ctx->dtd_specified = 0;
    ctx->parse_operation =
      ssh_xml_parser_parse_stream(ctx->parser, FALSE,
                                  ctx->config.stream,
                                  ctx->config.stream_name,
                                  ctx->config.destructor_cb,
                                  ctx->config.destructor_cb_context,
                                  ssh_ipm_parse_result_cb,
                                  thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_config_parse_result)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* The parsing is completed either successfully or unsuccessfully. */
  if (ctx->parse_result == FALSE ||
      ctx->auth_domain_reset_failed == 1)
    {
    fail:
      /* Operation failed.  Abort any pending policy modification
         operation now. */
      SSH_ASSERT(!ctx->commit_called);
      ssh_pm_abort(pm);

      /* Purge all partially read policy objects from the policy
         manager context. */
      ssh_ipm_purge_new_policy_objects(ctx);
      SSH_FSM_SET_NEXT(ssh_ipm_st_config_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Update PM, IKE, and engine parameters. */
  if (!ssh_ipm_update_params(ctx))
    goto fail;

  SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_commit)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  /* Commit our rule changes. */

  SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit_result);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SSH_DEBUG(SSH_D_LOWSTART, ("Indicating DNS name changes"));
  if (ctx->dns_names_allowed && do_indicate && !ctx->aborted)
    {
      SSH_FSM_ASYNC_CALL({
        ctx->sub_operation =
          ssh_pm_indicate_dns_change(pm,
                                     NULL, NULL,
                                     ssh_pm_indicate_cb, ctx);
      });
    }
  else
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    {
      ctx->commit_called = 1;
      SSH_FSM_ASYNC_CALL({
        (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
                   ssh_ipm_pm_commit_cb, ctx);
      });
    }

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_config_commit_result)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;
      SshADTHandle h, hnext;
      SshIpmRule rule;

  if (ctx->commit_failed)
    SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);
  else
    {
#ifdef SSHDIST_IPSEC_DNSPOLICY
      if (ctx->dns_names_allowed && do_indicate)
        SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit_unused);
      else
#endif /* SSHDIST_IPSEC_DNSPOLICY */
        {
          /* If we do not have DNSPOLICY, no need to go to
             unused commit. */
          SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit_done);

          SSH_DEBUG(SSH_D_LOWOK, ("Unused rules deleted"));

          /* Now, remove them from the rule container. */
          for (h = ssh_adt_enumerate_start(ctx->rules);
               h != SSH_ADT_INVALID;
               h = hnext)
            {
              hnext = ssh_adt_enumerate_next(ctx->rules, h);
              rule = ssh_adt_get(ctx->rules, h);

              if (rule->unused)
                ssh_adt_delete(ctx->rules, h);
            }
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_commit_unused)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit_unused_result);

  /* Delete unused rules. */
  ctx->commit_called = 1;
  SSH_FSM_ASYNC_CALL({
    (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
               ssh_ipm_unused_commit_cb, ctx);
  });

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_config_commit_unused_result)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  if (ctx->commit_failed)
    SSH_FSM_SET_NEXT(ssh_ipm_st_config_error);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_st_config_commit_done);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_commit_done)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  /* Purge old policy objects */
  ssh_ipm_purge_old_policy_objects(ctx);

  SSH_FSM_SET_NEXT(ssh_ipm_st_config_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_error)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  ctx->parse_result = FALSE;
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_terminate);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_terminate)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* Free temporary configuration parameters. */
#ifdef SSHDIST_IPSEC_NAT
  while (ctx->config_parameters.nat_list != NULL)
    {
      SshIpmNatConfig nat;
      nat = ctx->config_parameters.nat_list;
      ctx->config_parameters.nat_list = nat->next;
      if (nat->ifname)
        ssh_free(nat->ifname);
      ssh_free(nat);
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  ssh_free(ctx->config_parameters.internal_nat_first);
  ssh_free(ctx->config_parameters.internal_nat_last);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#endif /* SSHDIST_IPSEC_NAT */

  memset(&ctx->config_parameters, 0,
         sizeof(ctx->config_parameters));

  /* Free dynamically allocate stream name. */
  ssh_free(ctx->config.stream_name);

  /* Free all possible temporary parsing state from the context. */
  while (ctx->state)
    ssh_ipm_pop(ctx);

  /* Clear buffers. */
  ssh_buffer_clear(&ctx->ldap_servers);

  if (!ctx->bootstrap_done)
    {
      /* The parsing is done and so is our bootstrap. */
      ctx->bootstrap_done = 1;
      SSH_ASSERT(ctx->bootstrap.rule != SSH_IPSEC_INVALID_INDEX);
      ssh_pm_rule_delete(pm, ctx->bootstrap.rule);

      SSH_FSM_SET_NEXT(ssh_ipm_st_config_done);
      SSH_FSM_ASYNC_CALL({
        ctx->commit_called = 1;
        (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_PM_COMMIT,
                   ssh_ipm_bootstrap_commit_cb, ctx);
      });
      SSH_NOTREACHED;
    }

  if (!ctx->initial_done)
    {
      ctx->parse_result = FALSE;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  if (ctx->radius_acct_client != NULL)
    {
      ssh_radius_client_destroy(ctx->radius_acct_client);
      ctx->radius_acct_client = NULL;
    }

  if (ctx->radius_acct_servers != NULL)
    {
      ssh_radius_client_server_info_destroy(ctx->radius_acct_servers);
      ctx->radius_acct_servers = NULL;
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  /* Configuration done. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_config_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_config_done)
{
  SshIpmContext ctx = (SshIpmContext) thread_context;

  /* Register a zero-timeout for calling the completion callback. */
  ssh_register_timeout(&ctx->timeout, 0, 0, ssh_ipm_parse_result_timeout, ctx);

  /* We are done. */
  ctx->parse_completed = 1;
  return SSH_FSM_FINISH;
}


/************************* Internal help functions **************************/

void
ssh_ipm_error(SshIpmContext ctx, const char *fmt, ...)
{
  va_list ap;
  const char *input_name;
  SshUInt32 line, column;

  va_start(ap, fmt);
  ssh_vsnprintf(ssh_sstr(ctx->buf), sizeof(ctx->buf), fmt, ap);
  va_end(ap);

  ssh_xml_location(ctx->parser, &input_name, &line, &column);
  if (input_name == NULL)
    input_name = "<initialization>";

  ssh_ipm_xml_error(ctx->parser, input_name, line, column,
                    ssh_csstr(ctx->buf), ctx);
}


void
ssh_ipm_warning(SshIpmContext ctx, const char *fmt, ...)
{
   va_list ap;
  const char *input_name;
  SshUInt32 line, column;

  va_start(ap, fmt);
  ssh_vsnprintf(ssh_sstr(ctx->buf), sizeof(ctx->buf), fmt, ap);
  va_end(ap);

  ssh_xml_location(ctx->parser, &input_name, &line, &column);
  if (input_name == NULL)
    input_name = "<initialization>";

  ssh_ipm_xml_warning(ctx->parser, input_name, line, column,
                      ssh_csstr(ctx->buf), ctx);

}


/****************** Public functions for XML configuration ******************/

SshIpmContext
ssh_ipm_context_create(void * pm_context, SshIpmParams params,
                       SshIpmCtxEventCB cb, void *cb_ctx)
{
  SshIpmContext ctx;
  SshXmlParamsStruct xml_params;
  SshXmlVerifierParamsStruct verifier_params;
  char *cp;
  SshPm pm;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    return NULL;

  memset(ctx, 0, sizeof(*ctx));

  ctx->start_time = ssh_time();
  ctx->pm = pm_context;
  ctx->params = params;
  ctx->cb = cb;
  ctx->cb_ctx = cb_ctx;

  /* Create a prefix that is used to relative system resources. */

  ctx->prefix = ssh_strdup(ctx->params->config_file);
  if (ctx->prefix == NULL)
    goto error;

  cp = strrchr(ctx->prefix, '/');
  if (cp)
    *(cp + 1) = '\0';
  else
    ctx->prefix[0] = '\0';

  /* Create an XML parser. */

  memset(&xml_params, 0, sizeof(xml_params));

  ctx->parser = ssh_xml_parser_create(&xml_params,
                                      &ssh_ipm_xml_content_handler,
                                      &ssh_ipm_xml_error_handler,
                                      NULL,
                                      ssh_ipm_xml_entity_resolver,
                                      NULL_FNPTR,
                                      ctx);
  if (ctx->parser == NULL)
    goto error;

  /* Create XML verifier. */

  memset(&verifier_params, 0, sizeof(verifier_params));
  verifier_params.no_attr_decl_override = TRUE;
  verifier_params.no_forward_id_refs = TRUE;

  ctx->verifier = ssh_xml_verifier_create(&verifier_params,
                                          ssh_ipm_xml_dtd_callback, ctx);
  if (ctx->verifier == NULL)
    goto error;

  /* Bind verifier and parser together. */
  if (!ssh_xml_parser_set_verifier(ctx->parser, ctx->verifier))
    goto error;

  /* Create ADT containers. */
  ctx->rules
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshIpmRuleStruct, adt_header),

                             SSH_ADT_HASH,      ssh_ipm_xmlconf_rule_hash,
                             SSH_ADT_COMPARE,   ssh_ipm_xmlconf_rule_compare,
                             SSH_ADT_DESTROY,   ssh_ipm_xmlconf_rule_destroy,
                             SSH_ADT_CONTEXT,   ctx,

                             SSH_ADT_ARGS_END);
  if (ctx->rules == NULL)
    goto error;

  ctx->audit_modules
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshIpmAuditStruct, adt_header),

                             SSH_ADT_HASH,      ssh_ipm_xmlconf_audit_hash,
                             SSH_ADT_COMPARE,   ssh_ipm_xmlconf_audit_compare,
                             SSH_ADT_DESTROY,   ssh_ipm_xmlconf_audit_destroy,
                             SSH_ADT_CONTEXT,   ctx,

                             SSH_ADT_ARGS_END);
  if (ctx->audit_modules == NULL)
    goto error;

  ctx->policy_objects
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshIpmPolicyObjectStruct,
                                               adt_header),

                             SSH_ADT_HASH,      ssh_ipm_xmlconf_object_hash,
                             SSH_ADT_COMPARE,   ssh_ipm_xmlconf_object_compare,
                             SSH_ADT_DESTROY,   ssh_ipm_xmlconf_object_destroy,
                             SSH_ADT_CONTEXT,   ctx,

                             SSH_ADT_ARGS_END);
  if (ctx->policy_objects == NULL)
    goto error;


  ctx->auth_groups
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshIpmAuthGroupIdStruct,
                                               adt_header),

                             SSH_ADT_HASH,      ssh_ipm_xmlconf_group_hash,
                             SSH_ADT_COMPARE,   ssh_ipm_xmlconf_group_compare,
                             SSH_ADT_DESTROY,   ssh_ipm_xmlconf_group_destroy,
                             SSH_ADT_CONTEXT,   ctx,

                             SSH_ADT_ARGS_END);
  if (ctx->auth_groups == NULL)
    goto error;

  /* Init the first authorization group ID. */
  ctx->next_group_id = 1;

  ctx->authorization = ssh_pm_authorization_local_create();
  if (ctx->authorization == NULL)
    goto error;


  /* Init FSM. */
  ssh_fsm_init(&ctx->fsm, ctx);

  /* Init buffers. */
  ssh_buffer_init(&ctx->ldap_servers);

  pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* Set IKE redirect decision callbacks */
#ifdef SSHDIST_IKE_REDIRECT
  ssh_pm_set_ike_redirect_decision_callback(pm,
                                            ssh_ike_redirect_decision_cb,
                                            ctx);
#endif /* SSHDIST_IKE_REDIRECT */

  /* Set the legacy client authentication callbacks. */
  ssh_pm_set_legacy_auth_client_callbacks(pm,
                                          ssh_ipm_legacy_auth_client_query_cb,
                                          ssh_ipm_legacy_auth_client_result_cb,
                                          ctx);

  /* Set authorization callback. */
  ssh_pm_set_authorization_callback(pm, ssh_pm_authorization_local_callback,
                                    ctx->authorization);


  ctx->parse_completed = 1;
  /* All done. */
  return ctx;


  /* Error handling. */

 error:

  ssh_ipm_context_destroy(ctx);

  return NULL;
}


Boolean
ssh_ipm_context_shutdown(SshIpmContext ctx)
{
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_HTTP_SERVER
#ifdef SSHDIST_CERT
  SshPm pm;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_HTTP_SERVER */
#endif /* SSHDIST_IKE_CERT_AUTH */
  Boolean rv = TRUE;

  if (ctx == NULL)
    return TRUE;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_HTTP_SERVER
#ifdef SSHDIST_CERT
  pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_HTTP_SERVER */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Clear policy objects. */
  if (ctx->policy_objects)
    ssh_adt_clear(ctx->policy_objects);

  if (ctx->sub_operation)
    {
      ssh_operation_abort(ctx->sub_operation);
      ctx->sub_operation = NULL;
    }

#ifdef SSH_IPSEC_HTTP_INTERFACE
  /* Stop HTTP statistics. */
  rv = ssh_ipm_http_statistics_stop(ctx);
#endif /* SSH_IPSEC_HTTP_INTERFACE */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_HTTP_SERVER
#ifdef SSHDIST_CERT
  ssh_pm_cert_access_server_stop(pm);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_HTTP_SERVER */
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (ctx->parse_completed)
    return rv;
  else
    return FALSE;
}


void
ssh_ipm_context_destroy(SshIpmContext ctx)
{
  if (ctx == NULL)
    return;

  /* Uninit FSM. */
  ssh_fsm_uninit(&ctx->fsm);

  ssh_free(ctx->prefix);

  ssh_xml_verifier_destroy(ctx->verifier);
  ssh_xml_parser_destroy(ctx->parser);

  if (ctx->rules)
    ssh_adt_destroy(ctx->rules);
  if (ctx->audit_modules)
    ssh_adt_destroy(ctx->audit_modules);
  if (ctx->policy_objects)
    ssh_adt_destroy(ctx->policy_objects);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  while (ctx->media_list != NULL)
    {
      SshIpmMediaConfig media;

      media = ctx->media_list;
      ctx->media_list = media->next;
      ssh_free(media);
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


  while (ctx->la_client_auth)
    {
      SshIpmLegacyAuthClientAuth auth;

      auth = ctx->la_client_auth;
      ctx->la_client_auth = auth->next;

      ssh_free(auth->user_name);
      ssh_free(auth->password);
      ssh_free(auth);
    }

  ssh_buffer_uninit(&ctx->ldap_servers);

  if (ctx->auth_groups)
    ssh_adt_destroy(ctx->auth_groups);
  ssh_pm_authorization_local_destroy(ctx->authorization);

#ifdef SSH_IPSEC_HTTP_INTERFACE
  /* Destroy possible HTTP statistics.  Normally, these are stopped
     already at ssh_ipm_context_shutdown() above. */
  SSH_VERIFY(ssh_ipm_http_statistics_stop(ctx));
#endif /* SSH_IPSEC_HTTP_INTERFACE */

#ifdef SSHDIST_EXTERNALKEY
  if (ctx->ek_providers)
    ssh_free(ctx->ek_providers);
#endif /* SSHDIST_EXTERNALKEY */

  if (ctx->bootstrap.traffic_selector)
    ssh_free(ctx->bootstrap.traffic_selector);

  ssh_free(ctx);
}

static void ipm_operation_aborted(void *context)
{
  SshIpmContext ctx = context;

  if (ctx->sub_operation)
    {
      ssh_operation_abort(ctx->sub_operation);
      ctx->sub_operation = NULL;
    }

  if (ctx->parse_operation)
    {
      ssh_operation_abort(ctx->parse_operation);
      ctx->parse_operation = NULL;
    }

  if (!ctx->commit_called)
    {
      ssh_fsm_set_next(&ctx->thread, ssh_ipm_st_config_parse_result);
      if (ssh_fsm_get_callback_flag(&ctx->thread))
        SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
    }

  ctx->aborted = 1;
  ctx->parse_status_cb = NULL_FNPTR;
  ctx->parse_status_cb_context = NULL;
}

SshOperationHandle
ssh_ipm_configure(SshIpmContext ctx,
                  SshPmStatusCB status_cb, void *status_cb_context)
{
  /* Recursive parsing is not supported. */
  SSH_ASSERT(ctx->parse_status_cb == NULL_FNPTR);

  /* Init our context for parsing configuration file. */
  ctx->precedence_used_min = 100000000;
  ctx->refresh_flows = 0;
  ctx->ldap_changed = 0;
  ctx->http_interface = 0;
  ctx->auth_domains = 0;
  ctx->default_auth_domain_present = 0;
  ctx->commit_called = 0;
  ctx->commit_failed = 0;
  ctx->pm_flags = 0;
  ctx->engine_params_set = 0;

  /* Store completion callback. */
  ctx->aborted = 0;
  ctx->parse_completed = 0;
  ctx->parse_status_cb = status_cb;
  ctx->parse_status_cb_context = status_cb_context;

  ssh_operation_register_no_alloc(ctx->operation, ipm_operation_aborted, ctx);

  /* Start an FSM thread for handling the reconfiguration. */
  ssh_fsm_thread_init(&ctx->fsm, &ctx->thread, ssh_ipm_st_config_start,
                      NULL_FNPTR, NULL_FNPTR, ctx);

  return ctx->operation;

}

SshUInt32
ssh_ipm_get_refresh_flows_timeout(SshIpmContext ctx)
{
  return ctx->refresh_flows;
}

SshUInt32
ssh_ipm_get_refresh_timeout(SshIpmContext ctx)
{
  return ctx->refresh;
}

#else /* SSH_IPSEC_XML_CONFIGURATION */

/* Dummy stub functions for the "no-xml configuration switch" */

SshIpmContext
ssh_ipm_context_create(SshPm pm, SshIpmParams params,
                       SshIpmCtxEventCB cb, void *cb_ctx)
{
  return (SshIpmContext) pm;
}

Boolean
ssh_ipm_context_shutdown(SshIpmContext ctx)
{
  return TRUE;
}

void
ssh_ipm_context_destroy(SshIpmContext ctx)
{
  return;
}

SshOperationHandle
ssh_ipm_configure(SshIpmContext ctx, SshPmStatusCB status_cb,
                  void *status_cb_context)
{
  SshPm pm = (*ctx->cb)(ctx->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
  status_cb(pm, TRUE, status_cb_context);

  return NULL;
}

SshUInt32
ssh_ipm_get_refresh_timeout(SshIpmContext ctx)
{
  return 0;
}

SshUInt32
ssh_ipm_get_refresh_flows_timeout(SshIpmContext ctx)
{
  return 0;
}
#endif /* SSH_IPSEC_XML_CONFIGURATION */
