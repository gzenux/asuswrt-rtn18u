/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp PayloadID handling functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshmiscstring.h"
#ifdef SSHDIST_IKE_CERT_AUTH
#include "x509.h"
#include "dn.h"
#endif /* SSHDIST_IKE_CERT_AUTH */

#define SSH_DEBUG_MODULE "SshIkeId"

#define SSH_HASH_DATA(hash, data, len)                                      \
do                                                                          \
  {                                                                         \
    size_t i;                                                               \
                                                                            \
    for (i = 0; i < (len); i++)                                              \
      (hash) = ((((hash) << 19) ^ ((hash) >> 13))                           \
                + ((unsigned char *) (data))[i]);                           \
  }                                                                         \
while (0)

SshUInt32
ssh_ike_id_hash(SshIkePayloadID id)
{
  SshUInt32 hash = 0;

  if (id == NULL)
    return hash;

  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      SSH_HASH_DATA(hash, id->identification.ipv4_addr,
                    id->identification_len);
      break;

    case IPSEC_ID_IPV6_ADDR:
      SSH_HASH_DATA(hash, id->identification.ipv6_addr,
                    id->identification_len);
      break;

    case IPSEC_ID_IPV4_ADDR_SUBNET:
      SSH_HASH_DATA(hash, &id->identification.ipv4_addr_subnet_and_netmask,
                    id->identification_len);
      break;

    case IPSEC_ID_IPV6_ADDR_SUBNET:
      SSH_HASH_DATA(hash, &id->identification.ipv6_addr_subnet_and_netmask,
                    id->identification_len);
      break;

    case IPSEC_ID_IPV4_ADDR_RANGE:
      SSH_HASH_DATA(hash, &id->identification.ipv4_addr_range,
                    id->identification_len);
      break;

    case IPSEC_ID_IPV6_ADDR_RANGE:
      SSH_HASH_DATA(hash, &id->identification.ipv6_addr_range,
                    id->identification_len);
      break;

    case IPSEC_ID_FQDN:
      SSH_HASH_DATA(hash, id->identification.fqdn, id->identification_len);
      break;

    case IPSEC_ID_USER_FQDN:
      SSH_HASH_DATA(hash, id->identification.user_fqdn,
                    id->identification_len);
      break;

    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      SSH_HASH_DATA(hash, id->identification.asn1_data,
                    id->identification_len);
      break;

    case IPSEC_ID_KEY_ID:
      SSH_HASH_DATA(hash, id->identification.key_id,
                    id->identification_len);
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        int cnt;

        for (cnt = 0;
            cnt < id->identification.id_list_number_of_items;
            cnt++)
          {
            hash += ssh_ike_id_hash(&id->identification.id_list_items[cnt]);
          }
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    }

  return hash;
}

Boolean ssh_ike_id_compare(SshIkePayloadID id1,
                           SshIkePayloadID id2)
{
  if (id1 == id2)
    return TRUE;

  if (id1 == NULL || id2 == NULL)
    return FALSE;

  if ((id1->id_type == id2->id_type) &&
      (id1->identification_len == id2->identification_len))
    {
      switch (id1->id_type)
        {
        case IPSEC_ID_IPV4_ADDR:
          return memcmp(id1->identification.ipv4_addr,
                        id2->identification.ipv4_addr,
                        id1->identification_len) == 0;
        case IPSEC_ID_IPV6_ADDR:
          return memcmp(id1->identification.ipv6_addr,
                        id2->identification.ipv6_addr,
                        id1->identification_len) == 0;
        case IPSEC_ID_IPV4_ADDR_SUBNET:
          return memcmp(&id1->identification.ipv4_addr_subnet_and_netmask,
                        &id2->identification.ipv4_addr_subnet_and_netmask,
                        id1->identification_len) == 0;
        case IPSEC_ID_IPV6_ADDR_SUBNET:
          return memcmp(&id1->identification.ipv6_addr_subnet_and_netmask,
                        &id2->identification.ipv6_addr_subnet_and_netmask,
                        id1->identification_len) == 0;
        case IPSEC_ID_IPV4_ADDR_RANGE:
          return memcmp(&id1->identification.ipv4_addr_range,
                        &id2->identification.ipv4_addr_range,
                        id1->identification_len) == 0;
        case IPSEC_ID_IPV6_ADDR_RANGE:
          return memcmp(&id1->identification.ipv6_addr_range,
                        &id2->identification.ipv6_addr_range,
                        id1->identification_len) == 0;
        case IPSEC_ID_FQDN:
          return !strcmp((const char *)id1->identification.fqdn,
                         (const char *)id2->identification.fqdn);
        case IPSEC_ID_USER_FQDN:
          return !strcmp((const char *)id1->identification.user_fqdn,
                         (const char *)id2->identification.user_fqdn);
        case IPSEC_ID_DER_ASN1_DN:
        case IPSEC_ID_DER_ASN1_GN:
          return memcmp(id1->identification.asn1_data,
                        id2->identification.asn1_data,
                        id1->identification_len) == 0;
        case IPSEC_ID_KEY_ID:
          return memcmp(id1->identification.key_id,
                        id2->identification.key_id,
                        id1->identification_len) == 0;
#ifdef SSHDIST_IKE_ID_LIST
        case IPSEC_ID_LIST:
          {
            int cnt;
            if (id1->identification.id_list_number_of_items !=
                id2->identification.id_list_number_of_items)
              return FALSE;

            for (cnt = 0;
                cnt < id1->identification.id_list_number_of_items;
                cnt++)
              {
                if (!ssh_ike_id_compare(&id1->identification.
                                        id_list_items[cnt],
                                        &id2->identification.
                                        id_list_items[cnt]))
                  return FALSE;
              }
            return TRUE;
          }
#endif /* SSHDIST_IKE_ID_LIST */
        }
      return FALSE;
    }
  else
    return FALSE;
}

void
ssh_ike_id_free_internal(SshIkePayloadID id, Boolean free_top_level)
{
  if (id)
    {
      switch (id->id_type)
        {
        case IPSEC_ID_IPV4_ADDR:
        case IPSEC_ID_IPV6_ADDR:
        case IPSEC_ID_IPV4_ADDR_SUBNET:
        case IPSEC_ID_IPV6_ADDR_SUBNET:
        case IPSEC_ID_IPV4_ADDR_RANGE:
        case IPSEC_ID_IPV6_ADDR_RANGE:
          break;
        case IPSEC_ID_FQDN:
          ssh_free(id->identification.fqdn);
          break;
        case IPSEC_ID_USER_FQDN:
          ssh_free(id->identification.user_fqdn);
          break;
        case IPSEC_ID_DER_ASN1_DN:
        case IPSEC_ID_DER_ASN1_GN:
          ssh_free(id->identification.asn1_data);
          break;
        case IPSEC_ID_KEY_ID:
          ssh_free(id->identification.key_id);
          break;
#ifdef SSHDIST_IKE_ID_LIST
        case IPSEC_ID_LIST:
          {
            int cnt;

            if (id->identification.id_list_items)
              {
                for (cnt = 0;
                    cnt < id->identification.id_list_number_of_items;
                    cnt++)
                  {
                    ssh_ike_id_free_internal(&id->identification.
                                             id_list_items[cnt], FALSE);
                  }
                ssh_free(id->identification.id_list_items);
              }
            break;
          }
#endif /* SSHDIST_IKE_ID_LIST */
        }
      if (free_top_level)
        ssh_free(id);
    }
}

void
ssh_ike_id_free(SshIkePayloadID id)
{
  ssh_ike_id_free_internal(id, TRUE);
}

/* Split string `str' to two part separated by `sep'. Return the
   beginning of the later part, or the string, if is does not contain
   separator. As a side effect destroys the string by replacing the
   found separators with NUL character */
unsigned char *ssh_ike_split_string(unsigned char *str, char sep)
{
  int i, len;

  len = ssh_ustrlen(str);

  for (i = 0; i < len; i++)
    {
      if (str[i] == sep)
        {
          str[i] = '\0';
          return str + i + 1;
        }
    }
  return str;
}

size_t ssh_ike_id_read_hexdata(unsigned char *result,
                               const unsigned char *input)
{
  int i = 0;

#define VALUE(_c) \
  (unsigned char )(((_c) >= 'A' && (_c) <= 'F') ? ((_c) - ('A' - 10)) : \
    ((_c) >= 'a' && (_c) <= 'f') ? ((_c) - ('a' - 10)) : \
    ((_c) - '0'))
#define HEXBYTE(_hex) (((VALUE(_hex[0]) << 4) + (VALUE(_hex[1]))))

  /* Get rid of whitespace at the beginning */
  while (*input == ' ') input++;
  while (*input)
    {
      unsigned int r = HEXBYTE(input);
      if (r > 255)
        return 0;
      result[i++] = (unsigned char)r;
      input += 2;
      /* Remove optional whitespace between bytes */
      while (*input == ' ') input++;
    }
#undef HEXBYTE
#undef VALUE

  return i;
}

/* Small internal utility function to correctly parse ipv4/ipv6
   address from `data' to `destination';

   the payload of `id' is returned as-is if the parsing was
   successfully and is_ipv4 flag matches ipv4 state of the parsed
   address.  otherwise the `id' is ssh_freed and NULL is returned.

   This function ensures that for example ipv6(1.2.3.4) is, indeed,
   invalid while ipv6(::1.2.3.4) is valid.  Respectively I think that
   ipv4(dead:beef) would've worked before but no longer.
*/
SshIkePayloadID ssh_ipaddr_parse_to_internal(unsigned char *data,
                                             unsigned char *destination,
                                             Boolean is_ipv4,
                                             SshIkePayloadID id)
{
  SshIpAddrStruct temp_addr;

  if (!ssh_ipaddr_parse(&temp_addr, data))
    goto fail;
  if (SSH_IP_IS4(&temp_addr) != is_ipv4)
    goto fail;

  if (is_ipv4)
    SSH_IP4_ENCODE(&temp_addr, destination);
  else
    SSH_IP6_ENCODE(&temp_addr, destination);

  return id;

 fail:
  ssh_free(id);
  return NULL;
}


#define IKE_SKIP_WHITESPACE(s) while (*(s) && isspace(*s)) (s)++
#define IKE_SKIP_ALPHANUM(s) while (*(s) && isalnum(*s)) (s)++
#define IKE_SKIP_DIGIT_AND_CHAR(s,c) \
        while (*(s) && (isdigit(*s) || *(s) == (c))) (s)++
#define IKE_TRIM_WHITESPACE(s) \
  do { \
    unsigned char *__p; \
    for (__p = (s) + ssh_ustrlen(s) - 1; \
         __p >= (s) && isspace(*__p); \
         __p--) ; \
    __p[1] = '\0'; \
  } while (0)

SshIkePayloadID ssh_ike_string_to_id_internal(unsigned char *string,
                                              size_t *bytes_used)
{
  SshIkeIpsecIdentificationData iddata;
  SshIkePayloadID newp;
  unsigned char *p, *copy, *type_name, *protoname, *portname, *dh, *data;

  if (!string)
    return NULL;

  /* Remove possbile trailing ')' */
  copy = ssh_strdup(string);
  if (copy == NULL)
    return NULL;

  type_name = copy;
  IKE_SKIP_WHITESPACE(type_name);
  protoname = type_name;
  while (*protoname &&
         (isalnum(*protoname) || *protoname == '@' || *protoname == '_'))
    protoname++;
  IKE_SKIP_WHITESPACE(protoname);
  if (*protoname != '(')
    goto id_fail;
  *protoname++ = '\0';
  IKE_TRIM_WHITESPACE(type_name);

  /* If the type is missing, we can not continue */
  if (ssh_usstrcmp(type_name, ""))
    {
      int type_id;

      type_id = ssh_find_keyword_number(ssh_ike_id_type_keywords,
                                        ssh_csstr(type_name));
      if (type_id == -1)
        goto id_fail;

      newp = ssh_calloc(1, sizeof(*newp));
      if (!newp)
        goto id_fail;

      newp->id_type = type_id;
    }
  else
    {
    id_fail:
      ssh_free(copy);
      return NULL;
    }

  IKE_SKIP_WHITESPACE(protoname);
  portname = protoname;
  IKE_SKIP_ALPHANUM(portname);
  IKE_SKIP_WHITESPACE(portname);
  if (*portname == ':')
    {
      /* Port found. */
      dh = portname + 1;
      IKE_SKIP_WHITESPACE(dh);
      IKE_SKIP_ALPHANUM(dh);
      IKE_SKIP_WHITESPACE(dh);
      if (*dh == '-')
        {
          /* Range end found. */
          dh++;
          IKE_SKIP_WHITESPACE(dh);
          IKE_SKIP_ALPHANUM(dh);
          IKE_SKIP_WHITESPACE(dh);
        }
      if (*dh == ',')
        {
          /* Comma found, so we really had port and proto. */
          *portname++ = '\0';
          *dh++ = '\0';
          IKE_SKIP_WHITESPACE(portname);
          IKE_TRIM_WHITESPACE(portname);
          IKE_TRIM_WHITESPACE(protoname);
        }
      else
        {
          /* Didn't find comma so the proto and port must be missing. */
          dh = protoname;
          protoname = ssh_ustr("");
          portname = ssh_ustr("");
        }
    }
  else if (*portname == ',')
    {
      /* Comma found, but no port present. */
      *portname++ = '\0';
      dh = portname;
      portname = ssh_ustr("");
      IKE_TRIM_WHITESPACE(protoname);
    }
  else
    {
      /* Something else, so no proto or port present. */
      dh = protoname;
      protoname = ssh_ustr("");
      portname = ssh_ustr("");
    }

  IKE_SKIP_WHITESPACE(dh);
  if (dh[0] == '[')
    {
      /* We might have length here, skip it. */
      data = dh + 1;
      IKE_SKIP_DIGIT_AND_CHAR(data, '.');
      if (*data == ']')
        {
          data++;
          IKE_SKIP_WHITESPACE(data);
          if (*data == '=')
            {
              /* Length found skip it. */
              data++;
            }
          else
            {
              /* No '=' char, so no length. */
              data = dh;
            }
        }
      else
        {
          /* No closing bracket, so no length. */
          data = dh;
        }
    }
  else
    {
      /* No length. */
      data = dh;
    }

  IKE_SKIP_WHITESPACE(data);

  if (ssh_usstrcmp(protoname, ""))
    {
      newp->protocol_id = ssh_find_keyword_number(ssh_ip_protocol_id_keywords,
                                                  ssh_csstr(protoname));
      if ((int) newp->protocol_id == -1)
        goto fail;
    }
  if (ssh_usstrcmp(portname, ""))
    {
      unsigned char *range_end = ssh_ike_split_string(portname, '-');

      IKE_SKIP_WHITESPACE(range_end);
      IKE_TRIM_WHITESPACE(portname);
      newp->port_number = (int)ssh_ustrtol(portname, NULL, 0);

      if (range_end != portname)
        newp->port_range_end = (int)ssh_ustrtol(range_end, NULL, 0);
      else
        newp->port_range_end = newp->port_number;

      if (newp->port_range_end < newp->port_number)
        goto fail;
    }
  newp->raw_id_packet = NULL;

  iddata = &(newp->identification);


  /* Return bytes used. */
  if (bytes_used)
    {
      /* Search end, and we cannot have list here. */
      dh = data;
      while (*dh && *dh != ')')
        dh++;
      *dh = '\0';
      *bytes_used = (dh - copy) + 1;
    }
  else
    {
      /* The whole string must be used. */
      IKE_TRIM_WHITESPACE(data);
      dh = data + ssh_ustrlen(data) - 1;
      if (*dh != ')')
        goto fail;
      *dh = '\0';
    }
  IKE_TRIM_WHITESPACE(data);

  switch (newp->id_type)
    {
    case IPSEC_ID_FQDN:
      newp->identification_len = ssh_ustrlen(data);
      iddata->fqdn = ssh_strdup(data);
      if (iddata->fqdn == NULL)
        {
        fail:
          ssh_free(newp);
          ssh_free(copy);
          return NULL;
        }
      break;
    case IPSEC_ID_USER_FQDN:
      newp->identification_len = ssh_ustrlen(data);
      iddata->user_fqdn = ssh_strdup(data);
      if (iddata->user_fqdn == NULL)
        goto fail;
      break;
    case IPSEC_ID_IPV4_ADDR:
      newp->identification_len = 4;
      newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv4_addr, TRUE, newp);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      {
        unsigned int mask;
        int masklen;

        newp->identification_len = 8;
        p = ssh_ike_split_string(data, '/');
        if (p == data)
          goto fail;
        IKE_SKIP_WHITESPACE(p);
        IKE_TRIM_WHITESPACE(data);
        newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv4_addr_subnet,
                                            TRUE, newp);
        if (newp == NULL)
          goto id_fail;
        masklen = (int)ssh_ustrtol(p, NULL, 10);
        if (masklen > 32)
          goto fail;

        mask = ((masklen == 32)
                ? 0xffffffff
                : ((masklen != 0)
                   ? 0xffffffff << (32 - masklen)
                   : 0x0));
        SSH_IKE_PUT32(iddata->ipv4_addr_netmask, mask);
      }
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      newp->identification_len = 8;
      p = ssh_ike_split_string(data, '-');
      if (p == data)
        goto fail;
      IKE_SKIP_WHITESPACE(p);
      IKE_TRIM_WHITESPACE(data);
      newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv4_addr_range1,
                                          TRUE, newp);
      if (newp == NULL)
        goto id_fail;
      newp = ssh_ipaddr_parse_to_internal(p, iddata->ipv4_addr_range2,
                                          TRUE, newp);
      if (newp == NULL)
        goto id_fail;

      if (memcmp(iddata->ipv4_addr_range1, iddata->ipv4_addr_range2,
                 sizeof(iddata->ipv4_addr_range1)) > 0)
        goto fail;
      break;
    case IPSEC_ID_IPV6_ADDR:
      newp->identification_len = 16;
      newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv6_addr, FALSE,
                                          newp);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      {
        unsigned int mask;
        int masklen;
        int w;

        newp->identification_len = 32;
        p = ssh_ike_split_string(data, '/');
        if (p == data)
          goto fail;

        IKE_SKIP_WHITESPACE(p);
        IKE_TRIM_WHITESPACE(data);

        newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv6_addr_subnet,
                                            FALSE, newp);
        if (newp == NULL)
          goto id_fail;

        masklen = (int)ssh_ustrtol(p, NULL, 10);
        if (masklen > 128)
          goto fail;

        for (w = 0; w < 4; w++)
          {
            mask = ((masklen >= 32)
                    ? 0xffffffff
                    : ((masklen != 0)
                       ? 0xffffffff << (32 - masklen)
                       : 0x0));
            SSH_IKE_PUT32(iddata->ipv6_addr_netmask + w * 4, mask);

            if (masklen >= 32)
              masklen -= 32;
            else
              masklen = 0;
          }
      }
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      newp->identification_len = 32;
      p = ssh_ike_split_string(data, '-');
      if (p == data)
        goto fail;
      IKE_SKIP_WHITESPACE(p);
      IKE_TRIM_WHITESPACE(data);
      newp = ssh_ipaddr_parse_to_internal(data, iddata->ipv6_addr_range1,
                                          FALSE, newp);
      if (newp == NULL)
        goto id_fail;

      newp = ssh_ipaddr_parse_to_internal(p, iddata->ipv6_addr_range2,
                                          FALSE, newp);
      if (newp == NULL)
        goto id_fail;

      if (memcmp(iddata->ipv6_addr_range1, iddata->ipv6_addr_range2,
                 sizeof(iddata->ipv6_addr_range1)) > 0)
        goto fail;
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
#ifdef SSHDIST_CERT
      {
        SshDNStruct dn;

        ssh_dn_init(&dn);
        /* The input is LDAP DN (character string of format C=FI,O= ... */
        if (ssh_dn_decode_ldap(data, &dn))
          {
            if (!ssh_dn_encode_der(&dn, &iddata->asn1_data,
                                   &newp->identification_len, NULL))
              {
                ssh_free(newp);
                newp = NULL;
              }
          }
        else
          {
            ssh_free(newp);
            newp = NULL;
          }
        ssh_dn_clear(&dn);
      }
      break;
#else /* SSHDIST_CERT */
      {
        int len;

        len = strlen(data);
        iddata->asn1_data = ssh_malloc(len);
        if (iddata->asn1_data == NULL)
          goto fail;
        if ((newp->identification_len =
             ssh_ike_id_read_hexdata(iddata->asn1_data, data)) == 0)
          {
            ssh_free(iddata->asn1_data);
            iddata->asn1_data = NULL;
            goto fail;
          }
      }
      break;
#endif /* SSHDIST_CERT */
    case IPSEC_ID_KEY_ID:
      {
        int len;

        len = ssh_ustrlen(data);
        iddata->key_id = ssh_malloc(len);
        if (iddata->key_id == NULL)
          goto fail;
        if ((newp->identification_len =
             ssh_ike_id_read_hexdata(iddata->key_id, data)) == 0)
          {
            ssh_free(iddata->key_id);
            iddata->key_id = NULL;
            goto fail;
          }
      }
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        SshIkePayloadID id;
        SshUInt32 cnt, alloc;
        size_t used;

        cnt = 0;
        alloc = 0;
        newp->identification.id_list_items = NULL;
        do {
          id = ssh_ike_string_to_id_internal(data, &used);
          if (id == NULL)
            {
            list_fail:
              newp->identification.id_list_number_of_items = cnt;
              ssh_ike_id_free(newp);
              ssh_free(copy);
              return NULL;
            }
          if (alloc == cnt)
            {
              if (!ssh_recalloc(&newp->identification.id_list_items,
                                &alloc, alloc + 5,
                                sizeof(newp->identification.id_list_items[0])))
                goto list_fail;
            }
          newp->identification.id_list_items[cnt] = *id;
          ssh_free(id);
          cnt++;
          data += used;
          IKE_SKIP_WHITESPACE(data);
          if (!*data)
            break;
          if (*data != ',')
            goto list_fail;
          data++;
          IKE_SKIP_WHITESPACE(data);
        } while (1);
        newp->identification.id_list_number_of_items = cnt;
      }
      break;
#endif /* SSHDIST_IKE_ID_LIST */
    }
  ssh_free(copy);
  return newp;
}

/*                                                              shade{0.9}
 * ssh_ike_string_to_id
 *
 * Convert string of format:
 * id-type-name(proto-name:port-number,[0..id-data-len]=id-data-presentation)
 * back to id-structure. The id-string does not have to contain part
 * enclosed between brackets, so it can also be of format:
 * id-type-name(proto-name:port-number,id-data-presentation). Also
 * protocol name and port number may be omitted. They will default to
 * value zero.  The port-number can also be specified as `start-end'
 * to specify a port number range. Return NULL in case of error.  shade{1.0}
 */
SshIkePayloadID ssh_ike_string_to_id(unsigned char *string)
{
  return ssh_ike_string_to_id_internal(string, NULL);
}

/*                                                              shade{0.9}
 * ssh_ike_id_to_string
 * Convert id-structure to string. The Resulting string is of format
 * id-type-name(proto-name:port-number,[0..id-data-len]=id-data-presentation)
 *                                                              shade{1.0}
 */
char *ssh_ike_id_to_string(char *buffer,
                           size_t buflen,
                           SshIkePayloadID id)
{
  SshIkeIpsecIdentificationData data;
  size_t len, dlen = 0;
  int i, j;
  int netmask_len;
  const char *type;
  const char *proto;
  unsigned char tempbuf[20], portbuf[20];
  char *start = buffer;
  SshIpAddrStruct ip1, ip2;

#define SSH_MIN(_a, _b) (((_a) < (_b)) ? (_a) : (_b))

  if (!id)
    {
      ssh_snprintf(ssh_ustr(buffer), buflen, "unknown(any:0,[0..0]=)");
      return start;
    }

  data = &(id->identification);
  len = id->identification_len;

  type = ssh_find_keyword_name(ssh_ike_id_type_keywords, id->id_type);
  if (type == NULL) type = "unknown";

  if (id->protocol_id == 0)
    proto = "any";
  else
    proto = ssh_find_keyword_name(ssh_ip_protocol_id_keywords,
                                  id->protocol_id);
  if (proto == NULL)
    {
      proto = ssh_sstr(tempbuf);
      ssh_snprintf(tempbuf, sizeof(tempbuf), "%d", id->protocol_id);
    }

  if (id->port_range_end && id->port_range_end != id->port_number)
    ssh_snprintf(portbuf, sizeof(portbuf), "%d-%d",
                 id->port_number, id->port_range_end);
  else
    ssh_snprintf(portbuf, sizeof(portbuf), "%d", id->port_number);
  if (id->identification_len == 0)
    ssh_snprintf(ssh_ustr(buffer), buflen, "%s(%s:%s,", type, proto, portbuf);
  else
    ssh_snprintf(ssh_ustr(buffer), buflen, "%s(%s:%s,[0..%d]=", type, proto,
                 portbuf, (int) id->identification_len - 1);
  buflen -= strlen(buffer);
  buffer += strlen(buffer);

  if (len >= buflen - 1)
    len = buflen - 1;

  switch (id->id_type)
    {
    case IPSEC_ID_FQDN:
      strncpy(buffer, (char *) data->fqdn, len);
      dlen = ssh_strnlen((char *)data->fqdn, len);
      break;
    case IPSEC_ID_USER_FQDN:
      strncpy(buffer, (char *) data->user_fqdn, len);
      dlen = ssh_strnlen((char *)data->user_fqdn, len);
      break;
    case IPSEC_ID_IPV4_ADDR:
      dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%u.%u.%u.%u",
                          data->ipv4_addr[0],
                          data->ipv4_addr[1],
                          data->ipv4_addr[2],
                          data->ipv4_addr[3]);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      for (i = 0; i < 4; i++)
        {
          for (j = 0; j < 8; j++)
            if ((data->ipv4_addr_netmask[i] & (1 << (7-j))) == 0)
              break;
          if (j != 8)
            break;
        }
      if (i == 4) j = 0;
      netmask_len = i * 8 + j;
      for (; i < 4; i++)
        {
          for (; j < 8; j++)
            if ((data->ipv4_addr_netmask[i] & (1 << (7-j))) != 0)
              break;
          if (j != 8)
            break;
          j = 0;
        }
      if (i != 4 && j != 8)
        {
          dlen = ssh_snprintf(ssh_ustr(buffer), buflen,
                              "%u.%u.%u.%u, netmask %u.%u.%u.%u",
                              data->ipv4_addr_subnet[0],
                              data->ipv4_addr_subnet[1],
                              data->ipv4_addr_subnet[2],
                              data->ipv4_addr_subnet[3],
                              data->ipv4_addr_netmask[0],
                              data->ipv4_addr_netmask[1],
                              data->ipv4_addr_netmask[2],
                              data->ipv4_addr_netmask[3]);
        }
      else
        {
          dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%u.%u.%u.%u/%d",
                              data->ipv4_addr_subnet[0],
                              data->ipv4_addr_subnet[1],
                              data->ipv4_addr_subnet[2],
                              data->ipv4_addr_subnet[3],
                              netmask_len);
        }
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%u.%u.%u.%u-%u.%u.%u.%u",
                          data->ipv4_addr_range1[0],
                          data->ipv4_addr_range1[1],
                          data->ipv4_addr_range1[2],
                          data->ipv4_addr_range1[3],
                          data->ipv4_addr_range2[0],
                          data->ipv4_addr_range2[1],
                          data->ipv4_addr_range2[2],
                          data->ipv4_addr_range2[3]);
      break;
    case IPSEC_ID_IPV6_ADDR:
      SSH_IP6_DECODE(&ip1, data->ipv6_addr);
      dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%@",
                           ssh_ipaddr_render, &ip1);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      for (i = 0; i < 16; i++)
        {
          for (j = 0; j < 8; j++)
            if ((data->ipv6_addr_netmask[i] & (1 << (7-j))) == 0)
              break;
          if (j != 8)
            break;
        }
      if (i == 16) j = 0;
      netmask_len = i * 8 + j;
      for (; i < 16; i++)
        {
          for (; j < 8; j++)
            if ((data->ipv6_addr_netmask[i] & (1 << (7-j))) != 0)
              break;
          if (j != 8)
            break;
          j = 0;
        }
      if (i != 16 && j != 8)
        {
          dlen = ssh_snprintf(
                ssh_ustr(buffer), buflen,
                "%x:%x:%x:%x:%x:%x:%x:%x, "
                "netmask %x:%x:%x:%x:%x:%x:%x:%x",
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 2),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 4),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 6),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 8),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 10),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 12),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_subnet + 14),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 2),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 4),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 6),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 8),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 10),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 12),
                (unsigned int) SSH_IKE_GET16(data->ipv6_addr_netmask + 14));
        }
      else
        {
          SSH_IP6_DECODE(&ip1, data->ipv6_addr_subnet);
          dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%@/%d",
                              ssh_ipaddr_render, &ip1,
                              netmask_len);
        }
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      SSH_IP6_DECODE(&ip1, data->ipv6_addr_range1);
      SSH_IP6_DECODE(&ip2, data->ipv6_addr_range2);
      dlen = ssh_snprintf(ssh_ustr(buffer), buflen, "%@-%@",
                          ssh_ipaddr_render, &ip1,
                          ssh_ipaddr_render, &ip2);
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
#ifdef SSHDIST_CERT
      {
        SshDNStruct dn;
        char *ldap;

        ssh_dn_init(&dn);
        if (ssh_dn_decode_der(data->asn1_data, id->identification_len,
                              &dn,
                              NULL))
          {
            if (ssh_dn_encode_ldap(&dn, &ldap))
              {
                strncpy(buffer, ldap, buflen - 1);
                dlen = ssh_strnlen((char *)ldap, buflen - 1);
                ssh_free(ldap);
              }
          }
        ssh_dn_clear(&dn);
      }
      break;
#else /* SSHDIST_CERT */
      dlen = 0;
      for (i = 0; (unsigned)i < len && dlen < buflen; i++)
        {
          dlen += ssh_snprintf(ssh_ustr(buffer + dlen), buflen - dlen, "%02x ",
                               data->asn1_data[i]);
        }
      break;
#endif /* SSHDIST_CERT */
    case IPSEC_ID_KEY_ID:
      dlen = 0;
      for (i = 0; (unsigned)i < len && dlen < buflen; i++)
        {
          dlen += ssh_snprintf(ssh_ustr(buffer + dlen), buflen - dlen, "%02x ",
                               data->key_id[i]);
        }
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        int cnt;

        dlen = 0;
        if (id->identification.id_list_items)
          {
            for (cnt = 0; cnt < data->id_list_number_of_items; cnt++)
              {
                if (cnt != 0)
                  {
                    dlen += ssh_snprintf(ssh_ustr(buffer + dlen),
                                         buflen - dlen, ", ");
                  }
                ssh_ike_id_to_string(buffer + dlen, buflen - dlen,
                                     &(data->id_list_items[cnt]));
                dlen += strlen(buffer + dlen);
                if (buflen <= dlen)
                  break;
              }
          }
      }
      break;
#endif /* SSHDIST_IKE_ID_LIST */
    }
  buffer[dlen] = '\0';
  buflen -= strlen(buffer);
  buffer += strlen(buffer);
  ssh_snprintf(ssh_ustr(buffer), buflen, ")");

  return start;
}

/*                                                              shade{0.9}
 * ssh_ike_id_render
 * Renderer function for an id-structure.  This can be used with the
 * ssh_snprintf and ssh_vsnprintf functions to render an
 * SshIkePayloadID to a print buffer.
 *                                                              shade{1.0}
 */
int ssh_ike_id_render(unsigned char *buf, int buf_size, int precision,
                      void *datum)
{
  SshIkePayloadID id = (SshIkePayloadID) datum;
  int len;

  (void) ssh_ike_id_to_string(ssh_sstr(buf), buf_size, id);

  len = ssh_ustrlen(buf);
  if (len >= buf_size - 1)
    return buf_size + 1;

  if (precision >= 0)
    if (len > precision)
      len = precision;

  return len;
}

/*                                                              shade{0.9}
 * ssh_ike_id_render_short
 * Renderer function for an id-structure.  This works like
 * ssh_ike_id_render but it only prints the textual presentation of
 * the id.  it does not print the type of the ID or its length.  This
 * can be used with the ssh_snprintf and ssh_vsnprintf functions to
 * render an SshIkePayloadID to a print buffer.
 *                                                              shade{1.0}
 */
int ssh_ike_id_render_short(unsigned char *buf, int buf_size, int precision,
                            void *datum)
{
  SshIkePayloadID id = (SshIkePayloadID) datum;
  int len;
  size_t offset = 0;
  unsigned char *cp;

  if (id == NULL || id->id_type == 0)
    {
      len = ssh_snprintf(buf, buf_size, "No Id");
      if (len >= buf_size - 1)
        return buf_size + 1;
    }
  else
    {
      (void) ssh_ike_id_to_string(ssh_sstr(buf), buf_size, id);

      len = ssh_ustrlen(buf);
      if (len >= buf_size - 1)
        return buf_size + 1;

    next:
      cp = ssh_ustrchr(buf, '=');
      if (cp)
        {
          cp++;
          memmove(buf + offset, cp, len - (cp - (buf + offset)) + 1);
          cp = ssh_ustrchr(buf, ')');
          if (cp)
            {
              /* Check if we have an ID_LIST, and if so skip to the
                 next address item. This function assumes a lot from
                 the internal operation of ssh_ike_id_to_string() */
              if (*(cp + 1) == ',')
                {
                  *cp = ',';
                  *(cp + 1) = ' ';
                  offset = cp - buf + 2;
                  len = ssh_ustrlen(buf);
                  goto next;
                }
              else
                *cp = '\0';
            }
          len = ssh_ustrlen(buf);
        }
    }

  if (precision >= 0)
    if (len > precision)
      len = precision;

  return len;
}

Boolean ssh_ike_id_copy(SshIkePayloadID from, SshIkePayloadID to)
{
  /* Copy id payload */
  if (from && to)
    {
      memmove(to, from, sizeof(struct SshIkePayloadIDRec));

      /* Duplicate the next level of data */
      switch (to->id_type)
        {
        case IPSEC_ID_FQDN:
          to->identification.fqdn = ssh_memdup(to->identification.fqdn,
                                               to->identification_len);
          if (to->identification.fqdn == NULL)
            return FALSE;
          break;
        case IPSEC_ID_USER_FQDN:
          to->identification.user_fqdn =
            ssh_memdup(to->identification.user_fqdn,
                       to->identification_len);
          if (to->identification.user_fqdn == NULL)
            return FALSE;
          break;
        case IPSEC_ID_DER_ASN1_DN:
        case IPSEC_ID_DER_ASN1_GN:
          to->identification.asn1_data =
            ssh_memdup(to->identification.asn1_data,
                       to->identification_len);
          if (to->identification.asn1_data == NULL)
            return FALSE;
          break;
        case IPSEC_ID_KEY_ID:
          to->identification.key_id = ssh_memdup(to->identification.key_id,
                                                 to->identification_len);
          if (to->identification.key_id == NULL)
            return FALSE;
          break;
#ifdef SSHDIST_IKE_ID_LIST
        case IPSEC_ID_LIST:
          {
            int cnt;

            to->identification.id_list_items =
              ssh_calloc(to->identification.id_list_number_of_items,
                         sizeof(to->identification.id_list_items[0]));
            if (to->identification.id_list_items == NULL)
              return FALSE;

            for (cnt = 0;
                cnt < to->identification.id_list_number_of_items;
                cnt++)
              {
                if (!ssh_ike_id_copy(&(from->identification.
                                       id_list_items[cnt]),
                                     &(to->identification.id_list_items[cnt])))
                  return FALSE;
              }
            break;
          }
#endif /* SSHDIST_IKE_ID_LIST */
        case IPSEC_ID_IPV4_ADDR:
        case IPSEC_ID_IPV4_ADDR_SUBNET:
        case IPSEC_ID_IPV4_ADDR_RANGE:
        case IPSEC_ID_IPV6_ADDR:
        case IPSEC_ID_IPV6_ADDR_SUBNET:
        case IPSEC_ID_IPV6_ADDR_RANGE:
          /* These are self-contained */
          break;
        }
      to->raw_id_packet = NULL;
    }
  return TRUE;
}

SshIkePayloadID
ssh_ike_id_dup(SshIkePayloadID id)
{
  SshIkePayloadID newp = NULL;

  if (id)
    {
      newp = ssh_malloc(sizeof(*newp));
      if (newp == NULL)
        return NULL;
      if (!ssh_ike_id_copy(id, newp))
        {
          ssh_free(newp);
          return NULL;
        }
    }
  return newp;
}

/* Decode ID from `id' into subfields. The name1 will contain printed
   copy of the address for field ip-address types, or the domain name
   for fqdn, or user-name for user-fqdn, or the ASN1 data for DN, and
   GN types, or key-id. The name2 will contain subnet or end or range
   addresses for ip-types and the domain-name for user-fqdn type. The
   field name1_len and name2_len indicate the space reserved by the
   upper level, and they will be set to indicate the space used.

   For the ID_LIST type the name1 and name2 will ignored (name1_len and
   name2_len are set to 0).

   The function returns TRUE on success. Even in case of failure the
   function may modify values pointed by arguments.  */
Boolean
ssh_ike_id_decode(SshIkePayloadID id,
                  SshIkeIpsecIdentificationType *type,
                  SshIkeIpsecIPProtocolID *proto,
                  SshUInt16 *port,
                  SshUInt16 *port_range_end,
                  unsigned char *name1, size_t *name1_len,
                  unsigned char *name2, size_t *name2_len)
{
  unsigned char *p, *at;
  unsigned char *n1 = NULL, *n2 = NULL;
  SshIpAddrStruct ipaddr;

  if (!id)
    return FALSE;

  *type = id->id_type;
  *proto = (id->protocol_id == 0) ? SSH_IPPROTO_ANY : id->protocol_id;
  *port = id->port_number;

  if (port_range_end)
    *port_range_end = id->port_range_end;

  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      if (!name1 || *name1_len == 0)
        return FALSE;
      SSH_IP4_DECODE(&ipaddr, id->identification.ipv4_addr);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      n1 = name1;
      break;
    case IPSEC_ID_FQDN:
      if (!name1 || *name1_len == 0)
        return FALSE;
      ssh_ustrncpy(name1, id->identification.fqdn, *name1_len);
      n1 = name1;
      break;
    case IPSEC_ID_USER_FQDN:
      if (!name1 || !name2 || *name1_len == 0 || *name2_len == 0)
        return FALSE;
      p = at = ssh_ustrchr(id->identification.user_fqdn, '@');
      if (!at)
        return FALSE;
      *at++ = '\0';
      ssh_ustrncpy(name1, id->identification.user_fqdn, *name1_len);
      ssh_ustrncpy(name2, at, *name2_len);
      *p = '@'; /* restore the contents of ID */
      n1 = name1;
      n2 = name2;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      if (!name1 || !name2 || *name1_len == 0 || *name2_len == 0)
        return FALSE;
      SSH_IP4_DECODE(&ipaddr, id->identification.ipv4_addr_subnet);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      SSH_IP4_DECODE(&ipaddr, id->identification.ipv4_addr_netmask);
      ssh_ipaddr_print(&ipaddr, name2, *name2_len);
      n1 = name1;
      n2 = name2;
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      if (!name1 || !name2 || *name1_len == 0 || *name2_len == 0)
        return FALSE;
      SSH_IP4_DECODE(&ipaddr, id->identification.ipv4_addr_range1);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      SSH_IP4_DECODE(&ipaddr, id->identification.ipv4_addr_range2);
      ssh_ipaddr_print(&ipaddr, name2, *name2_len);
      n1 = name1;
      n2 = name2;
      break;
    case IPSEC_ID_IPV6_ADDR:
      if (!name1 || *name1_len == 0)
        return FALSE;
      SSH_IP6_DECODE(&ipaddr, id->identification.ipv6_addr);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      n1 = name1;
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      if (!name1 || !name2 || *name1_len == 0 || *name2_len == 0)
        return FALSE;
      SSH_IP6_DECODE(&ipaddr, id->identification.ipv6_addr_subnet);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      SSH_IP6_DECODE(&ipaddr, id->identification.ipv6_addr_netmask);
      ssh_ipaddr_print(&ipaddr, name2, *name2_len);
      n1 = name1;
      n2 = name2;
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      if (!name1 || !name2 || *name1_len == 0 || *name2_len == 0)
        return FALSE;
      SSH_IP6_DECODE(&ipaddr, id->identification.ipv6_addr_range1);
      ssh_ipaddr_print(&ipaddr, name1, *name1_len);
      SSH_IP6_DECODE(&ipaddr, id->identification.ipv6_addr_range2);
      ssh_ipaddr_print(&ipaddr, name2, *name2_len);
      n1 = name1;
      n2 = name2;
      break;

    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      {
        int i, len = SSH_MIN(id->identification_len, *name1_len / 3 - 2);

        for (i = 0; i < len; i++)
          ssh_snprintf(name1 + i * 3, 4, "%02x ",
                       id->identification.asn1_data[i]);
        break;
      }
      break;
    case IPSEC_ID_KEY_ID:
      {
        int i, len = SSH_MIN(id->identification_len, *name1_len / 3 - 2);

        for (i = 0; i < len; i++)
          ssh_snprintf(name1 + i * 3, 4, "%02x ",
                       id->identification.key_id[i]);
      }
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      if (name1_len)
        *name1_len = 0;
      if (name2_len)
        *name2_len = 0;
      break;
#endif /* SSHDIST_IKE_ID_LIST */
    }

#undef SSH_MIN

  if (n1)
    *name1_len = ssh_ustrlen(n1);
  if (n2)
    *name2_len = ssh_ustrlen(n2);

  return TRUE;
}

/* Encode data given as arguments as a new ID payload type */
Boolean ssh_ike_id_encode(SshIkePayloadID id,
                          SshIkeIpsecIdentificationType type,
                          SshIkeIpsecIPProtocolID proto,
                          SshUInt16 port,
                          SshUInt16 port_range_end,
                          const unsigned char *name1,
                          const unsigned char *name2)
{
  size_t datalen, len;

  if (!name1)
    return FALSE;

  id->id_type = type;
  id->protocol_id = (proto == SSH_IPPROTO_ANY) ? 0 : proto;
  id->port_number = port;
  id->port_range_end = port_range_end;

  switch (id->id_type)
    {
    case IPSEC_ID_FQDN:
      id->identification.fqdn = ssh_strdup(name1);
      if (id->identification.fqdn == NULL)
        return FALSE;
      id->identification_len = strlen((char *)id->identification.fqdn);
      break;
    case IPSEC_ID_USER_FQDN:
      if (!name2)
        return FALSE;

      len = ssh_ustrlen(name1) + ssh_ustrlen(name2) + 2;
      id->identification.user_fqdn = ssh_malloc(len);
      if (id->identification.user_fqdn == NULL)
        return FALSE;
      ssh_snprintf(id->identification.user_fqdn, len,
                   "%s@%s", name1, name2);
      id->identification_len = len - 1;
      break;
    case IPSEC_ID_IPV4_ADDR:
      datalen = sizeof(id->identification.ipv4_addr);
      if (!ssh_inet_strtobin(name1, id->identification.ipv4_addr, &datalen))
        return FALSE;
      id->identification_len = 4;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      if (!name2)
        return FALSE;
      datalen = sizeof(id->identification.ipv4_addr_subnet);
      if (!ssh_inet_strtobin(name1, id->identification.ipv4_addr_subnet,
                             &datalen))
        return FALSE;
      if (ssh_usstrcmp(name2, "255.255.255.255"))
        {
          if (!ssh_inet_strtobin(name2,
                                 id->identification.ipv4_addr_netmask,
                                 &datalen))
            return FALSE;
        }
      else
        SSH_IKE_PUT32(id->identification.ipv4_addr_netmask, 0xffffffff);
      id->identification_len = 8;
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      if (!name2)
        return FALSE;
      datalen = sizeof(id->identification.ipv4_addr_range1);
      if (!ssh_inet_strtobin(name1, id->identification.ipv4_addr_range1,
                             &datalen) ||
          !ssh_inet_strtobin(name2,
                             id->identification.ipv4_addr_range2,
                             &datalen))
        return FALSE;
      id->identification_len = 8;
      break;
    case IPSEC_ID_IPV6_ADDR:
      id->identification_len = 16;
      if (!ssh_inet_strtobin(name1, id->identification.ipv6_addr,
                             &id->identification_len))
        return FALSE;
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      if (!name2)
        return FALSE;

      datalen = 16;
      if (!ssh_inet_strtobin(name1, id->identification.ipv6_addr_subnet,
                             &datalen))
        return FALSE;

      if (ssh_ustrchr(name2, ':'))
        {
          /* The netmask is specified as a hexadecimal IPv6
             address. */
          datalen = 16;
          if (!ssh_inet_strtobin(name2,
                                 id->identification.ipv6_addr_netmask,
                                 &datalen))
            return FALSE;
        }
      else
        {
          int masklen;
          unsigned int mask;
          int w;

          /* Otherwise, the netmask must be an integer number between
             0 and 128. */

          masklen = (int) ssh_ustrtol(name2, NULL, 10);
          if (masklen > 128)
            return FALSE;

          for (w = 0; w < 4; w++)
            {
              mask = ((masklen >= 32)
                      ? 0xffffffff
                      : ((masklen != 0)
                         ? 0xffffffff << (32 - masklen)
                         : 0x0));
              SSH_IKE_PUT32(id->identification.ipv6_addr_netmask + w * 4,
                            mask);

              if (masklen >= 32)
                masklen -= 32;
              else
                masklen = 0;
            }
        }
      id->identification_len = 32;
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      if (!name2)
        return FALSE;

      datalen = 16;
      if (!ssh_inet_strtobin(name1, id->identification.ipv6_addr_range1,
                             &datalen))
        return FALSE;

      datalen = 16;
      if (!ssh_inet_strtobin(name2,
                             id->identification.ipv6_addr_range2,
                             &datalen))
        return FALSE;

      id->identification_len = 32;
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      len = ssh_ustrlen(name1);
      id->identification.asn1_data = ssh_malloc(len);
      if (id->identification.asn1_data == NULL)
        return FALSE;
      if ((id->identification_len =
           ssh_ike_id_read_hexdata(id->identification.asn1_data, name1)) == 0)
        {
          ssh_free(id->identification.asn1_data);
          id->identification.asn1_data = NULL;
          return FALSE;
        }
      break;
    case IPSEC_ID_KEY_ID:
      len = ssh_ustrlen(name1);
      id->identification.key_id = ssh_malloc(len);
      if (id->identification.key_id == NULL)
        return FALSE;
      if ((id->identification_len =
           ssh_ike_id_read_hexdata(id->identification.key_id, name1)) == 0)
        {
          ssh_free(id->identification.key_id);
          id->identification.key_id = NULL;
          return FALSE;
        }
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      id->identification.id_list_number_of_items = 0;
      id->identification.id_list_items = NULL;
      id->identification_len = 0;
      break;
#endif /* SSHDIST_IKE_ID_LIST */
    }
  return TRUE;
}
