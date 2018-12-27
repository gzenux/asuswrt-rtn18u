/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Distinguished names encoder between DER and string LDAP formats. The
   LDAP string is suitable for configuration files etc. The DER format
   is used by X.509 certificate code.
*/

#include "sshincludes.h"

#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshasn1.h"
#include "x509.h"
#include "dn.h"
#include "oid.h"
#include "sshstr.h"

#include <ctype.h>

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertDNEncode"

/* We need routines for making it possible to handle distinguished names
   in reasonably simple manner. */

/* Initialize a DN. */
void ssh_dn_init(SshDN dn)
{
  dn->rdn_count = 0;
  dn->rdn       = NULL;
  dn->ldap      = NULL;
  dn->der       = NULL;
  dn->der_len   = 0;
}

SshDN ssh_dn_create(const unsigned char *der, size_t der_len,
                    SshX509Config config)
{
  SshDN dn;

  if ((dn = ssh_calloc(1, sizeof(*dn))) != NULL)
    {
      ssh_dn_init(dn);
      if (ssh_dn_decode_der(der, der_len, dn, config) == 0)
        {
          ssh_dn_clear(dn);
          ssh_free(dn);
          return NULL;
        }
    }
  return dn;
}

/* Clear the DN. */
void ssh_dn_clear(SshDN dn)
{
  SshRDN temp, next;
  unsigned int i;

  if (dn == NULL)
    return;

  for (i = 0; i < dn->rdn_count; i++)
    {
      for (temp = dn->rdn[i]; temp; temp = next)
        {
          next = temp->next;
          /* Free OID. */
          ssh_free(temp->oid);
          /* Free contents. */
          ssh_str_free(temp->c);
          ssh_free(temp);
        }
    }
  dn->rdn_count = 0;
  ssh_free(dn->rdn);
  dn->rdn       = NULL;

  dn->ldap      = NULL;
  dn->der       = NULL;
  dn->der_len   = 0;
}

int ssh_dn_empty(SshDN dn)
{
  if (dn->rdn == NULL)
    return 1;
  return 0;
}

int ssh_rdn_equal(SshRDN op1, SshRDN op2)
{
  for (; op1 && op2; op1 = op1->next, op2 = op2->next)
    {
      /* The RDN is bad if OID is NULL. */
      if (op1->oid == NULL || op2->oid == NULL)
        return 0;

      if (ssh_ustrcmp(op1->oid, op2->oid) != 0)
        return 0;
      if (ssh_str_cmp(op1->c, op2->c) != 0)
        return 0;
    }
  /* The RDN's have different number of parts. */
  if (op1 != NULL || op2 != NULL)
    return 0;

  return 1;
}

int ssh_dn_equal(SshDN op1, SshDN op2)
{
  int i;
  if (op1 == NULL || op2 == NULL)
    {
      if (op1 != NULL || op2 != NULL)
        return 0;
      return 1;
    }

  if (op1->rdn_count != op2->rdn_count)
    return 0;

  for (i = 0; i < op1->rdn_count; i++)
    {
      if (ssh_rdn_equal(op1->rdn[i], op2->rdn[i]) == 0)
        return 0;
    }
  return 1;
}

unsigned int ssh_dn_length(SshDN dn)
{
  return dn->rdn_count;
}

/* This is O(n) algorithm, where n is the number of parts in the RDN.
 */
unsigned int ssh_rdn_length(SshRDN rdn)
{
  unsigned int l;
  for (l = 0; rdn; rdn = rdn->next, l++)
    ;
  return l;
}

/* Put in a new RDN, steal the original. */
Boolean ssh_dn_put_rdn(SshDN dn, SshRDN rdn)
{
  SshRDN *tmp;

  /* Allocate some new space for the RDN. */
  if ((tmp = ssh_realloc(dn->rdn,
                         sizeof(SshRDN) * (dn->rdn_count),
                         sizeof(SshRDN) * (dn->rdn_count + 1))) != NULL)
    {
      dn->rdn = tmp;
      /* Place the new RDN in. */
      dn->rdn[dn->rdn_count] = rdn;
      dn->rdn_count++;
      return TRUE;
    }
  return FALSE;
}

void ssh_dn_reverse(SshDN dn)
{
  SshRDN t;
  size_t i;

  /* Verify a bit. */

  if (dn == NULL)
    return;
  if (dn->rdn == NULL)
    return;

  /* Do the reversing. */
  for (i = 0; i < dn->rdn_count/2; i++)
    {
      t = dn->rdn[i];
      dn->rdn[i] = dn->rdn[dn->rdn_count - (i + 1)];
      dn->rdn[dn->rdn_count - (i + 1)] = t;
    }
}

/* We don't need a remove function.*/

/* Handling of RDN's. */
void ssh_rdn_init(SshRDN r)
{
  memset(r, 0, sizeof(*r));
}

void ssh_rdn_clear(SshRDN r)
{
  ssh_free(r->oid);
  ssh_str_free(r->c);
  r->next = NULL;
  r->oid  = NULL;
  r->c = NULL;
}

SshRDN ssh_rdn_alloc(unsigned char *oid, SshCharset charset,
                     unsigned char *c, size_t c_len)
{
  SshRDN rdn = ssh_malloc(sizeof(*rdn));

  if (rdn)
    {
      ssh_rdn_init(rdn);
      rdn->oid = oid;

      if (c != NULL)
        {
          /* Convert to the internal representation. */
          rdn->c = ssh_str_make(charset, c, c_len);
          if (rdn->c == NULL)
            {
              ssh_free(rdn);
              return NULL;
            }
        }
    }
  else
    {
      ssh_free(c);
    }
  return rdn;
}

SshRDN ssh_rdn_copy(SshRDN rdn)
{
  SshRDN prev = NULL;
  SshRDN copy_list = NULL;

  for (; rdn; rdn = rdn->next)
    {
      SshRDN copy;

      if ((copy = ssh_malloc(sizeof(*copy))) == NULL)
        {
          ssh_rdn_free(copy_list);
          copy_list = NULL;
          break;
        }
      ssh_rdn_init(copy);
      copy->c = ssh_str_dup(rdn->c);
      copy->oid = ssh_strdup(rdn->oid);

      if (copy_list == NULL)
        copy_list = copy;
      else
        prev->next = copy;

      prev = copy;
    }
  return copy_list;
}

void ssh_rdn_free(SshRDN rdn)
{
  SshRDN temp;

  for (; rdn; rdn = temp)
    {
      temp = rdn->next;
      ssh_free(rdn->oid);
      ssh_str_free(rdn->c);
      ssh_free(rdn);
    }
}

SshRDN ssh_dn_take_last_rdn(SshDN dn)
{
  if (dn == NULL)
    return NULL;
  if (dn->rdn_count == 0)
    return NULL;
  return dn->rdn[dn->rdn_count - 1];
}

/* Routines which do things with RDN's and DN's. */

/* Basic comparison routines. */

/* Question: is a distinguished name <CN=Mika Kojo,O=SSH> same as
   <O=SSH,CN=Mika Kojo>? I think they are not, but cannot be sure
   if really so. */
int ssh_dn_compare(SshDN a, SshDN b)
{
  return 0;
}

/* Matching should be easier, e.g. we support wildcards such as '*' and
   '?' to see whether a matches the mask. */
int ssh_dn_match(SshDN a, SshDN mask)
{
  return 0;
}

/* Own comparison function for allowing both lower and upper case to pass. */
int ssh_dn_memcmp(const unsigned char *a, const unsigned char *b, size_t len)
{
  size_t i;
  unsigned char ap, bp;

  for (i = 0; i < len; i++)
    {
      ap = toupper(a[i]);
      bp = toupper(b[i]);
      if (ap < bp)
        return -1;
      if (ap > bp)
        return 1;
    }
  return 0;
}

#define SSH_DN_MAX_DIMENSION (18 + 1)
#define SSH_DN_C      (1 << 0)
#define SSH_DN_L      (1 << 1)
#define SSH_DN_SERIAL_NO    (1 << 2)
#define SSH_DN_STREET (1 << 3)
#define SSH_DN_ST     (1 << 4)
#define SSH_DN_O      (1 << 5)
#define SSH_DN_OU     (1 << 6)
#define SSH_DN_CN     (1 << 7)
#define SSH_DN_MAILTO (1 << 8)
#define SSH_DN_UNSTRUCTURED (1 << 9)
#define SSH_DN_SURNAME      (1 << 10)
#define SSH_DN_TITLE        (1 << 11)
#define SSH_DN_NAME         (1 << 12)
#define SSH_DN_GNAME        (1 << 13)
#define SSH_DN_INITIALS     (1 << 14)
#define SSH_DN_GQ           (1 << 15)
#define SSH_DN_X500UID      (1 << 16)
#define SSH_DN_DNQ          (1 << 17)

const unsigned int ssh_dn_connex[SSH_DN_MAX_DIMENSION] =
{
  /* Root. */
  SSH_DN_C | SSH_DN_L | SSH_DN_ST | SSH_DN_O,
  /* Country. */
  SSH_DN_L | SSH_DN_ST | SSH_DN_O,
  /* Locality */
  SSH_DN_L | SSH_DN_ST | SSH_DN_STREET | SSH_DN_O | SSH_DN_OU | SSH_DN_CN |
    SSH_DN_MAILTO,
  /* Serial number */
  SSH_DN_O | SSH_DN_OU | SSH_DN_CN | SSH_DN_MAILTO,
  /* Street */
  SSH_DN_O | SSH_DN_OU | SSH_DN_CN | SSH_DN_MAILTO,
  /* State */
  SSH_DN_L | SSH_DN_ST | SSH_DN_STREET | SSH_DN_O | SSH_DN_OU | SSH_DN_CN |
    SSH_DN_MAILTO,
  /* Organization */
  SSH_DN_L | SSH_DN_ST | SSH_DN_STREET | SSH_DN_OU | SSH_DN_CN |
    SSH_DN_MAILTO,
  /* Organization unit */
  SSH_DN_L | SSH_DN_ST | SSH_DN_STREET | SSH_DN_OU | SSH_DN_CN |
    SSH_DN_MAILTO,
  /* Common name */
  0,
  /* Mail-to, non-standard thing. */
  0,
  /* Unstructured name. */
  0,
  /* Surname */
  0,
  /* Title */
  0,
  /* Name */
  0,
  /* Given name. */
  0,
  /* Initials. */
  0,
  /* Generation qualifier */
  0,
  /* X.500 unique identifier */
  0,
  /* DN Qualifier */
  0
};

/* Code which tries to figure out whether this DN can be seen to be
   correct in X.521 sense. */

int ssh_dn_is_valid(SshDN dn)
{
  SshRDN temp_rdn;
  int j;
  unsigned int i;
  unsigned int mask, prev_mask, unknown;
  const SshOidStruct *oid;

  /* Assume that nobody does correct X.500 directory names anymore. This
     is a reasonable assumption. */
  unknown = 0;

  /* Do the main loop. */
  for (i = 0, prev_mask = ssh_dn_connex[0]; i < dn->rdn_count; i++)
    {
      /* Compute the RND mask, which we assume to be the correct way to
         do things. This is not very clear in the X.521 paper which I
         read. However, perhaps it was too old. */
      mask = 0;
      for (temp_rdn = dn->rdn[i]; temp_rdn; temp_rdn = temp_rdn->next)
        {
          /* Try to figure out the oid. */
          oid = ssh_oid_find_by_oid_of_type(temp_rdn->oid, SSH_OID_DN);
          if (oid == NULL)
            unknown++;
          else
            mask |= 1 << oid->extra_int;
        }
      if (unknown)
        {
          /* We are now playing in unknown territory, thus what can we
             do but pass? */
          prev_mask = ~((unsigned int)0);
          continue;
        }

      /* Check if this is even possible! */
      if ((mask & prev_mask) == 0)
        return 0;

      /* Compute new mask. */
      prev_mask = 0;
      for (j = 0; j < SSH_DN_MAX_DIMENSION - 1; j++)
        if (((1 << j) & mask))
          prev_mask |= ssh_dn_connex[j + 1];
      /* Continue now. */
    }
  return unknown + 1;
}


/* Find RDN by the oid. Oid must be in the number format (i.e 1.2.3.4, not as
   string "SN"). Returns NULL if there is no entry matching to oid. The SshRDN
   returned is shared with the SshDN and it is valid as long as dn given to
   this function is valid and is not modified. */
SshRDN ssh_find_rdn_by_oid(SshDN dn, const char *oid)
{
  int i;

  for (i = 0; i < dn->rdn_count; i++)
    {
      if (ssh_usstrcmp(dn->rdn[i]->oid, oid) == 0)
        {
          return dn->rdn[i];
        }
    }
  return NULL;
}

/* This function converts the given string `str' to Asn.1 DER encoded
   data blob with given `charset'. */
Boolean
ssh_str_get_der(SshAsn1Context c,
                SshStr str, SshCharset charset, SshAsn1Node *node)
{
  SshStr new_str;
  unsigned char *buf;
  size_t buf_len;
  SshAsn1Status status = SSH_ASN1_STATUS_OPERATION_FAILED;

  if (str == NULL)
    return FALSE;

  new_str = ssh_str_charset_convert(str, charset);
  if (new_str == NULL)
    return FALSE;

  buf = ssh_str_get(new_str, &buf_len);
  ssh_str_free(new_str);
  if (buf == NULL)
    return FALSE;

  switch (charset)
    {
    case SSH_CHARSET_PRINTABLE:
      status =
        ssh_asn1_create_node(c, node, "(printable-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_VISIBLE:
      status =
        ssh_asn1_create_node(c, node, "(visible-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_US_ASCII:
      status =
        ssh_asn1_create_node(c, node, "(ia5-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_T61:
      status =
        ssh_asn1_create_node(c, node, "(teletex-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_BMP:
      status =
        ssh_asn1_create_node(c, node, "(bmp-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_UNIVERSAL:
      status =
        ssh_asn1_create_node(c, node, "(universal-string ())", buf, buf_len);
      break;
    case SSH_CHARSET_UTF8:
      status =
        ssh_asn1_create_node(c, node, "(utf8-string ())", buf, buf_len);
      break;
    default:
      ssh_fatal("ssh_str_get_der: charset %u not supported in this function.",
                charset);
      break;
    }

  ssh_free(buf);

  if (status != SSH_ASN1_STATUS_OK)
    return FALSE;

  return TRUE;
}

int ssh_dn_char_str_cmp(unsigned char *first_buffer,
                        size_t first_buffer_size,
                        unsigned char *second_buffer,
                        size_t second_buffer_size)
{
  SshDNStruct dn1[1], dn2[1];
  char *first_name = NULL, *second_name = NULL;
  int rv = -1;

  ssh_dn_init(dn1);
  ssh_dn_init(dn2);

  if (!ssh_dn_decode_der(first_buffer, first_buffer_size, dn1, NULL))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("Failed to decode buffer1:"),
                        first_buffer, first_buffer_size);
      goto end;
    }

  if (!ssh_dn_decode_der(second_buffer, second_buffer_size, dn2, NULL))
    {
      SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("Failed to decode buffer2:"),
                        second_buffer, second_buffer_size);
      goto end;
    }

  if (!ssh_dn_encode_ldap(dn1, &first_name))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode DN name"));
      goto end;
    }

  if (!ssh_dn_encode_ldap(dn2, &second_name))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode DN name"));
      goto end;
    }

  if (!strcmp(first_name, second_name))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("DN names match: '%s' '%s'",
                              first_name, second_name));
      rv = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("DN names mismatch: '%s' '%s'",
                              first_name, second_name));
      rv = -1;
    }

 end:
  if (first_name != NULL)
    ssh_free(first_name);

  if (second_name != NULL)
    ssh_free(second_name);

  ssh_dn_clear(dn1);
  ssh_dn_clear(dn2);

  return rv;
}
#endif /* SSHDIST_CERT */
