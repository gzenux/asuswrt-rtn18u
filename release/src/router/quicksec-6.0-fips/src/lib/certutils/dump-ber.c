/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certview BER dumper.
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshfileio.h"
#include "sshmp.h"
#include "sshasn1.h"
#include "oid.h"
#include "iprintf.h"

const char *classes[4] =
{
  "UNIVERSAL",
  "APPLICATION",
  "CONTEXT",
  "PRIVATE"
};

const char *encodings[2] =
{
  "p",
  "c"
};

const char *length_encodings[2] =
{
  "d",
  "i",
};

const char *tags[32] =
{
  "RESERVED",    /* 0 */
  "BOOLEAN",     /* 1 */
  "INTEGER",     /* 2 */
  "BIT STRING",        /* 3 */
  "OCTET STRING",      /* 4 */
  "NULL",                /* 5 */
  "OBJECT IDENTIFIER",    /* 6 */
  "ODE",               /* 7 */
  "ETI",               /* 8 */
  "REAL",              /* 9 */
  "ENUM",              /* 10 */
  "EMBEDDED",          /* 11 */
  "UTF8 STRING",       /* 12 */
  "RESERVED",  "RESERVED",  "RESERVED", /* 13 14 15 */
  "SEQUENCE",  /* 16 */
  "SET",       /* 17 */
  "NUMERIC STRING",  /* 18 */
  "PRINTABLE STRING",  /* 19 */
  "TELETEX STRING",    /* 20 */
  "VIDEOTEX STRING",   /* 21 */
  "IA5 STRING",        /* 22 */
  "UNIVERSAL TIME",    /* 23 */
  "GENERALIZED TIME",  /* 24 */
  "GRAPHIC STRING",    /* 25 */
  "VISIBLE STRING",    /* 26 */
  "GENERAL STRING",     /* 27 */
  "UNIVERSAL STRING",    /* 28 */
  "UNRESTRICTED STRING",   /* 29 */
  "BMP STRING",          /* 30 */
  "RESERVED"           /* 31 */
};

typedef struct BerDumpContextRec
{
  int block_offset;
  int indent_step;
  Boolean no_string_decode;
  Boolean print_offsets;
} *BerDumpContext, BerDumpContextStruct;

static
int print_tree(SshAsn1Context context, SshAsn1Tree tree,
               int pos, BerDumpContext conf);

static
void print_ber_time(SshBerTime ber_time)
{
  const char *month_table[13] =
  { "n/a", "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec" };
  char *day_postfix = "  ";

  if ((ber_time->day % 10) == 0)
    day_postfix = "th";
  if ((ber_time->day % 10) == 1 && ber_time->day / 10 != 1)
    day_postfix = "st";
  if ((ber_time->day % 10) == 2 && ber_time->day / 10 != 1)
    day_postfix = "nd";
  if ((ber_time->day % 10) == 3 && ber_time->day / 10 != 1)
    day_postfix = "rd";
  if ((ber_time->day % 10) > 3 || ber_time->day / 10 == 1)
    day_postfix = "th";

  /* Assume GMT. */
  printf("%04d %s %2d%s, %02d:%02d:%02d GMT\n",
         ber_time->year, month_table[ber_time->month],
         ber_time->day, day_postfix,
         ber_time->hour, ber_time->minute, (unsigned int)ber_time->second);
}

static
void print_long_integer(SshMPInteger mpint)
{
  int len = ssh_mprz_get_size(mpint, 16);
  char *buffer;
  int i;

  buffer = ssh_mprz_get_str(mpint, 16);
  if (!buffer)
    return;

  if (len < 40)
    {
      printf("   %s", buffer);
    }
  else
    {
      printf("\n       ");
      for (i = 0; i < strlen(buffer); i++)
        {
          if ((i % 70) == 0 && i > 0)
            printf("\\\n       ");
          printf("%c", buffer[i]);
        }
    }
  ssh_xfree(buffer);
  printf(" (%u bits)\n", ssh_mprz_get_size(mpint, 2));
}

static
void ssh_oid_dump(char *oid)
{
  const SshOidStruct *oids;

  oids = ssh_oid_find_by_oid(oid);
  if (oids == NULL)
    printf("%s\n", oid);
  else
    printf("%s (%s)\n", oids->std_name, oid);
}

static
int print_node(SshAsn1Context context,
               int level, SshAsn1Node node, int pos,
               BerDumpContext conf)
{
  SshAsn1Class class_type;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  SshAsn1Tree tree;
  size_t length;
  unsigned char *data;
  SshAsn1Status status;
  SshBerTimeStruct ber_time;
  char *oid;
  int i, omega;
  SshAsn1Context tmpctx;

  if ((status = ssh_asn1_node_get(node, &class_type, &encoding, &tag_number,
                                  &length_encoding,
                                  &length, &data)) != SSH_ASN1_STATUS_OK)
    {
      printf("error: status code \"%s\"\n", ssh_asn1_error_string(status));
      exit(1);
    }


  if (conf->print_offsets)
      printf("%04d :", pos);
  else
    printf(" ");

  i = level * conf->indent_step; while (i--)  putchar(' ');
  iprintf_get(NULL, &level, NULL);
  i = level; while (i--)  putchar(' ');
#if 0


  for (i = 0; i < level; i++)
    printf("  ");
#endif

  if (tag_number < 32 && class_type == SSH_ASN1_CLASS_UNIVERSAL)
    printf(" %s", tags[tag_number]);
  else
    {
      if (class_type < SSH_ASN1_CLASS_MAX)
        printf(" %s %d", classes[class_type], (int)tag_number);
      else
        printf(" [CLASS %d TAG %d]", (int)class_type, (int)tag_number);
    }

  if (class_type == SSH_ASN1_CLASS_UNIVERSAL)
    switch (tag_number)
      {
      case SSH_ASN1_TAG_SET:
      case SSH_ASN1_TAG_SEQUENCE:
        if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
          printf("\n");
        else
          printf("  (indefinite form)\n");
        break;

      case SSH_ASN1_TAG_INTEGER:
        {
          SshMPIntegerStruct mpint;

          ssh_mprz_init(&mpint);
          status = ssh_asn1_read_node(context, node,
                                      "(integer ())", &mpint);
          if (status != SSH_ASN1_STATUS_OK)
            printf("  [failure]\n");
          else
            print_long_integer(&mpint);
          ssh_mprz_clear(&mpint);
        }
      break;
      case SSH_ASN1_TAG_BOOLEAN:
        if (length == 0)
          {
            printf("  [failure]\n");
            break;
          }

        if (data[0] == 0)
          printf("  FALSE\n");
        else
          printf("  TRUE\n");
        break;
      case SSH_ASN1_TAG_OID_TYPE:
        status = ssh_asn1_read_node(context, node,
                                    "(object-identifier ())",
                                    &oid);
        if (status == SSH_ASN1_STATUS_OK)
          {
            printf("  ");
            ssh_oid_dump(oid);
            ssh_free(oid);
          }
        else
          {
            printf("\n");
            ssh_write_file_hexl(NULL, data, length);
          }
        break;
      case SSH_ASN1_TAG_NULL:
        printf("\n");
        break;
      case SSH_ASN1_TAG_GENERALIZED_TIME:
        status = ssh_asn1_read_node(context, node,
                                    "(generalized-time ())",
                                    &ber_time);
        if (status == SSH_ASN1_STATUS_OK)
          {
            printf("  ");
            print_ber_time(&ber_time);
          }
        else
          {
            printf("\n");
            ssh_write_file_hexl(NULL, data, length);
          }
        break;
      case SSH_ASN1_TAG_UNIVERSAL_TIME:
        status = ssh_asn1_read_node(context, node,
                                    "(utc-time ())",
                                    &ber_time);
        if (status == SSH_ASN1_STATUS_OK)
          {
            printf("  ");
            print_ber_time(&ber_time);
          }
        else
          {
            printf("\n");
            ssh_write_file_hexl(NULL, data, length);
          }
        break;

      case SSH_ASN1_TAG_VISIBLE_STRING:
      case SSH_ASN1_TAG_PRINTABLE_STRING:
      case SSH_ASN1_TAG_IA5_STRING:
      case SSH_ASN1_TAG_TELETEX_STRING:
      case SSH_ASN1_TAG_OCTET_STRING:
      default:

        omega = length;
        if (!conf->no_string_decode)
          {
            for (omega = 0; omega < length; omega++)
              {
                if (omega > 0 && conf->no_string_decode)
                  break;

                /* Check whether the octet string can be decoded! */
                tmpctx = ssh_asn1_init();
                status =
                  ssh_asn1_decode(tmpctx, data + omega, length - omega, &tree);
                if (status == SSH_ASN1_STATUS_OK ||
                    status == SSH_ASN1_STATUS_OK_GARBAGE_AT_END ||
                    status == SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
                  {
                    if (ssh_asn1_get_current(tree) == NULL)
                      {
                        ssh_asn1_free(tmpctx);
                        continue;
                      }
                    /* What a co-incidence it is ASN.1 */
                    if (omega == 0 && status == SSH_ASN1_STATUS_OK)
                      printf(" (expanding to ASN.1)\n");
                    else
                      {
                        if (status != SSH_ASN1_STATUS_OK)
                          printf(" (expanding to ASN.1 at sub-offset %lu with"
                                 " garbage at end)\n", (unsigned long)omega);
                        else
                          printf(" (expanding to ASN.1 at sub-offset %lu)\n",
                                 (unsigned long)omega);
                      }
                    conf->block_offset++;
                    print_tree(tmpctx, tree,
                               pos + omega + ssh_asn1_node_size(node) - length,
                               conf);
                    conf->block_offset--;
                    ssh_asn1_free(tmpctx);
                    break;
                  }
                ssh_asn1_free(tmpctx);
              }
          }

        if (omega >= length || (omega && conf->no_string_decode))
          {
            /* Perform some nice string quessing here, someday. */
            printf("  (%lu bytes)\n", (unsigned long)length);
            if (conf->print_offsets)
              ssh_write_file_hexl(NULL, data, length);
            else
              {
                iprintf("#I");
                cu_dump_hex_and_text(data, length);
                iprintf("#i");
              }
          }
        break;
      }
  else
    {
      if (encoding != 1)
        {
          printf(" (%lu bytes) \n", (unsigned long)length);
          if (conf->print_offsets)
            ssh_write_file_hexl(NULL, data, length);
          else
            cu_dump_hex_and_text(data, length);

        }
      else
        {
          if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
            printf("\n");
          else
            printf("  (indefinite form) \n");
        }
    }

  /* Remember to free what you've allocated. */
  ssh_xfree(data);

  return pos + ssh_asn1_node_size(node);
}

static
int print_tree(SshAsn1Context context,
               SshAsn1Tree tree, int pos,
               BerDumpContext conf)
{
  do
    {
      pos = print_node(context,  conf->block_offset,
                       ssh_asn1_get_current(tree), pos, conf);

      if (ssh_asn1_move_down(tree) == SSH_ASN1_STATUS_OK)
        {
          conf->block_offset++;
          pos = print_tree(context, tree, pos, conf);
          conf->block_offset--;
          ssh_asn1_move_up(tree);
        }
    }
  while (ssh_asn1_move_forward(tree, 1));

  return pos;
}

/* Return FALSE on failure, TRUE on success. */
Boolean cu_dump_ber(unsigned char *buf, size_t buf_size, size_t offset,
                    Boolean no_string_decode, Boolean print_offsets)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  BerDumpContextStruct conf;

#if 0
  int print_level;

  iprintf_get(NULL, &print_level, NULL);

#endif

  conf.no_string_decode = no_string_decode;
  conf.print_offsets = print_offsets;
  conf.block_offset = 0;

  iprintf_get(NULL, NULL, &(conf.indent_step));
  context = ssh_asn1_init();
  status  = ssh_asn1_decode(context, buf + offset,
                            buf_size - offset, &tree);
  if (status == SSH_ASN1_STATUS_OK)
    print_tree(context, tree, 0,  &conf);
  else if (status == SSH_ASN1_STATUS_OK_GARBAGE_AT_END)
    {
      printf("warning: Garbage at end.\n");
      print_tree(context, tree, 0, &conf);
    }
  else if (status == SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      printf("warning: Bad garbage at end.\n");
      print_tree(context, tree, 0,  &conf);
    }
  else
    {
      printf("Could not ber decode read buffer.\n");
      ssh_asn1_free(context);
      return FALSE;
    }
  ssh_asn1_free(context);
  return TRUE;
}

void cu_dump_hex_and_text(unsigned char *str, size_t len)
{
#define SSHCVW 16
  char textdump[SSHCVW + 1];
  size_t i,j;
  for (i = j = 0; i < len; i++)
    {
      if (i > 0)
        iprintf(":");
      if (i > 0 && (i % SSHCVW) == 0)
        {
          textdump[j] = '\0';
          for (; j < SSHCVW; j++)
            iprintf("   ");
          j = 0;
          iprintf("   %s\n", textdump);
        }
      iprintf("%02x", str[i]);
      textdump[j++] = isprint(str[i]) ? str[i] : '.';
    }
  textdump[j] = '\0';
  for (; j < SSHCVW; j++)
    iprintf("   ");
  iprintf("    %s\n", textdump);
  return;
}
#endif /* SSHDIST_CERT */
