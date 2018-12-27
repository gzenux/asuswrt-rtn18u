/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Helper for viewing some BER encoded files.
*/

#include "sshincludes.h"
#include "sshglobals.h"
#include "sshfileio.h"
#include "sshasn1.h"
#include "oid.h"
#include "iprintf.h"
#include "sshgetopt.h"

void usage(void)
{
  printf("usage: ssh-berdump [options] [[:bhp:]file]\n"
         "options: \n"
         " -o x  starts at offset position x.\n"
         " -s    expand strings to ASN.1 if they can be parsed as such.\n"
         "\n");
  exit(0);
}

int main(int argc, char **argv)
{
  int opt;
  char *file, *program;
  unsigned char *buf;
  size_t buf_size;
  size_t offset;
  Boolean ret;
  Boolean no_string_decode = 1;

  printf("SSH BER/DER Dumper\n"
         "Copyright (c) 2002 - 2014, INSIDE Secure Oy."
         "  All rights reserved.\n");

  program = argv[0];

  ssh_global_init();

  if (!ssh_math_library_initialize())
    {
      ssh_warning("%s: Failed to initialize math library.", program);
      exit(1);
    }

  /* Defaults. */
  file = NULL;
  offset = 0;

  while ((opt = ssh_getopt(argc, argv, "o:s", NULL)) != -1)
    {
      switch (opt)
        {
        case 'o': offset = atoi(ssh_optarg); break;
        case 's': no_string_decode = 0; break;
        case '?':
        default: usage(); exit(1);
        }
    }

  while (ssh_optind < argc)
    {
      file = argv[ssh_optind];
      ssh_optind++;
      ret = ssh_read_gen_file(file, &buf, &buf_size);

      if (!ret)
        {
          ssh_warning("%s: Could not read input file '%s'", program, file);
          continue;
        }

      if (file[0] != ':')
        {
          int i;

          for(i = 0; isspace(buf[i]) && i < buf_size; i++)
            ;

          if (i < buf_size && buf[i] == '-')
            {
              /* Try pem format. */
              ssh_free(buf);
              if (!ssh_read_file_base64(file, &buf, &buf_size))
                {
                  ssh_warning("ssh-berdump: Could not read file as "
                              "base64 %s\n",
                              file);
                  if (!ssh_read_file(file, &buf, &buf_size))
                    {
                      ssh_warning("ssh-berdump: Could not read file %s\n",
                                  file);
                      continue;
                    }
                }
            }
          else if (i < buf_size && isxdigit(buf[i]))
            {
              for(; isxdigit(buf[i]) && i < buf_size; i++)
                ;

              if (buf[i] == ':')
                {
                  /* Try hexl format. */
                  ssh_free(buf);
                  if (!ssh_read_file_hexl(file, &buf, &buf_size))
                    {
                      ssh_warning("ssh-berdump: "
                                  "Could not read hexl encoded file %s", file);
                      if (!ssh_read_file(file, &buf, &buf_size))
                        {
                          ssh_warning("ssh-berdump: Could not read file %s\n",
                                      file);
                          continue;
                        }
                    }
                }
            }
        }

      if (offset >= buf_size)
        {
          ssh_warning("%s: Start offset %zd larger than input size %zd",
                      program, offset, buf_size);
          ssh_xfree(buf);
          continue;
        }

      (void)cu_dump_ber(buf, buf_size,
                        offset, no_string_decode, TRUE);
      ssh_xfree(buf);
    }
  ssh_math_library_uninitialize(); /* Not really necessary */

  ssh_util_uninit();
  return 0;
}
