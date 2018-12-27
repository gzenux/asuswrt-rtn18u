/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML conformance testing tool for OASIS XML testsuite.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshxml.h"
#include "sshurl.h"
#include "sshfdstream.h"

#define SSH_DEBUG_MODULE "xmlconf"

/***************************** Static variables *****************************/

static int retval = 0;
static char *program = NULL;
static int namespaces = 1;
static int verbose = 0;
static int quiet = 0;
static int skip_too_loose = 0;

char *input_prefix = NULL;
char *test_input_prefix = NULL;
char *test_filename = NULL;

/* Parser for the testsuite. */
SshXmlParser parser;
SshXmlVerifier verifier;

/* Parser for individual XML test. */
SshXmlParser test_parser;
SshXmlVerifier test_verifier;

/* Statistics. */
SshUInt32 num_tests = 0;
SshUInt32 num_skipped = 0;
SshUInt32 num_failed_valid = 0;
SshUInt32 num_accepted_invalid = 0;
SshUInt32 num_accepted_not_wf = 0;
SshUInt32 num_accepted_error = 0;


/************************ Handling system resources *************************/

static SshOperationHandle
system_resource(const char *prefix, const char *sysid,
                SshXmlStreamCB result_cb, void *result_cb_context)
{
  SshStream stream;
  char *name;

  /* We only handle system resources. */
  if (sysid == NULL)
    {
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  if (prefix)
    {
      name = ssh_xmalloc(strlen(prefix) + 1 + strlen(sysid) + 1);
      name[0] = '\0';
      strcat(name, prefix);
      strcat(name, "/");
      strcat(name, sysid);
    }
  else
    {
      name = ssh_xstrdup(sysid);
    }

  stream = ssh_stream_fd_file(name, TRUE, FALSE);
  if (stream == NULL)
    {
      if (verbose)
        fprintf(stderr, "%s: Could not open file `%s'\n", program, name);
      ssh_xfree(name);
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  /* All done. */
  (*result_cb)(stream, name, NULL_FNPTR, NULL, result_cb_context);

  ssh_xfree(name);
  return NULL;
}


/************************* Handlers for test parser *************************/

static enum
{
  TEST_IGNORE,
  TEST_VALID,
  TEST_INVALID,
  TEST_NOT_WF,
  TEST_ERROR
} test_type;

SshXmlResultCB test_continue_result_cb;
void *test_continue_result_cb_context;

static unsigned char test_error_message[204];
static SshXmlResult test_result;


static void
test_result_cb(SshXmlResult result, void *context)
{
  test_result = result;

  /* Test processed.  Let's complete the start element. */
  (*test_continue_result_cb)(SSH_XML_OK, test_continue_result_cb_context);
}


static void
test_warning(SshXmlParser parser,
             const char *input_name, SshUInt32 line, SshUInt32 column,
             const char *message, void *context)
{
  if (verbose > 2)
    fprintf(stderr,
            "%s:%d: Warning: %s\n", input_name, (int) line,
            message);
}

static void
test_error(SshXmlParser parser,
           const char *input_name, SshUInt32 line, SshUInt32 column,
           const char *message, void *context)
{
  ssh_snprintf(test_error_message, sizeof(test_error_message),
               "%s:%d: Error: %s", input_name, (int) line,
               message);
}

static void
test_fatal_error(SshXmlParser parser,
                 const char *input_name, SshUInt32 line, SshUInt32 column,
                 const char *message, void *context)
{
  ssh_snprintf(test_error_message, sizeof(test_error_message),
               "%s:%d: Error: %s", input_name, (int) line,
               message);
}

static SshXmlErrorHandlerStruct test_error_handler =
{
  test_warning,
  test_error,
  test_fatal_error,
};


static SshOperationHandle
test_dtd_callback(SshXmlParser parser,
                  const unsigned char *pubid, size_t pubid_len,
                  const unsigned char *sysid, size_t sysid_len,
                  SshXmlStreamCB result_cb, void *result_cb_context,
                  void *context)
{
  return system_resource(test_input_prefix, (char *) sysid, result_cb,
                         result_cb_context);
}


static SshOperationHandle
test_entity_resolver(SshXmlParser parser, const char *where_defined,
                     Boolean general,
                     const unsigned char *name, size_t name_len,
                     const unsigned char *pubid, size_t pubid_len,
                     const unsigned char *sysid, size_t sysid_len,
                     SshXmlStreamCB result_cb,
                     void *result_cb_context,
                     void *context)
{
  return system_resource(test_input_prefix, (char *) sysid, result_cb,
                         result_cb_context);
}


/******************** Handlers for the testsuite parser *********************/

static void
result_cb(SshXmlResult result, void *context)
{
  if (result != SSH_XML_OK)
    {
      fprintf(stderr, "%s: parsing failed: %d\n", program, result);
      retval = result;
    }
  else
    {
      /* Print results. */
      fprintf(stdout,
              "#\t\t\t\t#fail\t#accept\n"
              "# Time\t\t#tests\t#skip\tvalid\tinval\tnot wf\terror\n"
              "%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
              (unsigned int) ssh_time(),
              (unsigned int) num_tests,
              (unsigned int) num_skipped,
              (unsigned int) num_failed_valid,
              (unsigned int) num_accepted_invalid,
              (unsigned int) num_accepted_not_wf,
              (unsigned int) num_accepted_error);
    }
}

static SshOperationHandle
xmlconf_start_element(SshXmlParser parser,
                      const unsigned char *name, size_t name_len,
                      SshADTContainer attributes,
                      SshXmlResultCB result_cb, void *result_cb_context,
                      void *context)
{
  const unsigned char *value;
  size_t value_len;
  char *cp;
  const char *file;
  Boolean enable;

  if (!ssh_xml_match(name, name_len, ssh_custr("TEST"), 0))
    {
      /* Ignore this tag. */
      (*result_cb)(SSH_XML_OK, result_cb_context);
      return NULL;
    }

  /* A new test starts. */
  num_tests++;

  /* Check if the test requires namespaces. */

  value = ssh_xml_get_attr_value(attributes, ssh_custr("NAMESPACE"), 0,
                                 &value_len);
  SSH_ASSERT(value != NULL);
  if (ssh_xml_match(value, value_len, ssh_custr("yes"), 0))
    {
      /* Do we process namespaces? */
      if (!namespaces)
        {
          num_skipped++;
          test_type = TEST_IGNORE;
          (*result_cb)(SSH_XML_OK, result_cb_context);
          return NULL;
        }
    }

  /* We are processing this test. */

  /* Get its type. */
  value = ssh_xml_get_attr_value(attributes, ssh_custr("TYPE"), 0, &value_len);
  SSH_ASSERT(value != NULL);
  if (ssh_xml_match(value, value_len, ssh_custr("valid"), 0))
    test_type = TEST_VALID;
  else if (ssh_xml_match(value, value_len, ssh_custr("invalid"), 0))
    test_type = TEST_INVALID;
  else if (ssh_xml_match(value, value_len, ssh_custr("not-wf"), 0))
    test_type = TEST_NOT_WF;
  else if (ssh_xml_match(value, value_len, ssh_custr("error"), 0))
    test_type = TEST_ERROR;
  else
    SSH_NOTREACHED;

  if (verbose)
    {
      /* Print test ID. */
      value = ssh_xml_get_attr_value(attributes, ssh_custr("ID"), 0, NULL);
      SSH_ASSERT(value != NULL);
      fprintf(stdout, "TEST: %s\n", value);
    }

  /* Check namespaces. */

  value = ssh_xml_get_attr_value(attributes, ssh_custr("NAMESPACE"), 0,
                                 &value_len);
  SSH_ASSERT(value != NULL);
  if (ssh_xml_match(value, value_len, ssh_custr("yes"), 0))
    enable = TRUE;
  else
    enable = FALSE;

  ssh_xml_parser_feature(test_parser, SSH_XML_PARSER_NAMESPACES, enable);

  /* Get URI. */

  value = ssh_xml_get_attr_value(attributes, ssh_custr("URI"), 0, NULL);
  SSH_ASSERT(value != NULL);

  ssh_xfree(test_input_prefix);
  test_input_prefix = NULL;

  /* Get the location of this tag. */
  ssh_xml_location(parser, &file, NULL, NULL);

  cp = NULL;
  if (file)
    cp = strrchr(file, '/');

  if (cp)
    {
      test_input_prefix = ssh_xmalloc(cp - file + 1
                                      + strlen((char *) value) + 1);
      memcpy(test_input_prefix, file, cp - file);
      test_input_prefix[cp - file] = '\0';
      strcat(test_input_prefix, "/");
      strcat(test_input_prefix, (char *) value);
    }
  else
    {
      test_input_prefix = ssh_xstrdup(value);
    }

  /* Save continuation callback. */
  test_continue_result_cb = result_cb;
  test_continue_result_cb_context = result_cb_context;

  ssh_xfree(test_filename);
  test_filename = ssh_xstrdup(test_input_prefix);

  test_error_message[0] = '\0';

  if (verbose > 1)
    fprintf(stdout, "FILE: %s\n", test_input_prefix);

  /* Parse the test */
  ssh_xml_parser_parse_xml_file(test_parser, test_input_prefix,
                                test_result_cb, NULL);

  /* And create the input prefix. */
  cp = strrchr(test_input_prefix, '/');
  if (cp)
    *cp = '\0';
  else
    {
      ssh_xfree(test_input_prefix);
      test_input_prefix = NULL;
    }

  /* All done here.  We continue from the result callback. */
  return NULL;



}

static SshOperationHandle
xmlconf_end_element(SshXmlParser parser,
                    const unsigned char *name, size_t name_len,
                    SshXmlResultCB result_cb, void *result_cb_context,
                    void *context)
{
  if (!ssh_xml_match(name, name_len, ssh_custr("TEST"), 0))
    {
      /* This was not a test. */
      (*result_cb)(SSH_XML_OK, result_cb_context);
      return NULL;
    }

  /* Check the result of the test. */
  switch (test_type)
    {
    case TEST_IGNORE:
      /* The test was ignored. */
      break;

    case TEST_VALID:
      if (test_result != SSH_XML_OK)
        {
          if (!quiet)
            {
              fprintf(stdout, "Test: %s:\n", test_filename);
              fprintf(stdout, "  FAIL: expected VALID, parser says %d\n",
                      test_result);
              fprintf(stdout, "  ERROR: %s\n", test_error_message);
            }
          num_failed_valid++;
        }
      break;

    case TEST_INVALID:
    case TEST_NOT_WF:
    case TEST_ERROR:
      if (test_result == SSH_XML_OK)
        {
          if (!quiet && !skip_too_loose)
            {
              fprintf(stdout, "Test: %s:\n", test_filename);
              fprintf(stdout,
                      "  FAIL: expected %s, parser says OK\n",
                      (test_type == TEST_INVALID
                       ? "INVALID"
                       : (test_type == TEST_NOT_WF
                          ? "NOT WELL-FORMED"
                          : "ERROR")));
            }

          switch (test_type)
            {
            case TEST_INVALID:
              num_accepted_invalid++;
              break;

            case TEST_NOT_WF:
              num_accepted_not_wf++;
              break;

            case TEST_ERROR:
              num_accepted_error++;
              break;

            default:
              SSH_NOTREACHED;
              break;
            }
        }
      break;
    }

  /* And continue. */
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static SshXmlContentHandlerStruct content_handler =
{
  NULL_FNPTR,
  NULL_FNPTR,
  xmlconf_start_element,
  xmlconf_end_element,
  NULL_FNPTR,
  NULL_FNPTR,
  NULL_FNPTR,
};


static void
xmlconf_warning(SshXmlParser parser,
                const char *input_name, SshUInt32 line, SshUInt32 column,
                const char *message, void *context)
{
  fprintf(stderr,
          "%s:%d: Warning: %s\n", input_name, (int) line,
          message);
}

static void
xmlconf_error(SshXmlParser parser,
              const char *input_name, SshUInt32 line, SshUInt32 column,
              const char *message, void *context)
{
  fprintf(stderr,
          "%s:%d: Error: %s\n", input_name, (int) line,
          message);
}

static void
xmlconf_fatal_error(SshXmlParser parser,
                    const char *input_name, SshUInt32 line, SshUInt32 column,
                    const char *message, void *context)
{
  fprintf(stderr,
          "%s:%d: Error: %s\n", input_name, (int) line,
          message);
}

static SshXmlErrorHandlerStruct error_handler =
{
  xmlconf_warning,
  xmlconf_error,
  xmlconf_fatal_error,
};


static SshOperationHandle
dtd_callback(SshXmlParser parser,
             const unsigned char *pubid, size_t pubid_len,
             const unsigned char *sysid, size_t sysid_len,
             SshXmlStreamCB result_cb, void *result_cb_context,
             void *context)
{
  return system_resource(input_prefix, (char *) sysid, result_cb,
                         result_cb_context);
}


static SshOperationHandle
entity_resolver(SshXmlParser parser, const char *where_defined,
                Boolean general,
                const unsigned char *name, size_t name_len,
                const unsigned char *pubid, size_t pubid_len,
                const unsigned char *sysid, size_t sysid_len,
                SshXmlStreamCB result_cb,
                void *result_cb_context,
                void *context)
{
  return system_resource(input_prefix, (char *) sysid, result_cb,
                         result_cb_context);
}


/************************** Static help functions ***************************/

static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... CONFORMANCE-TEST-FILE\n\
  -D LEVEL      set debug level string to LEVEL\n\
  -h            print this help and exit\n\
  -n            don't test namespaces\n\
  -v            verbose output\n",
          program);
}


/*********************************** Main ***********************************/

int
main(int argc, char *argv[])
{
  int opt;
  char *cp;

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  /* Parse options. */
  while ((opt = ssh_getopt(argc, argv, "D:hlnqv", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'l':
          skip_too_loose = 1;
          break;

        case 'n':
          namespaces = 0;
          break;

        case 'q':
          quiet = 1;
          break;

        case 'v':
          verbose++;
          break;

        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n", program);
          exit (1);
          break;
        }
    }

  if (ssh_optind >= argc)
    {
      fprintf(stderr, "%s: No conformance test input file specified\n",
              program);
      usage();
      exit(1);
    }

  ssh_event_loop_initialize();

  /* Create an XML parser for parsing the testsuite. */

  /* Create parser. */
  parser = ssh_xml_parser_create(NULL, &content_handler, &error_handler,
                                 NULL, entity_resolver, NULL_FNPTR, NULL);
  SSH_ASSERT(parser != NULL);

  /* Create verifier. */
  verifier = ssh_xml_verifier_create(NULL, dtd_callback, NULL);
  SSH_ASSERT(verifier != NULL);

  if (!ssh_xml_parser_set_verifier(parser, verifier))
    {
      fprintf(stderr, "%s: Could not set XML verifier\n", program);
      exit(1);
    }

  /* Create an XML parser for parsing individual tests. */

  /* Create parser. */
  test_parser = ssh_xml_parser_create(NULL, NULL, &test_error_handler,
                                      NULL, test_entity_resolver,
                                      NULL_FNPTR, NULL);
  SSH_ASSERT(test_parser != NULL);

  /* Create verifier. */
  test_verifier = ssh_xml_verifier_create(NULL, test_dtd_callback, NULL);
  SSH_ASSERT(test_verifier != NULL);

  if (!ssh_xml_parser_set_verifier(test_parser, test_verifier))
    {
      fprintf(stderr, "%s: Could not set XML verifier\n", program);
      exit(1);
    }


  /* Create input prefix. */
  input_prefix = ssh_xstrdup(argv[ssh_optind]);
  cp = strrchr(input_prefix, '/');
  if (cp)
    *cp = '\0';
  else
    {
      ssh_xfree(input_prefix);
      input_prefix = NULL;
    }

  /* Parse input file. */
  ssh_xml_parser_parse_xml_file(parser, argv[ssh_optind], result_cb, NULL);

  /* And run. */
  ssh_event_loop_run();

  /* Cleanup. */
  ssh_xml_verifier_destroy(verifier);
  ssh_xml_parser_destroy(parser);

  ssh_xml_verifier_destroy(test_verifier);
  ssh_xml_parser_destroy(test_parser);

  ssh_event_loop_uninitialize();

  ssh_xfree(input_prefix);
  ssh_xfree(test_input_prefix);
  ssh_xfree(test_filename);

  ssh_util_uninit();
  return retval;
}
