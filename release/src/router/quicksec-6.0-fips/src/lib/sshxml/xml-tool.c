/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML tool.
   This also serves as an example how to use the XML library
   SAX and Verifier components and shows how to attach a DOM
   layer to the parser and how DOM's are traversed.
*/

#include "sshincludes.h"
#include "sshgetopt.h"
#include "ssheloop.h"
#include "sshxml.h"
#include "sshxml_dom.h"
#include "sshurl.h"
#include "sshhttp.h"
#include "sshfdstream.h"

#define SSH_DEBUG_MODULE "xml-tool"

/***************************** Global variables *****************************/

SshUInt32 num_warnings = 0;
SshUInt32 num_errors = 0;
SshUInt32 num_fatal_errors = 0;
int retval;
char *program;

SshUInt32 verbose = 0;
int dont_verify = 0;
int expand_namespaces = 0;
Boolean use_dom = FALSE;
int input_is_dtd = 0;
int compress = 0;

SshXmlParser parser = NULL;
SshXmlDom dom = NULL;
SshXmlVerifier verifier = NULL;

int num_args;
char **arguments;


/************************** Static help functions ***************************/

/* Recursive function to traverse DOM tree `node' (and its children)
   of the DOM `dom'. */
static void
traverse_dom(SshXmlDom dom, SshXmlDomNode node)
{
  SshXmlDomNode n;
  const unsigned char *ucp;
  size_t len;

  switch (ssh_xml_dom_node_get_type(node))
    {
    case SSH_XML_DOM_NODE_ELEMENT:
      fprintf(stdout, "<%s XXX attributes>",
              ssh_xml_dom_node_get_name(node, NULL));

      /* Traverse children. */
      for (n = ssh_xml_dom_node_get_first_child(node);
           n;
           n = ssh_xml_dom_node_get_next(n))
        traverse_dom(dom, n);

      fprintf(stdout, "</%s>", ssh_xml_dom_node_get_name(node, NULL));
      break;

    case SSH_XML_DOM_NODE_TEXT:
    case SSH_XML_DOM_NODE_COMMENT:
      ucp = ssh_xml_dom_node_get_value(node, &len);
      fwrite(ucp, len, 1, stdout);
      break;
    }
}

/* Result callback for the parser operation. */
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
      /* If dom was created, traverse the parsed document contents
         using it. */
      if (dom && verbose)
        {
          SshXmlDomNode node = ssh_xml_dom_get_root_node(dom);

          for (node = ssh_xml_dom_node_get_first_child(node);
               node;
               node = ssh_xml_dom_node_get_next(node))
            traverse_dom(dom, node);
        }
    }

  fprintf(stdout, "%s: #warnings=%u, #errors=%u, #fatal errors=%u\n",
          arguments[ssh_optind - 1],
          (unsigned int) num_warnings,
          (unsigned int) num_errors,
          (unsigned int) num_fatal_errors);

  if (ssh_optind < num_args)
    {
      /* Continue parsing with the next document. */
      num_warnings = 0;
      num_errors = 0;
      num_fatal_errors = 0;

      /* Clear the attached DOM. No need to clear SAX, as it is alive
         only till call of parse result callback. */
      if (dom)
        ssh_xml_dom_clear(dom);

      if (input_is_dtd)
        ssh_xml_parser_parse_dtd_file(parser, arguments[ssh_optind++],
                                      result_cb, NULL);
      else
        ssh_xml_parser_parse_xml_file(parser, arguments[ssh_optind++],
                                      result_cb, NULL);
    }
}

/* Print usage text to the standard output. */
static void
usage(void)
{
  fprintf(stdout, "\
Usage: %s [OPTION]... XML-FILE\n\
  -c            compress\n\
  -d            input is DTD\n\
  -D LEVEL      set debug level string to LEVEL\n\
  -f            do not allow forward ID attribute references\n\
  -h            print this help and exit\n\
  -M            use DOM\n\
  -n            expand namespaces\n\
  -v            verbose output\n\
  -V            don't verify\n",
          program);
}

static void
print_literal(const unsigned char *data, size_t data_len)
{
  size_t i;

  for (i = 0; i < data_len; i++)
    if (data[i] == '\'')
      printf("&#27;");
    else
      printf("%c", data[i]);
}

/*********************** Handling external resources ************************/
/* Context structure for HTTP operations. */
struct SshXmlToolHttpCtxRec
{
  SshHttpClientContext http_ctx;
  SshXmlStreamCB result_cb;
  void *result_cb_context;

  SshOperationHandle http_handle;
  SshOperationHandleStruct handle;
};

typedef struct SshXmlToolHttpCtxRec SshXmlToolHttpCtxStruct;
typedef struct SshXmlToolHttpCtxRec *SshXmlToolHttpCtx;

static void
xmltest_http_stream_destructor(void *context)
{
  SshXmlToolHttpCtx ctx = (SshXmlToolHttpCtx) context;

  ssh_http_client_uninit(ctx->http_ctx);
  ssh_xfree(ctx);
}

static void
xmltest_http_abort_cb(void *context)
{
  SshXmlToolHttpCtx ctx = (SshXmlToolHttpCtx) context;

  /* Abort the pending HTTP operation. */
  SSH_ASSERT(ctx->http_handle != NULL);
  ssh_operation_abort(ctx->http_handle);

  /* And destroy our context. */
  xmltest_http_stream_destructor(ctx);
}

static void
xmltest_http_result_cb(SshHttpClientContext client_ctx,
                       SshHttpResult result,
                       SshTcpError ip_error,
                       SshStream stream,
                       void *callback_context)
{
  SshXmlToolHttpCtx ctx = (SshXmlToolHttpCtx) callback_context;

  /* This completes our system resource operation and invalidates the
     operation handle. */
  ssh_operation_unregister(&ctx->handle);

  if (result != SSH_HTTP_RESULT_SUCCESS)
    {
      (*ctx->result_cb)(NULL, NULL, NULL_FNPTR, NULL, ctx->result_cb_context);
      xmltest_http_stream_destructor(ctx);
      return;
    }

  (*ctx->result_cb)(stream, NULL, xmltest_http_stream_destructor, ctx,
                    ctx->result_cb_context);
}

/* Fetching system resources with HTTP. */
static SshOperationHandle
system_resource_http(const unsigned char *url, SshXmlStreamCB result_cb,
                     void *result_cb_context)
{
  SshXmlToolHttpCtx ctx;
  SshHttpClientParams params;
  SshOperationHandle http_handle;

  memset(&params, 0, sizeof(params));
  params.http_proxy_url = ssh_ustr("http://www-cache.ssh.fi:8080");

  ctx = ssh_xcalloc(1, sizeof(*ctx));
  ctx->http_ctx = ssh_http_client_init(&params);
  if (ctx->http_ctx == NULL)
    {
      ssh_xfree(ctx);
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  ctx->result_cb = result_cb;
  ctx->result_cb_context = result_cb_context;

  /* Start an HTTP operation. */
  http_handle = ssh_http_get(ctx->http_ctx, url,
                             xmltest_http_result_cb, ctx,
                             SSH_HTTP_HDR_END);
  if (http_handle == NULL)
    {
      /* The HTTP operation was synchronous and our context is already
         freed and the result callback is called. */
      return NULL;
    }

  /* Asynchronous operation. */
  ctx->http_handle = http_handle;

  /* Create an operation handle for our operation. */
  ssh_operation_register_no_alloc(&ctx->handle,
                                  xmltest_http_abort_cb,
                                  ctx);

  return &ctx->handle;
}

/* Fetching system resources from files. */
static SshOperationHandle
system_resource_file(const unsigned char *name,
                     SshXmlStreamCB result_cb, void *result_cb_context)
{
  SshStream stream;

  stream = ssh_stream_fd_file(ssh_csstr(name), TRUE, FALSE);
  if (stream == NULL)
    {
      fprintf(stderr, "%s: Could not open file `%s'\n",
              program, name);
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  /* All done. */
  (*result_cb)(stream, ssh_csstr(name), NULL_FNPTR, NULL, result_cb_context);
  return NULL;
}

/* Handle external system resources. This is the entry point to
   external resouce management and dispatches between HTTP and FILE
   references. */
static SshOperationHandle
system_resource(const unsigned char *sysid,
                SshXmlStreamCB result_cb, void *result_cb_context)
{
  unsigned char *scheme;

  if (verbose > 2)
    fprintf(stdout, "%s: about to fetch system resource `%s'", program, sysid);

  /* First, consider system ID as an URL. */
  if (ssh_url_parse(sysid, &scheme, NULL, NULL, NULL, NULL, NULL))
    {
      SshOperationHandle handle = NULL;

      /* Looks good. */
      if (ssh_usstrcmp(scheme, "http") == 0)
        {
          handle = system_resource_http(sysid, result_cb, result_cb_context);
        }
      else
        {
          fprintf(stderr, "%s: Unsupported external system resource `%s'\n",
                  program, sysid);
          (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
          handle = NULL;
        }

      ssh_free(scheme);
      return handle;
    }

  /* Try to read it from file system. */
  return system_resource_file(sysid, result_cb, result_cb_context);
}


/***************************** Content handler ******************************/

static SshOperationHandle
xmltool_start_document(SshXmlParser parser,
                       SshXmlResultCB result_cb, void *result_cb_context,
                       void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_end_document(SshXmlParser parser,
                     SshXmlResultCB result_cb, void *result_cb_context,
                     void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

/* Print elements while we encounter them. */
static SshOperationHandle
xmltool_start_element(SshXmlParser parser,
                      const unsigned char *name, size_t name_len,
                      SshADTContainer attributes,
                      SshXmlResultCB result_cb, void *result_cb_context,
                      void *context)
{
  SshADTHandle h;

  if (expand_namespaces)
    {
      const unsigned char *lname;
      const unsigned char *ns;

      lname = ssh_xml_get_local_name(parser, name, name_len, NULL);
      ns = ssh_xml_get_namespace(parser, name, name_len, NULL);

      if (ns)
        fprintf(stdout, "<%s:%s", ns, lname);
      else
        fprintf(stdout, "<%s", name);
    }
  else
    fprintf(stdout, "<%s", name);

  /* Print attributes. */
  for (h = ssh_adt_enumerate_start(attributes);
       h;
       h = ssh_adt_enumerate_next(attributes, h))
    {
      if (expand_namespaces)
        {
          const unsigned char *name;
          size_t name_len;
          const unsigned char *ns;

          name = ssh_xml_attr_handle_get_name(attributes, h, &name_len);
          ns = ssh_xml_get_attr_namespace(parser,name, name_len, NULL);

          if (ns)
            fprintf(stdout, " %s:%s=",
                    ns,
                    ssh_xml_get_local_name(parser, name, name_len, NULL));
          else
            fprintf(stdout, " %s=",
                    ssh_xml_get_local_name(parser, name, name_len, NULL));
        }
      else
        {
          fprintf(stdout, " %s=",
                  ssh_xml_attr_handle_get_name(attributes, h, NULL));
        }

      fprintf(stdout, "'%s'",
              ssh_xml_attr_handle_get_value(attributes, h, NULL));
    }
  fprintf(stdout, ">");
  if (compress)
    fprintf(stdout, "\n");

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_end_element(SshXmlParser parser,
                    const unsigned char *name, size_t name_len,
                    SshXmlResultCB result_cb, void *result_cb_context,
                    void *context)
{
  fprintf(stdout, "</%.*s>",(int) name_len, name);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_characters(SshXmlParser parser,
                   const unsigned char *data, size_t data_len,
                   Boolean all_whitespace,
                   SshXmlResultCB result_cb, void *result_cb_context,
                   void *context)
{
  if (!compress || !all_whitespace)
    fprintf(stdout, "%.*s", (int) data_len, data);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_ignorable_wspace(SshXmlParser parser,
                         const unsigned char *data, size_t data_len,
                         Boolean in_dtd,
                         SshXmlResultCB result_cb, void *result_cb_context,
                         void *context)
{
  if ((!in_dtd || verbose > 1) && !compress)
    fprintf(stdout, "%.*s", (int) data_len, data);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_pi(SshXmlParser parser,
           const unsigned char *name, size_t name_len,
           const unsigned char *data, size_t data_len,
           SshXmlResultCB result_cb, void *result_cb_context,
           void *context)
{
  fprintf(stdout, "<?%s %s?>", name, data);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshXmlContentHandlerStruct content_handler =
{
  xmltool_start_document,
  xmltool_end_document,
  xmltool_start_element,
  xmltool_end_element,
  xmltool_characters,
  xmltool_ignorable_wspace,
  xmltool_pi,
};


/****************************** Error handler *******************************/

static void
xmltool_warning(SshXmlParser parser,
                const char *input_name, SshUInt32 line, SshUInt32 column,
                const char *message, void *context)
{
  num_warnings++;
  fprintf(stderr,
          "%s:%d: Warning: %s\n", input_name, (int) line,
          message);
}

static void
xmltool_error(SshXmlParser parser,
              const char *input_name, SshUInt32 line, SshUInt32 column,
              const char *message, void *context)
{
  num_errors++;
  fprintf(stderr,
          "%s:%d: Error: %s\n", input_name, (int) line,
          message);
}

static void
xmltool_fatal_error(SshXmlParser parser,
                    const char *input_name, SshUInt32 line, SshUInt32 column,
                    const char *message, void *context)
{
  num_fatal_errors++;
  fprintf(stderr,
          "%s:%d: Error: %s\n", input_name, (int) line,
          message);
}

static SshXmlErrorHandlerStruct error_handler =
{
  xmltool_warning,
  xmltool_error,
  xmltool_fatal_error,
};


/******************************* DTD handler ********************************/

static SshOperationHandle
xmltool_entity_decl(SshXmlParser parser,
                    const unsigned char *name, size_t name_len,
                    Boolean general, Boolean internal,
                    const unsigned char *value, size_t value_len,
                    const unsigned char *pubid, size_t pubid_len,
                    const unsigned char *sysid, size_t sysid_len,
                    const unsigned char *ndata, size_t ndata_len,
                    SshXmlResultCB result_cb, void *result_cb_context,
                    void *context)
{
  if (general)
    {
      if (internal)
        {
          fprintf(stdout, "<!ENTITY %s '", name);
          print_literal(value, value_len);
          fprintf(stdout, "'>");
        }
      else
        {
          if (pubid)
            {
              if (ndata)
                {
                  fprintf(stdout, "<!ENTITY %s PUBLIC '", name);
                  print_literal(pubid, pubid_len);
                  fprintf(stdout, "' '");
                  print_literal(sysid, sysid_len);
                  fprintf(stdout, "' NDATA '");
                  print_literal(ndata, ndata_len);
                  fprintf(stdout, "'>");
                }
              else
                {
                  fprintf(stdout, "<!ENTITY %s PUBLIC '", name);
                  print_literal(pubid, pubid_len);
                  fprintf(stdout, "' '");
                  print_literal(sysid, sysid_len);
                  fprintf(stdout, "'>");
                }
            }
          else
            {
              fprintf(stdout, "<!ENTITY %s SYSTEM '", name);
              print_literal(sysid, sysid_len);
              fprintf(stdout, "'>");
            }
        }
    }
  else
    {
      if (internal)
        {
          fprintf(stdout, "<!ENTITY %% %s '", name);
          print_literal(value, value_len);
          fprintf(stdout, "'>");
        }
      else
        {
          if (pubid)
            {
              fprintf(stdout, "<!ENTITY %% %s PUBLIC '", name);
              print_literal(pubid, pubid_len);
              fprintf(stdout, "' '");
              print_literal(sysid, sysid_len);
              fprintf(stdout, "'>");
            }
          else
            {
              fprintf(stdout, "<!ENTITY %% %s SYSTEM '", name);
              print_literal(sysid, sysid_len);
              fprintf(stdout, "'>");
            }
        }
    }
  if (compress)
    fprintf(stdout, "\n");

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_notation_decl(SshXmlParser parser,
                      const unsigned char *name,
                      size_t name_len,
                      const unsigned char *pubid,
                      size_t pubid_len,
                      const unsigned char *sysid,
                      size_t sysid_len,
                      SshXmlResultCB result_cb,
                      void *result_cb_context,
                      void *context)
{
  fprintf(stdout, "<!NOTATION %s ", name);

  if (pubid && sysid)
    {
      fprintf(stdout, "PUBLIC '");
      print_literal(pubid, pubid_len);
      fprintf(stdout, "' '");
      print_literal(sysid, sysid_len);
      fprintf(stdout, "'>");
    }
  else if (sysid)
    {
      fprintf(stdout, "SYSTEM '");
      print_literal(sysid, sysid_len);
      fprintf(stdout, "'>");
    }
  else if (pubid)
    {
      fprintf(stdout, "PUBLIC '");
      print_literal(pubid, pubid_len);
      fprintf(stdout, "'>");
    }
  if (compress)
    fprintf(stdout, "\n");

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_element_decl(SshXmlParser parser,
                     const unsigned char *name, size_t name_len,
                     SshXmlElementContentSpec content_spec,
                     const unsigned char *content_spec_expr,
                     size_t content_spec_expr_len,
                     SshXmlResultCB result_cb, void *result_cb_context,
                     void *context)
{
  fprintf(stdout, "<!ELEMENT %s ", name);
  switch (content_spec)
    {
    case SSH_XML_ELEMENT_CONTENT_EMPTY:
      fprintf(stdout, "EMPTY");
      break;

    case SSH_XML_ELEMENT_CONTENT_ANY:
      fprintf(stdout, "ANY");
      break;

    case SSH_XML_ELEMENT_CONTENT_EXPR:
      fprintf(stdout, "%s", content_spec_expr);
      break;
    }
  fprintf(stdout, ">");
  if (compress)
    fprintf(stdout, "\n");

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_attlist_decl(SshXmlParser parser,
                     const unsigned char *element_name,
                     size_t element_name_len,
                     SshADTContainer attribute_defs,
                     SshXmlResultCB result_cb, void *result_cb_context,
                     void *context)
{
  fprintf(stdout, "<!ATTLIST %s %lu attributes>", element_name,
          (unsigned long)ssh_adt_num_objects(attribute_defs));
  if (compress)
    fprintf(stdout, "\n");
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
xmltool_doctype(SshXmlParser parser,
                const unsigned char *name, size_t name_len,
                const unsigned char *pubid, size_t pubid_len,
                const unsigned char *sysid, size_t sysid_len,
                SshXmlResultCB result_cb, void *result_cb_context,
                void *context)
{
  if (pubid && sysid)
    fprintf(stdout, "<!DOCTYPE %s PUBLIC '%s' '%s'>", name, pubid, sysid);
  else if (sysid)
    fprintf(stdout, "<!DOCTYPE %s SYSTEM '%s'>", name, sysid);
  else
    fprintf(stdout, "<!DOCTYPE %s>\n", name);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshXmlDtdHandlerStruct dtd_handler =
{
  xmltool_entity_decl,
  xmltool_notation_decl,
  xmltool_element_decl,
  xmltool_attlist_decl,
  xmltool_doctype,
};


/***************************** Entity resolver ******************************/

static SshOperationHandle
xmltool_entity_resolver(SshXmlParser parser, const char *where_defined,
                        Boolean general,
                        const unsigned char *name, size_t name_len,
                        const unsigned char *pubid, size_t pubid_len,
                        const unsigned char *sysid, size_t sysid_len,
                        SshXmlStreamCB result_cb,
                        void *result_cb_context,
                        void *context)
{
  /* We only handle system resources. */
  if (sysid == NULL)
    {
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  return system_resource(sysid, result_cb, result_cb_context);
}


/********************** DTD callback for the verifier ***********************/

static SshOperationHandle
dtd_callback(SshXmlParser parser,
             const unsigned char *pubid, size_t pubid_len,
             const unsigned char *sysid, size_t sysid_len,
             SshXmlStreamCB result_cb, void *result_cb_context,
             void *context)
{
  /* We handle only system resources. */
  if (sysid == NULL)
    {
      (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
      return NULL;
    }

  return system_resource(sysid, result_cb, result_cb_context);
}


/*********************************** Main ***********************************/

int
main(int argc, char *argv[])
{
  int opt;
  SshXmlVerifierParamsStruct verifier_params;

  memset(&verifier_params, 0, sizeof(verifier_params));

  program = strrchr(argv[0], '/');
  if (program)
    program++;
  else
    program = argv[0];

  /* Parse options. */
  while ((opt = ssh_getopt(argc, argv, "cdD:hfMnvV", NULL)) != EOF)
    {
      switch (opt)
        {
        case 'c':
          compress = 1;
          break;

        case 'd':
          input_is_dtd = 1;
          break;

        case 'D':
          ssh_debug_set_level_string(ssh_optarg);
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'f':
          verifier_params.no_forward_id_refs = TRUE;
          break;

        case 'M':
          use_dom = TRUE;
          break;

        case 'n':
          expand_namespaces = 1;
          break;

        case 'v':
          verbose++;
          break;

        case 'V':
          dont_verify = 1;
          break;

        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n", program);
          exit (1);
          break;
        }
    }

  if (ssh_optind >= argc)
    {
      fprintf(stderr, "%s: No XML file specified\n", program);
      usage();
      exit(1);
    }

  ssh_event_loop_initialize();

  /* Create parser. */
  parser = ssh_xml_parser_create(NULL,
                                 verbose ? &content_handler : NULL,
                                 &error_handler,
                                 verbose > 1 ? &dtd_handler : NULL,
                                 xmltool_entity_resolver,
                                 NULL_FNPTR,
                                 (void *) 42);
  if (parser == NULL)
    {
      fprintf(stderr, "%s: Could not create XML parser\n", program);
      exit(1);
    }

  /* Should we use DOM? */
  if (use_dom)
    {
      dom = ssh_xml_dom_create(NULL);
      if (dom == NULL)
        {
          fprintf(stderr, "%s: Could not create DOM object\n", program);
          exit(1);
        }

      if (!ssh_xml_parser_set_dom(parser, dom))
        {
          fprintf(stderr, "%s: Could not set DOM object to parser\n", program);
          exit(1);
        }
    }

  /* Create verifier. */
  verifier = ssh_xml_verifier_create(&verifier_params, dtd_callback, NULL);
  if (verifier == NULL)
    {
      fprintf(stderr, "%s: Could not create XML verifier\n", program);
      exit(1);
    }

  /* Set the verifier unless it is not wanted by our user. */
  if (!dont_verify)
    if (!ssh_xml_parser_set_verifier(parser, verifier))
      {
        fprintf(stderr, "%s: Could not set XML verifier\n", program);
        exit(1);
      }

  /* Parse input files */
  num_args = argc;
  arguments = argv;
  if (input_is_dtd)
    ssh_xml_parser_parse_dtd_file(parser, argv[ssh_optind++], result_cb, NULL);
  else
    ssh_xml_parser_parse_xml_file(parser, argv[ssh_optind++], result_cb, NULL);

  /* And run. */
  ssh_event_loop_run();

  ssh_xml_parser_destroy(parser);
  ssh_xml_verifier_destroy(verifier);
  ssh_xml_dom_destroy(dom);

  ssh_event_loop_uninitialize();
  ssh_util_uninit();
  return retval;
}
