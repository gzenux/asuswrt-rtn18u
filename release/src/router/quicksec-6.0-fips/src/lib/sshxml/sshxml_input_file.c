/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   File input for the XML parser.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"
#include "sshfdstream.h"

#define SSH_DEBUG_MODULE "SshXmlInputFile"


/***************************** Public functions *****************************/

/* The actual parsing function taking the type of the file as a
   boolean argument `dtd'. */
static SshOperationHandle
ssh_xml_parser_parse_file(SshXmlParser parser, Boolean dtd,
                          const char *file_name, SshXmlResultCB result_cb,
                          void *context)
{
  SshStream stream;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Parsing %s file `%s'",
                              dtd ? "DTD" : "XML",
                              file_name));

  stream = ssh_stream_fd_file(file_name, TRUE, FALSE);
  if (stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open input file `%s'", file_name));
      if (result_cb)
        (*result_cb)(SSH_XML_ERROR, context);



      return NULL;
    }

  /* Parse the input stream. */
  return ssh_xml_parser_parse_stream(parser, dtd, stream, file_name,
                                     NULL_FNPTR, NULL, result_cb, context);
}


SshOperationHandle
ssh_xml_parser_parse_xml_file(SshXmlParser parser,
                              const char *file_name,
                              SshXmlResultCB result_cb,
                              void *context)
{
  return ssh_xml_parser_parse_file(parser, FALSE, file_name, result_cb,
                                   context);
}


SshOperationHandle
ssh_xml_parser_parse_dtd_file(SshXmlParser parser,
                              const char *file_name,
                              SshXmlResultCB result_cb,
                              void *context)
{
  return ssh_xml_parser_parse_file(parser, TRUE, file_name, result_cb,
                                   context);
}
