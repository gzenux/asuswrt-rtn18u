/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"
#include "sshdatastream.h"

#define SSH_DEBUG_MODULE "SshXmlInputData"


/* The actual data parser function with boolean arg dtd defining the
   data type */
static SshOperationHandle
ssh_xml_parser_parse_data(SshXmlParser parser, Boolean dtd,
                          const unsigned char *data, size_t data_len,
                          SshXmlResultCB result_cb, void *context)
{
  SshStream stream;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Parsing %s data",
                              dtd ? "DTD" : "XML"));

  stream = ssh_data_stream_create(data, data_len, FALSE);
  if (stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create data stream"));
      if (result_cb)
        (*result_cb)(SSH_XML_ERROR, context);



      return NULL;
    }

  /* Parse the input stream. */
  return ssh_xml_parser_parse_stream(parser, dtd, stream, NULL, NULL_FNPTR,
                                     NULL, result_cb, context);
}

SshOperationHandle
ssh_xml_parser_parse_xml_data(SshXmlParser parser,
                                   const unsigned char *data,
                                   size_t data_len,
                                   SshXmlResultCB result_cb,
                                   void *context)
{
  return ssh_xml_parser_parse_data(parser, FALSE, data, data_len, result_cb,
                                   context);
}


SshOperationHandle
ssh_xml_parser_parse_dtd_data(SshXmlParser parser,
                                   const unsigned char *data,
                                   size_t data_len,
                                   SshXmlResultCB result_cb,
                                   void *context)
{
  return ssh_xml_parser_parse_data(parser, TRUE, data, data_len, result_cb,
                                   context);
}
