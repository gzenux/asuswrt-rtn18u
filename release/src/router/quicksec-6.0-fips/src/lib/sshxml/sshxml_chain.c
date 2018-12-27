/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Chaining handlers in an XML parser.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"

void
ssh_xml_parser_get_handlers(SshXmlParser parser,
                            SshXmlContentHandlerStruct *content_handler_return,
                            SshXmlErrorHandlerStruct *error_handler_return,
                            SshXmlDtdHandlerStruct *dtd_handler_return,
                            SshXmlEntityCB *entity_resolver_return,
                            SshXmlParseDoneCB *parse_done_cb_return,
                            void **handler_context_return)
{
  /* All handlers must be queried at once. */
  *content_handler_return       = parser->content_handler;
  *error_handler_return         = parser->error_handler;
  *dtd_handler_return           = parser->dtd_handler;
  *entity_resolver_return       = parser->entity_resolver;
  *parse_done_cb_return         = parser->parse_done_cb;
  *handler_context_return       = parser->handler_context;
}


void
ssh_xml_parser_set_handlers(SshXmlParser parser,
                            const SshXmlContentHandlerStruct *content_handler,
                            const SshXmlErrorHandlerStruct *error_handler,
                            const SshXmlDtdHandlerStruct *dtd_handler,
                            SshXmlEntityCB entity_resolver,
                            SshXmlParseDoneCB parse_done_cb,
                            void *handler_context)
{
  /* Only some handlers need to be set.  Unspecified handlers are
     cleared. */

  if (content_handler)
    parser->content_handler = *content_handler;
  else
    memset(&parser->content_handler, 0, sizeof(parser->content_handler));

  if (error_handler)
    parser->error_handler = *error_handler;
  else
    memset(&parser->error_handler, 0, sizeof(parser->error_handler));

  if (dtd_handler)
    parser->dtd_handler = *dtd_handler;
  else
    memset(&parser->dtd_handler, 0, sizeof(parser->dtd_handler));

  parser->entity_resolver       = entity_resolver;
  parser->parse_done_cb         = parse_done_cb;
  parser->handler_context       = handler_context;
}
