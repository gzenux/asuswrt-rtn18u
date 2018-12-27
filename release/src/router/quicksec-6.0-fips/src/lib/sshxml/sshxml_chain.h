/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Chaining handlers in an XML parser.
*/

#ifndef SSHXML_CHAIN_H
#define SSHXML_CHAIN_H

#include "sshxml.h"

/* ************************** Chaining handlers *****************************/

/** Get the currently configured handlers of the parser 'parser'.  All
    handlers must be queried at once.  Therefore, all return arguments
    must be non-NULL. */
void ssh_xml_parser_get_handlers(
                        SshXmlParser parser,
                        SshXmlContentHandlerStruct *content_handler_return,
                        SshXmlErrorHandlerStruct *error_handler_return,
                        SshXmlDtdHandlerStruct *dtd_handler_return,
                        SshXmlEntityCB *entity_resolver_return,
                        SshXmlParseDoneCB *parse_done_cb_return,
                        void **handler_context_return);

/** Set new handlers for the parser 'parser'.  The function sets all
    handlers at once.  If some of the handler arguments have the value
    NULL, those handlers are cleared from the parser 'parser'. */
void ssh_xml_parser_set_handlers(
                        SshXmlParser parser,
                        const SshXmlContentHandlerStruct *content_handler,
                        const SshXmlErrorHandlerStruct *error_handler,
                        const SshXmlDtdHandlerStruct *dtd_handler,
                        SshXmlEntityCB entity_resolver,
                        SshXmlParseDoneCB parse_done_cb,
                        void *handler_context);

#endif /* not SSHXML_CHAIN_H */
