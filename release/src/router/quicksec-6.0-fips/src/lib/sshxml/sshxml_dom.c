/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Document Object Model (DOM) interface for the XML library.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshXmlDom"

/************************** Static help functions ***************************/

/* Allocate a new DOM node of type `type'. */
static SshXmlDomNode
ssh_xml_dom_node_alloc(SshXmlDom dom, SshXmlDomNodeType type)
{
  SshXmlDomNode node;

  node = ssh_calloc(1, sizeof(*node));
  if (node == NULL)
    return NULL;

  node->type = type;

  return node;
}

/* Free the DOM node `node'.  If the node has any children, they will
   also be freed. */
static void
ssh_xml_dom_node_free(SshXmlDomNode node)
{
  if (node == NULL)
    return;

  switch (node->type)
    {
    case SSH_XML_DOM_NODE_ELEMENT:
      /* Free attributes. */
      ssh_xml_attributes_free(node->u.element.attributes);

      /* Free all children. */
      while (node->u.element.children)
        {
          SshXmlDomNode n;

          n = node->u.element.children;
          node->u.element.children = n->next;

          ssh_xml_dom_node_free(n);
        }
      break;

    case SSH_XML_DOM_NODE_TEXT:
      ssh_free(node->u.text.data);
      break;

    case SSH_XML_DOM_NODE_COMMENT:
      ssh_free(node->u.comment.data);
      break;
    }

  ssh_free(node);
}

/* Append the child `child' to the end of the list of children of the
   element `parent'. */
static void
ssh_xml_dom_node_append_child(SshXmlDomNode parent, SshXmlDomNode child)
{
  SSH_ASSERT(parent->type == SSH_XML_DOM_NODE_ELEMENT);
  child->parent = parent;

  if (parent->u.element.children_tail)
    {
      parent->u.element.children_tail->next = child;
      child->prev = parent->u.element.children_tail;
    }
  else
    {
      parent->u.element.children = child;
    }

  parent->u.element.children_tail = child;
}

/* Append data `data', `data_len' to the end of the current data in
   the node `node'.  There are restrictions on the type of the node
   `node'. */
static Boolean
ssh_xml_dom_node_append_data(SshXmlDomNode node, const unsigned char *data,
                             size_t data_len)
{
  unsigned char *ndata;
  unsigned char **datap = NULL;
  size_t *lenp = NULL;

  switch (node->type)
    {
    case SSH_XML_DOM_NODE_TEXT:
      datap = &node->u.text.data;
      lenp = &node->u.text.data_len;
      break;

    case SSH_XML_DOM_NODE_COMMENT:
      datap = &node->u.comment.data;
      lenp = &node->u.comment.data_len;
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  if (datap == NULL || lenp == NULL)
    return FALSE;

  ndata = ssh_realloc(*datap, *lenp ? *lenp + 1 : 0, *lenp + data_len + 1);
  if (ndata == NULL)
    return FALSE;

  memcpy(ndata + *lenp, data, data_len);
  *datap = ndata;
  *lenp = *lenp + data_len;
  ndata[*lenp] = '\0';

  return TRUE;
}


/***************************** Content handler ******************************/

static SshOperationHandle
ssh_xml_dom_start_document(SshXmlParser parser, SshXmlResultCB result_cb,
                           void *result_cb_context,
                           void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_end_document(SshXmlParser parser,
                         SshXmlResultCB result_cb,
                         void *result_cb_context,
                         void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_start_element(SshXmlParser parser,
                          const unsigned char *name,
                          size_t name_len,
                          SshADTContainer attributes,
                          SshXmlResultCB result_cb,
                          void *result_cb_context,
                          void *context)
{
  SshXmlDom dom = (SshXmlDom) context;
  SshXmlDomNode node;

  if (dom->node)
    {
      /* Create an element. */
      node = ssh_xml_dom_node_alloc(dom, SSH_XML_DOM_NODE_ELEMENT);
      if (node == NULL)
        {
          (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
          return NULL;
        }

      /* Save its name. */
      node->u.element.name = name;
      node->u.element.name_len = name_len;

      /* Steal attributes. */
      node->u.element.attributes = attributes;
      ssh_xml_steal_attributes(parser);

      /* Append it to the current element and use it as the new
         current node. */
      ssh_xml_dom_node_append_child(dom->node, node);
      dom->node = node;
    }

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_end_element(SshXmlParser parser,
                        const unsigned char *name,
                        size_t name_len,
                        SshXmlResultCB result_cb,
                        void *result_cb_context,
                        void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->node && dom->node->parent)
    {
      /* Move to our parent. */
      dom->node = dom->node->parent;
    }
  /* This is an unbalanced end-element.  Check how to handle this. */
  else if (dom->params.pass_unbalanced_elements)
    {
      if (dom->content_handler.end_element)
        return (*dom->content_handler.end_element)(parser,
                                                   name, name_len,
                                                   result_cb,
                                                   result_cb_context,
                                                   dom->handler_context);
      /* FALLTHROUGH. */
    }

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_characters(SshXmlParser parser,
                       const unsigned char *data,
                       size_t data_len,
                       Boolean all_whitespace,
                       SshXmlResultCB result_cb,
                       void *result_cb_context,
                       void *context)
{
  SshXmlDom dom = (SshXmlDom) context;
  SshXmlDomNode node;

  if (dom->node)
    {
      /* Check if the last child is a text node.  If so, append this
         data to the end of the existing data. */
      node = dom->node->u.element.children_tail;
      if (node == NULL || node->type != SSH_XML_DOM_NODE_TEXT)
        {
          /* Create a new text node. */
          node = ssh_xml_dom_node_alloc(dom, SSH_XML_DOM_NODE_TEXT);
          if (node == NULL)
            goto error;

          /* Append the child to its parent. */
          ssh_xml_dom_node_append_child(dom->node, node);
        }
      /* Append data. */
      if (!ssh_xml_dom_node_append_data(node, data, data_len))
        goto error;
    }

  /* All done. */
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;

  /* Error handling. */

 error:

  (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_ignorable_wspace(SshXmlParser parser,
                             const unsigned char *data,
                             size_t data_len,
                             Boolean in_dtd,
                             SshXmlResultCB result_cb,
                             void *result_cb_context,
                             void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_pi(SshXmlParser parser,
               const unsigned char *target,
               size_t target_len,
               const unsigned char *data,
               size_t data_len,
               SshXmlResultCB result_cb,
               void *result_cb_context,
               void *context)
{
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

const
static SshXmlContentHandlerStruct ssh_xml_dom_content_handler =
{
  ssh_xml_dom_start_document,
  ssh_xml_dom_end_document,
  ssh_xml_dom_start_element,
  ssh_xml_dom_end_element,
  ssh_xml_dom_characters,
  ssh_xml_dom_ignorable_wspace,
  ssh_xml_dom_pi,
};


/****************************** Error handler *******************************/

static void
ssh_xml_dom_warning(SshXmlParser parser,
                    const char *input_name, SshUInt32 line,
                    SshUInt32 column,
                    const char *message, void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->error_handler.warning)
    (*dom->error_handler.warning)(parser, input_name, line, column,
                                  message, dom->handler_context);
}

static void
ssh_xml_dom_error(SshXmlParser parser,
                  const char *input_name, SshUInt32 line, SshUInt32 column,
                  const char *message, void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->error_handler.error)
    (*dom->error_handler.error)(parser, input_name, line, column,
                                message, dom->handler_context);
}

static void
ssh_xml_dom_fatal_error(SshXmlParser parser,
                        const char *input_name, SshUInt32 line,
                        SshUInt32 column,
                        const char *message, void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->error_handler.fatal_error)
    (*dom->error_handler.fatal_error)(parser, input_name, line, column,
                                      message, dom->handler_context);
}

const
static SshXmlErrorHandlerStruct ssh_xml_dom_error_handler =
{
  ssh_xml_dom_warning,
  ssh_xml_dom_error,
  ssh_xml_dom_fatal_error,
};


/******************************* DTD handler ********************************/

static SshOperationHandle
ssh_xml_dom_entity_decl(SshXmlParser parser,
                        const unsigned char *name,
                        size_t name_len,
                        Boolean general,
                        Boolean internal,
                        const unsigned char *value,
                        size_t value_len,
                        const unsigned char *pubid,
                        size_t pubid_len,
                        const unsigned char *sysid,
                        size_t sysid_len,
                        const unsigned char *ndata,
                        size_t ndata_len,
                        SshXmlResultCB result_cb,
                        void *result_cb_context,
                        void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->dtd_handler.entity_decl)
    return (*dom->dtd_handler.entity_decl)(parser,
                                           name, name_len,
                                           general, internal,
                                           value, value_len,
                                           pubid, pubid_len,
                                           sysid, sysid_len,
                                           ndata, ndata_len,
                                           result_cb, result_cb_context,
                                           dom->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_notation_decl(SshXmlParser parser,
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
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->dtd_handler.notation_decl)
    return (*dom->dtd_handler.notation_decl)(parser,
                                             name, name_len,
                                             pubid, pubid_len,
                                             sysid, sysid_len,
                                             result_cb, result_cb_context,
                                             dom->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_element_decl(SshXmlParser parser,
                         const unsigned char *name,
                         size_t name_len,
                         SshXmlElementContentSpec content_spec,
                         const unsigned char *content_spec_expr,
                         size_t content_spec_expr_len,
                         SshXmlResultCB result_cb,
                         void *result_cb_context,
                         void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->dtd_handler.element_decl)
    return (*dom->dtd_handler.element_decl)(parser,
                                            name, name_len,
                                            content_spec,
                                            content_spec_expr,
                                            content_spec_expr_len,
                                            result_cb, result_cb_context,
                                            dom->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_attlist_decl(SshXmlParser parser,
                         const unsigned char *element_name,
                         size_t element_name_len,
                         SshADTContainer attribute_defs,
                         SshXmlResultCB result_cb,
                         void *result_cb_context,
                         void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->dtd_handler.attlist_decl)
    return (*dom->dtd_handler.attlist_decl)(parser,
                                            element_name, element_name_len,
                                            attribute_defs,
                                            result_cb, result_cb_context,
                                            dom->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_dom_doctype(SshXmlParser parser,
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
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->dtd_handler.doctype)
    return (*dom->dtd_handler.doctype)(parser,
                                       name, name_len,
                                       pubid, pubid_len,
                                       sysid, sysid_len,
                                       result_cb, result_cb_context,
                                       dom->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

const
static SshXmlDtdHandlerStruct ssh_xml_dom_dtd_handler =
{
  ssh_xml_dom_entity_decl,
  ssh_xml_dom_notation_decl,
  ssh_xml_dom_element_decl,
  ssh_xml_dom_attlist_decl,
  ssh_xml_dom_doctype,
};


/***************************** Entity resolver ******************************/

static SshOperationHandle
ssh_xml_dom_entity_resolver(SshXmlParser parser,
                            const char *where_defined,
                            Boolean general,
                            const unsigned char *name,
                            size_t name_len,
                            const unsigned char *pubid,
                            size_t pubid_len,
                            const unsigned char *sysid,
                            size_t sysid_len,
                            SshXmlStreamCB result_cb,
                            void *result_cb_context,
                            void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->entity_resolver)
    return (*dom->entity_resolver)(parser, where_defined, general,
                                   name, name_len,
                                   pubid, pubid_len,
                                   sysid, sysid_len,
                                   result_cb, result_cb_context,
                                   dom->handler_context);

  (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
  return NULL;
}


/*************************** Parse done callback ****************************/

static void
ssh_xml_dom_parse_done_cb(SshXmlParser parser, void *context)
{
  SshXmlDom dom = (SshXmlDom) context;

  if (dom->parse_done_cb)
    (*dom->parse_done_cb)(parser, dom->handler_context);
}


/****************** Document Object Model (DOM) interface *******************/

SshXmlDom
ssh_xml_dom_create(SshXmlDomParams params)
{
  SshXmlDom dom;

  dom = ssh_calloc(1, sizeof(*dom));
  if (dom == NULL)
    goto error;

  if (params)
    dom->params = *params;

  /* Create root element. */
  dom->root = ssh_xml_dom_node_alloc(dom, SSH_XML_DOM_NODE_ELEMENT);
  if (dom->root == NULL)
    goto error;

  /* Set the current node. */
  dom->node = dom->root;

  /* All done. */
  return dom;

  /* Error handling. */

 error:

  ssh_xml_dom_destroy(dom);

  return NULL;
}


void
ssh_xml_dom_destroy(SshXmlDom dom)
{
  if (dom == NULL)
    return;

  /* Free root element. */
  ssh_xml_dom_node_free(dom->root);

  ssh_free(dom);
}


void
ssh_xml_dom_clear(SshXmlDom dom)
{
  /* Free all children of the root element. */
  while (dom->root->u.element.children)
    {
      SshXmlDomNode n;

      n = dom->root->u.element.children;
      dom->root->u.element.children = n->next;

      ssh_xml_dom_node_free(n);
    }
  dom->root->u.element.children = NULL;
  dom->root->u.element.children_tail = NULL;

  /* Clear the current node. */
  dom->node = dom->root;
}


Boolean
ssh_xml_parser_set_dom(SshXmlParser parser, SshXmlDom dom)
{
  /* Store pointer to our XML parser. */
  dom->parser = parser;

  /* Hook between the low-level parser and the user-supplied handlers.
     Since we are the same implementation, we can access the parse's
     internal fields directly.  There is actually functions for doing
     this but we do not want to bloat the code more than necessary. */

  dom->content_handler  = parser->content_handler;
  dom->error_handler    = parser->error_handler;
  dom->dtd_handler      = parser->dtd_handler;
  dom->entity_resolver  = parser->entity_resolver;
  dom->parse_done_cb    = parser->parse_done_cb;
  dom->handler_context  = parser->handler_context;

  /* Register our own handlers. */
  parser->content_handler       = ssh_xml_dom_content_handler;
  parser->error_handler         = ssh_xml_dom_error_handler;
  parser->dtd_handler           = ssh_xml_dom_dtd_handler;
  parser->entity_resolver       = ssh_xml_dom_entity_resolver;
  parser->parse_done_cb         = ssh_xml_dom_parse_done_cb;
  parser->handler_context       = dom;

  /* All done. */
  return TRUE;
}


void
ssh_xml_dom_detach(SshXmlDom dom)
{
  SshXmlParser parser = dom->parser;

  SSH_ASSERT(parser != NULL);

  /* Restore the intercepted handlers. */
  parser->content_handler       = dom->content_handler;
  parser->error_handler         = dom->error_handler;
  parser->dtd_handler           = dom->dtd_handler;
  parser->entity_resolver       = dom->entity_resolver;
  parser->parse_done_cb         = dom->parse_done_cb;
  parser->handler_context       = dom->handler_context;

  /* We are detached from the parser. */
  dom->parser = NULL;
}


/****************************** DOM interface *******************************/

SshXmlDomNode
ssh_xml_dom_get_root_node(SshXmlDom dom)
{
  return dom->root;
}


SshXmlDomNodeType
ssh_xml_dom_node_get_type(SshXmlDomNode node)
{
  return node->type;
}


const unsigned char *
ssh_xml_dom_node_get_name(SshXmlDomNode node, size_t *name_len_return)
{
  const unsigned char *name = NULL;
  size_t len = 0;

  switch (node->type)
    {
    case SSH_XML_DOM_NODE_ELEMENT:
      name = node->u.element.name;
      len = node->u.element.name_len;
      break;

    case SSH_XML_DOM_NODE_TEXT:
    case SSH_XML_DOM_NODE_COMMENT:
      break;
    }

  if (name_len_return)
    *name_len_return = len;

  return name;
}


const unsigned char *
ssh_xml_dom_node_get_value(SshXmlDomNode node, size_t *value_len_return)
{
  unsigned char *value = NULL;
  size_t len = 0;

  switch (node->type)
    {
    case SSH_XML_DOM_NODE_ELEMENT:
      break;

    case SSH_XML_DOM_NODE_TEXT:
      value = node->u.text.data;
      len = node->u.text.data_len;
      break;

    case SSH_XML_DOM_NODE_COMMENT:
      value = node->u.comment.data;
      len = node->u.comment.data_len;
      break;
    }

  if (value_len_return)
    *value_len_return = len;

  return value;
}


SshXmlDomNode
ssh_xml_dom_node_get_parent(SshXmlDomNode node)
{
  return node->parent;
}


SshXmlDomNode
ssh_xml_dom_node_get_first_child(SshXmlDomNode node)
{
  if (node->type == SSH_XML_DOM_NODE_ELEMENT)
    return node->u.element.children;

  return NULL;
}


SshXmlDomNode
ssh_xml_dom_node_get_last_child(SshXmlDomNode node)
{
  if (node->type == SSH_XML_DOM_NODE_ELEMENT)
    return node->u.element.children_tail;

  return NULL;
}


SshXmlDomNode
ssh_xml_dom_node_get_prev(SshXmlDomNode node)
{
  return node->prev;
}


SshXmlDomNode
ssh_xml_dom_node_get_next(SshXmlDomNode node)
{
  return node->next;
}


SshADTContainer
ssh_xml_dom_node_get_attributes(SshXmlDomNode node)
{
  if (node->type == SSH_XML_DOM_NODE_ELEMENT)
    return node->u.element.attributes;

  return NULL;
}
