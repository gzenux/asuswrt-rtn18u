/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Document Object Model (DOM) interface for the XML library.

   <keywords DOM (Document Object Model), Document Object Model (DOM)>
*/

#ifndef SSHXML_DOM_H
#define SSHXML_DOM_H

#include "sshxml.h"

/* ************************ Types and definitions ***************************/

/** A Document Object Model (DOM) object. */
typedef struct SshXmlDomRec *SshXmlDom;


/* **************** Document Object Model (DOM) interface *******************/

/** Parameters for a DOM object.  If any of the fields has the value
    NULL or 0, the default value will be used for that field. */
struct SshXmlDomParamsRec
{



  /** Pass unbalanced elements to the upper levels in the SAX chain. */
  Boolean pass_unbalanced_elements;
};

typedef struct SshXmlDomParamsRec SshXmlDomParamsStruct;
typedef struct SshXmlDomParamsRec *SshXmlDomParams;

/** Creates a DOM object.

    @param params
    Specifies optional parameters for the module. If the argument
    'params' has the value NULL, or any of its fields have the value
    NULL or 0, the default values will be used for those fields. */
SshXmlDom ssh_xml_dom_create(SshXmlDomParams params);

/** Destroy the DOM object 'dom'. */
void ssh_xml_dom_destroy(SshXmlDom dom);

/** Free all nodes from the DOM tree 'dom'.  After this call the
    objects is in the same state as it is after ssh_xml_com_create()
    call. */
void ssh_xml_dom_clear(SshXmlDom dom);




/** Attach the DOM module 'dom' for the XML parser 'parser'. */
Boolean ssh_xml_parser_set_dom(SshXmlParser parser, SshXmlDom dom);

/** Detach the DOM module 'dom' from its current attachment to a parser
    or to a verifier. The module must be attached when this is called. */
void ssh_xml_dom_detach(SshXmlDom dom);


/* **************************** DOM interface *******************************/

/** DOM node types. */
typedef enum
{
  SSH_XML_DOM_NODE_ELEMENT,      /** Element. */
  SSH_XML_DOM_NODE_TEXT,         /** Text. */
  SSH_XML_DOM_NODE_COMMENT       /** Comment. */



} SshXmlDomNodeType;

/** A DOM node. */
typedef struct SshXmlDomNodeRec *SshXmlDomNode;

/** Get the root element of the DOM object 'dom'. That is, get the root
    of the document being parsed with the parser this 'dom' is attached
    to. */
SshXmlDomNode ssh_xml_dom_get_root_node(SshXmlDom dom);

/** Get the type of the node 'node'. */
SshXmlDomNodeType ssh_xml_dom_node_get_type(SshXmlDomNode node);

/** Get the name of the element node 'node'. */
const unsigned char *ssh_xml_dom_node_get_name(SshXmlDomNode node,
                                               size_t *name_len_return);

/** Get the value of the node 'node'. */
const unsigned char *ssh_xml_dom_node_get_value(SshXmlDomNode node,
                                                size_t *value_len_return);

/** Get the parent of the node 'node'. */
SshXmlDomNode ssh_xml_dom_node_get_parent(SshXmlDomNode node);

/** Get the first child node of the element node 'node'. */
SshXmlDomNode ssh_xml_dom_node_get_first_child(SshXmlDomNode node);

/** Get the last child node of the element node 'node'. */
SshXmlDomNode ssh_xml_dom_node_get_last_child(SshXmlDomNode node);

/** Get the previous sibling of the node 'node'. */
SshXmlDomNode ssh_xml_dom_node_get_prev(SshXmlDomNode node);

/** Get the next sibling of the node 'node'. */
SshXmlDomNode ssh_xml_dom_node_get_next(SshXmlDomNode node);

/** Get the attributes of the element node 'node'. */
SshADTContainer ssh_xml_dom_node_get_attributes(SshXmlDomNode node);

#endif /* not SSHXML_DOM_H */
